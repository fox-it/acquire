from __future__ import annotations

import csv
import gzip
import hashlib
import io
import logging
import re
import time
from typing import TYPE_CHECKING, Any, Callable

from acquire.utils import StrEnum

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target import Target
    from dissect.target.helpers.fsutil import TargetPath

log = logging.getLogger(__name__)


class HashFunc(StrEnum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"

    def as_hashlib_method(self) -> Callable[..., Any] | None:
        if self == HashFunc.MD5:
            return hashlib.md5
        if self == HashFunc.SHA1:
            return hashlib.sha1
        if self == HashFunc.SHA256:
            return hashlib.sha256
        return None


PROGRESS_LOG_STEP = 10000  # processed files

CSV_COLUMNS = ["path", "file-size"] + [h.value for h in HashFunc]


def get_paths_from_dir(
    target: Target,
    glob: str,
    extensions: set[str] | None = None,
) -> Iterator[Path]:
    """Yield paths that match provided `glob` pattern and `extensions` values"""

    extension_suffixes = {f".{ext}" for ext in extensions} if extensions else None

    for path in target.fs.path("/").glob(glob):
        if extensions and path.suffix not in extension_suffixes:
            continue
        yield path


def get_path_details(path: TargetPath, hash_funcs: Iterator[HashFunc] | None = None) -> tuple:
    """
    Calculate and return the details for specified path.

    The details include file size and hashes, calculated for
    hash functions provided in `hash_funcs`.
    """

    hash_funcs = hash_funcs or []
    if hash_funcs:
        provided_hash_funcs_sorted = sorted(set(hash_funcs))

        hashes = path.get().hash(algos=[f.as_hashlib_method() for f in provided_hash_funcs_sorted])

        hashes_map = dict(zip(provided_hash_funcs_sorted, hashes))
    else:
        hashes_map = {}

    file_size = path.stat().st_size

    return {
        "path": str(path),
        "file-size": file_size,
        **{func.value: digest for func, digest in hashes_map.items()},
    }


def filter_out_nonfiles(paths: Iterator[Path]) -> Iterator[Path]:
    """Filter out paths that are not files"""
    for path in paths:
        try:
            is_file = path.is_file()
        except OSError:
            log.debug("Exception while determining file properties of `%s`, skipping", path, exc_info=True)
            continue

        if not is_file:
            continue

        yield path


def filter_out_huge_files(paths: Iterator[Path], *, max_size_bytes: int) -> Iterator[Path]:
    """Filter out paths that are larger than `max_size_bytes` value"""
    for path in paths:
        try:
            file_size = path.stat().st_size
        except Exception:
            log.debug("Exception while getting the size of `%s`, skipping", path, exc_info=True)
            continue

        if file_size > max_size_bytes:
            continue

        yield path


def filter_out_by_value_match(
    paths: Iterator[Path],
    *,
    value: bytes,
    offsets: Iterator[int] = (0,),
) -> Iterator[Path]:
    """Filter out paths where file data matches the provided `value` at the specified offsets"""

    if not offsets:
        raise ValueError("No offsets provided")

    value_len = len(value)
    bytes_to_read = value_len + max(offsets)

    for path in paths:
        try:
            fh = path.open("rb")
        except Exception:
            log.debug("Exception while opening path `%s`, skipping", path, exc_info=True)
            continue

        buffer = fh.read(bytes_to_read)
        for offset in offsets:
            if buffer[offset : offset + value_len] == value:
                continue

        yield path


def filter_out_by_path_match(
    paths: Iterator[Path],
    *,
    re_pattern: str,
    re_flags: re.RegexFlag = re.IGNORECASE,
) -> Iterator[Path]:
    """Filter out paths that match provided regex pattern"""
    pattern = re.compile(re_pattern, flags=re_flags)
    return filter(lambda p: not pattern.match(str(p)), paths)


def collect_hashes(
    target: Target,
    specs: Iterator[Iterator[tuple]],
    path_filters: Iterator[Callable[[Iterator[Path]], Iterator[Path]]] | None = None,
) -> Iterator[tuple]:
    """
    Walk through the paths, calculate hashes and return details per path.

    Spec contains a path selector and a list of hash functions to compute against the paths.
    For example:
        [
            ("dir", ("sysvol/Windows/", ("exe", "dll", "sys"))),
            (HashFunc.MD5, HashFunc.SHA1)
        ]
    """

    log.info("Starting to collect hashes for spec: %s", specs)

    stream_hash_func_pairs = []

    for spec in filter(lambda spec: spec[0][0] == "glob", specs):
        path_selector, hash_funcs = spec
        glob_value = path_selector[1]
        paths_stream = target.fs.path("/").glob(glob_value)

        stream_hash_func_pairs.append((paths_stream, hash_funcs))

    for spec in filter(lambda spec: spec[0][0] == "dir", specs):
        path_selector, hash_funcs = spec
        path_selector_param = path_selector[1]

        if isinstance(path_selector_param, (tuple, list)):
            dir_name, extensions = path_selector_param
            extensions = set(extensions) if extensions else set()
        else:
            dir_name = path_selector_param
            extensions = None

        # Create a glob to recursively catch all files inside a directory
        dir_glob = str(target.fs.path(dir_name).joinpath("**/*"))

        paths_stream = get_paths_from_dir(target, dir_glob, extensions)
        stream_hash_func_pairs.append((paths_stream, hash_funcs))

    path_filters = path_filters or []

    for paths, hash_funcs in stream_hash_func_pairs:
        seen_paths = set()

        paths = filter_out_nonfiles(paths)

        for filter_func in path_filters:
            paths = filter_func(paths)

        for path in paths:
            path_str = str(path)
            if path_str in seen_paths:
                continue

            seen_paths.add(path_str)

            try:
                details = get_path_details(path, hash_funcs)
            except Exception:
                log.debug("Error while processing path `{path}`, skipping", exc_info=True)
                continue

            yield details


def serialize_into_csv(rows: Iterator[list], compress: bool = True) -> tuple[int, bytes]:
    """
    Serialize provided rows into normal or gzip-compressed CSV, and return a tuple
    containing the number of rows processed and the result bytes.
    """

    raw_buffer = io.BytesIO()

    counter = 0
    start = time.time()

    buffer = gzip.GzipFile(fileobj=raw_buffer, mode="wb") if compress else raw_buffer

    with io.TextIOWrapper(buffer, encoding="utf-8") as wrapper:
        csv_writer = csv.DictWriter(wrapper, fieldnames=CSV_COLUMNS)
        csv_writer.writeheader()
        for row in rows:
            csv_writer.writerow(row)
            counter += 1
            if counter % PROGRESS_LOG_STEP == 0:
                log.info(
                    "%s files processed in %.2f secs, last row: %s",
                    counter,
                    (time.time() - start),
                    row,
                )

    return (counter, raw_buffer.getvalue())
