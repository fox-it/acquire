from __future__ import annotations

import dataclasses
import errno
import logging
import subprocess
import textwrap
from collections import defaultdict
from dataclasses import dataclass
from itertools import groupby
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Optional, Sequence, Type, Union

from dissect.target import Target
from dissect.target.exceptions import (
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
    SymlinkRecursionError,
)
from dissect.target.helpers import fsutil

from acquire.utils import StrEnum, get_formatted_exception, normalize_path

if TYPE_CHECKING:
    from acquire.outputs.base import Output

log = logging.getLogger(__name__)


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    MISSING = "missing"
    EMPTY = "empty"


class ArtifactType(StrEnum):
    FILE = "file"
    SYMLINK = "symlink"
    GLOB = "glob"
    DIR = "dir"
    COMMAND = "command"

    # when outcome is known before path is resolved into a file or directory
    PATH = "path"


@dataclass(frozen=True)
class Record:
    module_name: str
    outcome: Outcome
    artifact_type: ArtifactType
    artifact_value: str
    details: Optional[str] = None


def serialize_path(path: Any) -> str:
    if not isinstance(path, fsutil.TargetPath):
        return str(path)

    if not getattr(path, "_fs", None):
        return str(path)

    # Naive way to serialize TargetPath filesystem's metadata is
    # to rely on uniqueness of `path._fs` object
    fs_id = id(path._fs)
    return f"{path._fs.__fstype__}:{fs_id}:{path}"


@dataclass
class CollectionReport:
    registry: set[Record] = dataclasses.field(default_factory=set)

    seen_paths: set[str] = dataclasses.field(default_factory=set)

    def _register(
        self,
        module_name: str,
        outcome: Outcome,
        artifact_type: ArtifactType,
        artifact_value: Union[str, Path],
        details: Optional[str] = None,
    ) -> None:
        if isinstance(artifact_value, Path):
            artifact_value = serialize_path(artifact_value)

        if artifact_type in (ArtifactType.FILE, ArtifactType.DIR):
            self.seen_paths.add(artifact_value)

        self.registry.add(
            Record(
                module_name=module_name,
                outcome=outcome,
                artifact_type=artifact_type,
                artifact_value=artifact_value,
                details=details,
            )
        )

    def add_file_collected(self, module: str, path: Path) -> None:
        self._register(module, Outcome.SUCCESS, ArtifactType.FILE, path)

    def add_symlink_collected(self, module: str, path: Path) -> None:
        self._register(module, Outcome.SUCCESS, ArtifactType.SYMLINK, path)

    def add_symlink_failed(self, module: str, path: Path) -> None:
        self._register(module, Outcome.FAILURE, ArtifactType.SYMLINK, path)

    def add_file_failed(self, module: str, failed_path: Path) -> None:
        exc = get_formatted_exception()
        self._register(module, Outcome.FAILURE, ArtifactType.FILE, failed_path, exc)

    def add_file_missing(self, module: str, missing_path: Path) -> None:
        self._register(module, Outcome.MISSING, ArtifactType.FILE, missing_path)

    def add_glob_failed(self, module: str, failed_pattern: str) -> None:
        exc = get_formatted_exception()
        self._register(module, Outcome.FAILURE, ArtifactType.GLOB, failed_pattern, exc)

    def add_glob_empty(self, module: str, pattern: str) -> None:
        self._register(module, Outcome.EMPTY, ArtifactType.GLOB, pattern)

    def add_dir_collected(self, module: str, path: Path) -> None:
        self._register(module, Outcome.SUCCESS, ArtifactType.DIR, path)

    def add_dir_failed(self, module: str, failed_path: Path) -> None:
        exc = get_formatted_exception()
        self._register(module, Outcome.FAILURE, ArtifactType.DIR, failed_path, exc)

    def add_dir_missing(self, module: str, missing_path: Path) -> None:
        self._register(module, Outcome.MISSING, ArtifactType.DIR, missing_path)

    def add_path_failed(self, module: str, failed_path: Path) -> None:
        exc = get_formatted_exception()
        self._register(module, Outcome.FAILURE, ArtifactType.PATH, failed_path, exc)

    def add_path_missing(self, module: str, missing_path: Path) -> None:
        self._register(module, Outcome.MISSING, ArtifactType.PATH, missing_path)

    def add_command_collected(self, module: str, command_parts: Sequence[str]) -> None:
        self._register(module, Outcome.SUCCESS, ArtifactType.COMMAND, tuple(command_parts))

    def add_command_failed(self, module: str, command_parts: Sequence[str]) -> None:
        exc = get_formatted_exception()
        self._register(module, Outcome.FAILURE, ArtifactType.COMMAND, tuple(command_parts), exc)

    def get_records_per_module_per_outcome(self, serialize_records=False) -> dict[str, dict[str, list[Record]]]:
        grouped_records = defaultdict(lambda: defaultdict(list))

        # sort records by module name and outcome to prepare for grouping
        sorted_registry = sorted(self.registry, key=lambda rec: (rec.module_name, rec.outcome))

        for module_name, records_per_module in groupby(sorted_registry, lambda r: r.module_name):
            for outcome, records_per_module_outcome in groupby(records_per_module, lambda r: r.outcome):
                if serialize_records:
                    records = map(lambda r: dataclasses.asdict(r), records_per_module_outcome)
                else:
                    records = records_per_module_outcome
                grouped_records[module_name][outcome].extend(records)

        return grouped_records

    def get_counts_per_module_per_outcome(self) -> dict[str, dict[str, int]]:
        records_map = self.get_records_per_module_per_outcome()
        for module, records_per_module in records_map.items():
            for outcome, records_per_module_outcome in records_per_module.items():
                records_map[module][outcome] = len(records_per_module_outcome)
        return records_map

    def was_path_seen(self, path: Path) -> bool:
        return serialize_path(path) in self.seen_paths


class Collector:
    METADATA_BASE = "$metadata$"
    COMMAND_OUTPUT_BASE = f"{METADATA_BASE}/command-output"

    def __init__(self, target: Target, output: Output, base: str = "fs", skip_list: Optional[set] = None):
        self.target = target
        self.output = output
        self.base = base
        self.skip_list = skip_list or set()

        self.report = CollectionReport()
        self.bound_module_name = None

        self.output.init(self.target)

    def __enter__(self) -> Collector:
        return self

    def __exit__(self, *args, **kwargs) -> None:
        self.close()

    def bind(self, module: Type) -> None:
        self.bound_module_name = module.__name__

    def unbind(self) -> None:
        self.bound_module_name = None

    def close(self) -> None:
        self.output.close()

    def _create_output_path(self, path: Path, base: Optional[str] = None) -> str:
        base = base or self.base
        outpath = str(path)

        if base:
            # Make sure that `outpath` is not an abolute path, since
            # `fsutil.join()` (that uses `posixpath.join()`) discards all previous path
            # components if an encountered component is an absolute path.
            outpath = outpath.lstrip("/")
            outpath = fsutil.join(base, outpath)

        return outpath

    def collect(
        self, spec: Iterable, module_name: Optional[str] = None, follow: bool = True, volatile: bool = False
    ) -> None:
        module_name = self.bound_module_name or module_name
        if not module_name:
            raise ValueError("Module name must be provided or Collector needs to be bound to a module")

        for spec_item in spec:
            transform_func = None
            if len(spec_item) == 3:
                artifact_type, value, transform_func = spec_item
            else:
                artifact_type, value = spec_item

            if transform_func is not None:
                values = transform_func(self.target, value)
            else:
                values = [value]

            for value in values:
                if artifact_type in (ArtifactType.FILE, ArtifactType.DIR):
                    self.collect_path(value, module_name=module_name, follow=follow, volatile=volatile)
                elif artifact_type == ArtifactType.SYMLINK:
                    self.collect_symlink(value, module_name=module_name)
                elif artifact_type == ArtifactType.GLOB:
                    self.collect_glob(value, module_name=module_name)
                elif artifact_type == ArtifactType.COMMAND:
                    command_parts, output_filename = value
                    self.collect_command_output(command_parts, output_filename, module_name=module_name)
                else:
                    raise ValueError("Unknown artifact type %s in spec: %s", artifact_type, spec)

    def collect_file(
        self,
        path: Union[str, fsutil.TargetPath],
        size: Optional[int] = None,
        outpath: Optional[str] = None,
        module_name: Optional[str] = None,
        base: Optional[str] = None,
        volatile: bool = False,
    ) -> None:
        module_name = self.bound_module_name or module_name
        if not module_name:
            raise ValueError("Module name must be provided or Collector needs to be bound to a module")

        if not isinstance(path, fsutil.TargetPath):
            path = self.target.fs.path(path)

        if self.report.was_path_seen(path):
            log.info("- Collecting file %s: Skipped (DEDUP)", path)
            return

        outpath = self._create_output_path(outpath or path, base)
        entry = path.get()

        try:
            if volatile:
                self.output.write_volatile(outpath, entry, size)
            else:
                self.output.write_entry(outpath, entry, size)

            self.report.add_file_collected(module_name, path)
            result = "OK"
        except FileNotFoundError:
            self.report.add_file_missing(module_name, path)
            result = "File not found"
        except Exception as exc:
            log.error("Failed to collect file", exc_info=True)
            self.report.add_file_failed(module_name, path)
            result = repr(exc)

        log.info("- Collecting file %s: %s", path, result)

    def collect_symlink(self, path: fsutil.TargetPath, module_name: Optional[str] = None) -> None:
        try:
            outpath = self._create_output_path(path)
            self.output.write_bytes(outpath, b"", path.get(), 0)

            self.report.add_symlink_collected(module_name, path)
            result = "OK"
        except Exception as exc:
            self.report.add_symlink_failed(module_name, path)
            log.error("Failed to collect symlink %s (-> %s)", path, path.readlink(), exc_info=True)
            result = repr(exc)

        log.info("- Collecting symlink %s: %s", path, result)

    def collect_dir(
        self,
        path: Union[str, fsutil.TargetPath],
        seen_paths: Optional[set] = None,
        module_name: Optional[str] = None,
        follow: bool = True,
        volatile: bool = False,
    ) -> None:
        module_name = self.bound_module_name or module_name
        if not module_name:
            raise ValueError("Module name must be provided or Collector needs to be bound to a module")

        if not isinstance(path, fsutil.TargetPath):
            path = self.target.fs.path(path)

        log.info("- Collecting directory %s", path)

        seen_paths = seen_paths or set()
        try:
            resolved = path.resolve()
            if resolved in seen_paths:
                log.debug("Breaking out of symlink loop: path %s linking to %s", path, resolved)
                return
            seen_paths.add(resolved)

            for entry in path.iterdir():
                self.collect_path(
                    entry, seen_paths=seen_paths, module_name=module_name, follow=follow, volatile=volatile
                )

        except OSError as error:
            if error.errno == errno.ENOENT:
                self.report.add_dir_missing(module_name, path)
                log.error("- Directory %s is not found", path)
            elif error.errno == errno.EACCES:
                self.report.add_dir_failed(module_name, path)
                log.error("- Permission denied while accessing directory %s", path)
            else:
                self.report.add_dir_failed(module_name, path)
                log.error("- OSError while collecting directory %s (%s)", path, error)
        except Exception:
            self.report.add_dir_failed(module_name, path)
            log.error("- Failed to collect directory %s", path, exc_info=True)

    def collect_glob(self, pattern: str, module_name: Optional[str] = None) -> None:
        module_name = self.bound_module_name or module_name
        if not module_name:
            raise ValueError("Module name must be provided or Collector needs to be bound to a module")

        log.info("- Collecting glob %s", pattern)
        try:
            glob_is_empty = True
            for entry in self.target.fs.path("/").glob(pattern.lstrip("/")):
                glob_is_empty = False
                self.collect_path(entry, module_name=module_name)
        except Exception:
            log.error("- Failed to collect glob %s", pattern, exc_info=True)
            self.report.add_glob_failed(module_name, pattern)
        else:
            if glob_is_empty:
                self.report.add_glob_empty(module_name, pattern)
            else:
                log.info("- Collecting glob %s succeeded", pattern)

    def collect_path(
        self,
        path: Union[str, fsutil.TargetPath],
        seen_paths: Optional[set] = None,
        module_name: Optional[str] = None,
        follow: bool = True,
        volatile: bool = False,
    ) -> None:
        module_name = self.bound_module_name or module_name
        if not module_name:
            raise ValueError("Module name must be provided or Collector needs to be bound to a module")

        if not isinstance(path, fsutil.TargetPath):
            path = self.target.fs.path(path)

        if self.skip_list and normalize_path(self.target, path) in self.skip_list:
            self.report.add_path_failed(module_name, path)
            log.error("- Skipping collection of %s, path is on the skip list", path)
            return

        try:
            # If a path does not exist, is_dir(), is_file() and is_symlink() will return False (and not raise an
            # exception), so we need to explicitly trigger an exception for this using path.get().
            path.get()
            is_dir = path.is_dir()
            is_file = path.is_file()
            is_symlink = path.is_symlink()
        except OSError as error:
            if error.errno == errno.ENOENT:
                self.report.add_path_missing(module_name, path)
                log.error("- Path %s is not found", path)
            elif error.errno == errno.EACCES:
                self.report.add_path_failed(module_name, path)
                log.error("- Permission denied while accessing path %s", path)
            else:
                self.report.add_path_failed(module_name, path)
                log.error("- OSError while collecting path %s", path)
            return
        except (FileNotFoundError, NotADirectoryError, NotASymlinkError, SymlinkRecursionError, ValueError):
            self.report.add_path_missing(module_name, path)
            log.error("- Path %s is not found", path)
            return
        except Exception:
            self.report.add_path_failed(module_name, path)
            log.error("- Failed to collect path %s", path, exc_info=True)
            return

        if is_symlink:
            self.collect_symlink(path, module_name=module_name)

            if follow:
                # Follow the symlink, call ourself again with the resolved path
                self.collect_path(
                    path.resolve(), seen_paths=seen_paths, module_name=module_name, follow=follow, volatile=volatile
                )
        elif is_dir:
            self.collect_dir(path, seen_paths=seen_paths, module_name=module_name, follow=follow, volatile=volatile)
        elif is_file:
            self.collect_file(path, module_name=module_name, volatile=volatile)
        else:
            self.report.add_path_failed(module_name, path)
            log.error("- Don't know how to collect %s in module %s", path, module_name)

    def collect_command_output(
        self,
        command_parts: list[str],
        output_filename: str,
        module_name: Optional[str] = None,
    ) -> None:
        module_name = self.bound_module_name or module_name
        if not module_name:
            raise ValueError("Module name must be provided or Collector needs to be bound to a module")

        output_base = fsutil.join(self.base, self.COMMAND_OUTPUT_BASE) if self.base else self.COMMAND_OUTPUT_BASE
        full_output_path = fsutil.join(output_base, output_filename)

        log.info("- Collecting output from command `%s`", " ".join(command_parts))
        try:
            command_output = subprocess.check_output(command_parts, stderr=subprocess.STDOUT, shell=True)
            self.output.write_bytes(full_output_path, command_output)
            self.report.add_command_collected(module_name, command_parts)
        except Exception:
            self.report.add_command_failed(module_name, command_parts)
            log.error("- Failed to collect output from command `%s`", " ".join(command_parts), exc_info=True)
            return

    def write_bytes(self, destination_path: str, data: bytes) -> None:
        self.output.write_bytes(destination_path, data, None)
        self.report.add_file_collected(self.bound_module_name, destination_path)


def get_report_summary(report: CollectionReport) -> str:
    """Create a table-view report summary with success/failure/missing/empty counters per module"""

    record_counts = report.get_counts_per_module_per_outcome()

    if not record_counts:
        return ""

    module_name_max_len = max(len(module_name) for module_name in record_counts.keys())
    # Must be as long as a header
    module_name_max_len = max(len("Module"), module_name_max_len)

    row_template = (
        f"{{module_name: >{module_name_max_len}s}} | "
        "{success_count: >10} | "
        "{failure_count: >10} | "
        "{missing_count: >10} | "
        "{empty_count: >10}"
    )

    header = row_template.format(
        module_name="Module",
        success_count="Success",
        failure_count="Failure",
        missing_count="Missing",
        empty_count="Empty",
    )

    splitter = "-" * len(header)

    rows = [
        row_template.format(
            module_name=module_name,
            success_count=counts.get(Outcome.SUCCESS, ""),
            failure_count=counts.get(Outcome.FAILURE, ""),
            missing_count=counts.get(Outcome.MISSING, ""),
            empty_count=counts.get(Outcome.EMPTY, ""),
        )
        for module_name, counts in record_counts.items()
    ]

    total_counts = defaultdict(int)
    for counts in record_counts.values():
        for count_type, value in counts.items():
            total_counts[count_type] += value

    total_counts_row = row_template.format(
        module_name="Total",
        success_count=total_counts[Outcome.SUCCESS],
        failure_count=total_counts[Outcome.FAILURE],
        missing_count=total_counts[Outcome.MISSING],
        empty_count=total_counts[Outcome.EMPTY],
    )

    return "\n".join(
        [
            splitter,
            header,
            splitter,
            *rows,
            splitter,
            total_counts_row,
            splitter,
        ]
    )


def get_full_formatted_report(report: CollectionReport, record_indent: int = 4) -> str:
    """
    Create a full list of successful / failed / missing / empty artifacts collected,
    broken down by module.
    """

    record_line_template = "{record.outcome}: {record.artifact_type}:{record.artifact_value}"
    blocks = []

    for module_name, records_per_module in report.get_records_per_module_per_outcome().items():
        blocks.append(module_name)
        for _, records_per_module_per_outcome in records_per_module.items():
            record_lines = []
            for record in records_per_module_per_outcome:
                record_lines.append(record_line_template.format(record=record))

            paragraph = "\n".join(record_lines)
            paragraph = textwrap.indent(paragraph, prefix=record_indent * " ")

            blocks.append(paragraph)

    return "\n".join(blocks)
