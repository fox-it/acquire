from __future__ import annotations

import dataclasses
import errno
import logging
import subprocess
import textwrap
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import groupby
from typing import TYPE_CHECKING, BinaryIO, Callable

from dissect.target.exceptions import (
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
    SymlinkRecursionError,
)
from dissect.target.helpers import fsutil

from acquire.utils import StrEnum, get_formatted_exception, normalize_path

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from dissect.target import Target
    from dissect.target.filesystem import Filesystem

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
    details: str | None = None


@dataclass
class CollectionReport:
    target: Target

    registry: set[Record] = dataclasses.field(default_factory=set)
    seen_paths: set[str] = dataclasses.field(default_factory=set)

    def _uniq_path(self, path: str | fsutil.TargetPath) -> str:
        path = normalize_path(self.target, path, resolve_parents=False, preserve_case=False)
        # Depending on the way they are constructed, windows paths may start with a root '/'
        # followed by a drive letter or start immediately with a drive letter (and no root. To make
        # sure both types are matched identical, add a root if none is present.
        if not path.startswith("/"):
            path = f"/{path}"

        return path

    def _register(
        self,
        module_name: str,
        outcome: Outcome,
        artifact_type: ArtifactType,
        artifact_value: str | fsutil.TargetPath,
        details: str | None = None,
    ) -> None:
        if artifact_type in (ArtifactType.FILE, ArtifactType.DIR, ArtifactType.SYMLINK, ArtifactType.PATH):
            # Any path like artefacts are expected to be resolved to the level needed.
            artifact_value = self._uniq_path(artifact_value)
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

    def add_file_collected(self, module: str, path: fsutil.TargetPath) -> None:
        self._register(module, Outcome.SUCCESS, ArtifactType.FILE, path)

    def add_symlink_collected(self, module: str, path: fsutil.TargetPath) -> None:
        self._register(module, Outcome.SUCCESS, ArtifactType.SYMLINK, path)

    def add_symlink_failed(self, module: str, path: fsutil.TargetPath) -> None:
        self._register(module, Outcome.FAILURE, ArtifactType.SYMLINK, path)

    def add_file_failed(self, module: str, failed_path: fsutil.TargetPath) -> None:
        exc = get_formatted_exception()
        self._register(module, Outcome.FAILURE, ArtifactType.FILE, failed_path, exc)

    def add_file_missing(self, module: str, missing_path: fsutil.TargetPath) -> None:
        self._register(module, Outcome.MISSING, ArtifactType.FILE, missing_path)

    def add_glob_failed(self, module: str, failed_pattern: str) -> None:
        exc = get_formatted_exception()
        self._register(module, Outcome.FAILURE, ArtifactType.GLOB, failed_pattern, exc)

    def add_glob_empty(self, module: str, pattern: str) -> None:
        self._register(module, Outcome.EMPTY, ArtifactType.GLOB, pattern)

    def add_dir_collected(self, module: str, path: fsutil.TargetPath) -> None:
        self._register(module, Outcome.SUCCESS, ArtifactType.DIR, path)

    def add_dir_failed(self, module: str, failed_path: fsutil.TargetPath) -> None:
        exc = get_formatted_exception()
        self._register(module, Outcome.FAILURE, ArtifactType.DIR, failed_path, exc)

    def add_dir_missing(self, module: str, missing_path: fsutil.TargetPath) -> None:
        self._register(module, Outcome.MISSING, ArtifactType.DIR, missing_path)

    def add_path_collected(self, module: str, path: fsutil.TargetPath) -> None:
        self._register(module, Outcome.SUCCESS, ArtifactType.PATH, path)

    def add_path_failed(self, module: str, failed_path: fsutil.TargetPath) -> None:
        exc = get_formatted_exception()
        self._register(module, Outcome.FAILURE, ArtifactType.PATH, failed_path, exc)

    def add_path_missing(self, module: str, missing_path: fsutil.TargetPath) -> None:
        self._register(module, Outcome.MISSING, ArtifactType.PATH, missing_path)

    def add_command_collected(self, module: str, command_parts: Sequence[str]) -> None:
        self._register(module, Outcome.SUCCESS, ArtifactType.COMMAND, tuple(command_parts))

    def add_command_failed(self, module: str, command_parts: Sequence[str]) -> None:
        exc = get_formatted_exception()
        self._register(module, Outcome.FAILURE, ArtifactType.COMMAND, tuple(command_parts), exc)

    def get_records_per_module_per_outcome(self, serialize_records: bool = False) -> dict[str, dict[str, list[Record]]]:
        grouped_records = defaultdict(lambda: defaultdict(list))

        # sort records by module name and outcome to prepare for grouping
        sorted_registry = sorted(self.registry, key=lambda rec: (rec.module_name, rec.outcome))

        for module_name, records_per_module in groupby(sorted_registry, lambda r: r.module_name):
            for outcome, records_per_module_outcome in groupby(records_per_module, lambda r: r.outcome):
                if serialize_records:
                    records = (dataclasses.asdict(r) for r in records_per_module_outcome)
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

    def was_path_seen(self, path: str | fsutil.TargetPath) -> bool:
        path = self._uniq_path(path)
        return path in self.seen_paths


class Collector:
    METADATA_BASE = "$metadata$"
    COMMAND_OUTPUT_BASE = f"{METADATA_BASE}/command-output"

    def __init__(self, target: Target, output: Output, base: str = "fs", skip_list: set | None = None):
        self.target = target
        self.output = output
        self.base = base
        self.skip_list = skip_list or set()

        self.report = CollectionReport(target)
        self.bound_module_name = None
        self.filter = lambda _: False

        self.output.init(self.target)

    def __enter__(self) -> Collector:  # noqa: PYI034
        return self

    def __exit__(self, *args, **kwargs) -> None:
        self.close()

    @contextmanager
    def bind_module(self, module: type) -> Collector:
        try:
            self.bind(module)
            yield self
        finally:
            self.unbind()

    @contextmanager
    def file_filter(self, filter: Callable[[fsutil.TargetPath], bool] | None) -> Collector:
        try:
            if filter:
                self.filter = filter
            yield self
        finally:
            self.filter = lambda _: False

    def bind(self, module: type) -> None:
        self.bound_module_name = module.__name__

    def unbind(self) -> None:
        self.bound_module_name = None

    def close(self) -> None:
        self.output.close()

    def _output_path(self, path: str | fsutil.TargetPath, base: str | None = None) -> str:
        if base is None:
            base = self.base

        # When constructing an output path from a collected path, normalization generally already
        # happened and is not needed, so this will be a no-op. However when constructing an output
        # path based on an explicitly provided output path, it is nice to be able to normalize any
        # sysvol part to an actual driveletter.
        outpath = normalize_path(self.target, path, resolve_parents=False, preserve_case=True)

        if base:
            base = base.strip("/")
            # Make sure that `outpath` is not an abolute path, since `fsutil.join()` (which uses
            # `posixpath.join()`) discards all previous path components if an encountered component
            # is an absolute path.
            outpath = outpath.lstrip("/")
            outpath = fsutil.join(base, outpath)

        return outpath

    def collect(
        self,
        spec: Iterator,
        module_name: str | None = None,
        follow: bool = True,
        volatile: bool = False,
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

            values = transform_func(self.target, value) if transform_func is not None else [value]

            for value in values:
                if artifact_type in (ArtifactType.FILE, ArtifactType.DIR, ArtifactType.SYMLINK, ArtifactType.PATH):
                    self.collect_path(value, module_name=module_name, volatile=volatile)
                elif artifact_type == ArtifactType.GLOB:
                    self.collect_glob(value, module_name=module_name)
                elif artifact_type == ArtifactType.COMMAND:
                    command_parts, output_filename = value
                    self.collect_command_output(command_parts, output_filename, module_name=module_name)
                else:
                    raise ValueError("Unknown artifact type %s in spec: %s", artifact_type, spec)

    def _get_symlink_branches(self, path: fsutil.TargetPath) -> tuple[fsutil.TargetPath, list[fsutil.TargetPath]]:
        """Given a ``path`` that contains symlinks in any of its intermediate parts, collect all these
        intermediate branches that end in a symlink.

        Args:
            path: The path to collect the branches for. It is assumed to be normalized with respect to path
                  separators and Windows device root and sysvol parts.

        Returns:
            A tuple of the full path with all intermediaries resolved except for its final part and a list of
            the collected intermediate symlink branches.
        """
        cur_path = None
        branches = []

        for path_part in path.parts[:-1]:
            cur_path = self.target.fs.path(path_part) if cur_path is None else cur_path.joinpath(path_part)

            if cur_path.is_symlink():
                branches.append(cur_path)

                # resolve() fully resolves cur_path, so there is no use in
                # recursively calling _get_symlink_branches(), we only need to walk
                # over the remaining parts to see if any of them are symlinks.
                cur_path = cur_path.resolve()

        last_part = path.parts[-1]
        path = cur_path.joinpath(last_part)

        return path, branches

    def collect_path(
        self,
        path: str | fsutil.TargetPath,
        outpath: str | None = None,
        module_name: str | None = None,
        base: str | None = None,
        volatile: bool = False,
        seen_paths: set[fsutil.TargetPath] | None = None,
    ) -> None:
        """Collect a path from the target's root filesystem, including any intermediary symlinks.

        Args:
            path: The path to collect (this may be a file, directory or symlink).
            outpath: A posix style explicit path where to store the collected path. In case ``path``
                     is a directory this will be the new base directory. It is concatenated with
                     ``base`` to get the final output path. Windows device path and sysvol parts are
                     normalized. When set, intermediate symlinks of ``path`` are not collected. When
                     not set, it will be constructed from the given ``path``.
            module_name: When set it indicates the module doing the collection, used for logging and
                         reporting. When not set the :class:``Collector``'s ``bound_module`` will be
                         used.
            base: A different base path to use to store the file, it is prepended to the given or
                  generated ``outpath``.
            volatile: When this flag is set, the collection of a number of artefacts is performed slightly different.
                      Symlinks at the end of a path will not be collected, empty directories will be collected,
                      files will be collected in a slower but more robust way, any errors while reading the bytes
                      will not fail the collection of the file and all bytes already retrieved will be stored.
            seen_paths: A list of normalized path strings, used when calling this function
                        recursively to collect directories to break out of symlink loops.
        """
        module_name = self.bound_module_name or module_name
        if not module_name:
            raise ValueError("Module name must be provided or Collector needs to be bound to a module")

        if not isinstance(path, fsutil.TargetPath):
            path = self.target.fs.path(path)

        log.debug("- Collecting path %s", path)

        # This dedup is a shortcut as when the normalized path and, optionally, its intermediary
        # symlinks are collected, the orignal non-normalized path is also added to the report and
        # dedup list. This prevents rerunning a number of normalizing steps to find out if the
        # normalized version of the path should be deduplicated.
        if self.report.was_path_seen(path):
            log.info("- Collecting path %s: Skipped (DEDUP)", path)
            return

        # If a path is used in any of the report.add_path_*() functions, it is used for
        # deduping. In case of errors and depending on the processing stage, the path that
        # resulted in these errors changes.
        error_path = path

        try:
            if outpath:
                # If an outpath is explicitly provided, there is no use to store any of the
                # intermediate symlinks to the original path.
                collect_inpath = normalize_path(self.target, path, resolve_parents=True, preserve_case=True)
            else:
                # If there is no explicit outpath, the branch collection will resolve the parents.
                # ONLY REPLACE device root, sysvol & path seps.
                collect_inpath = normalize_path(self.target, path, resolve_parents=False, preserve_case=True)
            collect_inpath = self.target.fs.path(collect_inpath)

            error_path = collect_inpath

            # For breaking out of symlink loops and skipping files from the skip_list we need a
            # fully normalized path except for resolving the final part.
            # RESOLVE parents, REPLACE device root, sysvol, path seps & casing
            os_clean_path = normalize_path(self.target, path, resolve_parents=True, preserve_case=False)

            # If direct_collect is True, it indicates collect_path() was not called recursively.
            # This is useful info to log errors in case a directory was tried to collect but it was
            # empty.
            direct_collect = False

            if seen_paths is None:
                seen_paths = set()
                direct_collect = True
            elif os_clean_path in seen_paths:
                self.report.add_path_failed(module_name, path)
                log.error("- Skipping collection of %s, breaking out of symlink loop", path)
                return

            seen_paths.add(os_clean_path)

            if self.skip_list and os_clean_path in self.skip_list:
                self.report.add_path_failed(module_name, path)
                log.info("- Skipping collection of %s, path is on the skip list", path)
                return

            # If a path does not exist, is_dir(), is_file() and is_symlink() will return False (and
            # not raise an exception), so we need to explicitly trigger an exception for this using
            # collect_inpath.get().
            path_entry = collect_inpath.get()
            is_dir = collect_inpath.is_dir()
            is_file = collect_inpath.is_file()
            is_symlink = collect_inpath.is_symlink()

            branches = []
            if not outpath:
                collect_inpath, branches = self._get_symlink_branches(collect_inpath)

            # If the collect_inpath and branches resulting from path are all skipped due to deduping,
            # we don't want to report success of collecting path.
            all_deduped = True
            if self.report.was_path_seen(collect_inpath):
                # The collect_inpath is skipped, but any symlink branches will still be collected,
                # as we may not have collected this file through the specific symlinks set in path.
                log.info("- Collecting path %s: Skipped (DEDUP)", collect_inpath)

            elif self.filter(collect_inpath):
                log.info("- Collecting path %s: Skipped (filtered out)", collect_inpath)
                # No need to collect the symlink branches, as they would point to nowhere.
                return

            else:
                all_deduped = False
                collect_outpath = self._output_path(outpath or collect_inpath, base)

                if is_symlink:
                    log.info("- Collecting symlink %s to: %s", collect_inpath, collect_outpath)
                    self.output.write_entry(collect_outpath, path_entry)
                    self.report.add_symlink_collected(module_name, collect_inpath)
                    log.info("- Collecting symlink %s succeeded", collect_inpath)

                    if not volatile:
                        self.collect_path(
                            collect_inpath.resolve(),
                            # If explicitly provided, the symlink itself was already saved as outpath, where it
                            # links to wil be saved under its own name.
                            outpath=None,
                            module_name=module_name,
                            base=base,
                            volatile=volatile,
                            seen_paths=seen_paths,
                        )

                elif is_dir:
                    dir_is_empty = True
                    for entry in collect_inpath.iterdir():
                        dir_is_empty = False

                        # If an explicit outpath was provided, we store all entries on top of the provided
                        # outpath.
                        if outpath:
                            outpath = fsutil.join(outpath, entry.name)

                        self.collect_path(
                            entry,
                            outpath=outpath,
                            module_name=module_name,
                            base=base,
                            volatile=volatile,
                            seen_paths=seen_paths,
                        )

                    if dir_is_empty:
                        if direct_collect and not volatile:
                            self.report.add_dir_failed(module_name, collect_inpath)
                            log.error("- Failed to collect directory %s, it is empty", collect_inpath)
                            return

                        if volatile:
                            log.info("- Collecting EMPTY directory %s to: %s", collect_inpath, collect_outpath)
                            self.output.write_entry(collect_outpath, collect_inpath)
                            self.report.add_dir_collected(module_name, collect_inpath)
                            log.info("- Collecting EMPTY directory %s succeeded", collect_inpath)

                elif is_file:
                    log.info("- Collecting file %s to: %s", collect_inpath, collect_outpath)
                    if volatile:
                        self.output.write_volatile(collect_outpath, path_entry)
                    else:
                        self.output.write_entry(collect_outpath, path_entry)
                    self.report.add_file_collected(module_name, collect_inpath)
                    log.info("- Collecting file %s succeeded", collect_inpath)

                else:
                    self.report.add_path_failed(module_name, path)
                    log.error("- Don't know how to collect %s in module %s", path, module_name)
                    return

            # All branches are symlinks, collect them as such. If an explicit outpath is set, the list of
            # branches will be empty.
            for branch_path in branches:
                log.info("- Collecting symlink branch path %s", branch_path)
                error_path = branch_path
                if self.report.was_path_seen(branch_path):
                    log.info("- Collecting symlink branch path %s: Skipped (DEDUP)", branch_path)
                else:
                    all_deduped = False
                    outpath = self._output_path(branch_path, base)
                    self.output.write_entry(outpath, branch_path.get())
                    self.report.add_symlink_collected(module_name, branch_path)
                    log.info("- Collecting symlink branch suceeded %s", branch_path)

        except (FileNotFoundError, NotADirectoryError, NotASymlinkError, SymlinkRecursionError, ValueError):
            self.report.add_path_missing(module_name, error_path)
            log.error("- Path %s is not found (while collecting %s)", error_path, path)  # noqa: TRY400
        except OSError as error:
            if error.errno == errno.ENOENT:
                self.report.add_path_missing(module_name, error_path)
                log.error("- Path %s is not found (while collecting %s)", error_path, path)  # noqa: TRY400
            elif error.errno == errno.EACCES:
                self.report.add_path_failed(module_name, error_path)
                log.error("- Permission denied while accessing path %s (while collecting %s)", error_path, path)  # noqa: TRY400
            else:
                self.report.add_path_failed(module_name, error_path)
                log.error("- OSError while collecting path %s (while collecting %s)", error_path, path)  # noqa: TRY400
        except Exception:
            self.report.add_path_failed(module_name, error_path)
            log.error("- Failed to collect path %s (while collecting %s)", error_path, path, exc_info=True)  # noqa: G201
        else:
            if not all_deduped and collect_inpath != path:
                self.report.add_path_collected(module_name, path)
            log.debug("- Collecting path %s succeeded", path)

    def collect_file_raw(
        self,
        path: str | fsutil.TargetPath,
        fs: Filesystem,
        mountpoint: str,
        outpath: str | None = None,
        module_name: str | None = None,
        base: str | None = None,
        file_accessor: Callable[[BinaryIO, int], BinaryIO] | None = None,
    ) -> None:
        """Collect a single file from one of the target's filesystems.

        Args:
            path: The path to the file to collect. This path will be fully resolved before
                  collecting and construction of the output path.
            fs: The filesystem to collect the path from.
            mountpoint: The (possibly fake) mountpoint of the given filesystem, to make the path
                        unique within the target. If ``outpath`` is not supplied it will be
                        concatenated with ``path`` and ``base`` to construct the ``outpath``.
            outpath: A posix style explicit path where to store the collected file. It is
                     concatenated with ``base`` to get the final output path. Windows device path
                     and sysvol parts are normalized. When not set, it will be constructed from the
                     given ``path``.
            module_name: When set it indicates the module doing the collection, used for logging and
                         reporting. When not set the ``Collector``'s ``bound_module`` will be used.
            base: A different base path to use to store the file, it is prepended to the given or
                  generated ``outpath``.
            file_accessor:
        """
        module_name = self.bound_module_name or module_name
        if not module_name:
            raise ValueError("Module name must be provided or Collector needs to be bound to a module")

        if not isinstance(path, fsutil.TargetPath):
            path = fs.path(path)

        # As path is not unique on the target, collect_inpath is constructed to be unique a (but fake)
        # path. The actual file entry collected comes from path, collect_inpath is used for logging,
        # reporting and deduplication purposes. This needs to be set here to be able to log and
        # deduplicate in case exceptions are raised early on.
        collect_inpath = fsutil.join(mountpoint, path.as_posix().lstrip("/"))

        try:
            # As we don't collect any intermediate or end symlinks, the path needs to be fully
            # resolved.
            path = path.resolve()

            if self.filter(path):
                log.info("- Collecting path %s: Skipped (filtered out)", collect_inpath)
                return

            # In general normalization will not do much as the path is already fully resolved and
            # passed in posix form. Also files on non-root filesystems generally don't have any
            # drive path or driveletter part.
            collect_inpath = normalize_path(self.target, path.as_posix(), resolve_parents=False, preserve_case=True)
            if mountpoint:
                collect_inpath = fsutil.join(mountpoint, collect_inpath.lstrip("/"))

            if self.report.was_path_seen(collect_inpath):
                log.info("- Collecting path %s (%s on %s): Skipped (DEDUP)", collect_inpath, path, fs)
                return

            entry = path.get()

            if not path.is_file():
                log.error("- Failed to collect path %s (%s on %s): not a file", collect_inpath, path, fs)
                self.report.add_file_failed(module_name, collect_inpath)
                return

            log.info("- Collecting file %s (%s on %s)", collect_inpath, path, fs)

            collect_outpath = self._output_path(outpath or collect_inpath, base=base)

            fh = entry.open()

            if file_accessor is not None:
                fh, size = file_accessor(fh)
            else:
                size = fh.size

            self.output.write(
                collect_outpath,
                fh,
                entry,
                size=size,
            )
        except OSError as error:
            if error.errno == errno.ENOENT:
                self.report.add_file_missing(module_name, collect_inpath)
                log.error("- File %s (%s on %s) is not found", collect_inpath, path, fs)  # noqa: TRY400
            elif error.errno == errno.EACCES:
                self.report.add_file_failed(module_name, collect_inpath)
                log.error("- Permission denied while accessing file %s (%s on %s)", collect_inpath, path, fs)  # noqa: TRY400
            else:
                self.report.add_file_failed(module_name, collect_inpath)
                log.error("- OSError while collecting file %s (%s on %s)", collect_inpath, path, fs)  # noqa: TRY400
        except (FileNotFoundError, NotADirectoryError, NotASymlinkError, SymlinkRecursionError, ValueError):
            self.report.add_file_missing(module_name, collect_inpath)
            log.error("- File %s (%s on %s) not found", collect_inpath, path, fs)  # noqa: TRY400
        except Exception:
            self.report.add_file_failed(module_name, collect_inpath)
            log.exception("- Failed to collect file %s (%s on %s)", collect_inpath, path, fs)
        else:
            self.report.add_file_collected(module_name, collect_inpath)
            log.info("- Collecting file %s (%s on %s) succeeded", collect_inpath, path, fs)

    def collect_glob(self, pattern: str, module_name: str | None = None) -> None:
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
            log.exception("- Failed to collect glob %s", pattern)
            self.report.add_glob_failed(module_name, pattern)
        else:
            if glob_is_empty:
                self.report.add_glob_empty(module_name, pattern)
                log.error("- Failed to collect glob %s, it is empty", pattern)
            else:
                log.info("- Collecting glob %s succeeded", pattern)

    def collect_command_output(
        self,
        command_parts: list[str],
        output_filename: str,
        module_name: str | None = None,
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
            log.exception("- Failed to collect output from command `%s`", " ".join(command_parts))
            return
        log.info("- Collecting output from command `%s` succeeded", " ".join(command_parts))

    def write_bytes(self, destination_path: str, data: bytes) -> None:
        self.output.write_bytes(destination_path, data)
        self.report.add_file_collected(self.bound_module_name, destination_path)


def get_report_summary(report: CollectionReport) -> str:
    """Create a table-view report summary with success/failure/missing/empty counters per module"""

    record_counts = report.get_counts_per_module_per_outcome()

    if not record_counts:
        return ""

    module_name_max_len = max(len(module_name) for module_name in record_counts)
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
        for records_per_module_per_outcome in records_per_module.values():
            record_lines = [record_line_template.format(record=record) for record in records_per_module_per_outcome]

            paragraph = "\n".join(record_lines)
            paragraph = textwrap.indent(paragraph, prefix=record_indent * " ")

            blocks.append(paragraph)

    return "\n".join(blocks)
