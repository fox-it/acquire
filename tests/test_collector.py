from __future__ import annotations

import errno
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from dissect.target.exceptions import (
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
    SymlinkRecursionError,
)
from dissect.target.helpers.fsutil import TargetPath

from acquire.collector import ArtifactType, CollectionReport, Collector

if TYPE_CHECKING:
    from dissect.target import Target


@pytest.fixture
def mock_collector(mock_target: Target) -> Collector:
    with patch("acquire.outputs.base.Output", autospec=True) as mock_output:
        return Collector(mock_target, mock_output)


MOCK_SEEN_PATHS = set()
MOCK_MODULE_NAME = "DUMMY"


@pytest.mark.parametrize(
    ("path_str", "expected"),
    [
        ("some/path", "/some/path"),
        ("/some/path", "/some/path"),
        ("some/path/", "/some/path/"),
    ],
)
def test_collection_report__uniq_path(mock_target: Target, path_str: str, expected: str) -> None:
    path = mock_target.fs.path(path_str)
    with patch("acquire.collector.normalize_path", return_value=path_str, autospec=True):
        test_report = CollectionReport(mock_target)

        assert test_report._uniq_path(path_str) == expected
        assert test_report._uniq_path(path) == expected


def test_collector_collect_no_module_name(mock_collector: Collector) -> None:
    with pytest.raises(ValueError, match="Module name must be provided or Collector needs to be bound to a module"):
        mock_collector.collect([[ArtifactType.PATH, "/some/path"]])


def test_collector_collect_invalid_artifact_type(mock_collector: Collector) -> None:
    with pytest.raises(ValueError, match="Unknown artifact type"):
        mock_collector.collect([["dummy_type", "/some/path"]], MOCK_MODULE_NAME)


def test_collector_collect_transform_func(mock_collector: Collector) -> None:
    mock_transform = MagicMock()
    with patch.object(mock_collector, "collect_path", autospec=True):
        mock_collector.collect([[ArtifactType.PATH, "/some/path", mock_transform]], MOCK_MODULE_NAME)

    assert mock_transform.call_args.args == (mock_collector.target, "/some/path")


@pytest.mark.parametrize(
    ("spec", "collect_func"),
    [
        ((ArtifactType.FILE, "/some/path"), "collect_path"),
        ((ArtifactType.DIR, "/some/path"), "collect_path"),
        ((ArtifactType.SYMLINK, "/some/path"), "collect_path"),
        ((ArtifactType.PATH, "/some/path"), "collect_path"),
        ((ArtifactType.GLOB, "/some/glob*"), "collect_glob"),
        ((ArtifactType.COMMAND, (["./some", "--command"], "output_file")), "collect_command_output"),
    ],
)
def test_collector_collect(
    mock_collector: Collector, spec: tuple[ArtifactType, str | tuple[list[str], str]], collect_func: str
) -> None:
    with (
        patch.object(mock_collector, "collect_path", autospec=True),
        patch.object(mock_collector, "collect_glob", autospec=True),
        patch.object(mock_collector, "collect_command_output", autospec=True),
    ):
        mock_collector.collect([spec], MOCK_MODULE_NAME)

        called_func = getattr(mock_collector, collect_func)

    if spec[0] == ArtifactType.COMMAND:
        assert called_func.call_args.args[0] == spec[1][0]
        assert called_func.call_args.args[1] == spec[1][1]
    else:
        assert called_func.call_args.args[0] == spec[1]

    assert called_func.call_args.kwargs["module_name"] == MOCK_MODULE_NAME


@pytest.mark.parametrize(
    ("path_str", "base", "expected"),
    [
        ("/some/path", None, "fs/some/path"),
        ("some/path", None, "fs/some/path"),
        ("/some/path/", None, "fs/some/path/"),
        ("/some/path", "/bar/", "bar/some/path"),
        ("some/path", "/bar/", "bar/some/path"),
        ("/some/path/", "/bar/", "bar/some/path/"),
    ],
)
def test_collector__output_path(
    mock_target: Target,
    mock_collector: Collector,
    path_str: str,
    base: str | None,
    expected: str,
) -> None:
    path = mock_target.fs.path(path_str)

    with patch("acquire.collector.normalize_path", return_value=path_str, autospec=True):
        assert mock_collector._output_path(path_str, base=base) == expected
        assert mock_collector._output_path(path, base=base) == expected


def test_collector__get_symlink_branches(mock_target: Target, mock_collector: Collector) -> None:
    path = mock_target.fs.path("/symlink/dir1/some-dir/some-file")
    path, branches = mock_collector._get_symlink_branches(path)

    assert path == mock_target.fs.path("/symlink/dir3/some-dir/some-file")
    assert branches == [
        mock_target.fs.path("/symlink/dir1"),
        mock_target.fs.path("/symlink/dir2/some-dir"),
    ]


def test_collector_collect_path_no_module_name(mock_collector: Collector) -> None:
    with pytest.raises(ValueError, match="Module name must be provided or Collector needs to be bound to a module"):
        mock_collector.collect_path("/some/path")


@pytest.mark.parametrize(
    ("outpath", "base", "volatile", "as_targetpath"),
    [
        (None, None, False, True),
        (None, None, False, False),
        (None, None, True, True),
        ("/some/other/path", None, False, True),
        ("/some/other/path", "/my/base", False, True),
        ("/some/other/path", None, True, True),
        ("/some/other/path", "/my/base", True, True),
    ],
)
def test_collector_collect_path_with_file(
    mock_target: Target,
    mock_collector: Collector,
    outpath: str,
    base: str,
    volatile: bool,
    as_targetpath: bool,
) -> None:
    # We use a path that does not need to be modified by the normalize_path()
    # function, so we can easily use it to check if it was properly used in the
    # writer function call.
    path_str = "/foo/bar/some-file"
    path = mock_target.fs.path(path_str)
    collect_path = path if as_targetpath else path_str
    writer = {
        False: "write_entry",
        True: "write_volatile",
    }

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector.report, "add_file_collected", autospec=True) as mock_report,
    ):
        mock_collector.collect_path(
            collect_path,
            outpath=outpath,
            module_name=MOCK_MODULE_NAME,
            base=base,
            volatile=volatile,
        )

        outpath = mock_collector._output_path(outpath or path, base=base)
        writer_func = getattr(mock_collector.output, writer.get(volatile))

        writer_func.assert_called_once()
        assert writer_func.call_args.args[0] == outpath

        assert mock_report.call_args.args == (MOCK_MODULE_NAME, path)

        info_log_call_args = {call_args.args for call_args in mock_log.info.call_args_list}
        call_args = ("- Collecting file %s succeeded", path)
        assert call_args in info_log_call_args

        assert mock_log.debug.call_args.args == ("- Collecting path %s succeeded", path)


def test_collector_collect_path_early_dedup(mock_target: Target, mock_collector: Collector) -> None:
    path_str = "/foo/bar/some-file"
    path = mock_target.fs.path(path_str)

    with patch("acquire.collector.log", autospec=True) as mock_log:
        mock_collector.collect_path(path, module_name=MOCK_MODULE_NAME)
        mock_collector.collect_path(path, module_name=MOCK_MODULE_NAME)

        mock_collector.output.write_entry.assert_called_once()
        mock_collector.output.write_volatile.assert_not_called()

        assert mock_log.info.call_args.args == ("- Collecting path %s: Skipped (DEDUP)", path)


def test_collector_collect_path_early_dedup_mocked(mock_target: Target, mock_collector: Collector) -> None:
    path_str = "/foo/bar/some-file"
    path = mock_target.fs.path(path_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector.report, "was_path_seen", autospec=True, return_value=True),
    ):
        mock_collector.collect_path(path, module_name=MOCK_MODULE_NAME)

        mock_collector.output.write_entry.assert_not_called()
        mock_collector.output.write_volatile.assert_not_called()

        assert mock_log.info.call_args.args == ("- Collecting path %s: Skipped (DEDUP)", path)


def test_collector_collect_path_in_seen_paths(mock_target: Target, mock_collector: Collector) -> None:
    path_str = "/foo/bar/some-file"
    path = mock_target.fs.path(path_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector.report, "add_path_failed", autospec=True) as mock_report,
    ):
        mock_collector.collect_path(path, module_name=MOCK_MODULE_NAME, seen_paths={path_str})

        mock_collector.output.write_entry.assert_not_called()
        mock_collector.output.write_volatile.assert_not_called()

        assert mock_report.call_args.args == (MOCK_MODULE_NAME, path)

        assert mock_log.error.call_args.args == ("- Skipping collection of %s, breaking out of symlink loop", path)


def test_collector_collect_path_in_skiplist(mock_target: Target, mock_collector: Collector) -> None:
    path_str = "/foo/bar/some-file"
    path = mock_target.fs.path(path_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector.report, "add_path_failed", autospec=True) as mock_report,
        patch.object(mock_collector, "skip_list", new=[path_str]),
    ):
        mock_collector.collect_path(path, module_name=MOCK_MODULE_NAME)

        mock_collector.output.write_entry.assert_not_called()
        mock_collector.output.write_volatile.assert_not_called()

        assert mock_report.call_args.args == (MOCK_MODULE_NAME, path)

        assert mock_log.info.call_args.args == ("- Skipping collection of %s, path is on the skip list", path)


def test_collector_collect_path_with_filter(mock_target: Target, mock_collector: Collector) -> None:
    path_str = "/foo/bar/some-file"
    path = mock_target.fs.path(path_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector, "filter", return_value=True, autospec=True),
    ):
        mock_collector.collect_path(path, module_name=MOCK_MODULE_NAME)

        mock_collector.output.write_entry.assert_not_called()
        mock_collector.output.write_volatile.assert_not_called()

        assert mock_log.info.call_args.args == ("- Collecting path %s: Skipped (filtered out)", path)


def test_collector_collect_path_unknown_type(mock_target: Target, mock_collector: Collector) -> None:
    path_str = "/foo/bar/non-existing-file"
    path = mock_target.fs.path(path_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector, "report") as mock_report,
        patch.object(mock_collector.report, "was_path_seen", return_value=False),
        patch("acquire.collector.normalize_path", return_value=path_str, autospec=True),
        patch.multiple(
            TargetPath,
            get=MagicMock(return_value=True),
            is_dir=MagicMock(return_value=False),
            is_file=MagicMock(return_value=False),
            is_symlink=MagicMock(return_value=False),
        ),
    ):
        mock_collector.collect_path(path, module_name=MOCK_MODULE_NAME)

        mock_collector.output.write_entry.assert_not_called()
        mock_collector.output.write_volatile.assert_not_called()

        assert mock_report.add_path_failed.call_args.args == (MOCK_MODULE_NAME, path)

        assert mock_log.error.call_args.args == ("- Don't know how to collect %s in module %s", path, MOCK_MODULE_NAME)


def test_collector_collect_path_with_symlink_branches(mock_target: Target, mock_collector: Collector) -> None:
    path_str = "/symlink/dir1/some-dir/some-file"
    path = mock_target.fs.path(path_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector.report, "add_file_collected", autospec=True) as mock_file_report,
        patch.object(mock_collector.report, "add_symlink_collected", autospec=True) as mock_symlink_report,
    ):
        mock_collector.collect_path(path, module_name=MOCK_MODULE_NAME)

        collect_paths = [
            mock_target.fs.path("/symlink/dir3/some-dir/some-file"),
            mock_target.fs.path("/symlink/dir1"),
            mock_target.fs.path("/symlink/dir2/some-dir"),
        ]

        assert mock_collector.output.write_entry.call_count == 3
        for num, collect_path in enumerate(collect_paths):
            outpath = mock_collector._output_path(collect_path)
            assert mock_collector.output.write_entry.call_args_list[num].args[0] == outpath

        assert mock_file_report.call_args.args == (MOCK_MODULE_NAME, collect_paths[0])

        info_log_call_args = {call_args.args for call_args in mock_log.info.call_args_list}
        call_args = ("- Collecting file %s succeeded", collect_paths[0])
        assert call_args in info_log_call_args

        for num, collect_path in enumerate(collect_paths[1:]):
            assert mock_symlink_report.call_args_list[num].args == (MOCK_MODULE_NAME, collect_path)

            call_args = ("- Collecting symlink branch suceeded %s", collect_path)
            assert call_args in info_log_call_args

        assert mock_log.debug.call_args.args == ("- Collecting path %s succeeded", path)


def test_collector_collect_path_with_symlink_branches_and_outpath(
    mock_target: Target,
    mock_collector: Collector,
) -> None:
    # When a path is collected with an explicit outpath, no symlink branches should be collected.
    path_str = "/symlink/dir1/some-dir/some-file"
    path = mock_target.fs.path(path_str)
    outpath_str = "/some/other/path"
    outpath = mock_collector._output_path(outpath_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector.report, "add_file_collected", autospec=True) as mock_file_report,
        patch.object(mock_collector.report, "add_symlink_collected", autospec=True) as mock_symlink_report,
    ):
        mock_collector.collect_path(path, module_name=MOCK_MODULE_NAME, outpath=outpath_str)

        mock_collector.output.write_entry.assert_called_once()
        assert mock_collector.output.write_entry.call_args.args[0] == outpath

        mock_file_report.assert_called_once()
        collect_path = mock_target.fs.path("/symlink/dir3/some-dir/some-file")
        assert mock_file_report.call_args.args == (MOCK_MODULE_NAME, collect_path)

        mock_symlink_report.assert_not_called()

        info_log_call_args = {call_args.args for call_args in mock_log.info.call_args_list}
        call_args = ("- Collecting file %s succeeded", collect_path)
        assert call_args in info_log_call_args

        assert mock_log.debug.call_args.args == ("- Collecting path %s succeeded", path)


def test_collector_collect_path_late_dedup_mocked(mock_target: Target, mock_collector: Collector) -> None:
    symlink_path_str = "/symlink/dir2/some-dir"
    symlink_path = mock_target.fs.path(symlink_path_str)
    collect_path = symlink_path / "some-file"
    final_path_str = "/symlink/dir3/some-dir/some-file"
    final_path = mock_target.fs.path(final_path_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector.report, "add_file_collected", autospec=True) as mock_file_report,
        patch.object(mock_collector.report, "add_symlink_collected", autospec=True) as mock_symlink_report,
        patch.object(mock_collector.report, "seen_paths", new={final_path_str}),
    ):
        mock_collector.collect_path(collect_path, module_name=MOCK_MODULE_NAME)

        outpath = mock_collector._output_path(symlink_path)
        mock_collector.output.write_entry.assert_called_once()
        assert mock_collector.output.write_entry.call_args.args[0] == outpath

        mock_file_report.assert_not_called()
        assert mock_symlink_report.call_args.args == (MOCK_MODULE_NAME, symlink_path)

        info_log_call_args = {call_args.args for call_args in mock_log.info.call_args_list}
        call_args = ("- Collecting path %s: Skipped (DEDUP)", final_path)
        assert call_args in info_log_call_args


def test_collector_collect_path_dedup_symlink_branch(mock_target: Target, mock_collector: Collector) -> None:
    symlink_path_str = "/symlink/dir2/some-dir"
    symlink_path = mock_target.fs.path(symlink_path_str)
    collect_path = symlink_path / "some-file"
    final_path_str = "/symlink/dir3/some-dir/some-file"
    final_path = mock_target.fs.path(final_path_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector.report, "add_file_collected", autospec=True) as mock_file_report,
        patch.object(mock_collector.report, "add_symlink_collected", autospec=True) as mock_symlink_report,
        patch.object(mock_collector.report, "seen_paths", new={symlink_path_str}),
    ):
        mock_collector.collect_path(collect_path, module_name=MOCK_MODULE_NAME)

        outpath = mock_collector._output_path(final_path)
        mock_collector.output.write_entry.assert_called_once()
        assert mock_collector.output.write_entry.call_args.args[0] == outpath

        mock_symlink_report.assert_not_called()
        assert mock_file_report.call_args.args == (MOCK_MODULE_NAME, final_path)

        info_log_call_args = {call_args.args for call_args in mock_log.info.call_args_list}
        call_args = ("- Collecting symlink branch path %s: Skipped (DEDUP)", symlink_path)
        assert call_args in info_log_call_args

        assert mock_log.debug.call_args.args == ("- Collecting path %s succeeded", collect_path)


@pytest.mark.parametrize(
    ("report_func", "exception", "log_msg"),
    [
        (
            "add_path_missing",
            OSError(errno.ENOENT, "foo"),
            "- Path %s is not found (while collecting %s)",
        ),
        (
            "add_path_failed",
            OSError(errno.EACCES, "foo"),
            "- Permission denied while accessing path %s (while collecting %s)",
        ),
        (
            "add_path_failed",
            OSError(255, "foo"),
            "- OSError while collecting path %s (while collecting %s)",
        ),
        (
            "add_path_missing",
            FileNotFoundError,
            "- Path %s is not found (while collecting %s)",
        ),
        (
            "add_path_missing",
            NotADirectoryError,
            "- Path %s is not found (while collecting %s)",
        ),
        (
            "add_path_missing",
            NotASymlinkError,
            "- Path %s is not found (while collecting %s)",
        ),
        (
            "add_path_missing",
            SymlinkRecursionError,
            "- Path %s is not found (while collecting %s)",
        ),
        (
            "add_path_missing",
            ValueError,
            "- Path %s is not found (while collecting %s)",
        ),
        (
            "add_path_failed",
            Exception,
            "- Failed to collect path %s (while collecting %s)",
        ),
    ],
)
def test_collector_collect_path_with_exception(
    mock_target: Target, mock_collector: Collector, report_func: str, exception: type[Exception], log_msg: str
) -> None:
    path_str = "/foo/bar/non-existing-file"
    path = mock_target.fs.path(path_str)
    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector, "report") as mock_report,
        patch.object(mock_collector.report, "was_path_seen", return_value=False),
        patch("acquire.collector.normalize_path", return_value=path_str, autospec=True),
        patch.object(TargetPath, "get", side_effect=exception, autospec=True),
    ):
        mock_collector.collect_path(path, module_name=MOCK_MODULE_NAME)

        mock_collector.output.write_entry.assert_not_called()
        mock_collector.output.write_volatile.assert_not_called()

        report_func = getattr(mock_report, report_func)
        assert report_func.call_args.args == (MOCK_MODULE_NAME, path)

        mock_log.error.assert_called_once()
        assert mock_log.error.call_args.args == (log_msg, path, path)


def test_collector_collect_path_with_dir(mock_target: Target, mock_collector: Collector) -> None:
    path_str = "/foo/bar/"
    path = mock_target.fs.path(path_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector.report, "add_file_collected", autospec=True) as mock_file_report,
        patch.object(mock_collector.report, "add_symlink_collected", autospec=True) as mock_symlink_report,
    ):
        mock_collector.collect_path(path, module_name=MOCK_MODULE_NAME, seen_paths={path_str})

        collect_paths = [
            mock_target.fs.path("/foo/bar/some-file"),
            mock_target.fs.path("/foo/bar/own-file"),
            mock_target.fs.path("/foo/bar/some-symlink"),
        ]

        assert mock_collector.output.write_entry.call_count == 3
        write_call_args = {call.args[0] for call in mock_collector.output.write_entry.call_args_list}
        for collect_path in collect_paths:
            outpath = mock_collector._output_path(collect_path)
            assert outpath in write_call_args

        file_report_call_args = {call.args for call in mock_file_report.call_args_list}
        info_log_call_args = {call_args.args for call_args in mock_log.info.call_args_list}
        error_log_calls = {call_args.args for call_args in mock_log.error.call_args_list}

        for collect_path in collect_paths[:2]:
            assert (MOCK_MODULE_NAME, collect_path) in file_report_call_args

            call_args = ("- Collecting file %s succeeded", collect_path)
            assert call_args in info_log_call_args

        assert mock_symlink_report.call_args.args == (MOCK_MODULE_NAME, collect_paths[2])

        assert ("- Collecting symlink %s succeeded", collect_paths[2]) in info_log_call_args

        # There is 1 empty subdirectory, but it should be silently skipped
        empty_dir = mock_target.fs.path("/foo/bar/some-dir")
        assert ("- Failed to collect directory %s, it is empty", empty_dir) not in error_log_calls

        assert mock_log.debug.call_args.args == ("- Collecting path %s succeeded", path)


def test_collector_collect_path_with_empty_dir(mock_target: Target, mock_collector: Collector) -> None:
    path_str = "/foo/bar/some-dir/"
    path = mock_target.fs.path(path_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector.report, "add_dir_failed", autospec=True) as mock_report,
    ):
        mock_collector.collect_path(path, module_name=MOCK_MODULE_NAME)

        mock_collector.output.write_entry.assert_not_called()
        mock_collector.output.write_volatile.assert_not_called()

        assert mock_report.call_args.args == (MOCK_MODULE_NAME, path)

        assert mock_log.error.call_args.args == ("- Failed to collect directory %s, it is empty", path)


def test_collector_collect_path_with_empty_dir_volatile(mock_target: Target, mock_collector: Collector) -> None:
    path_str = "/foo/bar/some-dir/"
    path = mock_target.fs.path(path_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector.report, "add_dir_collected", autospec=True) as mock_report,
    ):
        mock_collector.collect_path(path, module_name=MOCK_MODULE_NAME, volatile=True)

        outpath = mock_collector._output_path(path)
        mock_collector.output.write_entry.assert_called_once()
        assert mock_collector.output.write_entry.call_args.args[0] == outpath

        assert mock_report.call_args.args == (MOCK_MODULE_NAME, path)

        info_log_call_args = {call_args.args for call_args in mock_log.info.call_args_list}
        call_args = ("- Collecting EMPTY directory %s succeeded", path)
        assert call_args in info_log_call_args

        assert mock_log.debug.call_args.args == ("- Collecting path %s succeeded", path)


def test_collector_collect_path_with_symlink(
    mock_target: Target,
    mock_collector: Collector,
) -> None:
    symlink_path_str = "/foo/bar/some-symlink"
    symlink_path = mock_target.fs.path(symlink_path_str)
    final_path_str = "/foo/bar/some-file"
    final_path = mock_target.fs.path(final_path_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector.report, "add_file_collected", autospec=True) as mock_file_report,
        patch.object(mock_collector.report, "add_symlink_collected", autospec=True) as mock_symlink_report,
    ):
        mock_collector.collect_path(symlink_path, module_name=MOCK_MODULE_NAME)

        assert mock_collector.output.write_entry.call_count == 2
        write_call_args = {call.args[0] for call in mock_collector.output.write_entry.call_args_list}
        for collect_path in [symlink_path, final_path]:
            outpath = mock_collector._output_path(collect_path)
            assert outpath in write_call_args

        assert mock_symlink_report.call_args.args == (MOCK_MODULE_NAME, symlink_path)
        assert mock_file_report.call_args.args == (MOCK_MODULE_NAME, final_path)

        info_log_call_args = {call_args.args for call_args in mock_log.info.call_args_list}
        symlink_call_args = ("- Collecting symlink %s succeeded", symlink_path)
        file_call_args = ("- Collecting file %s succeeded", final_path)

        assert symlink_call_args in info_log_call_args
        assert file_call_args in info_log_call_args

        assert mock_log.debug.call_args.args == ("- Collecting path %s succeeded", symlink_path)


def test_collector_collect_path_with_symlink_volatile(
    mock_target: Target,
    mock_collector: Collector,
) -> None:
    symlink_path_str = "/foo/bar/some-symlink"
    symlink_path = mock_target.fs.path(symlink_path_str)

    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector.report, "add_file_collected", autospec=True) as mock_file_report,
        patch.object(mock_collector.report, "add_symlink_collected", autospec=True) as mock_symlink_report,
    ):
        mock_collector.collect_path(symlink_path, module_name=MOCK_MODULE_NAME, volatile=True)

        assert mock_collector.output.write_entry.call_count == 1
        outpath = mock_collector._output_path(symlink_path)
        assert mock_collector.output.write_entry.call_args.args[0] == outpath

        assert mock_symlink_report.call_args.args == (MOCK_MODULE_NAME, symlink_path)
        mock_file_report.assert_not_called()

        info_log_call_args = {call_args.args for call_args in mock_log.info.call_args_list}
        symlink_call_args = ("- Collecting symlink %s succeeded", symlink_path)
        assert symlink_call_args in info_log_call_args

        assert mock_log.debug.call_args.args == ("- Collecting path %s succeeded", symlink_path)


def test_collector_collect_glob(mock_collector: Collector) -> None:
    with (
        patch.object(mock_collector, "collect_path", autospec=True),
        patch.object(mock_collector, "report"),
    ):
        mock_collector.collect_glob("/foo/bar/*", module_name=MOCK_MODULE_NAME)

        assert mock_collector.collect_path.call_count == 4
        assert mock_collector.collect_path.call_args.kwargs.get("module_name", None) == MOCK_MODULE_NAME
