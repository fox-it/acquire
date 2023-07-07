import errno
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from dissect.target import Target
from dissect.target.exceptions import (
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
    SymlinkRecursionError,
)
from dissect.target.filesystem import VirtualFilesystem

from acquire.collector import CollectionReport, Collector, Outcome


def test_collector() -> None:
    target = Target("local")

    with patch("acquire.collector.log", autospec=True) as mock_log:
        fs_1 = VirtualFilesystem()
        fs_1.map_file("$MFT", None)
        target.fs.mount("C:", fs_1)
        target.filesystems.add(fs_1)

        fs_2 = VirtualFilesystem()
        fs_2.map_file("$MFT", None)
        target.fs.mount("D:", fs_2)
        target.filesystems.add(fs_2)

        collector = Collector(target, Mock())

        collector.collect_dir("C:", module_name="test")
        collector.collect_dir("D:", module_name="test")

        assert not mock_log.info.call_args.args[0] == "- Collecting file %s: Skipped (DEDUP)"


@pytest.fixture
def mock_collector(mock_target) -> Collector:
    collector = Collector(mock_target, Mock())
    return collector


MOCK_SEEN_PATHS = set()
MOCK_MODULE_NAME = "DUMMY"


def test_collector_collect_path_no_module_name(mock_collector: Collector) -> None:
    with pytest.raises(ValueError):
        mock_collector.collect_path("/some/path")


def test_collector_collect_path_dir_as_target_path(mock_target: Target, mock_collector: Collector) -> None:
    with patch.object(mock_collector, "collect_dir", autospec=True):
        path = mock_target.fs.path("/foo/bar")
        mock_collector.collect_path(
            path,
            seen_paths=MOCK_SEEN_PATHS,
            module_name=MOCK_MODULE_NAME,
        )
        mock_collector.collect_dir.assert_called()


def test_collector_collect_path_dir(mock_collector: Collector) -> None:
    with patch.object(mock_collector, "collect_dir", autospec=True):
        mock_collector.collect_path(
            "/foo/bar",
            seen_paths=MOCK_SEEN_PATHS,
            module_name=MOCK_MODULE_NAME,
        )
        mock_collector.collect_dir.assert_called()


def test_collector_collect_path_file(mock_collector: Collector) -> None:
    with patch.object(mock_collector, "collect_file", autospec=True):
        mock_collector.collect_path(
            "/foo/bar/some-file",
            seen_paths=MOCK_SEEN_PATHS,
            module_name=MOCK_MODULE_NAME,
        )
        mock_collector.collect_file.assert_called()


def test_collector_collect_path_symlink(mock_collector: Collector) -> None:
    with patch.object(mock_collector, "collect_symlink", autospec=True), patch.object(
        mock_collector, "collect_file", autospec=True
    ):
        mock_collector.collect_path(
            "/foo/bar/some-symlink",
            follow=False,
            seen_paths=MOCK_SEEN_PATHS,
            module_name=MOCK_MODULE_NAME,
        )
        mock_collector.collect_symlink.assert_called()
        mock_collector.collect_file.assert_not_called()


def test_collector_collect_path_symlink_follow(mock_collector: Collector) -> None:
    with patch.object(mock_collector, "collect_symlink", autospec=True), patch.object(
        mock_collector, "collect_file", autospec=True
    ):
        mock_collector.collect_path(
            "/foo/bar/some-symlink",
            follow=True,
            seen_paths=MOCK_SEEN_PATHS,
            module_name=MOCK_MODULE_NAME,
        )
        mock_collector.collect_symlink.assert_called()
        mock_collector.collect_file.assert_called()


@pytest.mark.parametrize(
    "path, symlink_called, file_called",
    [
        (
            "/foo/bar/own-file",
            False,
            False,
        ),
        (
            "/foo/own-symlink",
            True,
            False,
        ),
        (
            "/foo/bar/some-file",
            False,
            True,
        ),
        (
            "/foo/bar/some-symlink",
            True,
            True,
        ),
    ],
)
def test_collector_collect_path_skip_list(
    mock_collector: Collector, path: str, symlink_called: bool, file_called: bool
) -> None:
    with (
        patch.object(mock_collector, "skip_list", new={"/foo/bar/own-file"}),
        patch.object(mock_collector, "collect_symlink", autospec=True),
        patch.object(mock_collector, "collect_file", autospec=True),
    ):
        mock_collector.collect_path(
            path,
            follow=True,
            seen_paths=MOCK_SEEN_PATHS,
            module_name=MOCK_MODULE_NAME,
        )
        if symlink_called:
            mock_collector.collect_symlink.assert_called()
        else:
            mock_collector.collect_symlink.assert_not_called()

        if file_called:
            mock_collector.collect_file.assert_called()
        else:
            mock_collector.collect_file.assert_not_called()


def test_collector_collect_glob(mock_collector: Collector) -> None:
    with patch.object(mock_collector, "collect_file", autospec=True), patch.object(
        mock_collector, "report", autospec=True
    ):
        mock_collector.collect_glob(
            "/foo/bar/*",
            module_name=MOCK_MODULE_NAME,
        )
        assert len(mock_collector.collect_file.mock_calls) == 3
        assert mock_collector.collect_file.call_args.kwargs.get("module_name", None) == MOCK_MODULE_NAME


def test_collector_collect_path_non_existing_file(mock_collector: Collector) -> None:
    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector, "report", autospec=True) as mock_report,
    ):
        mock_collector.collect_path(
            "/foo/bar/non-existing-file",
            seen_paths=MOCK_SEEN_PATHS,
            module_name=MOCK_MODULE_NAME,
        )
        mock_report.add_path_missing.assert_called()
        mock_log.error.assert_called()
        assert mock_log.error.call_args.args[0] == "- Path %s is not found"


def test_collector_collect_path_no_file_type(mock_target: Target, mock_collector: Collector) -> None:
    path = mock_target.fs.path("/foo/bar/non-existing-file")
    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector, "report", autospec=True) as mock_report,
        patch.multiple(
            path,
            get=MagicMock(return_value=True),
            is_dir=MagicMock(return_value=False),
            is_file=MagicMock(return_value=False),
            is_symlink=MagicMock(return_value=False),
        ),
    ):
        mock_collector.collect_path(
            path,
            seen_paths=MOCK_SEEN_PATHS,
            module_name=MOCK_MODULE_NAME,
        )
        mock_report.add_path_failed.assert_called()
        mock_log.error.assert_called()
        assert mock_log.error.call_args.args[0] == "- Don't know how to collect %s in module %s"


@pytest.mark.parametrize(
    "report_func, exception, log_msg",
    [
        (
            "add_path_missing",
            OSError(errno.ENOENT, "foo"),
            "- Path %s is not found",
        ),
        (
            "add_path_failed",
            OSError(errno.EACCES, "foo"),
            "- Permission denied while accessing path %s",
        ),
        (
            "add_path_failed",
            OSError(255, "foo"),
            "- OSError while collecting path %s",
        ),
        (
            "add_path_missing",
            FileNotFoundError,
            "- Path %s is not found",
        ),
        (
            "add_path_missing",
            NotADirectoryError,
            "- Path %s is not found",
        ),
        (
            "add_path_missing",
            NotASymlinkError,
            "- Path %s is not found",
        ),
        (
            "add_path_missing",
            SymlinkRecursionError,
            "- Path %s is not found",
        ),
        (
            "add_path_missing",
            ValueError,
            "- Path %s is not found",
        ),
        (
            "add_path_failed",
            Exception,
            "- Failed to collect path %s",
        ),
    ],
)
def test_collector_collect_path_with_exception(mock_target, mock_collector, report_func, exception, log_msg) -> None:
    path = mock_target.fs.path("/foo/bar/non-existing-file")
    with (
        patch("acquire.collector.log", autospec=True) as mock_log,
        patch.object(mock_collector, "report", autospec=True) as mock_report,
        patch.object(path, "get", side_effect=exception, autospec=True),
    ):
        mock_collector.collect_path(
            path,
            seen_paths=MOCK_SEEN_PATHS,
            module_name=MOCK_MODULE_NAME,
        )
        report_func = getattr(mock_report, report_func)
        report_func.assert_called()
        mock_log.error.assert_called()
        assert mock_log.error.call_args.args[0] == log_msg


def create_target_with_files(tmp_path: Path, paths: list[str]) -> Path:
    target = Target("local")

    fs = VirtualFilesystem()
    target.filesystems.add(fs)

    for path in paths:
        creation_path = tmp_path.joinpath(path)
        creation_path.parent.mkdir(parents=True, exist_ok=True)
        creation_path.touch()
    fs.map_dir("/", tmp_path)
    target.fs.mount("/", fs)

    return target


def collect_report(
    collector: Collector,
    function_name: str,
    collect_point: Path,
) -> CollectionReport:
    func = getattr(collector, f"collect_{function_name}")
    func(collect_point, module_name=MOCK_MODULE_NAME)

    return collector.report


@pytest.mark.parametrize(
    "function_name, collection_point, expected_results, create_paths",
    [
        (
            "dir",
            "collect",
            2,
            ["collect/this/file", "collect/this/test"],
        ),
        (
            "glob",
            "/collect/*/file",
            1,
            ["collect/this/file"],
        ),
        (
            "glob",
            "/collect/*/file",
            0,
            [],
        ),
        ("file", "collect/this/file", 1, ["collect/this/file"]),
    ],
)
def test_collector_report_succeeded(
    tmp_path: Path,
    mock_collector: Collector,
    function_name: str,
    collection_point: str,
    expected_results: int,
    create_paths: list[str],
):
    target = create_target_with_files(tmp_path, create_paths)
    mock_collector.target = target

    report = collect_report(mock_collector, function_name, collection_point)
    successful_outputs = list(value for value in report.registry if value.outcome == Outcome.SUCCESS)
    assert len(successful_outputs) == expected_results
