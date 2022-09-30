import errno
from unittest.mock import Mock, patch

import pytest
from dissect.target import Target
from dissect.target.exceptions import (
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
    SymlinkRecursionError,
)
from dissect.target.filesystem import VirtualFile, VirtualFilesystem, VirtualSymlink

from acquire.collector import Collector


def test_collector():
    target = Target("local")

    fs_1 = VirtualFilesystem()
    fs_1.map_file("$MFT", None)
    target.fs.mount("C:", fs_1)
    target.filesystems.add(fs_1)

    fs_2 = VirtualFilesystem()
    fs_2.map_file("$MFT", None)
    target.fs.mount("D:", fs_2)
    target.filesystems.add(fs_2)

    collector = Collector(target, Mock())
    collector.collect_file("$MFT", module_name="test")

    assert not collector.report.was_path_seen(fs_2.get("$MFT"))


@pytest.fixture
def mock_file():
    return Mock()


@pytest.fixture
def mock_fs(mock_file):
    fs = VirtualFilesystem(case_sensitive=False)
    fs.makedirs("/foo/bar")
    fs.map_file_entry("/foo/bar/some-file", VirtualFile(fs, "some-file", mock_file))
    fs.map_file_entry("/foo/bar/some-symlink", VirtualSymlink(fs, "some-symlink", "/foo/bar/some_file"))
    return fs


@pytest.fixture
def mock_target(mock_fs):
    target = Target()
    target.fs.mount("/", mock_fs)
    target.filesystems.add(mock_fs)
    return target


@pytest.fixture
def mock_collector(mock_target):
    collector = Collector(mock_target, Mock())
    return collector


MOCK_SEEN_PATHS = set()
MOCK_MODULE_NAME = "DUMMY"


def test_collector_collect_path_no_module_name(mock_collector):
    with pytest.raises(ValueError):
        mock_collector.collect_path("/some/path")


def test_collector_collect_path_dir_as_target_path(mock_target, mock_collector):
    with patch.object(mock_collector, "collect_dir", autospec=True):
        path = mock_target.fs.path("/foo/bar")
        mock_collector.collect_path(
            path,
            seen_paths=MOCK_SEEN_PATHS,
            module_name=MOCK_MODULE_NAME,
        )
        mock_collector.collect_dir.assert_called()


def test_collector_collect_path_dir(mock_collector):
    with patch.object(mock_collector, "collect_dir", autospec=True):
        mock_collector.collect_path(
            "/foo/bar",
            seen_paths=MOCK_SEEN_PATHS,
            module_name=MOCK_MODULE_NAME,
        )
        mock_collector.collect_dir.assert_called()


def test_collector_collect_path_file(mock_collector):
    with patch.object(mock_collector, "collect_file", autospec=True):
        mock_collector.collect_path(
            "/foo/bar/some-file",
            seen_paths=MOCK_SEEN_PATHS,
            module_name=MOCK_MODULE_NAME,
        )
        mock_collector.collect_file.assert_called()


def test_collector_collect_path_symlink(mock_collector):
    with patch("acquire.collector.log") as mock_log:
        with patch.object(mock_collector, "report", autospec=True) as mock_report:
            mock_collector.collect_path(
                "/foo/bar/some-symlink",
                seen_paths=MOCK_SEEN_PATHS,
                module_name=MOCK_MODULE_NAME,
            )
            mock_report.add_path_failed.assert_called()
            mock_log.error.assert_called()
            assert mock_log.error.call_args.args[0] == "- Can't collect %s (symlink to %s) in module %s"


def test_collector_collect_path_non_existing_file(mock_collector):
    with patch("acquire.collector.log", autospec=True) as mock_log:
        with patch.object(mock_collector, "report", autospec=True) as mock_report:
            mock_collector.collect_path(
                "/foo/bar/non-existing-file",
                seen_paths=MOCK_SEEN_PATHS,
                module_name=MOCK_MODULE_NAME,
            )
            mock_report.add_path_missing.assert_called()
            mock_log.error.assert_called()
            assert mock_log.error.call_args.args[0] == "- Path %s is not found"


def test_collector_collect_path_no_file_type(mock_target, mock_collector):
    path = mock_target.fs.path("/foo/bar/non-existing-file")
    with patch("acquire.collector.log", autospec=True) as mock_log:
        with patch.object(mock_collector, "report", autospec=True) as mock_report:
            with patch.object(path, "get", return_value=True, autospec=True):
                with patch.object(path, "is_dir", return_value=False, autospec=True):
                    with patch.object(path, "is_file", return_value=False, autospec=True):
                        with patch.object(path, "is_symlink", return_value=False, autospec=True):
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
def test_collector_collect_path_with_exception(mock_target, mock_collector, report_func, exception, log_msg):
    path = mock_target.fs.path("/foo/bar/non-existing-file")
    with patch("acquire.collector.log", autospec=True) as mock_log:
        with patch.object(mock_collector, "report", autospec=True) as mock_report:
            with patch.object(path, "get", side_effect=exception, autospec=True):
                mock_collector.collect_path(
                    path,
                    seen_paths=MOCK_SEEN_PATHS,
                    module_name=MOCK_MODULE_NAME,
                )
                report_func = getattr(mock_report, report_func)
                report_func.assert_called()
                mock_log.error.assert_called()
                assert mock_log.error.call_args.args[0] == log_msg
