from unittest.mock import Mock

import pytest
from dissect.target import Target
from dissect.target.filesystem import VirtualFile, VirtualFilesystem, VirtualSymlink


@pytest.fixture
def mock_file() -> Mock:
    return Mock()


@pytest.fixture
def mock_fs(mock_file) -> VirtualFilesystem:
    fs = VirtualFilesystem(case_sensitive=False)
    fs.makedirs("/foo/bar")
    fs.map_file_entry("/foo/bar/some-file", VirtualFile(fs, "some-file", mock_file))
    fs.map_file_entry("/foo/bar/own-file", VirtualFile(fs, "own-file", mock_file))
    fs.map_file_entry("/foo/bar/some-symlink", VirtualSymlink(fs, "some-symlink", "/foo/bar/some-file"))
    fs.map_file_entry("/foo/own-symlink", VirtualSymlink(fs, "own-symlink", "/foo/bar/own-file"))
    return fs


@pytest.fixture
def mock_target(mock_fs) -> Target:
    target = Target()
    target.fs.mount("/", mock_fs)
    target.filesystems.add(mock_fs)
    target.os = "mock"
    return target
