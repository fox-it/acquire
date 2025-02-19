from __future__ import annotations

import io
from pathlib import Path
from typing import BinaryIO

import pytest
from dissect.target import Target
from dissect.target.filesystem import VirtualFile, VirtualFilesystem, VirtualSymlink


@pytest.fixture
def mock_file() -> BinaryIO:
    return io.BytesIO(b"Mock File")


@pytest.fixture
def mock_fs(mock_file: BinaryIO) -> VirtualFilesystem:
    fs = VirtualFilesystem(case_sensitive=False)
    fs.makedirs("/foo/bar/some-dir")
    fs.map_file_entry("/foo/bar/some-file", VirtualFile(fs, "some-file", mock_file))
    fs.map_file_entry("/foo/bar/own-file", VirtualFile(fs, "own-file", mock_file))
    fs.map_file_entry("/foo/bar/some-symlink", VirtualSymlink(fs, "some-symlink", "/foo/bar/some-file"))
    fs.map_file_entry("/foo/own-symlink", VirtualSymlink(fs, "own-symlink", "/foo/bar/own-file"))

    fs.map_file_entry("/symlink/dir1", VirtualSymlink(fs, "dir1", "/symlink/dir2"))
    fs.map_file_entry("/symlink/dir2/some-dir", VirtualSymlink(fs, "some-dir", "/symlink/dir3/some-dir"))
    fs.map_file_entry("/symlink/dir3/some-dir/some-file", VirtualFile(fs, "some-file", mock_file))
    return fs


@pytest.fixture
def mock_target(mock_fs: VirtualFilesystem) -> Target:
    target = Target()
    target.fs.mount("/", mock_fs)
    target.filesystems.add(mock_fs)
    target.os = "mock"
    return target


@pytest.fixture
def public_key() -> str:
    return Path("tests/_data/public_key.pem").read_text()
