import tarfile
from pathlib import Path

import pytest
from dissect.target.filesystem import VirtualFilesystem

from acquire.outputs import TarOutput


@pytest.fixture
def tar_output(tmp_path: Path) -> TarOutput:
    return TarOutput(tmp_path)


@pytest.mark.parametrize(
    "entry_name",
    [
        "/foo/bar/some-file",
        "/foo/bar/some-symlink",
        "/foo/bar/some-dir",
    ],
)
def test_tar_output_write_entry(mock_fs: VirtualFilesystem, tar_output: TarOutput, entry_name: str) -> None:
    entry = mock_fs.get(entry_name)
    tar_output.write_entry(entry_name, entry)
    tar_output.close()

    tar_file = tarfile.open(tar_output.path)
    files = tar_file.getmembers()

    assert len(files) == 1

    file = files[0]
    assert file.path == entry_name

    if entry.is_dir():
        assert file.isdir()
    elif entry.is_symlink():
        assert file.issym()
    elif entry.is_file():
        assert file.isfile()
