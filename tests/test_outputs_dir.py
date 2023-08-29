from pathlib import Path

import pytest
from dissect.target.filesystem import VirtualFilesystem

from acquire.outputs import DirectoryOutput


@pytest.fixture
def dir_output(tmp_path: Path) -> DirectoryOutput:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return DirectoryOutput(tmp_path)


def leaves(path: Path) -> list[Path]:
    leave_paths = []

    dir_is_empty = True
    for path in path.iterdir():
        dir_is_empty = False
        if path.is_dir():
            leave_paths.extend(leaves(path))
        else:
            leave_paths.append(path)

    if dir_is_empty:
        leave_paths.append(path)

    return leave_paths


@pytest.mark.parametrize(
    "entry_name",
    [
        "/foo/bar/some-file",
        "/foo/bar/some-symlink",
        "/foo/bar/some-dir",
    ],
)
def test_dir_output_write_entry(mock_fs: VirtualFilesystem, dir_output: DirectoryOutput, entry_name: str) -> None:
    entry = mock_fs.get(entry_name)
    dir_output.write_entry(entry_name, entry)
    dir_output.close()

    path = dir_output.path
    files = leaves(path)

    assert len(files) == 1

    file = files[0]
    assert str(file)[len(str(path)) :] == entry_name

    if entry.is_dir():
        assert file.is_dir()
    elif entry.is_symlink():
        assert file.is_file()
    elif entry.is_file():
        assert file.is_file()
