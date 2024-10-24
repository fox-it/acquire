import tarfile
from pathlib import Path

import pytest
from dissect.target.filesystem import VirtualFilesystem

from acquire.outputs import TarOutput
from acquire.tools.decrypter import EncryptedFile


@pytest.fixture(params=[(True, "gzip"), (True, "bzip2"), (True, "xz"), (False, None)])
def tar_output(tmp_path: Path, request: pytest.FixtureRequest) -> TarOutput:
    compress, compression_method = request.param
    return TarOutput(tmp_path, compress=compress, compression_method=compression_method)


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

    assert tar_output.path.suffix == f".{tar_output.compression}" if tar_output.compression else ".tar"
    assert len(files) == 1

    file = files[0]
    assert file.path == entry_name

    if entry.is_dir():
        assert file.isdir()
    elif entry.is_symlink():
        assert file.issym()
    elif entry.is_file():
        assert file.isfile()


def test_tar_output_encrypt(mock_fs: VirtualFilesystem, public_key: bytes, tmp_path: Path) -> None:
    entry_name = "/foo/bar/some-file"
    entry = mock_fs.get(entry_name)
    tar_output = TarOutput(tmp_path, compress=True, compression_method="gzip", encrypt=True, public_key=public_key)
    tar_output.write_entry(entry_name, entry)
    tar_output.close()

    encrypted_stream = EncryptedFile(tar_output.path.open("rb"), Path("tests/data/private_key.pem"))
    decrypted_path = tmp_path / "decrypted.tar"
    # Direct streaming is not an option because tarfile needs seek when reading from encrypted files directly
    with open(decrypted_path, "wb") as f:
        f.write(encrypted_stream.read())

    tar_file = tarfile.open(name=decrypted_path, mode="r")
    assert entry.open().read() == tar_file.extractfile(entry_name).read()
