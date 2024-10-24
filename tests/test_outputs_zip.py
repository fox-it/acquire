import stat
import zipfile
from pathlib import Path

import pytest
from dissect.target.filesystem import VirtualFilesystem

from acquire.outputs import ZipOutput
from acquire.tools.decrypter import EncryptedFile


@pytest.fixture(params=[(True, "deflate"), (True, "bzip2"), (True, "lzma"), (False, None)])
def zip_output(tmp_path: Path, request: pytest.FixtureRequest) -> ZipOutput:
    compress, compression_method = request.param
    return ZipOutput(tmp_path, compress=compress, compression_method=compression_method)


@pytest.mark.parametrize(
    "entry_name",
    [
        "/foo/bar/some-file",
        "/foo/bar/some-symlink",
        "/foo/bar/some-dir",
    ],
)
def test_zip_output_write_entry(mock_fs: VirtualFilesystem, zip_output: ZipOutput, entry_name: str) -> None:
    entry = mock_fs.get(entry_name)

    assert zip_output.compression == zip_output.archive.compression
    zip_output.write_entry(entry_name, entry)
    zip_output.close()

    zip_file = zipfile.ZipFile(zip_output.path, mode="r")
    files = zip_file.filelist
    assert len(files) == 1

    file = files[0]
    assert file.filename == entry_name

    file_type = file.external_attr >> 16

    # zipfile only supports is_dir(). we have all the information we need to determine the file type in 'external_attr'
    if entry.is_dir():
        assert stat.S_ISDIR(file_type)
    elif entry.is_symlink():
        assert stat.S_ISLNK(file_type)
    elif entry.is_file():
        assert stat.S_ISREG(file_type)


def test_zip_output_encrypt(mock_fs: VirtualFilesystem, public_key: bytes, tmp_path: Path) -> None:
    entry_name = "/foo/bar/some-file"
    entry = mock_fs.get(entry_name)
    zip_output = ZipOutput(tmp_path, compress=True, compression_method="bzip2", encrypt=True, public_key=public_key)
    zip_output.write_entry(entry_name, entry)
    zip_output.close()

    encrypted_stream = EncryptedFile(zip_output.path.open("rb"), Path("tests/data/private_key.pem"))
    decrypted_path = tmp_path / "decrypted.zip"
    # Direct streaming is not an option because zipfile needs seek when reading from encrypted files directly
    with open(decrypted_path, "wb") as f:
        f.write(encrypted_stream.read())

    zip_file = zipfile.ZipFile(decrypted_path, mode="r")
    assert entry.open().read() == zip_file.open(entry_name).read()
