from __future__ import annotations

import io
import tarfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from acquire.outputs import TarOutput
from acquire.tools.decrypter import EncryptedFile

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem


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

    with tarfile.open(tar_output.path) as tar_file:
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

    encrypted_stream = EncryptedFile(tar_output.path.open("rb"), Path("tests/_data/private_key.pem"))
    decrypted_path = tmp_path / "decrypted.tar"
    # Direct streaming is not an option because tarfile needs seek when reading from encrypted files directly
    Path(decrypted_path).write_bytes(encrypted_stream.read())

    with tarfile.open(name=decrypted_path, mode="r") as tar_file:
        assert entry.open().read() == tar_file.extractfile(entry_name).read()


def test_tar_output_race_condition_with_shrinking_file(tmp_path: Path, public_key: bytes) -> None:
    class ShrinkingFile(io.BytesIO):
        """
        A file-like object that returns 5 bytes less than required.
        Simulates a file on disk that has shrunk in between the time of
        determining the size and actually reading the data.
        """

        def __init__(self, data: bytes):
            super().__init__(data)

        def read(self, size: int) -> bytes:
            return super().read(size - 5)

    content = b"some text"

    content_padded = content[:-5] + tarfile.NUL * 5
    file = ShrinkingFile(content)

    tar_output = TarOutput(tmp_path / "race.tar", encrypt=True, public_key=public_key)
    tar_output.write("file.log", file)
    tar_output.close()
    file.close()

    encrypted_stream = EncryptedFile(tar_output.path.open("rb"), Path("tests/_data/private_key.pem"))
    decrypted_path = tmp_path / "decrypted.tar"

    # Direct streaming is not an option because tarfile needs seek when reading from encrypted files directly
    Path(decrypted_path).write_bytes(encrypted_stream.read())

    with tarfile.open(name=decrypted_path, mode="r") as tar_file:
        member = tar_file.getmember("file.log")
        extracted = tar_file.extractfile(member).read()
        # The content should be padded with zeros to match the original size, despite the fact that the file shrunk
        assert extracted == content_padded


def test_tar_output_race_condition_with_growing_file(tmp_path: Path, public_key: bytes) -> None:
    class GrowingFile(io.BytesIO):
        """
        A file-like object that returns 3 extra bytes.
        Simulates a file on disk that has grown in between the time of
        determining the size and actually reading the data.
        """

        def __init__(self, data: bytes):
            super().__init__(data)

        def read(self, size: int) -> bytes:
            return super().read(size) + b"FOX"

    content = b"some text"

    file = GrowingFile(content)

    tar_output = TarOutput(tmp_path / "race.tar", encrypt=True, public_key=public_key)
    tar_output.write("file.log", file)
    tar_output.close()
    file.close()

    encrypted_stream = EncryptedFile(tar_output.path.open("rb"), Path("tests/_data/private_key.pem"))
    decrypted_path = tmp_path / "decrypted.tar"

    # Direct streaming is not an option because tarfile needs seek when reading from encrypted files directly
    Path(decrypted_path).write_bytes(encrypted_stream.read())

    with tarfile.open(name=decrypted_path, mode="r") as tar_file:
        member = tar_file.getmember("file.log")
        extracted = tar_file.extractfile(member).read()
        # The content should match the original content, without the extra bytes
        # because the file was read with the original size
        assert extracted == content
