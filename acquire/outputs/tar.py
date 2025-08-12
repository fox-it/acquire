from __future__ import annotations

import copy
import io
import shutil
import tarfile
from typing import TYPE_CHECKING, BinaryIO

from acquire.crypt import EncryptedStream
from acquire.outputs.base import Output

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.filesystem import FilesystemEntry

TAR_COMPRESSION_METHODS = {"gzip": "gz", "bzip2": "bz2", "xz": "xz"}


class TarOutput(Output):
    """Tar archive acquire output format. Output can be compressed and/or encrypted.

    Args:
        path: The path to write the tar archive to.
        compress: Whether to compress the tar archive.
        compression_method: Compression method to use (Default: gzip). Supports "gzip", "bzip2", "xz".
        encrypt: Whether to encrypt the tar archive.
        public_key: The RSA public key to encrypt the header with.
    """

    def __init__(
        self,
        path: Path,
        compress: bool = False,
        compression_method: str = "gzip",
        encrypt: bool = False,
        public_key: bytes | None = None,
    ) -> None:
        self.compression = None
        ext = ".tar" if ".tar" not in path.suffixes else ""
        mode = "w|" if encrypt else "w:"

        if compress:
            self.compression = TAR_COMPRESSION_METHODS.get(compression_method, "gz")

            ext += f".{self.compression}" if f".{self.compression}" not in path.suffixes else ""
            mode += self.compression

        if encrypt:
            ext += ".enc"

        self._fh = None
        self.path = path.with_suffix(path.suffix + ext)

        if encrypt:
            self._fh = EncryptedStream(self.path.open("wb"), public_key)
            self.tar = tarfile.open(fileobj=self._fh, mode=mode)  # noqa: SIM115
        else:
            self.tar = tarfile.open(name=self.path, mode=mode)  # noqa: SIM115

    def write(
        self,
        output_path: str,
        fh: BinaryIO,
        entry: FilesystemEntry | Path | None = None,
        size: int | None = None,
    ) -> None:
        """Write a file-like object to a tar file.

        The data from ``fh`` is written, while ``entry`` is used to get some properties of the file.

        Args:
            output_path: The path of the entry in the output.
            fh: The file-like object of the entry to write.
            entry: The optional filesystem entry to write.
            size: The optional file size in bytes of the entry to write.
        """
        stat = None
        size = size or getattr(fh, "size", None)

        if size is None and fh.seekable():
            offset = fh.tell()
            fh.seek(0, io.SEEK_END)
            size = fh.tell()
            fh.seek(offset)

        info = self.tar.tarinfo()
        info.name = output_path
        info.uname = "root"
        info.gname = "root"
        info.size = size or 0

        if entry:
            if entry.is_symlink():
                info.type = tarfile.SYMTYPE
                info.linkname = entry.readlink()
            elif entry.is_dir():
                info.type = tarfile.DIRTYPE

            stat = entry.lstat()

            if stat:
                info.mtime = stat.st_mtime

        # Inline version of Python stdlib's tarfile.addfile & tarfile.copyfileobj,
        # to allow for padding and more control over the tar file writing.
        self.tar._check("awx")

        if fh is None and info.isreg() and info.size != 0:
            raise ValueError("fileobj not provided for non zero-size regular file")

        info = copy.copy(info)

        buf = info.tobuf(self.tar.format, self.tar.encoding, self.tar.errors)
        self.tar.fileobj.write(buf)
        self.tar.offset += len(buf)
        bufsize = self.tar.copybufsize
        if fh is not None:
            bufsize = bufsize or 16 * 1024

            if info.size == 0:
                return
            if info.size is None:
                shutil.copyfileobj(fh, self.tar.fileobj, bufsize)
                return

            blocks, remainder = divmod(info.size, bufsize)
            for _ in range(blocks):
                # Prevents "long reads" because it reads at max bufsize bytes at a time
                buf = fh.read(bufsize)
                if len(buf) < bufsize:
                    # raise exception("unexpected end of data")
                    # PATCH; instead of raising an exception, pad the data to the desired length
                    buf += tarfile.NUL * (bufsize - len(buf))
                self.tar.fileobj.write(buf)

            if remainder != 0:
                # Prevents "long reads" because it reads at max bufsize bytes at a time
                buf = fh.read(remainder)
                if len(buf) < remainder:
                    # raise exception("unexpected end of data")
                    # PATCH; instead of raising an exception, pad the data to the desired length
                    buf += tarfile.NUL * (remainder - len(buf))
                self.tar.fileobj.write(buf)

            blocks, remainder = divmod(info.size, tarfile.BLOCKSIZE)
            if remainder > 0:
                self.tar.fileobj.write(tarfile.NUL * (tarfile.BLOCKSIZE - remainder))
                blocks += 1
            self.tar.offset += blocks * tarfile.BLOCKSIZE

        self.tar.members.append(info)

    def close(self) -> None:
        """Closes the tar file."""
        self.tar.close()
        if self._fh:
            self._fh.close()
