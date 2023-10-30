import io
import shutil
import stat
import zipfile
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Optional, Union

from dissect.target.filesystem import FilesystemEntry

from acquire.crypt import EncryptedStream
from acquire.outputs.base import Output


class ZipOutput(Output):
    """Zip archive acquire output format. Output can be compressed and/or encrypted.

    Args:
        path: The path to write the zip archive to.
        compress: Whether to compress the zip archive.
        encrypt: Whether to encrypt the zip archive.
        public_key: The RSA public key to encrypt the header with.
    """

    def __init__(
        self,
        path: Path,
        compress: bool = False,
        encrypt: bool = False,
        public_key: Optional[bytes] = None,
    ) -> None:
        ext = ".zip" if ".zip" not in path.suffixes else ""

        if encrypt:
            ext += ".enc"

        self._fh = None
        self.path = path.with_suffix(path.suffix + ext)

        if compress:
            self.compression = zipfile.ZIP_LZMA
        else:
            self.compression = zipfile.ZIP_STORED

        if encrypt:
            self._fh = EncryptedStream(self.path.open("wb"), public_key)
            self.archive = zipfile.ZipFile(fileobj=self._fh, mode="w", compression=self.compression, allowZip64=True)
        else:
            self.archive = zipfile.ZipFile(self.path, mode="w", compression=self.compression, allowZip64=True)

    def write(
        self,
        output_path: str,
        fh: BinaryIO,
        entry: Optional[Union[FilesystemEntry, Path]] = None,
        size: Optional[int] = None,
    ) -> None:
        """Write a filesystem entry or file-like object to a zip file.

        Args:
            output_path: The path of the entry in the output format.
            fh: The file-like object of the entry to write.
            entry: The optional filesystem entry of the entry to write.
            size: The optional file size in bytes of the entry to write.
        """
        lstat = None
        size = size or getattr(fh, "size", None)

        if size is None and fh.seekable():
            offset = fh.tell()
            fh.seek(0, io.SEEK_END)
            size = fh.tell()
            fh.seek(offset)

        info = zipfile.ZipInfo()
        info.filename = output_path
        info.file_size = size or 0

        if entry:
            if entry.is_symlink():
                # System which created ZIP archive, 3 = Unix; 0 = Windows
                # Windows does not have symlinks, so this must be a unixoid system
                info.create_system = 3

                # The Python zipfile module accepts the 16-bit "Mode" field (that stores st_mode field from
                # struct stat, containing user/group/other permissions, setuid/setgid and symlink info, etc) of the
                # ASi extra block for Unix as bits 16-31 of the external_attr
                unix_st_mode = (
                    stat.S_IFLNK
                    | stat.S_IRUSR
                    | stat.S_IWUSR
                    | stat.S_IXUSR
                    | stat.S_IRGRP
                    | stat.S_IWGRP
                    | stat.S_IXGRP
                    | stat.S_IROTH
                    | stat.S_IWOTH
                    | stat.S_IXOTH
                )
                info.external_attr = unix_st_mode << 16

            lstat = entry.lstat()
            if lstat:
                dt = datetime.fromtimestamp(lstat.st_mtime)
                info.date_time = (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

        with self.archive.open(info, "w") as zfh:
            shutil.copyfileobj(fh, zfh)

    def close(self) -> None:
        """Closes the archive file."""
        self.archive.close()
        if self._fh:
            self._fh.close()
