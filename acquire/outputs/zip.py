import io
import pyzipper
from pathlib import Path
from typing import BinaryIO, Optional, Union
from datetime import datetime

from dissect.target.filesystem import FilesystemEntry

from acquire.crypt import EncryptedStream
from acquire.outputs.base import Output


class ZipOutput(Output):
    """zip archive acquire output format. Output can be compressed and/or encrypted.

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

        self._fh = None
        self.path = path.with_suffix(path.suffix + ext)

        if encrypt:
            self.archive = pyzipper.AESZipFile(self.path, 'w', compression=pyzipper.ZIP_LZMA)
        else:
            self.archive = pyzipper.ZipFile(self.path, 'w', compression=pyzipper.ZIP_LZMA)

    def write(
        self,
        output_path: str,
        fh: BinaryIO,
        entry: Optional[Union[FilesystemEntry, Path]],
        size: Optional[int] = None,
    ) -> None:
        """Write a filesystem entry or file-like object to a zip file.

        Args:
            output_path: The path of the entry in the output format.
            fh: The file-like object of the entry to write.
            entry: The optional filesystem entry of the entry to write.
            size: The optional file size in bytes of the entry to write.
        """
        stat = None
        size = size or getattr(fh, "size", None)

        if size is None and fh.seekable():
            offset = fh.tell()
            fh.seek(0, io.SEEK_END)
            size = fh.tell()
            fh.seek(offset)

        info = pyzipper.ZipInfo()
        info.filename = output_path

        # some BinaryIO objects have no size, but `zipfile` uses len() in several places,
        # so we read the whole data first
        try:
            info.file_size = len(fh)
        except:
            fh = fh.read()
            info.file_size = len(fh)

        if entry:
            if entry.is_symlink():
                # System which created ZIP archive, 3 = Unix; 0 = Windows
                # Windows does not have symlinks, so this must be a unixoid system
                info.create_system = 3

                # The Python zipfile module accepts the 16-bit "Mode" field (that stores st_mode field from struct stat, containing user/group/other permissions, setuid/setgid and symlink info, etc) of the ASi extra block for Unix as bits 16-31 of the external_attr
                unix_st_mode = stat.S_IFLNK | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH
                info.external_attr = unix_st_mode << 16

            stat = entry.lstat()

            if stat:
                dt = datetime.fromtimestamp(stat.st_mtime)
                info.date_time = (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

        self.archive.writestr(info, fh)

    def close(self) -> None:
        """Closes the archive file."""
        self.archive.close()
