import io
from typing import BinaryIO, Optional, Union

import acquire.utils
from dissect.target.filesystem import FilesystemEntry
from dissect.target.helpers import fsutil
from dissect.target.target import Target


class Output:
    """Base class to implement acquire output formats with.

    New output formats should sub-class this base class to gain access to various write implementation.

    Args:
        target: The Optional target that we're using acquire on.
    """

    def init(self, target: Optional[Target] = None):
        pass

    def write(
        self,
        path: Union[str, fsutil.TargetPath],
        fh: BinaryIO,
        size: Optional[int] = None,
        entry: Optional[FilesystemEntry] = None,
    ) -> None:
        """Write a filesystem entry or file-like object to the implemented output type.
        Implenenting classes should create their own implementation.

        Args:
            path: The path of the entry to write in the output format
            fh: The file-like object of the entry to write
            size: The optional filesize in bytes of the entry to write
            entry: the optional filesystem entry of the entry to write
        """
        raise NotImplementedError()

    def write_entry(
        self,
        path: Union[str, fsutil.TargetPath],
        size: Optional[int] = None,
        entry: Optional[FilesystemEntry] = None,
    ) -> None:
        """Write a filesystem entry to the implemented output format.

        Args:
            path: The path of the entry to write in the output format
            size: The optional filesize in bytes of the entry to write
            entry: The optional filesystem entry of the entry to write
        """
        with entry.open("rb") as fh:
            self.write(path, fh, size=size, entry=entry)

    def write_bytes(
        self,
        path: Union[str, fsutil.TargetPath],
        data: bytes,
        size: Optional[int] = None,
        entry: Optional[FilesystemEntry] = None,
    ) -> None:
        """Write raw bytes to the implemtend output format.

        Args:
            path: The path of the entry to write in the output format
            data: The raw bytes to write
            size: The optional filesize in bytes of the entry to write
            entry: The optional filesystem entry of the entry to write
        """

        stream = io.BytesIO(data)
        self.write(path, stream, size=size, entry=entry)

    def write_volatile(
        self,
        path: Union[str, fsutil.TargetPath],
        size: Optional[int] = None,
        entry: Optional[FilesystemEntry] = None,
    ) -> None:
        """Write specified path to the implementd output format.
        Handles files that live in volatile filesystems. Such as procfs and sysfs.

        Args:
            path: The path of the entry to write in the output format
            size: The optional filesize in bytes of the entry to write
            entry: The optional filesystem entry of the entry to write
        """
        try:
            fh = acquire.utils.VolatileAlignedStream(entry)
            buf = fh.read()
            size = size or fh.tell()
        except (OSError, PermissionError):
            # Various OSErrors can occur here.
            # If one does occur, we'd still like to have the corresponding entry.
            buf = b""
            size = 0

        self.write_bytes(path, buf, size=size, entry=entry)

    def close(self) -> None:
        """Closes all handles of the file-like objects passed to the write function.
        Implenenting classes should create their own implementation."""
        raise NotImplementedError()
