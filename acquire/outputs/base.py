import io
from pathlib import Path
from typing import BinaryIO, Optional, Union

from dissect.target.filesystem import FilesystemEntry
from dissect.target.target import Target

import acquire.utils


class Output:
    """Base class to implement acquire output formats with.

    New output formats must sub-class this class.

    Args:
        target: The target that we're using acquire on.
    """

    def init(self, target: Target):
        pass

    def write(
        self,
        output_path: Union[str, Path],
        fh: BinaryIO,
        size: Optional[int] = None,
        entry: Optional[FilesystemEntry] = None,
    ) -> None:
        """Write a filesystem entry or file-like object to the implemented output type.

        Args:
            output_path: The path of the entry in the output format.
            fh: The file-like object of the entry to write.
            size: The optional file size in bytes of the entry to write.
            entry: The optional filesystem entry of the entry to write.
        """
        raise NotImplementedError()

    def write_entry(
        self,
        output_path: Union[str, Path],
        size: Optional[int] = None,
        entry: Optional[FilesystemEntry] = None,
    ) -> None:
        """Write a filesystem entry to the output format.

        Args:
            output_path: The path of the entry in the output format.
            size: The optional file size in bytes of the entry to write.
            entry: The optional filesystem entry of the entry to write.
        """
        with entry.open() as fh:
            self.write(output_path, fh, size, entry)

    def write_bytes(
        self,
        output_path: Union[str, Path],
        data: bytes,
        size: Optional[int] = None,
        entry: Optional[FilesystemEntry] = None,
    ) -> None:
        """Write raw bytes to the output format.

        Args:
            output_path: The path of the entry in the output format.
            data: The raw bytes to write.
            size: The optional file size in bytes of the entry to write.
            entry: The optional filesystem entry of the entry to write.
        """

        stream = io.BytesIO(data)
        self.write(output_path, stream, size, entry)

    def write_volatile(
        self,
        output_path: Union[str, Path],
        size: Optional[int] = None,
        entry: Optional[FilesystemEntry] = None,
    ) -> None:
        """Write specified path to the output format.
        Handles files that live in volatile filesystems. Such as procfs and sysfs.

        Args:
            output_path: The path of the entry in the output format.
            size: The optional file size in bytes of the entry to write.
            entry: The optional filesystem entry of the entry to write.
        """
        try:
            fh = acquire.utils.VolatileStream(Path(entry.path))
            buf = fh.read()
            size = size or len(buf)
        except (OSError, PermissionError):
            # Various OSErrors can occur here.
            # If one does occur, we'd still like to have the corresponding entry.
            buf = b""
            size = 0

        self.write_bytes(output_path, buf, size, entry)

    def close(self) -> None:
        """Closes the output."""
        raise NotImplementedError()
