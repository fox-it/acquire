from __future__ import annotations

import io
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from acquire.volatilestream import VolatileStream

if TYPE_CHECKING:
    from dissect.target.filesystem import FilesystemEntry


class Output:
    """Base class to implement acquire output formats with.

    New output formats must sub-class this class.
    """

    def init(self, path: Path, **kwargs) -> None:
        pass

    def write(
        self,
        output_path: str,
        fh: BinaryIO,
        entry: FilesystemEntry | Path | None,
        size: int | None = None,
    ) -> None:
        """Write a file-like object to the output.

        Args:
            output_path: The path of the entry in the output.
            fh: The file-like object of the entry to write.
            entry: The optional filesystem entry to write.
            size: The optional file size in bytes of the entry to write.
        """
        raise NotImplementedError

    def write_entry(
        self,
        output_path: str,
        entry: FilesystemEntry | Path,
        size: int | None = None,
    ) -> None:
        """Write a filesystem entry to the output.

        Args:
            output_path: The path of the entry in the output.
            entry: The filesystem entry to write.
            size: The optional file size in bytes of the entry to write.
        """
        if entry.is_dir() or entry.is_symlink():
            self.write_bytes(output_path, b"", entry=entry, size=0)
        else:
            with entry.open() as fh:
                self.write(output_path, fh, entry=entry, size=size)

    def write_bytes(
        self,
        output_path: str,
        data: bytes,
        entry: FilesystemEntry | Path | None = None,
        size: int | None = None,
    ) -> None:
        """Write raw bytes to the output format.

        Args:
            output_path: The path of the entry in the output.
            data: The raw bytes to write.
            entry: The optional filesystem entry to write.
            size: The optional file size in bytes of the entry to write.
        """

        stream = io.BytesIO(data)
        self.write(output_path, stream, entry=entry, size=size)

    def write_volatile(
        self,
        output_path: str,
        entry: FilesystemEntry | Path,
        size: int | None = None,
    ) -> None:
        """Write a filesystem entry to the output.

        Handles files that live in volatile filesystems. Such as procfs and sysfs.

        Args:
            output_path: The path of the entry in the output.
            entry: The filesystem entry to write.
            size: The optional file size in bytes of the entry to write.
        """
        try:
            fh = VolatileStream(Path(entry.path))
            buf = fh.read()
            size = size or len(buf)
        except (OSError, PermissionError):
            # Various OSErrors can occur here.
            # If one does occur, we'd still like to have the corresponding entry.
            buf = b""
            size = 0

        self.write_bytes(output_path, buf, entry=entry, size=size)

    def close(self) -> None:
        """Closes the output."""
        raise NotImplementedError
