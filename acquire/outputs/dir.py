from __future__ import annotations

import platform
import shutil
from typing import TYPE_CHECKING, BinaryIO

from acquire.outputs.base import Output

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.filesystem import FilesystemEntry


class DirectoryOutput(Output):
    def __init__(self, path: Path, **kwargs):
        self.path = path

    def write(
        self,
        output_path: str,
        fh: BinaryIO,
        entry: FilesystemEntry | Path | None = None,
        size: int | None = None,
    ) -> None:
        """Write a file-like object to a directory.

        The data from ``fh`` is written, while ``entry`` is used to get some properties of the file.

        On Windows platforms ``:`` is replaced with ``_`` in the output_path.

        Args:
            output_path: The path of the entry in the output.
            fh: The file-like object of the entry to write.
            entry: The optional filesystem entry to write.
            size: The optional file size in bytes of the entry to write.
        """
        if platform.system() == "Windows":
            output_path = output_path.replace(":", "_")

        out_path = self.path.joinpath(output_path.lstrip("/"))

        if entry and entry.is_dir():
            out_path.mkdir(parents=True, exist_ok=True)

        else:
            out_path.parent.mkdir(parents=True, exist_ok=True)

            with out_path.open("wb") as fhout:
                shutil.copyfileobj(fh, fhout)

    def close(self) -> None:
        pass
