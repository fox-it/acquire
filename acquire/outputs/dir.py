import platform
import shutil
from pathlib import Path
from typing import BinaryIO, Optional, Union

from dissect.target.filesystem import FilesystemEntry

from acquire.outputs.base import Output


class DirectoryOutput(Output):
    def __init__(self, path: Path, **kwargs):
        self.path = path

    def write(
        self, output_path: str, fh: BinaryIO, entry: Optional[Union[FilesystemEntry, Path]], size: Optional[int] = None
    ) -> None:
        if platform.system() == "Windows":
            output_path = output_path.replace(":", "_")

        out_path = self.path.joinpath(output_path)
        out_dir = out_path.parent
        if not out_dir.exists():
            out_dir.mkdir(parents=True)

        with out_path.open("wb") as fhout:
            shutil.copyfileobj(fh, fhout)

    def close(self) -> None:
        pass
