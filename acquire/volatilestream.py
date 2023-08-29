import os
from io import SEEK_SET, UnsupportedOperation
from pathlib import Path
from stat import S_IRGRP, S_IROTH, S_IRUSR

from dissect.util.stream import AlignedStream

try:
    # Windows systems do not have the fcntl module.
    from fcntl import F_SETFL, fcntl

    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False


class VolatileStream(AlignedStream):
    """Streaming class to handle various procfs and sysfs edge-cases.  Backed by `AlignedStream`.

    Args:
        path: Path of the file to obtain a file-handle from.
        mode: Mode string to open the file-handle with. Such as "rt" and "rb".
        flags: Flags to open the file-descriptor with.
        size: The maximum size of the stream. None if unknown.
    """

    def __init__(
        self,
        path: Path,
        mode: str = "rb",
        # Windows and Darwin systems don't have O_NOATIME or O_NONBLOCK. Add them if they are available.
        flags: int = (os.O_RDONLY | getattr(os, "O_NOATIME", 0) | getattr(os, "O_NONBLOCK", 0)),
        size: int = 1024 * 1024 * 5,
    ):
        self.fh = path.open(mode)
        self.fd = self.fh.fileno()

        if HAS_FCNTL:
            fcntl(self.fd, F_SETFL, flags)

        st_mode = os.fstat(self.fd).st_mode
        write_only = (st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) == 0  # novermin

        super().__init__(0 if write_only else size)

    def seek(self, pos: int, whence: int = SEEK_SET) -> int:
        raise UnsupportedOperation("VolatileStream is not seekable")

    def seekable(self) -> bool:
        return False

    def _read(self, offset: int, length: int) -> bytes:
        result = []
        while length:
            try:
                buf = os.read(self.fd, min(length, self.size - offset))
            except BlockingIOError:
                break

            if not buf:
                break

            result.append(buf)
            offset += len(buf)
            length -= len(buf)
        return b"".join(result)
