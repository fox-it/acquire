from __future__ import annotations

import os
from concurrent import futures
from io import SEEK_SET, UnsupportedOperation
from stat import S_IRGRP, S_IROTH, S_IRUSR
from typing import TYPE_CHECKING, Any, Callable

from dissect.util.stream import AlignedStream

if TYPE_CHECKING:
    from pathlib import Path

try:
    # Windows systems do not have the fcntl module.
    from fcntl import F_SETFL, fcntl

    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False


def timeout(func: Callable, *, timelimit: int) -> Callable:
    """Timeout a function if it takes too long to complete.

    Args:
        func: a function to wrap.
        timelimit: The time in seconds that an operation is allowed to run.

    Raises:
        TimeoutError: If its time exceeds the timelimit
    """

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        with futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(func, *args, **kwargs)

            try:
                result = future.result(timelimit)
            except futures.TimeoutError:
                raise TimeoutError
            finally:
                # Make sure the thread stops right away.
                executor._threads.clear()
                futures.thread._threads_queues.clear()

            return result

    return wrapper


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

        self._os_read = timeout(os.read, timelimit=5)

        super().__init__(0 if write_only else size)

    def seek(self, pos: int, whence: int = SEEK_SET) -> int:
        raise UnsupportedOperation("VolatileStream is not seekable")

    def seekable(self) -> bool:
        return False

    def _read(self, offset: int, length: int) -> bytes:
        result = []
        while length:
            try:
                buf = self._os_read(self.fd, min(length, self.size - offset))
            except (BlockingIOError, TimeoutError):
                break

            if not buf:
                break

            result.append(buf)
            offset += len(buf)
            length -= len(buf)
        return b"".join(result)
