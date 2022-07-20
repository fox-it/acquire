import io
import tarfile

from acquire.crypt import EncryptedStream
from acquire.outputs.base import Output


class TarOutput(Output):
    def __init__(self, path, compress=False, encrypt=False, public_key=None, **kwargs):
        ext = ".tar" if ".tar" not in path.suffixes else ""
        mode = "w|" if encrypt else "w:"

        if compress:
            ext += ".gz" if ".gz" not in path.suffixes else ""
            mode += "gz"

        if encrypt:
            ext += ".enc"

        self._fh = None
        self.path = path.with_suffix(path.suffix + ext)

        if encrypt:
            self._fh = EncryptedStream(self.path.open("wb"), public_key)
            self.tar = tarfile.open(fileobj=self._fh, mode=mode)
        else:
            self.tar = tarfile.open(name=self.path, mode=mode)

    def write(self, path, fh, size=None, entry=None):
        size = size or getattr(fh, "size", None)
        if size is None:
            offset = fh.tell()
            fh.seek(0, io.SEEK_END)
            size = fh.tell()
            fh.seek(offset)

        info = self.tar.tarinfo()
        info.name = path
        info.uname = "root"
        info.gname = "root"
        info.size = size

        self.tar.addfile(info, fh)

    def close(self):
        self.tar.close()
        if self._fh:
            self._fh.close()
