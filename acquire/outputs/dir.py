import os
import shutil
import platform

from acquire.outputs.base import Output


class DirectoryOutput(Output):
    def __init__(self, path, **kwargs):
        self.path = path

    def write(self, path, fh, size=None, entry=None):
        if platform.system() == "Windows":
            path = path.replace(":", "_")

        outpath = os.path.join(self.path, path)
        outdir = os.path.dirname(outpath)
        if not os.path.exists(outdir):
            os.makedirs(outdir)

        with open(outpath, "wb") as fhout:
            shutil.copyfileobj(fh, fhout)

    def close(self):
        pass
