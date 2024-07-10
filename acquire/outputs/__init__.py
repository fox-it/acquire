from acquire.outputs.dir import DirectoryOutput
from acquire.outputs.tar import TAR_COMPRESSION_METHODS, TarOutput
from acquire.outputs.zip import ZIP_COMPRESSION_METHODS, ZipOutput

__all__ = ["DirectoryOutput", "TarOutput", "ZipOutput"]

OUTPUTS = {"tar": TarOutput, "dir": DirectoryOutput, "zip": ZipOutput}

COMPRESSION_METHODS = {*TAR_COMPRESSION_METHODS, *ZIP_COMPRESSION_METHODS}
