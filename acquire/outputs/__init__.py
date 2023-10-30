from acquire.outputs.dir import DirectoryOutput
from acquire.outputs.tar import TarOutput
from acquire.outputs.zip import ZipOutput

__all__ = ["DirectoryOutput", "TarOutput", "ZipOutput"]

OUTPUTS = {"tar": TarOutput, "dir": DirectoryOutput, "zip": ZipOutput}
