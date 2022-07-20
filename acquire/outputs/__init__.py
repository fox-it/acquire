from acquire.outputs.dir import DirectoryOutput
from acquire.outputs.tar import TarOutput

__all__ = [
    "DirectoryOutput",
    "TarOutput",
]

OUTPUTS = {
    "tar": TarOutput,
    "dir": DirectoryOutput,
}
