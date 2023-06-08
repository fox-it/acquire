from acquire.outputs.dir import DirectoryOutput
from acquire.outputs.tar import TarOutput

try:
    import pyzipper
    from acquire.outputs.zip import ZipOutput
    HAVE_ZIP = True
except:
    HAVE_ZIP = False

__all__ = [
    "DirectoryOutput",
    "TarOutput"
]

if HAVE_ZIP:
    __all__.append("ZipOutput")

OUTPUTS = {
    "tar": TarOutput,
    "dir": DirectoryOutput
}

if HAVE_ZIP:
    OUTPUTS["zip"] = ZipOutput