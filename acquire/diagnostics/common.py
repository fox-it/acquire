import json
import platform
from pathlib import Path


def diagnostics_info_json(output: Path) -> None:
    # Dynamic imports are required to avoid import errors on unsupported platforms
    system = platform.system().lower()
    if system == "windows":
        from .windows import diagnostics_info  # noqa: PLC0415
    elif system == "linux":
        from .linux import diagnostics_info  # noqa: PLC0415
    else:
        raise NotImplementedError(f"Diagnostics not implemented for OS: {system}")
    data = diagnostics_info()
    with output.open("w") as f:
        json.dump(data, f, default=str, indent=2)
