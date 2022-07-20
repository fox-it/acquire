from pathlib import Path
from typing import List, Optional, Protocol, runtime_checkable


@runtime_checkable
class UploaderPlugin(Protocol):
    """Creates a typing definition to which an UploaderPlugin should adhere."""

    def upload_files(self, paths: List[Path], proxies: Optional[dict[str, str]] = None) -> None:
        """Uploads the files in ``paths`` to a destination.

        Args:
            paths: A list of files to upload.
            proxies: Proxies used as an intermediate during an upload.
        """
        ...
