import logging
from pathlib import Path
from typing import List, Optional, Protocol, runtime_checkable

log = logging.getLogger(__name__)


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

    def upload_file(self, path: Path, **kwargs):
        ...


def upload_file(path: Path, plugin: UploaderPlugin, attempts: int = 0, **kwargs):
    if attempts > 3:
        raise ValueError("Too many attempts for %s. Stopping.", path)

    try:
        log.info("Uploading %s", path)
        plugin.upload_file(path=path, **kwargs)
        log.info("Uploaded %s", path)
    except Exception:
        log.error("Upload %s FAILED. See log file for details. Retrying", path)
        log.exception("")
        upload_file(path=path, plugin=plugin, attempts=attempts + 1, **kwargs)
