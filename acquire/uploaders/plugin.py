import logging
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)

__all__ = [
    "UploaderPlugin",
    "upload_files_using_uploader",
]

MAX_RETRIES = 4


class UploaderPlugin:
    """Creates a typing definition to which an UploaderPlugin should adhere."""

    def prepare_client(self, paths: list[Path], proxies: Optional[dict[str, str]] = None) -> Any:
        """Prepares a client for the upload."""
        raise NotImplementedError()

    def upload_file(self, client: Any, path: Path) -> None:
        """Uploads a file/path using the ``client``."""
        raise NotImplementedError()

    def finish(self, client: Any) -> None:
        """A cleanup step or anything required to finish the upload."""
        raise NotImplementedError()


def upload_files_using_uploader(
    uploader: UploaderPlugin, paths: list[Path], proxies: Optional[dict[str, str]] = None
) -> None:
    """Uploads the files in ``paths`` to a destination.

    Args:
        uploader: The plugin used to upload files.
        paths: A list of files to upload.
        proxies: Proxies used as an intermediate during an upload.
    """
    paths = [Path(path) if isinstance(path, str) else path for path in paths]
    client = uploader.prepare_client(paths, proxies)

    for path in paths:
        try:
            _upload_file(uploader, client, path)
        except ValueError:
            log.error("Too many attempts for %s. Stopping.", path)

    uploader.finish(client)


def _upload_file(uploader: UploaderPlugin, client: Any, path: Path, attempts: int = 0) -> None:
    """Upload a file, pointed to by ``path`` using a ``client``.

    Args:
        uploader: The plugin used to upload files.
        client: The method we use to upload.
        path: The path to the file to upload.
        attempts: The number of attempts it was to upload this file.

    Raises:
        ValueError: If the maximum number of attempts was reached.
    """
    if attempts >= MAX_RETRIES:
        raise ValueError()

    try:
        log.info("Uploading %s", path)
        uploader.upload_file(client=client, path=path)
        log.info("Uploaded %s", path)
    except Exception:
        log.error("Upload %s FAILED. See log file for details. Retrying", path)
        log.exception("")
        _upload_file(uploader, path, client, attempts=attempts + 1)
