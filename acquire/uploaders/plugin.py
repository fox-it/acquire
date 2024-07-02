from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from acquire.gui import GUI

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
    uploader: UploaderPlugin, paths: list[str | Path], proxies: Optional[dict[str, str]] = None
) -> None:
    """Uploads the files in ``paths`` to a destination.

    Args:
        uploader: The plugin used to upload files.
        paths: A list of files to upload.
        proxies: Proxies used as an intermediate during an upload.
    """
    paths = [Path(path) if isinstance(path, str) else path for path in paths]
    client = uploader.prepare_client(paths, proxies)

    counter = 0
    upload_gui = GUI()
    upload_gui.progress = 55

    for path in paths:
        for retry in range(MAX_RETRIES):
            if retry == MAX_RETRIES - 1:
                error_log = ("Upload %s FAILED after too many attempts. Stopping.", path)
            else:
                error_log = ("Upload %s FAILED. See log file for details. Retrying", path)

            try:
                log.info("Uploading %s", path)
                uploader.upload_file(client, path)
                log.info("Uploaded %s", path)
                break
            except Exception:
                log.error(*error_log)
                log.exception("")

        counter += 1
        upload_gui.progress = 55 + (counter // len(paths) * 40)

    uploader.finish(client)
