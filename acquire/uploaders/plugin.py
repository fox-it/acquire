import logging
from pathlib import Path
from typing import Optional, Any

log = logging.getLogger(__name__)


class UploaderPlugin:
    """Creates a typing definition to which an UploaderPlugin should adhere."""

    def upload_files(self, paths: list[Path], proxies: Optional[dict[str, str]] = None) -> None:
        """Uploads the files in ``paths`` to a destination.

        Args:
            paths: A list of files to upload.
            proxies: Proxies used as an intermediate during an upload.
        """
        paths = [Path(path) if isinstance(path, str) else path for path in paths]
        client = self._prepare_client(paths, proxies)

        for path in paths:
            try:
                self.upload_file(client=client, path=path)
            except ValueError:
                pass

        self.finish(client)

    def upload_file(self, client: Any, path: Path, attempts: int = 0) -> None:
        """Upload a file, pointed to by ``path`` using a ``client``.

        Args:
            client: The method we use to upload.
            path: The path to the file to upload.
            attempts: The number of attempts it was to upload this file.

        Raises:
            ValueError: If the maximum number of attempts was reached.
        """
        if attempts > 3:
            raise ValueError("Too many attempts for %s. Stopping.", path)

        try:
            log.info("Uploading %s", path)
            self._upload_file(client=client, path=path)
            log.info("Uploaded %s", path)
        except Exception:
            log.error("Upload %s FAILED. See log file for details. Retrying", path)
            log.exception("")
            self.upload_file(path=path, client=client, attempts=attempts + 1)

    def _prepare_client(self, paths: list[Path], proxies: Optional[dict[str, str]] = None) -> Any:
        """Prepares a client for th transfer."""
        raise NotImplementedError()

    def _upload_file(self, client: Any, path: Path) -> None:
        """Uploads a file/path using the ``client``."""
        raise NotImplementedError()

    def finish(self, client: Any) -> None:
        """A cleanup step or anything required to finish the upload."""
        raise NotImplementedError()
