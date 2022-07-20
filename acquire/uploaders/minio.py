import logging
import os
from pathlib import Path
from typing import Any, List, Optional

from acquire.uploaders.plugin import UploaderPlugin

log = logging.getLogger(__name__)


class MinIO(UploaderPlugin):
    def __init__(self, upload: dict[str, str], **kwargs: dict[str, Any]) -> None:
        """An uploader plugin that uploads files using minio.

        Args:
            upload: Contains credentials and information to use for the transfer.

        Raises:
            ValueError: When the configuration is invalid.
        """

        self.endpoint = upload.get("endpoint")
        self.access_id = upload.get("access_id")
        self.access_key = upload.get("access_key")
        self.bucket_name = upload.get("bucket")

        if not all((self.endpoint, self.access_id, self.access_key, self.bucket_name)):
            raise ValueError("Invalid cloud upload configuration")

    def upload_files(self, paths: List[Path], proxies: Optional[dict[str, str]] = None) -> None:
        """Uploads files using MinIO

        Args:
            paths: The files to upload.
            proxies: The proxies to use during the upload.

        Raises:
            RuntimeError: When the minio module is not installed.
        """
        try:
            import urllib3
            from minio import Minio
        except ImportError:
            raise RuntimeError("Minio upload module is not available")

        http_client = urllib3.proxy_from_url(proxies["http"]) if proxies else None

        client = Minio(self.endpoint, self.access_id, self.access_key, http_client=http_client)
        for path in paths:
            try:
                log.info("Uploading %s", path)
                client.fput_object(self.bucket_name, os.path.basename(path), path)
                log.info("Uploaded %s", path)
            except Exception:
                log.error("Upload %s FAILED. See log file for details.", path)
                log.exception("")
