from __future__ import annotations

from logging import getLogger
from pathlib import Path
from typing import TYPE_CHECKING, Any

from acquire.uploaders.plugin import UploaderPlugin

if TYPE_CHECKING:
    from azure.storage.blob import ContainerClient

log = getLogger(__name__)


class AzureStorage(UploaderPlugin):
    def __init__(self, upload: dict[str, str], **kwargs: dict[str, Any]) -> None:
        """An uploader plugin that uploads files to Azure Blob Storage using a container-level SAS URL.

        Args:
            upload: Contains the SAS URL and optional folder prefix to use for the transfer.

        Raises:
            ValueError: When the configuration is invalid.
        """
        self.sas_url = upload.get("sas_url")
        self.folder = upload.get("folder", "").rstrip("/")

        if not self.sas_url:
            raise ValueError("Invalid Azure Storage upload configuration: sas_url is required")

    def prepare_client(self, paths: list[Path], proxies: dict[str, str] | None = None) -> Any:
        """Prepares an Azure ContainerClient used to upload files.

        Args:
            paths: The files to upload.
            proxies: Not supported

        Raises:
            RuntimeError: When the azure-storage-blob module is not installed.
        """
        try:
            from azure.storage.blob import ContainerClient  # noqa: PLC0415
        except ImportError:
            raise RuntimeError("Azure Storage upload module is not available. Install 'azure-storage-blob'.")

        if proxies:
            self.log.warning("Proxy configurations are not supported for Azure Storage uploads. Ignoring proxies.")

        return ContainerClient.from_container_url(self.sas_url)

    def upload_file(self, client: ContainerClient, path: Path) -> None:
        """Uploads a single file to Azure Blob Storage.

        Args:
            client: The Azure ContainerClient to use for the upload.
            path: The path of the file to upload.
        """
        destination_path = path.name
        if self.folder:
            destination_path = Path(self.folder) / path.name

        with path.open("rb") as data:
            client.upload_blob(name=str(destination_path), data=data, overwrite=True)

    def finish(self, client: Any) -> None:
        """Closes the Azure ContainerClient.

        Args:
            client: The Azure ContainerClient to close.
        """
        client.close()
