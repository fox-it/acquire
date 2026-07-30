from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, mock_open, patch

import pytest

from acquire.uploaders.azure import AzureStorage
from acquire.uploaders.plugin import upload_files_using_uploader
from acquire.uploaders.plugin_registry import UploaderRegistry

if TYPE_CHECKING:
    from collections.abc import Callable


VALID_SAS_URL = "https://account.blob.core.windows.net/container?sv=2021-06-08&sig=abc"


@pytest.fixture
def plugin_registry() -> UploaderRegistry:
    return UploaderRegistry("")


@pytest.fixture
def load_plugin(plugin_registry: UploaderRegistry) -> UploaderRegistry:
    plugin_registry.register("azure", AzureStorage)
    return plugin_registry


@pytest.fixture
def azure_plugin(load_plugin: UploaderRegistry) -> type[AzureStorage]:
    return load_plugin.get("azure")


@pytest.fixture
def azure_instance(azure_plugin: type[AzureStorage]) -> AzureStorage:
    return azure_plugin(upload={"sas_url": VALID_SAS_URL})


@pytest.mark.parametrize(
    "arguments",
    [
        {"sas_url": VALID_SAS_URL},
        {"sas_url": VALID_SAS_URL, "extra_field": "ignored"},
    ],
)
def test_azure_inputs(azure_plugin: type[AzureStorage], arguments: dict) -> None:
    instance = azure_plugin(upload=arguments)

    assert instance.sas_url == VALID_SAS_URL
    assert instance.folder == ""


def test_azure_valueerror_missing_sas_url(azure_plugin: type[AzureStorage]) -> None:
    """Empty sas_url raises ValueError."""
    with pytest.raises(ValueError, match="sas_url is required"):
        azure_plugin(upload={})


def test_azure_valueerror_empty_sas_url(azure_plugin: type[AzureStorage]) -> None:
    """Empty string sas_url raises ValueError."""
    with pytest.raises(ValueError, match="sas_url is required"):
        azure_plugin(upload={"sas_url": ""})


def test_azure_folder_initialization(azure_plugin: Callable) -> None:
    instance_nested = azure_plugin(upload={"sas_url": VALID_SAS_URL, "folder": "Uploads/sub"})
    assert instance_nested.folder == "Uploads/sub"


def test_prepare_client_no_module(azure_instance: AzureStorage) -> None:
    """Raises RuntimeError when azure-storage-blob is not installed."""
    with (
        patch.dict("sys.modules", {"azure.storage.blob": None}),
        pytest.raises(RuntimeError, match="Azure Storage upload module is not available"),
    ):
        azure_instance.prepare_client([])


def _make_azure_module_mock() -> MagicMock:
    """Creates a sys.modules mock for azure.storage.blob that includes the required package hierarchy."""
    mock_blob_module = MagicMock()
    mock_container_client = MagicMock()
    mock_blob_module.ContainerClient = mock_container_client
    return mock_blob_module, mock_container_client


def test_prepare_client_returns_container_client(azure_instance: AzureStorage) -> None:
    mock_blob_module, mock_container_client_cls = _make_azure_module_mock()
    mock_client = MagicMock()
    mock_container_client_cls.from_container_url.return_value = mock_client

    module_patches = {
        "azure": MagicMock(),
        "azure.storage": MagicMock(),
        "azure.storage.blob": mock_blob_module,
    }
    with patch.dict("sys.modules", module_patches):
        client = azure_instance.prepare_client([Path("file.tar")])

    mock_container_client_cls.from_container_url.assert_called_once_with(VALID_SAS_URL)
    assert client is mock_client


def test_upload_file_without_folder(azure_instance: AzureStorage) -> None:
    mock_client = MagicMock()
    test_path = Path("example.tar")

    with patch.object(Path, "open", mock_open(read_data=b"data")):
        azure_instance.upload_file(mock_client, test_path)

    mock_client.upload_blob.assert_called_once()
    call_kwargs = mock_client.upload_blob.call_args
    assert call_kwargs.kwargs["name"] == "example.tar"
    assert call_kwargs.kwargs["overwrite"] is True


def test_upload_file_with_folder(azure_instance: AzureStorage) -> None:
    mock_client = MagicMock()
    test_path = Path("example.tar")
    azure_instance.folder = "forensics/2026"

    with patch.object(Path, "open", mock_open(read_data=b"data")):
        azure_instance.upload_file(mock_client, test_path)

    call_kwargs = mock_client.upload_blob.call_args
    assert call_kwargs.kwargs["name"] == "forensics/2026/example.tar"


def test_finish_closes_client(azure_instance: AzureStorage) -> None:
    mock_client = MagicMock()
    azure_instance.finish(mock_client)
    mock_client.close.assert_called_once()


def test_upload_files_integration(azure_instance: AzureStorage) -> None:
    """Ensures upload_files_using_uploader calls the right lifecycle methods."""
    mock_client = MagicMock()
    azure_instance.prepare_client = MagicMock(return_value=mock_client)
    azure_instance.upload_file = MagicMock()
    azure_instance.finish = MagicMock()

    upload_files_using_uploader(azure_instance, [Path("hello.tar")])

    azure_instance.prepare_client.assert_called_once()
    azure_instance.upload_file.assert_called_once_with(mock_client, Path("hello.tar"))
    azure_instance.finish.assert_called_once_with(mock_client)
