from __future__ import annotations

from pathlib import Path
from typing import Callable
from unittest.mock import Mock, patch

import pytest

from acquire.uploaders.minio import MinIO
from acquire.uploaders.plugin import upload_files_using_uploader
from acquire.uploaders.plugin_registry import UploaderRegistry


@pytest.fixture
def plugin_registry() -> UploaderRegistry:
    return UploaderRegistry("")


@pytest.fixture
def load_plugin(plugin_registry: UploaderRegistry) -> UploaderRegistry:
    plugin_registry.register("cloud", MinIO)
    return plugin_registry


@pytest.fixture
def minio_plugin(load_plugin: UploaderRegistry) -> type[MinIO]:
    return load_plugin.get("cloud")


@pytest.fixture
def minio_instance(minio_plugin: type[MinIO]) -> MinIO:
    return minio_plugin(upload={"endpoint": "test", "access_id": "test", "access_key": "test", "bucket": "test"})


@pytest.mark.parametrize(
    "arguments",
    [
        {"endpoint": "test", "access_id": "test", "access_key": "test", "bucket": "test"},
        {"endpoint": "test", "access_id": "test", "access_key": "test", "bucket": "test", "hello_world": "test"},
    ],
)
def test_minio_inputs(minio_plugin: type[MinIO], arguments: dict) -> None:
    minio = minio_plugin(upload=arguments)

    assert minio.endpoint == "test"
    assert minio.access_id == "test"
    assert minio.access_key == "test"
    assert minio.bucket_name == "test"


def test_minio_typeerror(minio_plugin: type[MinIO]) -> None:
    """Not enough arguments provided."""
    arguments = {}
    with pytest.raises(TypeError):
        minio_plugin(**arguments)


def test_minio_valueerror(minio_plugin: type[MinIO]) -> None:
    """Empty arguments."""
    arguments = {"endpoint": "", "access_id": "", "access_key": "", "bucket": ""}
    with pytest.raises(ValueError, match="Invalid cloud upload configuration"):
        minio_plugin(upload=arguments)


def test_upload_files(minio_instance: MinIO) -> None:
    # Generates an internal error, which is caught
    upload_files_using_uploader(minio_instance, [Path("hello")])


def test_upload_file_multiple_failures(minio_instance: MinIO) -> None:
    mocked_upload = Mock()
    mocked_upload.side_effect = [Exception, Exception, Exception, "Hello"]
    minio_instance.upload_file = mocked_upload

    with patch("acquire.uploaders.plugin.log") as mocked_logger:
        # Only three retry attempts get made
        upload_files_using_uploader(minio_instance, [Path("hello")])
        mocked_logger.error.assert_called_with("Upload %s FAILED. See log file for details. Retrying", Path("hello"))

    # One extra gives a value error.
    mocked_upload.side_effect = [Exception, Exception, Exception, Exception]
    with patch("acquire.uploaders.plugin.log") as mocked_logger:
        upload_files_using_uploader(minio_instance, [Path("hello")])
        mocked_logger.error.assert_called_with("Upload %s FAILED after too many attempts. Stopping.", Path("hello"))


def test_minio_folder_initialization(minio_plugin: Callable) -> None:
    arguments = {"endpoint": "test", "access_id": "test", "access_key": "test", "bucket": "test", "folder": "Uploads/"}
    minio = minio_plugin(upload=arguments)
    assert minio.folder == "Uploads"

    arguments["folder"] = "Uploads/test_folder"
    minio_no_backslash = minio_plugin(upload=arguments)
    assert minio_no_backslash.folder == "Uploads/test_folder"

    arguments.pop("folder")
    minio_no_folder = minio_plugin(upload=arguments)
    assert minio_no_folder.folder == ""


def test_upload_file_with_folder(minio_instance: MinIO) -> None:
    mock_client = Mock()
    test_path = Path("example.txt")
    minio_instance.folder = "test_folder"
    minio_instance.upload_file(mock_client, test_path)

    mock_client.fput_object.assert_called_once_with("test", "test_folder/example.txt", test_path)


def test_upload_file_without_folder(minio_instance: MinIO) -> None:
    mock_client = Mock()
    test_path = Path("example.txt")
    minio_instance.folder = ""
    minio_instance.upload_file(mock_client, test_path)

    mock_client.fput_object.assert_called_once_with("test", "example.txt", test_path)
