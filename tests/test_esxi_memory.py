from __future__ import annotations

from unittest.mock import patch

import pytest

from acquire.esxi import EsxiMemoryManager


def test_vsish_command() -> None:
    memory = EsxiMemoryManager()
    with patch("subprocess.check_output", return_value=b"hello"):
        assert memory._execute_vsish_command(["hello", "world"]) == "hello"


@pytest.mark.parametrize(
    ("command_output", "expected_result"),
    [(b"1", "1"), (b"1 2", "1")],
)
def test_process_number(command_output: bytes, expected_result: str) -> None:
    memory = EsxiMemoryManager()
    with patch("subprocess.check_output", return_value=command_output):
        assert memory._get_group_id() == expected_result


def test_process_number_empty() -> None:
    memory = EsxiMemoryManager()
    with (
        patch("subprocess.check_output", return_value=b""),
        pytest.raises(ValueError, match="Something went wrong, group_id was empty"),
    ):
        memory._get_group_id()


def test_get_scheme() -> None:
    memory = EsxiMemoryManager()
    with patch("subprocess.check_output", return_value=b"hello:10"):
        assert memory._get_memory_scheme() == {"hello": "10"}
