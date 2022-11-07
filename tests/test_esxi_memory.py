from unittest.mock import patch

import pytest

from acquire.esxi import EsxiMemoryManager


def test_vsish_command():
    memory = EsxiMemoryManager()
    with patch("subprocess.check_output", return_value=b"hello"):
        assert memory._execute_vsish_command(["hello", "world"]) == "hello"


@pytest.mark.parametrize(
    "command_output, expected_result",
    [(b"1", "1"), (b"1 2", "1")],
)
def test_process_number(command_output, expected_result):
    memory = EsxiMemoryManager()
    with patch("subprocess.check_output", return_value=command_output):
        assert memory._get_group_id() == expected_result


def test_process_number_empty():
    memory = EsxiMemoryManager()
    with patch("subprocess.check_output", return_value=b""):
        with pytest.raises(ValueError):
            memory._get_group_id()


def test_get_scheme():
    memory = EsxiMemoryManager()
    with patch("subprocess.check_output", return_value=b"hello:10"):
        assert memory._get_memory_scheme() == {"hello": "10"}
