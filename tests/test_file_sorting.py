from __future__ import annotations

from pathlib import Path

import pytest

from acquire.acquire import sort_files


@pytest.mark.parametrize(
    ("input", "expected_output"),
    [
        (
            ["test.log", "test.tar"],
            [Path("test.tar"), Path("test.log")],
        ),
        (
            ["test.json", "test.log", "test.tar"],
            [Path("test.tar"), Path("test.json"), Path("test.log")],
        ),
        (
            ["test.json", "test.log", "test.asdf"],
            [Path("test.asdf"), Path("test.json"), Path("test.log")],
        ),
        (
            ["test3.log", "test2.log", "test1.log"],
            [Path("test1.log"), Path("test2.log"), Path("test3.log")],
        ),
    ],
)
def test_file_sorting(input: list[str], expected_output: list[str]) -> None:
    assert sort_files(input) == expected_output
