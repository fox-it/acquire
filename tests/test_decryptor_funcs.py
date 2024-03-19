from multiprocessing import Queue
from pathlib import Path
from typing import Optional

import pytest

from acquire.tools.decrypter import check_existing, find_enc_files


def test_find_non_encrypted_files(tmp_path: Path):
    input_files = [tmp_path / "test", tmp_path / "help"]

    for file in input_files:
        file.touch()

    assert find_enc_files(input_files) == []


def test_find_inside_dir(tmp_path: Path):
    output_path = tmp_path.joinpath("output/for/this/test")
    output_path.mkdir(parents=True)

    rel_path = output_path.relative_to(tmp_path)

    expected_outputs = []

    for directory in rel_path.parents:
        searchable_file = tmp_path / directory / "test.enc"
        searchable_file.touch()
        expected_outputs.append(searchable_file)

    assert sorted(find_enc_files([tmp_path])) == sorted(expected_outputs)


@pytest.mark.parametrize(
    "existing,out_path,expected_result,expected_msg",
    [
        pytest.param(None, None, False, None, id="out_path_not_exists"),
        pytest.param("test.tar.gz", None, True, "Output file", id="out_path_exists"),
        pytest.param(None, None, False, None, id="decompressed_not_exists"),
        pytest.param("test.tar", None, True, "Decompressed file", id="decompressed_exists"),
        pytest.param(None, "test.tar", False, None, id="custom_filename_not_exists"),
        pytest.param("test.tar", "test.tar", True, None, id="custom_filename_exists"),
    ],
)
def test_check_existing(
    tmp_path: Path, out_path: str, existing: Optional[str], expected_result: bool, expected_msg: Optional[str]
):
    queue = Queue()
    out_path = tmp_path / (out_path or "test.tar.gz")
    in_path = tmp_path / "test.tar.gz.enc"
    in_path.touch()

    if existing:
        existing = tmp_path / existing
        existing.touch()

    result = check_existing(in_path, out_path, queue)

    assert result == expected_result

    if expected_msg:
        _, msg_result = queue.get(timeout=1)
        assert expected_msg in msg_result
