from pathlib import Path

from acquire.tools.decrypter import find_enc_files


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
