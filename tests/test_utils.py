import argparse
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from dissect.target import Target
from dissect.target.helpers.fsutil import TargetPath

from acquire.acquire import MODULES, PROFILES, VOLATILE
from acquire.utils import (
    check_and_set_acquire_args,
    check_and_set_log_args,
    create_argument_parser,
    normalize_path,
)


def get_args(**kwargs) -> argparse.Namespace:
    default_args = {
        "no_log": True,
        "log": None,
        "output": Path("."),
        "children": False,
        "upload": None,
        "auto_upload": False,
        "public_key": None,
    }

    parser = create_argument_parser(PROFILES, VOLATILE, MODULES)
    default_args = dict(parser.parse_args(args=[])._get_kwargs())
    default_args.update(kwargs)

    args = argparse.Namespace(**default_args)
    return args


def get_mock_path(
    is_dir: bool = True,
    exists: bool = True,
    parent_is_dir: bool = True,
    tree_depth: int = 1,
) -> MagicMock:
    mock_path = MagicMock(spec_set=Path)
    mock_path.__str__ = lambda _: "/some/path"

    if exists:
        mock_path.is_dir.return_value = is_dir
        mock_path.is_file.return_value = not is_dir
    else:
        mock_path.is_dir.return_value = False
        mock_path.is_file.return_value = False

    mock_path.exists.return_value = exists

    mock_parent = None
    if tree_depth:
        mock_parent = get_mock_path(is_dir=parent_is_dir, tree_depth=(tree_depth - 1))
    mock_path.parent = mock_parent

    return mock_path


def test_check_and_set_log_args_no_log() -> None:
    args = get_args(no_log=True)
    with patch("acquire.utils.get_utc_now_str", return_value="foo"):
        check_and_set_log_args(args)

    assert args.start_time == "foo"
    assert args.log_path is None
    assert not args.log_to_dir
    assert not args.log_delay


@pytest.mark.parametrize(
    "arg_name",
    [
        "log",
        "output",
    ],
)
@pytest.mark.parametrize(
    "mock_path, log_to_dir, log_delay",
    [
        # Log to a directory
        (get_mock_path(), True, True),
        # Log to a file and the file already exists
        (get_mock_path(is_dir=False), False, False),
        # Log to a file which does not yet exist, but it's parent directory does
        (get_mock_path(exists=False), False, False),
    ],
)
def test_check_and_set_log_args(
    arg_name: str,
    mock_path: MagicMock,
    log_to_dir: bool,
    log_delay: bool,
) -> None:
    args = get_args(**{arg_name: mock_path})
    with patch("acquire.utils.get_utc_now_str", return_value="foo"):
        check_and_set_log_args(args)

    assert args.start_time == "foo"
    assert args.log_path == mock_path
    assert args.log_to_dir == log_to_dir
    assert args.log_delay == log_delay


def test_check_and_set_log_args_fail_log_to_file_with_children() -> None:
    mock_path = get_mock_path(is_dir=False)
    args = get_args(log=mock_path, children=True)
    with pytest.raises(ValueError, match="Log path must be a directory when using multiple targets or --children"):
        check_and_set_log_args(args)


def test_check_and_set_log_args_fail_log_to_path_not_exists() -> None:
    mock_path = get_mock_path(exists=False, parent_is_dir=False)
    args = get_args(log=mock_path)
    with pytest.raises(ValueError, match="Log path doesn't exist: /some/path"):
        check_and_set_log_args(args)


@pytest.mark.parametrize(
    "arg_name",
    [
        "upload",
        "auto_upload",
    ],
)
def test_check_and_set_acquire_args_upload_auto_upload(arg_name: str) -> None:
    cagent_key = "bar"
    config = {
        "upload": {"mode": "foo"},
        "cagent_key": cagent_key,
    }

    mock_upload_plugin = MagicMock()
    upload_plugins = {"foo": mock_upload_plugin}

    args = get_args(**{arg_name: True, "config": config})
    check_and_set_acquire_args(args, upload_plugins)


@pytest.mark.parametrize(
    "arg_name",
    [
        "upload",
        "auto_upload",
    ],
)
@pytest.mark.parametrize(
    "upload_config, plugin_side_effect, error_match",
    [
        (
            {},
            None,
            "Uploading is not configured",
        ),
        (
            {"upload": {}},
            None,
            "Uploading is not configured",
        ),
        (
            {"upload": {"mode": "bar"}},
            None,
            "Invalid upload mode: bar",
        ),
        (
            {"upload": {"mode": "foo"}},
            ValueError("Plugin init error"),
            "Plugin init error",
        ),
    ],
)
def test_check_and_set_acquire_args_upload_auto_upload_fail(
    arg_name: str, upload_config: dict, plugin_side_effect: bool, error_match: str
) -> None:
    config = {"cagent_key": "bar"}
    config.update(upload_config)

    mock_upload_plugin = MagicMock()
    if plugin_side_effect:
        mock_upload_plugin.side_effect = plugin_side_effect
    upload_plugins = {"foo": mock_upload_plugin}

    args = get_args(**{arg_name: True, "config": config})

    with pytest.raises(ValueError, match=error_match):
        check_and_set_acquire_args(args, upload_plugins)


@pytest.mark.parametrize(
    "children, arg_name, output",
    [
        # Output without children to a directory
        (
            False,
            "output",
            get_mock_path(),
        ),
        # Output with children to a directory
        (
            True,
            "output",
            get_mock_path(),
        ),
        # Output_file without children to a file
        (
            False,
            "output_file",
            get_mock_path(is_dir=False),
        ),
    ],
)
def test_check_and_set_acquire_args_output(children: bool, arg_name: str, output: Path) -> None:
    args = get_args(**{"children": children, arg_name: output, "config": {}})

    result = check_and_set_acquire_args(args, MagicMock())

    assert result is None


@pytest.mark.parametrize(
    "children, arg_name, output, error_match",
    [
        # Output_file and children defined at the same time
        (
            True,
            "output_file",
            get_mock_path(is_dir=False),
            "--children can not be used with --output-file. Use --output instead",
        ),
        # Output_file is a directory
        (
            False,
            "output_file",
            get_mock_path(),
            "--output-file must be a path to a file in an existing directory",
        ),
        # Output_file has a non-existing parent directory
        (
            False,
            "output_file",
            get_mock_path(is_dir=False, parent_is_dir=False),
            "--output-file must be a path to a file in an existing directory",
        ),
        # Output is a non-existing directory
        (
            False,
            "output",
            get_mock_path(exists=False),
            "Output directory doesn't exist or is a file: /some/path",
        ),
        # Output is a file
        (
            False,
            "output",
            get_mock_path(exists=False, is_dir=False),
            "Output directory doesn't exist or is a file: /some/path",
        ),
    ],
)
def test_check_and_set_acquire_args_output_fail(children: bool, arg_name: str, output: Path, error_match: str) -> None:
    args = get_args(**{"children": children, arg_name: output, "config": {}})

    with pytest.raises(ValueError, match=error_match):
        check_and_set_acquire_args(args, MagicMock())


def test_check_and_set_acquire_args_encrypt_with_public_key_config() -> None:
    config = {"public_key": "PUBLIC KEY"}

    args = get_args(encrypt=True, config=config)
    check_and_set_acquire_args(args, MagicMock())

    assert args.public_key == "PUBLIC KEY"


def test_check_and_set_acquire_args_encrypt_with_public_key_arg() -> None:
    mock_path = get_mock_path(is_dir=False)
    mock_path.read_text = lambda: "PUBLIC KEY"

    args = get_args(encrypt=True, public_key=mock_path, config={})
    check_and_set_acquire_args(args, MagicMock())

    assert args.public_key == "PUBLIC KEY"


@pytest.mark.parametrize(
    "public_key",
    [
        None,
        get_mock_path(),
    ],
)
def test_check_and_set_acquire_args_encrypt_without_public_key_fail(public_key: Optional[Path]) -> None:
    args = get_args(encrypt=True, public_key=public_key, config={})

    with pytest.raises(ValueError, match=r"No public key available \(embedded or argument\)"):
        check_and_set_acquire_args(args, MagicMock())


@pytest.mark.parametrize(
    "path, resolve_parents, preserve_case, sysvol, os, result, as_path",
    [
        (
            "/foo/bar",
            False,
            False,
            None,
            "dummy",
            "/foo/bar",
            True,
        ),
        (
            "/foo/BAR",
            False,
            False,
            None,
            "dummy",
            "/foo/BAR",
            True,
        ),
        (
            "/foo/BAR",
            False,
            True,
            None,
            "dummy",
            "/foo/BAR",
            True,
        ),
        (
            "/bla/../foo/bar",
            False,
            False,
            None,
            "dummy",
            "/bla/../foo/bar",
            True,
        ),
        (
            "/bla/../foo/bar",
            True,
            False,
            None,
            "dummy",
            "/foo/bar",
            True,
        ),
        (
            "c:\\foo\\bar",
            False,
            False,
            "c:",
            "windows",
            "c:/foo/bar",
            True,
        ),
        (
            "C:\\foo\\bar",
            False,
            False,
            "c:",
            "windows",
            "c:/foo/bar",
            True,
        ),
        (
            "\\??\\C:\\foo\\bar",
            False,
            False,
            "c:",
            "windows",
            "c:/foo/bar",
            True,
        ),
        (
            "\\??\\c:\\foo\\bar",
            False,
            False,
            "c:",
            "windows",
            "c:/foo/bar",
            True,
        ),
        (
            "D:\\foo\\bar",
            False,
            False,
            "c:",
            "windows",
            "d:/foo/bar",
            True,
        ),
        (
            "D:\\Foo\\BAR",
            False,
            True,
            "c:",
            "windows",
            "D:/Foo/BAR",
            True,
        ),
        (
            "sysvol\\foo\\bar",
            False,
            True,
            "c:",
            "windows",
            "C:/foo/bar",
            True,
        ),
        (
            "sysvol/foo/bar",
            False,
            True,
            None,
            "dummy",
            "sysvol/foo/bar",
            True,
        ),
        (
            "/??/sysvol/foo/bar",
            False,
            True,
            None,
            "dummy",
            "/??/sysvol/foo/bar",
            True,
        ),
        (
            "sysvol/Foo/../BAR",
            True,
            False,
            "c:",
            "windows",
            "c:/bar",
            True,
        ),
        (
            "sysvol/Foo/../BAR",
            True,
            True,
            "c:",
            "windows",
            "C:/Foo/../BAR",
            False,
        ),
        (
            "/??/sysvol/Foo/../BAR",
            True,
            False,
            "c:",
            "windows",
            "c:/foo/../bar",
            False,
        ),
        (
            "sysvol",
            False,
            True,
            "SYSVOL",
            "windows",
            "sysvol",
            False,
        ),
        (
            "a:",
            False,
            True,
            "C:",
            "windows",
            "A:",
            False,
        ),
    ],
)
def test_utils_normalize_path(
    mock_target: Target,
    path: str,
    resolve_parents: bool,
    preserve_case: bool,
    sysvol: Optional[str],
    os: str,
    result: str,
    as_path: bool,
) -> None:
    case_sensitive = True
    if os == "windows":
        case_sensitive = False

    with (
        patch.object(mock_target, "os", new=os),
        patch.object(mock_target.fs, "_case_sensitive", new=case_sensitive),
        patch.object(mock_target.fs, "_alt_separator", new=("\\" if os == "windows" else "/")),
        patch.dict(mock_target.props, {"sysvol_drive": sysvol}),
    ):
        if as_path:
            path = TargetPath(mock_target.fs, path)

        normalized_path = normalize_path(
            mock_target,
            path,
            resolve_parents=resolve_parents,
            preserve_case=preserve_case,
        )

        assert normalized_path == result
