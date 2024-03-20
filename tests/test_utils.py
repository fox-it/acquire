import argparse
import platform
from pathlib import Path, PureWindowsPath
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from dissect.target import Target

from acquire.acquire import MODULES, PROFILES, VOLATILE
from acquire.utils import (
    check_and_set_acquire_args,
    check_and_set_log_args,
    create_argument_parser,
    normalize_path,
    normalize_sysvol,
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
    with pytest.raises(ValueError, match="Log path must be a directory when using --children"):
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

    if arg_name == "upload":
        assert "cagent_key" not in args
    else:
        assert args.cagent_key == cagent_key


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
            "--children can not be used with --output_file. Use --output instead",
        ),
        # Output_file is a directory
        (
            False,
            "output_file",
            get_mock_path(),
            "--output_file must be a path to a file in an existing directory",
        ),
        # Output_file has a non-existing parent directory
        (
            False,
            "output_file",
            get_mock_path(is_dir=False, parent_is_dir=False),
            "--output_file must be a path to a file in an existing directory",
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


def test_check_and_set_acquire_args_cagent() -> None:
    cagent_key = "KEY"
    cagent_certificate = "CERT"
    config = {
        "cagent_key": cagent_key,
        "cagent_certificate": cagent_certificate,
    }
    args = get_args(config=config)
    check_and_set_acquire_args(args, MagicMock())

    assert args.cagent_key == cagent_key
    assert args.cagent_certificate == cagent_certificate


@pytest.mark.parametrize(
    "path, sysvol, resolve, lower_case, case_sensitive, os, result",
    [
        (
            Path("/foo/bar"),
            None,
            False,
            True,
            True,
            "dummy",
            "/foo/bar",
        ),
        (
            Path("/foo/BAR"),
            None,
            False,
            True,
            False,
            "dummy",
            "/foo/bar",
        ),
        (
            Path("/foo/BAR"),
            None,
            False,
            True,
            True,
            "dummy",
            "/foo/BAR",
        ),
        (
            Path("/foo/../bar"),
            None,
            False,
            True,
            True,
            "dummy",
            "/foo/../bar",
        ),
        (
            Path("/foo/../foo/bar"),
            None,
            True,
            True,
            True,
            "dummy",
            "/foo/bar",
        ),
        (
            PureWindowsPath("c:\\foo\\bar"),
            "c:",
            False,
            True,
            False,
            "windows",
            "c:/foo/bar",
        ),
        (
            PureWindowsPath("C:\\foo\\bar"),
            "c:",
            False,
            True,
            False,
            "windows",
            "c:/foo/bar",
        ),
        (
            PureWindowsPath("\\??\\C:\\foo\\bar"),
            "c:",
            False,
            True,
            False,
            "windows",
            "c:/foo/bar",
        ),
        (
            PureWindowsPath("\\??\\c:\\foo\\bar"),
            "c:",
            False,
            True,
            False,
            "windows",
            "c:/foo/bar",
        ),
        (
            PureWindowsPath("D:\\foo\\bar"),
            "c:",
            False,
            True,
            False,
            "windows",
            "d:/foo/bar",
        ),
        (
            PureWindowsPath("D:\\Foo\\BAR"),
            "c:",
            False,
            False,
            False,
            "windows",
            "D:/Foo/BAR",
        ),
        (
            PureWindowsPath("sysvol\\foo\\bar"),
            "c:",
            False,
            False,
            False,
            "windows",
            "c:/foo/bar",
        ),
    ],
)
def test_utils_normalize_path(
    mock_target: Target,
    path: Path,
    sysvol: Optional[str],
    resolve: bool,
    lower_case: bool,
    case_sensitive: bool,
    os: str,
    result: str,
) -> None:
    with patch.object(mock_target, "os", new=os), patch.object(
        mock_target.fs, "_case_sensitive", new=case_sensitive
    ), patch.dict(mock_target.props, {"sysvol_drive": sysvol}):
        resolved_path = normalize_path(mock_target, path, resolve=resolve, lower_case=lower_case)

        if platform.system() == "Windows":
            # A resolved path on windows adds a C:\ prefix. So we check if it ends with our expected
            # path string
            assert resolved_path.endswith(result)
        else:
            assert resolved_path == result


@pytest.mark.parametrize(
    "path, sysvol, result",
    [
        ("sysvol/foo/bar", "c:", "c:/foo/bar"),
        ("/sysvol/foo/bar", "c:", "c:/foo/bar"),
    ],
)
def test_normalize_sysvol(path: str, sysvol: str, result: str) -> None:
    assert normalize_sysvol(path, sysvol) == result
