import argparse
import pathlib
import platform
from unittest.mock import MagicMock, patch

import pytest
from dissect.target import Target

from acquire.acquire import MODULES, PROFILES
from acquire.utils import (
    check_and_set_acquire_args,
    check_and_set_log_args,
    create_argument_parser,
    normalize_path,
)


def get_args(**kwargs):
    default_args = {
        "no_log": True,
        "log": None,
        "output": pathlib.Path("."),
        "children": False,
        "upload": None,
        "auto_upload": False,
        "public_key": None,
    }

    parser = create_argument_parser(PROFILES, MODULES)
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
    mock_path = MagicMock(spec_set=pathlib.Path)
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


def test_check_and_set_log_args_no_log():
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
):
    args = get_args(**{arg_name: mock_path})
    with patch("acquire.utils.get_utc_now_str", return_value="foo"):
        check_and_set_log_args(args)

    assert args.start_time == "foo"
    assert args.log_path == mock_path
    assert args.log_to_dir == log_to_dir
    assert args.log_delay == log_delay


def test_check_and_set_log_args_fail_log_to_file_with_children():
    mock_path = get_mock_path(is_dir=False)
    args = get_args(log=mock_path, children=True)
    with pytest.raises(ValueError, match="Log path must be a directory when using --children"):
        check_and_set_log_args(args)


def test_check_and_set_log_args_fail_log_to_path_not_exists():
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
def test_check_and_set_acquire_args_upload_auto_upload(arg_name):
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
def test_check_and_set_acquire_args_upload_auto_upload_fail(arg_name, upload_config, plugin_side_effect, error_match):
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
    "children, output",
    [
        # Output without children to a directory
        (
            False,
            get_mock_path(),
        ),
        # Output with children to a directoy
        (
            True,
            get_mock_path(),
        ),
        # Output without children to a file
        (
            False,
            get_mock_path(is_dir=False),
        ),
        # Output without children to a non-existing file, but the parent directory exists
        (
            False,
            get_mock_path(exists=False),
        ),
    ],
)
def test_check_and_set_acquire_args_output(children, output):
    args = get_args(children=children, output=output, config={})
    result = check_and_set_acquire_args(args, MagicMock())

    assert result is None


@pytest.mark.parametrize(
    "children, output, error_match",
    [
        # Output with children to a file
        (
            True,
            get_mock_path(is_dir=False),
            "Output path must be a directory when using --children",
        ),
        # Output without children to a non-existing file with non-existing parent
        (
            False,
            get_mock_path(exists=False, parent_is_dir=False),
            "Output path doesn't exist: /some/path",
        ),
    ],
)
def test_check_and_set_acquire_args_output_fail(children, output, error_match):
    args = get_args(children=children, output=output, config={})

    with pytest.raises(ValueError, match=error_match):
        check_and_set_acquire_args(args, MagicMock())


def test_check_and_set_acquire_args_encrypt_with_public_key_config():
    config = {"public_key": "PUBLIC KEY"}

    args = get_args(encrypt=True, config=config)
    check_and_set_acquire_args(args, MagicMock())

    assert args.public_key == "PUBLIC KEY"


def test_check_and_set_acquire_args_encrypt_with_public_key_arg():
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
def test_check_and_set_acquire_args_encrypt_without_public_key_fail(public_key):
    args = get_args(encrypt=True, public_key=public_key, config={})

    with pytest.raises(ValueError, match=r"No public key available \(embedded or argument\)"):
        check_and_set_acquire_args(args, MagicMock())


def test_check_and_set_acquire_args_cagent():
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
    "path, resolve, norm_path, case_sensitive, os",
    [
        (
            pathlib.Path("/foo/bar"),
            False,
            "/foo/bar",
            True,
            "dummy",
        ),
        (
            pathlib.Path("/foo/BAR"),
            False,
            "/foo/bar",
            False,
            "dummy",
        ),
        (
            pathlib.Path("/foo/BAR"),
            False,
            "/foo/BAR",
            True,
            "dummy",
        ),
        (
            pathlib.Path("/foo/../bar"),
            False,
            "/foo/../bar",
            True,
            "dummy",
        ),
        (
            pathlib.Path("/foo/../foo/bar"),
            True,
            "/foo/bar",
            True,
            "dummy",
        ),
        (
            pathlib.PureWindowsPath("c:\\foo\\bar"),
            False,
            "sysvol/foo/bar",
            False,
            "windows",
        ),
        (
            pathlib.PureWindowsPath("C:\\foo\\bar"),
            False,
            "sysvol/foo/bar",
            False,
            "windows",
        ),
        (
            pathlib.PureWindowsPath("\\??\\C:\\foo\\bar"),
            False,
            "sysvol/foo/bar",
            False,
            "windows",
        ),
        (
            pathlib.PureWindowsPath("\\??\\c:\\foo\\bar"),
            False,
            "sysvol/foo/bar",
            False,
            "windows",
        ),
        (
            pathlib.PureWindowsPath("D:\\foo\\bar"),
            False,
            "d:/foo/bar",
            False,
            "windows",
        ),
    ],
)
@pytest.mark.skipif(platform.system() == "Windows", reason="Compares Posix Paths. Needs to be fixed.")
def test_utils_normalize_path(
    mock_target: Target,
    path: pathlib.Path,
    resolve: bool,
    norm_path: str,
    case_sensitive: bool,
    os: str,
) -> None:
    with patch.object(mock_target, "os", new=os):
        with patch.object(mock_target.fs, "_case_sensitive", new=case_sensitive):
            assert normalize_path(mock_target, path, resolve=resolve) == norm_path
