from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from acquire.acquire import (
    MODULES,
    PROFILES,
    VOLATILE,
    create_argument_parser,
    parse_acquire_args,
)

if TYPE_CHECKING:
    from argparse import Namespace


@pytest.fixture
def acquire_parser_args(config: list[str], argument_list: list[str]) -> Namespace:
    config_dict = {}
    config_dict["arguments"] = config
    with patch("argparse._sys.argv", ["", *argument_list]):
        return parse_acquire_args(create_argument_parser(PROFILES, VOLATILE, MODULES), config=config_dict)[0]


@pytest.mark.parametrize(("config", "argument_list"), [([], [])])
def test_no_defaults_in_config(acquire_parser_args: Namespace) -> None:
    assert not acquire_parser_args.force_fallback


@pytest.mark.parametrize(("config", "argument_list"), [(["--force-fallback"], [])])
def test_one_config_default_argument(acquire_parser_args: Namespace) -> None:
    assert acquire_parser_args.force_fallback


@pytest.mark.parametrize(("config", "argument_list"), [(["-f", "test"], ["-f", "best"])])
def test_config_default_argument_override(acquire_parser_args: Namespace) -> None:
    assert acquire_parser_args.file == ["best"]


@pytest.mark.parametrize(("config", "argument_list"), [([], ["target1", "target2"])])
def test_local_target_fallbactargets(acquire_parser_args: Namespace) -> None:
    assert acquire_parser_args.targets == ["target1", "target2"]


@pytest.mark.parametrize(
    ("config", "argument_list", "arg_to_test", "expected_value"),
    [
        (["--etc"], ["--no-etc"], "etc", False),
        (["--no-etc"], ["--etc"], "etc", True),
        (["--encrypt"], ["--no-encrypt"], "encrypt", False),
        (["--no-encrypt"], ["--encrypt"], "encrypt", True),
        (["--encrypt", "--ssh"], ["--no-ssh"], "ssh", False),
        (["--private-keys"], ["--no-private-keys"], "private_keys", False),
        (["--no-private-keys"], ["--private-keys"], "private_keys", True),
    ],
)
def test_overwrites_optionals(acquire_parser_args: Namespace, arg_to_test: str, expected_value: bool) -> None:
    assert getattr(acquire_parser_args, arg_to_test) is expected_value
