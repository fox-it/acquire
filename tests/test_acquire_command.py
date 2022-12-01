from argparse import Namespace
from typing import List
from unittest.mock import patch

import pytest

from acquire.acquire import (
    CONFIG,
    MODULES,
    PROFILES,
    create_argument_parser,
    parse_acquire_args,
)


@pytest.fixture
def acquire_parser_args(config: List, argument_list: List) -> Namespace:
    CONFIG["arguments"] = config
    with patch("argparse._sys.argv", [""] + argument_list):
        return parse_acquire_args(create_argument_parser(PROFILES, MODULES), config_defaults=CONFIG["arguments"])


@pytest.mark.parametrize("config, argument_list", [([], [])])
def test_no_defaults_in_config(acquire_parser_args):
    assert not acquire_parser_args.force_fallback


@pytest.mark.parametrize("config, argument_list", [(["--force-fallback"], [])])
def test_one_config_default_argument(acquire_parser_args):
    assert acquire_parser_args.force_fallback


@pytest.mark.parametrize("config, argument_list", [(["-f", "test"], ["-f", "best"])])
def test_config_default_argument_override(acquire_parser_args):
    assert acquire_parser_args.file == ["best"]
