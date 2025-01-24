from __future__ import annotations

from argparse import Namespace
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from acquire.acquire import acquire_children_and_targets
from acquire.gui import GUI

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target


@pytest.mark.parametrize(
    ("num_children", "skip_parent", "auto_upload", "expected_shards"),
    [
        (0, False, False, [90]),  # 90 (default, leaves 10% for final 'step')
        (0, False, True, [50]),  # 50% till upload (upload progresses in plugin)
        (1, False, False, [45, 90]),  # two children to 90%
        (1, True, False, [90]),  # without parent, it's just one target - so 90%
        (1, False, True, [25, 50]),  # two children to 50%
        (1, True, True, [50]),  # one till upload (50%)
        (2, False, False, [30, 60, 90]),  # two children + parent till 90%
        (2, False, True, [16, 33, 50]),  # two children + parent till 50%
        (50, False, True, list(range(51))),  # Should not be zero filled...
    ],
)
@patch("acquire.gui.base.Stub", spec=True)
@patch("acquire.acquire.acquire_target", create=True)
def test_gui(
    mock_target: Target, gui: GUI, num_children: int, skip_parent: bool, auto_upload: bool, expected_shards: list[int]
) -> None:
    def list_children() -> Iterator[Target]:
        yield from [mock_target] * num_children

    mock_target.list_children = list_children

    class Diagnostic_GUI(MagicMock):
        @property
        def shard(self) -> int:
            return 0

        @shard.setter
        def shard(self, shard: int) -> None:
            shards.append(shard)

    GUI.__new__ = lambda x: Diagnostic_GUI()
    shards = []
    args = Namespace(child=False, auto_upload=auto_upload, children=True, skip_parent=skip_parent, start_time=0)
    acquire_children_and_targets(mock_target, args)
    assert shards == expected_shards
