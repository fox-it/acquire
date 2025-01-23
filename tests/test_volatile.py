from __future__ import annotations

from time import sleep, time

import pytest

from acquire.volatilestream import timeout


def test_timeout() -> None:
    def snooze() -> None:
        sleep(10)

    function = timeout(snooze, timelimit=5)
    start = time()

    with pytest.raises(TimeoutError):
        function()

    end = time()

    assert end - start < 6
