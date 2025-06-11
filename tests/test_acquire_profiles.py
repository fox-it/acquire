import pytest
from dissect.target.plugin import OSPlugin
from dissect.target.plugins.os.default._os import DefaultOSPlugin
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.plugins.os.unix.linux.fortios._os import FortiOSPlugin
from dissect.target.target import Target

from acquire.acquire import PROFILES, _get_modules_for_profile


@pytest.mark.parametrize(
    argnames=("os_plugin", "expected_value"),
    argvalues=[
        (
            FortiOSPlugin,
            ["Etc", "Boot", "Home", "SSH", "Var"],
        ),
        (
            LinuxPlugin,
            ["Etc", "Boot", "Home", "SSH", "Var"],
        ),
        (
            DefaultOSPlugin,
            [],
        ),
    ],
)
def test_profile_selection_linux(os_plugin: OSPlugin, expected_value: list[str]) -> None:
    target = Target()
    target._os_plugin = os_plugin
    target.apply()

    assert (
        list(_get_modules_for_profile(target, "minimal", PROFILES, "No collection set for OS '%s' with profile '%s'"))
        == expected_value
    )
