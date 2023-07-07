import pytest

from acquire.acquire import MODULES


@pytest.mark.parametrize("module", MODULES.keys())
def test_validate_module_spec(module):
    for spec in MODULES[module].SPEC:
        type, collectable, *_ = spec
        if type == "glob":
            assert "*" in collectable
        else:
            assert "*" not in collectable
