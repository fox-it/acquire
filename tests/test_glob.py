from textwrap import indent

import pytest

from acquire.acquire import MODULES


@pytest.mark.parametrize("module", MODULES.keys())
def test_validate_module_spec(module):
    data_in_spec = []
    for spec in MODULES[module].SPEC:
        type, collectable, *_ = spec
        if type == "glob":
            data_in_spec.append(spec + ("*" in collectable,))
        else:
            data_in_spec.append(spec + ("*" not in collectable,))

    faulty_specs = list(filter(lambda x: x[-1] is False, data_in_spec))
    formatted_specs = "\n".join([f"({spec[0]!r}, {spec[1]!r}) was faulty" for spec in faulty_specs])
    assert len(faulty_specs) == 0, f"{module}:\n{indent(formatted_specs, prefix='    ')}"
