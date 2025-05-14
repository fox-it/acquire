from __future__ import annotations

from textwrap import indent

import pytest

from acquire.acquire import MODULES


@pytest.mark.parametrize("module", MODULES.keys())
def test_validate_module_spec(module: str) -> None:
    data_in_spec = []
    for spec in MODULES[module].SPEC:
        type_, collectable, *_ = spec
        if type_ == "glob":
            data_in_spec.append((*spec, "*" in collectable))
        elif type_ == "path":
            data_in_spec.append((*spec, "*" not in collectable))
        else:
            assert type_ == "command", "Only 'path', 'glob' or 'command' are allowed inside a spec"

    faulty_specs = list(filter(lambda x: x[-1] is False, data_in_spec))
    formatted_specs = "\n".join([f"({spec[0]!r}, {spec[1]!r}) was faulty" for spec in faulty_specs])
    assert len(faulty_specs) == 0, f"{module}:\n{indent(formatted_specs, prefix='    ')}"
