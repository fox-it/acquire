from __future__ import annotations

from unittest.mock import Mock, patch

from acquire.uploaders.plugin_registry import PluginRegistry


def test_registry_functionality() -> None:
    data = PluginRegistry[int]("<undefined>")
    data.register("name", int)

    assert data.get("name")(20) == 20


def test_registry_functionality_iterator() -> None:
    plugins = [("test", str), ("best", int)]
    data = PluginRegistry("<undefined>", plugins)

    assert len(data.items()) == 2
    assert data.get("best")(20) == 20
    assert data.get("test")("hello") == "hello"


def test_registry_entrypoint() -> None:
    mocked_output = Mock()
    with patch.object(PluginRegistry, "_find_entrypoint_data", return_value=[mocked_output]):
        data = PluginRegistry("<undefined>")
        assert data.get(mocked_output.name) == mocked_output.load.return_value


def test_registry_entrypoint_failed() -> None:
    mocked_output = Mock()
    mocked_output.load.side_effect = [ModuleNotFoundError]
    data = PluginRegistry("-")

    with patch.object(PluginRegistry, "_find_entrypoint_data", return_value=[mocked_output]):
        data.load_entrypoint_plugins("test")
        assert len(data.items()) == 0
