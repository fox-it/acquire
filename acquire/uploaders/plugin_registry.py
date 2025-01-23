from __future__ import annotations

import logging
from importlib import metadata
from typing import TYPE_CHECKING, Generic, TypeVar

from acquire.uploaders.plugin import UploaderPlugin

if TYPE_CHECKING:
    from collections.abc import ItemsView, Iterator

T = TypeVar("T")

log = logging.getLogger("acquire")


class PluginRegistry(Generic[T]):
    """Maintains a collection of plugins.

    Includes functionality to load plugins from classes defined in entrypoints.
    """

    def __init__(self, name: str, plugins: Iterator[tuple[str, T]] | None = None):
        """Create a plugin registry, with an optional plugin Iterator.

        Args:
            name: The name of an entrypoint we want to load plugins from.
            plugins: An Iterator that contains plugins that we want to register.
        """
        self.plugins: dict[str, T] = {}

        plugins = plugins or []
        for plugin_name, klass in plugins:
            self.register(plugin_name, klass)

        self.load_entrypoint_plugins(name)

    def register(self, name: str, plugin: T) -> None:
        """Registers a plugin to the plugins dictionary.

        Args:
            name: The key of the dictionary.
            plugin: The plugin class to register.
        """
        self.plugins.update({name: plugin})

    def remove(self, name: str) -> None:
        """Removes a plugin from the plugins dictionary.

        Args:
            name: The key to remove.
        """
        self.plugins.pop(name)

    def items(self) -> ItemsView[str, T]:
        """Returns all the items inside the ``plugins`` dictionary"""
        return self.plugins.items()

    def get(self, name: str) -> T:
        return self.plugins.get(name)

    def _find_entrypoint_data(self, entry_point_name: str) -> list[metadata.EntryPoint]:
        """Searches through the entrypoints to find specific entry_point names.

        Args:
            entry_point_name: The name to search for.

        Returns:
            A list with entry_points associated with that name."""
        try:
            entrypoint_plugins = metadata.entry_points()[entry_point_name]
        except KeyError:
            entrypoint_plugins = []
        return entrypoint_plugins

    def load_entrypoint_plugins(self, name: str) -> None:
        """Loads all classes defined in the entrypoints that use the specified ``name``.

        Loads the class loaded from the entrypoint with the form: ``<name>=<path>:<class>``
        as <name> <loaded class>

        Args:
            name: The entrypoint to search for.
        """
        class_plugins = self._find_entrypoint_data(name)

        for ep in class_plugins:
            try:
                # Loads the class of the entrypoint, and registers it.
                self.register(ep.name, ep.load())
                log.debug("Loaded plugin %s", ep)
            except ModuleNotFoundError:  # noqa: PERF203
                log.exception("Entrypoint module could not be loaded")


UploaderRegistry = PluginRegistry[UploaderPlugin]
"""An PluginRegistry instance that registers ``UploaderPlugin`` plugins"""
