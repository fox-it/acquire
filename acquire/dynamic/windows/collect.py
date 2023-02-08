from logging import getLogger
from typing import Iterable, Optional

from acquire.dynamic.windows.exceptions import AccessDeniedError
from acquire.dynamic.windows.handles import Handle, get_handles
from acquire.dynamic.windows.named_objects import NamedObject, NamedObjectType
from acquire.dynamic.windows.ntdll import (
    close_handle,
    open_directory_object,
    query_directory_object,
)

log = getLogger(__name__)


def collect_named_objects(path: str = "\\") -> list[NamedObject]:
    """Collects all named objects in the directory.

    Parameters:
        path: point to start searching from
    """

    try:
        dir_handle = open_directory_object(dir_name=path, root_handle=None)
    except AccessDeniedError:
        return []

    named_objects = query_directory_object(path_to_dir=path, dir_handle=dir_handle)

    dir_objects = [obj for obj in named_objects if obj.type_name == NamedObjectType.DIRECTORY]

    root_dir_path = path if path.endswith("\\") else f"{path}\\"

    for obj in dir_objects:
        named_objects += collect_named_objects(f"{root_dir_path}{obj.name}", dir_handle)

    close_handle(dir_handle)

    return named_objects


def collect_open_handles(handle_types: Optional[list[NamedObject]] = None) -> Iterable[Handle]:
    """Collect open handles

    Collect open handles and optionally provide a list to explicitly collect specific types of handles.

    Parameters:
        handle_types: list containing the handle types to collect as strings
    """
    for handle in get_handles():
        try:
            if not handle_types or NamedObjectType(handle.handle_type) in handle_types:
                yield handle
        # Continue if an invalid NamedObjectType is observed
        except ValueError:
            log.warning(f"Observed an unknown NamedObjectType: {handle.handle_type if handle else None}")
            continue
