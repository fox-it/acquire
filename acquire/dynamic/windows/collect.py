from typing import List

from acquire.dynamic.windows.exceptions import AccessDeniedError
from acquire.dynamic.windows.named_objects import NamedObject, NamedObjectType
from acquire.dynamic.windows.ntdll import (
    close_handle,
    open_directory_object,
    query_directory_object,
)


def collect_named_objects(path: str = "\\") -> List[NamedObject]:
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
