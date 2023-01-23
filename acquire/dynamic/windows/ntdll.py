from __future__ import annotations

import ctypes
from enum import IntEnum, IntFlag
from typing import List

from acquire.dynamic.windows.exceptions import (
    AccessDeniedError,
    HandleNotClosedSuccessfullyError,
    NoMoreEntriesError,
)
from acquire.dynamic.windows.named_objects import NamedObject
from acquire.dynamic.windows.types import (
    BOOL,
    DWORD,
    HANDLE,
    IO_STATUS_BLOCK,
    LPVOID,
    NTSTATUS,
    NULL,
    OBJECT_DIRECTORY_INFORMATION,
    PHANDLE,
    PULONG,
    PUNICODE_STRING,
    PVOID,
    ULONG,
    UNICODE_STRING,
)

# https://github.com/pentestmonkey/windows-privesc-check/blob/master/wpc/ntobj.py


ntdll = ctypes.windll.ntdll
NtQueryInformationFile = ntdll.NtQueryInformationFile
NtQueryInformationFile.argtypes = [
    HANDLE,
    ctypes.POINTER(IO_STATUS_BLOCK),
    LPVOID,
    ULONG,
    DWORD,
]
ntdll.NtQueryInformationFile.restype = NTSTATUS

NtQuerySystemInformation = ntdll.NtQuerySystemInformation
NtQuerySystemInformation.argtypes = [
    ULONG,
    LPVOID,
    DWORD,
    ctypes.POINTER(DWORD),
]
ntdll.NtQuerySystemInformation.restype = NTSTATUS

NtQueryObject = ntdll.NtQueryObject
NtQueryObject.argtypes = [
    HANDLE,
    ULONG,
    LPVOID,
    DWORD,
    PULONG,
]
NtQueryObject.restype = NTSTATUS

STANDARD_RIGHTS_ALL = 0x001F0000
BUFFER_SIZE = 1024


class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", PUNICODE_STRING),
        ("Attributes", ULONG),
        ("SecurityDescriptor", PVOID),
        ("SecurityQualityOfService", PVOID),
    ]


class NtStatusCode(IntEnum):
    STATUS_SUCCESS = 0x00000000
    STATUS_MORE_ENTRIES = 0x00000105
    STATUS_ACCESS_DENIED = 0xC0000022
    STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
    STATUS_INVALID_HANDLE = 0xC0000008
    STATUS_NO_MORE_ENTRIES = 0x8000001A
    STATUS_BUFFER_OVERFLOW = 0x80000005


class ACCESS_MASK(IntFlag):
    DIRECTORY_QUERY = 0x0001
    DIRECTORY_TRAVERSE = 0x0002
    DIRECTORY_CREATE_OBJECT = 0x0004
    DIRECTORY_CREATE_SUBDIRECTORY = 0x0008
    DIRECTORY_ALL_ACCESS = STANDARD_RIGHTS_ALL | 0xF


class OBJ_ATTR(IntFlag):
    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/shared/ntdef.h
    https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles
    """

    OBJ_INHERIT = 0x00000002
    OBJ_PERMANENT = 0x00000010
    OBJ_EXCLUSIVE = 0x00000020
    OBJ_CASE_INSENSITIVE = 0x00000040
    OBJ_OPENIF = 0x00000080
    OBJ_OPENLINK = 0x00000100
    OBJ_KERNEL_HANDLE = 0x00000200
    OBJ_FORCE_ACCESS_CHECK = 0x00000400
    OBJ_IGNORE_IMPERSONATED_DEVICEMAP = 0x00000800
    OBJ_VALID_ATTRIBUTES = 0x00000FF2


# Define interface
NtOpenDirectoryObject = ntdll.NtOpenDirectoryObject
NtOpenDirectoryObject.argtypes = [
    PHANDLE,  # DirectoryHandle
    DWORD,  # DesiredAccess
    ctypes.POINTER(OBJECT_ATTRIBUTES),  # ObjectAttributes
]
NtOpenDirectoryObject.restype = NTSTATUS


# Define interface
NtQueryDirectoryObject = ntdll.NtQueryDirectoryObject
NtQueryDirectoryObject.argtypes = [
    HANDLE,  # DirectoryHandle
    PVOID,  # Buffer
    ULONG,  # Length
    BOOL,  # ReturnSingleEntry
    BOOL,  # RestartScan
    PULONG,  # Context
    PULONG,  # ReturnLength
]
NtQueryDirectoryObject.restype = NTSTATUS

RtlNtStatusToDosError = ntdll.RtlNtStatusToDosError
RtlNtStatusToDosError.argtypes = [NTSTATUS]
RtlNtStatusToDosError.restype = ULONG

CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.argtypes = [HANDLE]
CloseHandle.restype = BOOL


def initialize_object_attributes(
    destination_attributes: OBJECT_ATTRIBUTES,
    name: PUNICODE_STRING,
    attributes: OBJ_ATTR,
    root_directory: HANDLE,
    security_descriptor: PVOID,
) -> None:
    """Initializes the OBJECT_ATTRIBUTES structure.

    Allocates said information at the address of InitializedAttributes
    """
    ctypes.memset(ctypes.addressof(destination_attributes), 0, ctypes.sizeof(destination_attributes))
    destination_attributes.Length = ctypes.sizeof(destination_attributes)
    destination_attributes.ObjectName = name
    destination_attributes.Attributes = attributes
    destination_attributes.RootDirectory = root_directory
    destination_attributes.SecurityDescriptor = security_descriptor
    destination_attributes.SecurityQualityOfService = None


def close_handle(handle: HANDLE) -> None:
    """Closes an opened handle."""
    if not CloseHandle(handle):
        raise HandleNotClosedSuccessfullyError()


def validate_ntstatus(status: NTSTATUS) -> None:
    """Validates the result status of a Nt call

    Parameters:
        status: the return value of a ntcall
    """
    if status == NtStatusCode.STATUS_ACCESS_DENIED:
        raise AccessDeniedError("Couldn't access the resource")
    if status == NtStatusCode.STATUS_NO_MORE_ENTRIES:
        raise NoMoreEntriesError("There are no more entries available.")
    if status not in (NtStatusCode.STATUS_SUCCESS, NtStatusCode.STATUS_MORE_ENTRIES):
        raise ctypes.WinError(RtlNtStatusToDosError(status))


def open_directory_object(dir_name: str, root_handle: HANDLE = None) -> HANDLE:
    """Opens a handle to a specific directory structure of NamedObjects.

    Parameters:
        dir_name: Specific directory we want to try and open.
        root_handle: From which point we want to start querying the object.
    """

    object_name = UNICODE_STRING.from_str(dir_name)
    p_name = ctypes.pointer(object_name)

    obj_attrs = OBJECT_ATTRIBUTES()
    initialize_object_attributes(obj_attrs, p_name, OBJ_ATTR.OBJ_CASE_INSENSITIVE, root_handle, NULL)

    returned_handle = HANDLE()
    desired_access = ACCESS_MASK.DIRECTORY_QUERY | ACCESS_MASK.DIRECTORY_TRAVERSE
    status = NtOpenDirectoryObject(ctypes.byref(returned_handle), desired_access.value, ctypes.byref(obj_attrs))

    validate_ntstatus(status)

    return returned_handle


def query_directory_object(path_to_dir: str, dir_handle: HANDLE) -> List[NamedObject]:
    """Queries a directory object.

    Parameters:
        path_to_dir: The full path to the specific dir object getting queried
        dir_handle: A pointer to the directory we wish to query.
    """
    context = ULONG(0)
    previous_context = 0

    buffer = ctypes.create_string_buffer(BUFFER_SIZE)
    ntstatus = NtStatusCode.STATUS_MORE_ENTRIES
    objects = []
    while ntstatus == NtStatusCode.STATUS_MORE_ENTRIES:
        return_length = ULONG(0)
        ntstatus = NtQueryDirectoryObject(
            dir_handle,
            ctypes.byref(buffer),
            BUFFER_SIZE,
            False,
            False,
            ctypes.byref(context),
            ctypes.byref(return_length),
        )
        elements_in_buffer = context.value - previous_context
        dir_info_buffer = ctypes.cast(buffer, ctypes.POINTER(OBJECT_DIRECTORY_INFORMATION * elements_in_buffer))

        try:
            validate_ntstatus(ntstatus)
        except NoMoreEntriesError:
            break

        objects += [
            NamedObject.from_directory_information(path_to_dir, directory_information)
            for directory_information in dir_info_buffer.contents
        ]

        previous_context = context.value

    return objects
