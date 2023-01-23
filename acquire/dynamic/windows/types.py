from __future__ import annotations

import ctypes
from ctypes.wintypes import (
    BOOL,
    DWORD,
    HANDLE,
    LPDWORD,
    LPVOID,
    LPWSTR,
    PHANDLE,
    PULONG,
    ULONG,
    USHORT,
    WCHAR,
)
from enum import IntEnum

PVOID = ctypes.c_void_p
NTSTATUS = ULONG
NULL = None

ULONG_PTR = ctypes.c_size_t


class ProcessToken(IntEnum):
    TOKEN_QUERY = 0x0008
    TOKEN_ADJUST_PRIVILEGES = 0x0020


class ProcessAccess(IntEnum):
    PROCESS_TERMINATE = 0x0001
    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_DUP_HANDLE = 0x0040
    PROCESS_CREATE_PROCESS = 0x0080
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_SET_INFORMATION = 0x0200
    PROCESS_QUERY_INFORMATION = 0x0400
    SYNCHRONIZE = 0x00100000
    PROCESS_ALL_ACCESS = 0x1F0FFF


class ErrorCode(IntEnum):
    ERROR_SUCCESS = 0x0
    ERROR_ACCESS_DENIED = 0x5
    ERROR_INVALID_PARAMETER = 0x57
    ERROR_PARTIAL_COPY = 0x12B
    ERROR_NOT_ALL_ASSIGNED = 0x514


class DuplicateHandleFlags(IntEnum):
    DUPLICATE_CLOSE_SOURCE = 0x00000001
    DUPLICATE_SAME_ACCESS = 0x00000002
    DUPLICATE_SAME_ATTRIBUTES = 0x00000004


class SYSTEM_INFORMATION_CLASS(IntEnum):
    SystemHandleInformation = 0x10
    SystemExtendedHandleInformation = 0x40


class OBJECT_INFORMATION_CLASS(IntEnum):
    ObjectBasicInformation = 0
    ObjectNameInformation = 1
    ObjectTypeInformation = 2


class FILE_INFORMATION_CLASS(IntEnum):
    FileNameInformation = 9


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", PVOID),
        ("UniqueProcessId", ULONG_PTR),
        ("HandleValue", ULONG_PTR),
        ("GrantedAccess", ULONG),
        ("CreatorBackTraceIndex", USHORT),
        ("ObjectTypeIndex", USHORT),
        ("HandleAttributes", ULONG),
        ("Reserved", ULONG),
    ]

    @property
    def object(self) -> str:
        return hex(self.Object)

    @property
    def unique_process_id(self) -> str:
        return str(self.UniqueProcessId)

    @property
    def handle_value(self) -> str:
        return str(self.HandleValue)

    @property
    def granted_access(self) -> str:
        return str(self.GrantedAccess)

    @property
    def creator_back_trace_index(self) -> str:
        return str(self.CreatorBackTraceIndex)

    @property
    def object_type_index(self) -> str:
        return str(self.ObjectTypeIndex)

    @property
    def handle_attributes(self) -> str:
        return str(self.HandleAttributes)

    @property
    def reserved(self) -> str:
        return str(self.Reserved)


class SYSTEM_HANDLE_INFORMATION_EX(ctypes.Structure):
    _fields_ = [
        ("NumberOfHandles", ULONG_PTR),
        ("Reserved", ULONG_PTR),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
    ]


def FileNameInformationFactory(file_name_size: int = 1):
    class FILE_NAME_INFORMATION(ctypes.Structure):
        _fields_ = [("FileNameLength", ULONG), ("FileName", WCHAR * file_name_size)]

    return FILE_NAME_INFORMATION()


class IO_STATUS_BLOCK_DUMMYUNIONNAME(ctypes.Union):
    _fields_ = [("Status", NTSTATUS), ("Pointer", ULONG_PTR)]


class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [("DUMMYUNIONNAME", IO_STATUS_BLOCK_DUMMYUNIONNAME), ("Information", ctypes.c_size_t)]


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", DWORD),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", 1 * LUID_AND_ATTRIBUTES),
    ]


class Handle:
    """Handle object"""

    def __init__(self, handle: SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, handle_type: str, handle_name: str) -> None:
        self.name = handle_name
        self.handle_type = handle_type

        self.object = handle.object
        self.unique_process_id = handle.unique_process_id
        self.handle_value = handle.handle_value
        self.granted_access = handle.granted_access
        self.creator_back_trace_index = handle.creator_back_trace_index
        self.object_type_index = handle.object_type_index
        self.handle_attributes = handle.handle_attributes
        self.reserved = handle.reserved
        self._handle = handle

    @property
    def dictionary(self):
        return {key: value for key, value in self.__dict__.items() if not key.startswith("_")}


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", LPWSTR),
    ]

    def __str__(self) -> str:
        return self.Buffer

    @classmethod
    def from_str(cls, value: str) -> UNICODE_STRING:
        """Initializes a UNICODE_STRING structure."""
        destination = cls()
        value_buffer = ctypes.create_unicode_buffer(value)

        ctypes.memset(ctypes.addressof(destination), 0, ctypes.sizeof(destination))
        destination.Buffer = ctypes.cast(value_buffer, LPWSTR)
        destination.Length = ctypes.sizeof(value_buffer) - 2  # Excluding terminating NULL character
        destination.MaximumLength = destination.Length

        return destination


class PUBLIC_OBJECT_TYPE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Name", UNICODE_STRING),
        ("Reserved", ULONG * 22),
    ]

    @property
    def name(self) -> str:
        return str(self.Name)


PUNICODE_STRING = ctypes.POINTER(UNICODE_STRING)


class OBJECT_DIRECTORY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Name", UNICODE_STRING),
        ("TypeName", UNICODE_STRING),
    ]

    @property
    def name(self) -> str:
        return str(self.Name)

    @property
    def type_name(self) -> str:
        return str(self.TypeName)


__all__ = [
    "BOOL",
    "DWORD",
    "HANDLE",
    "LPWSTR",
    "PHANDLE",
    "PULONG",
    "ULONG",
    "USHORT",
    "PVOID",
    "NTSTATUS",
    "NULL",
    "UNICODE_STRING",
    "PUNICODE_STRING",
    "OBJECT_DIRECTORY_INFORMATION",
    "ProcessToken",
    "ProcessAccess",
    "ErrorCode",
    "DuplicateHandleFlags",
    "SYSTEM_INFORMATION_CLASS",
    "OBJECT_INFORMATION_CLASS",
    "FILE_INFORMATION_CLASS",
    "SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX",
    "SYSTEM_HANDLE_INFORMATION_EX",
    "PUBLIC_OBJECT_TYPE_INFORMATION",
    "IO_STATUS_BLOCK_DUMMYUNIONNAME",
    "IO_STATUS_BLOCK",
    "LUID",
    "LUID_AND_ATTRIBUTES",
    "TOKEN_PRIVILEGES",
    "Handle",
    "WCHAR",
    "LPVOID",
    "LPDWORD",
]
