from __future__ import annotations

import ctypes
from ctypes.wintypes import BOOL, DWORD, HANDLE, LPWSTR, PHANDLE, PULONG, ULONG, USHORT

PVOID = ctypes.c_void_p
NTSTATUS = ULONG
NULL = None


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", LPWSTR),
    ]

    def __str__(self) -> str:
        return self.Buffer

    @classmethod
    def from_str(cls, value: str) -> None:
        """Initializes a UNICODE_STRING structure."""
        destination = cls()
        value_buffer = ctypes.create_unicode_buffer(value)

        ctypes.memset(ctypes.addressof(destination), 0, ctypes.sizeof(destination))
        destination.Buffer = ctypes.cast(value_buffer, LPWSTR)
        destination.Length = ctypes.sizeof(value_buffer) - 2  # Excluding terminating NULL character
        destination.MaximumLength = destination.Length

        return destination


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
]
