from __future__ import annotations

import csv
import ctypes
import gzip
import io
import threading
from logging import Filter, LogRecord, getLogger
from queue import Empty, Queue
from typing import TYPE_CHECKING

from acquire.dynamic.windows.exceptions import OpenProcessError
from acquire.dynamic.windows.ntdll import (
    NtQueryInformationFile,
    NtQueryObject,
    NtQuerySystemInformation,
    NtStatusCode,
    close_handle,
)
from acquire.dynamic.windows.types import (
    BOOL,
    DWORD,
    FILE_INFORMATION_CLASS,
    HANDLE,
    IO_STATUS_BLOCK,
    OBJECT_INFORMATION_CLASS,
    PHANDLE,
    PUBLIC_OBJECT_TYPE_INFORMATION,
    SYSTEM_HANDLE_INFORMATION_EX,
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX,
    SYSTEM_INFORMATION_CLASS,
    ULONG,
    DuplicateHandleFlags,
    ErrorCode,
    FileNameInformationFactory,
    Handle,
    ProcessAccess,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

log = getLogger(__name__)

OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
OpenProcessToken.argtypes = [HANDLE, DWORD, PHANDLE]

kernel32 = ctypes.windll.kernel32
OpenProcess = kernel32.OpenProcess
OpenProcess.restype = HANDLE

DuplicateHandle = kernel32.DuplicateHandle
DuplicateHandle.argtypes = [HANDLE, HANDLE, HANDLE, ctypes.POINTER(HANDLE), DWORD, BOOL, DWORD]

GetLastError = kernel32.GetLastError
SetLastError = kernel32.SetLastError
GetCurrentProcessId = kernel32.GetCurrentProcessId


class DuplicateFilter(Filter):
    def __init__(self) -> None:
        super().__init__()
        self.msgs = set()

    def filter(self, record: LogRecord) -> bool:
        msg = record.getMessage()
        if show := msg not in self.msgs:
            self.msgs.add(msg)

        return show


def get_handle_type_info(handle: SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) -> str | None:
    """Return type of handle.

    Args:
        handle: handle for which to return the type information.

    Raises:
        RuntimeError: Raised when the result of the object query is unknown (other than SUCCESS, LENGTH MISMATCH or
        INVALID).
    """
    public_object_type_information = PUBLIC_OBJECT_TYPE_INFORMATION()
    size = DWORD(ctypes.sizeof(public_object_type_information))
    while True:
        result = NtQueryObject(
            handle,
            OBJECT_INFORMATION_CLASS.ObjectTypeInformation,
            ctypes.byref(public_object_type_information),
            size,
            None,
        )

        if result == NtStatusCode.STATUS_SUCCESS:
            return public_object_type_information.name
        if result == NtStatusCode.STATUS_INFO_LENGTH_MISMATCH:
            size = DWORD(size.value * 4)
            ctypes.resize(public_object_type_information, size.value)
        elif result == NtStatusCode.STATUS_INVALID_HANDLE:
            return None
        else:
            raise RuntimeError(hex(result))


def open_process(pid: int) -> int:
    """Obtain a handle for the given PID.

    More info: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

    Args:
        pid: integer that represents the process ID.

    Raises:
        OpenProcessError: Raies when the System Idle Process, the System Process or one of the CSRSS processes are tried
        to be opened.
    """
    SetLastError(0)

    h_process = OpenProcess(
        ProcessAccess.PROCESS_DUP_HANDLE,
        False,
        pid,
    )

    error = GetLastError()
    if error in [ErrorCode.ERROR_INVALID_PARAMETER, ErrorCode.ERROR_ACCESS_DENIED]:
        raise OpenProcessError(
            f"Likely tried opening the System Idle Process, the System Process or one of the Client Server Run-Time"
            f"Subsystem (CSRSS) processes [pid: {pid}]"
        )

    # No valid handle could be obtained, display the error code
    if h_process == 0:
        raise OpenProcessError(f"OpenProcess Error: 0x{error:x} [pid: {pid}]")

    return h_process


def _get_file_name_thread(h_file: HANDLE, queue: Queue) -> None:
    iob = IO_STATUS_BLOCK()
    file_name_information = FileNameInformationFactory()
    file_name = None

    while True:
        result = NtQueryInformationFile(
            h_file,
            ctypes.byref(iob),
            ctypes.byref(file_name_information),
            ULONG(ctypes.sizeof(file_name_information)),
            FILE_INFORMATION_CLASS.FileNameInformation,
        )

        if result == NtStatusCode.STATUS_BUFFER_OVERFLOW:
            file_name_information = FileNameInformationFactory(file_name_information.FileNameLength)
        elif result == NtStatusCode.STATUS_SUCCESS:
            file_name = file_name_information.FileName
            break
        else:
            # Multiple StatusCodes can be observed. In almost all cases FileNameLength is 0. Breaking for now
            break

    queue.put(file_name)


def get_handle_name(pid: int, handle: SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) -> str | None:
    """Return handle name."""

    remote = pid != GetCurrentProcessId()

    if remote:
        try:
            h_remote = open_process(pid)
        except OpenProcessError as e:
            log.error(e)  # noqa: TRY400
            return None
        try:
            handle = duplicate_handle(h_remote, handle)
        except RuntimeError:
            close_handle(h_remote)
            return None

    # Use threading to try (max a second) to get the handle name, since it might hang
    queue = Queue()
    thread = threading.Thread(target=_get_file_name_thread, args=(handle, queue))
    thread.daemon = True
    thread.start()
    thread.join(1.0)

    result = None
    if not thread.is_alive():
        try:
            result = queue.get_nowait()
        except Empty:
            pass

    return result


def get_handles() -> Iterator[Handle]:
    """Returns all handles of a target."""
    system_handle_information = SYSTEM_HANDLE_INFORMATION_EX()
    size = DWORD(ctypes.sizeof(system_handle_information))
    duplicate_filter = DuplicateFilter()
    log.addFilter(duplicate_filter)

    while True:
        result = NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
            ctypes.byref(system_handle_information),
            size,
            ctypes.byref(size),
        )

        if result == NtStatusCode.STATUS_SUCCESS:
            break
        elif result == NtStatusCode.STATUS_INFO_LENGTH_MISMATCH:
            size = DWORD(size.value * 4)
            ctypes.resize(system_handle_information, size.value)
        else:
            raise RuntimeError(hex(result))

    p_handles = ctypes.cast(
        system_handle_information.Handles,
        ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * system_handle_information.NumberOfHandles),
    )
    for handle in p_handles.contents:
        try:
            handle_type = get_handle_type_info(handle.HandleValue)
            handle_name = get_handle_name(handle.UniqueProcessId, handle.HandleValue)

            if not handle_name:
                continue

            yield Handle(handle, handle_type, handle_name)
        except Exception as handle_error:
            log.error("An error occurred while parsing handle, skipping handle. Error: %s", handle_error)  # noqa: TRY400

    log.removeFilter(duplicate_filter)


def duplicate_handle(h_process: int, handle: SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) -> HANDLE:
    """Create duplicate handle.

    When the source handle is in use by another program, one needs to create a duplicate handle in order to have full
    control of that handle. This prevents performing operations on the source handle that might have been closed by
    the other program.
    """
    h_dup = HANDLE()
    SetLastError(0)
    result = DuplicateHandle(
        h_process,
        handle,
        kernel32.GetCurrentProcess(),
        ctypes.byref(h_dup),
        0,
        False,
        DuplicateHandleFlags.DUPLICATE_SAME_ACCESS,
    )
    if result == 0:
        raise RuntimeError

    return h_dup


def serialize_handles_into_csv(rows: Iterator[Handle], compress: bool = True) -> bytes:
    """Serialize handle data into a csv.

    Serialize provided rows into normal or gzip-compressed CSV, and return a tuple
    containing the result bytes.
    """

    raw_buffer = io.BytesIO()

    buffer = gzip.GzipFile(fileobj=raw_buffer, mode="wb") if compress else raw_buffer

    with io.TextIOWrapper(buffer, encoding="utf-8") as wrapper:
        csv_writer = None
        for i, row in enumerate(rows):
            if i == 0:
                csv_writer = csv.DictWriter(wrapper, fieldnames=row.dictionary.keys())
                csv_writer.writeheader()

            csv_writer.writerow(row.dictionary)

    return raw_buffer.getvalue()
