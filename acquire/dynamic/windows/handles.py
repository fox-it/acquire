import csv
import ctypes
import gzip
import io
import struct
import threading
from logging import Filter, LogRecord, getLogger
from queue import Queue
from typing import Iterable, Optional

from acquire.dynamic.windows.exceptions import OpenProcessError
from acquire.dynamic.windows.ntdll import NtStatusCode, close_handle, ntdll
from acquire.dynamic.windows.types import (
    BOOL,
    DUPLICATE_SAME_ACCESS,
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
    ErrorCode,
    Handle,
    ProcessAccess,
)

log = getLogger(__name__)

advapi32 = ctypes.windll.advapi32
advapi32.OpenProcessToken.argtypes = [HANDLE, DWORD, PHANDLE]

kernel32 = ctypes.windll.kernel32
kernel32.OpenProcess.restype = HANDLE
kernel32.DuplicateHandle.argtypes = (HANDLE, HANDLE, HANDLE, ctypes.POINTER(HANDLE), DWORD, BOOL, DWORD)


class DuplicateFilter(Filter):
    def __init__(self) -> None:
        super().__init__()
        self.msgs = set()

    def filter(self, record: LogRecord) -> bool:
        seen = (msg := record.getMessage()) not in self.msgs
        self.msgs.add(msg)
        return seen


def get_handle_type_info(handle: SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) -> Optional[str]:
    """Return type of handle.

    Parameters:
        handle: handle for which to return the type information.

    Raises:
        RuntimeError: Raised when the result of the object query is unknown (other than SUCCESS, LENGTH MISMATCH or
        INVALID).
    """
    public_object_type_information = PUBLIC_OBJECT_TYPE_INFORMATION()
    size = DWORD(ctypes.sizeof(public_object_type_information))
    while True:
        result = ntdll.NtQueryObject(
            handle,
            OBJECT_INFORMATION_CLASS.ObjectTypeInformation,
            ctypes.byref(public_object_type_information),
            size,
            None,
        )

        if result == NtStatusCode.STATUS_SUCCESS:
            return str(public_object_type_information.Name)
        elif result == NtStatusCode.STATUS_INFO_LENGTH_MISMATCH:
            size = DWORD(size.value * 4)
            ctypes.resize(public_object_type_information, size.value)
        elif result == NtStatusCode.STATUS_INVALID_HANDLE:
            return None
        else:
            raise RuntimeError(hex(result))


def _get_file_name_thread(h_file: int, q: Queue):
    iob = IO_STATUS_BLOCK()
    file_name_information = ctypes.create_string_buffer(0x1000)

    result = ntdll.NtQueryInformationFile(
        h_file,
        ctypes.byref(iob),
        file_name_information,
        len(file_name_information),
        FILE_INFORMATION_CLASS.FileNameInformation,
    )

    file_name = None
    if result == NtStatusCode.STATUS_SUCCESS:
        file_name_length = struct.unpack("<I", file_name_information[:4])[0]
        file_name = file_name_information[4 : 4 + file_name_length].decode("utf-16-le")

    q.put(file_name)


def get_handle_name(pid: int, handle: SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) -> Optional[str]:
    """Return handle name."""

    remote = pid != kernel32.GetCurrentProcessId()
    h_remote = None

    if remote:
        try:
            h_remote = open_process(pid)
        except OpenProcessError as e:
            log.error(e)
            return None
        try:
            handle = duplicate_handle(h_remote, handle)
        except RuntimeError:
            close_handle(h_remote)
            return None

    q = Queue()
    thread = threading.Thread(target=_get_file_name_thread, args=(handle, q))
    thread.daemon = True
    thread.start()
    thread.join(1.0)

    result = None
    if not thread.is_alive():
        try:
            result = q.get_nowait()
        except Exception: # noqa
            pass

    return result


def get_handles() -> Iterable[Handle]:
    """Returns all handles of a target."""
    system_handle_information = SYSTEM_HANDLE_INFORMATION_EX()
    size = DWORD(ctypes.sizeof(system_handle_information))
    log.addFilter(DuplicateFilter())

    while True:
        result = ntdll.NtQuerySystemInformation(
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
        handle_type = get_handle_type_info(handle.HandleValue)
        handle_name = get_handle_name(handle.UniqueProcessId, handle.HandleValue)

        if not handle_name:
            continue

        yield Handle(handle, handle_type, handle_name)
    log.removeFilter(DuplicateFilter())


def open_process(pid: int) -> int:
    """Obtain a handle for the given PID.

    More info: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

    Parameters:
        pid: integer that represents the process ID.

    Raises:
        OpenProcessError: Raies when the System Idle Process, the System Process or one of the CSRSS processes are tried
        to be opened.
    """
    kernel32.SetLastError(0)

    h_process = kernel32.OpenProcess(
        ProcessAccess.PROCESS_DUP_HANDLE,
        False,
        pid,
    )

    error = kernel32.GetLastError()
    if error in [ErrorCode.ERROR_INVALID_PARAMETER, ErrorCode.ERROR_ACCESS_DENIED]:
        raise OpenProcessError(
            f"Likely tried opening the System Idle Process, the System Process or one of the Client Server Run-Time"
            f"Subsystem (CSRSS) processes [pid: {pid}]"
        )

    # No valid handle could be obtained, display the error code
    if h_process == 0:
        raise OpenProcessError(f"OpenProcess Error: 0x{error:x} [pid: {pid}]")

    return h_process


def duplicate_handle(h_process: int, handle: SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) -> HANDLE:
    """Create duplicate handle.

    When the source handle is in use by another program, one needs to create a duplicate handle in order to have full
    control of that handle. This prevents performing operations on the source handle that might have been closed by
    the other program.
    """
    h_dup = HANDLE()
    kernel32.SetLastError(0)
    result = kernel32.DuplicateHandle(
        h_process, handle, kernel32.GetCurrentProcess(), ctypes.byref(h_dup), 0, False, DUPLICATE_SAME_ACCESS
    )
    if result == 0:
        raise RuntimeError()

    return h_dup


def serialize_handles_into_csv(rows: Iterable[Handle], compress: bool = True) -> bytes:
    """Serialize handle data into a csv.

    Serialize provided rows into normal or gzip-compressed CSV, and return a tuple
    containing the result bytes.
    """

    raw_buffer = io.BytesIO()

    if compress:
        buffer = gzip.GzipFile(fileobj=raw_buffer, mode="wb")
    else:
        buffer = raw_buffer

    with io.TextIOWrapper(buffer, encoding="utf-8") as wrapper:
        csv_writer = None
        for i, row in enumerate(rows):
            if i == 0:
                csv_writer = csv.DictWriter(wrapper, fieldnames=row.dictionary.keys())
                csv_writer.writeheader()

            csv_writer.writerow(row.dictionary)

    return raw_buffer.getvalue()
