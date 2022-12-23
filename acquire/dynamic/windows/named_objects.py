from __future__ import annotations

from enum import Enum

from acquire.dynamic.windows.types import OBJECT_DIRECTORY_INFORMATION


class NamedObjectType(Enum):
    ALPC_PORT = "ALPC Port"
    CALLBACK = "Callback"
    DESKTOP = "Desktop"
    DEVICE = "Device"  # NtOpenFile
    DIRECTORY = "Directory"  # NtOpenDirectoryObject
    DRIVER = "Driver"
    ETW_REGISTRATION = "EtwRegistration"
    EVENT = "Event"  # NtOpenEvent
    FILE = "File"  # NtOpenFile
    FILTER_CONNECTION_PORT = "FilterConnectionPort"
    IO_COMPLETION = "IoCompletion"
    IR_TIMER = "IRTimer"
    JOB = "Job"
    KEY = "Key"  # (Zw|Nt)OpenKey
    KEYED_EVENT = "KeyedEvent"
    MUTANT = "Mutant"  # NtOpenMutant
    MUTEX = "Mutex"
    PARTITION = "Partition"
    PROCESS = "Process"
    SECTION = "Section"  # NtOpenSection
    SESSION = "Session"
    SEMAPHORE = "Semaphore"  # (NtOpenSemaphore)
    SYMBOLIC_LINK = "SymbolicLink"  # NtOpenSymbolicLinkObject, NtQuerySymbolicLinkObject
    TIMER = "Timer"  # NtOpenTimer
    THREAD = "Thread"
    TOKEN = "Token"
    TP_WORKER_FACTORY = "TpWorkerFactory"
    TYPE = "Type"
    WAIT_COMPLETION_PACKET = "WaitCompletionPacket"
    WINDOWS_STATION = "WindowStation"

    UNKNOWN = "Unknown"


class NamedObject:
    __slots__ = [
        "root",
        "name",
        "type_name",
    ]

    def __init__(self, root: str, name: str, type_name: NamedObjectType) -> None:
        self.root = root if root.endswith("\\") else f"{root}\\"
        self.name = name
        self.type_name = type_name

    def __repr__(self) -> str:
        return f"{self.root}{self.name}, {self.type_name}"

    @classmethod
    def from_directory_information(
        cls, root_name: str, directory_information: OBJECT_DIRECTORY_INFORMATION
    ) -> NamedObject:
        return cls(
            root=root_name,
            name=directory_information.name,
            type_name=NamedObjectType(directory_information.type_name),
        )
