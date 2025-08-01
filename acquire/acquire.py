from __future__ import annotations

import argparse
import enum
import functools
import io
import itertools
import logging
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import warnings
from collections import defaultdict
from itertools import chain, product
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Callable, NamedTuple, NoReturn

from dissect.target import Target
from dissect.target.filesystems import ntfs
from dissect.target.helpers import fsutil
from dissect.target.loaders.local import _windows_get_devices
from dissect.target.plugins.apps.webserver import iis
from dissect.target.plugins.os.windows.cam import CamPlugin
from dissect.target.plugins.os.windows.log import evt, evtx
from dissect.target.tools.utils import args_to_uri
from dissect.util.stream import RunlistStream

from acquire.collector import Collector, get_full_formatted_report, get_report_summary
from acquire.dynamic.windows.named_objects import NamedObjectType
from acquire.esxi import esxi_memory_context_manager
from acquire.gui import GUI
from acquire.hashes import (
    HashFunc,
    collect_hashes,
    filter_out_by_path_match,
    filter_out_by_value_match,
    filter_out_huge_files,
    serialize_into_csv,
)
from acquire.log import get_file_handler, reconfigure_log_file, setup_logging
from acquire.outputs import OUTPUTS
from acquire.uploaders.minio import MinIO
from acquire.uploaders.plugin import UploaderPlugin, upload_files_using_uploader
from acquire.uploaders.plugin_registry import UploaderRegistry
from acquire.utils import (
    check_and_set_acquire_args,
    check_and_set_log_args,
    create_argument_parser,
    format_output_name,
    get_formatted_exception,
    get_user_name,
    get_utc_now,
    get_utc_now_str,
    is_user_admin,
    normalize_path,
    parse_acquire_args,
    persist_execution_report,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.filesystem import Filesystem

try:
    from acquire.version import version
except ImportError:
    version = "0.0.dev"

try:
    # Injected by pystandalone builder
    from acquire.config import CONFIG
except ImportError:
    CONFIG = defaultdict(lambda: None)


VERSION = version
ACQUIRE_BANNER = rf"""
                       _
  __ _  ___ __ _ _   _(_)_ __ ___
 / _` |/ __/ _` | | | | | '__/ _ \
| (_| | (_| (_| | |_| | | | |  __/
 \__,_|\___\__, |\__,_|_|_|  \___|
  by Fox-IT   |_|             v{VERSION}
  part of NCC Group
"""[1:]

MODULES = {}
MODULE_LOOKUP = {}

CLI_ARGS_MODULE = "cli-args"

log = logging.getLogger("acquire")
log.propagate = 0
log_file_handler = None
logging.lastResort = None
logging.raiseExceptions = False


def misc_windows_user_homes(target: Target) -> Iterator[fsutil.TargetPath]:
    misc_dirs = {
        ("Windows/ServiceProfiles/LocalService", False),
        ("Windows/ServiceProfiles/NetworkService", False),
        ("Windows/System32/config/systemprofile", False),
        ("Users", True),
        ("Documents and Settings", True),
    }

    for fs in target.fs.path().iterdir():
        if fs.name.lower() == "c:":
            continue

        for misc_dir, get_subdirs in misc_dirs:
            misc_path = fs.joinpath(misc_dir)

            if not misc_path.exists():
                continue

            if get_subdirs:
                for entry in misc_path.iterdir():
                    if entry.is_dir():
                        yield entry
            else:
                yield misc_path


def misc_unix_user_homes(target: Target) -> Iterator[fsutil.TargetPath]:
    user_dirs = ["root", "home/*"]

    home_dirs = (target.fs.path("/").glob(path) for path in user_dirs)
    yield from itertools.chain.from_iterable(home_dirs)


def misc_macos_user_homes(target: Target) -> Iterator[fsutil.TargetPath]:
    yield from itertools.chain(target.fs.path("/Users/").glob("*"), misc_unix_user_homes(target))


MISC_MAPPING = {
    "macos": misc_macos_user_homes,
    "windows": misc_windows_user_homes,
}


def from_user_home(target: Target, path: str) -> Iterator[str]:
    try:
        for user_details in target.user_details.all_with_home():
            yield user_details.home_path.joinpath(path).as_posix()
    except Exception as e:
        log.warning("Error occurred when requesting all user homes")
        log.debug("", exc_info=e)

    misc_user_homes = MISC_MAPPING.get(target.os, misc_unix_user_homes)
    for user_dir in misc_user_homes(target):
        yield user_dir.joinpath(path).as_posix()


def iter_ntfs_filesystems(target: Target) -> Iterator[tuple[ntfs.NtfsFilesystem, str | None, str, str]]:
    mount_lookup = defaultdict(list)
    for mount, fs in target.fs.mounts.items():
        mount_lookup[fs].append(mount)

    for fs in target.filesystems:
        # The attr check is needed to correctly collect fake NTFS filesystems
        # where the MFT etc. are added to a VirtualFilesystem. This happens for
        # instance when the target is an acquired tar target.
        if not isinstance(fs, ntfs.NtfsFilesystem) and not hasattr(fs, "ntfs"):
            log.warning("Skipping %s - not an NTFS filesystem", fs)
            continue

        if fs in mount_lookup:
            mountpoints = mount_lookup[fs]

            for main_mountpoint in mountpoints:
                if main_mountpoint != "sysvol":
                    break

            name = main_mountpoint
            mountpoints = ", ".join(mountpoints)
        else:
            main_mountpoint = None
            name = f"vol-{fs.ntfs.serial:x}"
            mountpoints = "No mounts"
            log.warning("Unmounted NTFS filesystem found %s (%s)", fs, name)

        yield fs, main_mountpoint, name, mountpoints


def iter_esxi_filesystems(target: Target) -> Iterator[tuple[Filesystem, str, str, str | None]]:
    for mount, fs in target.fs.mounts.items():
        if not mount.startswith("/vmfs/volumes/"):
            continue

        uuid = mount[len("/vmfs/volumes/") :]  # strip /vmfs/volumes/
        name = None
        if fs.__type__ == "fat":
            name = fs.volume.name
        elif fs.__type__ == "vmfs":
            name = fs.vmfs.label

        yield fs, mount, uuid, name


def register_module(*args, **kwargs) -> Callable[[type[Module]], type[Module]]:
    def wrapper(module_cls: type[Module]) -> type[Module]:
        name = module_cls.__name__

        if name in MODULES:
            raise ValueError(
                f"Module name is already registered: registration for {module_cls} conflicts with {MODULES[name]}"
            )

        desc = module_cls.DESC or name
        kwargs["help"] = f"acquire {desc}"
        kwargs["action"] = argparse.BooleanOptionalAction
        kwargs["dest"] = name.lower()
        module_cls.__modname__ = name

        if not hasattr(module_cls, "__cli_args__"):
            module_cls.__cli_args__ = []
        module_cls.__cli_args__.append((args, kwargs))

        MODULES[name] = module_cls
        return module_cls

    return wrapper


def module_arg(*args, **kwargs) -> Callable[[type[Module]], type[Module]]:
    def wrapper(module_cls: type[Module]) -> type[Module]:
        if not hasattr(module_cls, "__cli_args__"):
            module_cls.__cli_args__ = []
        module_cls.__cli_args__.append((args, kwargs))
        return module_cls

    return wrapper


def local_module(cls: type[object]) -> object:
    """A decorator that sets property `__local__` on a module class to mark it for local target only"""
    cls.__local__ = True
    return cls


class ExecutionOrder(enum.IntEnum):
    TOP = 0
    DEFAULT = 1
    BOTTOM = 2


class Module:
    DESC = None
    SPEC = ()
    EXEC_ORDER = ExecutionOrder.DEFAULT

    @classmethod
    def run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        desc = cls.DESC or cls.__name__.lower()
        log.info("*** Acquiring %s", desc)

        with collector.bind_module(cls):
            collector.collect(cls.SPEC)

            spec_ext = cls.get_spec_additions(target, cli_args)
            if spec_ext:
                collector.collect(list(spec_ext))

            cls._run(target, cli_args, collector)

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        pass

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        pass


@register_module("--sys")
@module_arg(
    "--full-sys",
    action=argparse.BooleanOptionalAction,
    help="acquire all Sysfs (/sys) entries",
)
@local_module
class Sys(Module):
    DESC = """all or a subset of Sysfs (/sys) entries (live systems only). Defaults to a subset.
    Use --full-sys to acquire all entries."""
    EXEC_ORDER = ExecutionOrder.BOTTOM

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        spec_path = "/sys" if cli_args.full_sys else "/sys/module"
        spec = [("path", spec_path)]

        collector.collect(spec, follow=False, volatile=True)


@register_module("--proc")
@module_arg(
    "--full-proc",
    action=argparse.BooleanOptionalAction,
    help="acquire all Procfs (/proc) entries",
)
@local_module
class Proc(Module):
    DESC = """all or a subset of Procfs (/proc) entries (live systems only). Defaults to a subset.
    Use --full-proc to acquire all entries."""
    EXEC_ORDER = ExecutionOrder.BOTTOM

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        if cli_args.full_proc:
            spec = [("path", "/proc")]
        else:
            spec = [
                ("path", "/proc/sys/kernel/hostname"),
                ("path", "/proc/uptime"),
                ("path", "/proc/stat"),
            ]
            spec = itertools.chain(spec, cls._get_proc_specs(target))
        collector.collect(spec, follow=False, volatile=True)

    @classmethod
    def _get_proc_specs(cls, target: Target) -> Iterator[tuple[str, str]]:
        pid_paths = ["status", "stat", "environ"]
        for proc, part in itertools.product(target.proc.iter_proc(), pid_paths):
            yield ("path", proc / part)


@register_module("--proc-net")
@local_module
class ProcNet(Module):
    DESC = "Procfs network files (live systems only)"
    EXEC_ORDER = ExecutionOrder.BOTTOM

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        # With network namespaces, /proc/net is a references to /proc/<pid>/net,
        # It contains the same information as /proc/net, however it only shows the information from the
        # namespace where the process is the member of.
        # TODO: Research about network namespaces
        spec = [
            ("path", "/proc/net/"),
            ("path", "/proc/self/net/"),
        ]
        collector.collect(spec, follow=False, volatile=True)


@register_module("-n", "--ntfs")
class NTFS(Module):
    DESC = "NTFS filesystem metadata"

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        for fs, main_mountpoint, name, mountpoints in iter_ntfs_filesystems(target):
            log.info("Acquiring from %s as %s (%s)", fs, name, mountpoints)

            for filename in ("$MFT", "$Boot", "$Secure:$SDS"):
                if main_mountpoint is not None:
                    path = fsutil.join(main_mountpoint, filename)
                    collector.collect_path(path)

                else:
                    # In case the NTFS filesystem is not mounted, which should not occur but
                    # iter_ntfs_filesystems allows for the possibility, we fall back to raw file
                    # collection.
                    collector.collect_file_raw(filename, fs, name)

            cls.collect_usnjrnl(collector, fs, name)

    @classmethod
    def collect_usnjrnl(cls, collector: Collector, fs: Filesystem, name: str) -> None:
        def usnjrnl_accessor(journal: BinaryIO) -> tuple[BinaryIO, int]:
            # If the filesystem is a virtual NTFS filesystem, journal will be
            # plain BinaryIO, not a RunlistStream.
            if isinstance(journal, RunlistStream):
                i = 0
                while journal.runlist[i][0] is None:
                    journal.seek(journal.runlist[i][1] * journal.block_size, io.SEEK_CUR)
                    i += 1
                size = journal.size - journal.tell()
            else:
                size = journal.size

            return (journal, size)

        collector.collect_file_raw(
            "$Extend/$Usnjrnl:$J",
            fs,
            name,
            file_accessor=usnjrnl_accessor,
        )


@register_module("-r", "--registry")
class Registry(Module):
    DESC = "registry hives"
    HIVES = ("drivers", "sam", "security", "software", "system", "default")
    SPEC = (
        ("path", "sysvol/windows/system32/config/txr"),
        ("path", "sysvol/windows/system32/config/regback"),
        ("glob", "sysvol/System Volume Information/_restore*/RP*/snapshot/_REGISTRY_*"),
        ("glob", "ntuser.dat*", from_user_home),
        ("glob", "AppData/Local/Microsoft/Windows/UsrClass.dat*", from_user_home),
        ("glob", "Local Settings/Application Data/Microsoft/Windows/UsrClass.dat*", from_user_home),
    )

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        # Glob all hives to include e.g. .LOG files and .regtrans-ms files.
        files = []
        for hive in cls.HIVES:
            pattern = f"sysvol/windows/system32/config/{hive}*"
            files.extend([("path", entry) for entry in target.fs.path().glob(pattern) if entry.is_file()])
        return files


@register_module("--netstat")
@local_module
class Netstat(Module):
    DESC = "netstat output"
    SPEC = (("command", (["powershell.exe", "netstat", "-a", "-n", "-o"], "netstat")),)
    EXEC_ORDER = ExecutionOrder.BOTTOM


@register_module("--devices")
@local_module
class Devices(Module):
    DESC = "devices output"
    EXEC_ORDER = ExecutionOrder.BOTTOM

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        try:
            lines = _windows_get_devices()
            collector.output.write_bytes("QueryDosDeviceA.txt", "\n".join(lines).encode("utf-8"))
            collector.report.add_command_collected(cls.__name__, ["QueryDosDeviceA"])
        except Exception:
            collector.report.add_command_failed(cls.__name__, ["QueryDosDeviceA"])
            log.exception("- Failed to collect output from command `QueryDosDeviceA`")
        return


@register_module("--win-processes")
@local_module
class WinProcesses(Module):
    DESC = "Windows process list"
    SPEC = (("command", (["tasklist", "/V", "/fo", "csv"], "win-processes")),)
    EXEC_ORDER = ExecutionOrder.BOTTOM


@register_module("--win-proc-env")
@local_module
class WinProcEnv(Module):
    DESC = "Process environment variables"
    SPEC = (
        (
            "command",
            (
                ["PowerShell", "-command", "Get-Process | ForEach-Object {$_.StartInfo.EnvironmentVariables}"],
                "win-process-env-vars",
            ),
        ),
    )
    EXEC_ORDER = ExecutionOrder.BOTTOM


@register_module("--win-arp-cache")
@local_module
class WinArpCache(Module):
    DESC = "ARP Cache"
    EXEC_ORDER = ExecutionOrder.BOTTOM

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        if float(target.ntversion) < 6.2:
            commands = [
                # < Windows 10
                ("command", (["arp", "-av"], "win7-arp-cache")),
            ]
        else:
            commands = [
                # Windows 10+ (PowerShell)
                ("command", (["PowerShell", "Get-NetNeighbor"], "win10-arp-cache")),
            ]
        return commands


@register_module("--win-rdp-sessions")
@local_module
class WinRDPSessions(Module):
    DESC = "Windows Remote Desktop session information"
    EXEC_ORDER = ExecutionOrder.BOTTOM

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        # where.exe instead of where, just in case the client runs in PS instead of CMD
        # by default where hides qwinsta on 32-bit systems because qwinsta is only 64-bit, but with recursive /R search
        # we can still manage to find it and by passing the exact path Windows will launch a 64-bit process
        # on systems capable of doing that.
        qwinsta = subprocess.run(
            ["where.exe", "/R", os.environ["WINDIR"], "qwinsta.exe"], capture_output=True, text=True
        ).stdout.split("\n")[0]
        return [
            ("command", ([qwinsta, "/VM"], "win-rdp-sessions")),
        ]


@register_module("--winpmem")
@local_module
class WinMemDump(Module):
    DESC = "Windows full memory dump"
    EXEC_ORDER = ExecutionOrder.BOTTOM

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        winpmem_file_name = "winpmem.exe"
        winpmem_exec = shutil.which(winpmem_file_name)

        command_parts = [winpmem_exec, "-"]

        if winpmem_exec is None:
            command_parts.pop(0)
            command_parts.insert(0, winpmem_file_name)
            collector.report.add_command_failed(cls.__name__, command_parts)
            log.error(
                "- Failed to collect output from command `%s`, program %s not found",
                " ".join(command_parts),
                winpmem_file_name,
            )
            return

        log.info("- Collecting output from command `%s`", " ".join(command_parts))

        mem_dump_path = collector.output.path.with_name("winpmem")
        mem_dump_errors_path = mem_dump_path.with_name("winpmem.errors")

        output_base = collector.COMMAND_OUTPUT_BASE
        if collector.base:
            output_base = fsutil.join(collector.base, collector.COMMAND_OUTPUT_BASE)

        mem_dump_output_path = fsutil.join(output_base, mem_dump_path.name)
        mem_dump_errors_output_path = fsutil.join(output_base, mem_dump_errors_path.name)

        with mem_dump_path.open(mode="wb") as mem_dump_fh, mem_dump_errors_path.open(mode="wb") as mem_dump_errors_fh:
            try:
                # The shell parameter must be set to False, as otherwise the
                # output from stdout is not piped into the filehandle.
                # The check parameter must be set to False, as winpmem.exe
                # always seems to exit with an error code, even on success.
                subprocess.run(
                    bufsize=0,
                    args=command_parts,
                    stdout=mem_dump_fh,
                    stderr=mem_dump_errors_fh,
                    shell=False,
                    check=False,
                )

            except Exception:
                collector.report.add_command_failed(cls.__name__, command_parts)
                log.exception(
                    "- Failed to collect output from command `%s`",
                    " ".join(command_parts),
                )
                return

        collector.output.write_entry(mem_dump_output_path, mem_dump_path)
        collector.output.write_entry(mem_dump_errors_output_path, mem_dump_errors_path)
        collector.report.add_command_collected(cls.__name__, command_parts)
        mem_dump_path.unlink()
        mem_dump_errors_path.unlink()


@register_module("--winmem-files")
class WinMemFiles(Module):
    DESC = "Windows memory files"
    SPEC = (
        ("path", "sysvol/pagefile.sys"),
        ("path", "sysvol/hiberfil.sys"),
        ("path", "sysvol/swapfile.sys"),
        ("path", "sysvol/windows/memory.dmp"),
        ("path", "sysvol/windows/minidump"),
    )

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()

        page_key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management"
        for reg_key in target.registry.keys(page_key):
            for page_path in reg_key.value("ExistingPageFiles").value:
                spec.add(("path", target.resolve(page_path)))

        crash_key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl"
        for reg_key in target.registry.keys(crash_key):
            spec.add(("path", target.resolve(reg_key.value("DumpFile").value)))
            spec.add(("path", target.resolve(reg_key.value("MinidumpDir").value)))

        return spec


@register_module("--cam-history")
class CamHistory(Module):
    DESC = "Capability Manager History Database"

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()

        cam_history_db_file = CamPlugin(target)._find_db()
        if cam_history_db_file and cam_history_db_file.exists():
            # Collect all files from the db path, including .db-wal and .db-shm files.
            spec.add(("path", cam_history_db_file.parent))
        return spec


@register_module("-e", "--eventlogs")
class EventLogs(Module):
    DESC = "event logs"

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()
        evt_log_paths = evt.EvtPlugin(target).get_logs(filename_glob="*.evt")
        for path in evt_log_paths:
            spec.add(("path", path))
        evtx_log_paths = evtx.EvtxPlugin(target).get_logs(filename_glob="*.evtx")
        for path in evtx_log_paths:
            spec.add(("path", path))
        return spec


@register_module("-t", "--tasks")
class Tasks(Module):
    SPEC = (
        ("path", "sysvol/windows/tasks"),
        ("path", "sysvol/windows/system32/tasks"),
        ("path", "sysvol/windows/syswow64/tasks"),
        ("path", "sysvol/windows/sysvol/domain/policies"),
        ("path", "sysvol/windows/system32/GroupPolicy/DataStore/"),
        # Task Scheduler Service transaction log
        ("path", "sysvol/SchedLgU.txt"),
        ("path", "sysvol/windows/SchedLgU.txt"),
        ("path", "sysvol/windows/tasks/SchedLgU.txt"),
        ("path", "sysvol/winnt/tasks/SchedLgU.txt"),
    )


@register_module("-ad", "--active-directory")
class ActiveDirectory(Module):
    DESC = "Active Directory data (policies, scripts, etc.)"
    SPEC = (("path", "sysvol/windows/sysvol/domain"),)

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()
        key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"
        for reg_key in target.registry.keys(key):
            try:
                spec.add(("path", reg_key.value("SysVol").value))
            except Exception:  # noqa: PERF203
                pass
        return spec


@register_module("-nt", "--ntds")
class NTDS(Module):
    SPEC = (("path", "sysvol/windows/NTDS"),)

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()

        key = "HKLM\\SYSTEM\\CurrentControlSet\\services\\NTDS\\Parameters"
        values = [
            ("path", "DSA Working Directory"),
            ("path", "DSA Database File"),
            ("path", "Database backup path"),
            ("path", "Database log files path"),
        ]
        for reg_key in target.registry.keys(key):
            for collect_type, value in values:
                path = reg_key.value(value).value
                spec.add((collect_type, path))

        return spec


@register_module("--etl")
class ETL(Module):
    DESC = "interesting ETL files"
    SPEC = (("glob", "sysvol/Windows/System32/WDI/LogFiles/*.etl"),)


@register_module("--recents")
class Recents(Module):
    DESC = "Windows recently used files artifacts"
    SPEC = (
        ("path", "AppData/Roaming/Microsoft/Windows/Recent", from_user_home),
        ("path", "AppData/Roaming/Microsoft/Office/Recent", from_user_home),
        ("glob", "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/*.lnk", from_user_home),
        ("glob", "Desktop/*.lnk", from_user_home),
        ("glob", "Recent/*.lnk", from_user_home),
        ("glob", "sysvol/ProgramData/Microsoft/Windows/Start Menu/Programs/*.lnk"),
    )


@register_module("--startup")
class Startup(Module):
    DESC = "Windows Startup folder"
    SPEC = (
        ("path", "sysvol/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"),
        ("path", "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup", from_user_home),
    )


def recyclebin_filter(path: fsutil.TargetPath) -> bool:
    return bool(path.stat().st_size >= (10 * 1024 * 1024))  # 10MB


@register_module("--recyclebin")
@module_arg(
    "--large-files",
    action=argparse.BooleanOptionalAction,
    help="Collect files larger than 10MB in the Recycle Bin",
)
@module_arg(
    "--data-files",
    action=argparse.BooleanOptionalAction,
    help="Collect the data files in the Recycle Bin",
)
class RecycleBin(Module):
    DESC = "recycle bin metadata and data files"

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        large_files_filter = None if cli_args.large_files else recyclebin_filter

        if large_files_filter:
            log.info("Skipping files in Recycle Bin that are larger than 10MB.")

        patterns = ["$Recycle.bin/*/$I*", "Recycler/*/INFO2", "Recycled/INFO2"]

        if cli_args.data_files is None or cli_args.data_files:
            patterns.extend(["$Recycle.Bin/$R*", "$Recycle.Bin/*/$R*", "RECYCLE*/D*"])

        with collector.file_filter(large_files_filter):
            for fs, main_mountpoint, name, mountpoints in iter_ntfs_filesystems(target):
                log.info("Acquiring recycle bin from %s as %s (%s)", fs, name, mountpoints)

                for pattern in patterns:
                    if main_mountpoint is not None:
                        pattern = fsutil.join(main_mountpoint, pattern)
                        collector.collect_glob(pattern)
                    else:
                        # In case the NTFS filesystem is not mounted, which should not occur but
                        # iter_ntfs_filesystems allows for the possibility, we fall back to raw file
                        # collection.
                        for entry in fs.path().glob(pattern):
                            if entry.is_file():
                                collector.collect_file_raw(fs, entry, name)


@register_module("--drivers")
class Drivers(Module):
    DESC = "installed drivers"
    SPEC = (("glob", "sysvol/windows/system32/drivers/*.sys"),)


@register_module("--exchange")
class Exchange(Module):
    DESC = "interesting Exchange configuration files"

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()

        key = "HKLM\\SOFTWARE\\Microsoft\\ExchangeServer"
        for reg_key in target.registry.keys(key):
            for subkey in reg_key.subkeys():
                try:
                    setup_key = subkey.subkey("Setup")
                    install_path = setup_key.value("MsiInstallPath").value
                    spec.update(
                        [
                            (
                                "path",
                                f"{install_path}\\TransportRoles\\Agents\\agents.config",
                            ),
                            (
                                "path",
                                f"{install_path}\\Logging\\Ews",
                            ),
                            (
                                "path",
                                f"{install_path}\\Logging\\CmdletInfra\\Powershell-Proxy\\Cmdlet",
                            ),
                            (
                                "path",
                                f"{install_path}\\TransportRoles\\Logs",
                            ),
                        ]
                    )
                except Exception:  # noqa: PERF203
                    pass
        return spec


@register_module("--mssql")
class MSSQL(Module):
    DESC = "MSSQL error logs"

    SPEC = (("glob", "/var/opt/mssql/log/errorlog*"),)

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple[str, str]]:
        log_paths = set()

        if not target.has_function("registry"):
            return

        for reg_key in target.registry.glob_ext("HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\*"):
            try:
                log_paths.add(reg_key.value("ErrorDumpDir").value)
            except Exception:
                pass

            try:
                subkey = reg_key.subkey("CPE")
                log_paths.add(subkey.value("ErrorDumpDir").value)
            except Exception:
                pass

        for log_path in log_paths:
            yield ("glob", f"{log_path}/ERRORLOG*")


@register_module("--iis")
class IIS(Module):
    DESC = "IIS logs"

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = {
            ("glob", "sysvol\\Windows\\System32\\LogFiles\\W3SVC*\\*.log"),
            ("glob", "sysvol\\Windows.old\\Windows\\System32\\LogFiles\\W3SVC*\\*.log"),
            ("glob", "sysvol\\inetpub\\logs\\LogFiles\\*.log"),
            ("glob", "sysvol\\inetpub\\logs\\LogFiles\\W3SVC*\\*.log"),
            ("glob", "sysvol\\Resources\\Directory\\*\\LogFiles\\Web\\W3SVC*\\*.log"),
        }
        iis_plugin = iis.IISLogsPlugin(target)
        spec.update(("path", log_path) for log_path in chain(*iis_plugin.log_dirs.values()))
        return spec


@register_module("--sharepoint")
class SharePoint(Module):
    DESC = "Windows SharePoint Server logs"

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()
        key = "HKLM\\SOFTWARE\\Microsoft\\Shared Tools\\Web Server Extensions\\*\\WSS"

        for reg_key in target.registry.glob_ext(key):
            try:
                spec.add(("path", reg_key.value("LogDir").value))
            except Exception:  # noqa: PERF203
                pass

        return spec


@register_module("--prefetch")
class Prefetch(Module):
    DESC = "Windows Prefetch files"
    SPEC = (("path", "sysvol/windows/prefetch"),)


@register_module("--appcompat")
class Appcompat(Module):
    DESC = "Windows Amcache and RecentFileCache"
    SPEC = (("path", "sysvol/windows/appcompat"),)


@register_module("--pca")
class PCA(Module):
    DESC = "Windows Program Compatibility Assistant"
    SPEC = (("path", "sysvol/windows/pca"),)


@register_module("--syscache")
class Syscache(Module):
    DESC = "Windows Syscache hive and log files"
    SPEC = (
        ("path", "sysvol/System Volume Information/Syscache.hve"),
        ("glob", "sysvol/System Volume Information/Syscache.hve.LOG*"),
    )


@register_module("--win-notifications")
class WindowsNotifications(Module):
    DESC = "Windows Push Notifications Database files."
    SPEC = (
        # Old Win7/Win10 version of the file
        ("path", "AppData/Local/Microsoft/Windows/Notifications/appdb.dat", from_user_home),
        # New version of the file
        ("path", "AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db", from_user_home),
    )


@register_module("--bits")
class BITS(Module):
    DESC = "Background Intelligent Transfer Service (BITS) queue/log DB"
    SPEC = (
        # Pre-Win10 the BITS DB files are called qmgr[01].dat, in Win10 it is
        # called qmgr.db and its transaction logs edb.log and edb.log[0-2]
        # Win 2000/XP/2003 path
        # (basically: \%ALLUSERSPROFILE%\Application Data\Microsoft\...)
        ("glob", "sysvol/Documents and Settings/All Users/Application Data/Microsoft/Network/Downloader/qmgr*.dat"),
        # Win Vista and higher path
        # (basically: \%ALLUSERSPROFILE%\Microsoft\...; %ALLUSERSPROFILE% == %PROGRAMDATA%)
        ("glob", "sysvol/ProgramData/Microsoft/Network/Downloader/qmgr*.dat"),
        # Win 10 files
        ("path", "sysvol/ProgramData/Microsoft/Network/Downloader/qmgr.db"),
        ("glob", "sysvol/ProgramData/Microsoft/Network/Downloader/edb.log*"),
    )


@register_module("--wbem")
class WBEM(Module):
    DESC = "Windows WBEM (WMI) database files"
    SPEC = (("path", "sysvol/windows/system32/wbem/Repository"),)


@register_module("--dhcp")
class DHCP(Module):
    DESC = "Windows Server DHCP files"

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()
        key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\DhcpServer\\Parameters"
        for reg_key in target.registry.keys(key):
            spec.add(("path", reg_key.value("DatabasePath").value))
        return spec


@register_module("--dns")
class DNS(Module):
    DESC = "Windows Server DNS files"
    SPEC = (
        ("glob", "sysvol/windows/system32/config/netlogon.*"),
        ("path", "sysvol/windows/system32/dns"),
    )


@register_module("--win-dns-cache")
@local_module
class WinDnsClientCache(Module):
    DESC = "The contents of Windows DNS client cache"
    SPEC = (
        (
            "command",
            # Powershell.exe understands a subcommand passed as single string parameter,
            # no need to split the subcommand in parts.
            (
                ["powershell.exe", "-Command", "Get-DnsClientCache | ConvertTo-Csv -NoTypeInformation"],
                "get-dnsclientcache",
            ),
        ),
    )
    EXEC_ORDER = ExecutionOrder.BOTTOM


@register_module("--powershell")
class PowerShell(Module):
    DESC = "Windows PowerShell Artefacts"
    SPEC = (("path", "AppData/Roaming/Microsoft/Windows/PowerShell", from_user_home),)


@register_module("--thumbnail-cache")
class ThumbnailCache(Module):
    DESC = "Windows thumbnail db artifacts"
    SPEC = (("glob", "AppData/Local/Microsoft/Windows/Explorer/thumbcache_*", from_user_home),)


@register_module("--text-editor")
class TextEditor(Module):
    DESC = "text editor (un)saved tab contents"
    # Only Windows 11 notepad & Notepad++ tabs for now, but locations for other text editors may be added later.
    SPEC = (
        ("path", "AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/", from_user_home),
        ("path", "AppData/Roaming/Notepad++/backup/", from_user_home),
    )


@register_module("--misc")
class Misc(Module):
    DESC = "miscellaneous Windows artefacts"
    SPEC = (
        ("path", "sysvol/windows/PFRO.log"),
        ("path", "sysvol/windows/setupapi.log"),
        ("path", "sysvol/windows/setupapidev.log"),
        ("glob", "sysvol/windows/inf/setupapi*.log"),
        ("glob", "sysvol/system32/logfiles/*/*.txt"),
        ("path", "sysvol/windows/system32/sru"),
        ("path", "sysvol/windows/system32/drivers/etc"),
        ("path", "sysvol/Windows/System32/WDI/LogFiles/StartupInfo"),
        ("path", "sysvol/windows/system32/GroupPolicy/DataStore/"),
        ("path", "sysvol/ProgramData/Microsoft/Group Policy/History/"),
        ("path", "AppData/Local/Microsoft/Group Policy/History/", from_user_home),
        ("glob", "sysvol/Windows/System32/LogFiles/SUM/*.mdb"),
        ("glob", "sysvol/ProgramData/USOShared/Logs/System/*.etl"),
        ("glob", "sysvol/Windows/Logs/WindowsUpdate/WindowsUpdate*.etl"),
        ("glob", "sysvol/Windows/Logs/CBS/CBS*.log"),
        # Windows Search DB
        ("path", "sysvol/ProgramData/Microsoft/Search/Data/Applications/Windows"),
        # Windows Search DB - Windows Search Database Roaming
        ("glob", "AppData/Roaming/Microsoft/Search/Data/Applications/S-1-*/*", from_user_home),
        ("path", "sysvol/Windows/SoftwareDistribution/DataStore"),
    )


@register_module("--av")
class AV(Module):
    DESC = "various antivirus logs"
    SPEC = (
        # AVG
        ("path", "sysvol/Documents and Settings/All Users/Application Data/AVG/Antivirus/log"),
        ("path", "sysvol/Documents and Settings/All Users/Application Data/AVG/Antivirus/report"),
        ("path", "sysvol/ProgramData/AVG/Antivirus/log"),
        ("path", "sysvol/ProgramData/AVG/Antivirus/report"),
        ("path", "sysvol/ProgramData/AVG/Persistent Data/Antivirus/Logs"),
        ("path", "sysvol/ProgramData/AVG/Antivirus/FileInfo2.db"),
        ("path", "sysvol/ProgramData/AVG/Antivirus/lsdb2.json"),
        # Avast
        ("path", "sysvol/Documents And Settings/All Users/Application Data/Avast Software/Avast/Log"),
        ("path", "sysvol/ProgramData/Avast Software/Avast/Log"),
        ("path", "Avast Software/Avast/Log", from_user_home),
        ("path", "sysvol/ProgramData/Avast Software/Avast/Chest/index.xml"),
        ("path", "sysvol/ProgramData/Avast Software/Persistent Data/Logs"),
        ("path", "sysvol/ProgramData/Avast Software/Icarus/Logs"),
        # Avira
        ("path", "sysvol/ProgramData/Avira/Antivirus/LOGFILES"),
        ("path", "sysvol/ProgramData/Avira/Security/Logs"),
        ("path", "sysvol/ProgramData/Avira/VPN"),
        # Bitdefender
        ("path", "sysvol/ProgramData/Bitdefender/Endpoint Security/Logs"),
        ("path", "sysvol/ProgramData/Bitdefender/Desktop/Profiles/Logs"),
        ("glob", "sysvol/Program Files*/Bitdefender*/*"),
        # ComboFix
        ("path", "sysvol/ComboFix.txt"),
        # Cybereason
        ("path", "sysvol/ProgramData/crs1/Logs"),
        ("path", "sysvol/ProgramData/apv2/Logs"),
        ("path", "sysvol/ProgramData/crb1/Logs"),
        # Cylance
        ("path", "sysvol/ProgramData/Cylance/Desktop"),
        ("path", "sysvol/ProgramData/Cylance/Optics/Log"),
        ("path", "sysvol/Program Files/Cylance/Desktop/log"),
        # ESET
        ("path", "sysvol/Documents and Settings/All Users/Application Data/ESET/ESET NOD32 Antivirus/Logs"),
        ("path", "sysvol/ProgramData/ESET/ESET NOD32 Antivirus/Logs"),
        ("path", "sysvol/ProgramData/ESET/ESET Security/Logs"),
        ("path", "sysvol/ProgramData/ESET/RemoteAdministrator/Agent/EraAgentApplicationData/Logs"),
        ("path", "sysvol/Windows/System32/config/systemprofile/AppData/Local/ESET/ESET Security/Quarantine"),
        ("path", "AppData/Local/ESET/ESET Security/Quarantine", from_user_home),
        # Emsisoft
        ("glob", "sysvol/ProgramData/Emsisoft/Reports/scan*.txt"),
        # F-Secure
        ("path", "sysvol/ProgramData/F-Secure/Log"),
        ("path", "AppData/Local/F-Secure/Log", from_user_home),
        ("path", "sysvol/ProgramData/F-Secure/Antivirus/ScheduledScanReports"),
        # HitmanPro
        ("path", "sysvol/ProgramData/HitmanPro/Logs"),
        ("path", "sysvol/ProgramData/HitmanPro.Alert/Logs"),
        ("path", "sysvol/ProgramData/HitmanPro.Alert/excalibur.db"),
        ("path", "sysvol/ProgramData/HitmanPro/Quarantine"),
        # Malwarebytes
        ("glob", "sysvol/ProgramData/Malwarebytes/Malwarebytes Anti-Malware/Logs/mbam-log-*.xml"),
        ("glob", "sysvol/ProgramData/Malwarebytes/MBAMService/logs/mbamservice.log*"),
        ("path", "AppData/Roaming/Malwarebytes/Malwarebytes Anti-Malware/Logs", from_user_home),
        ("path", "sysvol/ProgramData/Malwarebytes/MBAMService/ScanResults"),
        # McAfee
        ("path", "Application Data/McAfee/DesktopProtection", from_user_home),
        ("path", "sysvol/ProgramData/McAfee/DesktopProtection"),
        ("path", "sysvol/ProgramData/McAfee/Endpoint Security/Logs"),
        ("path", "sysvol/ProgramData/McAfee/Endpoint Security/Logs_Old"),
        ("path", "sysvol/ProgramData/Mcafee/VirusScan"),
        ("path", "sysvol/ProgramData/McAfee/MSC/Logs"),
        ("path", "sysvol/ProgramData/McAfee/Agent/AgentEvents"),
        ("path", "sysvol/ProgramData/McAfee/Agent/logs"),
        ("path", "sysvol/ProgramData/McAfee/datreputation/Logs"),
        ("path", "sysvol/ProgramData/Mcafee/Managed/VirusScan/Logs"),
        ("path", "sysvol/Documents and Settings/All Users/Application Data/McAfee/Common Framework/AgentEvents"),
        ("path", "sysvol/Documents and Settings/All Users/Application Data/McAfee/MCLOGS/SAE"),
        ("path", "sysvol/Documents and Settings/All Users/Application Data/McAfee/datreputation/Logs"),
        ("path", "sysvol/Documents and Settings/All Users/Application Data/McAfee/Managed/VirusScan/Logs"),
        ("path", "sysvol/Program Files (x86)/McAfee/DLP/WCF Service/Log"),
        # McAfee ePO
        ("path", "sysvol/Program Files (x86)/McAfee/ePolicy Orchestrator/Apache2/Logs"),
        ("path", "sysvol/Program Files (x86)/McAfee/ePolicy Orchestrator/DB/Events"),
        ("path", "sysvol/Program Files (x86)/McAfee/ePolicy Orchestrator/DB/Events/Debug"),
        ("path", "sysvol/Program Files (x86)/McAfee/ePolicy Orchestrator/Server/Logs"),
        # RogueKiller
        ("glob", "sysvol/ProgramData/RogueKiller/logs/AdliceReport_*.json"),
        # SUPERAntiSpyware
        ("path", "AppData/Roaming/SUPERAntiSpyware/Logs", from_user_home),
        # SecureAge
        ("path", "sysvol/ProgramData/SecureAge Technology/SecureAge/log"),
        # SentinelOne
        ("path", "sysvol/programdata/sentinel/logs"),
        # Sophos
        ("glob", "sysvol/Documents and Settings/All Users/Application Data/Sophos/Sophos */Logs"),
        ("glob", "sysvol/ProgramData/Sophos/Sophos */Logs"),
        ("path", "sysvol/ProgramData/Sophos/Logs"),
        # Symantec
        (
            "path",
            "sysvol/Documents and Settings/All Users/Application Data/Symantec/Symantec Endpoint Protection/Logs/AV",
        ),
        ("glob", "sysvol/ProgramData/Symantec/Symantec Endpoint Protection/*/Data/Logs"),
        ("path", "AppData/Local/Symantec/Symantec Endpoint Protection/Logs", from_user_home),
        ("path", "sysvol/Windows/System32/winevt/logs/Symantec Endpoint Protection Client.evtx"),
        ("glob", "sysvol/ProgramData/Symantec/Symantec Endpoint Protection/*/Data/CmnClnt/ccSubSDK"),
        ("glob", "sysvol/ProgramData/Symantec/Symantec Endpoint Protection/*/Data/registrationInfo.xml"),
        # TotalAV
        ("glob", "sysvol/Program Files*/TotalAV/logs"),
        ("path", "sysvol/ProgramData/TotalAV/logs"),
        # Trendmicro
        ("glob", "sysvol/Program Files*/Trend Micro"),
        ("path", "sysvol/ProgramData/Trend Micro"),
        # VIPRE
        ("path", "sysvol/ProgramData/VIPRE Business Agent/Logs"),
        ("path", "AppData/Roaming/VIPRE Business", from_user_home),
        ("path", "AppData/Roaming/GFI Software/AntiMalware/Logs", from_user_home),
        ("path", "AppData/Roaming/Sunbelt Software/AntiMalware/Logs", from_user_home),
        # Webroot
        ("path", "sysvol/ProgramData/WRData/WRLog.log"),
        # Microsoft Windows Defender
        ("path", "sysvol/ProgramData/Microsoft/Microsoft AntiMalware/Support"),
        ("glob", "sysvol/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender*.evtx"),
        ("path", "sysvol/ProgramData/Microsoft/Windows Defender/Support"),
        ("path", "sysvol/ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory"),
        ("path", "sysvol/Windows/Temp/MpCmdRun.log"),
        ("path", "sysvol/Windows.old/Windows/Temp/MpCmdRun.log"),
        ("path", "sysvol/ProgramData/Microsoft/Windows Defender/Scans/History/Service/Detection.log"),
        # Microsoft Safety Scanner
        ("path", "sysvol/Windows/Debug/msert.log"),
    )


@register_module("--quarantined")
class QuarantinedFiles(Module):
    DESC = "files quarantined by various antivirus products"
    SPEC = (
        # Microsoft Defender
        # https://knez.github.io/posts/how-to-extract-quarantine-files-from-windows-defender/
        ("path", "sysvol/ProgramData/Microsoft/Windows Defender/Quarantine"),
        # Symantec Endpoint Protection
        (
            "path",
            "sysvol/Documents and Settings/All Users/Application Data/Symantec/Symantec Endpoint Protection/Quarantine",
        ),
        ("glob", "sysvol/ProgramData/Symantec/Symantec Endpoint Protection/*/Data/Quarantine"),
        # Trend Micro
        # https://secret.inf.ufpr.br/papers/marcus_av_handson.pdf
        ("path", "sysvol/ProgramData/Trend Micro/AMSP/quarantine"),
        # McAfee
        ("path", "sysvol/Quarantine"),
        ("path", "sysvol/ProgramData/McAfee/VirusScan/Quarantine"),
        # Sophos
        ("glob", "sysvol/ProgramData/Sophos/Sophos/*/Quarantine"),
        ("glob", "sysvol/ProgramData/Sophos/Sophos */INFECTED"),
        ("path", "sysvol/ProgramData/Sophos/Safestore"),
        # HitmanPRO
        ("path", "sysvol/ProgramData/HitmanPro/Quarantine"),
    )


@register_module("--edr")
class EDR(Module):
    DESC = "various Endpoint Detection and Response (EDR) logs"
    SPEC = (
        # Carbon Black
        ("path", "sysvol/ProgramData/CarbonBlack/Logs"),
    )


@register_module("--history")
class History(Module):
    DESC = "browser history from IE, Edge, Firefox, and Chrome"

    class DirCombinations(NamedTuple):
        root_dirs: list[str]
        dir_extensions: list[str]
        history_files: list[str]

    COMMON_DIR_COMBINATIONS = (
        DirCombinations(
            [
                # Chromium - RHEL/Ubuntu - DNF/apt
                ".config/chromium",
                # Chrome - RHEL/Ubuntu - DNF
                ".config/google-chrome",
                # Edge - RHEL/Ubuntu - DNF/apt
                ".config/microsoft-edge",
                # Chrome - RHEL/Ubuntu - Flatpak
                ".var/app/com.google.Chrome/config/google-chrome",
                # Edge - RHEL/Ubuntu - Flatpak
                ".var/app/com.microsoft.Edge/config/microsoft-edge",
                # Chromium - RHEL/Ubuntu - Flatpak
                ".var/app/org.chromium.Chromium/config/chromium",
                # Chrome
                "AppData/Local/Google/Chrom*/User Data",
                # Edge
                "AppData/Local/Microsoft/Edge/User Data",
                "Library/Application Support/Microsoft Edge",
                "Local Settings/Application Data/Microsoft/Edge/User Data",
                # Chrome - Legacy
                "Library/Application Support/Chromium",
                "Library/Application Support/Google/Chrome",
                "Local Settings/Application Data/Google/Chrom*/User Data",
                # Chromium - RHEL/Ubuntu - snap
                "snap/chromium/common/chromium",
                # Brave - Windows
                "AppData/Local/BraveSoftware/Brave-Browser/User Data",
                "AppData/Roaming/BraveSoftware/Brave-Browser/User Data",
                # Brave - Linux
                ".config/BraveSoftware",
                # Brave - MacOS
                "Library/Application Support/BraveSoftware",
            ],
            ["*", "Snapshots/*/*"],
            [
                "Archived History",
                "Bookmarks",
                "Cookies*",
                "Network",
                "Current Session",
                "Current Tabs",
                "Extension Cookies",
                "Favicons",
                "History",
                "Last Session",
                "Last Tabs",
                "Login Data",
                "Login Data For Account",
                "Media History",
                "Shortcuts",
                "Snapshots",
                "Top Sites",
                "Web Data",
            ],
        ),
    )

    SPEC = (
        # IE
        ("path", "AppData/Local/Microsoft/Internet Explorer/Recovery", from_user_home),
        ("path", "AppData/Local/Microsoft/Windows/INetCookies", from_user_home),
        ("glob", "AppData/Local/Microsoft/Windows/WebCache/*.dat", from_user_home),
        # IE - index.dat
        ("path", "Cookies/index.dat", from_user_home),
        ("path", "Local Settings/History/History.IE5/index.dat", from_user_home),
        ("glob", "Local Settings/History/History.IE5/MSHist*/index.dat", from_user_home),
        ("path", "Local Settings/Temporary Internet Files/Content.IE5/index.dat", from_user_home),
        ("path", "Local Settings/Application Data/Microsoft/Feeds Cache/index.dat", from_user_home),
        ("path", "AppData/Local/Microsoft/Windows/History/History.IE5/index.dat", from_user_home),
        ("glob", "AppData/Local/Microsoft/Windows/History/History.IE5/MSHist*/index.dat", from_user_home),
        ("path", "AppData/Local/Microsoft/Windows/History/Low/History.IE5/index.dat", from_user_home),
        ("glob", "AppData/Local/Microsoft/Windows/History/Low/History.IE5/MSHist*/index.dat", from_user_home),
        ("path", "AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.IE5/index.dat", from_user_home),
        ("path", "AppData/Local/Microsoft/Windows/Temporary Internet Files/Low/Content.IE5/index.dat", from_user_home),
        ("path", "AppData/Roaming/Microsoft/Windows/Cookies/index.dat", from_user_home),
        ("path", "AppData/Roaming/Microsoft/Windows/Cookies/Low/index.dat", from_user_home),
        ("path", "AppData/Roaming/Microsoft/Windows/IEDownloadHistory/index.dat", from_user_home),
        # Firefox - Windows
        ("glob", "AppData/Local/Mozilla/Firefox/Profiles/*/*.sqlite*", from_user_home),
        ("glob", "AppData/Roaming/Mozilla/Firefox/Profiles/*/*.sqlite*", from_user_home),
        ("glob", "Application Data/Mozilla/Firefox/Profiles/*/*.sqlite*", from_user_home),
        # Firefox - macOS
        ("glob", "/Users/*/Library/Application Support/Firefox/Profiles/*/*.sqlite*"),
        # Firefox - RHEL/Ubuntu - Flatpak
        ("glob", ".var/app/org.mozilla.firefox/.mozilla/firefox/*/*.sqlite*", from_user_home),
        # Firefox - RHEL/Ubuntu - DNF/apt
        ("glob", ".mozilla/firefox/*/*.sqlite*", from_user_home),
        # Firefox - RHEL/Ubuntu - snap
        ("glob", "snap/firefox/common/.mozilla/firefox/*/*.sqlite*", from_user_home),
        # Brave - Ubuntu - snap
        ("glob", "snap/brave/[0-9]*/.config/BraveSoftware/**", from_user_home),
        # Safari - macOS
        ("path", "Library/Safari/Bookmarks.plist", from_user_home),
        ("path", "Library/Safari/Downloads.plist", from_user_home),
        ("path", "Library/Safari/Extensions/Extensions.plist", from_user_home),
        ("glob", "Library/Safari/History.*", from_user_home),
        ("path", "Library/Safari/LastSession.plist", from_user_home),
        ("path", "Library/Caches/com.apple.Safari/Cache.db", from_user_home),
    )

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()
        for root_dirs, extension_dirs, history_files in cls.COMMON_DIR_COMBINATIONS:
            for root_dir, extension_dir, history_file in product(root_dirs, extension_dirs, history_files):
                full_path = f"{root_dir}/{extension_dir}/{history_file}"
                search_type = "glob" if "*" in full_path else "path"

                spec.add((search_type, full_path, from_user_home))

        return spec


@register_module("--remoteaccess")
class RemoteAccess(Module):
    DESC = "common remote access tools' log files"
    SPEC = (
        # teamviewer
        ("glob", "sysvol/Program Files/TeamViewer/*.log"),
        ("glob", "sysvol/Program Files (x86)/TeamViewer/*.log"),
        ("glob", "/var/log/teamviewer*/*.log"),
        ("glob", "AppData/Roaming/TeamViewer/*.log", from_user_home),
        ("glob", "Library/Logs/TeamViewer/*.log", from_user_home),
        # anydesk - Windows
        ("path", "sysvol/ProgramData/AnyDesk"),
        ("path", "AppData/Roaming/AnyDesk", from_user_home),
        # anydesk - Mac + Linux
        ("glob", ".anydesk*/*", from_user_home),
        ("path", "/var/log/anydesk.trace"),
        # RustDesk - Windows
        ("path", "sysvol/ProgramData/RustDesk"),
        ("path", "AppData/Roaming/RustDesk/log/server/", from_user_home),
        # RustDesk - Mac + Linux
        ("path", ".local/share/logs/RustDesk/server/", from_user_home),
        ("path", "/var/log/RustDesk"),
        ("path", "Library/Logs/RustDesk/Server", from_user_home),
        # zoho
        ("path", "sysvol/ProgramData/ZohoMeeting/log"),
        ("path", "AppData/Local/ZohoMeeting/log", from_user_home),
        # realvnc
        ("path", "sysvol/ProgramData/RealVNC-Service/vncserver.log"),
        ("path", "AppData/Local/RealVNC/vncserver.log", from_user_home),
        # tightvnc
        ("path", "sysvol/ProgramData/TightVNC/Server/Logs"),
        # Remote desktop cache files
        ("path", "AppData/Local/Microsoft/Terminal Server Client/Cache", from_user_home),
        # Splashtop
        ("path", "sysvol/ProgramData/Splashtop/Temp/log"),
        ("path", "sysvol/Program Files (x86)/Splashtop/Splashtop Remote/Server/log"),
    )


@register_module("--webhosting")
class WebHosting(Module):
    DESC = "Web hosting software log files"
    SPEC = (
        # cPanel
        ("path", "/usr/local/cpanel/logs"),
        ("path", ".lastlogin", from_user_home),
    )


@register_module("--wer")
class WER(Module):
    DESC = "WER (Windows Error Reporting) related files"

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()

        for wer_dir in itertools.chain(
            ["sysvol/ProgramData/Microsoft/Windows/WER"],
            from_user_home(target, "AppData/Local/Microsoft/Windows/WER"),
        ):
            for path in target.fs.path(wer_dir).rglob("*"):
                if not path.is_file():
                    continue

                if path.stat().st_size >= (1024 * 1024 * 1024):  # 1GB
                    log.debug("Skipping WER file because it exceeds 1GB: %s", path)
                    continue

                spec.add(("path", path))

        return spec


@register_module("--etc")
class Etc(Module):
    SPEC = (
        # In OS-X /etc is a symlink to /private/etc. To prevent collecting
        # duplicates, we only use the /etc directory here.
        ("path", "/etc"),
        ("path", "/usr/local/etc"),
    )


@register_module("--boot")
class Boot(Module):
    SPEC = (
        ("glob", "/boot/config*"),
        ("glob", "/boot/efi*"),
        ("glob", "/boot/grub*"),
        ("glob", "/boot/init*"),
        ("glob", "/boot/system*"),
        # Proxmox specific file
        ("glob", "/boot/pve*"),
    )


def private_key_filter(path: fsutil.TargetPath) -> bool:
    if path.is_file() and not path.is_symlink():
        with path.open("rt") as file:
            return "PRIVATE KEY" in file.readline()
    return False


@register_module("--home")
class Home(Module):
    SPEC = (
        # Catches most shell related configuration files
        ("glob", ".*[akz]sh*", from_user_home),
        ("glob", "*/.*[akz]sh*", from_user_home),
        # Added to catch any shell related configuration file not caught with the above glob
        ("glob", ".*history", from_user_home),
        ("glob", "*/.*history", from_user_home),
        ("glob", ".*rc", from_user_home),
        ("glob", "*/.*rc", from_user_home),
        ("glob", ".*_logout", from_user_home),
        ("glob", "*/.*_logout", from_user_home),
        # Miscellaneous configuration files
        ("path", ".config", from_user_home),
        ("glob", "*/.config", from_user_home),
        ("path", ".wget-hsts", from_user_home),
        ("glob", "*/.wget-hsts", from_user_home),
        ("path", ".gitconfig", from_user_home),
        ("glob", "*/.gitconfig", from_user_home),
        ("path", ".selected_editor", from_user_home),
        ("glob", "*/.selected_editor", from_user_home),
        ("path", ".viminfo", from_user_home),
        ("glob", "*/.viminfo", from_user_home),
        ("path", ".lesshist", from_user_home),
        ("glob", "*/.lesshist", from_user_home),
        ("path", ".profile", from_user_home),
        ("glob", "*/.profile", from_user_home),
        # OS-X home (aka /Users)
        ("glob", ".bash_sessions/*", from_user_home),
        ("glob", "Library/LaunchAgents/*", from_user_home),
        ("glob", "Library/Logs/*", from_user_home),
        ("glob", "Preferences/*", from_user_home),
        ("glob", "Library/Preferences/*", from_user_home),
    )


@register_module("--ssh")
@module_arg("--private-keys", action=argparse.BooleanOptionalAction, help="Add any private keys")
class SSH(Module):
    SPEC = (
        ("glob", ".ssh/*", from_user_home),
        ("glob", "/etc/ssh/*"),
        ("glob", "sysvol/ProgramData/ssh/*"),
    )

    @classmethod
    def run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        # Acquire SSH configuration in sshd directories

        filter = None if cli_args.private_keys else private_key_filter

        if filter:
            log.info("Executing SSH without --private-keys, skipping private keys.")

        with collector.file_filter(filter):
            super().run(target, cli_args, collector)


@register_module("--docker")
class Docker(Module):
    DESC = "various Docker logs and configuration files"
    SPEC = (
        # Container log files
        ("glob", "/var/lib/docker/containers/*/*-json.log"),
        ("glob", "/var/lib/docker/containers/*/*.json"),
        ("glob", "/var/lib/docker/containers/*/hostname"),
        # Linux daemon configs
        ("path", "/etc/docker/daemon.json"),
        ("path", "/var/snap/docker/current/config/daemon.json"),
        # Windows daemon configs
        ("path", "sysvol/ProgramData/docker/config/daemon.json"),
        # User-specific config files (MacOS/Linux/Windows)
        ("path", ".docker/daemon.json", from_user_home),
        # Repositories
        ("path", "/var/lib/docker/image/overlay2/repositories.json"),
    )


@register_module("--var")
class Var(Module):
    SPEC = (
        # In OS-X /var is a symlink to /private/var. To prevent collecting
        # duplicates, we only use the /var directory here.
        ("path", "/var/log"),
        ("path", "/var/spool/at"),
        ("path", "/var/spool/cron"),
        ("path", "/var/spool/anacron"),
        ("path", "/var/lib/dpkg/status"),
        ("path", "/var/lib/rpm"),
        ("path", "/var/db"),
        ("path", "/var/audit"),
        ("path", "/var/cron"),
        ("path", "/var/run"),
        # Proxmox specific files
        ("path", "/var/lib/pve-cluster"),
        ("path", "/var/lib/pve-firewall"),
        ("path", "/var/lib/pve-manager"),
        # some OS-X specific files
        ("path", "/private/var/at"),
        ("path", "/private/var/db/diagnostics"),
        ("path", "/private/var/db/uuidtext"),
        ("path", "/private/var/vm/sleepimage"),
        ("glob", "/private/var/vm/swapfile*"),
        ("glob", "/private/var/folders/*/*/0/com.apple.notificationcenter/*/*"),
        # user specific cron on OS-X
        ("path", "/usr/lib/cron"),
    )


@register_module("--bsd")
class BSD(Module):
    SPEC = (
        ("path", "/bin/freebsd-version"),
        ("path", "/usr/ports"),
    )


@register_module("--applications")
class Applications(Module):
    SPEC = (
        ("path", "/usr/share/applications"),
        ("path", "/usr/local/share/applications"),
        ("path", "/var/lib/snapd/desktop/applications"),
        ("path", "/var/lib/flatpak/exports/share/applications"),
        ("path", ".local/share/applications", from_user_home),
    )


@register_module("--network")
class Network(Module):
    SPEC = (
        ("path", "/etc/systemd/network"),
        ("path", "/run/systemd/network"),
        ("path", "/usr/lib/systemd/network"),
        ("path", "/usr/local/lib/systemd/network"),
        ("path", "/etc/NetworkManager/system-connections"),
        ("path", "/usr/lib/NetworkManager/system-connections"),
        ("path", "/run/NetworkManager/system-connections"),
    )


@register_module("--macos")
class MacOS(Module):
    DESC = "macOS / OSX specific files and directories"
    SPEC = (
        # filesystem events
        ("path", "/.fseventsd"),
        # kernel extensions
        ("path", "/Library/Extensions"),
        ("path", "/System/Library/Extensions"),
        # logs
        ("path", "/Library/Logs"),
        # autorun locations
        ("path", "/Library/LaunchAgents"),
        ("path", "/Library/LaunchDaemons"),
        ("path", "/Library/StartupItems"),
        ("path", "/System/Library/LaunchAgents"),
        ("path", "/System/Library/LaunchDaemons"),
        ("path", "/System/Library/StartupItems"),
        # installed software
        ("path", "/Library/Receipts/InstallHistory.plist"),
        ("path", "/System/Library/CoreServices/SystemVersion.plist"),
        # system preferences
        ("path", "/Library/Preferences"),
        # DHCP settings
        ("path", "/private/var/db/dhcpclient/leases"),
    )


@register_module("--macos-applications-info")
class MacOSApplicationsInfo(Module):
    DESC = "macOS / OSX info.plist from all installed applications"
    SPEC = (
        ("glob", "/Applications/*/Contents/Info.plist"),
        ("glob", "Applications/*/Contents/Info.plist", from_user_home),
    )


@register_module("--bootbanks")
class Bootbanks(Module):
    DESC = "ESXi bootbanks"

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        # Both ESXi 6 and 7 compatible
        boot_dirs = {
            "boot": "BOOT",
            "bootbank": "BOOTBANK1",
            "altbootbank": "BOOTBANK2",
        }
        boot_fs = {}

        for boot_dir, boot_vol in boot_dirs.items():
            dir_path = target.fs.path(boot_dir)
            if dir_path.is_symlink() and dir_path.exists():
                dst = dir_path.readlink()
                fs = dst.get().top.fs
                boot_fs[fs] = boot_vol

        for fs, mountpoint, uuid, _ in iter_esxi_filesystems(target):
            if fs in boot_fs:
                name = boot_fs[fs]
                log.info("Acquiring %s (%s)", mountpoint, name)
                mountpoint_len = len(mountpoint)
                base = f"fs/{uuid}:{name}"
                for path in target.fs.path(mountpoint).rglob("*"):
                    outpath = path.as_posix()[mountpoint_len:]
                    collector.collect_path(path, outpath=outpath, base=base)


@register_module("--esxi")
class ESXi(Module):
    DESC = "ESXi interesting files"
    SPEC = (
        ("path", "/scratch/log"),
        ("path", "/locker/packages/var"),
        # ESXi 7
        ("path", "/scratch/cache"),
        ("path", "/scratch/vmkdump"),
        # ESXi 6
        ("path", "/scratch/vmware"),
    )


@register_module("--vmfs")
class VMFS(Module):
    DESC = "ESXi VMFS metadata files"

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        for fs, mountpoint, uuid, name in iter_esxi_filesystems(target):
            if fs.__type__ != "vmfs":
                continue

            log.info("Acquiring %s (%s)", mountpoint, name)
            mountpoint_len = len(mountpoint)
            base = f"fs/{uuid}:{name}"
            for path in target.fs.path(mountpoint).glob("*.sf"):
                outpath = path.as_posix()[mountpoint_len:]
                collector.collect_path(path, outpath=outpath, base=base)


@register_module("--activities-cache")
class ActivitiesCache(Module):
    DESC = "user's activities caches"
    SPEC = (("path", "AppData/Local/ConnectedDevicesPlatform", from_user_home),)


@register_module("--hashes")
@module_arg(
    "--hash-func",
    action="append",
    type=HashFunc,
    choices=[h.value for h in HashFunc],
    help="Hash function to use",
)
@module_arg("--dir-to-hash", action="append", help="Hash only files in a provided directory")
@module_arg("--ext-to-hash", action="append", help="Hash only files with the extensions provided")
@module_arg("--glob-to-hash", action="append", help="Hash only files that match provided glob")
class FileHashes(Module):
    DESC = "file hashes"

    DEFAULT_HASH_FUNCS = (HashFunc.MD5, HashFunc.SHA1, HashFunc.SHA256)
    DEFAULT_EXTENSIONS = (
        "bat",
        "cmd",
        "com",
        "dll",
        "exe",
        "installlog",
        "installutil",
        "js",
        "lnk",
        "ps1",
        "sys",
        "tlb",
        "vbs",
    )
    DEFAULT_PATHS = ("sysvol/Windows/",)

    MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100MB

    DEFAULT_FILE_FILTERS = (
        functools.partial(filter_out_by_path_match, re_pattern="^/(sysvol/)?Windows/WinSxS/"),
        functools.partial(filter_out_huge_files, max_size_bytes=MAX_FILE_SIZE_BYTES),
        functools.partial(filter_out_by_value_match, value=b"MZ", offsets=[0, 3]),
    )

    @classmethod
    def run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        log.info("*** Acquiring file hashes")

        specs = cls.get_specs(cli_args)

        with collector.bind_module(cls):
            start = time.time()

            path_hashes = collect_hashes(target, specs, path_filters=cls.DEFAULT_FILE_FILTERS)
            rows_count, csv_compressed_bytes = serialize_into_csv(path_hashes, compress=True)

            collector.write_bytes(
                f"{collector.base}/{collector.METADATA_BASE}/file-hashes.csv.gz",
                csv_compressed_bytes,
            )
            log.info("Hashing is done, %s files processed in %.2f secs", rows_count, (time.time() - start))

    @classmethod
    def get_specs(cls, cli_args: argparse.Namespace) -> Iterator[tuple]:
        path_selectors = []

        extensions = cli_args.ext_to_hash if cli_args.ext_to_hash else cls.DEFAULT_EXTENSIONS

        if cli_args.dir_to_hash or cli_args.glob_to_hash:
            if cli_args.glob_to_hash:
                path_selectors.extend([("glob", glob) for glob in cli_args.glob_to_hash])

            if cli_args.dir_to_hash:
                path_selectors.extend([("path", (dir_path, extensions)) for dir_path in cli_args.dir_to_hash])

        else:
            path_selectors.extend([("path", (dir_path, extensions)) for dir_path in cls.DEFAULT_PATHS])

        hash_funcs = cli_args.hash_func if cli_args.hash_func else cls.DEFAULT_HASH_FUNCS

        return [(path_selector, hash_funcs) for path_selector in path_selectors]


@register_module("--handles")
@module_arg(
    "--handle-types",
    action="extend",
    help="Collect only specified handle types",
    type=NamedObjectType,
    choices=[h.value for h in NamedObjectType],
    nargs="*",
)
@local_module
class OpenHandles(Module):
    DESC = "Open handles"

    @classmethod
    def run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        if sys.platform != "win32":
            log.error("Open Handles plugin can only run on Windows systems! Skipping...")
            return

        from acquire.dynamic.windows.collect import collect_open_handles
        from acquire.dynamic.windows.handles import serialize_handles_into_csv

        log.info("*** Acquiring open handles")

        handle_types = cli_args.handle_types

        with collector.bind_module(cls):
            handles = collect_open_handles(handle_types)
            csv_compressed_handles = serialize_handles_into_csv(handles)

            collector.write_bytes(
                f"{collector.base}/{collector.METADATA_BASE}/open_handles.csv.gz",
                csv_compressed_handles,
            )
            log.info("Collecting open handles is done.")


@register_module("--dpapi")
class DPAPI(Module):
    SPEC = (
        ("path", "sysvol/Windows/System32/Microsoft/Protect"),
        ("path", "AppData/Roaming/Microsoft/Protect", from_user_home),
        ("path", "Application Data/Microsoft/Protect", from_user_home),
    )


def print_disks_overview(target: Target) -> None:
    log.info("// Disks")
    try:
        for disk in target.disks:
            log.info("%s", disk)
            if not disk.vs:
                continue

            for volume in disk.vs.volumes:
                log.info("- %s", volume)
    except Exception:
        log.error("Failed to iterate disks")  # noqa: TRY400
    log.info("")


def print_volumes_overview(target: Target) -> None:
    log.info("// Volumes")
    try:
        for volume in target.volumes:
            log.info("%s", volume)
    except Exception:
        log.error("Failed to iterate volumes")  # noqa: TRY400
    log.info("")


def print_acquire_warning(target: Target) -> None:
    if target.os != "windows":
        log.warning("========================================== WARNING ==========================================")
        log.warning("")
        log.warning(
            "The support for operating system '%s' is experimental. Some artifacts may not yet be included and some ",
            target.os,
        )
        log.warning("features may not work as expected. Please notify upstream for any missing artifacts or features.")
        log.warning("")
        log.warning("========================================== WARNING ==========================================")


def _get_modules_for_profile(
    target: Target,
    profile_name: str,
    profiles: dict[str, dict[str, list[type[Module]]]],
    err_msg: str,
) -> dict[str, type[Module]]:
    if profile_name == "none":
        return {}

    if (profile_os := profiles.get(profile_name)) is None:
        log.error("No profile found named %s", profile_name)
        return {}

    if (profile := profile_os.get(target.os)) is None:
        for os in target.os_tree():
            if profile := profile_os.get(os):
                log.info(
                    "No collection set for OS %r with profile %r, using the one for OS %r instead",
                    target.os,
                    profile_name,
                    os,
                )
                break

    if not profile:
        log.error(err_msg, target.os, profile_name)
        return {}

    selected_modules = {}

    for mod in profile:
        selected_modules[mod.__modname__] = mod

    return selected_modules


def acquire_target(target: Target, args: argparse.Namespace, output_ts: str | None = None) -> list[str | Path]:
    acquire_gui = GUI()
    files = []
    output_ts = output_ts or get_utc_now_str()
    if args.log_to_dir:
        log_file = args.log_path.joinpath(format_output_name("Unknown", output_ts, "log"))
        # This will also rename the log file on disk, which was opened in main(), if the name is different
        reconfigure_log_file(log, log_file, delay=True)
    else:
        log_file = args.log_path

    skip_list = set()
    if log_file:
        files.append(log_file)
        if target.path.name == "local":
            skip_list.add(normalize_path(target, log_file, resolve_parents=True, preserve_case=False))

    print_disks_overview(target)
    print_volumes_overview(target)

    if not target._os_plugin:
        log.error("Error: Unable to detect OS")
        return files

    hostname = ""
    try:
        hostname = target.hostname
    except Exception:
        log.exception("Failed to get hostname")

    version = None
    try:
        version = target.version
    except Exception:
        log.exception("Failed to detect OS version")

    if version is None:
        os_plugin_name = target._os_plugin.__name__.lower()
        version = f"{target.os} ({os_plugin_name})"

    log.info("Target name: %s", target.name)
    log.info("Hostname: %s", hostname)
    log.info("OS: %s", version)
    log.info("")

    print_acquire_warning(target)

    modules_selected = {}
    modules_disabled = []
    modules_successful = []
    modules_failed = {}
    for name, mod in MODULES.items():
        name_slug = name.lower()
        # check if module was set in the arguments provided
        if (mod_arg := getattr(args, name_slug)) is True:
            modules_selected[name] = mod
        elif mod_arg is False:
            modules_disabled.append(name)

    profile = args.profile

    # Set profile to default if no profile, modules, files, directories or globes were selected
    if not profile and not modules_selected and not args.path and not args.glob:
        log.info("Using default collection profile")
        profile = "default"
        log.info("")

    normal_modules = _get_modules_for_profile(
        target, profile, PROFILES, "No collection set for OS '%s' with profile '%s'"
    )
    modules_selected.update(normal_modules)

    if not (volatile_profile := args.volatile_profile):
        volatile_profile = "none"

    volatile_modules = _get_modules_for_profile(
        target, volatile_profile, VOLATILE, "No collection set for OS '%s' with volatile profile '%s'"
    )
    modules_selected.update(volatile_modules)

    # Filter modules that are explicitly disabled
    for name in modules_disabled:
        modules_selected.pop(name, None)

    if not modules_selected:
        log.warning("NO modules selected!")
    else:
        log.info("Modules selected: %s", ", ".join(sorted(modules_selected)))

    local_only_modules = {name: module for name, module in modules_selected.items() if hasattr(module, "__local__")}
    if target.path.name != "local" and local_only_modules:
        for module in local_only_modules.values():
            modules_failed[module.__name__] = "Not running on a local target"
        log.error(
            "Can not use local-only modules with non-local targets. Skipping: %s",
            " ".join(sorted(local_only_modules.keys())),
        )
        log.info("")
        # Remove local-only modules from the modules list
        modules_selected = dict(modules_selected.items() - local_only_modules.items())

    log_file_handler = get_file_handler(log)
    # Prepare log file and output file names
    if log_file_handler and args.log_to_dir:
        log_file = format_output_name(target.name, output_ts, "log")
        # This will also rename the log file on disk, which was opened and written previously.
        log_file_handler.set_filename(log_file)
        log_path = Path(log_file_handler.baseFilename).resolve()
        log.info("Logging to file %s", log_path)
        files = [log_file_handler.baseFilename]
        if target.path.name == "local":
            skip_list = {normalize_path(target, log_path, resolve_parents=True, preserve_case=False)}

    output_path = args.output or args.output_file
    if output_path.is_dir():
        output_dir = format_output_name(target.name, output_ts)
        output_path = output_path.joinpath(output_dir)
    output_path = output_path.resolve()

    output = OUTPUTS[args.output_type](
        output_path,
        compress=args.compress,
        compression_method=args.compress_method,
        encrypt=args.encrypt,
        public_key=args.public_key,
    )
    files.append(output.path)
    if target.path.name == "local":
        skip_list.add(normalize_path(target, output.path, resolve_parents=True, preserve_case=False))

    log.info("Writing output to %s", output.path)
    if skip_list:
        log.info("Skipping own files: %s", ", ".join(skip_list))
    log.info("")

    dir_base = "fs"
    if target.os != "windows":
        dir_base = "fs/$rootfs$"

    with Collector(target, output, base=dir_base, skip_list=skip_list) as collector:
        # Acquire specified files
        if args.path or args.glob:
            log.info("*** Acquiring specified paths")
            spec = []

            if args.path:
                spec.extend([("path", path.strip()) for path in args.path])

            if args.glob:
                spec.extend([("glob", path.strip()) for path in args.glob])

            collector.collect(spec, module_name=CLI_ARGS_MODULE)
            modules_successful.append(CLI_ARGS_MODULE)
            log.info("")

        # Run modules (sort first based on execution order)
        modules_selected = sorted(modules_selected.items(), key=lambda module: module[1].EXEC_ORDER)
        for count, (name, mod) in enumerate(modules_selected):
            try:
                mod.run(target, args, collector)

                modules_successful.append(mod.__name__)
            except Exception:
                log.exception("Error while running module %s", name)
                modules_failed[mod.__name__] = get_formatted_exception()

            acquire_gui.progress = (acquire_gui.shard // len(modules_selected)) * count
            count += 1

            log.info("")

        collection_report = collector.report

    log.info("Done collecting artifacts:")

    # prepare and render full report only if logging level is more permissive than INFO
    if log.level < logging.INFO:
        log.debug(get_full_formatted_report(collection_report))

    log.info(get_report_summary(collection_report))

    if not args.disable_report:
        collection_report_serialized = collection_report.get_records_per_module_per_outcome(serialize_records=True)

        execution_report = {
            "target": str(target),
            "name": target.name,
            "timestamp": get_utc_now().isoformat(),
            "modules-successful": modules_successful,
            "modules-failed": modules_failed,
            **collection_report_serialized,
        }

        if args.output:
            report_file_name = format_output_name(target.name, postfix=output_ts, ext="report.json")
        else:
            report_file_name = f"{output_path.name}.report.json"

        report_file_path = output_path.parent / report_file_name
        persist_execution_report(report_file_path, execution_report)

        files.append(report_file_path)
        log.info("Acquisition report for %s is written to %s", target, report_file_path)

    log.info("Output: %s", output.path)
    return files


def upload_files(paths: list[str | Path], upload_plugin: UploaderPlugin, no_proxy: bool = False) -> None:
    proxies = None if no_proxy else urllib.request.getproxies()
    log.debug("Proxies: %s (no_proxy = %s)", proxies, no_proxy)

    log.info('Uploading files: "%s"', " ".join(map(str, paths)))
    try:
        upload_files_using_uploader(upload_plugin, paths, proxies)
    except Exception:
        log.error('Upload FAILED for files: "%s". See log file for details.', " ".join(map(str, paths)))  # noqa: TRY400
        raise
    else:
        log.info("Upload succeeded.")


class WindowsProfile:
    MINIMAL = (
        NTFS,
        EventLogs,
        Registry,
        Tasks,
        PowerShell,
        Prefetch,
        Appcompat,
        PCA,
        Misc,
        Startup,
    )
    DEFAULT = (
        *MINIMAL,
        ETL,
        Recents,
        RecycleBin,
        Drivers,
        Syscache,
        WBEM,
        AV,
        BITS,
        DHCP,
        DNS,
        ActiveDirectory,
        RemoteAccess,
        ActivitiesCache,
        CamHistory,
        DPAPI,
    )
    FULL = (
        *DEFAULT,
        History,
        NTDS,
        QuarantinedFiles,
        WindowsNotifications,
        SSH,
        IIS,
        SharePoint,
        TextEditor,
        Docker,
        MSSQL,
    )


class LinuxProfile:
    MINIMAL = (
        Etc,
        Boot,
        Home,
        SSH,
        Var,
    )
    DEFAULT = MINIMAL
    FULL = (
        *DEFAULT,
        Applications,
        Network,
        Docker,
        History,
        WebHosting,
        MSSQL,
    )


class BsdProfile:
    MINIMAL = (
        Etc,
        Boot,
        Home,
        SSH,
        Var,
        BSD,
    )
    DEFAULT = MINIMAL
    FULL = MINIMAL


class ESXiProfile:
    MINIMAL = (
        Bootbanks,
        ESXi,
        SSH,
    )
    DEFAULT = (
        *MINIMAL,
        VMFS,
    )
    FULL = DEFAULT


class MacOSProfile:
    MINIMAL = (
        Etc,
        Home,
        Var,
        MacOS,
        MacOSApplicationsInfo,
    )
    DEFAULT = MINIMAL
    FULL = (
        *DEFAULT,
        History,
        SSH,
        Docker,
    )


class ProxmoxProfile:
    MINIMAL = (
        Etc,
        Boot,
        Home,
        SSH,
        Var,
    )
    DEFAULT = MINIMAL
    FULL = (
        *DEFAULT,
        History,
        WebHosting,
    )


PROFILES = {
    "full": {
        "windows": WindowsProfile.FULL,
        "linux": LinuxProfile.FULL,
        "bsd": BsdProfile.FULL,
        "esxi": ESXiProfile.FULL,
        "macos": MacOSProfile.FULL,
        "proxmox": ProxmoxProfile.FULL,
    },
    "default": {
        "windows": WindowsProfile.DEFAULT,
        "linux": LinuxProfile.DEFAULT,
        "bsd": BsdProfile.DEFAULT,
        "esxi": ESXiProfile.DEFAULT,
        "macos": MacOSProfile.DEFAULT,
        "proxmox": ProxmoxProfile.DEFAULT,
    },
    "minimal": {
        "windows": WindowsProfile.MINIMAL,
        "linux": LinuxProfile.MINIMAL,
        "bsd": BsdProfile.MINIMAL,
        "esxi": ESXiProfile.MINIMAL,
        "macos": MacOSProfile.MINIMAL,
        "proxmox": ProxmoxProfile.MINIMAL,
    },
    "none": None,
}


class VolatileProfile:
    DEFAULT = (
        Devices,
        Netstat,
        WinProcesses,
        WinProcEnv,
        WinArpCache,
        WinRDPSessions,
        WinDnsClientCache,
        ProcNet,
        Proc,
        Sys,
    )


VOLATILE = {
    "default": {
        "windows": VolatileProfile.DEFAULT,
        "linux": VolatileProfile.DEFAULT,
        "bsd": VolatileProfile.DEFAULT,
        "esxi": VolatileProfile.DEFAULT,
        "macos": [],
        # proxmox is debian based
        "proxmox": VolatileProfile.DEFAULT,
    },
    "none": None,
}


def exit_success(default_args: list[str]) -> NoReturn:
    log.info("Acquire finished successful")
    log.info("Arguments: %s", " ".join(sys.argv[1:]))
    log.info("Default Arguments: %s", " ".join(default_args))
    log.info("Exiting with status code 0 (SUCCESS)")
    sys.exit(0)


def exit_failure(default_args: list[str]) -> NoReturn:
    log.error("Acquire FAILED")
    log.error("Arguments: %s", " ".join(sys.argv[1:]))
    log.error("Default Arguments: %s", " ".join(default_args))
    log.error("Exiting with status code 1 (FAILURE)")
    sys.exit(1)


def main() -> None:
    parser = create_argument_parser(PROFILES, VOLATILE, MODULES)
    args, rest = parse_acquire_args(parser, config=CONFIG)

    # Since output has a default value, set it to None when output_file is defined
    if args.output_file:
        args.output = None

    try:
        check_and_set_log_args(args)
    except ValueError as err:
        parser.exit(err)

    if args.log_to_dir:
        # When args.upload files are specified, only these files are uploaded
        # and no other action is done. Thus a log file specifically named
        # Upload_<date>.log is created
        file_prefix = "Upload" if args.upload else "Unknown"
        log_file = args.log_path.joinpath(format_output_name(file_prefix, args.start_time, "log"))
    else:
        log_file = args.log_path

    setup_logging(log, log_file, args.verbose, delay=args.log_delay)

    acquire_successful = True
    files_to_upload = [log_file]
    acquire_gui = None
    try:
        log.info(ACQUIRE_BANNER)
        log.info("User: %s | Admin: %s", get_user_name(), is_user_admin())
        log.info("Arguments: %s", " ".join(sys.argv[1:]))
        log.info("Default Arguments: %s", " ".join(args.config.get("arguments")))
        log.info("")

        if any(arg in sys.argv for arg in ["--file", "--dir", "-f", "-d"]):
            warnings.warn(
                "--file and --dir are deprecated in favor of --path and will be removed in acquire 3.22",
                DeprecationWarning,
                stacklevel=2,
            )
        if "--proc-net" in sys.argv:
            warnings.warn(
                "--proc-net will be merged with --proc and will be removed in acquire 3.23",
                DeprecationWarning,
                stacklevel=2,
            )

        # start GUI if requested through CLI / config
        flavour = None
        if args.gui == "always" or (
            args.gui == "depends" and os.environ.get("PYS_KEYSOURCE") == "prompt" and len(sys.argv) == 1
        ):
            flavour = platform.system()
        acquire_gui = GUI(flavour=flavour, upload_available=args.auto_upload)

        args.output, args.auto_upload, cancel = acquire_gui.wait_for_start(args)
        if cancel:
            log.info("Acquire cancelled")
            exit_success(args.config.get("arguments"))
        # From here onwards, the GUI will be locked and cannot be closed because we're acquiring

        plugins_to_load = [("cloud", MinIO)]
        upload_plugins = UploaderRegistry("acquire.plugins", plugins_to_load)

        check_and_set_acquire_args(args, upload_plugins)

        if args.upload:
            try:
                upload_files(args.upload, args.upload_plugin, args.no_proxy)
            except Exception:
                acquire_gui.message("Failed to upload files")
                log.exception("")
                exit_failure(args.config.get("arguments"))
            exit_success(args.config.get("arguments"))

        target_paths = []
        for target_path in args.targets:
            target_path = args_to_uri([target_path], args.loader, rest)[0] if args.loader else target_path
            if target_path == "local":
                target_query = {}
                if args.force_fallback:
                    target_query.update({"force-directory-fs": 1})

                if args.fallback:
                    target_query.update({"fallback-to-directory-fs": 1})

                if args.enable_nfs:
                    target_query.update({"enable-nfs": 1})

                target_query = urllib.parse.urlencode(target_query)
                target_path = f"{target_path}?{target_query}"
            target_paths.append(target_path)

        try:
            target_name = "Unknown"  # just in case open_all already fails
            for target in Target.open_all(target_paths):
                target_name = "Unknown"  # overwrite previous target name
                target_name = target.name
                log.info("Loading target %s", target_name)
                log.info(target)
                if target.os == "esxi" and target.name == "local":
                    # Loader found that we are running on an esxi host
                    # Perform operations to "enhance" memory
                    with esxi_memory_context_manager():
                        files_to_upload = acquire_children_and_targets(target, args)
                else:
                    files_to_upload = acquire_children_and_targets(target, args)
        except Exception:
            log.error("Failed to acquire target: %s", target_name)  # noqa: TRY400
            if not is_user_admin():
                log.error("Try re-running as administrator/root")  # noqa: TRY400
                acquire_gui.message("This application must be run as administrator.")
            raise

        files_to_upload = sort_files(files_to_upload)

    except Exception:
        log.error("Acquiring artifacts FAILED")  # noqa: TRY400
        log.exception("")
        acquire_successful = False
    else:
        log.info("Acquiring artifacts succeeded")

    try:
        # The auto-upload of files is done at the very very end to make sure any
        # logged exceptions are written to the log file before uploading.
        # This means that any failures from this point on will not be part of the
        # uploaded log files, they will be written to the logfile on disk though.
        if args.auto_upload and args.upload_plugin and files_to_upload:
            try:
                log_file_handler = get_file_handler(log)
                if log_file_handler:
                    log_file_handler.close()

                upload_files(files_to_upload, args.upload_plugin)
            except Exception:
                if acquire_gui:
                    acquire_gui.message("Failed to upload files")
                raise

        if acquire_gui:
            acquire_gui.finish()
            acquire_gui.wait_for_quit()

    except Exception:
        acquire_successful = False
        log.exception("")

    if acquire_successful:
        exit_success(args.config.get("arguments"))
    else:
        exit_failure(args.config.get("arguments"))


def load_child(target: Target, child_path: Path) -> None:
    log.info("")
    log.info("Loading child target %s", child_path)
    try:
        child = target.open_child(child_path)
        log.info(target)
    except Exception:
        log.exception("Failed to load child target")
        raise

    return child


def acquire_children_and_targets(target: Target, args: argparse.Namespace) -> list[str | Path]:
    if args.child:
        target = load_child(target, args.child)

    log.info("")

    files = []
    acquire_gui = GUI()

    counter = 0
    progress_limit = 50 if args.auto_upload else 90
    total_targets = 0
    if args.children:
        total_targets += len(list(target.list_children()))

    if (args.children and not args.skip_parent) or not args.children:
        total_targets += 1
        counter += 1
        acquire_gui.shard = int((progress_limit / total_targets) * counter)
        try:
            files.extend(acquire_target(target, args, args.start_time))

        except Exception:
            log.error("Failed to acquire main target")  # noqa: TRY400
            acquire_gui.message("Failed to acquire target")
            acquire_gui.wait_for_quit()
            raise

    if args.children:
        for child in target.list_children():
            counter += 1
            acquire_gui.shard = int((progress_limit / total_targets) * counter)
            try:
                child_target = load_child(target, child.path)
            except Exception:
                continue

            log.info("")

            try:
                child_files = acquire_target(child_target, args)
                files.extend(child_files)
            except Exception:
                log.exception("Failed to acquire child target %s", child_target.name)
                acquire_gui.message("Failed to acquire child target")
                continue

    return files


def sort_files(files: list[str | Path]) -> list[Path]:
    log_files: list[Path] = []
    tar_paths: list[Path] = []
    report_paths: list[Path] = []

    suffix_map = {".log": log_files, ".json": report_paths}

    for file in files:
        if isinstance(file, str):
            file = Path(file)

        suffix_map.get(file.suffix, tar_paths).append(file)

    # Reverse log paths, as the first one in ``files`` is the main one.
    log_files.reverse()

    return tar_paths + report_paths + log_files


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception:
        sys.exit(1)
