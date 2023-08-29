import argparse
import enum
import functools
import io
import itertools
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Iterator, Optional, Union

from dissect.target import Target, exceptions
from dissect.target.filesystem import Filesystem
from dissect.target.filesystems import dir, ntfs
from dissect.target.helpers import fsutil
from dissect.target.loaders.remote import RemoteStreamConnection
from dissect.target.loaders.targetd import TargetdLoader
from dissect.target.plugins.apps.webservers import iis
from dissect.target.plugins.os.windows.log import evt, evtx

from acquire.collector import Collector, get_full_formatted_report, get_report_summary
from acquire.dynamic.windows.named_objects import NamedObjectType
from acquire.esxi import esxi_memory_context_manager
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
ACQUIRE_BANNER = r"""
                       _
  __ _  ___ __ _ _   _(_)_ __ ___
 / _` |/ __/ _` | | | | | '__/ _ \
| (_| | (_| (_| | |_| | | | |  __/
 \__,_|\___\__, |\__,_|_|_|  \___|
  by Fox-IT   |_|             v{}
  part of NCC Group
""".format(
    VERSION
)[
    1:
]

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
        ("windows/serviceprofiles/localservice", False),
        ("windows/serviceprofiles/networkservice", False),
        ("windows/system32/config/systemprofile", False),
        ("users", True),
        ("documents and settings", True),
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
    for home_dir in itertools.chain.from_iterable(home_dirs):
        yield home_dir


def misc_osx_user_homes(target: Target) -> Iterator[fsutil.TargetPath]:
    for homedir in itertools.chain(target.fs.path("/Users/").glob("*"), misc_unix_user_homes(target)):
        yield homedir


MISC_MAPPING = {
    "osx": misc_osx_user_homes,
    "windows": misc_windows_user_homes,
}


def from_user_home(target: Target, path: str) -> Iterator[str]:
    for user_details in target.user_details.all_with_home():
        yield str(user_details.home_path.joinpath(path))

    misc_user_homes = MISC_MAPPING.get(target.os, misc_unix_user_homes)
    for user_dir in misc_user_homes(target):
        yield str(user_dir.joinpath(path))


def iter_ntfs_filesystems(target: Target) -> Iterator[tuple[ntfs.NtfsFilesystem, str, str]]:
    mount_lookup = defaultdict(list)
    for mount, fs in target.fs.mounts.items():
        mount_lookup[fs].append(mount)

    sysvol = target.fs.mounts["sysvol"]
    for fs in target.filesystems:
        if fs in mount_lookup:
            mountpoints = ", ".join(mount_lookup[fs])
        else:
            mountpoints = "No mounts"

        if not isinstance(fs, ntfs.NtfsFilesystem):
            log.warning("Skipping %s (%s) - not an NTFS filesystem", fs, mountpoints)
            continue

        if fs == sysvol:
            name = "sysvol"
        elif fs in mount_lookup:
            name = mount_lookup[fs][0]
        else:
            name = f"vol-{fs.ntfs.serial:x}"

        yield fs, name, mountpoints


def mount_all_ntfs_filesystems(target: Target) -> None:
    for fs, name, _ in iter_ntfs_filesystems(target):
        if name not in target.fs.mounts:
            target.fs.mount(name, fs)


def iter_esxi_filesystems(target: Target) -> Iterator[tuple[str, str, Filesystem]]:
    for mount, fs in target.fs.mounts.items():
        if not mount.startswith("/vmfs/volumes/"):
            continue

        uuid = mount[len("/vmfs/volumes/") :]  # strip /vmfs/volumes/
        name = None
        if fs.__fstype__ == "fat":
            name = fs.volume.name
        elif fs.__fstype__ == "vmfs":
            name = fs.vmfs.label

        yield uuid, name, fs


def register_module(*args, **kwargs):
    def wrapper(module_cls):
        name = module_cls.__name__

        if name in MODULES:
            raise ValueError(
                f"Module name is already registered: registration for {module_cls} conflicts with {MODULES[name]}"
            )

        desc = module_cls.DESC or name
        kwargs["help"] = f"acquire {desc}"
        kwargs["action"] = "store_true"
        kwargs["dest"] = name.lower()
        module_cls.__modname__ = name

        if not hasattr(module_cls, "__cli_args__"):
            module_cls.__cli_args__ = []
        module_cls.__cli_args__.append((args, kwargs))

        MODULES[name] = module_cls
        return module_cls

    return wrapper


def module_arg(*args, **kwargs):
    def wrapper(module_cls):
        if not hasattr(module_cls, "__cli_args__"):
            module_cls.__cli_args__ = []
        module_cls.__cli_args__.append((args, kwargs))
        return module_cls

    return wrapper


def local_module(cls):
    """A decorator that sets property `__local__` on a module class to mark it for local target only"""
    cls.__local__ = True
    return cls


class ExecutionOrder(enum.IntEnum):
    TOP = 0
    DEFAULT = 1
    BOTTOM = 2


class Module:
    DESC = None
    SPEC = []
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
@local_module
class Sys(Module):
    DESC = "Sysfs files (live systems only)"
    EXEC_ORDER = ExecutionOrder.BOTTOM

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        if not Path("/sys").exists():
            log.error("/sys is unavailable! Skipping...")
            return

        spec = [("dir", "/sys")]

        sysfs = dir.DirectoryFilesystem(Path("/sys"))

        target.filesystems.add(sysfs)
        target.fs.mount("/sys", sysfs)

        collector.collect(spec, follow=False, volatile=True)


@register_module("--proc")
@local_module
class Proc(Module):
    DESC = "Procfs files (live systems only)"
    EXEC_ORDER = ExecutionOrder.BOTTOM

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        if not Path("/proc").exists():
            log.error("/proc is unavailable! Skipping...")
            return

        spec = [("dir", "/proc")]
        procfs = dir.DirectoryFilesystem(Path("/proc"))

        target.filesystems.add(procfs)
        target.fs.mount("/proc", procfs)

        collector.collect(spec, follow=False, volatile=True)


@register_module("-n", "--ntfs")
class NTFS(Module):
    DESC = "NTFS filesystem metadata"

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        for fs, name, mountpoints in iter_ntfs_filesystems(target):
            log.info("Acquiring %s (%s)", fs, mountpoints)

            collector.collect_file(fs.path("$MFT"), outpath=name + "/$MFT")
            collector.collect_file(fs.path("$Boot"), outpath=name + "/$Boot")

            cls.collect_usnjrnl(collector, fs, name)
            cls.collect_ntfs_secure(collector, fs, name)

    @classmethod
    def collect_usnjrnl(cls, collector: Collector, fs: Filesystem, name: str) -> None:
        try:
            usnjrnl_path = fs.path("$Extend/$Usnjrnl:$J")
            entry = usnjrnl_path.get()
            journal = entry.open()

            i = 0
            while journal.runlist[i][0] is None:
                journal.seek(journal.runlist[i][1] * journal.block_size, io.SEEK_CUR)
                i += 1

            collector.output.write(
                f"{collector.base}/{name}/$Extend/$Usnjrnl:$J",
                journal,
                size=journal.size - journal.tell(),
                entry=entry,
            )
            collector.report.add_file_collected(cls.__name__, usnjrnl_path)
            result = "OK"
        except exceptions.FileNotFoundError:
            collector.report.add_file_missing(cls.__name__, usnjrnl_path)
            result = "File not found"
        except Exception as err:
            log.debug("Failed to acquire UsnJrnl", exc_info=True)
            collector.report.add_file_failed(cls.__name__, usnjrnl_path)
            result = repr(err)

        log.info("- Collecting file $Extend/$Usnjrnl:$J: %s", result)

    @classmethod
    def collect_ntfs_secure(cls, collector: Collector, fs: Filesystem, name: str) -> None:
        try:
            secure_path = fs.path("$Secure:$SDS")
            entry = secure_path.get()
            sds = entry.open()
            collector.output.write(
                f"{collector.base}/{name}/$Secure:$SDS",
                sds,
                size=sds.size,
                entry=entry,
            )
            collector.report.add_file_collected(cls.__name__, secure_path)
            result = "OK"
        except FileNotFoundError:
            collector.report.add_file_missing(cls.__name__, secure_path)
            result = "File not found"
        except Exception as err:
            log.debug("Failed to acquire SDS", exc_info=True)
            collector.report.add_file_failed(cls.__name__, secure_path)
            result = repr(err)

        log.info("- Collecting file $Secure:$SDS: %s", result)


@register_module("-r", "--registry")
class Registry(Module):
    DESC = "registry hives"
    HIVES = ["drivers", "sam", "security", "software", "system", "default"]
    SPEC = [
        ("dir", "sysvol/windows/system32/config/txr"),
        ("dir", "sysvol/windows/system32/config/regback"),
        ("glob", "sysvol/System Volume Information/_restore*/RP*/snapshot/_REGISTRY_*"),
        ("glob", "ntuser.dat*", from_user_home),
        ("glob", "AppData/Local/Microsoft/Windows/UsrClass.dat*", from_user_home),
        ("glob", "Local Settings/Application Data/Microsoft/Windows/UsrClass.dat*", from_user_home),
    ]

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        # Glob all hives to include e.g. .LOG files and .regtrans-ms files.
        files = []
        for hive in cls.HIVES:
            pattern = "sysvol/windows/system32/config/{}*".format(hive)
            for entry in target.fs.path().glob(pattern):
                if entry.is_file():
                    files.append(("file", entry))
        return files


@register_module("--netstat")
@local_module
class Netstat(Module):
    DESC = "netstat output"
    SPEC = [
        ("command", (["powershell.exe", "netstat", "-a", "-n", "-o"], "netstat")),
    ]
    EXEC_ORDER = ExecutionOrder.BOTTOM


@register_module("--win-processes")
@local_module
class WinProcesses(Module):
    DESC = "Windows process list"
    SPEC = [
        ("command", (["tasklist", "/V", "/fo", "csv"], "win-processes")),
    ]
    EXEC_ORDER = ExecutionOrder.BOTTOM


@register_module("--win-proc-env")
@local_module
class WinProcEnv(Module):
    DESC = "Process environment variables"
    SPEC = [
        (
            "command",
            (
                ["PowerShell", "-command", "Get-Process | ForEach-Object {$_.StartInfo.EnvironmentVariables}"],
                "win-process-env-vars",
            ),
        ),
    ]
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

        else:
            log.info("- Collecting output from command `%s`", " ".join(command_parts))

            mem_dump_path = collector.output.path.with_name("winpmem")
            mem_dump_errors_path = mem_dump_path.with_name("winpmem.errors")

            output_base = collector.COMMAND_OUTPUT_BASE
            if collector.base:
                output_base = fsutil.join(collector.base, collector.COMMAND_OUTPUT_BASE)

            mem_dump_output_path = fsutil.join(output_base, mem_dump_path.name)
            mem_dump_errors_output_path = fsutil.join(output_base, mem_dump_errors_path.name)

            with mem_dump_path.open(mode="wb") as mem_dump_fh:
                with mem_dump_errors_path.open(mode="wb") as mem_dump_errors_fh:
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
                        log.error(
                            "- Failed to collect output from command `%s`",
                            " ".join(command_parts),
                            exc_info=True,
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
    SPEC = [
        ("file", "sysvol/pagefile.sys"),
        ("file", "sysvol/hiberfil.sys"),
        ("file", "sysvol/swapfile.sys"),
        ("file", "sysvol/windows/memory.dmp"),
        ("dir", "sysvol/windows/minidump"),
    ]

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()

        page_key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management"
        for reg_key in target.registry.iterkeys(page_key):
            for page_path in reg_key.value("ExistingPageFiles").value:
                spec.add(("file", target.resolve(page_path)))

        crash_key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl"
        for reg_key in target.registry.iterkeys(crash_key):
            spec.add(("file", target.resolve(reg_key.value("DumpFile").value)))
            spec.add(("dir", target.resolve(reg_key.value("MinidumpDir").value)))

        return spec


@register_module("-e", "--eventlogs")
class EventLogs(Module):
    DESC = "event logs"

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()
        evt_log_paths = evt.EvtPlugin(target).get_logs(filename_glob="*.evt")
        for path in evt_log_paths:
            spec.add(("file", path))
        evtx_log_paths = evtx.EvtxPlugin(target).get_logs(filename_glob="*.evtx")
        for path in evtx_log_paths:
            spec.add(("file", path))
        return spec


@register_module("-t", "--tasks")
class Tasks(Module):
    SPEC = [
        ("dir", "sysvol/windows/tasks"),
        ("dir", "sysvol/windows/system32/tasks"),
        ("dir", "sysvol/windows/syswow64/tasks"),
        ("dir", "sysvol/windows/sysvol/domain/policies"),
        ("dir", "sysvol/windows/system32/GroupPolicy/DataStore/"),
    ]


@register_module("-ad", "--active-directory")
class ActiveDirectory(Module):
    DESC = "Active Directory data (policies, scripts, etc.)"
    SPEC = [
        ("dir", "sysvol/windows/sysvol/domain"),
    ]

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()
        key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"
        for reg_key in target.registry.iterkeys(key):
            try:
                spec.add(("dir", reg_key.value("SysVol").value))
            except Exception:
                pass
        return spec


@register_module("-nt", "--ntds")
class NTDS(Module):
    SPEC = [
        ("dir", "sysvol/windows/NTDS"),
    ]

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()

        key = "HKLM\\SYSTEM\\CurrentControlSet\\services\\NTDS\\Parameters"
        values = [
            ("dir", "DSA Working Directory"),
            ("file", "DSA Database File"),
            ("file", "Database backup path"),
            ("dir", "Database log files path"),
        ]
        for reg_key in target.registry.iterkeys(key):
            for collect_type, value in values:
                path = reg_key.value(value).value
                spec.add((collect_type, path))

        return spec


@register_module("--etl")
class ETL(Module):
    DESC = "interesting ETL files"
    SPEC = [
        ("glob", "sysvol/Windows/System32/WDI/LogFiles/*.etl"),
    ]


@register_module("--recents")
class Recents(Module):
    DESC = "Windows recently used files artifacts"
    SPEC = [
        ("dir", "AppData/Roaming/Microsoft/Windows/Recent", from_user_home),
        ("dir", "AppData/Roaming/Microsoft/Office/Recent", from_user_home),
        ("glob", "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/*.lnk", from_user_home),
        ("glob", "Desktop/*.lnk", from_user_home),
        ("glob", "Recent/*.lnk", from_user_home),
        ("glob", "sysvol/ProgramData/Microsoft/Windows/Start Menu/Programs/*.lnk"),
    ]


@register_module("--recyclebin")
class RecycleBin(Module):
    DESC = "recycle bin metadata"

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        for fs, name, mountpoints in iter_ntfs_filesystems(target):
            log.info("Acquiring recycle bin metadata from %s (%s)", fs, mountpoints)

            patterns = ["$Recycle.bin/**/$I*", "Recycler/*/INFO2", "Recycled/INFO2"]
            for pattern in patterns:
                for entry in fs.path().glob(pattern):
                    collector.collect_file(entry, outpath=fsutil.join(name, str(entry)))


@register_module("--drivers")
class Drivers(Module):
    DESC = "installed drivers"
    SPEC = [
        ("glob", "sysvol/windows/system32/drivers/*.sys"),
    ]


@register_module("--exchange")
class Exchange(Module):
    DESC = "interesting Exchange configuration files"

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()

        key = "HKLM\\SOFTWARE\\Microsoft\\ExchangeServer"
        for reg_key in target.registry.iterkeys(key):
            for subkey in reg_key.subkeys():
                try:
                    setup_key = subkey.subkey("Setup")
                    install_path = setup_key.value("MsiInstallPath").value
                    spec.update(
                        [
                            (
                                "file",
                                f"{install_path}\\TransportRoles\\Agents\\agents.config",
                            ),
                            (
                                "dir",
                                f"{install_path}\\Logging\\Ews",
                            ),
                            (
                                "dir",
                                f"{install_path}\\Logging\\CmdletInfra\\Powershell-Proxy\\Cmdlet",
                            ),
                            (
                                "dir",
                                f"{install_path}\\TransportRoles\\Logs",
                            ),
                        ]
                    )
                except Exception:
                    pass
        return spec


@register_module("--iis")
class IIS(Module):
    DESC = "IIS logs"

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set(
            [
                ("glob", "sysvol\\Windows\\System32\\LogFiles\\W3SVC*\\*.log"),
                ("glob", "sysvol\\Windows.old\\Windows\\System32\\LogFiles\\W3SVC*\\*.log"),
                ("glob", "sysvol\\inetpub\\logs\\LogFiles\\*.log"),
                ("glob", "sysvol\\inetpub\\logs\\LogFiles\\W3SVC*\\*.log"),
                ("glob", "sysvol\\Resources\\Directory\\*\\LogFiles\\Web\\W3SVC*\\*.log"),
            ]
        )
        iis_plugin = iis.IISLogsPlugin(target)
        spec.update([("file", log_path) for _, log_path in iis_plugin.iter_log_format_path_pairs()])
        return spec


@register_module("--prefetch")
class Prefetch(Module):
    DESC = "Windows Prefetch files"
    SPEC = [
        ("dir", "sysvol/windows/prefetch"),
    ]


@register_module("--appcompat")
class Appcompat(Module):
    DESC = "Windows Amcache and RecentFileCache"
    SPEC = [
        ("dir", "sysvol/windows/appcompat"),
    ]


@register_module("--pca")
class PCA(Module):
    DESC = "Windows Program Compatibility Assistant"
    SPEC = [
        ("dir", "sysvol/windows/pca"),
    ]


@register_module("--syscache")
class Syscache(Module):
    DESC = "Windows Syscache hive and log files"
    SPEC = [
        ("file", "sysvol/System Volume Information/Syscache.hve"),
        ("glob", "sysvol/System Volume Information/Syscache.hve.LOG*"),
    ]


@register_module("--win-notifications")
class WindowsNotifications(Module):
    DESC = "Windows Push Notifications Database files."
    SPEC = [
        # Old Win7/Win10 version of the file
        ("file", "AppData/Local/Microsoft/Windows/Notifications/appdb.dat", from_user_home),
        # New version of the file
        ("file", "AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db", from_user_home),
    ]


@register_module("--bits")
class BITS(Module):
    DESC = "Background Intelligent Transfer Service (BITS) queue/log DB"
    SPEC = [
        # Pre-Win10 the BITS DB files are called qmgr[01].dat, in Win10 it is
        # called qmgr.db and its transaction logs edb.log and edb.log[0-2]
        # Win 2000/XP/2003 path
        # (basically: \%ALLUSERSPROFILE%\Application Data\Microsoft\...)
        ("glob", "sysvol/Documents and Settings/All Users/Application Data/Microsoft/Network/Downloader/qmgr*.dat"),
        # Win Vista and higher path
        # (basically: \%ALLUSERSPROFILE%\Microsoft\...; %ALLUSERSPROFILE% == %PROGRAMDATA%)
        ("glob", "sysvol/ProgramData/Microsoft/Network/Downloader/qmgr*.dat"),
        # Win 10 files
        ("file", "sysvol/ProgramData/Microsoft/Network/Downloader/qmgr.db"),
        ("glob", "sysvol/ProgramData/Microsoft/Network/Downloader/edb.log*"),
    ]


@register_module("--wbem")
class WBEM(Module):
    DESC = "Windows WBEM (WMI) database files"
    SPEC = [
        ("dir", "sysvol/windows/system32/wbem/Repository"),
    ]


@register_module("--dhcp")
class DHCP(Module):
    DESC = "Windows Server DHCP files"

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()
        key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\DhcpServer\\Parameters"
        for reg_key in target.registry.iterkeys(key):
            spec.add(("dir", reg_key.value("DatabasePath").value))
        return spec


@register_module("--dns")
class DNS(Module):
    DESC = "Windows Server DNS files"
    SPEC = [
        ("glob", "sysvol/windows/system32/config/netlogon.*"),
        ("dir", "sysvol/windows/system32/dns"),
    ]


@register_module("--win-dns-cache")
@local_module
class WinDnsClientCache(Module):
    DESC = "The contents of Windows DNS client cache"
    SPEC = [
        (
            "command",
            # Powershell.exe understands a subcommand passed as single string parameter,
            # no need to split the subcommand in parts.
            (
                ["powershell.exe", "-Command", "Get-DnsClientCache | ConvertTo-Csv -NoTypeInformation"],
                "get-dnsclientcache",
            ),
        ),
    ]
    EXEC_ORDER = ExecutionOrder.BOTTOM


@register_module("--powershell")
class PowerShell(Module):
    DESC = "Windows PowerShell Artefacts"
    SPEC = [
        ("dir", "AppData/Roaming/Microsoft/Windows/PowerShell", from_user_home),
    ]


@register_module("--thumbnail-cache")
class ThumbnailCache(Module):
    DESC = "Windows thumbnail db artifacts"
    SPEC = [
        ("glob", "AppData/Local/Microsoft/Windows/Explorer/thumbcache_*", from_user_home),
    ]


@register_module("--misc")
class Misc(Module):
    DESC = "miscellaneous Windows artefacts"
    SPEC = [
        ("file", "sysvol/windows/PFRO.log"),
        ("file", "sysvol/windows/setupapi.log"),
        ("file", "sysvol/windows/setupapidev.log"),
        ("glob", "sysvol/windows/inf/setupapi*.log"),
        ("glob", "sysvol/system32/logfiles/*/*.txt"),
        ("dir", "sysvol/windows/system32/sru"),
        ("dir", "sysvol/windows/system32/drivers/etc"),
        ("dir", "sysvol/Windows/System32/WDI/LogFiles/StartupInfo"),
        ("dir", "sysvol/windows/system32/GroupPolicy/DataStore/"),
        ("dir", "sysvol/ProgramData/Microsoft/Group Policy/History/"),
        ("dir", "AppData/Local/Microsoft/Group Policy/History/", from_user_home),
        ("glob", "sysvol/Windows/System32/LogFiles/SUM/*.mdb"),
        ("glob", "sysvol/ProgramData/USOShared/Logs/System/*.etl"),
        ("glob", "sysvol/Windows/Logs/WindowsUpdate/WindowsUpdate*.etl"),
        ("glob", "sysvol/Windows/Logs/CBS/CBS*.log"),
    ]


@register_module("--av")
class AV(Module):
    DESC = "various antivirus logs"
    SPEC = [
        # AVG
        ("dir", "sysvol/Documents and Settings/All Users/Application Data/AVG/Antivirus/log"),
        ("dir", "sysvol/Documents and Settings/All Users/Application Data/AVG/Antivirus/report"),
        ("dir", "sysvol/ProgramData/AVG/Antivirus/log"),
        ("dir", "sysvol/ProgramData/AVG/Antivirus/report"),
        # Avast
        ("dir", "sysvol/Documents And Settings/All Users/Application Data/Avast Software/Avast/Log"),
        ("dir", "sysvol/ProgramData/Avast Software/Avast/Log"),
        ("dir", "Avast Software/Avast/Log", from_user_home),
        ("file", "sysvol/ProgramData/Avast Software/Avast/Chest/index.xml"),
        # Avira
        ("dir", "sysvol/ProgramData/Avira/Antivirus/LOGFILES"),
        ("dir", "sysvol/ProgramData/Avira/Security/Logs"),
        ("dir", "sysvol/ProgramData/Avira/VPN"),
        # Bitdefender
        ("dir", "sysvol/ProgramData/Bitdefender/Endpoint Security/Logs"),
        ("dir", "sysvol/ProgramData/Bitdefender/Desktop/Profiles/Logs"),
        ("glob", "sysvol/Program Files*/Bitdefender*/*"),
        # ComboFix
        ("file", "sysvol/ComboFix.txt"),
        # Cybereason
        ("dir", "sysvol/ProgramData/crs1/Logs"),
        ("dir", "sysvol/ProgramData/apv2/Logs"),
        ("dir", "sysvol/ProgramData/crb1/Logs"),
        # Cylance
        ("dir", "sysvol/ProgramData/Cylance/Desktop"),
        ("dir", "sysvol/ProgramData/Cylance/Optics/Log"),
        ("dir", "sysvol/Program Files/Cylance/Desktop/log"),
        # ESET
        ("dir", "sysvol/Documents and Settings/All Users/Application Data/ESET/ESET NOD32 Antivirus/Logs"),
        ("dir", "sysvol/ProgramData/ESET/ESET NOD32 Antivirus/Logs"),
        ("dir", "sysvol/ProgramData/ESET/ESET Security/Logs"),
        ("dir", "sysvol/ProgramData/ESET/RemoteAdministrator/Agent/EraAgentApplicationData/Logs"),
        ("dir", "sysvol/Windows/System32/config/systemprofile/AppData/Local/ESET/ESET Security/Quarantine"),
        # Emsisoft
        ("glob", "sysvol/ProgramData/Emsisoft/Reports/scan*.txt"),
        # F-Secure
        ("dir", "sysvol/ProgramData/F-Secure/Log"),
        ("dir", "AppData/Local/F-Secure/Log", from_user_home),
        ("dir", "sysvol/ProgramData/F-Secure/Antivirus/ScheduledScanReports"),
        # HitmanPro
        ("dir", "sysvol/ProgramData/HitmanPro/Logs"),
        ("dir", "sysvol/ProgramData/HitmanPro.Alert/Logs"),
        ("file", "sysvol/ProgramData/HitmanPro.Alert/excalibur.db"),
        ("dir", "sysvol/ProgramData/HitmanPro/Quarantine"),
        # Malwarebytes
        ("glob", "sysvol/ProgramData/Malwarebytes/Malwarebytes Anti-Malware/Logs/mbam-log-*.xml"),
        ("glob", "sysvol/ProgramData/Malwarebytes/MBAMService/logs/mbamservice.log*"),
        ("dir", "AppData/Roaming/Malwarebytes/Malwarebytes Anti-Malware/Logs", from_user_home),
        ("dir", "sysvol/ProgramData/Malwarebytes/MBAMService/ScanResults"),
        # McAfee
        ("dir", "Application Data/McAfee/DesktopProtection", from_user_home),
        ("dir", "sysvol/ProgramData/McAfee/DesktopProtection"),
        ("dir", "sysvol/ProgramData/McAfee/Endpoint Security/Logs"),
        ("dir", "sysvol/ProgramData/McAfee/Endpoint Security/Logs_Old"),
        ("dir", "sysvol/ProgramData/Mcafee/VirusScan"),
        ("dir", "sysvol/ProgramData/McAfee/Endpoint Security/Logs"),
        ("dir", "sysvol/ProgramData/McAfee/MSC/Logs"),
        # RogueKiller
        ("glob", "sysvol/ProgramData/RogueKiller/logs/AdliceReport_*.json"),
        # SUPERAntiSpyware
        ("dir", "AppData/Roaming/SUPERAntiSpyware/Logs", from_user_home),
        # SecureAge
        ("dir", "sysvol/ProgramData/SecureAge Technology/SecureAge/log"),
        # SentinelOne
        ("dir", "sysvol/programdata/sentinel/logs"),
        # Sophos
        ("glob", "sysvol/Documents and Settings/All Users/Application Data/Sophos/Sophos */Logs"),
        ("glob", "sysvol/ProgramData/Sophos/Sophos */Logs"),
        # Symantec
        (
            "dir",
            "sysvol/Documents and Settings/All Users/Application Data/Symantec/Symantec Endpoint Protection/Logs/AV",
        ),
        ("glob", "sysvol/ProgramData/Symantec/Symantec Endpoint Protection/*/Data/Logs"),
        ("dir", "AppData/Local/Symantec/Symantec Endpoint Protection/Logs", from_user_home),
        ("dir", "sysvol/Windows/System32/winevt/logs/Symantec Endpoint Protection Client.evtx"),
        ("glob", "sysvol/ProgramData/Symantec/Symantec Endpoint Protection/*/Data/CmnClnt/ccSubSDK"),
        ("glob", "sysvol/ProgramData/Symantec/Symantec Endpoint Protection/*/Data/registrationInfo.xml"),
        # TotalAV
        ("glob", "sysvol/Program Files*/TotalAV/logs"),
        ("dir", "sysvol/ProgramData/TotalAV/logs"),
        # Trendmicro
        ("glob", "sysvol/Program Files*/Trend Micro"),
        # VIPRE
        ("dir", "sysvol/ProgramData/VIPRE Business Agent/Logs"),
        ("dir", "AppData/Roaming/VIPRE Business", from_user_home),
        ("dir", "AppData/Roaming/GFI Software/AntiMalware/Logs", from_user_home),
        ("dir", "AppData/Roaming/Sunbelt Software/AntiMalware/Logs", from_user_home),
        # Webroot
        ("file", "sysvol/ProgramData/WRData/WRLog.log"),
        # Microsoft Windows Defender
        ("dir", "sysvol/ProgramData/Microsoft/Microsoft AntiMalware/Support"),
        ("glob", "sysvol/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender*.evtx"),
        ("dir", "sysvol/ProgramData/Microsoft/Windows Defender/Support"),
        ("dir", "sysvol/ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory"),
        ("file", "sysvol/Windows/Temp/MpCmdRun.log"),
        ("file", "sysvol/Windows.old/Windows/Temp/MpCmdRun.log"),
    ]


@register_module("--quarantined")
class QuarantinedFiles(Module):
    DESC = "files quarantined by various antivirus products"
    SPEC = [
        # Microsoft Defender
        # https://knez.github.io/posts/how-to-extract-quarantine-files-from-windows-defender/
        ("dir", "sysvol/ProgramData/Microsoft/Windows Defender/Quarantine"),
        # Symantec Endpoint Protection
        (
            "dir",
            "sysvol/Documents and Settings/All Users/Application Data/Symantec/Symantec Endpoint Protection/Quarantine",
        ),
        ("glob", "sysvol/ProgramData/Symantec/Symantec Endpoint Protection/*/Data/Quarantine"),
        # Trend Micro
        # https://secret.inf.ufpr.br/papers/marcus_av_handson.pdf
        ("dir", "sysvol/ProgramData/Trend Micro/AMSP/quarantine"),
        # McAfee
        ("dir", "sysvol/Quarantine"),
        ("dir", "sysvol/ProgramData/McAfee/VirusScan/Quarantine"),
        # Sophos
        ("glob", "sysvol/ProgramData/Sophos/Sophos/*/Quarantine"),
        ("glob", "sysvol/ProgramData/Sophos/Sophos */INFECTED"),
        ("dir", "sysvol/ProgramData/Sophos/Safestore"),
        # HitmanPRO
        ("dir", "sysvol/ProgramData/HitmanPro/Quarantine"),
    ]


@register_module("--history")
class History(Module):
    DESC = "browser history from IE, Edge, Firefox, and Chrome"

    SPEC = [
        # IE
        ("file", "Cookies/index.dat", from_user_home),
        ("file", "Local Settings/History/History.IE5/index.dat", from_user_home),
        ("glob", "Local Settings/History/History.IE5/MSHist*/index.dat", from_user_home),
        ("file", "Local Settings/Temporary Internet Files/Content.IE5/index.dat", from_user_home),
        ("file", "Local Settings/Application Data/Microsoft/Feeds Cache/index.dat", from_user_home),
        ("dir", "AppData/Local/Microsoft/Internet Explorer/Recovery", from_user_home),
        ("file", "AppData/Local/Microsoft/Windows/History/History.IE5/index.dat", from_user_home),
        (
            "glob",
            "AppData/Local/Microsoft/Windows/History/History.IE5/MSHist*/index.dat",
            from_user_home,
        ),
        (
            "file",
            "AppData/Local/Microsoft/Windows/History/Low/History.IE5/index.dat",
            from_user_home,
        ),
        (
            "glob",
            "AppData/Local/Microsoft/Windows/History/Low/History.IE5/MSHist*/index.dat",
            from_user_home,
        ),
        ("dir", "AppData/Local/Microsoft/Windows/INetCookies", from_user_home),
        (
            "file",
            "AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.IE5/index.dat",
            from_user_home,
        ),
        (
            "file",
            "AppData/Local/Microsoft/Windows/Temporary Internet Files/Low/Content.IE5/index.dat",
            from_user_home,
        ),
        ("glob", "AppData/Local/Microsoft/Windows/WebCache/*.dat", from_user_home),
        ("file", "AppData/Roaming/Microsoft/Windows/Cookies/index.dat", from_user_home),
        ("file", "AppData/Roaming/Microsoft/Windows/Cookies/Low/index.dat", from_user_home),
        ("file", "AppData/Roaming/Microsoft/Windows/IEDownloadHistory/index.dat", from_user_home),
        # Chrome
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Bookmarks", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Favicons", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/History", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Login Data", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Login Data For Account", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Shortcuts", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Top Sites", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Web Data", from_user_home),
        # Chrome - Legacy
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Current Session", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Current Tabs", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Archived History", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Last Session", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Last Tabs", from_user_home),
        (
            "glob",
            "Local Settings/Application Data/Google/Chrom*/User Data/*/Bookmarks",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Google/Chrom*/User Data/*/Favicons",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Google/Chrom*/User Data/*/History",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Google/Chrom*/User Data/*/Login Data",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Google/Chrom*/User Data/*/Login Data For Account",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Google/Chrom*/User Data/*/Shortcuts",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Google/Chrom*/User Data/*/Top Sites",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Google/Chrom*/User Data/*/Web Data",
            from_user_home,
        ),
        # Chrome - Legacy
        (
            "glob",
            "Local Settings/Application Data/Google/Chrom*/User Data/*/Current Session",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Google/Chrom*/User Data/*/Current Tabs",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Google/Chrom*/User Data/*/Archived History",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Google/Chrom*/User Data/*/Last Session",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Google/Chrom*/User Data/*/Last Tabs",
            from_user_home,
        ),
        ("glob", "Library/Application Support/Google/Chrome/*/Bookmarks", from_user_home),
        ("glob", "Library/Application Support/Google/Chrome/*/Favicons", from_user_home),
        ("glob", "Library/Application Support/Google/Chrome/*/History", from_user_home),
        ("glob", "Library/Application Support/Google/Chrome/*/Login Data", from_user_home),
        ("glob", "Library/Application Support/Google/Chrome/*/Login Data For Account", from_user_home),
        ("glob", "Library/Application Support/Google/Chrome/*/Shortcuts", from_user_home),
        ("glob", "Library/Application Support/Google/Chrome/*/Top Sites", from_user_home),
        ("glob", "Library/Application Support/Google/Chrome/*/Web Data", from_user_home),
        ("glob", "Library/Application Support/Chromium/*/Bookmarks", from_user_home),
        ("glob", "Library/Application Support/Chromium/*/Favicons", from_user_home),
        ("glob", "Library/Application Support/Chromium/*/History", from_user_home),
        ("glob", "Library/Application Support/Chromium/*/Login Data", from_user_home),
        ("glob", "Library/Application Support/Chromium/*/Login Data For Account", from_user_home),
        ("glob", "Library/Application Support/Chromium/*/Shortcuts", from_user_home),
        ("glob", "Library/Application Support/Chromium/*/Top Sites", from_user_home),
        ("glob", "Library/Application Support/Chromium/*/Web Data", from_user_home),
        # Chrome - Legacy
        ("glob", "Library/Application Support/Google/Chrome/*/Current Session", from_user_home),
        ("glob", "Library/Application Support/Google/Chrome/*/Current Tabs", from_user_home),
        ("glob", "Library/Application Support/Google/Chrome/*/Archived History", from_user_home),
        ("glob", "Library/Application Support/Google/Chrome/*/Last Session", from_user_home),
        ("glob", "Library/Application Support/Google/Chrome/*/Last Tabs", from_user_home),
        ("glob", "Library/Application Support/Chromium/*/Current Session", from_user_home),
        ("glob", "Library/Application Support/Chromium/*/Current Tabs", from_user_home),
        ("glob", "Library/Application Support/Chromium/*/Archived History", from_user_home),
        ("glob", "Library/Application Support/Chromium/*/Last Session", from_user_home),
        ("glob", "Library/Application Support/Chromium/*/Last Tabs", from_user_home),
        # Chrome - RHEL/Ubuntu - DNF
        ("glob", ".config/google-chrome/*/Bookmarks", from_user_home),
        ("glob", ".config/google-chrome/*/Favicons", from_user_home),
        ("glob", ".config/google-chrome/*/History", from_user_home),
        ("glob", ".config/google-chrome/*/Login Data", from_user_home),
        ("glob", ".config/google-chrome/*/Login Data For Account", from_user_home),
        ("glob", ".config/google-chrome/*/Shortcuts", from_user_home),
        ("glob", ".config/google-chrome/*/Top Sites", from_user_home),
        ("glob", ".config/google-chrome/*/Web Data", from_user_home),
        # Chrome - RHEL/Ubuntu - Flatpak
        ("glob", ".var/app/com.google.Chrome/config/google-chrome/*/Bookmarks", from_user_home),
        ("glob", ".var/app/com.google.Chrome/config/google-chrome/*/Favicons", from_user_home),
        ("glob", ".var/app/com.google.Chrome/config/google-chrome/*/History", from_user_home),
        ("glob", ".var/app/com.google.Chrome/config/google-chrome/*/Login Data", from_user_home),
        ("glob", ".var/app/com.google.Chrome/config/google-chrome/*/Login Data For Account", from_user_home),
        ("glob", ".var/app/com.google.Chrome/config/google-chrome/*/Shortcuts", from_user_home),
        ("glob", ".var/app/com.google.Chrome/config/google-chrome/*/Top Sites", from_user_home),
        ("glob", ".var/app/com.google.Chrome/config/google-chrome/*/Web Data", from_user_home),
        # Chromium - RHEL/Ubuntu - DNF/apt
        ("glob", ".config/chromium/*/Bookmarks", from_user_home),
        ("glob", ".config/chromium/*/Favicons", from_user_home),
        ("glob", ".config/chromium/*/History", from_user_home),
        ("glob", ".config/chromium/*/Login Data", from_user_home),
        ("glob", ".config/chromium/*/Login Data For Account", from_user_home),
        ("glob", ".config/chromium/*/Shortcuts", from_user_home),
        ("glob", ".config/chromium/*/Top Sites", from_user_home),
        ("glob", ".config/chromium/*/Web Data", from_user_home),
        # Chromium - RHEL/Ubuntu - Flatpak
        ("glob", ".var/app/org.chromium.Chromium/config/chromium/*/Bookmarks", from_user_home),
        ("glob", ".var/app/org.chromium.Chromium/config/chromium/*/Favicons", from_user_home),
        ("glob", ".var/app/org.chromium.Chromium/config/chromium/*/History", from_user_home),
        ("glob", ".var/app/org.chromium.Chromium/config/chromium/*/Login Data", from_user_home),
        ("glob", ".var/app/org.chromium.Chromium/config/chromium/*/Login Data For Account", from_user_home),
        ("glob", ".var/app/org.chromium.Chromium/config/chromium/*/Shortcuts", from_user_home),
        ("glob", ".var/app/org.chromium.Chromium/config/chromium/*/Top Sites", from_user_home),
        ("glob", ".var/app/org.chromium.Chromium/config/chromium/*/Web Data", from_user_home),
        # Chromium - RHEL/Ubuntu - snap
        ("glob", "snap/chromium/common/chromium/*/Bookmarks", from_user_home),
        ("glob", "snap/chromium/common/chromium/*/Favicons", from_user_home),
        ("glob", "snap/chromium/common/chromium/*/History", from_user_home),
        ("glob", "snap/chromium/common/chromium/*/Login Data", from_user_home),
        ("glob", "snap/chromium/common/chromium/*/Login Data For Account", from_user_home),
        ("glob", "snap/chromium/common/chromium/*/Shortcuts", from_user_home),
        ("glob", "snap/chromium/common/chromium/*/Top Sites", from_user_home),
        ("glob", "snap/chromium/common/chromium/*/Web Data", from_user_home),
        # Edge
        ("glob", "AppData/Local/Microsoft/Edge/User Data/*/Bookmarks", from_user_home),
        ("glob", "AppData/Local/Microsoft/Edge/User Data/*/Extension Cookies", from_user_home),
        ("glob", "AppData/Local/Microsoft/Edge/User Data/*/Favicons", from_user_home),
        ("glob", "AppData/Local/Microsoft/Edge/User Data/*/History", from_user_home),
        ("glob", "AppData/Local/Microsoft/Edge/User Data/*/Login Data", from_user_home),
        ("glob", "AppData/Local/Microsoft/Edge/User Data/*/Media History", from_user_home),
        ("glob", "AppData/Local/Microsoft/Edge/User Data/*/Shortcuts", from_user_home),
        ("glob", "AppData/Local/Microsoft/Edge/User Data/*/Top Sites", from_user_home),
        ("glob", "AppData/Local/Microsoft/Edge/User Data/*/Web Data", from_user_home),
        (
            "glob",
            "Local Settings/Application Data/Microsoft/Edge/User Data/*/Bookmarks",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Microsoft/Edge/User Data/*/Extension Cookies",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Microsoft/Edge/User Data/*/Favicons",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Microsoft/Edge/User Data/*/History",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Microsoft/Edge/User Data/*/Login Data",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Microsoft/Edge/User Data/*/Media History",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Microsoft/Edge/User Data/*/Shortcuts",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Microsoft/Edge/User Data/*/Top Sites",
            from_user_home,
        ),
        (
            "glob",
            "Local Settings/Application Data/Microsoft/Edge/User Data/*/Web Data",
            from_user_home,
        ),
        ("glob", "Library/Application Support/Microsoft Edge/*/Bookmarks", from_user_home),
        ("glob", "Library/Application Support/Microsoft Edge/*/Extension Cookies", from_user_home),
        ("glob", "Library/Application Support/Microsoft Edge/*/Favicons", from_user_home),
        ("glob", "Library/Application Support/Microsoft Edge/*/History", from_user_home),
        ("glob", "Library/Application Support/Microsoft Edge/*/Login Data", from_user_home),
        ("glob", "Library/Application Support/Microsoft Edge/*/Media History", from_user_home),
        ("glob", "Library/Application Support/Microsoft Edge/*/Shortcuts", from_user_home),
        ("glob", "Library/Application Support/Microsoft Edge/*/Top Sites", from_user_home),
        ("glob", "Library/Application Support/Microsoft Edge/*/Web Data", from_user_home),
        # Edge - RHEL/Ubuntu - DNF/apt
        ("glob", ".config/microsoft-edge/*/Bookmarks", from_user_home),
        ("glob", ".config/microsoft-edge/*/Favicons", from_user_home),
        ("glob", ".config/microsoft-edge/*/History", from_user_home),
        ("glob", ".config/microsoft-edge/*/Login Data", from_user_home),
        ("glob", ".config/microsoft-edge/*/Login Data For Account", from_user_home),
        ("glob", ".config/microsoft-edge/*/Shortcuts", from_user_home),
        ("glob", ".config/microsoft-edge/*/Top Sites", from_user_home),
        ("glob", ".config/microsoft-edge/*/Web Data", from_user_home),
        # Edge - RHEL/Ubuntu - Flatpak
        ("glob", ".var/app/com.microsoft.Edge/config/microsoft-edge/*/Bookmarks", from_user_home),
        ("glob", ".var/app/com.microsoft.Edge/config/microsoft-edge/*/Favicons", from_user_home),
        ("glob", ".var/app/com.microsoft.Edge/config/microsoft-edge/*/History", from_user_home),
        ("glob", ".var/app/com.microsoft.Edge/config/microsoft-edge/*/Login Data", from_user_home),
        ("glob", ".var/app/com.microsoft.Edge/config/microsoft-edge/*/Login Data For Account", from_user_home),
        ("glob", ".var/app/com.microsoft.Edge/config/microsoft-edge/*/Shortcuts", from_user_home),
        ("glob", ".var/app/com.microsoft.Edge/config/microsoft-edge/*/Top Sites", from_user_home),
        ("glob", ".var/app/com.microsoft.Edge/config/microsoft-edge/*/Web Data", from_user_home),
        # Firefox - Windows
        ("glob", "AppData/Local/Mozilla/Firefox/Profiles/*/*.sqlite*", from_user_home),
        ("glob", "AppData/Roaming/Mozilla/Firefox/Profiles/*/*.sqlite*", from_user_home),
        ("glob", "Application Data/Mozilla/Firefox/Profiles/*/*.sqlite*", from_user_home),
        # Firefox - macOS
        ("glob", "/Users/*/Library/Application Support/Firefox/Profiles/*/*.sqlite*"),
        # Firefox - RHEL/Ubuntu - Flatpak
        ("glob", ".var/app/org.mozilla.firefox/.mozilla/firefox/*/*.sqlite", from_user_home),
        # Firefox - RHEL/Ubuntu - DNF/apt
        ("glob", ".mozilla/firefox/*/*.sqlite", from_user_home),
        # Firefox - RHEL/Ubuntu - snap
        ("glob", "snap/firefox/common/.mozilla/firefox/*/*.sqlite", from_user_home),
        # Safari - macOS
        ("file", "Library/Safari/Bookmarks.plist", from_user_home),
        ("file", "Library/Safari/Downloads.plist", from_user_home),
        ("file", "Library/Safari/Extensions/Extensions.plist", from_user_home),
        ("glob", "Library/Safari/History.*", from_user_home),
        ("file", "Library/Safari/LastSession.plist", from_user_home),
        ("file", "Library/Caches/com.apple.Safari/Cache.db", from_user_home),
    ]


@register_module("--remoteaccess")
class RemoteAccess(Module):
    DESC = "common remote access tools' log files"
    SPEC = [
        # teamviewer
        ("glob", "sysvol/Program Files/TeamViewer/*.log"),
        ("glob", "sysvol/Program Files (x86)/TeamViewer/*.log"),
        ("glob", "AppData/Roaming/TeamViewer/*.log", from_user_home),
        # anydesk
        ("dir", "sysvol/ProgramData/AnyDesk"),
        ("glob", "AppData/Roaming/AnyDesk/*.trace", from_user_home),
        # zoho
        ("dir", "sysvol/ProgramData/ZohoMeeting/log"),
        ("dir", "AppData/Local/ZohoMeeting/log", from_user_home),
        # realvnc
        ("file", "sysvol/ProgramData/RealVNC-Service/vncserver.log"),
        ("file", "AppData/Local/RealVNC/vncserver.log", from_user_home),
        # tightvnc
        ("dir", "sysvol/ProgramData/TightVNC/Server/Logs"),
        # Remote desktop cache files
        ("dir", "AppData/Local/Microsoft/Terminal Server Client/Cache", from_user_home),
    ]


@register_module("--webhosting")
class WebHosting(Module):
    DESC = "Web hosting software log files"
    SPEC = [
        # cPanel
        ("dir", "/usr/local/cpanel/logs"),
        ("file", ".lastlogin", from_user_home),
    ]


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

                spec.add(("file", path))

        return spec


@register_module("--etc")
class Etc(Module):
    SPEC = [
        # In OS-X /etc is a symlink to /private/etc. To prevent collecting
        # duplicates, we only use the /etc directory here.
        ("dir", "/etc"),
        ("dir", "/usr/local/etc"),
    ]


@register_module("--boot")
class Boot(Module):
    SPEC = [
        ("glob", "/boot/config*"),
        ("glob", "/boot/efi*"),
        ("glob", "/boot/grub*"),
        ("glob", "/boot/init*"),
    ]


def private_key_filter(path: fsutil.TargetPath) -> bool:
    with path.open("rt") as file:
        return "PRIVATE KEY" in file.readline()


@register_module("--home")
class Home(Module):
    SPEC = [
        ("glob", ".*[akz]sh*", from_user_home),
        ("dir", ".config", from_user_home),
        ("glob", "*/.*[akz]sh*", from_user_home),
        ("glob", "*/.config", from_user_home),
        # OS-X home (aka /Users)
        ("glob", ".bash_sessions/*", from_user_home),
        ("glob", "Library/LaunchAgents/*", from_user_home),
        ("glob", "Library/Logs/*", from_user_home),
        ("glob", "Preferences/*", from_user_home),
        ("glob", "Library/Preferences/*", from_user_home),
    ]


@register_module("--ssh")
@module_arg("--private-keys", action="store_true", help="Add any private keys", default=False)
class SSH(Module):
    SPEC = [
        ("glob", ".ssh/*", from_user_home),
        ("glob", "/etc/ssh/*"),
        ("glob", "sysvol/ProgramData/ssh/*"),
    ]

    @classmethod
    def run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        # Acquire SSH configuration in sshd directories

        filter = None if cli_args.private_keys else private_key_filter

        if filter:
            log.info("Executing SSH without --private-keys, skipping private keys.")

        with collector.file_filter(filter):
            super().run(target, cli_args, collector)


@register_module("--var")
class Var(Module):
    SPEC = [
        # In OS-X /var is a symlink to /private/var. To prevent collecting
        # duplicates, we only use the /var directory here.
        ("dir", "/var/log"),
        ("dir", "/var/spool/at"),
        ("dir", "/var/spool/cron"),
        ("dir", "/var/spool/anacron"),
        ("dir", "/var/lib/dpkg/status"),
        ("dir", "/var/lib/rpm"),
        ("dir", "/var/db"),
        ("dir", "/var/audit"),
        ("dir", "/var/cron"),
        ("dir", "/var/run"),
        # some OS-X specific files
        ("dir", "/private/var/at"),
        ("dir", "/private/var/db/diagnostics"),
        ("dir", "/private/var/db/uuidtext"),
        ("file", "/private/var/vm/sleepimage"),
        ("glob", "/private/var/vm/swapfile*"),
        ("glob", "/private/var/folders/*/*/0/com.apple.notificationcenter/*/*"),
        # user specific cron on OS-X
        ("dir", "/usr/lib/cron"),
    ]


@register_module("--bsd")
class BSD(Module):
    SPEC = [
        ("file", "/bin/freebsd-version"),
        ("dir", "/usr/ports"),
    ]


@register_module("--osx")
class OSX(Module):
    DESC = "OS-X specific files and directories"
    SPEC = [
        # filesystem events
        ("dir", "/.fseventsd"),
        # kernel extensions
        ("dir", "/Library/Extensions"),
        ("dir", "/System/Library/Extensions"),
        # logs
        ("dir", "/Library/Logs"),
        # autorun locations
        ("dir", "/Library/LaunchAgents"),
        ("dir", "/Library/LaunchDaemons"),
        ("dir", "/Library/StartupItems"),
        ("dir", "/System/Library/LaunchAgents"),
        ("dir", "/System/Library/LaunchDaemons"),
        ("dir", "/System/Library/StartupItems"),
        # installed software
        ("dir", "/Library/Receipts/InstallHistory.plist"),
        ("file", "/System/Library/CoreServices/SystemVersion.plist"),
        # system preferences
        ("dir", "/Library/Preferences"),
    ]


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
        boot_fs = []

        for boot_dir, boot_vol in boot_dirs.items():
            dir_path = target.fs.path(boot_dir)
            if dir_path.is_symlink() and dir_path.exists():
                dst = dir_path.readlink()
                boot_fs.append((dst.name, boot_vol, dst.get().top.fs))

        for uuid, name, fs in boot_fs:
            log.info("Acquiring /vmfs/volumes/%s (%s)", uuid, name)
            base = f"fs/{uuid}:{name}"
            for path in fs.path("/").rglob("*"):
                if not path.is_file():
                    continue
                collector.collect_file(path, outpath=path, base=base)


@register_module("--esxi")
class ESXi(Module):
    DESC = "ESXi interesting files"
    SPEC = [
        ("dir", "/scratch/log"),
        ("dir", "/locker/packages/var"),
        # ESXi 7
        ("dir", "/scratch/cache"),
        ("dir", "/scratch/vmkdump"),
        # ESXi 6
        ("dir", "/scratch/vmware"),
    ]


@register_module("--vmfs")
class VMFS(Module):
    DESC = "ESXi VMFS metadata files"

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        for uuid, name, fs in iter_esxi_filesystems(target):
            if not fs.__fstype__ == "vmfs":
                continue

            log.info("Acquiring /vmfs/volumes/%s (%s)", uuid, name)
            base = f"fs/{uuid}:{name}"
            for path in fs.path("/").glob("*.sf"):
                if not path.is_file():
                    continue
                collector.collect_file(path, outpath=path, base=base)


@register_module("--activities-cache")
class ActivitiesCache(Module):
    DESC = "user's activities caches"
    SPEC = [
        ("glob", "AppData/Local/ConnectedDevicesPlatform/*/ActivitiesCache.db", from_user_home),
    ]


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

        if cli_args.ext_to_hash:
            extensions = cli_args.ext_to_hash
        else:
            extensions = cls.DEFAULT_EXTENSIONS

        if cli_args.dir_to_hash or cli_args.glob_to_hash:
            if cli_args.glob_to_hash:
                path_selectors.extend([("glob", glob) for glob in cli_args.glob_to_hash])

            if cli_args.dir_to_hash:
                path_selectors.extend([("dir", (dir_path, extensions)) for dir_path in cli_args.dir_to_hash])

        else:
            path_selectors.extend([("dir", (dir_path, extensions)) for dir_path in cls.DEFAULT_PATHS])

        if cli_args.hash_func:
            hash_funcs = cli_args.hash_func
        else:
            hash_funcs = cls.DEFAULT_HASH_FUNCS

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
        if not sys.platform == "win32":
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
        log.error("Failed to iterate disks")
    log.info("")


def print_volumes_overview(target: Target) -> None:
    log.info("// Volumes")
    try:
        for volume in target.volumes:
            log.info("%s", volume)
    except Exception:
        log.error("Failed to iterate volumes")
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


def modargs2json(args: argparse.Namespace) -> dict:
    json_opts = {}
    for module in MODULES.values():
        cli_arg = module.__cli_args__[-1:][0][1]
        if opt := cli_arg.get("dest"):
            json_opts[opt] = getattr(args, opt)
    return json_opts


def acquire_target(target: Target, *args, **kwargs) -> list[str]:
    if isinstance(target._loader, TargetdLoader):
        files = acquire_target_targetd(target, *args, **kwargs)
    else:
        files = acquire_target_regular(target, *args, **kwargs)
    return files


def acquire_target_targetd(target: Target, args: argparse.Namespace, output_ts: Optional[str] = None) -> list[str]:
    files = []
    if not len(target.hostname()):
        log.error("Unable to initialize targetd.")
        return files
    json_opts = modargs2json(args)
    json_opts["profile"] = args.profile
    json_opts["file"] = args.file
    json_opts["directory"] = args.directory
    json_opts["glob"] = args.glob
    m = {"targetd-meta": "acquire", "args": json_opts}
    json_str = json.dumps(m)
    targetd = target._loader.instance.client
    targetd.send_message(json_str.encode("utf-8"))
    targetd.sync()
    for stream in targetd.streams:
        files.append(stream.out_file)
    return files


def acquire_target_regular(target: Target, args: argparse.Namespace, output_ts: Optional[str] = None) -> list[str]:
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
            skip_list.add(normalize_path(target, log_file, resolve=True))

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

    # Prepare targets if necessary
    if target.os == "windows":
        mount_all_ntfs_filesystems(target)

    print_acquire_warning(target)

    modules_selected = {}
    modules_successful = []
    modules_failed = {}
    for name, mod in MODULES.items():
        name_slug = name.lower()
        # check if module was set in the arguments provided
        if getattr(args, name_slug):
            modules_selected[name] = mod

    profile = args.profile

    # Set profile to default if no profile, modules, files, directories or globes were selected
    if not profile and not modules_selected and not args.file and not args.directory and not args.glob:
        log.info("Using default collection profile")
        profile = "default"
        log.info("")

    if profile and profile != "none":
        if target.os not in PROFILES[profile]:
            log.error("No collection set for OS %s with profile %s", target.os, profile)
            return files

        for mod in PROFILES[profile][target.os]:
            modules_selected[mod.__modname__] = mod

    log.info("Modules selected: %s", ", ".join(sorted(modules_selected)))

    local_only_modules = {name: module for name, module in modules_selected.items() if hasattr(module, "__local__")}
    if target.path.name != "local" and local_only_modules:
        for name, module in local_only_modules.items():
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
            skip_list = {normalize_path(target, log_path, resolve=True)}

    output_path = args.output
    if output_path.is_dir():
        output_dir = format_output_name(target.name, output_ts)
        output_path = output_path.joinpath(output_dir)
    output_path = output_path.resolve()

    output = OUTPUTS[args.output_type](
        output_path,
        compress=args.compress,
        encrypt=args.encrypt,
        public_key=args.public_key,
    )
    files.append(output.path)
    if target.path.name == "local":
        skip_list.add(normalize_path(target, output.path, resolve=True))

    log.info("Writing output to %s", output.path)
    if skip_list:
        log.info("Skipping own files: %s", ", ".join(skip_list))
    log.info("")

    dir_base = "fs"
    if target.os != "windows":
        dir_base = "fs/$rootfs$"

    with Collector(target, output, base=dir_base, skip_list=skip_list) as collector:
        # Acquire specified files
        if args.file or args.directory or args.glob:
            log.info("*** Acquiring specified paths")
            spec = []

            if args.file:
                for path in args.file:
                    spec.append(("file", path.strip()))

            if args.directory:
                for path in args.directory:
                    spec.append(("dir", path.strip()))

            if args.glob:
                for path in args.glob:
                    spec.append(("glob", path.strip()))

            collector.collect(spec, module_name=CLI_ARGS_MODULE)
            modules_successful.append(CLI_ARGS_MODULE)
            log.info("")

        # Run modules (sort first based on execution order)
        modules_selected = sorted(modules_selected.items(), key=lambda module: module[1].EXEC_ORDER)
        for name, mod in modules_selected:
            try:
                mod.run(target, args, collector)

                modules_successful.append(mod.__name__)
            except Exception:
                log.error("Error while running module %s", name, exc_info=True)
                modules_failed[mod.__name__] = get_formatted_exception()
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

        if args.output.is_dir():
            report_file_name = format_output_name(target.name, postfix=output_ts, ext="report.json")
        else:
            report_file_name = f"{output_path.name}.report.json"

        report_file_path = output_path.parent / report_file_name
        persist_execution_report(report_file_path, execution_report)

        files.append(report_file_path)
        log.info("Acquisition report for %s is written to %s", target, report_file_path)

    log.info("Output: %s", output.path)
    return files


def upload_files(paths: list[Path], upload_plugin: UploaderPlugin, no_proxy: bool = False) -> None:
    proxies = None if no_proxy else urllib.request.getproxies()
    log.debug("Proxies: %s (no_proxy = %s)", proxies, no_proxy)

    try:
        upload_files_using_uploader(upload_plugin, paths, proxies)
    except Exception:
        log.error("Upload %s FAILED. See log file for details.", paths)
        log.exception("")


PROFILES = {
    "full": {
        "windows": [
            NTFS,
            EventLogs,
            Registry,
            Tasks,
            ETL,
            Recents,
            RecycleBin,
            Drivers,
            PowerShell,
            Prefetch,
            Appcompat,
            PCA,
            Syscache,
            WBEM,
            AV,
            ActivitiesCache,
            BITS,
            DHCP,
            DNS,
            History,
            Misc,
            NTDS,
            ActiveDirectory,
            QuarantinedFiles,
            RemoteAccess,
            WindowsNotifications,
            SSH,
            IIS,
        ],
        "linux": [
            Etc,
            Boot,
            Home,
            History,
            SSH,
            Var,
            WebHosting,
        ],
        "bsd": [
            Etc,
            Boot,
            SSH,
            Home,
            Var,
            BSD,
        ],
        "esxi": [
            Bootbanks,
            ESXi,
            VMFS,
            SSH,
        ],
        "osx": [
            Etc,
            Home,
            Var,
            OSX,
            History,
            SSH,
        ],
    },
    "default": {
        "windows": [
            NTFS,
            EventLogs,
            Registry,
            Tasks,
            ETL,
            Recents,
            RecycleBin,
            Drivers,
            PowerShell,
            Prefetch,
            Appcompat,
            PCA,
            Syscache,
            WBEM,
            AV,
            BITS,
            DHCP,
            DNS,
            Misc,
            ActiveDirectory,
            RemoteAccess,
            ActivitiesCache,
        ],
        "linux": [
            Etc,
            Boot,
            Home,
            SSH,
            Var,
        ],
        "bsd": [
            Etc,
            Boot,
            Home,
            SSH,
            Var,
            BSD,
        ],
        "esxi": [
            Bootbanks,
            ESXi,
            VMFS,
            SSH,
        ],
        "osx": [
            Etc,
            Home,
            Var,
            OSX,
        ],
    },
    "minimal": {
        "windows": [
            NTFS,
            EventLogs,
            Registry,
            Tasks,
            PowerShell,
            Prefetch,
            Appcompat,
            PCA,
            Misc,
        ],
        "linux": [
            Etc,
            Boot,
            Home,
            SSH,
            Var,
        ],
        "bsd": [
            Etc,
            Boot,
            Home,
            SSH,
            Var,
            BSD,
        ],
        "esxi": [
            Bootbanks,
            ESXi,
            SSH,
        ],
        "osx": [
            Etc,
            Home,
            Var,
            OSX,
        ],
    },
    "none": None,
}


def main() -> None:
    parser = create_argument_parser(PROFILES, MODULES)
    args = parse_acquire_args(parser, config=CONFIG)

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

    log.info(ACQUIRE_BANNER)
    log.info("User: %s | Admin: %s", get_user_name(), is_user_admin())
    log.info("Arguments: %s", " ".join(sys.argv[1:]))
    log.info("Default Arguments: %s", " ".join(args.config.get("arguments")))
    log.info("")

    plugins_to_load = [("cloud", MinIO)]
    upload_plugins = UploaderRegistry("acquire.plugins", plugins_to_load)

    try:
        check_and_set_acquire_args(args, upload_plugins)
    except ValueError as err:
        log.exception(err)
        parser.exit(1)

    if args.upload:
        try:
            upload_files(args.upload, args.upload_plugin, args.no_proxy)
        except Exception:
            log.exception("Failed to upload files")
        return

    RemoteStreamConnection.configure(args.cagent_key, args.cagent_certificate)

    target_path = args.target

    if target_path == "local":
        target_query = {}
        if args.force_fallback:
            target_query.update({"force-directory-fs": 1})

        if args.fallback:
            target_query.update({"fallback-to-directory-fs": 1})

        target_query = urllib.parse.urlencode(target_query)
        target_path = f"{target_path}?{target_query}"

    log.info("Loading target %s", target_path)

    try:
        target = Target.open(target_path)
        log.info(target)
    except Exception:
        if not is_user_admin():
            log.error("Failed to load target, try re-running as administrator/root.")
            parser.exit(1)
        log.exception("Failed to load target")
        raise

    if target.os == "esxi":
        # Loader found that we are running on an esxi host
        # Perform operations to "enhance" memory
        with esxi_memory_context_manager():
            acquire_children_and_targets(target, args)
    else:
        acquire_children_and_targets(target, args)


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


def acquire_children_and_targets(target: Target, args: argparse.Namespace) -> None:
    if args.child:
        target = load_child(target, args.child)

    log.info("")

    try:
        files = acquire_target(target, args, args.start_time)
    except Exception:
        log.exception("Failed to acquire target")
        raise

    if args.children:
        for child in target.list_children():
            try:
                child_target = load_child(target, child.path)
            except Exception:
                continue

            log.info("")

            try:
                child_files = acquire_target(child_target, args)
                files.extend(child_files)
            except Exception:
                log.exception("Failed to acquire child target")
                continue

    files = sort_files(files)

    if args.auto_upload:
        log_file_handler = get_file_handler(log)
        if log_file_handler:
            log_file_handler.close()

        log.info("")
        try:
            upload_files(files, args.upload_plugin)
        except Exception:
            log.exception("Failed to upload files")


def sort_files(files: list[Union[str, Path]]) -> list[Path]:
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
