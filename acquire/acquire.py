import argparse
import enum
import functools
import io
import itertools
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict, namedtuple
from itertools import product
from pathlib import Path
from typing import Iterator, Optional, Union

from dissect.target import Target, exceptions
from dissect.target.filesystem import Filesystem
from dissect.target.filesystems import ntfs
from dissect.target.helpers import fsutil
from dissect.target.loaders.remote import RemoteStreamConnection
from dissect.target.loaders.targetd import TargetdLoader
from dissect.target.plugins.apps.webserver import iis
from dissect.target.plugins.os.windows.log import evt, evtx
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
    try:
        for user_details in target.user_details.all_with_home():
            yield normalize_path(target, user_details.home_path.joinpath(path), lower_case=False)
    except Exception as e:
        log.warning("Error occurred when requesting all user homes")
        log.debug("", exc_info=e)

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

        # The attr check is needed to correctly collect fake NTFS filesystems
        # where the MFT etc. are added to a VirtualFilesystem. This happens for
        # instance when the target is an acquired tar target.
        if not isinstance(fs, ntfs.NtfsFilesystem) and not hasattr(fs, "ntfs"):
            log.warning("Skipping %s (%s) - not an NTFS filesystem", fs, mountpoints)
            continue

        if fs == sysvol:
            name = "sysvol"
        elif fs in mount_lookup:
            name = mount_lookup[fs][0]
        else:
            name = f"vol-{fs.ntfs.serial:x}"

        yield fs, name, mountpoints


def iter_esxi_filesystems(target: Target) -> Iterator[tuple[str, str, Filesystem]]:
    for mount, fs in target.fs.mounts.items():
        if not mount.startswith("/vmfs/volumes/"):
            continue

        uuid = mount[len("/vmfs/volumes/") :]  # strip /vmfs/volumes/
        name = None
        if fs.__type__ == "fat":
            name = fs.volume.name
        elif fs.__type__ == "vmfs":
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
        spec = [("dir", "/sys")]
        collector.collect(spec, follow=False, volatile=True)


@register_module("--proc")
@local_module
class Proc(Module):
    DESC = "Procfs files (live systems only)"
    EXEC_ORDER = ExecutionOrder.BOTTOM

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        spec = [("dir", "/proc")]
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

            # If the filesystem is a virtual NTFS filesystem, journal will be
            # plain BinaryIO, not a RunlistStream.
            if isinstance(journal, RunlistStream):
                i = 0
                while journal.runlist[i][0] is None:
                    journal.seek(journal.runlist[i][1] * journal.block_size, io.SEEK_CUR)
                    i += 1

            # Use the same method to construct the output path as is used in
            # collector.collect_file()
            outpath = collector._output_path(f"{name}/$Extend/$Usnjrnl:$J")

            collector.output.write(
                outpath,
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

            # Use the same method to construct the output path as is used in
            # collector.collect_file()
            outpath = collector._output_path(f"{name}/$Secure:$SDS")

            collector.output.write(
                outpath,
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
        # Task Scheduler Service transaction log
        ("file", "sysvol/SchedLgU.txt"),
        ("file", "sysvol/windows/SchedLgU.txt"),
        ("file", "sysvol/windows/tasks/SchedLgU.txt"),
        ("file", "sysvol/winnt/tasks/SchedLgU.txt"),
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


@register_module("--startup")
class Startup(Module):
    DESC = "Windows Startup folder"
    SPEC = [
        ("dir", "sysvol/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"),
        ("dir", "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup", from_user_home),
    ]


def recyclebin_filter(path: fsutil.TargetPath) -> bool:
    return bool(path.stat().st_size >= (10 * 1024 * 1024))  # 10MB


@register_module("--recyclebin")
@module_arg(
    "--large-files",
    action="store_true",
    help="Collect files larger than 10MB in the Recycle Bin",
    default=False,
)
@module_arg(
    "--no-data-files",
    action="store_true",
    help="Skip collection of data files in the Recycle Bin",
    default=False,
)
class RecycleBin(Module):
    DESC = "recycle bin metadata and data files"

    @classmethod
    def _run(cls, target: Target, cli_args: argparse.Namespace, collector: Collector) -> None:
        large_files_filter = None if cli_args.large_files else recyclebin_filter

        if large_files_filter:
            log.info("Skipping files in Recycle Bin that are larger than 10MB.")

        patterns = ["$Recycle.bin/*/$I*", "Recycler/*/INFO2", "Recycled/INFO2"]

        if not cli_args.no_data_files:
            patterns.extend(["$Recycle.Bin/$R*", "$Recycle.Bin/*/$R*", "RECYCLE*/D*"])

        with collector.file_filter(large_files_filter):
            for fs, name, mountpoints in iter_ntfs_filesystems(target):
                log.info("Acquiring recycle bin from %s (%s)", fs, mountpoints)

                for pattern in patterns:
                    for entry in fs.path().glob(pattern):
                        if entry.is_file():
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
        ("dir", "sysvol/ProgramData/Microsoft/Search/Data/Applications/Windows"),
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
        ("dir", "sysvol/ProgramData/McAfee/MSC/Logs"),
        ("dir", "sysvol/ProgramData/McAfee/Agent/AgentEvents"),
        ("dir", "sysvol/ProgramData/McAfee/Agent/logs"),
        ("dir", "sysvol/ProgramData/McAfee/datreputation/Logs"),
        ("dir", "sysvol/ProgramData/Mcafee/Managed/VirusScan/Logs"),
        ("dir", "sysvol/Documents and Settings/All Users/Application Data/McAfee/Common Framework/AgentEvents"),
        ("dir", "sysvol/Documents and Settings/All Users/Application Data/McAfee/MCLOGS/SAE"),
        ("dir", "sysvol/Documents and Settings/All Users/Application Data/McAfee/datreputation/Logs"),
        ("dir", "sysvol/Documents and Settings/All Users/Application Data/McAfee/Managed/VirusScan/Logs"),
        ("dir", "sysvol/Program Files (x86)/McAfee/DLP/WCF Service/Log"),
        ("dir", "sysvol/Program Files (x86)/McAfee/ePolicy Orchestrator/Apache2/Logs"),
        ("dir", "sysvol/Program Files (x86)/McAfee/ePolicy Orchestrator/DB/Events"),
        ("dir", "sysvol/Program Files (x86)/McAfee/ePolicy Orchestrator/DB/Events/Debug"),
        ("dir", "sysvol/Program Files (x86)/McAfee/ePolicy Orchestrator/Server/Logs"),
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
    DIR_COMBINATIONS = namedtuple("DirCombinations", ["root_dirs", "dir_extensions", "history_files"])
    COMMON_DIR_COMBINATIONS = [
        DIR_COMBINATIONS(
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
    ]

    SPEC = [
        # IE
        ("dir", "AppData/Local/Microsoft/Internet Explorer/Recovery", from_user_home),
        ("dir", "AppData/Local/Microsoft/Windows/INetCookies", from_user_home),
        ("glob", "AppData/Local/Microsoft/Windows/WebCache/*.dat", from_user_home),
        # IE - index.dat
        ("file", "Cookies/index.dat", from_user_home),
        ("file", "Local Settings/History/History.IE5/index.dat", from_user_home),
        ("glob", "Local Settings/History/History.IE5/MSHist*/index.dat", from_user_home),
        ("file", "Local Settings/Temporary Internet Files/Content.IE5/index.dat", from_user_home),
        ("file", "Local Settings/Application Data/Microsoft/Feeds Cache/index.dat", from_user_home),
        ("file", "AppData/Local/Microsoft/Windows/History/History.IE5/index.dat", from_user_home),
        ("glob", "AppData/Local/Microsoft/Windows/History/History.IE5/MSHist*/index.dat", from_user_home),
        ("file", "AppData/Local/Microsoft/Windows/History/Low/History.IE5/index.dat", from_user_home),
        ("glob", "AppData/Local/Microsoft/Windows/History/Low/History.IE5/MSHist*/index.dat", from_user_home),
        ("file", "AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.IE5/index.dat", from_user_home),
        ("file", "AppData/Local/Microsoft/Windows/Temporary Internet Files/Low/Content.IE5/index.dat", from_user_home),
        ("file", "AppData/Roaming/Microsoft/Windows/Cookies/index.dat", from_user_home),
        ("file", "AppData/Roaming/Microsoft/Windows/Cookies/Low/index.dat", from_user_home),
        ("file", "AppData/Roaming/Microsoft/Windows/IEDownloadHistory/index.dat", from_user_home),
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
        # Safari - macOS
        ("file", "Library/Safari/Bookmarks.plist", from_user_home),
        ("file", "Library/Safari/Downloads.plist", from_user_home),
        ("file", "Library/Safari/Extensions/Extensions.plist", from_user_home),
        ("glob", "Library/Safari/History.*", from_user_home),
        ("file", "Library/Safari/LastSession.plist", from_user_home),
        ("file", "Library/Caches/com.apple.Safari/Cache.db", from_user_home),
    ]

    @classmethod
    def get_spec_additions(cls, target: Target, cli_args: argparse.Namespace) -> Iterator[tuple]:
        spec = set()
        for root_dirs, extension_dirs, history_files in cls.COMMON_DIR_COMBINATIONS:
            for root_dir, extension_dir, history_file in product(root_dirs, extension_dirs, history_files):
                full_path = f"{root_dir}/{extension_dir}/{history_file}"
                search_type = "glob" if "*" in full_path else "file"

                spec.add((search_type, full_path, from_user_home))

        return spec


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
        ("glob", "/boot/system*"),
    ]


def private_key_filter(path: fsutil.TargetPath) -> bool:
    with path.open("rt") as file:
        return "PRIVATE KEY" in file.readline()


@register_module("--home")
class Home(Module):
    SPEC = [
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
        ("dir", ".config", from_user_home),
        ("glob", "*/.config", from_user_home),
        ("file", ".wget-hsts", from_user_home),
        ("glob", "*/.wget-hsts", from_user_home),
        ("file", ".gitconfig", from_user_home),
        ("glob", "*/.gitconfig", from_user_home),
        ("file", ".selected_editor", from_user_home),
        ("glob", "*/.selected_editor", from_user_home),
        ("file", ".viminfo", from_user_home),
        ("glob", "*/.viminfo", from_user_home),
        ("file", ".lesshist", from_user_home),
        ("glob", "*/.lesshist", from_user_home),
        ("file", ".profile", from_user_home),
        ("glob", "*/.profile", from_user_home),
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
        # DHCP settings
        ("dir", "/private/var/db/dhcpclient/leases"),
    ]


@register_module("--osx-applications-info")
class OSXApplicationsInfo(Module):
    DESC = "OS-X info.plist from all installed applications"
    SPEC = [
        ("glob", "/Applications/*/Contents/Info.plist"),
        ("glob", "Applications/*/Contents/Info.plist", from_user_home),
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
            if not fs.__type__ == "vmfs":
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
        ("dir", "AppData/Local/ConnectedDevicesPlatform", from_user_home),
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
    # debug logs contain references to flow objects and will give errors
    logging.getLogger().setLevel(logging.CRITICAL)
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


def _add_modules_for_profile(choice: str, operating_system: str, profile: dict, msg: str) -> Optional[dict]:
    modules_selected = dict()

    if choice and choice != "none":
        profile_dict = profile[choice]
        if operating_system not in profile_dict:
            log.error(msg, operating_system, choice)
            return None

        for mod in profile_dict[operating_system]:
            modules_selected[mod.__modname__] = mod

    return modules_selected


def acquire_target_regular(target: Target, args: argparse.Namespace, output_ts: Optional[str] = None) -> list[str]:
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

    profile_modules = _add_modules_for_profile(
        profile, target.os, PROFILES, "No collection set for OS %s with profile %s"
    )

    if not (volatile_profile := args.volatile_profile):
        volatile_profile = "none"

    volatile_modules = _add_modules_for_profile(
        volatile_profile, target.os, VOLATILE, "No collection set for OS %s with volatile profile %s"
    )

    if (profile_modules or volatile_modules) is None:
        return files

    modules_selected.update(profile_modules)
    modules_selected.update(volatile_modules)

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

    output_path = args.output or args.output_file
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
        count = 0
        for name, mod in modules_selected:
            try:
                mod.run(target, args, collector)

                modules_successful.append(mod.__name__)
            except Exception:
                log.error("Error while running module %s", name, exc_info=True)
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


def upload_files(paths: list[Path], upload_plugin: UploaderPlugin, no_proxy: bool = False) -> None:
    proxies = None if no_proxy else urllib.request.getproxies()
    log.debug("Proxies: %s (no_proxy = %s)", proxies, no_proxy)

    try:
        upload_files_using_uploader(upload_plugin, paths, proxies)
    except Exception:
        log.error("Upload %s FAILED. See log file for details.", paths)
        GUI().message("Upload failed.")
        log.exception("")


class WindowsProfile:
    MINIMAL = [
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
    ]
    DEFAULT = [
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
    ]
    FULL = [
        *DEFAULT,
        History,
        NTDS,
        QuarantinedFiles,
        WindowsNotifications,
        SSH,
        IIS,
    ]


class LinuxProfile:
    MINIMAL = [
        Etc,
        Boot,
        Home,
        SSH,
        Var,
    ]
    DEFAULT = MINIMAL
    FULL = [
        *DEFAULT,
        History,
        WebHosting,
    ]


class BsdProfile:
    MINIMAL = [
        Etc,
        Boot,
        Home,
        SSH,
        Var,
        BSD,
    ]
    DEFAULT = MINIMAL
    FULL = MINIMAL


class ESXiProfile:
    MINIMAL = [
        Bootbanks,
        ESXi,
        SSH,
    ]
    DEFAULT = [
        *MINIMAL,
        VMFS,
    ]
    FULL = DEFAULT


class OSXProfile:
    MINIMAL = [
        Etc,
        Home,
        Var,
        OSX,
        OSXApplicationsInfo,
    ]
    DEFAULT = MINIMAL
    FULL = [
        *DEFAULT,
        History,
        SSH,
    ]


PROFILES = {
    "full": {
        "windows": WindowsProfile.FULL,
        "linux": LinuxProfile.FULL,
        "bsd": BsdProfile.FULL,
        "esxi": ESXiProfile.FULL,
        "osx": OSXProfile.FULL,
    },
    "default": {
        "windows": WindowsProfile.DEFAULT,
        "linux": LinuxProfile.DEFAULT,
        "bsd": BsdProfile.DEFAULT,
        "esxi": ESXiProfile.DEFAULT,
        "osx": OSXProfile.DEFAULT,
    },
    "minimal": {
        "windows": WindowsProfile.MINIMAL,
        "linux": LinuxProfile.MINIMAL,
        "bsd": BsdProfile.MINIMAL,
        "esxi": ESXiProfile.MINIMAL,
        "osx": OSXProfile.MINIMAL,
    },
    "none": None,
}


class VolatileProfile:
    DEFAULT = [
        Netstat,
        WinProcesses,
        WinProcEnv,
        WinArpCache,
        WinRDPSessions,
        WinDnsClientCache,
    ]
    EXTENSIVE = [
        Proc,
        Sys,
    ]


VOLATILE = {
    "default": {
        "windows": VolatileProfile.DEFAULT,
        "linux": [],
        "bsd": [],
        "esxi": [],
        "osx": [],
    },
    "extensive": {
        "windows": VolatileProfile.DEFAULT,
        "linux": VolatileProfile.EXTENSIVE,
        "bsd": VolatileProfile.EXTENSIVE,
        "esxi": VolatileProfile.EXTENSIVE,
        "osx": [],
    },
    "none": None,
}


def main() -> None:
    parser = create_argument_parser(PROFILES, VOLATILE, MODULES)
    args = parse_acquire_args(parser, config=CONFIG)

    # start GUI if requested through CLI / config
    flavour = None
    if args.gui == "always" or (
        args.gui == "depends" and os.environ.get("PYS_KEYSOURCE") == "prompt" and len(sys.argv) == 1
    ):
        flavour = platform.system()

    acquire_gui = GUI(flavour=flavour, upload_available=args.auto_upload)
    args.output, args.auto_upload, cancel = acquire_gui.wait_for_start(args)

    # Since output has a default value, set it to None when output_file is defined
    if args.output_file:
        args.output = None

    if cancel:
        parser.exit(0)

    # From here onwards, the GUI will be locked and cannot be closed because we're acquiring

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

    if args.targetd:
        from targetd.tools.targetd import start_client

        # set @auto hostname to real hostname
        if args.targetd_hostname == "@auto":
            args.targetd_hostname = f"/host/{Target.open('local').hostname}"

        config = {
            "function": args.targetd_func,
            "topics": [args.targetd_hostname, args.targetd_groupname, args.targetd_globalname],
            "link": args.targetd_link,
            "address": args.targetd_ip,
            "port": args.targetd_port,
            "cacert_str": args.targetd_cacert,
            "service": args.targetd_func == "agent",
            "cacert": None,
        }
        start_client(args, presets=config)
        return

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
            acquire_gui.message("This application must be run as administrator.")
            acquire_gui.wait_for_quit()
            parser.exit(1)
        log.exception("Failed to load target")
        raise

    if target.os == "esxi" and target.name == "local":
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
        acquire_gui.shard = (progress_limit // total_targets) * counter
        try:
            files.extend(acquire_target(target, args, args.start_time))

        except Exception:
            log.exception("Failed to acquire target")
            acquire_gui.message("Failed to acquire target")
            acquire_gui.wait_for_quit()
            raise

    if args.children:
        for child in target.list_children():
            counter += 1
            acquire_gui.shard = (100 // total_targets) * counter
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
                acquire_gui.message("Failed to acquire child target")
                continue

    files = sort_files(files)

    if args.auto_upload:
        log_file_handler = get_file_handler(log)
        if log_file_handler:
            log_file_handler.close()

        log.info("")
        try:
            upload_files(files, args.upload_plugin)
            acquire_gui.finish()
            acquire_gui.wait_for_quit()
        except Exception:
            log.exception("Failed to upload files")
            acquire_gui.message("Failed to upload files")
            acquire_gui.wait_for_quit()
    else:
        acquire_gui.finish()
        acquire_gui.wait_for_quit()


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
