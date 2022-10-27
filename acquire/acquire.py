import enum
import functools
import io
import itertools
import logging
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from argparse import Namespace
from collections import defaultdict
from pathlib import Path

from dissect.target import Target, exceptions
from dissect.target.filesystems import ntfs
from dissect.target.helpers import fsutil
from dissect.target.plugins.os.windows import iis
from dissect.target.plugins.os.windows.log import evt, evtx

from acquire.collector import Collector, get_full_formatted_report, get_report_summary
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
from acquire.uploaders.plugin_registry import PluginRegistry, UploaderRegistry
from acquire.utils import (
    create_argument_parser,
    format_output_name,
    get_formatted_exception,
    get_user_name,
    get_utc_now,
    get_utc_now_str,
    is_user_admin,
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


def misc_windows_user_homes(target):
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


def from_user_home(target, path):
    for user_details in target.user_details.all_with_home():
        yield str(user_details.home_path.joinpath(path))
    if target.os == "windows":
        for misc_dir in misc_windows_user_homes(target):
            yield str(misc_dir.joinpath(path))


def iter_ntfs_filesystems(target):
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


def mount_all_ntfs_filesystems(target):
    for fs, name, _ in iter_ntfs_filesystems(target):
        if name not in target.fs.mounts:
            target.fs.mount(name, fs)


def iter_esxi_filesystems(target):
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
    def run(cls, target, cli_args, collector):
        desc = cls.DESC or cls.__name__.lower()
        log.info("*** Acquiring %s", desc)

        collector.bind(cls)

        try:
            collector.collect(cls.SPEC)

            spec_ext = cls.get_spec_additions(target)
            if spec_ext:
                collector.collect(list(spec_ext))

            cls._run(target, collector)
        finally:
            collector.unbind()

    @classmethod
    def get_spec_additions(cls, target):
        pass

    @classmethod
    def _run(cls, target, collector):
        pass


@register_module("-n", "--ntfs")
class NTFS(Module):
    DESC = "NTFS filesystem metadata"

    @classmethod
    def _run(cls, target, collector):
        for fs, name, mountpoints in iter_ntfs_filesystems(target):
            log.info("Acquiring %s (%s)", fs, mountpoints)

            collector.collect_file(fs.path("$MFT"), outpath=name + "/$MFT")
            collector.collect_file(fs.path("$Boot"), outpath=name + "/$Boot")

            cls.collect_usnjrnl(collector, fs, name)
            cls.collect_ntfs_secure(collector, fs, name)

    @classmethod
    def collect_usnjrnl(cls, collector: Collector, fs, name: str) -> None:
        usnjrnl_path = fs.path("$Extend/$Usnjrnl")

        try:
            entry = usnjrnl_path.get()
            journal = entry.entry.open("$J")

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
    def collect_ntfs_secure(cls, collector: Collector, fs, name: str) -> None:
        secure_path = fs.path("$Secure")
        try:
            entry = secure_path.get()
            sds = entry.entry.open("$SDS")
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
    def get_spec_additions(cls, target):
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
    def get_spec_additions(cls, target):
        if target.ntversion < 6.2:
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


@register_module("--win-rd-sessions")
@local_module
class WinRDPSessions(Module):
    DESC = "Windows Remote Desktop session information"
    SPEC = [
        ("command", (["qwinsta", "/VM"], "win-rd-sessions")),
    ]
    EXEC_ORDER = ExecutionOrder.BOTTOM


@register_module("--winpmem")
@local_module
class WinMemDump(Module):
    DESC = "Windows full memory dump"
    EXEC_ORDER = ExecutionOrder.BOTTOM

    @classmethod
    def _run(cls, target, collector):
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


@register_module("-e", "--eventlogs")
class EventLogs(Module):
    DESC = "event logs"

    @classmethod
    def get_spec_additions(cls, target):
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
    ]


@register_module("-nt", "--ntds")
class NTDS(Module):
    SPEC = [
        ("dir", "sysvol/windows/NTDS"),
    ]

    @classmethod
    def get_spec_additions(cls, target):
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
        ("glob", "Recent/*.lnk", from_user_home),
    ]


@register_module("--recyclebin")
class RecycleBin(Module):
    DESC = "recycle bin metadata"

    @classmethod
    def _run(cls, target, collector):
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
    def get_spec_additions(cls, target):
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
    def get_spec_additions(cls, target):
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
    def get_spec_additions(cls, target):
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
        ("dir", "sysvol/windows/sysvol/domain/policies/"),
        ("dir", "sysvol/windows/system32/GroupPolicy/DataStore/"),
        ("glob", "sysvol/Windows/System32/LogFiles/SUM/*.mdb"),
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
        # ESET
        ("dir", "sysvol/Documents and Settings/All Users/Application Data/ESET/ESET NOD32 Antivirus/Logs"),
        ("dir", "sysvol/ProgramData/ESET/ESET NOD32 Antivirus/Logs"),
        # Emsisoft
        ("glob", "sysvol/ProgramData/Emsisoft/Reports/scan*.txt"),
        # F-Secure
        ("dir", "sysvol/ProgramData/F-Secure/Log"),
        ("dir", "sysvol/Users*/AppData/Local/F-Secure/Log"),
        ("dir", "sysvol/ProgramData/F-Secure/Antivirus/ScheduledScanReports"),
        # HitmanPro
        ("dir", "sysvol/ProgramData/HitmanPro/Logs"),
        ("dir", "sysvol/ProgramData/HitmanPro.Alert/Logs"),
        ("file", "sysvol/ProgramData/HitmanPro.Alert/excalibur.db"),
        # Malwarebytes
        ("glob", "sysvol/ProgramData/Malwarebytes/Malwarebytes Anti-Malware/Logs/mbam-log-*.xml"),
        ("glob", "sysvol/ProgramData/Malwarebytes/MBAMService/logs/mbamservice.log*"),
        ("dir", "sysvol/Users*/AppData/Roaming/Malwarebytes/Malwarebytes Anti-Malware/Logs"),
        ("dir", "sysvol/ProgramData/Malwarebytes/MBAMService/ScanResults"),
        # McAfee
        ("dir", "sysvol/Users/All Users/Application Data/McAfee/DesktopProtection"),
        ("dir", "sysvol/ProgramData/McAfee/DesktopProtection"),
        ("dir", "sysvol/ProgramData/McAfee/Endpoint Security/Logs"),
        ("dir", "sysvol/ProgramData/McAfee/Endpoint Security/Logs_Old"),
        ("dir", "sysvol/ProgramData/Mcafee/VirusScan"),
        ("dir", "sysvol/ProgramData/McAfee/Endpoint Security/Logs"),
        # RogueKiller
        ("glob", "sysvol/ProgramData/RogueKiller/logs/AdliceReport_*.json"),
        # SUPERAntiSpyware
        ("dir", "sysvol/Users*/AppData/Roaming/SUPERAntiSpyware/Logs"),
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
    ]


@register_module("--history")
class History(Module):
    DESC = "browser history from IE, Firefox and Chrome"

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
            "file",
            "AppData/Local/Microsoft/Windows/History/History.IE5/MSHist*/index.dat",
            from_user_home,
        ),
        (
            "file",
            "AppData/Local/Microsoft/Windows/History/Low/History.IE5/index.dat",
            from_user_home,
        ),
        (
            "file",
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
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Current Session", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Current Tabs", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/History", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Archived History", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Last Session", from_user_home),
        ("glob", "AppData/Local/Google/Chrom*/User Data/*/Last Tabs", from_user_home),
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
            "Local Settings/Application Data/Google/Chrom*/User Data/*/History",
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
        ("glob", "/Users/*/Library/Applications Support/Google/Chrome/*/Current Session"),
        ("glob", "/Users/*/Library/Applications Support/Google/Chrome/*/Current Tabs"),
        ("glob", "/Users/*/Library/Applications Support/Google/Chrome/*/History"),
        ("glob", "/Users/*/Library/Applications Support/Google/Chrome/*/Archived History"),
        ("glob", "/Users/*/Library/Applications Support/Google/Chrome/*/Last Session"),
        ("glob", "/Users/*/Library/Applications Support/Google/Chrome/*/Last Tabs"),
        ("glob", "/Users/*/Library/Applications Support/Chromium/*/Current Session"),
        ("glob", "/Users/*/Library/Applications Support/Chromium/*/Current Tabs"),
        ("glob", "/Users/*/Library/Applications Support/Chromium/*/History"),
        ("glob", "/Users/*/Library/Applications Support/Chromium/*/Archived History"),
        ("glob", "/Users/*/Library/Applications Support/Chromium/*/Last Session"),
        ("glob", "/Users/*/Library/Applications Support/Chromium/*/Last Tabs"),
        # Firefox
        ("glob", "AppData/Local/Mozilla/Firefox/Profiles/*/*.sqlite*", from_user_home),
        ("glob", "AppData/Roaming/Mozilla/Firefox/Profiles/*/*.sqlite*", from_user_home),
        ("glob", "Application Data/Mozilla/Firefox/Profiles/*/*.sqlite*", from_user_home),
        ("glob", "/Users/*/Library/Applications Support/Firefox/Profiles/*/*.sqlite*"),
        # Safari
        ("glob", "/Users/*/Library/Safari/Bookmarks.plist"),
        ("glob", "/Users/*/Library/Safari/Downloads.plist"),
        ("glob", "/Users/*/Library/Safari/Extensions/Extensions.plist"),
        ("glob", "/Users/*/Library/Safari/History.*"),
        ("glob", "/Users/*/Library/Safari/LastSession.plist"),
        ("glob", "/Users/*/Library/Caches/com.apple.Safari/Cache.db"),
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


@register_module("--wer")
class WER(Module):
    DESC = "WER (Windows Error Reporting) related files"

    @classmethod
    def get_spec_additions(cls, target):
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


@register_module("--home")
class Home(Module):
    SPEC = [
        ("glob", "/root/.*[akz]sh*"),
        ("dir", "/root/.config"),
        ("glob", "/home/*/.*[akz]sh*"),
        ("glob", "/home/*/.config"),
        ("glob", "/home/*/*/.*[akz]sh*"),
        ("glob", "/home/*/*/.config"),
        # OS-X home (aka /Users)
        ("glob", "/Users/*/.*[akz]sh*"),
        ("glob", "/Users/*/.bash_sessions/*"),
        ("glob", "/Users/*/Library/LaunchAgents/*"),
        ("glob", "/Users/*/Library/Logs/*"),
        ("glob", "/Users/*/Preferences/*"),
        ("glob", "/Users/*/Library/Preferences/*"),
    ]


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
    def _run(cls, target, collector):
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
    def _run(cls, target, collector):
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
    def run(cls, target, cli_args, collector):
        log.info("*** Acquiring file hashes")

        specs = cls.get_specs(cli_args)

        collector.bind(cls)
        try:
            start = time.time()

            path_hashes = collect_hashes(target, specs, path_filters=cls.DEFAULT_FILE_FILTERS)
            rows_count, csv_compressed_bytes = serialize_into_csv(path_hashes, compress=True)

            collector.write_bytes(
                f"{collector.base}/{collector.METADATA_BASE}/file-hashes.csv.gz",
                csv_compressed_bytes,
            )
            log.info("Hashing is done, %s files processed in %.2f secs", rows_count, (time.time() - start))
        finally:
            collector.unbind()

    @classmethod
    def get_specs(cls, cli_args):
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


def print_disks_overview(target):
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


def print_volumes_overview(target):
    log.info("// Volumes")
    try:
        for volume in target.volumes:
            log.info("%s", volume)
    except Exception:
        log.error("Failed to iterate volumes")
    log.info("")


def acquire_target(target, args, output_path, log_path, output_ts=None):
    output_ts = output_ts or get_utc_now_str()
    if log_path and log_path.is_dir():
        log_file = log_path.joinpath(format_output_name("Unknown", output_ts, "log"))
        reconfigure_log_file(log, log_file, delay=True)
    else:
        log_file = log_path

    files = []
    if log_file:
        files.append(log_file)

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
    if log_file_handler and log_path and log_path.is_dir():
        log_file = format_output_name(target.name, output_ts, "log")
        log_file_handler.set_filename(log_file)
        log.info("Logging to file %s", Path(log_file_handler.baseFilename).resolve())
        files = [log_file_handler.baseFilename]

    if output_path.is_dir():
        log_dir = format_output_name(target.name, output_ts)
        output_path = output_path.joinpath(log_dir).resolve()

    public_key = CONFIG.get("public_key")
    if not public_key and args.public_key and Path(args.public_key).is_file():
        public_key = Path(args.public_key).read_text()

    output = OUTPUTS[args.output_type](
        output_path,
        compress=args.compress,
        encrypt=args.encrypt,
        public_key=public_key,
    )
    files.append(output.path)

    log.info("Writing output to %s", output.path)
    log.info("")

    dir_base = "fs"
    if target.os != "windows":
        dir_base = "fs/$rootfs$"

    with Collector(target, output, base=dir_base) as collector:
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
        modules_selected = dict(sorted(modules_selected.items(), key=lambda module: module[1].EXEC_ORDER))
        for name, mod in modules_selected.items():
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

        report_output_dir = output_path if output_path.is_dir() else output_path.parent
        report_file_path = persist_execution_report(
            output_dir=report_output_dir,
            prefix=target.name,
            timestamp=output_ts,
            report_data=execution_report,
        )
        files.append(report_file_path)
        log.info("Acquisition report for %s is written to %s", target, report_file_path)

    log.info("Output: %s", output.path)
    return files


def upload_files(
    paths,
    plugin_registry: PluginRegistry = None,
    no_proxy=False,
):

    proxies = None if no_proxy else urllib.request.getproxies()
    log.debug("Proxies: %s (no_proxy = %s)", proxies, no_proxy)

    upload = CONFIG.get("upload", {})
    upload_mode = upload.get("mode")

    if not upload or not upload_mode:
        raise ValueError("Uploading is not configured")

    try:
        if upload_mode in plugin_registry.plugins.keys():
            endpoint = plugin_registry.get(upload_mode)(**CONFIG)
            endpoint.upload_files(paths, proxies)
        else:
            raise ValueError("Invalid upload mode")

    except Exception:
        log.error("Upload %s FAILED. See log file for details.", paths)
        log.exception("")


PROFILES = {
    "full": {
        "windows": [
            AV,
            ActivitiesCache,
            Appcompat,
            BITS,
            DHCP,
            DNS,
            Drivers,
            ETL,
            EventLogs,
            History,
            Misc,
            NTDS,
            NTFS,
            Prefetch,
            QuarantinedFiles,
            Recents,
            RecycleBin,
            Registry,
            RemoteAccess,
            Syscache,
            Tasks,
            WBEM,
            WindowsNotifications,
        ],
        "linux": [
            Etc,
            Boot,
            Home,
            Var,
        ],
        "bsd": [
            Etc,
            Boot,
            Home,
            Var,
            BSD,
        ],
        "esxi": [
            Bootbanks,
            ESXi,
            VMFS,
        ],
        "osx": [
            Etc,
            Home,
            Var,
            OSX,
            History,
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
            Prefetch,
            Appcompat,
            Syscache,
            WBEM,
            AV,
            BITS,
            DHCP,
            DNS,
            Misc,
            RemoteAccess,
            ActivitiesCache,
        ],
        "linux": [
            Etc,
            Boot,
            Home,
            Var,
        ],
        "bsd": [
            Etc,
            Boot,
            Home,
            Var,
            BSD,
        ],
        "esxi": [
            Bootbanks,
            ESXi,
            VMFS,
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
            Prefetch,
            Appcompat,
            Misc,
        ],
        "linux": [
            Etc,
            Boot,
            Home,
            Var,
        ],
        "bsd": [
            Etc,
            Boot,
            Home,
            Var,
            BSD,
        ],
        "esxi": [
            Bootbanks,
            ESXi,
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


def main():
    parser = create_argument_parser(PROFILES, MODULES)
    args = parse_acquire_args(parser, config_defaults=CONFIG.get("arguments"))

    output_ts = get_utc_now_str()

    log_path = None
    log_file = None
    if not args.no_log:
        log_path = Path(args.log or args.output)

        if log_path.is_dir():
            log_prefix = "Upload" if args.upload else "Unknown"
            log_file = log_path.joinpath(format_output_name(log_prefix, output_ts, "log"))
        elif log_path.is_file() or (not log_path.exists() and log_path.parent.is_dir()):
            if args.children:
                parser.exit("Log path must be a directory when using --children")
            log_file = log_path
        else:
            parser.exit(f"Log path doesn't exist: {log_path}")

    setup_logging(log, log_file, args.verbose, delay=log_path and log_path.is_dir())

    plugins_to_load = [("cloud", MinIO)]
    plugin_registry = UploaderRegistry("acquire.plugins", plugins_to_load)

    log.info(ACQUIRE_BANNER)
    log.info("User: %s | Admin: %s", get_user_name(), is_user_admin())
    log.info("Arguments: %s", " ".join(sys.argv[1:]))
    log.info("Default Arguments: %s", " ".join(CONFIG.get("arguments", [])))

    log.info("")

    if args.upload:
        try:
            upload_files(args.upload, plugin_registry, args.no_proxy)
        except Exception:
            log.exception("Failed to upload files")
        return

    output_path = Path(args.output)
    if args.children and not output_path.is_dir():
        log.error("Output path must be a directory when using --children")
        parser.exit(1)
    elif not output_path.exists() and not output_path.parent.is_dir():
        log.error("Output path doesn't exist: %s", output_path)
        parser.exit(1)

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
        log.exception("Failed to load target")
        raise

    if target.os == "esxi":
        # Loader found that we are running on an esxi host
        # Perform operations to "enhance" memory
        with esxi_memory_context_manager():
            acquire_children_and_targets(target, args, output_path, log_path, output_ts, plugin_registry)
    else:
        acquire_children_and_targets(target, args, output_path, log_path, output_ts, plugin_registry)


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


def acquire_children_and_targets(
    target: Target, args: Namespace, output_path: Path, log_path: Path, output_ts: str, plugin_registry: PluginRegistry
):
    if args.child:
        load_child(target, args.child)

    log.info("")
    try:
        files = acquire_target(target, args, output_path, log_path, output_ts)
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
                child_files = acquire_target(child_target, args, output_path, log_path)
                files.extend(child_files)
            except Exception:
                log.exception("Failed to acquire child target")
                continue

    if args.auto_upload:
        log_file_handler = get_file_handler(log)
        if log_file_handler:
            log_file_handler.close()

        log.info("")
        try:
            upload_files(paths=files, plugin_registry=plugin_registry)
        except Exception:
            log.exception("Failed to upload files")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception:
        sys.exit(1)
