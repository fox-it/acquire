import argparse
import ctypes
import datetime
import fcntl
import getpass
import json
import os
import sys
import textwrap
import traceback
from enum import Enum
from pathlib import Path
from stat import S_IRGRP, S_IROTH, S_IRUSR
from typing import Dict, List, Optional, Union

import acquire.outputs
from dissect.target.helpers.fsutil import TargetPath
from dissect.util.stream import AlignedStream


class VolatileAlignedStream(AlignedStream):
    """A volatile streaming class to handle files that live in volatile filesystem. Such as procfs or sysfs.
    Handeling various edge-cases and OSErrors encountered within these filesystems.

    Set max_filesize to 0 or `None` to remove the maximum filesize limitation.

    Args:
        path: The path to the file to acquire a VolatileStream of
        string_flags: String flags, such as 'r' or 'rb' to open the file with.
        flags: Integer flags. such as `O_RDONLY` or `O_NONBLOCK` to open the file with.
        max_filesize: Set the maximum file size for streaming. Set to 0 or `None` to remove the maximum.
    """

    def __init__(
        self,
        path: Union[str, TargetPath],
        string_flags: str = "rb",
        flags: int = os.O_RDONLY | os.O_NONBLOCK | os.O_NOATIME,
        max_filesize=5242880,  # 5mb
    ):

        self.max_filesize = max_filesize
        self.fh = open(path, string_flags)
        self.fd = self.fh.fileno()

        fcntl.fcntl(self.fd, fcntl.F_SETFL, flags)

        self.pos = 0
        self.buf = b""

        super().__init__()

    def tell(self) -> int:
        return self.pos

    def _read(self, offset: int, length: int) -> bytes:
        prev_pos = None

        while True:
            if self.is_writeonly:
                break

            prev_pos = self.tell()
            self.buf += os.read(self.fd, 4096)

            self.pos = len(self.buf)

            if not self.max_filesize:
                if prev_pos == self.tell() or self.tell() >= self.max_filesize:
                    break
            else:
                if prev_pos == self.tell() or self.tell():
                    break

        return self.buf

    @property
    def seekable(self) -> bool:
        """Returns wether this stream is seekable."""
        return False

    def close(self) -> None:
        """Close the opened file-descriptor and sets the acquired buffer to `None`."""
        self.buf = None
        os.close(self.fd)

    @property
    def is_writeonly(self) -> bool:
        """Check wether the file-descriptor assiciated with this stream is write-only.

        Returns:
            A boolean indicating wether the file-descriptor is write-only
        """
        st_mode = os.fstat(self.fd).st_mode
        # files in proc can produce input/output errors because they are "write-only"
        # for example /proc/sysrq-trigger and /proc/sys/net/ipv6/conf/all/stable_secret
        return not st_mode & (S_IRUSR | S_IRGRP | S_IROTH)


class StrEnum(str, Enum):
    """Sortable and serializible string-based enum"""


def create_argument_parser(profiles: Dict, modules: Dict) -> argparse.ArgumentParser:
    desc = ""

    profile_names = (name for name in profiles.keys() if name != "none")

    for name in profile_names:
        desc += f"{name} profile:\n"
        minindent = max([len(os_) for os_ in profiles[name].keys()])
        descfmt = f"  {{:{minindent}s}}: {{}}\n"
        for os_ in profiles[name].keys():
            indent = 4 + len(os_)
            modlist = textwrap.wrap(", ".join([mod.__modname__ for mod in profiles[name][os_]]), 50)

            moddesc = modlist.pop(0)
            for ml in modlist:
                moddesc += "\n" + (" " * indent) + ml

            desc += descfmt.format(os_, moddesc)
        desc += "\n"

    parser = argparse.ArgumentParser(
        prog="acquire",
        description=desc,
        epilog=(
            "If no target is specified, 'local' is used.\n\n"
            "If no options are given, the collection profile 'default' is used."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        fromfile_prefix_chars="@",
    )

    parser.add_argument(
        "target",
        metavar="TARGET",
        default="local",
        nargs="?",
        help="target to load (default: local)",
    )
    parser.add_argument("-o", "--output", default=".", help="output directory")
    parser.add_argument(
        "-ot",
        "--output-type",
        choices=acquire.outputs.OUTPUTS.keys(),
        default="tar",
        help="output type (default: tar)",
    )
    parser.add_argument(
        "--compress",
        action="store_true",
        help="compress output (if supported by the output type)",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="encrypt output (if supported by the output type)",
    )
    parser.add_argument("--public-key", help=argparse.SUPPRESS)
    parser.add_argument("-l", "--log", help="log directory location")
    parser.add_argument("--no-log", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-p", "--profile", choices=profiles.keys(), help="collection profile")

    parser.add_argument("-f", "--file", action="append", help="acquire file")
    parser.add_argument("-d", "--directory", action="append", help="acquire directory recursively")
    parser.add_argument("-g", "--glob", action="append", help="acquire files matching glob pattern")

    parser.add_argument("--disable-report", action="store_true", help="disable acquisition report file")

    parser.add_argument("--child", help="only collect specific child")
    parser.add_argument(
        "--children",
        action="store_true",
        help="collect all children in addition to main target",
    )

    parser.add_argument(
        "--force-fallback",
        action="store_true",
        help="force filesystem access directly through OS level. Only supported with target 'local'",
    )
    parser.add_argument(
        "--fallback",
        action="store_true",
        help=(
            "fallback to OS level filesystem access if filesystem type is not supported. "
            "Only supported with target 'local'"
        ),
    )

    parser.add_argument(
        "-u",
        "--auto-upload",
        action="store_true",
        help="upload result files after collection",
    )
    parser.add_argument("--upload", nargs="+", help="upload specified files")
    parser.add_argument("--no-proxy", action="store_true", help="don't autodetect proxies")

    for module_cls in modules.values():
        for args, kwargs in module_cls.__cli_args__:
            parser.add_argument(*args, **kwargs)

    parser.add_argument("-v", "--verbose", action="count", default=3, help="increase output verbosity")
    return parser


def parse_acquire_args(parser: argparse.ArgumentParser, config_defaults: Optional[List] = None) -> argparse.Namespace:
    """Sets the command line args to defaults, if they were not set."""

    config_defaults = config_defaults or []

    config_defaults_args = parser.parse_args(config_defaults)
    command_line_args = parser.parse_args()

    for argument, value in command_line_args._get_kwargs():
        if parser.get_default(argument) == value:
            config_argument = getattr(config_defaults_args, argument, value)
            setattr(command_line_args, argument, config_argument)

    return command_line_args


def get_pid() -> int:
    """Get the current process ID (pid) of the acquire process.

    Returns:
        A int representing the process ID of the acquire process.

    """
    return os.getpid()


def get_ppid() -> int:
    """Get the current parent process ID (pid) of the acquire process.

    Returns:
        A int representing the parent process ID of the acquire process.
    """
    return os.getppid()


def get_user_name() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def is_user_admin() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        pass

    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except Exception:
        return False


def get_utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def get_utc_now_str() -> str:
    return get_utc_now().strftime("%Y%m%d%H%M%S")


def get_formatted_exception() -> str:
    exc_info = sys.exc_info()
    return "".join(traceback.format_exception(*exc_info))


def format_output_name(prefix, postfix=None, ext=None):
    if not postfix:
        postfix = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    name = "{}_{}".format(prefix, postfix)
    if ext:
        name = "{}.{}".format(name, ext)
    return name


def persist_execution_report(output_dir: Path, prefix: str, timestamp: str, report_data: Dict) -> Path:
    report_filename = format_output_name(prefix, postfix=timestamp, ext="report.json")
    report_full_path = output_dir / report_filename
    with open(report_full_path, "w") as f:
        f.write(json.dumps(report_data, sort_keys=True, indent=4))
    return report_full_path
