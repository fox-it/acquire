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
from io import SEEK_SET, UnsupportedOperation
from pathlib import Path
from stat import S_IRGRP, S_IROTH, S_IRUSR
from typing import Dict, List, Optional

from dissect.util.stream import AlignedStream

from acquire.outputs import OUTPUTS


class VolatileStream(AlignedStream):
    """Streaming class to handle various procfs and sysfs edge-cases.  Backed by `AlignedStream`.

    Args:
        path: Path of the file to obtain a file-handle from.
        mode: Mode string to open the file-handle with. Such as "rt" and "rb".
        flags: Flags to open the file-descriptor with.
        size: The maximum size of the stream. None if unknown.
    """

    def __init__(
        self,
        path: Path,
        mode: str = "rb",
        flags: int = os.O_RDONLY | os.O_NONBLOCK,
        size: int = 1024 * 1024 * 5,
    ):
        if sys.platform != "darwin":
            # O_NOATIME is not available on darwin systems. We still want to add it whenever possible.
            flags = flags | os.O_NOATIME

        self.fh = path.open(mode)
        self.fd = self.fh.fileno()
        fcntl.fcntl(self.fd, fcntl.F_SETFL, flags)

        st_mode = os.fstat(self.fd).st_mode
        write_only = (st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) == 0

        super().__init__(0 if write_only else size)

    def seek(self, pos: int, whence: int = SEEK_SET) -> int:
        raise UnsupportedOperation("VolatileStream is not seekable")

    def seekable(self) -> bool:
        return False

    def _read(self, offset: int, length: int) -> bytes:
        return os.read(self.fd, min(length, self.size - offset))


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
        choices=OUTPUTS.keys(),
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
