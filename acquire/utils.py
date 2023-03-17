import argparse
import ctypes
import datetime
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
from typing import Any, Optional

from dissect.util.stream import AlignedStream

from acquire.outputs import OUTPUTS
from acquire.uploaders.plugin_registry import UploaderRegistry

try:
    # Windows systems do not have the fcntl module.
    from fcntl import F_SETFL, fcntl

    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False


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
        # Windows and Darwin systems don't have O_NOATIME or O_NONBLOCK. Add them if they are available.
        flags: int = (os.O_RDONLY | getattr(os, "O_NOATIME", 0) | getattr(os, "O_NONBLOCK", 0)),
        size: int = 1024 * 1024 * 5,
    ):
        self.fh = path.open(mode)
        self.fd = self.fh.fileno()

        if HAS_FCNTL:
            fcntl(self.fd, F_SETFL, flags)

        st_mode = os.fstat(self.fd).st_mode
        write_only = (st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) == 0  # novermin

        super().__init__(0 if write_only else size)

    def seek(self, pos: int, whence: int = SEEK_SET) -> int:
        raise UnsupportedOperation("VolatileStream is not seekable")

    def seekable(self) -> bool:
        return False

    def _read(self, offset: int, length: int) -> bytes:
        return os.read(self.fd, min(length, self.size - offset))


class StrEnum(str, Enum):
    """Sortable and serializible string-based enum"""


def create_argument_parser(profiles: dict, modules: dict) -> argparse.ArgumentParser:
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
    parser.add_argument("-o", "--output", default=Path("."), type=Path, help="output directory")
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
    parser.add_argument("--public-key", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("-l", "--log", type=Path, help="log directory location")
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
    parser.add_argument(
        "--upload",
        nargs="+",
        help="upload specified files (all other acquire actions are ignored)",
    )
    parser.add_argument("--no-proxy", action="store_true", help="don't autodetect proxies")

    for module_cls in modules.values():
        for args, kwargs in module_cls.__cli_args__:
            parser.add_argument(*args, **kwargs)

    parser.add_argument("-v", "--verbose", action="count", default=3, help="increase output verbosity")
    return parser


def parse_acquire_args(
    parser: argparse.ArgumentParser,
    config: dict[str, Any],
) -> argparse.Namespace:
    """Parse and set the acquire command line arguments.

    The arguments are set to values supplied in ``config[arguments]``, when not
    changed from the default values specified in ``parser``.

    The ``config`` dict is added to the parsed command line arguments for
    convenience of later use.

    Args:
        parser: A parser for acquire command line arguments.
        config: A dict of global configuration values.

    Returns:
        A command line arguments namespace
    """
    command_line_args = parser.parse_args()
    _merge_args_and_config(parser, command_line_args, config)

    return command_line_args


def _merge_args_and_config(
    parser: argparse.ArgumentParser,
    command_line_args: argparse.Namespace,
    config: dict[str, Any],
):
    """Update the parsed command line arguments with the optional set of configured default arguments.

    The arguments are set to values supplied in ``config[arguments]``, when not
    changed from the default values specified in ``parser``.

    The ``config`` dict is added to the parsed command line arguments for
    convenience of later use.

    Args:
        parser: A parser for acquire command line arguments.
        command_line_args: The namespace with parsed commandline args. This
                           namespace is updated with the optional set of
                           configured default arguments.
        config: A dict of global configuration values.
    """
    config_defaults = config.get("arguments")
    if not config_defaults:
        config_defaults = config["arguments"] = []

    config_defaults_args = parser.parse_args(config_defaults)

    for argument, value in command_line_args._get_kwargs():
        if parser.get_default(argument) == value:
            config_argument = getattr(config_defaults_args, argument, value)
            setattr(command_line_args, argument, config_argument)

    setattr(command_line_args, "config", config)


def check_and_set_log_args(args: argparse.Namespace):
    """Check command line arguments which are related to logging.

    Also some arguments derived from the user supplied ones are set in the
    ``args`` namespace for convenience.

    This function is separate from ``check_and_set_acquire_args()`` as logging
    needs to be setup as soon as possible when running acquire.

    Args:
        args: The namespace containing the command line arguments.

    Raises:
        ValueError: When an invalid combination of arguments is found.
    """
    start_time = get_utc_now_str()
    log_path = None
    log_to_dir = False
    log_delay = False

    if not args.no_log:
        log_path = args.log or args.output

        if log_path.is_dir():
            log_to_dir = True
            log_delay = True
        elif log_path.is_file() or (not log_path.exists() and log_path.parent.is_dir()):
            # Logging to a single file is allowed, even if the file does not yet
            # exist, as it will be automatically created. However then the parent
            # directory must exist.
            if args.children:
                # If children are acquired, logging can only happen to separate
                # files, so log_path needs to be a directory.
                raise ValueError("Log path must be a directory when using --children")
        else:
            raise ValueError(f"Log path doesn't exist: {log_path}")

    setattr(args, "start_time", start_time)
    setattr(args, "log_path", log_path)
    setattr(args, "log_to_dir", log_to_dir)
    setattr(args, "log_delay", log_delay)


def check_and_set_acquire_args(
    args: argparse.Namespace,
    upload_plugins: UploaderRegistry,
):
    """Check the command line arguments and set some derived arguments.

    This function is separate from ``check_and_set_log_args()`` as logging
    needs to be setup as soon as possible when running acquire.

    Args:
        args: The namespace containing the command line arguments.
        upload_plugins: The registry of available upload plugins.

    Raises:
        ValueError: When an invalid combination of arguments is found.
    """
    upload_plugin = None

    # check & set upload related configuration
    if args.upload or args.auto_upload:
        upload_mode = args.config.get("upload", {}).get("mode")
        if not upload_mode:
            raise ValueError("Uploading is not configured")

        upload_plugin_cls = upload_plugins.get(upload_mode)
        if not upload_plugin_cls:
            raise ValueError(f"Invalid upload mode: {upload_mode}")

        # If initialization of the plugin fails, a ValueError is raised
        upload_plugin = upload_plugin_cls(**args.config)

    setattr(args, "upload_plugin", upload_plugin)

    if not args.upload:
        # check output related configuration
        if args.children and not args.output.is_dir():
            raise ValueError("Output path must be a directory when using --children")
        elif not args.output.exists() and not args.output.parent.is_dir():
            raise ValueError(f"Output path doesn't exist: {args.output}")

        # check & set encryption related configuration
        if args.encrypt:
            public_key = args.config.get("public_key")
            if not public_key and args.public_key and args.public_key.is_file():
                public_key = args.public_key.read_text()
            if not public_key:
                raise ValueError("No public key available (embedded or argument)")
            setattr(args, "public_key", public_key)

        # set cagent related configuration
        setattr(args, "cagent_key", args.config.get("cagent_key"))
        setattr(args, "cagent_certificate", args.config.get("cagent_certificate"))


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


def format_output_name(prefix: str, postfix: Optional[str] = None, ext: Optional[str] = None) -> str:
    if not postfix:
        postfix = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    name = f"{prefix}_{postfix}"
    if ext:
        name = f"{name}.{ext}"
    return name


def persist_execution_report(path: Path, report_data: dict) -> Path:
    with open(path, "w") as f:
        f.write(json.dumps(report_data, sort_keys=True, indent=4))
