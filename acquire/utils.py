import argparse
import ctypes
import datetime
import getpass
import json
import os
import re
import sys
import textwrap
import traceback
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from dissect.target import Target

from acquire.outputs import OUTPUTS
from acquire.uploaders.plugin_registry import UploaderRegistry

# Acquire Configuration for CAgent and TargetD
CAGENT_TARGETD_ATTRS = {
    "cagent_key",
    "cagent_certificate",
    "targetd_func",
    "targetd_cacert",
    "targetd_ip",
    "targetd_port",
    "targetd_hostname",
    "targetd_groupname",
    "targetd_globalname",
    "targetd_link",
}


class StrEnum(str, Enum):
    """Sortable and serializible string-based enum"""


def _create_profile_information(profiles: dict) -> str:
    desc = ""

    profile_names = (name for name in profiles.keys() if name != "none")
    for name in profile_names:
        profile_dict = profiles[name]
        desc += f"{name} profile:\n"

        minindent = max([len(os_) for os_ in profile_dict.keys()])
        descfmt = f"  {{:{minindent}s}}: {{}}\n"

        for os_, modlist in profile_dict.items():
            if not modlist:
                continue
            indent = 4 + len(os_)
            modlist = textwrap.wrap(", ".join([mod.__modname__ for mod in modlist]), 50)
            moddesc = modlist.pop(0)
            for ml in modlist:
                moddesc += "\n" + (" " * indent) + ml
            desc += descfmt.format(os_, moddesc)
        desc += "\n"

    return desc


def create_argument_parser(profiles: dict, volatile: dict, modules: dict) -> argparse.ArgumentParser:
    module_profiles = "Module:\n" + textwrap.indent(_create_profile_information(profiles), "  ")
    volatile_profiles = "Volatile:\n" + textwrap.indent(_create_profile_information(volatile), "  ")

    desc = module_profiles + volatile_profiles

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
    # Create a mutually exclusive group, such that only one of the output options can be used
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("-o", "--output", default=Path("."), type=Path, help="output directory")
    output_group.add_argument("-of", "--output-file", type=Path, help="output filename")

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
        "--targetd",
        action="store_true",
        help="setup and install targetd agent",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="encrypt output (if supported by the output type)",
    )
    parser.add_argument(
        "--gui",
        nargs="?",
        const="always",
        default="depends",
        action="store",
        help="launch with a GUI (if available for your platform)",
    )
    parser.add_argument("--public-key", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("-l", "--log", type=Path, help="log directory location")
    parser.add_argument("--no-log", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-p", "--profile", choices=profiles.keys(), help="collection profile")
    parser.add_argument("--volatile-profile", choices=volatile.keys(), help="volatile profile")

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
    parser.add_argument("--skip-parent", action="store_true", help="skip parent collection (when using --children)")

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
        log_path = args.log or args.output or args.output_file.parent

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
        if args.children and args.output_file:
            raise ValueError("--children can not be used with --output_file. Use --output instead")
        elif args.output_file and (not args.output_file.parent.is_dir() or args.output_file.is_dir()):
            raise ValueError("--output_file must be a path to a file in an existing directory")
        elif args.output and not args.output.is_dir():
            raise ValueError(f"Output directory doesn't exist or is a file: {args.output}")

        # check & set encryption related configuration
        if args.encrypt:
            public_key = args.config.get("public_key")
            if not public_key and args.public_key and args.public_key.is_file():
                public_key = args.public_key.read_text()
            if not public_key:
                raise ValueError("No public key available (embedded or argument)")
            setattr(args, "public_key", public_key)

        # set cagent/targetd related configuration
        for attr in CAGENT_TARGETD_ATTRS:
            setattr(args, attr, args.config.get(attr))

    if not args.children and args.skip_parent:
        raise ValueError("--skip-parent can only be set with --children")


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


DEVICE_SUBST = re.compile(r"^(/\?\?/)")
SYSVOL_SUBST = re.compile(r"^/?sysvol(?=/)", flags=re.IGNORECASE)


def normalize_path(target: Target, path: Path, *, resolve: bool = False, lower_case: bool = True) -> str:
    if resolve:
        path = path.resolve()

    path = path.as_posix()

    if target.os == "windows":
        path = DEVICE_SUBST.sub("", path)
        if sysvol_drive := target.props.get("sysvol_drive"):
            path = normalize_sysvol(path, sysvol_drive)

    if not target.fs.case_sensitive and lower_case:
        path = path.lower()

    return path


def normalize_sysvol(path: str, sysvol: str) -> str:
    return SYSVOL_SUBST.sub(sysvol, path)
