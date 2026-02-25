import json
import os
import platform
import stat
import subprocess
from pathlib import Path


def check_sudo() -> bool:
    return os.geteuid() == 0


def get_disk_info() -> dict:
    info = {}
    # RAID
    try:
        with Path("/proc/mdstat").open() as f:
            info["raid"] = f.read()
    except Exception as e:
        info["raid"] = f"Error: {e}"
    # LVM: Distinguish logical volumes and backing devices
    logical_volumes = []
    backing_devices = []
    lvm_error = None
    try:
        # Get logical volumes
        try:
            lvs_result = subprocess.run(
                ["lvs", "--noheadings", "-o", "lv_path"], capture_output=True, text=True, check=False
            )
            if lvs_result.returncode == 0:
                logical_volumes = [line.strip() for line in lvs_result.stdout.splitlines() if line.strip()]
            else:
                lvm_error = f"lvs failed: {lvs_result.stderr.strip()}"
        except FileNotFoundError:
            lvm_error = "lvs not found"
        # Get backing devices
        try:
            pvs_result = subprocess.run(
                ["pvs", "--noheadings", "-o", "pv_name"], capture_output=True, text=True, check=False
            )
            if pvs_result.returncode == 0:
                backing_devices = [line.strip() for line in pvs_result.stdout.splitlines() if line.strip()]
            else:
                lvm_error = (lvm_error or "") + f"; pvs failed: {pvs_result.stderr.strip()}"
        except FileNotFoundError:
            lvm_error = (lvm_error or "") + "; pvs not found"
    except Exception as e:
        lvm_error = f"Error: {e}"
    info["lvm"] = {
        "logical_volumes": logical_volumes,
        "backing_devices": backing_devices,
        "error": lvm_error,
    }

    luks_devices = []
    # Check /dev/mapper for dm-crypt devices
    try:
        luks_devices.extend(
            [
                Path("/dev/mapper") / entry.name
                for entry in Path("/dev/mapper").iterdir()
                if entry.name.startswith(("dm_crypt", "crypt"))
            ]
        )
    except Exception as e:
        luks_devices.append(f"Error: {e}")
    # Parse /etc/crypttab for configured LUKS devices
    try:
        if Path("/etc/crypttab").exists():
            with Path("/etc/crypttab").open() as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) > 1:
                            luks_devices.append(parts[1])
    except Exception as e:
        luks_devices.append(f"Error: {e}")
    info["luks"] = luks_devices
    return info


def walk_dev() -> list[str]:
    dev_tree = []
    for root, _, files in os.walk("/dev"):
        for name in files:
            dev_path = str(Path(root) / name)
            info = {"path": dev_path}
            try:
                st = Path.stat(dev_path)
                if stat.S_ISBLK(st.st_mode):
                    info["type"] = "block"
                elif stat.S_ISCHR(st.st_mode):
                    info["type"] = "char"
                else:
                    info["type"] = "other"
                info["major"] = os.major(st.st_rdev)
                info["minor"] = os.minor(st.st_rdev)
                info["mode"] = oct(st.st_mode)
                info["owner"] = st.st_uid
                info["group"] = st.st_gid
                if info["type"] == "block":
                    try:
                        blkid = subprocess.run(["blkid", dev_path], capture_output=True, text=True)
                        blkid_str = blkid.stdout.strip()
                        info["blkid"] = parse_blkid_output(blkid_str) if blkid_str else None
                    except Exception:
                        info["blkid"] = None
            except Exception as e:
                info["error"] = str(e)
            dev_tree.append(info)
    return dev_tree


def get_dmesg() -> list[str]:
    try:
        with os.popen("dmesg | tail -n 100") as f:
            return f.read().splitlines()
    except Exception as e:
        return [f"Error: {e}"]


def get_hardware_info() -> dict:
    info = {}
    # CPU
    try:
        with Path("/proc/cpuinfo").open() as f:
            cpuinfo_raw = f.read()
        # Parse into list of dicts (one per processor)
        cpu_blocks = cpuinfo_raw.strip().split("\n\n")
        cpuinfo = []
        for block in cpu_blocks:
            cpu = parse_key_value_lines(block.splitlines())
            if cpu:
                cpuinfo.append(cpu)
        info["cpuinfo"] = cpuinfo
    except Exception as e:
        info["cpuinfo"] = {"error": str(e)}
    # Memory
    try:
        with Path("/proc/meminfo").open() as f:
            meminfo_raw = f.read()
        meminfo = parse_key_value_lines(meminfo_raw.splitlines())
        info["meminfo"] = meminfo
    except Exception as e:
        info["meminfo"] = {"error": str(e)}
    # DMI
    dmi_path = Path("/sys/class/dmi/id/")
    dmi_info = {}
    if dmi_path.is_dir():
        for fpath in dmi_path.iterdir():
            if fpath.is_file() and os.access(fpath, os.R_OK):
                with fpath.open() as f:
                    dmi_info[fpath.name] = f.read().strip()
    info["dmi"] = dmi_info
    return info


def get_os_info() -> dict:
    info = {}
    try:
        with Path("/etc/os-release").open() as f:
            info["os-release"] = f.read()
    except Exception as e:
        info["os-release"] = f"Error: {e}"
    info["platform"] = platform.platform()
    info["uname"] = platform.uname()
    return info


def diagnostics_info() -> dict:
    info = {}
    info["running_as_root"] = check_sudo()
    info["disk_info"] = get_disk_info()
    devs = walk_dev()
    info["devices"] = devs
    info["dmesg"] = get_dmesg()
    info["hardware_info"] = get_hardware_info()
    info["os_info"] = get_os_info()
    return info


def diagnostics_info_json(output: Path) -> None:
    data = diagnostics_info()
    with output.open("w") as f:
        json.dump(data, f, default=str, indent=2)


def parse_key_value_lines(lines: list[str]) -> dict[str, str]:
    dev_tree = []
    for root, _, files in os.walk("/dev"):
        for name in files:
            path_obj = Path(root) / name
            dev_path = str(path_obj)
            info = {"path": dev_path}
            try:
                st = path_obj.stat()
                if stat.S_ISBLK(st.st_mode):
                    info["type"] = "block"
                elif stat.S_ISCHR(st.st_mode):
                    info["type"] = "char"
                else:
                    info["type"] = "other"
                info["major"] = os.major(st.st_rdev)
                info["minor"] = os.minor(st.st_rdev)
                info["mode"] = oct(st.st_mode)
                info["owner"] = st.st_uid
                info["group"] = st.st_gid
                if info["type"] == "block":
                    try:
                        blkid = subprocess.run(["blkid", dev_path], capture_output=True, text=True)
                        info["blkid"] = blkid.stdout.strip()
                    except Exception:
                        info["blkid"] = None
            except Exception as e:
                info["error"] = str(e)
            dev_tree.append(info)
    return dev_tree


def parse_blkid_output(blkid_str: str) -> dict:
    """Parse blkid output string into a dictionary of key-value pairs."""
    # Example: /dev/sda1: UUID="abcd-1234" TYPE="ext4" PARTUUID="efgh-5678"
    parts = blkid_str.split(None, 1)
    blkid_info = {}
    if len(parts) == 2:
        for item in parts[1].split():
            if "=" in item:
                k, v = item.split("=", 1)
                blkid_info[k] = v.strip('"')
    return blkid_info
