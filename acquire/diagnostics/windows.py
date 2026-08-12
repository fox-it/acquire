import ctypes
import getpass
import platform
import socket
import subprocess


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def get_os_info() -> dict:
    info = {}
    info["platform"] = platform.platform()
    info["system"] = platform.system()
    info["release"] = platform.release()
    info["version"] = platform.version()
    info["architecture"] = platform.architecture()
    info["node"] = platform.node()
    info["uname"] = platform.uname()
    return info


def get_user_info() -> dict:
    info = {}
    info["username"] = getpass.getuser()
    info["hostname"] = socket.gethostname()
    return info


def get_drives() -> list[str]:
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if bitmask & 1:
            drives.append(f"{letter}:\\")
        bitmask >>= 1
    return drives


def get_drive_info() -> dict:
    drives = get_drives()
    info = {}
    errors = {}
    for drive in drives:
        total, free = ctypes.c_ulonglong(), ctypes.c_ulonglong()
        try:
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(drive), None, ctypes.byref(total), ctypes.byref(free)
            )
            info[drive] = {"total_GB": total.value // (1024**3), "free_GB": free.value // (1024**3)}
        except Exception as e:
            errors[drive] = f"Error: {e}"
    info.update(errors)
    return info


def get_drive_filesystems() -> dict:
    """Return a dict mapping drive letters to filesystem types using GetVolumeInformationW."""
    filesystems = {}
    drives = get_drives()
    GetVolumeInformationW = ctypes.windll.kernel32.GetVolumeInformationW
    for drive in drives:
        fs_name_buf = ctypes.create_unicode_buffer(255)
        try:
            res = GetVolumeInformationW(
                ctypes.c_wchar_p(drive), None, 0, None, None, None, fs_name_buf, ctypes.sizeof(fs_name_buf)
            )
            if res:
                filesystems[drive] = fs_name_buf.value
            else:
                filesystems[drive] = "Unknown or inaccessible"
        except Exception as e:
            filesystems[drive] = f"Error: {e}"
    return filesystems


def parse_hardware_info(raw_info: dict) -> dict:
    def parse_block(block: str) -> dict:
        result = {}
        for line in block.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                result[key.strip()] = value.strip()
        return result

    parsed = {}
    # Parse CPU info
    cpu_raw = raw_info.get("cpu", "")
    if cpu_raw and not cpu_raw.startswith("Error"):
        cpus = [parse_block(b) for b in cpu_raw.split("\n\n") if b.strip()]
        parsed["cpu"] = cpus
    else:
        parsed["cpu"] = cpu_raw
    # Parse memory info
    mem_raw = raw_info.get("memory", "")
    if mem_raw and not mem_raw.startswith("Error"):
        mems = [parse_block(b) for b in mem_raw.split("\n\n") if b.strip()]
        parsed["memory"] = mems
    else:
        parsed["memory"] = mem_raw
    # Parse baseboard info
    base_raw = raw_info.get("baseboard", "")
    if base_raw and not base_raw.startswith("Error"):
        bases = [parse_block(b) for b in base_raw.split("\n\n") if b.strip()]
        parsed["baseboard"] = bases
    else:
        parsed["baseboard"] = base_raw
    return parsed


def get_hardware_info() -> dict:
    info = {}
    try:
        output = subprocess.check_output(
            [
                "powershell",
                "-Command",
                "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed | Format-List",  # noqa: E501
            ],
            universal_newlines=True,
        )
        info["cpu"] = output.strip()
    except Exception as e:
        info["cpu"] = f"Error: {e}"
    try:
        output = subprocess.check_output(
            [
                "powershell",
                "-Command",
                "Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity,Speed,Manufacturer | Format-List",
            ],
            universal_newlines=True,
        )
        info["memory"] = output.strip()
    except Exception as e:
        info["memory"] = f"Error: {e}"
    try:
        output = subprocess.check_output(
            [
                "powershell",
                "-Command",
                "Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,SerialNumber | Format-List",
            ],
            universal_newlines=True,
        )
        info["baseboard"] = output.strip()
    except Exception as e:
        info["baseboard"] = f"Error: {e}"
    return parse_hardware_info(info)


def parse_software_info(raw_info: dict) -> dict:
    def parse_block(block: str) -> dict:
        result = {}
        for line in block.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                result[key.strip()] = value.strip()
        return result

    parsed = {}
    sw_raw = raw_info.get("installed_software", "")
    if sw_raw and not sw_raw.startswith("Error"):
        sws = [parse_block(b) for b in sw_raw.split("\n\n") if b.strip()]
        parsed["installed_software"] = sws
    else:
        parsed["installed_software"] = sw_raw
    return parsed


def get_software_info() -> dict:
    info = {}
    try:
        output = subprocess.check_output(
            ["powershell", "-Command", "Get-CimInstance Win32_Product | Select-Object Name,Version | Format-List"],
            universal_newlines=True,
            stderr=subprocess.DEVNULL,
        )
        info["installed_software"] = output.strip()
    except Exception as e:
        info["installed_software"] = f"Error: {e}"
    return parse_software_info(info)


def diagnostics_info() -> dict:
    info = {}
    info["running_as_admin"] = is_admin()
    info["os_info"] = get_os_info()
    info["user_info"] = get_user_info()
    info["drive_info"] = get_drive_info()
    info["drive_filesystems"] = get_drive_filesystems()
    info["hardware_info"] = get_hardware_info()
    info["software_info"] = get_software_info()
    return info
