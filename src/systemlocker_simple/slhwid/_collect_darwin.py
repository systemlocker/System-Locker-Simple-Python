"""macOS §4A.1 factor collection through the system command-line tools.
Every source degrades gracefully; slow tools (system_profiler) run under a
hard timeout and simply leave their slot absent when they miss it."""

from __future__ import annotations

import re
import subprocess
import sys


def _run(command: list[str], timeout: float = 3.0) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def _first(pattern: str, text: str) -> str:
    match = re.search(pattern, text)
    return match.group(1) if match else ""


def _all(pattern: str, text: str) -> list[str]:
    return [m.group(1) for m in re.finditer(pattern, text)]


def collect() -> dict[str, str]:
    factors: dict[str, str] = {}

    expert = _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
    if value := _first(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', expert):
        factors["machine_guid"] = value
    if value := _first(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', expert):
        factors["board_serial"] = value
        factors["system_serial"] = value

    brand = _run(["sysctl", "-n", "machdep.cpu.brand_string"]).strip()
    if not brand:
        brand = _run(["sysctl", "-n", "hw.model"]).strip()
    cores = _run(["sysctl", "-n", "hw.physicalcpu"]).strip()
    if brand and cores:
        factors["cpu_id"] = f"{brand}-{cores}"

    if value := _first(r"ether\s+([0-9a-fA-F:]{17})", _run(["ifconfig", "en0"])):
        factors["mac"] = value
    if values := _all(r"Ethernet Address:\s*([0-9a-fA-F:]{17})", _run(["networksetup", "-listallhardwareports"])):
        factors["nic_identity"] = "|".join(sorted(values))

    if total := _run(["sysctl", "-n", "hw.memsize"]).strip():
        factors["ram_total"] = total

    if value := _first(
        r"<key>VolumeUUID</key>\s*<string>([^<]+)</string>", _run(["diskutil", "info", "-plist", "/"])
    ):
        factors["volume_id"] = value

    if name := _run(["scutil", "--get", "ComputerName"]).strip():
        factors["computer_name"] = name
    elif name := _run(["scutil", "--get", "LocalHostName"]).strip():
        factors["computer_name"] = name

    hardware = _run(["system_profiler", "SPHardwareDataType", "-json"], timeout=5.0)
    if value := _first(r'"spmachine_bootrom_version"\s*:\s*"([^"]+)"', hardware):
        factors["firmware"] = value

    memory = _run(["system_profiler", "SPMemoryDataType", "-json"], timeout=5.0)
    if serials := _all(r'"[^"]*serial[^"]*"\s*:\s*"([^"]+)"', memory):
        factors["memory_modules"] = "|".join(sorted(serials))

    battery = _run(["ioreg", "-r", "-c", "AppleSmartBattery"])
    if value := _first(r'"BatterySerialNumber"\s*=\s*"([^"]+)"', battery):
        factors["battery_serial"] = value
    elif value := _first(r'"Serial"\s*=\s*"?([^"\n]+)"?', battery):
        factors["battery_serial"] = value

    displays = _run(["system_profiler", "SPDisplaysDataType", "-json"], timeout=5.0)
    if models := _all(r'"spdisplays_model"\s*:\s*"([^"]+)"', displays):
        factors["gpu_id"] = "|".join(sorted(models))

    storage = _run(["system_profiler", "SPStorageDataType", "-json"], timeout=5.0)
    if serials := _all(r'"[a-z_]*serial[a-z_]*"\s*:\s*"([^"]+)"', storage):
        factors["disk_serial"] = "|".join(sorted(serials))

    displays_io = _run(["ioreg", "-r", "-c", "IODisplayConnect"])
    if blobs := _all(r'"IODisplayEDID"\s*=\s*<?([0-9a-fA-F]+)>?', displays_io):
        factors["monitor_edid"] = "|".join(sorted(b.lower() for b in blobs))

    version = _run(["sw_vers", "-productVersion"]).strip()
    build = _run(["sw_vers", "-buildVersion"]).strip()
    if version and build:
        factors["os_build"] = f"{version}-{build}"

    if not factors:
        raise RuntimeError("slhwid: no hardware factors available on this machine")
    return factors
