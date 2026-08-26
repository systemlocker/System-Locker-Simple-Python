"""Linux §4A.1 factor collection: the legacy slots reuse the shared hwid
collectors and the extended slots come from procfs, os-release, findmnt, and
DRM EDID files."""

from __future__ import annotations

import glob
import hashlib
import os
import re
import subprocess
import sys


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _read(path: str, binary: bool = False):
    try:
        if binary:
            with open(path, "rb") as source:
                return source.read()
        with open(path, encoding="utf-8", errors="replace") as source:
            value = source.read()
    except OSError:
        return b"" if binary else ""
    return value.strip()


def _multi_instance(values: list[str]) -> str:
    return "|".join(sorted(value for value in values if value))


def collect() -> dict[str, str]:
    from ..hwid._linux import collect as legacy_collect

    factors: dict[str, str] = {}
    try:
        factors.update(legacy_collect())
    except Exception:
        pass  # degrade: the legacy collector fails closed on machine_guid

    if host := os.uname().nodename:
        factors["computer_name"] = host

    try:
        meminfo = open("/proc/meminfo", encoding="ascii").read()
    except OSError:
        meminfo = ""
    if match := re.search(r"MemTotal:\s+(\d+)\s+kB", meminfo):
        factors["ram_total"] = str(int(match.group(1)) * 1024)

    if uuid_value := _run(["findmnt", "-no", "UUID", "/"]):
        factors["volume_id"] = uuid_value

    for slot, path in (
        ("firmware", "/sys/class/dmi/id/bios_version"),
        ("machine_guid", "/etc/machine-id"),
        ("board_serial", "/sys/class/dmi/id/board_serial"),
    ):
        try:
            value = open(path, encoding="ascii", errors="replace").read().strip()
        except OSError:
            continue
        if value and slot not in factors:
            factors[slot] = value

    # Schema-v2 raw signals. The legacy factor names collected above remain
    # untouched because a v1 helper must be recovered from its original view.
    for slot, path in (
        ("system_uuid", "/sys/class/dmi/id/product_uuid"),
        ("system_serial", "/sys/class/dmi/id/product_serial"),
        ("chassis_serial", "/sys/class/dmi/id/chassis_serial"),
    ):
        if value := _read(path):
            factors[slot] = value

    if serials := re.findall(r"(?mi)^\s*Serial Number:\s*(\S.*)$", _run(["dmidecode", "--type", "memory"])):
        factors["memory_modules"] = _multi_instance(serials)

    nic_identities = []
    for device_path in sorted(glob.glob("/sys/class/net/*/device")):
        if value := _read(os.path.join(os.path.dirname(device_path), "perm_address")):
            if value != "00:00:00:00:00:00":
                nic_identities.append(value)
    if value := _multi_instance(nic_identities):
        factors["nic_identity"] = value

    batteries = []
    for battery_path in sorted(glob.glob("/sys/class/power_supply/BAT*/serial_number")):
        if value := _read(battery_path):
            batteries.append(value)
    if value := _multi_instance(batteries):
        factors["battery_serial"] = value

    for path in ("/sys/class/tpm/tpm0/device/ek_pub", "/sys/class/tpm/tpm0/ek_pub"):
        if value := _read(path, binary=True):
            factors["tpm_ek"] = hashlib.sha256(value).hexdigest()
            break

    try:
        os_release = open("/etc/os-release", encoding="utf-8").read()
    except OSError:
        os_release = ""
    if match := re.search(r'(?m)^PRETTY_NAME="?([^"\n]+)"?', os_release):
        factors["os_build"] = match.group(1)

    blobs = []
    for path in sorted(glob.glob("/sys/class/drm/card*-*/edid")):
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        if data:
            blobs.append(data.hex())
    if blobs:
        factors["monitor_edid"] = "|".join(sorted(blobs))

    gpus = []
    for class_path in sorted(glob.glob("/sys/bus/pci/devices/*/class")):
        try:
            klass = open(class_path, encoding="ascii").read().strip()
        except OSError:
            continue
        if not klass.startswith("0x03"):
            continue
        base = os.path.dirname(class_path)
        try:
            vendor = open(os.path.join(base, "vendor"), encoding="ascii").read().strip()
            device = open(os.path.join(base, "device"), encoding="ascii").read().strip()
        except OSError:
            continue
        gpus.append(f"{vendor}:{device}")
    if gpus:
        factors["gpu_id"] = "|".join(sorted(gpus))

    return factors
