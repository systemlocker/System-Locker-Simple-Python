"""Windows hardware factor collection: registry reads + a MAC heuristic."""

from __future__ import annotations

import subprocess
import sys
import uuid


def _registry_value(path: str, name: str) -> str:
    try:
        result = subprocess.run(
            ["reg", "query", path, "/v", name],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    for line in result.stdout.splitlines():
        fields = line.split()
        for index in range(1, len(fields) - 1):
            if fields[index].upper() == "REG_SZ":
                return " ".join(fields[index + 1 :])
    return ""


def _mac_address() -> str:
    """First NIC MAC via uuid.getnode().

    getnode() returns a random value with the multicast bit set when no
    hardware address can be found; that bit never fires for real NICs, so
    we treat it as "no MAC" and degrade gracefully.
    """
    node = uuid.getnode()
    if (node >> 40) & 1 or node == 0:
        return ""
    return ":".join(f"{(node >> shift) & 0xFF:02x}" for shift in (40, 32, 24, 16, 8, 0))


def collect() -> dict[str, str]:
    """Collects Windows factors. machine_guid fails closed; the rest degrade."""
    machine_guid = _registry_value(r"HKLM\SOFTWARE\Microsoft\Cryptography", "MachineGuid")
    if machine_guid == "":
        raise RuntimeError("hwid: machine GUID unavailable")

    factors: dict[str, str] = {"machine_guid": machine_guid}
    hardware_id = _registry_value(r"HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation", "ComputerHardwareId")
    if hardware_id != "":
        factors["product_uuid"] = hardware_id.strip("{}")
    board_serial = _registry_value(r"HKLM\HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardSerialNumber")
    if board_serial != "":
        factors["board_serial"] = board_serial
    cpu_id = _registry_value(r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0", "Identifier")
    if cpu_id != "":
        factors["cpu_id"] = cpu_id
    mac = _mac_address()
    if mac != "":
        factors["mac"] = mac
    return factors


def device_hwid() -> str:
    from .core import compose

    return compose(collect())
