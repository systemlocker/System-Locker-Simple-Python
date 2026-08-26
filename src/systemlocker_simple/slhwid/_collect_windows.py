"""Windows §4A.1 factor collection: native registry reads, environment,
ctypes for the memory total, and best-effort wmic for disk serials. Every
source degrades gracefully — a missing source just leaves the slot absent,
which the threshold scheme absorbs."""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
import sys
import uuid
import winreg

_DISPLAY_CLASS_GUID = "{4d36e968-e325-11ce-bfc1-08002be10318}"


def _reg_value(path: str, name: str):
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            value, _ = winreg.QueryValueEx(key, name)
        return value
    except OSError:
        return None


def _reg_subkeys(path: str) -> list[str]:
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            return [winreg.EnumKey(key, i) for i in range(winreg.QueryInfoKey(key)[0])]
    except OSError:
        return []


def _run(command: list[str], timeout: float = 4.0) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def _mac_address() -> str:
    node = uuid.getnode()
    if (node >> 40) & 1 or node == 0:
        return ""
    return ":".join(f"{(node >> shift) & 0xFF:02x}" for shift in (40, 32, 24, 16, 8, 0))


def _ram_total() -> str:
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return str(status.ullTotalPhys)
    return ""


def _volume_serial() -> str:
    drive = os.environ.get("SystemDrive", "C:")
    output = _run(["cmd", "/c", "vol", drive])
    matches = re.findall(r"([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})", output)
    return matches[-1] if matches else ""


def _multi_instance(values: list[str]) -> str:
    cleaned = sorted(v for v in values if v)
    return "|".join(cleaned)


def _schema_v2_factors() -> dict[str, str]:
    """Collect optional SMBIOS/peripheral identities through CIM.

    WMIC is deprecated, so the v2-only data deliberately uses PowerShell's
    CIM cmdlets. A missing cmdlet, permission, or device simply omits the
    signal; collectors must never turn an optional identity into a failure.
    """
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "function Emit($n,$v){$c=@($v|?{$_ -ne $null -and ([string]$_).Trim().Length -gt 0}|"
        "%{([string]$_).Trim()}|sort);if($c.Count -gt 0){Write-Output ($n+'='+($c -join '|'))}};"
        "$p=Get-CimInstance Win32_ComputerSystemProduct;Emit 'system_uuid' $p.UUID;"
        "Emit 'system_serial' $p.IdentifyingNumber;"
        "Emit 'chassis_serial' (Get-CimInstance Win32_SystemEnclosure).SerialNumber;"
        "Emit 'disk_serial' (Get-CimInstance Win32_DiskDrive).SerialNumber;"
        "Emit 'memory_modules' (Get-CimInstance Win32_PhysicalMemory).SerialNumber;"
        "Emit 'nic_identity' (Get-CimInstance Win32_NetworkAdapter|?{$_.PhysicalAdapter}).PermanentAddress;"
        "Emit 'battery_serial' (Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData).SerialNumber;"
        "$ek=Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256;if($ek.IsPresent){Emit 'tpm_ek' $ek.PublicKeyHash}"
    )
    factors: dict[str, str] = {}
    for line in _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], 12.0).splitlines():
        name, separator, value = line.partition("=")
        if separator and name and value:
            factors[name] = value
    return factors


def collect() -> dict[str, str]:
    factors: dict[str, str] = {}

    machine_guid = _reg_value(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid")
    if machine_guid:
        factors["machine_guid"] = str(machine_guid)

    hardware_id = _reg_value(r"SYSTEM\CurrentControlSet\Control\SystemInformation", "ComputerHardwareId")
    if hardware_id:
        factors["product_uuid"] = str(hardware_id).strip("{}")

    board = _reg_value(r"HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardSerialNumber")
    if board is not None:
        factors["board_serial"] = str(board)

    firmware_parts: list[str] = []
    system_bios = _reg_value(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemBiosVersion")
    if system_bios is not None:
        firmware_parts.append(str(system_bios))
    bios_version = _reg_value(r"HARDWARE\DESCRIPTION\System\BIOS", "BIOSVersion")
    if bios_version is not None:
        parts = bios_version if isinstance(bios_version, list) else [bios_version]
        firmware_parts.extend(str(p) for p in parts)
    if joined := _multi_instance(firmware_parts):
        factors["firmware"] = joined

    cpu_id = _reg_value(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "Identifier")
    if cpu_id:
        factors["cpu_id"] = str(cpu_id)

    if name := os.environ.get("COMPUTERNAME", ""):
        factors["computer_name"] = name

    build = _reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber")
    ubr = _reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR")
    if build is not None and ubr is not None:
        factors["os_build"] = f"{build}-{ubr}"

    descs = []
    for subkey in _reg_subkeys(rf"SYSTEM\CurrentControlSet\Control\Class\{_DISPLAY_CLASS_GUID}"):
        value = _reg_value(
            rf"SYSTEM\CurrentControlSet\Control\Class\{_DISPLAY_CLASS_GUID}\{subkey}", "DriverDesc"
        )
        if value:
            descs.append(str(value))
    if joined := _multi_instance(descs):
        factors["gpu_id"] = joined

    blobs = []
    display_path = r"SYSTEM\CurrentControlSet\Enum\DISPLAY"
    for adapter in _reg_subkeys(display_path):
        for instance in _reg_subkeys(rf"{display_path}\{adapter}"):
            value = _reg_value(
                rf"{display_path}\{adapter}\{instance}\Device Parameters", "EDID"
            )
            if value:
                blobs.append(bytes(value).hex())
    if joined := _multi_instance(blobs):
        factors["monitor_edid"] = joined

    serials = [
        line.strip()
        for line in _run(["wmic", "diskdrive", "get", "SerialNumber"]).splitlines()
        if line.strip() and line.strip().lower() != "serialnumber"
    ]
    if joined := _multi_instance(serials):
        factors["disk_serial"] = joined

    if total := _ram_total():
        factors["ram_total"] = total

    if serial := _volume_serial():
        factors["volume_id"] = serial

    if mac := _mac_address():
        factors["mac"] = mac

    # Keep v1 collection above unchanged. These are raw signals for the v2
    # projector and still leave the legacy names available for v1 recovery.
    for name, value in _schema_v2_factors().items():
        # A v1 helper's disk serial must retain the legacy collector's exact
        # value. New-only signals can be added without changing that view.
        factors.setdefault(name, value)

    return factors
