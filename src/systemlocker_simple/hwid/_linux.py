"""Linux hardware factor collection: sysfs, /proc, and netlink-free MACs."""

from __future__ import annotations

from pathlib import Path

_VIRTUAL_PREFIXES = ("veth", "docker", "br-", "tun", "tap", "tailscale", "zt", "wg", "lo", "virbr")


def _read_trimmed(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _cpu_serial() -> str:
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == "Serial":
            return value.strip()
    return ""


def _disk_serial() -> str:
    try:
        entries = sorted(Path("/sys/block").iterdir())
    except OSError:
        return ""
    for entry in entries:
        name = entry.name
        if name.startswith(("loop", "ram", "dm-")):
            continue
        for candidate in (entry / "device" / "ident", entry / "device" / "serial", entry / "serial"):
            serial = _read_trimmed(str(candidate))
            if serial != "":
                return serial
    return ""


def _mac_address() -> str:
    import fcntl
    import socket
    import struct

    for name in socket.if_nameindex()[1:]:  # skip loopback (index 1 on Linux)
        interface_name = name[1]
        if interface_name.startswith(_VIRTUAL_PREFIXES):
            continue
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                mac = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack("256s", interface_name[:15].encode()))[18:24]
            finally:
                sock.close()
            if len(mac) == 6 and any(mac):
                return ":".join(f"{byte:02x}" for byte in mac)
        except OSError:
            continue
    return ""


def collect() -> dict[str, str]:
    """Collects Linux factors. /etc/machine-id fails closed; the rest degrade."""
    machine_id = _read_trimmed("/etc/machine-id")
    if machine_id == "":
        machine_id = _read_trimmed("/var/lib/dbus/machine-id")
    if machine_id == "":
        raise RuntimeError("hwid: /etc/machine-id unavailable")

    factors: dict[str, str] = {"machine_guid": machine_id}
    product_uuid = _read_trimmed("/sys/class/dmi/id/product_uuid")
    if product_uuid != "":
        factors["product_uuid"] = product_uuid
    board_serial = _read_trimmed("/sys/class/dmi/id/board_serial")
    if board_serial != "":
        factors["board_serial"] = board_serial
    cpu_id = _cpu_serial()
    if cpu_id != "":
        factors["cpu_id"] = cpu_id
    disk_serial = _disk_serial()
    if disk_serial != "":
        factors["disk_serial"] = disk_serial
    mac = _mac_address()
    if mac != "":
        factors["mac"] = mac
    return factors


def device_hwid() -> str:
    from .core import compose

    return compose(collect())
