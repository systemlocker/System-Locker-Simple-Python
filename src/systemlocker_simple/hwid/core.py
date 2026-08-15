"""Shared HWID specification: normalize factors, compose, hash.

Windows and Linux collectors live in ``_windows.py`` / ``_linux.py``.
"""

from __future__ import annotations

import base64
import hashlib

#: Canonical composition order from the specification.
FACTOR_ORDER = ("machine_guid", "product_uuid", "board_serial", "cpu_id", "disk_serial", "mac")

PLACEHOLDERS = frozenset(
    {"", "none", "unknown", "default string", "to be filled by o.e.m.", "not specified", "system serial number"}
)


def normalize(name: str, raw: str) -> str:
    """Trim, lowercase, strip NULs; MACs additionally drop separators."""
    value = raw.replace("\x00", "").strip().lower()
    if name == "mac":
        value = value.replace(":", "").replace("-", "").replace(" ", "")
    return value


def canonical_string(factors: dict[str, str]) -> str:
    parts: list[str] = []
    for name in FACTOR_ORDER:
        if name not in factors:
            continue
        value = normalize(name, factors[name])
        if value == "" or value in PLACEHOLDERS:
            continue
        parts.append(f"factor={name}|value={value}")
    return "&".join(parts)


def from_canonical(canonical: str) -> str:
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def compose(factors: dict[str, str]) -> str:
    return from_canonical(canonical_string(factors))
