"""Hardware-derived device identifiers (shared System Locker HWID spec)."""

from __future__ import annotations

import sys

from .core import FACTOR_ORDER, PLACEHOLDERS, canonical_string, compose, from_canonical, normalize

__all__ = ["FACTOR_ORDER", "PLACEHOLDERS", "canonical_string", "compose", "from_canonical", "normalize", "collect", "device_hwid"]


def collect() -> dict[str, str]:
    """Collects the available hardware factors on this platform.

    machine_guid is required and fails closed; optional factors degrade
    gracefully. Raises RuntimeError on unsupported platforms — supply your
    own HWID through the client configuration instead.
    """
    if sys.platform == "win32":
        from ._windows import collect as collect_windows

        return collect_windows()
    if sys.platform.startswith("linux"):
        from ._linux import collect as collect_linux

        return collect_linux()
    raise RuntimeError("hwid: hardware factor collection is not supported on this platform")


def device_hwid() -> str:
    """Derives the HWID for this machine in one call."""
    return compose(collect())
