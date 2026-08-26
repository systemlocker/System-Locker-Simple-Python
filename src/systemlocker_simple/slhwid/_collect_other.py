"""Unsupported-platform collection: fails closed. The module needs real
hardware factors, and a software-only fallback would weaken it."""

from __future__ import annotations


def collect() -> dict[str, str]:
    raise RuntimeError("slhwid: secret-sharing HWID is not supported on this platform")
