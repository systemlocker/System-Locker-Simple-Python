"""Typed errors carrying the server's raw reason string."""

from __future__ import annotations

from enum import Enum


class ErrorKind(str, Enum):
    CONFIGURATION = "Configuration"
    TRANSPORT = "Transport"
    SERVER = "Server"
    DENIED = "Denied"
    SSO = "SSO"
    LOCAL_FAILURE = "LocalFailure"
    UNKNOWN_REASON = "UnknownReason"


KNOWN_DENIED_REASONS = frozenset(
    {
        "no username", "no password", "no key", "no sys", "no hwid", "false",
        "not verified", "bad u/p", "bad key", "bad keys", "frozen", "paused",
        "destitute", "user limit", "hwid banned", "spoofsuspected", "hwid",
        "expired key", "outdated", "digest", "exp err big", "no var",
    }
)


class SimpleError(Exception):
    """Every client operation raises this; ``kind`` categorizes it and
    ``reason`` carries the server's raw reason string ("" for local
    failures)."""

    def __init__(self, kind: ErrorKind, message: str, reason: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.reason = reason


def classify(reason: str) -> SimpleError:
    if reason == "dbe":
        return SimpleError(ErrorKind.SERVER, "The server reported an internal error.", reason)
    for stage in ("ssowrong", "ssoexp", "sso"):
        if reason == stage or reason.startswith(stage + " "):
            guidance = {
                "sso": "This account requires a Google SSO token; visit the link to create one.",
                "ssoexp": "The Google SSO token expired; visit the link to renew it.",
                "ssowrong": "The supplied password is not the Google SSO token; visit the link.",
            }[stage]
            return SimpleError(ErrorKind.SSO, f"{guidance} Portal: {sso_link_from_reason(reason)}", reason)
    if reason in KNOWN_DENIED_REASONS:
        return SimpleError(ErrorKind.DENIED, f"The request was rejected: {reason}.", reason)
    return SimpleError(ErrorKind.UNKNOWN_REASON, f"The server returned an unrecognized failure: {reason}", reason)


def sso_link_from_reason(reason: str) -> str:
    _, separator, link = reason.partition(" ")
    return link if separator else ""


def sso_link(error: Exception) -> str:
    """Returns the portal URL from an sso/ssoexp/ssowrong error, or ''."""
    if isinstance(error, SimpleError) and error.kind is ErrorKind.SSO:
        return sso_link_from_reason(error.reason)
    return ""
