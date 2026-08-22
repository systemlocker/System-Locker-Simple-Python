"""The stateless Simple client and its management sub-API."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import IntEnum
from typing import Mapping, Sequence

from .errors import ErrorKind, SimpleError, classify
from .sso import begin_google_sso, google_sso_url
from .transport import HTTPClient, HTTPResponse

AUTH_PATH = "/auth"
VARIABLE_PATH = "/auth/variable"
API_V1_PATH = "/api/v1"


@dataclass
class Config:
    """Configures a Simple Client."""

    system_id: str = ""
    version: str = ""
    hwid: str = ""
    request_timeout_seconds: float = 15.0
    base_url: str = "https://systemlocker.net"
    user_agent: str = "systemlocker-simple-python/0.1"
    program_digest: str | None = None
    api_key: str | None = None


class ResetOutcome(IntEnum):
    GRANTED = 0
    DENIED = 1
    TOO_SOON = 2


@dataclass(frozen=True)
class Expiration:
    permanent: bool
    expires_at: str


@dataclass(frozen=True)
class VariableValue:
    found: bool
    value: str | None


class Management:
    """Wraps POST /api/v1 — server-side tooling; requires ``api_key``."""

    def __init__(self, client: "Client") -> None:
        self._client = client

    def _post(self, fields: Mapping[str, str | Sequence[str]]) -> str:
        if not self._client.config.api_key:
            raise SimpleError(ErrorKind.CONFIGURATION, "management API key not configured")
        merged = dict(fields)
        merged["key"] = self._client.config.api_key
        body, _headers = self._client.request(API_V1_PATH, merged)
        return body

    def redeemed_user_count(self) -> int:
        body = self._post({"select": "users"})
        try:
            return int(body)
        except ValueError as error:
            raise SimpleError(ErrorKind.UNKNOWN_REASON, f"non-numeric users response: {body}", body) from error

    def key_status(self, license_key: str) -> str:
        return self._post({"select": "key", "lkey": license_key})

    def key_expiration(self, license_key: str) -> Expiration:
        body = self._post({"select": "expiration", "lkey": license_key})
        lowered = body.lower()
        return Expiration(permanent=lowered in {"permanent", "never", "0"}, expires_at=body)

    def reset_hwid(self, license_key: str, as_admin: bool = True) -> str:
        fields: dict[str, str] = {"command": "hwidreset", "license": license_key}
        if not as_admin:
            fields["as_admin"] = "false"
        return self._post(fields)

    def reset_all_hwids(self) -> str:
        """Resets the HWID of every key in the system. Use with care."""
        return self._post({"command": "systemhwidreset"})

    def generate_keys(self, expiry: str, count: int, note: str = "") -> str:
        """``expiry`` is an ``ExpiryPreset`` value; count 1–100."""
        if not 1 <= count <= 100:
            raise SimpleError(ErrorKind.CONFIGURATION, "count must be in [1, 100]")
        if len(note) > 250:
            raise SimpleError(ErrorKind.CONFIGURATION, "note must be at most 250 characters")
        fields: dict[str, str] = {"command": "genkeys", "expire": expiry, "count": str(count)}
        if note:
            fields["note"] = note
        return self._post(fields)

    def ban_key(self, license_key: str) -> str:
        return self._post({"command": "bankey", "license": license_key})

    def adjust_expiry(self, license_key: str, new_expiry: str, tz: str) -> str:
        return self._post({"command": "adjustexpiry", "license": license_key, "newexpiry": new_expiry, "tz": tz})


#: Expiry presets accepted by the management API ("0" = permanent).
EXPIRY_PERMANENT = "0"
EXPIRY_ONE_DAY = "1"
EXPIRY_ONE_WEEK = "2"
EXPIRY_ONE_MONTH = "3"
EXPIRY_THREE_MONTHS = "4"
EXPIRY_ONE_YEAR = "5"


class Client:
    """Stateless Simple client: one request, one answer. Thread-safe."""

    def __init__(self, config: Config | None = None, http: HTTPClient | None = None) -> None:
        self.config = config or Config()
        if not self.config.hwid:
            try:
                from .hwid import device_hwid
                self.config.hwid = device_hwid()
            except Exception as error:
                raise SimpleError(ErrorKind.CONFIGURATION, f'Could not derive the default hardware ID: {error}. Supply a custom HWID or use "1" to disable device checks.') from error
        if not self.config.system_id:
            raise SimpleError(ErrorKind.CONFIGURATION, "System ID must not be empty.")
        if not self.config.version:
            raise SimpleError(ErrorKind.CONFIGURATION, "Version must not be empty.")
        if not self.config.base_url.startswith("https://"):
            raise SimpleError(ErrorKind.CONFIGURATION, "Base URL must use HTTPS.")
        self._http = http
        self._management: Management | None = None
        self._lock = threading.Lock()

    @property
    def http(self) -> HTTPClient:
        with self._lock:
            if self._http is None:
                self._http = HTTPClient(
                    timeout_seconds=self.config.request_timeout_seconds,
                    user_agent=self.config.user_agent,
                )
            return self._http

    def endpoint(self, path: str) -> str:
        return self.config.base_url.rstrip("/") + path

    def request(self, path: str, fields: Mapping[str, str | Sequence[str]]) -> tuple[str, dict[str, str]]:
        response = self.http.post_form(self.endpoint(path), fields)
        if not response.ok():
            message = (
                f"request failed: {response.error}"
                if response.error
                else f"server returned HTTP {response.status}: {response.body.strip()}"
            )
            raise SimpleError(ErrorKind.TRANSPORT, message)
        return response.body.strip(), response.headers

    def base_fields(self) -> dict[str, str]:
        fields = {
            "system": self.config.system_id,
            "version": self.config.version,
            "hwid": self.config.hwid,
            "clean": "1",
        }
        if self.config.program_digest:
            fields["digest"] = self.config.program_digest
        return fields

    # ── authentication ─────────────────────────────────────────────

    def authenticate_with_key(self, license_key: str) -> bool:
        return self._authenticate(self.base_fields() | {"key": license_key})

    def authenticate_with_password(self, username: str, password: str) -> bool:
        return self._authenticate(self.base_fields() | {"username": username, "password": password})

    # ── Google SSO ────────────────────────────────────────────────

    def google_sso_url(self) -> str:
        """Return the Google SSO portal URL for the configured system."""
        return google_sso_url(self.config.system_id)

    def begin_google_sso(self) -> tuple[str, bool]:
        """Open the Google SSO portal for the configured system.

        See :func:`systemlocker_simple.sso.begin_google_sso` for the
        ``(url, opened)`` result contract.
        """
        return begin_google_sso(self.config.system_id)

    def _authenticate(self, fields: dict[str, str]) -> bool:
        body, _ = self.request(AUTH_PATH, fields)
        if body == "true":
            return True
        raise classify(body)

    # ── intents ────────────────────────────────────────────────────

    def key_expiration_for_key(self, license_key: str) -> Expiration:
        return self._expiration(self.base_fields() | {"key": license_key})

    def key_expiration_for_password(self, username: str, password: str) -> Expiration:
        return self._expiration(self.base_fields() | {"username": username, "password": password})

    def _expiration(self, fields: dict[str, str]) -> Expiration:
        body, headers = self.request(AUTH_PATH, fields | {"intent": "expiration"})
        if headers.get("auth", "") != "true":
            raise classify(body)
        if body in {"Never", "N/A"}:
            return Expiration(permanent=True, expires_at=body)
        return Expiration(permanent=False, expires_at=body)

    def get_variable(self, name: str, license_key: str = "") -> VariableValue:
        fields = {"system": self.config.system_id, "variable": name, "clean": "1"}
        if license_key:
            fields["key"] = license_key
        body, headers = self.request(VARIABLE_PATH, fields)
        intent = headers.get("intent", "")
        if intent == "true":
            return VariableValue(found=True, value=body)
        if intent == "false":
            return VariableValue(found=False, value=None)
        raise classify(body)

    def reset_hwid_for_key(self, license_key: str) -> ResetOutcome:
        return self._reset_hwid(self.base_fields() | {"key": license_key})

    def reset_hwid_for_password(self, username: str, password: str) -> ResetOutcome:
        return self._reset_hwid(self.base_fields() | {"username": username, "password": password})

    def _reset_hwid(self, fields: dict[str, str]) -> ResetOutcome:
        body, headers = self.request(AUTH_PATH, fields | {"intent": "hwidreset"})
        auth_header = headers.get("auth", "")
        if auth_header not in {"", "true"}:
            raise classify(body)
        intent = headers.get("intent", "")
        if intent in {"true", "1"}:
            return ResetOutcome.GRANTED
        if intent == "toosoon":
            return ResetOutcome.TOO_SOON
        if intent in {"false", ""}:
            if body == "toosoon":
                return ResetOutcome.TOO_SOON
            if body in {"true", "1"}:
                return ResetOutcome.GRANTED
            return ResetOutcome.DENIED
        raise SimpleError(ErrorKind.UNKNOWN_REASON, f"Unexpected hwidreset response: {intent}", intent)

    def management(self) -> Management:
        with self._lock:
            if self._management is None:
                self._management = Management(self)
            return self._management
