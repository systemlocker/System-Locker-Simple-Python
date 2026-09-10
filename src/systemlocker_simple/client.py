"""The stateless Simple client and its management sub-API."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Mapping, Sequence

from .errors import ErrorKind, SimpleError, classify
from .sso import google_sso_url
from .transport import HTTPClient, HTTPResponse

if TYPE_CHECKING:
    from .invisible_folder import InvisibleFolder

AUTH_PATH = "/auth"
VARIABLE_PATH = "/auth/variable"
API_V1_PATH = "/api/v1"


@dataclass
class Config:
    """Configures a Simple Client."""

    system_id: str = ""
    version: str = ""
    hwid: str = ""
    hwid_mode: str = "legacy"
    sl_hwid_store: str = ""
    sl_hwid_extra_mandatory: list[str] | None = None
    request_timeout_seconds: float = 15.0
    base_url: str = "https://systemlocker.net"
    invisible_folder_base_url: str = "https://invisiblefolder.net"
    user_agent: str = "systemlocker-simple-python/1.1.0"
    program_digest: str | None = None
    invisible_folder_api_key: str | None = None
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
        if self.config.hwid_mode not in ("legacy", "sl-hwid"):
            raise SimpleError(ErrorKind.CONFIGURATION, 'HWID mode must be "legacy" or "sl-hwid".')
        # SL-HWID defers derivation to request time: the module enrolls or
        # recovers lazily (and refreshes only after a successful check), so an
        # eager call here would persist state for a client that never
        # authenticates.
        if not self.config.hwid and self.config.hwid_mode != "sl-hwid":
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
        self._invisible_folder: InvisibleFolder | None = None
        self._lock = threading.Lock()
        self._slhwid_session = None

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

    def _prepare_slhwid(self):
        """Recovers (or enrolls) the shared SL-HWID device identity; the
        session is cached for the post-authentication commit."""
        with self._lock:
            if self._slhwid_session is not None:
                return self._slhwid_session
            from .slhwid import Options, prepare as slhwid_prepare

            try:
                session = slhwid_prepare(
                    Options(
                        store_path=self.config.sl_hwid_store,
                        extra_mandatory=self.config.sl_hwid_extra_mandatory or [],
                    )
                )
            except Exception as error:
                raise SimpleError(ErrorKind.LOCAL_FAILURE, f"SL-HWID unavailable: {error}") from error
            self._slhwid_session = session
            return session

    def _commit_slhwid(self) -> None:
        """Re-centers the SL-HWID shares after the server accepted an
        authentication. Best-effort: the next launch re-derives."""
        with self._lock:
            session = self._slhwid_session
        if session is None:
            return
        try:
            session.commit()
        except Exception:
            pass  # non-fatal by design

    def _resolve_hwid(self) -> str:
        """Returns the HWID for outgoing requests. The legacy mode (and any
        explicit value) was already resolved at construction; "sl-hwid"
        enrolls or recovers lazily here, on the first request."""
        if self.config.hwid:
            return self.config.hwid
        return self._prepare_slhwid().hwid

    def base_fields(self) -> dict[str, str]:
        fields = {
            "system": self.config.system_id,
            "version": self.config.version,
            "hwid": self._resolve_hwid(),
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

    def _authenticate(self, fields: dict[str, str]) -> bool:
        body, _ = self.request(AUTH_PATH, fields)
        if body == "true":
            # The server accepted this identity on this device.
            self._commit_slhwid()
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

    def invisible_folder(self) -> "InvisibleFolder":
        """Return the Invisible Folder module (GET downloads and metadata)."""
        with self._lock:
            if self._invisible_folder is None:
                from .invisible_folder import InvisibleFolder
                self._invisible_folder = InvisibleFolder(self)
            return self._invisible_folder
