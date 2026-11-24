"""The stateless Simple client and its management sub-API."""

from __future__ import annotations

import json
import threading
from urllib.parse import quote
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
    user_agent: str = "systemlocker-simple-python/2.0.0"
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
    """Wraps the Management API v2 (``/api/v2``).

    Independent of the authentication protocol and meant for server-side
    tooling. ``api_key`` must hold a scoped v2 bearer credential for this
    system; treat it as a secret and keep it on servers you control.
    """

    # Duration in seconds for each expiry preset. "0" (permanent) is never
    # sent as a duration.
    _PRESET_SECONDS = {"0": 0, "1": 86400, "2": 604800, "3": 2592000, "4": 7776000, "5": 31536000}

    def __init__(self, client: "Client") -> None:
        self._client = client

    @property
    def system_path(self) -> str:
        return "/systems/" + quote(self._client.config.system_id, safe="")

    def key_path(self, license_key: str) -> str:
        return self.system_path + "/keys/" + quote(license_key, safe="")

    @staticmethod
    def _field(data, name, valid):
        # A missing field and an invalid value are both protocol errors
        # rather than silent defaults.
        if not isinstance(data, dict) or name not in data or not valid(data[name]):
            raise SimpleError(ErrorKind.TRANSPORT, f"invalid management field: {name}")
        return data[name]

    @staticmethod
    def _strings(value) -> bool:
        return isinstance(value, list) and all(isinstance(item, str) for item in value)

    @staticmethod
    def _nullable_string(value) -> bool:
        return value is None or isinstance(value, str)

    def request(self, method: str, path: str, data=None):
        """Call any v2 resource path and return the response's decoded ``data``.

        ``path`` is relative to ``/api/v2`` (for example ``/permissions`` or
        ``/systems/{id}/nightflyer``). POST/PUT/PATCH without ``data`` send an
        empty JSON object. A non-2xx response raises ``SimpleError`` whose
        ``reason`` is the server's error code (for example
        ``INSUFFICIENT_SCOPE``). Mutations are never retried.
        """
        credential = self._client.config.api_key
        if not credential or "\r" in credential or "\n" in credential:
            raise SimpleError(ErrorKind.CONFIGURATION, "a management bearer credential is required")
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"} or not isinstance(path, str) \
                or not path.startswith("/") or path.startswith("//") or "#" in path:
            raise SimpleError(ErrorKind.CONFIGURATION, "invalid management method or resource path")
        # Custom transports written before v2 may only implement post_form/get.
        request_json = getattr(self._client.http, "request_json", None)
        if not callable(request_json):
            raise SimpleError(ErrorKind.CONFIGURATION, "HTTP client must implement request_json for management")
        # The server requires a JSON Content-Type on every mutation, even one
        # without fields.
        if data is None and method in {"POST", "PUT", "PATCH"}:
            data = {}
        response = request_json(
            method, self._client.endpoint("/api/v2" + path),
            data, {"Authorization": "Bearer " + credential, "Accept": "application/json"},
        )
        if response.error:
            raise SimpleError(ErrorKind.TRANSPORT, response.error)
        try:
            payload = json.loads(response.body)
        except (ValueError, TypeError) as error:
            raise SimpleError(ErrorKind.TRANSPORT, f"management returned invalid JSON (HTTP {response.status})") from error
        if not response.ok():
            detail = payload.get("error") if isinstance(payload, dict) else None
            detail = detail if isinstance(detail, dict) else {}
            message = detail.get("message")
            code = detail.get("code")
            raise SimpleError(
                ErrorKind.TRANSPORT,
                message if isinstance(message, str) and message else f"management HTTP {response.status}",
                code if isinstance(code, str) else "",
            )
        if not isinstance(payload, dict) or "data" not in payload:
            raise SimpleError(ErrorKind.UNKNOWN_REASON, "management response is missing data")
        return payload["data"]

    def permissions(self) -> list[str]:
        """Scopes granted to the configured credential. Requires no scope."""
        return self._field(self.request("GET", "/permissions"), "scopes", self._strings)

    def redeemed_user_count(self) -> int:
        """The system's user count (accounts plus key-only redemptions).

        The server refreshes it periodically, so it can lag behind recent
        redemptions. Requires ``systems.read``.
        """
        return self._field(self.request("GET", self.system_path + "/statistics"), "total_users",
                           lambda value: type(value) is int and value >= 0)

    def key_status(self, license_key: str) -> str:
        """How a key is claimed: ``user`` (attached to an account), ``mikros``
        (redeemed without an account) or ``unclaimed``. Requires ``keys.read``."""
        return self._field(self.request("GET", self.key_path(license_key)), "claim_type",
                           lambda value: isinstance(value, str))

    def key_expiration(self, license_key: str) -> Expiration:
        """A key's expiry.

        ``expires_at`` is an RFC 3339 UTC timestamp, or empty when the key has
        no fixed expiry. ``permanent`` is only reported for redeemed keys: an
        unredeemed duration key has no timestamp yet either. Requires
        ``keys.read``.
        """
        data = self.request("GET", self.key_path(license_key))
        expiry = self._field(data, "expires_at", self._nullable_string)
        redeemed = self._field(data, "redeemed_at", self._nullable_string)
        return Expiration(permanent=expiry is None and redeemed is not None, expires_at=expiry or "")

    def reset_hwid(self, license_key: str) -> str:
        """Administrative HWID reset of one key (no cooldown).

        Returns the key's details as JSON text. Self-service resets use
        ``Client.reset_hwid_for_key``. Requires ``keys.update``.
        """
        return json.dumps(self.request("POST", self.key_path(license_key) + "/hwid-reset"))

    def reset_all_hwids(self) -> str:
        """Resets every key's HWID; returns ``{"updated": count}`` as JSON text.
        Use with care. Requires ``keys.update``."""
        return json.dumps(self.request("POST", self.system_path + "/keys/hwid-reset"))

    def generate_keys(self, expiry: str, count: int, note: str = "") -> str:
        """Generates ``count`` (1–100) keys; returns them one per line.

        ``expiry`` is an ``EXPIRY_*`` preset; duration presets start at
        redemption. ``note`` is at most 250 characters. Requires
        ``keys.create``.
        """
        if type(count) is not int or not 1 <= count <= 100:
            raise SimpleError(ErrorKind.CONFIGURATION, "count must be in [1, 100]")
        if len(note) > 250:
            raise SimpleError(ErrorKind.CONFIGURATION, "note must be at most 250 characters")
        if expiry not in self._PRESET_SECONDS:
            raise SimpleError(ErrorKind.CONFIGURATION, "invalid expiry preset")
        seconds = self._PRESET_SECONDS[expiry]
        policy = {"type": "after_redemption", "seconds": seconds} if seconds else {"type": "perpetual"}
        data = self.request("POST", self.system_path + "/keys", {"count": count, "notes": note, "expiry": policy})
        return "\n".join(self._field(data, "keys", self._strings))

    def ban_key(self, license_key: str) -> str:
        """Permanently deletes a key; returns ``{"deleted": true}`` as JSON text.
        Requires ``keys.delete``."""
        return json.dumps(self.request("DELETE", self.key_path(license_key)))

    def add_time(self, license_key: str, seconds: int) -> str:
        """Extends a key's expiry by a positive number of seconds.

        Returns the key's details as JSON text. Replaces the retired
        absolute-expiry adjustment, which has no v2 equivalent. Requires
        ``keys.update``.
        """
        if type(seconds) is not int or seconds <= 0:
            raise SimpleError(ErrorKind.CONFIGURATION, "seconds must be a positive integer")
        return json.dumps(self.request("POST", self.key_path(license_key) + "/time", {"seconds": seconds}))


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
