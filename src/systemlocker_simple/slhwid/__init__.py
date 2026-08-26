"""Fault-tolerant secret-sharing HWID module.

A random 244-bit key is shared across hardware factors with a threshold
scheme, and the transmitted HWID is a domain-separated hash of that key.
Ordinary hardware drift leaves the HWID unchanged; mandatory slots (by
default the module's own persisted random value) can never be routed
around.

The module is opt-in (see the Client's ``hwid_mode`` configuration) and can
also be driven directly::

    session = slhwid.prepare(slhwid.Options())
    # ... authenticate with session.hwid ...
    session.commit()  # after the server accepted the authentication
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, field

from .core import (
    CorruptHelperError,
    DriftError,
    Draw,
    SsError,
    SLSTORE_PREFIX,
    build_shares,
    check_word,
    CURRENT_NORM_VERSION,
    hwid_of,
    map_mandatory_to_current,
    normalize_factors,
    parse_helper,
    project_factors,
    recover_core,
    refresh_core,
    serialize_helper,
    slot_list,
    threshold,
    urandom_source,
)

__all__ = [
    "Options",
    "Session",
    "prepare",
    "DriftError",
    "CorruptHelperError",
    "SsError",
]

_SLOT_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_DEVICE_HELPER_ID = "device"


@dataclass
class Options:
    """Configuration for one :func:`prepare` call."""

    store_path: str = ""
    extra_mandatory: list[str] = field(default_factory=list)
    force_reenroll: bool = False


class Session:
    """One prepared secret-sharing HWID.

    ``hwid`` is available immediately; :meth:`commit` persists a re-centered
    share set and must only be called after the server accepted the
    authentication that used the hwid.
    """

    def __init__(self, hwid: str, fresh: bool, drifted: list[str], pending: bool) -> None:
        self._hwid = hwid
        self._fresh = fresh
        self._drifted = drifted
        self._pending = pending
        self._committed = False
        self._key = None
        self._draw = None
        self._factors: dict[str, str] = {}
        self._mandatory: set[str] = set()
        self._store = None
        self._expected_helper = b""

    @property
    def hwid(self) -> str:
        """The transmitted device identifier (43 characters, base64url)."""
        return self._hwid

    @property
    def freshly_enrolled(self) -> bool:
        """Whether this session created a key the server has never seen."""
        return self._fresh

    @property
    def drifted_slots(self) -> list[str]:
        """Enrolled slots that were dead at prepare time."""
        return self._drifted

    @property
    def pending_refresh(self) -> bool:
        """Whether any slot was dead (commit will re-center)."""
        return self._pending

    def commit(self) -> None:
        """Re-shares the recovered key over the hardware observed at prepare
        time and persists the new helper data.

        Failures are non-fatal: the next launch re-derives everything.
        """
        if self._committed or self._key is None:
            self._key = None
            return
        self._committed = True
        try:
            with _store_lock(self._store):
                current, found = self._store.read_helper(_DEVICE_HELPER_ID)
                if not found or not hmac.compare_digest(current, self._expected_helper):
                    # Another module user refreshed or re-enrolled after this
                    # session prepared. Do not restore a stale snapshot.
                    return
                blob, written = refresh_core(self._key, self._factors, self._mandatory, self._draw)
                if written:
                    self._store.write_helper(_DEVICE_HELPER_ID, blob)
                    self._pending = False
                    self._drifted = []
        except (OSError, SsError):
            pass  # the next launch re-derives
        finally:
            self._key = None  # best-effort zeroization of the reference


def _collect() -> dict[str, str]:
    import sys

    if sys.platform == "win32":
        from ._collect_windows import collect
    elif sys.platform == "darwin":
        from ._collect_darwin import collect
    elif sys.platform.startswith("linux"):
        from ._collect_linux import collect
    else:
        from ._collect_other import collect
    return collect()


def prepare(options: Options) -> Session:
    """Collects factors and recovers (or enrolls) the secret-sharing HWID."""
    return _prepare_with(options, _collect, urandom_source, None)


def _prepare_with(options: Options, collect, source, store) -> Session:
    mandatory = {"slstore"}
    for name in options.extra_mandatory:
        if not _SLOT_NAME.match(name):
            raise SsError(f"slhwid: invalid extra mandatory slot name {name!r}")
        mandatory.add(name)

    raw_factors = normalize_factors(collect())

    if store is None:
        from ._store import default_store

        store = default_store(options.store_path)
    hid = _DEVICE_HELPER_ID
    with _store_lock(store):
        return _prepare_locked(options, source, store, raw_factors, mandatory, hid)


def _prepare_locked(options: Options, source, store, raw_factors: dict[str, str],
                    requested_mandatory: set[str], hid: str) -> Session:
    blob, found = store.read_helper(hid)

    # The slstore factor is ours, not collectable hardware: recovery injects
    # the persisted value (read-only). An absent value with an existing
    # helper is intentional tampering and recover_core reports it as a
    # hard-locked mandatory failure below.
    if found and not options.force_reenroll and not raw_factors.get("slstore"):
        value = store.read_slstore()
        if value is not None:
            if len(value) != 32:
                raise CorruptHelperError("slhwid: store secret has the wrong size")
            raw_factors["slstore"] = value.hex()

    if not found or options.force_reenroll:
        if not raw_factors.get("slstore"):
            raw_factors["slstore"] = _ensure_slstore(store, source)
        factors = project_factors(raw_factors, CURRENT_NORM_VERSION)
        mandatory = map_mandatory_to_current(requested_mandatory)
        for name in sorted(mandatory):
            if not factors.get(name):
                raise SsError(f"slhwid: mandatory factor {name!r} is not available on this machine")
        n = len(factors)
        m = len(mandatory)
        t = threshold(n, m)
        d = Draw(source)
        k = tuple(d.elem() for _ in range(4))
        shares, salt = build_shares(k, slot_list(factors, mandatory), t, d)
        blob = serialize_helper(shares, mandatory, t, salt, check_word(k))
        store.write_helper(hid, blob)
        session = Session(hwid_of(k), True, [], False)
        session._key = k
        session._draw = Draw(source)
        session._factors = factors
        session._mandatory = mandatory
        session._store = store
        session._expected_helper = bytes(blob)
        return session

    try:
        helper = parse_helper(blob)
    except CorruptHelperError:
        raise CorruptHelperError("slhwid: stored helper data is corrupt; re-enroll to recover") from None
    recovery_factors = project_factors(raw_factors, helper.norm_version)
    result = recover_core(blob, recovery_factors)
    if not result.ok:
        if result.reason == "corrupt":
            raise CorruptHelperError("slhwid: stored helper data is corrupt; re-enroll to recover")
        raise DriftError(result.present, result.needed, result.missing, result.reason == "mandatory")
    session = Session(result.hwid, False, result.dead, result.pending)
    session._key = result.key
    session._draw = Draw(source)
    # A recovered v1 helper is deliberately re-shared as v2 only on Commit,
    # after authentication accepted its unchanged HWID.
    session._factors = project_factors(raw_factors, CURRENT_NORM_VERSION)
    # Do not let one application weaken hard locks selected by the application
    # that enrolled the shared device helper.
    session._mandatory = map_mandatory_to_current(slot.name for slot in helper.slots if slot.mandatory)
    session._store = store
    session._expected_helper = bytes(blob)
    return session


def _store_lock(store):
    lock = getattr(store, "lock", None)
    if lock is None:
        from contextlib import nullcontext

        return nullcontext()
    return lock()


def _ensure_slstore(store, source) -> str:
    value = store.read_slstore()
    if value is not None:
        if len(value) != 32:
            raise CorruptHelperError("slhwid: store secret has the wrong size")
        return value.hex()
    value = source(32)
    if len(value) != 32:
        raise SsError("slhwid: randomness failed")
    store.write_slstore(value)
    return value.hex()
