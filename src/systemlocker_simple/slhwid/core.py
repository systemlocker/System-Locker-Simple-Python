"""Pure cryptographic core of the §4A secret-sharing HWID module.

Implements GF(2^61-1) arithmetic, four-limb secret sharing, x-derivation,
helper-blob serialization, recovery and refresh. Everything here is pure and
platform-free; the lifecycle in ``__init__.py`` wires it to collectors,
storage and the CSPRNG. Python integers are arbitrary precision, so the
field operations reduce directly.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from itertools import combinations

P = (1 << 61) - 1

LEGACY_NORM_VERSION = 1
CURRENT_NORM_VERSION = 2

# A conservative physical-machine floor is nine current-schema slots;
# requiring one fewer tolerates one unavailable collector. Revisit this when
# the projection tables below change.
MINIMUM_FACTORS = 8

HELPER_MAGIC = b"SLSSHWID"
SLSTORE_PREFIX = b"SLSTOR1"


class SsError(Exception):
    """A local secret-sharing module failure."""


class CorruptHelperError(SsError):
    """Stored helper data failed its integrity check (distinct from drift)."""


class DriftError(SsError):
    """The stored secret could not be recovered from current hardware.

    ``mandatory`` marks a hard-locked slot as the cause (changed or absent);
    ``missing`` lists those slots. ``present``/``needed`` describe the drift
    budget.
    """

    def __init__(self, present: int, needed: int, missing: list[str], mandatory: bool) -> None:
        self.present = present
        self.needed = needed
        self.missing = missing
        self.mandatory = mandatory
        if mandatory:
            detail = f"mandatory factor(s) {', '.join(missing)} changed or absent; re-activation required"
        else:
            detail = f"hardware drifted past the recovery threshold ({present} factors present, {needed} needed); re-activation required"
        super().__init__(f"slhwid: {detail}")


# ── field arithmetic ────────────────────────────────────────────────


def addmod(a: int, b: int) -> int:
    s = a + b
    return s - P if s >= P else s


def submod(a: int, b: int) -> int:
    return a - b if a >= b else a + P - b


def mulmod(a: int, b: int) -> int:
    return (a * b) % P


def invmod(a: int) -> int:
    return pow(a, -1, P)


def _wipe(bytearrays) -> None:
    for b in bytearrays:
        if isinstance(b, bytearray):
            b[:] = bytearray(len(b))


class Draw:
    """Replays a byte source as consecutive 8-byte little-endian draws."""

    def __init__(self, source) -> None:
        self._source = source  # callable(n) -> bytes

    def elem(self) -> int:
        chunk = self._source(8)
        if len(chunk) != 8:
            raise SsError("slhwid: randomness exhausted")
        return int.from_bytes(chunk, "little") % P


def fixed_draw(data: bytes) -> Draw:
    """A Draw over a fixed byte stream (conformance vectors, tests)."""
    state = {"pos": 0}

    def source(n: int) -> bytes:
        start = state["pos"]
        state["pos"] += n
        return data[start : start + n]

    return Draw(source)


def urandom_source(n: int) -> bytes:
    import os

    return os.urandom(n)


# ── derivation ──────────────────────────────────────────────────────


def derive_x(slot: str, value: str, salt: int) -> int:
    h = hashlib.sha256()
    h.update(b"SL-SS-X1")
    h.update(bytes([0, salt, 0]))
    h.update(slot.encode("ascii"))
    h.update(b"\x00")
    h.update(value.encode("utf-8"))
    v = int.from_bytes(h.digest()[:8], "little") & P
    return 1 + v % (P - 1)


def key_bytes(k: tuple[int, int, int, int]) -> bytes:
    return struct.pack("<4Q", *k)


def check_word(k: tuple[int, int, int, int]) -> bytes:
    return hashlib.sha256(b"\x01" + b"SL-SS-CW1" + key_bytes(k)).digest()


def hwid_of(k: tuple[int, int, int, int]) -> str:
    import base64

    digest = hashlib.sha256(b"\x02" + b"SL-SS-ID1" + key_bytes(k)).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def ct_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# ── threshold ───────────────────────────────────────────────────────


def threshold(n: int, m: int) -> int:
    if n < MINIMUM_FACTORS:
        raise SsError(f"slhwid: need at least {MINIMUM_FACTORS} enrolled factor slots, have {n}")
    if m >= n:
        raise SsError(f"slhwid: mandatory slots ({m}) must be fewer than total ({n})")
    # Current enrollment cannot reach the first branch, but keeping the full
    # policy explicit makes the boundary and legacy rationale unambiguous.
    num, den = (4, 5) if n < 8 else (7, 10)
    t = (num * n + den - 1) // den
    return max(m + 1, min(t, n))


# ── normalization ───────────────────────────────────────────────────

_PLACEHOLDERS = {
    "", "0", "none", "unknown", "default", "default string", "to be filled by o.e.m.",
    "not specified", "not available", "not applicable", "not present", "n/a", "na", "null",
    "system serial number", "asset tag", "no asset tag", "123456789", "0123456789", "example",
}

_IDENTIFIER_FACTORS = {
    "machine_guid", "product_uuid", "system_uuid", "board_serial", "system_serial", "chassis_serial",
    "disk_serial", "volume_id", "tpm_ek", "memory_modules", "nic_identity", "battery_serial", "monitor_edid",
}


def normalize(name: str, raw: str) -> str:
    # ASCII-only folding is deliberate: Unicode hardware text must stay
    # byte-stable across native and managed implementations.
    value = raw.replace("\x00", "").strip().translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))
    if name in ("mac", "nic_identity"):
        value = value.replace(":", "").replace("-", "")
    return value


def is_missing(value: str) -> bool:
    return value.strip() in _PLACEHOLDERS


def _is_hex(value: str) -> bool:
    return all(char in "0123456789abcdefABCDEF" for char in value)


def _is_degenerate_identifier(value: str) -> bool:
    compact = "".join(char for char in value if char.isascii() and char.isalnum())
    return len(compact) >= 4 and (all(char == "0" for char in compact) or all(char == "f" for char in compact))


def _is_uuid_like(value: str) -> bool:
    valid_length = len(value) == 32 or (len(value) == 36 and all(value[index] == "-" for index in (8, 13, 18, 23)))
    compact = value.replace("-", "")
    return valid_length and len(compact) == 32 and _is_hex(compact) and not _is_degenerate_identifier(compact) and compact != "12345678123412341234123456789abc"


def is_sane_factor(name: str, value: str) -> bool:
    if not value or len(value.encode("utf-8")) > 4096 or is_missing(value):
        return False
    if name == "ram_total":
        return value.isascii() and value.isdecimal() and int(value) >= 128 * 1024 * 1024
    if name in ("machine_guid", "product_uuid", "system_uuid"):
        return _is_uuid_like(value)
    if name == "slstore":
        return len(value) == 64 and _is_hex(value) and not _is_degenerate_identifier(value)
    if name == "tpm_ek":
        return len(value) == 64 and _is_hex(value)
    if name in ("mac", "nic_identity"):
        return all(len(part) == 12 and _is_hex(part) and not _is_degenerate_identifier(part) for part in value.split("|"))
    if name in _IDENTIFIER_FACTORS:
        return all(not is_missing(part) and not _is_degenerate_identifier(part) for part in value.split("|"))
    return True


def normalize_factors(raw: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in raw.items():
        nv = normalize(name, value)
        if is_sane_factor(name, nv):
            out[name] = nv
    return out


_LEGACY_FACTOR_NAMES = (
    "slstore", "machine_guid", "product_uuid", "board_serial", "cpu_id", "disk_serial", "mac",
    "ram_total", "volume_id", "computer_name", "firmware", "gpu_id", "monitor_edid", "os_build",
)

_CURRENT_DIRECT_FACTOR_NAMES = (
    "slstore", "machine_guid", "cpu_id", "disk_serial", "ram_total", "volume_id", "firmware",
    "tpm_ek", "memory_modules", "nic_identity", "battery_serial",
)

_CURRENT_FACTOR_GROUPS = (
    ("platform_identity", ("system_uuid", "board_serial", "system_serial", "chassis_serial")),
    ("display_group", ("gpu_id", "monitor_edid")),
    ("software_environment", ("computer_name", "os_build")),
)


def _group_value(name: str, members: tuple[str, ...], raw: dict[str, str]) -> str:
    """Return one capped recovery value for correlated raw signals.

    Empty members are intentionally encoded. A partial group therefore has a
    stable, distinct value and any member change invalidates the one group
    vote without turning one physical failure domain into several votes.
    """
    encoded = bytearray(b"SL-HWID-GROUP2\x00")
    encoded += name.encode("ascii") + b"\x00"
    present = False
    for member in members:
        value = raw.get(member, "")
        present |= bool(value)
        encoded += member.encode("ascii") + b"\x00"
        encoded += value.encode("utf-8") + b"\x00"
    return hashlib.sha256(encoded).hexdigest() if present else ""


def project_factors(raw: dict[str, str], norm_version: int) -> dict[str, str]:
    """Project normalized raw signals into the helper's factor schema.

    Keep the v1 projection frozen: existing helpers derive their x-values
    from these historical slot names and values. New helpers always use v2.
    """
    if norm_version == LEGACY_NORM_VERSION:
        return {name: raw[name] for name in _LEGACY_FACTOR_NAMES if raw.get(name)}
    if norm_version != CURRENT_NORM_VERSION:
        raise SsError(f"slhwid: unsupported factor schema {norm_version}")
    out = {name: raw[name] for name in _CURRENT_DIRECT_FACTOR_NAMES if raw.get(name)}
    for name, members in _CURRENT_FACTOR_GROUPS:
        value = _group_value(name, members, raw)
        if value:
            out[name] = value
    return out


def current_mandatory_name(name: str) -> str:
    if name in ("product_uuid", "board_serial", "system_uuid", "system_serial", "chassis_serial"):
        return "platform_identity"
    if name in ("gpu_id", "monitor_edid"):
        return "display_group"
    if name in ("computer_name", "os_build"):
        return "software_environment"
    if name == "mac":
        return "nic_identity"
    return name


def map_mandatory_to_current(names) -> set[str]:
    return {current_mandatory_name(name) for name in names}


# ── sharing ─────────────────────────────────────────────────────────


def slot_list(factors: dict[str, str], mandatory: set[str]) -> list[tuple[str, str, bool]]:
    return [(name, factors[name], name in mandatory) for name in sorted(factors)]


def build_shares(k, slots, t: int, d: Draw):
    salt = 0
    xs: list[int] = []
    while True:
        xs = [derive_x(name, value, salt) for name, value, _ in slots]
        if len(set(xs)) == len(xs):
            break
        salt += 1
        if salt == 255:
            raise SsError("slhwid: x-coordinate collision loop")
    coeffs = [[0] * t for _ in range(4)]
    for limb in range(4):
        for j in range(1, t):
            coeffs[limb][j] = d.elem()
    shares: dict[str, tuple[int, int, int, int]] = {}
    for i, (name, _, _) in enumerate(slots):
        share = []
        for limb in range(4):
            acc = 0
            for j in range(t - 1, 0, -1):  # Horner
                acc = addmod(mulmod(acc, xs[i]), coeffs[limb][j])
            share.append(addmod(mulmod(acc, xs[i]), k[limb]))
        shares[name] = tuple(share)  # type: ignore[arg-type]
    return shares, salt


# ── helper blob ─────────────────────────────────────────────────────


def serialize_helper(shares, mandatory: set[str], t: int, salt: int, cw: bytes,
                     norm_version: int = CURRENT_NORM_VERSION) -> bytes:
    names = sorted(shares)
    payload = bytearray()
    payload += bytes([1, norm_version, salt, len(names)])
    payload += bytes([sum(1 for n in names if n in mandatory), t, 0, 0])
    for name in names:
        encoded = name.encode("ascii")
        payload += bytes([len(encoded)]) + encoded
        payload += bytes([1 if name in mandatory else 0])
        payload += struct.pack("<4Q", *shares[name])
    blob = bytearray()
    blob += HELPER_MAGIC
    blob += struct.pack("<I", len(payload))
    blob += payload
    blob += cw
    blob += hashlib.sha256(bytes(blob)).digest()
    return bytes(blob)


class HelperSlot:
    __slots__ = ("name", "mandatory", "share")

    def __init__(self, name: str, mandatory: bool, share) -> None:
        self.name = name
        self.mandatory = mandatory
        self.share = share


class Helper:
    __slots__ = ("norm_version", "salt", "threshold", "slots", "check_word")

    def __init__(self, norm_version: int, salt: int, threshold_: int, slots: list[HelperSlot], check_word: bytes) -> None:
        self.norm_version = norm_version
        self.salt = salt
        self.threshold = threshold_
        self.slots = slots
        self.check_word = check_word


def parse_helper(blob: bytes) -> Helper:
    corrupt = CorruptHelperError
    # This is writable local state: cap it before hashing/parsing so a corrupt
    # store cannot turn recovery into an allocation or combinatorics attack.
    if len(blob) > 4096:
        raise corrupt("slhwid: stored helper data is corrupt: oversized")
    if len(blob) < 8 + 4 + 8 + 32 + 32:
        raise corrupt("slhwid: stored helper data is corrupt: truncated")
    if blob[:8] != HELPER_MAGIC:
        raise corrupt("slhwid: stored helper data is corrupt: magic mismatch")
    if not ct_equal(hashlib.sha256(blob[:-32]).digest(), blob[-32:]):
        raise corrupt("slhwid: stored helper data is corrupt: integrity mismatch")
    payload_len = struct.unpack_from("<I", blob, 8)[0]
    if payload_len < 8 or payload_len > 4096 or 12 + payload_len + 64 != len(blob):
        raise corrupt("slhwid: stored helper data is corrupt: length mismatch")
    body = blob[12 : 12 + payload_len]
    cw = blob[12 + payload_len : 12 + payload_len + 32]
    if body[0] != 1:
        raise corrupt(f"slhwid: stored helper data is corrupt: unsupported version {body[0]}")
    if body[1] not in (LEGACY_NORM_VERSION, CURRENT_NORM_VERSION):
        raise corrupt(f"slhwid: stored helper data is corrupt: unsupported factor schema {body[1]}")
    if body[6] != 0 or body[7] != 0:
        raise corrupt("slhwid: stored helper data is corrupt: reserved header bits set")
    allowed = set(_LEGACY_FACTOR_NAMES if body[1] == LEGACY_NORM_VERSION else (
        *_CURRENT_DIRECT_FACTOR_NAMES, *(name for name, _ in _CURRENT_FACTOR_GROUPS)
    ))
    n = body[3]
    mandatory_header = body[4]
    helper = Helper(body[1], body[2], body[5], [], cw)
    if n == 0 or n > len(allowed):
        raise corrupt("slhwid: stored helper data is corrupt: invalid slot count")
    if helper.threshold == 0 or helper.threshold > n or mandatory_header == 0 or mandatory_header >= helper.threshold:
        raise corrupt("slhwid: stored helper data is corrupt: invalid threshold")
    rest = body[8:]
    seen: set[str] = set()
    previous = ""
    mandatory_count = 0
    for _ in range(n):
        if len(rest) < 1:
            raise corrupt("slhwid: stored helper data is corrupt: slot truncated")
        name_len = rest[0]
        if name_len == 0 or len(rest) < 1 + name_len + 1 + 32:
            raise corrupt("slhwid: stored helper data is corrupt: slot truncated")
        name = rest[1 : 1 + name_len].decode("ascii")
        if name not in allowed:
            raise corrupt(f"slhwid: stored helper data is corrupt: invalid slot {name!r}")
        if name in seen or (previous and previous >= name):
            raise corrupt(f"slhwid: stored helper data is corrupt: duplicate or unsorted slot {name!r}")
        seen.add(name)
        previous = name
        flags = rest[1 + name_len]
        if flags not in (0, 1):
            raise corrupt("slhwid: stored helper data is corrupt: invalid slot flags")
        mandatory = flags == 1
        mandatory_count += mandatory
        share = struct.unpack_from("<4Q", rest, 2 + name_len)
        if any(limb >= P for limb in share):
            raise corrupt("slhwid: stored helper data is corrupt: share limb out of range")
        helper.slots.append(HelperSlot(name, mandatory, share))
        rest = rest[2 + name_len + 32 :]
    if rest:
        raise corrupt("slhwid: stored helper data is corrupt: trailing bytes")
    if mandatory_count != mandatory_header:
        raise corrupt("slhwid: stored helper data is corrupt: mandatory count mismatch")
    if not any(slot.name == "slstore" and slot.mandatory for slot in helper.slots):
        raise corrupt("slhwid: stored helper data is corrupt: mandatory slstore missing")
    return helper


# ── recovery ────────────────────────────────────────────────────────


def _lagrange_at_zero(xs: list[int], ys: list[int]) -> int:
    total = 0
    for j in range(len(xs)):
        num = 1
        den = 1
        for k in range(len(xs)):
            if k == j:
                continue
            num = mulmod(num, xs[k])
            den = mulmod(den, submod(xs[k], xs[j]))
        total = addmod(total, mulmod(ys[j], mulmod(num, invmod(den))))
    return total


def _evaluate_at(xs: list[int], ys: list[int], xq: int) -> int:
    total = 0
    for j in range(len(xs)):
        num = 1
        den = 1
        for k in range(len(xs)):
            if k == j:
                continue
            num = mulmod(num, submod(xq, xs[k]))
            den = mulmod(den, submod(xs[j], xs[k]))
        total = addmod(total, mulmod(ys[j], mulmod(num, invmod(den))))
    return total


def _key_from_points(points):
    xs = [p[0] for p in points]
    return tuple(_lagrange_at_zero(xs, [p[1][limb] for p in points]) for limb in range(4))


def _find_recovering_subset(mandatory, optional, t: int, cw: bytes):
    """Searches size-t subsets containing every mandatory candidate.

    The sweep is exhaustive: neither intermediate failures nor a match
    truncate it, so the amount of work done does not signal which factors
    survived (side-channel resistance).
    """
    need = max(0, t - len(mandatory))
    if need > len(optional):
        return None
    names = [p[2] for p in optional]
    found = None
    found_names = set()
    for combo in combinations(range(len(optional)), need):
        points = mandatory + [optional[i] for i in combo]
        if found is None and ct_equal(check_word(_key_from_points(points)), cw):
            found = points
            found_names = {names[i] for i in combo}
    if found is None:
        return None
    return found, found_names


def _is_mandatory(helper: Helper, name: str) -> bool:
    for s in helper.slots:
        if s.name == name:
            return s.mandatory
    return False


class RecoverResult:
    __slots__ = ("ok", "reason", "key", "hwid", "live", "dead", "pending", "present", "needed", "missing")

    def __init__(self) -> None:
        self.ok = False
        self.reason = ""
        self.key = None
        self.hwid = ""
        self.live: list[str] = []
        self.dead: list[str] = []
        self.pending = False
        self.present = 0
        self.needed = 0
        self.missing: list[str] = []


def recover_core(blob: bytes, factors: dict[str, str]) -> RecoverResult:
    result = RecoverResult()
    try:
        helper = parse_helper(blob)
    except CorruptHelperError:
        result.reason = "corrupt"
        return result
    t = helper.threshold

    mandatory = []
    optional = []
    missing_mandatory: list[str] = []
    present = 0
    for slot in helper.slots:  # slots are stored sorted by name
        value = factors.get(slot.name, "")
        if not value:
            if slot.mandatory:
                missing_mandatory.append(slot.name)
            continue
        present += 1
        point = (derive_x(slot.name, value, helper.salt), slot.share, slot.name)
        if slot.mandatory:
            mandatory.append(point)
        else:
            optional.append(point)
    # The sweep runs to completion regardless of absences or failures
    # (constant-work shape); the hard-locked mandatory verdict is applied
    # afterwards and any accidental match is discarded.
    found = _find_recovering_subset(mandatory, optional, t, helper.check_word)
    if missing_mandatory:
        result.reason = "mandatory"
        result.present = present
        result.needed = t
        result.missing = missing_mandatory
        return result
    if found is None:
        # Diagnostic: if dropping one mandatory slot lets the rest of the
        # machine recover, that mandatory factor was changed (intentional
        # tampering) rather than the machine having drifted. Every mandatory
        # slot is tested (no early exit); the first culprit in stored order
        # wins.
        culprit = ""
        for ms in helper.slots:
            if not ms.mandatory:
                continue
            merged = mandatory + optional
            mand2 = [p for p in merged if p[2] != ms.name and _is_mandatory(helper, p[2])]
            opt2 = [p for p in merged if p[2] != ms.name and not _is_mandatory(helper, p[2])]
            if culprit == "" and _find_recovering_subset(mand2, opt2, t, helper.check_word) is not None:
                culprit = ms.name
        if culprit:
            result.reason = "mandatory"
            result.present = present
            result.needed = t
            result.missing = [culprit]
            return result
        result.reason = "drift"
        result.present = present
        result.needed = t
        return result

    points, subset_names = found
    k = _key_from_points(points)
    live: list[str] = []
    dead: list[str] = []
    for slot in helper.slots:
        if slot.name in subset_names or any(p[2] == slot.name for p in mandatory):
            live.append(slot.name)
            continue
        value = factors.get(slot.name, "")
        if not value:
            dead.append(slot.name)
            continue
        xq = derive_x(slot.name, value, helper.salt)
        xs = [p[0] for p in points]
        on_curve = all(
            _evaluate_at(xs, [p[1][limb] for p in points], xq) == slot.share[limb]
            for limb in range(4)
        )
        (live if on_curve else dead).append(slot.name)
    result.ok = True
    result.key = k
    result.hwid = hwid_of(k)
    result.live = sorted(live)
    result.dead = sorted(dead)
    result.pending = bool(dead)
    return result


def refresh_core(k, factors: dict[str, str], mandatory: set[str], d: Draw):
    """Re-shares k over the current factors; returns (blob, written)."""
    # This matters during v1 -> v2 migration: a legacy mandatory name may map
    # to a current group that is unavailable. Skipping the write preserves the
    # old hard lock instead of silently dropping it from the new helper.
    if any(not factors.get(name) for name in mandatory):
        return None, False
    slots = slot_list(factors, mandatory)
    m = sum(1 for s in slots if s[2])
    try:
        t = threshold(len(slots), m)
    except SsError:
        return None, False
    shares, salt = build_shares(k, slots, t, d)
    blob = serialize_helper(shares, mandatory, t, salt, check_word(k))
    return blob, True
