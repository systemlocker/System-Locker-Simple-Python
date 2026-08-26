# Security Policy

## Threat model

Simple assumes the machine performing the check is **friendly**:
you control where the client runs. The protocol is stateless —
one request, one answer — and intentionally does not sign responses. Anyone
who can intercept traffic or read this process's memory can forge a result;
if that matters for your deployment, use a **Bedrock** client, which
verifies an Ed25519 signature on every response.

What the library still does for you:

- HTTPS-only base URLs; TLS certificate validation always on.
- No secrets are persisted; requests carry only the fields the protocol
  defines.
- Typed errors distinguish infrastructure failures from license denials, so
  a network blip never silently counts as "licensed" —
  `authenticate_with_*` returns True only for a literal `true` answer.

## Keep in mind

- `hwid` locking is exact-match by default: the legacy hardware hash changes
  when the underlying hardware does. The opt-in SL-HWID mode (see below)
  tolerates minor hardware drift instead.
- The management API key grants key generation, bans, and expiry changes —
  keep it on servers you control.

## SL-HWID module (opt-in)

The opt-in threshold HWID mode (`hwid_mode="sl-hwid"`) makes copied state
and casual spoofing harder by requiring a stored enrollment plus enough
current factors. Our objective is to reduce HWID churn from minor hardware
changes, without reducing the strength of HWID as a locking mechanism. The
key itself is never persisted. The module zeroes key material after use;
because CPython objects are garbage-collected, this is best-effort in a
managed runtime.

Applications using the same store share one enrollment and HWID — that is
deliberate, so a launcher and the program it opens report one device
identity. Protect that store and choose a separate explicit store when
isolation is required.

The module changes the device identifier only. Simple responses remain
unsigned; on a hostile machine an attacker can still forge results
regardless of the HWID mode.

## Reporting a vulnerability

Report privately through the System Locker developer dashboard. Do not open
public issues for security problems.
