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

- `hwid` locking is exact-match; supply a stable value or use the `hwid`
  module's hardware composition.
- The management API key grants key generation, bans, and expiry changes —
  keep it on servers you control.

## Reporting a vulnerability

Report privately through the System Locker developer dashboard. Do not open
public issues for security problems.
