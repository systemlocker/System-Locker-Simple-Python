# System Locker Simple — Python

Official Python client for the **System Locker Simple** protocol
(`POST /auth`): one request, one answer. No sessions, no heartbeats, no
signatures — the right fit when the machine running the check is one you
control. For software distributed to untrusted machines,
use a **Bedrock** client instead: it verifies an Ed25519 signature on every
response.

## Install

```sh
pip install systemlocker-simple
```

Zero dependencies — standard library only. Python 3.10+. Fully typed.

## Quickstart

```python
from systemlocker_simple import Client, Config

client = Client(Config(
    system_id="abcdefghijklmnopqrst",  # from the dashboard
    version="1.0.0",
    # hwid stays "1" unless you want device locking.
))

try:
    ok = client.authenticate_with_key("SL-XXXX-XXXX-XXXX")
except Exception:
    raise SystemExit(1)  # transport / server error — never counts as licensed

if not ok:
    raise SystemExit(1)  # rejected — block the action

# …run the gated action…
```

## Operations

| Operation                          | Method                                                                                        |
| ---------------------------------- | --------------------------------------------------------------------------------------------- |
| Check a license key                | `authenticate_with_key(key)`                                                                  |
| Check username + password          | `authenticate_with_password(user, password)`                                                  |
| Key expiry (`Never` or a UTC date) | `key_expiration_for_key` / `key_expiration_for_password`                                      |
| Server-side variable               | `get_variable(name, key="")`                                                                  |
| Self-service HWID reset            | `reset_hwid_for_key` / `reset_hwid_for_password` → `ResetOutcome.GRANTED`/`DENIED`/`TOO_SOON` |

Errors raise `SimpleError` whose `kind` separates infrastructure problems
(`Transport`, `Server`) from license denials (`Denied` with the server's raw
reason: `frozen`, `hwid banned`, `expired key`, …), Google-SSO cases (`SSO`,
with `sso_link(error)` for the portal URL), and unrecognized reasons
(`UnknownReason`, raw string carried).

## Management API (server-side tooling)

```python
client = Client(Config(system_id=…, version="1.0.0", api_key="…"))

count = client.management().redeemed_user_count()
keys = client.management().generate_keys(EXPIRY_ONE_MONTH, 10, "june-batch")
```

Wraps `POST /api/v1`: key status/expiration, HWID resets (single/admin or
whole-system), key generation, bans, expiry adjustment. Keep the API key on
servers you control.

## Device identifiers (HWID)

The library derives a hardware ID by default. To provide your own stable ID:

```python
from systemlocker_simple.hwid import device_hwid

config.hwid = device_hwid()
```

Derives a stable identifier from the machine GUID, hardware UUID, CPU id,
and MAC (Windows and Linux). A developer-supplied stable value works just as
well. Set `config.hwid = "1"` only to explicitly disable device locking.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately through the
System Locker support channels, not via public issues.
