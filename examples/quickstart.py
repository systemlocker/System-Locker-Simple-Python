"""Smallest working Simple integration."""

from __future__ import annotations

from systemlocker_simple import Client, Config

config = Config(
    system_id="abcdefghijklmnopqrst",  # from the dashboard
    version="1.0.0",
    # hwid stays "1" unless you want device locking.
)
client = Client(config)

try:
    ok = client.authenticate_with_key("SL-XXXX-XXXX-XXXX")
except Exception as error:  # transport / server error — never counts as licensed
    print("check failed:", error)
    raise SystemExit(1) from error

if not ok:
    raise SystemExit(1)  # rejected — block the action

print("license ok — run the gated action")

expiration = client.key_expiration_for_key("SL-XXXX-XXXX-XXXX")
print("expires:", "never" if expiration.permanent else expiration.expires_at)

flags = client.get_variable("feature_flags")
if flags.found:
    print("feature_flags =", flags.value)
