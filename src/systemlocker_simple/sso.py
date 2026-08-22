"""Google SSO helpers for Simple account authentication.

Google-backed accounts have no local password on the server. When a
username/password check arrives without a valid SSO password, the server
answers an ``sso``/``ssoexp``/``ssowrong`` reason embedding the portal URL.
This module builds that URL — and deliberately stops there: the Simple
protocol targets trusted machines (typically servers), so delivery is left
to the developer (send it to your user through your own channel).
"""

from __future__ import annotations

from urllib.parse import quote

#: The server embeds this URL in sso/ssoexp/ssowrong denial reasons; the
#: client mirrors it so the flow can start before a denial is ever seen.
GOOGLE_SSO_PORTAL = "https://systemlocker.net/user/sso?system="


def google_sso_url(system_id: str) -> str:
    """Return the Google SSO portal URL for a system.

    After the user signs in there, the portal shows a system-specific
    password that is valid for 180 days and is then used as the account
    password.
    """
    return GOOGLE_SSO_PORTAL + quote(system_id, safe="")
