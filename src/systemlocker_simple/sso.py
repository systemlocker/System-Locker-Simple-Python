"""Google SSO helpers for Simple account authentication.

Google-backed accounts have no local password on the server. When a
username/password check arrives without a valid SSO password, the server
answers an ``sso``/``ssoexp``/``ssowrong`` reason embedding the portal URL.
These helpers build and open that portal.
"""

from __future__ import annotations

import webbrowser
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


def open_url(url: str) -> bool:
    """Launch the default browser at a URL.

    Uses the stdlib ``webbrowser`` module; returns whether a browser
    launched. Hosts without one (servers, containers) return ``False`` and
    the caller falls back to displaying the URL.
    """
    if not url:
        return False
    return webbrowser.open(url)


def begin_google_sso(system_id: str) -> tuple[str, bool]:
    """Open the Google SSO portal for a system in the default browser.

    The URL is always returned so flows without a browser can hand it to
    the developer; the second value reports whether the launch succeeded.
    """
    url = google_sso_url(system_id)
    return url, open_url(url)
