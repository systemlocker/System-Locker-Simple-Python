"""Official System Locker Simple client for Python.

Stateless license checks over POST /auth: one request, one answer. For
software on machines you control.
"""

from .client import (
    EXPIRY_ONE_DAY,
    EXPIRY_ONE_MONTH,
    EXPIRY_ONE_WEEK,
    EXPIRY_ONE_YEAR,
    EXPIRY_PERMANENT,
    EXPIRY_THREE_MONTHS,
    Client,
    Config,
    Expiration,
    Management,
    ResetOutcome,
    VariableValue,
)
from .errors import ErrorKind, SimpleError, classify, sso_link
from .invisible_folder import (
    DownloadIfNewResult,
    InvisibleFolder,
    InvisibleFolderCredential,
    InvisibleFolderFile,
    InvisibleFolderMetadata,
)
from .sso import GOOGLE_SSO_PORTAL, google_sso_url
from .transport import HTTPClient, HTTPResponse

__version__ = "1.2.0"

__all__ = [
    "Client",
    "Config",
    "DownloadIfNewResult",
    "ErrorKind",
    "Expiration",
    "GOOGLE_SSO_PORTAL",
    "EXPIRY_ONE_DAY",
    "EXPIRY_ONE_MONTH",
    "EXPIRY_ONE_WEEK",
    "EXPIRY_ONE_YEAR",
    "EXPIRY_PERMANENT",
    "EXPIRY_THREE_MONTHS",
    "HTTPClient",
    "HTTPResponse",
    "InvisibleFolder",
    "InvisibleFolderCredential",
    "InvisibleFolderFile",
    "InvisibleFolderMetadata",
    "Management",
    "ResetOutcome",
    "SimpleError",
    "VariableValue",
    "classify",
    "google_sso_url",
    "sso_link",
]
