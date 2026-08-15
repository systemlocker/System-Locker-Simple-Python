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
from .transport import HTTPClient, HTTPResponse

__version__ = "0.1.0"

__all__ = [
    "Client",
    "Config",
    "ErrorKind",
    "Expiration",
    "EXPIRY_ONE_DAY",
    "EXPIRY_ONE_MONTH",
    "EXPIRY_ONE_WEEK",
    "EXPIRY_ONE_YEAR",
    "EXPIRY_PERMANENT",
    "EXPIRY_THREE_MONTHS",
    "HTTPClient",
    "HTTPResponse",
    "Management",
    "ResetOutcome",
    "SimpleError",
    "VariableValue",
    "classify",
    "sso_link",
]
