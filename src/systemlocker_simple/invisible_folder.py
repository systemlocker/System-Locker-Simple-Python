"""Invisible Folder file delivery with the Simple credential set."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .errors import ErrorKind, SimpleError
from .transport import HTTPResponse

DOWNLOAD_PREFIX = "/a/"
METADATA_PREFIX = "/api/v1/files/"
METADATA_SUFFIX = "/metadata"
REVISIONS_KEY = "__revisions"

_REFERENCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{4,128}$")

FILE_STRING_FIELDS = ("id", "reference_id", "name", "mime_type", "uploaded_at")


def valid_reference_id(reference_id: str) -> bool:
    return bool(_REFERENCE_ID_PATTERN.match(reference_id or ""))


def percent_encode(value: str) -> str:
    from urllib.parse import quote
    return quote(value, safe="-_.")


@dataclass
class InvisibleFolderCredential:
    """Selects how a download authorizes against the file's protection.

    The default (all fields empty) downloads a public or hidden file. Fill in
    exactly one mode: ``file_password`` for password-protected files,
    ``license_key`` for System Locker Simple files, or ``username`` and
    ``password`` together for System Locker Simple files (account mode).
    """

    file_password: str = ""
    license_key: str = ""
    username: str = ""
    password: str = ""


class InvisibleFolderFile:
    __slots__ = ("id", "reference_id", "name", "mime_type", "size", "downloads", "uploaded_at", "permission_type_id")

    def __init__(self, **fields) -> None:
        for slot in self.__slots__:
            setattr(self, slot, fields[slot])


class InvisibleFolderMetadata:
    __slots__ = ("file", "values")

    def __init__(self, file: InvisibleFolderFile, values: dict) -> None:
        self.file = file
        #: metadata key -> {"value": str, "created_at": str | None}
        self.values = values


class DownloadIfNewResult:
    __slots__ = ("downloaded", "revision", "metadata", "bytes", "destination")

    def __init__(self, downloaded: bool, revision: str, metadata: InvisibleFolderMetadata) -> None:
        self.downloaded = downloaded
        self.revision = revision
        self.metadata = metadata
        self.bytes: bytes | None = None
        self.destination: str | None = None


class InvisibleFolder:
    """Downloads files from Invisible Folder using the end user's own
    credentials. The token-based Advanced permission is a Bedrock feature
    and is intentionally absent here."""

    def __init__(self, client) -> None:
        self._client = client

    def _check_prerequisites(self, reference_id: str) -> None:
        if not self._client.config.invisible_folder_base_url.startswith("https://"):
            raise SimpleError(ErrorKind.CONFIGURATION, "Invisible Folder base URL must use HTTPS.")
        if not valid_reference_id(reference_id):
            raise SimpleError(ErrorKind.CONFIGURATION, "Invisible Folder reference ID must be 4 through 128 URL-safe characters.")

    def _credential_headers(self, credential: InvisibleFolderCredential | None) -> dict[str, str]:
        credential = credential or InvisibleFolderCredential()
        modes = sum((
            bool(credential.file_password),
            bool(credential.license_key),
            bool(credential.username) or bool(credential.password),
        ))
        if modes > 1:
            raise SimpleError(
                ErrorKind.CONFIGURATION,
                "Invisible Folder credential must use one mode: file password, license key, or username and password.",
            )
        if bool(credential.username) != bool(credential.password):
            raise SimpleError(ErrorKind.CONFIGURATION, "Invisible Folder username and password must be supplied together.")

        headers: dict[str, str] = {}
        if credential.file_password:
            headers["X-Invisiblefolder-Password"] = credential.file_password
        if credential.license_key:
            headers["X-Systemlocker-Key"] = credential.license_key
        if credential.username:
            headers["X-Systemlocker-Username"] = credential.username
            headers["X-Systemlocker-Password"] = credential.password
        return headers

    def _endpoint(self, prefix: str, reference_id: str) -> str:
        return self._client.config.invisible_folder_base_url.rstrip("/") + prefix + reference_id

    # ── operations ─────────────────────────────────────────────────

    def download(self, reference_id: str, credential: InvisibleFolderCredential | None = None) -> bytes:
        self._check_prerequisites(reference_id)
        # The download route is a plain GET; credentials travel in headers
        # because GET request bodies are not supported.
        headers = {"X-Invisiblefolder-Download": "1", **self._credential_headers(credential)}
        response = self._client.http.get(self._endpoint(DOWNLOAD_PREFIX, reference_id), headers)
        return self._handle_download_response(response, "download")

    def download_to_file(self, reference_id: str, destination: str | Path, credential: InvisibleFolderCredential | None = None) -> Path:
        destination = Path(destination)
        if not str(destination):
            raise SimpleError(ErrorKind.CONFIGURATION, "Invisible Folder download destination cannot be empty.")
        payload = self.download(reference_id, credential)
        try:
            destination.write_bytes(payload)
        except OSError as error:
            raise SimpleError(ErrorKind.LOCAL_FAILURE, "Could not write Invisible Folder download destination.") from error
        return destination

    def metadata(self, reference_id: str, keys: list[str] | None = None) -> InvisibleFolderMetadata:
        self._check_prerequisites(reference_id)

        headers: dict[str, str] = {}
        if self._client.config.invisible_folder_api_key:
            headers["X-Api-Key"] = self._client.config.invisible_folder_api_key

        url = self._endpoint(METADATA_PREFIX, reference_id) + METADATA_SUFFIX
        if keys:
            url += "?keys[]=" + "&keys[]=".join(percent_encode(key) for key in keys)

        response = self._client.http.get(url, headers)
        if not response.ok():
            message = _error_message(response)
            if message:
                raise SimpleError(ErrorKind.TRANSPORT, f"Invisible Folder metadata request failed: {message}")
            raise _transport_error("metadata request", response)
        return _parse_metadata(response.body)

    def download_if_new(
        self,
        reference_id: str,
        known_revision: str = "",
        destination: str | Path | None = None,
        credential: InvisibleFolderCredential | None = None,
    ) -> DownloadIfNewResult:
        current = self.metadata(reference_id, [REVISIONS_KEY])
        revision_entry = current.values.get(REVISIONS_KEY)
        if revision_entry is None:
            raise SimpleError(ErrorKind.SERVER, "Invisible Folder metadata did not contain __revisions.")

        result = DownloadIfNewResult(False, revision_entry["value"], current)
        if known_revision != "" and known_revision == result.revision:
            return result

        result.downloaded = True
        if destination is not None:
            result.destination = str(self.download_to_file(reference_id, destination, credential))
        else:
            result.bytes = self.download(reference_id, credential)
        return result

    def _handle_download_response(self, response: HTTPResponse, action: str) -> bytes:
        if not response.ok():
            message = _error_message(response)
            if message:
                raise SimpleError(ErrorKind.TRANSPORT, f"Invisible Folder {action} failed: {message}")
            raise _transport_error(action, response)
        return response.body.encode("utf-8", "surrogateescape")


def _error_message(response: HTTPResponse) -> str:
    try:
        payload = json.loads(response.body)
    except (ValueError, UnicodeDecodeError):
        return ""
    if isinstance(payload, dict):
        for key in ("message", "error"):
            if isinstance(payload.get(key), str):
                return payload[key]
    return ""


def _transport_error(action: str, response: HTTPResponse) -> SimpleError:
    if response.error:
        return SimpleError(ErrorKind.TRANSPORT, f"Invisible Folder {action} failed: {response.error}")
    return SimpleError(ErrorKind.TRANSPORT, f"Invisible Folder {action} returned HTTP {response.status}.")


def _parse_metadata(body_text: str) -> InvisibleFolderMetadata:
    try:
        payload = json.loads(body_text)
    except ValueError as error:
        raise SimpleError(ErrorKind.SERVER, "Invisible Folder metadata JSON is invalid.") from error
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise SimpleError(ErrorKind.SERVER, "Invisible Folder metadata response has the wrong shape.")
    file = data.get("file")
    metadata = data.get("metadata")
    if not isinstance(file, dict) or not isinstance(metadata, dict):
        raise SimpleError(ErrorKind.SERVER, "Invisible Folder metadata response has the wrong shape.")

    for name in FILE_STRING_FIELDS:
        if name not in file or not isinstance(file[name], str):
            raise SimpleError(ErrorKind.SERVER, f"Invisible Folder file field '{name}' is missing or has the wrong type.")
    for name in ("size", "downloads"):
        value = file.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise SimpleError(ErrorKind.SERVER, f"Invisible Folder file field '{name}' has the wrong type.")
    permission_type_id = file.get("permission_type_id")
    if not isinstance(permission_type_id, int) or isinstance(permission_type_id, bool):
        raise SimpleError(ErrorKind.SERVER, "Invisible Folder file field 'permission_type_id' has the wrong type.")

    values: dict[str, dict] = {}
    for key, entry in metadata.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("value"), str):
            raise SimpleError(ErrorKind.SERVER, "Invisible Folder metadata entry has the wrong type.")
        created_at = entry.get("created_at")
        if created_at is not None and not isinstance(created_at, str):
            raise SimpleError(ErrorKind.SERVER, "Invisible Folder metadata creation time has the wrong type.")
        values[key] = {"value": entry["value"], "created_at": created_at}

    return InvisibleFolderMetadata(
        InvisibleFolderFile(
            id=file["id"],
            reference_id=file["reference_id"],
            name=file["name"],
            mime_type=file["mime_type"],
            size=file["size"],
            downloads=file["downloads"],
            uploaded_at=file["uploaded_at"],
            permission_type_id=file["permission_type_id"],
        ),
        values,
    )
