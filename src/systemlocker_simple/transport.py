"""Transport layer shared by the client and the management sub-API."""

from __future__ import annotations

from typing import Mapping, Sequence


class HTTPResponse:
    __slots__ = ("status", "body", "headers", "error")

    def __init__(self, status: int = 0, body: str = "", headers: Mapping[str, str] | None = None, error: str = "") -> None:
        self.status = status
        self.body = body
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.error = error

    def ok(self) -> bool:
        return not self.error and 200 <= self.status < 300

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class HTTPClient:
    """Override ``post_form`` to inject a fake."""

    def __init__(self, timeout_seconds: float = 15.0, user_agent: str = "systemlocker-simple-python/0.1") -> None:
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent

    def post_form(self, url: str, fields: Mapping[str, str | Sequence[str]], headers: Mapping[str, str] | None = None) -> HTTPResponse:
        from urllib.parse import urlencode
        from urllib.request import Request, build_opener, HTTPRedirectHandler
        from urllib.error import HTTPError

        pairs: list[tuple[str, str]] = []
        for key, value in fields.items():
            if isinstance(value, str):
                pairs.append((key, value))
            else:
                pairs.extend((key, item) for item in value)

        request = Request(
            url,
            data=urlencode(pairs).encode("utf-8"),
            headers={
                "User-Agent": self.user_agent,
                "Content-Type": "application/x-www-form-urlencoded",
                **{name: value for name, value in (headers or {}).items()},
            },
            method="POST",
        )
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = build_opener(NoRedirect())
        try:
            with opener.open(request, timeout=self.timeout_seconds) as result:
                return HTTPResponse(status=result.status, body=_read_bounded(result).decode("utf-8", "replace"), headers=dict(result.headers))
        except HTTPError as http_error:
            try:
                body = _read_bounded(http_error).decode("utf-8", "replace")
            except Exception:  # pragma: no cover - defensive
                body = ""
            return HTTPResponse(status=http_error.code, body=body, headers=dict(http_error.headers or {}))
        except Exception as error:
            return HTTPResponse(error=str(error))


def _read_bounded(stream: object) -> bytes:
    limit = 1024 * 1024
    headers = getattr(stream, "headers", None)
    if headers is not None and headers.get("Content-Length") and int(headers["Content-Length"]) > limit:
        raise ValueError("response body exceeds 1 MiB limit")
    body = stream.read(limit + 1)  # type: ignore[attr-defined]
    if len(body) > limit:
        raise ValueError("response body exceeds 1 MiB limit")
    return body
