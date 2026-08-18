"""Final browser CORS boundary for Queen Califia.

The API gateway and deployment entrypoints historically accumulated multiple CORS
hooks. This middleware is intentionally the outermost authority: it removes any
CORS response headers emitted by inner Flask extensions/hooks and re-emits them
only when the request Origin matches the project-scoped policy below.

CORS is a browser policy, not API authentication. Requests from unapproved Origin
values are therefore allowed to execute normally but receive no CORS permission.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable
from urllib.parse import urlsplit


_CANONICAL_ORIGINS = {
    "https://queencalifia.tamerian.com",
    "https://queencalifia-cyberai.web.app",
    "https://queencalifia-cyberai.firebaseapp.com",
}
_QUEEN_FIREBASE_PREVIEW = re.compile(
    r"^https://queencalifia-cyberai--[a-z0-9-]+\.web\.app$",
    re.IGNORECASE,
)
_DEV_SERVICE_ORIGIN = re.compile(
    r"^https?://queencalifia-cyberai(?::\d+)?$",
    re.IGNORECASE,
)
_CORS_RESPONSE_HEADERS = {
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-max-age",
}


def _normalize_origin(value: str) -> str | None:
    """Return a canonical origin or None for malformed/non-origin values."""
    raw = (value or "").strip()
    if not raw:
        return None

    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        return None

    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    if not parsed.hostname or parsed.username or parsed.password:
        return None
    if parsed.path or parsed.query or parsed.fragment:
        return None

    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    authority = f"{host}:{port}" if port is not None else host
    return f"{parsed.scheme.lower()}://{authority}"


def _configured_origins(values: str | Iterable[str]) -> set[str]:
    if isinstance(values, str):
        candidates = values.split(",")
    else:
        candidates = values

    normalized: set[str] = set()
    for candidate in candidates:
        origin = _normalize_origin(candidate)
        if origin:
            normalized.add(origin)
    return normalized


def is_browser_origin_allowed(
    origin: str,
    *,
    configured_origins: str | Iterable[str] = (),
    production: bool,
) -> bool:
    """Evaluate the single project-scoped browser-origin policy."""
    normalized = _normalize_origin(origin)
    if not normalized:
        return False

    if normalized in _configured_origins(configured_origins):
        return True
    if normalized in _CANONICAL_ORIGINS:
        return True
    if _QUEEN_FIREBASE_PREVIEW.fullmatch(normalized):
        return True

    if production:
        return False

    parsed = urlsplit(normalized)
    if parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return True
    return bool(_DEV_SERVICE_ORIGIN.fullmatch(normalized))


def _append_vary_origin(headers: list[tuple[str, str]]) -> None:
    for index, (name, value) in enumerate(headers):
        if name.lower() != "vary":
            continue
        tokens = [token.strip() for token in value.split(",") if token.strip()]
        if not any(token.lower() == "origin" for token in tokens):
            tokens.append("Origin")
        headers[index] = (name, ", ".join(tokens))
        return
    headers.append(("Vary", "Origin"))


class CorsOriginBoundaryMiddleware:
    """Make one outer middleware authoritative for all browser CORS headers."""

    def __init__(
        self,
        app: Callable,
        *,
        configured_origins: str | Iterable[str] = (),
        production: bool,
    ) -> None:
        self.app = app
        self.configured_origins = configured_origins
        self.production = production

    def __call__(self, environ, start_response):
        origin = environ.get("HTTP_ORIGIN", "")
        allowed = is_browser_origin_allowed(
            origin,
            configured_origins=self.configured_origins,
            production=self.production,
        )

        def boundary_start_response(status, response_headers, exc_info=None):
            headers = [
                (name, value)
                for name, value in response_headers
                if name.lower() not in _CORS_RESPONSE_HEADERS
            ]
            _append_vary_origin(headers)

            if allowed:
                headers.extend(
                    [
                        ("Access-Control-Allow-Origin", _normalize_origin(origin) or origin),
                        ("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS"),
                        (
                            "Access-Control-Allow-Headers",
                            "Content-Type,Authorization,X-QC-API-Key,X-QC-Admin-Key",
                        ),
                        ("Access-Control-Max-Age", "3600"),
                    ]
                )

            return start_response(status, headers, exc_info)

        return self.app(environ, boundary_start_response)
