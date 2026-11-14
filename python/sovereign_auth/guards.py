"""Request guards (wire contract, section 4); the port of src/guards.js.

Every service hostname in a tailnet is the same browser site (D20: ts.net is a public suffix), so SameSite
cookies give no isolation between apps. These guards do: a mutation must come from this hostname's own
pages, and on a strict hostname nothing but its own pages and top-level navigations reaches the app.

The core works on plain request data: a method and a mapping of lower-case header names to a value, or to a
list of values for a header sent more than once (as `headers_from_asgi` builds them). Every adapter and the
conformance vectors share this one decision.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ._js import js_trim

SAFE_METHODS = frozenset({"GET", "HEAD"})
FETCH_SITES = frozenset({"same-origin", "same-site", "cross-site", "none"})
DEFAULT_CONTENT_TYPES = ("application/json",)
DEFAULT_PORTS = {"https": 443, "http": 80}

MESSAGES = {
    "fetch_metadata_missing": "This address accepts requests only from browsers that send fetch metadata.",
    "fetch_metadata_malformed": "The request carries malformed fetch metadata.",
    "not_same_origin": "This address accepts only its own pages and top-level navigations.",
    "origin_missing": "Changes need an Origin header.",
    "origin_mismatch": "Changes are accepted only from this address's own pages.",
    "fetch_site": "Changes are accepted only from this address's own pages.",
    "content_type": "Changes are accepted only as application/json.",
}

_HOST = re.compile(r"^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*\.?|\[[0-9a-f:.]+\])$")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    status: int | None = None
    reason: str | None = None
    message: str | None = None


ALLOWED = Decision(True)


def _refused(reason: str) -> Decision:
    return Decision(False, 403, reason, MESSAGES[reason])


def normalize_origin(value: Any) -> str:
    """An exact origin: scheme, host and port, nothing else. 'https://example.ts.net/' and
    'https://EXAMPLE.ts.net' both normalize to 'https://example.ts.net'; a path, query, fragment or
    credentials is a configuration mistake. Stricter than the WHATWG parser Node uses: whitespace, control
    characters, backslashes and non-ASCII hosts are refused rather than repaired."""
    text = str(value)
    if not text or any(ch <= " " or ch == "\x7f" or ch == "\\" for ch in text) or not text.isascii():
        raise ValueError(f"not an origin: {value}")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise ValueError(f"not an origin: {value}") from None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise ValueError(f"not an http(s) origin: {value}")
    if "?" in text or "#" in text or "@" in parts.netloc or parts.path not in ("", "/"):
        raise ValueError(f"an origin has no path, query or credentials: {value}")
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    if not host or not _HOST.fullmatch(host):
        raise ValueError(f"not an origin: {value}")
    if port is not None and port != DEFAULT_PORTS[scheme]:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def header(headers: Mapping[str, Any] | None, name: str) -> str | None:
    """One header's value as text; a repeated header's values joined with ', ', as Node joins them."""
    value = headers.get(name) if headers is not None else None
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    return str(value)


def _check_isolation(method: str, headers: Mapping[str, Any]) -> Decision | None:
    """Resource isolation (D20), for strict hostnames: a request reaches the app only if the browser says it
    came from this origin, or it is a top-level document navigation. Anything else from a sibling hostname
    (fetch, image, script, iframe, form post) is refused, and so is a request with no fetch metadata."""
    site = header(headers, "sec-fetch-site")
    if site is None:
        return _refused("fetch_metadata_missing")
    if site not in FETCH_SITES:
        return _refused("fetch_metadata_malformed")
    if site == "same-origin":
        return None
    navigation = (
        method == "GET"
        and header(headers, "sec-fetch-mode") == "navigate"
        and header(headers, "sec-fetch-dest") == "document"
    )
    return None if navigation else _refused("not_same_origin")


def _check_mutation(method: str, headers: Mapping[str, Any], origins: frozenset[str], content_types: frozenset[str]) -> Decision | None:
    """The mutation guard, for every method but GET and HEAD on every hostname. The Origin must be exactly
    this hostname's (same-site is not enough, D20), and the body JSON, which no cross-site form can send."""
    origin = header(headers, "origin")
    if origin is None or origin == "":
        return _refused("origin_missing")
    if origin not in origins:
        return _refused("origin_mismatch")
    site = header(headers, "sec-fetch-site")
    if site is not None and site != "same-origin":
        return _refused("fetch_site")
    content_type = js_trim((header(headers, "content-type") or "").split(";")[0]).lower()
    if content_type not in content_types:
        return _refused("content_type")
    return None


class RequestGuard:
    """create_request_guard(origin=..., isolate=True, content_types=...):

    - origin: this hostname's origin, or a list of them. Requests are compared to it exactly.
    - isolate: apply resource isolation (on for sensitive apps and Home Base admin; a low-friction app on the
      shared hostname turns it off and keeps only the mutation guard).
    - content_types: the media types a mutation may carry. Widening it (a file upload) keeps the Origin
      check but loses the content type's protection in browsers without fetch metadata.
    """

    def __init__(self, origin: str | Iterable[str], *, isolate: bool = True, content_types: Iterable[str] = DEFAULT_CONTENT_TYPES):
        items = [origin] if isinstance(origin, str) else list(origin or [])
        if not items:
            raise ValueError("a request guard needs this hostname's origin")
        self.origins = frozenset(normalize_origin(item) for item in items)
        types = [content_types] if isinstance(content_types, str) else list(content_types)
        self.content_types = frozenset(js_trim(str(item)).lower() for item in types)
        if not self.content_types:
            raise ValueError("a request guard needs at least one content type")
        self.isolate = bool(isolate)

    def check(self, method: str = "GET", headers: Mapping[str, Any] | None = None) -> Decision:
        verb = str(method).upper()
        headers = headers or {}
        decision = _check_isolation(verb, headers) if self.isolate else None
        if decision is None and verb not in SAFE_METHODS:
            decision = _check_mutation(verb, headers, self.origins, self.content_types)
        return decision or ALLOWED


def create_request_guard(origin: str | Iterable[str], *, isolate: bool = True, content_types: Iterable[str] = DEFAULT_CONTENT_TYPES) -> RequestGuard:
    return RequestGuard(origin, isolate=isolate, content_types=content_types)
