"""ASGI adapter for the request guard (FastAPI, Starlette, or any ASGI app); the port of src/adapters.js.

GuardMiddleware takes the guard's decision as is and only decides what happens to a refused request:

- 'enforce' answers 403 with the refusal body (wire contract, section 4.4) and stops the request;
- 'report' logs what enforce would refuse and lets the request through;
- 'off' lets everything through silently, so callers keep one code path behind a flag.

    app.add_middleware(GuardMiddleware, guard=create_request_guard(origin), mode="enforce")
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from .guards import Decision, RequestGuard

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

MODES = frozenset({"off", "report", "enforce"})
FETCH_METADATA_VARY = ("Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest")
_logger = logging.getLogger("sovereign_auth")


def headers_from_scope(scope: Scope) -> dict[str, str | list[str]]:
    """The request's headers as the library reads them: lower-case names, each mapped to its value, or to a
    list of values when the client sent the header more than once (an identity header sent twice is then
    no identity, and a guard joins the values as Node does)."""
    headers: dict[str, str | list[str]] = {}
    for raw_name, raw_value in scope.get("headers") or []:
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        current = headers.get(name)
        if current is None:
            headers[name] = value
        elif isinstance(current, list):
            current.append(value)
        else:
            headers[name] = [current, value]
    return headers


def _vary_on_fetch_metadata(response_headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    """What an isolating guard lets through depends on the fetch metadata, so every response it passes on
    has to say so; otherwise a browser can serve a response cached for the app's own page to a sibling
    hostname's script or fetch. Values the app set are kept."""
    values: list[str] = []
    others: list[tuple[bytes, bytes]] = []
    for name, value in response_headers:
        if name.lower() == b"vary":
            values.extend(part.strip() for part in value.decode("latin-1").split(",") if part.strip())
        else:
            others.append((name, value))
    if "*" not in values:
        present = {value.lower() for value in values}
        values.extend(name for name in FETCH_METADATA_VARY if name.lower() not in present)
    return others + [(b"vary", ", ".join(values).encode("latin-1"))]


async def send_json(send: Send, status: int, body: dict, *, extra_headers: list[tuple[bytes, bytes]] | None = None) -> None:
    """Answers a refusal (the guard's, or an assurance decision's status and body) with no caching."""
    payload = json.dumps(body).encode("utf-8")
    headers = [
        (b"content-type", b"application/json; charset=utf-8"),
        (b"content-length", str(len(payload)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ] + list(extra_headers or [])
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload})


def refusal_body(decision: Decision) -> dict:
    return {"error": "request_refused", "reason": decision.reason, "message": decision.message}


def describe_refusal(decision: Decision, method: str, path: str, headers: dict, mode: str) -> str:
    """The method, the path without its query (a query can carry an OAuth code), the reason and the two
    headers that decided it. Never the identity headers or cookies."""
    verb = "would refuse" if mode == "report" else "refused"
    origin = headers.get("origin", "-")
    site = headers.get("sec-fetch-site", "-")
    return f"[sovereign-auth] {verb} {method} {path}: {decision.reason} (origin {origin}, sec-fetch-site {site})"


class GuardMiddleware:
    def __init__(self, app: ASGIApp, *, guard: RequestGuard, mode: str = "enforce", log: Callable[[str], None] | None = None):
        if mode not in MODES:
            raise ValueError(f"request guard mode must be off, report or enforce, not {mode}")
        if not isinstance(guard, RequestGuard):
            raise ValueError("GuardMiddleware needs a RequestGuard")
        self.app = app
        self.guard = guard
        self.mode = mode
        self.log = log or _logger.warning

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or self.mode == "off":
            await self.app(scope, receive, send)
            return
        headers = headers_from_scope(scope)
        decision = self.guard.check(scope.get("method", "GET"), headers)

        # Report mode too: a cached response would hide from the log a request that enforce would refuse.
        async def send_with_vary(message: Message) -> None:
            if message.get("type") == "http.response.start":
                message = dict(message)
                message["headers"] = _vary_on_fetch_metadata(list(message.get("headers") or []))
            await send(message)

        respond = send_with_vary if self.guard.isolate else send
        if not decision.allowed:
            self.log(describe_refusal(decision, scope.get("method", "GET"), scope.get("path", "/"), headers, self.mode))
            if self.mode == "enforce":
                await send_json(respond, decision.status or 403, refusal_body(decision))
                return
        await self.app(scope, receive, respond)
