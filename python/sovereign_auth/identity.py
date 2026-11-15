"""Who is asking (wire contract, sections 2 and 3); the port of src/identity.js.

In tailnet mode the member comes from the identity headers nginx sets, looked up in the directory snapshot by
stable user ID; the login alone never identifies anyone (D1), and anything that doesn't line up exactly
means no member.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from ._js import js_trim
from .snapshot import Member, Snapshot, SnapshotState

MODES = frozenset({"local", "tailnet"})
TAGGED_LOGIN = "tagged-devices"


class Reader(Protocol):
    def current(self) -> SnapshotState: ...


@dataclass(frozen=True)
class Resolution:
    member: Member | None
    reason: str | None = None
    snapshot: Snapshot | None = None
    snapshot_reason: str | None = None


def auth_mode(value: Any) -> str:
    """SOVEREIGN_AUTH_MODE: 'local' or 'tailnet'. Anything else, including nothing, is a configuration error:
    an app must not guess which kind of sign-in protects it."""
    mode = js_trim("" if value is None else str(value))
    if mode not in MODES:
        shown = "unset" if value is None else f"'{value}'"
        raise ValueError(f"SOVEREIGN_AUTH_MODE must be local or tailnet, not {shown}")
    return mode


def require_socket_listen(listen: Any) -> str:
    """The identity headers are trustworthy only because nothing but nginx can connect to the app's socket
    (SID-002), so tailnet mode needs the app to be listening there."""
    value = js_trim("" if listen is None else str(listen))
    if not value.startswith("unix:/"):
        raise ValueError("tailnet mode needs SOVEREIGN_LISTEN=unix:<socket path>: identity headers are trusted only on the app's socket")
    return value


def _single(headers: Mapping[str, Any] | None, name: str) -> str | None:
    """A header sent once, with a value. A repeated header (a list) is not an identity."""
    value = headers.get(name) if headers is not None else None
    return value if isinstance(value, str) and value != "" else None


def resolve_member(snapshot: Snapshot, headers: Mapping[str, Any] | None, *, app_id: str) -> Resolution:
    user_id = _single(headers, "x-sovereign-user-id")
    login = _single(headers, "x-sovereign-login")
    if not user_id or not login:
        return Resolution(None, "no_identity")
    if login == TAGGED_LOGIN:
        return Resolution(None, "tagged")
    member = snapshot.by_user_id.get(user_id)
    if member is None:
        return Resolution(None, "unknown_user")
    if member.login != login:
        return Resolution(None, "login_mismatch")
    if member.status != "active":
        return Resolution(None, "disabled")
    if app_id not in member.apps:
        return Resolution(None, "no_access")
    return Resolution(member)


class Identity:
    """Identity(app_id=..., mode=..., listen=..., reader=...).identify(headers) returns a Resolution: a member
    only in tailnet mode, with a good snapshot, and when every check passes. In local mode it always answers
    'local_mode', and the app uses its own sign-in."""

    def __init__(self, *, app_id: str, mode: Any, listen: Any = None, reader: Reader | None = None):
        if not isinstance(app_id, str) or not app_id:
            raise ValueError("an identity needs the app's ID")
        self.app_id = app_id
        self.mode = auth_mode(mode)
        if self.mode == "tailnet":
            require_socket_listen(listen)
            if reader is None or not callable(getattr(reader, "current", None)):
                raise ValueError("tailnet mode needs a snapshot reader")
        self._reader = reader

    def identify(self, headers: Mapping[str, Any] | None) -> Resolution:
        if self.mode == "local":
            return Resolution(None, "local_mode")
        state = self._reader.current()  # type: ignore[union-attr]
        if not state.ok or state.snapshot is None:
            return Resolution(None, "no_snapshot", snapshot_reason=state.reason)
        result = resolve_member(state.snapshot, headers, app_id=self.app_id)
        return Resolution(result.member, result.reason, state.snapshot)


def create_identity(*, app_id: str, mode: Any, listen: Any = None, reader: Reader | None = None) -> Identity:
    return Identity(app_id=app_id, mode=mode, listen=listen, reader=reader)
