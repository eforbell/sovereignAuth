"""Assurance (wire contract, sections 7 to 9; D12); the port of src/assurance.js.

An app names the protected action by its policy key, and the library decides from the policy matrix whether
this request meets it: a member for 'tailnet', a fresh enough assurance cookie for 'session' and 'recent',
and a redeemed action token bound to this exact request for 'every-time'. Anything short of that is answered
before the app's handler runs.

Every-time policies are Home Base's own (they need an administrator), and Home Base does not yet serve the
per-app redemption socket, so this port has no socket client: pass `redeem` to check every-time actions.
Without one, they are refused as 'unavailable', as they would be with Home Base down.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import math
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

from ._js import is_truthy, js_number, js_trim, safe_integer, strict_equal, to_string, utf8
from .identity import Identity
from .snapshot import Member, Snapshot
from .tokens import encode_base64url, verify_token

COOKIE_NAME = "__Host-sv_assurance"
ACTION_HEADER = "x-sovereign-action-token"
KINDS = frozenset({"synced", "device-bound", "hardware"})
MAX_ACTION_LIFETIME_SECONDS = 60
_HOSTNAME = re.compile(r"[a-z0-9.-]+")

# The same file as src/policy.json (a test keeps them identical): pip installs only python/.
POLICY: dict = json.loads(resources.files(__package__).joinpath("policy.json").read_text("utf-8"))

Redeem = Callable[..., Any]


def policy_for(key: str) -> dict:
    policy = POLICY["policies"].get(key) if isinstance(key, str) else None
    if policy is None:
        raise ValueError(f"no assurance policy named {key}")
    return policy


def _check_target(target: Any) -> None:
    if not isinstance(target, str) or "\r" in target or "\n" in target:
        raise ValueError("an action target is a string with no line breaks")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def request_digest(*, method: str, url: str, body: bytes | str | None, target: str) -> str:
    """The request digest an action token is bound to (section 9). body is the raw bytes the app received;
    None is no body (Node's undefined)."""
    _check_target(target)
    if body is None:
        data = b""
    elif isinstance(body, str):
        data = utf8(body)
    elif isinstance(body, (bytes, bytearray, memoryview)):
        data = bytes(body)
    else:
        raise TypeError("the request digest needs the raw body bytes, not a parsed body")
    text = "\n".join(["sovereign-action/1", to_string(method).upper(), to_string(url), encode_base64url(_sha256(data)), target])
    return encode_base64url(_sha256(utf8(text)))


def _has_body(headers: Mapping[str, Any]) -> bool:
    """headers['transfer-encoding'] !== undefined || Number(headers['content-length'] || 0) > 0: a header
    present with any value, even None (null), counts."""
    length = headers.get("content-length")
    return "transfer-encoding" in headers or js_number(length if is_truthy(length) else 0) > 0


def _cookie_values(headers: Mapping[str, Any] | None, name: str) -> list[str]:
    raw = headers.get("cookie") if headers is not None else None
    if isinstance(raw, (list, tuple)):
        text = "; ".join("" if item is None else to_string(item) for item in raw)
    else:
        text = raw if isinstance(raw, str) else ""
    values = []
    for pair in text.split(";"):
        at = pair.find("=")
        if at >= 0 and js_trim(pair[:at]) == name:
            values.append(js_trim(pair[at + 1 :]))
    return values


def assurance_cookie(headers: Mapping[str, Any] | None) -> tuple[str | None, str | None]:
    """Only a cookie named exactly __Host-sv_assurance counts. A sibling hostname can plant a same-named
    cookie without the prefix (D20), but not one with it; two with the prefixed name is not a question to
    guess at. Returns (token, None) or (None, reason)."""
    values = _cookie_values(headers, COOKIE_NAME)
    if len(values) > 1:
        return None, "duplicate_cookie"
    return (values[0], None) if values else (None, "no_cookie")


def _claims_hold(payload: dict, *, typ: str, snapshot: Snapshot, member: Member, hostname: str, policy: dict) -> str | None:
    """What every token says about who and where, checked the same way for cookies and action tokens."""
    if not strict_equal(payload.get("typ"), typ):
        return "wrong_type"
    if not strict_equal(payload.get("household"), snapshot.household):
        return "wrong_household"
    if not strict_equal(payload.get("aud"), hostname):
        return "wrong_audience"
    if not strict_equal(payload.get("sub"), member.user_id):
        return "wrong_member"
    if not strict_equal(payload.get("epoch"), member.epoch):
        return "stale_epoch"
    if not strict_equal(payload.get("global_epoch"), snapshot.global_epoch):
        return "stale_global_epoch"
    kind = payload.get("kind")
    if not isinstance(kind, str) or kind not in KINDS:
        return "wrong_kind"
    if policy["kind"] == "hardware" and kind != "hardware":
        return "wrong_kind"
    return None


@dataclass(frozen=True)
class AssuranceDecision:
    allowed: bool
    status: int | None = None
    body: dict | None = None
    reason: str | None = None
    member: Member | None = None
    level: str | None = None


@dataclass
class AssuranceRequest:
    method: str
    url: str
    headers: Mapping[str, Any] = field(default_factory=dict)
    body: bytes | str | None = None


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


async def _resolve(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class Assurance:
    """Assurance(app_id=..., hostname=..., identity=..., redeem=..., is_administrator=...).check(policy_key,
    request, target='') returns an AssuranceDecision: allowed with the member and level, or refused with the
    status and JSON body to answer. hostname is this app's service hostname, which cookies and tokens must
    name exactly. is_administrator(member) is needed only for Home Base's administrator policies; it may be
    async, and only True counts. redeem(token=, policy=, target=, digest=) may be async and answers a dict
    with 'redeemed' (and 'reason' when not)."""

    def __init__(
        self,
        *,
        app_id: str,
        hostname: str,
        identity: Identity,
        redeem: Redeem | None = None,
        is_administrator: Callable[[Member], bool | Awaitable[bool]] | None = None,
        now: Callable[[], float] = _now_ms,
        log: Callable[[str], None] = lambda message: None,
    ):
        if not isinstance(app_id, str) or not app_id:
            raise ValueError("assurance needs the app's ID")
        if not isinstance(hostname, str) or not _HOSTNAME.fullmatch(hostname):
            raise ValueError("assurance needs this app's hostname, in lower case")
        if not isinstance(identity, Identity) or identity.mode != "tailnet" or identity.app_id != app_id:
            raise ValueError("assurance needs this app's tailnet identity (an Identity in tailnet mode)")
        self.app_id = app_id
        self.hostname = hostname
        self._identity = identity
        self._redeem = redeem
        self._is_administrator = is_administrator
        self._now = now
        self._log = log

    @staticmethod
    def _refuse(status: int, body: dict, reason: str) -> AssuranceDecision:
        return AssuranceDecision(False, status, body, reason)

    def _step_up(self, key: str, policy: dict, reason: str | None, **extra: Any) -> AssuranceDecision:
        body = {"error": "step_up_required", "policy": key, "level": policy["level"], "kind": policy["kind"], **extra}
        return self._refuse(401, body, reason)

    def _check_cookie(self, key: str, policy: dict, headers: Mapping[str, Any], snapshot: Snapshot, member: Member) -> AssuranceDecision | None:
        token, reason = assurance_cookie(headers)
        if not token:
            # As in Node, an empty cookie value is a step-up with no reason (reason None).
            return self._step_up(key, policy, reason)
        verified = verify_token(token, keys=snapshot.keys, now=self._now)
        if not verified.ok or verified.payload is None:
            return self._step_up(key, policy, verified.reason or "malformed")
        claims = verified.payload
        wrong = _claims_hold(claims, typ="assurance", snapshot=snapshot, member=member, hostname=self.hostname, policy=policy)
        if wrong:
            return self._step_up(key, policy, wrong)
        window = POLICY["recent_seconds"] if policy["level"] == "recent" else policy["window_seconds"]
        seconds = math.floor(self._now() / 1000)
        auth_time = safe_integer(claims.get("auth_time"))
        if auth_time is None or auth_time > claims["iat"]:
            return self._step_up(key, policy, "malformed")
        if seconds - auth_time > window:
            return self._step_up(key, policy, "too_old")
        return None

    async def _check_action_token(self, key: str, policy: dict, request: AssuranceRequest, target: str, snapshot: Snapshot, member: Member) -> AssuranceDecision | None:
        # Without the raw bytes the digest would cover an empty body, and the token would not bind what is sent.
        if request.body is None and _has_body(request.headers):
            raise ValueError("every-time actions need the raw request body")
        digest = request_digest(method=request.method, url=request.url, body=request.body, target=target)

        def challenge(reason: str) -> AssuranceDecision:
            return self._step_up(key, policy, reason, target=target, digest=digest)

        if ACTION_HEADER not in request.headers:
            return challenge("no_token")
        header = request.headers[ACTION_HEADER]
        if not isinstance(header, str):
            return challenge("malformed")
        verified = verify_token(header, keys=snapshot.keys, now=self._now)
        if not verified.ok or verified.payload is None:
            return challenge(verified.reason or "malformed")
        claims = verified.payload
        wrong = _claims_hold(claims, typ="action", snapshot=snapshot, member=member, hostname=self.hostname, policy=policy)
        if wrong:
            return challenge(wrong)
        if not strict_equal(claims.get("app"), self.app_id):
            return challenge("wrong_app")
        if not strict_equal(claims.get("act"), key):
            return challenge("wrong_action")
        if not strict_equal(claims.get("tgt"), target):
            return challenge("wrong_target")
        if not strict_equal(claims.get("dig"), digest):
            return challenge("wrong_digest")
        if claims["exp"] - claims["iat"] > MAX_ACTION_LIFETIME_SECONDS:
            return challenge("malformed")
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            return challenge("malformed")
        # Checked here, then redeemed: Home Base consumes the jti and rechecks the member as it stands now.
        result = await self._redeem_token(token=header, policy=key, target=target, digest=digest)
        if result.get("redeemed") is not True:
            # Node passes the redeemer's reason through as it is: missing is left out of the body (and is
            # 'undefined' in the log reason), null stays null.
            body: dict = {"error": "step_up_refused", "policy": key}
            if "reason" in result:
                body["reason"] = result["reason"]
            shown = "undefined" if "reason" not in result else to_string(result["reason"])
            return self._refuse(403, body, f"redemption_{shown}")
        return None

    async def _redeem_token(self, **request: str) -> dict:
        if self._redeem is None:
            return {"redeemed": False, "reason": "unavailable"}
        try:
            result = await _resolve(self._redeem(**request))
        except Exception:
            return {"redeemed": False, "reason": "unavailable"}
        return result if isinstance(result, dict) else {"redeemed": False, "reason": "unavailable"}

    async def check(self, key: str, request: AssuranceRequest, target: str = "") -> AssuranceDecision:
        policy = policy_for(key)
        if policy["level"] == "every-time":
            _check_target(target)
        if policy.get("administrator") and self._is_administrator is None:
            raise ValueError(f"policy {key} needs an administrator, so assurance needs is_administrator")
        resolution = self._identity.identify(request.headers or {})
        member, snapshot = resolution.member, resolution.snapshot
        decision: AssuranceDecision | None
        if member is None or snapshot is None:
            reason = resolution.reason or "no_identity"
            decision = self._refuse(403, {"error": "not_a_member", "reason": reason}, reason)
        elif policy.get("administrator") and (await _resolve(self._is_administrator(member))) is not True:  # type: ignore[misc]
            decision = self._refuse(403, {"error": "not_authorized", "policy": key}, "not_administrator")
        elif policy["level"] in ("session", "recent"):
            decision = self._check_cookie(key, policy, request.headers or {}, snapshot, member)
        elif policy["level"] == "every-time":
            decision = await self._check_action_token(key, policy, request, target, snapshot, member)
        else:
            decision = None
        if decision is None:
            return AssuranceDecision(True, member=member, level=policy["level"])
        path = str(request.url or "/").split("?")[0]
        self._log(f"[sovereign-auth] {key} not met for {request.method} {path}: {decision.reason}")
        return decision


def create_assurance(**options: Any) -> Assurance:
    return Assurance(**options)
