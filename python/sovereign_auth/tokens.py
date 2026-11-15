"""Tokens (wire contract, section 6); the port of src/tokens.js.

v1.<payload>.<signature>: the payload base64url JSON, the signature Ed25519 over the ASCII bytes of
"v1.<payload>". There is no algorithm field and nothing to negotiate; the key is the snapshot key the
payload's kid names. Assurance cookies and action tokens both use it.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ._js import parse_json, safe_integer

VERSION = "v1"
MAX_TOKEN_LENGTH = 4096
MAX_FUTURE_SECONDS = 30
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")


def encode_base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_base64url(text: Any) -> bytes | None:
    """Strict base64url: the alphabet, no padding, and the one canonical spelling of the bytes, so a token
    can't be re-spelled (spare bits set, say) and still verify."""
    if not isinstance(text, str) or not _BASE64URL.fullmatch(text):
        return None
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None
    return raw if encode_base64url(raw) == text else None


def _utf16_length(text: str) -> int:
    """String length as JavaScript counts it, in UTF-16 code units."""
    return len(text) + sum(1 for ch in text if ord(ch) > 0xFFFF)


def sign_token(payload: Mapping[str, Any], private_key: Ed25519PrivateKey) -> str:
    """Home Base's side, and the tests'. The payload must name its kid."""
    if not isinstance(payload, Mapping) or not isinstance(payload.get("kid"), str) or not payload["kid"]:
        raise ValueError("a token payload names its kid")
    encoded = encode_base64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    signed = f"{VERSION}.{encoded}"
    return f"{signed}.{encode_base64url(private_key.sign(signed.encode('ascii')))}"


@dataclass(frozen=True)
class Verified:
    ok: bool
    payload: dict | None = None
    reason: str | None = None


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _is_seconds(value: Any) -> bool:
    number = safe_integer(value)
    return number is not None and number >= 0


def verify_token(token: Any, *, keys: Mapping[str, Ed25519PublicKey], now: Callable[[], float] = _now_ms) -> Verified:
    """Checks the format, the signature against keys[kid] and the token's own times. Returns Verified(ok=True,
    payload=...) or Verified(ok=False, reason=...): malformed, unknown_kid, bad_signature, expired or
    not_yet_valid. What the payload claims is the caller's to check."""
    if not isinstance(token, str) or _utf16_length(token) > MAX_TOKEN_LENGTH:
        return Verified(False, reason="malformed")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != VERSION:
        return Verified(False, reason="malformed")
    payload_bytes = decode_base64url(parts[1])
    signature = decode_base64url(parts[2])
    if payload_bytes is None or signature is None:
        return Verified(False, reason="malformed")
    try:
        payload = parse_json(payload_bytes.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):  # nesting deeper than Python's parser goes, before any signature check
        return Verified(False, reason="malformed")
    if not isinstance(payload, dict):
        return Verified(False, reason="malformed")
    if not isinstance(payload.get("kid"), str) or not _is_seconds(payload.get("iat")) or not _is_seconds(payload.get("exp")):
        return Verified(False, reason="malformed")
    key = keys.get(payload["kid"]) if keys is not None else None
    if key is None:
        return Verified(False, reason="unknown_kid")
    try:
        key.verify(signature, f"{parts[0]}.{parts[1]}".encode("ascii"))
    except (InvalidSignature, ValueError):
        return Verified(False, reason="bad_signature")
    seconds = math.floor(now() / 1000)
    if payload["exp"] <= seconds:
        return Verified(False, reason="expired")
    if payload["iat"] > seconds + MAX_FUTURE_SECONDS:
        return Verified(False, reason="not_yet_valid")
    return Verified(True, payload=payload)
