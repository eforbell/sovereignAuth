"""OAuth and other external callbacks (wire contract, section 10; D22); the port of src/oauth.js.

The one route allowed to act on URL parameters, and only in three steps. Start (a guarded POST) stores a
single-use state record bound to the member, this hostname and a __Host- correlation cookie. Landing (the
provider's redirect, a GET) changes nothing and needs no cookie: it renders a page that strips code and state
from the address bar and sends them once. Completion (a same-origin JSON POST from that page, behind the
mutation guard) takes the record, checks everything, and only then hands the app the code to exchange.

The boundary is the origin. The mutation guard keeps every other origin, sibling hostnames included, away
from the completion route. Pages on this origin are trusted: any of them could fetch or frame the landing
page and read what it reads, so nothing here pretends to tell them apart.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import inspect
import json
import re
import secrets
import time
import threading
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

from ._js import is_truthy, strict_equal
from .assurance import _cookie_values
from .guards import normalize_origin
from .snapshot import Member
from .tokens import _utf16_length

COOKIE_NAME = "__Host-sv_oauth"
MAX_AGE_SECONDS = 600
MAX_CODE_LENGTH = 4096
_STATE = re.compile(r"[A-Za-z0-9_-]{43}")
_HOSTNAME = re.compile(r"[a-z0-9.-]+")
_UNSAFE_PATH = re.compile(r"[\x00-\x20\x7f-\x9f\\:]")
_UNSAFE_LANDING = re.compile(r"[?#\\\x00-\x20\x7f-\x9f]")
_NONCE = re.compile(r"[A-Za-z0-9+/=_-]+")


def _random() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def pkce_challenge(verifier: str) -> str:
    """PKCE S256 (RFC 7636): the challenge is base64url(SHA-256(verifier))."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _same_text(a: Any, b: Any) -> bool:
    return hmac.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


@dataclass(frozen=True)
class OAuthRecord:
    state: str
    user_id: str
    hostname: str
    correlation: str
    code_verifier: str | None
    created: float  # milliseconds since the epoch, as the clock gave it
    data: Any = None


class MemoryStateStore:
    """The default store: in memory, so a restart forgets flows in progress (they last ten minutes anyway).
    Any store works that provides put(record) and take(state), where take returns the record at most once,
    ever: whoever takes it, it is gone. Either may be async."""

    def __init__(self, *, max_entries: int = 1000, now: Callable[[], float] = _now_ms):
        self._records: OrderedDict[str, OAuthRecord] = OrderedDict()
        self._max_entries = max_entries
        self._now = now
        self._lock = threading.Lock()  # FastAPI may call from several threads

    def put(self, record: OAuthRecord) -> None:
        with self._lock:
            for state in list(self._records):
                entry = self._records[state]
                if self._now() - entry.created > MAX_AGE_SECONDS * 1000 or len(self._records) >= self._max_entries:
                    del self._records[state]
                else:
                    break
            self._records[record.state] = record

    def take(self, state: str) -> OAuthRecord | None:
        with self._lock:
            return self._records.pop(state, None)


def _oauth_cookie(headers: Mapping[str, Any] | None) -> tuple[str | None, str | None]:
    values = _cookie_values(headers, COOKIE_NAME)
    if len(values) > 1:
        return None, "duplicate_cookie"
    return (values[0], None) if values else (None, "no_cookie")


def _set_cookie(value: str, max_age: int) -> str:
    return f"{COOKIE_NAME}={value}; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age={max_age}"


CLEAR_COOKIE = _set_cookie("", 0)


def _origin(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return parts.scheme.lower(), parts.netloc.lower()


def _check_same_origin_path(value: Any, what: str, landing_url: str) -> str:
    """A path the landing page posts to or moves on to. Browsers drop leading control characters and read a
    backslash as a slash, so those are refused outright; what is left must resolve, from the landing page,
    to this origin."""
    if not isinstance(value, str) or not value or _UNSAFE_PATH.search(value):
        raise ValueError(f"{what} must be a path on this hostname")
    # A browser reads any run of two or more leading slashes as a host ('///evil.example' is evil.example);
    # urljoin reads three or more as a path. With no colon, backslash or control character left, a value
    # not starting with '//' can only resolve to this origin.
    if value.startswith("//"):
        raise ValueError(f"{what} must be a path on this hostname")
    if _origin(urljoin(landing_url, value)) != _origin(landing_url):
        raise ValueError(f"{what} must be a path on this hostname")
    return value


def _script_json(value: str) -> str:
    """A setting passed into the landing page's script as JSON that can't close the script element."""
    return json.dumps(value).replace("<", "\\u003c")


def _landing_script(completion_path: str, done_path: str) -> str:
    return f"""(() => {{
  const say = (text) => {{ document.getElementById('status').textContent = text; }};
  const params = new URLSearchParams(location.search);
  const code = params.get('code');
  const state = params.get('state');
  const error = params.get('error');
  history.replaceState(null, '', location.pathname);
  if (!code || !state) {{ say(error ? 'The provider did not link the account (' + error + ').' : 'Nothing to finish here.'); return; }}
  fetch({_script_json(completion_path)}, {{
    method: 'POST',
    credentials: 'same-origin',
    headers: {{ 'content-type': 'application/json' }},
    body: JSON.stringify({{ code, state }}),
  }}).then((response) => response.json().catch(() => ({{}})).then((body) => {{
    if (response.ok) location.replace({_script_json(done_path)});
    else say('Linking did not finish (' + (body.reason || response.status) + '). Start again from the app.');
  }})).catch(() => say('Linking did not finish. Start again from the app.'));
}})();"""


@dataclass(frozen=True)
class OAuthStart:
    state: str
    code_challenge: str | None
    code_challenge_method: str | None
    set_cookie: str


@dataclass(frozen=True)
class OAuthPage:
    status: int
    headers: dict
    body: str


@dataclass(frozen=True)
class OAuthCompletion:
    ok: bool
    clear_cookie: str
    code: str | None = None
    code_verifier: str | None = None
    data: Any = None
    status: int | None = None
    body: dict | None = None
    reason: str | None = None


async def _resolve(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class OAuthFlow:
    """OAuthFlow(hostname=..., landing_path=..., completion_path=..., done_path='.', store=..., now=...):

    - hostname: this app's service hostname (lower case), which the record must name;
    - landing_path: the provider's redirect target as the browser sees it (with any mount prefix), so that
      landing_url is the redirect URI to register;
    - completion_path, done_path: where the landing page posts, and where it goes after; relative to it or
      absolute paths on this hostname.
    """

    def __init__(
        self,
        *,
        hostname: str,
        landing_path: str,
        completion_path: str,
        done_path: str = ".",
        store: Any = None,
        now: Callable[[], float] = _now_ms,
    ):
        if not isinstance(hostname, str) or not _HOSTNAME.fullmatch(hostname):
            raise ValueError("an OAuth flow needs this app's hostname, in lower case")
        # Node builds the landing URL with the URL parser, which refuses a host like 1.2.3.999; a hostname
        # the parser would refuse or rewrite is refused here too.
        try:
            if normalize_origin(f"https://{hostname}") != f"https://{hostname}":
                raise ValueError
        except ValueError:
            raise ValueError("an OAuth flow needs this app's hostname, in lower case") from None
        if (
            not isinstance(landing_path, str)
            or not landing_path.startswith("/")
            or landing_path.startswith("//")
            or _UNSAFE_LANDING.search(landing_path)
        ):
            raise ValueError("landing_path is the callback's absolute path as the browser sees it")
        store = store if store is not None else MemoryStateStore(now=now)
        if not callable(getattr(store, "put", None)) or not callable(getattr(store, "take", None)):
            raise ValueError("an OAuth state store needs put(record) and take(state)")
        self.hostname = hostname
        self.landing_url = f"https://{hostname}{landing_path}"
        self.completion_path = _check_same_origin_path(completion_path, "completion_path", self.landing_url)
        self.done_path = _check_same_origin_path(done_path, "done_path", self.landing_url)
        self._store = store
        self._now = now

    async def start(self, member: Member, *, pkce: bool = True, data: Any = None) -> OAuthStart:
        """Step 1, from the app's guarded POST. The app sends the browser to the provider with state (and the
        PKCE challenge, unless the provider has no PKCE) and sets the cookie. data is the app's own, returned
        at completion (which provider, say)."""
        user_id = getattr(member, "user_id", None)
        if not isinstance(user_id, str) or not user_id:
            raise ValueError("an OAuth flow starts for a member")
        verifier = _random() if pkce else None
        record = OAuthRecord(
            state=_random(),
            user_id=user_id,
            hostname=self.hostname,
            correlation=_random(),
            code_verifier=verifier,
            created=self._now(),
            data=data,
        )
        await _resolve(self._store.put(record))
        return OAuthStart(
            state=record.state,
            code_challenge=pkce_challenge(verifier) if verifier else None,
            code_challenge_method="S256" if verifier else None,
            set_cookie=_set_cookie(record.correlation, MAX_AGE_SECONDS),
        )

    def landing(self, *, nonce: str | None = None) -> OAuthPage:
        """Step 2, the provider's redirect: the same page for every request, no cookie read, nothing stored.
        It arrives with the code in its address, so it sends no Referer anywhere."""
        if nonce is not None and (not isinstance(nonce, str) or not _NONCE.fullmatch(nonce)):
            raise ValueError("a CSP nonce is base64")
        nonce_attribute = f' nonce="{nonce}"' if nonce else ""
        body = (
            '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1"><title>Linking…</title></head>\n'
            '<body><p id="status">Finishing the link…</p>\n'
            f"<script{nonce_attribute}>{_landing_script(self.completion_path, self.done_path)}</script></body></html>\n"
        )
        headers = {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
            "referrer-policy": "no-referrer",
        }
        return OAuthPage(200, headers, body)

    async def complete(self, *, member: Member | None, headers: Mapping[str, Any] | None, body: Any) -> OAuthCompletion:
        """Step 3, behind the mutation guard. The record is taken before anything else is checked, so a code
        and state can be tried once, by anyone, and then never again."""

        def refuse(status: int, reason: str | None) -> OAuthCompletion:
            return OAuthCompletion(False, CLEAR_COOKIE, status=status, body={"error": "oauth_refused", "reason": reason}, reason=reason)

        code = body.get("code") if isinstance(body, dict) else None
        state = body.get("state") if isinstance(body, dict) else None
        if (
            not isinstance(code, str)
            or not code
            or _utf16_length(code) > MAX_CODE_LENGTH
            or not isinstance(state, str)
            or not _STATE.fullmatch(state)
        ):
            return refuse(400, "malformed")
        record = await _resolve(self._store.take(state))
        if record is None:
            return refuse(403, "unknown_state")
        age = self._now() - record.created
        if not 0 <= age <= MAX_AGE_SECONDS * 1000:
            return refuse(403, "expired")
        user_id = getattr(member, "user_id", None)
        if not is_truthy(user_id) or not strict_equal(record.user_id, user_id):
            return refuse(403, "wrong_member")
        if record.hostname != self.hostname:
            return refuse(403, "wrong_hostname")
        cookie, reason = _oauth_cookie(headers)
        if not cookie:
            # As in Node, an empty cookie value is refused with no reason (reason is None).
            return refuse(403, reason)
        if not _same_text(cookie, record.correlation):
            return refuse(403, "wrong_correlation")
        return OAuthCompletion(True, CLEAR_COOKIE, code=code, code_verifier=record.code_verifier, data=record.data)


def create_oauth_flow(**options: Any) -> OAuthFlow:
    return OAuthFlow(**options)
