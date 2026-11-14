"""The directory snapshot (wire contract, section 5; D18); the port of src/snapshot.js, reader side only.

Home Base publishes the household directory as a file apps can read but not write, and trust comes from who
owns it, not from a signature: the file and its directory must belong to the Home Base user and be writable
by no one else, and nothing on the way there may be a symlink or writable by anyone but root. Writing the
snapshot is Home Base's job and stays in the Node library.
"""

from __future__ import annotations

import base64
import binascii
import calendar
import errno
import os
import re
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._js import parse_json, safe_integer

DEFAULT_SNAPSHOT_PATH = "/var/lib/sovereign-home/identity/snapshot.json"
FORMAT = 1
MAX_AGE_MS = 120_000
RECHECK_MS = 5_000
MAX_FUTURE_MS = 30_000
MAX_BYTES = 1024 * 1024
ROLES = frozenset({"parent", "kid"})
STATUSES = frozenset({"active", "disabled"})
WRITABLE_BY_OTHERS = 0o022

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
# RFC 3339 with a zone, the form Home Base writes (Date.prototype.toISOString). Date.parse in Node reads
# more spellings than this; anything else is refused here as malformed, which only ever fails closed.
_TIMESTAMP = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(?:(Z)|([+-])(\d{2}):(\d{2}))$"
)


class SnapshotError(Exception):
    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def _fail(reason: str, message: str) -> None:
    raise SnapshotError(reason, message)


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and len(value) > 0


def _count(value: Any) -> int | None:
    number = safe_integer(value)
    return number if number is not None and number >= 0 else None


@dataclass(frozen=True)
class Member:
    user_id: str
    member_id: str
    login: str
    name: str
    role: str
    status: str
    epoch: int
    apps: tuple[str, ...]


@dataclass(frozen=True)
class Snapshot:
    household: str
    generation: int
    written_at: int  # milliseconds since the epoch
    global_epoch: int
    keys: Mapping[str, Ed25519PublicKey]
    members: tuple[Member, ...]
    by_user_id: Mapping[str, Member]


def parse_timestamp_ms(text: str) -> int | None:
    match = _TIMESTAMP.match(text)
    if not match:
        return None
    year, month, day, hour, minute = (int(match.group(i)) for i in range(1, 6))
    second = int(match.group(6) or 0)
    millis = int((match.group(7) or "0")[:3].ljust(3, "0"))
    if not (1 <= month <= 12 and 1 <= day <= calendar.monthrange(year, month)[1]):
        return None
    if hour > 23 or minute > 59 or second > 59:
        return None
    offset = 0
    if match.group(9):
        off_hour, off_minute = int(match.group(10)), int(match.group(11))
        if off_hour > 23 or off_minute > 59:
            return None
        offset = (off_hour * 60 + off_minute) * (1 if match.group(9) == "+" else -1)
    seconds = calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0)) - offset * 60
    return seconds * 1000 + millis


def _import_key(entry: Any, index: int) -> tuple[str, Ed25519PublicKey]:
    """Ed25519 public keys travel as base64url of the raw 32 bytes; anything else is a malformed snapshot."""
    if not isinstance(entry, dict) or not _is_text(entry.get("kid")):
        _fail("malformed", f"keys[{index}].kid is missing")
    text = entry.get("public_key")
    raw = None
    if _is_text(text) and _BASE64URL.match(text):
        try:
            raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        except (binascii.Error, ValueError):
            raw = None
    if raw is None or len(raw) != 32:
        _fail("malformed", f"keys[{index}].public_key is not a raw Ed25519 key")
    return entry["kid"], Ed25519PublicKey.from_public_bytes(raw)


def _valid_member(member: Any, index: int) -> Member:
    where = f"members[{index}]"
    if not isinstance(member, dict) or not _is_text(member.get("user_id")):
        _fail("malformed", f"{where}.user_id is missing")
    if not _is_text(member.get("member_id")):
        _fail("malformed", f"{where}.member_id is missing")
    if not _is_text(member.get("login")):
        _fail("malformed", f"{where}.login is missing")
    if not isinstance(member.get("name"), str):
        _fail("malformed", f"{where}.name is missing")
    if not isinstance(member.get("role"), str) or member["role"] not in ROLES:
        _fail("malformed", f"{where}.role must be parent or kid")
    if not isinstance(member.get("status"), str) or member["status"] not in STATUSES:
        _fail("malformed", f"{where}.status must be active or disabled")
    epoch = _count(member.get("epoch"))
    if epoch is None:
        _fail("malformed", f"{where}.epoch must be a whole number")
    apps = member.get("apps")
    if not isinstance(apps, list) or not all(_is_text(app) for app in apps):
        _fail("malformed", f"{where}.apps must list app IDs")
    return Member(
        user_id=member["user_id"],
        member_id=member["member_id"],
        login=member["login"],
        name=member["name"],
        role=member["role"],
        status=member["status"],
        epoch=epoch,
        apps=tuple(apps),
    )


def parse_snapshot(data: Any) -> Snapshot:
    """Checks a parsed snapshot's shape and returns it in the form the library uses. Freshness and generation
    are the reader's business; this is only "is it a format-1 snapshot". Raises SnapshotError."""
    if not isinstance(data, dict):
        _fail("malformed", "the snapshot is not a JSON object")
    fmt = data.get("format")
    if safe_integer(fmt) != FORMAT:
        _fail("format", f"the snapshot is format {fmt}, not {FORMAT}")
    if not _is_text(data.get("household")):
        _fail("malformed", "household is missing")
    generation = safe_integer(data.get("generation"))
    if generation is None or generation < 1:
        _fail("malformed", "generation must be a positive whole number")
    written_at = parse_timestamp_ms(data["written_at"]) if _is_text(data.get("written_at")) else None
    if written_at is None:
        _fail("malformed", "written_at is not a time")
    global_epoch = _count(data.get("global_epoch"))
    if global_epoch is None:
        _fail("malformed", "global_epoch must be a whole number")
    if not isinstance(data.get("keys"), list):
        _fail("malformed", "keys must be a list")
    if not isinstance(data.get("members"), list):
        _fail("malformed", "members must be a list")
    keys = dict(_import_key(entry, index) for index, entry in enumerate(data["keys"]))
    if len(keys) != len(data["keys"]):
        _fail("malformed", "two keys share a kid")
    members = tuple(_valid_member(member, index) for index, member in enumerate(data["members"]))
    by_user_id = {member.user_id: member for member in members}
    if len(by_user_id) != len(members):
        _fail("malformed", "two members share a user_id")
    if len({member.login for member in members}) != len(members):
        _fail("malformed", "two members share a login")
    return Snapshot(
        household=data["household"],
        generation=generation,
        written_at=written_at,
        global_epoch=global_epoch,
        keys=MappingProxyType(keys),
        members=members,
        by_user_id=MappingProxyType(by_user_id),
    )


def _check_directories(directory: str, owner_uid: int, trusted_root: str | None) -> None:
    """Every directory from the top down to the snapshot's own: a real directory, not a symlink, owned by
    root (or, for the last one, the Home Base user) and writable by no one else. Whoever can write a
    directory on the way could swap what lies below it. Directories at or above trusted_root are not
    checked; that exists for tests, which can't build their tree under root-owned directories."""
    chain: list[str] = []
    current = directory
    while True:
        if trusted_root and (current == trusted_root or not current.startswith(trusted_root + os.sep)):
            break
        chain.insert(0, current)
        parent = os.path.dirname(current)
        if current == parent:
            break
        current = parent
    for current in chain:
        try:
            info = os.lstat(current)
        except OSError:
            _fail("missing", f"{current} does not exist")
        if stat.S_ISLNK(info.st_mode):
            _fail("untrusted", f"{current} is a symlink")
        if not stat.S_ISDIR(info.st_mode):
            _fail("untrusted", f"{current} is not a directory")
        allowed = info.st_uid == owner_uid if current == directory else info.st_uid == 0
        if not allowed:
            _fail("untrusted", f"{current} is owned by uid {info.st_uid}")
        if info.st_mode & WRITABLE_BY_OTHERS:
            _fail("untrusted", f"{current} is writable by group or others")


def _read_trusted_file(file: str, owner_uid: int) -> str:
    """Opens the file by descriptor without following a symlink, and checks the descriptor, not the path, so
    what is checked is what is read."""
    try:
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        if error.errno == errno.ENOENT:
            _fail("missing", f"{file} does not exist")
        if error.errno in (errno.ELOOP, errno.EMLINK):
            _fail("untrusted", f"{file} is a symlink")
        _fail("unreadable", f"{file}: {errno.errorcode.get(error.errno or 0, str(error))}")
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            _fail("untrusted", f"{file} is not a regular file")
        if info.st_uid != owner_uid:
            _fail("untrusted", f"{file} is owned by uid {info.st_uid}")
        if info.st_mode & WRITABLE_BY_OTHERS:
            _fail("untrusted", f"{file} is writable by group or others")
        if info.st_nlink != 1:
            _fail("untrusted", f"{file} has {info.st_nlink} links")
        if info.st_size > MAX_BYTES:
            _fail("malformed", f"{file} is larger than {MAX_BYTES} bytes")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BYTES:
                _fail("malformed", f"{file} is larger than {MAX_BYTES} bytes")
            chunks.append(chunk)
        # Node reads with 'utf8', which replaces invalid sequences rather than refusing them.
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        os.close(fd)


def _check_uid(uid: Any, what: str) -> int:
    if isinstance(uid, bool) or not isinstance(uid, int) or not 0 <= uid <= 2**53 - 1:
        raise ValueError(f"{what} needs the owner's uid" if what == "read_owned_file" else f"{what} needs the Home Base user's uid")
    return uid


def read_owned_file(file: str, *, uid: int, trusted_root: str | None = None) -> str:
    """The same trust for any small file: it and its directory owned by `uid`, every directory above them by
    root, nothing writable by anyone else, no symlinks, one link. Raises SnapshotError."""
    owner = _check_uid(uid, "read_owned_file")
    resolved = os.path.abspath(file)
    _check_directories(os.path.dirname(resolved), owner, trusted_root and os.path.abspath(trusted_root))
    return _read_trusted_file(resolved, owner)


@dataclass(frozen=True)
class SnapshotState:
    ok: bool
    snapshot: Snapshot | None = None
    reason: str | None = None
    message: str | None = None


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


class SnapshotReader:
    """SnapshotReader(home_base_uid=...).current() returns SnapshotState(ok=True, snapshot=...) or
    SnapshotState(ok=False, reason=..., message=...). It re-reads the file at most every recheck_ms, checks
    the age of what it holds on every call, and never accepts a generation lower than one it has seen."""

    def __init__(
        self,
        *,
        home_base_uid: int,
        file: str = DEFAULT_SNAPSHOT_PATH,
        now: Callable[[], int] = _now_ms,
        max_age_ms: int = MAX_AGE_MS,
        recheck_ms: int = RECHECK_MS,
        trusted_root: str | None = None,
    ):
        uid = _check_uid(home_base_uid, "a snapshot reader")
        if uid == 0:
            raise ValueError("the Home Base user is never root")
        self.home_base_uid = uid
        self.file = os.path.abspath(file)
        self._now = now
        self._max_age_ms = max_age_ms
        self._recheck_ms = recheck_ms
        self._trusted_root = trusted_root and os.path.abspath(trusted_root)
        self._highest_generation = 0
        self._checked_at: float = float("-inf")
        self._last: SnapshotState | None = None

    def _load(self) -> Snapshot:
        _check_directories(os.path.dirname(self.file), self.home_base_uid, self._trusted_root)
        text = _read_trusted_file(self.file, self.home_base_uid)
        try:
            data = parse_json(text)
        except ValueError:
            _fail("malformed", "the snapshot is not JSON")
        snapshot = parse_snapshot(data)
        if snapshot.generation < self._highest_generation:
            _fail("rollback", f"generation {snapshot.generation} is older than {self._highest_generation}")
        self._highest_generation = snapshot.generation
        return snapshot

    def current(self) -> SnapshotState:
        at = self._now()
        if at - self._checked_at >= self._recheck_ms or at < self._checked_at or self._last is None:
            self._checked_at = at
            try:
                self._last = SnapshotState(ok=True, snapshot=self._load())
            except SnapshotError as error:
                self._last = SnapshotState(ok=False, reason=error.reason, message=str(error))
        last = self._last
        if not last.ok or last.snapshot is None:
            return last
        age = at - last.snapshot.written_at
        if age > self._max_age_ms:
            return SnapshotState(ok=False, reason="stale", message=f"the snapshot is {round(age / 1000)} s old")
        if age < -MAX_FUTURE_MS:
            return SnapshotState(ok=False, reason="future", message="the snapshot was written in the future")
        return last


def create_snapshot_reader(**options: Any) -> SnapshotReader:
    return SnapshotReader(**options)
