"""sovereign-auth for Python: the port of the Node library at the repository root. It implements the same
wire contract (docs/wire-contract.md) and passes the same conformance vectors (vectors/)."""

from .assurance import (
    ACTION_HEADER,
    COOKIE_NAME,
    POLICY,
    Assurance,
    AssuranceDecision,
    AssuranceRequest,
    assurance_cookie,
    create_assurance,
    policy_for,
    request_digest,
)
from .guards import ALLOWED, Decision, RequestGuard, create_request_guard, normalize_origin
from .identity import Identity, Resolution, auth_mode, create_identity, require_socket_listen, resolve_member
from .snapshot import (
    DEFAULT_SNAPSHOT_PATH,
    Member,
    Snapshot,
    SnapshotError,
    SnapshotReader,
    SnapshotState,
    create_snapshot_reader,
    parse_snapshot,
    read_owned_file,
)
from .tokens import MAX_TOKEN_LENGTH, Verified, sign_token, verify_token

__all__ = [
    "ACTION_HEADER",
    "ALLOWED",
    "Assurance",
    "AssuranceDecision",
    "AssuranceRequest",
    "COOKIE_NAME",
    "DEFAULT_SNAPSHOT_PATH",
    "Decision",
    "Identity",
    "MAX_TOKEN_LENGTH",
    "Member",
    "POLICY",
    "RequestGuard",
    "Resolution",
    "Snapshot",
    "SnapshotError",
    "SnapshotReader",
    "SnapshotState",
    "Verified",
    "assurance_cookie",
    "auth_mode",
    "create_assurance",
    "create_identity",
    "create_request_guard",
    "create_snapshot_reader",
    "normalize_origin",
    "parse_snapshot",
    "policy_for",
    "read_owned_file",
    "request_digest",
    "require_socket_listen",
    "resolve_member",
    "sign_token",
    "verify_token",
]
