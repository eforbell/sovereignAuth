"""sovereign-auth for Python: the port of the Node library at the repository root. It implements the same
wire contract (docs/wire-contract.md) and passes the same conformance vectors (vectors/)."""

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

__all__ = [
    "ALLOWED",
    "DEFAULT_SNAPSHOT_PATH",
    "Decision",
    "Identity",
    "Member",
    "RequestGuard",
    "Resolution",
    "Snapshot",
    "SnapshotError",
    "SnapshotReader",
    "SnapshotState",
    "auth_mode",
    "create_identity",
    "create_request_guard",
    "create_snapshot_reader",
    "normalize_origin",
    "parse_snapshot",
    "read_owned_file",
    "require_socket_listen",
    "resolve_member",
]
