"""Identity-scoped offline mirror and durable outbox for Attacca.

The agent mirror is intentionally *not* an administrative project export.  It
stores only a schema-v1 :mod:`sync_protocol` snapshot for one authenticated
principal/actor visibility scope.  Every snapshot and pull is validated again
at the filesystem boundary, including the canonical ledger hash chain,
redacted anchors, projection digest, scope, and visibility fingerprint.

Local writes are schema-v1 client mutations in an append-only, hash-chained
outbox.  Mutation, receipt, conflict, resolution, and convergence records are
created with write+fsync+atomic publication and are never rewritten or
deleted.  A successful push is not reported as converged until a later
validated snapshot/pull contains the exact server cursor hash from its receipt.
This closes the ambiguous "commit succeeded, final pull failed" window across
process restarts.

The module is transport agnostic.  ``synchronize(remote)`` expects an adapter
with ``fetch_snapshot()``, ``pull()``, and ``push()`` methods.  The authenticated
HTTP implementation lives in :mod:`sync_client`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
try:  # Namespace-package import when integrated as ``attacca.offline_sync``.
    from . import sync_protocol as protocol
except (ImportError, ValueError):  # Direct module loading in tests.
    import sync_protocol as protocol
try:  # One canonical full-URL trust-boundary implementation for all clients.
    from . import terminal_flow as terminal_auth
except (ImportError, ValueError):  # Direct module loading in tests.
    import terminal_flow as terminal_auth

try:  # POSIX process lock (the supported Docker/Linux runtime).
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX client fallback.
    fcntl = None


MIRROR_FORMAT = "attacca.offline.identity-mirror"
SYNC_STATE_FORMAT = "attacca.offline.identity-sync-state"
JOURNAL_RECORD_FORMAT = "attacca.offline.identity-outbox-record"
CONVERGENCE_PROOF_FORMAT = "attacca.offline.convergence-proof"
OFFLINE_SYNC_SCHEMA_VERSION = 1
MIRROR_SCHEMA_VERSION = 2
SYNC_STATE_SCHEMA_VERSION = 2
JOURNAL_GENESIS_HASH = "0" * 64

_SYNC_STATE_MUTABLE_KEYS = {
    "mode", "pending_sync", "mirror_stale", "last_attempt_at",
    "last_success_at", "last_error", "last_local_write_at",
    "mirror_verified_at", "last_verified_remote_cursor", "last_reset_reason",
    "last_converged_ids",
}
_SYNC_STATE_IDENTITY_KEYS = {
    "format", "schema_version", "storage_key", "scope_fingerprint",
    "client_id", "device_id", "mirror_key", "projection_capabilities",
}
_SYNC_STATE_KEYS = (
    _SYNC_STATE_MUTABLE_KEYS | _SYNC_STATE_IDENTITY_KEYS | {"state_sha256"})
_SYNC_MODES = {
    "uninitialized", "offline_uninitialized", "offline", "pending",
    "syncing", "online", "conflict",
}

_MUTATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,199}$")
_RECORD_NAME_RE = re.compile(r"^(\d{20})\.json$")
_RESERVED_ATTRIBUTION_KEYS = {
    "actor_id", "actor_type", "authenticated_scope", "attribution",
    "human_user", "owner", "principal_id", "project_id", "role",
    "run_by_user", "server_id", "workspace",
}
_RESOURCE_ALIASES = {
    "handoffs": "handoffs", "handoff": "handoffs",
    "rules": "rules", "rule": "rules",
    "tasks": "tasks", "task": "tasks",
    "decisions": "decisions", "decision": "decisions",
    "messages": "room_messages", "message": "room_messages",
    "room": "room_messages", "room_messages": "room_messages",
    "agents": "agents", "agent": "agents",
    "bridges": "bridges", "bridge": "bridges",
    "plans": "task_plans", "task_plans": "task_plans",
    "logs": "full_log", "log": "full_log", "activity": "full_log",
    "full_log": "full_log", "events": "events", "records": "records",
    "actor_aliases": "actor_aliases", "inbox": "inbox_cursor",
    "inbox_cursor": "inbox_cursor", "project": "project",
    "cloud": "cloud_context", "cloud_context": "cloud_context",
    "disposition": "message_dispositions",
    "dispositions": "message_dispositions",
    "message_disposition": "message_dispositions",
    "message_dispositions": "message_dispositions",
}
_OPERATION_RESOURCE_ALIASES = {
    "message.dispose": "message_dispositions",
}


class OfflineSyncError(RuntimeError):
    """Base error for the local mirror, outbox, or sync boundary."""


class OfflineMirrorError(OfflineSyncError):
    """The local identity-scoped mirror is missing or failed validation."""


class OfflineSchemaCompatibilityError(OfflineMirrorError):
    """Verified local/remote bytes use an unsupported projection schema."""


class OfflineJournalError(OfflineSyncError):
    """The append-only outbox is malformed or its hash chain changed."""


class OfflineConflictError(OfflineSyncError):
    """A mutation conflict or requested resolution is invalid."""


class OfflineIdentityChangedError(OfflineSyncError):
    """Authenticated principal/actor/role changed and needs safe rebinding."""


class OfflineVisibilityChangedError(OfflineSyncError):
    """The same identity has a newer visibility/projection generation."""


class RemoteUnavailableError(ConnectionError):
    """Remote adapters may raise this for retryable connectivity failures."""


def _canonical_bytes(value, max_bytes=None):
    try:
        return protocol.canonical_json_bytes(value, max_bytes=max_bytes)
    except protocol.SyncProtocolError as error:
        raise OfflineSyncError(str(error)) from error


def _json_copy(value, max_bytes=None):
    return json.loads(_canonical_bytes(value, max_bytes=max_bytes).decode("utf-8"))


def _sha256(value):
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z")


def _validate_optional_timestamp(value, label):
    if value is None:
        return
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timestamp has no timezone")
    except (TypeError, ValueError) as error:
        raise OfflineSyncError("%s is not a timezone-aware timestamp" % label) \
            from error


def _required(label, value):
    value = str(value or "").strip()
    if not value:
        raise OfflineSyncError("%s is required" % label)
    return value


def normalize_server_url(value):
    """Return a credential-free canonical HTTP(S) origin/base path."""
    try:
        return terminal_auth.canonical_server_url(value)
    except terminal_auth.TerminalFlowError as error:
        raise OfflineSyncError(str(error)) from None


def mirror_storage_key(server_url, project_id, principal_id):
    identity = {
        "normalized_server_url": normalize_server_url(server_url),
        "project_id": _required("project_id", project_id),
        "principal_id": _required("principal_id", principal_id),
    }
    return "v1_" + hashlib.sha256(_canonical_bytes(identity)).hexdigest()


def _reject_symlink_components(path):
    """Reject an existing symlink anywhere in ``path`` without resolving it."""
    path = Path(path).absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise OfflineSyncError(
                "refusing symlink traversal in offline storage: %s" % current)


def _ensure_private_directory(path):
    path = Path(path).absolute()
    _reject_symlink_components(path)
    path.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(path)
    if not path.is_dir():
        raise OfflineSyncError("offline storage is not a directory: %s" % path)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def _fsync_directory(path):
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(str(path), flags)
    except OSError:  # Some network/client filesystems lack directory fsync.
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _read_json_file(path, max_bytes):
    path = Path(path)
    _reject_symlink_components(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
    except OSError as error:
        raise OfflineSyncError("cannot open %s: %s" % (path.name, error)) from error
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise OfflineSyncError("offline file is not regular: %s" % path)
        if details.st_size > int(max_bytes):
            raise OfflineSyncError("offline file exceeds its size limit: %s" % path)
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            raw = handle.read(int(max_bytes) + 1)
        if len(raw) > int(max_bytes):
            raise OfflineSyncError("offline file exceeds its size limit: %s" % path)
        value = json.loads(raw.decode("utf-8"))
        _canonical_bytes(value, max_bytes=max_bytes)
        return value
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OfflineSyncError("cannot parse %s: %s" % (path.name, error)) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _atomic_replace_json(path, value, max_bytes=None):
    target = Path(path)
    parent = _ensure_private_directory(target.parent)
    _reject_symlink_components(target)
    if target.exists() and target.is_symlink():
        raise OfflineSyncError("refusing symlinked offline file %s" % target)
    data = _canonical_bytes(value, max_bytes=max_bytes) + b"\n"
    descriptor, temporary = tempfile.mkstemp(
        prefix=".%s." % target.name, suffix=".tmp", dir=str(parent))
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _reject_symlink_components(target)
        os.replace(temporary, target)
        os.chmod(target, 0o600)
        _fsync_directory(parent)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _atomic_create_json(path, value, temporary_directory):
    target = Path(path)
    parent = _ensure_private_directory(target.parent)
    temporary_directory = _ensure_private_directory(temporary_directory)
    _reject_symlink_components(target)
    if target.exists():
        raise OfflineJournalError("outbox record already exists: %s" % target.name)
    data = _canonical_bytes(value, max_bytes=protocol.MAX_MUTATION_BYTES * 4) + b"\n"
    descriptor, temporary = tempfile.mkstemp(
        prefix="pending-", suffix=".json", dir=str(temporary_directory))
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, target)
        os.unlink(temporary)
        os.chmod(target, 0o600)
        _fsync_directory(parent)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _stable_identity(scope):
    scope = protocol.validate_scope(scope)
    return {key: scope[key] for key in (
        "server_id", "project_id", "principal_id")}


def _same_principal_scope(left, right):
    return _stable_identity(left) == _stable_identity(right)


def _contains_reserved_attribution(value):
    if isinstance(value, dict):
        return any(
            str(key).lower() in _RESERVED_ATTRIBUTION_KEYS
            or _contains_reserved_attribution(child)
            for key, child in value.items())
    if isinstance(value, list):
        return any(_contains_reserved_attribution(item) for item in value)
    return False


@dataclass(frozen=True)
class ConvergenceProof:
    """Tamper-evident summary produced only after validating the mirror."""

    normalized_server_url: str
    storage_key: str
    scope: dict
    visibility_fingerprint: str
    cursor: dict
    snapshot_sha256: str
    mirror_verified_at: str
    mirror_stale: bool
    convergence_awaiting_receipts: tuple
    own_canonical_events_observed: tuple
    online: bool
    projection_capabilities: dict = None

    def as_dict(self):
        value = {
            "format": CONVERGENCE_PROOF_FORMAT,
            "schema_version": MIRROR_SCHEMA_VERSION,
            "normalized_server_url": self.normalized_server_url,
            "storage_key": self.storage_key,
            "scope": _json_copy(self.scope),
            "projection_capabilities": _json_copy(
                self.projection_capabilities or
                protocol.current_projection_capabilities()),
            "visibility_fingerprint": self.visibility_fingerprint,
            "cursor": _json_copy(self.cursor),
            "snapshot_sha256": self.snapshot_sha256,
            "mirror_verified_at": self.mirror_verified_at,
            "mirror_stale": bool(self.mirror_stale),
            "convergence_awaiting_receipts": list(
                self.convergence_awaiting_receipts),
            "own_canonical_events_observed": list(
                self.own_canonical_events_observed),
            "online": bool(self.online),
            "validation": (
                "sync_protocol.schema-v1+projection-v2+scope+visibility+chain"),
        }
        value["proof_sha256"] = _sha256(value)
        return value


def validate_convergence_proof(value, *, expected_server_url=None,
                               expected_project=None, expected_scope=None,
                               expected_projection_capabilities=None,
                               require_online=False):
    """Validate a proof before a hook treats cached authority as binding."""
    required = {
        "format", "schema_version", "normalized_server_url", "storage_key",
        "scope", "projection_capabilities", "visibility_fingerprint",
        "cursor", "snapshot_sha256",
        "mirror_verified_at", "mirror_stale",
        "convergence_awaiting_receipts", "own_canonical_events_observed",
        "online", "validation", "proof_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise OfflineMirrorError("convergence proof has an invalid shape")
    checked = _json_copy(value, max_bytes=256 * 1024)
    digest = checked.pop("proof_sha256")
    if digest != _sha256(checked):
        raise OfflineMirrorError("convergence proof digest mismatch")
    checked["proof_sha256"] = digest
    if checked["format"] != CONVERGENCE_PROOF_FORMAT \
            or checked["schema_version"] != MIRROR_SCHEMA_VERSION \
            or checked["validation"] != \
            "sync_protocol.schema-v1+projection-v2+scope+visibility+chain":
        raise OfflineMirrorError("unsupported convergence proof")
    try:
        verified_at = datetime.fromisoformat(
            str(checked["mirror_verified_at"]).replace("Z", "+00:00"))
        if verified_at.tzinfo is None:
            raise ValueError("timestamp has no timezone")
    except (TypeError, ValueError) as error:
        raise OfflineMirrorError(
            "convergence proof verified_at is invalid") from error
    scope = protocol.validate_scope(
        checked["scope"], expected_scope=expected_scope)
    capabilities = protocol.validate_projection_capabilities(
        checked["projection_capabilities"])
    if expected_projection_capabilities is not None and capabilities != \
            protocol.validate_projection_capabilities(
                expected_projection_capabilities):
        raise OfflineMirrorError(
            "convergence proof projection capabilities mismatch")
    protocol.validate_visibility_fingerprint(
        checked["visibility_fingerprint"])
    protocol.validate_cursor(checked["cursor"])
    if not re.fullmatch(r"[0-9a-f]{64}", checked["snapshot_sha256"] or ""):
        raise OfflineMirrorError("convergence proof snapshot digest is invalid")
    expected_key = mirror_storage_key(
        checked["normalized_server_url"], scope["project_id"],
        scope["principal_id"])
    if checked["storage_key"] != expected_key:
        raise OfflineMirrorError("convergence proof storage identity mismatch")
    if expected_server_url is not None and checked["normalized_server_url"] \
            != normalize_server_url(expected_server_url):
        raise OfflineMirrorError("convergence proof belongs to another server")
    if expected_project is not None and scope["project_id"] != expected_project:
        raise OfflineMirrorError("convergence proof belongs to another project")
    for name in (
            "convergence_awaiting_receipts", "own_canonical_events_observed"):
        rows = checked[name]
        if not isinstance(rows, list) or len(rows) != len(set(rows)) \
                or any(not isinstance(item, str)
                       or not _MUTATION_ID_RE.fullmatch(item) for item in rows):
            raise OfflineMirrorError("convergence proof %s is invalid" % name)
    for name in ("mirror_stale", "online"):
        if not isinstance(checked[name], bool):
            raise OfflineMirrorError("convergence proof %s must be boolean" % name)
    if checked["online"] and (
            checked["mirror_stale"]
            or checked["convergence_awaiting_receipts"]):
        raise OfflineMirrorError("online proof cannot be stale or awaiting receipts")
    if require_online and not checked["online"]:
        raise OfflineMirrorError("convergence proof is not online")
    return checked


class OfflineProjectSync:
    """One authenticated identity mirror and one device's durable outbox."""

    def __init__(self, storage_root, server_url, scope, client_id, device_id,
                 visibility_fingerprint=None, wake_callback=None,
                 projection_capabilities=None):
        self.storage_root = Path(storage_root).absolute()
        self.normalized_server_url = normalize_server_url(server_url)
        self.scope = protocol.validate_scope(scope)
        self.project_id = self.scope["project_id"]
        self.principal_id = self.scope["principal_id"]
        self.client_id = _required("client_id", client_id)
        self.device_id = _required("device_id", device_id)
        self.visibility_fingerprint = (
            protocol.validate_visibility_fingerprint(visibility_fingerprint)
            if visibility_fingerprint is not None else None)
        self.projection_capabilities = \
            protocol.validate_projection_capabilities(
                projection_capabilities or
                protocol.current_projection_capabilities())
        self.storage_key = mirror_storage_key(
            self.normalized_server_url, self.project_id, self.principal_id)
        self.directory = self.storage_root / self.storage_key
        self.mirrors_directory = self.directory / "mirrors"
        self.outboxes_directory = self.directory / "outboxes"
        self.lock_path = self.directory / ".offline-sync.lock"
        self._wake_callback = wake_callback
        self._thread_lock = threading.RLock()
        self._lock_local = threading.local()
        self._configure_identity_paths()
        self._ensure_layout()
        self._migrate_legacy_mirror_if_safe()

    @staticmethod
    def _identity_key(scope, projection_capabilities):
        return "v1_" + hashlib.sha256(_canonical_bytes({
            "scope_fingerprint": protocol.scope_fingerprint(scope),
            "projection_capabilities":
                protocol.validate_projection_capabilities(
                    projection_capabilities),
        })).hexdigest()

    @staticmethod
    def _legacy_identity_key(scope):
        """Return the schema-v1 mirror key used before capability binding."""
        return "v1_" + hashlib.sha256(_canonical_bytes({
            "scope_fingerprint": protocol.scope_fingerprint(scope),
        })).hexdigest()

    def _mirror_path_for_scope(self, scope):
        key = self._identity_key(scope, self.projection_capabilities)
        directory = self.mirrors_directory / key
        return key, directory, directory / "snapshot.json"

    def _configure_identity_paths(self):
        self.mirror_key, self.mirror_directory, self.mirror_path = \
            self._mirror_path_for_scope(self.scope)
        material = {
            "scope_fingerprint": protocol.scope_fingerprint(self.scope),
            "client_id": self.client_id,
            "device_id": self.device_id,
        }
        self.outbox_key = "v1_" + hashlib.sha256(
            _canonical_bytes(material)).hexdigest()
        self.outbox_directory = self.outboxes_directory / self.outbox_key
        self.journal_directory = self.outbox_directory / "records"
        self.temporary_directory = self.outbox_directory / ".pending"
        # Journal records are shared across compatible projection upgrades so
        # an already-fsynced write is never lost.  Mutable mirror freshness is
        # capability-specific and must not let a newer client mark an older
        # mirror current (or vice versa).
        self.state_path = self.outbox_directory / (
            "sync-state-%s.json" % self.mirror_key)

    def _ensure_layout(self):
        for path in (
                self.storage_root, self.directory, self.mirrors_directory,
                self.mirror_directory, self.outboxes_directory, self.outbox_directory,
                self.journal_directory, self.temporary_directory):
            _ensure_private_directory(path)

    def _migrate_legacy_mirror_if_safe(self):
        """Copy a fully verified pre-capability mirror into this partition.

        The old bytes remain untouched for a still-running legacy client.  A
        migrated mirror is deliberately stale/pending because its visibility
        fingerprint did not bind projection capabilities; reconnect must
        negotiate and refresh it before this client can claim to be online.
        Invalid, cross-scope, or visibility-mismatched legacy bytes are simply
        not authority and are never copied.
        """
        if self.has_mirror():
            return False
        legacy_key = self._legacy_identity_key(self.scope)
        legacy_path = self.mirrors_directory / legacy_key / "snapshot.json"
        if not legacy_path.exists() or legacy_path.is_symlink():
            return False
        with self._locked():
            if self.has_mirror():
                return False
            try:
                wrapper = _read_json_file(
                    legacy_path,
                    protocol.MAX_SNAPSHOT_BYTES + 1024 * 1024)
                required = {
                    "format", "schema_version", "normalized_server_url",
                    "storage_key", "mirror_key", "scope_fingerprint",
                    "scope", "visibility_fingerprint", "verified_at",
                    "reset_reason", "snapshot_sha256", "snapshot",
                }
                if not isinstance(wrapper, dict) or set(wrapper) != required \
                        or wrapper.get("format") != MIRROR_FORMAT \
                        or wrapper.get("schema_version") != \
                        OFFLINE_SYNC_SCHEMA_VERSION \
                        or wrapper.get("normalized_server_url") != \
                        self.normalized_server_url \
                        or wrapper.get("storage_key") != self.storage_key:
                    return False
                scope = protocol.validate_scope(
                    wrapper["scope"], expected_scope=self.scope)
                visibility = protocol.validate_visibility_fingerprint(
                    wrapper["visibility_fingerprint"])
                if self.visibility_fingerprint is not None \
                        and visibility != self.visibility_fingerprint:
                    return False
                snapshot = protocol.validate_snapshot(
                    wrapper["snapshot"], expected_scope=scope,
                    expected_visibility=visibility)
                protocol.validate_projection_for_capabilities(
                    snapshot["projection"], scope,
                    self.projection_capabilities)
                if wrapper["mirror_key"] != legacy_key \
                        or wrapper["scope_fingerprint"] != \
                        protocol.scope_fingerprint(scope) \
                        or wrapper["snapshot_sha256"] != _sha256(snapshot):
                    return False
                if not isinstance(wrapper["verified_at"], str):
                    return False
                _validate_optional_timestamp(
                    wrapper["verified_at"], "legacy mirror verified_at")
                if wrapper["reset_reason"] is not None \
                        and not isinstance(wrapper["reset_reason"], str):
                    return False
            except (OfflineSyncError, protocol.SyncProtocolError):
                return False

            migrated = self._mirror_wrapper(
                snapshot, reset_reason="migrated from schema-v1 mirror")
            migrated["verified_at"] = wrapper["verified_at"]
            _atomic_replace_json(
                self.mirror_path, migrated,
                max_bytes=protocol.MAX_SNAPSHOT_BYTES + 1024 * 1024)
            if self.visibility_fingerprint is None:
                self.visibility_fingerprint = visibility
            state = self._read_state_locked()
            state.update({
                "mode": "pending", "pending_sync": True,
                "mirror_stale": True,
                "mirror_verified_at": wrapper["verified_at"],
                "last_verified_remote_cursor": _json_copy(
                    snapshot["cursor"]),
                "last_reset_reason": "migrated from schema-v1 mirror",
                "last_error": (
                    "projection capabilities require a hosted refresh"),
            })
            self._write_state_locked(state)
            return True

    @contextmanager
    def _locked(self):
        self._ensure_layout()
        with self._thread_lock:
            depth = int(getattr(self._lock_local, "depth", 0))
            if depth:
                self._lock_local.depth = depth + 1
                try:
                    yield
                finally:
                    self._lock_local.depth = depth
                return
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(str(self.lock_path), flags, 0o600)
            try:
                self._lock_local.depth = 1
                os.chmod(self.lock_path, 0o600)
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                self._lock_local.depth = 0
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def has_mirror(self):
        return self.mirror_path.is_file() and not self.mirror_path.is_symlink()

    def _validate_snapshot_for_identity(self, envelope, allow_scope_change=False,
                                        allow_visibility_change=False):
        try:
            checked = protocol.validate_snapshot(envelope)
            protocol.validate_projection_for_capabilities(
                checked["projection"], checked["scope"],
                self.projection_capabilities)
        except protocol.SyncProtocolError as error:
            error_class = OfflineSchemaCompatibilityError \
                if protocol.is_schema_compatibility_error(error) \
                else OfflineMirrorError
            raise error_class(
                "identity snapshot failed schema-v1/projection-v%d "
                "validation: %s" % (
                    self.projection_capabilities["schema_version"], error)
                ) from error
        if not _same_principal_scope(checked["scope"], self.scope):
            raise OfflineIdentityChangedError(
                "snapshot belongs to another server/project/principal")
        if not allow_scope_change and checked["scope"] != self.scope:
            raise OfflineIdentityChangedError(
                "snapshot actor or role differs from the authenticated scope")
        if self.visibility_fingerprint is not None \
                and not allow_visibility_change \
                and checked["visibility_fingerprint"] != \
                self.visibility_fingerprint:
            raise OfflineVisibilityChangedError(
                "snapshot visibility differs from the pinned mirror")
        return checked

    def _mirror_wrapper(self, snapshot, reset_reason=None):
        return {
            "format": MIRROR_FORMAT,
            "schema_version": MIRROR_SCHEMA_VERSION,
            "normalized_server_url": self.normalized_server_url,
            "storage_key": self.storage_key,
            "mirror_key": self._identity_key(
                snapshot["scope"], self.projection_capabilities),
            "projection_capabilities": _json_copy(
                self.projection_capabilities),
            "scope_fingerprint": protocol.scope_fingerprint(snapshot["scope"]),
            "scope": _json_copy(snapshot["scope"]),
            "visibility_fingerprint": snapshot["visibility_fingerprint"],
            "verified_at": _utc_now(),
            "reset_reason": str(reset_reason) if reset_reason else None,
            "snapshot_sha256": _sha256(snapshot),
            "snapshot": _json_copy(snapshot),
        }

    def _load_mirror_locked(self, require_current_scope=True):
        if not self.has_mirror():
            raise OfflineMirrorError(
                "no verified identity-scoped mirror for project %s" %
                self.project_id)
        try:
            wrapper = _read_json_file(
                self.mirror_path, protocol.MAX_SNAPSHOT_BYTES + 1024 * 1024)
        except OfflineSyncError as error:
            raise OfflineMirrorError(str(error)) from error
        required = {
            "format", "schema_version", "normalized_server_url",
            "storage_key", "mirror_key", "scope_fingerprint", "scope",
            "projection_capabilities", "visibility_fingerprint",
            "verified_at", "reset_reason",
            "snapshot_sha256", "snapshot",
        }
        if not isinstance(wrapper, dict) or set(wrapper) != required \
                or wrapper.get("format") != MIRROR_FORMAT \
                or wrapper.get("schema_version") != MIRROR_SCHEMA_VERSION:
            raise OfflineMirrorError("unsupported identity mirror wrapper")
        if wrapper["normalized_server_url"] != self.normalized_server_url \
                or wrapper["storage_key"] != self.storage_key:
            raise OfflineMirrorError("identity mirror storage key mismatch")
        try:
            scope = protocol.validate_scope(wrapper["scope"])
            capabilities = protocol.validate_projection_capabilities(
                wrapper["projection_capabilities"])
            visibility = protocol.validate_visibility_fingerprint(
                wrapper["visibility_fingerprint"])
            snapshot = protocol.validate_snapshot(
                wrapper["snapshot"], expected_scope=scope,
                expected_visibility=visibility)
            protocol.validate_projection_for_capabilities(
                snapshot["projection"], scope, capabilities)
        except protocol.SyncProtocolError as error:
            error_class = OfflineSchemaCompatibilityError \
                if protocol.is_schema_compatibility_error(error) \
                else OfflineMirrorError
            raise error_class(
                "stored identity mirror failed validation: %s" % error) from error
        if not _same_principal_scope(scope, self.scope):
            raise OfflineMirrorError("stored mirror belongs to another identity")
        if capabilities != self.projection_capabilities:
            raise OfflineSchemaCompatibilityError(
                "stored mirror projection capabilities differ from this client")
        if wrapper["mirror_key"] != self._identity_key(
                scope, capabilities) \
                or wrapper["scope_fingerprint"] != \
                protocol.scope_fingerprint(scope):
            raise OfflineMirrorError("stored mirror scope partition mismatch")
        if require_current_scope and scope != self.scope:
            raise OfflineIdentityChangedError(
                "stored mirror actor/role differs from this client scope")
        if require_current_scope and self.visibility_fingerprint is not None \
                and visibility != self.visibility_fingerprint:
            raise OfflineVisibilityChangedError(
                "stored mirror visibility differs from this client scope")
        if wrapper["snapshot_sha256"] != _sha256(snapshot):
            raise OfflineMirrorError("stored snapshot digest mismatch")
        return wrapper

    def _current_snapshot_locked(self):
        return self._load_mirror_locked()["snapshot"]

    def _cursor_locked(self):
        if not self.has_mirror():
            return protocol.make_cursor(0, protocol.GENESIS_HASH, 0)
        return _json_copy(self._current_snapshot_locked()["cursor"])

    def _rebind_scope_locked(self, scope, visibility):
        self.scope = protocol.validate_scope(scope)
        self.project_id = self.scope["project_id"]
        self.principal_id = self.scope["principal_id"]
        self.visibility_fingerprint = protocol.validate_visibility_fingerprint(
            visibility)
        self._configure_identity_paths()
        self._ensure_layout()

    def install_snapshot(self, envelope, *, reset=False, reset_reason=None):
        """Atomically install a fully validated schema-v1 snapshot.

        A different actor/role for the same principal is accepted only during
        an explicit reset and only when the old scope has no pending/conflicting
        writes.  A different server, project, or principal is never accepted.
        """
        checked = self._validate_snapshot_for_identity(
            envelope, allow_scope_change=reset,
            allow_visibility_change=reset or self.visibility_fingerprint is None)
        with self._locked():
            old_wrapper = self._load_mirror_locked(
                require_current_scope=not reset) if self.has_mirror() else None
            scope_change = checked["scope"] != self.scope
            if scope_change:
                _, journal = self._journal_locked()
                if journal["ready"] or journal["blocked"] \
                        or journal["conflicts"] or journal["awaiting"]:
                    raise OfflineIdentityChangedError(
                        "cannot rebind actor/role while the old outbox has "
                        "pending, conflicting, or unconverged writes")
            if old_wrapper is not None and not reset:
                old = old_wrapper["snapshot"]
                if checked["scope"] != old["scope"] \
                        or checked["visibility_fingerprint"] != \
                        old["visibility_fingerprint"]:
                    raise OfflineIdentityChangedError(
                        "normal mirror advance cannot change scope/visibility")
                old_records = old["records"]
                if checked["cursor"]["event_seq"] < old["cursor"]["event_seq"] \
                        or checked["cursor"]["context_version"] < \
                        old["cursor"]["context_version"] \
                        or checked["records"][:len(old_records)] != old_records:
                    raise OfflineMirrorError(
                        "normal mirror advance is not on the verified local chain")
            wrapper = self._mirror_wrapper(checked, reset_reason=reset_reason)
            _, target_directory, target_path = self._mirror_path_for_scope(
                checked["scope"])
            _ensure_private_directory(target_directory)
            _atomic_replace_json(
                target_path, wrapper,
                max_bytes=protocol.MAX_SNAPSHOT_BYTES + 1024 * 1024)
            if scope_change:
                self._rebind_scope_locked(
                    checked["scope"], checked["visibility_fingerprint"])
            elif self.visibility_fingerprint is None or reset:
                self.visibility_fingerprint = checked["visibility_fingerprint"]
            state = self._read_state_locked()
            state.update({
                "mirror_stale": False,
                "mirror_verified_at": wrapper["verified_at"],
                "last_verified_remote_cursor": _json_copy(checked["cursor"]),
                "last_reset_reason": str(reset_reason) if reset_reason else None,
            })
            if old_wrapper is None or state.get("mode") in {
                    "uninitialized", "offline_uninitialized"}:
                state["mode"] = "online"
            self._write_state_locked(state)
            return _json_copy(checked["cursor"])

    def local_snapshot(self):
        """Return the complete validated schema-v1 snapshot envelope."""
        with self._locked():
            return _json_copy(self._current_snapshot_locked())

    def local_projection(self):
        return _json_copy(self.local_snapshot()["projection"])

    def _record_paths_locked(self):
        paths = []
        for path in self.journal_directory.iterdir():
            if path.is_symlink():
                raise OfflineJournalError(
                    "symlink found in append-only outbox: %s" % path.name)
            match = _RECORD_NAME_RE.fullmatch(path.name)
            if not match or not path.is_file():
                raise OfflineJournalError(
                    "unexpected entry in append-only outbox: %s" % path.name)
            paths.append((int(match.group(1)), path))
        return sorted(paths)

    def _load_records_locked(self):
        records = []
        previous_hash = JOURNAL_GENESIS_HASH
        mutations = set()
        for expected, (sequence, path) in enumerate(
                self._record_paths_locked(), start=1):
            if sequence != expected:
                raise OfflineJournalError(
                    "outbox sequence gap: expected %d, found %d" %
                    (expected, sequence))
            try:
                record = _read_json_file(
                    path, protocol.MAX_MUTATION_BYTES * 4)
            except OfflineSyncError as error:
                raise OfflineJournalError(str(error)) from error
            digest = record.get("record_hash") if isinstance(record, dict) else None
            unsigned = dict(record) if isinstance(record, dict) else {}
            unsigned.pop("record_hash", None)
            if digest != _sha256(unsigned):
                raise OfflineJournalError(
                    "outbox record hash mismatch at sequence %d" % sequence)
            if record.get("format") != JOURNAL_RECORD_FORMAT \
                    or record.get("schema_version") != \
                    OFFLINE_SYNC_SCHEMA_VERSION \
                    or record.get("storage_key") != self.storage_key \
                    or record.get("scope_fingerprint") != \
                    protocol.scope_fingerprint(self.scope) \
                    or record.get("client_id") != self.client_id \
                    or record.get("device_id") != self.device_id \
                    or record.get("journal_seq") != sequence \
                    or record.get("prev_record_hash") != previous_hash:
                raise OfflineJournalError(
                    "outbox identity/chain mismatch at sequence %d" % sequence)
            kind = record.get("kind")
            if kind not in {
                    "mutation", "receipt", "conflict", "resolution",
                    "converged"}:
                raise OfflineJournalError(
                    "unknown outbox record kind %r" % kind)
            mutation_id = record.get("client_mutation_id")
            if not isinstance(mutation_id, str) \
                    or not _MUTATION_ID_RE.fullmatch(mutation_id):
                raise OfflineJournalError("invalid outbox mutation id")
            if kind == "mutation":
                if mutation_id in mutations:
                    raise OfflineJournalError(
                        "duplicate mutation record for %s" % mutation_id)
                try:
                    mutation = protocol.validate_client_mutation(
                        record.get("mutation"), expected_scope=self.scope)
                except protocol.SyncProtocolError as error:
                    raise OfflineJournalError(
                        "invalid queued mutation: %s" % error) from error
                if mutation["client_mutation_id"] != mutation_id \
                        or mutation["client_id"] != self.client_id \
                        or mutation["device_id"] != self.device_id:
                    raise OfflineJournalError("queued mutation identity mismatch")
                attribution = record.get("local_attribution")
                expected_attribution = {
                    "server_id": self.scope["server_id"],
                    "project_id": self.scope["project_id"],
                    "principal_id": self.scope["principal_id"],
                    "actor_id": self.scope["actor_id"],
                    "actor_type": self.scope["actor_type"],
                    "role": self.scope["role"],
                    "device_id": self.device_id,
                    "git_branch": mutation["metadata"].get("git_branch"),
                    "git_revision": mutation["metadata"].get("git_revision"),
                }
                if attribution != expected_attribution:
                    raise OfflineJournalError(
                        "queued mutation attribution mismatch")
                mutations.add(mutation_id)
            elif mutation_id not in mutations:
                raise OfflineJournalError(
                    "%s references an unknown mutation %s" %
                    (kind, mutation_id))
            if kind in {"receipt", "conflict"}:
                try:
                    result = protocol.validate_mutation_result(
                        record.get("remote"), expected_scope=self.scope)
                except protocol.SyncProtocolError as error:
                    raise OfflineJournalError(
                        "invalid stored mutation result: %s" % error) from error
                allowed = {"applied", "duplicate"} if kind == "receipt" \
                    else {"conflict", "rejected"}
                if result["status"] not in allowed \
                        or result["client_mutation_id"] != mutation_id:
                    raise OfflineJournalError(
                        "stored %s result disagrees with mutation" % kind)
            records.append(record)
            previous_hash = digest
        return records

    @staticmethod
    def _projection(records):
        mutations = []
        by_id = {}
        status = {}
        receipts = {}
        conflict_records = {}
        converged = {}
        resolutions = {}
        for record in records:
            mutation_id = record["client_mutation_id"]
            kind = record["kind"]
            if kind == "mutation":
                mutation = record["mutation"]
                mutations.append(mutation)
                by_id[mutation_id] = mutation
                status[mutation_id] = "pending"
            elif kind == "receipt":
                receipts[mutation_id] = record
                status[mutation_id] = "awaiting_convergence"
            elif kind == "converged":
                converged[mutation_id] = record
                status[mutation_id] = "acknowledged"
            elif kind == "conflict":
                conflict_records[mutation_id] = record
                status[mutation_id] = "conflict"
            elif kind == "resolution":
                resolutions[mutation_id] = record
                conflict_records.pop(mutation_id, None)
                resolution = record.get("resolution")
                status[mutation_id] = (
                    "pending" if resolution == "retry" else resolution)

        ready, blocked, conflicts = [], [], []
        order_blocked = False
        for mutation in mutations:
            mutation_id = mutation["client_mutation_id"]
            current = status[mutation_id]
            if current == "conflict":
                conflicts.append(conflict_records[mutation_id])
                order_blocked = True
            elif current in {"cancelled", "superseded"}:
                # Later immutable mutations still name this operation in
                # depends_on.  Do not pretend a local cancellation is a hosted
                # receipt; the later writes remain visibly blocked until they
                # are explicitly superseded/requeued.
                order_blocked = True
            elif current == "pending":
                (blocked if order_blocked else ready).append(mutation)
        awaiting = [
            receipts[item["client_mutation_id"]]
            for item in mutations
            if status[item["client_mutation_id"]] == "awaiting_convergence"
        ]
        return {
            "mutations": mutations, "by_id": by_id, "status": status,
            "ready": ready, "blocked": blocked, "conflicts": conflicts,
            "receipts": receipts, "awaiting": awaiting,
            "converged": converged, "resolutions": resolutions,
        }

    def _journal_locked(self):
        records = self._load_records_locked()
        return records, self._projection(records)

    def _append_record_locked(self, kind, mutation_id, content):
        records = self._load_records_locked()
        sequence = len(records) + 1
        record = {
            "format": JOURNAL_RECORD_FORMAT,
            "schema_version": OFFLINE_SYNC_SCHEMA_VERSION,
            "storage_key": self.storage_key,
            "scope_fingerprint": protocol.scope_fingerprint(self.scope),
            "client_id": self.client_id,
            "device_id": self.device_id,
            "journal_seq": sequence,
            "kind": kind,
            "client_mutation_id": mutation_id,
            "recorded_at": _utc_now(),
            "prev_record_hash": (
                records[-1]["record_hash"] if records
                else JOURNAL_GENESIS_HASH),
            **_json_copy(content),
        }
        record["record_hash"] = _sha256(record)
        _atomic_create_json(
            self.journal_directory / ("%020d.json" % sequence), record,
            self.temporary_directory)
        return _json_copy(record)

    def _read_state_locked(self):
        if not self.state_path.exists():
            return {
                "format": SYNC_STATE_FORMAT,
                "schema_version": SYNC_STATE_SCHEMA_VERSION,
                "storage_key": self.storage_key,
                "scope_fingerprint": protocol.scope_fingerprint(self.scope),
                "client_id": self.client_id,
                "device_id": self.device_id,
                "mirror_key": self.mirror_key,
                "projection_capabilities": _json_copy(
                    self.projection_capabilities),
                "mode": "uninitialized" if not self.has_mirror() else "pending",
                "pending_sync": False,
                "mirror_stale": not self.has_mirror(),
                "last_attempt_at": None,
                "last_success_at": None,
                "last_error": None,
                "last_local_write_at": None,
                "mirror_verified_at": None,
                "last_verified_remote_cursor": None,
                "last_reset_reason": None,
                "last_converged_ids": [],
            }
        try:
            state = _read_json_file(self.state_path, 1024 * 1024)
        except OfflineSyncError as error:
            raise OfflineSyncError("cannot load sync state: %s" % error) from error
        if not isinstance(state, dict) or set(state) != _SYNC_STATE_KEYS:
            raise OfflineSyncError("sync state has an invalid shape")
        digest = state.get("state_sha256")
        unsigned = dict(state)
        unsigned.pop("state_sha256", None)
        if not isinstance(digest, str) \
                or not re.fullmatch(r"[0-9a-f]{64}", digest) \
                or digest != _sha256(unsigned):
            raise OfflineSyncError("sync state digest mismatch")
        if state.get("format") != SYNC_STATE_FORMAT \
                or state.get("schema_version") != SYNC_STATE_SCHEMA_VERSION \
                or state.get("storage_key") != self.storage_key \
                or state.get("scope_fingerprint") != \
                protocol.scope_fingerprint(self.scope) \
                or state.get("client_id") != self.client_id \
                or state.get("device_id") != self.device_id \
                or state.get("mirror_key") != self.mirror_key:
            raise OfflineSyncError("sync state identity or format mismatch")
        try:
            state_capabilities = protocol.validate_projection_capabilities(
                state.get("projection_capabilities"))
        except protocol.SyncProtocolError as error:
            raise OfflineSyncError(
                "sync state projection capabilities are invalid: %s" % error) \
                from error
        if state_capabilities != self.projection_capabilities:
            raise OfflineSyncError(
                "sync state projection capabilities mismatch")
        if state.get("mode") not in _SYNC_MODES \
                or not isinstance(state.get("pending_sync"), bool) \
                or not isinstance(state.get("mirror_stale"), bool):
            raise OfflineSyncError("sync state mode or flags are invalid")
        for name in (
                "last_attempt_at", "last_success_at", "last_local_write_at",
                "mirror_verified_at"):
            _validate_optional_timestamp(state.get(name), "sync state %s" % name)
        for name in ("last_error", "last_reset_reason"):
            if state.get(name) is not None \
                    and not isinstance(state.get(name), str):
                raise OfflineSyncError("sync state %s is invalid" % name)
        cursor = state.get("last_verified_remote_cursor")
        if cursor is not None:
            try:
                protocol.validate_cursor(cursor)
            except protocol.SyncProtocolError as error:
                raise OfflineSyncError(
                    "sync state remote cursor is invalid: %s" % error) from error
        converged = state.get("last_converged_ids")
        if not isinstance(converged, list) or len(converged) > 100 \
                or len(converged) != len(set(converged)) \
                or any(not isinstance(item, str)
                       or not _MUTATION_ID_RE.fullmatch(item)
                       for item in converged):
            raise OfflineSyncError("sync state convergence list is invalid")
        return state

    def _write_state_locked(self, state):
        value = dict(state)
        value.pop("state_sha256", None)
        value.update({
            "format": SYNC_STATE_FORMAT,
            "schema_version": SYNC_STATE_SCHEMA_VERSION,
            "storage_key": self.storage_key,
            "scope_fingerprint": protocol.scope_fingerprint(self.scope),
            "client_id": self.client_id,
            "device_id": self.device_id,
            "mirror_key": self.mirror_key,
            "projection_capabilities": _json_copy(
                self.projection_capabilities),
        })
        if set(value) != _SYNC_STATE_KEYS - {"state_sha256"}:
            raise OfflineSyncError("refusing to write an incomplete sync state")
        value["state_sha256"] = _sha256(value)
        _atomic_replace_json(self.state_path, value, max_bytes=1024 * 1024)

    def _set_state(self, **updates):
        with self._locked():
            state = self._read_state_locked()
            state.update(updates)
            self._write_state_locked(state)

    def queue_mutation(self, operation, payload, *, metadata=None,
                       depends_on=None, client_mutation_id=None,
                       git_branch=None, git_revision=None, actor_id=None,
                       actor_type=None, owner=None):
        """Fsync one immutable schema-v1 mutation before returning it."""
        if actor_id is not None and actor_id != self.scope["actor_id"]:
            raise OfflineIdentityChangedError(
                "queued actor_id differs from authenticated scope")
        if actor_type is not None and actor_type != self.scope["actor_type"]:
            raise OfflineIdentityChangedError(
                "queued actor_type differs from authenticated scope")
        if owner is not None and owner != self.scope["principal_id"]:
            raise OfflineIdentityChangedError(
                "queued owner differs from authenticated principal")
        metadata = _json_copy(metadata or {}, max_bytes=protocol.MAX_MUTATION_BYTES)
        if _contains_reserved_attribution(metadata):
            raise OfflineSyncError(
                "mutation metadata must not override authenticated attribution")
        if git_branch is not None:
            metadata["git_branch"] = str(git_branch)
        if git_revision is not None:
            metadata["git_revision"] = str(git_revision)
        if client_mutation_id is None:
            prefix = hashlib.sha256(
                (self.client_id + "|" + self.device_id).encode("utf-8")
            ).hexdigest()[:12]
            client_mutation_id = "cm_%s_%s" % (prefix, uuid.uuid4().hex)
        client_mutation_id = str(client_mutation_id)
        if not _MUTATION_ID_RE.fullmatch(client_mutation_id):
            raise OfflineSyncError(
                "client_mutation_id must be 8-200 safe characters")
        with self._locked():
            if not self.has_mirror():
                raise OfflineMirrorError(
                    "initialize a verified identity snapshot before queuing writes")
            cursor = self._cursor_locked()
            records, projected = self._journal_locked()
            existing = projected["by_id"].get(client_mutation_id)
            dependencies = []
            for dependency in depends_on or []:
                dependency = str(dependency)
                if dependency not in dependencies:
                    dependencies.append(dependency)
            if existing is not None:
                semantic = {
                    "operation": str(operation),
                    "payload": _json_copy(payload),
                    "metadata": metadata,
                }
                if any(existing.get(key) != value
                       for key, value in semantic.items()):
                    raise OfflineJournalError(
                        "client_mutation_id already names different work")
                if depends_on is not None and list(existing.get("depends_on") or []) \
                        != dependencies:
                    raise OfflineJournalError(
                        "client_mutation_id already names different dependencies")
                return _json_copy(existing)
            previous = projected["mutations"][-1] \
                if projected["mutations"] else None
            if previous and previous["client_mutation_id"] not in dependencies:
                dependencies.append(previous["client_mutation_id"])
            known = set(projected["by_id"])
            if any(item not in known for item in dependencies):
                raise OfflineSyncError("depends_on references an unknown mutation")
            sequence = len(projected["mutations"]) + 1
            try:
                mutation = protocol.make_client_mutation(
                    self.scope, client_mutation_id, self.client_id,
                    self.device_id, sequence, operation, payload, cursor,
                    depends_on=dependencies, metadata=metadata)
            except protocol.SyncProtocolError as error:
                raise OfflineSyncError(str(error)) from error
            attribution = {
                "server_id": self.scope["server_id"],
                "project_id": self.scope["project_id"],
                "principal_id": self.scope["principal_id"],
                "actor_id": self.scope["actor_id"],
                "actor_type": self.scope["actor_type"],
                "role": self.scope["role"],
                "device_id": self.device_id,
                "git_branch": metadata.get("git_branch"),
                "git_revision": metadata.get("git_revision"),
            }
            self._append_record_locked("mutation", client_mutation_id, {
                "mutation": mutation, "local_attribution": attribution})
            state = self._read_state_locked()
            state.update({
                "mode": "pending", "pending_sync": True,
                "last_local_write_at": mutation["created_at"],
            })
            self._write_state_locked(state)
        if callable(self._wake_callback):
            try:
                self._wake_callback()
            except Exception:
                pass
        return _json_copy(mutation)

    def _append_receipt(self, mutation, result, audit_device_id=None):
        mutation_id = mutation["client_mutation_id"]
        with self._locked():
            _, projected = self._journal_locked()
            current = projected["status"].get(mutation_id)
            if current in {"awaiting_convergence", "acknowledged"}:
                return projected["receipts"][mutation_id]
            if current != "pending":
                raise OfflineJournalError(
                    "cannot receipt %s while status is %s" %
                    (mutation_id, current))
            checked = protocol.validate_mutation_result(
                result, expected_scope=self.scope)
            if checked["client_mutation_id"] != mutation_id \
                    or checked["request_sha256"] != mutation["request_sha256"] \
                    or checked["status"] not in {"applied", "duplicate"}:
                raise OfflineJournalError(
                    "hosted receipt does not match queued mutation")
            payload = {"remote": checked}
            if audit_device_id:
                payload["audit_device_id"] = str(audit_device_id)
            record = self._append_record_locked(
                "receipt", mutation_id, payload)
            state = self._read_state_locked()
            state.update({
                "mirror_stale": True, "pending_sync": True,
                "mode": "pending",
            })
            self._write_state_locked(state)
            return record

    def _append_conflict(self, mutation, result):
        mutation_id = mutation["client_mutation_id"]
        with self._locked():
            _, projected = self._journal_locked()
            if projected["status"].get(mutation_id) == "conflict":
                return next(item for item in projected["conflicts"]
                            if item["client_mutation_id"] == mutation_id)
            if projected["status"].get(mutation_id) != "pending":
                raise OfflineJournalError(
                    "cannot conflict %s in its current state" % mutation_id)
            checked = protocol.validate_mutation_result(
                result, expected_scope=self.scope)
            if checked["client_mutation_id"] != mutation_id \
                    or checked["request_sha256"] != mutation["request_sha256"] \
                    or checked["status"] not in {"conflict", "rejected"}:
                raise OfflineJournalError(
                    "hosted conflict does not match queued mutation")
            return self._append_record_locked(
                "conflict", mutation_id, {"remote": checked})

    def resolve_conflict(self, client_mutation_id, resolution, rationale,
                         replacement_mutation_id=None):
        resolution = str(resolution or "").strip().lower()
        if resolution not in {"retry", "cancelled", "superseded"}:
            raise OfflineConflictError(
                "resolution must be retry, cancelled, or superseded")
        rationale = _required("conflict resolution rationale", rationale)
        with self._locked():
            _, projected = self._journal_locked()
            if projected["status"].get(client_mutation_id) != "conflict":
                raise OfflineConflictError(
                    "mutation has no unresolved conflict")
            if resolution == "superseded" and replacement_mutation_id \
                    not in projected["by_id"]:
                raise OfflineConflictError(
                    "superseded resolution needs an existing replacement")
            record = self._append_record_locked(
                "resolution", client_mutation_id, {
                    "resolution": resolution, "rationale": rationale,
                    "replacement_mutation_id": replacement_mutation_id,
                })
            state = self._read_state_locked()
            state.update({"mode": "pending", "pending_sync": True})
            self._write_state_locked(state)
            return record

    def _record_at_cursor_locked(self, cursor):
        snapshot = self._current_snapshot_locked()
        sequence = cursor["event_seq"]
        if sequence <= 0 or sequence > len(snapshot["records"]):
            return None
        return snapshot["records"][sequence - 1]

    def _mark_converged_locked(self):
        _, projected = self._journal_locked()
        snapshot = self._current_snapshot_locked()
        head = snapshot["cursor"]
        confirmed = []
        for receipt in projected["awaiting"]:
            result = receipt["remote"]
            cursor = result.get("server_cursor")
            if cursor is None or head["event_seq"] < cursor["event_seq"] \
                    or head["context_version"] < cursor["context_version"]:
                continue
            record = self._record_at_cursor_locked(cursor)
            if record is None or record.get("hash") != cursor["event_hash"]:
                continue
            # A cursor proves only that *some* canonical event exists at that
            # position. Acceptance notices additionally require the server's
            # canonical event mapping and the visible event's authenticated
            # human/AI/device attribution to match this exact mutation. This
            # prevents a receipt pointed at an unrelated concurrent event from
            # being announced as this client's accepted work.
            mapping = result.get("result") or {}
            canonical_event_id = mapping.get("canonical_event_id")
            canonical_event_seq = mapping.get("canonical_event_seq")
            event = record.get("event") if record.get("kind") == "event" \
                else None
            event_device_id = event.get("device_id") \
                if isinstance(event, dict) else None
            expected_audit_device = receipt.get("audit_device_id")
            if expected_audit_device:
                device_matches = event_device_id == expected_audit_device
                # A newly upgraded client can still be replaying against an
                # older hosted process which authenticated only the physical
                # device and did not append X-Attacca-Client-Instance to the
                # ledger value.  The receipt request hash plus canonical event
                # id/sequence below already bind this exact mutation, so allow
                # that legacy physical-only value.  Never accept a different
                # compound instance: current servers must match it exactly.
                if not device_matches \
                        and expected_audit_device.startswith(
                            self.device_id + "/"):
                    device_matches = event_device_id == self.device_id
            else:
                # Receipts written before client-instance attribution did not
                # retain the exact request header.  Their immutable server
                # event mapping/request hash still proves which mutation was
                # applied, so accept the historical physical-device value or
                # that same device with one appended client instance.  New
                # receipts always take the exact branch above.
                device_matches = event_device_id == self.device_id or (
                    isinstance(event_device_id, str) and
                    event_device_id.startswith(self.device_id + "/"))
            if not isinstance(canonical_event_id, str) \
                    or not isinstance(canonical_event_seq, int) \
                    or isinstance(canonical_event_seq, bool) \
                    or canonical_event_seq != cursor["event_seq"] \
                    or not isinstance(event, dict) \
                    or event.get("event_id") != canonical_event_id \
                    or event.get("seq") != canonical_event_seq \
                    or event.get("actor_id") != self.scope["actor_id"] \
                    or event.get("actor_type") != self.scope["actor_type"] \
                    or event.get("owner") != self.scope["principal_id"] \
                    or not device_matches:
                continue
            mutation_id = receipt["client_mutation_id"]
            self._append_record_locked("converged", mutation_id, {
                "observed_cursor": _json_copy(cursor),
                "snapshot_cursor": _json_copy(head),
                "canonical_event_id": canonical_event_id,
                "request_sha256": result["request_sha256"],
            })
            confirmed.append(mutation_id)
        if confirmed:
            state = self._read_state_locked()
            state["last_converged_ids"] = (
                list(state.get("last_converged_ids") or []) + confirmed)[-100:]
            self._write_state_locked(state)
        return confirmed

    def _install_pull_result(self, result):
        with self._locked():
            wrapper = self._load_mirror_locked()
            snapshot = wrapper["snapshot"]
            try:
                checked = protocol.validate_pull_result(
                    result, expected_scope=self.scope,
                    expected_visibility=self.visibility_fingerprint)
                if checked["status"] == "ok":
                    protocol.validate_projection_for_capabilities(
                        checked["changes"], checked["scope"],
                        self.projection_capabilities, partial=True)
            except protocol.SyncProtocolError as error:
                error_class = OfflineSchemaCompatibilityError \
                    if protocol.is_schema_compatibility_error(error) \
                    else OfflineMirrorError
                raise error_class(
                    "pull result failed schema-v1/projection-v%d "
                    "validation: %s" % (
                        self.projection_capabilities["schema_version"], error)
                    ) from error
            if checked["status"] != "ok" \
                    or checked["from_cursor"] != snapshot["cursor"]:
                raise OfflineMirrorError(
                    "pull result does not advance the current mirror")
            projection = dict(snapshot["projection"])
            projection.update(_json_copy(checked["changes"]))
            records = list(snapshot["records"]) + list(checked["records"])
            try:
                advanced = protocol.make_snapshot(
                    self.scope, self.visibility_fingerprint,
                    checked["next_cursor"], projection, records,
                    generated_at=checked["generated_at"])
            except protocol.SyncProtocolError as error:
                error_class = OfflineSchemaCompatibilityError \
                    if protocol.is_schema_compatibility_error(error) \
                    else OfflineMirrorError
                raise error_class(
                    "merged pull projection failed validation: %s" % error) from error
            self.install_snapshot(advanced)
            return bool(checked["records"] or checked["changes"] \
                        or checked["next_cursor"] != checked["from_cursor"])

    @staticmethod
    def _is_unavailable(error):
        return isinstance(error, (
            RemoteUnavailableError, ConnectionError, TimeoutError, OSError))

    @staticmethod
    def _remote_contract_failure_kind(error):
        if error.__class__.__name__ == "SyncSchemaCompatibilityError" \
                or isinstance(error, OfflineSchemaCompatibilityError):
            return "schema_incompatible"
        if error.__class__.__name__ == "SyncResponseError":
            return "remote_contract_invalid"
        return None

    def _remote_contract_report(self, error, report, failure_kind):
        """Keep a verified mirror/outbox usable after non-auth contract drift."""
        usable = self.has_mirror()
        self._set_state(
            mode="offline" if usable else "offline_uninitialized",
            pending_sync=True, mirror_stale=True, last_error=str(error))
        report.update({
            "error": str(error),
            "failure_kind": failure_kind,
            "authentication_required": False,
            "offline_usable": usable,
        })
        return self._sync_report("offline", report)

    def _remote_snapshot(self, remote, allow_scope_change=False):
        method = getattr(remote, "fetch_snapshot", None)
        if not callable(method):
            raise OfflineSyncError("remote adapter has no fetch_snapshot()")
        snapshot = method(allow_scope_change=allow_scope_change)
        return self._validate_snapshot_for_identity(
            snapshot, allow_scope_change=allow_scope_change,
            allow_visibility_change=allow_scope_change
            or self.visibility_fingerprint is None)

    def _remote_pull(self, remote, cursor):
        method = getattr(remote, "pull", None)
        if not callable(method):
            raise OfflineSyncError("remote adapter has no pull()")
        result = method(
            cursor=_json_copy(cursor),
            visibility_fingerprint=self.visibility_fingerprint,
            limit=protocol.MAX_PULL_RECORDS)
        try:
            checked = protocol.validate_pull_result(result)
            if checked["status"] == "ok":
                protocol.validate_projection_for_capabilities(
                    checked["changes"], checked["scope"],
                    self.projection_capabilities, partial=True)
        except protocol.SyncProtocolError as error:
            error_class = OfflineSchemaCompatibilityError \
                if protocol.is_schema_compatibility_error(error) \
                else OfflineMirrorError
            raise error_class(
                "remote pull response failed validation: %s" % error) from error
        if checked["status"] == "ok":
            if checked["scope"] != self.scope:
                raise OfflineIdentityChangedError(
                    "successful pull changed actor or role without a reset")
            if checked["visibility_fingerprint"] != \
                    self.visibility_fingerprint:
                raise OfflineVisibilityChangedError(
                    "successful pull changed visibility without a reset")
        elif not _same_principal_scope(checked["scope"], self.scope):
            raise OfflineIdentityChangedError(
                "pull reset belongs to another server/project/principal")
        return checked

    def _remote_push(self, remote, mutations, known_receipts):
        method = getattr(remote, "push", None)
        if not callable(method):
            raise OfflineSyncError("remote adapter has no push()")
        result = method(
            mutations=_json_copy(mutations),
            known_receipts=list(known_receipts))
        try:
            return protocol.validate_push_result(
                result, expected_scope=self.scope,
                expected_visibility=self.visibility_fingerprint,
                expected_mutation_ids=[
                    item["client_mutation_id"] for item in mutations])
        except protocol.SyncProtocolError as error:
            error_class = OfflineSchemaCompatibilityError \
                if protocol.is_schema_compatibility_error(error) \
                else OfflineSyncError
            raise error_class(
                "remote push response failed validation: %s" % error) from error

    def _pull_until_current(self, remote, allow_initialize=True):
        changed = False
        if not self.has_mirror():
            if not allow_initialize:
                raise OfflineMirrorError("no verified local mirror")
            # A freshly negotiated projection can legitimately select a
            # capability-bound visibility fingerprint different from the
            # legacy pin supplied by an older watcher subscription.  With no
            # mirror there is no cached authority to relabel: validate the
            # stable authenticated principal, then install the server-selected
            # scope/visibility as an explicit initial reset.
            snapshot = self._remote_snapshot(
                remote, allow_scope_change=True)
            self.install_snapshot(
                snapshot, reset=True,
                reset_reason="initial projection capability binding")
            binder = getattr(remote, "bind_verified_identity", None)
            if callable(binder):
                binder(self.scope, self.visibility_fingerprint)
            changed = True
        while True:
            try:
                with self._locked():
                    cursor = self._cursor_locked()
            except (OfflineIdentityChangedError,
                    OfflineVisibilityChangedError):
                # Another authenticated process for this exact actor may have
                # atomically installed a newer visibility generation in the
                # shared principal cache. Reauthenticate and replace it from a
                # fresh full snapshot; never trust/relabel it locally.
                snapshot = self._remote_snapshot(
                    remote, allow_scope_change=True)
                self.install_snapshot(
                    snapshot, reset=True,
                    reset_reason="local visibility pin changed")
                binder = getattr(remote, "bind_verified_identity", None)
                if callable(binder):
                    binder(self.scope, self.visibility_fingerprint)
                changed = True
                continue
            result = self._remote_pull(remote, cursor)
            if result["status"] == "reset_required":
                snapshot = self._remote_snapshot(remote, allow_scope_change=True)
                self.install_snapshot(
                    snapshot, reset=True,
                    reset_reason="%s: %s" % (
                        result["reason_code"], result["reason"]))
                binder = getattr(remote, "bind_verified_identity", None)
                if callable(binder):
                    binder(self.scope, self.visibility_fingerprint)
                changed = True
                continue
            changed = self._install_pull_result(result) or changed
            if not result["has_more"]:
                if result["next_cursor"] != result["head_cursor"]:
                    # ``has_more`` is sequence-based, so a server can announce
                    # a newer context generation at the same event hash. Do not
                    # label the older projection current: verify an exact full
                    # snapshot at the announced head before converging.
                    snapshot = self._remote_snapshot(remote)
                    if snapshot["cursor"] != result["head_cursor"]:
                        raise OfflineMirrorError(
                            "full snapshot does not match the announced sync head")
                    self.install_snapshot(
                        snapshot, reset=False,
                        reset_reason="same-event context advance")
                    changed = True
                break
        with self._locked():
            confirmed = self._mark_converged_locked()
            state = self._read_state_locked()
            state.update({
                "mirror_stale": False,
                "last_verified_remote_cursor": self._cursor_locked(),
            })
            self._write_state_locked(state)
        return changed, confirmed

    def _sync_report(self, status, report):
        report["status"] = status
        current = self.status()
        report["pending_after"] = current["pending_count"]
        report["convergence_awaiting"] = current[
            "convergence_awaiting_receipts"]
        report["convergence_proof"] = current.get("convergence_proof")
        return report

    def synchronize(self, remote):
        """Pull, ordered push, and pull until exact receipt convergence."""
        attempt_at = _utc_now()
        self._set_state(
            mode="syncing", last_attempt_at=attempt_at, last_error=None)
        report = {
            "project": self.project_id, "client_id": self.client_id,
            "device_id": self.device_id, "status": "syncing",
            "pulled_before": False, "pulled_after": False,
            "applied": [], "duplicates": [], "conflicts": [],
            "rejected": [], "blocked": [], "converged": [], "error": None,
        }
        try:
            report["pulled_before"], first_converged = \
                self._pull_until_current(remote)
            report["converged"].extend(first_converged)
        except Exception as error:
            contract_failure = self._remote_contract_failure_kind(error)
            if contract_failure:
                return self._remote_contract_report(
                    error, report, contract_failure)
            if not self._is_unavailable(error):
                if isinstance(error, (OfflineMirrorError,
                                      OfflineIdentityChangedError,
                                      OfflineVisibilityChangedError)):
                    self._set_state(
                        mode="conflict", pending_sync=True, mirror_stale=True,
                        last_error=str(error))
                    report["error"] = str(error)
                    return self._sync_report("conflict", report)
                raise
            self._set_state(
                mode="offline" if self.has_mirror() else "offline_uninitialized",
                pending_sync=True, mirror_stale=True, last_error=str(error))
            report["error"] = str(error)
            return self._sync_report("offline", report)

        with self._locked():
            _, projected = self._journal_locked()
            ready = _json_copy(projected["ready"][:protocol.MAX_MUTATIONS])
            existing_conflicts = [
                item["client_mutation_id"] for item in projected["conflicts"]]
            report["blocked"] = [
                item["client_mutation_id"] for item in projected["blocked"]]
            known_receipts = list(projected["receipts"])
        if existing_conflicts:
            report["conflicts"] = existing_conflicts
            self._set_state(
                mode="conflict", pending_sync=True,
                last_error="unresolved offline mutation conflict")
            return self._sync_report("conflict", report)

        if ready:
            try:
                pushed = self._remote_push(remote, ready, known_receipts)
            except Exception as error:
                contract_failure = self._remote_contract_failure_kind(error)
                if contract_failure:
                    return self._remote_contract_report(
                        error, report, contract_failure)
                if not self._is_unavailable(error):
                    raise
                self._set_state(
                    mode="offline", pending_sync=True, mirror_stale=True,
                    last_error=str(error))
                report["error"] = str(error)
                return self._sync_report("offline", report)
            for mutation, result in zip(ready, pushed["results"]):
                mutation_id = mutation["client_mutation_id"]
                if result["status"] in {"applied", "duplicate"}:
                    remote_instance = str(getattr(
                        remote, "client_instance_id", "") or "").strip()
                    audit_device_id = self.device_id
                    if remote_instance:
                        audit_device_id += "/" + remote_instance
                    self._append_receipt(
                        mutation, result, audit_device_id=audit_device_id)
                    report["applied" if result["status"] == "applied"
                           else "duplicates"].append(mutation_id)
                    continue
                self._append_conflict(mutation, result)
                report["conflicts" if result["status"] == "conflict"
                       else "rejected"].append(mutation_id)
                with self._locked():
                    _, after = self._journal_locked()
                    report["blocked"] = [
                        item["client_mutation_id"] for item in after["blocked"]]
                self._set_state(
                    mode="conflict", pending_sync=True,
                    last_error=result["reason"])
                return self._sync_report("conflict", report)

        if not ready:
            # The pre-push pull already reached the hosted head and also
            # reconciled any receipts left awaiting after an interrupted prior
            # cycle. Avoid a second network request in the one-minute idle
            # watcher path when this cycle had nothing to push.
            final = self.status()
            pending = bool(
                final["pending_count"] or final["conflict_count"]
                or final["convergence_awaiting_count"]
                or final["mirror_stale"])
            self._set_state(
                mode="pending" if pending else "online",
                pending_sync=pending, last_success_at=_utc_now(),
                last_error=None)
            return self._sync_report(
                "pending" if pending else "online", report)

        try:
            report["pulled_after"], final_converged = \
                self._pull_until_current(remote)
            report["converged"].extend(
                item for item in final_converged
                if item not in report["converged"])
        except Exception as error:
            contract_failure = self._remote_contract_failure_kind(error)
            if contract_failure:
                return self._remote_contract_report(
                    error, report, contract_failure)
            if not self._is_unavailable(error):
                if isinstance(error, (OfflineMirrorError,
                                      OfflineIdentityChangedError,
                                      OfflineVisibilityChangedError)):
                    self._set_state(
                        mode="conflict", pending_sync=True, mirror_stale=True,
                        last_error=str(error))
                    report["error"] = str(error)
                    return self._sync_report("conflict", report)
                raise
            self._set_state(
                mode="offline", pending_sync=True, mirror_stale=True,
                last_error=str(error))
            report["error"] = str(error)
            return self._sync_report("offline", report)

        final = self.status()
        pending = bool(
            final["pending_count"] or final["conflict_count"]
            or final["convergence_awaiting_count"] or final["mirror_stale"])
        self._set_state(
            mode="pending" if pending else "online", pending_sync=pending,
            last_success_at=_utc_now(), last_error=None)
        return self._sync_report("pending" if pending else "online", report)

    def convergence_proof(self):
        with self._locked():
            wrapper = self._load_mirror_locked()
            state = self._read_state_locked()
            _, projected = self._journal_locked()
            awaiting = tuple(
                item["client_mutation_id"] for item in projected["awaiting"])
            observed = tuple(projected["converged"])[-100:]
            mirror_stale = bool(state.get("mirror_stale"))
            online = bool(
                state.get("mode") == "online" and not mirror_stale
                and not awaiting and not projected["ready"]
                and not projected["blocked"] and not projected["conflicts"])
            proof = ConvergenceProof(
                normalized_server_url=self.normalized_server_url,
                storage_key=self.storage_key,
                scope=_json_copy(wrapper["scope"]),
                projection_capabilities=_json_copy(
                    wrapper["projection_capabilities"]),
                visibility_fingerprint=wrapper["visibility_fingerprint"],
                cursor=_json_copy(wrapper["snapshot"]["cursor"]),
                snapshot_sha256=wrapper["snapshot_sha256"],
                mirror_verified_at=wrapper["verified_at"],
                mirror_stale=mirror_stale,
                convergence_awaiting_receipts=awaiting,
                own_canonical_events_observed=observed,
                online=online,
            ).as_dict()
            return validate_convergence_proof(
                proof, expected_server_url=self.normalized_server_url,
                expected_project=self.project_id, expected_scope=self.scope,
                expected_projection_capabilities=
                    self.projection_capabilities)

    def status(self):
        with self._locked():
            state = self._read_state_locked()
            records, projected = self._journal_locked()
            mirror_valid = False
            cursor = protocol.make_cursor(0, protocol.GENESIS_HASH, 0)
            proof = None
            if self.has_mirror():
                wrapper = self._load_mirror_locked()
                cursor = _json_copy(wrapper["snapshot"]["cursor"])
                mirror_valid = True
            pending_count = len(projected["ready"]) + len(projected["blocked"])
            mode = state.get("mode") or "uninitialized"
            if projected["conflicts"]:
                mode = "conflict"
            awaiting_ids = [
                item["client_mutation_id"] for item in projected["awaiting"]]
            mirror_stale = bool(state.get("mirror_stale"))
            pending_sync = bool(
                pending_count or projected["conflicts"] or awaiting_ids
                or mirror_stale)
            if mirror_valid:
                proof = self.convergence_proof()
            return {
                **_json_copy(state),
                "mode": mode,
                "normalized_server_url": self.normalized_server_url,
                "storage_key": self.storage_key,
                "mirror_key": self.mirror_key,
                "scope": _json_copy(self.scope),
                "projection_capabilities": _json_copy(
                    self.projection_capabilities),
                "visibility_fingerprint": self.visibility_fingerprint,
                "read_source": "verified_local_mirror" if mirror_valid else None,
                "mirror_valid": mirror_valid,
                "mirror_cursor": cursor,
                "mirror_stale": mirror_stale,
                "pending_sync": pending_sync,
                "pending_count": pending_count,
                "ready_count": len(projected["ready"]),
                "blocked_count": len(projected["blocked"]),
                "conflict_count": len(projected["conflicts"]),
                "convergence_awaiting_count": len(awaiting_ids),
                "convergence_awaiting_receipts": awaiting_ids,
                "acknowledged_count": len(projected["converged"]),
                "journal_records": len(records),
                "orphan_temporary_files": sorted(
                    item.name for item in self.temporary_directory.iterdir()),
                "convergence_proof": proof,
            }

    def pending_mutations(self):
        with self._locked():
            _, projected = self._journal_locked()
            ready = {item["client_mutation_id"] for item in projected["ready"]}
            blocked = {
                item["client_mutation_id"] for item in projected["blocked"]}
            awaiting = {
                item["client_mutation_id"] for item in projected["awaiting"]}
            result = []
            for mutation in projected["mutations"]:
                mutation_id = mutation["client_mutation_id"]
                if mutation_id not in ready | blocked | awaiting:
                    continue
                item = _json_copy(mutation)
                item["sync_state"] = (
                    "ready" if mutation_id in ready else
                    "blocked" if mutation_id in blocked else
                    "awaiting_convergence")
                result.append(item)
            return result

    def conflicts(self):
        with self._locked():
            _, projected = self._journal_locked()
            return _json_copy(projected["conflicts"])

    @staticmethod
    def _resource_for_operation(operation):
        normalized = str(operation or "").strip().lower()
        exact = _OPERATION_RESOURCE_ALIASES.get(normalized)
        if exact is not None:
            return exact
        prefix = normalized.split(".", 1)[0]
        return _RESOURCE_ALIASES.get(prefix)

    def pending_overlays(self, section=None):
        wanted = _RESOURCE_ALIASES.get(
            str(section).lower().replace("-", "_")) if section else None
        result = []
        for mutation in self.pending_mutations():
            resource = self._resource_for_operation(mutation["operation"])
            if wanted is not None and resource != wanted:
                continue
            result.append({
                "resource": resource,
                "client_mutation_id": mutation["client_mutation_id"],
                "operation": mutation["operation"],
                "payload": _json_copy(mutation["payload"]),
                "metadata": _json_copy(mutation["metadata"]),
                "sync_state": mutation["sync_state"],
            })
        return result

    def read_section(self, section, include_pending=False):
        name = str(section or "").strip().lower().replace("-", "_")
        snapshot = self.local_snapshot()
        projection = snapshot["projection"]
        if name in {"history", "events", "ledger"}:
            value = [record["event"] for record in snapshot["records"]
                     if record["kind"] == "event"]
            resource = "events"
        elif name in {"chain", "records"}:
            value = snapshot["records"]
            resource = "records"
        else:
            resource = _RESOURCE_ALIASES.get(name)
            if resource is None:
                raise OfflineMirrorError(
                    "unknown identity mirror section %r" % section)
            value = projection.get(resource)
            if resource == "handoffs" and name == "handoff":
                value = value[-1] if value else None
        copied = _json_copy(value)
        if not include_pending:
            return copied
        return {
            "records": copied,
            "pending": self.pending_overlays(resource),
        }

    def rules_for_role(self, role=None):
        requested = str(role or self.scope["role"]).lower()
        if self.scope["actor_type"] != "human" \
                and requested != self.scope["role"]:
            raise OfflineIdentityChangedError(
                "cannot unlock another role's cached rules")
        rules = self.read_section("rules") or []
        return sorted([
            item for item in rules
            if bool(item.get("enabled", 1))
            and str(item.get("scope") or "everyone") in
            ({"everyone", requested} if self.scope["actor_type"] != "human"
             else {"everyone", "director", "advisor", "worker", "human"})
        ], key=lambda item: (
            int(item.get("priority") or 100), str(item.get("rule_id") or "")))

    @staticmethod
    def _search_terms(query):
        terms = re.findall(r"[A-Za-z0-9]+", str(query or "").lower())
        if not terms:
            raise OfflineMirrorError("offline search requires a word or number")
        return terms

    def search_local(self, query, limit=100):
        terms = self._search_terms(query)
        snapshot = self.local_snapshot()
        candidates = []
        for resource, value in snapshot["projection"].items():
            rows = value if isinstance(value, list) else [value]
            for index, item in enumerate(rows):
                candidates.append((resource, index, item))
        for record in snapshot["records"]:
            if record["kind"] == "event":
                candidates.append(("event", record["seq"], record["event"]))
        for overlay in self.pending_overlays():
            candidates.append((
                "pending_mutation", overlay["client_mutation_id"], overlay))
        results = []
        bounded = max(1, min(int(limit), 1000))
        for kind, identifier, item in candidates:
            normalized = " ".join(re.findall(
                r"[A-Za-z0-9]+", _canonical_bytes(item).decode("utf-8").lower()))
            if all(term in normalized for term in terms):
                results.append({
                    "kind": kind, "id": identifier,
                    "record": _json_copy(item),
                })
                if len(results) >= bounded:
                    break
        return results

    def local_view(self):
        projection = self.local_projection()
        resources = {
            key: {"records": _json_copy(value),
                  "pending": self.pending_overlays(key)}
            for key, value in projection.items()
        }
        return {
            "project": self.project_id,
            "status": self.status(),
            "snapshot": self.local_snapshot(),
            "resources": resources,
            "pending_mutations": self.pending_mutations(),
            "conflicts": self.conflicts(),
        }


__all__ = [
    "MIRROR_FORMAT", "SYNC_STATE_FORMAT", "JOURNAL_RECORD_FORMAT",
    "CONVERGENCE_PROOF_FORMAT", "OFFLINE_SYNC_SCHEMA_VERSION",
    "MIRROR_SCHEMA_VERSION", "SYNC_STATE_SCHEMA_VERSION",
    "OfflineSyncError", "OfflineMirrorError",
    "OfflineSchemaCompatibilityError", "OfflineJournalError",
    "OfflineConflictError", "OfflineIdentityChangedError",
    "OfflineVisibilityChangedError",
    "RemoteUnavailableError", "ConvergenceProof", "normalize_server_url",
    "mirror_storage_key", "validate_convergence_proof", "OfflineProjectSync",
]
