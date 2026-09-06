"""Embeddable server-side engine for Attacca schema-v1 synchronization.

The engine deliberately contains no HTTP, MCP, authentication-token, or
Attacca application imports.  A trusted transport authenticates the request
and passes the resulting scope separately from the untrusted wire envelope.
Small injected callbacks adapt the canonical Attacca database to this engine:

* authorization decides whether the authenticated scope may read, push, and
  execute each operation;
* ledger callbacks expose a cursor and contiguous canonical events;
* one visibility projector returns policy material, an identity-filtered
  projection, and the event sequence numbers visible to that identity;
* the mutation callback applies one operation on the same SQLite connection.

Every new mutation is reserved, applied, and receipted in one savepoint.  A
callback must therefore use the supplied connection and must not commit,
rollback, or perform an irreversible external side effect.  A crash before
savepoint release rolls back both the domain write and reservation.  A lost
response after release is an exact duplicate on retry and returns the stored
receipt without applying the operation twice.
"""

from __future__ import annotations

import itertools
import json
import re
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

try:  # Namespace package when imported as ``attacca.sync_server``.
    from . import sync_protocol as protocol
except (ImportError, ValueError):  # Direct module loading in isolated tests.
    import sync_protocol as protocol


JOURNAL_SCHEMA_VERSION = 1
MAX_RECEIPT_LOOKUP_IDS = 100

# ---------------------------------------------------------------------------
# Live receipt retention
#
# A live receipt answers "did my write land?".  Deleting an ``applied`` row
# would answer "no record at all", which every client is entitled to read as
# *provably absent* and therefore safe to replay -- so hard-deleting applied
# rows would turn retention into a double-apply bug for any client whose
# outage outlived the window.  Retention therefore only *tombstones* applied
# rows: the retained result body (up to 16 KB) is dropped while the durable
# proof (status, request hash, canonical event mapping, server cursor,
# timestamp) is kept forever.  ``failed`` rows already mean "nothing applied",
# so they are deleted outright, and ``reserved`` rows are never touched at all
# because their outcome is still unknown.
# ---------------------------------------------------------------------------
LIVE_RETENTION_MAX_AGE_DAYS = 30
LIVE_RETENTION_MAX_ROWS_PER_DEVICE = 5000
LIVE_RETENTION_MAX_ROWS_PER_PASS = 500
# A reservation whose process died is finalized only after this long, so a
# slow-but-honest dispatch is never declared failed underneath itself.
LIVE_RESERVATION_GRACE_SECONDS = 300
LIVE_RECOVERY_SCAN_LIMIT = 500
_LIVE_RETENTION_KEYS = {
    "max_age_days", "max_rows_per_device", "max_rows_per_pass",
    "reservation_grace_seconds",
}

_RESERVED_ATTRIBUTION_KEYS = {
    "actor_id", "actor_type", "authenticated_scope", "attribution",
    "device_id", "human_user", "identity", "owner", "principal_id",
    "project_id", "role", "run_by_user", "server_id", "workspace",
}
_WIRE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$")


class SyncServerError(RuntimeError):
    """Base error for adapter, journal, or canonical server-state failures."""


class SyncServerAuthorizationError(SyncServerError):
    """The trusted scope is not authorized for a requested server action."""

    def __init__(self, action):
        super().__init__("authenticated scope is not authorized for %s" % action)
        self.action = action


class SyncServerStateError(SyncServerError):
    """Injected canonical state is malformed, incomplete, or inconsistent."""


class MutationConflict(Exception):
    """An adapter may raise this to return a structured precondition conflict."""

    def __init__(self, code, reason, current=None, retryable=False):
        super().__init__(reason)
        self.code = str(code or "precondition_conflict")
        self.reason = str(reason or "mutation precondition failed")
        self.current = current
        self.retryable = bool(retryable)


class MutationRejected(Exception):
    """An adapter may raise this for a safe, structured operation rejection."""

    def __init__(self, code, reason, current=None):
        super().__init__(reason)
        self.code = str(code or "mutation_rejected")
        self.reason = str(reason or "mutation was rejected")
        self.current = current


class _AbortMutation(Exception):
    def __init__(self, result):
        super().__init__(result.get("reason") or result.get("code"))
        self.result = result


@dataclass(frozen=True)
class ApplyRequest:
    """Sanitized operation passed to the application mutation adapter.

    ``authenticated_scope`` and ``attribution`` are derived only from the
    trusted caller.  Identity-like fields in queued metadata are removed.
    Operation payload remains operation data; it is never used by this engine
    to select the project, principal, actor, role, or journal partition.
    """

    authenticated_scope: dict
    attribution: dict
    client_mutation_id: str
    client_id: str
    device_id: str
    client_sequence: int
    operation: str
    payload: dict
    metadata: dict
    base_cursor: dict
    depends_on: tuple
    request_sha256: str


@dataclass(frozen=True)
class SyncServerAdapters:
    """Callbacks needed to embed :class:`SyncServerEngine`.

    Signatures::

      authorize(conn, trusted_scope, action, operation_or_none) -> bool
      head_cursor(conn, project_id) -> schema-v1 cursor
      read_events(conn, project_id, after_seq, through_seq, limit) -> events
      visibility_projector(
          conn, trusted_scope, mode, from_cursor, through_cursor, events
      ) -> {
          "visibility_policy": JSON,
          "projection": identity projection,       # except mode=policy
          "visible_event_seqs": [int, ...],         # except mode=policy
      }
      apply_mutation(conn, ApplyRequest) -> {
          "result": {...}, "server_cursor": cursor
      }

    A projector may declare ``supports_projection_resources = True`` to be
    called with one extra argument in ``pull`` mode: the exact list of
    resources that response may deliver.  Any other projector is called
    unchanged and its projection is narrowed afterwards.

    ``check_precondition`` has the same first two arguments as
    ``apply_mutation`` and returns ``None`` or a conflict mapping containing
    code/reason/current/retryable.  ``transaction`` optionally returns a
    context manager for one atomic operation; the default is a SQLite
    savepoint.  ``fault_injector(stage, ApplyRequest)`` exists for deterministic
    crash-window testing and is normally ``None``.
    """

    authorize: object
    head_cursor: object
    read_events: object
    visibility_projector: object
    apply_mutation: object
    check_precondition: object = None
    transaction: object = None
    fault_injector: object = None


def _json_copy(value, max_bytes=None):
    return json.loads(protocol.canonical_json_bytes(
        value, max_bytes=max_bytes).decode("utf-8"))


def _row_dict(cursor, row):
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        return dict(row)
    columns = [item[0] for item in cursor.description or ()]
    return dict(zip(columns, row))


def _wire_identifier(label, value):
    if not isinstance(value, str) or not _WIRE_IDENTIFIER_RE.fullmatch(value):
        raise SyncServerError("%s has unsafe syntax" % label)
    return value


def _live_retention_policy(value=None):
    """Validate one live-receipt retention policy, filling in the defaults."""
    policy = {
        "max_age_days": LIVE_RETENTION_MAX_AGE_DAYS,
        "max_rows_per_device": LIVE_RETENTION_MAX_ROWS_PER_DEVICE,
        "max_rows_per_pass": LIVE_RETENTION_MAX_ROWS_PER_PASS,
        "reservation_grace_seconds": LIVE_RESERVATION_GRACE_SECONDS,
    }
    if value is None:
        return policy
    if not isinstance(value, dict):
        raise TypeError("live_retention must be a mapping")
    unknown = sorted(set(value) - _LIVE_RETENTION_KEYS)
    if unknown:
        raise ValueError(
            "unknown live_retention key(s): %s" % ", ".join(unknown))
    for key, item in value.items():
        if isinstance(item, bool) or not isinstance(item, int) or item < 1:
            raise ValueError("live_retention.%s must be a positive int" % key)
        policy[key] = int(item)
    return policy


def _parse_timestamp(value):
    """Parse one canonical schema-v1 timestamp, or return None."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _age_seconds(value, now=None):
    """Seconds since ``value``; None when it cannot be compared."""
    parsed = _parse_timestamp(value)
    if parsed is None:
        return None
    return ((now or datetime.now(timezone.utc)) - parsed).total_seconds()


def _sanitize_metadata(value):
    if isinstance(value, dict):
        return {
            key: _sanitize_metadata(child)
            for key, child in value.items()
            if key.lower() not in _RESERVED_ATTRIBUTION_KEYS
        }
    if isinstance(value, list):
        return [_sanitize_metadata(child) for child in value]
    return value


class SyncServerEngine:
    """Identity-scoped snapshot/pull/push engine with an idempotency journal."""

    def __init__(self, connection, adapters, busy_timeout_ms=5000,
                 live_retention=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be sqlite3.Connection")
        if not isinstance(adapters, SyncServerAdapters):
            raise TypeError("adapters must be SyncServerAdapters")
        for name in (
                "authorize", "head_cursor", "read_events",
                "visibility_projector", "apply_mutation"):
            if not callable(getattr(adapters, name)):
                raise TypeError("adapter %s must be callable" % name)
        if adapters.check_precondition is not None \
                and not callable(adapters.check_precondition):
            raise TypeError("check_precondition adapter must be callable")
        if adapters.transaction is not None and not callable(adapters.transaction):
            raise TypeError("transaction adapter must be callable")
        if adapters.fault_injector is not None \
                and not callable(adapters.fault_injector):
            raise TypeError("fault_injector adapter must be callable")
        self.connection = connection
        self.adapters = adapters
        self.live_retention = _live_retention_policy(live_retention)
        self._lock = threading.RLock()
        self._savepoint_numbers = itertools.count(1)
        timeout = int(busy_timeout_ms)
        if timeout < 0 or timeout > 60000:
            raise ValueError("busy_timeout_ms must be 0..60000")
        self.connection.execute("PRAGMA busy_timeout=%d" % timeout)
        self._ensure_journal_schema()

    def _ensure_journal_schema(self):
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS sync_operations (
              schema_version INTEGER NOT NULL,
              project_id TEXT NOT NULL,
              principal_id TEXT NOT NULL,
              actor_id TEXT NOT NULL,
              device_id TEXT NOT NULL,
              client_mutation_id TEXT NOT NULL,
              client_id TEXT NOT NULL,
              client_sequence INTEGER NOT NULL,
              request_sha256 TEXT NOT NULL,
              mutation_json TEXT NOT NULL,
              state TEXT NOT NULL CHECK (state IN ('reserved', 'applied')),
              receipt_json TEXT,
              created_at TEXT NOT NULL,
              committed_at TEXT,
              PRIMARY KEY (
                project_id, principal_id, actor_id, device_id,
                client_mutation_id
              )
            )
        """)
        required = {
            "schema_version", "project_id", "principal_id", "actor_id",
            "device_id", "client_mutation_id", "client_id",
            "client_sequence", "request_sha256", "mutation_json", "state",
            "receipt_json", "created_at", "committed_at",
        }
        columns = {
            row[1] for row in self.connection.execute(
                "PRAGMA table_info(sync_operations)").fetchall()
        }
        if not required <= columns:
            raise SyncServerStateError(
                "sync_operations table has an incompatible schema")
        self.connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_sync_operations_fifo
            ON sync_operations (
              project_id, principal_id, actor_id, device_id, client_id,
              client_sequence
            )
        """)
        # Live hosted writes carry the very same client_mutation_id but no
        # queued schema-v1 envelope, so they keep their own partition of the
        # receipt store.  Mixing them into ``sync_operations`` would collide
        # on that table's primary key and break its client-mutation
        # validation; a separate table keeps replay and live idempotency
        # independently verifiable.
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS sync_live_operations (
              schema_version INTEGER NOT NULL,
              project_id TEXT NOT NULL,
              principal_id TEXT NOT NULL,
              actor_id TEXT NOT NULL,
              device_id TEXT NOT NULL,
              client_mutation_id TEXT NOT NULL,
              tool TEXT NOT NULL,
              request_sha256 TEXT NOT NULL,
              state TEXT NOT NULL CHECK (
                state IN ('reserved', 'applied', 'failed')
              ),
              receipt_json TEXT,
              created_at TEXT NOT NULL,
              committed_at TEXT,
              PRIMARY KEY (
                project_id, principal_id, actor_id, device_id,
                client_mutation_id
              )
            )
        """)
        live_required = {
            "schema_version", "project_id", "principal_id", "actor_id",
            "device_id", "client_mutation_id", "tool", "request_sha256",
            "state", "receipt_json", "created_at", "committed_at",
        }
        live_columns = {
            row[1] for row in self.connection.execute(
                "PRAGMA table_info(sync_live_operations)").fetchall()
        }
        if not live_required <= live_columns:
            raise SyncServerStateError(
                "sync_live_operations table has an incompatible schema")
        # Nullable additions, so a database written by an older generation
        # keeps working and one written here stays readable by it.  They are
        # added in place rather than behind a schema-version bump because no
        # wire envelope, digest, or stored receipt shape changes.
        #
        #   reserved_at_seq   ledger head when the id was claimed.  Its
        #                     presence also marks a row written by the
        #                     generation that applies the domain write and its
        #                     receipt in one transaction, so a stale
        #                     reservation from that generation *proves*
        #                     nothing was applied.
        #   applied_event_*   the canonical event this mutation produced, so
        #                     recovery and retention never have to parse the
        #                     receipt body to find it.
        #   pruned_at         when retention last trimmed this row, so the
        #                     opportunistic trigger is idempotent.
        for column, definition in (
                ("reserved_at_seq", "INTEGER"),
                ("applied_event_id", "TEXT"),
                ("applied_event_seq", "INTEGER"),
                ("pruned_at", "TEXT")):
            if column not in live_columns:
                self.connection.execute(
                    "ALTER TABLE sync_live_operations ADD COLUMN %s %s"
                    % (column, definition))
        self.connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_sync_live_operations_retention
            ON sync_live_operations (
              project_id, principal_id, actor_id, device_id, state,
              pruned_at, created_at
            )
        """)

    @contextmanager
    def _sqlite_savepoint(self):
        name = "attacca_sync_%d" % next(self._savepoint_numbers)
        self.connection.execute("SAVEPOINT %s" % name)
        try:
            yield
        except BaseException:
            self.connection.execute("ROLLBACK TO %s" % name)
            self.connection.execute("RELEASE %s" % name)
            raise
        else:
            self.connection.execute("RELEASE %s" % name)

    @contextmanager
    def _sqlite_write_transaction(self):
        if self.connection.in_transaction:
            with self._sqlite_savepoint():
                yield
            return
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise
        else:
            self.connection.execute("COMMIT")

    def _transaction(self, write=False):
        if self.adapters.transaction is not None:
            transaction = self.adapters.transaction(self.connection)
            if not hasattr(transaction, "__enter__") \
                    or not hasattr(transaction, "__exit__"):
                raise SyncServerStateError(
                    "transaction adapter must return a context manager")
            return transaction
        return self._sqlite_write_transaction() if write \
            else self._sqlite_savepoint()

    def _trusted_scope(self, scope):
        return protocol.validate_scope(scope)

    def _authorized(self, scope, action, operation=None):
        allowed = self.adapters.authorize(
            self.connection, _json_copy(scope), action, operation)
        return allowed is True

    def _require_authorized(self, scope, action):
        if not self._authorized(scope, action):
            raise SyncServerAuthorizationError(action)

    def _head(self, scope):
        value = self.adapters.head_cursor(
            self.connection, scope["project_id"])
        try:
            return protocol.validate_cursor(value)
        except protocol.SyncProtocolError as error:
            raise SyncServerStateError(
                "head_cursor adapter returned an invalid cursor: %s" % error) from error

    def _events(self, scope, after_seq, through_seq, limit):
        raw = self.adapters.read_events(
            self.connection, scope["project_id"], int(after_seq),
            int(through_seq), limit)
        try:
            events = list(raw)
        except TypeError as error:
            raise SyncServerStateError(
                "read_events adapter must return an iterable") from error
        if limit is not None and len(events) > int(limit):
            raise SyncServerStateError("read_events adapter ignored its limit")
        return [_json_copy(item, max_bytes=protocol.MAX_MUTATION_BYTES * 2)
                for item in events]

    def _project_view(self, scope, mode, start, through, events,
                      projection_capabilities=None,
                      projection_resources=None):
        projector = self.adapters.visibility_projector
        arguments = [
            self.connection, _json_copy(scope), mode,
            _json_copy(start) if start is not None else None,
            _json_copy(through) if through is not None else None,
            _json_copy(events),
        ]
        if projection_resources is not None and getattr(
                projector, "supports_projection_resources", False):
            # A projector that understands the narrowed request builds only
            # those resources; every other projector is narrowed below.
            arguments.append(list(projection_resources))
        raw = projector(*arguments)
        if not isinstance(raw, dict) or "visibility_policy" not in raw:
            raise SyncServerStateError(
                "visibility_projector must return visibility_policy")
        policy = _json_copy(raw["visibility_policy"], max_bytes=512 * 1024)
        selected_capabilities = protocol.negotiate_projection_capabilities(
            projection_capabilities)
        fingerprint = protocol.visibility_fingerprint(
            scope, protocol.projection_visibility_policy(
                policy, selected_capabilities))
        if mode == "policy":
            return fingerprint, {}, set()
        if "projection" not in raw or "visible_event_seqs" not in raw:
            raise SyncServerStateError(
                "visibility_projector omitted projection/event visibility")
        projection = protocol.filter_projection_for_capabilities(
            _json_copy(
                raw["projection"], max_bytes=protocol.MAX_SNAPSHOT_BYTES),
            scope, selected_capabilities, partial=mode == "pull")
        if projection_resources is not None:
            # A pull-only delivered subset.  Validation above still ran
            # against everything the projector returned, so narrowing here
            # can only remove already validated resources - it can never let
            # an unvalidated or cross-project resource through.
            requested = set(projection_resources)
            projection = {key: value for key, value in projection.items()
                          if key in requested}
        visible_raw = raw["visible_event_seqs"]
        if not isinstance(visible_raw, (list, tuple, set)):
            raise SyncServerStateError("visible_event_seqs must be a collection")
        visible = set()
        candidate = {item.get("seq") for item in events}
        for seq in visible_raw:
            if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
                raise SyncServerStateError("visible event sequence is invalid")
            if seq not in candidate:
                raise SyncServerStateError(
                    "projector marked an event outside the candidate window")
            visible.add(seq)
        return fingerprint, projection, visible

    @staticmethod
    def _chain_records(events, visible):
        records = []
        for event in events:
            if event.get("seq") in visible:
                records.append(protocol.make_visible_record(event))
            else:
                records.append(protocol.make_redacted_anchor(
                    event.get("seq"), event.get("prev_hash"), event.get("hash")))
        return records

    @staticmethod
    def _cursor_for_event(event):
        context_version = event.get("context_version")
        if not isinstance(context_version, int) \
                or isinstance(context_version, bool) or context_version < 0:
            raise SyncServerStateError(
                "canonical event has invalid context_version")
        return protocol.make_cursor(
            event.get("seq"), event.get("hash"), context_version)

    def snapshot(self, authenticated_scope, *, projection_capabilities=None):
        """Return a complete identity-filtered snapshot for a trusted caller."""
        scope = self._trusted_scope(authenticated_scope)
        self._require_authorized(scope, "sync.read")
        with self._lock, self._transaction():
            head = self._head(scope)
            events = self._events(scope, 0, head["event_seq"], None)
            fingerprint, projection, visible = self._project_view(
                scope, "snapshot", None, head, events,
                projection_capabilities=projection_capabilities)
            records = self._chain_records(events, visible)
            return protocol.make_snapshot(
                scope, fingerprint, head, projection, records)

    def _cursor_is_canonical(self, scope, cursor, head):
        if cursor["event_seq"] == 0:
            return cursor["event_hash"] == protocol.GENESIS_HASH \
                and cursor["context_version"] == 0
        if cursor["event_seq"] > head["event_seq"] \
                or cursor["context_version"] > head["context_version"]:
            return False
        event = self._events(
            scope, cursor["event_seq"] - 1, cursor["event_seq"], 1)
        if len(event) != 1 or event[0].get("seq") != cursor["event_seq"]:
            return False
        event_cursor = self._cursor_for_event(event[0])
        return event_cursor["event_hash"] == cursor["event_hash"] \
            and event_cursor["context_version"] <= cursor["context_version"]

    def pull(self, authenticated_scope, envelope, *,
             projection_capabilities=None, projection_resources=None):
        """Return a bounded delta or ``reset_required`` for a stale/forked view.

        ``projection_resources`` narrows only the resources THIS response
        delivers.  It is not a capability offer: the negotiated shape, and
        therefore the visibility fingerprint, is unchanged, so a client
        recovering from an oversized response can fetch one resource at a
        time without forcing a full reset.
        """
        scope = self._trusted_scope(authenticated_scope)
        self._require_authorized(scope, "sync.read")
        request = protocol.validate_pull_request(
            envelope, expected_scope=scope)
        subset = protocol.validate_projection_subset(
            projection_resources,
            capabilities=protocol.negotiate_projection_capabilities(
                projection_capabilities))
        with self._lock, self._transaction():
            head = self._head(scope)
            fingerprint, _, _ = self._project_view(
                scope, "policy", request["cursor"], head, [],
                projection_capabilities=projection_capabilities)
            if request["visibility_fingerprint"] != fingerprint:
                return protocol.make_reset_required(
                    scope, fingerprint, "visibility_changed",
                    "authenticated role or visibility policy changed", head)
            if not self._cursor_is_canonical(scope, request["cursor"], head):
                return protocol.make_reset_required(
                    scope, fingerprint, "cursor_diverged",
                    "local cursor is missing, stale, or on another hash chain", head)
            start = request["cursor"]
            events = self._events(
                scope, start["event_seq"], head["event_seq"], request["limit"])
            if head["event_seq"] > start["event_seq"] and not events:
                raise SyncServerStateError(
                    "read_events returned no progress before the canonical head")
            end = self._cursor_for_event(events[-1]) if events else start
            if end["event_seq"] == head["event_seq"] \
                    and end["event_hash"] == head["event_hash"]:
                # Projection context may advance without adding another ledger
                # event.  Carry the canonical head context so a current client
                # does not repeat an otherwise empty pull forever.
                end = head
            fingerprint_after, changes, visible = self._project_view(
                scope, "pull", start, end, events,
                projection_capabilities=projection_capabilities,
                projection_resources=subset)
            if fingerprint_after != fingerprint:
                return protocol.make_reset_required(
                    scope, fingerprint_after, "visibility_changed",
                    "visibility policy changed while preparing the delta", head)
            records = self._chain_records(events, visible)
            return protocol.make_pull_result(
                scope, fingerprint, start, end, head, records, changes)

    @staticmethod
    def _journal_key(scope, device_id, mutation_id):
        return (
            scope["project_id"], scope["principal_id"], scope["actor_id"],
            device_id, mutation_id,
        )

    def _journal_row(self, scope, device_id, mutation_id):
        cursor = self.connection.execute("""
            SELECT * FROM sync_operations
            WHERE project_id=? AND principal_id=? AND actor_id=?
              AND device_id=? AND client_mutation_id=?
        """, self._journal_key(scope, device_id, mutation_id))
        return _row_dict(cursor, cursor.fetchone())

    def _receipt_from_row(self, row, scope):
        if row is None:
            return None
        if row.get("state") != "applied" or not row.get("receipt_json"):
            raise SyncServerStateError(
                "sync journal contains a non-atomic reservation")
        try:
            value = json.loads(row["receipt_json"])
            receipt = protocol.validate_stored_receipt(
                value, expected_scope=scope)
            mutation = protocol.validate_client_mutation(
                json.loads(row["mutation_json"]), expected_scope=scope)
        except (TypeError, ValueError, json.JSONDecodeError,
                protocol.SyncProtocolError) as error:
            raise SyncServerStateError(
                "sync journal contains an invalid stored receipt") from error
        if row.get("schema_version") != JOURNAL_SCHEMA_VERSION \
                or row.get("project_id") != scope["project_id"] \
                or row.get("principal_id") != scope["principal_id"] \
                or row.get("actor_id") != scope["actor_id"] \
                or row.get("device_id") != mutation["device_id"] \
                or row.get("client_mutation_id") != mutation["client_mutation_id"] \
                or row.get("client_id") != mutation["client_id"] \
                or row.get("client_sequence") != mutation["client_sequence"] \
                or row.get("request_sha256") != mutation["request_sha256"] \
                or receipt["request_sha256"] != mutation["request_sha256"]:
            raise SyncServerStateError(
                "sync journal row, mutation, and receipt disagree")
        return receipt

    def _known_receipts(self, scope, device_id, client_id):
        cursor = self.connection.execute("""
            SELECT client_mutation_id FROM sync_operations
            WHERE project_id=? AND principal_id=? AND actor_id=?
              AND device_id=? AND client_id=? AND state='applied'
        """, (
            scope["project_id"], scope["principal_id"], scope["actor_id"],
            device_id, client_id,
        ))
        return {row[0] for row in cursor.fetchall()}

    def _dependency_result(self, scope, device_id, client_id, mutation_id):
        row = self._journal_row(scope, device_id, mutation_id)
        if row is not None and row.get("client_id") != client_id:
            return None
        receipt = self._receipt_from_row(row, scope) if row else None
        return receipt["applied"]["result"] if receipt else None

    @staticmethod
    def _resolve_reference(reference, mappings):
        mutation_id = reference["$local_ref"]
        if mutation_id not in mappings:
            raise MutationRejected(
                "unresolved_local_ref",
                "local reference dependency has no successful result")
        value = mappings[mutation_id]
        for segment in reference["path"]:
            if isinstance(value, dict) and segment in value:
                value = value[segment]
            elif isinstance(value, list) and segment.isdigit() \
                    and int(segment) < len(value):
                value = value[int(segment)]
            else:
                raise MutationRejected(
                    "unresolved_local_ref",
                    "local reference result path does not exist")
        return _json_copy(value)

    def _resolve_local_refs(self, value, mappings):
        if isinstance(value, dict):
            if set(value) == {"$local_ref", "path"}:
                return self._resolve_reference(value, mappings)
            return {key: self._resolve_local_refs(child, mappings)
                    for key, child in value.items()}
        if isinstance(value, list):
            return [self._resolve_local_refs(child, mappings) for child in value]
        return value

    @staticmethod
    def _apply_request(scope, mutation, resolved_payload):
        metadata = _sanitize_metadata(_json_copy(mutation["metadata"]))
        attribution = {
            "server_id": scope["server_id"],
            "project_id": scope["project_id"],
            "principal_id": scope["principal_id"],
            "actor_id": scope["actor_id"],
            "actor_type": scope["actor_type"],
            "role": scope["role"],
            "device_id": mutation["device_id"],
        }
        return ApplyRequest(
            authenticated_scope=_json_copy(scope),
            attribution=attribution,
            client_mutation_id=mutation["client_mutation_id"],
            client_id=mutation["client_id"],
            device_id=mutation["device_id"],
            client_sequence=mutation["client_sequence"],
            operation=mutation["operation"],
            payload=_json_copy(resolved_payload),
            metadata=metadata,
            base_cursor=_json_copy(mutation["base_cursor"]),
            depends_on=tuple(mutation["depends_on"]),
            request_sha256=mutation["request_sha256"],
        )

    def _fault(self, stage, request):
        if self.adapters.fault_injector is not None:
            self.adapters.fault_injector(stage, request)

    def _fifo_conflict(self, scope, mutation, head):
        cursor = self.connection.execute("""
            SELECT MAX(client_sequence) FROM sync_operations
            WHERE project_id=? AND principal_id=? AND actor_id=?
              AND device_id=? AND client_id=? AND state='applied'
        """, (
            scope["project_id"], scope["principal_id"], scope["actor_id"],
            mutation["device_id"], mutation["client_id"],
        ))
        maximum = cursor.fetchone()[0]
        if maximum is None:
            return None
        expected = int(maximum) + 1
        if mutation["client_sequence"] == expected:
            return None
        if mutation["client_sequence"] < expected:
            return protocol.conflict_result(
                scope, mutation, "client_sequence_reused",
                "client sequence is older than the committed FIFO head",
                current={"expected_client_sequence": expected},
                retryable=False, server_cursor=head)
        return protocol.conflict_result(
            scope, mutation, "client_sequence_gap",
            "client sequence skipped an uncommitted FIFO operation",
            current={"expected_client_sequence": expected},
            retryable=True, server_cursor=head)

    def _existing_outcome(self, row, scope, mutation):
        receipt = self._receipt_from_row(row, scope)
        return protocol.stored_receipt_outcome(receipt, mutation, scope)

    def _reserve_apply_receipt(self, scope, mutation, mappings):
        existing = self._journal_row(
            scope, mutation["device_id"], mutation["client_mutation_id"])
        if existing is not None:
            return self._existing_outcome(existing, scope, mutation)
        try:
            resolved_payload = self._resolve_local_refs(
                mutation["payload"], mappings)
        except MutationRejected as error:
            return protocol.rejected_result(
                scope, mutation, error.code, error.reason,
                current=error.current, server_cursor=self._head(scope))
        request = self._apply_request(scope, mutation, resolved_payload)
        try:
            with self._transaction(write=True):
                existing = self._journal_row(
                    scope, mutation["device_id"],
                    mutation["client_mutation_id"])
                if existing is not None:
                    return self._existing_outcome(existing, scope, mutation)
                head = self._head(scope)
                fifo = self._fifo_conflict(scope, mutation, head)
                if fifo is not None:
                    raise _AbortMutation(fifo)
                self.connection.execute("""
                    INSERT INTO sync_operations (
                      schema_version, project_id, principal_id, actor_id,
                      device_id, client_mutation_id, client_id,
                      client_sequence, request_sha256, mutation_json, state,
                      receipt_json, created_at, committed_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,'reserved',NULL,?,NULL)
                """, (
                    JOURNAL_SCHEMA_VERSION, scope["project_id"],
                    scope["principal_id"], scope["actor_id"],
                    mutation["device_id"], mutation["client_mutation_id"],
                    mutation["client_id"], mutation["client_sequence"],
                    mutation["request_sha256"],
                    protocol.canonical_json_bytes(mutation).decode("utf-8"),
                    protocol.utc_now(),
                ))
                if self.adapters.check_precondition is not None:
                    conflict = self.adapters.check_precondition(
                        self.connection, request)
                    if conflict is not None:
                        if not isinstance(conflict, dict):
                            raise SyncServerStateError(
                                "precondition adapter must return a mapping or None")
                        error = MutationConflict(
                            conflict.get("code"), conflict.get("reason"),
                            current=conflict.get("current"),
                            retryable=conflict.get("retryable", False))
                        raise _AbortMutation(protocol.conflict_result(
                            scope, mutation, error.code, error.reason,
                            current=error.current, retryable=error.retryable,
                            server_cursor=head))
                try:
                    applied = self.adapters.apply_mutation(
                        self.connection, request)
                except MutationConflict as error:
                    raise _AbortMutation(protocol.conflict_result(
                        scope, mutation, error.code, error.reason,
                        current=error.current, retryable=error.retryable,
                        server_cursor=self._head(scope))) from error
                except MutationRejected as error:
                    raise _AbortMutation(protocol.rejected_result(
                        scope, mutation, error.code, error.reason,
                        current=error.current,
                        server_cursor=self._head(scope))) from error
                if not isinstance(applied, dict) \
                        or set(applied) != {"result", "server_cursor"} \
                        or not isinstance(applied["result"], dict):
                    raise SyncServerStateError(
                        "apply_mutation must return result and server_cursor")
                server_cursor = protocol.validate_cursor(
                    applied["server_cursor"])
                canonical_head = self._head(scope)
                if server_cursor != canonical_head:
                    raise SyncServerStateError(
                        "apply_mutation cursor does not match canonical head")
                result = protocol.applied_result(
                    scope, mutation, applied["result"], server_cursor)
                receipt = protocol.make_stored_receipt(scope, mutation, result)
                self._fault("after_apply_before_receipt", request)
                updated = self.connection.execute("""
                    UPDATE sync_operations
                    SET state='applied', receipt_json=?, committed_at=?
                    WHERE project_id=? AND principal_id=? AND actor_id=?
                      AND device_id=? AND client_mutation_id=?
                      AND state='reserved' AND request_sha256=?
                """, (
                    protocol.canonical_json_bytes(receipt).decode("utf-8"),
                    protocol.utc_now(),
                    *self._journal_key(
                        scope, mutation["device_id"],
                        mutation["client_mutation_id"]),
                    mutation["request_sha256"],
                )).rowcount
                if updated != 1:
                    raise SyncServerStateError(
                        "idempotency reservation disappeared before receipt")
                self._fault("after_receipt_before_atomic_release", request)
            self._fault("after_atomic_release_before_response", request)
            return result
        except _AbortMutation as error:
            return error.result
        except sqlite3.IntegrityError:
            existing = self._journal_row(
                scope, mutation["device_id"],
                mutation["client_mutation_id"])
            if existing is None:
                raise
            return self._existing_outcome(existing, scope, mutation)

    def push(self, authenticated_scope, envelope, *,
             projection_capabilities=None):
        """Apply one bounded FIFO batch with durable per-mutation receipts."""
        scope = self._trusted_scope(authenticated_scope)
        self._require_authorized(scope, "sync.push")
        # Parse only enough bounded JSON to select the trusted journal device
        # partition.  Project/principal/actor always come from ``scope``.
        bounded = _json_copy(envelope, max_bytes=protocol.MAX_PUSH_BYTES)
        device_id = bounded.get("device_id") if isinstance(bounded, dict) else None
        client_id = bounded.get("client_id") if isinstance(bounded, dict) else None
        if not isinstance(device_id, str):
            device_id = "__invalid_device__"
        if not isinstance(client_id, str):
            client_id = "__invalid_client__"
        with self._lock:
            with self._transaction():
                fingerprint, _, _ = self._project_view(
                    scope, "policy", None, self._head(scope), [],
                    projection_capabilities=projection_capabilities)
                known = self._known_receipts(scope, device_id, client_id)
            request = protocol.validate_push_request(
                bounded, expected_scope=scope,
                expected_visibility=fingerprint, known_receipts=known)
            mappings = {}
            for dependency in {
                    item for mutation in request["mutations"]
                    for item in mutation["depends_on"]}:
                result = self._dependency_result(
                    scope, device_id, client_id, dependency)
                if result is not None:
                    mappings[dependency] = result
            results = []
            prior_failed = False
            for mutation in request["mutations"]:
                if prior_failed:
                    result = protocol.rejected_result(
                        scope, mutation, "prior_mutation_failed",
                        "an earlier FIFO mutation in this batch did not apply",
                        server_cursor=self._head(scope))
                elif not self._authorized(
                        scope, "sync.mutate", mutation["operation"]):
                    result = protocol.rejected_result(
                        scope, mutation, "forbidden_operation",
                        "authenticated role cannot perform this operation",
                        server_cursor=self._head(scope))
                else:
                    result = self._reserve_apply_receipt(
                        scope, mutation, mappings)
                results.append(result)
                if result["status"] in {"applied", "duplicate"}:
                    mappings[mutation["client_mutation_id"]] = result["result"]
                else:
                    prior_failed = True
            with self._transaction():
                final_head = self._head(scope)
                final_fingerprint, _, _ = self._project_view(
                    scope, "policy", None, final_head, [],
                    projection_capabilities=projection_capabilities)
            return protocol.make_push_result(
                scope, final_fingerprint, results, final_head)

    # -- live hosted write idempotency ------------------------------------

    @staticmethod
    def _live_key(scope, device_id, mutation_id):
        return (
            scope["project_id"], scope["principal_id"], scope["actor_id"],
            device_id, mutation_id,
        )

    def _live_row(self, scope, device_id, mutation_id):
        cursor = self.connection.execute("""
            SELECT * FROM sync_live_operations
            WHERE project_id=? AND principal_id=? AND actor_id=?
              AND device_id=? AND client_mutation_id=?
        """, self._live_key(scope, device_id, mutation_id))
        return _row_dict(cursor, cursor.fetchone())

    def _live_receipt_from_row(self, row, scope):
        """Return one validated receipt for a live row in any state."""
        if row is None:
            return None
        if row.get("state") == "applied":
            if not row.get("receipt_json"):
                raise SyncServerStateError(
                    "applied live operation has no stored receipt")
            try:
                receipt = protocol.validate_live_receipt(
                    json.loads(row["receipt_json"]), expected_scope=scope)
            except (TypeError, ValueError, json.JSONDecodeError,
                    protocol.SyncProtocolError) as error:
                raise SyncServerStateError(
                    "sync journal contains an invalid live receipt") from error
            if receipt["client_mutation_id"] != row["client_mutation_id"] \
                    or receipt["request_sha256"] != row["request_sha256"]:
                raise SyncServerStateError(
                    "live journal row and receipt disagree")
            return receipt
        # ``reserved`` is deliberately reported, never hidden: a client must
        # be able to distinguish "no record at all" (safe to replay) from
        # "this server started the write and never finished recording it".
        return protocol.make_live_receipt(
            scope, row["client_mutation_id"], row["tool"],
            row["request_sha256"],
            status="failed" if row.get("state") == "failed" else "reserved",
            recorded_at=row.get("committed_at") or row["created_at"])

    # -- bounded live-receipt retention -----------------------------------

    def live_retention_policy(self):
        """The retention bounds and per-state rules this engine applies."""
        policy = dict(self.live_retention)
        policy.update({
            "applied_rows": "tombstoned",
            "failed_rows": "deleted",
            "reserved_rows": "retained",
            "note": "An applied receipt is never deleted: absence of a row "
                    "means provably absent, which a client may replay.",
        })
        return policy

    def _live_partition(self, scope, device_id):
        return (
            scope["project_id"], scope["principal_id"], scope["actor_id"],
            device_id,
        )

    _LIVE_PARTITION_SQL = (
        "project_id=? AND principal_id=? AND actor_id=? AND device_id=?")
    # ``reserved`` is absent from every retention query on purpose.
    _LIVE_PRUNABLE_SQL = (
        _LIVE_PARTITION_SQL
        + " AND state IN ('applied','failed') AND pruned_at IS NULL")

    def _live_retention_cutoff(self, now=None):
        moment = (now or datetime.now(timezone.utc)) - timedelta(
            days=self.live_retention["max_age_days"])
        return moment.isoformat(timespec="milliseconds").replace(
            "+00:00", "Z")

    def _live_retention_due_locked(self, scope, device_id, now=None):
        """One indexed count/min decides whether a pass is worth running."""
        cursor = self.connection.execute(
            "SELECT COUNT(*) AS prunable, MIN(created_at) AS oldest "
            "FROM sync_live_operations WHERE " + self._LIVE_PRUNABLE_SQL,
            self._live_partition(scope, device_id))
        row = _row_dict(cursor, cursor.fetchone())
        if not row or not row.get("prunable"):
            return False
        if int(row["prunable"]) > self.live_retention["max_rows_per_device"]:
            return True
        oldest = row.get("oldest")
        return bool(oldest and oldest < self._live_retention_cutoff(now))

    def _live_retention_victims_locked(self, scope, device_id, now=None):
        partition = self._live_partition(scope, device_id)
        limit = self.live_retention["max_rows_per_pass"]
        columns = "client_mutation_id, state, receipt_json"
        victims = {}
        cursor = self.connection.execute(
            "SELECT " + columns + " FROM sync_live_operations WHERE "
            + self._LIVE_PRUNABLE_SQL
            + " AND created_at < ? ORDER BY created_at LIMIT ?",
            (*partition, self._live_retention_cutoff(now), limit))
        for row in cursor.fetchall():
            row = _row_dict(cursor, row)
            victims[row["client_mutation_id"]] = row
        # Everything past the newest ``max_rows_per_device`` prunable rows.
        cursor = self.connection.execute(
            "SELECT " + columns + " FROM sync_live_operations WHERE "
            + self._LIVE_PRUNABLE_SQL
            + " ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
            (*partition, limit, self.live_retention["max_rows_per_device"]))
        for row in cursor.fetchall():
            row = _row_dict(cursor, row)
            victims.setdefault(row["client_mutation_id"], row)
        return list(victims.values())[:limit]

    def _tombstone_receipt(self, receipt_json):
        """Drop the retained result body, keep the durable proof."""
        try:
            receipt = json.loads(receipt_json)
            if not isinstance(receipt, dict) or receipt.get("result") is None:
                return None
            receipt["result"] = None
            protocol.validate_live_receipt(receipt)
        except (TypeError, ValueError, json.JSONDecodeError,
                protocol.SyncProtocolError):
            # A receipt this engine can no longer parse still fails closed on
            # read.  Mark it pruned so retention stops revisiting it.
            return None
        return protocol.canonical_json_bytes(receipt).decode("utf-8")

    def _prune_live_operations_locked(self, scope, device_id, now=None):
        summary = {"tombstoned": 0, "deleted": 0, "scanned": 0}
        victims = self._live_retention_victims_locked(scope, device_id, now)
        summary["scanned"] = len(victims)
        if not victims:
            return summary
        partition = self._live_partition(scope, device_id)
        stamp = protocol.utc_now()
        for row in victims:
            key = (*partition, row["client_mutation_id"])
            if row["state"] == "failed":
                # "Nothing applied" and "no row at all" mean the same thing
                # to a client, so a failed row is safe to remove entirely.
                self.connection.execute(
                    "DELETE FROM sync_live_operations WHERE "
                    + self._LIVE_PARTITION_SQL
                    + " AND client_mutation_id=? AND state='failed'", key)
                summary["deleted"] += 1
                continue
            replacement = self._tombstone_receipt(row["receipt_json"])
            if replacement is None:
                self.connection.execute(
                    "UPDATE sync_live_operations SET pruned_at=? WHERE "
                    + self._LIVE_PARTITION_SQL + " AND client_mutation_id=?",
                    (stamp, *key))
                continue
            self.connection.execute(
                "UPDATE sync_live_operations SET receipt_json=?, pruned_at=? "
                "WHERE " + self._LIVE_PARTITION_SQL
                + " AND client_mutation_id=? AND state='applied'",
                (replacement, stamp, *key))
            summary["tombstoned"] += 1
        return summary

    def prune_live_operations(self, authenticated_scope, device_id,
                              force=False, now=None):
        """Apply bounded retention to one device's live receipts.

        Reserved rows are never pruned, applied rows keep their proof, and
        failed rows are removed.  Returns a summary of what the pass did.
        """
        scope = self._trusted_scope(authenticated_scope)
        self._require_authorized(scope, "sync.push")
        device_id = _wire_identifier("device_id", device_id)
        with self._lock:
            with self._transaction(write=True):
                if not force \
                        and not self._live_retention_due_locked(
                            scope, device_id, now):
                    return {"tombstoned": 0, "deleted": 0, "scanned": 0,
                            "due": False}
                summary = self._prune_live_operations_locked(
                    scope, device_id, now)
                summary["due"] = True
                return summary

    def _maybe_prune_live(self, scope, device_id):
        """Opportunistic retention that never breaks the operation it rides.

        Retention is a housekeeping side effect of a live write and of the
        watcher's receipt lookup, which is where an otherwise idle device
        reappears.  A failure here -- a busy database on the read path, a
        receipt this generation cannot parse -- must leave the caller's
        answer untouched, so nothing propagates out of this method.
        """
        try:
            if not self._live_retention_due_locked(scope, device_id):
                return None
            with self._transaction(write=True):
                return self._prune_live_operations_locked(scope, device_id)
        except (sqlite3.Error, SyncServerError, protocol.SyncProtocolError):
            return None

    # -- stranded reservation recovery ------------------------------------
    #
    # A live write is reserved, applied, and receipted.  The apply and the
    # receipt commit in one transaction, so a process killed mid-write rolls
    # both back -- but a reservation can still be stranded: the process may
    # die after the reservation commits and before the write starts, or an
    # older generation may have crashed between a separately committed apply
    # and its receipt.  Either way the row stays ``reserved``, which every
    # client correctly reads as "unknown" forever.  Recovery finalizes such a
    # row once it is provably no longer in flight.
    # ---------------------------------------------------------------------

    @staticmethod
    def _event_device_matches(value, device_id):
        """One physical device, with or without a client-instance suffix."""
        return value == device_id or (
            isinstance(value, str) and value.startswith(device_id + "/"))

    def _live_claimed_event_seqs_locked(self, scope, device_id):
        cursor = self.connection.execute(
            "SELECT applied_event_seq FROM sync_live_operations WHERE "
            + self._LIVE_PARTITION_SQL + " AND applied_event_seq IS NOT NULL",
            self._live_partition(scope, device_id))
        return {int(item[0]) for item in cursor.fetchall()
                if item[0] is not None}

    def _live_recovery_candidates_locked(self, scope, device_id, row, head):
        """Ledger events that could belong to one stranded reservation.

        Returns ``(candidates, truncated)``.  ``truncated`` means the scan
        could not cover the whole possible range, so "found nothing" must
        never be reported as "nothing happened".
        """
        lower = row.get("reserved_at_seq")
        truncated = False
        if lower is None:
            # A row from before reservation marking carries no lower bound,
            # so only the recent tail of the ledger can be inspected.
            lower = max(0, int(head["event_seq"]) - LIVE_RECOVERY_SCAN_LIMIT)
            truncated = lower > 0
        events = self.adapters.read_events(
            self.connection, scope["project_id"], int(lower),
            int(head["event_seq"]), LIVE_RECOVERY_SCAN_LIMIT + 1) or []
        if len(events) > LIVE_RECOVERY_SCAN_LIMIT:
            truncated = True
            events = events[:LIVE_RECOVERY_SCAN_LIMIT]
        claimed = self._live_claimed_event_seqs_locked(scope, device_id)
        reserved_at = _parse_timestamp(row.get("created_at"))
        candidates = []
        for event in events:
            if not isinstance(event, dict):
                continue
            if event.get("actor_id") != scope["actor_id"] \
                    or event.get("owner") != scope["principal_id"] \
                    or not self._event_device_matches(
                        event.get("device_id"), device_id):
                continue
            try:
                sequence = int(event.get("seq"))
            except (TypeError, ValueError):
                continue
            if sequence in claimed:
                # Another receipt already proved which mutation wrote this
                # event, so it can never be this one.
                continue
            created = _parse_timestamp(event.get("created_at"))
            if reserved_at is not None and created is not None \
                    and created < reserved_at:
                continue
            candidates.append(event)
        return candidates, truncated

    def _finalize_live_recovery_locked(self, scope, device_id, row, status,
                                       source, event=None):
        key = self._live_key(scope, device_id, row["client_mutation_id"])
        if status == "failed":
            self.connection.execute("""
                UPDATE sync_live_operations
                SET state='failed', receipt_json=NULL, committed_at=?
                WHERE project_id=? AND principal_id=? AND actor_id=?
                  AND device_id=? AND client_mutation_id=?
                  AND state='reserved'
            """, (protocol.utc_now(), *key))
            return self._live_row(scope, device_id, row["client_mutation_id"])
        event = event or {}
        event_id = event.get("event_id") or row.get("applied_event_id")
        event_seq = event.get("seq") or row.get("applied_event_seq")
        event_seq = int(event_seq) if event_seq else None
        receipt = protocol.make_live_receipt(
            scope, row["client_mutation_id"], row["tool"],
            row["request_sha256"], status="applied",
            canonical_event_id=event_id if event_seq else None,
            canonical_event_seq=event_seq if event_id else None,
            server_cursor=self._head(scope),
            result={"recovered": True, "recovery_source": source})
        self.connection.execute("""
            UPDATE sync_live_operations
            SET state='applied', receipt_json=?, committed_at=?,
                applied_event_id=?, applied_event_seq=?
            WHERE project_id=? AND principal_id=? AND actor_id=?
              AND device_id=? AND client_mutation_id=? AND state='reserved'
        """, (protocol.canonical_json_bytes(receipt).decode("utf-8"),
              protocol.utc_now(), event_id, event_seq, *key))
        return self._live_row(scope, device_id, row["client_mutation_id"])

    def _recover_stale_live_reservation_locked(self, scope, device_id, row,
                                               applied_only=False):
        """Finalize one reservation that is provably no longer in flight.

        ``applied_only`` is used by the reserve path, where releasing an id
        must never happen: a duplicate request arriving while a genuine
        dispatch is merely slow would otherwise be handed the freed id and
        apply the write a second time.  Turning a stranded *landed* write
        into ``duplicate`` is safe and is all the reserve path needs; the
        receipt lookup finalizes absence one round trip later.
        """
        if not row or row.get("state") != "reserved":
            return row
        age = _age_seconds(row.get("created_at"))
        if age is None or age < self.live_retention[
                "reservation_grace_seconds"]:
            # Still inside the window where an honest slow dispatch may be
            # holding this id: never declare an in-flight write finished.
            return row
        if row.get("applied_event_seq"):
            # The write applied but its receipt could not be stored; the
            # canonical event was stamped on the row at that moment.
            return self._finalize_live_recovery_locked(
                scope, device_id, row, "applied", "apply_stamp")
        if row.get("reserved_at_seq") is not None:
            # Written by the generation that commits the domain write and its
            # receipt together: a surviving reservation therefore proves the
            # write never applied.  No ledger guessing is needed or wanted.
            if applied_only:
                return row
            return self._finalize_live_recovery_locked(
                scope, device_id, row, "failed", "atomic_reservation")
        head = self._head(scope)
        candidates, truncated = self._live_recovery_candidates_locked(
            scope, device_id, row, head)
        if len(candidates) == 1:
            return self._finalize_live_recovery_locked(
                scope, device_id, row, "applied", "ledger_scan",
                event=candidates[0])
        if not candidates and not truncated and not applied_only:
            return self._finalize_live_recovery_locked(
                scope, device_id, row, "failed", "ledger_scan")
        # Several possible events, or a range this scan could not cover:
        # unknown stays unknown rather than becoming a guess.
        return row

    def _live_reserved_at_seq(self, scope):
        """Ledger head when an id is claimed; None when it cannot be read."""
        try:
            return int(self._head(scope)["event_seq"])
        except (SyncServerError, protocol.SyncProtocolError,
                TypeError, ValueError, KeyError):
            return None

    def _recover_stale_live_reservation(self, scope, device_id, row):
        """Best-effort recovery; a failure leaves the row exactly as it was."""
        try:
            with self._transaction(write=True):
                return self._recover_stale_live_reservation_locked(
                    scope, device_id, row)
        except (sqlite3.Error, SyncServerError, protocol.SyncProtocolError):
            return row

    def live_reserve(self, authenticated_scope, device_id, mutation_id, tool,
                     request_sha256):
        """Claim one live write id, or report the recorded prior outcome.

        Returns ``{'status': 'reserved'}`` when the caller owns the attempt,
        ``duplicate`` with the stored receipt when the identical body already
        applied, ``in_progress`` when a concurrent attempt holds the id, and
        ``conflict`` when the same id already named a different body.
        """
        scope = self._trusted_scope(authenticated_scope)
        self._require_authorized(scope, "sync.push")
        device_id = _wire_identifier("device_id", device_id)
        mutation_id = _wire_identifier("client_mutation_id", mutation_id)
        if not protocol.is_client_mutation_id(mutation_id):
            raise SyncServerStateError("client_mutation_id is unsafe")
        with self._lock:
            with self._transaction(write=True):
                row = self._live_row(scope, device_id, mutation_id)
                if row is not None:
                    if row["request_sha256"] != request_sha256:
                        return {"status": "conflict", "receipt": None,
                                "reason": "client_mutation_id was already "
                                          "used for a different request"}
                    if row["state"] == "reserved":
                        # A repeat of the same write is one of the two places
                        # a reservation stranded by a dead process is noticed.
                        # It may only *upgrade* the row to applied: freeing
                        # the id here would let this very request apply a
                        # still-running write twice.
                        row = self._recover_stale_live_reservation_locked(
                            scope, device_id, row, applied_only=True) or row
                    if row["state"] == "applied":
                        return {
                            "status": "duplicate",
                            "receipt": self._live_receipt_from_row(row, scope),
                        }
                    if row["state"] == "reserved":
                        return {
                            "status": "in_progress",
                            "receipt": self._live_receipt_from_row(row, scope),
                        }
                    # A previously failed attempt may be retried under the
                    # same id: nothing was applied.
                    self.connection.execute("""
                        UPDATE sync_live_operations
                        SET state='reserved', receipt_json=NULL,
                            created_at=?, committed_at=NULL,
                            reserved_at_seq=?, applied_event_id=NULL,
                            applied_event_seq=NULL, pruned_at=NULL
                        WHERE project_id=? AND principal_id=? AND actor_id=?
                          AND device_id=? AND client_mutation_id=?
                    """, (protocol.utc_now(), self._live_reserved_at_seq(scope),
                          *self._live_key(scope, device_id, mutation_id)))
                    return {"status": "reserved", "receipt": None}
                self.connection.execute("""
                    INSERT INTO sync_live_operations (
                      schema_version, project_id, principal_id, actor_id,
                      device_id, client_mutation_id, tool, request_sha256,
                      state, receipt_json, created_at, committed_at,
                      reserved_at_seq
                    ) VALUES (?,?,?,?,?,?,?,?, 'reserved', NULL, ?, NULL, ?)
                """, (
                    JOURNAL_SCHEMA_VERSION, scope["project_id"],
                    scope["principal_id"], scope["actor_id"], device_id,
                    mutation_id, str(tool), str(request_sha256),
                    protocol.utc_now(), self._live_reserved_at_seq(scope),
                ))
                self._maybe_prune_live(scope, device_id)
                return {"status": "reserved", "receipt": None}

    def live_commit(self, authenticated_scope, device_id, mutation_id, tool,
                    request_sha256, *, canonical_event_id,
                    canonical_event_seq, server_cursor, result=None):
        """Record the durable receipt for one applied live hosted write."""
        scope = self._trusted_scope(authenticated_scope)
        self._require_authorized(scope, "sync.push")
        device_id = _wire_identifier("device_id", device_id)
        mutation_id = _wire_identifier("client_mutation_id", mutation_id)
        receipt = protocol.make_live_receipt(
            scope, mutation_id, tool, request_sha256, status="applied",
            canonical_event_id=canonical_event_id,
            canonical_event_seq=canonical_event_seq,
            server_cursor=server_cursor, result=result)
        with self._lock:
            with self._transaction(write=True):
                # ``failed`` is accepted alongside ``reserved`` only for the
                # identical request body: recovery may have speculatively
                # released a reservation whose dispatch outlived the grace
                # period, and the genuine writer must be able to reclaim it
                # rather than be told its own write vanished.
                updated = self.connection.execute("""
                    UPDATE sync_live_operations
                    SET state='applied', receipt_json=?, committed_at=?,
                        applied_event_id=?, applied_event_seq=?,
                        pruned_at=NULL
                    WHERE project_id=? AND principal_id=? AND actor_id=?
                      AND device_id=? AND client_mutation_id=?
                      AND state IN ('reserved','failed')
                      AND request_sha256=?
                """, (
                    protocol.canonical_json_bytes(receipt).decode("utf-8"),
                    protocol.utc_now(),
                    canonical_event_id, canonical_event_seq,
                    *self._live_key(scope, device_id, mutation_id),
                    str(request_sha256),
                )).rowcount
                if updated != 1:
                    raise SyncServerStateError(
                        "live reservation disappeared before its receipt")
            self._maybe_prune_live(scope, device_id)
        return receipt

    def live_record_applied_event(self, authenticated_scope, device_id,
                                  mutation_id, canonical_event_id,
                                  canonical_event_seq):
        """Stamp the event a still-reserved row applied, best effort.

        The receipt itself could not be stored (a validation or state error
        after the domain write committed).  Recording the canonical event
        keeps the row honest: recovery must never later read it as "nothing
        applied".  When even the stamp is impossible the reservation marker
        is cleared instead, which downgrades that row to the conservative
        ledger scan rather than to a false absence.  Returns what it managed.
        """
        try:
            scope = self._trusted_scope(authenticated_scope)
            device_id = _wire_identifier("device_id", device_id)
            mutation_id = _wire_identifier("client_mutation_id", mutation_id)
        except (SyncServerError, protocol.SyncProtocolError):
            return "unrecorded"
        key = self._live_key(scope, device_id, mutation_id)
        exact = (isinstance(canonical_event_id, str)
                 and isinstance(canonical_event_seq, int)
                 and not isinstance(canonical_event_seq, bool)
                 and canonical_event_seq > 0)
        try:
            with self._lock:
                with self._transaction(write=True):
                    if exact:
                        updated = self.connection.execute("""
                            UPDATE sync_live_operations
                            SET applied_event_id=?, applied_event_seq=?
                            WHERE project_id=? AND principal_id=?
                              AND actor_id=? AND device_id=?
                              AND client_mutation_id=? AND state='reserved'
                        """, (canonical_event_id, canonical_event_seq,
                              *key)).rowcount
                        if updated == 1:
                            return "stamped"
                    degraded = self.connection.execute("""
                        UPDATE sync_live_operations SET reserved_at_seq=NULL
                        WHERE project_id=? AND principal_id=? AND actor_id=?
                          AND device_id=? AND client_mutation_id=?
                          AND state='reserved'
                    """, key).rowcount
                    # Never claim a stamp that did not happen: the row may
                    # have been finalized or pruned by somebody else.
                    return "degraded" if degraded == 1 else "unrecorded"
        except (sqlite3.Error, SyncServerError, protocol.SyncProtocolError):
            return "unrecorded"

    def live_fail(self, authenticated_scope, device_id, mutation_id):
        """Release one reservation whose operation provably did not apply."""
        scope = self._trusted_scope(authenticated_scope)
        self._require_authorized(scope, "sync.push")
        device_id = _wire_identifier("device_id", device_id)
        mutation_id = _wire_identifier("client_mutation_id", mutation_id)
        with self._lock:
            with self._transaction(write=True):
                self.connection.execute("""
                    UPDATE sync_live_operations
                    SET state='failed', receipt_json=NULL, committed_at=?
                    WHERE project_id=? AND principal_id=? AND actor_id=?
                      AND device_id=? AND client_mutation_id=?
                      AND state='reserved'
                """, (protocol.utc_now(),
                      *self._live_key(scope, device_id, mutation_id)))
            self._maybe_prune_live(scope, device_id)
        return True

    def _outbox_receipt_as_live(self, scope, device_id, mutation_id):
        """Present one queued-mutation receipt in the shared receipt shape."""
        row = self._journal_row(scope, device_id, mutation_id)
        if row is None:
            return None
        try:
            mutation = protocol.validate_client_mutation(
                json.loads(row["mutation_json"]), expected_scope=scope)
        except (TypeError, ValueError, json.JSONDecodeError,
                protocol.SyncProtocolError) as error:
            raise SyncServerStateError(
                "sync journal contains an invalid stored mutation") from error
        if row.get("state") != "applied" or not row.get("receipt_json"):
            return protocol.make_live_receipt(
                scope, mutation_id, mutation["operation"],
                mutation["request_sha256"], status="reserved",
                recorded_at=row["created_at"])
        receipt = self._receipt_from_row(row, scope)
        applied = receipt["applied"]
        mapping = applied.get("result") or {}
        return protocol.make_live_receipt(
            scope, mutation_id, mutation["operation"],
            receipt["request_sha256"], status="applied",
            canonical_event_id=mapping.get("canonical_event_id"),
            canonical_event_seq=mapping.get("canonical_event_seq"),
            server_cursor=applied.get("server_cursor"),
            result=None, recorded_at=receipt["stored_at"])

    def receipts(self, authenticated_scope, device_id, mutation_ids):
        """Return ``{id: receipt or None}`` for this exact device/principal."""
        scope = self._trusted_scope(authenticated_scope)
        self._require_authorized(scope, "sync.receipt.read")
        device_id = _wire_identifier("device_id", device_id)
        wanted = []
        for item in mutation_ids or []:
            item = _wire_identifier("client_mutation_id", item)
            if not protocol.is_client_mutation_id(item):
                raise SyncServerStateError("client_mutation_id is unsafe")
            if item not in wanted:
                wanted.append(item)
        if len(wanted) > MAX_RECEIPT_LOOKUP_IDS:
            raise SyncServerStateError(
                "receipt lookup accepts at most %d ids"
                % MAX_RECEIPT_LOOKUP_IDS)
        answer = {}
        with self._lock:
            for item in wanted:
                row = self._live_row(scope, device_id, item)
                if row is not None and row.get("state") == "reserved":
                    # "Did my write land?" is exactly when a reservation
                    # stranded by a dead process must stop answering
                    # "unknown" forever.
                    row = self._recover_stale_live_reservation(
                        scope, device_id, row) or row
                receipt = self._live_receipt_from_row(row, scope)
                if receipt is None or receipt.get("status") != "applied":
                    # The same id may have landed through the queued
                    # transport instead -- for example after this very
                    # lookup reported the live attempt absent and the client
                    # replayed it.  A live row proves only what the *live*
                    # attempt did, so an applied outbox receipt must never
                    # stay hidden behind it: absence is the one answer a
                    # client is entitled to replay.
                    queued = self._outbox_receipt_as_live(
                        scope, device_id, item)
                    if queued is not None and (
                            receipt is None
                            or queued.get("status") == "applied"):
                        receipt = queued
                answer[item] = receipt
            # An idle device reappears here, so this is also where its old
            # receipts are trimmed; it never affects the answer above.
            self._maybe_prune_live(scope, device_id)
        return answer

    def journal_receipt(self, authenticated_scope, device_id, mutation_id):
        """Read one scoped receipt for diagnostics without cross-scope lookup."""
        scope = self._trusted_scope(authenticated_scope)
        self._require_authorized(scope, "sync.receipt.read")
        device_id = _wire_identifier("device_id", device_id)
        mutation_id = _wire_identifier("client_mutation_id", mutation_id)
        with self._lock:
            row = self._journal_row(scope, device_id, mutation_id)
            return self._receipt_from_row(row, scope) if row else None


__all__ = [
    "JOURNAL_SCHEMA_VERSION", "MAX_RECEIPT_LOOKUP_IDS",
    "LIVE_RETENTION_MAX_AGE_DAYS", "LIVE_RETENTION_MAX_ROWS_PER_DEVICE",
    "LIVE_RETENTION_MAX_ROWS_PER_PASS", "LIVE_RESERVATION_GRACE_SECONDS",
    "LIVE_RECOVERY_SCAN_LIMIT", "SyncServerError",
    "SyncServerAuthorizationError", "SyncServerStateError",
    "MutationConflict", "MutationRejected", "ApplyRequest",
    "SyncServerAdapters", "SyncServerEngine",
]
