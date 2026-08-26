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

try:  # Namespace package when imported as ``attacca.sync_server``.
    from . import sync_protocol as protocol
except (ImportError, ValueError):  # Direct module loading in isolated tests.
    import sync_protocol as protocol


JOURNAL_SCHEMA_VERSION = 1

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

    def __init__(self, connection, adapters, busy_timeout_ms=5000):
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

    def _project_view(self, scope, mode, start, through, events):
        raw = self.adapters.visibility_projector(
            self.connection, _json_copy(scope), mode,
            _json_copy(start) if start is not None else None,
            _json_copy(through) if through is not None else None,
            _json_copy(events),
        )
        if not isinstance(raw, dict) or "visibility_policy" not in raw:
            raise SyncServerStateError(
                "visibility_projector must return visibility_policy")
        policy = _json_copy(raw["visibility_policy"], max_bytes=512 * 1024)
        fingerprint = protocol.visibility_fingerprint(scope, policy)
        if mode == "policy":
            return fingerprint, {}, set()
        if "projection" not in raw or "visible_event_seqs" not in raw:
            raise SyncServerStateError(
                "visibility_projector omitted projection/event visibility")
        projection = _json_copy(
            raw["projection"], max_bytes=protocol.MAX_SNAPSHOT_BYTES)
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

    def snapshot(self, authenticated_scope):
        """Return a complete identity-filtered snapshot for a trusted caller."""
        scope = self._trusted_scope(authenticated_scope)
        self._require_authorized(scope, "sync.read")
        with self._lock, self._transaction():
            head = self._head(scope)
            events = self._events(scope, 0, head["event_seq"], None)
            fingerprint, projection, visible = self._project_view(
                scope, "snapshot", None, head, events)
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

    def pull(self, authenticated_scope, envelope):
        """Return a bounded delta or ``reset_required`` for a stale/forked view."""
        scope = self._trusted_scope(authenticated_scope)
        self._require_authorized(scope, "sync.read")
        request = protocol.validate_pull_request(
            envelope, expected_scope=scope)
        with self._lock, self._transaction():
            head = self._head(scope)
            fingerprint, _, _ = self._project_view(
                scope, "policy", request["cursor"], head, [])
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
                scope, "pull", start, end, events)
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

    def push(self, authenticated_scope, envelope):
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
                    scope, "policy", None, self._head(scope), [])
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
                    scope, "policy", None, final_head, [])
            return protocol.make_push_result(
                scope, final_fingerprint, results, final_head)

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
    "JOURNAL_SCHEMA_VERSION", "SyncServerError",
    "SyncServerAuthorizationError", "SyncServerStateError",
    "MutationConflict", "MutationRejected", "ApplyRequest",
    "SyncServerAdapters", "SyncServerEngine",
]
