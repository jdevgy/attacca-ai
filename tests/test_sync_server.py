"""Isolated acceptance and threat tests for the embeddable sync server."""

import hashlib
import json
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Import both pure modules exactly the way every other suite does.  Loading
# them by path used to register a *second* ``sync_protocol`` object in
# sys.modules, so whichever suite imported first decided whether
# ``offline_sync.protocol`` and this module's ``p`` were the same class
# namespace; running tests.test_sync_compatibility before tests.test_sync_client
# then failed on protocol exceptions raised by the other instance.  One import
# per module keeps every suite order-independent.
import sync_protocol as p  # noqa: E402
import sync_server as s  # noqa: E402


def scope(principal="usr_jack", role="director", runtime="codex"):
    return {
        "server_id": "srv_test",
        "project_id": "agentg",
        "principal_id": principal,
        "actor_id": "agentg.%s.%s" % (role, runtime),
        "actor_type": "agent",
        "role": role,
    }


def canonical_event(seq, previous, audience="everyone", project="agentg",
                    actor="agentg.director.codex", body=None):
    payload = {"audience": audience, "body": body or "event %d" % seq}
    payload_json = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    value = {
        "event_id": "ev_%04d" % seq,
        "project_id": project,
        "seq": seq,
        "actor_id": actor,
        "actor_type": "agent",
        "owner": "usr_jack",
        "event_type": "note.sync",
        "payload": payload,
        "payload_json": payload_json,
        "payload_hash": payload_hash,
        "prev_hash": previous,
        "hash_version": 2,
        "context_version": seq,
        "base_revision": "abc123",
        "git_branch": "main",
        "device_id": "seed-device",
        "task_id": None,
        "created_at": "2026-08-24T00:00:%02d.000Z" % seq,
    }
    material = "|".join([
        previous, payload_hash, project, str(seq), value["event_type"],
        actor, value["created_at"], value["actor_type"], value["owner"],
        str(seq), value["base_revision"], value["git_branch"],
        value["device_id"], "",
    ])
    value["hash"] = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return value


class Harness:
    def __init__(self):
        self.policy_generation = 0
        self.head_context_offset = 0
        self.leak_secret = False
        self.apply_calls = 0
        self.apply_delay = 0
        self.fault_stage = None
        self.bad_apply_cursor = False
        self.authorizations = []
        self.requests = []
        self._counter_lock = threading.Lock()

    @staticmethod
    def create_schema(conn):
        conn.execute("""
            CREATE TABLE events (
              project_id TEXT NOT NULL,
              seq INTEGER NOT NULL,
              event_json TEXT NOT NULL,
              PRIMARY KEY (project_id, seq)
            )
        """)
        conn.execute("""
            CREATE TABLE domain_writes (
              project_id TEXT NOT NULL,
              principal_id TEXT NOT NULL,
              actor_id TEXT NOT NULL,
              mutation_id TEXT NOT NULL,
              operation TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              metadata_json TEXT NOT NULL,
              attribution_json TEXT NOT NULL,
              PRIMARY KEY (project_id, principal_id, actor_id, mutation_id)
            )
        """)
        previous = p.GENESIS_HASH
        for seq, audience, body in (
                (1, "everyone", "public one"),
                (2, "director", "director only"),
                (3, "worker", "worker secret")):
            event = canonical_event(seq, previous, audience=audience, body=body)
            conn.execute(
                "INSERT INTO events VALUES (?,?,?)",
                ("agentg", seq, json.dumps(event, sort_keys=True)))
            previous = event["hash"]

    def authorize(self, conn, trusted_scope, action, operation):
        self.authorizations.append((trusted_scope, action, operation))
        if operation == "admin.forbidden":
            return False
        return action in {
            "sync.read", "sync.push", "sync.mutate", "sync.receipt.read",
        }

    def head_cursor(self, conn, project_id):
        row = conn.execute(
            "SELECT event_json FROM events WHERE project_id=? "
            "ORDER BY seq DESC LIMIT 1", (project_id,)).fetchone()
        if row is None:
            return p.make_cursor(0, p.GENESIS_HASH, 0)
        event = json.loads(row[0])
        return p.make_cursor(
            event["seq"], event["hash"],
            event["context_version"] + self.head_context_offset)

    @staticmethod
    def read_events(conn, project_id, after_seq, through_seq, limit):
        sql = (
            "SELECT event_json FROM events WHERE project_id=? AND seq>? "
            "AND seq<=? ORDER BY seq"
        )
        params = [project_id, after_seq, through_seq]
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        return [json.loads(row[0]) for row in conn.execute(sql, params)]

    def visibility_projector(self, conn, trusted_scope, mode, start, through,
                             events):
        policy = {
            "role": trusted_scope["role"],
            "generation": self.policy_generation,
        }
        if mode == "policy":
            return {"visibility_policy": policy}
        visible = [
            event["seq"] for event in events
            if event["payload"]["audience"] in {
                "everyone", trusted_scope["role"]}
        ]
        if mode == "pull":
            projection = {
                "tasks": [{
                    "project_id": trusted_scope["project_id"],
                    "task_id": "T-delta",
                    "through": through["event_seq"],
                }],
            }
        else:
            projection = {
                "project": {
                    "project_id": trusted_scope["project_id"],
                    "name": "Agentg",
                    "context_version": through["context_version"],
                },
                "handoffs": [],
                "rules": [{
                    "project_id": trusted_scope["project_id"],
                    "rule_id": "R-everyone", "scope": "everyone",
                }],
                "tasks": [{
                    "project_id": trusted_scope["project_id"],
                    "task_id": "T-visible",
                }],
                "decisions": [],
                "room_messages": [],
                "agents": [{
                    "project_id": trusted_scope["project_id"],
                    "agent_id": trusted_scope["actor_id"],
                }],
                "bridges": [],
                "inbox_cursor": {
                    "actor_id": trusted_scope["actor_id"],
                    "last_read_seq": 0,
                },
                "task_plans": [],
                "full_log": ["identity-filtered local log"],
                "actor_aliases": [],
            }
            if self.leak_secret:
                projection["project"]["token_hash"] = "must-not-leak"
        return {
            "visibility_policy": policy,
            "projection": projection,
            "visible_event_seqs": visible,
        }

    @staticmethod
    def check_precondition(conn, request):
        if request.operation == "task.claim" and request.payload.get("blocked"):
            return {
                "code": "task_already_claimed",
                "reason": "another actor already holds the task",
                "current": {"claimed_by": "agentg.worker.claude"},
                "retryable": False,
            }
        return None

    def apply_mutation(self, conn, request):
        with self._counter_lock:
            self.apply_calls += 1
            self.requests.append(request)
        if self.apply_delay:
            time.sleep(self.apply_delay)
        conn.execute("""
            INSERT INTO domain_writes (
              project_id, principal_id, actor_id, mutation_id, operation,
              payload_json, metadata_json, attribution_json
            ) VALUES (?,?,?,?,?,?,?,?)
        """, (
            request.authenticated_scope["project_id"],
            request.authenticated_scope["principal_id"],
            request.authenticated_scope["actor_id"],
            request.client_mutation_id, request.operation,
            json.dumps(request.payload, sort_keys=True),
            json.dumps(request.metadata, sort_keys=True),
            json.dumps(request.attribution, sort_keys=True),
        ))
        head = self.head_cursor(
            conn, request.authenticated_scope["project_id"])
        event = canonical_event(
            head["event_seq"] + 1, head["event_hash"],
            audience="everyone",
            actor=request.authenticated_scope["actor_id"],
            body="applied %s" % request.client_mutation_id)
        event["owner"] = request.authenticated_scope["principal_id"]
        # Owner participates in hash-v2 material, so recompute after binding it.
        payload_hash = event["payload_hash"]
        material = "|".join([
            event["prev_hash"], payload_hash, event["project_id"],
            str(event["seq"]), event["event_type"], event["actor_id"],
            event["created_at"], event["actor_type"], event["owner"],
            str(event["context_version"]), event["base_revision"],
            event["git_branch"], event["device_id"], "",
        ])
        event["hash"] = hashlib.sha256(material.encode("utf-8")).hexdigest()
        conn.execute(
            "INSERT INTO events VALUES (?,?,?)",
            (event["project_id"], event["seq"],
             json.dumps(event, sort_keys=True)))
        if request.operation == "task.create":
            result = {"task_id": "T-created-%d" % request.client_sequence}
        elif request.operation == "task.claim":
            result = {"task_id": request.payload["task_id"], "claimed": True}
        else:
            result = {"ok": True}
        cursor = self.head_cursor(
            conn, request.authenticated_scope["project_id"])
        if self.bad_apply_cursor:
            cursor = p.make_cursor(
                cursor["event_seq"], "f" * 64,
                cursor["context_version"])
        return {
            "result": result,
            "server_cursor": cursor,
        }

    def fault_injector(self, stage, request):
        if stage == self.fault_stage:
            raise RuntimeError("simulated crash at %s" % stage)

    def adapters(self):
        return s.SyncServerAdapters(
            authorize=self.authorize,
            head_cursor=self.head_cursor,
            read_events=self.read_events,
            visibility_projector=self.visibility_projector,
            apply_mutation=self.apply_mutation,
            check_precondition=self.check_precondition,
            fault_injector=self.fault_injector,
        )


class ModuleIdentityTests(unittest.TestCase):
    """One module object per file, whatever order the suites are imported.

    A second ``sync_protocol`` instance makes ``SyncProtocolError`` raised by
    one copy invisible to ``except`` clauses compiled against the other, which
    is exactly how ``tests.test_sync_compatibility`` used to break
    ``tests.test_sync_client``.
    """

    def test_protocol_and_server_modules_are_process_singletons(self):
        import offline_sync
        import sync_client
        import sync_protocol
        import sync_server

        self.assertIs(sys.modules["sync_protocol"], p)
        self.assertIs(sync_protocol, p)
        self.assertIs(sync_server, s)
        self.assertIs(s.protocol, p)
        self.assertIs(offline_sync.protocol, p)
        self.assertIs(sync_client.protocol, p)
        # An error raised through one import path is catchable through the
        # other, which is the property the ordering bug destroyed.
        with self.assertRaises(sync_protocol.SyncProtocolError):
            p.validate_scope(dict(scope(), actor_id=""))

    def test_no_module_was_registered_under_a_private_alias(self):
        self.assertNotIn("attacca_sync_server_test", sys.modules)


class SyncServerTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "server.db"
        self.conn = sqlite3.connect(
            self.database, isolation_level=None, timeout=5)
        self.addCleanup(self.conn.close)
        self.harness = Harness()
        self.harness.create_schema(self.conn)
        self.engine = s.SyncServerEngine(
            self.conn, self.harness.adapters(), busy_timeout_ms=5000)
        self.scope = scope()

    def fingerprint(self, identity=None):
        identity = identity or self.scope
        return p.visibility_fingerprint(identity, {
            "role": identity["role"],
            "generation": self.harness.policy_generation,
        })

    def mutation(self, mutation_id="cm_device_0001", sequence=1,
                 operation="task.create", payload=None, identity=None,
                 depends_on=None, metadata=None, base_cursor=None):
        identity = identity or self.scope
        return p.make_client_mutation(
            identity, mutation_id, "client_home", "device_home", sequence,
            operation, payload if payload is not None else {"title": "Offline"},
            base_cursor or self.harness.head_cursor(
                self.conn, identity["project_id"]),
            depends_on=depends_on,
            metadata=metadata if metadata is not None else {
                "git_branch": "offline", "git_revision": "abc123"},
            created_at="2026-08-24T01:00:00.000Z",
        )

    def push_envelope(self, mutations, identity=None, known_receipts=None):
        identity = identity or self.scope
        return p.make_push_request(
            identity, self.fingerprint(identity), "client_home", "device_home",
            mutations, created_at="2026-08-24T01:01:00.000Z",
            known_receipts=known_receipts)

    def counts(self):
        return {
            "domain": self.conn.execute(
                "SELECT COUNT(*) FROM domain_writes").fetchone()[0],
            "journal": self.conn.execute(
                "SELECT COUNT(*) FROM sync_operations").fetchone()[0],
            "events": self.conn.execute(
                "SELECT COUNT(*) FROM events").fetchone()[0],
        }


class SnapshotPullTests(SyncServerTestCase):
    def test_snapshot_redacts_hidden_events_and_never_exposes_contents(self):
        snapshot = self.engine.snapshot(self.scope)
        checked = p.validate_snapshot(
            snapshot, expected_scope=self.scope,
            expected_visibility=self.fingerprint())
        self.assertEqual(
            [record["kind"] for record in checked["records"]],
            ["event", "event", "redacted"])
        serialized = p.canonical_json_bytes(checked).decode("utf-8")
        self.assertNotIn("worker secret", serialized)
        self.assertEqual(checked["cursor"]["event_seq"], 3)
        self.assertTrue(all(
            call[0] == self.scope for call in self.harness.authorizations))

    def test_pull_advances_across_redaction_and_resets_stale_or_forked_cursor(self):
        first = json.loads(self.conn.execute(
            "SELECT event_json FROM events WHERE seq=1").fetchone()[0])
        cursor = p.make_cursor(1, first["hash"], first["context_version"])
        request = p.make_pull_request(
            self.scope, cursor, self.fingerprint(), limit=2)
        result = self.engine.pull(self.scope, request)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["next_cursor"]["event_seq"], 3)
        self.assertEqual(
            [record["kind"] for record in result["records"]],
            ["event", "redacted"])

        self.harness.policy_generation = 1
        reset = self.engine.pull(self.scope, request)
        self.assertEqual(reset["status"], "reset_required")
        self.assertEqual(reset["reason_code"], "visibility_changed")

        fresh = p.make_pull_request(
            self.scope,
            p.make_cursor(1, "f" * 64, 1),
            self.fingerprint())
        reset = self.engine.pull(self.scope, fresh)
        self.assertEqual(reset["reason_code"], "cursor_diverged")

    def test_context_only_head_advance_converges_without_repeating_empty_pull(self):
        self.harness.head_context_offset = 2
        snapshot = self.engine.snapshot(self.scope)
        self.assertEqual(snapshot["cursor"]["event_seq"], 3)
        self.assertEqual(snapshot["cursor"]["context_version"], 5)
        request = p.make_pull_request(
            self.scope, snapshot["cursor"], self.fingerprint())
        result = self.engine.pull(self.scope, request)
        self.assertEqual(result["records"], [])
        self.assertEqual(result["next_cursor"], result["head_cursor"])
        self.assertEqual(result["next_cursor"]["context_version"], 5)

    def test_cross_principal_requests_and_projection_secrets_are_rejected(self):
        other = scope("usr_mallory", role="worker", runtime="claude")
        request = p.make_pull_request(
            self.scope, p.make_cursor(0, p.GENESIS_HASH, 0),
            self.fingerprint())
        with self.assertRaises(p.SyncProtocolError) as raised:
            self.engine.pull(other, request)
        self.assertEqual(raised.exception.code, "cross_principal_scope")

        self.harness.leak_secret = True
        with self.assertRaises(p.SyncProtocolError) as raised:
            self.engine.snapshot(self.scope)
        self.assertEqual(raised.exception.code, "secret_in_projection")


class IdempotencyAndAttributionTests(SyncServerTestCase):
    def test_exact_retry_is_duplicate_and_reused_id_body_is_conflict(self):
        mutation = self.mutation()
        envelope = self.push_envelope([mutation])
        first = self.engine.push(self.scope, envelope)
        duplicate = self.engine.push(self.scope, envelope)
        self.assertEqual(first["results"][0]["status"], "applied")
        self.assertEqual(duplicate["results"][0]["status"], "duplicate")
        self.assertEqual(self.harness.apply_calls, 1)

        changed = self.mutation(payload={"title": "different body"})
        conflict = self.engine.push(self.scope, self.push_envelope([changed]))
        self.assertEqual(conflict["results"][0]["status"], "conflict")
        self.assertEqual(
            conflict["results"][0]["code"], "idempotency_key_reused")
        self.assertEqual(self.counts()["domain"], 1)
        self.assertEqual(self.counts()["journal"], 1)

    def test_journal_partition_is_principal_actor_device_and_receipt_is_private(self):
        first = self.mutation()
        self.engine.push(self.scope, self.push_envelope([first]))
        other = scope("usr_mallory", role="worker", runtime="claude")
        other_mutation = self.mutation(identity=other)
        result = self.engine.push(
            other, self.push_envelope([other_mutation], identity=other))
        self.assertEqual(result["results"][0]["status"], "applied")
        self.assertEqual(self.counts()["journal"], 2)
        other_receipt = self.engine.journal_receipt(
            other, "device_home", first["client_mutation_id"])
        self.assertEqual(
            other_receipt["request_sha256"],
            other_mutation["request_sha256"])
        self.assertNotEqual(
            other_receipt["request_sha256"], first["request_sha256"])

    def test_queued_identity_metadata_is_stripped_and_trusted_scope_is_used(self):
        mutation = self.mutation(
            payload={"title": "work", "owner": "payload-mallory"},
            metadata={
                "owner": "metadata-mallory", "actor_id": "evil.actor",
                "project_id": "foreign", "git_branch": "safe-branch",
                "nested": {"owner": "nested-mallory", "note": "preserved"},
            })
        result = self.engine.push(self.scope, self.push_envelope([mutation]))
        self.assertEqual(result["results"][0]["status"], "applied")
        request = self.harness.requests[-1]
        self.assertEqual(request.authenticated_scope, self.scope)
        self.assertEqual(request.attribution["principal_id"], "usr_jack")
        self.assertEqual(request.attribution["actor_id"], self.scope["actor_id"])
        self.assertEqual(request.metadata, {
            "git_branch": "safe-branch", "nested": {"note": "preserved"}})
        row = self.conn.execute(
            "SELECT project_id, principal_id, actor_id FROM domain_writes"
        ).fetchone()
        self.assertEqual(row, ("agentg", "usr_jack", "agentg.director.codex"))


class OrderingAndConflictTests(SyncServerTestCase):
    def test_fifo_dependencies_resolve_local_refs_in_order(self):
        first = self.mutation()
        second = self.mutation(
            mutation_id="cm_device_0002", sequence=2,
            operation="task.claim",
            payload={"task_id": p.local_ref(
                first["client_mutation_id"], ["task_id"])},
            depends_on=[first["client_mutation_id"]])
        result = self.engine.push(
            self.scope, self.push_envelope([first, second]))
        self.assertEqual(
            [item["status"] for item in result["results"]],
            ["applied", "applied"])
        self.assertEqual(
            self.harness.requests[-1].payload["task_id"], "T-created-1")
        self.assertEqual(self.counts()["journal"], 2)

    def test_prior_receipt_resolves_a_later_batch_dependency(self):
        first = self.mutation()
        self.engine.push(self.scope, self.push_envelope([first]))
        second = self.mutation(
            mutation_id="cm_device_0002", sequence=2,
            operation="task.claim",
            payload={"task_id": p.local_ref(
                first["client_mutation_id"], ["task_id"])},
            depends_on=[first["client_mutation_id"]])
        envelope = self.push_envelope(
            [second], known_receipts={first["client_mutation_id"]})
        result = self.engine.push(self.scope, envelope)
        self.assertEqual(result["results"][0]["status"], "applied")
        self.assertEqual(
            self.harness.requests[-1].payload["task_id"], "T-created-1")

    def test_precondition_or_authorization_failure_blocks_later_fifo_work(self):
        blocked = self.mutation(
            operation="task.claim",
            payload={"task_id": "T-busy", "blocked": True})
        later = self.mutation(
            mutation_id="cm_device_0002", sequence=2)
        result = self.engine.push(
            self.scope, self.push_envelope([blocked, later]))
        self.assertEqual(
            [item["code"] for item in result["results"]],
            ["task_already_claimed", "prior_mutation_failed"])
        self.assertEqual(self.counts()["domain"], 0)
        self.assertEqual(self.counts()["journal"], 0)

        forbidden = self.mutation(operation="admin.forbidden")
        result = self.engine.push(
            self.scope, self.push_envelope([forbidden]))
        self.assertEqual(result["results"][0]["code"], "forbidden_operation")

    def test_fifo_gap_conflicts_then_expected_sequence_can_apply(self):
        fifth = self.mutation(mutation_id="cm_device_0005", sequence=5)
        self.engine.push(self.scope, self.push_envelope([fifth]))
        seventh = self.mutation(
            mutation_id="cm_device_0007", sequence=7,
            base_cursor=self.harness.head_cursor(self.conn, "agentg"))
        result = self.engine.push(self.scope, self.push_envelope([seventh]))
        self.assertEqual(result["results"][0]["code"], "client_sequence_gap")
        self.assertTrue(result["results"][0]["retryable"])

        sixth = self.mutation(
            mutation_id="cm_device_0006", sequence=6,
            base_cursor=self.harness.head_cursor(self.conn, "agentg"))
        result = self.engine.push(self.scope, self.push_envelope([sixth]))
        self.assertEqual(result["results"][0]["status"], "applied")


class CrashAndConcurrencyTests(SyncServerTestCase):
    def test_crashes_before_atomic_release_roll_back_domain_and_reservation(self):
        mutation = self.mutation()
        envelope = self.push_envelope([mutation])
        for stage in (
                "after_apply_before_receipt",
                "after_receipt_before_atomic_release"):
            self.harness.fault_stage = stage
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                self.engine.push(self.scope, envelope)
            self.assertEqual(
                self.counts(), {"domain": 0, "journal": 0, "events": 3})
        self.harness.fault_stage = None
        result = self.engine.push(self.scope, envelope)
        self.assertEqual(result["results"][0]["status"], "applied")
        self.assertEqual(
            self.counts(), {"domain": 1, "journal": 1, "events": 4})

    def test_lost_response_after_commit_retries_as_duplicate(self):
        mutation = self.mutation()
        envelope = self.push_envelope([mutation])
        self.harness.fault_stage = "after_atomic_release_before_response"
        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            self.engine.push(self.scope, envelope)
        self.assertEqual(
            self.counts(), {"domain": 1, "journal": 1, "events": 4})
        self.harness.fault_stage = None
        result = self.engine.push(self.scope, envelope)
        self.assertEqual(result["results"][0]["status"], "duplicate")
        self.assertEqual(self.harness.apply_calls, 1)

    def test_two_connections_racing_exact_request_apply_once(self):
        self.harness.apply_delay = 0.1
        mutation = self.mutation()
        envelope = self.push_envelope([mutation])
        other_conn = sqlite3.connect(
            self.database, isolation_level=None, timeout=5,
            check_same_thread=False)
        self.addCleanup(other_conn.close)
        first_conn = sqlite3.connect(
            self.database, isolation_level=None, timeout=5,
            check_same_thread=False)
        self.addCleanup(first_conn.close)
        first = s.SyncServerEngine(first_conn, self.harness.adapters())
        second = s.SyncServerEngine(other_conn, self.harness.adapters())
        gate = threading.Barrier(2)

        def run(engine):
            gate.wait(timeout=2)
            return engine.push(self.scope, envelope)["results"][0]["status"]

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(run, (first, second)))
        self.assertEqual(sorted(statuses), ["applied", "duplicate"])
        self.assertEqual(self.harness.apply_calls, 1)
        self.assertEqual(self.counts()["domain"], 1)
        self.assertEqual(self.counts()["journal"], 1)

    def test_oversized_push_is_rejected_before_any_journal_write(self):
        mutation = self.mutation(payload={"body": "x" * 2048})
        envelope = self.push_envelope([mutation])
        with mock.patch.object(p, "MAX_PUSH_BYTES", 512):
            with self.assertRaises(p.EnvelopeTooLarge):
                self.engine.push(self.scope, envelope)
        self.assertEqual(self.counts()["domain"], 0)
        self.assertEqual(self.counts()["journal"], 0)

        with mock.patch.object(p, "MAX_MUTATIONS", 0):
            with self.assertRaises(p.SyncProtocolError) as raised:
                self.engine.push(self.scope, envelope)
        self.assertEqual(raised.exception.code, "too_many_mutations")

    def test_tampered_journal_hash_is_detected_before_duplicate_disclosure(self):
        mutation = self.mutation()
        envelope = self.push_envelope([mutation])
        self.engine.push(self.scope, envelope)
        self.conn.execute(
            "UPDATE sync_operations SET request_sha256=?",
            ("sha256:" + "f" * 64,))
        with self.assertRaisesRegex(s.SyncServerStateError, "disagree"):
            self.engine.push(self.scope, envelope)

    def test_fabricated_apply_cursor_rolls_back_domain_and_reservation(self):
        self.harness.bad_apply_cursor = True
        mutation = self.mutation()
        with self.assertRaisesRegex(s.SyncServerStateError, "canonical head"):
            self.engine.push(self.scope, self.push_envelope([mutation]))
        self.assertEqual(
            self.counts(), {"domain": 0, "journal": 0, "events": 3})


class LiveReceiptTestCase(SyncServerTestCase):
    """Shared helpers for the live (hosted-write) receipt partition."""

    DEVICE = "device_home"

    def live_engine(self, **policy):
        return s.SyncServerEngine(
            self.conn, self.harness.adapters(), busy_timeout_ms=5000,
            live_retention=policy or None)

    def request_hash(self, body=None):
        return p.live_request_sha256("room_send", body or {"body": "live"})

    def reserve(self, engine, mutation_id, tool="room_send", body=None,
                device=None):
        return engine.live_reserve(
            self.scope, device or self.DEVICE, mutation_id, tool,
            self.request_hash(body))

    def commit(self, engine, mutation_id, tool="room_send", body=None,
               device=None, event_id="ev_0003", event_seq=3, result=None):
        return engine.live_commit(
            self.scope, device or self.DEVICE, mutation_id, tool,
            self.request_hash(body), canonical_event_id=event_id,
            canonical_event_seq=event_seq,
            server_cursor=self.harness.head_cursor(self.conn, "agentg"),
            result=result if result is not None else {"ok": True,
                                                      "body": "x" * 256})

    def applied_row(self, engine, mutation_id, **kwargs):
        self.reserve(engine, mutation_id, **{
            key: value for key, value in kwargs.items()
            if key in ("tool", "body", "device")})
        return self.commit(engine, mutation_id, **kwargs)

    def row(self, mutation_id, device=None):
        cursor = self.conn.execute(
            "SELECT * FROM sync_live_operations WHERE client_mutation_id=?"
            " AND device_id=?", (mutation_id, device or self.DEVICE))
        columns = [item[0] for item in cursor.description]
        found = cursor.fetchone()
        return dict(zip(columns, found)) if found else None

    def backdate(self, mutation_id, days=0, seconds=0, device=None):
        moment = datetime.now(timezone.utc) - timedelta(
            days=days, seconds=seconds)
        stamp = moment.isoformat(timespec="milliseconds").replace(
            "+00:00", "Z")
        self.conn.execute(
            "UPDATE sync_live_operations SET created_at=? "
            "WHERE client_mutation_id=? AND device_id=?",
            (stamp, mutation_id, device or self.DEVICE))
        return stamp

    def append_event(self, seq, actor=None, owner="usr_jack",
                     device=None, created_at=None):
        """Append one canonical event the recovery scan can find."""
        previous = self.conn.execute(
            "SELECT event_json FROM events WHERE project_id='agentg' "
            "ORDER BY seq DESC LIMIT 1").fetchone()
        previous_hash = json.loads(previous[0])["hash"] if previous \
            else p.GENESIS_HASH
        event = canonical_event(
            seq, previous_hash, actor=actor or self.scope["actor_id"])
        event["owner"] = owner
        event["device_id"] = device if device is not None else self.DEVICE
        if created_at:
            event["created_at"] = created_at
        self.conn.execute(
            "INSERT INTO events VALUES (?,?,?)",
            ("agentg", seq, json.dumps(event, sort_keys=True)))
        return event


class LiveReceiptRetentionTests(LiveReceiptTestCase):
    """Bounded retention that can never turn 'applied' into 'absent'."""

    def test_policy_is_reported_and_validated(self):
        default = self.engine.live_retention_policy()
        self.assertEqual(default["max_age_days"],
                         s.LIVE_RETENTION_MAX_AGE_DAYS)
        self.assertEqual(default["max_rows_per_device"],
                         s.LIVE_RETENTION_MAX_ROWS_PER_DEVICE)
        self.assertEqual(default["reservation_grace_seconds"],
                         s.LIVE_RESERVATION_GRACE_SECONDS)
        # The per-state rules are part of the published policy: they are what
        # makes a missing row safe to read as "provably absent".
        self.assertEqual(default["applied_rows"], "tombstoned")
        self.assertEqual(default["failed_rows"], "deleted")
        self.assertEqual(default["reserved_rows"], "retained")
        self.assertEqual(
            self.live_engine(max_age_days=2)["max_age_days"]
            if isinstance(self.live_engine(max_age_days=2), dict)
            else self.live_engine(max_age_days=2).live_retention[
                "max_age_days"], 2)
        for bad in ({"max_age_days": 0}, {"max_age_days": "30"},
                    {"max_age_days": True}, {"max_rows_per_device": -1}):
            with self.assertRaises(ValueError):
                self.live_engine(**bad)
        with self.assertRaises(ValueError):
            self.live_engine(retain_everything=1)

    def test_age_bound_tombstones_applied_and_deletes_failed_rows(self):
        engine = self.live_engine(max_age_days=1)
        self.applied_row(engine, "cm_live_applied_0001")
        self.reserve(engine, "cm_live_failed_0001")
        engine.live_fail(self.scope, self.DEVICE, "cm_live_failed_0001")
        self.reserve(engine, "cm_live_reserved_0001")
        for mutation_id in ("cm_live_applied_0001", "cm_live_failed_0001",
                            "cm_live_reserved_0001"):
            self.backdate(mutation_id, days=10)

        summary = engine.prune_live_operations(self.scope, self.DEVICE)
        self.assertTrue(summary["due"])
        self.assertEqual(summary["tombstoned"], 1)
        self.assertEqual(summary["deleted"], 1)

        # The applied row keeps its proof and loses only the retained body,
        # because a missing row means "safe to replay" to every client.
        applied = self.row("cm_live_applied_0001")
        self.assertEqual(applied["state"], "applied")
        self.assertIsNotNone(applied["pruned_at"])
        receipt = json.loads(applied["receipt_json"])
        self.assertIsNone(receipt["result"])
        self.assertEqual(receipt["status"], "applied")
        self.assertEqual(receipt["canonical_event_id"], "ev_0003")
        self.assertEqual(receipt["canonical_event_seq"], 3)
        self.assertIsNotNone(receipt["server_cursor"])
        self.assertEqual(receipt["request_sha256"], self.request_hash())
        self.assertLess(len(applied["receipt_json"]), 700)

        # A failed row already meant "nothing applied", so removing it is the
        # same answer in fewer bytes.
        self.assertIsNone(self.row("cm_live_failed_0001"))
        # A reserved row is never pruned: its outcome is still unknown.
        reserved = self.row("cm_live_reserved_0001")
        self.assertEqual(reserved["state"], "reserved")
        self.assertIsNone(reserved["pruned_at"])

        answer = engine.receipts(
            self.scope, self.DEVICE,
            ["cm_live_applied_0001", "cm_live_failed_0001"])
        self.assertEqual(answer["cm_live_applied_0001"]["status"], "applied")
        self.assertIsNone(answer["cm_live_applied_0001"]["result"])
        self.assertIsNone(answer["cm_live_failed_0001"])

        # A second pass is a no-op: pruned rows are not revisited.
        again = engine.prune_live_operations(self.scope, self.DEVICE)
        self.assertEqual(
            (again["tombstoned"], again["deleted"]), (0, 0))

    def test_recent_rows_are_left_alone_until_the_window_passes(self):
        engine = self.live_engine(max_age_days=1)
        self.applied_row(engine, "cm_live_fresh_0001")
        summary = engine.prune_live_operations(self.scope, self.DEVICE)
        self.assertFalse(summary["due"])
        self.assertIsNotNone(
            json.loads(self.row("cm_live_fresh_0001")["receipt_json"])
            ["result"])

    def test_per_device_cap_trims_oldest_prunable_rows_only(self):
        # Seed under a cap that never fires, so the explicit pass below is
        # the only thing that can trim anything.
        writer = self.live_engine(max_rows_per_device=1000, max_age_days=3650)
        engine = self.live_engine(max_rows_per_device=3, max_age_days=3650)
        for index in range(6):
            mutation_id = "cm_live_cap_%04d" % index
            self.applied_row(writer, mutation_id)
            self.backdate(mutation_id, days=60 - index)
        # Reserved rows share the partition and must neither be trimmed nor
        # block the cap from trimming the prunable ones.
        for index in range(2):
            self.reserve(writer, "cm_live_cap_reserved_%04d" % index)
        # Another device's receipts belong to another partition entirely.
        for index in range(4):
            other = "cm_live_other_%04d" % index
            self.applied_row(writer, other, device="device_laptop")
            self.backdate(other, days=90, device="device_laptop")

        summary = engine.prune_live_operations(self.scope, self.DEVICE)
        self.assertEqual(summary["tombstoned"], 3)
        self.assertEqual(summary["deleted"], 0)
        trimmed = [index for index in range(6)
                   if json.loads(self.row("cm_live_cap_%04d" % index)
                                 ["receipt_json"])["result"] is None]
        # created_at descends with the index, so the three oldest go.
        self.assertEqual(trimmed, [0, 1, 2])
        for index in range(2):
            reserved = self.row("cm_live_cap_reserved_%04d" % index)
            self.assertEqual(reserved["state"], "reserved")
            self.assertIsNone(reserved["pruned_at"])
        for index in range(4):
            other = self.row("cm_live_other_%04d" % index, "device_laptop")
            self.assertIsNotNone(json.loads(other["receipt_json"])["result"])

    def test_retention_runs_opportunistically_on_the_write_path(self):
        engine = self.live_engine(max_age_days=1)
        self.applied_row(engine, "cm_live_auto_0001")
        self.backdate("cm_live_auto_0001", days=10)
        # No explicit prune call: committing the next live write trims.
        self.applied_row(engine, "cm_live_auto_0002")
        self.assertIsNone(
            json.loads(self.row("cm_live_auto_0001")["receipt_json"])
            ["result"])
        self.assertIsNotNone(
            json.loads(self.row("cm_live_auto_0002")["receipt_json"])
            ["result"])

    def test_a_broken_retention_pass_never_breaks_the_lookup(self):
        engine = self.live_engine(max_age_days=1)
        self.applied_row(engine, "cm_live_guard_0001")
        self.backdate("cm_live_guard_0001", days=10)
        with mock.patch.object(
                engine, "_prune_live_operations_locked",
                side_effect=sqlite3.OperationalError("database is locked")):
            answer = engine.receipts(
                self.scope, self.DEVICE, ["cm_live_guard_0001"])
        self.assertEqual(answer["cm_live_guard_0001"]["status"], "applied")


class StrandedReservationRecoveryTests(LiveReceiptTestCase):
    """A reservation whose process died stops answering 'unknown' for ever."""

    def receipt_status(self, engine, mutation_id):
        answer = engine.receipts(self.scope, self.DEVICE, [mutation_id])
        return answer[mutation_id]

    def test_reservation_inside_the_grace_period_stays_unknown(self):
        engine = self.live_engine(reservation_grace_seconds=300)
        self.reserve(engine, "cm_live_inflight_0001")
        receipt = self.receipt_status(engine, "cm_live_inflight_0001")
        self.assertEqual(receipt["status"], "reserved")
        self.assertEqual(
            self.row("cm_live_inflight_0001")["state"], "reserved")

    def test_atomic_generation_reservation_becomes_provably_absent(self):
        """Apply and receipt commit together, so a survivor never applied."""
        engine = self.live_engine(reservation_grace_seconds=30)
        self.reserve(engine, "cm_live_crashed_0001")
        self.assertIsNotNone(self.row("cm_live_crashed_0001")
                             ["reserved_at_seq"])
        self.backdate("cm_live_crashed_0001", seconds=600)

        receipt = self.receipt_status(engine, "cm_live_crashed_0001")
        self.assertEqual(receipt["status"], "failed")
        self.assertIsNone(receipt["canonical_event_id"])
        self.assertEqual(self.row("cm_live_crashed_0001")["state"], "failed")

    def test_pre_atomic_stranded_reservation_is_finalized_from_the_ledger(self):
        """The crash window: applied, then killed before the receipt.

        An unmarked row is exactly what the earlier generation left behind
        when it committed the domain write in its own transaction and died
        before recording the receipt.
        """
        engine = self.live_engine(reservation_grace_seconds=30)
        self.reserve(engine, "cm_live_stranded_0001")
        self.conn.execute(
            "UPDATE sync_live_operations SET reserved_at_seq=NULL")
        created = self.backdate("cm_live_stranded_0001", seconds=600)
        landed = self.append_event(4, created_at=created)

        receipt = self.receipt_status(engine, "cm_live_stranded_0001")
        self.assertEqual(receipt["status"], "applied")
        self.assertEqual(receipt["canonical_event_id"], landed["event_id"])
        self.assertEqual(receipt["canonical_event_seq"], 4)
        self.assertEqual(receipt["request_sha256"], self.request_hash())
        self.assertEqual(receipt["result"],
                         {"recovered": True, "recovery_source": "ledger_scan"})
        row = self.row("cm_live_stranded_0001")
        self.assertEqual(row["state"], "applied")
        self.assertEqual(row["applied_event_seq"], 4)
        # A repeat of the same live write now answers duplicate instead of
        # blocking for ever on "another request is still applying this".
        self.assertEqual(
            self.reserve(engine, "cm_live_stranded_0001")["status"],
            "duplicate")

    def test_a_repeat_request_never_frees_a_reservation_it_could_reapply(self):
        """Reserve-path recovery may upgrade to applied, never release."""
        engine = self.live_engine(reservation_grace_seconds=30)
        self.reserve(engine, "cm_live_slowdup_0001")
        self.backdate("cm_live_slowdup_0001", seconds=600)

        # The original dispatch may simply be slow.  Handing this id back to
        # the duplicate would apply the very same write twice.
        repeat = self.reserve(engine, "cm_live_slowdup_0001")
        self.assertEqual(repeat["status"], "in_progress")
        self.assertEqual(repeat["receipt"]["status"], "reserved")
        self.assertEqual(self.row("cm_live_slowdup_0001")["state"], "reserved")

        # The receipt lookup is where absence is finalized instead.
        self.assertEqual(
            self.receipt_status(engine, "cm_live_slowdup_0001")["status"],
            "failed")

    def test_pre_atomic_reservation_with_no_ledger_event_is_absent(self):
        engine = self.live_engine(reservation_grace_seconds=30)
        self.reserve(engine, "cm_live_nothing_0001")
        self.conn.execute(
            "UPDATE sync_live_operations SET reserved_at_seq=NULL")
        self.backdate("cm_live_nothing_0001", seconds=600)
        self.assertEqual(
            self.receipt_status(engine, "cm_live_nothing_0001")["status"],
            "failed")

    def test_recovery_refuses_to_guess_between_two_candidate_events(self):
        engine = self.live_engine(reservation_grace_seconds=30)
        self.reserve(engine, "cm_live_two_0001")
        self.conn.execute(
            "UPDATE sync_live_operations SET reserved_at_seq=NULL")
        created = self.backdate("cm_live_two_0001", seconds=600)
        self.append_event(4, created_at=created)
        self.append_event(5, created_at=created)
        # Unknown is never upgraded to a guess, and never downgraded to
        # "absent" either: the client keeps reporting it as unresolved.
        self.assertEqual(
            self.receipt_status(engine, "cm_live_two_0001")["status"],
            "reserved")
        self.assertEqual(self.row("cm_live_two_0001")["state"], "reserved")

    def test_recovery_never_claims_an_event_another_receipt_owns(self):
        engine = self.live_engine(reservation_grace_seconds=30)
        created = None
        self.reserve(engine, "cm_live_owner_0001")
        self.commit(engine, "cm_live_owner_0001", event_id="ev_0004",
                    event_seq=4)
        self.reserve(engine, "cm_live_orphan_0001")
        self.conn.execute(
            "UPDATE sync_live_operations SET reserved_at_seq=NULL "
            "WHERE client_mutation_id='cm_live_orphan_0001'")
        created = self.backdate("cm_live_orphan_0001", seconds=600)
        self.append_event(4, created_at=created)

        # Event 4 is already proven to belong to another mutation, so the
        # stranded row has no candidate at all.
        self.assertEqual(
            self.receipt_status(engine, "cm_live_orphan_0001")["status"],
            "failed")

    def test_recovery_ignores_events_from_another_actor_or_device(self):
        engine = self.live_engine(reservation_grace_seconds=30)
        self.reserve(engine, "cm_live_foreign_0001")
        self.conn.execute(
            "UPDATE sync_live_operations SET reserved_at_seq=NULL")
        created = self.backdate("cm_live_foreign_0001", seconds=600)
        self.append_event(4, actor="agentg.worker.claude", created_at=created)
        self.append_event(5, device="device_laptop", created_at=created)
        self.append_event(6, owner="usr_mallory", created_at=created)
        self.assertEqual(
            self.receipt_status(engine, "cm_live_foreign_0001")["status"],
            "failed")

    def test_a_stamped_reservation_reports_the_write_it_actually_applied(self):
        """The receipt could not be stored, but the event id was recorded."""
        engine = self.live_engine(reservation_grace_seconds=30)
        self.reserve(engine, "cm_live_stamped_0001")
        landed = self.append_event(4)
        self.assertEqual(
            engine.live_record_applied_event(
                self.scope, self.DEVICE, "cm_live_stamped_0001",
                landed["event_id"], 4),
            "stamped")
        self.backdate("cm_live_stamped_0001", seconds=600)

        receipt = self.receipt_status(engine, "cm_live_stamped_0001")
        self.assertEqual(receipt["status"], "applied")
        self.assertEqual(receipt["canonical_event_id"], landed["event_id"])
        self.assertEqual(receipt["result"],
                         {"recovered": True, "recovery_source": "apply_stamp"})

    def test_an_unstampable_reservation_degrades_instead_of_lying(self):
        engine = self.live_engine(reservation_grace_seconds=30)
        self.reserve(engine, "cm_live_degraded_0001")
        # No canonical event was returned by the tool, so the exact stamp is
        # impossible; the reservation marker is cleared so recovery falls
        # back to the ledger scan rather than reporting a false absence.
        self.assertEqual(
            engine.live_record_applied_event(
                self.scope, self.DEVICE, "cm_live_degraded_0001", None, None),
            "degraded")
        row = self.row("cm_live_degraded_0001")
        self.assertIsNone(row["reserved_at_seq"])
        self.assertEqual(row["state"], "reserved")
        created = self.backdate("cm_live_degraded_0001", seconds=600)
        landed = self.append_event(4, created_at=created)
        receipt = self.receipt_status(engine, "cm_live_degraded_0001")
        self.assertEqual(receipt["status"], "applied")
        self.assertEqual(receipt["canonical_event_id"], landed["event_id"])

    def test_a_late_genuine_commit_reclaims_a_released_reservation(self):
        """Recovery must never make a slow writer look like a lost write."""
        engine = self.live_engine(reservation_grace_seconds=30)
        self.reserve(engine, "cm_live_slow_0001")
        self.backdate("cm_live_slow_0001", seconds=600)
        self.assertEqual(
            self.receipt_status(engine, "cm_live_slow_0001")["status"],
            "failed")

        receipt = self.commit(engine, "cm_live_slow_0001", event_id="ev_0004",
                              event_seq=4)
        self.assertEqual(receipt["status"], "applied")
        self.assertEqual(
            self.receipt_status(engine, "cm_live_slow_0001")["status"],
            "applied")
        self.assertEqual(self.row("cm_live_slow_0001")["applied_event_seq"], 4)

    def test_a_queued_replay_is_never_hidden_behind_a_released_live_row(self):
        """After recovery frees an id, the replay's receipt is the truth."""
        engine = self.live_engine(reservation_grace_seconds=30)
        mutation_id = "cm_device_0001"
        body = {"title": "Offline"}
        self.reserve(engine, mutation_id, tool="task_create", body=body)
        self.backdate(mutation_id, seconds=600)
        self.assertEqual(
            self.receipt_status(engine, mutation_id)["status"], "failed")

        # The client did exactly what "absent" entitles it to do: replay the
        # same id through the queued transport.
        engine.push(self.scope, self.push_envelope([
            self.mutation(mutation_id=mutation_id)]))
        receipt = self.receipt_status(engine, mutation_id)
        self.assertEqual(receipt["status"], "applied")
        # It is the queued receipt that answers, not the released live row.
        self.assertEqual(receipt["tool"], "task.create")
        self.assertIsNotNone(receipt["server_cursor"])
        # The released live row is still there; it just no longer answers.
        self.assertEqual(self.row(mutation_id)["state"], "failed")

    def test_recovery_is_scoped_to_the_asking_device_and_principal(self):
        engine = self.live_engine(reservation_grace_seconds=30)
        self.reserve(engine, "cm_live_scoped_0001")
        self.backdate("cm_live_scoped_0001", seconds=600)
        # Another device may not see, recover, or resolve this reservation.
        self.assertIsNone(engine.receipts(
            self.scope, "device_laptop", ["cm_live_scoped_0001"])
            ["cm_live_scoped_0001"])
        self.assertEqual(
            self.row("cm_live_scoped_0001")["state"], "reserved")
        self.assertIsNone(engine.receipts(
            scope(principal="usr_mallory"), self.DEVICE,
            ["cm_live_scoped_0001"])["cm_live_scoped_0001"])


if __name__ == "__main__":
    unittest.main()
