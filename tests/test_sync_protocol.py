"""Threat-focused contract tests for schema-v1 offline sync envelopes."""

import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_sync_protocol_test", ROOT / "sync_protocol.py")
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)


def digest(label):
    return hashlib.sha256(str(label).encode("utf-8")).hexdigest()


def scope(role="director", principal="usr_jack", runtime="codex",
          project="agentg", server="srv_primary"):
    return {
        "server_id": server,
        "project_id": project,
        "principal_id": principal,
        "actor_id": "%s.%s.%s" % (project, role, runtime),
        "actor_type": "agent",
        "role": role,
    }


def human_scope(principal="usr_jack"):
    return {
        "server_id": "srv_primary",
        "project_id": "agentg",
        "principal_id": principal,
        "actor_id": "web.jack",
        "actor_type": "human",
        "role": "human",
    }


def event(seq, previous, project="agentg", payload=None):
    payload = payload or {"body": "event %d" % seq}
    payload_json = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    value = {
        "event_id": "ev_%04d" % seq,
        "project_id": project,
        "seq": seq,
        "actor_id": "%s.director.codex" % project,
        "actor_type": "agent",
        "owner": "jack",
        "event_type": "note.sync",
        "payload": payload,
        "payload_json": payload_json,
        "payload_hash": payload_hash,
        "prev_hash": previous,
        "hash_version": 2,
        "context_version": seq,
        "base_revision": "abc123",
        "git_branch": "main",
        "device_id": "dev_home",
        "task_id": None,
        "created_at": "2026-08-24T00:00:%02d.000Z" % seq,
    }
    material = "|".join([
        previous, payload_hash, project, str(seq), value["event_type"],
        value["actor_id"], value["created_at"], value["actor_type"],
        value["owner"], str(value["context_version"]),
        value["base_revision"], value["git_branch"], value["device_id"], "",
    ])
    value["hash"] = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return value


def projection(identity=None):
    identity = identity or scope()
    return {
        "project": {
            "project_id": identity["project_id"],
            "name": "Attacca",
            "context_version": 3,
        },
        "handoffs": [{"version": 1, "content": {"objective": "sync"}}],
        "rules": [{
            "rule_id": "R-1", "title": "Two QA passes",
            "body": "Run them", "scope": "everyone", "enabled": 1,
            "version": 1,
        }],
        "tasks": [{"task_id": "T-39", "title": "Offline sync"}],
        "decisions": [{"decision_id": "D-1", "title": "Use an outbox"}],
        "room_messages": [{"seq": 1, "body": "local only"}],
        "agents": [{"agent_id": identity["actor_id"],
                    "role": identity["role"]}],
        "bridges": [],
        "inbox_cursor": {"actor_id": identity["actor_id"],
                         "last_read_seq": 1},
        "task_plans": [],
        "full_log": ["complete log line"],
        "actor_aliases": [],
    }


class ProtocolFixture(unittest.TestCase):
    def setUp(self):
        self.scope = scope()
        self.other_scope = scope(
            role="worker", principal="usr_mallory", runtime="claude")
        self.visibility = p.visibility_fingerprint(
            self.scope, {"role": "director", "bridges": []})
        first = event(1, p.GENESIS_HASH)
        self.h1, self.h2 = first["hash"], digest(2)
        third = event(3, self.h2)
        self.h3 = third["hash"]
        self.events = [
            p.make_visible_record(first),
            p.make_redacted_anchor(2, self.h1, self.h2),
            p.make_visible_record(third),
        ]
        self.cursor = p.make_cursor(3, self.h3, 3)

    def mutation(self, mutation_id="cm_device_0001", sequence=1,
                 operation="task.create", payload=None, depends_on=None,
                 identity=None, client_id="client_home",
                 device_id="device_home"):
        return p.make_client_mutation(
            identity or self.scope,
            mutation_id,
            client_id,
            device_id,
            sequence,
            operation,
            payload or {"title": "Offline task"},
            self.cursor,
            depends_on=depends_on,
            metadata={"git_branch": "offline-work", "git_revision": "abc123"},
            created_at="2026-08-24T01:00:00.000Z",
        )


class ScopeAndCanonicalJsonTests(ProtocolFixture):
    def test_canonical_json_and_fingerprints_are_stable_and_scoped(self):
        self.assertEqual(
            p.canonical_json_bytes({"b": 2, "a": 1}),
            b'{"a":1,"b":2}',
        )
        self.assertEqual(p.validate_scope(self.scope), self.scope)
        self.assertEqual(p.scope_fingerprint(self.scope),
                         p.scope_fingerprint(copy.deepcopy(self.scope)))
        self.assertNotEqual(
            self.visibility,
            p.visibility_fingerprint(self.scope, {"role": "worker"}),
        )
        self.assertNotEqual(p.scope_fingerprint(self.scope),
                            p.scope_fingerprint(self.other_scope))

    def test_scope_rejects_cross_principal_and_noncanonical_actor(self):
        with self.assertRaisesRegex(p.SyncProtocolError,
                                    "authenticated scope") as raised:
            p.validate_scope(self.scope, expected_scope=self.other_scope)
        self.assertEqual(raised.exception.code, "cross_principal_scope")

        malformed = dict(self.scope, actor_id="agentg.worker.codex")
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_scope(malformed)
        self.assertEqual(raised.exception.code, "noncanonical_actor")

        empty_runtime = dict(self.scope, actor_id="agentg.director.")
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_scope(empty_runtime)
        self.assertEqual(raised.exception.code, "noncanonical_actor")

        for field in ("actor_type", "role"):
            malformed = dict(self.scope)
            malformed[field] = []
            with self.assertRaises(p.SyncProtocolError):
                p.validate_scope(malformed)

    def test_cursor_genesis_and_visibility_mismatch_are_rejected(self):
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.make_cursor(0, self.h1, 0)
        self.assertEqual(raised.exception.code, "invalid_cursor")
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_visibility_fingerprint(
                self.visibility,
                expected=p.visibility_fingerprint(self.other_scope, {}),
            )
        self.assertEqual(raised.exception.code, "visibility_changed")

    def test_json_threat_limits_reject_cycles_depth_nan_and_size(self):
        cyclic = []
        cyclic.append(cyclic)
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.canonical_json_bytes(cyclic)
        self.assertEqual(raised.exception.code, "cyclic_json")

        deep = None
        for _ in range(p.MAX_JSON_DEPTH + 2):
            deep = [deep]
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.canonical_json_bytes(deep)
        self.assertEqual(raised.exception.code, "json_too_deep")

        with self.assertRaises(p.SyncProtocolError) as raised:
            p.canonical_json_bytes({"bad": float("nan")})
        self.assertEqual(raised.exception.code, "invalid_number")

        with self.assertRaises(p.EnvelopeTooLarge):
            p.canonical_json_bytes({"body": "x" * 100}, max_bytes=32)


class SnapshotAndPullTests(ProtocolFixture):
    def test_identity_scoped_snapshot_round_trip_with_redacted_anchor(self):
        snapshot = p.make_snapshot(
            self.scope, self.visibility, self.cursor,
            projection(self.scope), self.events,
            generated_at="2026-08-24T01:00:00.000Z",
        )
        checked = p.validate_snapshot(
            snapshot, expected_scope=self.scope,
            expected_visibility=self.visibility)
        self.assertEqual(checked["cursor"], self.cursor)
        self.assertEqual(checked["records"][1]["kind"], "redacted")
        self.assertNotIn("event", checked["records"][1])
        self.assertEqual(checked["projection"]["rules"][0]["rule_id"], "R-1")

    def test_snapshot_rejects_tampering_secrets_wrong_role_and_actor_inbox(self):
        snapshot = p.make_snapshot(
            self.scope, self.visibility, self.cursor,
            projection(self.scope), self.events)
        tampered = copy.deepcopy(snapshot)
        tampered["projection"]["project"]["name"] = "Changed"
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_snapshot(tampered)
        self.assertEqual(raised.exception.code, "projection_hash_mismatch")

        unsafe = projection(self.scope)
        unsafe["project"]["auth_tokens"] = [{"token_hash": "secret"}]
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.make_snapshot(
                self.scope, self.visibility, self.cursor, unsafe, self.events)
        self.assertEqual(raised.exception.code, "secret_in_projection")

        wrong_rule = projection(self.scope)
        wrong_rule["rules"][0]["scope"] = "worker"
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.make_snapshot(
                self.scope, self.visibility, self.cursor, wrong_rule, self.events)
        self.assertEqual(raised.exception.code, "cross_role_rule")

        wrong_inbox = projection(self.scope)
        wrong_inbox["inbox_cursor"]["actor_id"] = "agentg.worker.claude"
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.make_snapshot(
                self.scope, self.visibility, self.cursor, wrong_inbox, self.events)
        self.assertEqual(raised.exception.code, "cross_actor_inbox")

    def test_chain_rejects_gap_break_cursor_and_cross_project_event(self):
        start = p.make_cursor(0, p.GENESIS_HASH, 0)
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_chain([self.events[1]], start,
                             p.make_cursor(1, self.h2, 1))
        self.assertEqual(raised.exception.code, "chain_sequence_gap")

        broken = copy.deepcopy(self.events)
        broken[1]["prev_hash"] = digest("wrong")
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_chain(broken, start, self.cursor,
                             project_id="agentg")
        self.assertEqual(raised.exception.code, "chain_hash_break")

        wrong_cursor = p.make_cursor(3, digest("wrong-end"), 3)
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_chain(self.events, start, wrong_cursor)
        self.assertEqual(raised.exception.code, "cursor_chain_mismatch")

        foreign_event = event(1, p.GENESIS_HASH, project="foreign")
        foreign = p.make_visible_record(foreign_event)
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_chain(
                [foreign], start,
                p.make_cursor(1, foreign_event["hash"], 1),
                             project_id="agentg")
        self.assertEqual(raised.exception.code, "cross_project_event")

        tampered = copy.deepcopy(self.events[0])
        tampered["event"]["payload"]["body"] = "rewritten"
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_chain_record(tampered, project_id="agentg")
        self.assertEqual(raised.exception.code, "event_payload_mismatch")

    def test_pull_request_result_and_reset_required_shapes(self):
        request = p.make_pull_request(
            self.scope, p.make_cursor(1, self.h1, 1), self.visibility,
            limit=200, created_at="2026-08-24T01:00:00.000Z")
        p.validate_pull_request(
            request, expected_scope=self.scope,
            expected_visibility=self.visibility)

        result = p.make_pull_result(
            self.scope,
            self.visibility,
            p.make_cursor(1, self.h1, 1),
            p.make_cursor(2, self.h2, 2),
            self.cursor,
            [p.make_redacted_anchor(2, self.h1, self.h2)],
            {"rules": projection(self.scope)["rules"]},
            generated_at="2026-08-24T01:01:00.000Z",
        )
        checked = p.validate_pull_result(
            result, expected_scope=self.scope,
            expected_visibility=self.visibility)
        self.assertTrue(checked["has_more"])

        reset = p.make_reset_required(
            self.scope, self.visibility, "visibility_changed",
            "Role or bridge policy changed", self.cursor,
            generated_at="2026-08-24T01:02:00.000Z")
        self.assertEqual(p.validate_pull_result(reset)["status"],
                         "reset_required")

    def test_pull_rejects_bad_limit_has_more_digest_and_oversize(self):
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.make_pull_request(self.scope, self.cursor, self.visibility, limit=0)
        self.assertEqual(raised.exception.code, "invalid_limit")

        result = p.make_pull_result(
            self.scope, self.visibility, self.cursor, self.cursor, self.cursor,
            [], {}, has_more=False)
        wrong_more = copy.deepcopy(result)
        wrong_more["has_more"] = True
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_pull_result(wrong_more)
        self.assertEqual(raised.exception.code, "invalid_has_more")

        wrong_digest = copy.deepcopy(result)
        wrong_digest["changes_sha256"] = "sha256:" + digest("wrong")
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_pull_result(wrong_digest)
        self.assertEqual(raised.exception.code, "changes_hash_mismatch")

        snapshot = p.make_snapshot(
            self.scope, self.visibility, self.cursor,
            projection(self.scope), self.events)
        with mock.patch.object(p, "MAX_SNAPSHOT_BYTES", 256):
            with self.assertRaises(p.EnvelopeTooLarge):
                p.validate_snapshot(snapshot)

        request = p.make_pull_request(self.scope, self.cursor, self.visibility)
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_pull_request(
                request,
                expected_visibility=p.visibility_fingerprint(self.scope, {}))
        self.assertEqual(raised.exception.code, "visibility_changed")

    def test_pull_bounds_genesis_batches_and_projection_project_rows(self):
        start = p.make_cursor(0, p.GENESIS_HASH, 0)
        one = p.make_redacted_anchor(1, p.GENESIS_HASH, self.h1)
        with mock.patch.object(p, "MAX_PULL_RECORDS", 0):
            with self.assertRaises(p.SyncProtocolError) as raised:
                p.make_pull_result(
                    self.scope, self.visibility, start,
                    p.make_cursor(1, self.h1, 1),
                    p.make_cursor(1, self.h1, 1), [one], {})
        self.assertEqual(raised.exception.code, "too_many_records")

        foreign = projection(self.scope)
        foreign["tasks"][0]["project_id"] = "another-project"
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_identity_projection(foreign, self.scope)
        self.assertEqual(raised.exception.code, "cross_project_projection")


class MutationAndDependencyTests(ProtocolFixture):
    def test_mutation_hash_is_canonical_immutable_and_scope_bound(self):
        mutation = self.mutation()
        self.assertEqual(mutation["request_sha256"],
                         p.mutation_sha256(copy.deepcopy(mutation)))
        checked = p.validate_client_mutation(
            mutation, expected_scope=self.scope)
        self.assertEqual(checked["operation"], "task.create")

        changed = copy.deepcopy(mutation)
        changed["payload"]["title"] = "Changed after hashing"
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_client_mutation(changed, expected_scope=self.scope)
        self.assertEqual(raised.exception.code, "mutation_hash_mismatch")

        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_client_mutation(mutation, expected_scope=self.other_scope)
        self.assertEqual(raised.exception.code, "cross_principal_mutation")

    def test_push_orders_dependencies_and_resolves_declared_local_refs(self):
        first = self.mutation()
        second = self.mutation(
            mutation_id="cm_device_0002",
            sequence=2,
            operation="task.claim",
            payload={"task_id": p.local_ref(
                first["client_mutation_id"], ["task_id"])},
            depends_on=[first["client_mutation_id"]],
        )
        push = p.make_push_request(
            self.scope, self.visibility, "client_home", "device_home",
            [first, second], created_at="2026-08-24T01:01:00.000Z")
        checked = p.validate_push_request(push, expected_scope=self.scope)
        self.assertEqual(
            [item["client_sequence"] for item in checked["mutations"]], [1, 2])

        prior = "cm_prior_0000"
        later = self.mutation(
            mutation_id="cm_device_0003", sequence=3,
            operation="task.report",
            payload={"task_id": p.local_ref(prior, ["task_id"])},
            depends_on=[prior])
        retry = p.make_push_request(
            self.scope, self.visibility, "client_home", "device_home", [later],
            known_receipts={prior})
        p.validate_push_request(retry, expected_scope=self.scope,
                                known_receipts={prior})

    def test_push_rejects_forward_undeclared_self_duplicate_and_cross_client(self):
        first = self.mutation()
        future = "cm_device_0002"
        forward = self.mutation(
            mutation_id="cm_device_0003", sequence=1,
            payload={"task_id": p.local_ref(future, ["task_id"])},
            depends_on=[future])
        envelope = {
            "format": p.PUSH_REQUEST_FORMAT, "schema_version": p.SCHEMA_VERSION,
            "scope": self.scope, "visibility_fingerprint": self.visibility,
            "client_id": "client_home", "device_id": "device_home",
            "mutations": [forward], "created_at": "2026-08-24T01:00:00Z",
        }
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_push_request(envelope)
        self.assertEqual(raised.exception.code, "forward_dependency")

        undeclared = self.mutation(
            mutation_id="cm_device_0002", sequence=2,
            payload={"task_id": p.local_ref(
                first["client_mutation_id"], ["task_id"])})
        envelope["mutations"] = [first, undeclared]
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_push_request(envelope)
        self.assertEqual(raised.exception.code, "undeclared_local_ref")

        self_dependent = copy.deepcopy(first)
        self_dependent["depends_on"] = [first["client_mutation_id"]]
        self_dependent["request_sha256"] = p.mutation_sha256(self_dependent)
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_client_mutation(self_dependent)
        self.assertEqual(raised.exception.code, "self_dependency")

        envelope["mutations"] = [first, copy.deepcopy(first)]
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_push_request(envelope)
        self.assertEqual(raised.exception.code, "duplicate_mutation")

        other_client = self.mutation(
            mutation_id="cm_device_0002", sequence=2,
            client_id="client_office")
        envelope["mutations"] = [first, other_client]
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_push_request(envelope)
        self.assertEqual(raised.exception.code, "cross_client_mutation")

    def test_mutation_threat_model_rejects_secrets_unknown_fields_and_size(self):
        with self.assertRaises(p.SyncProtocolError) as raised:
            self.mutation(payload={"api_token": "atc_secret"})
        self.assertEqual(raised.exception.code, "secret_in_projection")

        mutation = self.mutation()
        mutation["unknown"] = "ambiguous hash material"
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_client_mutation(mutation)
        self.assertEqual(raised.exception.code, "unknown_field")

        mutation = self.mutation(payload={"body": "x" * 2048})
        with mock.patch.object(p, "MAX_MUTATION_BYTES", 512):
            with self.assertRaises(p.EnvelopeTooLarge):
                p.validate_client_mutation(mutation)

        first = self.mutation()
        push = p.make_push_request(
            self.scope, self.visibility, "client_home", "device_home", [first])
        with mock.patch.object(p, "MAX_MUTATIONS", 0):
            with self.assertRaises(p.SyncProtocolError) as raised:
                p.validate_push_request(push)
        self.assertEqual(raised.exception.code, "too_many_mutations")

        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_push_request(
                push,
                expected_visibility=p.visibility_fingerprint(self.scope, {}))
        self.assertEqual(raised.exception.code, "visibility_changed")


class ReceiptAndResultTests(ProtocolFixture):
    def test_receipt_returns_duplicate_for_exact_retry(self):
        mutation = self.mutation()
        applied = p.applied_result(
            self.scope, mutation, {"task_id": "T-40"}, self.cursor,
            recorded_at="2026-08-24T01:02:00.000Z")
        receipt = p.make_stored_receipt(
            self.scope, mutation, applied,
            stored_at="2026-08-24T01:02:00.000Z")
        outcome = p.stored_receipt_outcome(
            receipt, copy.deepcopy(mutation), self.scope,
            recorded_at="2026-08-24T01:03:00.000Z")
        self.assertEqual(outcome["status"], "duplicate")
        self.assertEqual(outcome["result"], {"task_id": "T-40"})
        self.assertEqual(outcome["server_cursor"], self.cursor)

    def test_receipt_detects_body_conflict_without_last_write_wins(self):
        mutation = self.mutation()
        applied = p.applied_result(
            self.scope, mutation, {"task_id": "T-40"}, self.cursor)
        receipt = p.make_stored_receipt(self.scope, mutation, applied)
        changed = self.mutation(payload={"title": "Different body"})
        outcome = p.stored_receipt_outcome(
            receipt, changed, self.scope,
            recorded_at="2026-08-24T01:03:00.000Z")
        self.assertEqual(outcome["status"], "conflict")
        self.assertEqual(outcome["code"], "idempotency_key_reused")
        self.assertFalse(outcome["retryable"])
        self.assertIsNone(outcome["result"])

    def test_receipt_rejects_cross_principal_without_disclosing_result(self):
        mutation = self.mutation()
        receipt = p.make_stored_receipt(
            self.scope, mutation,
            p.applied_result(
                self.scope, mutation, {"private": "T-40"}, self.cursor))
        other_mutation = self.mutation(identity=self.other_scope)
        outcome = p.stored_receipt_outcome(
            receipt, other_mutation, self.other_scope)
        self.assertEqual(outcome["status"], "rejected")
        self.assertEqual(outcome["code"],
                         "cross_principal_idempotency_key")
        self.assertIsNone(outcome["result"])

    def test_conflict_rejection_and_push_result_shapes_are_ordered(self):
        first = self.mutation()
        second = self.mutation(
            mutation_id="cm_device_0002", sequence=2)
        applied = p.applied_result(
            self.scope, first, {"task_id": "T-40"}, self.cursor)
        conflict = p.conflict_result(
            self.scope, second, "stale_task", "task is already claimed",
            current={"claimed_by": "agentg.worker.claude"},
            server_cursor=self.cursor)
        result = p.make_push_result(
            self.scope, self.visibility, [applied, conflict], self.cursor)
        checked = p.validate_push_result(
            result, expected_scope=self.scope,
            expected_mutation_ids=[first["client_mutation_id"],
                                   second["client_mutation_id"]])
        self.assertEqual(checked["status"], "partial")

        rejected = p.rejected_result(
            self.scope, second, "role_revoked", "cached role is no longer valid")
        self.assertEqual(rejected["status"], "rejected")
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_push_result(
                result,
                expected_mutation_ids=[second["client_mutation_id"],
                                       first["client_mutation_id"]])
        self.assertEqual(raised.exception.code, "push_result_order")

    def test_malformed_receipt_and_success_result_are_rejected(self):
        mutation = self.mutation()
        applied = p.applied_result(
            self.scope, mutation, {"task_id": "T-40"}, self.cursor)
        receipt = p.make_stored_receipt(self.scope, mutation, applied)
        receipt["request_sha256"] = "sha256:" + digest("other")
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_stored_receipt(receipt)
        self.assertEqual(raised.exception.code, "invalid_receipt")

        malformed = copy.deepcopy(applied)
        malformed["result"] = None
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_mutation_result(malformed)
        self.assertEqual(raised.exception.code, "invalid_success_result")

        malformed = copy.deepcopy(applied)
        malformed["status"] = []
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_mutation_result(malformed)
        self.assertEqual(raised.exception.code, "invalid_mutation_status")

        unsafe = copy.deepcopy(applied)
        unsafe["result"] = {"token_hash": "private"}
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_mutation_result(unsafe)
        self.assertEqual(raised.exception.code, "secret_in_projection")


class HumanScopeTests(ProtocolFixture):
    def test_human_projection_may_manage_all_rule_scopes_but_not_other_inbox(self):
        identity = human_scope()
        value = projection(identity)
        value["rules"] = [
            {"rule_id": "R-1", "scope": role, "enabled": 1}
            for role in ("everyone", "director", "advisor", "worker")
        ]
        checked = p.validate_identity_projection(value, identity)
        self.assertEqual(len(checked["rules"]), 4)

        value["inbox_cursor"]["actor_id"] = "web.someone-else"
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_identity_projection(value, identity)
        self.assertEqual(raised.exception.code, "cross_actor_inbox")


class PullBoundsAndSubsetTests(ProtocolFixture):
    """T-94 · a pull is never bounded more strictly than its own snapshot."""

    def test_pull_ceiling_matches_the_snapshot_ceiling(self):
        # A delta may carry any resource the snapshot carries, so a stricter
        # pull ceiling made every pull fail on a workspace whose snapshot is
        # accepted, and the client cursor could never advance.
        self.assertEqual(p.MAX_PULL_BYTES, p.MAX_SNAPSHOT_BYTES)
        oversized = p.make_pull_result(
            self.scope, self.visibility, self.cursor, self.cursor,
            self.cursor, [], {"full_log": ["line"]}, has_more=False)
        with mock.patch.object(p, "MAX_PULL_BYTES", 64):
            with self.assertRaises(p.EnvelopeTooLarge) as raised:
                p.validate_pull_result(oversized)
        self.assertEqual(raised.exception.code, "envelope_too_large")
        self.assertIn("envelope_too_large", p.OVERSIZED_RESPONSE_CODES)

    def test_projection_subset_is_pull_only_bounded_and_negotiated(self):
        # A capability offer may never omit a required schema-v1 resource; a
        # pull-only delivered subset may, because pull changes are partial.
        with self.assertRaises(p.SyncProtocolError):
            p.make_projection_capabilities(
                p.PROJECTION_SCHEMA_VERSION, ["rules", "agents"])
        subset = p.validate_projection_subset(["tasks", "rules", "tasks"])
        self.assertEqual(subset, ["rules", "tasks"])
        self.assertEqual(
            p.projection_subset_query(subset),
            {"projection_pull_resources": "rules,tasks"})
        self.assertEqual(
            p.projection_subset_from_query("tasks,rules"), ["rules", "tasks"])
        self.assertIsNone(p.projection_subset_from_query(None))
        self.assertIsNone(p.validate_projection_subset(None))
        self.assertEqual(p.projection_subset_query(None), {})

        for unsafe in (["Tasks"], ["../etc"], ["tasks", ""], "tasks", []):
            with self.assertRaises(p.SyncProtocolError):
                p.validate_projection_subset(unsafe)
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_projection_subset(["not_a_resource"])
        self.assertEqual(
            raised.exception.code, "unsupported_projection_resource")

        legacy = p.legacy_projection_capabilities()
        with self.assertRaises(p.SyncProtocolError) as raised:
            p.validate_projection_subset(
                ["cloud_context"], capabilities=legacy)
        self.assertEqual(
            raised.exception.code, "unnegotiated_projection_resource")

    def test_a_narrowed_delta_still_validates_as_a_partial_projection(self):
        value = projection(self.scope)
        narrowed = {"tasks": value["tasks"]}
        checked = p.validate_projection_for_capabilities(
            narrowed, self.scope, p.current_projection_capabilities(),
            partial=True)
        self.assertEqual(set(checked), {"tasks"})
        for resource in p.LARGE_PROJECTION_RESOURCES:
            self.assertIn(
                resource,
                p.current_projection_capabilities()["resources"])


if __name__ == "__main__":
    unittest.main()
