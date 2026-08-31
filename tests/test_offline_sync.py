"""Identity-scoped offline mirror/outbox and convergence regressions."""

import hashlib
import json
import os
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import offline_sync as offline  # noqa: E402
import sync_protocol as protocol  # noqa: E402


def identity(principal="usr_jack", role="director", runtime="codex"):
    return {
        "server_id": "srv_test",
        "project_id": "agentg",
        "principal_id": principal,
        "actor_id": "agentg.%s.%s" % (role, runtime),
        "actor_type": "agent",
        "role": role,
    }


def canonical_event(seq, previous, *, audience="everyone", body=None,
                    actor="agentg.director.codex", owner="usr_jack",
                    device="server-fixture"):
    payload = {"audience": audience, "body": body or "event %d" % seq}
    payload_json = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    value = {
        "event_id": "ev_%04d" % seq,
        "project_id": "agentg",
        "seq": seq,
        "actor_id": actor,
        "actor_type": "agent",
        "owner": owner,
        "event_type": "note.sync",
        "payload": payload,
        "payload_json": payload_json,
        "payload_hash": payload_hash,
        "prev_hash": previous,
        "hash_version": 2,
        "context_version": seq,
        "base_revision": "abc123",
        "git_branch": "main",
        "device_id": device,
        "task_id": None,
        "created_at": "2026-08-24T00:00:%02d.000Z" % seq,
    }
    material = "|".join([
        previous, payload_hash, value["project_id"], str(seq),
        value["event_type"], actor, value["created_at"],
        value["actor_type"], owner, str(value["context_version"]),
        value["base_revision"], value["git_branch"], value["device_id"], "",
    ])
    value["hash"] = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return value


class FakeRemote:
    """Pure schema-v1 remote with deterministic failures and receipts."""

    def __init__(self, scope=None):
        self.scope = scope or identity()
        self.policy_generation = 0
        self.online = True
        self.events = []
        self.receipts = {}
        self.applied_ids = []
        self.fail_after_commit = set()
        self.fail_pull_after_push = set()
        self.misdirect_receipts = set()
        self.pull_failures = 0
        self.force_handoff_conflict = False
        previous = protocol.GENESIS_HASH
        for audience, body in (
                ("everyone", "public architecture history"),
                ("director", "director release rule discussed"),
                ("worker", "worker private hidden detail")):
            event = canonical_event(
                len(self.events) + 1, previous,
                audience=audience, body=body)
            self.events.append(event)
            previous = event["hash"]
        self.tasks = [{
            "project_id": "agentg", "task_id": "T-1",
            "title": "Identity mirror task", "status": "queued",
        }]
        self.room = [{
            "project_id": "agentg", "seq": 1,
            "body": "visible room history",
        }]
        self.bound = []

    def visibility(self):
        return protocol.visibility_fingerprint(self.scope, {
            "role": self.scope["role"],
            "generation": self.policy_generation,
        })

    def head(self):
        if not self.events:
            return protocol.make_cursor(0, protocol.GENESIS_HASH, 0)
        event = self.events[-1]
        return protocol.make_cursor(
            event["seq"], event["hash"], event["context_version"])

    def projection(self):
        role = self.scope["role"]
        return {
            "project": {
                "project_id": "agentg", "name": "Agentg",
                "context_version": self.head()["context_version"],
            },
            "handoffs": [{
                "project_id": "agentg", "version": 1,
                "content": {"objective": "Continue offline safely"},
            }],
            "rules": [{
                "project_id": "agentg", "rule_id": "R-everyone",
                "scope": "everyone", "enabled": 1, "priority": 1,
                "body": "Always run QA",
            }, {
                "project_id": "agentg", "rule_id": "R-role",
                "scope": role, "enabled": 1, "priority": 2,
                "body": "%s-only rule" % role,
            }],
            "tasks": list(self.tasks),
            "decisions": [{
                "project_id": "agentg", "decision_id": "D-1",
                "title": "Use scoped mirrors", "status": "accepted",
            }],
            "room_messages": list(self.room),
            "agents": [{
                "project_id": "agentg",
                "agent_id": self.scope["actor_id"], "role": role,
            }],
            "bridges": [],
            "inbox_cursor": {
                "actor_id": self.scope["actor_id"], "last_read_seq": 0,
            },
            "task_plans": [],
            "full_log": ["identity-filtered log line"],
            "actor_aliases": [],
        }

    def records(self, events=None):
        events = self.events if events is None else events
        visible = {"everyone", self.scope["role"]}
        return [
            protocol.make_visible_record(event)
            if event["payload"]["audience"] in visible
            else protocol.make_redacted_anchor(
                event["seq"], event["prev_hash"], event["hash"])
            for event in events
        ]

    def fetch_snapshot(self, allow_scope_change=False):
        if not self.online:
            raise offline.RemoteUnavailableError("hosted Attacca is offline")
        return protocol.make_snapshot(
            self.scope, self.visibility(), self.head(), self.projection(),
            self.records())

    def bind_verified_identity(self, scope, visibility_fingerprint):
        self.bound.append((scope, visibility_fingerprint))

    def pull(self, *, cursor, visibility_fingerprint, limit):
        if not self.online:
            raise offline.RemoteUnavailableError("hosted Attacca is offline")
        if self.pull_failures:
            self.pull_failures -= 1
            raise offline.RemoteUnavailableError(
                "connection dropped before convergence pull")
        if visibility_fingerprint != self.visibility():
            return protocol.make_reset_required(
                self.scope, self.visibility(), "visibility_changed",
                "role or visibility policy changed", self.head())
        if cursor["event_seq"]:
            index = cursor["event_seq"] - 1
            if index >= len(self.events) \
                    or self.events[index]["hash"] != cursor["event_hash"]:
                return protocol.make_reset_required(
                    self.scope, self.visibility(), "cursor_diverged",
                    "cursor no longer belongs to canonical chain", self.head())
        rows = self.events[cursor["event_seq"]:][:limit]
        next_cursor = cursor if not rows else protocol.make_cursor(
            rows[-1]["seq"], rows[-1]["hash"],
            rows[-1]["context_version"])
        changes = {}
        if rows:
            changes = {
                "project": self.projection()["project"],
                "tasks": list(self.tasks),
                "room_messages": list(self.room),
                "full_log": list(self.projection()["full_log"]),
            }
        return protocol.make_pull_result(
            self.scope, self.visibility(), cursor, next_cursor, self.head(),
            self.records(rows), changes)

    def _append_mutation_event(self, mutation):
        previous = self.events[-1]["hash"] if self.events \
            else protocol.GENESIS_HASH
        body = "%s %s" % (
            mutation["operation"],
            json.dumps(mutation["payload"], sort_keys=True))
        event = canonical_event(
            len(self.events) + 1, previous, body=body,
            actor=self.scope["actor_id"], owner=self.scope["principal_id"],
            device=mutation["device_id"])
        self.events.append(event)
        if mutation["operation"] == "room.send":
            self.room.append({
                "project_id": "agentg", "seq": event["seq"],
                "body": mutation["payload"].get("body"),
            })
        return event

    def push(self, *, mutations, known_receipts):
        if not self.online:
            raise offline.RemoteUnavailableError("hosted Attacca is offline")
        protocol.make_push_request(
            self.scope, self.visibility(), mutations[0]["client_id"],
            mutations[0]["device_id"], mutations,
            known_receipts=known_receipts)
        results = []
        prior_failed = False
        committed_to_drop = None
        pull_failure = False
        for mutation in mutations:
            mutation_id = mutation["client_mutation_id"]
            if prior_failed:
                result = protocol.rejected_result(
                    self.scope, mutation, "prior_mutation_failed",
                    "an earlier FIFO mutation failed",
                    server_cursor=self.head())
            elif mutation_id in self.receipts:
                result = dict(self.receipts[mutation_id])
                result.update({
                    "status": "duplicate", "code": "duplicate",
                    "reason": "identical mutation was already applied",
                    "recorded_at": protocol.utc_now(),
                })
                result = protocol.validate_mutation_result(
                    result, expected_scope=self.scope)
            elif mutation["operation"] == "handoff.update" \
                    and self.force_handoff_conflict:
                result = protocol.conflict_result(
                    self.scope, mutation, "context_moved",
                    "handoff context moved", current={"version": 99},
                    server_cursor=self.head())
            else:
                event = self._append_mutation_event(mutation)
                result = protocol.applied_result(
                    self.scope, mutation,
                    {"canonical_event_id": event["event_id"],
                     "canonical_event_seq": event["seq"]},
                    self.head())
                if mutation_id in self.misdirect_receipts:
                    altered = dict(result)
                    altered["result"] = {
                        "canonical_event_id": self.events[0]["event_id"],
                        "canonical_event_seq": event["seq"],
                    }
                    result = protocol.validate_mutation_result(
                        altered, expected_scope=self.scope)
                self.receipts[mutation_id] = result
                self.applied_ids.append(mutation_id)
                if mutation_id in self.fail_after_commit:
                    self.fail_after_commit.remove(mutation_id)
                    committed_to_drop = mutation_id
                if mutation_id in self.fail_pull_after_push:
                    self.fail_pull_after_push.remove(mutation_id)
                    pull_failure = True
            results.append(result)
            prior_failed = result["status"] not in {"applied", "duplicate"}
        response = protocol.make_push_result(
            self.scope, self.visibility(), results, self.head())
        if pull_failure:
            self.pull_failures += 1
        if committed_to_drop is not None:
            raise offline.RemoteUnavailableError(
                "connection dropped after canonical commit")
        return response


class OfflineIdentitySyncTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.remote = FakeRemote()

    def engine(self, name="home", scope=None, visibility=None, wake=None):
        scope = scope or self.remote.scope
        visibility = self.remote.visibility() if visibility is None else visibility
        return offline.OfflineProjectSync(
            self.root / "cache", "HTTPS://EXAMPLE.test:443/", scope,
            "client_%s" % name, "device_%s" % name,
            visibility_fingerprint=visibility, wake_callback=wake)

    def initialize(self, engine):
        return engine.install_snapshot(self.remote.fetch_snapshot())

    def queue(self, engine, body, mutation_id, operation="room.send"):
        return engine.queue_mutation(
            operation, {"body": body}, client_mutation_id=mutation_id,
            git_branch="feature/offline", git_revision="def456",
            actor_id=engine.scope["actor_id"],
            actor_type=engine.scope["actor_type"],
            owner=engine.scope["principal_id"])

    def test_identity_projection_is_private_searchable_and_never_admin_export(self):
        wake = []
        engine = self.engine(wake=lambda: wake.append("fsynced"))
        cursor = self.initialize(engine)
        self.assertEqual(cursor["event_seq"], 3)
        self.assertEqual(len(engine.read_section("history")), 2)
        self.assertEqual(len(engine.read_section("chain")), 3)
        self.assertNotIn(
            "worker private hidden detail",
            json.dumps(engine.local_snapshot(), sort_keys=True))
        self.assertFalse(engine.search_local("worker private hidden"))
        self.assertEqual(len(engine.rules_for_role()), 2)
        with self.assertRaises(offline.OfflineIdentityChangedError):
            engine.rules_for_role("worker")
        with self.assertRaises(offline.OfflineMirrorError):
            engine.install_snapshot({
                "format": "attacca.project-export",
                "manifest": {"project_id": "agentg"},
            })
        with self.assertRaises(offline.OfflineSyncError):
            engine.queue_mutation(
                "task.create", {"title": "forged attribution"},
                metadata={"nested": {"owner": "mallory"}},
                client_mutation_id="cm_forged_owner_0001")

        mutation = self.queue(
            engine, "unique pending overlay", "cm_private_0001")
        self.assertEqual(wake, ["fsynced"])
        self.assertTrue(engine.search_local("unique pending overlay"))
        overlay = engine.read_section("room", include_pending=True)
        self.assertEqual(
            overlay["pending"][0]["client_mutation_id"],
            mutation["client_mutation_id"])
        self.assertEqual(
            stat.S_IMODE(engine.directory.stat().st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE(engine.mirror_path.stat().st_mode), 0o600)
        record = next(engine.journal_directory.glob("*.json"))
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        raw = json.loads(record.read_text())
        self.assertEqual(
            raw["local_attribution"]["principal_id"], "usr_jack")
        self.assertEqual(
            raw["local_attribution"]["actor_id"],
            "agentg.director.codex")
        self.assertEqual(
            raw["local_attribution"]["git_branch"], "feature/offline")
        self.assertNotIn("api_token", json.dumps(raw))

        other_key = offline.mirror_storage_key(
            "https://example.test", "agentg", "usr_other")
        self.assertNotEqual(engine.storage_key, other_key)
        self.assertEqual(
            engine.storage_key,
            offline.mirror_storage_key(
                "https://EXAMPLE.test:443/", "agentg", "usr_jack"))

    def test_two_computers_retry_ambiguous_commit_without_duplicates(self):
        home = self.engine("home")
        office = self.engine("office")
        self.initialize(home)
        self.initialize(office)
        mutation_id = "cm_home_retry_0001"
        first = self.queue(home, "home offline work", mutation_id)
        repeated = self.queue(home, "home offline work", mutation_id)
        self.assertEqual(first, repeated)
        with self.assertRaises(offline.OfflineJournalError):
            self.queue(home, "different body", mutation_id)

        self.remote.fail_after_commit.add(mutation_id)
        first_sync = home.synchronize(self.remote)
        self.assertEqual(first_sync["status"], "offline")
        self.assertEqual(home.status()["pending_count"], 1)
        self.assertEqual(self.remote.applied_ids.count(mutation_id), 1)
        second_sync = home.synchronize(self.remote)
        self.assertEqual(second_sync["status"], "online")
        self.assertEqual(second_sync["duplicates"], [mutation_id])
        self.assertEqual(second_sync["converged"], [mutation_id])
        self.assertEqual(self.remote.applied_ids.count(mutation_id), 1)

        office_id = "cm_office_work_0001"
        self.queue(office, "office distinct work", office_id)
        self.assertEqual(office.synchronize(self.remote)["status"], "online")
        self.assertEqual(home.synchronize(self.remote)["status"], "online")
        self.assertTrue(home.search_local("office distinct work"))
        self.assertTrue(office.search_local("home offline work"))

    def test_receipt_survives_failed_final_pull_and_notifies_after_reconnect(self):
        engine = self.engine("convergence")
        self.initialize(engine)
        mutation_id = "cm_convergence_0001"
        self.queue(engine, "commit then lose pull", mutation_id)
        self.remote.fail_pull_after_push.add(mutation_id)

        interrupted = engine.synchronize(self.remote)
        self.assertEqual(interrupted["status"], "offline")
        self.assertEqual(interrupted["applied"], [mutation_id])
        state = engine.status()
        self.assertEqual(state["pending_count"], 0)
        self.assertEqual(state["convergence_awaiting_count"], 1)
        self.assertTrue(state["mirror_stale"])
        self.assertFalse(state["convergence_proof"]["online"])

        reloaded = self.engine("convergence")
        converged = reloaded.synchronize(self.remote)
        self.assertEqual(converged["status"], "online")
        self.assertEqual(converged["applied"], [])
        self.assertEqual(converged["duplicates"], [])
        self.assertEqual(converged["converged"], [mutation_id])
        proof = reloaded.status()["convergence_proof"]
        checked = offline.validate_convergence_proof(
            proof, expected_server_url="https://example.test",
            expected_project="agentg", expected_scope=self.remote.scope,
            require_online=True)
        self.assertIn(
            mutation_id, checked["own_canonical_events_observed"])
        self.assertEqual(checked["convergence_awaiting_receipts"], [])
        self.assertTrue(reloaded.search_local("commit then lose pull"))

    def test_receipt_pointing_at_unrelated_event_never_claims_convergence(self):
        engine = self.engine("misdirected")
        self.initialize(engine)
        mutation_id = "cm_misdirected_0001"
        self.queue(engine, "must not false-accept", mutation_id)
        self.remote.misdirect_receipts.add(mutation_id)
        result = engine.synchronize(self.remote)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["applied"], [mutation_id])
        self.assertEqual(result["converged"], [])
        status = engine.status()
        self.assertEqual(
            status["convergence_awaiting_receipts"], [mutation_id])
        self.assertFalse(status["convergence_proof"]["online"])

    def test_compound_device_receipt_accepts_legacy_physical_not_wrong_instance(self):
        def receipted(name, event_device=None):
            remote = FakeRemote()
            client_id = "client_%s" % name
            device_id = "device_%s" % name
            engine = offline.OfflineProjectSync(
                self.root / ("cache-" + name), "https://example.test",
                remote.scope, client_id, device_id,
                visibility_fingerprint=remote.visibility())
            engine.install_snapshot(remote.fetch_snapshot())
            mutation = engine.queue_mutation(
                "room.send", {"body": "device audit " + name},
                client_mutation_id="cm_device_%s_0001" % name)
            pushed = remote.push(mutations=[mutation], known_receipts=[])
            result = pushed["results"][0]
            if event_device is not None:
                original = remote.events[-1]
                replacement = canonical_event(
                    original["seq"], original["prev_hash"],
                    body=original["payload"]["body"],
                    actor=remote.scope["actor_id"],
                    owner=remote.scope["principal_id"], device=event_device)
                remote.events[-1] = replacement
                result = protocol.applied_result(
                    remote.scope, mutation, {
                        "canonical_event_id": replacement["event_id"],
                        "canonical_event_seq": replacement["seq"],
                    }, remote.head())
            engine._append_receipt(
                mutation, result,
                audit_device_id=device_id + "/" + client_id)
            return engine.synchronize(remote), engine, mutation

        # An upgraded client may receive a canonical event written by an old
        # server that recorded only the physical device. Exact event mapping
        # and request hash still prove this mutation, so it must converge.
        legacy, legacy_engine, legacy_mutation = receipted("legacy")
        self.assertEqual(legacy["status"], "online")
        self.assertEqual(
            legacy["converged"], [legacy_mutation["client_mutation_id"]])
        self.assertTrue(legacy_engine.convergence_proof()["online"])

        # A current server's different compound instance must not be accepted
        # as this client's attribution even on the same physical device.
        wrong, wrong_engine, wrong_mutation = receipted(
            "wrong", "device_wrong/another-client-instance")
        self.assertEqual(wrong["status"], "pending")
        self.assertEqual(wrong["converged"], [])
        self.assertEqual(
            wrong_engine.status()["convergence_awaiting_receipts"],
            [wrong_mutation["client_mutation_id"]])

    def test_conflict_is_durable_and_cancel_does_not_forge_a_dependency_receipt(self):
        engine = self.engine("conflict")
        self.initialize(engine)
        first = self.queue(
            engine, "handoff change", "cm_handoff_0001",
            operation="handoff.update")
        later = self.queue(
            engine, "must remain ordered", "cm_after_0002")
        self.remote.force_handoff_conflict = True
        result = engine.synchronize(self.remote)
        self.assertEqual(result["status"], "conflict")
        self.assertEqual(result["conflicts"], [first["client_mutation_id"]])
        self.assertEqual(result["blocked"], [later["client_mutation_id"]])

        reloaded = self.engine("conflict")
        reloaded.resolve_conflict(
            first["client_mutation_id"], "cancelled",
            "owner chose not to overwrite the handoff")
        state = reloaded.status()
        self.assertEqual(state["conflict_count"], 0)
        self.assertEqual(state["blocked_count"], 1)
        self.assertEqual(
            reloaded.pending_mutations()[0]["sync_state"], "blocked")
        self.assertNotIn(later["client_mutation_id"], self.remote.receipts)

    def test_visibility_and_role_resets_are_atomic_and_principal_is_pinned(self):
        engine = self.engine("reset")
        self.initialize(engine)
        second_process = self.engine("second-process")
        old_visibility = engine.visibility_fingerprint
        self.remote.policy_generation = 1
        result = engine.synchronize(self.remote)
        self.assertEqual(result["status"], "online")
        self.assertNotEqual(engine.visibility_fingerprint, old_visibility)
        self.assertEqual(engine.visibility_fingerprint, self.remote.visibility())
        director_visibility = engine.visibility_fingerprint
        self.assertTrue(self.remote.bound)
        # A process that retained the old pin reauthenticates against a fresh
        # snapshot instead of trusting/relabeling the other process's file.
        second = second_process.synchronize(self.remote)
        self.assertEqual(second["status"], "online")
        self.assertEqual(
            second_process.visibility_fingerprint, director_visibility)

        self.remote.scope = identity(role="advisor", runtime="claude")
        self.remote.policy_generation = 2
        changed = engine.synchronize(self.remote)
        self.assertEqual(changed["status"], "online")
        self.assertEqual(engine.scope["role"], "advisor")
        self.assertEqual(engine.scope["actor_id"], "agentg.advisor.claude")
        self.assertEqual(
            engine.local_snapshot()["scope"], self.remote.scope)
        self.assertEqual(len(engine.rules_for_role()), 2)

        # The Director and Advisor have separate visibility snapshots beneath
        # the same stable human-principal cache partition; neither overwrites
        # the other when Claude/Codex share one checkout.
        director = self.engine(
            "reset", scope=identity(), visibility=director_visibility)
        self.assertEqual(director.scope["role"], "director")
        self.assertEqual(director.local_snapshot()["scope"]["role"], "director")
        self.assertEqual(director.storage_key, engine.storage_key)
        self.assertNotEqual(director.mirror_key, engine.mirror_key)

        other = FakeRemote(identity(principal="usr_mallory"))
        with self.assertRaises(offline.OfflineIdentityChangedError):
            engine.install_snapshot(
                other.fetch_snapshot(), reset=True,
                reset_reason="token principal changed")
        self.assertEqual(engine.scope["principal_id"], "usr_jack")

    def test_role_change_with_pending_old_scope_write_is_an_explicit_conflict(self):
        engine = self.engine("role-pending")
        self.initialize(engine)
        self.queue(engine, "director-owned pending write", "cm_role_pending_0001")
        old_snapshot = engine.local_snapshot()
        self.remote.scope = identity(role="advisor", runtime="claude")
        self.remote.policy_generation = 8
        result = engine.synchronize(self.remote)
        self.assertEqual(result["status"], "conflict")
        self.assertIn("old outbox", result["error"])
        self.assertEqual(engine.scope["role"], "director")
        self.assertEqual(engine.local_snapshot(), old_snapshot)
        self.assertEqual(engine.status()["pending_count"], 1)

    def test_concurrent_queue_is_contiguous_and_outbox_tampering_is_fatal(self):
        engine = self.engine("concurrent")
        self.initialize(engine)

        def queue(index):
            return engine.queue_mutation(
                "task.report", {"index": index},
                client_mutation_id="cm_concurrent_%04d" % index)

        with ThreadPoolExecutor(max_workers=8) as executor:
            rows = list(executor.map(queue, range(1, 25)))
        self.assertEqual(
            sorted(item["client_sequence"] for item in rows),
            list(range(1, 25)))
        self.assertEqual(len(list(engine.journal_directory.glob("*.json"))), 24)
        self.assertEqual(engine.status()["pending_count"], 24)

        target = sorted(engine.journal_directory.glob("*.json"))[10]
        record = json.loads(target.read_text())
        record["mutation"]["payload"]["index"] = 9999
        target.write_text(json.dumps(record))
        with self.assertRaises(offline.OfflineJournalError):
            engine.status()

    def test_tampering_symlinks_and_forged_proofs_never_create_authority(self):
        engine = self.engine("tamper")
        self.initialize(engine)
        proof = engine.convergence_proof()
        forged = dict(proof)
        forged["scope"] = identity(role="worker", runtime="claude")
        with self.assertRaises(offline.OfflineMirrorError):
            offline.validate_convergence_proof(forged)

        original_state = engine.state_path.read_bytes()
        state = json.loads(original_state)
        state["mirror_stale"] = not state["mirror_stale"]
        engine.state_path.write_text(json.dumps(state))
        with self.assertRaises(offline.OfflineSyncError):
            engine.status()
        engine.state_path.write_bytes(original_state)

        wrapper = json.loads(engine.mirror_path.read_text())
        wrapper["snapshot"]["projection"]["project"]["name"] = "tampered"
        engine.mirror_path.write_text(json.dumps(wrapper))
        with self.assertRaises(offline.OfflineMirrorError):
            engine.local_snapshot()

        symlink_root = self.root / "symlink-cache"
        target = self.root / "outside"
        target.mkdir()
        os.symlink(target, symlink_root)
        with self.assertRaises(offline.OfflineSyncError):
            offline.OfflineProjectSync(
                symlink_root, "https://example.test", self.remote.scope,
                "client_bad", "device_bad", self.remote.visibility())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
