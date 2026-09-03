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
        # Live hosted writes keep their receipts in the same store the
        # reconnect path queries: {client_mutation_id: receipt fields}.
        self.live_receipts = {}
        self.receipt_lookups = []
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
        identity_handoffs = [{
            "project_id": "agentg",
            "actor_id": self.scope["actor_id"],
            "version": 1,
            "content": {"objective": "Continue offline safely"},
            "updated_by": self.scope["actor_id"],
            "updated_owner": self.scope["principal_id"],
            "updated_at": "2026-08-24T00:00:00.000Z",
            "event_id": "ev_handoff_0001",
            "legacy_source_version": None,
        }]
        project_handoffs = [{
            "project_id": "agentg",
            "version": 1,
            "content": {"objective": "Continue offline safely"},
            "updated_by": "agentg.director.codex",
            "updated_at": "2026-08-24T00:00:00.000Z",
        }]
        role_scopes = []
        if role in {"director", "advisor", "worker"}:
            role_scopes.append({
                "project_id": "agentg", "role": role, "version": 1,
                "content": "%s continuity scope" % role,
                "updated_by": self.scope["actor_id"],
                "updated_owner": self.scope["principal_id"],
                "updated_at": "2026-08-24T00:00:00.000Z",
                "event_id": "ev_role_scope_0001",
            })
        return {
            "project": {
                "project_id": "agentg", "name": "Agentg",
                "context_version": self.head()["context_version"],
            },
            "handoffs": list(identity_handoffs),
            "identity_handoffs": list(identity_handoffs),
            "project_handoffs": list(project_handoffs),
            "role_scopes": role_scopes,
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

    def land_live_write(self, mutation_id, tool, payload, operation=None):
        """Apply one live hosted write and store its durable receipt."""
        previous = self.events[-1]["hash"] if self.events \
            else protocol.GENESIS_HASH
        event = canonical_event(
            len(self.events) + 1, previous,
            body="%s %s" % (tool, json.dumps(payload, sort_keys=True)),
            actor=self.scope["actor_id"], owner=self.scope["principal_id"])
        self.events.append(event)
        if operation == "room.send" or tool == "room_send":
            self.room.append({
                "project_id": "agentg", "seq": event["seq"],
                "body": payload.get("body"),
            })
        self.live_receipts[mutation_id] = {
            "tool": tool,
            "request_sha256": protocol.live_request_sha256(tool, payload),
            "status": "applied",
            "event_id": event["event_id"],
            "event_seq": event["seq"],
        }
        return event

    def reserve_live_write(self, mutation_id, tool, payload):
        """Record a started-but-never-receipted write: unknown, not absent."""
        self.live_receipts[mutation_id] = {
            "tool": tool,
            "request_sha256": protocol.live_request_sha256(tool, payload),
            "status": "reserved",
        }

    def fetch_receipts(self, ids):
        if not self.online:
            raise offline.RemoteUnavailableError("hosted Attacca is offline")
        self.receipt_lookups.append(list(ids))
        answer = {}
        for item in ids:
            entry = self.live_receipts.get(item)
            if entry is None:
                answer[item] = None
                continue
            applied = entry.get("status", "applied") == "applied"
            answer[item] = protocol.make_live_receipt(
                self.scope, item, entry["tool"], entry["request_sha256"],
                status=entry.get("status", "applied"),
                canonical_event_id=entry.get("event_id") if applied else None,
                canonical_event_seq=entry.get("event_seq") if applied else None,
                server_cursor=self.head() if applied else None)
        return answer

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

    def ambiguous(self, engine, mutation_id, tool="room_send",
                  payload=None, operation="room.send", replayable=True):
        payload = payload or {"body": "ambiguous %s" % mutation_id}
        return engine.record_ambiguous_live_write(
            mutation_id, tool, payload, operation=operation,
            request_sha256=protocol.live_request_sha256(tool, payload),
            phase="response", replayable=replayable)

    def test_ambiguous_records_are_schema_checked_and_never_pending_work(self):
        engine = self.engine("ambiguity")
        self.initialize(engine)
        record = self.ambiguous(engine, "cm_ambiguous_0001")
        self.assertEqual(record["kind"], "ambiguous")
        self.assertEqual(record["ambiguous"]["phase"], "response")

        # An ambiguous write is not queued work: it is never replayed until
        # the hosted receipt says what happened.
        self.assertEqual(engine.pending_mutations(), [])
        status = engine.status()
        self.assertEqual(
            status["ambiguous_pending_reconcile"], ["cm_ambiguous_0001"])
        self.assertEqual(status["ambiguous_count"], 1)
        self.assertTrue(status["pending_sync"])
        self.assertFalse(status["convergence_proof"]["online"])

        # A malformed or reserved-attribution body never becomes replayable.
        forced = engine.record_ambiguous_live_write(
            "cm_ambiguous_0002", "agent_register",
            {"agent_id": "agentg.director.claude", "role": "director"},
            request_sha256=protocol.live_request_sha256("agent_register", {}),
            phase="response")
        self.assertFalse(forced["ambiguous"]["replayable"])
        self.assertEqual(forced["ambiguous"]["payload"], {})
        with self.assertRaises(offline.OfflineSyncError):
            engine.record_ambiguous_live_write(
                "short", "room_send", {"body": "bad id"})

        # The journal validates the stored record exactly like a mutation.
        paths = sorted(engine.journal_directory.iterdir())
        target = next(path for path in paths
                      if json.loads(path.read_text()).get("kind")
                      == "ambiguous")
        record = json.loads(target.read_text())
        record["ambiguous"]["phase"] = "teleported"
        target.write_text(json.dumps(record))
        with self.assertRaises(offline.OfflineJournalError):
            engine.status()

    def test_unwritable_journal_still_leaves_a_last_resort_ambiguous_trace(self):
        """A journal that refuses the record must not erase the evidence."""
        engine = self.engine("unjournaled")
        self.initialize(engine)
        payload = {"body": "outcome unknown and journal broken"}
        mutation_id = "cm_unjournaled_0001"

        def record():
            return engine.record_ambiguous_live_write(
                mutation_id, "room_send", payload, operation="room.send",
                request_sha256=protocol.live_request_sha256(
                    "room_send", payload),
                phase="response")

        # A merely read-only journal directory is NOT the failure mode: every
        # locked operation runs _ensure_layout first, which repairs 0o700 on a
        # directory this identity owns.  Prove that self-heal rather than
        # asserting a failure the outbox recovers from on its own.
        original_mode = stat.S_IMODE(engine.journal_directory.stat().st_mode)
        self.addCleanup(
            lambda: os.chmod(engine.journal_directory, original_mode))
        os.chmod(engine.journal_directory, 0o500)
        self.assertEqual(record()["kind"], "ambiguous")
        self.assertEqual(
            stat.S_IMODE(engine.journal_directory.stat().st_mode), 0o700)
        self.assertFalse(engine.unjournaled_log_path.exists())

        # A journal that genuinely cannot accept the record does fail: here
        # the append-only record set no longer validates.
        (engine.journal_directory / "not-a-record.txt").write_text("junk")
        with self.assertRaises(offline.OfflineJournalError):
            engine.record_ambiguous_live_write(
                "cm_unjournaled_0009", "room_send", payload,
                operation="room.send", phase="response")
        # ... and so does an outbox whose records directory is not a
        # directory at all, which fails before any permission repair.
        (engine.journal_directory / "not-a-record.txt").unlink()
        for path in list(engine.journal_directory.iterdir()):
            path.unlink()
        engine.journal_directory.rmdir()
        engine.journal_directory.write_text("clobbered")
        with self.assertRaises(FileExistsError):
            engine.record_ambiguous_live_write(
                "cm_unjournaled_0010", "room_send", payload,
                operation="room.send", phase="response")
        # Nothing was written anywhere yet: that is the gap being closed.
        self.assertFalse(engine.unjournaled_log_path.exists())

        # The last-resort trace lives beside the journal, so it still writes.
        self.assertTrue(engine.record_unjournaled_ambiguous_write(
            mutation_id, "room_send", operation="room.send",
            request_sha256=protocol.live_request_sha256("room_send", payload),
            phase="response", error="outbox record could not be created"))
        entries = engine.unjournaled_ambiguous_records()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["client_mutation_id"], mutation_id)
        self.assertEqual(entries[0]["tool"], "room_send")
        self.assertEqual(entries[0]["phase"], "response")
        self.assertEqual(entries[0]["device_id"], "device_unjournaled")
        self.assertIn("verify the hosted workspace", entries[0]["hint"])
        # The trace is a plain append-only text file, never a journal record.
        self.assertEqual(
            engine.unjournaled_log_path.name,
            offline.UNJOURNALED_AMBIGUOUS_LOG_NAME)
        self.assertEqual(engine.unjournaled_log_path.parent,
                         engine.outbox_directory)
        self.assertEqual(
            engine.unjournaled_log_path.read_text().count("\n"), 1)

        # It appends: a second unknown outcome never overwrites the first.
        self.assertTrue(engine.record_unjournaled_ambiguous_write(
            "cm_unjournaled_0002", "task_create", operation="task.create"))
        self.assertEqual(
            [item["client_mutation_id"]
             for item in engine.unjournaled_ambiguous_records()],
            [mutation_id, "cm_unjournaled_0002"])

        # Once the outbox is usable again the counter is surfaced in status.
        engine.journal_directory.unlink()
        engine.journal_directory.mkdir(mode=0o700)
        status = engine.status()
        self.assertEqual(status["ambiguous_unjournaled_count"], 2)
        self.assertEqual(
            status["ambiguous_unjournaled_ids"],
            [mutation_id, "cm_unjournaled_0002"])
        self.assertEqual(status["ambiguous_unjournaled_log"],
                         str(engine.unjournaled_log_path))
        self.assertEqual(status["ambiguous_count"], 0)
        self.assertEqual(status["ambiguous_pending_reconcile"], [])
        self.assertEqual(status["pending_count"], 0)

    def test_last_resort_ambiguous_trace_never_pins_the_device_to_pending(self):
        """The log has no resolution path, so it is not pending work."""
        engine = self.engine("unjournaled_mode")
        self.initialize(engine)
        engine.synchronize(self.remote)
        before = engine.status()
        self.assertEqual(before["ambiguous_unjournaled_count"], 0)
        self.assertIsNone(before["ambiguous_unjournaled_log"])

        self.assertTrue(engine.record_unjournaled_ambiguous_write(
            "cm_mode_0001", "room_send", operation="room.send"))
        after = engine.status()
        self.assertEqual(after["ambiguous_unjournaled_count"], 1)
        # Mode and pending_sync are deliberately unchanged: an unresolvable
        # trace must never leave this device permanently "pending".
        self.assertEqual(after["mode"], before["mode"])
        self.assertEqual(after["pending_sync"], before["pending_sync"])
        self.assertFalse(after["pending_sync"])
        self.assertEqual(after["mode"], "online")

    def test_last_resort_ambiguous_log_is_capped_and_never_raises(self):
        """Best effort means bounded, silent, and safe on a hostile path."""
        engine = self.engine("capped")
        self.initialize(engine)
        engine.unjournaled_log_path.write_text(
            "x" * (offline.MAX_UNJOURNALED_LOG_BYTES - 10))
        self.assertFalse(engine.record_unjournaled_ambiguous_write(
            "cm_over_cap_0001", "room_send"))
        # Unparsable content is skipped rather than raising into a brief.
        self.assertEqual(engine.unjournaled_ambiguous_records(), [])
        self.assertEqual(engine.status()["ambiguous_unjournaled_count"], 0)

        engine.unjournaled_log_path.unlink()
        # Every field is bounded, so an ordinary entry stays well inside the
        # per-entry limit even when the journal error is enormous.
        self.assertTrue(engine.record_unjournaled_ambiguous_write(
            "cm_big_0001", "room_send",
            error="e" * (offline.MAX_UNJOURNALED_ENTRY_BYTES * 2)))
        self.assertLessEqual(
            engine.unjournaled_log_path.stat().st_size,
            offline.MAX_UNJOURNALED_ENTRY_BYTES)
        self.assertEqual(
            len(engine.unjournaled_ambiguous_records()[0]["journal_error"]),
            500)

        # If an entry ever did exceed the limit it degrades to the
        # identifiers rather than writing truncated, unparsable JSON.
        original_limit = offline.MAX_UNJOURNALED_ENTRY_BYTES
        offline.MAX_UNJOURNALED_ENTRY_BYTES = 120
        self.addCleanup(
            setattr, offline, "MAX_UNJOURNALED_ENTRY_BYTES", original_limit)
        self.assertTrue(engine.record_unjournaled_ambiguous_write(
            "cm_big_0002", "room_send", error="still too large"))
        minimal = engine.unjournaled_ambiguous_records()[1]
        self.assertEqual(minimal["client_mutation_id"], "cm_big_0002")
        self.assertNotIn("journal_error", minimal)
        self.assertNotIn("storage_key", minimal)

        # A symlinked trace path is refused instead of followed.
        engine.unjournaled_log_path.unlink()
        target = self.root / "elsewhere.log"
        target.write_text("")
        engine.unjournaled_log_path.symlink_to(target)
        self.assertFalse(engine.record_unjournaled_ambiguous_write(
            "cm_symlink_0001", "room_send"))
        self.assertEqual(target.read_text(), "")
        self.assertEqual(engine.unjournaled_ambiguous_records(), [])

    def test_reconnect_reconciles_landed_and_absent_ambiguous_writes(self):
        engine = self.engine("reconcile")
        self.initialize(engine)
        landed_payload = {"body": "landed before the reply was lost"}
        absent_payload = {"body": "never reached the hosted ledger"}
        self.ambiguous(engine, "cm_landed_0001", payload=landed_payload)
        self.ambiguous(engine, "cm_absent_0001", payload=absent_payload)
        self.remote.land_live_write(
            "cm_landed_0001", "room_send", landed_payload,
            operation="room.send")

        report = engine.synchronize(self.remote)
        self.assertEqual(report["ambiguous_landed"], ["cm_landed_0001"])
        self.assertEqual(report["ambiguous_replayed"], ["cm_absent_0001"])
        self.assertTrue(report["receipt_lookup_supported"])
        self.assertEqual(report["applied"], ["cm_absent_0001"])
        # The landed write is never pushed again.
        self.assertEqual(self.remote.applied_ids, ["cm_absent_0001"])
        self.assertEqual(
            [item["body"] for item in self.remote.room].count(
                "landed before the reply was lost"), 1)
        summary = report["outage_summary"]
        self.assertEqual(summary["ambiguous_landed"], ["cm_landed_0001"])
        self.assertEqual(summary["ambiguous_replayed"], ["cm_absent_0001"])
        self.assertEqual(summary["queued_replayed"], [])
        self.assertEqual(summary["unresolved_ambiguous"], [])
        status = engine.status()
        self.assertEqual(status["ambiguous_pending_reconcile"], [])
        self.assertEqual(status["last_outage_summary"], summary)

        # A second cycle repeats nothing.
        again = engine.synchronize(self.remote)
        self.assertEqual(again["ambiguous_landed"], [])
        self.assertEqual(again["ambiguous_replayed"], [])
        self.assertEqual(self.remote.applied_ids, ["cm_absent_0001"])

    def test_unknown_receipt_or_missing_route_keeps_the_write_ambiguous(self):
        engine = self.engine("unknown")
        self.initialize(engine)
        payload = {"body": "outcome is genuinely unknown"}
        self.ambiguous(engine, "cm_unknown_0001", payload=payload)
        self.remote.reserve_live_write(
            "cm_unknown_0001", "room_send", payload)

        report = engine.synchronize(self.remote)
        self.assertEqual(report["ambiguous_unknown"], ["cm_unknown_0001"])
        self.assertEqual(report["ambiguous_replayed"], [])
        self.assertEqual(report["ambiguous_landed"], [])
        self.assertEqual(self.remote.applied_ids, [])
        self.assertEqual(
            engine.status()["ambiguous_pending_reconcile"],
            ["cm_unknown_0001"])
        self.assertEqual(
            report["outage_summary"]["unresolved_ambiguous"],
            ["cm_unknown_0001"])

        # An older hosted server has no receipt route at all: still unknown.
        class Older:
            def __init__(self, inner):
                self._inner = inner

            def fetch_snapshot(self, allow_scope_change=False):
                return self._inner.fetch_snapshot(
                    allow_scope_change=allow_scope_change)

            def pull(self, **kwargs):
                return self._inner.pull(**kwargs)

            def push(self, **kwargs):
                return self._inner.push(**kwargs)

        older = engine.reconcile_ambiguous(Older(self.remote))
        self.assertFalse(older["supported"])
        self.assertEqual(older["unknown"], ["cm_unknown_0001"])
        self.assertEqual(engine.pending_mutations(), [])

    def test_live_cursor_marks_the_mirror_stale_and_survives_v2_state(self):
        engine = self.engine("live-cursor")
        self.initialize(engine)
        self.assertIsNone(engine.live_cursor())
        head = engine.local_snapshot()["cursor"]
        ahead = protocol.make_cursor(
            head["event_seq"] + 5, "f" * 64, head["context_version"] + 1)
        engine.record_live_cursor(ahead)
        self.assertEqual(engine.live_cursor(), ahead)
        self.assertTrue(engine.status()["mirror_stale_below_live_cursor"])
        self.assertTrue(offline.OfflineProjectSync.cursor_behind(head, ahead))
        self.assertFalse(offline.OfflineProjectSync.cursor_behind(ahead, head))
        # The live cursor only ever moves forward.
        behind = protocol.make_cursor(1, "a" * 64, 0)
        self.assertEqual(engine.record_live_cursor(behind), ahead)

        # A schema-v2 state file from an older client still loads: it is
        # digest-checked exactly as before and upgraded in place.
        state = json.loads(engine.state_path.read_text())
        for key in ("live_cursor", "last_outage_summary",
                    "surfaced_ambiguous_ids", "state_sha256"):
            state.pop(key, None)
        state["schema_version"] = offline.SYNC_STATE_SCHEMA_VERSION - 1
        state["state_sha256"] = hashlib.sha256(json.dumps(
            state, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        engine.state_path.write_text(json.dumps(state))
        reloaded = self.engine("live-cursor")
        self.assertIsNone(reloaded.live_cursor())
        self.assertEqual(reloaded.status()["ambiguous_pending_reconcile"], [])
        # The upgraded shape persists on the next ordinary state write.
        reloaded.record_live_cursor(ahead)
        persisted = json.loads(reloaded.state_path.read_text())
        self.assertEqual(
            persisted["schema_version"], offline.SYNC_STATE_SCHEMA_VERSION)
        self.assertEqual(persisted["live_cursor"], ahead)


class OfflineDispositionParityTest(unittest.TestCase):
    """T-80: the mirror and the hosted store agree on what is still pending."""

    def setUp(self):
        import attacca as core
        self.core = core
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "parity.db"
        self.conn = core.connect(self.db)
        self.addCleanup(self.conn.close)
        checkout = Path(self.temp.name) / "checkout"
        checkout.mkdir()
        core.project_init(self.conn, "fixture", "human", path=checkout,
                          project_id="p", name="Parity")
        self.sender = "p.director.claude"
        self.actor = "p.director.codex"
        for actor_id, runtime in ((self.sender, "claude"),
                                  (self.actor, "codex")):
            core.agent_register(self.conn, "p", "fixture", "human",
                                agent_id=actor_id, role="director",
                                runtime=runtime)

    def scope(self):
        return {
            "server_id": "srv_parity", "project_id": "p",
            "principal_id": "fixture", "actor_id": self.actor,
            "actor_type": "agent", "role": "director",
        }

    def send(self, body, **kwargs):
        kwargs.setdefault("mentions", [self.actor])
        return self.core.room_send(
            self.conn, "p", self.sender, "agent", body, **kwargs)["event"]

    def test_projection_pending_matches_the_hosted_rules(self):
        core = self.core
        answered = self.send("Please verify the export")
        core.room_send(self.conn, "p", self.actor, "agent", "verified",
                       reply_to=answered["event_id"])
        retracted = self.send("Ignore this after all")
        core.append_event(self.conn, "p", self.sender, "agent",
                          core.MESSAGE_RETRACTION_EVENT_TYPE,
                          {"message_event_id": retracted["event_id"]})
        task_id = core.task_create(self.conn, "p", self.sender, "agent",
                                   "Ship it")["task_id"]
        completed = self.send("Finish the task", task_id=task_id)
        core.task_set_status(self.conn, "p", self.sender, "agent", task_id,
                             "done", reason="shipped")
        historical = self.send("Historical assignment")
        self.conn.execute(
            "INSERT INTO inbox_cursors (project_id, actor_id, last_read_seq,"
            " updated_at) VALUES ('p',?,?,?)",
            (self.actor, historical["seq"], core.now_iso()))
        deferred = self.send("Deferred on purpose")
        still_open = self.send("Genuinely open")
        hosted = core.pending_message_dispositions(
            self.conn, "p", self.actor, actor_type="agent",
            allow_baseline_write=True)
        core.message_dispose(self.conn, "p", self.actor, "agent",
                             deferred["event_id"], "deferred",
                             note="waiting on review")
        hosted = core.pending_message_dispositions(
            self.conn, "p", self.actor, actor_type="agent")
        self.assertEqual(
            [item["event_id"] for item in hosted["pending"]],
            [deferred["event_id"], still_open["event_id"]])

        projection = core._sync_projection(self.conn, self.scope())
        # The extended cursor record must remain a legal schema-v1 payload.
        protocol.validate_identity_projection(projection, self.scope())
        self.assertEqual(
            projection["inbox_cursor"]["disposition_baseline_seq"],
            historical["seq"])
        offline_state = core._projection_pending_dispositions(
            projection, self.actor, project_id="p", principal_id="fixture")
        self.assertEqual(
            [item["event_id"] for item in offline_state["pending"]],
            [item["event_id"] for item in hosted["pending"]])
        self.assertEqual(offline_state["baseline_seq"],
                         hosted["baseline_seq"])
        for event_id in (answered["event_id"], retracted["event_id"],
                         completed["event_id"], historical["event_id"]):
            hosted_record = hosted["dispositions"][event_id]
            offline_record = offline_state["dispositions"][event_id]
            self.assertTrue(hosted_record["implicit"])
            self.assertEqual(offline_record["disposition"],
                             hosted_record["disposition"])
            self.assertEqual(offline_record["reason"], hosted_record["reason"])
        self.assertEqual(
            offline_state["dispositions"][deferred["event_id"]][
                "disposition"], "deferred")

    def test_queued_offline_bulk_disposition_clears_the_same_rows(self):
        core = self.core
        first = self.send("First assignment")
        second = self.send("Second assignment")
        projection = core._sync_projection(self.conn, self.scope())
        overlays = [{
            "operation": "message.dispose_bulk",
            "client_mutation_id": "mut_offline_bulk_0001",
            "sync_state": "pending",
            "payload": {
                "event_ids": [first["event_id"]],
                "disposition": "acknowledged",
                "note": "handled before the outage",
            },
        }]
        state = core._projection_pending_dispositions(
            projection, self.actor, overlays=overlays, project_id="p",
            principal_id="fixture")
        self.assertEqual([item["event_id"] for item in state["pending"]],
                         [second["event_id"]])
        record = state["dispositions"][first["event_id"]]
        self.assertTrue(record["pending_sync"])
        self.assertEqual(record["client_mutation_id"],
                         "mut_offline_bulk_0001")
        baselined = core._projection_pending_dispositions(
            projection, self.actor, project_id="p", principal_id="fixture",
            overlays=[{
                "operation": "message.dispose_bulk",
                "client_mutation_id": "mut_offline_bulk_0002",
                "sync_state": "pending",
                "payload": {
                    "disposition": "acknowledged",
                    "note": "reconciled offline",
                    "filter": {"before_seq": second["seq"]},
                },
            }])
        self.assertEqual(baselined["pending"], [])
        self.assertEqual(baselined["baseline_seq"], second["seq"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
