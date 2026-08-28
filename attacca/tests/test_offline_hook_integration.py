"""Hook/watcher orchestration tests for identity-scoped offline continuity."""

import importlib.util
import json
import os
import hashlib
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest import mock
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import offline_sync as core  # noqa: E402
import sync_client as client  # noqa: E402
import sync_protocol as protocol  # noqa: E402

HOOK = ROOT / "hooks" / "session_start.py"
SPEC = importlib.util.spec_from_file_location(
    "attacca_offline_hook_integration_test", HOOK)
hook = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hook)


def delta(events=None, next_after=None):
    rows = list(events or [])
    return {
        "events": rows,
        "next_after": (rows[-1]["seq"] if rows else 0)
        if next_after is None else next_after,
        "may_have_more": False,
    }


class FakeOfflineAdapter:
    def __init__(self, status, snapshot=None, result=None,
                 server_url="http://attacca.invalid:4173"):
        self.current_status = dict(status)
        self.snapshot = snapshot
        self.result = result or {
            "status": "online", "applied": [], "duplicates": [],
            "conflicts": [], "blocked": [], "error": None,
        }
        self.server_url = server_url
        self.sync_calls = []
        self.pending = []
        self.conflict_rows = []
        self.observed = list(status.get("observed") or [])
        self.awaiting = list(status.get("awaiting") or [])
        self._refresh_proof()

    def _refresh_proof(self):
        if not isinstance(self.snapshot, dict) \
                or not isinstance(self.snapshot.get("scope"), dict):
            self.proof = {}
            self.current_status["convergence_proof"] = self.proof
            return
        scope = self.snapshot["scope"]
        stale = bool(self.current_status.get("mirror_stale"))
        online = bool(
            self.current_status.get("mode") == "online" and not stale
            and not self.awaiting
            and not self.current_status.get("pending_sync"))
        self.proof = core.ConvergenceProof(
            normalized_server_url=core.normalize_server_url(self.server_url),
            storage_key=core.mirror_storage_key(
                self.server_url, scope["project_id"], scope["principal_id"]),
            scope=scope,
            visibility_fingerprint=self.snapshot["visibility_fingerprint"],
            cursor=self.snapshot["cursor"],
            snapshot_sha256=hashlib.sha256(
                protocol.canonical_json_bytes(self.snapshot)).hexdigest(),
            mirror_verified_at="2026-08-24T06:00:00.000Z",
            mirror_stale=stale,
            convergence_awaiting_receipts=tuple(self.awaiting),
            own_canonical_events_observed=tuple(self.observed),
            online=online,
        ).as_dict()
        self.current_status.update({
            "scope": scope,
            "visibility_fingerprint": self.snapshot[
                "visibility_fingerprint"],
            "mirror_cursor": self.snapshot["cursor"],
            "mirror_verified_at": self.proof["mirror_verified_at"],
            "convergence_proof": self.proof,
        })

    def status(self):
        return json.loads(json.dumps(self.current_status))

    def synchronize(self, remote):
        self.sync_calls.append(remote)
        result = json.loads(json.dumps(self.result))
        if result["status"] == "online":
            self.current_status.update({
                "mode": "online", "pending_sync": False,
                "pending_count": 0, "conflict_count": 0,
                "mirror_stale": False,
            })
            self.pending = []
            self.conflict_rows = []
            for mutation_id in result.get("converged") or []:
                if mutation_id not in self.observed:
                    self.observed.append(mutation_id)
            self.awaiting = []
        elif result["status"] == "offline":
            self.current_status.update({
                "mode": "offline", "pending_sync": True,
                "mirror_stale": True,
            })
        elif result["status"] == "conflict":
            self.current_status.update({
                "mode": "conflict", "pending_sync": True,
                "conflict_count": len(result.get("conflicts") or []),
            })
        self._refresh_proof()
        return result

    def convergence_proof(self):
        return json.loads(json.dumps(self.proof))

    def local_snapshot(self):
        if isinstance(self.snapshot, Exception):
            raise self.snapshot
        return json.loads(json.dumps(self.snapshot))

    def pending_mutations(self):
        return json.loads(json.dumps(self.pending))

    def conflicts(self):
        return json.loads(json.dumps(self.conflict_rows))


class OfflineHookIntegrationTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.environment = mock.patch.dict(os.environ, {
            "HOME": str(self.root / "home"),
            "ATTACCA_WATCHER_DIR": str(self.root / "watcher"),
            "ATTACCA_RUNTIME": "codex",
            "ATTACCA_DEVICE_ID": "office-device",
        }, clear=False)
        self.environment.start()
        self.status = {
            "status": "linked", "project_id": "shared",
            "root": str(self.checkout),
            "link_path": str(self.checkout / ".attacca" / "project.json"),
            "state_path": str(self.root / "plugin-state.json"),
        }
        self.config = {
            "url": "http://attacca.invalid:4173",
            "actor": "codex", "owner": "jack",
        }
        self.scope = {
            "server_id": "srv_test", "project_id": "shared",
            "principal_id": "usr_jack",
            "actor_id": "shared.director.codex",
            "actor_type": "agent", "role": "director",
        }
        self.visibility = protocol.visibility_fingerprint(
            self.scope, {"generation": 1, "role": "director"})
        self.key = hook._register_watcher_subscription(
            self.status, ROOT, self.config, runtime="codex", now=0)

        def pin_identity(state):
            entry = state["subscriptions"][self.key]
            entry.update({
                "canonical_actor_id": self.scope["actor_id"],
                "actor_role": self.scope["role"],
                "identity_verified_at": "2026-08-24T05:59:00.000Z",
                "sync_scope": self.scope,
                "sync_visibility_fingerprint": self.visibility,
                "sync_schema_version": 1,
            })

        hook._mutate_state(hook._watcher_state_path(), pin_identity)

    def tearDown(self):
        self.environment.stop()
        self.tmp.cleanup()

    def watcher_state(self):
        return json.loads(hook._watcher_state_path().read_text())

    def test_watcher_client_key_and_identity_headers_are_exactly_scoped(self):
        credentials = Path.home() / ".attacca" / "credentials.json"
        credentials.parent.mkdir(parents=True)
        server_key = "https://attacca.example/tenant-a"
        credentials.write_text(json.dumps({
            "version": 1,
            "servers": {
                server_key: {
                    # Deliberately retain every retired credential shape here
                    # to prove D-17 never falls back to one of them.
                    "api_token": "human-bootstrap-must-not-leak",
                    "tokens": {"codex": "legacy-runtime-must-not-leak"},
                    "terminal_credential": {
                        "token": "legacy-terminal-must-not-leak",
                        "token_kind": "terminal",
                        "token_id": "terminal-test-id",
                        "device_id": "machine-device",
                        "bindings": [
                            {"project_id": "shared",
                             "actor_id": "shared.director.codex",
                             "runtime": "codex"},
                            {"project_id": "other",
                             "actor_id": "other.director.codex",
                             "runtime": "codex"},
                        ],
                    },
                    "agent_tokens": {
                        "shared": {
                            "shared.director.codex": {
                                "token": "shared-exact-token",
                                "runtime": "codex",
                            },
                        },
                        "other": {
                            "other.director.codex": {
                                "token": "other-exact-token",
                                "runtime": "codex",
                            },
                        },
                    },
                    "client_api_keys": {
                        "codex-install-a": {
                            "token": "atkey_tenant_a_install_a",
                            "token_kind": "client",
                            "token_id": "key-tenant-a-install-a",
                            "client_instance": "codex-install-a",
                            "username": "jack",
                            "project_memberships": ["shared", "other"],
                            "scope_mode": "selected_workspaces",
                            "label": "Codex office install",
                            "device_id": "machine-device",
                        },
                    },
                },
                "https://attacca.example/tenant-b": {
                    "client_api_keys": {
                        "codex-install-a": {
                            "token": "atkey_tenant_b_install_a",
                            "token_kind": "client",
                            "token_id": "key-tenant-b-install-a",
                            "client_instance": "codex-install-a",
                            "username": "jack",
                            "project_memberships": ["other"],
                            "scope_mode": "selected_workspaces",
                            "label": "Codex office install",
                            "device_id": "machine-device",
                        },
                    },
                },
            },
        }))
        os.chmod(credentials, 0o600)
        base = {
            "server_url": server_key,
            "runtime": "codex", "actor": "codex",
            "project_id": "shared",
            "canonical_actor_id": "shared.director.codex",
            "device_id": "machine-device",
            "client_instance": "codex-install-a",
        }
        other = dict(base, project_id="other",
                     canonical_actor_id="other.director.codex")

        with mock.patch.dict(os.environ, {
                "ATTACCA_API_TOKEN": "unscoped-env-must-not-leak",
                "ATTACCA_PROJECT": "",
                "ATTACCA_ACTOR": "codex"}, clear=False):
            self.assertEqual(
                hook._watcher_api_token(base), "atkey_tenant_a_install_a")
            self.assertEqual(
                hook._watcher_api_token(other), "atkey_tenant_a_install_a")
            # D-17 keys authenticate the installed client/human account, not
            # one AI model. Exact actor authority remains a request header
            # checked by the hosted server.
            self.assertEqual(hook._watcher_api_token(dict(
                base, canonical_actor_id="shared.director.claude")),
                "atkey_tenant_a_install_a")
            bootstrap = dict(base)
            bootstrap.pop("canonical_actor_id")
            self.assertEqual(hook._watcher_api_token(bootstrap),
                             "atkey_tenant_a_install_a")
            bootstrap_headers = hook._watcher_request_headers(bootstrap)
            self.assertEqual(bootstrap_headers["Authorization"],
                             "Bearer atkey_tenant_a_install_a")
            self.assertEqual(bootstrap_headers["X-Attacca-Actor"], "codex")
            claude_headers = hook._watcher_request_headers(dict(
                base, canonical_actor_id="shared.director.claude"))
            self.assertEqual(claude_headers["Authorization"],
                             "Bearer atkey_tenant_a_install_a")
            self.assertEqual(claude_headers["X-Attacca-Actor"],
                             "shared.director.claude")
            self.assertIsNone(hook._watcher_api_token(dict(
                base, project_id="not-a-membership")))
            self.assertIsNone(hook._watcher_api_token(dict(
                base, client_instance="different-install")))
            tenant_b = dict(
                other, server_url="https://attacca.example/tenant-b/")
            self.assertEqual(hook._watcher_api_token(tenant_b),
                             "atkey_tenant_b_install_a")

            headers = hook._watcher_request_headers(base)
            self.assertEqual(headers["Authorization"],
                             "Bearer atkey_tenant_a_install_a")
            self.assertEqual(headers["X-Attacca-Project"], "shared")
            self.assertEqual(headers["X-Attacca-Actor"],
                             "shared.director.codex")
            self.assertEqual(headers["X-Attacca-Client-Instance"],
                             "codex-install-a")
            self.assertEqual(headers["X-Attacca-Device-ID"],
                             "machine-device")
            self.assertEqual(headers["X-Attacca-Device"],
                             "machine-device")
        self.assertNotIn("token", json.dumps(self.watcher_state()).lower())

    def verified_status(self, **updates):
        value = {
            "mode": "pending", "read_source": "verified_local_mirror",
            "mirror_valid": True,
            "mirror_verified_at": "2026-08-24T06:00:00.000Z",
            "mirror_cursor": protocol.make_cursor(
                0, protocol.GENESIS_HASH, 9),
            "mirror_stale": False, "pending_sync": True,
            "pending_count": 1, "conflict_count": 0,
            "journal_records": 1,
            "last_local_write_at": "2026-08-24T06:01:00.000Z",
            "scope": self.scope,
            "visibility_fingerprint": self.visibility,
        }
        value.update(updates)
        return value

    def snapshot(self):
        projection = {
            "project": {"project_id": "shared", "name": "Shared"},
            "rules": [
                {"project_id": "shared", "rule_id": "R-1",
                 "title": "Build on v2",
                 "body": "Use v2.", "scope": "everyone", "enabled": 1,
                 "priority": 1},
                {"project_id": "shared", "rule_id": "R-2",
                 "title": "Director QA",
                 "body": "Review releases.", "scope": "director",
                 "enabled": 1, "priority": 2},
            ],
            "handoffs": [{"project_id": "shared", "version": 9, "content": {
                "objective": "Continue from local state"}}],
            "tasks": [{"project_id": "shared", "task_id": "T-7",
                       "title": "Offline work",
                       "status": "claimed"}],
            "decisions": [{"project_id": "shared", "decision_id": "D-2",
                           "status": "accepted"}],
            "room_messages": [{"project_id": "shared", "seq": 40,
                               "body": "cached room message"}],
            "agents": [{"project_id": "shared",
                        "agent_id": "shared.director.codex",
                        "role": "director"}],
            "bridges": [{"project_a": "shared", "project_b": "peer"}],
            "inbox_cursor": {
                "actor_id": "shared.director.codex", "last_read_seq": 40},
            "task_plans": [],
            "full_log": ["line %d" % number for number in range(41)],
            "actor_aliases": [],
        }
        return protocol.make_snapshot(
            self.scope, self.visibility,
            protocol.make_cursor(0, protocol.GENESIS_HASH, 9),
            projection, [])

    def test_queued_write_wakes_immediately_and_acceptance_is_durable(self):
        def delay(state):
            state["subscriptions"][self.key]["next_poll_at_epoch"] = 999

        hook._mutate_state(hook._watcher_state_path(), delay)
        adapter = FakeOfflineAdapter(
            self.verified_status(), self.snapshot(), result={
                "status": "online", "applied": ["cm_home_0001"],
                "duplicates": ["cm_home_0000"], "conflicts": [],
                "blocked": [], "converged": [
                    "cm_home_0001", "cm_home_0000"], "error": None,
            })
        remote = object()
        with mock.patch.object(hook, "_settings_interval", return_value=60):
            result = hook._watcher_tick(
                self.key, now=10, offline_adapter=adapter,
                remote_adapter=remote,
                delta_loader=lambda after: delta(next_after=41),
                notifier=lambda *_: None)
        self.assertTrue(result["write_woke"])
        self.assertEqual(result["sync_status"], "online")
        self.assertTrue(result["sync_queued"])
        self.assertEqual(adapter.sync_calls, [remote])
        entry = self.watcher_state()["subscriptions"][self.key]
        self.assertEqual(entry["next_poll_at_epoch"], 70)
        self.assertEqual(entry["offline_failure_count"], 0)
        self.assertEqual(entry["last_sync_result"], "online")
        accepted = [row for row in entry["pending"]
                    if row["kind"] == "offline_sync_accepted"]
        self.assertEqual(len(accepted), 1)
        self.assertIn("safely deduplicated", accepted[0]["summary"])

    def test_minute_poll_skips_full_sync_without_relevant_change(self):
        def current(state):
            entry = state["subscriptions"][self.key]
            entry.update({"event_cursor": 41,
                          "event_cursor_initialized": True,
                          "last_full_sync_at_epoch": 50,
                          "next_poll_at_epoch": 0})

        hook._mutate_state(hook._watcher_state_path(), current)
        adapter = FakeOfflineAdapter(self.verified_status(
            mode="online", pending_sync=False, pending_count=0,
            journal_records=0, last_local_write_at=None), self.snapshot())
        with mock.patch.object(hook, "_settings_interval", return_value=60), \
             mock.patch.object(hook, "_watcher_refresh_inbox_entry",
                               return_value={"ok": True, "staged": 0}):
            result = hook._watcher_tick(
                self.key, now=100, offline_adapter=adapter,
                remote_adapter=object(),
                delta_loader=lambda after: delta(next_after=41))
        self.assertTrue(result["due"])
        self.assertFalse(result["full_sync_performed"])
        self.assertIsNone(result["full_sync_reason"])
        self.assertEqual(adapter.sync_calls, [])

    def test_relevant_signal_and_ten_minute_safety_refresh_full_mirror(self):
        def current(state):
            entry = state["subscriptions"][self.key]
            entry.update({"event_cursor": 41,
                          "event_cursor_initialized": True,
                          "last_full_sync_at_epoch": 50,
                          "next_poll_at_epoch": 0})

        hook._mutate_state(hook._watcher_state_path(), current)
        adapter = FakeOfflineAdapter(self.verified_status(
            mode="online", pending_sync=False, pending_count=0,
            journal_records=0, last_local_write_at=None), self.snapshot())
        event = {"seq": 42, "event_id": "ev_42",
                 "event_type": "task.updated", "task_id": "T-1",
                 "payload": {}}
        with mock.patch.object(hook, "_settings_interval", return_value=60), \
             mock.patch.object(hook, "_watcher_refresh_inbox_entry",
                               return_value={"ok": True, "staged": 0}):
            changed = hook._watcher_tick(
                self.key, now=100, offline_adapter=adapter,
                remote_adapter=object(),
                delta_loader=lambda after: delta([event], next_after=42))
            safety = hook._watcher_tick(
                self.key, now=700, offline_adapter=adapter,
                remote_adapter=object(),
                delta_loader=lambda after: delta(next_after=42))
        self.assertTrue(changed["full_sync_performed"])
        self.assertEqual(changed["full_sync_reason"], "relevant_change")
        self.assertTrue(safety["full_sync_performed"])
        self.assertEqual(safety["full_sync_reason"], "safety_refresh")
        self.assertEqual(len(adapter.sync_calls), 2)
        entry = self.watcher_state()["subscriptions"][self.key]
        self.assertEqual(entry["last_full_sync_at_epoch"], 700)
        self.assertEqual(entry["last_full_sync_reason"], "safety_refresh")

    def test_outage_uses_backoff_dedup_and_verified_mirror_state(self):
        adapter = FakeOfflineAdapter(
            self.verified_status(), self.snapshot(), result={
                "status": "offline", "applied": [], "duplicates": [],
                "conflicts": [], "blocked": [],
                "error": "connection refused",
            })
        with mock.patch.object(hook, "_settings_interval", return_value=60):
            first = hook._watcher_tick(
                self.key, now=0, force=True, offline_adapter=adapter,
                remote_adapter=object())
            throttled = hook._watcher_tick(
                self.key, now=1, offline_adapter=adapter,
                remote_adapter=object())
            second = hook._watcher_tick(
                self.key, now=60, offline_adapter=adapter,
                remote_adapter=object())
        self.assertTrue(first["offline"])
        self.assertFalse(throttled["due"])
        self.assertTrue(second["offline"])
        entry = self.watcher_state()["subscriptions"][self.key]
        self.assertEqual(entry["offline_failure_count"], 2)
        self.assertEqual(entry["offline_retry_seconds"], 120)
        self.assertEqual(entry["next_poll_at_epoch"], 180)
        self.assertEqual(len(entry["pending"]), 1)
        self.assertEqual(entry["pending"][0]["kind"],
                         "offline_connection_error")
        self.assertIn("continue work", entry["pending"][0]["summary"])
        self.assertEqual(len(adapter.sync_calls), 2)
        self.assertNotIn("event_cursor", entry)

    def test_conflict_delta_is_queued_and_later_writes_stay_blocked(self):
        adapter = FakeOfflineAdapter(
            self.verified_status(), self.snapshot(), result={
                "status": "conflict", "applied": [], "duplicates": [],
                "conflicts": ["cm_conflict_0001"],
                "blocked": ["cm_later_0002"], "error": None,
            })
        adapter.conflict_rows = [{
            "client_mutation_id": "cm_conflict_0001",
            "remote": {"reason": "context moved"},
        }]
        with mock.patch.object(hook, "_settings_interval", return_value=60):
            result = hook._watcher_tick(
                self.key, now=0, force=True, offline_adapter=adapter,
                remote_adapter=object(),
                delta_loader=lambda after: delta(next_after=41),
                notifier=lambda *_: None)
        self.assertEqual(result["sync_status"], "conflict")
        entry = self.watcher_state()["subscriptions"][self.key]
        rows = [row for row in entry["pending"]
                if row["kind"] == "offline_sync_conflict"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["blocked"], ["cm_later_0002"])
        self.assertIn("nothing was discarded", rows[0]["summary"])

    def test_active_output_continues_from_verified_mirror_with_scoped_rules(self):
        adapter = FakeOfflineAdapter(self.verified_status(), self.snapshot())
        adapter.pending = [{
            "client_mutation_id": "cm_pending_0001", "operation": "task.report",
            "client_sequence": 1, "created_at": "2026-08-24T06:01:00Z",
            "sync_state": "ready",
        }]
        adapter.conflict_rows = [{
            "client_mutation_id": "cm_conflict_0001",
            "remote": {"reason": "context moved"},
        }]
        adapter.current_status.update({"pending_count": 1,
                                       "conflict_count": 1})
        with mock.patch.object(
                hook, "_plugin_and_config",
                return_value=(ROOT, self.config)), \
             mock.patch.object(
                 hook, "_ensure_background_watcher",
                 return_value={"ok": True, "already_running": True}), \
             mock.patch.object(hook, "_watcher_pending_notice",
                               return_value=None), \
             mock.patch.object(hook, "_settings_interval", return_value=60), \
             mock.patch.object(hook, "_update_offer", return_value=None), \
             mock.patch.object(hook, "_mcp_snapshot",
                               side_effect=RuntimeError("connection refused")):
            output = hook._active_output(
                self.status, offline_adapter=adapter)
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("ATTACCA ACTIVE OFFLINE SESSION BRIEF", context)
        self.assertIn("CONTINUE WORK", context)
        self.assertIn("verified_local_mirror", context)
        self.assertIn('"event_seq": 0', context)
        self.assertIn("Build on v2", context)
        self.assertIn("Director QA", context)
        self.assertNotIn("Worker-only secret", context)
        self.assertIn("cm_pending_0001", context)
        self.assertIn("cm_conflict_0001", context)
        self.assertIn("work may continue", output["systemMessage"])

    def test_revoked_client_key_blocks_valid_old_mirror_at_session_start(self):
        adapter = FakeOfflineAdapter(self.verified_status(), self.snapshot())
        with mock.patch.object(
                hook, "_plugin_and_config",
                return_value=(ROOT, self.config)), \
             mock.patch.object(
                 hook, "_ensure_background_watcher",
                 return_value={"ok": True, "already_running": True}), \
             mock.patch.object(
                 hook, "_watcher_pending_notice", return_value={
                     "system_message": "stale outage continuity",
                     "context": (
                         "ATTACCA ACTIVE OFFLINE SESSION BRIEF — "
                         "AUTHORITATIVE VERIFIED LOCAL MIRROR; CONTINUE WORK"),
                 }), \
             mock.patch.object(hook, "_settings_interval", return_value=60), \
             mock.patch.object(hook, "_update_offer", return_value=None), \
             mock.patch.object(
                 hook, "_mcp_snapshot",
                 side_effect=hook.HostedAuthenticationRequired(
                     "revoked client-install key", http_status=401)):
            output = hook._active_output(
                self.status, offline_adapter=adapter)
        context = output["hookSpecificOutput"]["additionalContext"]
        serialized = json.dumps(output)
        self.assertIn("ATTACCA AUTHENTICATION REQUIRED", context)
        self.assertIn("HOST REACHABLE, CACHE BLOCKED", context)
        self.assertIn("HTTP 401", context)
        self.assertIn("browser sign-in", context.lower())
        self.assertIn("/app", context)
        self.assertIn("hot-reloads", context)
        self.assertNotIn("setup --interactive", context)
        self.assertNotIn("paste-token", context)
        self.assertNotIn("enter a new API token", context)
        self.assertIn("cached authority blocked", output["systemMessage"])
        self.assertNotIn("AUTHORITATIVE VERIFIED LOCAL MIRROR", serialized)
        self.assertNotIn("CONTINUE WORK", serialized)
        self.assertNotIn("work may continue", serialized)
        self.assertNotIn("Build on v2", serialized)
        self.assertNotIn("cached room message", serialized)
        entry = self.watcher_state()["subscriptions"][self.key]
        self.assertTrue(entry["auth_required"])
        self.assertEqual(entry["offline_mode"], "auth_required")
        self.assertEqual(
            [row["kind"] for row in entry["pending"]],
            ["authentication_required"])

    def test_periodic_auth_rejection_drops_stale_outage_continuity_notice(self):
        adapter = FakeOfflineAdapter(self.verified_status(), self.snapshot())
        stale_notice = {
            "system_message": "stale outage continuity",
            "context": (
                "ATTACCA ACTIVE OFFLINE SESSION BRIEF — AUTHORITATIVE "
                "VERIFIED LOCAL MIRROR; CONTINUE WORK"),
        }
        with mock.patch.object(
                hook, "_plugin_and_config",
                return_value=(ROOT, self.config)), \
             mock.patch.object(
                 hook, "_ensure_background_watcher",
                 return_value={"ok": False, "error": "daemon unavailable"}), \
             mock.patch.object(hook, "_watcher_pending_notice",
                               return_value=stale_notice), \
             mock.patch.object(hook, "_settings_interval", return_value=60), \
             mock.patch.object(
                 hook, "_mcp_snapshot",
                 side_effect=hook.HostedAuthenticationRequired(
                     "AI scope forbidden", http_status=403)):
            output = hook._periodic_output(
                self.status, "UserPromptSubmit", offline_adapter=adapter)
        serialized = json.dumps(output)
        self.assertIn("ATTACCA AUTHENTICATION REQUIRED", serialized)
        self.assertIn("HTTP 403", serialized)
        self.assertNotIn("AUTHORITATIVE VERIFIED LOCAL MIRROR", serialized)
        self.assertNotIn("CONTINUE WORK", serialized)
        self.assertNotIn("stale outage continuity", serialized)

    def test_watcher_revoked_client_key_queues_auth_notice_not_offline_continuity(self):
        adapter = FakeOfflineAdapter(self.verified_status(), self.snapshot())
        with mock.patch.object(
                adapter, "synchronize",
                side_effect=client.SyncAuthenticationError(
                    "revoked client-install key", http_status=401)), \
             mock.patch.object(hook, "_settings_interval", return_value=60):
            result = hook._watcher_tick(
                self.key, now=0, force=True, offline_adapter=adapter,
                remote_adapter=object(), notifier=lambda *_: None)
        self.assertFalse(result["ok"])
        self.assertTrue(result["authentication_required"])
        self.assertFalse(result["offline"])
        entry = self.watcher_state()["subscriptions"][self.key]
        self.assertTrue(entry["auth_required"])
        self.assertEqual(entry["offline_mode"], "auth_required")
        self.assertEqual(len(entry["pending"]), 1)
        self.assertEqual(entry["pending"][0]["kind"],
                         "authentication_required")
        summary = entry["pending"][0]["summary"]
        self.assertIn("No installation credential was sent", summary)
        self.assertIn("Cached authority and offline queueing are blocked",
                      summary)
        self.assertNotIn("VERIFIED LOCAL MIRROR", summary)
        self.assertNotIn("continue work", summary.lower())
        self.assertNotIn("offline_connection_error", json.dumps(entry))
        self.assertNotIn("connection_error", json.dumps(entry))

    def test_watcher_role_change_blocks_cached_authority(self):
        adapter = FakeOfflineAdapter(self.verified_status(), self.snapshot())
        with mock.patch.object(
                adapter, "synchronize",
                side_effect=client.SyncAuthenticationError(
                    "host rejected the actor after its role changed",
                    http_status=403)), \
             mock.patch.object(hook, "_settings_interval", return_value=60):
            result = hook._watcher_tick(
                self.key, now=0, force=True, offline_adapter=adapter,
                remote_adapter=object(), notifier=lambda *_: None)
        self.assertTrue(result["authentication_required"])
        self.assertFalse(result["offline"])
        entry = self.watcher_state()["subscriptions"][self.key]
        self.assertEqual(entry["offline_mode"], "auth_required")
        self.assertEqual(entry["pending"][0]["kind"],
                         "authentication_required")
        self.assertIn("No installation credential was sent",
                      entry["pending"][0]["summary"])
        self.assertNotIn("continue work",
                         entry["pending"][0]["summary"].lower())

    def test_auth_notice_distinguishes_rejected_sent_credential(self):
        with mock.patch.object(
                hook, "_watcher_api_token", return_value="atkey_present"):
            hook._watcher_queue_auth_required(
                self.key, self.watcher_state()["subscriptions"][self.key],
                client.SyncAuthenticationError(
                    "revoked client-install key", http_status=401), 0)
        summary = self.watcher_state()["subscriptions"][self.key][
            "pending"][-1]["summary"]
        self.assertIn("server rejected the installation credential", summary)
        self.assertNotIn("No installation credential was sent", summary)

    def test_auth_latch_survives_outage_then_verified_sync_clears_it(self):
        adapter = FakeOfflineAdapter(self.verified_status(), self.snapshot())
        with mock.patch.object(
                adapter, "synchronize",
                side_effect=client.SyncAuthenticationError(
                    "client-install key revoked", http_status=401)), \
             mock.patch.object(hook, "_settings_interval", return_value=60):
            revoked = hook._watcher_tick(
                self.key, now=0, force=True, offline_adapter=adapter,
                remote_adapter=object(), notifier=lambda *_: None)
        self.assertTrue(revoked["authentication_required"])

        def pin_marker(state):
            state["subscriptions"][self.key][
                "last_offline_write_marker"] = hook._offline_write_marker(
                    adapter.status())

        hook._mutate_state(hook._watcher_state_path(), pin_marker)
        with mock.patch.object(hook, "_settings_interval", return_value=60):
            throttled = hook._watcher_tick(
                self.key, now=1, offline_adapter=adapter,
                remote_adapter=object(), notifier=lambda *_: None)
        self.assertFalse(throttled["due"])
        self.assertTrue(throttled["authentication_required"])
        self.assertFalse(throttled["offline"])

        adapter.result = {
            "status": "offline", "applied": [], "duplicates": [],
            "conflicts": [], "blocked": [], "error": "connection refused",
        }
        with mock.patch.object(hook, "_settings_interval", return_value=60):
            outage = hook._watcher_tick(
                self.key, now=60, force=True, offline_adapter=adapter,
                remote_adapter=object(), notifier=lambda *_: None)
        self.assertTrue(outage["authentication_required"])
        self.assertFalse(outage["offline"])
        latched = self.watcher_state()["subscriptions"][self.key]
        self.assertTrue(latched["auth_required"])
        self.assertEqual(latched["offline_mode"], "auth_required")
        self.assertEqual(
            {row["kind"] for row in latched["pending"]},
            {"authentication_required"})
        self.assertNotIn("continue work", json.dumps(latched).lower())

        adapter.result = {
            "status": "online", "applied": [], "duplicates": [],
            "conflicts": [], "blocked": [], "converged": [], "error": None,
        }
        with mock.patch.object(hook, "_settings_interval", return_value=60):
            recovered = hook._watcher_tick(
                self.key, now=120, force=True, offline_adapter=adapter,
                remote_adapter=object(),
                delta_loader=lambda after: delta(next_after=41),
                notifier=lambda *_: None)
        self.assertTrue(recovered["ok"])
        self.assertEqual(recovered["sync_status"], "online")
        repaired = self.watcher_state()["subscriptions"][self.key]
        self.assertNotIn("auth_required", repaired)
        self.assertNotIn("auth_required_at", repaired)
        self.assertFalse(any(
            row["kind"] == "authentication_required"
            for row in repaired["pending"]))

        adapter.result = {
            "status": "offline", "applied": [], "duplicates": [],
            "conflicts": [], "blocked": [], "error": "connection refused",
        }
        with mock.patch.object(hook, "_settings_interval", return_value=60):
            later_outage = hook._watcher_tick(
                self.key, now=180, force=True, offline_adapter=adapter,
                remote_adapter=object(), notifier=lambda *_: None)
        self.assertTrue(later_outage["offline"])
        self.assertFalse(later_outage.get("authentication_required", False))

    def test_authenticated_mutation_conflict_clears_prior_auth_latch(self):
        adapter = FakeOfflineAdapter(
            self.verified_status(), self.snapshot(), result={
                "status": "conflict", "applied": [], "duplicates": [],
                "conflicts": ["cm_domain_conflict"], "blocked": [],
                "error": "task version precondition failed",
            })
        adapter.conflict_rows = [{
            "client_mutation_id": "cm_domain_conflict",
            "remote": {"reason": "task version precondition failed"},
        }]
        entry = self.watcher_state()["subscriptions"][self.key]
        hook._watcher_queue_auth_required(
            self.key, entry,
            hook.HostedAuthenticationRequired(
                "old client-install key revoked", 401), 0)
        with mock.patch.object(hook, "_settings_interval", return_value=60):
            result = hook._watcher_tick(
                self.key, now=60, force=True, offline_adapter=adapter,
                remote_adapter=object(),
                delta_loader=lambda after: delta(next_after=41),
                notifier=lambda *_: None)
        self.assertEqual(result["sync_status"], "conflict")
        repaired = self.watcher_state()["subscriptions"][self.key]
        self.assertNotIn("auth_required", repaired)
        self.assertTrue(any(
            row["kind"] == "offline_sync_conflict"
            for row in repaired["pending"]))

    def test_prelatched_auth_blocks_session_fallback_on_later_outage(self):
        adapter = FakeOfflineAdapter(self.verified_status(), self.snapshot())
        entry = self.watcher_state()["subscriptions"][self.key]
        hook._watcher_queue_auth_required(
            self.key, entry,
            hook.HostedAuthenticationRequired(
                "client-install key revoked", http_status=401),
            0)
        with mock.patch.object(
                hook, "_plugin_and_config",
                return_value=(ROOT, self.config)), \
             mock.patch.object(
                 hook, "_ensure_background_watcher",
                 return_value={"ok": True, "already_running": True}), \
             mock.patch.object(hook, "_settings_interval", return_value=60), \
             mock.patch.object(hook, "_update_offer", return_value=None), \
             mock.patch.object(hook, "_mcp_snapshot",
                               side_effect=ConnectionRefusedError("offline")):
            output = hook._active_output(
                self.status, offline_adapter=adapter)
        serialized = json.dumps(output)
        self.assertIn("ATTACCA AUTHENTICATION REQUIRED", serialized)
        self.assertIn("browser sign-in", serialized.lower())
        self.assertIn("/app", serialized)
        self.assertNotIn("setup --interactive", serialized)
        self.assertNotIn("paste-token", serialized)
        self.assertNotIn("AUTHORITATIVE VERIFIED LOCAL MIRROR", serialized)
        self.assertNotIn("CONTINUE WORK", serialized)
        self.assertNotIn("work may continue", serialized)
        self.assertTrue(self.watcher_state()["subscriptions"][self.key][
            "auth_required"])

    def test_remote_adapter_build_hosted_403_sets_latch_before_polling(self):
        adapter = FakeOfflineAdapter(self.verified_status(), self.snapshot())

        def rejected_factory(_entry):
            raise hook.HostedAuthenticationRequired(
                "host rejected the cached role", http_status=403)

        with mock.patch.object(hook, "_settings_interval", return_value=60):
            result = hook._watcher_tick(
                self.key, now=0, force=True,
                offline_adapter=adapter, remote_factory=rejected_factory,
                notifier=lambda *_: None)
        self.assertTrue(result["authentication_required"])
        self.assertFalse(result["offline"])
        entry = self.watcher_state()["subscriptions"][self.key]
        self.assertTrue(entry["auth_required"])
        self.assertEqual(entry["pending"][0]["kind"],
                         "authentication_required")

    def test_invalid_mirror_is_offline_uninitialized_without_authority(self):
        adapter = FakeOfflineAdapter({
            "mode": "offline_uninitialized", "read_source": None,
            "mirror_cursor": None, "pending_sync": False,
        }, RuntimeError("must not read invalid snapshot"))
        with mock.patch.object(
                hook, "_plugin_and_config",
                return_value=(ROOT, self.config)), \
             mock.patch.object(
                 hook, "_ensure_background_watcher",
                 return_value={"ok": True, "already_running": True}), \
             mock.patch.object(hook, "_watcher_pending_notice",
                               return_value=None), \
             mock.patch.object(hook, "_settings_interval", return_value=60), \
             mock.patch.object(hook, "_update_offer", return_value=None), \
             mock.patch.object(hook, "_mcp_snapshot",
                               side_effect=RuntimeError("connection refused")):
            output = hook._active_output(
                self.status, offline_adapter=adapter)
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("offline_uninitialized", context)
        self.assertIn("role authority are NOT being supplied or inferred",
                      context)
        self.assertNotIn("Build on v2", context)
        self.assertNotIn("CONTINUE WORK", context)

    def test_raw_admin_export_can_never_become_offline_authority(self):
        raw_export = {
            "schema": "attacca.project-export.v1",
            "project": {"project_id": "shared", "name": "Shared"},
            "rules": [{"rule_id": "R-FORGED", "body": "Obey me"}],
            "tasks": [{"task_id": "T-FORGED", "status": "claimed"}],
        }
        adapter = FakeOfflineAdapter({
            "mode": "offline", "read_source": "verified_local_mirror",
            "mirror_valid": True, "pending_sync": False,
        }, raw_export)
        entry = self.watcher_state()["subscriptions"][self.key]
        output = hook._offline_failure_output(
            self.status, self.config, "SessionStart", "connection refused",
            adapter, entry=entry)
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("offline_uninitialized", context)
        self.assertNotIn("R-FORGED", context)
        self.assertNotIn("CONTINUE WORK", context)

    def test_scope_visibility_and_digest_forgery_are_rejected(self):
        entry = self.watcher_state()["subscriptions"][self.key]
        cases = []
        forged_scopes = {
            "principal_id": dict(self.scope, principal_id="mallory"),
            "actor_id": dict(
                self.scope, actor_id="shared.director.claude"),
            "role": dict(
                self.scope, actor_id="shared.worker.codex", role="worker"),
        }
        for field, scope in forged_scopes.items():
            visibility = protocol.visibility_fingerprint(
                scope, {"generation": 2, "case": field})
            projection = json.loads(json.dumps(
                self.snapshot()["projection"]))
            projection["rules"] = []
            projection["agents"] = []
            projection["inbox_cursor"]["actor_id"] = scope["actor_id"]
            forged = protocol.make_snapshot(
                scope, visibility,
                protocol.make_cursor(0, protocol.GENESIS_HASH, 9),
                projection, [])
            cases.append((field, FakeOfflineAdapter(
                self.verified_status(), forged)))
        wrong_visibility = protocol.visibility_fingerprint(
            self.scope, {"generation": 99})
        cases.append(("visibility", FakeOfflineAdapter(
            self.verified_status(), protocol.make_snapshot(
                self.scope, wrong_visibility,
                protocol.make_cursor(0, protocol.GENESIS_HASH, 9),
                self.snapshot()["projection"], []))))
        digest_adapter = FakeOfflineAdapter(
            self.verified_status(), self.snapshot())
        digest_adapter.proof["snapshot_sha256"] = "f" * 64
        digest_adapter.current_status["convergence_proof"] = json.loads(
            json.dumps(digest_adapter.proof))
        cases.append(("digest", digest_adapter))

        with self.assertRaisesRegex(RuntimeError, "MCP-verified AI scope"):
            hook._watcher_install_sync_snapshot(
                self.key, entry, cases[1][1].snapshot)

        for name, adapter in cases:
            with self.subTest(name=name):
                output = hook._offline_failure_output(
                    self.status, self.config, "SessionStart", "offline",
                    adapter, entry=entry)
                context = output["hookSpecificOutput"]["additionalContext"]
                self.assertIn("offline_uninitialized", context)
                self.assertNotIn("AUTHORITATIVE VERIFIED LOCAL MIRROR", context)

    def test_receipt_is_not_announced_until_online_canonical_convergence(self):
        adapter = FakeOfflineAdapter(
            self.verified_status(awaiting=["cm_waiting_0001"]),
            self.snapshot(), result={
                "status": "pending", "applied": ["cm_waiting_0001"],
                "duplicates": [], "conflicts": [], "blocked": [],
                "converged": [], "error": None,
            })
        with mock.patch.object(hook, "_settings_interval", return_value=60):
            result = hook._watcher_tick(
                self.key, now=0, force=True, offline_adapter=adapter,
                remote_adapter=object(),
                delta_loader=lambda after: delta(next_after=0),
                notifier=lambda *_: None)
        self.assertEqual(result["sync_status"], "pending")
        self.assertFalse(result["sync_queued"])
        entry = self.watcher_state()["subscriptions"][self.key]
        self.assertEqual(entry["convergence_awaiting_ids"],
                         ["cm_waiting_0001"])
        self.assertEqual(entry["offline_pending_count"], 1)
        self.assertEqual(entry["offline_convergence_awaiting_count"], 1)
        self.assertFalse(any(row["kind"] == "offline_sync_accepted"
                             for row in entry["pending"]))

    def test_invalid_proof_downgrades_all_cached_status_claims(self):
        adapter = FakeOfflineAdapter(
            self.verified_status(
                mode="online", pending_sync=True, pending_count=99,
                conflict_count=88), self.snapshot())
        adapter.proof["snapshot_sha256"] = "e" * 64
        adapter.current_status["convergence_proof"] = json.loads(
            json.dumps(adapter.proof))
        entry = self.watcher_state()["subscriptions"][self.key]
        queued = hook._watcher_queue_error(
            self.key, entry, "server failed", 0,
            offline_status=adapter.status(), offline_adapter=adapter)
        self.assertTrue(queued)
        current = self.watcher_state()["subscriptions"][self.key]
        self.assertEqual(current["offline_mode"], "offline_uninitialized")
        self.assertFalse(current["offline_pending_sync"])
        self.assertEqual(current["offline_pending_count"], 0)
        self.assertEqual(current["offline_conflict_count"], 0)
        self.assertEqual(current["offline_convergence_awaiting_count"], 0)
        self.assertEqual(current["pending"][-1]["kind"], "connection_error")

    def test_interrupted_final_pull_notifies_once_after_restart_convergence(self):
        waiting = FakeOfflineAdapter(
            self.verified_status(awaiting=["cm_delayed_0001"]),
            self.snapshot(), result={
                "status": "offline", "applied": ["cm_delayed_0001"],
                "duplicates": [], "conflicts": [], "blocked": [],
                "converged": [], "error": "final pull unavailable",
            })
        with mock.patch.object(hook, "_settings_interval", return_value=60):
            first = hook._watcher_tick(
                self.key, now=0, force=True, offline_adapter=waiting,
                remote_adapter=object(), notifier=lambda *_: None)
        self.assertTrue(first["offline"])
        self.assertEqual(
            self.watcher_state()["subscriptions"][self.key][
                "convergence_awaiting_ids"], ["cm_delayed_0001"])

        # Reconstructing the adapter models a detached daemon/process restart.
        converged = FakeOfflineAdapter(
            self.verified_status(
                mode="online", pending_sync=False, pending_count=0,
                mirror_stale=False, observed=["cm_delayed_0001"], awaiting=[]),
            self.snapshot(), result={
                "status": "online", "applied": [], "duplicates": [],
                "conflicts": [], "blocked": [], "converged": [],
                "error": None,
            })
        with mock.patch.object(hook, "_settings_interval", return_value=60):
            second = hook._watcher_tick(
                self.key, now=60, force=True, offline_adapter=converged,
                remote_adapter=object(),
                delta_loader=lambda after: delta(next_after=0),
                notifier=lambda *_: None)
            third = hook._watcher_tick(
                self.key, now=120, force=True, offline_adapter=converged,
                remote_adapter=object(),
                delta_loader=lambda after: delta(next_after=0),
                notifier=lambda *_: None)
        self.assertTrue(second["sync_queued"])
        self.assertFalse(third["sync_queued"])
        rows = [row for row in
                self.watcher_state()["subscriptions"][self.key]["pending"]
                if row["kind"] == "offline_sync_accepted"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["accepted"], ["cm_delayed_0001"])
        self.assertIn("confirmed after reconnect", rows[0]["summary"])

    def test_default_adapter_is_inactive_until_authenticated_scope_exists(self):
        def remove_scope(state):
            entry = state["subscriptions"][self.key]
            entry.pop("sync_scope", None)
            entry.pop("sync_visibility_fingerprint", None)

        hook._mutate_state(hook._watcher_state_path(), remove_scope)
        entry = self.watcher_state()["subscriptions"][self.key]
        self.assertIsNone(hook._watcher_build_offline_adapter(entry))
        self.assertIsNone(hook._watcher_build_remote_adapter(entry))

    def test_client_key_snapshot_bootstraps_real_global_mirror_without_leaking_secret(self):
        def remove_scope(state):
            entry = state["subscriptions"][self.key]
            entry.pop("sync_scope", None)
            entry.pop("sync_visibility_fingerprint", None)

        hook._mutate_state(hook._watcher_state_path(), remove_scope)
        _, _, packaged_client = hook._watcher_sync_modules()
        captured = []
        expected = self.snapshot()

        class Transport:
            def request(inner, method, url, *, headers, body, timeout,
                        max_response_bytes):
                captured.append({
                    "method": method, "url": url,
                    "headers": dict(headers), "body": body,
                })
                return packaged_client.JsonHttpResponse(
                    200, {"content-type": "application/json"},
                    protocol.canonical_json_bytes(expected))

        with mock.patch.object(hook, "_watcher_api_token",
                               return_value="atkey_snapshot_secret"):
            result = hook._watcher_activate_identity_sync(
                self.status, self.config, transport=Transport(),
                runtime="codex")
        self.assertTrue(result["active"])
        self.assertEqual(captured[0]["method"], "GET")
        snapshot_url = urlsplit(captured[0]["url"])
        self.assertEqual(snapshot_url.scheme, "http")
        self.assertEqual(snapshot_url.netloc, "attacca.invalid:4173")
        self.assertEqual(snapshot_url.path,
                         "/v1/projects/shared/sync/snapshot")
        self.assertEqual(
            parse_qs(snapshot_url.query),
            {key: [value] for key, value in
             protocol.projection_capabilities_query().items()})
        self.assertEqual(captured[0]["headers"]["Authorization"],
                         "Bearer atkey_snapshot_secret")
        self.assertEqual(captured[0]["headers"]["X-Attacca-Project"],
                         "shared")
        self.assertEqual(captured[0]["headers"]["X-Attacca-Actor"],
                         self.scope["actor_id"])
        self.assertEqual(captured[0]["headers"][
            "X-Attacca-Client-Instance"],
            self.watcher_state()["subscriptions"][self.key][
                "client_instance"])
        self.assertEqual(captured[0]["headers"]["X-Attacca-Device-ID"],
                         "office-device")
        state = self.watcher_state()
        entry = state["subscriptions"][self.key]
        self.assertEqual(entry["sync_scope"], self.scope)
        self.assertEqual(entry["sync_visibility_fingerprint"], self.visibility)
        self.assertEqual(entry["offline_pending_count"], 0)
        self.assertEqual(entry["offline_conflict_count"], 0)
        self.assertEqual(entry["offline_convergence_awaiting_count"], 0)
        self.assertNotIn("atkey_snapshot_secret", json.dumps(state))
        local = hook._watcher_build_offline_adapter(entry)
        self.assertEqual(local.local_snapshot(), expected)
        with mock.patch.object(
                hook, "_watcher_api_token",
                side_effect=AssertionError("token must stay request-time")):
            remote = hook._watcher_build_remote_adapter(entry)
        self.assertEqual(remote.scope, self.scope)
        files = [path for path in (self.root / "watcher").rglob("*")
                 if path.is_file()]
        self.assertTrue(files)
        self.assertNotIn("atkey_snapshot_secret", "".join(
            path.read_text(errors="ignore") for path in files))

    def test_no_token_snapshot_requires_fresh_active_compatibility_status(self):
        def remove_scope(state):
            entry = state["subscriptions"][self.key]
            entry.pop("sync_scope", None)
            entry.pop("sync_visibility_fingerprint", None)

        hook._mutate_state(hook._watcher_state_path(), remove_scope)
        _, _, packaged_client = hook._watcher_sync_modules()
        expected = self.snapshot()
        captured = []
        client_instance = self.watcher_state()["subscriptions"][self.key][
            "client_instance"]

        class Transport:
            def request(inner, method, url, *, headers, body, timeout,
                        max_response_bytes):
                captured.append((url, dict(headers)))
                value = ({
                    "authentication_mode": "auto",
                    "authentication_required": False,
                    "effective_authentication": "optional",
                    "compatibility_active": True,
                } if url.endswith("/v1/auth/status") else expected)
                return packaged_client.JsonHttpResponse(
                    200, {"content-type": "application/json"},
                    protocol.canonical_json_bytes(value))

        with mock.patch.object(hook, "_watcher_api_token", return_value=None):
            result = hook._watcher_activate_identity_sync(
                self.status, self.config, transport=Transport(),
                runtime="codex")
        self.assertTrue(result["active"], result)
        self.assertEqual(len(captured), 2)
        self.assertEqual(urlsplit(captured[0][0]).path, "/v1/auth/status")
        snapshot_url = urlsplit(captured[1][0])
        self.assertEqual(snapshot_url.scheme, "http")
        self.assertEqual(snapshot_url.netloc, "attacca.invalid:4173")
        self.assertEqual(snapshot_url.path,
                         "/v1/projects/shared/sync/snapshot")
        self.assertEqual(
            parse_qs(snapshot_url.query),
            {key: [value] for key, value in
             protocol.projection_capabilities_query().items()})
        for _, headers in captured:
            self.assertNotIn("Authorization", headers)
            self.assertEqual(headers["X-Attacca-Project"], "shared")
            self.assertEqual(headers["X-Attacca-Actor"],
                             self.scope["actor_id"])
            self.assertEqual(headers["X-Attacca-Device-ID"],
                             "office-device")
            self.assertEqual(headers["X-Attacca-Client-Instance"],
                             client_instance)

    def test_authenticated_snapshot_repair_clears_revocation_latch(self):
        entry = self.watcher_state()["subscriptions"][self.key]
        hook._watcher_queue_auth_required(
            self.key, entry,
            hook.HostedAuthenticationRequired(
                "old client-install key revoked", 401), 0)
        _, _, packaged_client = hook._watcher_sync_modules()
        expected = self.snapshot()

        class Transport:
            def request(inner, method, url, *, headers, body, timeout,
                        max_response_bytes):
                return packaged_client.JsonHttpResponse(
                    200, {"content-type": "application/json"},
                    protocol.canonical_json_bytes(expected))

        with mock.patch.object(hook, "_watcher_api_token",
                               return_value="atkey_replacement"):
            result = hook._watcher_activate_identity_sync(
                self.status, self.config, transport=Transport(),
                runtime="codex")
        self.assertTrue(result["active"])
        repaired = self.watcher_state()["subscriptions"][self.key]
        self.assertNotIn("auth_required", repaired)
        self.assertNotIn("auth_required_at", repaired)
        self.assertFalse(any(row.get("kind") in {
            "authentication_required", "offline_connection_error",
            "connection_error"} for row in repaired.get("pending") or []))

    def test_auxiliary_cache_write_failure_never_escapes_live_mcp_activation(self):
        with mock.patch.object(
                hook, "_watcher_record_verified_identity",
                side_effect=OSError("read-only watcher state")):
            result = hook._watcher_activate_after_mcp(
                self.status, self.config, {"status": {}})
        self.assertFalse(result["ok"])
        self.assertFalse(result["active"])
        self.assertIn("read-only watcher state", result["error"])

    def test_factory_receives_fsync_after_write_wake_callback(self):
        captured = {}

        def factory(entry, wake):
            captured["entry"] = entry
            captured["wake"] = wake
            return object()

        entry = self.watcher_state()["subscriptions"][self.key]
        result = hook._watcher_build_offline_adapter(entry, factory=factory)
        self.assertIsNotNone(result)
        with mock.patch.object(hook, "_watcher_process_matches",
                               return_value=False):
            wake_result = captured["wake"]()
        self.assertTrue(wake_result["ok"])
        updated = self.watcher_state()["subscriptions"][self.key]
        self.assertEqual(updated["next_poll_at_epoch"], 0)
        self.assertEqual(updated["wake_reason"], "local_write")
        self.assertEqual(captured["entry"]["offline_directory"], str(
            hook._watcher_offline_directory(self.key)))


if __name__ == "__main__":
    unittest.main()
