"""Deterministic tests for the autonomous Attacca background watcher."""

import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "session_start.py"
SPEC = importlib.util.spec_from_file_location("attacca_watcher_test", HOOK)
watch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(watch)
CORE_SPEC = importlib.util.spec_from_file_location(
    "attacca_watcher_core_test", ROOT / "attacca.py")
core = importlib.util.module_from_spec(CORE_SPEC)
CORE_SPEC.loader.exec_module(core)


def event(seq, event_type, payload=None, task_id=None,
          actor="shared.worker.claude", created_at=None):
    value = {
        "event_id": "ev-%d" % seq,
        "seq": seq,
        "event_type": event_type,
        "actor_id": actor,
        "operational_actor_id": actor,
        "task_id": task_id,
        "context_version": seq,
        "payload": payload or {},
    }
    if created_at:
        value["created_at"] = created_at
    return value


def delta(events=None, next_after=None, may_have_more=False):
    rows = list(events or [])
    if next_after is None:
        next_after = rows[-1]["seq"] if rows else 0
    return {"events": rows, "next_after": next_after,
            "may_have_more": may_have_more}


class FakeResponse:
    def __init__(self, value):
        self.body = json.dumps(value).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self.body


class AutonomousWatcherTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.env = mock.patch.dict(os.environ, {
            "HOME": str(self.root / "home"),
            "ATTACCA_WATCHER_DIR": str(self.root / "watcher"),
            "ATTACCA_RUNTIME": "codex",
            "ATTACCA_DEVICE_ID": "office-device",
        }, clear=False)
        self.env.start()
        self.status = {
            "status": "linked", "project_id": "shared",
            "root": str(self.checkout),
            "link_path": str(self.checkout / ".attacca" / "project.json"),
        }
        self.config = {"url": "http://attacca.test:4173",
                       "actor": "codex", "owner": "jack"}

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def register(self, now=0):
        return watch._register_watcher_subscription(
            self.status, ROOT, self.config, runtime="codex", now=now)

    def state(self):
        return json.loads(watch._watcher_state_path().read_text())

    def test_default_is_one_minute_and_subscription_is_machine_global(self):
        self.assertEqual(watch.DEFAULT_UPDATE_INTERVAL_SECONDS, 60)
        key = self.register()
        entry = self.state()["subscriptions"][key]
        self.assertEqual(entry["device_id"], "office-device")
        self.assertEqual(entry["server_url"], "http://attacca.test:4173")
        self.assertNotIn("token", json.dumps(entry).lower())
        self.assertEqual(watch._watcher_state_path(),
                         self.root / "watcher" / "watcher-state.json")

    def test_authenticated_client_key_honors_custom_interval_and_off(self):
        """Protected Settings uses the shared install-scoped client key."""
        db = self.root / "authenticated-settings.db"
        actor_id = "shared.director.codex"
        conn = core.connect(db)
        try:
            core.project_init(
                conn, "setup", "human", path=self.checkout,
                project_id="shared", name="Shared")
            core.set_current_owner("alice")
            try:
                core.agent_register(
                    conn, "shared", actor_id, "agent", agent_id=actor_id,
                    role="director", runtime="codex",
                    registration_username="alice")
            finally:
                core.set_current_owner(None)
            core.auth_create_user(
                conn, "alice", "correct-horse", is_admin=True,
                bootstrap=True)
            user = conn.execute(
                "SELECT * FROM auth_users WHERE username='alice'").fetchone()
            principal = core._auth_principal(
                conn, user, "session", actor_type="human")
            conn.execute(
                "INSERT OR IGNORE INTO auth_project_memberships"
                " (user_id,project_id,granted_at,granted_by)"
                " VALUES (?,?,?,?)",
                (user["user_id"], "shared", core.now_iso(), "alice"))
            terminal = watch._terminal_flow_module()
            client_instance = terminal.load_client_instance_id(
                runtime="codex")
            credential = core.auth_client_key_create(
                conn, principal, "Watcher test client", client_instance,
                memberships=["shared"], device_id="office-device")
            core.server_settings_store(conn, {
                "auth.activation_requested": True,
                "auth.activated": True,
            })
            token_kinds = [row["token_kind"] for row in conn.execute(
                "SELECT token_kind FROM auth_tokens ORDER BY token_id")]
            self.assertEqual(token_kinds, ["client"])
        finally:
            conn.close()

        server = core.AttaccaServer(("127.0.0.1", 0), db, auth=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = "http://127.0.0.1:%d" % server.server_address[1]
        config = {"url": url, "actor": "codex", "owner": "alice"}
        entry = {
            "server_url": url, "project_id": "shared",
            "runtime": "codex", "actor": "codex",
            "canonical_actor_id": actor_id,
            "device_id": "office-device", "plugin_root": str(ROOT),
        }
        credential_path = Path.home() / ".attacca" / "credentials.json"
        credential_path.parent.mkdir(parents=True, exist_ok=True)
        poison_legacy = "legacy-actor-token-must-not-be-used"
        credential_path.write_text(json.dumps({
            "version": 2,
            "servers": {url: {"agent_tokens": {
                "shared": {actor_id: {
                    "token": poison_legacy, "runtime": "codex",
                }},
            }}},
        }))
        credential_path.chmod(0o600)
        terminal.save_terminal_credential(
            url, credential, device_id="office-device",
            credentials_path=credential_path,
            client_instance_id=client_instance, runtime="codex")

        try:
            # Recovery preserves old records for rollback but must select the
            # install-scoped client principal for every protected call.
            self.assertEqual(watch._watcher_api_token(entry),
                             credential["token"])
            self.assertNotEqual(watch._watcher_api_token(entry), poison_legacy)
            server.update_interval_seconds = 300
            self.assertEqual(
                watch._settings_interval(config, entry=entry), 300)

            key = watch._register_watcher_subscription(
                self.status, ROOT, config, runtime="codex", now=0)

            def verify_identity(state):
                current = state["subscriptions"][key]
                current["canonical_actor_id"] = actor_id
                current["actor_role"] = "director"

            watch._mutate_state(watch._watcher_state_path(), verify_identity)
            custom = watch._watcher_tick(
                key, now=0, force=True,
                delta_loader=lambda after: delta(next_after=after),
                notifier=lambda *_: None)
            self.assertTrue(custom["ok"])
            self.assertEqual(
                self.state()["subscriptions"][key]["interval_seconds"], 300)
            self.assertEqual(
                self.state()["subscriptions"][key]["next_poll_at_epoch"],
                300)

            server.update_interval_seconds = 0
            disabled = watch._watcher_tick(
                key, now=300, force=True,
                delta_loader=lambda after: delta(next_after=after),
                notifier=lambda *_: None)
            self.assertTrue(disabled["disabled"])
            self.assertEqual(
                self.state()["subscriptions"][key]["interval_seconds"], 0)

            wrong_scope = dict(
                entry, canonical_actor_id="other.director.codex")
            self.assertEqual(
                watch._settings_interval(config, entry=wrong_scope),
                watch.DEFAULT_UPDATE_INTERVAL_SECONDS)
            self.assertNotIn(credential["token"], json.dumps(self.state()))
            self.assertNotIn(poison_legacy, json.dumps(self.state()))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_symlinked_watcher_root_is_not_resolved_past_storage_guard(self):
        target = self.root / "watcher-target"
        target.mkdir()
        link = self.root / "watcher-link"
        link.symlink_to(target, target_is_directory=True)
        with mock.patch.dict(
                os.environ, {"ATTACCA_WATCHER_DIR": str(link)}, clear=False):
            self.assertEqual(
                watch._watcher_state_path(),
                link.absolute() / "watcher-state.json")
            _, offline, _ = watch._watcher_sync_modules()
            scope = {
                "server_id": "server-one",
                "project_id": "shared",
                "principal_id": "jack",
                "actor_id": "shared.director.codex",
                "actor_type": "agent",
                "role": "director",
            }
            with self.assertRaisesRegex(
                    offline.OfflineSyncError, "symlink traversal"):
                offline.OfflineProjectSync(
                    watch._watcher_offline_directory("unused"),
                    "http://attacca.test:4173", scope,
                    "watcher-client", "office-device")

    def test_runtime_modules_reload_when_same_root_contents_change(self):
        """Stable code wins over poisoned metadata and bypasses stale pyc."""
        with tempfile.TemporaryDirectory() as tmp:
            runtime_root = Path(tmp) / "runtime"
            runtime_root.mkdir()
            for relative in (
                    "sync_protocol.py", "offline_sync.py", "sync_client.py",
                    "terminal_flow.py"):
                shutil.copy2(ROOT / relative, runtime_root / relative)
            protocol_path = runtime_root / "sync_protocol.py"
            poisoned = protocol_path.read_text().replace(
                '"cloud_context",', '"cloud_contexx",')
            self.assertNotEqual(poisoned, protocol_path.read_text())
            protocol_path.write_text(poisoned)
            fixed_mtime_ns = 1_700_000_000_000_000_000
            os.utime(protocol_path, ns=(fixed_mtime_ns, fixed_mtime_ns))

            with mock.patch.object(
                    watch, "_stable_plugin_root",
                    return_value=runtime_root):
                old_protocol = watch._watcher_sync_modules()[0]
            scope = {
                "server_id": "server-one",
                "project_id": "shared",
                "principal_id": "jack",
                "actor_id": "shared.director.codex",
                "actor_type": "agent",
                "role": "director",
            }
            with self.assertRaisesRegex(ValueError, "unknown field"):
                old_protocol.validate_identity_projection(
                    {"cloud_context": {}}, scope, partial=True)

            current_protocol = watch._watcher_sync_modules()[0]
            visibility = current_protocol.visibility_fingerprint(
                scope, {"role": "director"})
            projection = {
                "project": {"project_id": "shared"},
                "handoffs": [], "rules": [], "tasks": [],
                "decisions": [], "room_messages": [], "agents": [],
                "bridges": [], "inbox_cursor": None,
                "cloud_context": {"content": "current managed context"},
            }
            snapshot = current_protocol.make_snapshot(
                scope, visibility,
                current_protocol.make_cursor(
                    0, current_protocol.GENESIS_HASH, 0),
                projection, [])
            stale_entry = {
                "project_id": "shared",
                "canonical_actor_id": "shared.director.codex",
                "actor_role": "director",
                "sync_scope": scope,
                "sync_visibility_fingerprint": visibility,
                "plugin_root": str(runtime_root),
            }
            # Subscription plugin_root is migration metadata, never an
            # executable source. A complete old cache cannot reject the new
            # stable projection schema.
            self.assertEqual(
                watch._offline_snapshot_projection(
                    snapshot, stale_entry)["cloud_context"]["content"],
                "current managed context")

            # Replace the poisoned source with equal-length current content and
            # restore its exact mtime. Exact-byte execution must still avoid a
            # timestamp-valid stale .pyc image.
            protocol_path.write_bytes((ROOT / "sync_protocol.py").read_bytes())
            os.utime(protocol_path, ns=(fixed_mtime_ns, fixed_mtime_ns))
            with mock.patch.object(
                    watch, "_stable_plugin_root",
                    return_value=runtime_root):
                new_protocol = watch._watcher_sync_modules()[0]
            self.assertIsNot(old_protocol, new_protocol)
            self.assertEqual(
                new_protocol.validate_identity_projection(
                    {"cloud_context": {}}, scope, partial=True),
                {"cloud_context": {}})

            # Repeated emergency in-place repairs remain strictly bounded in a
            # daemon that cannot restart immediately. Namespace eviction is
            # safe because any live adapter already owns direct module/class
            # references rather than depending on sys.modules lookups.
            protocol_base = (ROOT / "sync_protocol.py").read_bytes()
            terminal_path = runtime_root / "terminal_flow.py"
            terminal_base = (ROOT / "terminal_flow.py").read_bytes()
            generations = max(
                watch._RUNTIME_SOURCE_CACHE_LIMIT,
                watch._RUNTIME_MODULE_CACHE_LIMIT) + 5
            for generation in range(generations):
                protocol_path.write_bytes(
                    protocol_base +
                    ("\n# bounded sync generation %04d\n" % generation
                     ).encode("ascii"))
                terminal_path.write_bytes(
                    terminal_base +
                    ("\n# bounded auth generation %04d\n" % generation
                     ).encode("ascii"))
                os.utime(protocol_path,
                         ns=(fixed_mtime_ns, fixed_mtime_ns))
                os.utime(terminal_path,
                         ns=(fixed_mtime_ns, fixed_mtime_ns))
                with mock.patch.object(
                        watch, "_stable_plugin_root",
                        return_value=runtime_root):
                    watch._watcher_sync_modules()
                    watch._terminal_flow_module()

            self.assertLessEqual(
                len(watch._RUNTIME_SOURCE_CACHE),
                watch._RUNTIME_SOURCE_CACHE_LIMIT)
            self.assertLessEqual(
                len(watch._SYNC_MODULE_CACHE),
                watch._RUNTIME_MODULE_CACHE_LIMIT)
            self.assertLessEqual(
                len(watch._TERMINAL_MODULE_CACHE),
                watch._RUNTIME_MODULE_CACHE_LIMIT)
            sync_names = [
                name for name in sys.modules
                if name.startswith("_attacca_hook_sync_")]
            terminal_names = [
                name for name in sys.modules
                if name.startswith("_attacca_hook_terminal_")]
            self.assertLessEqual(
                len(sync_names), watch._RUNTIME_MODULE_CACHE_LIMIT * 5)
            self.assertLessEqual(
                len(terminal_names), watch._RUNTIME_MODULE_CACHE_LIMIT)

    def test_upgrade_rebind_makes_backed_off_subscription_due_now(self):
        link = self.checkout / ".attacca" / "project.json"
        link.parent.mkdir()
        link.write_text(json.dumps({
            "schema_version": 1, "project_id": "shared"}))
        key = self.register(now=0)

        def back_off(state):
            entry = state["subscriptions"][key]
            entry["next_poll_at_epoch"] = 9999999999
            entry["last_error"] = "old schema rejected cloud_context"

        watch._mutate_state(watch._watcher_state_path(), back_off)
        with mock.patch.object(
                watch, "_ensure_registered_watcher",
                return_value={"ok": True, "started": True}):
            result = watch._restart_background_watcher_after_upgrade(ROOT)
        self.assertTrue(result["upgrade_restart"])
        entry = self.state()["subscriptions"][key]
        self.assertEqual(entry["next_poll_at_epoch"], 0)
        self.assertEqual(entry["wake_reason"], "executable_root_rebound")
        self.assertEqual(entry["last_error"],
                         "old schema rejected cloud_context")
        with mock.patch.object(watch, "_settings_interval", return_value=60):
            tick = watch._watcher_tick(
                key, now=1, force=False,
                offline_factory=lambda *_: None,
                delta_loader=lambda after: delta(next_after=after),
                notifier=lambda *_: None)
        self.assertTrue(tick["ok"])
        self.assertTrue(tick["due"])
        self.assertIsNone(
            self.state()["subscriptions"][key]["last_error"])

    def test_registration_rebind_also_bypasses_existing_backoff(self):
        key = self.register(now=0)

        def stale_cache(state):
            entry = state["subscriptions"][key]
            entry["plugin_root"] = "/old/codex/cache"
            entry["next_poll_at_epoch"] = 9999999999
            entry["last_error"] = "old schema"

        watch._mutate_state(watch._watcher_state_path(), stale_cache)
        renewed = watch._register_watcher_subscription(
            self.status, ROOT, self.config, runtime="codex", now=123)
        self.assertEqual(renewed, key)
        entry = self.state()["subscriptions"][key]
        self.assertEqual(entry["plugin_root"], str(ROOT.resolve()))
        self.assertEqual(entry["next_poll_at_epoch"], 0)
        self.assertEqual(entry["wake_reason"], "executable_root_rebound")
        self.assertEqual(entry["wake_requested_at_epoch"], 123)
        self.assertEqual(entry["last_error"], "old schema")

    def test_idle_tick_queues_changed_state_once_and_hook_drains_it(self):
        key = self.register()
        baseline = delta([event(
            1, "project.created", {"name": "Shared"})])
        changed = delta([
            event(2, "task.created", {"title": "Review release"},
                  task_id="T-7"),
            event(3, "rule.created", {
                "rule_id": "R-1", "version": 1, "title": "Build on v2"}),
        ])
        with mock.patch.object(watch, "_settings_interval", return_value=60):
            first = watch._watcher_tick(
                key, now=0, force=True, delta_loader=lambda after: baseline,
                notifier=lambda *_: None)
            second = watch._watcher_tick(
                key, now=60, force=True, delta_loader=lambda after: changed,
                notifier=lambda *_: None)
            duplicate = watch._watcher_tick(
                key, now=120, force=True,
                delta_loader=lambda after: delta(next_after=3),
                notifier=lambda *_: None)
        self.assertFalse(first["queued"])
        self.assertTrue(first["cursor_initialized"])
        self.assertTrue(second["queued"])
        self.assertFalse(duplicate["queued"])
        self.assertEqual(len(self.state()["subscriptions"][key]["pending"]), 2)
        notice = watch._watcher_pending_notice(self.status, self.config)
        self.assertIn("Build on v2", notice["context"])
        self.assertIn("client was idle", notice["context"])
        self.assertEqual(self.state()["subscriptions"][key]["pending"], [])
        self.assertIsNone(watch._watcher_pending_notice(
            self.status, self.config))

    def test_unchanged_delta_never_materializes_a_full_snapshot(self):
        key = self.register()
        watch._watcher_tick(
            key, now=0, force=True,
            delta_loader=lambda after: delta(next_after=10),
            notifier=lambda *_: None)
        cursors = []

        def unchanged(after):
            cursors.append(after)
            return delta(next_after=after)

        with mock.patch.object(watch, "_settings_interval", return_value=60), \
                mock.patch.object(
                    watch, "_mcp_snapshot",
                    side_effect=AssertionError("full snapshot is forbidden")):
            result = watch._watcher_tick(
                key, now=60, force=True, delta_loader=unchanged,
                notifier=lambda *_: None)
        self.assertFalse(result["queued"])
        self.assertEqual(result["event_count"], 0)
        self.assertEqual(cursors, [10])
        entry = self.state()["subscriptions"][key]
        self.assertEqual(entry["event_cursor"], 10)
        self.assertEqual(entry["next_poll_at_epoch"], 120)
        self.assertNotIn("snapshot", entry)

    def test_registration_race_event_is_not_lost_in_initial_baseline(self):
        key = self.register(now=100)
        with mock.patch.object(watch, "_settings_interval", return_value=60):
            result = watch._watcher_tick(
                key, now=101, force=True,
                delta_loader=lambda after: delta([
                    event(1, "room.message", {"body": "already in brief"},
                          created_at="1970-01-01T00:01:00+00:00"),
                    event(2, "room.message", {"body": "raced startup"},
                          created_at="1970-01-01T00:02:00+00:00"),
                ], next_after=2), notifier=lambda *_: None)
        self.assertTrue(result["cursor_initialized"])
        self.assertTrue(result["queued"])
        self.assertEqual(result["relevant_count"], 1)
        entry = self.state()["subscriptions"][key]
        self.assertEqual(entry["pending"], [])
        self.assertEqual(len(entry["attention"]), 1)
        self.assertIn("raced startup", entry["attention"][0]["body"])
        self.assertNotIn("already in brief", entry["attention"][0]["body"])

    def test_all_relevant_event_families_are_durable_and_concise(self):
        key = self.register()
        with mock.patch.object(watch, "_settings_interval", return_value=60):
            watch._watcher_tick(
                key, now=0, force=True,
                delta_loader=lambda after: delta(next_after=0),
                notifier=lambda *_: None)
            result = watch._watcher_tick(
                key, now=60, force=True,
                delta_loader=lambda after: delta([
                    event(1, "room.message", {
                        "msg_type": "directive", "body": "Ship the fix",
                        "origin_project": "master", "authority":
                        "master-directive"}),
                    event(2, "task.status_changed", {
                        "title": "Repair cache", "to": "review"},
                        task_id="T-27"),
                    event(3, "task.plan.suggested", {
                        "plan_version": 2, "status": "changes_requested",
                        "section_id": "tests", "note": "Add outage coverage"},
                        task_id="T-35"),
                    event(4, "rule.updated", {
                        "rule_id": "R-4", "version": 3,
                        "title": "History first"}),
                    event(5, "decision.resolved", {
                        "decision_id": "D-8", "resolution": "accepted",
                        "title": "Use cursors"}),
                    event(6, "handoff.updated", {
                        "fields": ["active_work", "next_actions"]}),
                    event(7, "bridge.created", {
                        "with": "upstream", "relation": "master"}),
                    event(8, "cloud_context.updated", {"version": 4}),
                    event(9, "agent.registered", {"agent_id": "noise"}),
                ], next_after=9), notifier=lambda *_: None)
        self.assertTrue(result["queued"])
        self.assertEqual(result["event_count"], 9)
        self.assertEqual(result["relevant_count"], 8)
        entry = self.state()["subscriptions"][key]
        self.assertEqual(entry["event_cursor"], 9)
        self.assertEqual(len(entry["attention"]), 1)
        self.assertEqual(entry["attention"][0]["body"], "Ship the fix")
        self.assertEqual(len(entry["pending"]), 7)
        self.assertTrue(all(row["kind"] == "project_entity_delta"
                            for row in entry["pending"]))
        self.assertNotIn(
            "agent.registered",
            {event_type for row in entry["pending"]
             for event_type in row["event_types"]})
        summary = "\n".join(row["summary"] for row in entry["pending"])
        for expected in ("Task T-27", "Task plan T-35", "Project Rule R-4",
                         "Decision D-8", "Handoff", "Bridge upstream",
                         "Cloud Context v4"):
            self.assertIn(expected, summary)
        self.assertNotIn("Ship the fix", summary)
        self.assertNotIn("agent.registered", summary)

    def test_raw_event_feed_paginates_with_cursor_identity_and_token(self):
        requests = []
        responses = iter([
            delta([event(1, "room.message", {"body": "one"}),
                   event(2, "task.created", {"title": "two"}, "T-2")],
                  next_after=2, may_have_more=True),
            delta(next_after=2),
        ])

        def opener(request, timeout):
            requests.append((request, timeout))
            return FakeResponse(next(responses))

        entry = {
            "server_url": "https://attacca.test",
            "project_id": "shared/space", "runtime": "codex",
            "actor": "shared.director.codex", "owner": "jack",
            "device_id": "office-device",
            "client_instance": "stored-kimi-install-9",
        }
        with mock.patch.object(watch, "_watcher_api_token",
                               return_value="test-token"), \
             mock.patch.object(watch, "_client_instance_id",
                               side_effect=AssertionError(
                                   "must use subscription client_instance")):
            result = watch._watcher_event_delta(entry, 0, opener=opener)
        self.assertEqual(result["next_after"], 2)
        self.assertFalse(result["may_have_more"])
        self.assertEqual(len(result["events"]), 2)
        self.assertEqual(len(requests), 2)
        self.assertIn("/shared%2Fspace/events?after=0", requests[0][0].full_url)
        self.assertIn("events?after=2", requests[1][0].full_url)
        self.assertEqual(requests[0][0].get_header("Authorization"),
                         "Bearer test-token")
        self.assertEqual(requests[0][0].get_header("X-attacca-actor"),
                         "shared.director.codex")
        self.assertEqual(requests[0][0].get_header(
            "X-attacca-client-instance"), "stored-kimi-install-9")
        self.assertEqual(requests[0][1],
                         watch.AUXILIARY_HTTP_TIMEOUT_SECONDS)

    def test_daemon_loop_ticks_without_any_lifecycle_event(self):
        self.register()
        ticks = []
        waits = []
        clock = iter([0, 0, 0, 300, 300, 300, 600, 600, 600, 600])

        def fake_clock():
            try:
                return next(clock)
            except StopIteration:
                return 600

        with mock.patch.object(
                watch, "_watcher_tick",
                side_effect=lambda key, now=None: ticks.append((key, now)) or
                {"ok": True}):
            result = watch._watcher_daemon_loop(
                ROOT, "test-nonce", wait=waits.append,
                clock=fake_clock, max_ticks=3)
        self.assertTrue(result["ok"])
        self.assertEqual(len(ticks), 3)
        self.assertEqual(waits, [watch.WATCHER_WAKE_SECONDS] * 2)

    def test_one_machine_daemon_scans_every_registered_subscription(self):
        first = self.register()
        other_checkout = self.root / "other-checkout"
        other_checkout.mkdir()
        other_status = dict(
            self.status, project_id="other", root=str(other_checkout),
            link_path=str(other_checkout / ".attacca" / "project.json"))
        second = watch._register_watcher_subscription(
            other_status, ROOT,
            {"url": self.config["url"], "actor": "claude", "owner": "jack"},
            runtime="claude", now=0)
        ticks = []
        with mock.patch.object(
                watch, "_watcher_tick",
                side_effect=lambda key, now=None: ticks.append(key) or
                {"ok": True}):
            result = watch._watcher_daemon_loop(
                ROOT, "all-subscriptions", wait=lambda _: None,
                clock=lambda: 0, max_ticks=1)
        self.assertTrue(result["ok"])
        self.assertEqual(set(ticks), {first, second})
        self.assertEqual(len(ticks), 2)

    def test_daemon_passes_sync_factories_to_every_tick(self):
        key = self.register()
        local_factory = object()
        remote_factory = object()
        calls = []

        def tick(subscription_key, now=None, **options):
            calls.append((subscription_key, now, options))
            return {"ok": True}

        with mock.patch.object(watch, "_watcher_tick", side_effect=tick):
            result = watch._watcher_daemon_loop(
                ROOT, "factory-daemon", wait=lambda _: None,
                clock=lambda: 17, max_ticks=1,
                offline_factory=local_factory,
                remote_factory=remote_factory)
        self.assertTrue(result["ok"])
        self.assertEqual(calls, [(key, 17, {
            "offline_factory": local_factory,
            "remote_factory": remote_factory,
        })])

    def test_two_checkouts_share_machine_global_mirror_root(self):
        first = self.register()
        second_checkout = self.root / "same-project-second-checkout"
        second_checkout.mkdir()
        second_status = dict(
            self.status, root=str(second_checkout),
            link_path=str(second_checkout / ".attacca" / "project.json"))
        second = watch._register_watcher_subscription(
            second_status, ROOT, self.config, runtime="codex", now=0)
        self.assertNotEqual(first, second)
        state = self.state()["subscriptions"]
        self.assertEqual(state[first]["offline_directory"],
                         state[second]["offline_directory"])
        self.assertEqual(Path(state[first]["offline_directory"]),
                         self.root / "watcher" / "offline")

    def test_old_daemon_that_refuses_exit_is_preserved_without_respawn(self):
        key = self.register()

        def install_daemon(state):
            state["daemon"] = {
                "nonce": "old-nonce", "pid": 4242, "running": True,
                "plugin_root": str(ROOT), "plugin_version": "0.0.0",
            }

        watch._mutate_state(watch._watcher_state_path(), install_daemon)
        with mock.patch.object(
                watch, "_watcher_process_matches",
                side_effect=lambda pid, nonce: nonce == "old-nonce"), \
             mock.patch.object(
                 watch, "_signal_watcher_process", return_value=True) as signal, \
             mock.patch.object(watch.time, "time", side_effect=[0, 0, 4]), \
             mock.patch.object(
                 watch.subprocess, "Popen",
                 side_effect=AssertionError("must not spawn")):
            result = watch._ensure_background_watcher(
                self.status, ROOT, self.config, runtime="codex")
        self.assertFalse(result["ok"])
        self.assertTrue(result["restart_pending"])
        self.assertEqual(result["subscription_key"], key)
        signal.assert_called_once_with(
            4242, "old-nonce", watch.signal.SIGTERM,
            launch_fingerprint=None,
            hook_path=ROOT / "hooks" / "session_start.py")
        state = self.state()
        self.assertEqual(state["daemon"]["nonce"], "old-nonce")
        self.assertNotIn("daemon_launch", state)

    def test_same_version_old_dependency_fingerprint_forces_daemon_restart(self):
        key = self.register()
        current = watch._watcher_launch_identity_for_root(ROOT)
        stale_identity = dict(
            current, launch_fingerprint="sha256:" + "0" * 64)

        def install_daemon(state):
            state["daemon"] = {
                "nonce": "same-version-old-code", "pid": 4243,
                "running": True, "plugin_root": str(ROOT),
                "plugin_version": current["launch_version"],
                **stale_identity,
            }

        watch._mutate_state(watch._watcher_state_path(), install_daemon)
        child = mock.Mock(pid=7373)
        with mock.patch.object(
                watch, "_watcher_process_matches",
                side_effect=[True, False, False]), \
             mock.patch.object(
                 watch, "_signal_watcher_process",
                 return_value=True) as signal_process, \
             mock.patch.object(
                 watch, "_watcher_lock_available", return_value=True), \
             mock.patch.object(
                 watch.subprocess, "Popen", return_value=child) as spawn:
            result = watch._ensure_registered_watcher(
                key, self.checkout, ROOT)
        self.assertTrue(result["started"])
        self.assertEqual(result["pid"], 7373)
        signal_process.assert_called_once_with(
            4243, "same-version-old-code", watch.signal.SIGTERM,
            launch_fingerprint=stale_identity["launch_fingerprint"],
            hook_path=ROOT / "hooks" / "session_start.py")
        command = spawn.call_args.args[0]
        self.assertEqual(Path(command[1]),
                         ROOT / "hooks" / "session_start.py")
        launch = self.state()["daemon_launch"]
        self.assertEqual(launch["pid"], 7373)
        self.assertEqual(launch["launch_version"],
                         current["launch_version"])
        self.assertEqual(launch["launch_fingerprint"],
                         current["launch_fingerprint"])

    def test_held_lifetime_lock_never_overwrites_stale_daemon_metadata(self):
        key = self.register()

        def install_daemon(state):
            state["daemon"] = {
                "nonce": "stale-nonce", "pid": 5151, "running": True,
                "plugin_root": str(ROOT), "plugin_version": "0.0.0",
            }

        watch._mutate_state(watch._watcher_state_path(), install_daemon)
        with mock.patch.object(
                watch, "_watcher_process_matches", return_value=False), \
             mock.patch.object(watch, "_watcher_lock_available",
                               return_value=False), \
             mock.patch.object(
                 watch.subprocess, "Popen",
                 side_effect=AssertionError("must not spawn")):
            result = watch._ensure_background_watcher(
                self.status, ROOT, self.config, runtime="codex")
        self.assertFalse(result["ok"])
        self.assertTrue(result["restart_pending"])
        self.assertEqual(result["subscription_key"], key)
        state = self.state()
        self.assertEqual(state["daemon"]["nonce"], "stale-nonce")
        self.assertNotIn("daemon_launch", state)

    def test_concurrent_ensure_rechecks_winner_under_state_lock(self):
        key = self.register()
        identity = dict(watch._CAPTURED_WATCHER_LAUNCH_IDENTITY)

        def winner_arrives():
            def install(state):
                state["daemon"] = {
                    "nonce": "winner", "pid": 6161, "running": True,
                    "plugin_root": str(ROOT),
                    "plugin_version": identity["launch_version"],
                    **identity,
                }
            watch._mutate_state(watch._watcher_state_path(), install)
            return True

        with mock.patch.object(
                watch, "_watcher_process_matches",
                side_effect=lambda pid, nonce: nonce == "winner"), \
             mock.patch.object(
                 watch, "_watcher_process_launch_matches",
                 side_effect=lambda pid, nonce, **_: nonce == "winner"), \
             mock.patch.object(watch, "_watcher_lock_available",
                               side_effect=winner_arrives), \
             mock.patch.object(
                 watch.subprocess, "Popen",
                 side_effect=AssertionError("must not spawn")):
            result = watch._ensure_background_watcher(
                self.status, ROOT, self.config, runtime="codex")
        self.assertTrue(result["already_running"])
        self.assertEqual(result["pid"], 6161)
        self.assertEqual(result["subscription_key"], key)
        state = self.state()
        self.assertEqual(state["daemon"]["nonce"], "winner")
        self.assertNotIn("daemon_launch", state)

    def test_child_promotes_only_its_reserved_launch_after_flock(self):
        self.register()
        pid = os.getpid()
        identity = dict(watch._CAPTURED_WATCHER_LAUNCH_IDENTITY)

        def reserve(state):
            state["daemon_launch"] = {
                "nonce": "ours", "pid": pid, "running": False,
                "plugin_root": str(ROOT),
                "plugin_version": identity["launch_version"],
                **identity,
            }

        watch._mutate_state(watch._watcher_state_path(), reserve)
        watch._watcher_mark_daemon(
            "ours", ROOT, launch_identity=identity,
            running=True, heartbeat_at_epoch=1)
        promoted = self.state()
        self.assertNotIn("daemon_launch", promoted)
        self.assertEqual(promoted["daemon"]["nonce"], "ours")
        self.assertEqual(promoted["daemon"]["pid"], pid)
        watch._watcher_mark_daemon(
            "competitor", ROOT, launch_identity=identity,
            running=True, heartbeat_at_epoch=2)
        after = self.state()
        self.assertEqual(after["daemon"]["nonce"], "ours")
        self.assertEqual(after["daemon"]["heartbeat_at_epoch"], 1)

    def test_child_cannot_promote_reserved_launch_with_changed_fingerprint(self):
        """A same-nonce hot-upgrade cannot replace its reserved code identity."""
        self.register()
        identity = dict(watch._CAPTURED_WATCHER_LAUNCH_IDENTITY)
        tampered = dict(identity, launch_fingerprint="sha256:" + "0" * 64)

        def reserve(state):
            state["daemon_launch"] = {
                "nonce": "same-nonce", "pid": os.getpid(),
                "running": False, "plugin_root": str(ROOT),
                "plugin_version": identity["launch_version"],
                **identity,
            }

        watch._mutate_state(watch._watcher_state_path(), reserve)
        watch._watcher_mark_daemon(
            "same-nonce", ROOT, launch_identity=tampered, running=True)
        state = self.state()
        self.assertNotIn("daemon", state)
        self.assertEqual(state["daemon_launch"]["launch_fingerprint"],
                         identity["launch_fingerprint"])

    def test_outage_is_deduplicated_and_does_not_advance_cursor(self):
        key = self.register()
        failing = lambda after: (_ for _ in ()).throw(
            RuntimeError("server offline"))
        with mock.patch.object(watch, "_settings_interval", return_value=60):
            watch._watcher_tick(key, now=0, force=True,
                                delta_loader=failing)
            watch._watcher_tick(key, now=60, force=True,
                                delta_loader=failing)
        entry = self.state()["subscriptions"][key]
        self.assertNotIn("event_cursor", entry)
        self.assertEqual(len(entry["pending"]), 1)
        self.assertIn("retry automatically", entry["pending"][0]["summary"])

    def test_legacy_snapshot_event_count_becomes_delta_cursor(self):
        key = self.register()

        def add_legacy_snapshot(state):
            state["subscriptions"][key]["snapshot"] = {
                "counts": {"events": 41}}

        watch._mutate_state(watch._watcher_state_path(), add_legacy_snapshot)
        self.register(now=30)
        entry = self.state()["subscriptions"][key]
        self.assertEqual(entry["event_cursor"], 41)
        self.assertTrue(entry["event_cursor_initialized"])

    # --- private watcher state: concurrent atomic replace (T-96) -------------
    #
    # A lifecycle hook in another session (or a second daemon) replaces
    # watcher-state.json with ``os.replace``. The post-open identity check in
    # ``_open_private_watcher_file`` can observe that rename and used to raise
    # ``WatcherStateSecurityError`` straight out of ``_read_state``,
    # killing the daemon. A replace whose new target is still one of our
    # own private files is benign and must be retried; anything else
    # must still fail closed.

    def private_replacement(self, path, payload, suffix="race"):
        """Write one 0600 sibling that a race can rename over ``path``."""
        replacement = Path(str(path) + "." + suffix)
        descriptor = os.open(
            str(replacement), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")
        os.chmod(str(replacement), 0o600)
        return replacement

    def replace_during_open(self, make_replacement, limit=1):
        """Patch fchmod so a replace lands between open() and the id check."""
        races = []
        real_fchmod = os.fchmod

        def racing_fchmod(descriptor, mode):
            real_fchmod(descriptor, mode)
            if len(races) < limit and stat.S_ISREG(
                    os.fstat(descriptor).st_mode):
                races.append(len(races) + 1)
                make_replacement(len(races))

        return races, mock.patch.object(
            watch.os, "fchmod", side_effect=racing_fchmod)

    def test_benign_state_replace_race_is_retried_and_reads_new_content(self):
        path = watch._watcher_state_path()
        watch._write_state(path, {"generation": "old"})
        replacement = self.private_replacement(path, {"generation": "new"})
        races, patch = self.replace_during_open(
            lambda _: os.replace(str(replacement), str(path)))
        with patch, mock.patch.object(watch.time, "sleep") as sleep:
            state = watch._read_state(path)
        self.assertEqual(races, [1])
        self.assertEqual(state, {"generation": "new"})
        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(
            stat.S_IMODE(os.lstat(str(path)).st_mode), 0o600)

    def test_state_replace_race_survives_a_real_concurrent_writer(self):
        path = watch._watcher_state_path()
        watch._write_state(path, {"generation": "old"})
        races, patch = self.replace_during_open(
            lambda _: watch._write_state(path, {"generation": "written"}))
        with patch:
            state = watch._read_state(path)
        self.assertEqual(races, [1])
        self.assertEqual(state, {"generation": "written"})

    def test_replace_race_with_unsafe_target_still_fails_closed(self):
        victim = self.root / "victim"
        victim.write_text("file victim\n")
        os.chmod(str(victim), 0o644)
        path = watch._watcher_state_path()

        def group_readable(_):
            swapped = Path(str(path) + ".loose")
            descriptor = os.open(
                str(swapped), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            os.chmod(str(swapped), 0o644)
            os.replace(str(swapped), str(path))

        def symlink_swap(_):
            swapped = Path(str(path) + ".link")
            os.symlink(str(victim), str(swapped))
            os.replace(str(swapped), str(path))

        def directory_swap(_):
            swapped = Path(str(path) + ".dir")
            swapped.mkdir()
            os.rename(str(swapped), str(path) + ".kept")
            os.unlink(str(path))
            os.rename(str(path) + ".kept", str(path))

        for name, swap in (("group-readable", group_readable),
                           ("symlink", symlink_swap),
                           ("directory", directory_swap)):
            with self.subTest(replacement=name):
                for stale in self.root.glob("watcher/watcher-state.json*"):
                    if stale.is_dir():
                        shutil.rmtree(str(stale))
                    else:
                        stale.unlink()
                watch._write_state(path, {"generation": "old"})
                races, patch = self.replace_during_open(swap)
                with patch, mock.patch.object(watch.time, "sleep") as sleep:
                    with self.assertRaises(
                            watch.WatcherStateSecurityError) as caught:
                        watch._read_state(path)
                self.assertEqual(races, [1])
                self.assertNotIsInstance(
                    caught.exception, watch.WatcherStateBusyError)
                self.assertIn("changed while it was opened",
                              str(caught.exception))
                sleep.assert_not_called()
                self.assertEqual(victim.read_text(), "file victim\n")
                self.assertEqual(
                    stat.S_IMODE(os.lstat(str(victim)).st_mode), 0o644)

    def test_endless_replace_race_exhausts_retries_and_stays_closed(self):
        path = watch._watcher_state_path()
        watch._write_state(path, {"generation": "old"})
        replacements = [self.private_replacement(
            path, {"generation": index}, suffix="race-%d" % index)
            for index in range(watch.WATCHER_REPLACE_RETRY_ATTEMPTS)]
        races, patch = self.replace_during_open(
            lambda attempt: os.replace(
                str(replacements[attempt - 1]), str(path)),
            limit=len(replacements))
        with patch, mock.patch.object(watch.time, "sleep") as sleep:
            with self.assertRaises(watch.WatcherStateBusyError) as caught:
                watch._read_state(path)
        self.assertEqual(len(races), watch.WATCHER_REPLACE_RETRY_ATTEMPTS)
        self.assertEqual(sleep.call_count,
                         watch.WATCHER_REPLACE_RETRY_ATTEMPTS - 1)
        self.assertIsInstance(
            caught.exception, watch.WatcherStateSecurityError)
        self.assertIn("atomically replaced", str(caught.exception))

    def test_unlocked_readers_never_see_a_security_error_under_writers(self):
        """Real threads: an unlocked read races a locked atomic writer."""
        path = watch._watcher_state_path()
        watch._write_state(path, {"generation": 0})
        stop = threading.Event()
        start = threading.Barrier(3)
        seen = []
        unsafe = []

        def writer():
            start.wait(timeout=5)
            generation = 0
            while not stop.is_set() and generation < 200:
                generation += 1
                watch._mutate_state(
                    path, lambda state: state.update(
                        {"generation": generation}))

        def reader():
            start.wait(timeout=5)
            while not stop.is_set():
                try:
                    seen.append(watch._read_state(path).get("generation"))
                except watch.WatcherStateBusyError:
                    seen.append(None)  # tolerated: retries were exhausted
                except BaseException as error:
                    unsafe.append(error)
                    return

        threads = [threading.Thread(target=writer),
                   threading.Thread(target=reader)]
        for thread in threads:
            thread.start()
        start.wait(timeout=5)
        threads[0].join(timeout=30)
        stop.set()
        threads[1].join(timeout=30)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(
            [repr(error) for error in unsafe], [],
            "a benign concurrent replace must never fail closed")
        self.assertTrue(seen)
        self.assertTrue(any(value is not None for value in seen))

    def test_daemon_loop_survives_a_busy_state_read_and_keeps_ticking(self):
        key = self.register()
        ticks = []
        waits = []

        def tick(subscription_key, now=None, **options):
            ticks.append(subscription_key)
            if len(ticks) == 1:
                raise watch.WatcherStateBusyError(
                    "watcher path was atomically replaced by a concurrent "
                    "writer 5 times while it was opened: %s"
                    % watch._watcher_state_path())
            return {"ok": True}

        with mock.patch.object(watch, "_watcher_tick", side_effect=tick), \
                mock.patch.object(watch, "_watcher_daemon_log") as logged:
            result = watch._watcher_daemon_loop(
                ROOT, "busy-daemon", wait=waits.append, clock=lambda: 0,
                max_ticks=3)
        self.assertTrue(result["ok"])
        self.assertEqual(result["ticks"], 3)
        self.assertEqual(ticks, [key, key, key])
        self.assertEqual(waits, [watch.WATCHER_WAKE_SECONDS] * 2)
        self.assertEqual(logged.call_count, 1)
        self.assertIn("atomically replaced", logged.call_args[0][0])
        daemon = self.state()["daemon"]
        self.assertEqual(daemon["nonce"], "busy-daemon")
        self.assertIn("heartbeat_at_epoch", daemon)
        self.assertEqual(daemon["subscription_count"], 1)

    def test_daemon_loop_still_exits_on_a_real_state_security_failure(self):
        self.register()
        ticks = []

        def tick(subscription_key, now=None, **options):
            ticks.append(subscription_key)
            raise watch.WatcherStateSecurityError(
                "watcher path changed while it was opened: %s"
                % watch._watcher_state_path())

        with mock.patch.object(watch, "_watcher_tick", side_effect=tick), \
                mock.patch.object(watch, "_watcher_daemon_log") as logged:
            with self.assertRaises(watch.WatcherStateSecurityError):
                watch._watcher_daemon_loop(
                    ROOT, "unsafe-daemon", wait=lambda _: None,
                    clock=lambda: 0, max_ticks=3)
        self.assertEqual(len(ticks), 1)
        logged.assert_not_called()


if __name__ == "__main__":
    unittest.main()
