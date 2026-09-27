"""Idle watcher identity recovery against an isolated authenticated server."""

import hashlib
import importlib.util
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hook = load("watcher_identity_recovery_hook", ROOT / "hooks/session_start.py")
core = load("watcher_identity_recovery_core", ROOT / "attacca.py")


class WatcherIdentityRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        patch = mock.patch.dict(os.environ, {
            "HOME": str(self.home), "ATTACCA_RUNTIME": "codex",
            "ATTACCA_DEVICE_ID": "identity-test-device",
            "ATTACCA_WATCHER_DIR": str(self.root / "watcher"),
        })
        patch.start()
        self.addCleanup(patch.stop)
        self.actor = "shared.director.codex.shannon"
        self.db = self.root / "test.db"
        connection = core.connect(self.db)
        try:
            core.project_init(connection, "setup", "human", path=self.checkout,
                              project_id="shared", name="Shared")
            core.set_current_owner("alice")
            try:
                core.agent_register(
                    connection, "shared", self.actor, "agent",
                    agent_id=self.actor, role="director", runtime="codex",
                    registration_username="alice")
            finally:
                core.set_current_owner(None)
            core.auth_create_user(connection, "alice", "isolated-test-password",
                                  is_admin=True, bootstrap=True)
            user = connection.execute(
                "SELECT * FROM auth_users WHERE username='alice'").fetchone()
            self.principal = core._auth_principal(
                connection, user, "session", actor_type="human")
            connection.execute(
                "INSERT OR IGNORE INTO auth_project_memberships"
                " (user_id,project_id,granted_at,granted_by) VALUES (?,?,?,?)",
                (user["user_id"], "shared", core.now_iso(), "alice"))
            self.terminal = hook._terminal_flow_module()
            self.instance = self.terminal.load_client_instance_id(runtime="codex")
            self.credential = core.auth_client_key_create(
                connection, self.principal, "Isolated client", self.instance,
                memberships=["shared"], device_id="identity-test-device")
            core.server_settings_store(connection, {
                "auth.activation_requested": True, "auth.activated": True})
        finally:
            connection.close()
        self.server = core.AttaccaServer(("127.0.0.1", 0), self.db, auth=True)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = "http://127.0.0.1:%s" % self.server.server_address[1]
        self.config = {"url": self.url, "actor": "codex", "owner": "alice"}
        self.status = {"project_id": "shared", "status": "linked",
                       "root": str(self.checkout),
                       "link_path": str(self.checkout / ".attacca/project.json")}
        self.save_credential(self.credential)
        core.machine_actor_binding_set(
            self.url, "shared", "codex", self.actor,
            client_instance=self.instance, home=self.home)
        self.key = hook._register_watcher_subscription(
            self.status, ROOT, self.config, runtime="codex", now=0)

    def save_credential(self, credential):
        self.terminal.save_terminal_credential(
            self.url, credential, device_id="identity-test-device",
            client_instance_id=self.instance, runtime="codex")

    def entry(self):
        return hook._read_state(hook._watcher_state_path())["subscriptions"][self.key]

    def update(self, **fields):
        def mutate(state):
            state["subscriptions"][self.key].update(fields)
        hook._mutate_state(hook._watcher_state_path(), mutate)

    def tick(self, now=100):
        return hook._watcher_tick(self.key, now=now, notifier=lambda *_: None)

    def test_exact_binding_is_used_and_other_scopes_never_supply_identity(self):
        entry = self.entry()
        self.assertNotIn("canonical_actor_id", entry)
        self.assertEqual(hook._watcher_request_actor(entry), self.actor)
        for field, replacement in (("server_url", self.url + "/other"),
                                   ("project_id", "other"),
                                   ("runtime", "claude"),
                                   ("client_instance", "other-install")):
            other = dict(entry, **{field: replacement})
            self.assertIsNone(hook._watcher_bound_actor(other), field)
        headers = hook._watcher_request_headers(entry)
        self.assertEqual(headers["X-Attacca-Actor"], self.actor)
        self.assertTrue(headers["Authorization"].startswith("Bearer "))

    def test_idle_tick_bootstraps_named_identity_and_reclassifies_staged_mail(self):
        self.update(attention=[{
            "event_id": "ev_old", "message_key": "event:ev_old", "seq": 1,
            "actor": "shared.director.claude", "body": "Please act",
            "mentions": [self.actor], "directed_to_you": False,
            "group_context": True, "priority_attention": False,
            "delivered_at": "earlier", "acknowledged": True,
        }], rendered={"ev_old": {"body_sha256": "old"}})
        with mock.patch.object(hook, "_mcp_snapshot",
                               side_effect=AssertionError("No AI turn needed")):
            result = self.tick()
        self.assertTrue(result["ok"], result)
        entry = self.entry()
        self.assertEqual(entry["canonical_actor_id"], self.actor)
        self.assertEqual(entry["actor_role"], "director")
        self.assertEqual(entry["sync_scope"]["actor_id"], self.actor)
        row = entry["attention"][0]
        self.assertTrue(row["directed_to_you"])
        self.assertFalse(row["group_context"])
        self.assertNotIn("delivered_at", row)
        self.assertNotIn("ev_old", entry.get("rendered", {}))
        with mock.patch.object(hook, "_watcher_fetch_sync_snapshot",
                               side_effect=AssertionError("Unchanged idle tick")):
            quiet = self.tick(now=161)
        self.assertTrue(quiet["ok"], quiet)

    def test_new_credential_recovers_latched_watcher_before_old_retry_deadline(self):
        self.assertTrue(self.tick()["ok"])
        self.update(auth_required=True, offline_mode="auth_required",
                    next_poll_at_epoch=99999,
                    last_error="HTTP Error 401: Unauthorized",
                    last_inbox_error="HTTP Error 401: Unauthorized")
        connection = core.connect(self.db)
        try:
            replacement = core.auth_client_key_create(
                connection, self.principal, "Replacement", self.instance,
                memberships=["shared"], device_id="identity-test-device")
        finally:
            connection.close()
        self.save_credential(replacement)
        result = self.tick(now=101)
        self.assertTrue(result["ok"], result)
        entry = self.entry()
        self.assertNotIn("auth_required", entry)
        self.assertNotIn("last_inbox_error", entry)
        self.assertEqual(entry["verified_credential_fingerprint"],
                         hashlib.sha256(replacement["token"].encode()).hexdigest())

    def test_visibility_pin_error_recovers_before_adapter_status_can_trap_daemon(self):
        self.assertTrue(self.tick()["ok"])
        protocol, _, _ = hook._watcher_sync_modules()
        entry = self.entry()
        stale = protocol.visibility_fingerprint(entry["sync_scope"], {"old": True})
        self.update(sync_visibility_fingerprint=stale, next_poll_at_epoch=0)
        with mock.patch.object(hook, "_watcher_fetch_sync_snapshot",
                               wraps=hook._watcher_fetch_sync_snapshot) as fetch:
            result = self.tick(now=200)
        self.assertTrue(result["ok"], result)
        self.assertEqual(fetch.call_count, 1)
        self.assertNotEqual(self.entry()["sync_visibility_fingerprint"], stale)

    def test_latched_historical_401_does_not_prevent_stale_visibility_recovery(self):
        self.assertTrue(self.tick()["ok"])
        protocol, _, _ = hook._watcher_sync_modules()
        previous = self.entry()
        stale = protocol.visibility_fingerprint(previous["sync_scope"], {"old": True})
        self.update(sync_visibility_fingerprint=stale, next_poll_at_epoch=0,
                    auth_required=True, offline_mode="auth_required",
                    last_error="hosted MCP rejected credential (HTTP 401)")
        with mock.patch.object(hook, "_watcher_fetch_sync_snapshot",
                               wraps=hook._watcher_fetch_sync_snapshot) as fetch:
            result = self.tick(now=200)
        self.assertTrue(result["ok"], result)
        self.assertTrue(fetch.called)
        self.assertNotIn("auth_required", self.entry())
        self.assertNotEqual(self.entry()["sync_visibility_fingerprint"], stale)

    def replace_persisted_mirror_visibility(self):
        """Model another client replacing disk while our subscription stays current."""
        protocol, _, _ = hook._watcher_sync_modules()
        adapter = hook._watcher_build_offline_adapter(self.entry())
        snapshot = adapter.local_snapshot()
        changed = protocol.make_snapshot(
            snapshot["scope"], protocol.visibility_fingerprint(
                snapshot["scope"], {"other_client_generation": True}),
            snapshot["cursor"], snapshot["projection"], snapshot["records"])
        adapter.install_snapshot(changed, reset=True,
                                 reset_reason="isolated other-client replacement")
        return adapter

    def test_current_subscription_recovers_actual_persisted_visibility_mismatch(self):
        self.assertTrue(self.tick()["ok"])
        previous = self.entry()
        changed = self.replace_persisted_mirror_visibility()
        _, offline, _ = hook._watcher_sync_modules()
        with self.assertRaisesRegex(offline.OfflineVisibilityChangedError,
                                   "stored mirror visibility differs"):
            hook._watcher_build_offline_adapter(self.entry()).status()
        self.assertNotEqual(changed.visibility_fingerprint,
                            previous["sync_visibility_fingerprint"])
        self.update(next_poll_at_epoch=0)
        result = self.tick(now=200)
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.entry()["sync_visibility_fingerprint"],
                         previous["sync_visibility_fingerprint"])
        recovered = hook._watcher_build_offline_adapter(self.entry())
        self.assertEqual(recovered.local_snapshot()["visibility_fingerprint"],
                         previous["sync_visibility_fingerprint"])

    def test_actual_persisted_visibility_recovery_preserves_pending_outbox(self):
        self.assertTrue(self.tick()["ok"])
        original = hook._watcher_build_offline_adapter(self.entry())
        original.queue_mutation("room.send", {"body": "Isolated original actor write"},
                                client_mutation_id="cm_original_visibility_write")
        journal = {path.name: path.read_bytes() for path in original.journal_directory.iterdir()}
        self.replace_persisted_mirror_visibility()
        self.update(auth_required=True, identity_refresh_required=True,
                    last_error="historical hosted HTTP 401")
        current, recovered = hook._watcher_recover_identity(self.key, self.entry())
        self.assertNotIn("auth_required", current)
        self.assertNotIn("identity_refresh_required", current)
        self.assertEqual(recovered.scope["actor_id"], self.actor)
        self.assertEqual(recovered.pending_mutations(), original.pending_mutations())
        self.assertEqual(len(recovered.pending_mutations()), 1)
        self.assertEqual(journal, {path.name: path.read_bytes()
                                  for path in original.journal_directory.iterdir()})

    def test_visibility_reset_does_not_overwrite_corrupt_persisted_mirror(self):
        self.assertTrue(self.tick()["ok"])
        changed = self.replace_persisted_mirror_visibility()
        wrapper = json.loads(changed.mirror_path.read_text())
        wrapper["snapshot_sha256"] = "0" * 64
        changed.mirror_path.write_text(json.dumps(wrapper))
        before = changed.mirror_path.read_bytes()
        self.update(auth_required=True, identity_refresh_required=True)
        with self.assertRaisesRegex(Exception, "stored snapshot digest mismatch"):
            hook._watcher_recover_identity(self.key, self.entry())
        self.assertEqual(changed.mirror_path.read_bytes(), before)
        self.assertTrue(self.entry()["auth_required"])

    def test_priority_sync_does_not_initialize_unread_event_history(self):
        self.update(event_cursor=0, event_cursor_initialized=False,
                    cursor_registered_at_epoch=100)
        with mock.patch.object(hook, "_watcher_event_delta") as events:
            result = hook._watcher_tick(self.key, now=100, force=True,
                                       notifier=lambda *_: None)
        self.assertTrue(result["ok"], result)
        events.assert_not_called()
        self.assertFalse(result["cursor_initialized"])
        self.assertFalse(self.entry()["event_cursor_initialized"])
        rows = [{"event_id": "epoch-%s" % seq, "seq": seq,
                 "event_type": "room.message", "actor_id": "shared.director.claude",
                 "created_at": timestamp, "payload": {"body": "row-%s" % seq}}
                for seq, timestamp in ((1, "1970-01-01T00:00:50+00:00"),
                                       (2, "1970-01-01T00:02:30+00:00"))]
        with mock.patch.object(hook, "_watcher_event_delta", return_value={
                "events": rows, "next_after": 2, "may_have_more": False}):
            result = self.tick(now=200)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["cursor_initialized"])
        self.assertTrue(self.entry()["event_cursor_initialized"])
        self.assertEqual([row["seq"] for row in self.entry()["attention"]], [2])

    def test_empty_hosted_inbox_prevents_raw_history_replay_but_preserves_staged_mail(self):
        self.assertTrue(self.tick()["ok"])
        hook._watcher_stage_attention(self.key, [{
            "event_id": "staged-1020", "seq": 1020, "actor": "shared.director.claude",
            "body": "GENUINE PREVIOUSLY STAGED MAIL"}])
        self.update(event_cursor=0, event_cursor_initialized=True,
                    attention_ack_cursor=0, next_poll_at_epoch=0)
        events = [{"event_id": "historical-%s" % seq, "seq": seq,
                   "event_type": "room.message", "actor_id": "shared.director.claude",
                   "payload": {"body": "OLD HISTORY"}} for seq in range(8, 138)]
        events.append({"event_id": "new-1035", "seq": 1035,
                       "event_type": "room.message", "actor_id": "shared.director.claude",
                       "payload": {"body": "GENUINE NEW MESSAGE"}})
        with mock.patch.object(hook, "_watcher_event_delta", return_value={
                "events": events, "next_after": 1035, "may_have_more": False}), \
                mock.patch.object(hook, "_watcher_inbox_page", return_value={
                    "messages": [], "read_cursor": 1034, "may_have_more": False,
                    "pending_dispositions": [], "pending_disposition_total": 0}):
            result = self.tick(now=200)
        self.assertTrue(result["ok"], result)
        entry = self.entry()
        self.assertEqual(entry["attention_ack_cursor"], 1034)
        self.assertEqual([row["seq"] for row in entry["attention"]], [1020, 1035])
        self.assertNotIn("delivered_at", entry["attention"][0])
        self.assertEqual(entry["attention"][0]["body"], "GENUINE PREVIOUSLY STAGED MAIL")

    def test_delta_ack_floor_applies_before_staging_and_does_not_filter_inbox_rows(self):
        self.assertTrue(self.tick()["ok"])
        self.update(event_cursor=0, event_cursor_initialized=True, next_poll_at_epoch=0)
        events = [{"event_id": "event-%s" % seq, "seq": seq,
                   "event_type": "room.message", "actor_id": "shared.director.claude",
                   "payload": {"body": "row-%s" % seq}} for seq in (12, 54)]
        result = hook._watcher_tick(self.key, now=200, force=True,
            delta_loader=lambda _: {"events": events, "next_after": 54,
                                    "may_have_more": False, "inbox_read_cursor": 53},
            notifier=lambda *_: None)
        self.assertTrue(result["ok"], result)
        self.assertEqual([row["seq"] for row in self.entry()["attention"]], [54])
        hook._watcher_stage_attention(self.key, [{
            "event_id": "explicit-inbox-12", "seq": 12,
            "actor": "shared.director.claude", "body": "Explicit hosted unread"}])
        self.assertEqual([row["seq"] for row in self.entry()["attention"]], [12, 54])

    def test_empty_inbox_cursor_keeps_older_pending_disposition(self):
        self.assertTrue(self.tick()["ok"])
        with mock.patch.object(hook, "_watcher_inbox_page", return_value={
                "messages": [], "read_cursor": 1034, "may_have_more": False,
                "pending_dispositions": [{"event_id": "unresolved-8", "seq": 8,
                    "actor": "shared.director.claude", "body": "UNRESOLVED ASSIGNMENT"}],
                "pending_disposition_total": 1}):
            hook._watcher_refresh_inbox_entry(self.key, self.entry())
        self.assertEqual(self.entry()["attention_ack_cursor"], 1034)
        self.assertEqual(self.entry()["pending_dispositions"][0]["seq"], 8)

    def test_invalid_or_failed_inbox_peek_does_not_invent_read_baseline(self):
        self.assertTrue(self.tick()["ok"])
        self.update(attention_ack_cursor=73)
        for cursor in (True, -1, 2.5, "invalid"):
            with self.subTest(cursor=cursor), \
                    mock.patch.object(hook, "_watcher_inbox_page", return_value={
                        "messages": [], "read_cursor": cursor, "may_have_more": False}):
                with self.assertRaisesRegex(RuntimeError, "invalid read cursor"):
                    hook._watcher_refresh_inbox_entry(self.key, self.entry())
            self.assertEqual(self.entry()["attention_ack_cursor"], 73)
        with mock.patch.object(hook, "_watcher_inbox_page", side_effect=RuntimeError("offline")):
            with self.assertRaisesRegex(RuntimeError, "offline"):
                hook._watcher_refresh_inbox_entry(self.key, self.entry())
        self.assertEqual(self.entry()["attention_ack_cursor"], 73)
        with mock.patch.object(hook, "_watcher_inbox_page", return_value={
                "messages": [], "may_have_more": False}):
            hook._watcher_refresh_inbox_entry(self.key, self.entry())
        self.assertEqual(self.entry()["attention_ack_cursor"], 73)

    def test_raw_history_floor_preserves_existing_unrendered_same_id(self):
        entry = {"canonical_actor_id": self.actor, "attention_ack_cursor": 73,
                 "attention": [{"event_id": "retained", "message_key": "event:retained",
                                "seq": 12, "actor": "shared.director.claude",
                                "body": "Already staged", "acknowledged": False}]}
        rows = [{"event_id": event_id, "seq": seq, "event_type": "room.message",
                 "actor_id": "shared.director.claude", "payload": {"body": body}}
                for event_id, seq, body in (("retained", 12, "Already staged"),
                                            ("old-absent", 13, "History"),
                                            ("new", 74, "New mail"))]
        self.assertEqual(hook._watcher_merge_attention(entry, rows), 1)
        self.assertEqual([row["seq"] for row in entry["attention"]], [12, 74])
        self.assertTrue(entry["attention"][0]["acknowledged"])
        self.assertNotIn("delivered_at", entry["attention"][0])

    def test_local_recovery_failure_is_not_reported_as_another_hosted_401(self):
        self.assertTrue(self.tick()["ok"])
        self.update(next_poll_at_epoch=0, auth_required=True,
                    last_error="hosted MCP rejected credential (HTTP 401)")
        with mock.patch.object(hook, "_watcher_recover_identity", side_effect=RuntimeError(
                "local mirror cannot be opened")), \
                mock.patch.object(hook, "_watcher_queue_auth_required") as auth_failure:
            result = self.tick(now=200)
        self.assertFalse(result["ok"])
        self.assertEqual(result["failure_kind"], "identity_recovery_failed")
        self.assertEqual(result["error"], "local mirror cannot be opened")
        self.assertTrue(self.entry()["auth_required"])
        self.assertEqual(self.entry()["last_identity_recovery_error"], result["error"])
        auth_failure.assert_not_called()

    def test_missing_credential_status_failures_are_not_fabricated_auth_rejections(self):
        _, _, client = hook._watcher_sync_modules()
        responses = [
            client.JsonHttpResponse(503, {"content-type": "application/json"}, b'{}'),
            client.JsonHttpResponse(200, {"content-type": "text/html"}, b'<html>proxy</html>'),
            client.JsonHttpResponse(200, {"content-type": "application/json"}, b'{bad'),
            client.JsonHttpResponse(200, {"content-type": "application/json"}, b'[]'),
            client.JsonHttpResponse(200, {"content-type": "application/json"}, b'{}'),
            client.JsonHttpResponse(200, {"content-type": "application/json"},
                                    b'{"authentication_required":false}'),
            client.JsonHttpResponse(200, {"content-type": "application/json"},
                                    b'{"authentication_required":false,"effective_authentication":'
                                    b'"optional","compatibility_active":false}'),
            client.JsonHttpResponse(True, {"content-type": "application/json"}, b'{}'),
        ]
        for response in responses:
            with self.subTest(status=response.status, body=response.body):
                transport = mock.Mock()
                transport.request.return_value = response
                with mock.patch.object(hook, "_watcher_api_token", return_value=None):
                    with self.assertRaises(RuntimeError) as raised:
                        hook._watcher_fetch_sync_snapshot(self.entry(), transport=transport)
                self.assertFalse(hook._authentication_required_error(raised.exception))
                self.assertEqual(transport.request.call_count, 1)

    def test_missing_credential_auth_rejection_says_no_credential_was_sent(self):
        _, _, client = hook._watcher_sync_modules()
        responses = [
            client.JsonHttpResponse(401, {"content-type": "application/json"}, b'{}'),
            client.JsonHttpResponse(200, {"content-type": "application/json"},
                                    b'{"authentication_required":true}'),
        ]
        for response in responses:
            transport = mock.Mock()
            transport.request.return_value = response
            with self.subTest(status=response.status), \
                    mock.patch.object(hook, "_watcher_api_token", return_value=None):
                with self.assertRaisesRegex(hook.HostedAuthenticationRequired,
                                            "No client credential was sent"):
                    hook._watcher_fetch_sync_snapshot(self.entry(), transport=transport)
            self.assertEqual(transport.request.call_count, 1)

    def test_sync_denial_distinguishes_missing_and_supplied_credentials(self):
        _, _, client = hook._watcher_sync_modules()
        compatibility = client.JsonHttpResponse(
            200, {"content-type": "application/json"},
            b'{"authentication_required":false,"effective_authentication":"optional",'
            b'"compatibility_active":true}')
        for token in (None, "isolated-test-credential"):
            for status in (401, 403):
                with self.subTest(credential_present=bool(token), status=status):
                    transport = mock.Mock()
                    denied = client.JsonHttpResponse(
                        status, {"content-type": "application/json"}, b'{}')
                    transport.request.side_effect = [denied] if token else [compatibility, denied]
                    with mock.patch.object(hook, "_watcher_api_token", return_value=token):
                        with self.assertRaises(hook.HostedAuthenticationRequired) as raised:
                            hook._watcher_fetch_sync_snapshot(self.entry(), transport=transport)
                    self.assertEqual(raised.exception.http_status, status)
                    self.assertIn("supplied terminal credential" if token else
                                  "No client credential was sent", str(raised.exception))
                    sent = transport.request.call_args.kwargs["headers"]
                    self.assertEqual("Authorization" in sent, bool(token))

    def test_stale_visibility_during_backoff_does_not_postpone_retry_forever(self):
        self.assertTrue(self.tick()["ok"])
        protocol, _, _ = hook._watcher_sync_modules()
        stale = protocol.visibility_fingerprint(self.entry()["sync_scope"],
                                                 {"superseded": True})
        self.update(sync_visibility_fingerprint=stale, next_poll_at_epoch=300)
        with mock.patch.object(hook, "_watcher_fetch_sync_snapshot",
                               side_effect=AssertionError("Premature retry")):
            waiting = self.tick(now=200)
        self.assertFalse(waiting["due"], waiting)
        self.assertEqual(self.entry()["next_poll_at_epoch"], 300)
        recovered = self.tick(now=300)
        self.assertTrue(recovered["ok"], recovered)

    def test_auth_rejection_never_claims_offline_success_or_retries_every_second(self):
        rejected = dict(self.credential, token="atpair_" + "z" * 48)
        self.save_credential(rejected)
        # Auth UI progress is tested separately; this isolates the watcher's
        # authenticated snapshot and backoff contract.
        with mock.patch.object(hook, "_terminal_flow_notice", return_value={
                "message": "Authorization pending", "result": {
                    "status": "pending", "interval": 60}}):
            result = self.tick()
            with mock.patch.object(hook, "_watcher_fetch_sync_snapshot",
                                   side_effect=AssertionError("Backoff ignored")):
                next_result = self.tick(now=101)
        self.assertTrue(result["authentication_required"], result)
        self.assertFalse(result["offline"])
        self.assertTrue(next_result["authentication_required"], next_result)
        self.assertFalse(next_result["due"])

    def test_paused_watcher_does_not_bootstrap_or_recover_until_resumed(self):
        self.server.update_interval_seconds = 0
        with mock.patch.object(hook, "_watcher_fetch_sync_snapshot",
                               side_effect=AssertionError("Paused snapshot")):
            result = self.tick()
        self.assertTrue(result["disabled"], result)
        self.assertNotIn("canonical_actor_id", self.entry())
        self.server.update_interval_seconds = 60
        resumed = self.tick(now=161)
        self.assertTrue(resumed["ok"], resumed)
        self.assertEqual(self.entry()["canonical_actor_id"], self.actor)

    def test_failed_settings_request_does_not_resume_a_saved_pause(self):
        self.server.update_interval_seconds = 0
        self.assertTrue(self.tick()["disabled"])
        self.save_credential(dict(self.credential, token="atpair_" + "x" * 48))
        with mock.patch.object(hook, "_watcher_fetch_sync_snapshot",
                               side_effect=AssertionError("Paused recovery")):
            result = self.tick(now=161)
        self.assertTrue(result["disabled"], result)
        self.assertEqual(self.entry()["interval_seconds"], 0)

    def test_mcp_invalid_scope_error_cannot_enable_an_older_hook_mirror(self):
        with mock.patch.object(hook, "_offline_session_payload",
                               side_effect=AssertionError("Older mirror used")):
            result = hook._offline_failure_output(
                self.status, self.config, "SessionStart", RuntimeError(
                    "verified offline mirror is unavailable or invalid: no "
                    "verified identity-scoped mirror"), object(), entry=self.entry())
        text = json.dumps(result)
        self.assertIn("CACHE BLOCKED", text)
        self.assertNotIn("CONTINUE WORK", text)

    def test_binding_scope_tampering_fails_closed(self):
        entry = self.entry()
        config_path = self.home / ".attacca/config.json"
        machine = json.loads(config_path.read_text())
        row = next(iter(machine["actor_bindings"].values()))
        row["project_id"] = "other"
        config_path.write_text(json.dumps(machine))
        with self.assertRaisesRegex(RuntimeError, "scope differs"):
            hook._watcher_request_actor(entry)

    def test_explicit_identity_change_keeps_previous_mail_in_a_separate_archive(self):
        entry = {"canonical_actor_id": self.actor, "attention": [{"seq": 10}],
                 "pending_dispositions": [{"seq": 11}], "attention_ack_cursor": 11,
                 "event_cursor": 20, "rendered": {"old": {"at": "yesterday"}}}
        hook._watcher_rebind_delivery_identity(entry, "shared.director.codex.gibbs")
        self.assertEqual(entry["attention"], [])
        self.assertEqual(entry["attention_ack_cursor"], 0)
        old = entry["identity_delivery_archives"][self.actor][0]
        self.assertEqual(old["attention"], [{"seq": 10}])
        self.assertEqual(old["pending_dispositions"], [{"seq": 11}])

    def test_identity_switch_cannot_reassign_pending_old_actor_outbox(self):
        self.assertTrue(self.tick()["ok"])
        previous = self.entry()
        old_adapter = hook._watcher_build_offline_adapter(previous)
        old_adapter.queue_mutation("room.send", {"body": "Original actor write"},
                                   client_mutation_id="cm_original_actor_write")
        replacement = "shared.director.codex.gibbs"
        connection = core.connect(self.db)
        core.set_current_owner("alice")
        try:
            core.agent_register(
                connection, "shared", replacement, "agent", agent_id=replacement,
                role="director", runtime="codex", registration_username="alice")
        finally:
            core.set_current_owner(None)
            connection.close()
        core.machine_actor_binding_set(
            self.url, "shared", "codex", replacement,
            client_instance=self.instance, home=self.home)
        with self.assertRaisesRegex(Exception, "old outbox has"):
            hook._watcher_recover_identity(self.key, self.entry())
        self.assertEqual(self.entry()["canonical_actor_id"], self.actor)
        self.assertEqual(old_adapter.scope["actor_id"], self.actor)
        self.assertEqual(len(old_adapter.pending_mutations()), 1)


if __name__ == "__main__":
    unittest.main()
