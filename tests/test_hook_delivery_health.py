"""Local-only lifecycle delivery, host identity and truthful health checks."""

import importlib.util
import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "hook_delivery_health", ROOT / "hooks/session_start.py")
hook = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hook)


class HookDeliveryHealthTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.status = {"status": "linked", "root": str(self.root),
                       "project_id": "sample"}
        self.config = {"url": "http://127.0.0.1:1", "actor": "codex",
                       "owner": "", "runtime": "codex"}
        environment = mock.patch.dict(os.environ, {
            "HOME": str(self.root), "ATTACCA_RUNTIME": "codex",
            "ATTACCA_WATCHER_DIR": str(self.root / "watcher"),
            "ATTACCA_DEVICE_ID": "isolated-device",
            "ATTACCA_CLIENT_INSTANCE": "isolated-client"}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def stage(self, **fields):
        key = hook._register_watcher_subscription(
            self.status, ROOT, self.config, runtime="codex")
        def mutate(state):
            state["daemon"] = {"pid": 42, "nonce": "isolated"}
            state["subscriptions"][key].update({
                "canonical_actor_id": "sample.director.codex",
                "actor_role": "director", "interval_seconds": 60,
                "last_poll_at_epoch": time.time(), **fields})
        hook._mutate_state(hook._watcher_state_path(), mutate)
        return key

    def post_tool(self):
        with mock.patch.object(hook, "_plugin_and_config", return_value=(ROOT, self.config)), \
                mock.patch.object(hook, "_watcher_process_matches", return_value=True), \
                mock.patch.object(hook, "urlopen", side_effect=AssertionError("network forbidden")), \
                mock.patch.object(hook, "_mcp_snapshot", side_effect=AssertionError("full brief forbidden")), \
                mock.patch.object(hook, "_terminal_flow_notice", side_effect=AssertionError("auth mutation forbidden")):
            return hook._post_tool_output(self.status, {"hook_event_name": "PostToolUse"})

    def test_codex_session_markers_select_own_runtime_without_plugin_root(self):
        for marker in ("CODEX_THREAD_ID", "CODEX_SESSION_ID", "CODEX_PLUGIN_ROOT"):
            with mock.patch.dict(os.environ, {marker: "codex-host"}, clear=True):
                self.assertEqual(hook._runtime_name(), "codex")
        with mock.patch.dict(os.environ, {
                "CODEX_THREAD_ID": "parent", "ATTACCA_RUNTIME": "claude"}, clear=True):
            self.assertEqual(hook._runtime_name(), "claude")
        with mock.patch.dict(os.environ, {"CLAUDE_PLUGIN_ROOT": "/native/claude"}, clear=True):
            self.assertEqual(hook._runtime_name(), "claude")

    def test_snapshot_subprocess_carries_exact_subscription_installation(self):
        entry = {"server_url": self.config["url"], "actor": "codex", "runtime": "codex",
                 "client_instance": "exact-codex", "device_id": "exact-device"}
        config = hook._watcher_subscription_config(entry)
        captured = {}
        def capture(*args, **kwargs):
            captured.update(kwargs["env"])
            raise RuntimeError("captured without execution")
        with mock.patch.dict(os.environ, {"ATTACCA_CLIENT_INSTANCE": "wrong-claude",
                                          "ATTACCA_RUNTIME": "claude"}), \
                mock.patch.object(hook.subprocess, "run", side_effect=capture):
            with self.assertRaisesRegex(RuntimeError, "without execution"):
                hook._mcp_snapshot(self.status, ROOT, config)
        self.assertEqual(captured["ATTACCA_RUNTIME"], "codex")
        self.assertEqual(captured["ATTACCA_CLIENT_INSTANCE"], "exact-codex")
        self.assertEqual(captured["ATTACCA_DEVICE_ID"], "exact-device")
        self.assertEqual(captured["ATTACCA_ACTOR_TYPE"], "agent")

    def test_post_tool_delivers_changed_rows_once_without_blocking_or_network(self):
        key = self.stage(attention=[{"message_key": "event:e1", "event_id": "e1",
            "seq": 1, "actor": "sample.director.claude", "body": "Please review",
            "directed_to_you": True, "acknowledged": True}], pending=[{
                "kind": "project_entity_delta", "entity_key": "task:T-1",
                "summary": "Task changed", "fingerprint": "one"}])
        first = self.post_tool()
        self.assertEqual(set(first), {"hookSpecificOutput"})
        specific = first["hookSpecificOutput"]
        self.assertEqual(specific["hookEventName"], "PostToolUse")
        self.assertIn("Please review", specific["additionalContext"])
        self.assertIn("Task changed", specific["additionalContext"])
        with mock.patch.object(hook, "_mutate_state", wraps=hook._mutate_state) as write:
            self.assertIsNone(self.post_tool())
            write.assert_not_called()
        entry = hook._read_state(hook._watcher_state_path())["subscriptions"][key]
        self.assertIn("e1", entry["rendered"])
        self.assertEqual(entry["pending"], [])

    def test_post_tool_auth_gate_never_delivers_cached_mail_and_warns_once(self):
        key = self.stage(auth_required=True, attention=[{
            "event_id": "blocked", "message_key": "event:blocked", "body": "PRIVATE"}])
        first = self.post_tool()
        self.assertIn("authentication_required", json.dumps(first))
        self.assertNotIn("PRIVATE", json.dumps(first))
        self.assertIsNone(self.post_tool())
        entry = hook._read_state(hook._watcher_state_path())["subscriptions"][key]
        self.assertNotIn("rendered", entry)
        self.assertEqual(len(entry["attention"]), 1)

    def test_post_tool_batches_operational_deltas_without_losing_remainder(self):
        key = self.stage(pending=[{"kind": "project_entity_delta", "entity_key": "task:%d" % i,
                                 "summary": "Changed %d" % i, "fingerprint": str(i)}
                                for i in range(7)])
        self.post_tool()
        entry = hook._read_state(hook._watcher_state_path())["subscriptions"][key]
        self.assertEqual(len(entry["pending"]), 7 - hook.WATCHER_NOTICE_BATCH_SIZE)
        for unused in range(7 // hook.WATCHER_NOTICE_BATCH_SIZE):
            self.post_tool()
        self.assertIsNone(self.post_tool())

    def test_post_tool_withholds_old_scope_while_identity_recovery_is_pending(self):
        key = self.stage(identity_refresh_required=True, offline_mirror_stale=True,
                         attention=[{"event_id": "old", "message_key": "event:old",
                                     "body": "OLD SCOPE PRIVATE"}])
        first = self.post_tool()
        self.assertIn("identity_verification_required", json.dumps(first))
        self.assertNotIn("OLD SCOPE PRIVATE", json.dumps(first))
        entry = hook._read_state(hook._watcher_state_path())["subscriptions"][key]
        self.assertNotIn("rendered", entry)
        self.assertEqual(len(entry["attention"]), 1)

    def test_post_tool_rechecks_concurrent_auth_and_identity_latches_under_lock(self):
        for latch in ("auth_required", "identity_refresh_required"):
            with self.subTest(latch=latch):
                key = self.stage(auth_required=False, identity_refresh_required=False,
                                 post_tool_health_state="ready", pending=[], rendered={},
                                 attention=[{"event_id": "raced", "message_key": "event:raced",
                                             "body": "PRIVATE RACE SENTINEL"}])
                original = hook._mutate_state
                def raced(path, callback):
                    if callback.__name__ == "drain":
                        def latch_before_lock(state):
                            state["subscriptions"][key][latch] = True
                        original(path, latch_before_lock)
                    return original(path, callback)
                with mock.patch.object(hook, "_mutate_state", side_effect=raced):
                    output = self.post_tool()
                self.assertNotIn("PRIVATE RACE SENTINEL", json.dumps(output))
                entry = hook._read_state(hook._watcher_state_path())["subscriptions"][key]
                self.assertNotIn("raced", entry.get("rendered", {}))
                self.assertNotIn("delivered_at", entry["attention"][0])

    def test_post_tool_failed_transaction_does_not_consume_mail_or_entity_deltas(self):
        key = self.stage(post_tool_health_state="ready", attention=[{
            "event_id": "retry", "message_key": "event:retry", "body": "DELIVERY RETRY"}],
            pending=[{"kind": "project_entity_delta", "entity_key": "task:retry",
                      "summary": "ENTITY RETRY", "fingerprint": "retry"}])
        original = hook._write_state
        def failed_write(path, state):
            if path == hook._watcher_state_path():
                raise OSError("isolated transaction write failure")
            return original(path, state)
        with mock.patch.object(hook, "_write_state", side_effect=failed_write):
            failed = self.post_tool()
            self.assertIsNone(self.post_tool())
        self.assertNotIn("DELIVERY RETRY", json.dumps(failed))
        entry = hook._read_state(hook._watcher_state_path())["subscriptions"][key]
        self.assertNotIn("retry", entry.get("rendered", {}))
        self.assertNotIn("delivered_at", entry["attention"][0])
        self.assertEqual(len(entry["pending"]), 1)
        success = self.post_tool()
        self.assertIn("DELIVERY RETRY", json.dumps(success))
        self.assertIn("ENTITY RETRY", json.dumps(success))
        self.assertIsNone(self.post_tool())

    def test_post_tool_renderer_failure_rolls_back_earlier_mail_consumption(self):
        key = self.stage(post_tool_health_state="ready", attention=[{
            "event_id": "retry", "message_key": "event:retry", "body": "DELIVERY RETRY"}],
            pending=[{"kind": "project_entity_delta", "entity_key": "task:retry",
                      "summary": "ENTITY RETRY", "fingerprint": "retry"}])
        with mock.patch.object(hook, "_watcher_pending_notice", side_effect=ValueError(
                "isolated later renderer failure")):
            failed = self.post_tool()
        self.assertNotIn("DELIVERY RETRY", json.dumps(failed))
        entry = hook._read_state(hook._watcher_state_path())["subscriptions"][key]
        self.assertNotIn("retry", entry.get("rendered", {}))
        self.assertEqual(len(entry["pending"]), 1)
        self.assertIn("DELIVERY RETRY", json.dumps(self.post_tool()))

    def test_post_tool_has_no_metadata_write_after_consuming_delivery(self):
        self.stage(post_tool_health_state="ready", attention=[{
            "event_id": "one", "message_key": "event:one", "body": "ONLY TRANSACTION"}])
        original = hook._mutate_state
        transactions = []
        def tracked(path, callback):
            if path == hook._watcher_state_path():
                transactions.append(callback.__name__)
                if len(transactions) > 1:
                    raise OSError("forbidden post-delivery bookkeeping")
            return original(path, callback)
        with mock.patch.object(hook, "_mutate_state", side_effect=tracked):
            output = self.post_tool()
        self.assertIn("ONLY TRANSACTION", json.dumps(output))
        self.assertEqual(transactions, ["drain"])

    def test_post_tool_diagnostic_cleanup_cannot_hide_committed_delivery(self):
        self.stage(post_tool_health_state="ready", attention=[{
            "event_id": "one", "message_key": "event:one", "body": "COMMITTED DELIVERY"}])
        with mock.patch.object(hook, "_post_tool_local_diagnostic", side_effect=OSError(
                "isolated nonessential diagnostic cleanup failure")):
            output = self.post_tool()
        self.assertIn("COMMITTED DELIVERY", json.dumps(output))
        self.assertIsNone(self.post_tool())

    def test_oversized_post_tool_context_stays_queued_instead_of_being_lost(self):
        key = self.stage(pending=[{"kind": "project_entity_delta", "entity_key": "large",
                                  "summary": "x" * 40000, "fingerprint": "large"}])
        self.assertIsNone(self.post_tool())
        entry = hook._read_state(hook._watcher_state_path())["subscriptions"][key]
        self.assertEqual(len(entry["pending"]), 1)

    def test_large_staged_mail_page_is_reduced_until_every_row_is_delivered(self):
        rows = [{"event_id": "e%d" % i, "message_key": "event:e%d" % i,
                 "seq": i, "actor": "sample.director.claude", "body": "x" * 2400,
                 "directed_to_you": True, "acknowledged": False} for i in range(50)]
        key = self.stage(pending_dispositions=rows[:25], attention=rows[25:])
        for unused in range(5):
            output = self.post_tool()
            if output:
                self.assertLess(len(output["hookSpecificOutput"]["additionalContext"].encode()), 32768)
        entry = hook._read_state(hook._watcher_state_path())["subscriptions"][key]
        self.assertEqual(len(entry["rendered"]), 50)
        self.assertIsNone(self.post_tool())

    def test_corrupt_watcher_state_warns_once_and_recovers_without_tool_block(self):
        self.stage()
        original = hook._read_state
        def read(path):
            if path == hook._watcher_state_path():
                raise ValueError("broken private state")
            return original(path)
        with mock.patch.object(hook, "_read_state", side_effect=read):
            first = self.post_tool()
            self.assertIn("could not be read or validated", json.dumps(first))
            self.assertNotIn("decision", first)
            self.assertIsNone(self.post_tool())
        self.assertIn("state access recovered", json.dumps(self.post_tool()))
        self.assertIsNone(self.post_tool())

    def test_main_post_tool_never_enters_full_lifecycle(self):
        payload = {"hook_event_name": "PostToolUse", "cwd": str(self.root)}
        with mock.patch.object(hook, "_hook_input", return_value=payload), \
                mock.patch.object(hook, "prompt_status", return_value=self.status), \
                mock.patch.object(hook, "_post_tool_output", return_value=None) as drain, \
                mock.patch.object(hook, "_active_output", side_effect=AssertionError("startup")), \
                mock.patch.object(hook, "_periodic_output", side_effect=AssertionError("network poll")), \
                mock.patch("sys.stdout", io.StringIO()) as output:
            self.assertEqual(hook.main([]), 0)
            self.assertEqual(output.getvalue(), "")
            drain.assert_called_once()

    def test_only_exact_retired_cron_prompts_are_blocked_before_any_work(self):
        prompt = "/attacca:inbox [ATTACCA_MANAGED_INBOX_LOOP_V1:sample]"
        payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt}
        with mock.patch.object(hook, "_hook_input", return_value=payload), \
                mock.patch.object(hook, "prompt_status", side_effect=AssertionError("must stop early")), \
                mock.patch("sys.stdout", io.StringIO()) as output:
            self.assertEqual(hook.main([]), 0)
            self.assertEqual(json.loads(output.getvalue())["decision"], "block")
        for text in ("Explain " + prompt, prompt + " and fix my build", "ordinary prompt"):
            self.assertIsNone(hook._retired_managed_pulse_output(dict(payload, prompt=text)))
        self.assertIsNone(hook._retired_managed_pulse_output(dict(payload, hook_event_name="Stop")))

    def test_transport_health_requires_success_and_not_just_live_daemon(self):
        entry = {"canonical_actor_id": "sample.director.codex", "interval_seconds": 60,
                 "last_poll_at_epoch": 100}
        self.assertEqual(hook._watcher_transport_health(entry, True, 120)["state"], "ready")
        self.assertEqual(hook._watcher_transport_health(entry, True, 500)["state"], "stale")
        self.assertEqual(hook._watcher_transport_health(entry, False, 120)["state"], "daemon_stopped")
        self.assertEqual(hook._watcher_transport_health(dict(entry, auth_required=True), True, 120)["state"], "authentication_required")
        self.assertEqual(hook._watcher_transport_health(dict(entry, interval_seconds=0), True, 120)["state"], "paused")

    def test_claude_resume_requires_monitor_verification_even_after_configuration(self):
        module = SimpleNamespace(register_session=mock.Mock())
        with mock.patch.dict(os.environ, {"ATTACCA_RUNTIME": "claude"}), \
                mock.patch.object(hook, "_session_receiver_module", return_value=module), \
                mock.patch.object(hook, "_session_receiver_health", return_value={"running": False}):
            notice = hook._session_wake_notice(self.status, {"session_id": "exact-session", "source": "resume"})
        self.assertIn("CHECK REQUIRED", notice["context"])
        self.assertIn("not proof it is running", notice["context"])
        self.assertIn("start exactly one Monitor", notice["context"])
        self.assertIn("--session-id exact-session", notice["context"])
        module.register_session.assert_called_once_with(str(self.root), "claude", "exact-session")

    def test_codex_launch_success_does_not_claim_delivery_verified(self):
        module = SimpleNamespace(register_session=mock.Mock(), start_codex_receiver=mock.Mock(return_value=True))
        with mock.patch.object(hook, "_session_receiver_module", return_value=module), \
                mock.patch.object(hook, "_session_receiver_health", return_value={"running": False}):
            notice = hook._session_wake_notice(self.status, {"session_id": "exact-session"})
        self.assertIn("launch requested", notice["context"])
        self.assertIn("not verified yet", notice["context"])

    def test_old_receiver_generation_is_not_claimed_as_supported_ready_delivery(self):
        module = SimpleNamespace(register_session=mock.Mock(), start_codex_receiver=mock.Mock(return_value=False))
        with mock.patch.object(hook, "_session_receiver_module", return_value=module), \
                mock.patch.object(hook, "_session_receiver_health", return_value={
                    "running": True, "current_generation": False,
                    "diagnostic": "receiver_generation_stale"}):
            notice = hook._session_wake_notice(self.status, {"session_id": "exact-session"})
        self.assertIn("older receiver generation", notice["context"])
        self.assertNotIn("heartbeat observed", notice["context"])

    def test_inherited_outer_session_id_never_authorizes_receiver_launch(self):
        module = SimpleNamespace(register_session=mock.Mock(), start_codex_receiver=mock.Mock())
        with mock.patch.dict(os.environ, {"CODEX_THREAD_ID": "outer-session"}), \
                mock.patch.object(hook, "_session_receiver_module", return_value=module):
            notice = hook._session_wake_notice(self.status, {})
        module.start_codex_receiver.assert_not_called()
        module.register_session.assert_not_called()
        self.assertIn("unavailable", notice["context"])

    def test_auth_gated_session_start_still_provides_receiver_rearm_instruction(self):
        payload = {"hook_event_name": "SessionStart", "cwd": str(self.root)}
        with mock.patch.object(hook, "_hook_input", return_value=payload), \
                mock.patch.object(hook, "prompt_status", return_value=self.status), \
                mock.patch.object(hook, "_reconcile_claude_project_mcp", return_value=None), \
                mock.patch.object(hook, "_active_output", return_value={
                    "hookSpecificOutput": {"hookEventName": "SessionStart",
                      "additionalContext": "ATTACCA AUTHENTICATION REQUIRED — CACHE BLOCKED"}}), \
                mock.patch.object(hook, "_session_wake_notice", return_value={
                    "system_message": "receiver", "context": "VERIFY RECEIVER"}), \
                mock.patch("sys.stdout", io.StringIO()) as output:
            self.assertEqual(hook.main([]), 0)
            self.assertIn("VERIFY RECEIVER", output.getvalue())
            self.assertIn("CACHE BLOCKED", output.getvalue())


if __name__ == "__main__":
    unittest.main()
