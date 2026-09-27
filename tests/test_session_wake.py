"""Behavioral checks for event-driven, local-only session receivers."""

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_session_wake_test", ROOT / "hooks" / "wait_for_change.py")
receiver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receiver)
THREAD = "01234567-89ab-cdef-8123-456789abcdef"
SECOND_THREAD = "11234567-89ab-cdef-8123-456789abcdef"


def mail(event="ev-1", **overrides):
    row = {"event_id": event, "actor": "example.director.claude",
           "body": "Please inspect the failing test.", "directed_to_you": True,
           "requires_disposition": True, "seq": 1}
    row.update(overrides)
    return row


def entry(rows=None, **overrides):
    value = {"canonical_actor_id": "example.worker.codex",
             "actor": "codex", "client_instance": "local-install",
             "attention": rows or [], "interval_seconds": 60}
    value.update(overrides)
    return value


class ChangeObserverTest(unittest.TestCase):
    def test_sixty_unchanged_checks_produce_no_notice(self):
        observer = receiver.ChangeObserver()
        for unused in range(60):
            self.assertIsNone(observer.prepare("scope", entry()))
        self.assertEqual(observer.saved, {})

    def test_new_actionable_batch_announces_once_after_acceptance(self):
        observer = receiver.ChangeObserver()
        state = entry([mail(), mail("ev-2")])
        first = observer.prepare("scope", state)
        self.assertIn("2 new actionable", first["message"])
        self.assertEqual(observer.prepare("scope", state), first)
        observer.accept(first)
        self.assertIsNone(observer.prepare("scope", state))
        restarted = receiver.ChangeObserver(copy.deepcopy(observer.saved))
        self.assertIsNone(restarted.prepare("scope", state))
        state["attention"].append(mail("ev-3"))
        self.assertIn("1 new actionable", restarted.prepare("scope", state)["message"])

    def test_broadcast_and_directed_without_disposition_wake(self):
        state = entry([mail(requires_disposition=False),
                       mail("ev-2", requires_disposition=False,
                            directed_to_you=False, broadcast_to_everyone=True)])
        self.assertEqual(len(receiver.event_keys(state)), 2)

    def test_deferred_blocked_claimed_self_and_context_do_not_wake(self):
        rows = [mail("ev-" + state, disposition={"disposition": state})
                for state in ("deferred", "blocked", "claimed")]
        rows += [mail("ev-self", actor="example.worker.codex"),
                 mail("ev-context", requires_disposition=False, directed_to_you=False,
                      group_context=True),
                 mail("ev-bridge-context", requires_disposition=False,
                      directed_to_you=False, group_context=True,
                      priority_attention=True, origin_project="consumer")]
        self.assertEqual(receiver.event_keys(entry(rows)), set())

    def test_receivers_do_not_mark_rendered_acknowledged_or_disposed(self):
        state = entry([mail()], pending_dispositions=[mail()])
        original = copy.deepcopy(state)
        observer = receiver.ChangeObserver()
        notice = observer.prepare("scope", state)
        observer.accept(notice)
        self.assertEqual(state, original)
        self.assertEqual(len(receiver.event_keys(state)), 1)

    def test_delivered_rows_do_not_wake_until_body_changes(self):
        row = mail()
        state = entry([row], rendered={"ev-1": {
            "body_sha256": receiver.hook._watcher_body_sha256(row["body"]),
            "disposition_state": None, "rendered_at": "already"}})
        self.assertEqual(receiver.event_keys(state), set())
        row["body"] += " Updated requirement."
        self.assertEqual(len(receiver.event_keys(state)), 1)

    def test_routine_entity_refresh_is_not_a_reason_for_an_idle_ai_turn(self):
        state = entry(pending=[
            {"kind": kind, "actor": "example.director.claude",
             "entity_key": "task:T-1", "through": index}
            for index, kind in enumerate(("project_delta", "project_entity_delta",
                                           "project_delta_backlog"))])
        self.assertEqual(receiver.event_keys(state), set())

    def test_offline_conflict_is_actionable(self):
        state = entry(pending=[{"kind": "offline_sync_conflict", "fingerprint": "conflict-1"}])
        observer = receiver.ChangeObserver()
        notice = observer.prepare("scope", state)
        self.assertIsNotNone(notice)
        observer.accept(notice)
        self.assertIsNone(observer.prepare("scope", state))

    def test_failure_and_recovery_each_emit_once(self):
        observer = receiver.ChangeObserver()
        failed = entry(auth_required=True)
        notice = observer.prepare("scope", failed)
        self.assertIn("authorization_required", notice["message"])
        observer.accept(notice)
        self.assertIsNone(observer.prepare("scope", failed))
        recovered = observer.prepare("scope", entry())
        self.assertIn("recovered", recovered["message"])
        observer.accept(recovered)
        self.assertIsNone(observer.prepare("scope", entry()))

    def test_later_outage_episode_has_new_delivery_identity(self):
        observer = receiver.ChangeObserver()
        first = observer.prepare("scope", entry(auth_required=True))
        observer.accept(first)
        recovery = observer.prepare("scope", entry())
        observer.accept(recovery)
        second = observer.prepare("scope", entry(auth_required=True))
        self.assertNotEqual(first["event_id"], second["event_id"])

    def test_actor_scopes_do_not_share_announcements(self):
        observer = receiver.ChangeObserver()
        notice = observer.prepare("actor-one", entry([mail()]))
        observer.accept(notice)
        self.assertIsNotNone(observer.prepare("actor-two", entry([mail()])))


class SessionReceiverProcessTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.environment = mock.patch.dict(os.environ, {
            "ATTACCA_WATCHER_DIR": str(self.directory / "watcher"),
            "ATTACCA_RUNTIME": "claude"})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_shared_codex_process_still_gets_separate_session_receipts(self):
        parent = (100, "start-token")
        first = receiver._state_directory("codex", self.directory, parent, THREAD)
        second = receiver._state_directory("codex", self.directory, parent, SECOND_THREAD)
        self.assertNotEqual(first, second)

    def test_claude_monitor_is_silent_and_preserves_watcher_bytes(self):
        self._run_monitor(entry(), ticks=3, expected_signals=0)

    def test_claude_monitor_signals_once_and_does_not_consume_mail(self):
        self._run_monitor(entry([mail()]), ticks=3, expected_signals=1)

    def _run_monitor(self, staged, ticks, expected_signals):
        path = receiver.hook._watcher_state_path()
        receiver.hook._write_state(path, {"subscriptions": {"subscription": staged},
                                         "daemon": {"pid": 123, "nonce": "test",
                                                    "heartbeat_at_epoch": time.time()}})
        original = path.read_bytes()
        output = io.StringIO()
        with mock.patch.object(receiver.hook, "prompt_status", return_value={"status": "linked"}), \
                mock.patch.object(receiver.hook, "_plugin_and_config", return_value=(ROOT, {})), \
                mock.patch.object(receiver.hook, "_watcher_subscription_key", return_value="subscription"), \
                mock.patch.object(receiver.hook, "_watcher_process_matches", return_value=True), \
                mock.patch.object(receiver, "host_alive", return_value=True), \
                mock.patch.object(receiver.time, "sleep"), \
                mock.patch.object(receiver.hook, "urlopen", side_effect=AssertionError("receiver attempted network")), \
                mock.patch("sys.stdout", output):
            self.assertEqual(receiver.run(self.directory, "claude", max_ticks=ticks), 0)
            first = output.getvalue().count("ATTACCA_EVENT:")
            self.assertEqual(first, expected_signals)
            receiver.run(self.directory, "claude", max_ticks=ticks)
            self.assertEqual(output.getvalue().count("ATTACCA_EVENT:"), first)
        self.assertEqual(path.read_bytes(), original)
        if os.name != "nt":
            for saved in path.parent.glob("wake/*/watcher-state.json"):
                self.assertEqual(saved.stat().st_mode & 0o777, 0o600)

    @unittest.skipIf(receiver.hook.fcntl is None, "POSIX flock required")
    def test_second_receiver_cannot_hold_same_lifetime_lock(self):
        directory = self.directory / "receiver"
        first = receiver._monitor_lock(directory)
        self.assertIsNotNone(first)
        try:
            self.assertIsNone(receiver._monitor_lock(directory))
        finally:
            os.close(first)
        second = receiver._monitor_lock(directory)
        self.assertIsNotNone(second)
        os.close(second)

    def test_codex_without_exact_owner_never_starts_transport(self):
        with mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch("codex_wake.queue_event") as queue:
            self.assertEqual(receiver.run(self.directory, "codex", THREAD, parent=None), 2)
            queue.assert_not_called()

    def test_ambiguous_codex_delivery_does_not_block_or_repeat_later_mail(self):
        staged = entry([mail()])
        path = receiver.hook._watcher_state_path()
        state = {"subscriptions": {"subscription": staged},
                 "daemon": {"pid": 123, "nonce": "test"}}
        receiver.hook._write_state(path, state)
        sleeps = []

        def next_tick(_interval):
            sleeps.append(True)
            if len(sleeps) == 1:
                staged["attention"].append(mail("ev-2"))
                receiver.hook._write_state(path, state)

        with mock.patch.object(receiver.hook, "prompt_status", return_value={"status": "linked"}), \
                mock.patch.object(receiver.hook, "_plugin_and_config", return_value=(ROOT, {})), \
                mock.patch.object(receiver.hook, "_watcher_subscription_key", return_value="subscription"), \
                mock.patch.object(receiver, "daemon_healthy", return_value=True), \
                mock.patch.object(receiver, "host_alive", return_value=True), \
                mock.patch.object(receiver.time, "sleep", side_effect=next_tick), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch("codex_wake.queue_event", side_effect=[
                    {"status": "pending_unknown"}, {"status": "queued"}]) as queue:
            self.assertEqual(receiver.run(
                self.directory, "codex", THREAD, (123, "start"), max_ticks=3), 0)
            self.assertEqual(queue.call_count, 2)
            self.assertIn("1 new actionable", queue.call_args_list[0][0][4])
            self.assertIn("1 new actionable", queue.call_args_list[1][0][4])
        self.assertEqual(len(json.loads(path.read_text())["subscriptions"][
            "subscription"]["attention"]), 2)

    def test_corrupt_receiver_receipt_stops_instead_of_reannouncing_mail(self):
        directory = receiver._state_directory(
            "claude", self.directory, ("native-monitor", os.getppid()), None)
        receiver.hook._ensure_private_watcher_directory(directory)
        receipt = directory / receiver.hook.WATCHER_STATE_NAME
        receipt.write_text("{invalid")
        output = io.StringIO()
        with mock.patch("sys.stdout", output), \
                mock.patch.object(receiver.hook, "prompt_status") as status:
            self.assertEqual(receiver.run(self.directory, "claude", max_ticks=1), 2)
            status.assert_not_called()
        self.assertIn("receiver state is invalid", output.getvalue())
        self.assertEqual(receipt.read_text(), "{invalid")

    def test_host_process_does_not_guess_a_different_session(self):
        with mock.patch.object(receiver.os, "getppid", return_value=42), \
                mock.patch.object(Path, "read_text", side_effect=FileNotFoundError):
            self.assertIsNone(receiver.host_process("codex"))

    def test_reused_pid_start_time_is_not_a_live_session_owner(self):
        fields = ["S", "1"] + ["0"] * 17 + ["new-start"]
        raw = "42 (codex worker) " + " ".join(fields)
        with mock.patch.object(Path, "read_text", return_value=raw):
            self.assertFalse(receiver.host_alive((42, "old-start")))
            self.assertTrue(receiver.host_alive((42, "new-start")))


if __name__ == "__main__":
    unittest.main()
