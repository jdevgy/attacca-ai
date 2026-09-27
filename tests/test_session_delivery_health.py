"""Isolated receiver event-channel, resume, repair and honest health contracts."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from tests.test_session_wake import receiver, entry, mail, THREAD, SECOND_THREAD, ROOT


class SessionDeliveryHealthTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="attacca-receiver-health-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.environment = mock.patch.dict(os.environ, {
            "HOME": str(self.root / "home"),
            "ATTACCA_WATCHER_DIR": str(self.root / "watcher"),
            "ATTACCA_RUNTIME": "claude", "CLAUDE_SESSION_ID": "",
            "ATTACCA_DISABLE_WATCHER": "0"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.path = receiver.hook._watcher_state_path()
        self.state = {"subscriptions": {"subscription": entry()},
                      "daemon": {"pid": 123, "nonce": "fixture",
                                 "heartbeat_at_epoch": time.time()}}
        self.save()

    def save(self):
        receiver.hook._write_state(self.path, self.state)

    @contextlib.contextmanager
    def isolated(self, output=None, sleep=None):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(receiver.hook, "prompt_status", return_value={
                "status": "linked", "project_id": "example", "root": str(self.root)}))
            stack.enter_context(mock.patch.object(receiver.hook, "_plugin_and_config", return_value=(ROOT, {})))
            stack.enter_context(mock.patch.object(receiver.hook, "_watcher_subscription_key", return_value="subscription"))
            stack.enter_context(mock.patch.object(receiver.hook, "_watcher_process_matches", return_value=True))
            stack.enter_context(mock.patch.object(receiver, "host_alive", return_value=True))
            stack.enter_context(mock.patch.object(receiver, "host_process", return_value=None))
            stack.enter_context(mock.patch.object(receiver.time, "sleep", side_effect=sleep))
            stack.enter_context(mock.patch.object(receiver.hook, "urlopen", side_effect=AssertionError("unexpected network IO")))
            stack.enter_context(mock.patch.object(receiver.hook, "_ensure_background_watcher", return_value={"started": True}))
            if output is not None:
                stack.enter_context(mock.patch("sys.stdout", output))
            yield

    def run_receiver(self, **kwargs):
        return receiver.run(self.root, "claude", THREAD, max_ticks=3, **kwargs)

    def receipt(self, runtime="claude", session_id=THREAD):
        path = receiver._state_directory(runtime, self.root, None, session_id) / receiver.hook.WATCHER_STATE_NAME
        return receiver._read_receipt(path)

    def test_jsonl_emits_each_new_batch_once_with_monotonic_ids(self):
        self.state["subscriptions"]["subscription"] = entry([mail()])
        self.save()
        output = io.StringIO()
        ticks = []

        def sleep(unused):
            ticks.append(True)
            if len(ticks) == 1:
                self.state["subscriptions"]["subscription"]["attention"].append(mail("ev-2"))
                self.save()

        with self.isolated(output, sleep):
            self.assertEqual(self.run_receiver(jsonl=True), 0)
            self.assertEqual(self.run_receiver(jsonl=True), 0)
        values = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([value["sequence"] for value in values], [1, 2])
        self.assertEqual([value["actionable_count"] for value in values], [1, 1])
        for value in values:
            self.assertEqual(value["schema_version"], 1)
            self.assertEqual(value["type"], "attacca.event")
            self.assertEqual(value["event_id"], "%s:%d" % (value["scope"], value["sequence"]))
            self.assertNotIn("Please inspect", json.dumps(value))
        self.assertEqual(len(self.state["subscriptions"]["subscription"]["attention"]), 2)
        self.assertEqual(self.receipt()["_health"]["last_delivery_state"], "stdout_emitted")

    def test_quiet_jsonl_and_healthy_restart_emit_nothing(self):
        output = io.StringIO()
        with self.isolated(output):
            for unused in range(2):
                receiver.run(self.root, "claude", THREAD, max_ticks=60, jsonl=True)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(self.receipt()["_health"]["ai_processing"], "unverified")

    def test_explicit_resumed_session_uses_same_receipts_with_new_parent(self):
        self.state["subscriptions"]["subscription"] = entry([mail()])
        self.save()
        output = io.StringIO()
        with self.isolated(output):
            self.run_receiver(parent=(10, "old-start"))
            self.run_receiver(parent=(11, "new-start"))
        self.assertEqual(output.getvalue().count("ATTACCA_EVENT:"), 1)
        first = receiver._state_directory("claude", self.root, (10, "old-start"), THREAD)
        second = receiver._state_directory("claude", self.root, (11, "new-start"), THREAD)
        self.assertEqual(first, second)

    @unittest.skipIf(receiver.hook.fcntl is None, "POSIX lifetime locks required")
    def test_concurrent_claude_resume_cannot_share_one_session_ledger(self):
        directory = receiver._state_directory("claude", self.root, (10, "old"), THREAD)
        lock = receiver._monitor_lock(directory)
        self.assertIsNotNone(lock)
        try:
            with mock.patch.object(receiver.hook, "prompt_status") as status:
                self.assertEqual(receiver.run(self.root, "claude", THREAD, (11, "new"), max_ticks=1), 0)
            status.assert_not_called()
        finally:
            os.close(lock)

    def test_exact_parent_registration_keeps_new_sessions_independent(self):
        with mock.patch.object(receiver, "host_process", return_value=(10, "start")):
            self.assertTrue(receiver.register_session(self.root, "claude", THREAD)["registered"])
        self.assertEqual(receiver._registered_session(self.root, "claude", (10, "start")), THREAD)
        self.assertIsNone(receiver._registered_session(self.root, "claude", (10, "reused")))
        self.assertIsNone(receiver._registered_session(self.root, "codex", (10, "start")))
        self.assertIsNone(receiver._registered_session(self.root / "other", "claude", (10, "start")))
        with mock.patch.object(receiver, "host_process", return_value=(10, "start")):
            receiver.register_session(self.root, "claude", SECOND_THREAD)
        self.assertEqual(receiver._registered_session(self.root, "claude", (10, "start")), SECOND_THREAD)

    def test_monitor_adopts_registration_if_it_started_before_hook(self):
        self.state["subscriptions"]["subscription"] = entry([mail()])
        self.save()
        output = io.StringIO()
        parent = (10, "start")
        receiver.register_session(self.root, "claude", THREAD, parent=parent)
        with self.isolated(output):
            receiver.run(self.root, "claude", parent=parent, max_ticks=1)
            receiver.run(self.root, "claude", THREAD, parent=(11, "resumed"), max_ticks=1)
        self.assertEqual(output.getvalue().count("ATTACCA_EVENT:"), 1)

    def test_monitor_does_not_overwrite_corrupt_receipt_when_new_session_arrives(self):
        parent = (10, "start")
        target = receiver._state_directory("claude", self.root, parent, SECOND_THREAD) / receiver.hook.WATCHER_STATE_NAME
        receiver.hook._write_state(target, {})
        target.write_text("{invalid")
        ticks = []

        def sleep(unused):
            ticks.append(True)
            if len(ticks) == 1:
                receiver.register_session(self.root, "claude", SECOND_THREAD, parent=parent)

        with self.isolated(io.StringIO(), sleep):
            self.run_receiver(parent=parent)
        self.assertEqual(target.read_text(), "{invalid")

    def test_status_rejects_corrupt_receipt_instead_of_reporting_healthy(self):
        target = receiver._state_directory("claude", self.root, None, THREAD) / receiver.hook.WATCHER_STATE_NAME
        receiver.hook._write_state(target, {})
        target.write_text("{invalid")
        with mock.patch.object(receiver, "host_process", return_value=None):
            status = receiver.receiver_status(self.root, "claude", THREAD)
        self.assertFalse(status["running"])
        self.assertEqual(status["diagnostic"], "receiver_state_invalid")

    def test_stdout_crash_is_uncertain_and_never_replays_the_same_wake(self):
        self.state["subscriptions"]["subscription"] = entry([mail()])
        self.save()
        with self.isolated(), mock.patch("builtins.print", side_effect=BrokenPipeError):
            with self.assertRaises(BrokenPipeError):
                self.run_receiver()
        self.assertEqual(self.receipt()["_health"]["last_delivery_state"], "pending_unknown")
        output = io.StringIO()
        with self.isolated(output):
            self.run_receiver()
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(len(self.state["subscriptions"]["subscription"]["attention"]), 1)

    def test_status_requires_actual_fresh_receiver_heartbeat(self):
        snapshots = []
        with self.isolated(sleep=lambda unused: snapshots.append(
                receiver.receiver_status(self.root, "claude", THREAD))):
            self.run_receiver()
            stopped = receiver.receiver_status(self.root, "claude", THREAD)
        self.assertTrue(all(row["configured"] and row["running"] for row in snapshots))
        self.assertTrue(stopped["configured"])
        self.assertFalse(stopped["running"])
        self.assertEqual(stopped["ai_processing"], "unverified")

    def test_configuration_or_registration_alone_is_not_running(self):
        receiver.register_session(self.root, "claude", THREAD, parent=(12, "start"))
        with mock.patch.object(receiver, "host_process", return_value=(12, "start")):
            status = receiver.receiver_status(self.root, "claude", THREAD)
        self.assertFalse(status["running"])
        self.assertEqual(status["diagnostic"], "receiver_not_running")

    def test_fresh_old_receiver_generation_is_not_current_health(self):
        directory = receiver._state_directory("codex", self.root, None, THREAD)
        receiver.hook._write_state(directory / receiver.hook.WATCHER_STATE_NAME, {
            "_health": {"running": True, "pid": 123, "pid_start": "test",
                        "heartbeat_at_epoch": time.time(), "generation": "old-code"}})
        with mock.patch.object(receiver, "host_process", return_value=None), \
                mock.patch.object(receiver, "host_alive", return_value=True):
            status = receiver.receiver_status(self.root, "codex", THREAD)
        self.assertTrue(status["running"])
        self.assertFalse(status["current_generation"])
        self.assertEqual(status["diagnostic"], "receiver_generation_stale")

    def test_old_generation_does_not_spawn_endless_duplicate_codex_receivers(self):
        with mock.patch.dict(os.environ, {"CODEX_THREAD_ID": THREAD}), \
                mock.patch.object(receiver, "host_process", return_value=(42, "start")), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch.object(receiver, "receiver_status", return_value={
                    "running": True, "current_generation": False}) as status, \
                mock.patch.object(receiver.subprocess, "Popen") as launch:
            for unused in range(3):
                self.assertFalse(receiver.start_codex_receiver(self.root, THREAD))
        self.assertEqual(status.call_count, 3)
        launch.assert_not_called()

    def test_pidfd_stop_revalidates_after_pin_and_never_signals_reused_pid(self):
        health = {"pid": 123, "pid_start": "original"}
        with mock.patch.object(receiver, "_owned_receiver_process", side_effect=[True, False]), \
                mock.patch.object(receiver.os, "pidfd_open", return_value=71, create=True) as pin, \
                mock.patch.object(receiver.signal, "pidfd_send_signal", create=True) as signal, \
                mock.patch.object(receiver.os, "close") as close, \
                mock.patch.object(receiver.os, "kill", side_effect=AssertionError("bare PID forbidden")):
            self.assertEqual(receiver._stop_owned_stale_receiver(
                health, self.root, THREAD, (42, "parent")), "ownership_changed")
        pin.assert_called_once_with(123, 0)
        signal.assert_not_called()
        close.assert_called_once_with(71)

    def test_verified_stale_receiver_uses_bounded_pidfd_term_only(self):
        health = {"pid": 123, "pid_start": "original"}
        poll = mock.Mock()
        poll.poll.return_value = [(71, receiver.select.POLLIN)]
        with mock.patch.object(receiver, "_owned_receiver_process", return_value=True), \
                mock.patch.object(receiver.os, "pidfd_open", return_value=71, create=True), \
                mock.patch.object(receiver.signal, "pidfd_send_signal", create=True) as signal, \
                mock.patch.object(receiver.select, "poll", return_value=poll), \
                mock.patch.object(receiver.os, "close"), \
                mock.patch.object(receiver.os, "kill", side_effect=AssertionError("bare PID forbidden")):
            self.assertEqual(receiver._stop_owned_stale_receiver(
                health, self.root, THREAD, (42, "parent")), "stopped")
        signal.assert_called_once_with(71, receiver.signal.SIGTERM, None, 0)
        poll.poll.assert_called_once_with(int(receiver.RECEIVER_STOP_TIMEOUT_SECONDS * 1000))

    def test_stale_receiver_stop_timeout_does_not_force_kill(self):
        poll = mock.Mock()
        poll.poll.return_value = []
        with mock.patch.object(receiver, "_owned_receiver_process", return_value=True), \
                mock.patch.object(receiver.os, "pidfd_open", return_value=71, create=True), \
                mock.patch.object(receiver.signal, "pidfd_send_signal", create=True) as signal, \
                mock.patch.object(receiver.select, "poll", return_value=poll), \
                mock.patch.object(receiver.os, "close"), \
                mock.patch.object(receiver.os, "kill", side_effect=AssertionError("bare PID forbidden")):
            self.assertEqual(receiver._stop_owned_stale_receiver(
                {"pid": 123}, self.root, THREAD, (42, "parent")), "stop_timeout")
        self.assertEqual(signal.call_count, 1)

    def test_unverified_stale_receiver_is_never_signalled(self):
        with mock.patch.object(receiver, "_owned_receiver_process", return_value=False), \
                mock.patch.object(receiver.os, "pidfd_open", create=True) as pin, \
                mock.patch.object(receiver.signal, "pidfd_send_signal", create=True) as signal:
            self.assertEqual(receiver._stop_owned_stale_receiver(
                {"pid": 123}, self.root, THREAD, (42, "parent")), "ownership_unverified")
        pin.assert_not_called()
        signal.assert_not_called()

    def test_stale_receiver_rearm_preserves_receipts_and_serializes_launch(self):
        parent = (42, "parent")
        directory = receiver._state_directory("codex", self.root, parent, THREAD)
        receipt = directory / receiver.hook.WATCHER_STATE_NAME
        saved = {"_health": {"pid": 123, "pid_start": "old", "runtime": "codex",
                             "session_id": THREAD, "generation": "old-generation"},
                 "scope": {"announced": ["already-announced"], "sequence": 7},
                 "_pending_deliveries": {}}
        saved["_pending_deliveries"]["scope"] = receiver.ChangeObserver(saved).prepare(
            "scope", entry([mail()]))
        receiver.hook._write_state(receipt, saved)
        before = receipt.read_bytes()
        with mock.patch.dict(os.environ, {"CODEX_THREAD_ID": THREAD}), \
                mock.patch.object(receiver, "host_process", return_value=parent), \
                mock.patch.object(receiver, "host_alive", return_value=True), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch.object(receiver, "receiver_status", return_value={
                    "running": True, "current_generation": False}), \
                mock.patch.object(receiver, "_stop_owned_stale_receiver", return_value="stopped") as stop, \
                mock.patch.object(receiver, "_process_identity", side_effect=lambda pid: (pid, "new")), \
                mock.patch.object(receiver, "_owned_receiver_process", return_value=True), \
                mock.patch.object(receiver.subprocess, "Popen", return_value=mock.Mock(pid=456)) as launch:
            self.assertTrue(receiver.start_codex_receiver(self.root, THREAD))
            self.assertTrue(receiver.start_codex_receiver(self.root, THREAD))
        self.assertEqual(stop.call_count, 1)
        self.assertEqual(launch.call_count, 1)
        self.assertEqual(receipt.read_bytes(), before)
        repair = receiver._read_receipt(directory / "repair" / receiver.hook.WATCHER_STATE_NAME)
        self.assertEqual(repair["attempts"], 1)
        self.assertEqual(repair["status"], "launch_requested")

    def test_stale_rearm_failure_is_bounded_and_never_spawns(self):
        directory = receiver._state_directory("codex", self.root, None, THREAD)
        receiver.hook._write_state(directory / receiver.hook.WATCHER_STATE_NAME, {
            "_health": {"pid": 123, "pid_start": "old", "runtime": "codex",
                        "session_id": THREAD, "generation": "old"}})
        with mock.patch.dict(os.environ, {"CODEX_THREAD_ID": THREAD}), \
                mock.patch.object(receiver, "host_process", return_value=(42, "parent")), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch.object(receiver, "receiver_status", return_value={
                    "running": True, "current_generation": False}), \
                mock.patch.object(receiver, "_stop_owned_stale_receiver", return_value="stop_timeout") as stop, \
                mock.patch.object(receiver.subprocess, "Popen") as launch:
            for unused in range(5):
                self.assertFalse(receiver.start_codex_receiver(self.root, THREAD))
        stop.assert_called_once()
        launch.assert_not_called()

    def test_previous_successful_launch_does_not_block_the_next_generation_upgrade(self):
        parent = (42, "parent")
        directory = receiver._state_directory("codex", self.root, parent, THREAD)
        scope = {"runtime": "codex", "cwd": str(self.root.resolve()),
                 "session_id": THREAD, "parent": list(parent)}
        health = {**scope, "pid": 123, "pid_start": "old", "generation": "previous"}
        receiver.hook._write_state(directory / receiver.hook.WATCHER_STATE_NAME, {"_health": health})
        receiver.hook._write_state(directory / "repair" / receiver.hook.WATCHER_STATE_NAME, {
            **scope, "target_generation": "previous", "attempts": 1,
            "next_at_epoch": time.time() + 300, "status": "launch_requested",
            "launched_process": health})
        with mock.patch.dict(os.environ, {"CODEX_THREAD_ID": THREAD}), \
                mock.patch.object(receiver, "host_process", return_value=parent), \
                mock.patch.object(receiver, "host_alive", return_value=True), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch.object(receiver, "receiver_status", return_value={
                    "running": True, "current_generation": False}), \
                mock.patch.object(receiver, "_owned_receiver_process", return_value=True), \
                mock.patch.object(receiver, "_stop_owned_stale_receiver", return_value="stopped") as stop, \
                mock.patch.object(receiver, "_process_identity", side_effect=lambda pid: (pid, "start")), \
                mock.patch.object(receiver.subprocess, "Popen", return_value=mock.Mock(pid=456)) as launch:
            self.assertTrue(receiver.start_codex_receiver(self.root, THREAD))
        stop.assert_called_once()
        launch.assert_called_once()
        repair = receiver._read_receipt(directory / "repair" / receiver.hook.WATCHER_STATE_NAME)
        self.assertEqual(repair["target_generation"], receiver.RECEIVER_GENERATION)
        self.assertEqual(repair["attempts"], 1)

    def test_current_generation_does_not_override_contradictory_health_scope(self):
        parent = (42, "parent")
        directory = receiver._state_directory("codex", self.root, parent, THREAD)
        baseline = {"runtime": "codex", "cwd": str(self.root.resolve()),
                    "session_id": THREAD, "parent": list(parent),
                    "generation": receiver.RECEIVER_GENERATION}
        for field, wrong in (("runtime", "claude"), ("session_id", SECOND_THREAD),
                             ("cwd", str(self.root / "other"))):
            receiver.hook._write_state(directory / receiver.hook.WATCHER_STATE_NAME,
                                       {"_health": {**baseline, field: wrong}})
            with self.subTest(field=field), \
                    mock.patch.dict(os.environ, {"CODEX_THREAD_ID": THREAD}), \
                    mock.patch.object(receiver, "host_process", return_value=parent), \
                    mock.patch("codex_wake.queue_supported", return_value=True), \
                    mock.patch.object(receiver, "receiver_status", return_value={
                        "running": True, "current_generation": True}), \
                    mock.patch.object(receiver.subprocess, "Popen") as launch, \
                    mock.patch.object(receiver, "_stop_owned_stale_receiver") as stop:
                self.assertFalse(receiver.start_codex_receiver(self.root, THREAD))
            launch.assert_not_called()
            stop.assert_not_called()

    def test_queue_checkpoint_requires_exact_committed_or_pending_envelope(self):
        import codex_wake
        directory = receiver._state_directory("codex", self.root, None, THREAD)
        with mock.patch.object(codex_wake, "queue_supported", return_value=True), \
                mock.patch.object(codex_wake.subprocess, "run", side_effect=
                                  codex_wake.subprocess.TimeoutExpired("isolated", 1)):
            self.assertEqual(codex_wake.queue_event(
                directory, THREAD, "scope:1", True, "isolated notice")["status"], "pending_unknown")
        receipt = directory / receiver.hook.WATCHER_STATE_NAME
        receiver.hook._write_state(receipt, {})
        self.assertFalse(receiver._queue_checkpoint_verified(directory, THREAD))
        pending = receiver.ChangeObserver().prepare("scope", entry([mail()]))
        receiver.hook._write_state(receipt, {"_pending_deliveries": {"scope": pending}})
        self.assertTrue(receiver._queue_checkpoint_verified(directory, THREAD))
        receiver.hook._write_state(receipt, {"scope": pending["next"]})
        self.assertTrue(receiver._queue_checkpoint_verified(directory, THREAD))
        receiver.hook._write_state(receipt, {"other-scope": pending["next"]})
        self.assertFalse(receiver._queue_checkpoint_verified(directory, THREAD))

    def test_dead_legacy_receiver_with_uncheckpointed_receipt_cannot_relaunch(self):
        import codex_wake
        parent = (42, "parent")
        directory = receiver._state_directory("codex", self.root, parent, THREAD)
        with mock.patch.object(codex_wake, "queue_supported", return_value=True), \
                mock.patch.object(codex_wake.subprocess, "run", side_effect=
                                  codex_wake.subprocess.TimeoutExpired("isolated", 1)):
            codex_wake.queue_event(directory, THREAD, "scope:1", True, "isolated notice")
        receiver.hook._write_state(directory / receiver.hook.WATCHER_STATE_NAME, {
            "_health": {"runtime": "codex", "session_id": THREAD, "pid": 123,
                        "pid_start": "old", "generation": "old", "running": False}})
        with mock.patch.dict(os.environ, {"CODEX_THREAD_ID": THREAD}), \
                mock.patch.object(receiver, "host_process", return_value=parent), \
                mock.patch.object(codex_wake, "queue_supported", return_value=True), \
                mock.patch.object(receiver, "receiver_status", return_value={"running": False}), \
                mock.patch.object(receiver, "_process_identity", return_value=None), \
                mock.patch.object(receiver, "_stop_owned_stale_receiver") as stop, \
                mock.patch.object(receiver.subprocess, "Popen") as launch:
            self.assertFalse(receiver.start_codex_receiver(self.root, THREAD))
        stop.assert_not_called()
        launch.assert_not_called()
        repair = receiver._read_receipt(directory / "repair" / receiver.hook.WATCHER_STATE_NAME)
        self.assertEqual(repair["status"], "queue_checkpoint_unverified")

    def test_queue_checkpoint_bound_refuses_unbounded_history(self):
        directory = receiver._state_directory("codex", self.root, None, THREAD)
        receiver.hook._write_state(directory / receiver.hook.WATCHER_STATE_NAME, {
            "scope": {"sequence": 10000000, "announced": []}})
        self.assertFalse(receiver._queue_checkpoint_verified(directory, THREAD))

    def test_live_producer_does_not_mask_auth_identity_or_sync_failure(self):
        for failure, diagnostic in (({"auth_required": True}, "authorization_required"),
                                    ({"identity_refresh_required": True}, "identity_refresh_required"),
                                    ({"sync_bootstrap_error": "failed"}, "identity_sync_failed"),
                                    ({"last_inbox_error": "failed"}, "inbox_sync_failed"),
                                    ({"offline_conflict_count": 1}, "sync_conflict")):
            self.state["subscriptions"]["subscription"] = entry(**failure)
            self.save()
            snapshots = []
            with self.isolated(io.StringIO(), sleep=lambda unused: snapshots.append(
                    receiver.receiver_status(self.root, "claude", THREAD))):
                self.run_receiver()
            with self.subTest(diagnostic=diagnostic):
                self.assertTrue(all(row["running"] for row in snapshots))
                self.assertTrue(all(row["producer_running"] for row in snapshots))
                self.assertFalse(any(row["watcher_healthy"] for row in snapshots))
                self.assertTrue(all(row["diagnostic"] == diagnostic for row in snapshots))

    def test_paused_subscription_is_reported_without_event_or_repair(self):
        self.state["subscriptions"]["subscription"] = entry(interval_seconds=0)
        self.save()
        output = io.StringIO()
        snapshots = []
        with self.isolated(output, sleep=lambda unused: snapshots.append(
                receiver.receiver_status(self.root, "claude", THREAD))):
            self.run_receiver()
        self.assertEqual(output.getvalue(), "")
        self.assertTrue(all(row["subscription_state"] == "paused" for row in snapshots))
        self.assertFalse(any(row["watcher_healthy"] for row in snapshots))

    def test_linux_live_pid_does_not_hide_stale_or_missing_watcher_heartbeat(self):
        with mock.patch.object(receiver.hook, "_watcher_process_matches", return_value=True), \
                mock.patch.object(receiver.time, "time", return_value=1000):
            self.assertFalse(receiver.daemon_healthy({"pid": 1, "nonce": "test"}))
            self.assertFalse(receiver.daemon_healthy({"pid": 1, "nonce": "test", "heartbeat_at_epoch": 800}))
            self.assertFalse(receiver.daemon_healthy({"pid": 1, "nonce": "test", "heartbeat_at_epoch": 1001}))
            self.assertTrue(receiver.daemon_healthy({"pid": 1, "nonce": "test", "heartbeat_at_epoch": 999}))

    def test_persistent_watcher_failure_produces_one_event_not_one_per_poll(self):
        clock = [1000]
        self.state["daemon"]["heartbeat_at_epoch"] = 500
        self.save()
        output = io.StringIO()
        with self.isolated(output, sleep=lambda unused: clock.__setitem__(0, clock[0] + 60)), \
                mock.patch.object(receiver.time, "time", side_effect=lambda: clock[0]), \
                mock.patch.object(receiver.time, "monotonic", side_effect=lambda: clock[0]):
            receiver.run(self.root, "claude", THREAD, max_ticks=8, repair=False)
        self.assertEqual(output.getvalue().count("ATTACCA_EVENT:"), 1)
        self.assertIn("watcher_heartbeat_stale", output.getvalue())

    def test_missing_watcher_rearm_is_bounded_and_survives_receipt_reload(self):
        saved = {}
        with mock.patch.object(receiver.hook, "_ensure_background_watcher", return_value={"started": True}) as ensure:
            for now in (0, 1, 60, 61, 180, 480, 9999):
                receiver._repair_watcher(saved, "watcher_not_running", {}, ROOT, {}, "claude", "key", entry(), now)
                saved = json.loads(json.dumps(saved))
        self.assertEqual(ensure.call_count, 3)
        self.assertEqual(saved["_repair"]["attempts"], 3)

    def test_stalled_live_producer_is_woken_never_killed_or_restarted(self):
        with mock.patch.object(receiver.hook, "_watcher_wake_subscription") as wake, \
                mock.patch.object(receiver.hook, "_ensure_background_watcher") as ensure:
            receiver._repair_watcher({}, "watcher_heartbeat_stale", {}, ROOT, {}, "claude", "key", entry(), 0)
        wake.assert_called_once_with("key", "receiver_health_probe")
        ensure.assert_not_called()

    def test_paused_or_disabled_watcher_is_never_rearmed(self):
        with mock.patch.object(receiver.hook, "_ensure_background_watcher") as ensure:
            receiver._repair_watcher({}, "watcher_not_running", {}, ROOT, {}, "claude", "key", entry(interval_seconds=0), 0)
            with mock.patch.dict(os.environ, {"ATTACCA_DISABLE_WATCHER": "1"}):
                receiver._repair_watcher({}, "watcher_not_running", {}, ROOT, {}, "claude", "key", entry(), 0)
        ensure.assert_not_called()

    def test_codex_queue_acceptance_is_not_ai_processing(self):
        self.state["subscriptions"]["subscription"] = entry([mail()])
        self.save()
        with self.isolated(), mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch("codex_wake.queue_event", return_value={"status": "queued"}) as queue:
            receiver.run(self.root, "codex", THREAD, (10, "start"), max_ticks=2)
        queue.assert_called_once()
        health = self.receipt("codex")["_health"]
        self.assertEqual(health["last_delivery_state"], "queued")
        self.assertEqual(health["ai_processing"], "unverified")

    def test_status_cli_is_local_read_only_and_json(self):
        output = io.StringIO()
        with mock.patch.object(receiver, "run", side_effect=AssertionError("status launched monitor")), \
                mock.patch.object(receiver, "host_process", return_value=None), \
                mock.patch("sys.stdout", output):
            self.assertEqual(receiver.main(["--runtime", "claude", "--cwd", str(self.root), "--session-id", THREAD, "--status"]), 0)
        self.assertFalse(json.loads(output.getvalue())["running"])


if __name__ == "__main__":
    unittest.main()
