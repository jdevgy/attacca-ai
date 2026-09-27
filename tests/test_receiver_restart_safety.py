"""Independent no-network tests for receiver replacement delivery boundaries."""

import json
import os
import subprocess
import unittest
from unittest import mock

from tests import test_session_delivery_health as fixtures


receiver = fixtures.receiver


class ReceiverRestartSafetyTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SessionDeliveryHealthTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.state["subscriptions"]["subscription"] = fixtures.entry([
            fixtures.mail("old-A")])
        self.fixture.save()

    def add_new_mail(self):
        self.fixture.state["subscriptions"]["subscription"]["attention"].append(
            fixtures.mail("new-B"))
        self.fixture.save()

    def run_receiver(self, ticks=1):
        return receiver.run(self.fixture.root, "codex", fixtures.THREAD,
                            parent=(42, "fixture-owner"), max_ticks=ticks,
                            repair=False)

    def queue_directory(self):
        return receiver._state_directory(
            "codex", self.fixture.root, None, fixtures.THREAD) / fixtures.THREAD

    def test_interrupted_notice_is_recovered_before_new_keys_use_next_sequence(self):
        attempts = []

        def interrupted(directory, session, event_id, actionable, message, **unused):
            attempts.append((event_id, message))
            raise SystemExit("simulated interruption after queue intent")

        with self.fixture.isolated(), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch("codex_wake.queue_event", side_effect=interrupted):
            with self.assertRaises(SystemExit):
                self.run_receiver()
        self.add_new_mail()

        def resumed(directory, session, event_id, actionable, message, **unused):
            attempts.append((event_id, message))
            return {"status": "pending_unknown" if len(attempts) == 2 else "queued"}

        with self.fixture.isolated(), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch("codex_wake.queue_event", side_effect=resumed):
            self.assertEqual(self.run_receiver(ticks=4), 0)
        self.assertEqual(len(attempts), 3)
        self.assertEqual(attempts[0], attempts[1])
        self.assertNotEqual(attempts[1][0], attempts[2][0])
        self.assertEqual(int(attempts[2][0].rsplit(":", 1)[1]),
                         int(attempts[1][0].rsplit(":", 1)[1]) + 1)
        self.assertIn("1 new actionable change(s)", attempts[2][1])

    def test_real_uncertain_queue_receipt_is_not_reissued_and_new_mail_progresses(self):
        import codex_wake

        commands = []

        def crash_after_intent(command, **unused):
            commands.append(command)
            raise SystemExit("simulated command in flight")

        with self.fixture.isolated(), \
                mock.patch.object(codex_wake, "queue_supported", return_value=True), \
                mock.patch.object(codex_wake.subprocess, "run", side_effect=crash_after_intent):
            with self.assertRaises(SystemExit):
                self.run_receiver()
        receipts = list(self.queue_directory().glob("*.json"))
        self.assertEqual(len(receipts), 1)
        original = receipts[0].read_bytes()
        self.assertEqual(json.loads(original)["status"], "pending_unknown")
        self.add_new_mail()

        def accepted(command, **unused):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0)

        with self.fixture.isolated(), \
                mock.patch.object(codex_wake, "queue_supported", return_value=True), \
                mock.patch.object(codex_wake.subprocess, "run", side_effect=accepted):
            self.assertEqual(self.run_receiver(ticks=4), 0)
        self.assertEqual(receipts[0].read_bytes(), original)
        self.assertEqual(len(commands), 2, "only original A and distinct new B may start")
        self.assertIn("1 new actionable change(s)", commands[-1][-1])
        self.assertEqual(len(list(self.queue_directory().glob("*.json"))), 2)
        health = self.fixture.receipt(runtime="codex")["_health"]
        self.assertEqual(health["ai_processing"], "unverified")

    def test_accepted_queue_receipt_survives_crash_before_observer_accept(self):
        import codex_wake

        with self.fixture.isolated(), \
                mock.patch.object(codex_wake, "queue_supported", return_value=True), \
                mock.patch.object(codex_wake.subprocess, "run", return_value=
                                  subprocess.CompletedProcess(["isolated"], 0)), \
                mock.patch.object(receiver.ChangeObserver, "accept",
                                  side_effect=SystemExit("interrupted after acceptance")):
            with self.assertRaises(SystemExit):
                self.run_receiver()
        receipts = list(self.queue_directory().glob("*.json"))
        self.assertEqual(len(receipts), 1)
        original = receipts[0].read_bytes()
        self.assertEqual(json.loads(original)["status"], "queued")
        self.add_new_mail()
        with self.fixture.isolated(), \
                mock.patch.object(codex_wake, "queue_supported", return_value=True), \
                mock.patch.object(codex_wake.subprocess, "run", return_value=
                                  subprocess.CompletedProcess(["isolated"], 0)) as launch:
            self.assertEqual(self.run_receiver(ticks=4), 0)
        self.assertEqual(receipts[0].read_bytes(), original)
        self.assertEqual(launch.call_count, 1, "B needs one command; accepted A needs none")
        self.assertIn("1 new actionable change(s)", launch.call_args.args[0][-1])

    def check_delayed_envelope(self, initial):
        attempts = []

        def delayed(directory, session, event_id, actionable, message, **unused):
            attempts.append((event_id, message))
            if len(attempts) == 1:
                self.add_new_mail()
                return {"status": initial}
            return {"status": "queued"}

        with self.fixture.isolated(), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch("codex_wake.queue_event", side_effect=delayed):
            self.assertEqual(self.run_receiver(ticks=4), 0)
        self.assertEqual(len(attempts), 3)
        self.assertEqual(attempts[0], attempts[1])
        self.assertNotEqual(attempts[1][0], attempts[2][0])
        self.assertIn("1 new actionable change(s)", attempts[2][1])

    def test_busy_pending_envelope_does_not_absorb_new_mail(self):
        self.check_delayed_envelope("busy")

    def test_retryable_pending_envelope_does_not_absorb_new_mail(self):
        self.check_delayed_envelope("retryable")

    def check_blocked_pending_envelope(self, flag, diagnostic):
        with self.fixture.isolated(), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch("codex_wake.queue_event", return_value={"status": "busy"}):
            self.assertEqual(self.run_receiver(), 0)
        pending = self.fixture.receipt(runtime="codex")["_pending_deliveries"]
        self.fixture.state["subscriptions"]["subscription"][flag] = True
        self.add_new_mail()
        with self.fixture.isolated(), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch("codex_wake.queue_event", return_value={"status": "busy"}) as queue:
            self.assertEqual(self.run_receiver(ticks=2), 0)
        queue.assert_not_called()
        after = self.fixture.receipt(runtime="codex")
        self.assertEqual(after["_pending_deliveries"], pending)
        self.assertEqual(after["_health"]["problem"], diagnostic)
        self.fixture.state["subscriptions"]["subscription"].pop(flag)
        self.fixture.save()
        with self.fixture.isolated(), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch("codex_wake.queue_event", return_value={"status": "queued"}) as queue:
            self.assertEqual(self.run_receiver(ticks=4), 0)
        self.assertEqual(queue.call_count, 2, "old A and new B remain separate after authorization repair")

    def test_pending_action_is_preserved_but_not_queued_during_auth_rejection(self):
        self.check_blocked_pending_envelope("auth_required", "authorization_required")

    def test_pending_action_waits_for_current_identity_verification(self):
        self.check_blocked_pending_envelope("identity_refresh_required", "identity_refresh_required")

    def test_corrupt_pending_envelopes_fail_closed_without_queue_or_discard(self):
        with self.fixture.isolated(), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch("codex_wake.queue_event", return_value={"status": "busy"}):
            self.assertEqual(self.run_receiver(), 0)
        original = self.fixture.receipt(runtime="codex")
        scope = next(iter(original["_pending_deliveries"]))
        directory = receiver._state_directory("codex", self.fixture.root, None, fixtures.THREAD)
        mutations = (
            ("mapping", lambda row: row.update(_pending_deliveries=[])),
            ("scope", lambda row: row["_pending_deliveries"][scope].update(scope="other-identity")),
            ("sequence", lambda row: row["_pending_deliveries"][scope].update(sequence=True)),
            ("event", lambda row: row["_pending_deliveries"][scope].update(event_id="other:1")),
            ("body", lambda row: row["_pending_deliveries"][scope].update(message="x" * 4097)),
            ("next", lambda row: row["_pending_deliveries"][scope].update(next=[])),
        )
        for name, corrupt in mutations:
            with self.subTest(name=name):
                damaged = json.loads(json.dumps(original))
                corrupt(damaged)
                receiver.hook._write_state(directory / receiver.hook.WATCHER_STATE_NAME, damaged)
                with self.fixture.isolated(), \
                        mock.patch("codex_wake.queue_supported", return_value=True), \
                        mock.patch("codex_wake.queue_event", return_value={"status": "busy"}) as queue:
                    self.assertEqual(self.run_receiver(ticks=2), 0)
                queue.assert_not_called()
                after = self.fixture.receipt(runtime="codex")
                self.assertEqual(after["_pending_deliveries"], damaged["_pending_deliveries"])
                self.assertEqual(after["_health"]["problem"], "receiver_state_invalid")

    def test_unverified_process_is_never_pinned_or_signalled(self):
        with mock.patch.object(receiver, "_owned_receiver_process", return_value=False), \
                mock.patch.object(receiver.os, "pidfd_open") as pin, \
                mock.patch.object(receiver.signal, "pidfd_send_signal") as send, \
                mock.patch.object(receiver.os, "kill") as bare_signal:
            self.assertEqual(receiver._stop_owned_stale_receiver(
                {"pid": 3456}, self.fixture.root, fixtures.THREAD, (42, "owner")),
                "ownership_unverified")
        pin.assert_not_called()
        send.assert_not_called()
        bare_signal.assert_not_called()

    def test_pid_reuse_after_pin_is_not_signalled(self):
        with mock.patch.object(receiver, "_owned_receiver_process", side_effect=[True, False]), \
                mock.patch.object(receiver.os, "pidfd_open", return_value=12345) as pin, \
                mock.patch.object(receiver.signal, "pidfd_send_signal") as send, \
                mock.patch.object(receiver.os, "close") as close, \
                mock.patch.object(receiver.os, "kill") as bare_signal:
            self.assertEqual(receiver._stop_owned_stale_receiver(
                {"pid": 3456}, self.fixture.root, fixtures.THREAD, (42, "owner")),
                "ownership_changed")
        pin.assert_called_once_with(3456, 0)
        send.assert_not_called()
        bare_signal.assert_not_called()
        close.assert_called_once_with(12345)

    def test_verified_target_uses_pidfd_sigterm_only_and_closes_descriptor(self):
        poll = mock.Mock()
        poll.poll.return_value = [(12345, receiver.select.POLLIN)]
        with mock.patch.object(receiver, "_owned_receiver_process", return_value=True), \
                mock.patch.object(receiver.os, "pidfd_open", return_value=12345), \
                mock.patch.object(receiver.signal, "pidfd_send_signal") as send, \
                mock.patch.object(receiver.select, "poll", return_value=poll), \
                mock.patch.object(receiver.os, "close") as close, \
                mock.patch.object(receiver.os, "kill") as bare_signal:
            self.assertEqual(receiver._stop_owned_stale_receiver(
                {"pid": 3456}, self.fixture.root, fixtures.THREAD, (42, "owner")),
                "stopped")
        send.assert_called_once_with(12345, receiver.signal.SIGTERM, None, 0)
        poll.poll.assert_called_once_with(int(receiver.RECEIVER_STOP_TIMEOUT_SECONDS * 1000))
        close.assert_called_once_with(12345)
        bare_signal.assert_not_called()

    def test_stop_timeout_does_not_escalate_to_bare_signal_or_sigkill(self):
        poll = mock.Mock()
        poll.poll.return_value = []
        with mock.patch.object(receiver, "_owned_receiver_process", return_value=True), \
                mock.patch.object(receiver.os, "pidfd_open", return_value=12345), \
                mock.patch.object(receiver.signal, "pidfd_send_signal") as send, \
                mock.patch.object(receiver.select, "poll", return_value=poll), \
                mock.patch.object(receiver.os, "close") as close, \
                mock.patch.object(receiver.os, "kill") as bare_signal:
            self.assertEqual(receiver._stop_owned_stale_receiver(
                {"pid": 3456}, self.fixture.root, fixtures.THREAD, (42, "owner")),
                "stop_timeout")
        send.assert_called_once_with(12345, receiver.signal.SIGTERM, None, 0)
        close.assert_called_once_with(12345)
        bare_signal.assert_not_called()

    def test_failed_pidfd_open_has_no_unsafe_signal_fallback(self):
        with mock.patch.object(receiver, "_owned_receiver_process", return_value=True), \
                mock.patch.object(receiver.os, "pidfd_open", side_effect=PermissionError("denied")), \
                mock.patch.object(receiver.signal, "pidfd_send_signal") as send, \
                mock.patch.object(receiver.os, "kill") as bare_signal:
            self.assertEqual(receiver._stop_owned_stale_receiver(
                {"pid": 3456}, self.fixture.root, fixtures.THREAD, (42, "owner")),
                "stop_failed")
        send.assert_not_called()
        bare_signal.assert_not_called()

    def test_failed_owned_stop_is_bounded_and_never_launches_behind_old_receiver(self):
        directory = receiver._state_directory(
            "codex", self.fixture.root, None, fixtures.THREAD)
        receiver.hook._write_state(directory / receiver.hook.WATCHER_STATE_NAME, {
            "_health": {"pid": 3456, "pid_start": "old-start", "generation": "old"}})
        with mock.patch.dict(os.environ, {"CODEX_THREAD_ID": fixtures.THREAD}), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch.object(receiver, "host_process", return_value=(42, "owner")), \
                mock.patch.object(receiver, "receiver_status", return_value={
                    "running": True, "current_generation": False}), \
                mock.patch.object(receiver, "_process_identity", return_value=(3456, "old-start")), \
                mock.patch.object(receiver, "_stop_owned_stale_receiver", return_value="stop_timeout") as stop, \
                mock.patch.object(receiver.subprocess, "Popen") as launch:
            for clock in (1000, 1001, 1060, 1061, 1180, 1181, 10000):
                with mock.patch.object(receiver.time, "time", return_value=clock):
                    self.assertFalse(receiver.start_codex_receiver(self.fixture.root, fixtures.THREAD))
        self.assertEqual(stop.call_count, 3)
        launch.assert_not_called()
        repair = receiver._read_receipt(directory / "repair" / receiver.hook.WATCHER_STATE_NAME)
        self.assertEqual(repair["attempts"], 3)
        self.assertEqual(repair["status"], "stop_timeout")

    def test_prior_successful_upgrade_record_does_not_block_next_generation(self):
        parent = (42, "owner")
        directory = receiver._state_directory(
            "codex", self.fixture.root, parent, fixtures.THREAD)
        scope = {"runtime": "codex", "cwd": str(self.fixture.root.resolve()),
                 "session_id": fixtures.THREAD, "parent": list(parent)}
        health = {**scope, "pid": 3456, "pid_start": "previous-start",
                  "generation": "previous-generation"}
        receipt = {"_health": health, "retained": {"sequence": 7, "announced": ["A"]}}
        receipt_path = directory / receiver.hook.WATCHER_STATE_NAME
        receiver.hook._write_state(receipt_path, receipt)
        before = receipt_path.read_bytes()
        receiver.hook._write_state(directory / "repair" / receiver.hook.WATCHER_STATE_NAME, {
            **scope, "target_generation": "previous-generation", "attempts": 3,
            "next_at_epoch": 99999999999, "status": "launch_requested",
            "launched_process": health})
        with mock.patch.dict(os.environ, {"CODEX_THREAD_ID": fixtures.THREAD}), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch.object(receiver, "host_process", return_value=parent), \
                mock.patch.object(receiver, "host_alive", return_value=True), \
                mock.patch.object(receiver, "receiver_status", return_value={
                    "running": True, "current_generation": False}), \
                mock.patch.object(receiver, "_owned_receiver_process", return_value=True), \
                mock.patch.object(receiver, "_process_identity", return_value=(5678, "new-start")), \
                mock.patch.object(receiver, "_stop_owned_stale_receiver", return_value="stopped") as stop, \
                mock.patch.object(receiver.subprocess, "Popen", return_value=mock.Mock(pid=5678)) as launch:
            self.assertTrue(receiver.start_codex_receiver(self.fixture.root, fixtures.THREAD))
        stop.assert_called_once_with(health, self.fixture.root, fixtures.THREAD, parent)
        launch.assert_called_once()
        self.assertEqual(receipt_path.read_bytes(), before)
        repaired = receiver._read_receipt(directory / "repair" / receiver.hook.WATCHER_STATE_NAME)
        self.assertEqual(repaired["target_generation"], receiver.RECEIVER_GENERATION)
        self.assertEqual(repaired["attempts"], 1)

    def test_resumed_session_with_dead_previous_parent_can_launch_without_signal(self):
        parent = (42, "resumed-owner")
        directory = receiver._state_directory("codex", self.fixture.root, parent, fixtures.THREAD)
        receipt_path = directory / receiver.hook.WATCHER_STATE_NAME
        receiver.hook._write_state(receipt_path, {"_health": {
            "runtime": "codex", "cwd": str(self.fixture.root.resolve()),
            "session_id": fixtures.THREAD, "parent": [41, "old-owner"],
            "pid": 3456, "pid_start": "dead-start", "running": False,
            "generation": receiver.RECEIVER_GENERATION},
            "retained": {"sequence": 7, "announced": ["A"]}})
        before = receipt_path.read_bytes()
        with mock.patch.dict(os.environ, {"CODEX_THREAD_ID": fixtures.THREAD}), \
                mock.patch("codex_wake.queue_supported", return_value=True), \
                mock.patch.object(receiver, "host_process", return_value=parent), \
                mock.patch.object(receiver, "host_alive", side_effect=lambda item: item == parent), \
                mock.patch.object(receiver, "receiver_status", return_value={
                    "running": False, "current_generation": True}), \
                mock.patch.object(receiver, "_process_identity", side_effect=
                                  lambda pid: (5678, "new-start") if pid == 5678 else None), \
                mock.patch.object(receiver, "_stop_owned_stale_receiver") as stop, \
                mock.patch.object(receiver.subprocess, "Popen", return_value=mock.Mock(pid=5678)) as launch:
            self.assertTrue(receiver.start_codex_receiver(self.fixture.root, fixtures.THREAD))
        stop.assert_not_called()
        launch.assert_called_once()
        self.assertEqual(receipt_path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
