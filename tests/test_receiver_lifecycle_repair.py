"""Real turn boundaries repair receivers without repeated or empty prompts."""

import contextlib
import io
import json
import unittest
from unittest import mock

from tests import test_hook_delivery_health as fixtures

ROOT, hook = fixtures.ROOT, fixtures.hook


THREAD = "01234567-89ab-cdef-8123-456789abcdef"
READY = {"running": True, "current_generation": True}
STALE = {"running": True, "current_generation": False,
         "diagnostic": "receiver_generation_stale"}


class ReceiverLifecycleRepairTest(unittest.TestCase):
    # Reuse the isolated fixture, not the parent class's test methods.
    setUp = fixtures.HookDeliveryHealthTests.setUp
    stage = fixtures.HookDeliveryHealthTests.stage

    @contextlib.contextmanager
    def repair_fixture(self, health=STALE):
        self.key = self.stage()
        with mock.patch.object(hook, "_plugin_and_config", return_value=(ROOT, self.config)), \
                mock.patch.object(hook, "_session_receiver_health", return_value=health) as probe, \
                mock.patch.object(hook, "_session_wake_notice", return_value={
                    "context": "receiver needs repair", "system_message": "delivery health"}) as arm, \
                mock.patch.object(hook, "urlopen", side_effect=AssertionError("unexpected network")), \
                mock.patch.object(hook.time, "time", return_value=100):
            yield probe, arm

    def repair(self, event="UserPromptSubmit", **changes):
        payload = {"hook_event_name": event, "session_id": THREAD, **changes}
        return hook._session_wake_repair_notice(self.status, payload)

    def test_healthy_boundary_does_not_launch_or_write(self):
        with self.repair_fixture(READY) as (_, arm):
            before = hook._watcher_state_path().read_bytes()
            self.assertIsNone(self.repair())
            self.assertIsNone(self.repair("Stop"))
            self.assertEqual(hook._watcher_state_path().read_bytes(), before)
            arm.assert_not_called()

    def test_failed_repair_is_throttled_and_identical_notice_is_not_repeated(self):
        with self.repair_fixture() as (_, arm):
            self.assertIsNotNone(self.repair())
            before = hook._watcher_state_path().read_bytes()
            self.assertIsNone(self.repair("Stop"))
            self.assertEqual(hook._watcher_state_path().read_bytes(), before)
            with mock.patch.object(hook.time, "time", return_value=161):
                self.assertIsNone(self.repair("Stop"))
            self.assertEqual(arm.call_count, 2)

    def test_successful_repair_emits_one_truthful_receipt(self):
        with self.repair_fixture() as (probe, arm):
            probe.side_effect = [STALE, READY]
            result = self.repair()
            self.assertIn("not AI processing", result["context"])
            arm.assert_called_once()
            probe.side_effect = None
            probe.return_value = READY
            before = hook._watcher_state_path().read_bytes()
            self.assertIsNone(self.repair("Stop"))
            self.assertEqual(hook._watcher_state_path().read_bytes(), before)

    def test_late_heartbeat_reports_recovery_without_another_launch(self):
        with self.repair_fixture() as (probe, arm):
            self.assertIsNotNone(self.repair())
            probe.return_value = READY
            self.assertIn("current-generation", self.repair("Stop")["context"])
            self.assertIsNone(self.repair("Stop"))
            arm.assert_called_once()

    def test_missing_session_and_non_turn_events_never_repair(self):
        with self.repair_fixture() as (_, arm):
            for event in ("PostToolUse", "SessionStart", "Other"):
                self.assertIsNone(self.repair(event))
            for session in (None, "", "latest", "not-a-session"):
                self.assertIsNone(self.repair(session_id=session))
            arm.assert_not_called()

    def test_paused_subscription_is_not_reenabled(self):
        with self.repair_fixture() as (_, arm):
            def pause(state):
                state["subscriptions"][self.key]["interval_seconds"] = 0
            hook._mutate_state(hook._watcher_state_path(), pause)
            self.assertIsNone(self.repair())
            arm.assert_not_called()

    def test_other_sessions_have_independent_health_notice_receipts(self):
        with self.repair_fixture() as (_, arm):
            self.assertIsNotNone(self.repair())
            self.assertIsNotNone(self.repair(session_id="11234567-89ab-cdef-8123-456789abcdef"))
            self.assertEqual(arm.call_count, 2)

    def test_actual_prompt_and_stop_entrypoints_repair_then_stay_quiet(self):
        for event in ("UserPromptSubmit", "Stop"):
            with self.subTest(event=event), self.repair_fixture() as (_, arm):
                payload = {"hook_event_name": event, "session_id": THREAD,
                           "cwd": str(self.root)}
                # Give each entrypoint an independent diagnostics ledger.
                def clear(state):
                    state["subscriptions"][self.key].pop("receiver_boundary_checks", None)
                hook._mutate_state(hook._watcher_state_path(), clear)
                with mock.patch.object(hook, "_hook_input", return_value=payload), \
                        mock.patch.object(hook, "prompt_status", return_value=self.status), \
                        mock.patch.object(hook, "_consume_rebrief_pending", return_value=False), \
                        mock.patch.object(hook, "_periodic_output", return_value=None):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(hook.main([]), 0)
                    self.assertIn("receiver needs repair", json.dumps(json.loads(output.getvalue())))
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(hook.main([]), 0)
                    self.assertEqual(output.getvalue(), "")
                    arm.assert_called_once()
