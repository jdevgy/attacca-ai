"""Event-only Codex wake transport, with no live AI prompts in tests."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_codex_event_wake_test", ROOT / "hooks" / "codex_wake.py")
wake = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wake)
THREAD = "01234567-89ab-cdef-8123-456789abcdef"
SECOND_THREAD = "11234567-89ab-cdef-8123-456789abcdef"


class CodexEventWakeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "receipts"
        self.support = mock.patch.object(wake, "queue_supported", return_value=True)
        self.support.start()
        self.addCleanup(self.support.stop)
        self.runner = mock.patch.object(wake.subprocess, "run")
        self.run = self.runner.start()
        self.addCleanup(self.runner.stop)
        self.run.return_value = subprocess.CompletedProcess([], 0)

    def send(self, **overrides):
        args = dict(state_dir=self.root, session_id=THREAD,
                    event_id="server/project/actor:ev-12", actionable=True,
                    message="Attacca: new actionable mail is ready. Read the staged inbox.")
        args.update(overrides)
        return wake.queue_event(**args)

    def receipts(self):
        return list(self.root.glob("*/*.json"))

    def test_quiet_transport_never_calls_codex_or_writes_receipts(self):
        for unused in range(60):
            self.assertEqual(self.send(actionable=False)["status"], "not_actionable")
        self.run.assert_not_called()
        self.assertFalse(self.root.exists())

    def test_exact_uuid_target_and_no_shell(self):
        self.assertEqual(self.send()["status"], "queued")
        args, kwargs = self.run.call_args
        self.assertEqual(args[0][:4], ["codex", "queue", "--thread", THREAD])
        self.assertEqual(args[0][4], "--message")
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["timeout"], 15)

    def test_unknown_session_never_chooses_latest_or_session_name(self):
        for value in (None, "", "default", "latest", "my session", THREAD.replace("-", ""), " " + THREAD):
            with self.subTest(target=value):
                self.assertEqual(self.send(session_id=value)["status"], "invalid_target")
        self.run.assert_not_called()

    def test_repeat_and_fresh_module_share_durable_receipt(self):
        self.assertEqual(self.send()["status"], "queued")
        self.assertEqual(self.send()["status"], "duplicate")
        fresh = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(fresh)
        with mock.patch.object(fresh, "queue_supported", return_value=True):
            self.assertEqual(fresh.queue_event(
                self.root, THREAD, "server/project/actor:ev-12", True,
                "Changed wording does not duplicate an existing event.")["status"], "duplicate")
        self.run.assert_called_once()

    def test_new_event_other_session_and_other_scope_each_send_once(self):
        self.send()
        self.assertEqual(self.send(event_id="server/project/actor:ev-13")["status"], "queued")
        self.assertEqual(self.send(session_id=SECOND_THREAD)["status"], "queued")
        self.assertEqual(self.send(event_id="server/other/actor:ev-12")["status"], "queued")
        self.assertEqual(self.run.call_count, 4)

    def test_receipt_is_private_has_no_message_body_or_raw_event(self):
        self.send(message="$(do-not-execute) private event summary")
        record = self.receipts()[0]
        raw = record.read_text()
        self.assertNotIn("private event", raw)
        self.assertNotIn("server/project", raw)
        if os.name != "nt":
            self.assertEqual(record.stat().st_mode & 0o777, 0o600)
            self.assertEqual(record.parent.stat().st_mode & 0o777, 0o700)

    def test_timeout_is_durable_unknown_and_never_retried(self):
        self.run.side_effect = subprocess.TimeoutExpired("codex", 15)
        self.assertEqual(self.send()["status"], "pending_unknown")
        self.assertEqual(self.send()["status"], "pending_unknown")
        self.run.assert_called_once()

    def test_nonzero_is_not_mislabeled_unsupported_or_automatically_retried(self):
        self.run.return_value.returncode = 2
        self.assertEqual(self.send(), {"status": "pending_unknown", "returncode": 2})
        self.assertEqual(self.send()["status"], "pending_unknown")
        self.run.assert_called_once()

    def test_process_spawn_failure_is_safe_to_retry(self):
        self.run.side_effect = [FileNotFoundError("codex"), subprocess.CompletedProcess([], 0)]
        self.assertEqual(self.send()["status"], "retryable")
        self.assertEqual(self.send()["status"], "queued")
        self.assertEqual(self.run.call_count, 2)

    def test_crash_after_acceptance_before_receipt_commit_cannot_replay(self):
        original = wake._write_receipt

        def fail_commit(path, receipt):
            if receipt["status"] == "queued":
                raise OSError("disk full after CLI accepted input")
            original(path, receipt)

        with mock.patch.object(wake, "_write_receipt", side_effect=fail_commit):
            self.assertEqual(self.send()["status"], "state_error")
        self.assertEqual(self.send()["status"], "pending_unknown")
        self.run.assert_called_once()

    def test_receipt_committed_before_child_starts(self):
        def inspect(*args, **kwargs):
            receipt = json.loads(self.receipts()[0].read_text())
            self.assertEqual(receipt["status"], "pending_unknown")
            return subprocess.CompletedProcess([], 0)
        self.run.side_effect = inspect
        self.assertEqual(self.send()["status"], "queued")

    def test_missing_capability_does_not_attempt_queue_or_write_receipt(self):
        wake.queue_supported.return_value = False
        self.assertEqual(self.send()["status"], "unsupported")
        self.run.assert_not_called()
        self.assertFalse(self.root.exists())

    def test_bad_or_oversized_inputs_are_rejected_before_transport(self):
        for changes, expected in (({"event_id": ""}, "invalid_event"),
                                  ({"event_id": "a" * 1025}, "invalid_event"),
                                  ({"message": ""}, "invalid_message"),
                                  ({"message": "a\x00b"}, "invalid_message"),
                                  ({"message": "é" * 2049}, "invalid_message")):
            self.assertEqual(self.send(**changes)["status"], expected)
        self.run.assert_not_called()

    def test_public_state_directory_cannot_be_used(self):
        if os.name == "nt":
            self.skipTest("POSIX permission policy")
        self.root.mkdir(mode=0o755)
        self.assertEqual(self.send()["status"], "state_error")
        self.run.assert_not_called()

    def test_symlink_directory_or_receipt_is_rejected(self):
        target = Path(self.temporary.name) / "target"
        target.mkdir(mode=0o700)
        self.root.symlink_to(target, target_is_directory=True)
        self.assertEqual(self.send()["status"], "state_error")
        self.run.assert_not_called()
        self.root.unlink()
        self.send()
        receipt = self.receipts()[0]
        original = receipt.read_text()
        receipt.unlink()
        destination = target / "receipt.json"
        destination.write_text(original)
        receipt.symlink_to(destination)
        self.assertEqual(self.send()["status"], "state_error")
        self.run.assert_called_once()

    def test_corrupt_or_scope_mismatched_receipt_never_replays(self):
        self.send()
        receipt = self.receipts()[0]
        receipt.write_text("{invalid")
        self.assertEqual(self.send()["status"], "state_error")
        receipt.write_text(json.dumps({"thread": SECOND_THREAD, "status": "queued"}))
        self.assertEqual(self.send()["status"], "state_error")
        self.run.assert_called_once()

    def test_receipt_limit_does_not_evict_and_replay_old_events(self):
        with mock.patch.object(wake, "MAX_RECEIPTS_PER_SESSION", 1):
            self.send()
            self.assertEqual(self.send(event_id="new")["status"], "state_error")
            self.assertEqual(self.send()["status"], "duplicate")
        self.run.assert_called_once()

    @unittest.skipIf(os.name == "nt", "POSIX concurrent lock test")
    def test_concurrent_attempts_cannot_duplicate(self):
        entered = threading.Event()
        release = threading.Event()
        outcomes = []

        def blocked(*args, **kwargs):
            entered.set()
            release.wait(5)
            return subprocess.CompletedProcess([], 0)

        self.run.side_effect = blocked
        worker = threading.Thread(target=lambda: outcomes.append(self.send()))
        worker.start()
        try:
            self.assertTrue(entered.wait(5))
            self.assertEqual(self.send()["status"], "busy")
        finally:
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcomes, [{"status": "queued"}])
        self.run.assert_called_once()


class CodexQueueCapabilityTest(unittest.TestCase):
    def setUp(self):
        wake.queue_supported.cache_clear()
        self.addCleanup(wake.queue_supported.cache_clear)

    def test_installed_capability_not_a_guessed_version_threshold(self):
        with mock.patch.object(wake.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, "Usage: codex queue --thread <THREAD> --message <TEXT>")) as runner:
            self.assertTrue(wake.queue_supported("/installed/codex"))
            self.assertTrue(wake.queue_supported("/installed/codex"))
            runner.assert_called_once()
            self.assertEqual(runner.call_args[0][0], ["/installed/codex", "queue", "--help"])

    def test_old_cli_missing_executable_or_probe_timeout_stays_disabled(self):
        for outcome in (subprocess.CompletedProcess([], 2, "unknown subcommand queue"),
                        subprocess.CompletedProcess([], 0, "codex --help"),
                        FileNotFoundError("missing"), subprocess.TimeoutExpired("codex", 5)):
            wake.queue_supported.cache_clear()
            with mock.patch.object(wake.subprocess, "run") as runner:
                if isinstance(outcome, Exception):
                    runner.side_effect = outcome
                else:
                    runner.return_value = outcome
                self.assertFalse(wake.queue_supported())


if __name__ == "__main__":
    unittest.main()
