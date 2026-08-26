"""Regression tests for conservative machine-global watcher pruning."""

import importlib.util
import json
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "session_start.py"
SPEC = importlib.util.spec_from_file_location(
    "attacca_watcher_subscription_hygiene_test", HOOK)
watch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(watch)


class WatcherSubscriptionHygieneTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.sandbox = Path(self.temporary.name)
        self.environment = mock.patch.dict(os.environ, {
            "HOME": str(self.sandbox / "home"),
            "ATTACCA_WATCHER_DIR": str(self.sandbox / "watcher"),
            "ATTACCA_RUNTIME": "codex",
            "ATTACCA_DEVICE_ID": "hygiene-device",
            "ATTACCA_CLIENT_INSTANCE": "hygiene-client",
        }, clear=False)
        self.environment.start()
        self.config = {
            "url": "http://unreachable.attacca.test:4173",
            "actor": "codex",
            "owner": "jack",
        }

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def make_checkout(self, name="checkout", project="shared"):
        root = self.sandbox / name
        link = root / ".attacca" / "project.json"
        link.parent.mkdir(parents=True)
        link.write_text(json.dumps({"project_id": project}) + "\n")
        status = {
            "status": "linked",
            "project_id": project,
            "root": str(root),
            "link_path": str(link),
        }
        key = watch._register_watcher_subscription(
            status, ROOT, self.config, runtime="codex", now=0)
        return key, status, root, link

    def state(self):
        return json.loads(watch._watcher_state_path().read_text())

    def mutate(self, callback):
        return watch._mutate_state(watch._watcher_state_path(), callback)

    def test_dead_test_root_requires_grace_then_prunes_registration_only(self):
        key, _status, root, _link = self.make_checkout()
        shared_offline = Path(
            self.state()["subscriptions"][key]["offline_directory"])
        shared_offline.mkdir(parents=True)
        retained = shared_offline / "identity-scoped-outbox-sentinel"
        retained.write_text("must survive subscription pruning\n")
        shutil.rmtree(root)

        first = watch._prune_missing_watcher_subscriptions(now=0)
        second = watch._prune_missing_watcher_subscriptions(now=1)
        self.assertEqual(first["removed"], [])
        self.assertEqual(second["removed"], [])
        entry = self.state()["subscriptions"][key]
        self.assertEqual(entry["local_path_missing_reason"],
                         "checkout_root_absent")
        self.assertEqual(entry["local_path_missing_observations"], 2)

        final = watch._prune_missing_watcher_subscriptions(
            now=watch.WATCHER_MISSING_GRACE_SECONDS)
        self.assertEqual(final["removed"], [key])
        self.assertNotIn(key, self.state()["subscriptions"])
        self.assertEqual(retained.read_text(),
                         "must survive subscription pruning\n")

    def test_missing_project_link_uses_same_sustained_absence_contract(self):
        key, _status, root, link = self.make_checkout()
        link.unlink()
        self.assertTrue(root.is_dir())

        for now in (10, 11):
            result = watch._prune_missing_watcher_subscriptions(now=now)
            self.assertEqual(result["removed"], [])
        entry = self.state()["subscriptions"][key]
        self.assertEqual(entry["local_path_missing_reason"],
                         "project_link_absent")

        result = watch._prune_missing_watcher_subscriptions(
            now=10 + watch.WATCHER_MISSING_GRACE_SECONDS)
        self.assertEqual(result["removed"], [key])
        self.assertNotIn(key, self.state()["subscriptions"])

    def test_valid_checkout_survives_auth_and_server_errors_and_recovers(self):
        key, _status, root, link = self.make_checkout()

        def seed_failures(state):
            entry = state["subscriptions"][key]
            entry.update({
                "last_error": "HTTP Error 401: Unauthorized",
                "sync_bootstrap_error": "connection refused",
                "offline_failure_count": 999,
                "local_path_missing_since_epoch": 0,
                "local_path_missing_last_checked_epoch": 1,
                "local_path_missing_observations": 50,
                "local_path_missing_reason": "checkout_root_absent",
            })

        self.mutate(seed_failures)
        result = watch._prune_missing_watcher_subscriptions(
            now=watch.WATCHER_MISSING_GRACE_SECONDS * 10)
        state = self.state()
        self.assertEqual(result["removed"], [])
        self.assertEqual(result["recovered"], [key])
        self.assertIn(key, state["subscriptions"])
        self.assertTrue(root.is_dir())
        self.assertTrue(link.is_file())
        for field in watch._WATCHER_MISSING_FIELDS:
            self.assertNotIn(field, state["subscriptions"][key])
        self.assertEqual(state["subscriptions"][key]["last_error"],
                         "HTTP Error 401: Unauthorized")

    def test_relative_or_inaccessible_path_is_unknown_not_prunable(self):
        key, _status, _root, _link = self.make_checkout()

        def make_path_unprovable(state):
            entry = state["subscriptions"][key]
            entry["root"] = "relative/checkout"
            entry["local_path_missing_since_epoch"] = 0
            entry["local_path_missing_last_checked_epoch"] = 1
            entry["local_path_missing_observations"] = 100
            entry["local_path_missing_reason"] = "checkout_root_absent"

        self.mutate(make_path_unprovable)
        result = watch._prune_missing_watcher_subscriptions(
            now=watch.WATCHER_MISSING_GRACE_SECONDS * 10)
        self.assertEqual(result["removed"], [])
        self.assertIn(key, self.state()["subscriptions"])

        denied_root = self.sandbox / "permission-denied-checkout"

        def point_at_denied_root(state):
            state["subscriptions"][key]["root"] = str(denied_root)

        self.mutate(point_at_denied_root)
        real_stat = os.stat

        def selectively_denied(path, *args, **kwargs):
            if str(path) == str(denied_root):
                raise PermissionError("not proof")
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(watch.os, "stat",
                               side_effect=selectively_denied):
            result = watch._prune_missing_watcher_subscriptions(
                now=watch.WATCHER_MISSING_GRACE_SECONDS * 20)
        self.assertEqual(result["removed"], [])
        self.assertIn(key, self.state()["subscriptions"])

    def test_concurrent_reregistration_recreates_pruned_entry_without_loss(self):
        key, status, root, _link = self.make_checkout()
        shutil.rmtree(root)

        def make_due(state):
            entry = state["subscriptions"][key]
            entry.update({
                "local_path_missing_since_epoch": 0,
                "local_path_missing_last_checked_epoch": 1,
                "local_path_missing_observations": (
                    watch.WATCHER_MISSING_MIN_OBSERVATIONS - 1),
                "local_path_missing_reason": "checkout_root_absent",
            })

        self.mutate(make_due)
        entered = threading.Event()
        release = threading.Event()
        original = watch._watcher_subscription_missing_reason

        def blocking_reason(entry):
            entered.set()
            if not release.wait(timeout=3):
                raise AssertionError("concurrent registration never released")
            return original(entry)

        prune_result = []
        register_result = []
        with mock.patch.object(
                watch, "_watcher_subscription_missing_reason",
                side_effect=blocking_reason):
            pruning = threading.Thread(
                target=lambda: prune_result.append(
                    watch._prune_missing_watcher_subscriptions(
                        now=watch.WATCHER_MISSING_GRACE_SECONDS + 2)))
            pruning.start()
            self.assertTrue(entered.wait(timeout=3))
            registering = threading.Thread(
                target=lambda: register_result.append(
                    watch._register_watcher_subscription(
                        status, ROOT, self.config, runtime="codex", now=99)))
            registering.start()
            release.set()
            pruning.join(timeout=3)
            registering.join(timeout=3)

        self.assertFalse(pruning.is_alive())
        self.assertFalse(registering.is_alive())
        self.assertEqual(prune_result[0]["removed"], [key])
        self.assertEqual(register_result, [key])
        entry = self.state()["subscriptions"][key]
        for field in watch._WATCHER_MISSING_FIELDS:
            self.assertNotIn(field, entry)
        self.assertEqual(entry["next_poll_at_epoch"], 99)

    def test_daemon_prunes_due_dead_root_and_stays_healthy(self):
        dead_key, _status, dead_root, _link = self.make_checkout(
            "dead", "dead-project")
        live_key, _status, _root, _link = self.make_checkout(
            "live", "live-project")
        shutil.rmtree(dead_root)

        def make_due(state):
            entry = state["subscriptions"][dead_key]
            entry.update({
                "local_path_missing_since_epoch": 0,
                "local_path_missing_last_checked_epoch": 1,
                "local_path_missing_observations": (
                    watch.WATCHER_MISSING_MIN_OBSERVATIONS - 1),
                "local_path_missing_reason": "checkout_root_absent",
            })

        self.mutate(make_due)
        ticks = []
        now = watch.WATCHER_MISSING_GRACE_SECONDS + 2
        with mock.patch.object(
                watch, "_watcher_tick",
                side_effect=lambda key, **_options: ticks.append(key) or
                {"ok": True}):
            result = watch._watcher_daemon_loop(
                ROOT, "hygiene-daemon", wait=lambda _seconds: None,
                clock=lambda: now, max_ticks=1)

        self.assertTrue(result["ok"])
        self.assertEqual(ticks, [live_key])
        state = self.state()
        self.assertNotIn(dead_key, state["subscriptions"])
        self.assertIn(live_key, state["subscriptions"])
        self.assertFalse(state["daemon"]["running"])
        self.assertEqual(state["daemon"]["subscription_count"], 1)
        self.assertEqual(state["daemon"]["pruned_subscription_count"], 1)


if __name__ == "__main__":
    unittest.main()
