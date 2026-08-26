"""Security and durability regressions for machine-global watcher files."""

import importlib.util
import json
import os
import stat
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "session_start.py"
SPEC = importlib.util.spec_from_file_location(
    "attacca_watcher_private_state_test", HOOK)
watch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(watch)


def file_mode(path):
    return stat.S_IMODE(os.lstat(str(path)).st_mode)


@contextmanager
def permissive_umask():
    previous = os.umask(0)
    try:
        yield
    finally:
        os.umask(previous)


class WatcherPrivateStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.sandbox = Path(self.temporary.name)
        self.home = self.sandbox / "home"
        self.watcher = self.home / ".attacca" / "watcher"
        self.environment = mock.patch.dict(os.environ, {
            "HOME": str(self.home),
            "ATTACCA_WATCHER_DIR": str(self.watcher),
            "ATTACCA_RUNTIME": "codex",
            "ATTACCA_DEVICE_ID": "private-state-device",
            "ATTACCA_CLIENT_INSTANCE": "private-state-client",
        }, clear=False)
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def state_path(self):
        return watch._watcher_state_path()

    def test_fresh_state_temp_and_lock_are_private_under_permissive_umask(self):
        captured_temporary_modes = []
        real_replace = os.replace

        def inspect_replace(source, destination):
            source_path = Path(source)
            if source_path.parent == self.watcher \
                    and source_path.name.endswith(".tmp"):
                captured_temporary_modes.append(file_mode(source_path))
            return real_replace(source, destination)

        with permissive_umask(), mock.patch.object(
                watch.os, "replace", side_effect=inspect_replace):
            watch._mutate_state(
                self.state_path(), lambda state: state.update({"fresh": True}))

        self.assertEqual(file_mode(self.watcher), 0o700)
        self.assertEqual(file_mode(self.state_path()), 0o600)
        self.assertEqual(
            file_mode(self.watcher / ".watcher-state.json.lock"), 0o600)
        self.assertEqual(captured_temporary_modes, [0o600])
        self.assertEqual(json.loads(self.state_path().read_text()),
                         {"fresh": True})

    def test_existing_permissive_modes_are_repaired_without_data_loss(self):
        self.watcher.mkdir(parents=True, mode=0o755)
        os.chmod(self.watcher.parent, 0o755)
        os.chmod(self.watcher, 0o755)
        state_path = self.state_path()
        state_path.write_text('{"preserved":{"value":7}}\n')
        state_lock = self.watcher / ".watcher-state.json.lock"
        lifetime_lock = self.watcher / "watcher.lock"
        log_path = self.watcher / "watcher.log"
        for path in (state_path, state_lock, lifetime_lock, log_path):
            if not path.exists():
                path.write_text("existing\n")
            os.chmod(path, 0o644)

        loaded = watch._read_state(state_path)
        self.assertEqual(loaded, {"preserved": {"value": 7}})
        watch._mutate_state(
            state_path, lambda state: state.update({"second": True}))
        self.assertTrue(watch._watcher_lock_available())
        descriptor = watch._open_private_watcher_file(
            log_path, os.O_WRONLY | os.O_APPEND, create=True)
        os.close(descriptor)

        self.assertEqual(file_mode(self.watcher), 0o700)
        self.assertEqual(
            file_mode(self.watcher.parent), 0o755,
            "the watcher must not chmod unrelated ancestors")
        for path in (state_path, state_lock, lifetime_lock, log_path):
            self.assertEqual(file_mode(path), 0o600, str(path))
        self.assertEqual(json.loads(state_path.read_text()), {
            "preserved": {"value": 7}, "second": True})

    def test_symlinked_directory_and_files_are_rejected_without_victim_change(self):
        victim_directory = self.sandbox / "victim-directory"
        victim_directory.mkdir(mode=0o755)
        victim_sentinel = victim_directory / "sentinel"
        victim_sentinel.write_text("directory victim\n")
        self.watcher.parent.mkdir(parents=True)
        self.watcher.symlink_to(victim_directory, target_is_directory=True)

        with self.assertRaises(watch.WatcherStateSecurityError):
            watch._mutate_state(
                self.state_path(), lambda state: state.update({"bad": True}))
        self.assertEqual(victim_sentinel.read_text(), "directory victim\n")
        self.assertEqual(file_mode(victim_directory), 0o755)

        self.watcher.unlink()
        self.watcher.mkdir(mode=0o700)
        victim_file = self.sandbox / "victim-file"
        victim_file.write_text("file victim\n")
        os.chmod(victim_file, 0o644)

        checks = [
            (self.state_path(), lambda: watch._read_state(self.state_path())),
            (self.watcher / ".watcher-state.json.lock",
             lambda: watch._mutate_state(
                 self.state_path(),
                 lambda state: state.update({"bad": True}))),
            (self.watcher / "watcher.lock", watch._watcher_lock_available),
        ]
        for target, operation in checks:
            for existing in self.watcher.iterdir():
                if existing.is_symlink() or existing.is_file():
                    existing.unlink()
            target.symlink_to(victim_file)
            with self.subTest(target=target.name):
                with self.assertRaises(watch.WatcherStateSecurityError):
                    operation()
                self.assertEqual(victim_file.read_text(), "file victim\n")
                self.assertEqual(file_mode(victim_file), 0o644)

    def test_nonregular_private_file_targets_are_rejected(self):
        self.watcher.mkdir(parents=True, mode=0o700)
        targets = (
            self.state_path(),
            self.watcher / ".watcher-state.json.lock",
            self.watcher / "watcher.lock",
            self.watcher / "watcher.log",
        )
        for target in targets:
            for existing in self.watcher.iterdir():
                if existing.is_file() or existing.is_symlink():
                    existing.unlink()
                elif existing.is_dir():
                    existing.rmdir()
            target.mkdir()
            with self.subTest(target=target.name):
                with self.assertRaises(watch.WatcherStateSecurityError):
                    watch._open_private_watcher_file(
                        target, os.O_RDWR | os.O_APPEND, create=True)
                self.assertTrue(target.is_dir())

    def test_mocked_daemon_launch_makes_log_and_lifetime_lock_private(self):
        self.watcher.mkdir(parents=True, mode=0o755)
        os.chmod(self.watcher, 0o755)
        log_path = self.watcher / "watcher.log"
        log_path.write_text("old log\n")
        os.chmod(log_path, 0o644)
        launch_root = self.sandbox / "checkout"
        launch_root.mkdir()
        process = SimpleNamespace(pid=424242)

        with permissive_umask(), mock.patch.object(
                watch.subprocess, "Popen", return_value=process) as popen:
            result = watch._ensure_registered_watcher(
                "saved-subscription", launch_root, ROOT)

        self.assertTrue(result["started"])
        self.assertEqual(result["pid"], 424242)
        popen.assert_called_once()
        self.assertEqual(file_mode(self.watcher), 0o700)
        self.assertEqual(file_mode(log_path), 0o600)
        self.assertEqual(file_mode(self.watcher / "watcher.lock"), 0o600)
        self.assertEqual(file_mode(self.state_path()), 0o600)
        self.assertEqual(
            file_mode(self.watcher / ".watcher-state.json.lock"), 0o600)

    def test_symlinked_log_aborts_launch_and_does_not_modify_victim(self):
        self.watcher.mkdir(parents=True, mode=0o700)
        victim = self.sandbox / "log-victim"
        victim.write_text("never append\n")
        os.chmod(victim, 0o644)
        (self.watcher / "watcher.log").symlink_to(victim)
        launch_root = self.sandbox / "checkout"
        launch_root.mkdir()

        with mock.patch.object(watch.subprocess, "Popen") as popen:
            with self.assertRaises(watch.WatcherStateSecurityError):
                watch._ensure_registered_watcher(
                    "saved-subscription", launch_root, ROOT)

        popen.assert_not_called()
        self.assertEqual(victim.read_text(), "never append\n")
        self.assertEqual(file_mode(victim), 0o644)
        state = watch._read_state(self.state_path())
        self.assertNotIn("daemon_launch", state)

    def test_concurrent_mutations_preserve_every_writer(self):
        count = 24
        barrier = threading.Barrier(count)
        failures = []

        def worker(index):
            try:
                barrier.wait(timeout=5)
                watch._mutate_state(
                    self.state_path(),
                    lambda state: state.setdefault("writers", {}).update({
                        str(index): index}))
            except BaseException as error:  # captured for the main test thread
                failures.append(error)

        threads = [threading.Thread(target=worker, args=(index,))
                   for index in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(failures, [])
        self.assertEqual(watch._read_state(self.state_path())["writers"], {
            str(index): index for index in range(count)})
        self.assertEqual(file_mode(self.watcher), 0o700)
        self.assertEqual(file_mode(self.state_path()), 0o600)
        self.assertEqual(
            file_mode(self.watcher / ".watcher-state.json.lock"), 0o600)


if __name__ == "__main__":
    unittest.main()
