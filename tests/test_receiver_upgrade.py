"""Real, isolated process handover for exact-session receiver upgrades.

Only the queue CLI and producer are fixtures. Receiver code, process identity,
pidfd signalling, lifecycle flocks, and durable receipts use real subprocesses.
Every executable/configuration/state path belongs to a temporary directory.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
THREAD = "01234567-89ab-cdef-8123-456789abcdef"
OTHER_THREAD = "11234567-89ab-cdef-8123-456789abcdef"

HELPER = r'''
import json, os, sys
sys.path.insert(0, os.path.join(os.environ['TASK_PLUGIN'], 'hooks'))
import wait_for_change as receiver
action, cwd, thread = sys.argv[1:]
if action == 'start':
    result = receiver.start_codex_receiver(cwd, thread)
elif action == 'status':
    result = receiver.receiver_status(cwd, 'codex', thread)
else:
    raise ValueError(action)
print(json.dumps(result), flush=True)
'''

HOST = r'''
import json, os, subprocess, sys
from pathlib import Path
if sys.argv[1:3] == ['queue', '--help']:
    print('queue --thread UUID --message TEXT')
    raise SystemExit(0)
if sys.argv[1:2] == ['queue']:
    with open(os.environ['TASK_QUEUE_LOG'], 'a') as stream:
        stream.write(json.dumps(sys.argv[1:]) + '\n')
    raise SystemExit(int(Path(os.environ['TASK_QUEUE_RESULT']).read_text()))
helper = os.environ['TASK_RECEIVER_HELPER']
for line in sys.stdin:
    request = json.loads(line)
    if request['action'] == 'exit':
        break
    command = [sys.executable, '-c', helper,
               'start' if request['action'] == 'concurrent_start' else request['action'],
               request['cwd'], request['thread']]
    children = [subprocess.Popen(command, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True) for _ in range(
                    2 if request['action'] == 'concurrent_start' else 1)]
    results = []
    for child in children:
        stdout, stderr = child.communicate(timeout=12)
        results.append({'code': child.returncode, 'stdout': stdout, 'stderr': stderr})
    print(json.dumps(results), flush=True)
'''


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


@unittest.skipUnless(sys.platform.startswith("linux") and
                     hasattr(os, "pidfd_open") and
                     hasattr(signal, "pidfd_send_signal"),
                     "Linux pidfd and process identity required")
class ReceiverUpgradeProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="attacca-receiver-upgrade-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.checkout = self.root / "checkout"
        (self.checkout / ".attacca").mkdir(parents=True)
        (self.checkout / ".attacca/project.json").write_text(json.dumps({
            "schema_version": 1, "project_id": "fixture"}))
        self.plugin = self.home / ".attacca/plugin/attacca"
        spec = importlib.util.spec_from_file_location(
            "receiver_upgrade_fixture_core", ROOT / "attacca.py")
        core = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(core)
        for relative in core.PLUGIN_FILES:
            destination = self.plugin / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        self.binaries = self.root / "bin"
        self.binaries.mkdir()
        self.fake_codex = self.binaries / "codex"
        self.fake_codex.write_text("#!" + sys.executable + "\n" + HOST)
        self.fake_codex.chmod(0o700)
        self.queue_log = self.root / "queue.jsonl"
        self.queue_result = self.root / "queue-result"
        self.queue_result.write_text("0")
        self.watcher = self.home / ".attacca/watcher"
        self.watcher.mkdir(mode=0o700, parents=True)
        self.state_path = self.watcher / "watcher-state.json"
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("ATTACCA_", "CODEX_", "CLAUDE_", "KIMI_"))}
        self.env.update({
            "HOME": str(self.home), "USERPROFILE": str(self.home),
            "PATH": str(self.binaries) + os.pathsep + os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1", "ATTACCA_RUNTIME": "codex",
            "ATTACCA_URL": "http://127.0.0.1:9", "ATTACCA_ACTOR": "codex",
            "ATTACCA_DEVICE_ID": "isolated-upgrade-device",
            "ATTACCA_CLIENT_INSTANCE": "isolated-upgrade-client",
            "ATTACCA_DISABLE_WATCHER": "1", "ATTACCA_AUTOSTART": "0",
            "ATTACCA_WATCHER_DIR": str(self.watcher),
            "TASK_PLUGIN": str(self.plugin), "TASK_QUEUE_LOG": str(self.queue_log),
            "TASK_QUEUE_RESULT": str(self.queue_result), "TASK_RECEIVER_HELPER": HELPER,
        })
        producer_env = dict(self.env, ATTACCA_WATCHER_NONCE="isolated-producer")
        self.producer = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.read()"],
            env=producer_env, cwd=self.root, stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self._stop_producer)
        self._launch_host()
        self.addCleanup(self._stop_host)
        material = ["http://127.0.0.1:9", "fixture", "codex", "codex",
                    "isolated-upgrade-device", str(self.checkout.resolve())]
        self.key = hashlib.sha256(json.dumps(material, separators=(",", ":"),
                                            ensure_ascii=False).encode()).hexdigest()
        self.state = {"daemon": {"pid": self.producer.pid, "nonce": "isolated-producer",
                                 "heartbeat_at_epoch": time.time()},
                      "subscriptions": {self.key: {
                          "canonical_actor_id": "fixture.worker.codex.qa",
                          "actor": "codex", "runtime": "codex",
                          "client_instance": "isolated-upgrade-client",
                          "interval_seconds": 60, "attention": []}}}
        self._save(self.state_path, self.state)

    @staticmethod
    def _save(path, value):
        path = Path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = path.with_name(".fixture-write.json")
        temporary.write_text(json.dumps(value))
        temporary.chmod(0o600)
        os.replace(temporary, path)

    def _stop_producer(self):
        self.producer.communicate(timeout=5)

    def _launch_host(self):
        self.host = subprocess.Popen([sys.executable, str(self.fake_codex), "host"],
                                     env=self.env, cwd=self.checkout,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)

    def _stop_host(self):
        if self.host.poll() is None:
            self.host.stdin.close()
            self.host.wait(timeout=5)
        self.host.stdout.close()
        self.host.stderr.close()
        deadline = time.monotonic() + 8
        while self._receiver_pids() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(self._receiver_pids(), [], "fixture receiver outlived its host")

    def _receiver_pids(self):
        expected = str(self.plugin / "hooks/wait_for_change.py").encode()
        pids = []
        for path in Path("/proc").iterdir():
            if not path.name.isdigit():
                continue
            try:
                argv = (path / "cmdline").read_bytes().split(b"\0")
                if len(argv) > 1 and argv[1] == expected:
                    pids.append(int(path.name))
            except OSError:
                pass
        return sorted(pids)

    def _request(self, action, cwd=None, thread=THREAD):
        self.host.stdin.write(json.dumps({"action": action,
            "cwd": str(cwd or self.checkout), "thread": thread}) + "\n")
        self.host.stdin.flush()
        self.assertTrue(select.select([self.host.stdout], [], [], 15)[0],
                        "isolated receiver helper timed out")
        line = self.host.stdout.readline()
        self.assertTrue(line, "fixture host exited")
        rows = json.loads(line)
        for row in rows:
            self.assertEqual(row["code"], 0, row["stderr"])
        return [json.loads(row["stdout"]) for row in rows]

    def _wait(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        value = None
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.05)
        self.fail("isolated receiver condition timed out: %r" % value)

    def _status(self):
        return self._request("status")[0]

    def _receipt_path(self):
        return Path(self._status()["state_directory"]) / "watcher-state.json"

    def _receipt(self):
        try:
            return json.loads(self._receipt_path().read_text())
        except FileNotFoundError:
            return {}

    def _queue_calls(self):
        return self.queue_log.read_text().splitlines() if self.queue_log.exists() else []

    def _stage(self, number):
        self.state["subscriptions"][self.key]["attention"].append({
            "event_id": "fixture-event-%d" % number, "seq": number,
            "actor": "fixture.director.claude.qa", "body": "Review %d" % number,
            "directed_to_you": True, "requires_disposition": True})
        self.state["daemon"]["heartbeat_at_epoch"] = time.time()
        self._save(self.state_path, self.state)

    def _upgrade_bytes(self):
        target = self.plugin / "hooks/codex_wake.py"
        target.write_text(target.read_text() + "\n# Isolated receiver upgrade generation.\n")

    def test_concurrent_upgrade_preserves_queued_and_uncertain_receipts(self):
        import fcntl
        self._stage(1)
        self.assertEqual(self._request("start"), [True])
        self._wait(lambda: self._receipt().get("_health", {}).get("last_delivery_state") == "queued")
        self.queue_result.write_text("1")
        self._stage(2)
        self._wait(lambda: self._receipt().get("_health", {}).get("last_delivery_state") == "pending_unknown")
        old = self._receipt()
        old_pid = old["_health"]["pid"]
        directory = self._receipt_path().parent
        receipts = {p.name: p.read_bytes() for p in (directory / THREAD).glob("*.json")}
        self.assertEqual({json.loads(value)["status"] for value in receipts.values()},
                         {"queued", "pending_unknown"})
        self.assertEqual(len(self._queue_calls()), 2)
        self._upgrade_bytes()
        self.assertFalse(self._status()["current_generation"])
        # A concurrent caller may report busy while the other owns the
        # nonblocking launch lock; at least one must complete the handover.
        self.assertTrue(any(self._request("concurrent_start")))
        self._wait(lambda: self._status().get("current_generation"))
        current = self._receipt()
        self.assertNotEqual(current["_health"]["pid"], old_pid)
        self.assertEqual(self._receiver_pids(), [current["_health"]["pid"]])
        self.assertEqual({key: value for key, value in current.items() if not key.startswith("_")},
                         {key: value for key, value in old.items() if not key.startswith("_")})
        self.assertEqual(receipts, {p.name: p.read_bytes() for p in (directory / THREAD).glob("*.json")})
        descriptor = os.open(directory / "receiver.lock", os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
        time.sleep(0.2)
        self.assertEqual(len(self._queue_calls()), 2)
        self.queue_result.write_text("0")
        self._stage(3)
        self._wait(lambda: len(self._queue_calls()) == 3)
        self.assertEqual(self._request("start"), [True])
        self.assertEqual(len(self._receiver_pids()), 1)
        # A completed old launch record must not mask the next upgrade.
        second_pid = self._receipt()["_health"]["pid"]
        self._upgrade_bytes()
        self.assertEqual(self._request("start"), [True])
        self._wait(lambda: self._status().get("current_generation"))
        self.assertNotEqual(self._receipt()["_health"]["pid"], second_pid)
        self.assertEqual(len(self._receiver_pids()), 1)
        self.assertEqual(len(self._queue_calls()), 3)

    def test_wrong_session_health_cannot_authorize_receiver_replacement(self):
        self.assertEqual(self._request("start"), [True])
        self._wait(lambda: self._status().get("running"))
        path = self._receipt_path()
        saved = self._receipt()
        old_pid = saved["_health"]["pid"]
        self._upgrade_bytes()
        saved["_health"]["session_id"] = OTHER_THREAD
        self._save(path, saved)
        self.assertEqual(self._request("start"), [False])
        self.assertEqual(self._receiver_pids(), [old_pid])
        self.assertEqual(self._queue_calls(), [])

    def test_same_session_resumes_under_a_new_host_without_replaying_mail(self):
        self._stage(1)
        self.assertEqual(self._request("start"), [True])
        self._wait(lambda: self._receipt().get("_health", {}).get("last_delivery_state") == "queued")
        saved = self._receipt()
        directory = self._receipt_path().parent
        receipts = {p.name: p.read_bytes() for p in (directory / THREAD).glob("*.json")}
        old_host = self.host.pid
        old_receiver = saved["_health"]["pid"]
        self._stop_host()
        self.assertEqual(self._receiver_pids(), [])
        self._launch_host()
        self.assertNotEqual(self.host.pid, old_host)
        self.assertEqual(self._request("start"), [True])
        self._wait(lambda: self._status().get("current_generation"))
        current = self._receipt()
        self.assertNotEqual(current["_health"]["pid"], old_receiver)
        self.assertEqual(current["_health"]["parent"][0], self.host.pid)
        self.assertEqual(self._receiver_pids(), [current["_health"]["pid"]])
        self.assertEqual(receipts, {p.name: p.read_bytes() for p in (directory / THREAD).glob("*.json")})
        time.sleep(0.2)
        self.assertEqual(len(self._queue_calls()), 1)
        self._stage(2)
        self._wait(lambda: len(self._queue_calls()) == 2)

    def test_existing_lifetime_lock_prevents_an_unrecorded_second_receiver(self):
        import fcntl
        directory = self.watcher / "wake" / _digest([
            "codex", str(self.checkout.resolve()), "session", THREAD])
        directory.mkdir(parents=True, mode=0o700)
        descriptor = os.open(directory / "receiver.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self._request("start"), [False])
            self.assertEqual(self._receiver_pids(), [])
            self.assertEqual(self._queue_calls(), [])
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
