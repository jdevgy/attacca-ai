"""Adversarial regression coverage for Attacca's Codex TOML lock domain."""

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "attacca.py"


def load_core(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c = load_core("attacca_codex_toml_concurrency_core")


MIXED_DUPLICATE_FIXTURE = """# unrelated preamble survives every repair
model = "gpt-5"
approval_policy = "never"

[projects."/work/alpha"]
trust_level = "trusted"

[mcp_servers.attacca]
command = "python3"
args = ["/old/attacca.py", "connect"]
env = { ATTACCA_ACTOR = "codex", ATTACCA_URL = "http://inline-old:4173" }

[mcp_servers.attacca.env]
ATTACCA_ACTOR = "codex"
ATTACCA_URL = "http://descendant-old:4173"

[mcp_servers.other]
command = "keep-other"

["mcp_servers".attacca.headers]
X-Stale = "remove-me"

[workspace]
name = "keep-workspace"
"""


PROCESS_WORKER = r"""
import importlib.util
import os
import stat
import sys
import time
from pathlib import Path

script, action, home, url, gate = sys.argv[1:]
spec = importlib.util.spec_from_file_location(
    "attacca_codex_toml_worker_%s" % os.getpid(), script)
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
gate = Path(gate)
deadline = time.time() + 20
while not gate.exists():
    if time.time() >= deadline:
        raise SystemExit("start gate timed out")
    time.sleep(0.005)
home = Path(home)
if action == "configure":
    core.configure_codex(None, url, home / "attacca.db", home=home)
elif action == "switch":
    core.machine_server_set(url, home=home, validate=False)
elif action == "unrelated":
    target = home / ".codex" / "config.toml"
    with core._exclusive_codex_config_lock(target):
        text = target.read_text()
        if "[concurrent_user_config]" not in text:
            text += ("\n[concurrent_user_config]\n"
                     "retained = \"yes\"\n")
        core._atomic_switch_write(
            target, text.encode("utf-8"),
            mode=stat.S_IMODE(target.stat().st_mode))
else:
    raise SystemExit("unknown action")
"""


@unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
class CodexTomlConcurrencyRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name) / "home"
        self.codex_home = self.home / ".codex"
        self.config = self.codex_home / "config.toml"
        self.codex_home.mkdir(parents=True)

    def assert_canonical(self, expected_urls):
        text = self.config.read_text()
        parsed = tomllib.loads(text)
        self.assertEqual(text.count("[mcp_servers.attacca]"), 1)
        self.assertNotIn("[mcp_servers.attacca.env]", text)
        self.assertNotIn('["mcp_servers".attacca.headers]', text)
        attacca = parsed["mcp_servers"]["attacca"]
        self.assertEqual(attacca["command"], "python3")
        self.assertEqual(attacca["env"]["ATTACCA_ACTOR"], "codex")
        self.assertIn(attacca["env"]["ATTACCA_URL"], expected_urls)
        self.assertEqual(parsed["model"], "gpt-5")
        self.assertEqual(parsed["approval_policy"], "never")
        self.assertEqual(
            parsed["projects"]["/work/alpha"]["trust_level"], "trusted")
        self.assertEqual(
            parsed["mcp_servers"]["other"]["command"], "keep-other")
        self.assertEqual(parsed["workspace"]["name"], "keep-workspace")
        return parsed

    def test_threads_share_one_complete_read_normalize_write_critical_section(self):
        self.config.write_text(MIXED_DUPLICATE_FIXTURE)
        os.chmod(self.config, 0o600)
        repair = c._codex_config_repair_module()
        original = repair.repair_codex_config
        counter_lock = threading.Lock()
        active = 0
        maximum_active = 0

        def observed_repair(*args, **kwargs):
            nonlocal active, maximum_active
            with counter_lock:
                active += 1
                maximum_active = max(maximum_active, active)
            # Make an unlocked implementation overlap deterministically.
            time.sleep(0.02)
            try:
                return original(*args, **kwargs)
            finally:
                with counter_lock:
                    active -= 1

        urls = {"http://thread-%02d.test:4173" % index
                for index in range(24)}
        with mock.patch.object(
                repair, "repair_codex_config", side_effect=observed_repair):
            with ThreadPoolExecutor(max_workers=12) as pool:
                list(pool.map(
                    lambda url: c.configure_codex(
                        None, url, self.home / "attacca.db", home=self.home),
                    sorted(urls)))

        self.assertEqual(maximum_active, 1)
        self.assert_canonical(urls)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        lock = c._codex_config_lock_path(self.config)
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

    def test_processes_mix_setup_repairs_switches_and_unrelated_locked_write(self):
        self.config.write_text(MIXED_DUPLICATE_FIXTURE)
        os.chmod(self.config, 0o600)
        gate = Path(self.temporary.name) / "go"
        urls = ["http://process-%02d.test:4173" % index
                for index in range(18)]
        actions = ["configure" if index % 2 else "switch"
                   for index in range(len(urls))]
        actions.append("unrelated")
        worker_urls = urls + [urls[0]]
        environment = dict(os.environ)
        environment.update({
            "HOME": str(self.home),
            "ATTACCA_OWNER": "",
            "ATTACCA_AUTOSTART": "0",
        })
        environment.pop("CODEX_HOME", None)
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", PROCESS_WORKER, str(SCRIPT), action,
                 str(self.home), url, str(gate)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=environment)
            for action, url in zip(actions, worker_urls)
        ]
        gate.write_text("go\n")
        outputs = [process.communicate(timeout=45) for process in processes]
        self.assertEqual(
            [process.returncode for process in processes],
            [0] * len(processes), outputs)

        parsed = self.assert_canonical(set(urls))
        self.assertEqual(
            parsed["concurrent_user_config"]["retained"], "yes")
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        self.assertEqual(
            stat.S_IMODE(c._codex_config_lock_path(
                self.config).stat().st_mode), 0o600)
        backup = self.config.with_name("config.toml.attacca-backup")
        self.assertTrue(backup.is_file())
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        # A final server switch must leave its machine source of truth and all
        # Codex TOML bytes consistent after the mixed workload has drained.
        final_url = "http://final-winner.test:4173"
        c.machine_server_set(final_url, home=self.home, validate=False)
        final = self.assert_canonical({final_url})
        self.assertEqual(
            final["concurrent_user_config"]["retained"], "yes")
        self.assertEqual(
            json.loads(c.machine_config_path(self.home).read_text())
            ["server_url"], final_url)

    def test_concurrent_first_install_is_private_and_has_one_winning_url(self):
        urls = {"http://first-install-%02d.test:4173" % index
                for index in range(20)}
        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(
                lambda url: c.configure_codex(
                    None, url, self.home / "attacca.db", home=self.home),
                sorted(urls)))
        parsed = tomllib.loads(self.config.read_text())
        self.assertIn(
            parsed["mcp_servers"]["attacca"]["env"]["ATTACCA_URL"], urls)
        self.assertEqual(self.config.read_text().count(
            "[mcp_servers.attacca]"), 1)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        self.assertEqual(
            stat.S_IMODE(c._codex_config_lock_path(
                self.config).stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
