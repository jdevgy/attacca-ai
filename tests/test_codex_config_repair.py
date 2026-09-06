"""Regression tests for Codex TOML repair during repeated Attacca installs."""

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None
import unittest
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "attacca.py"
REPAIR_SCRIPT = ROOT / "tools" / "repair_codex_config.py"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c = load_module("attacca_codex_repair_core", SCRIPT)
repair = load_module("attacca_codex_repair_tool", REPAIR_SCRIPT)


# The stale descendant is deliberately line 14, matching the live Codex
# startup failure: duplicate [mcp_servers.attacca.env].
LINE_14_DUPLICATE_ENV = """# user comment must survive
model = "gpt-5"

[projects."/work/app"]
trust_level = "trusted"

[mcp_servers.attacca]
command = "python3"
args = ["/old/attacca.py", "connect"]
env = { ATTACCA_ACTOR = "codex", ATTACCA_URL = "http://old:4173" }

# stale descendant survived prior installer replacement
# Codex reports the next line as the duplicate key
[mcp_servers.attacca.env]
ATTACCA_ACTOR = "codex"
ATTACCA_URL = "http://older:4173"

[mcp_servers.other]
command = "other"
"""


class StandaloneCodexRepairTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "codex" / "config.toml"
        self.config.parent.mkdir()

    @unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
    def test_exact_line_14_duplicate_env_is_repaired_and_idempotent(self):
        self.assertEqual(
            LINE_14_DUPLICATE_ENV.splitlines()[13],
            "[mcp_servers.attacca.env]")
        with self.assertRaises(tomllib.TOMLDecodeError) as raised:
            tomllib.loads(LINE_14_DUPLICATE_ENV)
        self.assertIn("line 14", str(raised.exception))
        self.config.write_text(LINE_14_DUPLICATE_ENV)
        os.chmod(self.config, 0o640)

        first = repair.repair_codex_config(
            self.config, "http://attacca-host:4173", "/stable/attacca.py")
        first_bytes = self.config.read_bytes()
        backup_bytes = Path(first["backup"]).read_bytes()
        parsed = tomllib.loads(first_bytes.decode())

        self.assertTrue(first["changed"])
        self.assertEqual(first["validator"], "tomllib")
        self.assertEqual(backup_bytes, LINE_14_DUPLICATE_ENV.encode())
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o640)
        self.assertEqual(first_bytes.decode().count(
            "[mcp_servers.attacca]"), 1)
        self.assertNotIn("[mcp_servers.attacca.env]", first_bytes.decode())
        self.assertIn("# user comment must survive", first_bytes.decode())
        self.assertEqual(parsed["model"], "gpt-5")
        self.assertEqual(parsed["projects"]["/work/app"]["trust_level"],
                         "trusted")
        self.assertEqual(parsed["mcp_servers"]["other"]["command"], "other")
        self.assertEqual(parsed["mcp_servers"]["attacca"]["args"],
                         ["/stable/attacca.py", "connect"])
        self.assertEqual(parsed["mcp_servers"]["attacca"]["env"], {
            "ATTACCA_ACTOR": "codex",
            "ATTACCA_URL": "http://attacca-host:4173",
        })

        second = repair.repair_codex_config(
            self.config, "http://attacca-host:4173", "/stable/attacca.py")
        third = repair.repair_codex_config(
            self.config, "http://attacca-host:4173", "/stable/attacca.py")
        self.assertFalse(second["changed"])
        self.assertFalse(third["changed"])
        self.assertEqual(self.config.read_bytes(), first_bytes)
        self.assertEqual(Path(first["backup"]).read_bytes(), backup_bytes)

    @unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
    def test_all_root_descendant_quoted_and_partial_tables_are_removed(self):
        fixture = """# preserved preamble
[mcp_servers.attacca.env]
ATTACCA_URL = "http://first"

[mcp_servers.other]
command = "keep"
# this unrelated section comment survives

[mcp_servers."attacca"]
command = "stale"

["mcp_servers".attacca.headers]
X = "stale"

[workspace]
name = "keep-me"

[mcp_servers.attacca]
command = "duplicate"
"""
        self.config.write_text(fixture)
        result = repair.repair_codex_config(
            self.config, "https://sync.example.test/base/", "/opt/a b/attacca.py")
        text = self.config.read_text()
        parsed = tomllib.loads(text)
        paths = [
            repair._table_header_path(line) for line in text.splitlines()
            if repair._is_attacca_table(repair._table_header_path(line))
        ]
        self.assertTrue(result["changed"])
        self.assertEqual(paths, [repair.ATTACCA_TABLE_PREFIX])
        self.assertIn("# preserved preamble", text)
        self.assertIn("# this unrelated section comment survives", text)
        self.assertEqual(parsed["workspace"]["name"], "keep-me")
        self.assertEqual(parsed["mcp_servers"]["other"]["command"], "keep")
        self.assertEqual(
            parsed["mcp_servers"]["attacca"]["args"],
            ["/opt/a b/attacca.py", "connect"])
        self.assertEqual(
            parsed["mcp_servers"]["attacca"]["env"]["ATTACCA_URL"],
            "https://sync.example.test/base")

    # The "original left untouched" message comes from the tomllib
    # validation branch; the structural fallback raises a different error.
    @unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
    def test_invalid_unrelated_toml_is_never_backed_up_or_replaced(self):
        fixture = """[mcp_servers.attacca]
command = "stale"

[unrelated]
broken = [
"""
        self.config.write_text(fixture)
        with self.assertRaisesRegex(
                repair.CodexConfigRepairError, "original left untouched"):
            repair.repair_codex_config(
                self.config, "http://host:4173", "/stable/attacca.py")
        self.assertEqual(self.config.read_text(), fixture)
        self.assertFalse(Path(
            str(self.config) + ".attacca-backup").exists())

    def test_symlinked_config_is_refused_without_touching_target(self):
        actual = self.root / "actual.toml"
        actual.write_text('model = "keep"\n')
        self.config.symlink_to(actual)
        with self.assertRaisesRegex(
                repair.CodexConfigRepairError, "refusing to replace symlinked"):
            repair.repair_codex_config(
                self.config, "http://host:4173", "/stable/attacca.py")
        self.assertEqual(actual.read_text(), 'model = "keep"\n')

    def test_unsafe_backup_symlink_is_refused_before_config_write(self):
        self.config.write_text(LINE_14_DUPLICATE_ENV)
        protected = self.root / "protected"
        protected.write_text("do not overwrite")
        Path(str(self.config) + ".attacca-backup").symlink_to(protected)
        with self.assertRaisesRegex(
                repair.CodexConfigRepairError, "unsafe symlinked Codex backup"):
            repair.repair_codex_config(
                self.config, "http://host:4173", "/stable/attacca.py")
        self.assertEqual(self.config.read_text(), LINE_14_DUPLICATE_ENV)
        self.assertEqual(protected.read_text(), "do not overwrite")

    @unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
    def test_standalone_cli_repairs_private_new_config_and_reports_noop(self):
        self.config.unlink(missing_ok=True)
        command = [
            sys.executable, str(REPAIR_SCRIPT),
            "--config", str(self.config),
            "--server-url", "http://host:4173",
            "--script-path", "/stable/attacca.py",
        ]
        first = subprocess.run(command, capture_output=True, text=True,
                               timeout=15)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("config repaired", first.stdout)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        first_bytes = self.config.read_bytes()
        second = subprocess.run(command, capture_output=True, text=True,
                                timeout=15)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("already canonical", second.stdout)
        self.assertEqual(self.config.read_bytes(), first_bytes)
        self.assertEqual(
            tomllib.loads(first_bytes.decode())["mcp_servers"]["attacca"]
            ["env"]["ATTACCA_URL"], "http://host:4173")

    @unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
    def test_parallel_identical_repairs_leave_one_entry_and_exact_backup(self):
        self.config.write_text(LINE_14_DUPLICATE_ENV)

        def run(_):
            return repair.repair_codex_config(
                self.config, "http://host:4173", "/stable/attacca.py")

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(run, range(24)))
        parsed = tomllib.loads(self.config.read_text())
        self.assertEqual(self.config.read_text().count(
            "[mcp_servers.attacca]"), 1)
        self.assertEqual(parsed["mcp_servers"]["attacca"]["env"]
                         ["ATTACCA_URL"], "http://host:4173")
        self.assertEqual(
            Path(str(self.config) + ".attacca-backup").read_text(),
            LINE_14_DUPLICATE_ENV)
        self.assertTrue(any(item["changed"] for item in results))


class InstallerCodexRepairIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
    def test_real_served_installer_is_warning_clean_and_idempotent_three_times(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            codex_home = home / ".codex"
            config = codex_home / "config.toml"
            fake_bin = root / "bin"
            codex_home.mkdir(parents=True)
            fake_bin.mkdir()
            config.write_text(LINE_14_DUPLICATE_ENV)

            # The fake CLI makes the test exercise the complete Codex branch
            # without touching the developer's real plugin cache or config.
            fake_codex = fake_bin / "codex"
            fake_codex.write_text("#!/bin/sh\nexit 0\n")
            fake_codex.chmod(0o755)

            server = c.AttaccaServer(
                ("127.0.0.1", 0), root / "attacca.db", auth=False)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = "http://127.0.0.1:%d" % server.server_address[1]
            env = dict(os.environ)
            env.update({
                "HOME": str(home),
                "CODEX_HOME": str(codex_home),
                "PATH": os.pathsep.join((
                    str(fake_bin), str(Path(sys.executable).parent),
                    "/usr/local/bin", "/usr/bin", "/bin")),
                "PYTHONWARNINGS": "error::ResourceWarning",
            })
            try:
                with urllib.request.urlopen(
                        base + "/install.sh", timeout=10) as response:
                    installer = response.read().decode()
                snapshots = []
                for run_number in range(1, 4):
                    completed = subprocess.run(
                        ["sh"], input=installer, text=True, cwd=root, env=env,
                        capture_output=True, timeout=60)
                    self.assertEqual(
                        completed.returncode, 0,
                        "installer run %d failed:\n%s\n%s" %
                        (run_number, completed.stdout, completed.stderr))
                    self.assertEqual(
                        completed.stderr, "",
                        "installer run %d emitted warnings" % run_number)
                    snapshots.append(config.read_bytes())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

            self.assertEqual(snapshots[0], snapshots[1])
            self.assertEqual(snapshots[1], snapshots[2])
            text = snapshots[-1].decode()
            parsed = tomllib.loads(text)
            self.assertEqual(text.count("[mcp_servers.attacca]"), 1)
            self.assertNotIn("[mcp_servers.attacca.env]", text)
            self.assertEqual(
                parsed["mcp_servers"]["attacca"]["env"]["ATTACCA_URL"],
                base)
            self.assertEqual(
                parsed["mcp_servers"]["other"]["command"], "other")
            self.assertEqual(
                Path(str(config) + ".attacca-backup").read_text(),
                LINE_14_DUPLICATE_ENV)

            installed = home / ".attacca" / "plugin" / "attacca"
            hook_manifest = json.loads(
                (installed / "hooks" / "hooks.json").read_text())
            hook_commands = {
                hook["command"]
                for groups in hook_manifest["hooks"].values()
                for group in groups
                for hook in group["hooks"]
            }
            self.assertEqual(hook_commands, {
                'python3 "$HOME/.attacca/plugin/attacca/hooks/session_start.py"'
            })
            self.assertFalse(any("plugins/cache" in command
                                 for command in hook_commands))

    @unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
    def test_configure_codex_repairs_then_survives_three_identical_reruns(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            config = home / ".codex" / "config.toml"
            config.parent.mkdir(parents=True)
            config.write_text(LINE_14_DUPLICATE_ENV)

            snapshots = []
            for _ in range(3):
                returned = c.configure_codex(
                    None, "http://host:4173", Path(temporary) / "db",
                    home=home)
                self.assertEqual(returned, str(config))
                snapshots.append(config.read_bytes())
            self.assertEqual(snapshots[0], snapshots[1])
            self.assertEqual(snapshots[1], snapshots[2])
            parsed = tomllib.loads(snapshots[-1].decode())
            self.assertEqual(snapshots[-1].decode().count(
                "[mcp_servers.attacca]"), 1)
            self.assertEqual(parsed["mcp_servers"]["other"]["command"],
                             "other")
            self.assertEqual(parsed["mcp_servers"]["attacca"]["env"]
                             ["ATTACCA_URL"], "http://host:4173")
            self.assertEqual(
                Path(str(config) + ".attacca-backup").read_text(),
                LINE_14_DUPLICATE_ENV)

            c.configure_codex(
                None, "http://new-host:4173", Path(temporary) / "db",
                home=home)
            updated = tomllib.loads(config.read_text())
            self.assertEqual(config.read_text().count(
                "[mcp_servers.attacca]"), 1)
            self.assertEqual(updated["mcp_servers"]["attacca"]["env"]
                             ["ATTACCA_URL"], "http://new-host:4173")

    @unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
    def test_configure_codex_repairs_descendant_only_partial_block(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            config = home / ".codex" / "config.toml"
            config.parent.mkdir(parents=True)
            config.write_text(
                '# keep\n[mcp_servers.attacca.env]\nOLD = "1"\n\n'
                '[mcp_servers.keep]\ncommand = "yes"\n')
            c.configure_codex(
                None, "http://host:4173", Path(temporary) / "db",
                home=home)
            parsed = tomllib.loads(config.read_text())
            self.assertEqual(parsed["mcp_servers"]["keep"]["command"], "yes")
            self.assertNotIn("OLD", parsed["mcp_servers"]["attacca"]["env"])
            self.assertEqual(config.read_text().count(
                "[mcp_servers.attacca]"), 1)

    def test_repair_helper_is_in_the_downloadable_plugin_manifest(self):
        self.assertIn("tools/repair_codex_config.py", c.PLUGIN_FILES)


if __name__ == "__main__":
    unittest.main()
