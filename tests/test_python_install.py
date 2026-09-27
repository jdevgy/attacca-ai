"""Local-source installer: no download, safe URL wiring, native-tool parity."""

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import attacca
import install as local_install


ROOT = Path(__file__).resolve().parents[1]


class PythonInstallerUnitTests(unittest.TestCase):
    def test_canonical_origins(self):
        for value, expected in (
                ("http://127.0.0.1:4173/", "http://127.0.0.1:4173"),
                ("https://Example.COM:443", "https://example.com"),
                ("http://[::1]:4173", "http://[::1]:4173")):
            with self.subTest(value=value):
                self.assertEqual(local_install.server_origin(value), expected)

    def test_unsafe_or_ambiguous_origins_rejected(self):
        for value in ("", "ftp://example.com", "http://user:secret@example.com",
                      "http://example.com/path", "http://example.com/?query=1",
                      "http://example.com/#fragment", "http://bad$host:4173",
                      "http://`id`:4173", "http://$(id):4173",
                      'http://host";id:4173', "http://example.com:99999",
                      "http://example.com\n", " http://example.com",
                      "http://exa\tmple.com", "http://[broken" ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    local_install.server_origin(value)

    def test_payload_uses_local_snapshot_and_neutral_cwd(self):
        observed = {}

        def run(command, **kwargs):
            observed.update(kwargs)
            self.assertEqual(command, ["/test/sh"])
            archive_path = Path(kwargs["env"]["ATTACCA_INSTALL_ARCHIVE"])
            self.assertEqual(archive_path.parent, Path(kwargs["cwd"]))
            self.assertNotEqual(Path(kwargs["cwd"]), ROOT)
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(archive.read("install.py"),
                                 (ROOT / "install.py").read_bytes())
                self.assertEqual(archive.read("attacca.py"),
                                 (ROOT / "attacca.py").read_bytes())
                for name in ("plugin-mcp.json", ".codex-plugin/plugin.json"):
                    config = json.loads(archive.read(name))
                    for server in config["mcpServers"].values():
                        self.assertEqual(server["env"]["ATTACCA_URL"],
                                         "https://example.com:8443")
                self.assertFalse(set(archive.namelist()) & {
                    "AGENTS.md", "CLAUDE.md", ".attacca/project.json",
                    ".mcp.json", "attacca.db"})
            self.assertIn('BASE="https://example.com:8443"', kwargs["input"])
            self.assertIn("ATTACCA_INSTALL_ARCHIVE", kwargs["input"])
            return subprocess.CompletedProcess(command, 7)

        with mock.patch.object(local_install.shutil, "which", return_value="/test/sh"), \
                mock.patch.object(local_install.subprocess, "run", side_effect=run):
            self.assertEqual(local_install.main(["--url", "https://example.com:8443"]), 7)
        self.assertFalse(Path(observed["cwd"]).exists())

    def test_missing_shell_fails_before_preparing_payload(self):
        with mock.patch.object(local_install.shutil, "which", return_value=None), \
                mock.patch.object(attacca, "_capture_distribution_snapshot") as snapshot, \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as error:
                local_install.main([])
            self.assertEqual(error.exception.code, 2)
            snapshot.assert_not_called()

    def test_readme_keeps_short_start_and_separate_advanced_reference(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quick = readme.split("## Quick start (local server)", 1)[1].split(
            "## Everyday commands", 1)[0]
        self.assertLess(len(quick.split()), 300)
        self.assertIn("python3 install.py --url http://127.0.0.1:4173", quick)
        self.assertIn("curl -fsSL http://127.0.0.1:4173/install.sh | sh", quick)
        self.assertIn("python3 attacca.py auth reset-password USERNAME", readme)
        self.assertIn("attacca server set http://NEW_HOST:4173 --same-server", readme)
        self.assertEqual(readme.count("<details>"), 1)
        self.assertEqual(readme.count("</details>"), 1)
        self.assertLess(readme.index("<details>"), readme.index("## Architecture"))
        self.assertLess(readme.index("## REST API"), readme.index("</details>"))


@unittest.skipUnless(shutil.which("sh"), "POSIX shell required")
class PythonInstallerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="attacca-python-install-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for command in ("sh", "mktemp", "cp", "rm", "chmod", "mkdir", "ln", "sed"):
            path = shutil.which(command)
            if not path:
                self.skipTest("missing shell utility: " + command)
            (self.bin / command).symlink_to(path)
        (self.bin / "python3").symlink_to(sys.executable)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("ATTACCA_", "CODEX_", "CLAUDE_", "KIMI_"))}
        self.env.update({
            "HOME": str(self.home), "USERPROFILE": str(self.home),
            "PATH": str(self.bin), "PYTHONDONTWRITEBYTECODE": "1",
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_DATA_HOME": str(self.home / ".local/share"),
            "ATTACCA_DISABLE_WATCHER": "1", "ATTACCA_AUTOSTART": "0",
            "ATTACCA_DISABLE_SESSION_WAKE": "1",
            "TASK_TEST_COMMAND_LOG": str(self.root / "commands.txt"),
        })

    def run_install(self):
        # No server listens here. No curl/wget/native client from the real
        # machine is on PATH; all configuration belongs to this test's home.
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "install.py"),
             "--url", "http://127.0.0.1:9"],
            cwd=str(ROOT), env=self.env, capture_output=True, text=True,
            timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("local Attacca " + attacca.VERSION, result.stdout)
        self.assertNotIn("downloading attacca", result.stdout)
        installed = self.home / ".attacca/plugin/attacca"
        self.assertEqual((installed / "install.py").read_bytes(),
                         (ROOT / "install.py").read_bytes())
        self.assertEqual((installed / "attacca.py").read_bytes(),
                         (ROOT / "attacca.py").read_bytes())
        self.assertEqual((self.home / ".local/bin/attacca").resolve(),
                         installed / "attacca.py")
        return result

    def test_real_source_install_twice_without_curl_or_server(self):
        self.run_install()
        self.run_install()
        self.assertTrue((self.home / ".attacca/plugin-data/rollback/attacca/attacca.py").is_file())
        self.assertFalse((self.home / ".attacca/attacca.db").exists())

    def test_existing_database_is_neither_opened_nor_changed(self):
        database = self.home / ".attacca/attacca.db"
        database.parent.mkdir()
        sentinel = b"Installer must not even try to open this database.\n"
        database.write_bytes(sentinel)
        self.run_install()
        self.assertEqual(database.read_bytes(), sentinel)
        self.assertFalse(database.with_name("attacca.db-wal").exists())

    def test_same_installer_drives_native_clients(self):
        for client in ("claude", "codex", "kimi"):
            path = self.bin / client
            path.write_text('#!/bin/sh\nprintf "%s\\n" "' + client +
                            ' $*" >> "$TASK_TEST_COMMAND_LOG"\nexit 0\n')
            path.chmod(0o755)
        result = self.run_install()
        commands = (self.root / "commands.txt").read_text()
        self.assertIn("claude plugin install attacca@agentg --scope user", commands)
        self.assertIn("codex plugin add attacca@attacca-local", commands)
        self.assertIn("codex mcp get attacca", commands)
        self.assertIn("kimi code: native plugin installed/updated", result.stdout)
        self.assertTrue((self.home / ".codex/config.toml").is_file())


if __name__ == "__main__":
    unittest.main()
