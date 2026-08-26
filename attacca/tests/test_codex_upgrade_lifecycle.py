"""Regression tests for live Codex hooks across plugin replacement."""

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c = _load("attacca_upgrade_contract", ROOT / "attacca.py")
compat = _load("attacca_codex_hook_compat_test",
               ROOT / "codex_hook_compat.py")


class CodexUpgradeLifecycleTestCase(unittest.TestCase):
    def _stable_plugin(self, parent):
        stable = Path(parent) / "stable" / "attacca"
        (stable / "hooks").mkdir(parents=True)
        (stable / "hooks" / "session_start.py").write_text(
            "print('stable-hook-ran')\n", encoding="utf-8")
        shutil.copy2(ROOT / "codex_hook_compat.py",
                     stable / "codex_hook_compat.py")
        return stable

    def _cached_hook(self, cache_root, version):
        hook = Path(cache_root) / version / "hooks" / "session_start.py"
        hook.parent.mkdir(parents=True)
        hook.write_text("print('old-hook-ran')\n", encoding="utf-8")
        return hook

    def test_snapshot_survives_cache_deletion_and_restores_executable_hook(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stable = self._stable_plugin(root)
            cache = root / "codex" / "plugins" / "cache" / \
                "attacca-local" / "attacca"
            old_version = "0.4.3+codex.old-session"
            self._cached_hook(cache, old_version)
            state = root / "state" / "cache-compat.json"

            self.assertEqual(
                compat.snapshot_codex_cache(cache, state), [old_version])
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)
            shutil.rmtree(cache)

            # The registry is outside Codex's replaceable cache, so a later
            # run still knows what an interrupted prior run removed.
            versions = compat.snapshot_codex_cache(cache, state)
            self.assertEqual(versions, [old_version])
            result = compat.restore_codex_cache(cache, stable, versions)
            restored = cache / old_version
            self.assertEqual(result["repaired"], [old_version])
            self.assertTrue(restored.is_symlink())
            self.assertEqual(restored.resolve(), stable.resolve())
            ran = subprocess.run(
                [sys.executable, str(restored / "hooks" / "session_start.py")],
                capture_output=True, text=True, check=True)
            self.assertEqual(ran.stdout.strip(), "stable-hook-ran")

    def test_restore_is_idempotent_and_never_overwrites_invalid_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stable = self._stable_plugin(root)
            cache = root / "cache"
            version = "0.4.3+codex.live"
            first = compat.restore_codex_cache(cache, stable, [version])
            second = compat.restore_codex_cache(cache, stable, [version])
            self.assertEqual(first["repaired"], [version])
            self.assertEqual(second["present"], [version])

            invalid = cache / "0.4.2+codex.partial"
            invalid.write_text("do not replace", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,
                                        "refusing to replace"):
                compat.restore_codex_cache(
                    cache, stable, ["0.4.2+codex.partial"])
            self.assertEqual(invalid.read_text(encoding="utf-8"),
                             "do not replace")

    def test_rendered_installer_restores_cache_deleted_by_fake_codex(self):
        script = c.INSTALL_SH_TEMPLATE.format(
            base="http://127.0.0.1:1", version=c.VERSION,
            required_files=repr(c.PLUGIN_FILES))
        start = script.index("# Codex CLI: add the native setup skill")
        end = script.index("# Do not claim Codex works", start)
        codex_block = script[start:end]
        self.assertIn("codex_hook_compat.py", c.PLUGIN_FILES)
        self.assertLess(codex_block.index(" snapshot "),
                        codex_block.index("plugin marketplace remove"))
        self.assertLess(codex_block.index("trap 'attacca_restore_codex_cache"),
                        codex_block.index("plugin marketplace remove"))
        self.assertGreater(codex_block.index("attacca_restore_codex_cache; then"),
                           codex_block.index("codex plugin add"))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            codex_home = home / ".codex"
            stable = self._stable_plugin(root)
            cache = codex_home / "plugins" / "cache" / \
                "attacca-local" / "attacca"
            old_version = "0.4.3+codex.open-thread"
            self._cached_hook(cache, old_version)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_codex = fake_bin / "codex"
            fake_codex.write_text(
                "#!/bin/sh\n"
                "cache=\"$CODEX_HOME/plugins/cache/attacca-local/attacca\"\n"
                "if [ \"$1 $2 $3\" = \"plugin marketplace remove\" ]; then\n"
                "  rm -rf \"$cache\"\n"
                "elif [ \"$1 $2\" = \"plugin add\" ]; then\n"
                "  mkdir -p \"$cache/0.4.4+codex.new/hooks\"\n"
                "  cp \"$ATTACCA_TEST_STABLE/hooks/session_start.py\" "
                "\"$cache/0.4.4+codex.new/hooks/session_start.py\"\n"
                "fi\n"
                "exit 0\n", encoding="utf-8")
            fake_codex.chmod(0o755)
            env = dict(os.environ)
            env.update({
                "HOME": str(home),
                "CODEX_HOME": str(codex_home),
                "ATTACCA_TEST_STABLE": str(stable),
                "PATH": str(fake_bin) + os.pathsep + env.get("PATH", ""),
            })
            run = subprocess.run(
                ["sh", "-c", "set -e\nDEST=\"$ATTACCA_TEST_STABLE\"\n" +
                 codex_block], env=env, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            restored = cache / old_version
            self.assertTrue(restored.is_symlink(), run.stdout)
            self.assertEqual(restored.resolve(), stable.resolve())
            self.assertTrue(
                (cache / "0.4.4+codex.new" / "hooks" /
                 "session_start.py").is_file())
            state = home / ".attacca" / "plugin-data" / \
                "codex-attacca" / "cache-compat.json"
            self.assertEqual(
                json.loads(state.read_text(encoding="utf-8"))[
                    "cache_versions"], [old_version])

    def test_distributed_hook_uses_stable_non_cache_command(self):
        manifest = json.loads(
            (ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        commands = [
            hook["command"]
            for groups in manifest["hooks"].values()
            for group in groups for hook in group["hooks"]
        ]
        self.assertTrue(commands)
        self.assertEqual(set(commands), {
            'python3 "$HOME/.attacca/plugin/attacca/hooks/session_start.py"'})
        self.assertTrue(all("plugins/cache" not in item for item in commands))


if __name__ == "__main__":
    unittest.main()
