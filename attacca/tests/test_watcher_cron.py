"""Setup installs an idempotent per-minute update cron (project core directive).

Attacca setup must install a crontab entry that pings for updates every minute,
independently of whether a coding client is open. ensure_watcher_cron is that
install: idempotent per checkout root, non-destructive to unrelated entries,
and fail-soft where cron is unavailable.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

os.environ["ATTACCA_OWNER"] = ""
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("attacca", ROOT / "attacca.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def _fake_crontab(store):
    """A stand-in `crontab` binary backed by a file: `-l` prints it (rc 1 when
    absent), `-` overwrites it from stdin."""
    path = Path(store).parent / "crontab"
    path.write_text(
        "#!/usr/bin/env bash\n"
        'if [ "$1" = "-l" ]; then [ -f "%s" ] && cat "%s" || exit 1; exit 0; fi\n'
        'if [ "$1" = "-" ]; then cat > "%s"; exit 0; fi\n'
        "exit 2\n" % (store, store, store))
    path.chmod(0o755)
    return str(path)


class WatcherCronTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = str(Path(self.tmp.name) / "crontab.store")
        self.fake = _fake_crontab(self.store)
        self.root = str(Path(self.tmp.name) / "repo")
        Path(self.root).mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def _lines(self):
        p = Path(self.store)
        return p.read_text().splitlines() if p.exists() else []

    def _markers(self):
        return [ln for ln in self._lines() if "attacca-watcher" in ln]

    def test_install_then_idempotent_then_refresh(self):
        r1 = c.ensure_watcher_cron(self.root, url="http://h:1",
                                   crontab_bin=self.fake)
        self.assertEqual(r1["status"], "installed")
        self.assertEqual(len(self._markers()), 1)
        line = self._markers()[0]
        self.assertTrue(line.startswith("* * * * *"))
        self.assertIn("--watcher-ensure", line)
        self.assertIn("--cwd", line)

        r2 = c.ensure_watcher_cron(self.root, url="http://h:1",
                                   crontab_bin=self.fake)
        self.assertEqual(r2["status"], "already")
        self.assertEqual(len(self._markers()), 1)

        r3 = c.ensure_watcher_cron(self.root, url="http://h:2",
                                   crontab_bin=self.fake)
        self.assertEqual(r3["status"], "refreshed")
        self.assertEqual(len(self._markers()), 1)
        self.assertIn("http://h:2", self._markers()[0])

    def test_preserves_unrelated_crontab_lines(self):
        Path(self.store).write_text("0 3 * * * /usr/bin/backup\n")
        c.ensure_watcher_cron(self.root, crontab_bin=self.fake)
        text = Path(self.store).read_text()
        self.assertIn("/usr/bin/backup", text)
        self.assertEqual(len(self._markers()), 1)

    def test_two_roots_get_separate_entries(self):
        root2 = str(Path(self.tmp.name) / "repo2")
        Path(root2).mkdir()
        c.ensure_watcher_cron(self.root, crontab_bin=self.fake)
        c.ensure_watcher_cron(root2, crontab_bin=self.fake)
        self.assertEqual(len(self._markers()), 2)

    def test_missing_crontab_fails_soft(self):
        r = c.ensure_watcher_cron(self.root,
                                  crontab_bin="/nonexistent/crontab-xyz")
        self.assertFalse(r["ok"])
        self.assertIn(r["status"], ("error", "unavailable"))

    def test_no_crontab_binary_reports_unavailable(self):
        r = c.ensure_watcher_cron(self.root, crontab_bin=None)
        # Environments with a real crontab will install; those without report
        # unavailable. Either way the call never raises.
        self.assertIn("status", r)


if __name__ == "__main__":
    unittest.main()
