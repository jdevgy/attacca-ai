"""poll_status: one compact per-request status (update-needed + new mail),
monotonic update checks (never offer a downgrade)."""
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


class PollStatusTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = c.connect(Path(self.tmp.name) / "t.db")
        repo = Path(self.tmp.name) / "repo"
        repo.mkdir()
        c.project_init(self.conn, "h", "human", path=str(repo),
                       project_id="p1", name="P1")

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _s(self, **kw):
        return c.poll_status(self.conn, "p1", **kw)

    def test_current_versions_are_up_to_date(self):
        r = self._s(plugin_version=c.VERSION, law_version=c.MANAGED_BLOCK_VERSION)
        self.assertTrue(r["update"]["up_to_date"])
        self.assertFalse(r["update"]["binary_update_available"])
        self.assertFalse(r["update"]["managed_law_update_available"])

    def test_behind_flags_both_updates(self):
        r = self._s(plugin_version="0.0.1",
                    law_version=c.MANAGED_BLOCK_VERSION - 1)
        self.assertTrue(r["update"]["binary_update_available"])
        self.assertTrue(r["update"]["managed_law_update_available"])
        self.assertFalse(r["update"]["up_to_date"])

    def test_newer_local_law_is_not_a_downgrade(self):
        r = self._s(law_version=c.MANAGED_BLOCK_VERSION + 5)
        self.assertFalse(r["update"]["managed_law_update_available"])

    def test_no_version_means_no_update_claim(self):
        r = self._s()
        self.assertFalse(r["update"]["binary_update_available"])
        self.assertFalse(r["update"]["managed_law_update_available"])
        self.assertEqual(r["update"]["server_version"], c.VERSION)

    def test_mail_counts_for_actor(self):
        c.agent_register(self.conn, "p1", "p1.director.claude", "agent",
                         role="director", runtime="claude")
        c.agent_register(self.conn, "p1", "p1.worker.kimi", "agent",
                         role="worker", runtime="kimi")
        c.room_send(self.conn, "p1", "p1.worker.kimi", "agent",
                    "hey @p1.director.claude look at this", msg_type="chat")
        r = self._s(actor_id="p1.director.claude", actor_type="agent")
        self.assertIsNotNone(r["mail"])
        self.assertIn("unread_addressed", r["mail"])
        self.assertIn("has_new_mail", r["mail"])
        # no actor -> no mail section
        self.assertIsNone(self._s()["mail"])

    def test_cursor_tracks_event_head(self):
        r = self._s()
        self.assertIn("event_seq", r["cursor"])
        self.assertGreaterEqual(r["cursor"]["event_seq"], 0)


if __name__ == "__main__":
    unittest.main()
