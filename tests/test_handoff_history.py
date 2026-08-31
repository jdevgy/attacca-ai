"""Handoff history: past versions viewable (CLI + REST + panel)."""
import importlib.util, os, unittest, tempfile
from pathlib import Path
os.environ["ATTACCA_OWNER"] = ""
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("attacca", ROOT / "attacca.py")
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


class HandoffHistoryTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = c.connect(Path(self.tmp.name) / "t.db")
        repo = Path(self.tmp.name) / "repo"; repo.mkdir()
        c.project_init(self.conn, "h", "human", path=str(repo),
                       project_id="p1", name="P1")
        c.agent_register(self.conn, "p1", "p1.director.claude", "agent",
                         role="director", runtime="claude")
        self.actor = "p1.director.claude"

    def tearDown(self):
        self.conn.close(); self.tmp.cleanup()

    def _update(self, obj):
        c.update_handoff(self.conn, "p1", self.actor, "agent", obj)

    def _history(self, limit):
        return c.handoff_history(
            self.conn, "p1", limit=limit, actor_id=self.actor,
            actor_type="agent")

    def test_history_returns_all_versions_newest_first(self):
        self._update({"objective": "v1 goal"})
        self._update({"objective": "v2 goal"})
        self._update({"what_changed": "did stuff"})
        h = self._history(10)
        self.assertEqual(h["handoff_actor"], self.actor)
        self.assertGreaterEqual(len(h["versions"]), 3)
        self.assertGreater(h["versions"][0]["version"],
                           h["versions"][-1]["version"])
        self.assertEqual(h["versions"][0]["content"].get("what_changed"),
                         "did stuff")

    def test_limit_respected(self):
        for i in range(5):
            self._update({"objective": "goal %d" % i})
        self.assertLessEqual(len(self._history(2)["versions"]), 2)


if __name__ == "__main__":
    unittest.main()
