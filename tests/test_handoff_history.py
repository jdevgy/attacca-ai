"""Handoff history: past versions viewable (CLI + REST + panel).

The project keeps two independent append-only histories: the Director-governed
shared project handoff and each exact AI identity's own handoff.
"""
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
        c.update_identity_handoff(self.conn, "p1", self.actor, "agent", obj)

    def _update_shared(self, obj):
        c.update_handoff(self.conn, "p1", self.actor, "agent", obj)

    def _history(self, limit):
        return c.identity_handoff_history(
            self.conn, "p1", limit=limit, actor_id=self.actor,
            actor_type="agent")

    def _shared_history(self, limit):
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

    def test_shared_history_is_project_wide_and_has_no_owner(self):
        self._update({"objective": "identity only"})
        self._update_shared({"objective": "shared v1"})
        self._update_shared({"what_changed": "shared v2"})
        h = self._shared_history(10)
        self.assertEqual(h["handoff_scope"], "project")
        self.assertNotIn("handoff_actor", h)
        self.assertEqual([item["version"] for item in h["versions"]], [2, 1])
        self.assertEqual(h["versions"][0]["content"]["objective"],
                         "shared v1")
        self.assertEqual(h["versions"][0]["updated_by"], self.actor)
        # The identity history is untouched by the shared writes.
        self.assertEqual(
            [item["version"] for item in self._history(10)["versions"]], [1])
        with self.assertRaisesRegex(
                c.AttaccaError, "identity_handoff_history"):
            c.handoff_history(
                self.conn, "p1", limit=10, actor_id=self.actor,
                actor_type="agent", target_actor_id=self.actor)

    def test_limit_respected(self):
        for i in range(5):
            self._update({"objective": "goal %d" % i})
        self.assertLessEqual(len(self._history(2)["versions"]), 2)
        for i in range(5):
            self._update_shared({"objective": "shared goal %d" % i})
        self.assertLessEqual(len(self._shared_history(2)["versions"]), 2)


if __name__ == "__main__":
    unittest.main()
