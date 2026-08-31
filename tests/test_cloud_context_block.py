"""Cloud Context -> AGENTS.md/CLAUDE.md marker block: versioned, sha-stamped,
auto-refreshed in place, preserving all content outside the markers."""
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


class CloudContextBlockTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "t.db"
        self.conn = c.connect(self.db)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        c.project_init(self.conn, "h", "human", path=str(self.repo),
                       project_id="p1", name="P1")
        c.agent_register(self.conn, "p1", "p1.director.claude", "agent",
                         role="director", runtime="claude")
        (self.repo / "AGENTS.md").write_text("# Mine\n\nLocal note.\n")

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _set(self, text):
        c.cloud_context_set(self.conn, "p1", "p1.director.claude", "agent", text)

    def _refresh(self, create=False):
        return c.refresh_cloud_context_block(
            self.conn, "p1", str(self.repo), files=["AGENTS.md"], create=create)

    def test_not_forced_without_opt_in(self):
        self._set("# Ctx")
        r = self._refresh(create=False)
        self.assertEqual(r["files"][0]["status"], "absent")
        self.assertNotIn("ATTACCA_CLOUD_CONTEXT",
                         (self.repo / "AGENTS.md").read_text())

    def test_create_then_current_then_updated_preserving_local(self):
        self._set("# Ctx\nProd only.")
        self.assertEqual(self._refresh(create=True)["files"][0]["status"],
                         "created")
        self.assertEqual(self._refresh(create=True)["files"][0]["status"],
                         "current")
        self._set("# Ctx v2\nChanged.")
        # once the block exists it refreshes even without create
        self.assertEqual(self._refresh(create=False)["files"][0]["status"],
                         "updated")
        text = (self.repo / "AGENTS.md").read_text()
        self.assertIn("Local note.", text)          # local content preserved
        self.assertIn("Ctx v2", text)               # refreshed body
        present, ver, sha = c.cloud_context_block_present(text)
        self.assertTrue(present)
        self.assertEqual(ver, "2")

    def test_sha_in_cloud_context_and_block(self):
        self._set("hello")
        cc = c.cloud_context_get(self.conn, "p1")["cloud_context"]
        self.assertIn("sha256", cc)
        block = c.cloud_context_block(cc, "p1")
        self.assertIn("sha=%s" % cc["sha256"][:16], block)
        self.assertIn("ATTACCA_CLOUD_CONTEXT:END", block)


if __name__ == "__main__":
    unittest.main()
