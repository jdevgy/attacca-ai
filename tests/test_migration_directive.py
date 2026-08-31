"""Attacca project-migration directive: server-side (bundled), retrievable, and
source detection for the setup migration option. Not part of the managed block.
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


class MigrationDirectiveTestCase(unittest.TestCase):
    def test_directive_is_versioned_and_complete(self):
        d = c.migration_directive()
        self.assertEqual(d["version"], c.PROJECT_MIGRATION_DIRECTIVE_VERSION)
        self.assertIn("Cloud Context", d["directive"])
        self.assertIn("rule_create", d["directive"])
        self.assertIn("archive", d["directive"].lower())
        self.assertEqual(d["authority_order"][0],
                         "latest explicit owner directive")

    def test_directive_kept_out_of_managed_block(self):
        # The migration directive must NOT be embedded in the managed
        # AGENTS.md/CLAUDE.md block (keeps that block small).
        block = c.managed_instruction_block("p", None)
        self.assertNotIn("Attacca Project Migration Directive", block)
        self.assertIn("bundled with the Attacca binary",
                      c.migration_directive()["storage"])

    def test_detects_common_history_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "docs" / "LOG.md").write_text("# log\n")
            (root / "CHANGELOG.md").write_text("# changes\n")
            rels = {s["rel"] for s in c.detect_migration_sources(str(root))}
            self.assertIn("docs/LOG.md", rels)
            self.assertIn("CHANGELOG.md", rels)

    def test_no_sources_is_empty_not_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(c.detect_migration_sources(tmp), [])
        self.assertEqual(c.detect_migration_sources(None), [])

    def test_directive_includes_detected_sources_for_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "LOG.md").write_text("# log\n")
            d = c.migration_directive(tmp)
            self.assertIn("LOG.md", {s["rel"] for s in d["migration_sources"]})


class MigrationDirectiveHttpTestCase(unittest.TestCase):
    """Served token-free over REST for setup clients."""

    def setUp(self):
        from tests.test_http import ServerFixture
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        c.connect(self.db).close()
        self.server = ServerFixture(self.db)

    def tearDown(self):
        self.server.stop()
        self.tmp.cleanup()

    def test_rest_endpoint_serves_directive(self):
        status, payload, _ = self.server.request(
            "GET", "/v1/migration-directive")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["version"],
                         c.PROJECT_MIGRATION_DIRECTIVE_VERSION)
        self.assertIn("directive", payload)
        self.assertIn("authority_order", payload)


if __name__ == "__main__":
    unittest.main()
