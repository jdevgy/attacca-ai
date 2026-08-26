"""Server-authoritative managed-law: the server serves the current law CONTENT
so clients can apply it without a plugin/binary reinstall."""
import importlib.util, os, unittest
from pathlib import Path
os.environ["ATTACCA_OWNER"] = ""
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("attacca", ROOT / "attacca.py")
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


class ManagedLawPayloadTestCase(unittest.TestCase):
    def test_serves_current_law_content(self):
        p = c.managed_law_payload("agentg", None)
        self.assertEqual(p["version"], c.MANAGED_BLOCK_VERSION)
        self.assertEqual(p["server_software_version"], c.VERSION)
        self.assertTrue(p["block"].startswith("<!-- MANAGED_ATTACCA:BEGIN"))
        self.assertIn("MANAGED_ATTACCA:END", p["block"])
        self.assertTrue(p["sha256"])

    def test_default_project_uses_template(self):
        p = c.managed_law_payload()
        self.assertIn("v=%d" % c.MANAGED_BLOCK_VERSION, p["block"])


if __name__ == "__main__":
    unittest.main()
