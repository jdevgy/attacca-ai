"""Regression checks for the repository's package-root layout."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class RepositoryRootContractTest(unittest.TestCase):
    def test_runtime_and_distribution_inputs_live_at_repository_root(self):
        self.assertTrue((ROOT / "attacca.py").is_file())
        self.assertTrue((ROOT / "plugin-mcp.json").is_file())
        self.assertTrue((ROOT / "hooks" / "session_start.py").is_file())
        self.assertFalse((ROOT / "attacca" / "attacca.py").exists())

    def test_devcontainer_starts_server_from_repository_root(self):
        script = (ROOT / ".devcontainer" / "start-attacca.sh").read_text()
        self.assertIn('cd "$ROOT" || exit 1', script)
        self.assertNotIn('cd "$ROOT/attacca"', script)
        self.assertIn("python3 attacca.py", script)


if __name__ == "__main__":
    unittest.main()
