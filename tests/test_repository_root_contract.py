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

    def test_public_packaging_does_not_require_personal_workspace_configuration(self):
        import json
        manifest = json.loads((ROOT / ".codex-plugin/plugin.json").read_text())
        self.assertEqual(manifest["mcpServers"]["attacca"]["env"]["ATTACCA_ACTOR"],
                         "codex")
        ignores = (ROOT / ".gitignore").read_text().splitlines()
        for private in ("AGENTS.md", "CLAUDE.md", ".mcp.json", ".devcontainer/"):
            self.assertIn(private, ignores)


if __name__ == "__main__":
    unittest.main()
