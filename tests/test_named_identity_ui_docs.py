"""Named identity panel and guided-setup contracts."""

import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "web" / "admin.html"


class NamedIdentityUiDocsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.panel = PANEL.read_text(encoding="utf-8")

    def test_identity_helpers_prefer_friendly_name_and_short_address(self):
        match = re.search(
            r"// TESTABLE_NAMED_IDENTITY_HELPERS:BEGIN\n(?P<body>.*?)"
            r"\n\s*// TESTABLE_NAMED_IDENTITY_HELPERS:END",
            self.panel,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        program = "\n".join([
            "const identityPart = value => String(value).replace(/^./, c => c.toUpperCase());",
            "const actorDisplay = value => `compat:${value}`;",
            match.group("body"),
            "const gibbs = {agent_id:'engine.director.codex.gibbs', role:'director', runtime:'codex', persona_name:'Gibbs', short_name:'@Gibbs'};",
            "const red = {agent_id:'engine.director.codex.red', role:'director', runtime:'codex'};",
            "const legacy = {agent_id:'engine.director.codex', role:'director', runtime:'codex', display_name:'Existing compatibility identity'};",
            "process.stdout.write(JSON.stringify({",
            "  gibbs:[agentPersonaName(gibbs), agentShortName(gibbs), agentChoiceLabel(gibbs)],",
            "  red:[agentPersonaName(red), agentShortName(red)],",
            "  legacy:[agentPersonaName(legacy), agentShortName(legacy), agentChoiceLabel(legacy)]",
            "}));",
        ])
        completed = subprocess.run(
            ["node", "-e", program], text=True, capture_output=True, check=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["gibbs"], [
            "Gibbs", "@Gibbs", "Gibbs · @Gibbs · Director · Codex",
        ])
        self.assertEqual(result["red"], ["Red", "@Red"])
        self.assertEqual(result["legacy"][:2], ["", ""])
        self.assertIn("Existing compatibility identity", result["legacy"][2])

    def test_panel_generates_names_and_accepts_short_mentions_without_raw_id_input(self):
        self.assertIn('placeholder="@Gibbs, @Turing"', self.panel)
        self.assertIn('identity_mode: "new"', self.panel)
        self.assertIn("Generated AI identity reserved", self.panel)
        self.assertIn("persona_name", self.panel)
        self.assertIn("short_name", self.panel)
        self.assertNotIn('id="agent-id-new"', self.panel)
        self.assertNotIn('name="agent_id_new"', self.panel)

    def test_guides_preserve_server_wide_never_reuse_and_setup_lifecycle(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        skill = (ROOT / "skills" / "setup" / "SKILL.md").read_text(
            encoding="utf-8")
        kimi = (ROOT / "kimi-commands" / "setup.md").read_text(
            encoding="utf-8")
        for guide in (readme, skill, kimi):
            self.assertIn("Gibbs", guide)
            self.assertIn("@Gibbs", guide)
            self.assertIn("case-insensitive", guide)
            self.assertIn("historical", guide)
            self.assertIn("temporary", guide)
            self.assertIn("server", guide.lower())
        self.assertIn("selection-only", readme)
        self.assertIn("Make default", readme)
        self.assertIn("current MCP process", skill)
        self.assertIn("current MCP process", kimi)
        self.assertIn("identity_mode=repair", skill)
        self.assertIn("identity_mode=repair", kimi)


if __name__ == "__main__":
    unittest.main()
