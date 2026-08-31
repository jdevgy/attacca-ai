"""Source-contract checks for bridge participation controls in the web panel."""

import unittest
from pathlib import Path


PANEL = (Path(__file__).resolve().parents[1] / "web" / "admin.html")


class BridgePanelSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.panel = PANEL.read_text()

    def test_exposes_every_participation_policy_and_response_field(self):
        for preset, label in (
                ("all", "All roles"),
                ("directors_advisors", "Directors + Advisors"),
                ("directors", "Directors only"),
                ("selected_agents", "Selected agents")):
            self.assertIn(f'["{preset}", "{label}"]', self.panel)
        for field in (
                "bridge.participation", "bridge.allowed_agents",
                "bridge.peer_participation", "bridge.peer_allowed_agents",
                "bridge.can_participate"):
            self.assertIn(field, self.panel)

    def test_updates_access_without_using_relationship_deletion(self):
        self.assertIn('data-form="update-bridge-participation"', self.panel)
        self.assertIn("Save participation", self.panel)
        update_start = self.panel.index(
            'if (kind === "update-bridge-participation")')
        update_end = self.panel.index(
            'if (kind === "register-agent")', update_start)
        update_handler = self.panel[update_start:update_end]
        self.assertIn('method: "PUT"', update_handler)
        self.assertIn("participation:", update_handler)
        self.assertIn("peer_participation:", update_handler)
        self.assertNotIn('method: "DELETE"', update_handler)

        self.assertIn("Delete relationship", self.panel)
        remove_start = self.panel.index('if (action === "remove-bridge")')
        remove_end = self.panel.index(
            'if (action === "open-connected-room")', remove_start)
        remove_handler = self.panel[remove_start:remove_end]
        self.assertIn('method: "DELETE"', remove_handler)
        self.assertIn("To change who can participate", remove_handler)

    def test_denied_conversation_is_visible_and_send_is_disabled(self):
        self.assertIn(
            "const conversationDenied = Boolean(activeBridge && "
            "activeBridge.can_participate === false);", self.panel)
        self.assertIn("Conversation access denied", self.panel)
        self.assertIn("Sending is disabled for this identity", self.panel)
        self.assertIn("The relationship remains connected", self.panel)

    def test_project_rules_management_uses_versioned_server_apis(self):
        self.assertIn("Project Rules / Directives", self.panel)
        self.assertIn("/rules?include_all=1&include_disabled=1", self.panel)
        self.assertIn("These rules are server-side startup law", self.panel)
        self.assertIn("watcher checks for changes every 60 seconds", self.panel)
        self.assertIn("They sit above static managed AGENTS instructions",
                      self.panel)
        for field in ("title", "body", "scope", "priority",
                      "expected_version"):
            self.assertIn(f'name="{field}"', self.panel)
        for scope in ("everyone", "director", "advisor", "worker"):
            self.assertIn(f'"{scope}"', self.panel)

        create_start = self.panel.index('if (kind === "create-rule")')
        create_end = self.panel.index('if (kind === "update-rule")',
                                      create_start)
        create_handler = self.panel[create_start:create_end]
        self.assertIn('pathFor("/rules")', create_handler)
        self.assertIn('method: "POST"', create_handler)

        update_start = create_end
        update_end = self.panel.index('if (kind === "update-handoff")',
                                      update_start)
        update_handler = self.panel[update_start:update_end]
        self.assertIn('method: "PUT"', update_handler)
        self.assertIn("expected_version", update_handler)
        self.assertIn('action === "toggle-rule"', self.panel)
        self.assertIn("Disable rule", self.panel)
        self.assertIn("Enable rule", self.panel)


if __name__ == "__main__":
    unittest.main()
