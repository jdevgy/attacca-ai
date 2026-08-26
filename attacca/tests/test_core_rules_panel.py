"""Source and shipped-panel regressions for the dedicated Core Rules view."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


PANEL = Path(__file__).resolve().parents[1] / "web" / "admin.html"


class CoreRulesPanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.panel = PANEL.read_text(encoding="utf-8")

    def test_panel_script_is_valid_javascript(self) -> None:
        script = re.search(
            r"^  <script>\n(?P<script>.*)^  </script>$",
            self.panel,
            flags=re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(script)
        completed = subprocess.run(
            ["node", "--check", "-"],
            input=script.group("script"),
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_rules_is_a_direct_top_level_hash_view_with_live_count(self) -> None:
        self.assertIn('data-view="rules"', self.panel)
        self.assertIn('id="nav-rules"', self.panel)
        self.assertEqual(self.panel.count('id="nav-rules"'), 1)
        self.assertRegex(
            self.panel,
            r'const VIEWS = \[[^\]]*"room", "rules", "network"',
        )
        self.assertIn('rules: renderRules', self.panel)
        self.assertIn('location.hash.slice(1)', self.panel)
        self.assertIn('ruleBadge.textContent = String(rules.length)', self.panel)
        self.assertIn('`${enabledRules} enabled of ${rules.length} loaded rules`', self.panel)

    def test_single_rules_manager_is_not_duplicated_in_ai_network(self) -> None:
        self.assertEqual(self.panel.count("function renderRules()"), 1)
        self.assertEqual(self.panel.count('id="core-rules-manager"'), 1)
        self.assertEqual(self.panel.count('data-form="create-rule"'), 1)
        self.assertNotIn('id="project-rules"', self.panel)

        network_start = self.panel.index("function renderNetwork()")
        network_end = self.panel.index(
            "function renderAuthenticatedSettings()", network_start)
        network = self.panel[network_start:network_end]
        self.assertNotIn("Project Rules / Directives", network)
        self.assertNotIn('data-form="create-rule"', network)
        self.assertNotIn('data-form="update-rule"', network)
        self.assertNotIn("canManageProjectRules", network)

    def test_manager_has_full_versioned_crud_scope_priority_and_toggle_controls(self) -> None:
        rules_start = self.panel.index("function renderRules()")
        rules_end = self.panel.index("function renderNetwork()", rules_start)
        rules = self.panel[rules_start:rules_end]
        for field in ("title", "body", "scope", "priority", "expected_version"):
            self.assertIn(f'name="{field}"', rules)
        for scope in ("everyone", "director", "advisor", "worker"):
            self.assertIn(f'"{scope}"', self.panel)
        for text in (
            "Create Core Rule",
            "Save rule changes",
            "Disable rule",
            "Enable rule",
            "Lower numbers load first",
        ):
            self.assertIn(text, rules)
        self.assertIn('data-action="toggle-rule"', rules)
        self.assertIn('data-version="${h(rule.version)}"', rules)
        self.assertIn('/rules?include_all=1&include_disabled=1', self.panel)
        self.assertIn('pathFor("/rules")', self.panel)
        self.assertIn('expected_version: Number(button.dataset.version)', self.panel)

    def test_permissions_are_explicit_and_read_only_controls_are_disabled(self) -> None:
        rules_start = self.panel.index("function renderRules()")
        rules_end = self.panel.index("function renderNetwork()", rules_start)
        rules = self.panel[rules_start:rules_end]
        self.assertIn("canManageProjectRules()", rules)
        self.assertIn("Human / Director management enabled", rules)
        self.assertIn("Read only for this identity", rules)
        self.assertIn("Human or registered Director management only", rules)
        self.assertIn('canManageRules ? "" : "disabled"', rules)
        self.assertIn("cannot create, edit, enable, or disable", rules)

    def test_startup_role_scope_and_one_minute_sync_are_explained(self) -> None:
        for text in (
            "These rules are server-side startup law",
            "Every enabled rule scoped to <code>everyone</code> or an AI's registered role",
            "loaded at startup, resume, and lifecycle refresh",
            "watcher checks for changes every 60 seconds",
            "home and office checkouts receive the same current directives",
            "They sit above static managed AGENTS instructions",
        ):
            self.assertIn(text, self.panel)

    def test_filter_and_selected_project_survive_refreshes(self) -> None:
        self.assertIn('ruleFilter: ""', self.panel)
        self.assertIn('id="rule-search"', self.panel)
        self.assertIn('state.ruleFilter = event.target.value', self.panel)
        self.assertIn('value="${h(state.ruleFilter)}"', self.panel)
        select_start = self.panel.index("async function selectProject")
        select_end = self.panel.index('document.addEventListener("click"', select_start)
        self.assertNotIn("ruleFilter", self.panel[select_start:select_end])
        self.assertIn('const key = `${state.projectId || "none"}:${state.view}`', self.panel)
        self.assertIn("shouldReplaceRender(state.renderedKey", self.panel)

    def test_empty_error_and_accessibility_states_remain_visible(self) -> None:
        self.assertIn('aria-label="Filter Core Rules"', self.panel)
        self.assertIn('aria-label="Core Rules list"', self.panel)
        self.assertIn('state.errors.rules ? errorNotice(state.errors.rules)', self.panel)
        self.assertIn('"No matching Core Rules"', self.panel)
        self.assertIn('"No Core Rules"', self.panel)


if __name__ == "__main__":
    unittest.main()
