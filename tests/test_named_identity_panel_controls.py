"""Focused source contracts for named-identity and Role Scope panel controls."""

from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "web" / "admin.html"


class NamedIdentityPanelControlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.panel = PANEL.read_text(encoding="utf-8")

    def test_role_scope_history_uses_full_server_paging_search_and_sort(self) -> None:
        for contract in (
            "roleScopeHistory: newListPage()",
            'roleScopeHistory: "roleScopeHistory"',
            'listQuery("roleScopeHistory", {',
            "q: state.roleScopeHistorySearch",
            'id="role-scope-history-search"',
            'sortControl("roleScopeHistory")',
            'pageToolbar("roleScopeHistory", historyResponse, "versions", '
            '"role-scope revisions")',
            '"role-scope-history-search": '
            '["roleScopeHistorySearch", "roleScopeHistory", false]',
            'resetListPage("roleScopeHistory")',
        ):
            self.assertIn(contract, self.panel)
        self.assertNotIn(
            "`/role-scopes/${encodeURIComponent(roleScope)}/history?limit=",
            self.panel,
        )
        self.assertIn(
            "Search and date order are applied to the complete authorized "
            "revision history before each page.",
            self.panel,
        )

    def test_bridge_participation_selects_friendly_names_not_raw_input(self) -> None:
        for contract in (
            "function bridgeAgentOptions(workspaceId, allowedAgents = [])",
            "data-bridge-agent-select",
            'name="${agentsName}" multiple',
            "Choose friendly names or @ShortNames.",
            'formData.getAll("selected_agents")',
            'formData.getAll("peer_selected_agents")',
            'peerAgents.innerHTML = bridgeAgentOptions(event.target.value, [])',
        ):
            self.assertIn(contract, self.panel)
        self.assertNotIn("Comma-separated registered AI actor IDs", self.panel)
        self.assertNotIn('placeholder="${h(workspaceId)}.director.codex"', self.panel)

    def test_compatibility_choice_never_uses_raw_actor_as_label(self) -> None:
        match = re.search(
            r"// TESTABLE_NAMED_IDENTITY_HELPERS:BEGIN\n(?P<body>.*?)"
            r"\n\s*// TESTABLE_NAMED_IDENTITY_HELPERS:END",
            self.panel,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        program = "\n".join((
            'const identityPart = value => String(value).replace(/^./, '
            'character => character.toUpperCase());',
            match.group("body"),
            "const legacy = {agent_id:'engine.director.codex', "
            "operational_actor_id:'engine.director.codex', "
            "display_name:'ENGINE.DIRECTOR.CODEX', role:'director', "
            "runtime:'codex'};",
            "process.stdout.write(JSON.stringify({"
            "label:agentChoiceLabel(legacy),"
            "description:agentDisplayDescription(legacy)}));",
        ))
        completed = subprocess.run(
            ["node", "-e", program], capture_output=True, text=True,
            timeout=10, check=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["label"],
            "Existing compatibility identity · Director · Codex",
        )
        self.assertEqual(result["description"], "")
        self.assertNotIn("engine.director.codex", result["label"])

    def test_task_plan_histories_use_independent_server_pages(self) -> None:
        for contract in (
            "function taskPlanRequestSuffix(selected = state.taskPlan)",
            "revision_limit: String(PANEL_PAGE_SIZE)",
            "revision_offset: String(Math.max(0, selected.revisionOffset",
            'params.set("revision_q", selected.revisionQuery)',
            'params.set("revision_filter", selected.revisionFilter)',
            "action_limit: String(PANEL_PAGE_SIZE)",
            "action_offset: String(Math.max(0, selected.actionOffset",
            'params.set("action_q", selected.actionQuery)',
            'params.set("action_filter", selected.actionFilter)',
            "payload?.pagination?.revisions",
            "payload?.plan?.actions_pagination",
            'id="task-plan-revision-search"',
            'id="task-plan-revision-filter"',
            'id="task-plan-action-search"',
            'id="task-plan-action-filter"',
            'taskPlanSortControl("revision")',
            'taskPlanSortControl("action")',
            'taskPlanPageToolbar(payload, "revision", "plan revisions")',
            'taskPlanPageToolbar(payload, "action", "plan actions")',
            'data-action="task-plan-page"',
            'queueTaskPlanFilterRefresh(event.target, "revision")',
            'queueTaskPlanFilterRefresh(event.target, "action")',
            "const latestVersion = Number(task.plan?.version)",
            "selected outside this page",
        ):
            self.assertIn(contract, self.panel)
        self.assertIn(
            "Revision search, status, and date order apply to the complete "
            "immutable history before each page.",
            self.panel,
        )
        self.assertIn(
            "Activity search, type, and date order apply to the complete "
            "selected-revision history before each page.",
            self.panel,
        )

    def test_cloud_copy_and_named_setup_wording_stay_current(self) -> None:
        self.assertIn(
            "loaded at session start and refreshed when its version changes",
            self.panel,
        )
        self.assertIn(
            "This document is loaded into every AI session, then cached while "
            "unchanged.",
            self.panel,
        )
        kimi = (ROOT / "kimi-commands" / "setup.md").read_text(
            encoding="utf-8")
        self.assertNotIn("always have a color", kimi)
        self.assertIn("human-friendly names such as **Gibbs**", kimi)

    def test_browser_script_remains_valid_javascript(self) -> None:
        script = self.panel.split("<script>", 1)[1].rsplit("</script>", 1)[0]
        completed = subprocess.run(
            ["node", "--check"], input=script, capture_output=True, text=True,
            timeout=10, check=False,
        )
        self.assertEqual(
            completed.returncode, 0, msg=completed.stderr + completed.stdout)


if __name__ == "__main__":
    unittest.main()
