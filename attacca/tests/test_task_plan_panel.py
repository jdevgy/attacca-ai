"""Control Panel regressions for View Plan, reviews, and attribution."""

import json
import re
import subprocess
import unittest
from pathlib import Path


PANEL = Path(__file__).resolve().parents[1] / "web" / "admin.html"


class TaskPlanPanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.panel = PANEL.read_text(encoding="utf-8")

    def test_panel_javascript_is_valid(self):
        script = re.search(
            r"^  <script>\n(?P<script>.*)^  </script>$", self.panel,
            flags=re.DOTALL | re.MULTILINE)
        self.assertIsNotNone(script)
        checked = subprocess.run(
            ["node", "--check", "-"], input=script.group("script"),
            text=True, capture_output=True, timeout=10, check=False)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_tasks_have_obvious_view_or_add_plan_actions(self):
        self.assertIn('data-action="view-task-plan"', self.panel)
        self.assertIn('"View plan →"', self.panel)
        self.assertIn('"Add plan →"', self.panel)
        self.assertIn("function renderTaskPlanPanel(task)", self.panel)
        self.assertIn('aria-label="Detailed plan for ${h(task.task_id)}"',
                      self.panel)
        self.assertIn("No plan yet", self.panel)
        self.assertIn("Loading full plan…", self.panel)
        self.assertIn("Plan could not load", self.panel)

    def test_create_and_revision_editor_is_structured_and_versioned(self):
        self.assertIn('name="plan_required"', self.panel)
        self.assertIn("Required for this large task", self.panel)
        self.assertIn('data-form="set-task-plan"', self.panel)
        for field in ("title", "overview", "sections_markdown",
                      "expected_version", "submit_for_review"):
            self.assertIn('name="%s"' % field, self.panel)
        self.assertIn("## Heading [stable-id]", self.panel)
        self.assertIn("parsePlanSectionsMarkdown(values.sections_markdown)",
                      self.panel)
        self.assertIn("Create revision", self.panel)
        self.assertIn("Submit for review", self.panel)
        self.assertIn("stale", self.panel.lower())

    def test_markdown_section_parser_preserves_ids_and_rejects_empty_body(self):
        match = re.search(
            r"// TESTABLE_TASK_PLAN_HELPERS:BEGIN(?P<body>.*?)"
            r"// TESTABLE_TASK_PLAN_HELPERS:END",
            self.panel, flags=re.DOTALL)
        self.assertIsNotNone(match)
        program = match.group("body") + r'''
const parsed = parsePlanSectionsMarkdown(
  "## Scope [scope]\nLong scope.\n\n## QA [qa]\nTwo passes.");
let error = "";
try { parsePlanSectionsMarkdown("## Empty [empty]\n"); }
catch (caught) { error = caught.message; }
process.stdout.write(JSON.stringify({parsed, error,
  markdown: planSectionsToMarkdown(parsed)}));
'''
        evaluated = subprocess.run(
            ["node", "-"], input=program, text=True, capture_output=True,
            timeout=10, check=False)
        self.assertEqual(evaluated.returncode, 0, evaluated.stderr)
        result = json.loads(evaluated.stdout)
        self.assertEqual([item["section_id"] for item in result["parsed"]],
                         ["scope", "qa"])
        self.assertIn("needs detailed content", result["error"])
        self.assertIn("## Scope [scope]", result["markdown"])

    def test_review_controls_cover_whole_plan_and_individual_sections(self):
        for action in ("approve-task-plan", "suggest-task-plan",
                       "comment-task-plan", "submit-task-plan",
                       "edit-task-plan", "cancel-plan-edit"):
            self.assertIn('data-action="%s"' % action, self.panel)
        for text in ("Approve entire plan", "Approve section",
                     "Suggest overall edit", "Suggest edit", "Comment"):
            self.assertIn(text, self.panel)
        self.assertIn('data-section="${h(section.section_id)}"', self.panel)
        self.assertIn("Humans and Directors", self.panel.replace(
            "a human or registered Director", "Humans and Directors"))
        self.assertIn("This identity may still leave attributed comments and edit suggestions",
                      self.panel)

    def test_required_plan_gate_is_explicit_in_task_reporting_controls(self):
        self.assertIn("const planReady = !task.plan_required || task.plan?.status === \"approved\"",
                      self.panel)
        self.assertIn("Approval gate active", self.panel)
        self.assertIn("cannot move to review or done until the latest plan is approved",
                      self.panel)
        self.assertIn('<option value="review" ${planReady ? "selected" : "disabled"}',
                      self.panel)
        self.assertIn('<option value="done" ${planReady ? "" : "disabled"}',
                      self.panel)
        self.assertIn('needs approved plan', self.panel)
        self.assertIn('value="blocked" ${planReady ? "" : "selected"}',
                      self.panel)

    def test_plan_routes_are_lazy_loaded_and_refreshed_during_polling(self):
        self.assertIn("async function openTaskPlan(taskId, version = null)",
                      self.panel)
        self.assertIn("endpoints.selectedPlan", self.panel)
        self.assertIn('key === "selectedPlan"', self.panel)
        self.assertIn("state.taskPlan.selectedVersion", self.panel)
        for suffix in ("/plan${suffix}", "/plan/submit", "/plan/review"):
            self.assertIn(suffix, self.panel)
        self.assertIn('method: "PUT", body', self.panel)
        self.assertIn('method: "POST", body', self.panel)

    def test_plan_activity_shows_separate_ai_human_git_and_device_origin(self):
        self.assertIn("Plan activity · immutable attribution", self.panel)
        self.assertIn('actionAttribution("By", action)', self.panel)
        self.assertIn("Run by user", self.panel)
        self.assertIn("action.git_branch", self.panel)
        self.assertIn("action.git_revision", self.panel)
        self.assertIn("action.device_id", self.panel)
        self.assertIn(" · device ${h(action.device_id)}", self.panel)
        self.assertIn("Human user:", self.panel)
        self.assertNotIn("Run by user: not recorded</strong>", self.panel)

    def test_every_server_value_in_plan_renderer_is_html_escaped(self):
        plan_start = self.panel.index("function renderTaskPlanPanel(task)")
        plan_end = self.panel.index("function renderRoom()", plan_start)
        renderer = self.panel[plan_start:plan_end]
        for expression in (
                "h(plan.title)", "h(plan.overview)", "h(section.title)",
                "h(section.body)", "h(detail.note)",
                "h(section.section_id)"):
            self.assertIn(expression, renderer)

    def test_settings_explains_machine_local_server_switching(self):
        self.assertIn(
            "Connection changes stay local to each client installation",
            self.panel)
        self.assertIn("active AI opens sign-in and secure key collection",
                      self.panel)
        self.assertIn("never asks a human to run a shell command", self.panel)
        self.assertNotIn("attacca server set URL", self.panel)


if __name__ == "__main__":
    unittest.main()
