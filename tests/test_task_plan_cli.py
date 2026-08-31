"""End-to-end CLI regressions for detailed task plans."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "attacca.py")
SPEC = importlib.util.spec_from_file_location(
    "attacca_task_plan_cli_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)

SECTIONS = [
    {"section_id": "design", "title": "Design", "body": "Define the API."},
    {"section_id": "tests", "title": "Tests", "body": "Run both QA passes."},
]


class TaskPlanCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "cli-plans.db"
        self.checkout = self.root / "repo"
        self.checkout.mkdir()
        conn = c.connect(self.db)
        c.project_init(conn, "setup", "human", path=str(self.checkout),
                       project_id="cli-plans", name="CLI Plans")
        c.set_current_owner("cli-owner")
        c.agent_register(
            conn, "cli-plans", "cli-owner", "human",
            agent_id="cli-plans.director.codex", role="director",
            runtime="codex")
        conn.close()
        c.set_current_owner(None)
        self.env = dict(os.environ)
        self.env["ATTACCA_OWNER"] = "cli-owner"

    def tearDown(self):
        c.set_current_owner(None)
        self.tmp.cleanup()

    def run_cli(self, *args, json_output=True, expected=0):
        command = [
            sys.executable, SCRIPT, "--db", str(self.db),
            "--project", "cli-plans", "--actor", "cli-plans.director.codex",
            "--actor-type", "agent",
        ]
        if json_output:
            command.append("--json")
        command.extend(args)
        result = subprocess.run(
            command, cwd=str(self.checkout), env=self.env,
            capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(result.returncode, expected, result.stderr)
        if json_output and expected == 0:
            return json.loads(result.stdout)
        return result

    def test_cli_full_plan_lifecycle_and_human_rendering(self):
        created = self.run_cli(
            "task", "create", "Large CLI task", "--risk", "high",
            "--plan-required")
        self.assertTrue(created["plan_required"])
        task_id = created["task_id"]
        written = self.run_cli(
            "task", "plan", "set", task_id,
            "--title", "CLI implementation plan",
            "--overview", "All CLI paths.",
            "--sections-json", json.dumps(SECTIONS))
        self.assertEqual(written["plan"]["status"], "draft")
        submitted = self.run_cli(
            "task", "plan", "submit", task_id,
            "--expected-version", "1")
        self.assertEqual(submitted["plan"]["status"], "in_review")
        approved = self.run_cli(
            "task", "plan", "review", task_id,
            "--expected-version", "1", "--action", "approve",
            "--note", "CLI review complete")
        self.assertEqual(approved["plan"]["status"], "approved")
        opened = self.run_cli("task", "plan", "get", task_id)
        self.assertEqual(opened["plan"]["title"], "CLI implementation plan")
        self.assertEqual(opened["plan"]["actions"][-1]["owner"], "cli-owner")
        rendered = self.run_cli(
            "task", "plan", "get", task_id, json_output=False)
        self.assertIn("plan v1 [approved]", rendered.stdout)
        self.assertIn("1. Design [design]", rendered.stdout)
        self.assertIn("Review history:", rendered.stdout)
        self.assertIn("run by cli-owner", rendered.stdout)

    def test_cli_revision_from_file_and_invalid_json_error(self):
        task_id = self.run_cli(
            "task", "create", "File plan", "--plan-required")["task_id"]
        section_file = self.root / "sections.json"
        section_file.write_text(json.dumps(SECTIONS), encoding="utf-8")
        first = self.run_cli(
            "task", "plan", "set", task_id, "--title", "from file",
            "--sections-file", str(section_file), "--submit")
        self.assertEqual(first["plan"]["status"], "in_review")
        revised = [dict(item) for item in SECTIONS]
        revised[0]["body"] = "Revised API design."
        second_file = self.root / "sections-v2.json"
        second_file.write_text(json.dumps(revised), encoding="utf-8")
        second = self.run_cli(
            "task", "plan", "set", task_id, "--title", "from file v2",
            "--sections-file", str(second_file), "--expected-version", "1")
        self.assertEqual(second["plan"]["version"], 2)
        stale = self.run_cli(
            "task", "plan", "set", task_id, "--title", "stale overwrite",
            "--sections-json", json.dumps(SECTIONS),
            "--expected-version", "1", expected=2)
        self.assertIn("stale task plan: expected v1, current is v2",
                      stale.stderr)
        historical = self.run_cli(
            "task", "plan", "get", task_id, "--version", "1")
        self.assertEqual(historical["plan"]["title"], "from file")
        invalid = self.run_cli(
            "task", "plan", "set", task_id, "--title", "invalid",
            "--sections-json", "not-json", "--expected-version", "2",
            expected=2)
        self.assertIn("plan sections must be valid JSON", invalid.stderr)


if __name__ == "__main__":
    unittest.main()
