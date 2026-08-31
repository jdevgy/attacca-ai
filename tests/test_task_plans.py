"""Durable detailed task-plan model and MCP regressions."""

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
    "attacca_task_plans_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


SECTIONS = [
    {"section_id": "scope", "title": "Scope",
     "body": "Define the complete user-visible boundary and exclusions."},
    {"section_id": "implementation", "title": "Implementation",
     "body": "Build the model, every transport, the panel, and regressions."},
]


class PlanMcpClient:
    def __init__(self, db, actor):
        env = dict(os.environ)
        env["ATTACCA_DB"] = str(db)
        env["ATTACCA_PROJECT"] = "plans"
        env["ATTACCA_ACTOR"] = actor
        env["ATTACCA_ACTOR_TYPE"] = "agent"
        env["ATTACCA_OWNER"] = "mcp-human"
        self.proc = subprocess.Popen(
            [sys.executable, SCRIPT, "mcp"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=env)
        self.next_id = 1

    def request(self, method, params=None):
        request_id = self.next_id
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()
        response = json.loads(self.proc.stdout.readline())
        assert response["id"] == request_id
        return response

    def initialize(self):
        self.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "plan-test", "version": "1"},
        })
        self.proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "method": "notifications/initialized",
        }) + "\n")
        self.proc.stdin.flush()

    def call(self, name, arguments):
        response = self.request(
            "tools/call", {"name": name, "arguments": arguments})
        result = response["result"]
        text = result["content"][0]["text"]
        return result.get("isError", False), text, (
            None if result.get("isError") else json.loads(text))

    def close(self):
        if self.proc.poll() is None:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        self.proc.stdout.close()
        self.proc.stderr.close()


class TaskPlanModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "plans.db"
        self.checkout = Path(self.tmp.name) / "repo"
        self.checkout.mkdir()
        self.conn = c.connect(self.db)
        c.set_current_owner(None)
        c.set_current_git_context()
        c.project_init(
            self.conn, "setup", "human", path=str(self.checkout),
            project_id="plans", name="Task Plans")
        for actor, role, runtime in (
                ("plans.director.codex", "director", "codex"),
                ("plans.worker.claude", "worker", "claude"),
                ("plans.advisor.kimi", "advisor", "kimi")):
            c.agent_register(
                self.conn, "plans", "setup", "human", agent_id=actor,
                role=role, runtime=runtime)
        self.task_id = c.task_create(
            self.conn, "plans", "plans.director.codex", "agent",
            "Implement detailed plans", plan_required=True)["task_id"]

    def tearDown(self):
        c.set_current_owner(None)
        c.set_current_git_context()
        self.conn.close()
        self.tmp.cleanup()

    def make_plan(self, submit=False, actor="plans.director.codex"):
        return c.task_plan_set(
            self.conn, "plans", self.task_id, actor, "agent",
            title="Detailed delivery plan", overview="Long-form overview.",
            sections=SECTIONS, submit_for_review=submit)

    def test_create_get_list_and_immutable_origin_attribution(self):
        c.set_current_owner("Jdevgy")
        c.set_current_git_context(
            "feature/plans", "abc123def456", "home-laptop")
        created = self.make_plan(submit=True)
        self.assertEqual(created["plan"]["version"], 1)
        self.assertEqual(created["plan"]["status"], "in_review")
        self.assertEqual(created["plan"]["sections"], SECTIONS)
        self.assertEqual(created["plan"]["authored_by"],
                         "plans.director.codex")
        self.assertEqual(created["plan"]["authored_owner"], "Jdevgy")
        action = created["plan"]["actions"][0]
        self.assertEqual(action["event_type"], "task.plan.created")
        self.assertEqual(action["operational_actor_id"],
                         "plans.director.codex")
        self.assertEqual(action["owner"], "Jdevgy")
        self.assertEqual(action["attribution"]["run_by_user"], "Jdevgy")
        self.assertEqual(action["git_branch"], "feature/plans")
        self.assertEqual(action["git_revision"], "abc123def456")
        self.assertEqual(action["device_id"], "home-laptop")
        board_task = c.task_list(self.conn, "plans")["tasks"][0]
        self.assertTrue(board_task["plan_required"])
        self.assertEqual(board_task["plan"]["version"], 1)
        self.assertEqual(board_task["plan"]["section_count"], 2)
        shown = c.task_show(self.conn, "plans", self.task_id)
        self.assertEqual(shown["plan"]["status"], "in_review")
        self.assertTrue(c.verify_ledger(self.conn, "plans")["ok"])

    def test_revisions_are_immutable_and_stale_writes_are_rejected(self):
        first = self.make_plan()
        with self.assertRaisesRegex(c.AttaccaError, "expected_version=1"):
            c.task_plan_set(
                self.conn, "plans", self.task_id,
                "plans.director.codex", "agent", "Overwrite", "", SECTIONS)
        with self.assertRaisesRegex(c.AttaccaError, "stale task plan"):
            c.task_plan_set(
                self.conn, "plans", self.task_id,
                "plans.director.codex", "agent", "Overwrite", "", SECTIONS,
                expected_version=0)
        changed_sections = [dict(section) for section in SECTIONS]
        changed_sections[1]["body"] = "A revised implementation sequence."
        second = c.task_plan_set(
            self.conn, "plans", self.task_id, "plans.director.codex", "agent",
            "Detailed delivery plan v2", "Updated overview.", changed_sections,
            expected_version=first["plan"]["version"])
        self.assertEqual(second["plan"]["version"], 2)
        history = c.task_plan_get(self.conn, "plans", self.task_id, version=1)
        self.assertEqual(history["plan"]["title"], "Detailed delivery plan")
        self.assertEqual([item["version"] for item in history["revisions"]],
                         [2, 1])

    def test_submit_suggest_revise_and_approve_workflow(self):
        draft = self.make_plan()
        submitted = c.task_plan_submit(
            self.conn, "plans", self.task_id, "plans.director.codex", "agent",
            expected_version=draft["plan"]["version"])
        self.assertEqual(submitted["plan"]["status"], "in_review")
        c.set_current_owner("Reviewer")
        c.set_current_git_context("review/plans", "beef1234", "office")
        suggested = c.task_plan_review(
            self.conn, "plans", self.task_id, "plans.advisor.kimi", "agent",
            expected_version=1, action="suggest_edit",
            section_id="implementation", note="Add rollback coverage.")
        self.assertEqual(suggested["plan"]["status"], "changes_requested")
        suggestion = suggested["plan"]["suggestions"][0]
        self.assertEqual(suggestion["payload"]["section_id"], "implementation")
        self.assertEqual(suggestion["owner"], "Reviewer")
        self.assertEqual(suggestion["device_id"], "office")
        revised = c.task_plan_set(
            self.conn, "plans", self.task_id, "plans.director.codex", "agent",
            "Approved shape", "Rollback added.", SECTIONS,
            expected_version=1, submit_for_review=True)
        self.assertEqual(revised["plan"]["version"], 2)
        section_approval = c.task_plan_review(
            self.conn, "plans", self.task_id, "plans.director.codex", "agent",
            expected_version=2, action="approve", section_id="scope")
        self.assertEqual(section_approval["plan"]["status"], "in_review")
        approved = c.task_plan_review(
            self.conn, "plans", self.task_id, "plans.director.codex", "agent",
            expected_version=2, action="approve",
            note="Plan is ready to execute.")
        self.assertEqual(approved["plan"]["status"], "approved")
        self.assertEqual(len(approved["plan"]["approvals"]), 2)

    def test_human_approval_is_human_once_not_missing_run_by_user(self):
        self.make_plan(submit=True)
        c.set_current_owner("Jdevgy")
        approved = c.task_plan_review(
            self.conn, "plans", self.task_id, "Jdevgy", "human",
            expected_version=1, action="approve")
        action = approved["plan"]["approvals"][-1]
        self.assertEqual(action["actor_type"], "human")
        self.assertEqual(action["attribution"]["human_user"], "Jdevgy")
        self.assertIsNone(action["attribution"]["run_by_user"])

    def test_worker_claimant_may_write_but_not_approve(self):
        c.task_claim(
            self.conn, "plans", "plans.worker.claude", "agent", self.task_id)
        plan = self.make_plan(actor="plans.worker.claude")
        self.assertEqual(plan["plan"]["authored_by"], "plans.worker.claude")
        c.task_plan_submit(
            self.conn, "plans", self.task_id, "plans.worker.claude", "agent", 1)
        commented = c.task_plan_review(
            self.conn, "plans", self.task_id, "plans.worker.claude", "agent",
            expected_version=1, action="comment", note="Worker context note.")
        self.assertEqual(commented["plan"]["status"], "in_review")
        self.assertEqual(commented["plan"]["comments"][0]
                         ["operational_actor_id"], "plans.worker.claude")
        with self.assertRaisesRegex(c.AttaccaError, "approval requires"):
            c.task_plan_review(
                self.conn, "plans", self.task_id, "plans.worker.claude", "agent",
                expected_version=1, action="approve")

    def test_unregistered_ai_cannot_suggest_or_comment(self):
        self.make_plan(submit=True)
        for action, note in (("suggest_edit", "Change it"),
                             ("comment", "Looks interesting")):
            with self.subTest(action=action), self.assertRaisesRegex(
                    c.AttaccaError, "require a registered AI"):
                c.task_plan_review(
                    self.conn, "plans", self.task_id, "rogue-runtime", "agent",
                    expected_version=1, action=action, note=note)
        plan = c.task_plan_get(self.conn, "plans", self.task_id)["plan"]
        self.assertEqual(plan["status"], "in_review")
        self.assertEqual(
            [item["event_type"] for item in plan["actions"]],
            ["task.plan.created"])

    def test_required_plan_gates_review_and_done_until_latest_is_approved(self):
        c.task_claim(
            self.conn, "plans", "plans.director.codex", "agent", self.task_id)
        with self.assertRaisesRegex(c.AttaccaError, "status is missing"):
            c.task_report(
                self.conn, "plans", "plans.director.codex", "agent",
                self.task_id, "Premature review", requested_state="review")
        draft = self.make_plan()
        with self.assertRaisesRegex(c.AttaccaError, "status is draft"):
            c.task_report(
                self.conn, "plans", "plans.director.codex", "agent",
                self.task_id, "Premature done", requested_state="done")
        c.task_plan_submit(
            self.conn, "plans", self.task_id, "plans.director.codex", "agent",
            expected_version=1)
        with self.assertRaisesRegex(c.AttaccaError, "status is in_review"):
            c.task_set_status(
                self.conn, "plans", "plans.director.codex", "agent",
                self.task_id, "done", reason="Not approved")
        c.task_plan_review(
            self.conn, "plans", self.task_id, "plans.advisor.kimi", "agent",
            expected_version=1, action="suggest_edit", note="Change scope.")
        with self.assertRaisesRegex(
                c.AttaccaError, "status is changes_requested"):
            c.task_report(
                self.conn, "plans", "plans.director.codex", "agent",
                self.task_id, "Still premature", requested_state="review")
        revised = c.task_plan_set(
            self.conn, "plans", self.task_id, "plans.director.codex", "agent",
            "Approved revision", "Suggestion addressed.", SECTIONS,
            expected_version=draft["plan"]["version"],
            submit_for_review=True)
        c.task_plan_review(
            self.conn, "plans", self.task_id, "plans.director.codex", "agent",
            expected_version=revised["plan"]["version"], action="approve")
        finished = c.task_report(
            self.conn, "plans", "plans.director.codex", "agent",
            self.task_id, "Approved plan executed",
            evidence=[{"kind": "test", "result": "pass"}],
            requested_state="done")
        self.assertEqual(finished["status"], "done")

    def test_optional_plan_does_not_silently_become_required(self):
        optional = c.task_create(
            self.conn, "plans", "plans.director.codex", "agent",
            "Optional planning notes", plan_required=False)["task_id"]
        c.task_plan_set(
            self.conn, "plans", optional, "plans.director.codex", "agent",
            "Optional draft", "Useful but not a gate.", SECTIONS)
        shown = c.task_show(self.conn, "plans", optional)
        self.assertFalse(shown["plan_required"])
        finished = c.task_report(
            self.conn, "plans", "plans.director.codex", "agent", optional,
            "Done without formal approval",
            evidence=[{"kind": "test", "result": "pass"}],
            requested_state="done")
        self.assertEqual(finished["status"], "done")

    def test_invalid_sections_and_review_transitions_fail_atomically(self):
        bad_sections = [
            {"section_id": "same", "title": "One", "body": "Body"},
            {"section_id": "same", "title": "Two", "body": "Body"},
        ]
        with self.assertRaisesRegex(c.AttaccaError, "duplicate"):
            c.task_plan_set(
                self.conn, "plans", self.task_id,
                "plans.director.codex", "agent", "Bad", "", bad_sections)
        self.assertIsNone(
            c.task_plan_get(self.conn, "plans", self.task_id)["plan"])
        self.make_plan()
        with self.assertRaisesRegex(c.AttaccaError, "must be in_review"):
            c.task_plan_review(
                self.conn, "plans", self.task_id,
                "plans.director.codex", "agent", 1, "suggest_edit",
                note="Not while draft")
        with self.assertRaisesRegex(c.AttaccaError, "unknown plan section"):
            c.task_plan_review(
                self.conn, "plans", self.task_id,
                "plans.director.codex", "agent", 1, "comment",
                section_id="missing", note="Wrong target")
        plan = c.task_plan_get(self.conn, "plans", self.task_id)["plan"]
        self.assertEqual(plan["status"], "draft")
        self.assertEqual(len(plan["actions"]), 1)


class TaskPlanMcpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "mcp-plans.db"
        root = Path(self.tmp.name) / "repo"
        root.mkdir()
        conn = c.connect(self.db)
        c.project_init(conn, "setup", "human", path=str(root),
                       project_id="plans", name="MCP Plans")
        c.agent_register(
            conn, "plans", "setup", "human",
            agent_id="plans.director.codex", role="director",
            runtime="codex")
        conn.close()
        self.client = PlanMcpClient(self.db, "plans.director.codex")
        self.client.initialize()

    def tearDown(self):
        self.client.close()
        self.tmp.cleanup()

    def test_all_plan_tools_are_discoverable_and_round_trip(self):
        listed = self.client.request("tools/list")["result"]["tools"]
        tools = {item["name"]: item for item in listed}
        for name in ("task_plan_get", "task_plan_set", "task_plan_submit",
                     "task_plan_review"):
            self.assertIn(name, tools)
        self.assertIn("plan_required",
                      tools["task_create"]["inputSchema"]["properties"])
        is_error, _, created = self.client.call("task_create", {
            "title": "Large MCP task", "plan_required": True,
        })
        self.assertFalse(is_error)
        task_id = created["task_id"]
        is_error, _, plan = self.client.call("task_plan_set", {
            "task_id": task_id, "title": "MCP plan",
            "overview": "Created over MCP.", "sections": SECTIONS,
            "submit_for_review": True,
        })
        self.assertFalse(is_error)
        self.assertEqual(plan["plan"]["status"], "in_review")
        is_error, text, _ = self.client.call("task_report", {
            "task_id": task_id, "summary": "Too early",
            "requested_state": "done",
        })
        self.assertTrue(is_error)
        self.assertIn("requires an approved detailed plan", text)
        is_error, _, reviewed = self.client.call("task_plan_review", {
            "task_id": task_id, "expected_version": 1,
            "action": "approve", "note": "Ready",
        })
        self.assertFalse(is_error)
        self.assertEqual(reviewed["plan"]["status"], "approved")
        is_error, _, opened = self.client.call(
            "task_plan_get", {"task_id": task_id})
        self.assertFalse(is_error)
        self.assertEqual(opened["plan"]["title"], "MCP plan")
        self.assertEqual(opened["plan"]["actions"][-1]["owner"], "mcp-human")
        is_error, _, finished = self.client.call("task_report", {
            "task_id": task_id, "summary": "Approved MCP plan executed",
            "requested_state": "done",
            "evidence": [{"kind": "test", "result": "pass"}],
        })
        self.assertFalse(is_error)
        self.assertEqual(finished["status"], "done")

    def test_stale_mcp_revision_returns_a_clear_tool_error(self):
        _, _, created = self.client.call(
            "task_create", {"title": "Conflict", "plan_required": True})
        self.client.call("task_plan_set", {
            "task_id": created["task_id"], "title": "v1",
            "sections": SECTIONS,
        })
        is_error, text, _ = self.client.call("task_plan_set", {
            "task_id": created["task_id"], "title": "stale",
            "sections": SECTIONS, "expected_version": 0,
        })
        self.assertTrue(is_error)
        self.assertIn("stale task plan", text)


if __name__ == "__main__":
    unittest.main()
