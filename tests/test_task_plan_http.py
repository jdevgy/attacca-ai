"""Real HTTP plan workflow and principal-bound attribution regressions."""

import importlib.util
import os
import tempfile
import unittest
import urllib.parse
from pathlib import Path


os.environ["ATTACCA_OWNER"] = ""

from tests.test_http import ServerFixture  # noqa: E402


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_task_plan_http_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


SECTIONS = [
    {"section_id": "acceptance", "title": "Acceptance criteria",
     "body": "Every interface round-trips one canonical plan."},
    {"section_id": "qa", "title": "Quality assurance",
     "body": "Run two independent verification passes."},
]


class TaskPlanHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "plan-http.db"
        checkout = Path(self.tmp.name) / "repo"
        checkout.mkdir()
        conn = c.connect(self.db)
        c.project_init(conn, "setup", "human", path=str(checkout),
                       project_id="webplans", name="Web Plans")
        c.auth_create_user(
            conn, "jdevgy", "correct horse battery staple",
            display_name="Jdevgy", is_admin=True)
        c.set_current_owner("jdevgy")
        c.agent_register(
            conn, "webplans", "jdevgy", "human",
            agent_id="webplans.director.codex", role="director",
            runtime="codex")
        c.agent_register(
            conn, "webplans", "jdevgy", "human",
            agent_id="webplans.advisor.claude", role="advisor",
            runtime="claude")
        self.director_token = c.auth_token_create(
            conn, "jdevgy", "director", actor_id="webplans.director.codex",
            actor_type="agent", project_id="webplans",
            runtime="codex")["token"]
        self.advisor_token = c.auth_token_create(
            conn, "jdevgy", "advisor", actor_id="webplans.advisor.claude",
            actor_type="agent", project_id="webplans",
            runtime="claude")["token"]
        self.human_token = c.auth_token_create(
            conn, "jdevgy", "human", actor_type="human")["token"]
        c.server_settings_store(conn, {"authentication": True})
        conn.close()
        c.set_current_owner(None)
        self.server = ServerFixture(self.db)

    def tearDown(self):
        self.server.stop()
        c.set_current_owner(None)
        c.set_current_git_context()
        self.tmp.cleanup()

    def request(self, method, path, body=None, token=None, headers=None,
                expected=200):
        merged = {"Authorization": "Bearer %s" % (token or self.director_token)}
        merged.update(headers or {})
        status, payload, _ = self.server.request(
            method, path, body, headers=merged)
        self.assertEqual(status, expected, payload)
        return payload

    def test_rest_create_review_revise_approve_and_historical_get(self):
        created = self.request(
            "POST", "/v1/projects/webplans/tasks",
            {"title": "Large hosted task", "risk_level": "high",
             "plan_required": True},
            headers={"X-Attacca-Actor": "webplans.director.codex",
                     "X-Attacca-Owner": "forged-owner"})
        task_id = created["task_id"]
        base = "/v1/projects/webplans/tasks/%s/plan" % task_id
        plan = self.request(
            "PUT", base,
            {"title": "Hosted delivery", "overview": "Detailed plan body.",
             "sections": SECTIONS, "submit_for_review": True},
            headers={"X-Attacca-Actor": "webplans.director.codex",
                     "X-Attacca-Owner": "forged-owner",
                     "X-Attacca-Git-Branch": "feature/hosted-plan",
                     "X-Attacca-Git-Revision": "a1b2c3d4",
                     "X-Attacca-Device-ID": "home-machine"})["plan"]
        self.assertEqual(plan["status"], "in_review")
        authored = plan["actions"][0]
        self.assertEqual(authored["operational_actor_id"],
                         "webplans.director.codex")
        self.assertEqual(authored["owner"], "jdevgy")
        self.assertEqual(authored["attribution"]["run_by_user"], "jdevgy")
        self.assertEqual(authored["git_branch"], "feature/hosted-plan")
        self.assertEqual(authored["git_revision"], "a1b2c3d4")
        self.assertEqual(authored["device_id"], "home-machine")

        premature = self.request(
            "POST", "/v1/projects/webplans/tasks/%s/report" % task_id,
            {"summary": "Premature completion", "requested_state": "done"},
            headers={"X-Attacca-Actor": "webplans.director.codex"},
            expected=400)
        self.assertIn("requires an approved detailed plan", premature["error"])
        self.assertIn("in_review", premature["error"])

        suggestion = self.request(
            "POST", base + "/review",
            {"expected_version": 1, "action": "suggest_edit",
             "section_id": "qa", "note": "Include an offline rerun."},
            token=self.advisor_token,
            headers={"X-Attacca-Actor": "webplans.advisor.claude",
                     "X-Attacca-Git-Branch": "review/plan",
                     "X-Attacca-Git-Revision": "eeff0011",
                     "X-Attacca-Device-ID": "office-machine"})["plan"]
        self.assertEqual(suggestion["status"], "changes_requested")
        review_action = suggestion["suggestions"][0]
        self.assertEqual(review_action["operational_actor_id"],
                         "webplans.advisor.claude")
        self.assertEqual(review_action["owner"], "jdevgy")
        self.assertEqual(review_action["device_id"], "office-machine")

        revised_sections = [dict(item) for item in SECTIONS]
        revised_sections[1]["body"] += " Includes an offline rerun."
        revised = self.request(
            "PUT", base,
            {"title": "Hosted delivery v2", "overview": "Suggestion applied.",
             "sections": revised_sections, "expected_version": 1,
             "submit_for_review": True},
            headers={"X-Attacca-Actor": "webplans.director.codex"})["plan"]
        self.assertEqual(revised["version"], 2)
        approved = self.request(
            "POST", base + "/review",
            {"expected_version": 2, "action": "approve",
             "note": "Human approval."}, token=self.human_token,
            headers={"X-Attacca-Owner": "ignored-spoof",
                     "X-Attacca-Device-ID": "human-browser"})["plan"]
        self.assertEqual(approved["status"], "approved")
        human = approved["approvals"][-1]
        self.assertEqual(human["actor_type"], "human")
        self.assertEqual(human["attribution"]["human_user"], "jdevgy")
        self.assertIsNone(human["attribution"]["run_by_user"])
        self.assertEqual(human["device_id"], "human-browser")
        finished = self.request(
            "POST", "/v1/projects/webplans/tasks/%s/report" % task_id,
            {"summary": "Approved hosted plan executed",
             "requested_state": "done",
             "evidence": [{"kind": "test", "result": "pass"}]},
            headers={"X-Attacca-Actor": "webplans.director.codex"})
        self.assertEqual(finished["status"], "done")

        latest = self.request("GET", base, token=self.human_token)
        historical = self.request(
            "GET", base + "?" + urllib.parse.urlencode({"version": 1}),
            token=self.human_token)
        self.assertEqual(latest["plan"]["version"], 2)
        self.assertEqual(historical["plan"]["version"], 1)
        self.assertEqual(historical["plan"]["status"], "changes_requested")
        self.assertEqual([item["version"] for item in latest["revisions"]],
                         [2, 1])

    def test_rest_version_conflict_permissions_and_validation(self):
        created = self.request(
            "POST", "/v1/projects/webplans/tasks",
            {"title": "Conflict task", "plan_required": True},
            headers={"X-Attacca-Actor": "webplans.director.codex"})
        base = "/v1/projects/webplans/tasks/%s/plan" % created["task_id"]
        self.request(
            "PUT", base, {"title": "v1", "sections": SECTIONS},
            headers={"X-Attacca-Actor": "webplans.director.codex"})
        stale = self.request(
            "PUT", base,
            {"title": "stale", "sections": SECTIONS,
             "expected_version": 0},
            headers={"X-Attacca-Actor": "webplans.director.codex"},
            expected=400)
        self.assertIn("stale task plan", stale["error"])
        denied = self.request(
            "POST", base + "/review",
            {"expected_version": 1, "action": "approve"},
            token=self.advisor_token,
            headers={"X-Attacca-Actor": "webplans.advisor.claude"},
            expected=400)
        self.assertIn("plan must be in_review", denied["error"])
        self.request(
            "POST", base + "/submit", {"expected_version": 1},
            headers={"X-Attacca-Actor": "webplans.director.codex"})
        denied = self.request(
            "POST", base + "/review",
            {"expected_version": 1, "action": "approve"},
            token=self.advisor_token,
            headers={"X-Attacca-Actor": "webplans.advisor.claude"},
            expected=400)
        self.assertIn("approval requires", denied["error"])
        invalid = self.request(
            "POST", base + "/review",
            {"expected_version": 1, "action": "suggest_edit",
             "section_id": "unknown", "note": "No such section"},
            token=self.advisor_token,
            headers={"X-Attacca-Actor": "webplans.advisor.claude"},
            expected=400)
        self.assertIn("unknown plan section", invalid["error"])

        conn = c.connect(self.db)
        rows = conn.execute(
            "SELECT actor_id, actor_type, owner, git_branch, base_revision,"
            " device_id FROM events WHERE project_id='webplans'"
            " AND event_type LIKE 'task.plan.%' ORDER BY seq").fetchall()
        self.assertTrue(rows)
        self.assertTrue(all(row["owner"] == "jdevgy" for row in rows))
        self.assertTrue(c.verify_ledger(conn, "webplans")["ok"])
        conn.close()


if __name__ == "__main__":
    unittest.main()
