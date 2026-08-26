"""Live REST/startup regressions for durable role-scoped Project Rules."""

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


# Keep ledger attribution independent from the machine running the suite.
os.environ["ATTACCA_OWNER"] = ""

from attacca.tests.test_http import ServerFixture  # noqa: E402


ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "session_start.py"
SPEC = importlib.util.spec_from_file_location(
    "attacca_project_rules_live_api_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)

REPO_ONLY_WORKFLOW_TEXT = (
    "Maximum-effort completion and fan-out",
    "Two QA passes before completion",
)


class ProjectRulesLiveApiTest(unittest.TestCase):
    """Drive the real hosted HTTP server and native startup hook."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "project-rules.db"
        self.checkout = self.root / "repo"
        self.checkout.mkdir()
        link = self.checkout / ".attacca"
        link.mkdir()
        (link / "project.json").write_text(json.dumps({
            "schema_version": 1,
            "project_id": "rulespace",
        }))
        conn = c.connect(self.db)
        c.project_init(
            conn, "setup", "human", path=str(self.checkout),
            project_id="rulespace", name="Rule Space")
        conn.close()
        self.server = ServerFixture(self.db)

    def tearDown(self):
        self.server.stop()
        c.set_current_owner(None)
        self.tmp.cleanup()

    @staticmethod
    def _headers(actor="rules-owner", actor_type="human"):
        return {
            "X-Attacca-Actor": actor,
            "X-Attacca-Actor-Type": actor_type,
        }

    def _request(self, method, path, body=None, actor="rules-owner",
                 actor_type="human", expected=200):
        status, payload, _ = self.server.request(
            method, path, body,
            headers=self._headers(actor, actor_type))
        self.assertEqual(status, expected, payload)
        return payload

    def _register(self, runtime, role):
        result = self._request(
            "POST", "/v1/projects/rulespace/agents",
            {"agent_id": runtime,
             "display_name": "%s %s" % (role.title(), runtime.title()),
             "role": role, "runtime": runtime},
            actor=runtime, actor_type="agent")
        self.assertEqual(result["role"], role)
        self.assertEqual(result["agent_id"],
                         "rulespace.%s.%s" % (role, runtime))
        return result["agent_id"]

    def _create_rule(self, title, scope, priority, body=None,
                     actor="rules-owner", actor_type="human"):
        result = self._request(
            "POST", "/v1/projects/rulespace/rules",
            {"title": title,
             "body": body or "%s server directive body" % title,
             "scope": scope, "priority": priority},
            actor=actor, actor_type=actor_type)
        rule = result["rule"]
        self.assertEqual(rule["scope"], scope)
        self.assertEqual(rule["priority"], priority)
        self.assertTrue(rule["enabled"])
        self.assertEqual(rule["version"], 1)
        return rule

    def _rules(self, actor="rules-owner", actor_type="human",
               management=False, expected=200):
        suffix = "?include_all=1&include_disabled=1" if management else ""
        return self._request(
            "GET", "/v1/projects/rulespace/rules" + suffix,
            actor=actor, actor_type=actor_type, expected=expected)

    @staticmethod
    def _titles(payload, field="rules"):
        return [rule["title"] for rule in payload[field]]

    def _run_startup(self, runtime="codex"):
        home = self.root / ("home-" + runtime)
        data = self.root / ("plugin-data-" + runtime)
        home.mkdir(exist_ok=True)
        env = dict(os.environ)
        env["PLUGIN_ROOT"] = str(ROOT)
        env["PLUGIN_DATA"] = str(data)
        env["HOME"] = str(home)
        env["ATTACCA_URL"] = self.server.base
        env["ATTACCA_ACTOR"] = runtime
        env["ATTACCA_OWNER"] = ""
        env["ATTACCA_DISABLE_WATCHER"] = "1"
        env["ATTACCA_WATCHER_DIR"] = str(
            self.root / ("watcher-" + runtime))
        for key in ("CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA",
                    "KIMI_PLUGIN_ROOT", "KIMI_PLUGIN_DATA"):
            env.pop(key, None)
        result = subprocess.run(
            [sys.executable, str(HOOK)], cwd=str(self.checkout), env=env,
            input=json.dumps({
                "cwd": str(self.checkout),
                "hook_event_name": "SessionStart",
                "source": "startup",
            }), capture_output=True, text=True, timeout=15, check=True)
        self.assertTrue(result.stdout, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn("Attacca active", payload["systemMessage"])
        context = payload["hookSpecificOutput"]["additionalContext"]
        self.assertIn("ATTACCA ACTIVE SESSION BRIEF", context)
        brief = json.loads(context.split("\n\n", 1)[1])
        return payload, context, brief

    def test_rest_crud_toggle_and_optimistic_version_conflict(self):
        director = self._register("codex", "director")
        created = self._create_rule(
            "Protect API v2", "director", 40,
            body="Only Directors may approve the v2 boundary.",
            actor=director, actor_type="agent")

        managed = self._rules(
            actor=director, actor_type="agent", management=True)
        self.assertEqual(self._titles(managed), ["Protect API v2"])
        self.assertEqual(managed["rules"][0], created)

        path = "/v1/projects/rulespace/rules/%s" % created["rule_id"]
        updated = self._request(
            "PUT", path,
            {"title": "Protect advisor API v2",
             "body": "Advisors review; Directors retain final authority.",
             "scope": "advisor", "priority": 7,
             "expected_version": 1},
            actor=director, actor_type="agent")["rule"]
        self.assertEqual(updated["version"], 2)
        self.assertEqual(updated["scope"], "advisor")
        self.assertEqual(updated["priority"], 7)

        conflict = self._request(
            "PUT", path,
            {"title": "STALE OVERWRITE", "expected_version": 1},
            actor=director, actor_type="agent", expected=400)
        self.assertIn("rule conflict", conflict["error"])
        self.assertIn("v2", conflict["error"])
        after_conflict = self._rules(
            actor=director, actor_type="agent", management=True)["rules"][0]
        self.assertEqual(after_conflict["title"],
                         "Protect advisor API v2")
        self.assertEqual(after_conflict["version"], 2)

        disabled = self._request(
            "PUT", path,
            {"enabled": False, "expected_version": 2},
            actor=director, actor_type="agent")["rule"]
        self.assertFalse(disabled["enabled"])
        self.assertEqual(disabled["version"], 3)
        self.assertEqual(self._rules(
            actor=director, actor_type="agent")["rules"], [])
        managed_disabled = self._rules(
            actor=director, actor_type="agent", management=True)["rules"]
        self.assertEqual(len(managed_disabled), 1)
        self.assertFalse(managed_disabled[0]["enabled"])

        enabled = self._request(
            "PUT", path,
            {"enabled": True, "expected_version": 3},
            actor=director, actor_type="agent")["rule"]
        self.assertTrue(enabled["enabled"])
        self.assertEqual(enabled["version"], 4)
        self.assertEqual(self._rules(
            actor=director, actor_type="agent")["rules"], [])
        self.assertEqual(self._titles(self._rules()),
                         ["Protect advisor API v2"])
        managed_enabled = self._rules(
            actor=director, actor_type="agent", management=True)["rules"]
        self.assertEqual(managed_enabled[0]["version"], 4)
        self.assertTrue(managed_enabled[0]["enabled"])

    def test_role_scopes_handoff_startup_and_repo_text_boundary(self):
        director = self._register("claude", "director")
        advisor = self._register("advisorbot", "advisor")
        worker = self._register("codex", "worker")
        for title, scope, priority in (
                ("Everyone rule", "everyone", 10),
                ("Director rule", "director", 20),
                ("Advisor rule", "advisor", 30),
                ("Worker rule", "worker", 40)):
            self._create_rule(title, scope, priority)

        expected = {
            director: ["Everyone rule", "Director rule"],
            advisor: ["Everyone rule", "Advisor rule"],
            worker: ["Everyone rule", "Worker rule"],
            "rulespace.unassigned.stranger": ["Everyone rule"],
        }
        handoffs = {}
        for actor, titles in expected.items():
            listed = self._rules(actor=actor, actor_type="agent")
            self.assertEqual(self._titles(listed), titles)
            handoff = self._request(
                "GET", "/v1/projects/rulespace/handoff",
                actor=actor, actor_type="agent")
            self.assertEqual(self._titles(handoff, "project_rules"), titles)
            handoffs[actor] = handoff

        self.assertEqual(self._titles(self._rules()), [
            "Everyone rule", "Director rule", "Advisor rule", "Worker rule"])
        self.assertEqual(self._titles(self._rules(
            actor=director, actor_type="agent", management=True)), [
                "Everyone rule", "Director rule", "Advisor rule",
                "Worker rule"])
        denied = self._rules(
            actor=worker, actor_type="agent", management=True, expected=400)
        self.assertIn("registered Director", denied["error"])
        forbidden = self._request(
            "POST", "/v1/projects/rulespace/rules",
            {"title": "Worker cannot govern", "body": "must fail",
             "scope": "everyone", "priority": 1},
            actor=worker, actor_type="agent", expected=400)
        self.assertIn("registered Director", forbidden["error"])

        local_text = "# Repo-only workflow\n\n%s\n%s\n" % (
            REPO_ONLY_WORKFLOW_TEXT[0], REPO_ONLY_WORKFLOW_TEXT[1])
        (self.checkout / "AGENTS.md").write_text(local_text)
        c.install_instructions(
            "rulespace", str(self.checkout), self.db)
        installed = (self.checkout / "AGENTS.md").read_text()
        for marker in REPO_ONLY_WORKFLOW_TEXT:
            self.assertIn(marker, installed)
        managed_match = re.search(
            r"<!-- MANAGED_ATTACCA:BEGIN[\s\S]*?"
            r"<!-- MANAGED_ATTACCA:END -->", installed)
        self.assertIsNotNone(managed_match)
        generated_block = c.managed_instruction_block("rulespace", self.db)
        for marker in REPO_ONLY_WORKFLOW_TEXT:
            self.assertNotIn(marker, managed_match.group(0))
            self.assertNotIn(marker, generated_block)

        _, startup_context, startup = self._run_startup("codex")
        self.assertEqual(startup["actor"], worker)
        self.assertEqual(self._titles(startup, "project_rules"),
                         ["Everyone rule", "Worker rule"])
        self.assertEqual(startup["project_rules"],
                         handoffs[worker]["project_rules"])

        server_rules = self._rules(
            actor=director, actor_type="agent", management=True)
        boundaries = (
            json.dumps(server_rules, sort_keys=True),
            json.dumps(handoffs[worker], sort_keys=True),
            startup_context,
            generated_block,
            managed_match.group(0),
        )
        for marker in REPO_ONLY_WORKFLOW_TEXT:
            for boundary in boundaries:
                self.assertNotIn(marker, boundary)


if __name__ == "__main__":
    unittest.main()
