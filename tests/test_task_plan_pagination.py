"""Bounded full-data pagination for task-plan revisions and actions.

All fixtures use temporary SQLite files and ephemeral loopback servers.  The
configured/shared Attacca process is never discovered or contacted.
"""

import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from tests.test_http import ServerFixture


os.environ["ATTACCA_OWNER"] = ""
ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_task_plan_pagination_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class TaskPlanPaginationTests(unittest.TestCase):
    REVISION_COUNT = 137
    ACTION_COUNT = 137

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.db = self.root / "task-plan-pages.db"
        self.connection = c.connect(self.db)
        self.addCleanup(self.connection.close)
        checkout = self.root / "checkout"
        checkout.mkdir()
        c.project_init(
            self.connection, "fixture", "human", path=checkout,
            project_id="planpages", name="Plan pages")
        self.actor = "planpages.director.codex"
        c.agent_register(
            self.connection, "planpages", "fixture", "human",
            agent_id=self.actor, role="director", runtime="codex")
        self.task_id = c.task_create(
            self.connection, "planpages", self.actor, "agent",
            "Large plan history", plan_required=True)["task_id"]
        self._seed_revisions()
        self._seed_actions()

    @staticmethod
    def timestamp(number):
        minute, second = divmod(number, 60)
        return "2026-08-31T00:%02d:%02d.000Z" % (minute, second)

    def _seed_revisions(self):
        statuses = c.TASK_PLAN_STATUSES
        for version in range(1, self.REVISION_COUNT + 1):
            marker = " Needle Revision" if version in {3, 80, 131} else ""
            title = "Plan revision %03d%s" % (version, marker)
            sections = [{
                "section_id": "scope", "title": "Scope",
                "body": "Revision %03d full body%s" % (
                    version,
                    " sectionmarkereighty" if version == 80 else ""),
            }]
            digest = hashlib.sha256(
                ("plan-%03d" % version).encode("ascii")).hexdigest()
            at = self.timestamp(version)
            self.connection.execute(
                "INSERT INTO task_plan_revisions "
                "(project_id,task_id,version,title,overview,sections,status,"
                "content_sha256,authored_by,authored_owner,authored_at,"
                "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                ("planpages", self.task_id, version, title,
                 "Overview for revision %03d%s" % (
                     version,
                     " overviewmarkereightyone" if version == 81 else ""),
                 json.dumps(sections), statuses[(version - 1) % len(statuses)],
                 digest, self.actor, "fixture", at, at))

    def _seed_actions(self):
        event_types = c.TASK_PLAN_EVENT_TYPES
        for ordinal in range(1, self.ACTION_COUNT + 1):
            note = "Deep Action Marker" if ordinal == 120 else \
                "Action note %03d" % ordinal
            c.append_event(
                self.connection, "planpages", self.actor, "agent",
                event_types[(ordinal - 1) % len(event_types)],
                {"plan_version": self.REVISION_COUNT,
                 "ordinal": ordinal, "note": note},
                task_id=self.task_id)

    def get(self, **kwargs):
        return c.task_plan_get(
            self.connection, "planpages", self.task_id, **kwargs)

    def test_default_pages_are_capped_exact_and_keep_selected_plan(self):
        opened = self.get(revision_limit=999, action_limit=999)
        self.assertEqual(opened["plan"]["version"], self.REVISION_COUNT)
        self.assertEqual(
            [row["version"] for row in opened["revisions"]],
            list(range(137, 77, -1)))
        self.assertEqual(
            [row["payload"]["ordinal"]
             for row in opened["plan"]["actions"]],
            list(range(1, 61)))
        self.assertEqual(
            {key: opened[key] for key in (
                "total", "unfiltered_total", "limit", "offset",
                "has_more")},
            {"total": 137, "unfiltered_total": 137, "limit": 60,
             "offset": 0, "has_more": True})
        expected_actions = {
            "total": 137, "unfiltered_total": 137, "limit": 60,
            "offset": 0, "has_more": True,
        }
        self.assertEqual(
            opened["pagination"]["actions"], expected_actions)
        self.assertEqual(
            opened["plan"]["actions_pagination"], expected_actions)
        for key in ("actions", "approvals", "suggestions", "comments"):
            self.assertLessEqual(len(opened["plan"][key]), 60)

        second = self.get(revision_offset=60, action_offset=60)
        self.assertEqual(
            [row["version"] for row in second["revisions"]],
            list(range(77, 17, -1)))
        self.assertEqual(
            [row["payload"]["ordinal"]
             for row in second["plan"]["actions"]],
            list(range(61, 121)))
        self.assertEqual(second["offset"], 60)
        self.assertTrue(second["has_more"])
        self.assertEqual(
            second["pagination"]["actions"]["offset"], 60)

        last = self.get(revision_offset=120, action_offset=120)
        self.assertEqual(len(last["revisions"]), 17)
        self.assertEqual(len(last["plan"]["actions"]), 17)
        self.assertFalse(last["has_more"])
        self.assertFalse(last["pagination"]["actions"]["has_more"])

    def test_search_filter_sort_and_offsets_use_complete_histories(self):
        revision = self.get(
            revision_query="needle revision", revision_filter="approved")
        self.assertEqual(revision["plan"]["version"], 137)
        self.assertEqual(
            [row["version"] for row in revision["revisions"]], [80])
        self.assertEqual(revision["total"], 1)
        self.assertEqual(revision["unfiltered_total"], 137)
        self.assertFalse(revision["has_more"])

        oldest_approved = self.get(
            revision_filter="approved", revision_sort="oldest",
            revision_limit=3)
        self.assertEqual(
            [row["version"] for row in oldest_approved["revisions"]],
            [4, 8, 12])
        self.assertEqual(oldest_approved["total"], 34)
        self.assertEqual(oldest_approved["unfiltered_total"], 137)

        action = self.get(
            action_query="deep action marker", action_filter="comments")
        self.assertEqual(
            [row["payload"]["ordinal"]
             for row in action["plan"]["actions"]], [120])
        self.assertEqual(action["pagination"]["actions"]["total"], 1)
        self.assertEqual(
            action["pagination"]["actions"]["unfiltered_total"], 137)
        newest_comments = self.get(
            action_filter="comments", action_sort="newest", action_limit=3)
        self.assertEqual(
            [row["payload"]["ordinal"]
             for row in newest_comments["plan"]["actions"]],
            [132, 126, 120])
        self.assertEqual(
            newest_comments["pagination"]["actions"]["total"], 22)

    def test_revision_search_uses_full_overview_and_section_bodies(self):
        body_only = self.get(
            revision_query="sectionmarkereighty", revision_limit=5)
        self.assertEqual(
            [row["version"] for row in body_only["revisions"]], [80])
        self.assertNotIn("_search_content", body_only["revisions"][0])

        overview_only = self.get(
            revision_query="overviewmarkereightyone", revision_limit=5)
        self.assertEqual(
            [row["version"] for row in overview_only["revisions"]], [81])
        self.assertNotIn("_search_content", overview_only["revisions"][0])

    def test_invalid_filters_and_sorts_fail_without_partial_pages(self):
        for kwargs, message in (
                ({"revision_filter": "not-a-status"}, "revision_filter"),
                ({"action_filter": "not-an-action"}, "action_filter"),
                ({"revision_sort": "sideways"}, "revision_sort"),
                ({"action_sort": "sideways"}, "action_sort")):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(
                    c.AttaccaError, message):
                self.get(**kwargs)

    def test_mcp_schema_and_dispatch_expose_both_independent_pages(self):
        tool = next(item for item in c.MCP_TOOLS
                    if item["name"] == "task_plan_get")
        properties = tool["inputSchema"]["properties"]
        for prefix in ("revision", "action"):
            for suffix in ("q", "filter", "limit", "offset", "sort"):
                self.assertIn("%s_%s" % (prefix, suffix), properties)
            self.assertEqual(properties[prefix + "_limit"]["maximum"], 60)

        session = c.McpSession(
            self.db, default_project="planpages", actor=self.actor,
            actor_type="agent", detect_cwd=False, owner="fixture",
            preserve_actor_identity=True)
        try:
            opened = session.dispatch_tool("task_plan_get", {
                "task_id": self.task_id,
                "revision_filter": "approved", "revision_limit": 2,
                "revision_sort": "oldest",
                "action_filter": "comments", "action_limit": 2,
                "action_sort": "newest",
            })
        finally:
            if session.conn is not None:
                session.conn.close()
        self.assertEqual(
            [row["version"] for row in opened["revisions"]], [4, 8])
        self.assertEqual(
            [row["payload"]["ordinal"]
             for row in opened["plan"]["actions"]], [132, 126])
        self.assertEqual(opened["limit"], 2)
        self.assertEqual(opened["plan"]["actions_pagination"]["limit"], 2)

    def test_rest_parses_page_search_filter_and_sort_query_parameters(self):
        server = ServerFixture(self.db)
        self.addCleanup(server.stop)
        query = urllib.parse.urlencode({
            "revision_q": "needle revision",
            "revision_filter": "approved",
            "revision_limit": 1,
            "revision_offset": 0,
            "revision_sort": "oldest",
            "action_filter": "comments",
            "action_limit": 2,
            "action_offset": 1,
            "action_sort": "newest",
        })
        status, opened, _ = server.request(
            "GET", "/v1/projects/planpages/tasks/%s/plan?%s" %
            (self.task_id, query), headers={
                "X-Attacca-Actor": self.actor,
            })
        self.assertEqual(status, 200, opened)
        self.assertEqual(
            [row["version"] for row in opened["revisions"]], [80])
        self.assertEqual(opened["total"], 1)
        self.assertEqual(opened["unfiltered_total"], 137)
        self.assertEqual(
            [row["payload"]["ordinal"]
             for row in opened["plan"]["actions"]], [126, 120])
        self.assertEqual(opened["pagination"]["actions"], {
            "total": 22, "unfiltered_total": 137, "limit": 2,
            "offset": 1, "has_more": True,
        })

    def test_verified_offline_plan_uses_the_same_independent_sixty_row_pages(self):
        plans = []
        for row in self.connection.execute(
                "SELECT * FROM task_plan_revisions WHERE project_id=?"
                " AND task_id=? ORDER BY version",
                ("planpages", self.task_id)).fetchall():
            item = dict(row)
            item["sections"] = json.loads(item["sections"] or "[]")
            plans.append(item)
        records = []
        for row in self.connection.execute(
                "SELECT * FROM events WHERE project_id=? AND task_id=?"
                " AND event_type LIKE 'task.plan.%' ORDER BY seq",
                ("planpages", self.task_id)).fetchall():
            event = dict(row)
            event["payload"] = json.loads(event["payload"] or "{}")
            records.append({"kind": "event", "seq": event["seq"],
                            "event": event})
        snapshot = {
            "scope": {"project_id": "planpages"},
            "projection": {
                "tasks": [{"task_id": self.task_id}],
                "task_plans": plans,
            },
            "records": records,
        }
        opened = c._offline_proxy_plan(
            snapshot, self.task_id, revision_limit=999, action_limit=999)
        self.assertEqual(len(opened["revisions"]), 60)
        self.assertEqual(len(opened["plan"]["actions"]), 60)
        self.assertEqual(opened["unfiltered_total"], self.REVISION_COUNT)
        self.assertEqual(
            opened["pagination"]["actions"]["unfiltered_total"],
            self.ACTION_COUNT)
        self.assertTrue(opened["has_more"])
        self.assertTrue(opened["pagination"]["actions"]["has_more"])

        second = c._offline_proxy_plan(
            snapshot, self.task_id, revision_offset=60,
            action_offset=60, revision_sort="newest", action_sort="oldest")
        self.assertEqual(
            [row["version"] for row in second["revisions"]],
            list(range(77, 17, -1)))
        self.assertEqual(
            [row["payload"]["ordinal"]
             for row in second["plan"]["actions"]],
            list(range(61, 121)))

        body_only = c._offline_proxy_plan(
            snapshot, self.task_id,
            revision_query="sectionmarkereighty", revision_limit=5)
        self.assertEqual(
            [row["version"] for row in body_only["revisions"]], [80])
        self.assertNotIn("_search_content", body_only["revisions"][0])
        overview_only = c._offline_proxy_plan(
            snapshot, self.task_id,
            revision_query="overviewmarkereightyone", revision_limit=5)
        self.assertEqual(
            [row["version"] for row in overview_only["revisions"]], [81])


if __name__ == "__main__":
    unittest.main()
