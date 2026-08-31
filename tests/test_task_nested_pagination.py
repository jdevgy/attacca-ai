"""Bounded task-board summaries and independently paged task histories."""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


os.environ["ATTACCA_OWNER"] = ""
ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_task_nested_pagination_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class TaskNestedPaginationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        checkout = root / "checkout"
        checkout.mkdir()
        self.conn = c.connect(root / "tasks.db")
        self.addCleanup(self.conn.close)
        c.project_init(
            self.conn, "fixture", "human", path=checkout,
            project_id="taskpages", name="Task pages")
        self.actor = "taskpages.director.codex"
        c.agent_register(
            self.conn, "taskpages", "fixture", "human",
            agent_id=self.actor, role="director", runtime="codex")
        self.task_id = c.task_create(
            self.conn, "taskpages", self.actor, "agent",
            "Deep task history")["task_id"]
        for ordinal in range(1, 138):
            c.append_event(
                self.conn, "taskpages", self.actor, "agent",
                "task.status_changed",
                {"from": "queued", "to": "queued", "ordinal": ordinal,
                 "note": "Deep Task Marker" if ordinal == 120 else
                         "ordinary"},
                task_id=self.task_id)
        for ordinal in range(72):
            c.task_create(
                self.conn, "taskpages", self.actor, "agent",
                "Additional task %03d" % ordinal)

    def test_board_is_capped_and_embeds_only_lifecycle_summary(self):
        board = c.task_list(self.conn, "taskpages")
        self.assertEqual(board["total"], 73)
        self.assertEqual(board["unfiltered_total"], 73)
        self.assertEqual(board["limit"], 60)
        self.assertEqual(len(board["tasks"]), 60)
        self.assertTrue(board["has_more"])
        deep = next(item for item in board["tasks"]
                    if item["task_id"] == self.task_id)
        self.assertEqual(deep["actions_total"], 138)
        self.assertTrue(deep["actions_compacted"])
        self.assertLessEqual(len(deep["actions"]),
                             len(c.TASK_ATTRIBUTION_EVENT_TYPES))
        self.assertEqual(
            deep["attribution"]["status_changed"]["payload"]["ordinal"],
            137)

    def test_task_show_caps_and_filters_complete_nested_histories(self):
        opened = c.task_show(self.conn, "taskpages", self.task_id)
        self.assertEqual(len(opened["actions"]), 60)
        self.assertEqual(opened["actions_pagination"], {
            "total": 138, "unfiltered_total": 138, "limit": 60,
            "offset": 0, "has_more": True,
        })
        self.assertEqual(len(opened["history"]), 60)
        self.assertEqual(opened["history_pagination"]["limit"], 60)
        self.assertTrue(opened["history_pagination"]["has_more"])

        marker = c.task_show(
            self.conn, "taskpages", self.task_id,
            action_query="deep task marker",
            action_filter="task.status_changed",
            history_query="deep task marker",
            history_filter="task.status_changed")
        self.assertEqual(
            [item["payload"]["ordinal"] for item in marker["actions"]],
            [120])
        self.assertEqual(marker["actions_pagination"]["total"], 1)
        self.assertEqual(
            marker["actions_pagination"]["unfiltered_total"], 138)
        self.assertEqual(len(marker["history"]), 1)
        self.assertEqual(marker["history_pagination"]["total"], 1)
        self.assertEqual(
            marker["history_pagination"]["unfiltered_total"], 138)

        newest = c.task_show(
            self.conn, "taskpages", self.task_id,
            action_filter="task.status_changed", action_limit=2,
            action_offset=1, action_sort="newest")
        self.assertEqual(
            [item["payload"]["ordinal"] for item in newest["actions"]],
            [136, 135])
        self.assertEqual(newest["actions_pagination"]["total"], 137)
        self.assertEqual(newest["actions_pagination"]["offset"], 1)

    def test_mcp_schema_and_dispatch_expose_independent_pages(self):
        task_list_tool = next(item for item in c.MCP_TOOLS
                              if item["name"] == "task_list")
        for field in ("q", "limit", "offset", "sort"):
            self.assertIn(field, task_list_tool["inputSchema"]["properties"])
        task_show_tool = next(item for item in c.MCP_TOOLS
                              if item["name"] == "task_show")
        for prefix in ("action", "history"):
            for suffix in ("q", "filter", "limit", "offset", "sort"):
                self.assertIn(
                    "%s_%s" % (prefix, suffix),
                    task_show_tool["inputSchema"]["properties"])

        session = c.McpSession(
            self.conn.execute("PRAGMA database_list").fetchone()["file"],
            default_project="taskpages", actor=self.actor,
            actor_type="agent", detect_cwd=False,
            preserve_actor_identity=True)
        try:
            shown = session.dispatch_tool("task_show", {
                "task_id": self.task_id,
                "action_filter": "task.status_changed",
                "action_limit": 3, "action_sort": "newest",
                "history_limit": 2, "history_offset": 2,
            })
        finally:
            if session.conn is not None:
                session.conn.close()
        self.assertEqual(len(shown["actions"]), 3)
        self.assertEqual(shown["actions"][0]["payload"]["ordinal"], 137)
        self.assertEqual(shown["actions_pagination"]["total"], 137)
        self.assertEqual(len(shown["history"]), 2)
        self.assertEqual(shown["history_pagination"]["offset"], 2)


if __name__ == "__main__":
    unittest.main()
