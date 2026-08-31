"""render_state_markdown: the synced Attacca projection rendered as Markdown
files (HANDOFF, CLOUD_CONTEXT, RULES, TASKS, DECISIONS, ROOM, LOG) so the local
sync produces human/AI-readable files, not just snapshot.json."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ["ATTACCA_OWNER"] = ""
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("attacca", ROOT / "attacca.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def _projection():
    return {
        "project": {"project_id": "p1", "name": "P1"},
        "handoffs": [{"version": 2, "updated_by": "p1.director.claude",
                      "content": json.dumps({
                          "objective": "Ship it",
                          "next_actions": "Do the thing"})}],
        "cloud_context": {"content": "# Summary\nProd only.", "version": 3},
        "rules": [
            {"rule_id": "R-2", "title": "Low pri", "body": "later",
             "scope": "everyone", "priority": 200, "enabled": True},
            {"rule_id": "R-1", "title": "High pri", "body": "commit to main",
             "scope": "director", "priority": 10, "enabled": True},
        ],
        "tasks": [{"task_id": "T-1", "status": "done",
                   "claimed_by": "x", "title": "First | task"}],
        "decisions": [{"decision_id": "D-1", "title": "Use SQLite",
                       "status": "accepted", "detail": "WAL mode",
                       "rationale": "zero-dep"}],
        "room_messages": [{"actor": "p1.director.claude", "msg_type": "chat",
                           "at": "2026-08-26", "body": "hello\nthere"}],
        "full_log": ["2026-08-26 event.one", "2026-08-26 event.two"],
    }


class RenderStateMarkdownTestCase(unittest.TestCase):
    def test_renders_all_sections(self):
        out = c.render_state_markdown(_projection())
        self.assertEqual(set(out), {
            "README.md", "HANDOFF.md", "CLOUD_CONTEXT.md", "RULES.md",
            "TASKS.md", "DECISIONS.md", "ROOM.md", "LOG.md"})

    def test_handoff_json_content_is_parsed(self):
        out = c.render_state_markdown(_projection())
        self.assertIn("Ship it", out["HANDOFF.md"])
        self.assertIn("## Objective", out["HANDOFF.md"])

    def test_cloud_context_passthrough(self):
        out = c.render_state_markdown(_projection())
        self.assertIn("Prod only.", out["CLOUD_CONTEXT.md"])

    def test_rules_sorted_by_priority(self):
        out = c.render_state_markdown(_projection())
        self.assertLess(out["RULES.md"].index("R-1"), out["RULES.md"].index("R-2"))

    def test_tasks_table_escapes_pipe(self):
        out = c.render_state_markdown(_projection())
        self.assertIn("| T-1 | done |", out["TASKS.md"])
        self.assertIn("First \\| task", out["TASKS.md"])

    def test_log_and_room_and_decisions(self):
        out = c.render_state_markdown(_projection())
        self.assertIn("event.one", out["LOG.md"])
        self.assertIn("hello there", out["ROOM.md"])
        self.assertIn("D-1", out["DECISIONS.md"])

    def test_empty_projection_is_safe(self):
        out = c.render_state_markdown({})
        self.assertIn("HANDOFF.md", out)
        self.assertIn("_No handoff written yet._", out["HANDOFF.md"])
        self.assertEqual(c.render_state_markdown(None).keys(), out.keys())

    def test_write_state_markdown_creates_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "mirror"
            written = c.write_state_markdown(str(target), _projection())
            self.assertEqual(len(written), 8)
            self.assertTrue((target / "HANDOFF.md").is_file())
            self.assertIn("Ship it", (target / "HANDOFF.md").read_text())
            # idempotent re-write
            c.write_state_markdown(str(target), _projection())
            self.assertEqual(len(list(target.glob("*.md"))), 8)


if __name__ == "__main__":
    unittest.main()
