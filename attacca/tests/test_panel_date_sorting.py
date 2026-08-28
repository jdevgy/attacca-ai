"""Control Panel date sorting and curated Project Log regressions."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


PANEL = Path(__file__).resolve().parents[1] / "web" / "admin.html"


class PanelDateSortingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PANEL.read_text(encoding="utf-8")
        match = re.search(
            r"// TESTABLE_SORT_HELPERS:BEGIN\n(?P<body>.*?)"
            r"\n\s*// TESTABLE_SORT_HELPERS:END",
            cls.source,
            flags=re.DOTALL,
        )
        if not match:
            raise AssertionError("testable sort-helper block is missing")
        cls.helpers = match.group("body")

    def run_node(self, assertions: str) -> None:
        program = "\n".join([
            '"use strict";',
            'const assert = require("node:assert/strict");',
            self.helpers,
            assertions,
        ])
        completed = subprocess.run(
            ["node", "-e", program], capture_output=True, text=True,
            timeout=10, check=False)
        self.assertEqual(completed.returncode, 0,
                         msg=completed.stderr + completed.stdout)

    def test_sort_directions_ties_fallbacks_and_invalid_dates(self) -> None:
        self.run_node("""
          const rows = [
            {task_id: "T-10", updated_at: "2026-01-02T00:00:00Z"},
            {task_id: "T-2", updated_at: "2026-01-02T00:00:00Z"},
            {task_id: "T-1", created_at: "2026-01-01T00:00:00Z"},
            {task_id: "T-99", updated_at: "invalid"}
          ];
          const newest = sortDatedRows(rows, {
            direction: "newest", dateFields: ["updated_at", "created_at"],
            idFields: ["task_id"]});
          assert.deepEqual(newest.map(row => row.task_id),
                           ["T-10", "T-2", "T-1", "T-99"]);
          const oldest = sortDatedRows(rows, {
            direction: "oldest", dateFields: ["updated_at", "created_at"],
            idFields: ["task_id"]});
          assert.deepEqual(oldest.map(row => row.task_id),
                           ["T-1", "T-2", "T-10", "T-99"]);
          assert.deepEqual(rows.map(row => row.task_id),
                           ["T-10", "T-2", "T-1", "T-99"]);
        """)

    def test_panel_exposes_persistent_sorting_and_distinct_log_view(self) -> None:
        for view in ("workspaces", "tasks", "decisions", "handoff", "rules",
                     "agents", "network", "log"):
            self.assertIn(f'sortControl("{view}")', self.source)
        self.assertIn('storageGet("attacca.admin.sorts"', self.source)
        self.assertIn('storageSet("attacca.admin.sorts"', self.source)
        self.assertIn('data-view="log"', self.source)
        self.assertIn("function renderLog()", self.source)
        self.assertIn('log: pathFor("/log?limit=80")', self.source)
        self.assertIn("Activity remains the complete raw event ledger", self.source)
        self.assertIn("Newest first", self.source)
        self.assertIn("Oldest first", self.source)
        self.assertIn('for (const warning of result?.warnings || [])',
                      self.source)
        self.assertIn('toast(warning, "warning")', self.source)
        self.assertIn("Oldest first” sorts within this loaded window",
                      self.source)


if __name__ == "__main__":
    unittest.main()
