"""Lifecycle stale-link checks must not trust a paginated project page."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_hook_project_page_fallback", ROOT / "hooks" / "session_start.py")
hook = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hook)


def success(request_id, payload):
    return {"jsonrpc": "2.0", "id": request_id, "result": {
        "content": [{"type": "text", "text": json.dumps(payload)}]}}


class HookProjectPageFallbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.status = {"root": str(self.checkout),
                       "project_id": "target-workspace"}
        self.config = {"url": "https://attacca.invalid",
                       "actor": "codex", "owner": ""}

    def completed(self, exact_status=None):
        rows = {
            2: {"projects": [
                    {"project_id": "other-%03d" % index,
                     "name": "Other %03d" % index}
                    for index in range(60)],
                "total": 101, "unfiltered_total": 101, "limit": 60,
                "offset": 0, "has_more": True},
            3: {"agents": [], "total": 0, "unfiltered_total": 0,
                "limit": 60, "offset": 0, "has_more": False},
            4: {"rules": [], "total": 0, "unfiltered_total": 0,
                "limit": 60, "offset": 0, "has_more": False},
            5: {"cloud_context": {"version": 0, "content": ""}},
            6: {"scopes": []},
            7: {"handoff": {}, "context_version": 1},
            8: {"log": []},
            9: {"messages": [], "unread_total": 0},
            10: {"messages": []},
            11: {"tasks": [], "total": 0, "unfiltered_total": 0,
                 "limit": 60, "offset": 0, "has_more": False},
            12: exact_status,
        }
        responses = [success(request_id, payload)
                     for request_id, payload in rows.items()
                     if payload is not None]
        if exact_status is None:
            responses.append({
                "jsonrpc": "2.0", "id": 12, "result": {
                    "isError": True,
                    "content": [{"type": "text",
                                 "text": "unknown project target-workspace"}],
                }})
        return subprocess.CompletedProcess(
            ["attacca", "connect"], 0,
            stdout="\n".join(json.dumps(item) for item in responses) + "\n",
            stderr="")

    def test_exact_scoped_status_proves_valid_link_omitted_from_first_page(self):
        exact = {"project": "target-workspace", "counts": {},
                 "you": {"actor_id": "target-workspace.director.codex"}}
        with mock.patch.object(
                hook.subprocess, "run", return_value=self.completed(exact)):
            snapshot = hook._mcp_snapshot(
                self.status, ROOT, self.config, mark_inbox_read=False)
        self.assertEqual(snapshot["project"], "target-workspace")
        self.assertEqual(snapshot["status"], exact)

    def test_missing_exact_status_still_reports_stale_with_partial_label(self):
        with mock.patch.object(
                hook.subprocess, "run", return_value=self.completed(None)):
            with self.assertRaisesRegex(
                    hook.StaleProjectLink,
                    r"Available workspaces \(first page\): Other 000"):
                hook._mcp_snapshot(
                    self.status, ROOT, self.config, mark_inbox_read=False)


if __name__ == "__main__":
    unittest.main()
