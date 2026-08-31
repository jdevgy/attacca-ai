"""Lifecycle startup drains every binding-rule page before compaction."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_hook_rule_pagination", ROOT / "hooks" / "session_start.py")
hook = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hook)


def success(request_id, payload):
    return {"jsonrpc": "2.0", "id": request_id, "result": {
        "content": [{"type": "text", "text": json.dumps(payload)}]}}


class HookRulePaginationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.checkout = Path(self.temp.name) / "checkout"
        self.checkout.mkdir()
        self.status = {"root": str(self.checkout), "project_id": "rules"}
        self.config = {"url": "https://attacca.invalid",
                       "actor": "codex", "owner": ""}
        self.actor = "rules.director.codex.gibbs"
        self.rules = [{
            "project_id": "rules", "rule_id": "R-%d" % (index + 1),
            "title": "Rule %03d" % index,
            "body": ("binding-%03d " % index) + ("x" * 400),
            "scope": "everyone", "priority": index,
            "enabled": True, "version": 1,
        } for index in range(137)]

    def completed(self, responses):
        return subprocess.CompletedProcess(
            ["attacca", "connect"], 0,
            stdout="\n".join(json.dumps(item) for item in responses) + "\n",
            stderr="")

    def initial_responses(self, total=None):
        total = len(self.rules) if total is None else total
        first = self.rules[:hook.STARTUP_RULE_PAGE_SIZE]
        payloads = {
            2: {"projects": [{"project_id": "rules", "name": "Rules"}],
                "total": 1, "unfiltered_total": 1, "limit": 60,
                "offset": 0, "has_more": False},
            3: {"agents": [{"agent_id": self.actor, "role": "director",
                            "runtime": "codex"}],
                "total": 1, "unfiltered_total": 1, "limit": 60,
                "offset": 0, "has_more": False},
            4: {"rules": first, "total": total,
                "unfiltered_total": total,
                "enabled_total": total, "limit": 60, "offset": 0,
                "has_more": len(first) < total},
            5: {"cloud_context": None},
            6: {"role_scope": None},
            7: {"handoff": {}, "context_version": 1, "decisions": [],
                "recent_activity": []},
            8: {"entries": [], "total": 0, "unfiltered_total": 0,
                "limit": 60, "offset": 0, "has_more": False},
            9: {"messages": [], "unread_total": 0},
            10: {"messages": []},
            11: {"tasks": [], "total": 0, "unfiltered_total": 0,
                 "limit": 60, "offset": 0, "has_more": False},
            12: {"project": "rules", "counts": {}, "you": {
                "actor_id": self.actor, "actor_type": "agent",
                "identity": {"role": "director", "runtime": "codex"}}},
        }
        return [success(request_id, payload)
                for request_id, payload in payloads.items()]

    def test_startup_drains_later_pages_then_names_compaction_omissions(self):
        calls = []

        def run(*_args, **kwargs):
            requests = [json.loads(line)
                        for line in kwargs["input"].splitlines()]
            calls.append(requests)
            rule_calls = [item for item in requests
                          if item.get("method") == "tools/call" and
                          item.get("params", {}).get("name") == "rule_list"]
            if any(item.get("id") == 4 for item in rule_calls):
                return self.completed(self.initial_responses())
            responses = []
            for item in rule_calls:
                offset = item["params"]["arguments"]["offset"]
                page = self.rules[offset:offset + 60]
                responses.append(success(item["id"], {
                    "rules": page, "total": len(self.rules),
                    "unfiltered_total": len(self.rules),
                    "enabled_total": len(self.rules),
                    "limit": 60, "offset": offset,
                    "has_more": offset + len(page) < len(self.rules),
                }))
            return self.completed(responses)

        with mock.patch.object(hook.subprocess, "run", side_effect=run):
            snapshot = hook._mcp_snapshot(
                self.status, ROOT, self.config, mark_inbox_read=False)
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            [item["params"]["arguments"]["offset"]
             for item in calls[1] if item.get("method") == "tools/call"],
            [60, 120])
        self.assertEqual(
            [row["rule_id"] for row in snapshot["rules"]["rules"]],
            [row["rule_id"] for row in self.rules])
        self.assertFalse(snapshot["rules"]["has_more"])

        compact = hook._compact_snapshot(snapshot)
        included = {row["rule_id"] for row in compact["project_rules"]}
        omitted = set(compact["project_rules_omitted_ids"])
        self.assertTrue(omitted)
        self.assertEqual(included | omitted,
                         {row["rule_id"] for row in self.rules})

    def test_startup_rejects_rule_directory_above_finite_bound(self):
        too_many = (hook.STARTUP_RULE_PAGE_SIZE *
                    hook.STARTUP_RULE_MAX_PAGES) + 1
        with mock.patch.object(
                hook.subprocess, "run",
                return_value=self.completed(
                    self.initial_responses(total=too_many))) as run:
            with self.assertRaisesRegex(
                    RuntimeError, "above the startup safety bound"):
                hook._mcp_snapshot(
                    self.status, ROOT, self.config, mark_inbox_read=False)
        self.assertEqual(run.call_count, 1)

    def test_startup_accepts_complete_legacy_unpaged_rule_directory(self):
        responses = self.initial_responses()
        responses = [
            success(4, {"rules": self.rules}) if item.get("id") == 4
            else item for item in responses]
        with mock.patch.object(
                hook.subprocess, "run",
                return_value=self.completed(responses)) as run:
            snapshot = hook._mcp_snapshot(
                self.status, ROOT, self.config, mark_inbox_read=False)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(len(snapshot["rules"]["rules"]), len(self.rules))
        self.assertEqual(snapshot["rules"]["total"], len(self.rules))
        self.assertFalse(snapshot["rules"]["has_more"])
        self.assertTrue(snapshot["rules"]["legacy_unpaged"])


if __name__ == "__main__":
    unittest.main()
