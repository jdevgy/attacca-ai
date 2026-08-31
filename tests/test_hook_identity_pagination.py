"""Lifecycle identity resolution across the bounded agent directory.

These tests exercise only in-memory hook snapshots.  They never discover,
query, reconfigure, or signal a running Attacca service.
"""

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "session_start.py"
SPEC = importlib.util.spec_from_file_location(
    "attacca_hook_identity_pagination_test", HOOK)
hook = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hook)


class HookIdentityPaginationTestCase(unittest.TestCase):
    def _snapshot(self, role, include_current=False):
        current = "large.director.codex.gibbs"
        agents = [{
            "agent_id": "large.worker.codex.persona-%03d" % index,
            "role": "worker",
            "runtime": "codex",
            "owner": "jack",
        } for index in range(60)]
        if include_current:
            agents[0] = {
                "agent_id": current,
                "role": role,
                "runtime": "codex",
                "owner": "jack",
                "display_name": "Gibbs",
            }
        return {
            "project": "large",
            "checked_at": "2026-08-31T00:00:00+00:00",
            "status": {
                "project": "large",
                "you": {
                    "actor_id": current,
                    "actor_type": "agent",
                    "identity": {
                        "workspace": "large",
                        "role": role,
                        "runtime": "codex",
                        "owner": "jack",
                    },
                },
                "counts": {"agents": 75},
            },
            "agents": {
                "agents": agents,
                "total": 75,
                "limit": 60,
                "offset": 0,
                "has_more": True,
            },
            "handoff": {},
            "inbox": {},
            "room": {},
            "tasks": {},
            "rules": {},
        }

    def test_configured_actor_omitted_from_first_page_does_not_reenter_setup(self):
        snapshot = self._snapshot("director")

        record = hook._current_actor_record(snapshot)
        self.assertEqual(record["agent_id"],
                         "large.director.codex.gibbs")
        self.assertEqual(record["role"], "director")
        self.assertTrue(record["status_identity_projection"])
        self.assertFalse(hook._needs_role_setup(snapshot))
        self.assertEqual(
            hook._compact_snapshot(snapshot)["actor_role"], "director")

    def test_authoritative_unassigned_status_still_requires_role_setup(self):
        snapshot = self._snapshot("unassigned")

        self.assertTrue(hook._needs_role_setup(snapshot))

    def test_matching_directory_row_remains_preferred(self):
        snapshot = self._snapshot("worker", include_current=True)

        record = hook._current_actor_record(snapshot)
        self.assertEqual(record["display_name"], "Gibbs")
        self.assertNotIn("status_identity_projection", record)
        self.assertFalse(hook._needs_role_setup(snapshot))


if __name__ == "__main__":
    unittest.main()
