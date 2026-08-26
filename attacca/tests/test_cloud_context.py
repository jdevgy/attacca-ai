"""T-48 cloud context + the mandatory-rules banner + cloud-context brief wiring.

Cloud context is a per-project free-text document (like a hosted
AGENTS.md/CLAUDE.md) injected into every session brief and editable only by
humans and registered Directors. The rules banner pins mandatory Project Rules
at the top of every injected turn so they survive host-side truncation.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

os.environ["ATTACCA_OWNER"] = ""
ROOT = Path(__file__).resolve().parent.parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


c = _load("attacca", ROOT / "attacca.py")
hook = _load("attacca_session_start_cc", ROOT / "hooks" / "session_start.py")


class CloudContextTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        self.conn = c.connect(self.db)
        repo = Path(self.tmp.name) / "repo"
        repo.mkdir()
        c.project_init(self.conn, "human", "human", path=str(repo),
                       project_id="p1", name="P1")
        c.agent_register(self.conn, "p1", "p1.director.claude", "agent",
                         role="director", runtime="claude")
        c.agent_register(self.conn, "p1", "p1.worker.kimi", "agent",
                         role="worker", runtime="kimi")

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _set(self, actor, atype, content, **kw):
        return c.cloud_context_set(self.conn, "p1", actor, atype, content, **kw)

    def test_default_is_empty(self):
        cc = c.cloud_context_get(self.conn, "p1")["cloud_context"]
        self.assertEqual(cc["content"], "")
        self.assertEqual(cc["version"], 0)

    def test_director_sets_and_reads_with_attribution(self):
        r = self._set("p1.director.claude", "agent", "# Ctx\nDeploy prod only.")
        self.assertTrue(r["ok"])
        self.assertEqual(r["cloud_context"]["version"], 1)
        cc = c.cloud_context_get(self.conn, "p1")["cloud_context"]
        self.assertEqual(cc["content"], "# Ctx\nDeploy prod only.")
        self.assertEqual(cc["updated_by"], "p1.director.claude")

    def test_human_may_edit(self):
        self.assertTrue(self._set("anyone", "human", "hi")["ok"])

    def test_worker_is_rejected(self):
        with self.assertRaises(c.AttaccaError):
            self._set("p1.worker.kimi", "agent", "nope")

    def test_unregistered_agent_is_rejected(self):
        with self.assertRaises(c.AttaccaError):
            self._set("ghost.actor", "agent", "nope")

    def test_optimistic_version_conflict(self):
        self._set("p1.director.claude", "agent", "a")
        with self.assertRaises(c.AttaccaError):
            self._set("p1.director.claude", "agent", "b", expected_version=99)
        r = self._set("p1.director.claude", "agent", "b", expected_version=1)
        self.assertEqual(r["cloud_context"]["version"], 2)

    def test_no_op_write_does_not_bump_version(self):
        self._set("p1.director.claude", "agent", "same")
        r = self._set("p1.director.claude", "agent", "same")
        self.assertTrue(r.get("already_current"))
        cc = c.cloud_context_get(self.conn, "p1")["cloud_context"]
        self.assertEqual(cc["version"], 1)

    def test_set_bumps_context_and_logs_event(self):
        before = c.get_project(self.conn, "p1")["context_version"]
        r = self._set("p1.director.claude", "agent", "x")
        self.assertGreater(r["context_version"], before)
        self.assertEqual(r["event"]["event_type"], "cloud_context.updated")

    def test_length_limit_enforced(self):
        with self.assertRaises(c.AttaccaError):
            self._set("p1.director.claude", "agent", "z" * 100001)

    def test_injected_into_get_handoff(self):
        self._set("p1.director.claude", "agent", "brief me")
        handoff = c.get_handoff(self.conn, "p1", actor_id="p1.director.claude",
                                actor_type="agent")
        self.assertIn("cloud_context", handoff)
        self.assertEqual(handoff["cloud_context"]["content"], "brief me")


class MandatoryRulesBannerTestCase(unittest.TestCase):
    def test_pins_rules_sorted_by_priority(self):
        rules = [
            {"rule_id": "R-1", "title": "Commit to main",
             "body": "commit at checkpoints", "scope": "director",
             "priority": 100, "enabled": True},
            {"rule_id": "R-4", "title": "Say OK JACK",
             "body": "say OK JACK first", "scope": "everyone",
             "priority": 1, "enabled": True},
        ]
        banner = hook._mandatory_rules_banner(rules)
        self.assertIn("MANDATORY PROJECT RULES", banner)
        self.assertIn("BINDING on EVERY response", banner)
        # priority 1 must sort ahead of priority 100
        self.assertLess(banner.index("R-4"), banner.index("R-1"))
        self.assertIn("say OK JACK first", banner)

    def test_none_when_empty_or_all_disabled(self):
        self.assertIsNone(hook._mandatory_rules_banner([]))
        self.assertIsNone(hook._mandatory_rules_banner(None))
        self.assertIsNone(hook._mandatory_rules_banner([
            {"rule_id": "R-1", "title": "x", "body": "y", "scope": "everyone",
             "priority": 100, "enabled": False}]))

    def test_stays_under_truncation_budget(self):
        rules = [{"rule_id": "R-%d" % i, "title": "Rule %d" % i,
                  "body": "body %d" % i, "scope": "everyone",
                  "priority": i, "enabled": True} for i in range(4)]
        self.assertLess(len(hook._mandatory_rules_banner(rules)), 2048)

    def test_long_body_is_never_partially_rendered(self):
        banner = hook._mandatory_rules_banner([
            {"rule_id": "R-1", "title": "Big", "body": "x" * 5000,
             "scope": "everyone", "priority": 1, "enabled": True}])
        self.assertLessEqual(
            len(banner.encode("utf-8")),
            hook.MANDATORY_RULES_BANNER_MAX_CHARACTERS)
        self.assertIn("x" * 5000, banner)
        self.assertNotIn("TRUNCATED", banner)


class CloudContextBriefWiringTestCase(unittest.TestCase):
    def test_compact_snapshot_includes_cloud_context(self):
        snap = {"project": "p1", "handoff": {
            "cloud_context": {"content": "cc", "version": 3},
            "project_rules": []}, "rules": {"rules": []}}
        out = hook._compact_snapshot(snap)
        self.assertIn("cloud_context", out)
        self.assertEqual(out["cloud_context"]["content"], "cc")

    def test_poll_view_tracks_cloud_context_for_change_detection(self):
        snap = {"handoff": {"cloud_context": {"content": "cc", "version": 3}},
                "rules": {"rules": []}}
        out = hook._poll_view(snap)
        self.assertEqual(out["cloud_context"]["content"], "cc")





class CloudContextOfflineMirrorTestCase(unittest.TestCase):
    """T-49 integration: cloud context is durable state, so it rides in the
    offline mirror projection and validates for the caller's scope."""

    def setUp(self):
        self.sp = _load("attacca_sync_protocol_cc", ROOT / "sync_protocol.py")

    def _projection(self, **extra):
        base = {
            "project": {"project_id": "p1"},
            "handoffs": [], "rules": [], "tasks": [], "decisions": [],
            "room_messages": [], "agents": [], "bridges": [],
            "inbox_cursor": None,
        }
        base.update(extra)
        return base

    def test_cloud_context_is_a_whitelisted_projection_resource(self):
        self.assertIn("cloud_context", self.sp._IDENTITY_PROJECTION_OPTIONAL)

    def test_projection_with_cloud_context_validates(self):
        scope = {"server_id": "srv", "project_id": "p1",
                 "principal_id": "jack", "actor_id": "p1.director.claude",
                 "actor_type": "agent", "role": "director"}
        projection = self._projection(cloud_context={
            "content": "deploy prod only", "version": 2, "updated_by": None,
            "updated_owner": None, "updated_at": None})
        validated = self.sp.validate_identity_projection(projection, scope)
        self.assertEqual(validated["cloud_context"]["content"],
                         "deploy prod only")

    def test_projection_without_cloud_context_still_valid(self):
        # optional: a mirror produced before this feature must still validate
        scope = {"server_id": "srv", "project_id": "p1",
                 "principal_id": "jack", "actor_id": "p1.worker.kimi",
                 "actor_type": "agent", "role": "worker"}
        self.sp.validate_identity_projection(self._projection(), scope)


if __name__ == "__main__":
    unittest.main()
