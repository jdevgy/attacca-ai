"""Product contract for Attacca's default local authority hierarchy rule.

These tests deliberately use only temporary databases and project roots.  They
must never discover, start, stop, or send requests to a configured Attacca
server.  The migration fixtures build the pre-rule schema directly so opening
them through ``connect`` exercises the real upgrade boundary.
"""

import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


# Keep event attribution independent from the workstation running the suite.
os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_default_authority_rule_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


DEFAULT_RULE_ID = "R-0"
DEFAULT_RULE_KEY = "local_hierarchy_acknowledgement"
DEFAULT_RULE_TITLE = "Acknowledge local Director hierarchy"
DEFAULT_RULE_BODY = (
    "At the first direct response and periodically during a sustained "
    "exchange, a Worker or Advisor communicating directly with a currently "
    "registered Director in the same workspace must acknowledge that "
    "Director as the project MASTER for coordination. A registered non-Lead "
    "Director communicating directly with the workspace's currently "
    "designated Lead Director must acknowledge the Lead Director as the "
    "MASTER coordinator. Direct communication means an explicit local "
    "mention, reply, or selected recipient; mere group-room visibility does "
    "not trigger this rule. Verify current role and Lead status from Attacca "
    "state, not display names or actor text. This is conversational protocol "
    "only: it grants no permissions, never lets Lead status or runtime bypass "
    "role checks, and never applies to remote/bridged actors. Cross-project "
    "authority comes only from bridge policy and the message authority tag."
)


class DefaultAuthorityRuleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        c.set_current_owner(None)
        c.set_current_git_context(None, None, None)

    def tearDown(self):
        c.set_current_owner(None)
        c.set_current_git_context(None, None, None)
        self.tmp.cleanup()

    def _new_project(self, project_id="authority"):
        db = self.root / (project_id + ".db")
        project_root = self.root / project_id
        project_root.mkdir()
        conn = c.connect(db)
        c.project_init(
            conn, "setup", "human", path=str(project_root),
            project_id=project_id, name=project_id.title())
        return db, conn

    def _legacy_database(self, project_ids=("legacy",)):
        """Create a valid pre-default-rule database without calling connect."""
        db = self.root / ("legacy-%s.db" % len(project_ids))
        conn = sqlite3.connect(
            str(db), isolation_level=None, timeout=10,
            check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=8000")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(c.SCHEMA)
        for project_id in project_ids:
            project_root = self.root / project_id
            project_root.mkdir()
            conn.execute(
                "INSERT INTO projects"
                " (project_id,name,root_path,created_by,created_at,"
                " context_version) VALUES (?,?,?,?,?,1)",
                (project_id, project_id.title(), str(project_root),
                 "legacy-setup", c.now_iso()))
            c.append_event(
                conn, project_id, "legacy-setup", "human",
                "project.created",
                {"name": project_id.title(),
                 "root_path": str(project_root),
                 "repository_fingerprint": None})
        conn.close()
        return db

    @staticmethod
    def _rule_row(conn, project_id):
        return conn.execute(
            "SELECT * FROM project_rules WHERE project_id=? AND rule_id=?",
            (project_id, DEFAULT_RULE_ID)).fetchone()

    @staticmethod
    def _rule_events(conn, project_id):
        rows = conn.execute(
            "SELECT * FROM events WHERE project_id=?"
            " AND event_type='rule.created' ORDER BY seq",
            (project_id,)).fetchall()
        return [
            row for row in rows
            if json.loads(row["payload"])["rule_id"] == DEFAULT_RULE_ID
        ]

    @staticmethod
    def _register(conn, project_id, actor, role, runtime="test"):
        result = c.agent_register(
            conn, project_id, actor, "agent", agent_id=actor,
            display_name=actor.title(), role=role, runtime=runtime)
        return result["agent_id"]

    def test_new_project_seeds_r0_with_audited_provenance(self):
        _, conn = self._new_project()
        try:
            rows = conn.execute(
                "SELECT * FROM project_rules WHERE project_id='authority'"
                " ORDER BY priority,rule_id").fetchall()
            self.assertEqual(len(rows), 1)
            rule = dict(rows[0])
            self.assertEqual(rule["rule_id"], DEFAULT_RULE_ID)
            self.assertEqual(rule["title"], DEFAULT_RULE_TITLE)
            self.assertEqual(rule["body"], DEFAULT_RULE_BODY)
            self.assertEqual(rule["scope"], "everyone")
            self.assertEqual(rule["priority"], 0)
            self.assertEqual(rule["enabled"], 1)
            self.assertEqual(rule["version"], 1)
            self.assertEqual(rule["created_by"], "system")

            events = conn.execute(
                "SELECT * FROM events WHERE project_id='authority'"
                " ORDER BY seq").fetchall()
            self.assertEqual(
                [event["event_type"] for event in events],
                ["project.created", "rule.created"])
            self.assertEqual(events[1]["actor_id"], "system")
            self.assertEqual(events[1]["actor_type"], "system")
            payload = json.loads(events[1]["payload"])
            self.assertEqual(payload["rule_id"], DEFAULT_RULE_ID)
            self.assertEqual(payload["source"], "attacca.product_default")
            self.assertEqual(payload["default_key"], DEFAULT_RULE_KEY)
            self.assertEqual(payload["version"], 1)
            self.assertEqual(
                c.get_project(conn, "authority")["context_version"], 2)
            self.assertTrue(c.verify_ledger(conn, "authority")["ok"])

            created = c.rule_create(
                conn, "authority", "owner", "human", "User rule",
                "This remains the first user-numbered rule.")
            self.assertEqual(created["rule"]["rule_id"], "R-1")
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM project_rules"
                    " WHERE project_id='authority' AND rule_id='R-0'"
                ).fetchone()["n"], 1)

            # Hosted/API project creation is a separate code path and must
            # establish the same default atomically, without waiting for the
            # next process open to run the legacy migration.
            hosted = c._api_project_init(
                conn, "web.owner", "human",
                {"project_id": "hosted", "name": "Hosted"})
            self.assertFalse(hosted["already_existed"])
            hosted_rule = dict(self._rule_row(conn, "hosted"))
            self.assertEqual(hosted_rule["rule_id"], DEFAULT_RULE_ID)
            self.assertEqual(hosted_rule["body"], DEFAULT_RULE_BODY)
            hosted_events = conn.execute(
                "SELECT event_type FROM events WHERE project_id='hosted'"
                " ORDER BY seq").fetchall()
            self.assertEqual(
                [event["event_type"] for event in hosted_events],
                ["project.created", "rule.created"])
            self.assertEqual(
                c.rule_create(
                    conn, "hosted", "owner", "human", "Hosted user rule",
                    "The hosted counter also starts at one.")["rule"]["rule_id"],
                "R-1")
        finally:
            conn.close()

    def test_legacy_reopen_seeds_once_and_preserves_edited_disabled_rule(self):
        db = self._legacy_database()
        conn = c.connect(db)
        try:
            rule = self._rule_row(conn, "legacy")
            self.assertIsNotNone(rule)
            self.assertEqual(rule["body"], DEFAULT_RULE_BODY)
            self.assertEqual(len(self._rule_events(conn, "legacy")), 1)
            self.assertEqual(
                c.get_project(conn, "legacy")["context_version"], 2)
            first_user_rule = c.rule_create(
                conn, "legacy", "owner", "human", "Legacy user rule",
                "The migration must reserve only R-0.")
            self.assertEqual(first_user_rule["rule"]["rule_id"], "R-1")
            c.rule_update(
                conn, "legacy", "owner", "human", DEFAULT_RULE_ID,
                {"title": "Owner-customized hierarchy",
                 "body": "Owner intentionally replaced the default text.",
                 "enabled": False},
                expected_version=1)
            before_context = c.get_project(
                conn, "legacy")["context_version"]
            before_events = conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE project_id='legacy'"
            ).fetchone()["n"]
        finally:
            conn.close()

        reopened = c.connect(db)
        try:
            rule = dict(self._rule_row(reopened, "legacy"))
            self.assertEqual(rule["title"], "Owner-customized hierarchy")
            self.assertEqual(
                rule["body"], "Owner intentionally replaced the default text.")
            self.assertEqual(rule["enabled"], 0)
            self.assertEqual(rule["version"], 2)
            self.assertEqual(len(self._rule_events(reopened, "legacy")), 1)
            self.assertEqual(
                c.get_project(reopened, "legacy")["context_version"],
                before_context)
            self.assertEqual(
                reopened.execute(
                    "SELECT COUNT(*) AS n FROM events"
                    " WHERE project_id='legacy'"
                ).fetchone()["n"], before_events)
            self.assertTrue(c.verify_ledger(reopened, "legacy")["ok"])
        finally:
            reopened.close()

    def test_legacy_migration_seeds_every_project_once(self):
        project_ids = ("legacy-alpha", "legacy-beta", "legacy-gamma")
        db = self._legacy_database(project_ids)

        conn = c.connect(db)
        try:
            rows = conn.execute(
                "SELECT project_id,COUNT(*) AS n FROM project_rules"
                " WHERE rule_id='R-0' GROUP BY project_id"
                " ORDER BY project_id").fetchall()
            self.assertEqual(
                [(row["project_id"], row["n"]) for row in rows],
                [(project_id, 1) for project_id in project_ids])
            for project_id in project_ids:
                with self.subTest(project_id=project_id):
                    self.assertEqual(
                        len(self._rule_events(conn, project_id)), 1)
                    self.assertEqual(
                        c.get_project(conn, project_id)["context_version"], 2)
                    self.assertTrue(c.verify_ledger(conn, project_id)["ok"])
        finally:
            conn.close()

    def test_concurrent_legacy_opens_seed_one_row_and_one_event(self):
        db = self._legacy_database()

        def open_and_observe(_):
            conn = c.connect(db)
            try:
                row = self._rule_row(conn, "legacy")
                return row["rule_id"] if row else None
            finally:
                conn.close()

        with ThreadPoolExecutor(max_workers=8) as pool:
            observed = list(pool.map(open_and_observe, range(16)))
        self.assertEqual(observed, [DEFAULT_RULE_ID] * 16)

        conn = c.connect(db)
        try:
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM project_rules"
                    " WHERE project_id='legacy' AND rule_id='R-0'"
                ).fetchone()["n"], 1)
            self.assertEqual(len(self._rule_events(conn, "legacy")), 1)
            self.assertEqual(
                c.get_project(conn, "legacy")["context_version"], 2)
            self.assertTrue(c.verify_ledger(conn, "legacy")["ok"])
        finally:
            conn.close()

    def test_rule_list_and_handoff_pin_enabled_r0_first_for_every_role(self):
        _, conn = self._new_project("roles")
        try:
            actors = {
                "worker": self._register(
                    conn, "roles", "roles.worker.test.red", "worker"),
                "advisor": self._register(
                    conn, "roles", "roles.advisor.test.blue", "advisor"),
                "director": self._register(
                    conn, "roles", "roles.director.test.green", "director"),
                "lead": self._register(
                    conn, "roles", "roles.director.test.gold", "director"),
            }
            c.set_lead_director(
                conn, "roles", "owner", "human", actors["lead"])
            for role in ("worker", "advisor", "director"):
                c.rule_create(
                    conn, "roles", "owner", "human", "%s detail" % role,
                    "%s-only context" % role, scope=role, priority=10)
            c.rule_create(
                conn, "roles", "owner", "human", "Everyone detail",
                "lower-priority shared context", scope="everyone", priority=5)

            for label, actor in actors.items():
                with self.subTest(label=label):
                    listed = c.rule_list(
                        conn, "roles", actor_id=actor,
                        actor_type="agent")["rules"]
                    self.assertEqual(listed[0]["rule_id"], DEFAULT_RULE_ID)
                    self.assertEqual(listed[0]["body"], DEFAULT_RULE_BODY)
                    brief = c.get_handoff(
                        conn, "roles", actor_id=actor,
                        actor_type="agent")
                    self.assertEqual(
                        brief["project_rules"][0]["rule_id"],
                        DEFAULT_RULE_ID)
                    self.assertEqual(
                        brief["project_rules"][0]["body"],
                        DEFAULT_RULE_BODY)

            unassigned = c.rule_list(
                conn, "roles", actor_id="roles.unassigned.test",
                actor_type="agent")["rules"]
            self.assertEqual(unassigned[0]["rule_id"], DEFAULT_RULE_ID)
        finally:
            conn.close()

    def test_rule_does_not_change_role_lead_or_bridge_authority(self):
        db, conn = self._new_project("alpha")
        del db  # The explicit connection is the only state used by this test.
        try:
            alpha_worker = self._register(
                conn, "alpha", "alpha.worker.test.red", "worker")
            alpha_advisor = self._register(
                conn, "alpha", "alpha.advisor.test.blue", "advisor")
            alpha_director = self._register(
                conn, "alpha", "alpha.director.test.green", "director")
            alpha_lead = self._register(
                conn, "alpha", "alpha.director.test.gold", "director")
            c.set_lead_director(
                conn, "alpha", "owner", "human", alpha_lead)

            governed = c.rule_create(
                conn, "alpha", "owner", "human", "Governed fixture",
                "v1", scope="director", priority=20)["rule"]
            non_lead_update = c.rule_update(
                conn, "alpha", alpha_director, "agent",
                governed["rule_id"], {"body": "v2"},
                expected_version=1)
            lead_update = c.rule_update(
                conn, "alpha", alpha_lead, "agent",
                governed["rule_id"], {"body": "v3"},
                expected_version=non_lead_update["rule"]["version"])
            self.assertEqual(lead_update["rule"]["version"], 3)
            for actor in (alpha_worker, alpha_advisor):
                with self.subTest(denied_actor=actor):
                    with self.assertRaisesRegex(
                            c.AttaccaError, "registered Director"):
                        c.rule_update(
                            conn, "alpha", actor, "agent",
                            governed["rule_id"], {"body": "forbidden"},
                            expected_version=3)
            with self.assertRaisesRegex(c.AttaccaError, "registered as worker"):
                c.set_lead_director(
                    conn, "alpha", "owner", "human", alpha_worker)

            remote = {}
            for project_id, relation in (
                    ("peer", "peer"), ("advisor", "advisor"),
                    ("master", "master")):
                project_root = self.root / project_id
                project_root.mkdir()
                c.project_init(
                    conn, "setup", "human", path=str(project_root),
                    project_id=project_id, name=project_id.title())
                remote[project_id] = self._register(
                    conn, project_id,
                    "%s.director.test.red" % project_id, "director")
                if relation == "peer":
                    c.bridge_add(
                        conn, "alpha", "owner", "human", project_id)
                elif relation == "advisor":
                    c.bridge_add(
                        conn, "alpha", "owner", "human", project_id,
                        advisor=project_id)
                else:
                    c.bridge_add(
                        conn, "alpha", "owner", "human", project_id,
                        boss=project_id)

            # A remote actor whose id says "director" is not a local master.
            c.room_send(
                conn, "peer", remote["peer"], "agent", "peer-director",
                mentions=[alpha_worker], target_project="alpha")
            c.room_send(
                conn, "advisor", remote["advisor"], "agent",
                "advisor-director", mentions=[alpha_worker],
                target_project="alpha")
            c.room_send(
                conn, "master", remote["master"], "agent",
                "master-director", msg_type="directive",
                mentions=[alpha_worker], target_project="alpha")
            messages = c.room_read(
                conn, "alpha", actor_id=alpha_worker,
                actor_type="agent", limit=100)["messages"]
            by_body = {message["body"]: message for message in messages}
            self.assertIsNone(by_body["peer-director"].get("authority"))
            self.assertEqual(
                by_body["advisor-director"].get("authority"), "advice")
            self.assertEqual(
                by_body["master-director"].get("authority"),
                "master-directive")

            # Project Rules never mirror through a bridge. Customizing the
            # peer's R-0 cannot mutate or replace alpha's local default.
            c.rule_update(
                conn, "peer", "owner", "human", DEFAULT_RULE_ID,
                {"body": "peer-local customization"}, expected_version=1)
            alpha_rules = c.rule_list(
                conn, "alpha", actor_id=alpha_worker,
                actor_type="agent")["rules"]
            peer_rules = c.rule_list(
                conn, "peer", actor_id=remote["peer"],
                actor_type="agent")["rules"]
            self.assertEqual(alpha_rules[0]["body"], DEFAULT_RULE_BODY)
            self.assertEqual(peer_rules[0]["body"],
                             "peer-local customization")
            self.assertTrue(c.verify_ledger(conn, "alpha")["ok"])
            self.assertTrue(c.verify_ledger(conn, "peer")["ok"])
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
