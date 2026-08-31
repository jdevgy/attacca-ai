"""Focused, isolated contracts for project-global named AI identities.

Every database and process state used here is temporary.  This suite never
discovers, contacts, reloads, or mutates a configured/live Attacca server.
"""

import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path


os.environ["ATTACCA_OWNER"] = ""
ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_unique_named_identity_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class NamedIdentityTestCase(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.db = self.root / "attacca.db"
        self.conn = c.connect(self.db)
        c.project_init(
            self.conn, "setup", "human", path=str(self.root / "repo"),
            project_id="engine", name="Engine")
        c.set_current_owner("jack")

    def tearDown(self):
        c.set_current_owner(None)
        self.conn.close()
        self.temporary.cleanup()

    def new_identity(self, role="director", runtime="codex"):
        return c.agent_register(
            self.conn, "engine", runtime, "agent", role=role,
            runtime=runtime, canonical_identity=True,
            allocate_persona=True, distinct_identity=True,
            registration_username="jack", authorized_owner_labels=["jack"])

    def test_names_allocate_globally_and_reservations_never_release(self):
        gibbs = self.new_identity("director", "codex")
        turing = self.new_identity("worker", "claude")
        self.assertEqual(gibbs["agent_id"], "engine.director.codex.gibbs")
        self.assertEqual(turing["agent_id"], "engine.worker.claude.turing")
        self.assertEqual(gibbs["identity"]["persona_name"], "Gibbs")
        self.assertEqual(gibbs["identity"]["short_name"], "@Gibbs")

        self.conn.execute(
            "DELETE FROM agents WHERE project_id='engine' AND agent_id=?",
            (gibbs["agent_id"],))
        hopper = self.new_identity("advisor", "kimi")
        self.assertEqual(hopper["agent_id"], "engine.advisor.kimi.hopper")
        rows = self.conn.execute(
            "SELECT persona,reserved_actor_id FROM agent_persona_reservations"
            " WHERE project_id='engine' ORDER BY reserved_at,persona"
        ).fetchall()
        # ``reserved_at`` has millisecond precision, so reservations created
        # in one tick use persona as their deterministic wire/export tie
        # breaker.  Allocation order is proven by the returned identities;
        # the durable registry contract is the complete never-reused set.
        self.assertEqual({row["persona"] for row in rows},
                         {"gibbs", "turing", "hopper"})
        with self.assertRaises(sqlite3.DatabaseError):
            self.conn.execute(
                "DELETE FROM agent_persona_reservations"
                " WHERE project_id='engine' AND persona='gibbs'")
        with self.assertRaises(sqlite3.DatabaseError):
            self.conn.execute(
                "UPDATE agent_persona_reservations SET persona='curie'"
                " WHERE project_id='engine' AND persona='gibbs'")

    def test_creation_boundary_rescans_post_marker_history_before_allocation(self):
        first = self.new_identity()
        nowi = c.now_iso()
        # Simulate a raw/import writer after the one-time migration marker.
        # It bypasses registration and therefore has no reservation row yet.
        self.conn.execute(
            "INSERT INTO agents"
            " (project_id,agent_id,display_name,role,runtime,owner,actor_type,"
            " registered_at,last_seen_at) VALUES"
            " ('engine','engine.worker.claude.turing','Old Turing','worker',"
            " 'claude','jack','agent',?,?)",
            (nowi, nowi))
        self.assertIsNone(self.conn.execute(
            "SELECT 1 FROM agent_persona_reservations"
            " WHERE project_id='engine' AND persona='turing'").fetchone())

        second = self.new_identity()
        self.assertEqual(first["identity"]["persona"], "gibbs")
        self.assertEqual(second["identity"]["persona"], "hopper")
        reserved = self.conn.execute(
            "SELECT reserved_actor_id FROM agent_persona_reservations"
            " WHERE project_id='engine' AND persona='turing'").fetchone()
        self.assertEqual(
            reserved["reserved_actor_id"],
            "engine.worker.claude.turing")

    def test_unicode_persona_input_and_post_marker_history_fail_closed(self):
        before = self.conn.execute(
            "SELECT COUNT(*) AS n FROM agents WHERE project_id='engine'"
        ).fetchone()["n"]
        with self.assertRaisesRegex(c.AttaccaError, "wire-safe ASCII"):
            c.agent_register(
                self.conn, "engine", "codex", "agent", role="director",
                runtime="codex", persona="Gíbbs", canonical_identity=True,
                distinct_identity=True, registration_username="jack",
                authorized_owner_labels=["jack"])
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS n FROM agents WHERE project_id='engine'"
        ).fetchone()["n"], before)

        created = self.new_identity()
        c.append_event(
            self.conn, "engine", created["agent_id"], "agent",
            "fixture.post_marker_identity_reference",
            {"referenced_actor": "engine.worker.claude.curíe"})
        with self.assertRaisesRegex(
                c.AttaccaError, "invalid_agent_persona_history"):
            self.new_identity()

    def test_search_finds_inactive_name_without_reservation_audit_leakage(self):
        gibbs = self.new_identity()
        self.conn.execute(
            "DELETE FROM agents WHERE project_id='engine' AND agent_id=?",
            (gibbs["agent_id"],))
        result = c.search_project(
            self.conn, "engine", "Gibbs", actor_id="reader",
            actor_type="agent", limit=60)
        named = [item for item in result["results"]
                 if item["kind"] == "identity_name"]
        self.assertEqual(len(named), 1)
        self.assertEqual(named[0]["text"],
                         "Reserved identity name @Gibbs (never reused)")
        self.assertEqual(set(named[0]["data"]), {
            "project_id", "persona", "persona_name", "reserved_at"})
        self.assertNotIn("reserved_actor_id", named[0]["data"])
        self.assertNotIn("source", named[0]["data"])

    def test_migration_seeds_historic_personas_before_first_allocation(self):
        legacy_db = self.root / "legacy.db"
        raw = sqlite3.connect(str(legacy_db), isolation_level=None)
        try:
            raw.executescript(c.SCHEMA)
            raw.execute(
                "INSERT INTO projects"
                " (project_id,name,root_path,created_by,created_at,"
                " context_version) VALUES ('legacy','Legacy',NULL,'setup',?,1)",
                (c.now_iso(),))
            raw.execute(
                "INSERT INTO agents"
                " (project_id,agent_id,display_name,role,runtime,owner,"
                " actor_type,registered_at,last_seen_at)"
                " VALUES ('legacy','legacy.worker.claude.gibbs','Old Gibbs',"
                " 'worker','claude','jack','agent',?,?)",
                (c.now_iso(), c.now_iso()))
            raw.execute("DROP TABLE agent_persona_reservations")
        finally:
            raw.close()

        migrated = c.connect(legacy_db)
        try:
            reservation = migrated.execute(
                "SELECT * FROM agent_persona_reservations"
                " WHERE project_id='legacy' AND persona='gibbs'").fetchone()
            self.assertIsNotNone(reservation)
            self.assertEqual(reservation["reserved_actor_id"],
                             "legacy.worker.claude.gibbs")
            created = c.agent_register(
                migrated, "legacy", "codex", "agent", role="director",
                runtime="codex", canonical_identity=True,
                allocate_persona=True, distinct_identity=True)
            self.assertEqual(created["agent_id"],
                             "legacy.director.codex.turing")
        finally:
            migrated.close()

    def test_explicit_duplicate_name_fails_but_exact_reuse_is_allowed(self):
        gibbs = self.new_identity()
        with self.assertRaisesRegex(c.AttaccaError, "persona_name_reserved"):
            c.agent_register(
                self.conn, "engine", "claude", "agent", role="worker",
                runtime="claude", persona="GIBBS", canonical_identity=True,
                distinct_identity=True, registration_username="jack",
                authorized_owner_labels=["jack"])
        repeated = c.agent_register(
            self.conn, "engine", gibbs["agent_id"], "agent",
            agent_id=gibbs["agent_id"], role="director", runtime="codex",
            persona="gibbs", canonical_identity=True,
            registration_username="jack", authorized_owner_labels=["jack"])
        self.assertTrue(repeated["already_registered"])
        self.assertEqual(repeated["agent_id"], gibbs["agent_id"])

    def test_legacy_duplicate_personas_allow_exact_reuse_but_short_name_is_ambiguous(self):
        gibbs = self.new_identity()
        duplicate = "engine.worker.claude.gibbs"
        nowi = c.now_iso()
        # A pre-feature database may already contain the same old color/name
        # in multiple role/runtime namespaces. Migration preserves both rows.
        self.conn.execute(
            "INSERT INTO agents"
            " (project_id,agent_id,display_name,role,runtime,owner,actor_type,"
            " registered_at,last_seen_at) VALUES ('engine',?,'Old Gibbs',"
            " 'worker','claude','jack','agent',?,?)",
            (duplicate, nowi, nowi))
        c._seed_project_persona_reservations(
            self.conn, "engine", force=True)
        selected = c.select_registered_agent_identity(
            self.conn, "engine", gibbs["agent_id"], agent_id=duplicate,
            role="worker", runtime="claude", registration_username="jack",
            authorized_owner_labels=["jack"])
        self.assertEqual(selected["agent_id"], duplicate)
        with self.assertRaisesRegex(c.AttaccaError,
                                    "room_mention_ambiguous"):
            c.room_send(
                self.conn, "engine", gibbs["agent_id"], "agent",
                "@Gibbs review this")

    def test_authenticated_runtime_contradiction_is_atomic_but_admin_can_migrate(self):
        gibbs = self.new_identity()
        before = {
            "agents": [tuple(row) for row in self.conn.execute(
                "SELECT * FROM agents WHERE project_id='engine' ORDER BY agent_id")],
            "aliases": [tuple(row) for row in self.conn.execute(
                "SELECT * FROM actor_aliases WHERE project_id='engine'")],
            "events": self.conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE project_id='engine'"
            ).fetchone()["n"],
        }
        with self.assertRaisesRegex(
                c.AuthorizationError, "agent_registration_not_idempotent"):
            c.agent_register(
                self.conn, "engine", gibbs["agent_id"], "agent",
                agent_id=gibbs["agent_id"], role="director",
                runtime="claude", canonical_identity=True,
                registration_username="jack",
                authorized_owner_labels=["jack"])
        with self.assertRaisesRegex(
                c.AuthorizationError, "agent_registration_not_idempotent"):
            c.agent_register(
                self.conn, "engine", gibbs["agent_id"], "agent",
                agent_id=gibbs["agent_id"], role="director",
                runtime="codex", persona="turing",
                canonical_identity=True, registration_username="jack",
                authorized_owner_labels=["jack"])
        after = {
            "agents": [tuple(row) for row in self.conn.execute(
                "SELECT * FROM agents WHERE project_id='engine' ORDER BY agent_id")],
            "aliases": [tuple(row) for row in self.conn.execute(
                "SELECT * FROM actor_aliases WHERE project_id='engine'")],
            "events": self.conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE project_id='engine'"
            ).fetchone()["n"],
        }
        self.assertEqual(after, before)

        migrated = c.agent_register(
            self.conn, "engine", gibbs["agent_id"], "agent",
            agent_id=gibbs["agent_id"], role="director", runtime="claude",
            canonical_identity=True, registration_username="jack",
            allow_foreign_owner=True, authorized_owner_labels=["jack"])
        self.assertEqual(migrated["agent_id"],
                         "engine.director.claude.gibbs")
        alias = self.conn.execute(
            "SELECT canonical_actor_id FROM actor_aliases"
            " WHERE project_id='engine' AND legacy_actor_id=?",
            (gibbs["agent_id"],)).fetchone()
        self.assertEqual(alias["canonical_actor_id"], migrated["agent_id"])
        reservation = self.conn.execute(
            "SELECT reserved_actor_id FROM agent_persona_reservations"
            " WHERE project_id='engine' AND persona='gibbs'").fetchone()
        self.assertEqual(reservation["reserved_actor_id"], gibbs["agent_id"])

    def test_mcp_persona_reuse_is_selection_only_and_preserves_both_identities(self):
        gibbs = self.new_identity()
        turing = self.new_identity()
        nowi = c.now_iso()
        for index, actor in enumerate((gibbs["agent_id"], turing["agent_id"]), 1):
            self.conn.execute(
                "INSERT INTO inbox_cursors"
                " (project_id,actor_id,last_read_seq,updated_at)"
                " VALUES ('engine',?,?,?)", (actor, index, nowi))
            self.conn.execute(
                "INSERT INTO identity_handoffs"
                " (project_id,actor_id,version,content,updated_by,updated_at)"
                " VALUES ('engine',?,1,?,?,?)",
                (actor, json.dumps({"objective": actor}), actor, nowi))
            self.conn.execute(
                "INSERT INTO tasks"
                " (project_id,task_id,title,status,claimed_by,created_at,updated_at)"
                " VALUES ('engine',?,?, 'claimed',?,?,?)",
                ("T-%d" % index, "Task %d" % index, actor, nowi, nowi))

        def snapshot():
            return {
                table: [tuple(row) for row in self.conn.execute(query)]
                for table, query in {
                    "agents": "SELECT * FROM agents WHERE project_id='engine' ORDER BY agent_id",
                    "aliases": "SELECT * FROM actor_aliases WHERE project_id='engine' ORDER BY legacy_actor_id",
                    "cursors": "SELECT * FROM inbox_cursors WHERE project_id='engine' ORDER BY actor_id",
                    "handoffs": "SELECT * FROM identity_handoffs WHERE project_id='engine' ORDER BY actor_id,version",
                    "tasks": "SELECT * FROM tasks WHERE project_id='engine' ORDER BY task_id",
                    "events": "SELECT * FROM events WHERE project_id='engine' ORDER BY seq",
                }.items()
            }

        before = snapshot()
        session = c.McpSession(
            self.db, default_project="engine", actor=turing["agent_id"],
            actor_type="agent", detect_cwd=False,
            preserve_actor_identity=True)
        selected = session.dispatch_tool("agent_register", {
            "project": "engine", "role": "director", "runtime": "codex",
            "persona": "GiBbS", "identity_mode": "reuse",
        })
        self.assertEqual(selected["agent_id"], gibbs["agent_id"])
        self.assertTrue(selected["selection_only"])
        self.assertEqual(session.actor, gibbs["agent_id"])
        session._conn().close()
        self.assertEqual(snapshot(), before)

        class RouteMatch:
            @staticmethod
            def group(index):
                return "engine"

        class FakeHandler:
            principal = None

            def __init__(route_self):
                route_self.reply = None

            def _conn(route_self):
                return self.conn

            @staticmethod
            def _actor():
                return turing["agent_id"], "agent"

            @staticmethod
            def _body_json():
                return {"role": "director", "runtime": "codex",
                        "persona": "Gibbs", "identity_mode": "reuse"}

            def _reply_json(route_self, status, body, headers=None):
                route_self.reply = (status, body, headers)

        handler = FakeHandler()
        c._r_agent_register(handler, RouteMatch(), {})
        self.assertEqual(handler.reply[0], 200)
        self.assertEqual(handler.reply[1]["agent_id"], gibbs["agent_id"])
        self.assertTrue(handler.reply[1]["selection_only"])
        self.assertEqual(snapshot(), before)
        with self.assertRaisesRegex(c.AttaccaError,
                                    "identity_reuse_target_required"):
            c.select_registered_agent_identity(
                self.conn, "engine", turing["agent_id"],
                role="director", runtime="codex", persona="curie")

    def test_inline_and_explicit_short_mentions_store_only_canonical_ids(self):
        source = self.new_identity()
        c.project_init(
            self.conn, "setup", "human", path=str(self.root / "target"),
            project_id="target", name="Target")
        target = c.agent_register(
            self.conn, "target", "codex", "agent", role="director",
            runtime="codex", canonical_identity=True,
            allocate_persona=True, distinct_identity=True,
            registration_username="jack", authorized_owner_labels=["jack"])
        self.assertEqual(source["identity"]["persona"], "gibbs")
        self.assertEqual(target["identity"]["persona"], "gibbs")

        # Resolve no target identity data until bridge existence is proven.
        c.project_init(
            self.conn, "setup", "human", path=str(self.root / "secret"),
            project_id="secret", name="Secret")
        c.agent_register(
            self.conn, "secret", "codex", "agent", role="director",
            runtime="codex", canonical_identity=True,
            allocate_persona=True, distinct_identity=True,
            registration_username="jack", authorized_owner_labels=["jack"])
        errors = []
        for body in ("@Gibbs secret", "@Missing secret"):
            with self.assertRaises(c.AttaccaError) as caught:
                c.room_send(
                    self.conn, "engine", source["agent_id"], "agent", body,
                    target_project="secret")
            errors.append(str(caught.exception))
        self.assertEqual(errors[0], errors[1])
        self.assertIn("not connected", errors[0])

        other_source = self.new_identity("worker", "claude")
        c.project_init(
            self.conn, "setup", "human", path=str(self.root / "denied"),
            project_id="denied", name="Denied")
        c.agent_register(
            self.conn, "denied", "codex", "agent", role="director",
            runtime="codex", canonical_identity=True,
            allocate_persona=True, distinct_identity=True,
            registration_username="jack", authorized_owner_labels=["jack"])
        c.bridge_add(
            self.conn, "engine", source["agent_id"], "agent", "denied",
            participation="selected_agents",
            selected_agents=[other_source["agent_id"]])
        denied_errors = []
        for body in ("@Gibbs denied", "@Missing denied"):
            with self.assertRaises(c.AttaccaError) as caught:
                c.room_send(
                    self.conn, "engine", source["agent_id"], "agent", body,
                    target_project="denied")
            denied_errors.append(str(caught.exception))
        self.assertEqual(denied_errors[0], denied_errors[1])
        self.assertIn("not allowed to participate", denied_errors[0])

        c.bridge_add(
            self.conn, "engine", source["agent_id"], "agent", "target")

        sent = c.room_send(
            self.conn, "engine", source["agent_id"], "agent",
            "@gIbBs Do this", target_project="target")
        self.assertEqual(sent["mirrored_to"], ["target"])
        mirrored = self.conn.execute(
            "SELECT payload FROM events WHERE project_id='target'"
            " AND event_type='room.message' ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(json.loads(mirrored["payload"])["mentions"],
                         [target["agent_id"]])

        c.room_send(
            self.conn, "engine", source["agent_id"], "agent",
            r"email dev@Gibbs.example, @everyone, escaped \@Missing, and "
            "@%s are prose" % source["agent_id"])
        local = self.conn.execute(
            "SELECT payload FROM events WHERE project_id='engine'"
            " AND event_type='room.message' ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        self.assertNotIn("mentions", json.loads(local["payload"]))

        explicit = c.room_send(
            self.conn, "engine", source["agent_id"], "agent", "Please act",
            mentions=["GIBBS"])
        exact_event = self.conn.execute(
            "SELECT payload FROM events WHERE project_id='engine' AND seq=?",
            (explicit["event"]["seq"],)).fetchone()
        self.assertEqual(json.loads(exact_event["payload"])["mentions"],
                         [source["agent_id"]])
        with self.assertRaisesRegex(c.AttaccaError, "room_mention_unknown"):
            c.room_send(
                self.conn, "engine", source["agent_id"], "agent",
                "@Missing please act")

        self.conn.execute(
            "DELETE FROM agents WHERE project_id='target' AND agent_id=?",
            (target["agent_id"],))
        with self.assertRaisesRegex(c.AttaccaError, "room_mention_inactive"):
            c.room_send(
                self.conn, "engine", source["agent_id"], "agent",
                "@Gibbs still there?", target_project="target")


if __name__ == "__main__":
    unittest.main()
