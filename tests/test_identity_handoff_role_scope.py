"""D-19/D-20 contracts for identity handoffs, role scopes, and personas.

These tests deliberately exercise the storage layer, MCP dispatch, hosted REST
surface, and lifecycle request order.  A handoff belongs to one exact actor;
Role Scope is shared by role; an optional persona suffix creates another exact
actor without changing that actor's role or runtime authority.
"""

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock


# Keep test attribution independent from the machine running the suite.
os.environ["ATTACCA_OWNER"] = ""

from tests.test_http import ServerFixture  # noqa: E402


ROOT = Path(__file__).resolve().parent.parent

SPEC = importlib.util.spec_from_file_location(
    "attacca_identity_handoff_role_scope_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)

HOOK_SPEC = importlib.util.spec_from_file_location(
    "attacca_identity_handoff_startup_under_test",
    ROOT / "hooks" / "session_start.py")
hook = importlib.util.module_from_spec(HOOK_SPEC)
HOOK_SPEC.loader.exec_module(hook)


DIRECTOR = "p1.director.codex"
DIRECTOR_RED = "p1.director.codex.red"
DIRECTOR_BLUE = "p1.director.codex.blue"
WORKER = "p1.worker.claude"
ADVISOR = "p1.advisor.kimi"
HUMAN = "web.owner"


def register_exact(conn, project_id, actor_id, role, runtime):
    """Register an exact fixture identity without invoking setup migration."""
    return c.agent_register(
        conn, project_id, actor_id, "agent", agent_id=actor_id,
        display_name=actor_id, role=role, runtime=runtime,
        canonical_identity=False)


class IdentityHandoffRoleScopeStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "identity.db"
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.conn = c.connect(self.db)
        c.project_init(
            self.conn, "setup", "human", path=str(self.repo),
            project_id="p1", name="Identity Project")
        for actor, role, runtime in (
                (DIRECTOR, "director", "codex"),
                (DIRECTOR_RED, "director", "codex"),
                (DIRECTOR_BLUE, "director", "codex"),
                (WORKER, "worker", "claude"),
                (ADVISOR, "advisor", "kimi")):
            register_exact(self.conn, "p1", actor, role, runtime)
        c.set_lead_director(
            self.conn, "p1", HUMAN, "human", DIRECTOR_RED)

    def tearDown(self):
        self.conn.close()
        c.set_current_owner(None)
        self.tmp.cleanup()

    def _update(self, actor, actor_type, updates, expected):
        return c.update_identity_handoff(
            self.conn, "p1", actor, actor_type, updates,
            expected_version=expected)

    def test_schema_migrates_only_latest_exact_legacy_writer_once(self):
        db = self.root / "legacy.db"
        conn = c.connect(db)
        try:
            for project_id in ("exact", "ambiguous", "raw", "persona"):
                repo = self.root / ("repo-" + project_id)
                repo.mkdir()
                c.project_init(
                    conn, "setup", "human", path=str(repo),
                    project_id=project_id, name=project_id.title())
                register_exact(
                    conn, project_id,
                    "%s.director.codex" % project_id,
                    "director", "codex")
                register_exact(
                    conn, project_id,
                    "%s.worker.claude" % project_id,
                    "worker", "claude")
            register_exact(
                conn, "raw", "raw-director", "director", "custom")
            register_exact(
                conn, "persona", "persona.director.codex.red",
                "director", "codex")

            # Only the latest legacy row matters.  In ``exact`` it has an
            # exact registered canonical writer, so that one writer receives
            # one seed.  The older worker row must not be cloned or migrated.
            conn.execute(
                "INSERT INTO handoffs"
                " (project_id,version,content,updated_by,updated_at)"
                " VALUES (?,?,?,?,?)",
                ("exact", 1, c.canonical_json({"objective": "old worker"}),
                 "exact.worker.claude", "2026-01-01T00:00:00.000Z"))
            conn.execute(
                "INSERT INTO handoffs"
                " (project_id,version,content,updated_by,updated_at)"
                " VALUES (?,?,?,?,?)",
                ("exact", 2, c.canonical_json({"objective": "latest exact"}),
                 "exact.director.codex", "2026-01-02T00:00:00.000Z"))

            # An ambiguous latest writer stays only in the immutable legacy
            # archive even though an older row had an exact registered writer.
            conn.execute(
                "INSERT INTO handoffs"
                " (project_id,version,content,updated_by,updated_at)"
                " VALUES (?,?,?,?,?)",
                ("ambiguous", 1,
                 c.canonical_json({"objective": "older exact"}),
                 "ambiguous.director.codex",
                 "2026-01-01T00:00:00.000Z"))
            conn.execute(
                "INSERT INTO handoffs"
                " (project_id,version,content,updated_by,updated_at)"
                " VALUES (?,?,?,?,?)",
                ("ambiguous", 2,
                 c.canonical_json({
                     "objective": "ambiguous web row",
                     "risks": "legacy risk must remain archive-only",
                 }),
                 "web.admin", "2026-01-02T00:00:00.000Z"))

            # Merely having an agents-table row does not make a raw legacy id
            # an exact canonical identity. It remains archive-only.
            conn.execute(
                "INSERT INTO handoffs"
                " (project_id,version,content,updated_by,updated_at)"
                " VALUES (?,?,?,?,?)",
                ("raw", 1, c.canonical_json({"objective": "raw legacy"}),
                 "raw-director", "2026-01-03T00:00:00.000Z"))

            # A four-part D-20 persona is an exact canonical writer and owns
            # its one migrated identity seed just like the default persona.
            conn.execute(
                "INSERT INTO handoffs"
                " (project_id,version,content,updated_by,updated_at)"
                " VALUES (?,?,?,?,?)",
                ("persona", 7,
                 c.canonical_json({"objective": "red persona legacy"}),
                 "persona.director.codex.red",
                 "2026-01-04T00:00:00.000Z"))
        finally:
            conn.close()

        migrated = c.connect(db)
        try:
            exact_rows = migrated.execute(
                "SELECT * FROM identity_handoffs WHERE project_id='exact'"
                " ORDER BY actor_id,version").fetchall()
            self.assertEqual(len(exact_rows), 1)
            self.assertEqual(exact_rows[0]["actor_id"],
                             "exact.director.codex")
            self.assertEqual(exact_rows[0]["version"], 1)
            self.assertEqual(exact_rows[0]["legacy_source_version"], 2)
            self.assertEqual(
                json.loads(exact_rows[0]["content"])["objective"],
                "latest exact")
            self.assertEqual(migrated.execute(
                "SELECT COUNT(*) AS n FROM identity_handoffs"
                " WHERE project_id='ambiguous'").fetchone()["n"], 0)
            self.assertEqual(migrated.execute(
                "SELECT COUNT(*) AS n FROM identity_handoffs"
                " WHERE project_id='raw'").fetchone()["n"], 0)
            persona = migrated.execute(
                "SELECT * FROM identity_handoffs"
                " WHERE project_id='persona'").fetchone()
            self.assertIsNotNone(persona)
            self.assertEqual(persona["actor_id"],
                             "persona.director.codex.red")
            self.assertEqual(persona["version"], 1)
            self.assertEqual(persona["legacy_source_version"], 7)
            self.assertEqual(
                json.loads(persona["content"])["objective"],
                "red persona legacy")
            # Migration never consumes or rewrites the compatibility archive.
            self.assertEqual(migrated.execute(
                "SELECT COUNT(*) AS n FROM handoffs"
                " WHERE project_id IN"
                " ('exact','ambiguous','raw','persona')").fetchone()["n"],
                6)

            # The first real identity write in a project with only ambiguous
            # legacy history starts from an empty identity document. It never
            # clones unrelated fallback fields from the global archive.
            first = c.update_identity_handoff(
                migrated, "ambiguous", "ambiguous.director.codex", "agent",
                {"objective": "fresh exact identity"}, expected_version=0)
            self.assertEqual(first["handoff_version"], 1)
            current = c.get_identity_handoff(
                migrated, "ambiguous",
                actor_id="ambiguous.director.codex", actor_type="agent")
            self.assertEqual(current["handoff"]["objective"],
                             "fresh exact identity")
            self.assertIsNone(current["handoff"]["risks"])
        finally:
            migrated.close()

        # Re-opening is idempotent; the seed is not replayed as version 2.
        reopened = c.connect(db)
        try:
            self.assertEqual(reopened.execute(
                "SELECT COUNT(*) AS n FROM identity_handoffs"
                " WHERE project_id='exact'").fetchone()["n"], 1)
            self.assertEqual(reopened.execute(
                "SELECT COUNT(*) AS n FROM identity_handoffs"
                " WHERE project_id='persona'").fetchone()["n"], 1)
            self.assertEqual(reopened.execute(
                "SELECT COUNT(*) AS n FROM identity_handoffs"
                " WHERE project_id='raw'").fetchone()["n"], 0)
        finally:
            reopened.close()

    def test_every_exact_identity_writes_only_its_own_handoff(self):
        expected = {
            DIRECTOR_RED: "red director",
            WORKER: "worker",
            ADVISOR: "advisor",
        }
        for actor, objective in expected.items():
            result = self._update(
                actor, "agent", {"objective": objective}, expected=0)
            self.assertEqual(result["handoff_actor"], actor)
            self.assertEqual(result["handoff_version"], 1)

        for actor, objective in expected.items():
            own = c.get_identity_handoff(
                self.conn, "p1", actor_id=actor, actor_type="agent")
            self.assertEqual(own["handoff_actor"], actor)
            self.assertEqual(own["handoff"]["objective"], objective)
            self.assertEqual(own["handoff_version"], 1)
            # The exact identity handoff is also embedded in the brief.
            brief = c.get_handoff(
                self.conn, "p1", actor_id=actor, actor_type="agent")
            self.assertEqual(brief["identity_handoff_actor"], actor)
            self.assertEqual(
                brief["identity_handoff"]["objective"], objective)
            self.assertEqual(brief["identity_handoff_version"], 1)

        # Humans and console identities own no identity handoff at all.
        with self.assertRaisesRegex(
                c.AttaccaError, "registered AI|identity handoff owner"):
            self._update(
                HUMAN, "human", {"objective": "human"}, expected=0)
        # A human identity cannot select the id of a registered AI and mutate
        # that AI's continuity record by changing only actor_type.
        with self.assertRaisesRegex(
                c.AttaccaError, "registered AI|identity handoff owner"):
            self._update(
                DIRECTOR_RED, "human", {"objective": "impersonated"},
                expected=1)
        self.assertEqual(c.get_identity_handoff(
            self.conn, "p1", actor_id=DIRECTOR_RED,
            actor_type="agent")["handoff"]["objective"], "red director")

    def test_coordination_reads_foreign_identity_without_granting_write(self):
        self._update(
            DIRECTOR_RED, "agent", {"active_work": "red work"}, 0)

        foreign_ai = c.get_identity_handoff(
            self.conn, "p1", actor_id=WORKER, actor_type="agent",
            target_actor_id=DIRECTOR_RED)
        self.assertEqual(foreign_ai["handoff_actor"], DIRECTOR_RED)
        self.assertEqual(foreign_ai["handoff"]["active_work"], "red work")
        # The same coordination read is available through the full brief, and
        # role scope/authority remain the reader's, not the target owner's.
        brief = c.get_handoff(
            self.conn, "p1", actor_id=WORKER, actor_type="agent",
            target_actor_id=DIRECTOR_RED)
        self.assertEqual(brief["identity_handoff_actor"], DIRECTOR_RED)
        self.assertEqual(
            brief["identity_handoff"]["active_work"], "red work")
        self.assertEqual(brief["role_scope"]["actor"], WORKER)

        # Humans own no identity handoff, so they are not a coordination
        # target either.
        with self.assertRaisesRegex(c.AttaccaError, "not a registered AI"):
            c.get_identity_handoff(
                self.conn, "p1", actor_id=DIRECTOR_BLUE, actor_type="agent",
                target_actor_id=HUMAN)
        human_read = c.get_identity_handoff(
            self.conn, "p1", actor_id=HUMAN, actor_type="human")
        self.assertIsNone(human_read["handoff_actor"])
        with self.assertRaisesRegex(c.AttaccaError, "not registered|unknown|"
                                    "not a registered AI"):
            c.get_identity_handoff(
                self.conn, "p1", actor_id=WORKER, actor_type="agent",
                target_actor_id="p1.worker.ghost")

    def test_handoff_versions_conflict_per_identity_not_per_project(self):
        red_v1 = self._update(
            DIRECTOR_RED, "agent", {"objective": "red v1"}, 0)
        blue_v1 = self._update(
            DIRECTOR_BLUE, "agent", {"objective": "blue v1"}, 0)
        self.assertEqual(red_v1["handoff_version"], 1)
        self.assertEqual(blue_v1["handoff_version"], 1)

        # Blue's project-context bump does not stale Red's identity version.
        red_v2 = self._update(
            DIRECTOR_RED, "agent", {"objective": "red v2"}, 1)
        self.assertEqual(red_v2["handoff_version"], 2)
        with self.assertRaisesRegex(
                c.AttaccaError, "identity handoff conflict.*expected v1"):
            self._update(
                DIRECTOR_RED, "agent", {"objective": "stale red"}, 1)

        # The same numeric expected version remains valid for Blue because
        # version counters are scoped by exact identity.
        blue_v2 = self._update(
            DIRECTOR_BLUE, "agent", {"objective": "blue v2"}, 1)
        self.assertEqual(blue_v2["handoff_version"], 2)

        history = c.identity_handoff_history(
            self.conn, "p1", actor_id=WORKER, actor_type="agent",
            target_actor_id=DIRECTOR_RED, limit=20)
        self.assertEqual(history["handoff_actor"], DIRECTOR_RED)
        self.assertEqual(
            [item["version"] for item in history["versions"]], [2, 1])
        self.assertEqual(
            [item["content"]["objective"] for item in history["versions"]],
            ["red v2", "red v1"])

    def test_role_scope_authority_versions_history_and_applicability(self):
        director_v1 = c.role_scope_set(
            self.conn, "p1", DIRECTOR_BLUE, "agent", "director",
            "director shared background", expected_version=0)
        worker_v1 = c.role_scope_set(
            self.conn, "p1", DIRECTOR_BLUE, "agent", "worker",
            "worker shared background", expected_version=0)
        advisor_v1 = c.role_scope_set(
            self.conn, "p1", HUMAN, "human", "advisor",
            "advisor shared background", expected_version=0)
        lead_v1 = c.role_scope_set(
            self.conn, "p1", HUMAN, "human", "lead_director",
            "lead-only coordination background", expected_version=0)
        for result in (director_v1, worker_v1, advisor_v1, lead_v1):
            self.assertEqual(result["role_scope"]["version"], 1)

        worker_v2 = c.role_scope_set(
            self.conn, "p1", HUMAN, "human", "worker",
            "worker background v2", expected_version=1)
        self.assertEqual(worker_v2["role_scope"]["version"], 2)
        with self.assertRaisesRegex(c.AttaccaError, "role scope conflict"):
            c.role_scope_set(
                self.conn, "p1", DIRECTOR_BLUE, "agent", "worker",
                "stale overwrite", expected_version=1)
        for actor in (WORKER, ADVISOR):
            with self.assertRaisesRegex(
                    c.AttaccaError, "human or registered Director"):
                c.role_scope_set(
                    self.conn, "p1", actor, "agent", "worker",
                    "unauthorized", expected_version=2)

        worker_scope = c.role_scope_get(
            self.conn, "p1", actor_id=WORKER, actor_type="agent")
        self.assertEqual(
            [(item["role"], item["content"])
             for item in worker_scope["scopes"]],
            [("worker", "worker background v2")])
        advisor_scope = c.role_scope_get(
            self.conn, "p1", actor_id=ADVISOR, actor_type="agent")
        self.assertEqual(
            [item["role"] for item in advisor_scope["scopes"]], ["advisor"])
        non_lead = c.role_scope_get(
            self.conn, "p1", actor_id=DIRECTOR_BLUE, actor_type="agent")
        self.assertEqual(
            [item["role"] for item in non_lead["scopes"]], ["director"])
        lead = c.role_scope_get(
            self.conn, "p1", actor_id=DIRECTOR_RED, actor_type="agent")
        self.assertEqual(
            [item["role"] for item in lead["scopes"]],
            ["director", "lead_director"])
        self.assertIn("director shared background", lead["effective_content"])
        self.assertIn("lead-only coordination", lead["effective_content"])
        with self.assertRaisesRegex(c.AttaccaError, "only read its own"):
            c.role_scope_get(
                self.conn, "p1", actor_id=WORKER, actor_type="agent",
                role="director")
        with self.assertRaisesRegex(c.AttaccaError, "list all"):
            c.role_scope_get(
                self.conn, "p1", actor_id=WORKER, actor_type="agent",
                include_all=True)

        management = c.role_scope_get(
            self.conn, "p1", actor_id=DIRECTOR_BLUE, actor_type="agent",
            include_all=True)
        self.assertEqual(
            {item["role"] for item in management["scopes"]},
            {"director", "advisor", "worker", "lead_director"})
        history = c.role_scope_history(
            self.conn, "p1", "worker", actor_id=DIRECTOR_BLUE,
            actor_type="agent", limit=20)
        self.assertEqual(
            [(item["version"], item["content"], item["updated_by"])
             for item in history["versions"]],
            [(2, "worker background v2", HUMAN),
             (1, "worker shared background", DIRECTOR_BLUE)])
        with self.assertRaisesRegex(c.AttaccaError, "only read its own"):
            c.role_scope_history(
                self.conn, "p1", "director", actor_id=WORKER,
                actor_type="agent", limit=20)

    def test_optional_personas_are_exactly_separate_continuity_owners(self):
        self.assertEqual(c.canonical_agent_id("p1", "director", "codex"),
                         DIRECTOR)
        self.assertEqual(
            c.canonical_agent_id(
                "p1", "director", "codex", persona="red"),
            DIRECTOR_RED)
        self.assertEqual(
            c.parse_canonical_agent_id(DIRECTOR), {
                "project_id": "p1", "role": "director",
                "runtime": "codex", "persona": None})
        self.assertEqual(
            c.parse_canonical_agent_id(DIRECTOR_BLUE), {
                "project_id": "p1", "role": "director",
                "runtime": "codex", "persona": "blue"})

        # Canonical registration preserves the persona selected by the exact
        # four-part actor hint instead of collapsing both sessions to default.
        persona_project = "personas"
        persona_repo = self.root / "persona-repo"
        persona_repo.mkdir()
        c.project_init(
            self.conn, "setup", "human", path=str(persona_repo),
            project_id=persona_project, name="Personas")
        red = c.agent_register(
            self.conn, persona_project,
            "personas.director.codex.amber", "agent",
            agent_id="personas.director.codex.amber", role="director",
            runtime="codex", canonical_identity=True)
        blue = c.agent_register(
            self.conn, persona_project,
            "personas.director.codex.cyan", "agent",
            agent_id="personas.director.codex.cyan", role="director",
            runtime="codex", canonical_identity=True)
        self.assertEqual(red["agent_id"], "personas.director.codex.amber")
        self.assertEqual(blue["agent_id"], "personas.director.codex.cyan")

        self._update(
            DIRECTOR_RED, "agent", {"objective": "red continuity"}, 0)
        self._update(
            DIRECTOR_BLUE, "agent", {"objective": "blue continuity"}, 0)
        self.assertEqual(c.get_identity_handoff(
            self.conn, "p1", actor_id=DIRECTOR_RED,
            actor_type="agent")["handoff"]["objective"], "red continuity")
        self.assertEqual(c.get_identity_handoff(
            self.conn, "p1", actor_id=DIRECTOR_BLUE,
            actor_type="agent")["handoff"]["objective"], "blue continuity")

        c.role_scope_set(
            self.conn, "p1", DIRECTOR_RED, "agent", "director",
            "shared by every director persona", expected_version=0)
        for persona in (DIRECTOR_RED, DIRECTOR_BLUE):
            self.assertEqual(c.role_scope_get(
                self.conn, "p1", actor_id=persona,
                actor_type="agent")["scopes"][0]["content"],
                "shared by every director persona")

        c.room_send(
            self.conn, "p1", WORKER, "agent", "persona inbox event")
        red_inbox = c.inbox_read(
            self.conn, "p1", DIRECTOR_RED, mark_read=True,
            actor_type="agent")
        self.assertEqual(red_inbox["unread_total"], 1)
        self.assertEqual(c.inbox_read(
            self.conn, "p1", DIRECTOR_RED, mark_read=False,
            actor_type="agent")["unread_total"], 0)
        # Red's cursor cannot consume Blue's inbox merely because both use
        # the same role/runtime.
        self.assertEqual(c.inbox_read(
            self.conn, "p1", DIRECTOR_BLUE, mark_read=False,
            actor_type="agent")["unread_total"], 1)

        red_task = c.task_create(
            self.conn, "p1", WORKER, "agent", "Red task")["task_id"]
        blue_task = c.task_create(
            self.conn, "p1", WORKER, "agent", "Blue task")["task_id"]
        self.assertEqual(c.task_claim(
            self.conn, "p1", DIRECTOR_RED, "agent",
            red_task)["claimed_by"], DIRECTOR_RED)
        with self.assertRaisesRegex(c.AttaccaError, "not claimable"):
            c.task_claim(
                self.conn, "p1", DIRECTOR_BLUE, "agent", red_task)
        self.assertEqual(c.task_claim(
            self.conn, "p1", DIRECTOR_BLUE, "agent",
            blue_task)["claimed_by"], DIRECTOR_BLUE)


class IdentityHandoffRoleScopeMcpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "mcp.db"
        repo = self.root / "repo"
        repo.mkdir()
        conn = c.connect(self.db)
        c.project_init(
            conn, "setup", "human", path=str(repo),
            project_id="p1", name="MCP Identity")
        for actor, role, runtime in (
                (DIRECTOR, "director", "codex"),
                (DIRECTOR_RED, "director", "codex"),
                (DIRECTOR_BLUE, "director", "codex"),
                (WORKER, "worker", "claude")):
            register_exact(conn, "p1", actor, role, runtime)
        c.update_identity_handoff(
            conn, "p1", DIRECTOR_BLUE, "agent",
            {"objective": "blue over MCP"}, expected_version=0)
        conn.close()

    def tearDown(self):
        c.set_current_owner(None)
        self.tmp.cleanup()

    def _session(self, actor):
        return c.McpSession(
            self.db, default_project="p1", actor=actor,
            actor_type="agent", detect_cwd=False,
            preserve_actor_identity=True)

    def test_standard_mcp_resolution_reuses_default_unless_persona_selected(self):
        default_a = c.McpSession(
            self.db, default_project="p1", actor="codex",
            actor_type="agent", detect_cwd=False, device_id="container-a")
        default_b = c.McpSession(
            self.db, default_project="p1", actor="codex",
            actor_type="agent", detect_cwd=False, device_id="container-b")
        explicit_red = c.McpSession(
            self.db, default_project="p1", actor=DIRECTOR_RED,
            actor_type="agent", detect_cwd=False, device_id="container-c")
        self.assertEqual(default_a._actor("p1"), DIRECTOR)
        self.assertEqual(default_b._actor("p1"), DIRECTOR)
        self.assertEqual(explicit_red._actor("p1"), DIRECTOR_RED)
        self.assertNotEqual(explicit_red._actor("p1"), default_a._actor("p1"))

    def test_mcp_schemas_and_dispatch_expose_identity_and_role_scope(self):
        tools = {item["name"]: item for item in c.MCP_TOOLS}
        self.assertIn("target_actor_id",
                      tools["get_handoff"]["inputSchema"]["properties"])
        self.assertIn("target_actor_id",
                      tools["get_identity_handoff"]["inputSchema"][
                          "properties"])
        for name in ("update_handoff", "update_identity_handoff"):
            self.assertIn(
                "expected_handoff_version",
                tools[name]["inputSchema"]["properties"])
            self.assertNotIn(
                "target_actor_id", tools[name]["inputSchema"]["properties"])
        self.assertIn("identity", tools["get_handoff"]["description"].lower())
        self.assertIn("shared", tools["update_handoff"]["description"].lower())
        self.assertIn(
            "director", tools["update_handoff"]["description"].lower())
        self.assertIn(
            "own", tools["update_identity_handoff"]["description"].lower())
        for name in ("role_scope_get", "role_scope_set", "role_scope_history",
                     "get_identity_handoff", "update_identity_handoff",
                     "identity_handoff_history"):
            self.assertIn(name, tools)

        red = self._session(DIRECTOR_RED)
        foreign = red.dispatch_tool(
            "get_identity_handoff", {"target_actor_id": DIRECTOR_BLUE})
        self.assertEqual(foreign["handoff_actor"], DIRECTOR_BLUE)
        self.assertEqual(foreign["handoff"]["objective"], "blue over MCP")
        foreign_brief = red.dispatch_tool(
            "get_handoff", {"target_actor_id": DIRECTOR_BLUE})
        self.assertEqual(
            foreign_brief["identity_handoff_actor"], DIRECTOR_BLUE)
        self.assertIsNone(foreign_brief["handoff_actor"])
        self.assertEqual(foreign_brief["handoff_scope"], "project")

        # Coordination targeting is a read-only feature. Surface client misuse
        # instead of silently pretending a foreign-targeted update succeeded.
        for tool in ("update_handoff", "update_identity_handoff"):
            with self.assertRaisesRegex(
                    c.AttaccaError, "target_actor_id.*read|cannot target"):
                red.dispatch_tool(tool, {
                    "target_actor_id": DIRECTOR_BLUE,
                    "objective": "must be rejected",
                    "expected_handoff_version": 0,
                })
        own = red.dispatch_tool("update_identity_handoff", {
            "objective": "red over MCP",
            "expected_handoff_version": 0,
        })
        self.assertEqual(own["handoff_actor"], DIRECTOR_RED)
        self.assertEqual(red.dispatch_tool(
            "get_identity_handoff", {})["handoff"]["objective"],
            "red over MCP")
        self.assertEqual(red.dispatch_tool(
            "get_handoff", {})["identity_handoff"]["objective"],
            "red over MCP")
        self.assertEqual(red.dispatch_tool(
            "get_identity_handoff", {"target_actor_id": DIRECTOR_BLUE})[
                "handoff"]["objective"], "blue over MCP")
        with self.assertRaisesRegex(
                c.AttaccaError, "identity handoff conflict"):
            red.dispatch_tool("update_identity_handoff", {
                "objective": "stale red MCP overwrite",
                "expected_handoff_version": 0,
            })
        history = red.dispatch_tool(
            "identity_handoff_history", {"target_actor_id": DIRECTOR_BLUE})
        self.assertEqual(history["handoff_actor"], DIRECTOR_BLUE)
        self.assertEqual(
            [item["content"]["objective"] for item in history["versions"]],
            ["blue over MCP"])

        # The shared project handoff is a separate, Director-only record.
        shared = red.dispatch_tool("update_handoff", {
            "objective": "shared over MCP",
            "expected_handoff_version": 0,
        })
        self.assertIsNone(shared["handoff_actor"])
        self.assertEqual(shared["handoff_scope"], "project")
        brief = red.dispatch_tool("get_handoff", {})
        self.assertEqual(brief["handoff"]["objective"], "shared over MCP")
        self.assertEqual(brief["identity_handoff"]["objective"],
                         "red over MCP")

        scope = red.dispatch_tool("role_scope_set", {
            "role": "worker", "content": "MCP worker background",
            "expected_version": 0,
        })
        self.assertEqual(scope["role_scope"]["version"], 1)
        history = red.dispatch_tool("role_scope_history", {
            "role": "worker", "limit": 20,
        })
        self.assertEqual(history["versions"][0]["content"],
                         "MCP worker background")
        worker = self._session(WORKER)
        applicable = worker.dispatch_tool("role_scope_get", {})
        self.assertEqual(
            [item["role"] for item in applicable["scopes"]], ["worker"])
        worker_handoff = worker.dispatch_tool("update_identity_handoff", {
            "objective": "worker-owned MCP continuity",
            "expected_handoff_version": 0,
        })
        self.assertEqual(worker_handoff["handoff_actor"], WORKER)
        self.assertEqual(worker_handoff["handoff_version"], 1)
        with self.assertRaisesRegex(
                c.AttaccaError, "may only be edited by a registered Director"):
            worker.dispatch_tool("update_handoff", {
                "objective": "worker cannot own the shared handoff",
                "expected_handoff_version": 1,
            })
        with self.assertRaisesRegex(
                c.AttaccaError, "human or registered Director"):
            worker.dispatch_tool("role_scope_set", {
                "role": "worker", "content": "forbidden",
                "expected_version": 1,
            })
        with self.assertRaisesRegex(c.AttaccaError, "only read its own"):
            worker.dispatch_tool("role_scope_history", {
                "role": "director", "limit": 20,
            })


class IdentityHandoffRoleScopeRestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.db = cls.root / "rest.db"
        repo = cls.root / "repo"
        repo.mkdir()
        conn = c.connect(cls.db)
        c.project_init(
            conn, "setup", "human", path=str(repo),
            project_id="p1", name="REST Identity")
        for actor, role, runtime in (
                (DIRECTOR_RED, "director", "codex"),
                (DIRECTOR_BLUE, "director", "codex"),
                (WORKER, "worker", "claude")):
            register_exact(conn, "p1", actor, role, runtime)
        conn.close()
        cls.server = ServerFixture(cls.db)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tmp.cleanup()

    def request(self, method, path, body=None, actor=DIRECTOR_RED,
                actor_type="agent", expected=200):
        status, payload, _ = self.server.request(
            method, path, body, headers={
                "X-Attacca-Actor": actor,
                "X-Attacca-Actor-Type": actor_type,
            })
        self.assertEqual(status, expected, payload)
        return payload

    def test_rest_identity_handoff_target_history_and_owner_only_update(self):
        red = self.request("PUT", "/v1/projects/p1/identity-handoff", {
            "objective": "REST red",
            "expected_handoff_version": 0,
        })
        self.assertEqual(red["handoff_actor"], DIRECTOR_RED)
        blue = self.request(
            "PUT", "/v1/projects/p1/identity-handoff", {
                "objective": "REST blue",
                "expected_handoff_version": 0,
            }, actor=DIRECTOR_BLUE)
        self.assertEqual(blue["handoff_actor"], DIRECTOR_BLUE)

        target = urllib.parse.quote(DIRECTOR_RED, safe="")
        foreign = self.request(
            "GET", "/v1/projects/p1/identity-handoff?actor=" + target,
            actor=WORKER)
        self.assertEqual(foreign["handoff_actor"], DIRECTOR_RED)
        self.assertEqual(foreign["identity_handoff_actor"], DIRECTOR_RED)
        self.assertEqual(foreign["handoff"]["objective"], "REST red")

        brief = self.request(
            "GET", "/v1/projects/p1/handoff?target_actor_id=" + target,
            actor=WORKER)
        self.assertEqual(brief["identity_handoff_actor"], DIRECTOR_RED)
        self.assertEqual(brief["identity_handoff"]["objective"], "REST red")
        self.assertIsNone(brief["handoff_actor"])

        history = self.request(
            "GET", "/v1/projects/p1/identity-handoff/history?actor=" +
            target, actor=WORKER)
        self.assertEqual(history["handoff_actor"], DIRECTOR_RED)
        self.assertEqual(history["versions"][0]["content"]["objective"],
                         "REST red")

        # A body-supplied target is rejected rather than silently ignored.
        rejected_target = self.request(
            "PUT", "/v1/projects/p1/identity-handoff", {
                "target_actor_id": DIRECTOR_RED,
                "objective": "must be rejected",
                "expected_handoff_version": 1,
            }, actor=DIRECTOR_BLUE, expected=400)
        self.assertRegex(
            rejected_target["error"], "target_actor_id.*read|cannot target")
        blue_v2 = self.request(
            "PUT", "/v1/projects/p1/identity-handoff", {
                "objective": "REST blue v2",
                "expected_handoff_version": 1,
            }, actor=DIRECTOR_BLUE)
        self.assertEqual(blue_v2["handoff_actor"], DIRECTOR_BLUE)
        red_after = self.request(
            "GET", "/v1/projects/p1/identity-handoff?actor=" + target,
            actor=WORKER)
        self.assertEqual(red_after["handoff"]["objective"], "REST red")

        worker_own = self.request(
            "PUT", "/v1/projects/p1/identity-handoff", {
                "objective": "worker-owned REST continuity",
                "expected_handoff_version": 0,
            }, actor=WORKER)
        self.assertEqual(worker_own["handoff_actor"], WORKER)
        self.assertEqual(worker_own["handoff_version"], 1)

        conflict = self.request(
            "PUT", "/v1/projects/p1/identity-handoff", {
                "objective": "stale REST red",
                "expected_handoff_version": 0,
            }, expected=400)
        self.assertIn("identity handoff conflict", conflict["error"])

    def test_rest_shared_handoff_is_director_only_and_project_wide(self):
        written = self.request("PUT", "/v1/projects/p1/handoff", {
            "objective": "REST shared objective",
            "expected_handoff_version": 0,
        })
        self.assertIsNone(written["handoff_actor"])
        self.assertEqual(written["handoff_scope"], "project")
        self.assertEqual(written["handoff_version"], 1)

        seen = self.request("GET", "/v1/projects/p1/handoff", actor=WORKER)
        self.assertEqual(seen["handoff"]["objective"], "REST shared objective")
        self.assertEqual(seen["shared_handoff"], seen["handoff"])
        self.assertEqual(seen["handoff_scope"], "project")

        history = self.request(
            "GET", "/v1/projects/p1/handoff/history", actor=WORKER)
        self.assertEqual(history["handoff_scope"], "project")
        self.assertEqual(history["versions"][0]["content"]["objective"],
                         "REST shared objective")

        refused = self.request(
            "PUT", "/v1/projects/p1/handoff", {
                "objective": "worker overwrite",
                "expected_handoff_version": 1,
            }, actor=WORKER, expected=400)
        self.assertIn("registered Director", refused["error"])
        rejected_target = self.request(
            "PUT", "/v1/projects/p1/handoff", {
                "target_actor_id": DIRECTOR_BLUE,
                "objective": "must be rejected",
                "expected_handoff_version": 1,
            }, expected=400)
        self.assertRegex(
            rejected_target["error"], "target_actor_id.*read|cannot target")

    def test_rest_role_scope_crud_authority_and_history(self):
        created = self.request(
            "PUT", "/v1/projects/p1/role-scopes/worker", {
                "content": "REST worker background",
                "expected_version": 0,
            })
        self.assertEqual(created["role_scope"]["version"], 1)

        applicable = self.request(
            "GET", "/v1/projects/p1/role-scopes", actor=WORKER)
        self.assertEqual(
            [(item["role"], item["content"])
             for item in applicable["scopes"]],
            [("worker", "REST worker background")])
        denied = self.request(
            "PUT", "/v1/projects/p1/role-scopes/worker", {
                "content": "worker cannot govern", "expected_version": 1,
            }, actor=WORKER, expected=400)
        self.assertIn("registered Director", denied["error"])

        updated = self.request(
            "PUT", "/v1/projects/p1/role-scopes/worker", {
                "content": "REST worker background v2",
                "expected_version": 1,
            })
        self.assertEqual(updated["role_scope"]["version"], 2)
        history = self.request(
            "GET", "/v1/projects/p1/role-scopes/worker/history",
            actor=WORKER)
        self.assertEqual(
            [item["version"] for item in history["versions"]], [2, 1])
        self.assertEqual(
            [item["content"] for item in history["versions"]],
            ["REST worker background v2", "REST worker background"])
        foreign_history = self.request(
            "GET", "/v1/projects/p1/role-scopes/director/history",
            actor=WORKER, expected=400)
        self.assertIn("only read its own", foreign_history["error"])


class IdentityHandoffStartupOrderTest(unittest.TestCase):
    def test_lifecycle_fetches_governance_then_identity_then_operations(self):
        observed = []
        observed_envs = []

        def fake_run(*args, **kwargs):
            observed_envs.append(dict(kwargs["env"]))
            requests = [json.loads(line) for line in kwargs["input"].splitlines()]
            responses = []
            for request in requests:
                request_id = request.get("id")
                if request_id is None:
                    continue
                if request.get("method") == "initialize":
                    responses.append({
                        "jsonrpc": "2.0", "id": request_id, "result": {}})
                    continue
                name = request["params"]["name"]
                observed.append(name)
                values = {
                    "list_projects": {"projects": [{"project_id": "p1"}]},
                    "rule_list": {"rules": []},
                    "cloud_context_get": {"cloud_context": {
                        "version": 1, "content": "cloud"}},
                    "role_scope_get": {"actor": DIRECTOR_RED, "scopes": [{
                        "role": "director", "version": 1,
                        "content": "role"}], "effective_content": "role"},
                    "get_handoff": {
                        "context_version": 1, "handoff_actor": DIRECTOR_RED,
                        "handoff_version": 1,
                        "handoff": {"objective": "identity"}},
                    "get_project_log": {"project": "p1", "lines": []},
                    "check_inbox": {"messages": [], "unread_total": 0},
                    "room_read": {"messages": []},
                    "task_list": {"tasks": []},
                    "attacca_status": {
                        "you": {"actor_id": DIRECTOR_RED}, "counts": {}},
                    "agent_list": {"agents": [{
                        "agent_id": DIRECTOR_RED, "role": "director"}]},
                }
                value = values.get(name, {})
                responses.append({
                    "jsonrpc": "2.0", "id": request_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(value)}],
                        "isError": False,
                    },
                })
            return subprocess.CompletedProcess(
                args=args[0] if args else [], returncode=0,
                stdout="\n".join(json.dumps(item) for item in responses) + "\n",
                stderr="")

        status = {"project_id": "p1", "root": str(ROOT)}
        config = {
            "url": "http://127.0.0.1:4173", "actor": DIRECTOR_RED,
            "owner": None,
        }
        with mock.patch.object(hook.subprocess, "run", side_effect=fake_run):
            snapshot = hook._mcp_snapshot(
                status, ROOT, config, mark_inbox_read=False)

        # Identity discovery may happen first. Once the exact actor is known,
        # D-19's durable startup order is strict and observable.
        order = [
            "rule_list", "cloud_context_get", "role_scope_get",
            "get_handoff", "get_project_log", "check_inbox", "room_read",
            "task_list",
        ]
        for name in order:
            self.assertIn(name, observed, "%s was not fetched: %r" %
                          (name, observed))
        for earlier, later in zip(order, order[1:]):
            self.assertLess(
                observed.index(earlier), observed.index(later),
                "%s must be fetched before %s: %r" %
                (earlier, later, observed))
        self.assertEqual(observed.count("get_handoff"), 1)
        self.assertEqual(observed_envs[0]["ATTACCA_ACTOR"], DIRECTOR_RED)

        compact = hook._compact_snapshot(snapshot)
        compact_keys = list(compact)
        brief_order = [
            "project_rules", "cloud_context", "role_scope", "handoff",
            "unread_room", "tasks",
        ]
        for earlier, later in zip(brief_order, brief_order[1:]):
            self.assertLess(
                compact_keys.index(earlier), compact_keys.index(later),
                "%s must be injected before %s: %r" %
                (earlier, later, compact_keys))
        self.assertEqual(compact["role_scope"]["effective_content"], "role")
        self.assertEqual(compact["handoff"]["objective"], "identity")


if __name__ == "__main__":
    unittest.main()
