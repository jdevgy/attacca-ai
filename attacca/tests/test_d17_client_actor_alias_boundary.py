"""D-17 client-install credentials stay separate from AI identity aliases."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_d17_client_alias_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class ClientActorAliasBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.conn = c.connect(Path(self.temp.name) / "alias-boundary.db")
        c.auth_create_user(
            self.conn, "owner", "owner-password", bootstrap=True,
            is_admin=True)
        c.auth_create_user(self.conn, "other", "other-password")
        owner = self.conn.execute(
            "SELECT * FROM auth_users WHERE username='owner'").fetchone()
        other = self.conn.execute(
            "SELECT * FROM auth_users WHERE username='other'").fetchone()
        for user in (owner, other):
            self.conn.execute(
                "INSERT INTO auth_project_memberships"
                " (user_id,project_id,granted_at,granted_by)"
                " VALUES (?,?,?,?)",
                (user["user_id"], "project", c.now_iso(), "owner"))
        c.set_current_owner("owner")
        c.project_init(
            self.conn, "web.owner", "human",
            path=Path(self.temp.name) / "repo", project_id="project")
        c.agent_register(
            self.conn, "project", "web.owner", "human",
            agent_id="project.director.codex", role="director",
            runtime="codex", registration_username="owner")
        c.set_current_owner("other")
        c.agent_register(
            self.conn, "project", "web.other", "human",
            agent_id="project.worker.claude", role="worker",
            runtime="claude", registration_username="other")
        self.conn.execute(
            "INSERT INTO actor_aliases"
            " (project_id,legacy_actor_id,canonical_actor_id,migrated_at)"
            " VALUES (?,?,?,?)",
            ("project", "project.director.old-codex",
             "project.director.codex", c.now_iso()))
        self.conn.execute(
            "INSERT INTO actor_aliases"
            " (project_id,legacy_actor_id,canonical_actor_id,migrated_at)"
            " VALUES (?,?,?,?)",
            ("project", "project.worker.old-claude",
             "project.worker.claude", c.now_iso()))
        principal = c._auth_principal(
            self.conn, owner, "session", session_hash="session")
        created = c.auth_client_key_create(
            self.conn, principal, "Codex on laptop", "laptop-client",
            memberships=["project"])
        self.token_id = created["record"]["token_id"]
        self.principal = c.auth_token_principal(self.conn, created["token"])

    def tearDown(self):
        c.set_current_owner(None)
        self.conn.close()
        self.temp.cleanup()

    def test_alias_resolution_is_request_authorization_not_key_identity(self):
        selected = c.auth_client_principal_scope(
            self.conn, self.principal, "project",
            "project.director.old-codex")

        self.assertEqual(selected["actor_id"], "project.director.codex")
        self.assertEqual(selected["role"], "director")
        self.assertEqual(selected["runtime"], "codex")
        token = self.conn.execute(
            "SELECT actor_id,project_id,runtime,actor_type,client_label"
            " FROM auth_tokens WHERE token_id=?", (self.token_id,)).fetchone()
        self.assertIsNone(token["actor_id"])
        self.assertIsNone(token["project_id"])
        self.assertEqual(token["runtime"], "client")
        self.assertEqual(token["actor_type"], "client")
        self.assertEqual(token["client_label"], "Codex on laptop")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS n FROM auth_token_actor_bindings"
            " WHERE token_id=?", (self.token_id,)).fetchone()["n"], 0)

    def test_alias_does_not_bypass_registered_actor_owner(self):
        with self.assertRaisesRegex(c.AuthorizationError,
                                    "client_actor_denied"):
            c.auth_client_principal_scope(
                self.conn, self.principal, "project",
                "project.worker.old-claude")


if __name__ == "__main__":
    unittest.main()
