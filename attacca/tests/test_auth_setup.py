"""Hosted setup authentication and machine-credential isolation tests."""

import importlib.util
import json
import os
import stat
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_auth_setup_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class CredentialIsolationTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.credentials = self.root / "credentials.json"
        self.identity = self.root / "identity.json"
        self.patches = [
            mock.patch.object(c, "CREDENTIALS_FILE", self.credentials),
            mock.patch.object(c, "IDENTITY_FILE", self.identity),
            mock.patch.dict(os.environ, {c.ENV_API_TOKEN: ""}, clear=False),
        ]
        for patcher in self.patches:
            patcher.start()
        os.environ.pop(c.ENV_API_TOKEN, None)

    def tearDown(self):
        c._remote_setup_auth.context = None
        for patcher in reversed(self.patches):
            patcher.stop()
        self.tmp.cleanup()

    def test_full_url_project_actor_scope_and_same_runtime_do_not_collide(self):
        server = "https://attacca.example/tenant-a"
        first = "atc_first-secret"
        second = "atc_second-secret"
        returned = c.save_api_token(
            server, first, runtime="codex", project_id="alpha",
            actor_id="alpha.director.codex")
        c.save_api_token(
            server, second, runtime="codex", project_id="beta",
            actor_id="beta.worker.codex")
        self.assertEqual(returned, str(self.credentials))
        self.assertEqual(
            stat.S_IMODE(self.credentials.stat().st_mode), 0o600)
        self.assertEqual(c.load_api_token(
            server, runtime="codex", project_id="alpha",
            actor_id="alpha.director.codex"), first)
        self.assertEqual(c.load_api_token(
            server, runtime="codex", project_id="beta",
            actor_id="beta.worker.codex"), second)
        # A short runtime is usable only inside an already selected project.
        self.assertEqual(c.load_api_token(
            server, runtime="codex", project_id="alpha",
            actor_id="codex"), first)
        self.assertIsNone(c.load_api_token(
            server, runtime="codex", actor_id="codex"))
        self.assertIsNone(c.load_api_token(
            server, runtime="codex", project_id="missing",
            actor_id="missing.director.codex"))

        # A full path is part of the trust boundary.
        c.save_api_token(
            "https://attacca.example/tenant-b", "atc_tenant-b",
            runtime="codex", project_id="alpha",
            actor_id="alpha.director.codex")
        self.assertEqual(c.load_api_token(
            "https://attacca.example/tenant-b", runtime="codex",
            project_id="alpha", actor_id="alpha.director.codex"),
            "atc_tenant-b")
        self.assertEqual(c.load_api_token(
            server, runtime="codex", project_id="alpha",
            actor_id="alpha.director.codex"), first)

        # Human bootstrap credentials are opt-in and never a linked AI
        # fallback.
        c.save_api_token(server, "atc_human")
        self.assertIsNone(c.load_api_token(
            server, runtime="claude", project_id="alpha",
            actor_id="alpha.director.claude"))
        self.assertEqual(c.load_api_token(server, allow_human=True),
                         "atc_human")

    def test_legacy_runtime_credentials_are_read_only_when_unambiguous(self):
        key = c._credential_server_key("http://legacy.example:4173")
        self.credentials.write_text(json.dumps({
            "version": 1,
            "servers": {key: {"tokens": {"codex": "atc_legacy"}}},
        }))
        os.chmod(self.credentials, 0o600)
        self.assertEqual(c.load_api_token(
            key, runtime="codex"), "atc_legacy")
        self.assertIsNone(c.load_api_token(
            key, runtime="codex", project_id="alpha",
            actor_id="alpha.director.codex"))
        self.credentials.write_text(json.dumps({
            "version": 1,
            "servers": {key: {"tokens": {
                "codex": "atc_codex", "claude": "atc_claude"}}},
        }))
        self.assertIsNone(c.load_api_token(key, runtime="codex"))
        with self.assertRaisesRegex(
                c.AttaccaError, "runtime-only credentials are legacy read-only"):
            c.save_api_token(key, "atc_new-legacy", runtime="codex")


class SetupSessionLifecycleTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "auth-setup.db"
        self.credentials = self.root / "credentials.json"
        self.identity = self.root / "identity.json"
        conn = c.connect(self.db)
        try:
            c.auth_create_user(
                conn, "alice", "correct-horse", "Alice", is_admin=True,
                bootstrap=True)
            c.set_current_owner("legacy-owner")
            c.project_init(
                conn, "seed", "human", path=self.root / "checkout",
                project_id="alpha", name="Alpha")
            c.agent_register(
                conn, "alpha", "seed", "human",
                agent_id="alpha.director.codex", role="director",
                runtime="codex", display_name="Alpha Codex")
        finally:
            c.set_current_owner(None)
            conn.close()
        self.server = c.AttaccaServer(("127.0.0.1", 0), self.db, auth=True)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.url = "http://%s:%d" % (host, port)
        self.patches = [
            mock.patch.object(c, "CREDENTIALS_FILE", self.credentials),
            mock.patch.object(c, "IDENTITY_FILE", self.identity),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        c._remote_setup_auth.context = None
        for patcher in reversed(self.patches):
            patcher.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.tmp.cleanup()

    def _force_enforced_temp_server(self):
        conn = c.connect(self.db)
        try:
            c.server_settings_store(conn, {
                "auth.activation_requested": True,
                "auth.activated": True,
                "auth.activated_by": "test-temp-only",
            })
        finally:
            conn.close()

    def _approve_zero_binding_flow(self):
        """Start in one process, approve in the browser, finish in another."""
        self._force_enforced_temp_server()
        with self.assertRaisesRegex(
                c.AuthenticationError, "terminal_enrollment_pending"):
            c.ensure_remote_setup_auth(self.url, "codex", interactive=False)
        state_path = self.credentials.with_name("terminal-flow.json")
        state = json.loads(state_path.read_text())
        flow = state["flows"][c.configured_server_url(self.url)]

        # The browser/account session approves the device but is closed before
        # any setup process resumes; no cookie crosses the process boundary.
        c.remote_setup_login(self.url, "alice", "correct-horse")
        approved = c.remote_json(
            self.url, "POST",
            "/v1/auth/terminal-enrollments/%s/approve" %
            urllib.parse.quote(flow["user_code"], safe=""),
            {"project_memberships": [], "actor_bindings": []})
        self.assertEqual(approved["status"], "approved")
        c.close_remote_setup_session(self.url)
        self.assertIsNone(c._remote_setup_session(self.url))

        # Simulate a fresh CLI/runtime process. It polls, verifies, and stores
        # the browser-approved zero-binding terminal at mode 0600.
        c._remote_setup_auth.context = None
        first_resume = c.ensure_remote_setup_auth(
            self.url, "codex", interactive=False)
        self.assertTrue(first_resume["provisional_human"])
        self.assertEqual(first_resume["bindings"], [])
        self.assertEqual(stat.S_IMODE(self.credentials.stat().st_mode), 0o600)

        # A second process has no browser state but resumes from the private
        # device credential and verifies it against the enforced server.
        c._remote_setup_auth.context = None
        second_resume = c.ensure_remote_setup_auth(
            self.url, "claude", interactive=False)
        self.assertTrue(second_resume["provisional_human"])
        self.assertEqual(second_resume["token_id"], first_resume["token_id"])
        return second_resume

    def test_provisional_terminal_cross_process_setup_then_exact_self_bind(self):
        provisional = self._approve_zero_binding_flow()
        visible = c.remote_json(
            self.url, "GET", "/v1/projects", actor="codex",
            actor_type="agent")
        self.assertIn("alpha", {item["project_id"]
                                for item in visible["projects"]})
        with self.assertRaises(c.AttaccaError):
            c.remote_json(
                self.url, "POST", "/v1/projects/alpha/room",
                {"body": "provisional terminals are setup-only"},
                actor="codex", actor_type="agent")
        with self.assertRaises(c.AttaccaError):
            c.remote_json(
                self.url, "PUT", "/v1/settings", {"verbose": True},
                actor="codex", actor_type="agent")

        created = c.remote_json(
            self.url, "POST", "/v1/projects",
            {"project_id": "delta", "name": "Delta"},
            actor="codex", actor_type="agent")
        self.assertEqual(created["project_id"], "delta")
        actor_id = "delta.director.codex-exact"
        registered = c.remote_json(
            self.url, "POST", "/v1/projects/delta/agents",
            {"agent_id": actor_id, "display_name": "Delta Codex",
             "role": "director", "runtime": "codex"},
            actor=actor_id, actor_type="agent")
        self.assertEqual(registered["agent_id"], actor_id)

        # Yet another process promotes the same credential through the narrow,
        # audited self-binding endpoint. No actor token is minted.
        c._remote_setup_auth.context = None
        resumed = c.ensure_remote_setup_auth(
            self.url, actor_id, interactive=False)
        self.assertTrue(resumed["provisional_human"])
        bound = c.provision_setup_agent_token(self.url, "delta", actor_id)
        self.assertEqual(bound["status"], "bound")
        self.assertEqual(bound["binding_count"], 1)
        self.assertIsNone(c._remote_setup_session(self.url))

        token = c.load_api_token(
            self.url, runtime="codex", project_id="delta",
            actor_id=actor_id)
        self.assertTrue(token.startswith("atd_"))
        status = c.remote_json(
            self.url, "GET", "/v1/auth/status", actor=actor_id,
            actor_type="agent", bearer_token=token, project_id="delta")
        self.assertIn(actor_id, {
            item["actor_id"] for item in status["principal"]["bindings"]})
        self.assertEqual(status["principal"]["token_id"],
                         provisional["token_id"])
        with self.assertRaises(c.AttaccaError):
            c.remote_json(
                self.url, "PUT", "/v1/settings", {"verbose": True},
                actor=actor_id, actor_type="agent",
                bearer_token=token, project_id="delta")

        conn = c.connect(self.db)
        try:
            kinds = [row["token_kind"] for row in conn.execute(
                "SELECT token_kind FROM auth_tokens ORDER BY created_at")]
            self.assertEqual(kinds, ["terminal"])
            exact = conn.execute(
                "SELECT * FROM agents WHERE project_id='delta' AND agent_id=?",
                (actor_id,)).fetchone()
            self.assertIsNotNone(exact)
            self.assertEqual(exact["owner"], "alice")
            event = conn.execute(
                "SELECT * FROM events WHERE project_id='delta'"
                " AND event_type='auth.terminal_binding_added'"
                " ORDER BY seq DESC LIMIT 1").fetchone()
            self.assertIsNotNone(event)
            self.assertEqual(event["owner"], "alice")
            self.assertNotIn(token, "\n".join(conn.iterdump()))
        finally:
            conn.close()

    def test_failed_provisional_binding_mints_no_actor_credential(self):
        self._approve_zero_binding_flow()
        with self.assertRaises(c.AuthenticationError):
            c.provision_setup_agent_token(
                self.url, "alpha", "alpha.worker.does-not-exist")
        self.assertIsNone(c._remote_setup_session(self.url))
        conn = c.connect(self.db)
        try:
            rows = conn.execute(
                "SELECT token_kind FROM auth_tokens").fetchall()
            self.assertEqual([row["token_kind"] for row in rows],
                             ["terminal"])
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM auth_token_actor_bindings"
            ).fetchone()["n"], 0)
        finally:
            conn.close()

    def test_setup_parser_never_accepts_plaintext_token_in_argv(self):
        parser = c.build_parser()
        setup_parser = parser._subparsers._group_actions[0].choices["setup"]
        setup = next(action for action in setup_parser._actions
                     if action.dest == "paste_token")
        self.assertEqual(setup.nargs, 0)
        help_text = setup_parser.format_help()
        self.assertNotIn("--api-token", help_text)
        self.assertIn("--paste-token", help_text)
        self._force_enforced_temp_server()
        with mock.patch.object(
                c.getpass, "getpass",
                side_effect=AssertionError("device flow must not ask password")):
            with self.assertRaisesRegex(
                    c.AuthenticationError, "terminal_enrollment_pending"):
                c.ensure_remote_setup_auth(
                    self.url, "codex", interactive=False,
                    login_username="ignored-legacy-name")


if __name__ == "__main__":
    unittest.main()
