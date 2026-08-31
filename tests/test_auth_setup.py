"""Hosted setup authentication and client-install credential isolation tests.

Every HTTP server binds to loopback port 0 and every credential/database path
lives in a TemporaryDirectory. Nothing in this module discovers or contacts
an installed/live Attacca server.
"""

import http.client
import http.cookies
import importlib.util
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import terminal_flow  # noqa: E402


SPEC = importlib.util.spec_from_file_location(
    "attacca_auth_setup_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class ClientCredentialIsolationTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.credentials = self.root / "credentials.json"
        self.instances = self.root / "client-instances"

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def credential(token, instance, projects=None, username="alice"):
        return {
            "token": token,
            "token_kind": "client",
            "token_id": "key_" + instance,
            "client_instance": instance,
            "username": username,
            "project_memberships": list(projects or []),
            "scope_mode": ("selected_workspaces" if projects
                           else "account_memberships"),
        }

    def test_full_server_url_and_client_install_are_independent_boundaries(self):
        tenant_a = "https://attacca.example/tenant-a"
        tenant_b = "https://attacca.example/tenant-b"
        home = "client-home"
        office = "client-office"
        home_a = "atkey_key_home-a.home-a-secret"
        office_a = "atkey_key_office-a.office-a-secret"
        home_b = "atkey_key_home-b.home-b-secret"

        terminal_flow.save_client_api_key(
            tenant_a, self.credential(home_a, home, ["alpha"]),
            client_instance=home, credentials_path=self.credentials)
        terminal_flow.save_client_api_key(
            tenant_a, self.credential(office_a, office, ["alpha", "beta"]),
            client_instance=office, credentials_path=self.credentials)
        terminal_flow.save_client_api_key(
            tenant_b, self.credential(home_b, home, ["alpha"]),
            client_instance=home, credentials_path=self.credentials)

        self.assertEqual(
            stat.S_IMODE(self.credentials.stat().st_mode), 0o600)
        self.assertEqual(terminal_flow.load_client_api_key(
            tenant_a, client_instance=home, project_id="alpha",
            credentials_path=self.credentials), home_a)
        self.assertEqual(terminal_flow.load_client_api_key(
            tenant_a, client_instance=office, project_id="beta",
            credentials_path=self.credentials), office_a)
        self.assertEqual(terminal_flow.load_client_api_key(
            tenant_b, client_instance=home, project_id="alpha",
            credentials_path=self.credentials), home_b)
        self.assertIsNone(terminal_flow.load_client_api_key(
            tenant_a, client_instance=home, project_id="beta",
            credentials_path=self.credentials))

        # Exact actors are request selectors, never key-store dimensions.
        headers = terminal_flow.client_request_headers(
            tenant_a, client_instance=home, project_id="alpha",
            actor_id="alpha.director.claude",
            credentials_path=self.credentials)
        self.assertEqual(headers["X-Attacca-Actor"],
                         "alpha.director.claude")
        self.assertEqual(headers["X-Attacca-Client-Instance"], home)
        self.assertEqual(headers["Authorization"], "Bearer " + home_a)

        serialized = json.loads(self.credentials.read_text())
        record = serialized["servers"][
            terminal_flow.canonical_server_url(tenant_a)]
        self.assertNotIn("actor_bindings", record)
        self.assertNotIn("runtime", record["client_api_keys"][home])

    def test_stable_instance_ids_are_private_and_runtime_install_specific(self):
        codex_path = self.instances / "codex.json"
        claude_path = self.instances / "claude.json"
        codex_first = terminal_flow.load_client_instance_id(
            codex_path, runtime="codex")
        codex_second = terminal_flow.load_client_instance_id(
            codex_path, runtime="codex")
        claude = terminal_flow.load_client_instance_id(
            claude_path, runtime="claude")
        self.assertEqual(codex_first, codex_second)
        self.assertNotEqual(codex_first, claude)
        self.assertTrue(codex_first.startswith("client_"))
        self.assertEqual(stat.S_IMODE(codex_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(claude_path.stat().st_mode), 0o600)

    def test_retired_credentials_are_detected_but_never_loaded_as_client_keys(self):
        server = terminal_flow.canonical_server_url(
            "http://legacy.example:4173")
        self.credentials.write_text(json.dumps({
            "version": 1,
            "servers": {server: {
                "terminal_credential": {"token": "atd_retired.secret"},
                "agent_tokens": {"alpha": {
                    "alpha.director.codex": {"token": "ats_retired"},
                }},
            }},
        }))
        os.chmod(self.credentials, 0o600)
        status = terminal_flow.client_api_key_status(
            server, client_instance="client-new",
            credentials_path=self.credentials)
        self.assertEqual(status["status"], "authorization_required")
        self.assertTrue(status["legacy_credential_present"])
        self.assertIsNone(terminal_flow.load_client_api_key(
            server, client_instance="client-new",
            credentials_path=self.credentials))


class SetupClientAuthorizationTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "setup-auth.db"
        self.credentials = self.root / "credentials.json"
        self.identity = self.root / "identity.json"
        self.client_instance = "client-setup-test"
        self.device_id = "device-setup-test"

        conn = c.connect(self.db)
        try:
            c.auth_create_user(
                conn, "alice", "correct-horse", "Alice", is_admin=True,
                bootstrap=True)
            user = conn.execute(
                "SELECT * FROM auth_users WHERE username='alice'").fetchone()
            principal = c._auth_principal(
                conn, user, "session", session_hash="fixture")
            c.set_current_owner("alice")
            c.project_init(
                conn, "web.alice", "human", path=self.root / "checkout",
                project_id="alpha", name="Alpha")
            c.auth_grant_project_membership(
                conn, principal, "alpha", granted_by="alice")
            for actor, runtime in (
                    ("alpha.director.codex", "codex"),
                    ("alpha.director.claude", "claude")):
                c.agent_register(
                    conn, "alpha", "web.alice", "human", agent_id=actor,
                    role="director", runtime=runtime,
                    registration_username="alice")
        finally:
            c.set_current_owner(None)
            conn.close()

        self.server = c.AttaccaServer(
            ("127.0.0.1", 0), self.db, auth=True, auth_mode="auto")
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.url = "http://%s:%d" % (host, port)
        self.patchers = [
            mock.patch.object(c, "CREDENTIALS_FILE", self.credentials),
            mock.patch.object(c, "IDENTITY_FILE", self.identity),
            mock.patch.object(c, "find_project_link", return_value=None),
            mock.patch.object(c, "load_client_instance_id",
                              return_value=self.client_instance),
            mock.patch.object(c, "load_device_id",
                              return_value=self.device_id),
        ]
        for patcher in self.patchers:
            patcher.start()
        self.token = self._create_client_key()
        self._activate()

    def tearDown(self):
        c._remote_setup_auth.context = None
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive())
        self.tmp.cleanup()

    def _request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(
            self.server.server_address[0], self.server.server_address[1],
            timeout=5)
        payload = json.dumps(body).encode() if body is not None else None
        merged = {"Accept": "application/json", **(headers or {})}
        if payload is not None:
            merged["Content-Type"] = "application/json"
        connection.request(method, path, body=payload, headers=merged)
        response = connection.getresponse()
        raw = response.read()
        result = {"status": response.status, "headers": response.headers,
                  "body": json.loads(raw) if raw else {}}
        connection.close()
        return result

    @staticmethod
    def _session_headers(response):
        cookies = {}
        for line in response["headers"].get_all("Set-Cookie") or []:
            parsed = http.cookies.SimpleCookie()
            parsed.load(line)
            cookies.update({name: value.value
                            for name, value in parsed.items()})
        return {
            "Cookie": "; ".join("%s=%s" % item for item in cookies.items()),
            "X-Attacca-CSRF": cookies["attacca_csrf"],
        }

    def _create_client_key(self):
        login = self._request("POST", "/v1/auth/login", {
            "username": "alice", "password": "correct-horse"})
        self.assertEqual(login["status"], 200, login["body"])
        self.browser = self._session_headers(login)
        created = self._request("POST", "/v1/auth/client-keys", {
            "label": "Setup test client",
            "client_instance": self.client_instance,
            "device_id": self.device_id,
            "project_memberships": ["alpha"],
        }, self.browser)
        self.assertEqual(created["status"], 201, created["body"])
        self.token_id = created["body"]["record"]["token_id"]
        return created["body"]["token"]

    def _activate(self):
        activated = self._request("POST", "/v1/auth/activation", {
            "enabled": True, "confirmed": True,
        }, self.browser)
        self.assertEqual(activated["status"], 200, activated["body"])

    def test_environment_key_hot_loads_without_rewriting_actor_or_storage(self):
        conn = c.connect(self.db)
        try:
            before = [tuple(row) for row in conn.execute(
                "SELECT * FROM agents ORDER BY agent_id")]
        finally:
            conn.close()

        with mock.patch.dict(os.environ, {
                c.ENV_API_TOKEN: self.token,
                c.ENV_CLIENT_INSTANCE: self.client_instance,
        }, clear=False):
            first = c.ensure_remote_setup_auth(
                self.url, "alpha.director.codex", interactive=False)
            self.assertTrue(first["authenticated"])
            self.assertEqual(first["token_kind"], "client")
            self.assertEqual(first["credential_source"], "environment")
            self.assertFalse(self.credentials.exists())

            verified = c.provision_setup_agent_token(
                self.url, "alpha", "alpha.director.codex")
            self.assertEqual(verified["credential_kind"], "client")
            self.assertEqual(verified["status"], "ready")
            self.assertEqual(verified["credential_source"], "active_process")

            # The same key selects another exact actor owned by the same human.
            c._remote_setup_auth.context = None
            second = c.ensure_remote_setup_auth(
                self.url, "alpha.director.claude", interactive=False)
            self.assertTrue(second["authenticated"])
            selected = c.remote_json(
                self.url, "GET", "/v1/projects/alpha/status",
                actor="alpha.director.claude", actor_type="agent",
                project_id="alpha")
            self.assertEqual(selected["project"], "alpha")

        conn = c.connect(self.db)
        try:
            after = [tuple(row) for row in conn.execute(
                "SELECT * FROM agents ORDER BY agent_id")]
            self.assertEqual(after, before)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM auth_token_actor_bindings"
                " WHERE token_id=?", (self.token_id,)).fetchone()["n"], 0)
        finally:
            conn.close()

    def test_private_key_survives_fresh_process_and_hot_loads_without_browser(self):
        saved = terminal_flow.save_client_api_key(
            self.url, {
                "token": self.token,
                "token_id": self.token_id,
                "client_instance": self.client_instance,
                "username": "alice",
                "project_memberships": ["alpha"],
                "device_id": self.device_id,
            }, client_instance=self.client_instance,
            credentials_path=self.credentials)
        self.assertTrue(saved["authorized"])
        self.assertEqual(stat.S_IMODE(self.credentials.stat().st_mode), 0o600)

        c._remote_setup_auth.context = None
        runtime_flow = c._terminal_flow_runtime()
        with mock.patch.dict(os.environ, {c.ENV_API_TOKEN: ""}, clear=False), \
                mock.patch.object(runtime_flow, "authorize_client",
                                  side_effect=AssertionError(
                                      "stored key must not reopen browser")):
            os.environ.pop(c.ENV_API_TOKEN, None)
            result = c.ensure_remote_setup_auth(
                self.url, "alpha.director.codex", interactive=False)
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["kind"], "client_api_key")
        self.assertEqual(result["credentials_file"], str(self.credentials))

    def test_missing_key_requests_integrated_browser_hidden_tty_authorization(self):
        self.credentials.unlink(missing_ok=True)
        c._remote_setup_auth.context = None
        required = {
            "status": "authorization_required", "authorized": False,
            "authorization_url": self.url + "/app#settings",
            "client_instance": self.client_instance, "hot_reload": True,
        }
        runtime_flow = c._terminal_flow_runtime()
        with mock.patch.dict(os.environ, {c.ENV_API_TOKEN: ""}, clear=False), \
                mock.patch.object(
                    runtime_flow, "authorize_client", return_value=required
                ) as authorize, \
                mock.patch.object(
                    c.getpass, "getpass",
                    side_effect=AssertionError(
                        "setup must not ask for an account password")):
            os.environ.pop(c.ENV_API_TOKEN, None)
            with self.assertRaisesRegex(
                    c.AuthenticationError, "client_authorization_required"):
                c.ensure_remote_setup_auth(
                    self.url, "alpha.director.codex", interactive=True)
        authorize.assert_called_once()
        kwargs = authorize.call_args.kwargs
        self.assertTrue(kwargs["open_browser"])
        self.assertTrue(kwargs["prompt"])
        self.assertEqual(kwargs["client_instance"], self.client_instance)

    def test_setup_parser_has_no_plaintext_secret_argument(self):
        parser = c.build_parser()
        setup_parser = parser._subparsers._group_actions[0].choices["setup"]
        help_text = setup_parser.format_help().lower()
        self.assertNotIn("--api-token", help_text)
        self.assertNotIn("--password", help_text)
        self.assertNotIn("--paste-token", help_text)
        paste = next(action for action in setup_parser._actions
                     if action.dest == "paste_token")
        self.assertEqual(paste.nargs, 0)
        parsed = parser.parse_args(["setup", "--paste-token"])
        self.assertIs(parsed.paste_token, True)


if __name__ == "__main__":
    unittest.main()
