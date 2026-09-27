"""Owner-controlled login transitions, including historical explicit opt-outs.

All databases and listeners are disposable fixtures. No installed configuration,
browser, credentials or shared Attacca service is used by these tests.
"""

import http.client
import http.cookies
import importlib.util
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("attacca_login_toggle", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class LoginPolicyHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="attacca-login-history-")
        self.addCleanup(self.temp.cleanup)
        self.conn = c.connect(Path(self.temp.name) / "history.sqlite")
        self.addCleanup(self.conn.close)

    def policy(self, values):
        self.conn.execute("DELETE FROM server_settings")
        c.server_settings_store(self.conn, values)
        return c.server_access_mode(self.conn)

    def test_explicit_historical_owner_disable_overrides_old_setup_mode(self):
        for old_mode in (None, "legacy", "protected"):
            settings = {"auth.activated": False,
                        "auth.deactivated_by": "operator",
                        "auth.deactivated_at": "2026-09-01T00:00:00.000Z"}
            if old_mode is not None:
                settings["server.setup_mode"] = old_mode
            with self.subTest(old_mode=old_mode):
                self.assertEqual(self.policy(settings), "local")

    def test_missing_activation_is_not_an_owner_choice_to_disable_login(self):
        for mode in (None, "legacy", "protected", "pending", "local"):
            for activated in (None, False):
                values = {}
                if mode is not None:
                    values["server.setup_mode"] = mode
                if activated is not None:
                    values["auth.activated"] = activated
                with self.subTest(mode=mode, activated=activated):
                    self.assertEqual(self.policy(values), mode or "legacy")

    def test_partial_or_null_historical_optout_does_not_open_console(self):
        for values in ({"auth.deactivated_by": "operator"},
                       {"auth.deactivated_at": "2026-09-01T00:00:00.000Z"},
                       {"auth.deactivated_by": None, "auth.deactivated_at": None}):
            with self.subTest(values=values):
                self.assertEqual(self.policy({"server.setup_mode": "protected",
                                              "auth.activated": False,
                                              **values}), "protected")

    def test_enabled_activation_wins_over_stale_disable_metadata(self):
        self.assertEqual(self.policy({
            "server.setup_mode": "local", "auth.activated": True,
            "auth.deactivated_by": "operator",
            "auth.deactivated_at": "2026-09-01T00:00:00.000Z"}), "protected")


class LoginToggleHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="attacca-login-toggle-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "server.sqlite"
        self.server = None
        self.addCleanup(self.stop_server)
        self.start_server()
        response = self.request("POST", "/v1/setup", {
            "mode": "protected", "confirmed": True,
            "username": "operator", "password": "test-operator-password"})
        self.assertEqual(response["status"], 201, response["body"])
        self.owner = self.session_headers(response)

    def start_server(self, bind="127.0.0.1", auth_mode="auto"):
        self.server = c.AttaccaServer((bind, 0), self.db, auth_mode=auth_mode)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def stop_server(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
            self.server = None

    def restart_server(self, **kwargs):
        self.stop_server()
        self.start_server(**kwargs)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        outgoing = {"Accept": "application/json", **(headers or {})}
        if body is not None:
            outgoing["Content-Type"] = "application/json"
        try:
            connection.request(method, path, json.dumps(body) if body is not None else None,
                               outgoing)
            response = connection.getresponse()
            raw = response.read()
            return {"status": response.status, "headers": response.headers,
                    "body": json.loads(raw) if "application/json" in
                    response.getheader("Content-Type", "") else raw.decode("utf-8")}
        finally:
            connection.close()

    @staticmethod
    def session_headers(response):
        cookies = http.cookies.SimpleCookie()
        for header in response["headers"].get_all("Set-Cookie") or []:
            cookies.load(header)
        return {"Cookie": "; ".join("%s=%s" % (name, item.value)
                                    for name, item in cookies.items()),
                "X-Attacca-CSRF": cookies["attacca_csrf"].value}

    def status(self):
        response = self.request("GET", "/v1/auth/status")
        self.assertEqual(response["status"], 200, response["body"])
        return response["body"]

    def toggle(self, enabled, headers=None, **extra):
        return self.request("POST", "/v1/auth/activation",
                            {"enabled": enabled, "confirmed": True, **extra},
                            self.owner if headers is None else headers)

    def disable(self):
        response = self.toggle(False)
        self.assertEqual(response["status"], 200, response["body"])
        self.assertFalse(response["body"]["activated"])
        self.assertEqual(self.status()["access_mode"], "local")

    def seed_key_and_identity(self):
        conn = c.connect(self.db)
        try:
            c.set_current_owner("operator")
            c.project_init(conn, "web.operator", "human", path=self.root / "checkout",
                           project_id="example", name="Example")
            c.agent_register(conn, "example", "web.operator", "human",
                             agent_id="example.director.codex", role="director",
                             runtime="codex", registration_username="operator")
            row = conn.execute("SELECT * FROM auth_users WHERE username='operator'").fetchone()
            principal = c._auth_principal(conn, row, "session")
            key = c.auth_client_key_create(conn, principal, "Example client",
                                           "toggle-test-client", memberships=["example"])
            key["user_id"] = row["user_id"]
            key["password_hash"] = row["password_hash"]
            return key
        finally:
            c.set_current_owner(None)
            conn.close()

    def test_disable_opens_console_and_api_then_owner_can_reenable(self):
        self.assertEqual(self.request("GET", "/v1/projects")["status"], 401)
        self.disable()
        status = self.status()
        self.assertTrue(status["anonymous_access"])
        self.assertFalse(status["authentication_required"])
        self.assertFalse(status["authenticated"])
        self.assertFalse(status["setup_required"])
        self.assertFalse(status["bootstrap_required"])
        self.assertTrue(status["bootstrapped"])
        for path in ("/", "/app", "/v1/projects", "/v1/settings"):
            with self.subTest(path=path):
                response = self.request("GET", path)
                self.assertEqual(response["status"], 200, response["body"])
        enabled = self.toggle(True)
        self.assertEqual(enabled["status"], 200, enabled["body"])
        self.assertTrue(self.status()["authentication_required"])
        self.assertFalse(self.status()["anonymous_access"])
        self.assertEqual(self.status()["access_mode"], "protected")
        self.assertEqual(self.request("GET", "/v1/projects")["status"], 401)
        self.assertEqual(self.request("GET", "/v1/projects", headers=self.owner)["status"], 200)

    def test_accounts_passwords_keys_and_exact_agent_identity_survive_both_transitions(self):
        key = self.seed_key_and_identity()
        headers = {"Authorization": "Bearer " + key["token"],
                   c.CLIENT_INSTANCE_HEADER: "toggle-test-client",
                   "X-Attacca-Actor": "example.director.codex"}
        for enabled in (False, True):
            result = self.toggle(enabled)
            self.assertEqual(result["status"], 200, result["body"])
            response = self.request("GET", "/v1/projects/example/status", headers=headers)
            self.assertEqual(response["status"], 200, response["body"])
            conn = c.connect(self.db)
            try:
                row = conn.execute("SELECT * FROM auth_users WHERE username='operator'").fetchone()
                self.assertEqual(row["user_id"], key["user_id"])
                self.assertEqual(row["password_hash"], key["password_hash"])
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM auth_users").fetchone()[0], 1)
                token = c.auth_token_principal(conn, key["token"])
                self.assertEqual(token["user_id"], key["user_id"])
                scope = c.auth_client_principal_scope(conn, token, "example", "example.director.codex")
                self.assertEqual(scope["actor_id"], "example.director.codex")
                self.assertEqual(scope["role"], "director")
                self.assertEqual(c._auth_setting(conn, "server.setup_mode"),
                                 "protected" if enabled else "local")
            finally:
                conn.close()

    def test_choice_survives_real_server_recreation_in_both_directions(self):
        self.disable()
        self.restart_server()
        self.assertEqual(self.status()["access_mode"], "local")
        self.assertTrue(self.status()["anonymous_access"])
        self.assertEqual(self.request("GET", "/v1/projects")["status"], 200)
        result = self.toggle(True)
        self.assertEqual(result["status"], 200, result["body"])
        self.restart_server()
        self.assertEqual(self.status()["access_mode"], "protected")
        self.assertFalse(self.status()["anonymous_access"])
        self.assertEqual(self.request("GET", "/v1/projects")["status"], 401)

    def test_historical_explicit_disable_is_honored_after_restart_without_new_toggle(self):
        conn = c.connect(self.db)
        try:
            # Simulate the old release's owner-confirmed operation: enforcement
            # was disabled but the separate setup mode was left protected.
            c.server_settings_store(conn, {
                "server.setup_mode": "protected", "auth.activated": False,
                "auth.deactivated_by": "operator",
                "auth.deactivated_at": "2026-09-01T00:00:00.000Z"})
        finally:
            conn.close()
        self.restart_server()
        status = self.status()
        self.assertEqual(status["access_mode"], "local")
        self.assertTrue(status["anonymous_access"])
        self.assertFalse(status["setup_required"])
        self.assertTrue(status["bootstrapped"])
        self.assertEqual(self.request("GET", "/v1/projects")["status"], 200)

    def test_malformed_toggle_or_missing_confirmation_leaves_policy_unchanged(self):
        for enabled in (None, 0, 1, "false", "true", []):
            with self.subTest(enabled=enabled):
                response = self.toggle(enabled)
                self.assertEqual(response["status"], 400, response["body"])
                self.assertTrue(self.status()["authentication_required"])
        for confirmed in (None, False, 1, "true"):
            with self.subTest(confirmed=confirmed):
                response = self.toggle(False, confirmed=confirmed)
                self.assertEqual(response["status"], 400, response["body"])
                self.assertTrue(self.status()["authentication_required"])

    def test_failure_mid_toggle_rolls_back_both_policy_and_authentication_settings(self):
        conn = c.connect(self.db)
        try:
            row = conn.execute("SELECT * FROM auth_users WHERE username='operator'").fetchone()
            principal = c._auth_principal(conn, row, "session")
            before = [tuple(row) for row in conn.execute(
                "SELECT setting_key,value,updated_at FROM server_settings ORDER BY setting_key")]
            # Abort the final setting after the earlier policy/activation writes
            # have executed; a separate non-transactional mode write would leak.
            conn.execute("CREATE TEMP TRIGGER fail_login_toggle BEFORE UPDATE ON server_settings "
                         "WHEN NEW.setting_key='auth.deactivated_at' BEGIN "
                         "SELECT RAISE(ABORT, 'test login toggle write failure'); END")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "test login toggle write failure"):
                c.auth_activate(conn, principal, confirmed=True, server=self.server, enabled=False)
            after = [tuple(row) for row in conn.execute(
                "SELECT setting_key,value,updated_at FROM server_settings ORDER BY setting_key")]
            self.assertEqual(after, before)
            self.assertEqual(c.server_access_mode(conn), "protected")
            self.assertIs(c._auth_setting(conn, "auth.activated"), True)
            conn.execute("DROP TRIGGER fail_login_toggle")
        finally:
            conn.close()
        self.assertTrue(self.status()["authentication_required"])
        self.assertEqual(self.request("GET", "/v1/projects")["status"], 401)
        self.disable()

    def test_anonymous_cannot_toggle_policy_even_after_login_disabled(self):
        for enabled in (False, True):
            response = self.toggle(enabled, headers={})
            self.assertEqual(response["status"], 401, response["body"])
        self.disable()
        for enabled in (False, True):
            response = self.toggle(enabled, headers={})
            self.assertEqual(response["status"], 401, response["body"])
        self.assertTrue(self.status()["anonymous_access"])

    def test_owner_session_csrf_stays_required_with_or_without_login(self):
        for current_enabled in (True, False):
            for bad_csrf in (None, "incorrect-csrf-token"):
                headers = {"Cookie": self.owner["Cookie"]}
                if bad_csrf is not None:
                    headers["X-Attacca-CSRF"] = bad_csrf
                response = self.toggle(not current_enabled, headers=headers)
                self.assertEqual(response["status"], 403, response["body"])
                self.assertIn("CSRF", response["body"]["error"])
                self.assertEqual(self.status()["authentication_required"], current_enabled)
            if current_enabled:
                self.disable()

    def test_nonowner_administrator_cannot_disable_login(self):
        conn = c.connect(self.db)
        try:
            c.auth_create_user(conn, "other-admin", "test-other-password", is_admin=True)
        finally:
            conn.close()
        response = self.request("POST", "/v1/auth/login", {
            "username": "other-admin", "password": "test-other-password"})
        self.assertEqual(response["status"], 200, response["body"])
        result = self.toggle(False, headers=self.session_headers(response))
        self.assertEqual(result["status"], 403, result["body"])
        self.assertIn("server_owner_required", result["body"]["error"])
        self.assertTrue(self.status()["authentication_required"])

    def test_client_key_cannot_toggle_even_when_owned_by_server_owner(self):
        key = self.seed_key_and_identity()
        headers = {"Authorization": "Bearer " + key["token"],
                   c.CLIENT_INSTANCE_HEADER: "toggle-test-client"}
        response = self.toggle(False, headers=headers)
        self.assertEqual(response["status"], 403, response["body"])
        self.assertIn("client_key_route_denied", response["body"]["error"])
        self.assertTrue(self.status()["authentication_required"])

    def test_network_exposed_disable_requires_explicit_risk_acknowledgement(self):
        self.restart_server(bind="0.0.0.0")
        self.assertTrue(self.status()["network_exposed"])
        for acknowledgement in (None, False, "true", 1):
            extra = {} if acknowledgement is None else {"acknowledge_network_risk": acknowledgement}
            response = self.toggle(False, **extra)
            self.assertEqual(response["status"], 400, response["body"])
            self.assertIn("network_exposure_confirmation_required", response["body"]["error"])
            self.assertTrue(self.status()["authentication_required"])
        response = self.toggle(False, acknowledge_network_risk=True)
        self.assertEqual(response["status"], 200, response["body"])
        self.assertTrue(self.status()["anonymous_access"])

    def test_login_free_console_keeps_host_origin_and_fetch_site_guards(self):
        self.disable()
        for headers in ({"Host": "malicious.example:%d" % self.port},
                        {"Origin": "http://malicious.example"},
                        {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(headers=headers):
                response = self.request("GET", "/v1/projects", headers=headers)
                self.assertEqual(response["status"], 403, response["body"])
                self.assertIn("local_access_denied", response["body"]["error"])
        self.assertEqual(self.request("GET", "/v1/projects")["status"], 200)

    def test_login_disabled_does_not_accept_invalid_or_revoked_bearer(self):
        key = self.seed_key_and_identity()
        conn = c.connect(self.db)
        try:
            conn.execute("UPDATE auth_tokens SET revoked_at=? WHERE token_id=?",
                         (c.now_iso(), key["record"]["token_id"]))
        finally:
            conn.close()
        self.disable()
        for token in (key["token"], "atkey_invalid", "atpair_invalid", "atsvc_invalid"):
            with self.subTest(token_kind=token.split("_")[0]):
                response = self.request("GET", "/v1/projects", headers={
                    "Authorization": "Bearer " + token,
                    c.CLIENT_INSTANCE_HEADER: "toggle-test-client"})
                self.assertEqual(response["status"], 401, response["body"])
                self.assertIn("invalid_credential", response["body"]["error"])

    def test_logout_does_not_reintroduce_login_gate_and_owner_can_sign_in_optionally(self):
        self.disable()
        logout = self.request("POST", "/v1/auth/logout", {}, self.owner)
        self.assertEqual(logout["status"], 200, logout["body"])
        self.assertTrue(self.status()["anonymous_access"])
        self.assertEqual(self.request("GET", "/v1/projects")["status"], 200)
        login = self.request("POST", "/v1/auth/login", {
            "username": "operator", "password": "test-operator-password"})
        self.assertEqual(login["status"], 200, login["body"])
        self.assertTrue(login["body"]["authenticated"])
        self.assertTrue(login["body"]["anonymous_access"])
        owner_session = self.session_headers(login)
        signed_in = self.request("GET", "/v1/auth/status", headers=owner_session)
        self.assertTrue(signed_in["body"]["user"]["is_owner"])
        enabled = self.toggle(True, headers=owner_session)
        self.assertEqual(enabled["status"], 200, enabled["body"])
        self.assertEqual(self.request("GET", "/v1/projects")["status"], 401)

    def test_compatibility_override_cannot_claim_login_was_enabled(self):
        self.disable()
        self.restart_server(auth_mode="compatibility")
        response = self.toggle(True)
        self.assertEqual(response["status"], 400, response["body"])
        self.assertIn("auth-mode auto", response["body"]["error"])
        self.assertEqual(self.status()["access_mode"], "local")
        self.assertTrue(self.status()["anonymous_access"])


if __name__ == "__main__":
    unittest.main()
