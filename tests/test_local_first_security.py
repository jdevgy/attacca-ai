"""Independent adversarial coverage for login-free and first-run boundaries."""

import email.message
import http.client
import http.cookies
import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("attacca_local_access_security", ROOT / "local_access.py")
local = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(local)

CORE_SPEC = importlib.util.spec_from_file_location("attacca_local_first_security_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(CORE_SPEC)
CORE_SPEC.loader.exec_module(c)


class LocalBoundaryUnitTests(unittest.TestCase):
    def handler(self, headers=None, peer="127.0.0.1", destination="127.0.0.1", method="GET"):
        message = email.message.Message()
        for name, value in (headers if headers is not None else [("Host", "127.0.0.1:9876")]):
            message[name] = value
        return SimpleNamespace(headers=message, client_address=(peer, 55555),
                               command=method, connection=SimpleNamespace(
                                   getsockname=lambda: (destination, 9876)))

    def test_native_local_client_without_origin_is_permitted(self):
        local.validate_request(self.handler())

    def test_same_origin_browser_json_write_is_permitted(self):
        handler = self.handler([("Host", "localhost:9876"), ("Origin", "http://localhost:9876"),
                                ("Sec-Fetch-Site", "same-origin"),
                                ("Content-Type", "application/json; charset=utf-8")], method="POST")
        local.validate_request(handler, require_loopback=True)

    def test_same_site_foreign_origin_still_fails(self):
        handler = self.handler([("Host", "localhost:9876"), ("Origin", "http://evil.localhost:9876"),
                                ("Sec-Fetch-Site", "same-site")])
        with self.assertRaises(local.LocalAccessError):
            local.validate_request(handler)

    def test_dns_rebinding_and_malformed_hosts_fail(self):
        for host in ("attacker.example:9876", "localhost.attacker:9876", "127.0.0.1:9877",
                     "127.0.0.1", "127.0.0.1:", "user@127.0.0.1:9876", "127.0.0.1:9876/",
                     "127.0.0.1:9876#x", "127.0.0.1:9876?x", "127.0.0.1:9876,evil", "127.0.0.1:9876 ",
                     "127.0.0.1:9876\\evil", "127.0.0.2:9876", "127.0.0.1:0", "[::1]:9876"):
            with self.subTest(host=host), self.assertRaises(local.LocalAccessError):
                local.validate_request(self.handler([("Host", host)]))

    def test_missing_or_duplicate_host_fails(self):
        for headers in ([], [("Host", "127.0.0.1:9876"), ("Host", "127.0.0.1:9876")]):
            with self.subTest(headers=headers), self.assertRaises(local.LocalAccessError):
                local.validate_request(self.handler(headers))

    def test_origin_must_match_exact_http_authority(self):
        for origin in ("null", "https://127.0.0.1:9876", "http://evil.example", "http://127.0.0.1:9877",
                       "http://127.0.0.1", "http://localhost:9876", "http://u@127.0.0.1:9876",
                       "http://127.0.0.1:9876/", "http://127.0.0.1:9876?x", "http://127.0.0.1:9876#x"):
            with self.subTest(origin=origin), self.assertRaises(local.LocalAccessError):
                local.validate_request(self.handler([("Host", "127.0.0.1:9876"), ("Origin", origin)]))

    def test_duplicate_origin_fails(self):
        with self.assertRaises(local.LocalAccessError):
            local.validate_request(self.handler([("Host", "127.0.0.1:9876"),
                                                 ("Origin", "http://127.0.0.1:9876"),
                                                 ("Origin", "http://127.0.0.1:9876")]))

    def test_cross_site_read_and_write_fail(self):
        for method in ("GET", "POST"):
            with self.subTest(method=method), self.assertRaises(local.LocalAccessError):
                local.validate_request(self.handler([("Host", "127.0.0.1:9876"),
                                                     ("Sec-Fetch-Site", "cross-site"),
                                                     ("Content-Type", "application/json")], method=method))

    def test_form_and_text_plain_writes_fail_even_without_origin(self):
        for content_type in (None, "text/plain", "application/x-www-form-urlencoded", "multipart/form-data"):
            headers = [("Host", "127.0.0.1:9876")]
            if content_type:
                headers.append(("Content-Type", content_type))
            with self.subTest(content_type=content_type), self.assertRaises(local.LocalAccessError):
                local.validate_request(self.handler(headers, method="POST"))

    def test_forwarded_headers_never_grant_setup_authority(self):
        handler = self.handler([("Host", "127.0.0.1:9876"), ("Forwarded", "for=127.0.0.1;host=localhost"),
                                ("X-Forwarded-For", "127.0.0.1"), ("X-Real-IP", "127.0.0.1"),
                                ("Content-Type", "application/json")], peer="192.0.2.5", method="POST")
        self.assertFalse(local.setup_allowed(handler))
        with self.assertRaisesRegex(local.LocalAccessError, "local_setup_only"):
            local.validate_request(handler, require_loopback=True)

    def test_forwarded_host_does_not_replace_actual_destination(self):
        handler = self.handler([("Host", "public.example:9876"), ("X-Forwarded-Host", "localhost:9876")])
        with self.assertRaises(local.LocalAccessError):
            local.validate_request(handler)

    def test_nonloopback_destination_requires_actual_ip_not_localhost(self):
        local.validate_request(self.handler([("Host", "192.0.2.10:9876")], destination="192.0.2.10"))
        with self.assertRaises(local.LocalAccessError):
            local.validate_request(self.handler([("Host", "localhost:9876")], destination="192.0.2.10"))

    def test_ipv6_loopback_and_mapped_ipv4_work(self):
        for destination, peer, host in (("::1", "::1", "[::1]:9876"),
                                         ("::ffff:127.0.0.1", "::ffff:127.0.0.1", "127.0.0.1:9876")):
            with self.subTest(destination=destination):
                local.validate_request(self.handler([("Host", host)], destination=destination, peer=peer),
                                       require_loopback=True)

    def test_ipv6_authority_cannot_hide_text_after_closing_bracket(self):
        with self.assertRaises(local.LocalAccessError):
            local.validate_request(self.handler([("Host", "[::1]attacker:9876")], destination="::1", peer="::1"))

    def test_bind_is_not_inferred_from_hostname_or_forwarding(self):
        for address in ("0.0.0.0", "::", "192.0.2.1", "localhost", "unknown"):
            self.assertTrue(local.network_exposed((address, 9876)))
        for address in ("127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1"):
            self.assertFalse(local.network_exposed((address, 9876)))


class LocalFirstHttpSecurityTests(unittest.TestCase):
    """Only temporary databases and ephemeral sockets; never installed state."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "security.db"
        self.start_server()

    def start_server(self, bind="127.0.0.1"):
        self.server = c.AttaccaServer((bind, 0), self.db)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def tearDown(self):
        self.stop_server()
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        request_headers = dict(headers or {})
        payload = json.dumps(body).encode() if body is not None else None
        if payload is not None:
            request_headers.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=payload, headers=request_headers)
        response = conn.getresponse()
        raw = response.read()
        data = json.loads(raw) if "json" in (response.getheader("Content-Type") or "") else raw
        result = response.status, data, response.headers
        conn.close()
        return result

    def choose(self, mode="local", **extra):
        return self.request("POST", "/v1/setup", {"mode": mode, "confirmed": True, **extra})

    def assert_accounts(self, expected):
        conn = c.connect(self.db)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM auth_users").fetchone()[0], expected)
        finally:
            conn.close()

    def seed_project(self):
        response = self.request("POST", "/v1/projects", {"project_id": "example", "name": "Example"},
                                {"X-Attacca-Actor": "web.local", "X-Attacca-Actor-Type": "human"})
        self.assertEqual(response[0], 200, response[1])

    def test_local_selection_is_persistent_and_not_authenticated(self):
        before = self.request("GET", "/v1/auth/status")[1]
        self.assertTrue(before["setup_required"])
        self.assertFalse(before["anonymous_access"])
        code, local_state, _ = self.choose()
        self.assertEqual(code, 200, local_state)
        self.assertEqual(local_state["access_mode"], "local")
        self.assertTrue(local_state["anonymous_access"])
        self.assertFalse(local_state["authenticated"])
        self.assertIsNone(local_state["user"])
        self.assertIsNone(local_state["principal"])
        self.assertFalse(local_state["bootstrap_required"])
        self.assert_accounts(0)
        self.stop_server()
        self.start_server()
        after = self.request("GET", "/v1/auth/status")[1]
        self.assertEqual(after["access_mode"], "local")
        self.assertTrue(after["anonymous_access"])
        self.assertFalse(after["setup_required"])

    def test_invalid_protected_choice_leaves_no_owner_or_selection(self):
        for body in ({"mode": "protected", "confirmed": True, "username": "owner", "password": "x"},
                     {"mode": "protected", "confirmed": True, "username": "", "password": "long-enough-password"},
                     {"mode": "protected", "confirmed": False, "username": "owner", "password": "long-enough-password"}):
            with self.subTest(body={k: v for k, v in body.items() if k != "password"}):
                self.assertEqual(self.request("POST", "/v1/setup", body)[0], 400)
                self.assert_accounts(0)
                self.assertEqual(self.request("GET", "/v1/auth/status")[1]["access_mode"], "pending")

    def test_protected_choice_atomically_enforces_login_and_cannot_be_downgraded(self):
        code, state, _ = self.choose("protected", username="owner", password="long-enough-password")
        self.assertEqual(code, 201, state)
        self.assertTrue(state["authenticated"])
        self.assertTrue(state["authentication_required"])
        self.assertFalse(state["anonymous_access"])
        self.assertEqual(state["access_mode"], "protected")
        self.assertEqual(self.request("GET", "/v1/projects")[0], 401)
        self.assertEqual(self.choose()[0], 403)
        self.stop_server()
        self.start_server()
        self.assertTrue(self.request("GET", "/v1/auth/status")[1]["authentication_required"])
        self.assertEqual(self.choose()[0], 403)
        self.assert_accounts(1)

    def test_local_mode_can_be_explicitly_protected_later(self):
        self.assertEqual(self.choose()[0], 200)
        self.assertEqual(self.choose("protected", username="owner", password="long-enough-password")[0], 403)
        code, state, _ = self.choose("protected", upgrade_local=True, username="owner", password="long-enough-password")
        self.assertEqual(code, 201, state)
        self.assertTrue(state["authentication_required"])
        self.assertEqual(self.choose()[0], 403)

    def test_local_policy_cannot_be_reopened_by_legacy_bootstrap(self):
        self.assertEqual(self.choose()[0], 200)
        response = self.request("POST", "/v1/auth/bootstrap", {"username": "attacker", "password": "long-enough-password"})
        self.assertEqual(response[0], 403, response[1])
        self.assert_accounts(0)
        self.assertEqual(self.request("GET", "/v1/auth/status")[1]["access_mode"], "local")

    def test_failed_activation_rolls_back_owner_and_onboarding(self):
        with mock.patch.object(c, "auth_activate", side_effect=c.AttaccaError("test activation failure")):
            response = self.choose("protected", username="owner", password="long-enough-password")
        self.assertEqual(response[0], 400, response[1])
        self.assert_accounts(0)
        state = self.request("GET", "/v1/auth/status")[1]
        self.assertTrue(state["setup_required"])
        self.assertFalse(state["authentication_required"])
        conn = c.connect(self.db)
        try:
            self.assertIsNone(c._auth_setting(conn, "auth.owner_user_id"))
        finally:
            conn.close()

    def test_legacy_account_install_cannot_be_claimed_through_new_setup(self):
        self.stop_server()
        conn = c.connect(self.db)
        try:
            c.auth_create_user(conn, "existing", "existing-password", is_admin=True, bootstrap=True)
            c.server_settings_store(conn, {"server.setup_mode": "legacy"})
        finally:
            conn.close()
        self.start_server()
        self.assertEqual(self.choose()[0], 403)
        self.assertEqual(self.choose("protected", username="attacker", password="long-enough-password")[0], 403)
        self.assert_accounts(1)
        status = self.request("GET", "/v1/auth/status")[1]
        self.assertFalse(status["anonymous_access"])
        self.assertFalse(status["setup_required"])

    def test_concurrent_protected_setup_has_one_owner_and_one_winner(self):
        barrier = threading.Barrier(3)
        responses = []

        def choose_owner(name):
            barrier.wait()
            responses.append(self.choose("protected", username=name, password="long-enough-password"))

        threads = [threading.Thread(target=choose_owner, args=(name,)) for name in ("first", "second")]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sorted(response[0] for response in responses), [201, 403], responses)
        self.assert_accounts(1)
        self.assertTrue(self.request("GET", "/v1/auth/status")[1]["authentication_required"])

    def test_competing_first_run_modes_cannot_overwrite_each_other(self):
        barrier = threading.Barrier(3)
        responses = []

        def choose_mode(mode):
            barrier.wait()
            responses.append(self.choose(mode, username="owner", password="long-enough-password"))

        threads = [threading.Thread(target=choose_mode, args=(mode,)) for mode in ("local", "protected")]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        codes = sorted(response[0] for response in responses)
        self.assertIn(codes, ([200, 403], [201, 403]), responses)
        state = self.request("GET", "/v1/auth/status")[1]
        self.assertEqual(state["access_mode"], "local" if codes[0] == 200 else "protected")

    def test_legacy_bootstrap_racing_local_choice_has_only_one_winner(self):
        barrier = threading.Barrier(3)
        responses = {}

        def choose_local():
            barrier.wait()
            responses["local"] = self.choose()

        def bootstrap():
            barrier.wait()
            responses["bootstrap"] = self.request("POST", "/v1/auth/bootstrap", {
                "username": "owner", "password": "long-enough-password"})

        threads = [threading.Thread(target=choose_local), threading.Thread(target=bootstrap)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        state = self.request("GET", "/v1/auth/status")[1]
        if responses["local"][0] == 200:
            self.assertEqual(responses["bootstrap"][0], 403)
            self.assertEqual(state["access_mode"], "local")
            self.assert_accounts(0)
        else:
            self.assertEqual(responses["local"][0], 403)
            self.assertEqual(responses["bootstrap"][0], 201)
            self.assertEqual(state["access_mode"], "legacy")
            self.assert_accounts(1)

    def test_network_bind_requires_separate_explicit_risk_confirmation(self):
        self.stop_server()
        self.start_server(bind="0.0.0.0")
        state = self.request("GET", "/v1/auth/status")[1]
        self.assertTrue(state["network_exposed"])
        self.assertTrue(state["login_recommended"])
        self.assertTrue(state["setup_allowed"])
        self.assertEqual(self.choose()[0], 400)
        self.assertEqual(self.choose(acknowledge_network_risk="true")[0], 400)
        self.assertEqual(self.choose(acknowledge_network_risk=True)[0], 200)

    def test_remote_peer_cannot_choose_or_bootstrap_even_with_forwarded_local_headers(self):
        guard = c._local_access_runtime()
        with mock.patch.object(guard, "setup_allowed", return_value=False):
            headers = {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}
            for route, body in (("/v1/setup", {"mode": "local", "confirmed": True}),
                                ("/v1/auth/bootstrap", {"username": "attacker", "password": "long-enough-password"})):
                with self.subTest(route=route):
                    code, data, _ = self.request("POST", route, body, headers)
                    self.assertEqual(code, 403, data)
                    self.assertIn("local_setup_only", data["error"])
        self.assert_accounts(0)
        self.assertTrue(self.request("GET", "/v1/auth/status")[1]["setup_required"])

    def test_http_origin_and_content_type_attacks_do_not_choose_policy(self):
        for headers in ({"Origin": "http://attacker.example"}, {"Origin": "null"},
                        {"Origin": "http://127.0.0.1:%d" % (self.port + 1)},
                        {"Sec-Fetch-Site": "cross-site"}, {"Content-Type": "text/plain"},
                        {"Content-Type": "application/x-www-form-urlencoded"}):
            with self.subTest(headers=headers):
                response = self.request("POST", "/v1/setup", {"mode": "local", "confirmed": True}, headers)
                self.assertEqual(response[0], 403, response[1])
        self.assertTrue(self.request("GET", "/v1/auth/status")[1]["setup_required"])

    def test_dns_rebinding_host_cannot_read_local_workspace_data(self):
        self.assertEqual(self.choose()[0], 200)
        self.seed_project()
        response = self.request("GET", "/v1/projects", headers={"Host": "attacker.example:%d" % self.port})
        self.assertEqual(response[0], 403, response[1])
        self.assertNotIn("Example", json.dumps(response[1]))

    def test_explicit_invalid_client_tokens_do_not_downgrade_to_anonymous(self):
        self.assertEqual(self.choose()[0], 200)
        for prefix in ("atkey_", "atpair_"):
            response = self.request("GET", "/v1/projects", headers={"Authorization": "Bearer " + prefix + "invalid"})
            self.assertEqual(response[0], 401, response[1])
        self.assertEqual(self.request("GET", "/v1/projects")[0], 200)

    def test_no_login_does_not_grant_account_or_key_admin(self):
        self.assertEqual(self.choose()[0], 200)
        for method, route, body in (("GET", "/v1/auth/client-keys", None),
                                    ("POST", "/v1/auth/client-keys", {"label": "forbidden", "client_instance": "fake"}),
                                    ("POST", "/v1/auth/activation", {"enabled": True, "confirmed": True}),
                                    ("GET", "/v1/auth/invitations", None)):
            with self.subTest(route=route):
                self.assertEqual(self.request(method, route, body)[0], 401)

    def test_protected_browser_session_still_requires_csrf(self):
        code, state, headers = self.choose("protected", username="owner", password="long-enough-password")
        self.assertEqual(code, 201, state)
        cookie = http.cookies.SimpleCookie()
        for line in headers.get_all("Set-Cookie") or []:
            cookie.load(line)
        session_headers = {"Cookie": "; ".join("%s=%s" % (key, value.value) for key, value in cookie.items())}
        self.assertEqual(self.request("PUT", "/v1/settings", {"verbose": False}, session_headers)[0], 403)
        session_headers["X-Attacca-CSRF"] = state["csrf_token"]
        self.assertEqual(self.request("PUT", "/v1/settings", {"verbose": False}, session_headers)[0], 200)

    def test_local_export_allowed_but_never_claims_an_authenticated_human(self):
        self.assertEqual(self.choose()[0], 200)
        self.seed_project()
        response = self.request("GET", "/v1/projects/example/export?format=json")
        self.assertEqual(response[0], 200, response[1])
        conn = c.connect(self.db)
        try:
            rows = conn.execute("SELECT owner FROM events WHERE project_id='example'").fetchall()
            self.assertTrue(rows)
            self.assertTrue(all(row["owner"] is None for row in rows))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM auth_project_memberships").fetchone()[0], 0)
        finally:
            conn.close()

    def test_no_login_sync_still_requires_registered_actor_and_device(self):
        self.assertEqual(self.choose()[0], 200)
        self.seed_project()
        registered = self.request("POST", "/v1/projects/example/agents", {
            "agent_id": "example.worker.codex", "role": "worker", "runtime": "codex",
            "canonical_identity": True,
        }, {"X-Attacca-Actor": "web.local", "X-Attacca-Actor-Type": "human"})
        self.assertEqual(registered[0], 200, registered[1])
        route = "/v1/projects/example/sync/snapshot"
        self.assertEqual(self.request("GET", route)[0], 401)
        self.assertEqual(self.request("GET", route, headers={
            "X-Attacca-Actor": "example.director.codex", "X-Attacca-Device-ID": "device-one"})[0], 403)
        response = self.request("GET", route, headers={
            "X-Attacca-Actor": "example.worker.codex", "X-Attacca-Device-ID": "device-one",
            "X-Attacca-Owner": "not-a-verified-human"})
        self.assertEqual(response[0], 200, response[1])
        self.assertEqual(response[1]["scope"]["actor_id"], "example.worker.codex")
        self.assertEqual(response[1]["scope"]["role"], "worker")
        self.assertTrue(response[1]["scope"]["principal_id"].startswith("legacy-device-"))
        self.assertNotEqual(response[1]["scope"]["principal_id"], "not-a-verified-human")
        self.assertFalse(self.request("GET", "/v1/auth/status")[1]["authenticated"])


if __name__ == "__main__":
    unittest.main()
