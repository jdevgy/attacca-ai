"""Hosted authentication, session, CSRF, and API-token acceptance tests."""

import http.client
import http.cookies
import importlib.util
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("attacca_auth_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class AuthHttpTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "auth.db"
        self.server = c.AttaccaServer(("127.0.0.1", 0), self.db, auth=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=5)
        payload = json.dumps(body).encode() if body is not None else None
        merged = {"Accept": "application/json", **(headers or {})}
        if payload is not None:
            merged["Content-Type"] = "application/json"
        connection.request(method, path, body=payload, headers=merged)
        response = connection.getresponse()
        raw = response.read()
        content_type = response.headers.get("Content-Type") or ""
        result = {
            "status": response.status,
            "headers": response.headers,
            "body": (json.loads(raw) if raw and "json" in content_type
                     else raw.decode("utf-8", "replace") if raw else {}),
        }
        connection.close()
        return result

    @staticmethod
    def cookies(response):
        values = {}
        for line in response["headers"].get_all("Set-Cookie") or []:
            parsed = http.cookies.SimpleCookie()
            parsed.load(line)
            values.update({key: morsel.value for key, morsel in parsed.items()})
        return values

    @staticmethod
    def session_headers(response, csrf=True):
        cookies = AuthHttpTestCase.cookies(response)
        headers = {"Cookie": "; ".join(
            "%s=%s" % item for item in cookies.items())}
        if csrf:
            headers["X-Attacca-CSRF"] = cookies["attacca_csrf"]
        return headers

    def bootstrap(self, username="alice", password="correct-horse"):
        response = self.request("POST", "/v1/auth/bootstrap", {
            "username": username,
            "display_name": username.title(),
            "password": password,
        })
        self.assertEqual(response["status"], 201, response["body"])
        return response

    def login(self, username="alice", password="correct-horse"):
        response = self.request("POST", "/v1/auth/login", {
            "username": username, "password": password})
        self.assertEqual(response["status"], 200, response["body"])
        return response

    def seed_projects_and_agent(self):
        conn = c.connect(self.db)
        try:
            c.set_current_owner("alice")
            c.project_init(conn, "seed", "human", path=Path(self.tmp.name) / "one",
                           project_id="one", name="One")
            c.project_init(conn, "seed", "human", path=Path(self.tmp.name) / "two",
                           project_id="two", name="Two")
            c.agent_register(
                conn, "one", "seed", "human",
                agent_id="one.director.codex", display_name="One Codex",
                role="director", runtime="codex")
        finally:
            c.set_current_owner(None)
            conn.close()

    def test_concurrent_first_admin_bootstrap_has_exactly_one_winner(self):
        barrier = threading.Barrier(3)
        results = []

        def create(username):
            barrier.wait()
            results.append(self.request("POST", "/v1/auth/bootstrap", {
                "username": username, "password": "bootstrap-password"}))

        threads = [threading.Thread(target=create, args=(name,))
                   for name in ("first", "second")]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(sorted(item["status"] for item in results), [201, 400])
        conn = c.connect(self.db)
        try:
            rows = conn.execute("SELECT username, is_admin FROM auth_users").fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["is_admin"], 1)
        finally:
            conn.close()

    def test_anonymous_compatibility_before_bootstrap_and_public_installer(self):
        # A server not started with --auth retains the existing anonymous
        # prototype behavior until the first account is deliberately created.
        other_db = Path(self.tmp.name) / "anonymous.db"
        other = c.AttaccaServer(("127.0.0.1", 0), other_db, auth=False)
        thread = threading.Thread(target=other.serve_forever, daemon=True)
        thread.start()
        old_server, old_host, old_port = self.server, self.host, self.port
        try:
            self.server, (self.host, self.port) = other, other.server_address
            status = self.request("GET", "/v1/auth/status")
            self.assertFalse(status["body"]["authentication_required"])
            self.assertTrue(status["body"]["bootstrap_required"])
            self.assertEqual(self.request("GET", "/v1/projects")["status"], 200)
        finally:
            self.server, self.host, self.port = old_server, old_host, old_port
            other.shutdown()
            other.server_close()
            thread.join(timeout=3)

        self.assertEqual(self.request("GET", "/install.sh")["status"], 200)
        self.assertEqual(self.request("GET", "/plugin.zip")["status"], 200)
        # --auth is a readiness request, not an enforcement switch. A normal
        # restart remains compatibility-active until explicit activation.
        self.assertEqual(self.request("GET", "/v1/projects")["status"], 200)
        self.assertEqual(self.request("POST", "/mcp", {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "auth-test", "version": "1"}},
        })["status"], 200)

    def test_login_cookie_flags_wrong_password_expiry_and_logout(self):
        bootstrap = self.bootstrap()
        cookie_lines = bootstrap["headers"].get_all("Set-Cookie") or []
        session_cookie = next(line for line in cookie_lines
                              if line.startswith("attacca_session="))
        csrf_cookie = next(line for line in cookie_lines
                           if line.startswith("attacca_csrf="))
        for flag in ("Path=/", "Max-Age=86400", "SameSite=Strict", "HttpOnly"):
            self.assertIn(flag, session_cookie)
        self.assertNotIn("HttpOnly", csrf_cookie)
        self.assertIn("SameSite=Strict", csrf_cookie)
        secure_login = self.request("POST", "/v1/auth/login", {
            "username": "alice", "password": "correct-horse"},
            {"X-Forwarded-Proto": "https"})
        self.assertEqual(secure_login["status"], 200)
        self.assertTrue(all("Secure" in line for line in
                            secure_login["headers"].get_all("Set-Cookie")))
        self.assertEqual(
            self.request("POST", "/v1/auth/login", {
                "username": "alice", "password": "wrong-password"})["status"],
            401)
        self.assertEqual(
            self.request("POST", "/v1/auth/login", {
                "username": "unknown", "password": "x"})["status"], 401)

        headers = self.session_headers(bootstrap)
        self.assertTrue(self.request("GET", "/v1/auth/status", headers=headers)
                        ["body"]["authenticated"])
        logout = self.request("POST", "/v1/auth/logout", headers=headers)
        self.assertEqual(logout["status"], 200)
        self.assertTrue(all("Max-Age=0" in line for line in
                            logout["headers"].get_all("Set-Cookie")))
        self.assertEqual(self.request("GET", "/v1/projects", headers=headers)
                         ["status"], 200)

        fresh = self.login()
        conn = c.connect(self.db)
        try:
            conn.execute("UPDATE auth_sessions SET expires_at=?",
                         ("2000-01-01T00:00:00.000Z",))
        finally:
            conn.close()
        self.assertFalse(self.request(
            "GET", "/v1/auth/status", headers=self.session_headers(fresh))
            ["body"]["authenticated"])

    def test_every_session_mutation_requires_exact_csrf(self):
        session = self.bootstrap()
        cookie_only = self.session_headers(session, csrf=False)
        wrong = {**cookie_only, "X-Attacca-CSRF": "csrf_wrong"}
        cases = [
            ("POST", "/v1/projects", {"name": "Blocked"}),
            ("PUT", "/v1/settings", {"verbose": True}),
            ("POST", "/v1/auth/tokens", {"label": "Blocked", "actor_type": "human"}),
            ("DELETE", "/v1/auth/tokens/tok_missing", None),
            ("POST", "/v1/auth/logout", None),
        ]
        for method, path, body in cases:
            with self.subTest(method=method, path=path, csrf="missing"):
                self.assertEqual(self.request(method, path, body, cookie_only)["status"], 403)
            with self.subTest(method=method, path=path, csrf="wrong"):
                self.assertEqual(self.request(method, path, body, wrong)["status"], 403)

    def test_token_hash_privileges_revocation_expiry_binding_and_spoofing(self):
        session = self.bootstrap()
        self.seed_projects_and_agent()
        browser = self.session_headers(session)
        self.server.auth_mode = "compatibility"
        created = self.request("POST", "/v1/auth/tokens", {
            "label": "Codex on laptop", "actor_type": "agent",
            "project_id": "one", "actor_id": "one.director.codex",
            "runtime": "codex", "legacy_migration": True}, browser)
        self.server.auth_mode = "auto"
        self.assertEqual(created["status"], 201, created["body"])
        token = created["body"]["token"]
        token_id = created["body"]["record"]["token_id"]
        human = self.request("POST", "/v1/auth/tokens", {
            "label": "Backup client", "actor_type": "human"}, browser)
        self.assertEqual(human["status"], 201, human["body"])
        human_token = human["body"]["token"]

        conn = c.connect(self.db)
        try:
            dump = "\n".join(conn.iterdump())
            self.assertNotIn(token, dump)
            self.assertNotIn(human_token, dump)
            self.assertIn(c.sha256_hex(token), dump)
            expired = c.auth_token_create(
                conn, "alice", "Expired", actor_id="one.director.codex",
                actor_type="agent", project_id="one", runtime="codex",
                expires_at="2999-01-01T00:00:00.000Z")["token"]
            conn.execute(
                "UPDATE auth_tokens SET expires_at=? WHERE token_hash=?",
                ("2000-01-01T00:00:00.000Z", c.sha256_hex(expired)))
            for invalid_expiry in ("tomorrow", "2999-01-01T00:00:00",
                                   "2000-01-01T00:00:00Z"):
                with self.assertRaises(c.AttaccaError):
                    c.auth_token_create(
                        conn, "alice", "Bad expiry", actor_type="human",
                        expires_at=invalid_expiry)
        finally:
            conn.close()

        agent_headers = {"Authorization": "Bearer " + token,
                         "X-Attacca-Actor": "one.director.codex",
                         "X-Attacca-Owner": "mallory"}
        projects = self.request("GET", "/v1/projects", headers=agent_headers)
        self.assertEqual([p["project_id"] for p in projects["body"]["projects"]], ["one"])
        mcp = self.request("POST", "/mcp", {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "auth-test", "version": "1"}},
        }, {**agent_headers, "X-Attacca-Project": "one"})
        self.assertEqual(mcp["status"], 200, mcp["body"])
        self.assertEqual(mcp["body"]["result"]["serverInfo"]["name"],
                         "attacca")
        self.assertEqual(self.request(
            "GET", "/v1/projects/two/status", headers=agent_headers)["status"], 403)
        spoofed = {**agent_headers, "X-Attacca-Actor": "two.director.codex"}
        self.assertEqual(self.request("GET", "/v1/projects", headers=spoofed)["status"], 403)

        for restricted in (agent_headers,
                           {"Authorization": "Bearer " + human_token}):
            self.assertEqual(self.request("GET", "/v1/auth/tokens",
                                          headers=restricted)["status"], 403)
            self.assertEqual(self.request(
                "POST", "/v1/auth/tokens", {"label": "Escalate",
                                               "actor_type": "human"},
                restricted)["status"], 403)

        # Authenticated actor and human ownership come only from the token;
        # forged legacy headers cannot alter immutable ledger attribution.
        human_spoof = {
            "Authorization": "Bearer " + human_token,
            "X-Attacca-Actor": "one.director.claude",
            "X-Attacca-Owner": "mallory",
        }
        written = self.request("POST", "/v1/projects/one/events", {
            "event_type": "note.auth_spoof_test", "payload": {"ok": True}},
            human_spoof)
        self.assertEqual(written["status"], 200, written["body"])
        conn = c.connect(self.db)
        try:
            row = conn.execute(
                "SELECT actor_id, actor_type, owner FROM events"
                " WHERE event_type='note.auth_spoof_test'").fetchone()
            self.assertEqual(
                (row["actor_id"], row["actor_type"], row["owner"]),
                ("web.alice", "human", "alice"))
        finally:
            conn.close()

        # Enforced mode rejects invalid/expired/revoked credentials. Before
        # explicit activation auto mode intentionally ignores stale bearer
        # values as part of bounded compatibility.
        conn = c.connect(self.db)
        try:
            c.server_settings_store(conn, {"auth.activated": True})
        finally:
            conn.close()
        invalid = self.request("GET", "/v1/projects", headers={
            "Authorization": "Bearer " + token + "-invalid"})
        self.assertEqual(invalid["status"], 401)
        self.assertNotIn(token, json.dumps(invalid["body"]))
        self.assertEqual(self.request("GET", "/v1/projects", headers={
            "Authorization": "Bearer " + expired})["status"], 401)

        revoked = self.request(
            "DELETE", "/v1/auth/tokens/%s" % token_id, headers=browser)
        self.assertEqual(revoked["status"], 200)
        self.assertEqual(self.request("GET", "/v1/projects",
                                      headers=agent_headers)["status"], 401)

    def test_admin_can_mint_for_legacy_owned_agent_and_user_is_authoritative(self):
        session = self.bootstrap(username="jdevgy")
        self.seed_projects_and_agent()
        conn = c.connect(self.db)
        try:
            conn.execute(
                "UPDATE agents SET owner='legacy-jack'"
                " WHERE project_id='one' AND agent_id='one.director.codex'")
        finally:
            conn.close()
        browser = self.session_headers(session)
        self.server.auth_mode = "compatibility"
        created = self.request("POST", "/v1/auth/tokens", {
            "label": "Existing Codex", "actor_type": "agent",
            "project_id": "one", "actor_id": "one.director.codex",
            "runtime": "codex", "legacy_migration": True}, browser)
        self.server.auth_mode = "auto"
        self.assertEqual(created["status"], 201, created["body"])
        token = created["body"]["token"]
        headers = {
            "Authorization": "Bearer " + token,
            "X-Attacca-Actor": "one.director.codex",
            "X-Attacca-Owner": "legacy-jack",
        }
        written = self.request("POST", "/v1/projects/one/events", {
            "event_type": "note.legacy_owner", "payload": {"ok": True}},
            headers)
        self.assertEqual(written["status"], 200, written["body"])
        exported = self.request(
            "GET", "/v1/projects/one/export?format=json", headers=browser)
        self.assertEqual(exported["status"], 200, exported["body"])
        self.assertNotIn(token, json.dumps(exported["body"]))
        conn = c.connect(self.db)
        try:
            row = conn.execute(
                "SELECT actor_id,actor_type,owner FROM events"
                " WHERE event_type='note.legacy_owner'").fetchone()
            self.assertEqual(
                (row["actor_id"], row["actor_type"], row["owner"]),
                ("one.director.codex", "agent", "jdevgy"))
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
