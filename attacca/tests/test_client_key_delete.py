"""Permanent client-key deletion contract and authorization regressions."""

import importlib.util
import http.client
import http.cookies
import json
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_client_key_delete_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class ClientKeyDeleteTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.conn = c.connect(Path(self.temp.name) / "delete.db")
        c.auth_create_user(self.conn, "owner", "owner-password",
                           display_name="Owner", is_admin=True,
                           bootstrap=True)
        c.auth_create_user(self.conn, "other", "other-password",
                           display_name="Other")
        owner = self.conn.execute(
            "SELECT * FROM auth_users WHERE username='owner'").fetchone()
        other = self.conn.execute(
            "SELECT * FROM auth_users WHERE username='other'").fetchone()
        self.owner = c._auth_principal(
            self.conn, owner, "session", session_hash="owner-session")
        self.other = c._auth_principal(
            self.conn, other, "session", session_hash="other-session")

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    def create_key(self, principal=None, instance="codex-laptop"):
        return c.auth_client_key_create(
            self.conn, principal or self.owner, "Codex laptop", instance)

    def test_delete_requires_prior_revocation(self):
        created = self.create_key()
        token_id = created["record"]["token_id"]
        with self.assertRaisesRegex(
                c.AttaccaError, "must_be_revoked_before_delete"):
            c.auth_client_key_delete(self.conn, self.owner, token_id)
        self.assertIsNotNone(c.auth_token_principal(
            self.conn, created["token"]))

    def test_delete_removes_token_and_bindings_but_keeps_safe_tombstone(self):
        created = self.create_key()
        token_id = created["record"]["token_id"]
        c.auth_client_key_revoke(self.conn, self.owner, token_id)
        result = c.auth_client_key_delete(self.conn, self.owner, token_id)
        self.assertTrue(result["deleted"])
        self.assertIsNone(self.conn.execute(
            "SELECT 1 FROM auth_tokens WHERE token_id=?", (token_id,)
        ).fetchone())
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS n FROM auth_token_project_bindings"
            " WHERE token_id=?", (token_id,)).fetchone()["n"], 0)
        tombstone = self.conn.execute(
            "SELECT * FROM auth_client_key_deletions WHERE token_id=?",
            (token_id,)).fetchone()
        self.assertEqual(tombstone["client_instance"], "codex-laptop")
        self.assertEqual(tombstone["deleted_by_name"], "owner")
        self.assertNotIn("token_hash", tombstone.keys())
        self.assertNotIn(created["token"], dict(tombstone).values())

    def test_non_owner_cannot_delete_revoked_key(self):
        created = self.create_key()
        token_id = created["record"]["token_id"]
        c.auth_client_key_revoke(self.conn, self.owner, token_id)
        with self.assertRaisesRegex(c.AuthorizationError,
                                    "client_key_not_owned"):
            c.auth_client_key_delete(self.conn, self.other, token_id)
        self.assertIsNotNone(self.conn.execute(
            "SELECT 1 FROM auth_tokens WHERE token_id=?", (token_id,)
        ).fetchone())


class ClientKeyDeleteHttpTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "delete-http.db"
        self.server = c.AttaccaServer(("127.0.0.1", 0), self.db, auth=True)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address
        boot = self.request("POST", "/v1/auth/bootstrap", {
            "username": "owner", "display_name": "Owner",
            "password": "owner-password",
        })
        self.assertEqual(boot["status"], 201, boot["body"])
        cookies = {}
        for line in boot["headers"].get_all("Set-Cookie") or []:
            parsed = http.cookies.SimpleCookie()
            parsed.load(line)
            cookies.update({key: item.value for key, item in parsed.items()})
        self.session = {
            "Cookie": "; ".join("%s=%s" % item
                                for item in cookies.items()),
            "X-Attacca-CSRF": cookies["attacca_csrf"],
        }

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=5)
        payload = json.dumps(body).encode() if body is not None else None
        request_headers = {"Accept": "application/json", **(headers or {})}
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        connection.request(method, path, body=payload, headers=request_headers)
        response = connection.getresponse()
        raw = response.read()
        result = {"status": response.status, "headers": response.headers,
                  "body": json.loads(raw) if raw else {}}
        connection.close()
        return result

    def test_permanent_delete_route_requires_revoked_key(self):
        created = self.request("POST", "/v1/auth/client-keys", {
            "label": "Codex laptop", "client_instance": "codex-laptop",
        }, self.session)
        self.assertEqual(created["status"], 201, created["body"])
        token_id = created["body"]["record"]["token_id"]
        path = "/v1/auth/client-keys/%s/permanent" % token_id
        refused = self.request("DELETE", path, {}, self.session)
        self.assertEqual(refused["status"], 400, refused["body"])
        revoked = self.request(
            "DELETE", "/v1/auth/client-keys/%s" % token_id, {}, self.session)
        self.assertEqual(revoked["status"], 200, revoked["body"])
        deleted = self.request("DELETE", path, {}, self.session)
        self.assertEqual(deleted["status"], 200, deleted["body"])
        self.assertTrue(deleted["body"]["deleted"])
        listed = self.request("GET", "/v1/auth/client-keys",
                              headers=self.session)
        self.assertEqual(listed["body"]["client_keys"], [])


if __name__ == "__main__":
    unittest.main()
