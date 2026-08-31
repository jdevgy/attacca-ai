"""Loopback E2E for browser sessions and per-install client API keys.

The server binds to 127.0.0.1 on port 0 and all state lives in one temporary
directory. The suite never discovers, contacts, activates, or mutates a live
Attacca server or installed credential.
"""

import http.client
import http.cookies
import importlib.util
import json
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import offline_sync  # noqa: E402
import terminal_flow  # noqa: E402


SPEC = importlib.util.spec_from_file_location(
    "attacca_client_auth_e2e_core", ROOT / "attacca.py")
core = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(core)


class FullClientAuthorizationE2E(unittest.TestCase):
    RUNTIMES = {
        "codex": "alpha.director.codex",
        "claude": "alpha.director.claude",
        "kimi": "alpha.worker.kimi",
        "generic": "alpha.advisor.generic",
    }

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "auth-e2e.db"
        connection = core.connect(self.db)
        try:
            created = core.auth_create_user(
                connection, "jack", "owner-password",
                display_name="Jack", is_admin=True, bootstrap=True)
            user = connection.execute(
                "SELECT * FROM auth_users WHERE username='jack'").fetchone()
            principal = {
                "user_id": user["user_id"], "username": "jack",
                "is_admin": True, "is_owner": True,
            }
            core.set_current_owner("jack")
            core.project_init(
                connection, "web.jack", "human", path=self.root / "alpha",
                project_id="alpha", name="Alpha")
            core.auth_grant_project_membership(
                connection, principal, "alpha", granted_by="jack")
            for runtime, actor in self.RUNTIMES.items():
                role = actor.split(".")[1]
                core.agent_register(
                    connection, "alpha", "web.jack", "human",
                    agent_id=actor, display_name="Alpha %s" % runtime.title(),
                    role=role, runtime=runtime, canonical_identity=True)

            core.auth_create_user(
                connection, "other", "other-password",
                display_name="Other Human")
            other = connection.execute(
                "SELECT * FROM auth_users WHERE username='other'").fetchone()
            core.auth_grant_project_membership(connection, {
                "user_id": other["user_id"], "username": "other",
                "is_admin": False,
            }, "alpha", granted_by="jack")
            core.set_current_owner("other")
            core.agent_register(
                connection, "alpha", "web.other", "human",
                agent_id="alpha.worker.foreign", display_name="Foreign",
                role="worker", runtime="foreign", canonical_identity=True)
        finally:
            core.set_current_owner(None)
            connection.close()

        self.server = core.AttaccaServer(
            ("127.0.0.1", 0), self.db, auth=True, auth_mode="auto")
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = "http://%s:%s" % (host, port)
        self.owner = self.login("jack", "owner-password")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())
        core.set_current_owner(None)
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        parsed = urllib.parse.urlsplit(self.base_url)
        connection = http.client.HTTPConnection(
            parsed.hostname, parsed.port, timeout=10)
        encoded = None if body is None else json.dumps(body).encode("utf-8")
        merged = {"Accept": "application/json", **(headers or {})}
        if encoded is not None:
            merged["Content-Type"] = "application/json"
        connection.request(method, path, body=encoded, headers=merged)
        response = connection.getresponse()
        raw = response.read()
        content_type = response.headers.get("Content-Type") or ""
        if raw and "json" in content_type:
            parsed_body = json.loads(raw)
        elif raw:
            parsed_body = raw
        else:
            parsed_body = {}
        result = {
            "status": response.status,
            "headers": response.headers,
            "body": parsed_body,
        }
        connection.close()
        return result

    @staticmethod
    def session_headers(response):
        cookies = {}
        for line in response["headers"].get_all("Set-Cookie") or []:
            parsed = http.cookies.SimpleCookie()
            parsed.load(line)
            cookies.update({name: morsel.value
                            for name, morsel in parsed.items()})
        return {
            "Cookie": "; ".join("%s=%s" % item
                                 for item in cookies.items()),
            "X-Attacca-CSRF": cookies["attacca_csrf"],
        }

    def login(self, username, password):
        response = self.request("POST", "/v1/auth/login", {
            "username": username, "password": password})
        self.assertEqual(response["status"], 200, response["body"])
        return self.session_headers(response)

    def create_client(self, runtime, actor):
        install_root = self.root / "clients" / runtime
        instance_file = install_root / "attacca-client.json"
        credentials = install_root / "credentials.json"
        instance = terminal_flow.load_client_instance_id(
            instance_file, runtime=runtime)
        created = self.request(
            "POST", "/v1/auth/client-keys", {
                "label": "%s isolated client" % runtime.title(),
                "client_instance": instance,
                "project_memberships": ["alpha"],
            }, self.owner)
        self.assertEqual(created["status"], 201, created["body"])
        token = created["body"]["token"]
        self.assertTrue(token.startswith("atkey_"))
        self.assertEqual(
            created["body"]["record"]["client_instance"], instance)
        verified = terminal_flow.verify_client_api_key(
            self.base_url, token, client_instance=instance,
            transport=terminal_flow.UrllibJsonTransport())
        stored = terminal_flow.save_client_api_key(
            self.base_url, verified, client_instance=instance,
            credentials_path=credentials)
        self.assertEqual(stored["status"], "ready")
        self.assertNotIn(token, json.dumps(stored))
        headers = terminal_flow.client_request_headers(
            self.base_url, client_instance=instance,
            project_id="alpha", actor_id=actor,
            device_id="device_%s" % runtime,
            credentials_path=credentials)
        headers.update({
            "X-Attacca-Git-Branch": "feature/auth-e2e",
            "X-Attacca-Git-Revision": "deadbeef%s" % runtime,
        })
        return {
            "runtime": runtime, "actor": actor, "instance": instance,
            "credentials": credentials, "token": token,
            "token_id": created["body"]["record"]["token_id"],
            "headers": headers,
        }

    def test_full_browser_key_activation_mirror_attribution_and_revocation(self):
        clients = {
            runtime: self.create_client(runtime, actor)
            for runtime, actor in self.RUNTIMES.items()
        }
        self.assertEqual(
            len({client["instance"] for client in clients.values()}), 4)
        self.assertEqual(
            len({client["token"] for client in clients.values()}), 4)

        listed = self.request(
            "GET", "/v1/auth/client-keys", headers=self.owner)
        self.assertEqual(listed["status"], 200, listed["body"])
        self.assertEqual(len(listed["body"]["client_keys"]), 4)
        serialized_list = json.dumps(listed["body"])
        for client in clients.values():
            self.assertNotIn(client["token"], serialized_list)
        self.assertTrue(all(
            row["username"] == "jack"
            for row in listed["body"]["client_keys"]))
        self.assertTrue(all(
            "actor" not in " ".join(row).lower()
            for row in listed["body"]["client_keys"]))

        activated = self.request(
            "POST", "/v1/auth/activation",
            {"enabled": True, "confirmed": True}, self.owner)
        self.assertEqual(activated["status"], 200, activated["body"])
        self.assertIs(activated["body"]["activated"], True)
        anonymous = self.request("GET", "/v1/projects")
        self.assertEqual(anonymous["status"], 401, anonymous["body"])

        for runtime, client in clients.items():
            with self.subTest(runtime=runtime):
                status = self.request(
                    "GET", "/v1/auth/status", headers=client["headers"])
                self.assertEqual(status["status"], 200, status["body"])
                self.assertEqual(
                    status["body"]["principal"]["token_kind"], "client")
                self.assertEqual(
                    status["body"]["principal"]["client_instance"],
                    client["instance"])
                self.assertEqual(status["body"]["user"]["username"], "jack")

                snapshot = self.request(
                    "GET", "/v1/projects/alpha/sync/snapshot",
                    headers=client["headers"])
                self.assertEqual(snapshot["status"], 200, snapshot["body"])
                scope = snapshot["body"]["scope"]
                self.assertEqual(scope["actor_id"], client["actor"])
                self.assertEqual(scope["project_id"], "alpha")
                mirror = offline_sync.OfflineProjectSync(
                    self.root / "mirrors" / runtime, self.base_url, scope,
                    client_id=client["instance"],
                    device_id="device_%s" % runtime)
                mirror.install_snapshot(
                    snapshot["body"], reset=True,
                    reset_reason="isolated auth enrollment")
                self.assertTrue(mirror.has_mirror())
                proof = mirror.convergence_proof()
                self.assertTrue(proof["online"])
                self.assertEqual(proof["scope"]["actor_id"], client["actor"])

                sent = self.request(
                    "POST", "/v1/projects/alpha/room",
                    {"body": "hello from %s" % runtime}, client["headers"])
                self.assertEqual(sent["status"], 200, sent["body"])

        # A key is not model/actor-bound: the Codex installation key may select
        # another exact same-human actor, and the server still audits that
        # actor rather than rewriting it to Codex.
        cross_headers = terminal_flow.client_request_headers(
            self.base_url,
            client_instance=clients["codex"]["instance"],
            project_id="alpha", actor_id="alpha.director.claude",
            credentials_path=clients["codex"]["credentials"])
        cross = self.request(
            "POST", "/v1/projects/alpha/room",
            {"body": "same install, exact Claude actor"}, cross_headers)
        self.assertEqual(cross["status"], 200, cross["body"])

        foreign_headers = dict(clients["generic"]["headers"])
        foreign_headers[terminal_flow.ACTOR_HEADER] = "alpha.worker.foreign"
        denied = self.request(
            "GET", "/v1/projects/alpha/room", headers=foreign_headers)
        self.assertEqual(denied["status"], 403, denied["body"])
        self.assertIn("actor belongs", denied["body"]["error"])

        connection = core.connect(self.db)
        try:
            rows = connection.execute(
                "SELECT actor_id,owner,git_branch,base_revision FROM events"
                " WHERE project_id='alpha' AND event_type='room.message'"
                " ORDER BY seq").fetchall()
        finally:
            connection.close()
        observed = {(row["actor_id"], row["owner"]) for row in rows}
        for actor in self.RUNTIMES.values():
            self.assertIn((actor, "jack"), observed)
        self.assertTrue(all(row["owner"] == "jack" for row in rows))
        self.assertTrue(any(
            row["actor_id"] == "alpha.director.codex" and
            row["git_branch"] == "feature/auth-e2e" and
            row["base_revision"] == "deadbeefcodex" for row in rows))

        # Full backups remain a human browser operation; the snapshot mirror
        # is the client-key path. Neither artifact contains any raw key.
        backup = self.request(
            "GET", "/v1/projects/alpha/export?format=json",
            headers=self.owner)
        self.assertEqual(backup["status"], 200, backup["body"])
        backup_bytes = backup["body"] if isinstance(backup["body"], bytes) \
            else json.dumps(backup["body"]).encode("utf-8")
        for client in clients.values():
            self.assertNotIn(client["token"].encode("utf-8"), backup_bytes)
        bearer_backup = self.request(
            "GET", "/v1/projects/alpha/export?format=json",
            headers=clients["claude"]["headers"])
        self.assertEqual(bearer_backup["status"], 403, bearer_backup["body"])

        revoked = self.request(
            "DELETE", "/v1/auth/client-keys/%s" %
            urllib.parse.quote(clients["codex"]["token_id"], safe=""),
            headers=self.owner)
        self.assertEqual(revoked["status"], 200, revoked["body"])
        self.assertIs(revoked["body"]["revoked"], True)
        rejected = self.request(
            "GET", "/v1/projects/alpha/room",
            headers=clients["codex"]["headers"])
        self.assertEqual(rejected["status"], 401, rejected["body"])
        unaffected = self.request(
            "GET", "/v1/projects/alpha/room",
            headers=clients["claude"]["headers"])
        self.assertEqual(unaffected["status"], 200, unaffected["body"])


if __name__ == "__main__":
    unittest.main()
