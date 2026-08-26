"""D-17 cutover and retired-terminal authentication regressions.

All servers bind to loopback port 0 and all databases are temporary. This
suite must never discover, connect to, restart, or mutate a configured server.
"""

import http.client
import http.cookies
import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_d17_cutover_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)
protocol, _sync_server = c._sync_runtime()


class D17CutoverTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "d17-cutover.db"
        conn = c.connect(self.db)
        try:
            c.auth_create_user(
                conn, "alice", "correct-horse", display_name="Alice",
                is_admin=True, bootstrap=True)
            c.auth_create_user(
                conn, "bob", "battery-staple", display_name="Bob")
            alice = conn.execute(
                "SELECT * FROM auth_users WHERE username='alice'").fetchone()
            bob = conn.execute(
                "SELECT * FROM auth_users WHERE username='bob'").fetchone()
            alice_principal = c._auth_principal(
                conn, alice, "session", session_hash="alice-fixture")
            bob_principal = c._auth_principal(
                conn, bob, "session", session_hash="bob-fixture")
            c.set_current_owner("alice")
            c.project_init(
                conn, "web.alice", "human", path=self.root / "project",
                project_id="proj", name="Project")
            c.project_init(
                conn, "web.alice", "human", path=self.root / "private",
                project_id="private", name="Private")
            c.auth_grant_project_membership(
                conn, alice_principal, "proj", granted_by="alice")
            c.auth_grant_project_membership(
                conn, alice_principal, "private", granted_by="alice")
            c.auth_grant_project_membership(
                conn, bob_principal, "proj", granted_by="alice")
            # Deliberately historical ids. Client authorization must never
            # rewrite them or infer authority from only the runtime suffix.
            c.agent_register(
                conn, "proj", "web.alice", "human",
                agent_id="proj.director.codex-legacy",
                display_name="Historic Director", role="director",
                runtime="codex", registration_username="alice")
            c.agent_register(
                conn, "proj", "web.alice", "human",
                agent_id="proj.worker.codex-legacy",
                display_name="Historic Worker", role="worker",
                runtime="codex", registration_username="alice")
            c.agent_register(
                conn, "private", "web.alice", "human",
                agent_id="private.director.codex-legacy",
                role="director", runtime="codex",
                registration_username="alice")
            c.set_current_owner("bob")
            c.agent_register(
                conn, "proj", "web.bob", "human",
                agent_id="proj.worker.bob", role="worker", runtime="other",
                registration_username="bob")
            c.set_current_owner("alice")
            c.set_lead_director(
                conn, "proj", "web.alice", "human",
                "proj.director.codex-legacy")
        finally:
            c.set_current_owner(None)
            conn.close()
        self.server = None
        self.thread = None
        self.start_server(auth=True, auth_mode="auto")
        self.alice = self.login("alice", "correct-horse")
        self.bob = self.login("bob", "battery-staple")

    def tearDown(self):
        self.stop_server()
        c.set_current_owner(None)
        self.tmp.cleanup()

    def start_server(self, auth=True, auth_mode="auto"):
        self.server = c.AttaccaServer(
            ("127.0.0.1", 0), self.db, auth=auth, auth_mode=auth_mode)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

    def stop_server(self):
        if self.server is None:
            return
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())
        self.server = None
        self.thread = None

    def restart_server(self, auth=True, auth_mode="auto"):
        self.stop_server()
        self.start_server(auth=auth, auth_mode=auth_mode)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(
            self.host, self.port, timeout=10)
        payload = json.dumps(body).encode() if body is not None else None
        merged = {"Accept": "application/json", **(headers or {})}
        if payload is not None:
            merged["Content-Type"] = "application/json"
        connection.request(method, path, body=payload, headers=merged)
        response = connection.getresponse()
        raw = response.read()
        content_type = response.headers.get("Content-Type") or ""
        body_value = (json.loads(raw) if raw and "json" in content_type
                      else raw.decode("utf-8", "replace") if raw else {})
        result = {"status": response.status, "headers": response.headers,
                  "body": body_value}
        connection.close()
        return result

    @staticmethod
    def session_headers(response):
        values = {}
        for line in response["headers"].get_all("Set-Cookie") or []:
            parsed = http.cookies.SimpleCookie()
            parsed.load(line)
            values.update({key: morsel.value
                           for key, morsel in parsed.items()})
        return {
            "Cookie": "; ".join("%s=%s" % item for item in values.items()),
            "X-Attacca-CSRF": values["attacca_csrf"],
        }

    def login(self, username, password):
        response = self.request("POST", "/v1/auth/login", {
            "username": username, "password": password})
        self.assertEqual(response["status"], 200, response["body"])
        return self.session_headers(response)

    def create_client(self, *, session=None, label="D-17 client",
                      instance="client-one", projects=("proj",),
                      device="device-one", expires_at=None):
        payload = {
            "label": label, "client_instance": instance,
            "project_memberships": list(projects),
        }
        if device is not None:
            payload["device_id"] = device
        if expires_at is not None:
            payload["expires_at"] = expires_at
        return self.request(
            "POST", "/v1/auth/client-keys", payload,
            session or self.alice)

    @staticmethod
    def client_headers(credential, actor, *, project="proj",
                       instance="client-one", device="device-one"):
        headers = {
            "Authorization": "Bearer " + credential["token"],
            "X-Attacca-Client-Instance": instance,
            "X-Attacca-Project": project,
            "X-Attacca-Actor": actor,
        }
        if device is not None:
            headers["X-Attacca-Device-ID"] = device
        return headers

    def activate(self, enabled=True, headers=None, confirmed=True,
                 expected=None):
        body = {"enabled": enabled, "confirmed": confirmed}
        if expected is not None:
            body["expected_readiness_version"] = expected
        return self.request(
            "POST", "/v1/auth/activation", body, headers or self.alice)

    def actor_state(self):
        conn = c.connect(self.db)
        try:
            return {
                "agents": [tuple(row) for row in conn.execute(
                    "SELECT project_id,agent_id,display_name,role,runtime,"
                    "owner,actor_type,registered_at FROM agents"
                    " ORDER BY project_id,agent_id")],
                "projects": [tuple(row) for row in conn.execute(
                    "SELECT project_id,name,lead_director,created_at"
                    " FROM projects ORDER BY project_id")],
            }
        finally:
            conn.close()

    def test_optional_cutover_state_has_no_terminal_migration_or_qa_gate(self):
        status = self.request("GET", "/v1/auth/status")
        self.assertEqual(status["status"], 200)
        self.assertFalse(status["body"]["authentication_required"])
        self.assertEqual(status["body"]["effective_authentication"],
                         "optional")
        policy = status["body"]["credential_policy"]
        self.assertEqual(policy["client_api_key"], "supported")
        self.assertEqual(policy["terminal"], "retired")
        self.assertFalse(policy["actor_bound_keys"])

        access = self.request("GET", "/v1/auth/access", headers=self.alice)
        self.assertEqual(access["status"], 200, access["body"])
        capabilities = access["body"]["capabilities"]
        self.assertTrue(capabilities["client_keys"])
        self.assertFalse(capabilities["terminal_enrollment"])
        self.assertFalse(capabilities["migration_scope"])
        readiness = access["body"]["compatibility"]
        self.assertTrue(readiness["ready"])
        self.assertEqual(readiness["blockers"], [])
        self.assertEqual(readiness["terminal_count"], 0)
        self.assertEqual(readiness["uncovered_client_count"], 0)
        self.assertIsNone(readiness["qa_evidence"])

    def test_retired_device_and_migration_routes_are_unreachable_and_inert(self):
        conn = c.connect(self.db)
        try:
            before = {
                "tokens": conn.execute(
                    "SELECT COUNT(*) AS n FROM auth_tokens").fetchone()["n"],
                "enrollments": conn.execute(
                    "SELECT COUNT(*) AS n FROM auth_device_enrollments"
                ).fetchone()["n"],
                "targets": conn.execute(
                    "SELECT COUNT(*) AS n FROM auth_migration_targets"
                ).fetchone()["n"],
            }
        finally:
            conn.close()
        calls = (
            ("POST", "/v1/auth/device/start", {"device_id": "retired"}),
            ("POST", "/v1/auth/device/poll", {"device_code": "retired"}),
            ("POST", "/v1/auth/terminal-enrollments/OLD/approve", {}),
            ("POST", "/v1/auth/migration-scope", {}),
        )
        for method, path, body in calls:
            with self.subTest(path=path):
                response = self.request(method, path, body, self.alice)
                self.assertEqual(response["status"], 404, response["body"])
        conn = c.connect(self.db)
        try:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM auth_tokens").fetchone()["n"],
                before["tokens"])
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM auth_device_enrollments"
            ).fetchone()["n"], before["enrollments"])
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM auth_migration_targets"
            ).fetchone()["n"], before["targets"])
        finally:
            conn.close()

    def test_client_snapshot_pull_push_is_exact_actor_device_and_human(self):
        before = self.actor_state()
        issued = self.create_client()
        self.assertEqual(issued["status"], 201, issued["body"])
        credential = issued["body"]
        self.assertTrue(credential["token"].startswith("atkey_"))
        self.assertEqual(self.activate()["status"], 200)
        headers = self.client_headers(
            credential, "proj.director.codex-legacy")

        snapshot_response = self.request(
            "GET", "/v1/projects/proj/sync/snapshot", headers=headers)
        self.assertEqual(snapshot_response["status"], 200,
                         snapshot_response["body"])
        snapshot = snapshot_response["body"]
        protocol.validate_snapshot(snapshot)
        self.assertEqual(snapshot["scope"]["actor_id"],
                         "proj.director.codex-legacy")

        cursor = snapshot["cursor"]
        query = urllib.parse.urlencode({
            "after_seq": cursor["event_seq"],
            "after_hash": cursor["event_hash"],
            "context_version": cursor["context_version"],
            "visibility_fingerprint": snapshot["visibility_fingerprint"],
        })
        pulled = self.request(
            "GET", "/v1/projects/proj/sync/pull?" + query, headers=headers)
        self.assertEqual(pulled["status"], 200, pulled["body"])
        protocol.validate_pull_result(pulled["body"])

        mutation = protocol.make_client_mutation(
            snapshot["scope"], "d17_room_send_0001", "client-one",
            "device-one", 1, "room.send", {"body": "D-17 sync"},
            snapshot["cursor"], metadata={
                "git_branch": "feature/d17",
                "git_revision": "deadbeef",
            })
        envelope = protocol.make_push_request(
            snapshot["scope"], snapshot["visibility_fingerprint"],
            "client-one", "device-one", [mutation])
        pushed = self.request(
            "POST", "/v1/projects/proj/sync/push", envelope, headers)
        self.assertEqual(pushed["status"], 200, pushed["body"])
        self.assertEqual(pushed["body"]["results"][0]["status"], "applied")

        conn = c.connect(self.db)
        try:
            event = conn.execute(
                "SELECT * FROM events WHERE project_id='proj'"
                " AND event_type='room.message' ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            self.assertEqual(event["actor_id"],
                             "proj.director.codex-legacy")
            self.assertEqual(event["owner"], "alice")
            self.assertEqual(event["device_id"], "device-one/client-one")
            self.assertEqual(event["git_branch"], "feature/d17")
            self.assertEqual(event["base_revision"], "deadbeef")
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM auth_token_actor_bindings"
            ).fetchone()["n"], 0)
        finally:
            conn.close()
        self.assertEqual(self.actor_state(), before)

        no_actor = dict(headers)
        no_actor.pop("X-Attacca-Actor")
        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/sync/snapshot",
            headers=no_actor)["status"], 403)
        wrong_actor = dict(headers)
        wrong_actor["X-Attacca-Actor"] = "proj.worker.bob"
        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/sync/snapshot",
            headers=wrong_actor)["status"], 403)

    def test_client_key_plaintext_is_one_time_user_scoped_and_revocable(self):
        alice_key = self.create_client()
        self.assertEqual(alice_key["status"], 201, alice_key["body"])
        raw = alice_key["body"]["token"]
        token_id = alice_key["body"]["record"]["token_id"]
        self.assertTrue(raw.startswith("atkey_"))
        listed = self.request(
            "GET", "/v1/auth/client-keys", headers=self.alice)
        self.assertEqual(listed["status"], 200, listed["body"])
        self.assertEqual(len(listed["body"]["client_keys"]), 1)
        self.assertNotIn(raw, json.dumps(listed["body"]))
        self.assertEqual(
            listed["body"]["client_keys"][0]["client_instance"],
            "client-one")

        bob_key = self.create_client(
            session=self.bob, instance="client-bob", device=None)
        self.assertEqual(bob_key["status"], 201, bob_key["body"])
        bob_list = self.request(
            "GET", "/v1/auth/client-keys", headers=self.bob)
        self.assertEqual(len(bob_list["body"]["client_keys"]), 1)
        self.assertEqual(
            bob_list["body"]["client_keys"][0]["username"], "bob")
        self.assertEqual(self.request(
            "DELETE", "/v1/auth/client-keys/%s" % token_id,
            headers=self.bob)["status"], 403)

        revoked = self.request(
            "DELETE", "/v1/auth/client-keys/%s" % token_id,
            headers=self.alice)
        self.assertEqual(revoked["status"], 200, revoked["body"])
        self.activate()
        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/status",
            headers=self.client_headers(
                alice_key["body"], "proj.director.codex-legacy")
        )["status"], 401)

    def test_member_cannot_scope_private_project_or_select_another_owner_actor(self):
        denied = self.create_client(
            session=self.bob, instance="client-bob-private",
            projects=("private",), device=None)
        self.assertEqual(denied["status"], 403, denied["body"])
        self.assertIn("membership", denied["body"]["error"])

        issued = self.create_client(
            session=self.bob, instance="client-bob", device=None)
        self.assertEqual(issued["status"], 201, issued["body"])
        self.activate()
        own_headers = self.client_headers(
            issued["body"], "proj.worker.bob", instance="client-bob",
            device=None)
        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/status",
            headers=own_headers)["status"], 200)
        stolen = dict(own_headers)
        stolen["X-Attacca-Actor"] = "proj.director.codex-legacy"
        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/status", headers=stolen)["status"],
            403)

    def test_request_hot_path_does_not_recompute_activation_readiness(self):
        issued = self.create_client()
        self.assertEqual(issued["status"], 201, issued["body"])
        self.activate()
        headers = self.client_headers(
            issued["body"], "proj.director.codex-legacy")
        with mock.patch.object(
                c, "auth_activation_readiness",
                side_effect=AssertionError("hot path recomputed readiness")):
            result = self.request(
                "GET", "/v1/projects/proj/room", headers=headers)
        self.assertEqual(result["status"], 200, result["body"])

    def test_activation_is_owner_confirmed_simple_and_persisted(self):
        self.assertEqual(self.activate(headers=self.bob)["status"], 403)
        self.assertEqual(self.activate(confirmed=False)["status"], 400)
        # D-17 deliberately removed the stale migration-readiness latch.
        activated = self.activate(expected="obsolete-readiness-version")
        self.assertEqual(activated["status"], 200, activated["body"])
        self.assertTrue(activated["body"]["activated"])
        self.assertEqual(self.request("GET", "/v1/projects")["status"], 401)
        self.restart_server(auth=True, auth_mode="auto")
        self.assertEqual(self.request("GET", "/v1/projects")["status"], 401)

        self.alice = self.login("alice", "correct-horse")
        disabled = self.activate(enabled=False)
        self.assertEqual(disabled["status"], 200, disabled["body"])
        self.assertFalse(disabled["body"]["activated"])
        self.restart_server(auth=True, auth_mode="auto")
        self.assertEqual(self.request("GET", "/v1/projects")["status"], 200)

    def test_activation_failure_rolls_back_alias_and_settings_in_one_transaction(self):
        isolated = self.root / "atomic.db"
        conn = c.connect(isolated)
        try:
            c.auth_create_user(
                conn, "owner", "owner-password", is_admin=True,
                bootstrap=True)
            user = conn.execute(
                "SELECT * FROM auth_users WHERE username='owner'").fetchone()
            principal = c._auth_principal(
                conn, user, "session", session_hash="atomic")
            c.set_current_owner("legacy-shell")
            c.project_init(
                conn, "legacy-shell", "human", path=self.root / "legacy",
                project_id="legacy", name="Legacy")
            c.agent_register(
                conn, "legacy", "legacy-shell", "human",
                agent_id="legacy.director.codex", role="director",
                runtime="codex")
            c.set_current_owner(None)
            with mock.patch.object(
                    c, "auth_grant_single_user_legacy_project_memberships",
                    side_effect=RuntimeError("injected cutover failure")):
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    c.auth_activate(conn, principal, True, enabled=True)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM auth_user_owner_aliases"
            ).fetchone()["n"], 0)
            self.assertIsNone(c._auth_setting(conn, "auth.activated", None))
            self.assertIsNone(c._auth_setting(
                conn, "auth.activation_requested", None))

            completed = c.auth_activate(
                conn, principal, True, enabled=True)
            self.assertTrue(completed["activated"])
            self.assertEqual(completed["claimed_legacy_owner_aliases"],
                             ["legacy-shell"])
            self.assertEqual(completed[
                "claimed_legacy_project_memberships"], ["legacy"])
        finally:
            c.set_current_owner(None)
            conn.close()

    def test_legacy_actor_bearer_is_disabled_after_activation(self):
        conn = c.connect(self.db)
        try:
            token = c.auth_token_create(
                conn, "alice", "retired actor token",
                actor_id="proj.director.codex-legacy", actor_type="agent",
                project_id="proj", runtime="codex")["token"]
        finally:
            conn.close()
        # It remains a bounded compatibility credential before the explicit
        # owner cutover, then fails closed once D-17 is active.
        pre = self.request("GET", "/v1/projects/proj/status", headers={
            "Authorization": "Bearer " + token,
            "X-Attacca-Project": "proj",
            "X-Attacca-Actor": "proj.director.codex-legacy",
        })
        self.assertEqual(pre["status"], 200, pre["body"])
        self.activate()
        post = self.request("GET", "/v1/projects/proj/status", headers={
            "Authorization": "Bearer " + token,
            "X-Attacca-Project": "proj",
            "X-Attacca-Actor": "proj.director.codex-legacy",
        })
        self.assertEqual(post["status"], 403, post["body"])
        self.assertIn("legacy_actor_token_disabled", post["body"]["error"])

    def test_security_fingerprint_covers_every_declared_auth_package_file(self):
        self.assertTrue(set(c.AUTH_ARTIFACT_FILES).issubset(
            set(c.PLUGIN_FILES)))
        package = self.root / "fingerprint-package"
        for relative in c.AUTH_ARTIFACT_FILES:
            target = package / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fixture:%s\n" % relative)
        with mock.patch.object(
                c, "script_path", return_value=str(package / "attacca.py")):
            before = c.auth_source_sha256()
            self.assertIsNotNone(before)
            target = package / "web" / "admin.html"
            target.write_text(target.read_text() + "changed auth UI\n")
            self.assertNotEqual(before, c.auth_source_sha256())
            target.unlink()
            self.assertIsNone(c.auth_source_sha256())


if __name__ == "__main__":
    unittest.main()
