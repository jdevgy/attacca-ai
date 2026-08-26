"""Independent black-box red-team for D-17 client authentication.

Every server in this file binds to loopback port 0 and every database lives in
a TemporaryDirectory. The suite has no code path for discovering or contacting
an installed/live Attacca server.
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


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_d17_auth_redteam_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)
protocol, _sync_server = c._sync_runtime()


class D17AuthRedTeam(unittest.TestCase):
    ALICE_ACTORS = (
        ("alpha.director.codex", "director", "codex"),
        ("alpha.director.claude", "director", "claude"),
        ("alpha.worker.kimi", "worker", "kimi"),
        ("alpha.advisor.generic", "advisor", "generic"),
        ("beta.director.codex", "director", "codex"),
        ("beta.director.claude", "director", "claude"),
    )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "redteam.db"
        conn = c.connect(self.db)
        try:
            c.auth_create_user(
                conn, "alice", "alice-password", display_name="Alice",
                is_admin=True, bootstrap=True)
            c.auth_create_user(
                conn, "bob", "bob-password", display_name="Bob")
            c.auth_create_user(
                conn, "admin2", "admin2-password", display_name="Admin Two",
                is_admin=True)
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
                conn, "web.alice", "human", path=self.root / "alpha",
                project_id="alpha", name="Alpha")
            c.project_init(
                conn, "web.alice", "human", path=self.root / "beta",
                project_id="beta", name="Beta")
            for project in ("alpha", "beta"):
                c.auth_grant_project_membership(
                    conn, alice_principal, project, granted_by="alice")
            c.auth_grant_project_membership(
                conn, bob_principal, "alpha", granted_by="alice")
            for actor_id, role, runtime in self.ALICE_ACTORS:
                project = actor_id.split(".", 1)[0]
                c.agent_register(
                    conn, project, "web.alice", "human", agent_id=actor_id,
                    display_name=actor_id, role=role, runtime=runtime,
                    registration_username="alice")
            c.set_current_owner("bob")
            c.agent_register(
                conn, "alpha", "web.bob", "human",
                agent_id="alpha.worker.bob", display_name="Bob Worker",
                role="worker", runtime="other",
                registration_username="bob")
            c.set_current_owner("alice")
            c.set_lead_director(
                conn, "alpha", "web.alice", "human",
                "alpha.director.codex")
            c.set_lead_director(
                conn, "beta", "web.alice", "human",
                "beta.director.codex")
        finally:
            c.set_current_owner(None)
            conn.close()

        self.server = c.AttaccaServer(
            ("127.0.0.1", 0), self.db, auth=True, auth_mode="auto")
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address
        self.alice = self.login("alice", "alice-password")
        self.bob = self.login("bob", "bob-password")
        self.admin2 = self.login("admin2", "admin2-password")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())
        c.set_current_owner(None)
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(
            self.host, self.port, timeout=10)
        encoded = None if body is None else json.dumps(body).encode("utf-8")
        merged = {"Accept": "application/json", **(headers or {})}
        if encoded is not None:
            merged["Content-Type"] = "application/json"
        connection.request(method, path, body=encoded, headers=merged)
        response = connection.getresponse()
        raw = response.read()
        content_type = response.headers.get("Content-Type") or ""
        value = (json.loads(raw) if raw and "json" in content_type
                 else raw.decode("utf-8", "replace") if raw else {})
        result = {"status": response.status, "headers": response.headers,
                  "body": value}
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
            "Cookie": "; ".join("%s=%s" % item for item in cookies.items()),
            "X-Attacca-CSRF": cookies["attacca_csrf"],
        }

    def login(self, username, password):
        response = self.request("POST", "/v1/auth/login", {
            "username": username, "password": password})
        self.assertEqual(response["status"], 200, response["body"])
        return self.session_headers(response)

    def create_client(self, *, session=None, instance="client-alice",
                      projects=("alpha",), device=None, label="D-17 client",
                      expires_at=None):
        body = {
            "label": label,
            "client_instance": instance,
            "project_memberships": list(projects),
        }
        if device is not None:
            body["device_id"] = device
        if expires_at is not None:
            body["expires_at"] = expires_at
        return self.request(
            "POST", "/v1/auth/client-keys", body, session or self.alice)

    @staticmethod
    def client_headers(result, actor, *, project="alpha",
                       instance="client-alice", device=None,
                       owner="mallory", branch=None, revision=None):
        headers = {
            "Authorization": "Bearer " + result["token"],
            "X-Attacca-Client-Instance": instance,
            "X-Attacca-Project": project,
            "X-Attacca-Actor": actor,
            # This must never override the authenticated human.
            "X-Attacca-Owner": owner,
        }
        if device is not None:
            headers["X-Attacca-Device-ID"] = device
        if branch is not None:
            headers[c.GIT_BRANCH_HEADER] = branch
        if revision is not None:
            headers[c.GIT_REVISION_HEADER] = revision
        return headers

    def create_service(self, *, session=None, label="red-team service",
                       projects=("alpha",), actors=(), expires_at=None):
        body = {
            "label": label,
            "project_memberships": list(projects),
            "actor_bindings": [{
                "project_id": actor.split(".", 1)[0], "actor_id": actor,
            } for actor in actors],
        }
        if expires_at is not None:
            body["expires_at"] = expires_at
        return self.request(
            "POST", "/v1/auth/service-keys", body,
            session or self.alice)

    @staticmethod
    def service_headers(result, *, project=None, actor=None,
                        owner="mallory", device="service-device",
                        instance="service-instance", branch=None,
                        revision=None):
        headers = {
            "Authorization": "Bearer " + result["token"],
            "X-Attacca-Owner": owner,
            "X-Attacca-Device-ID": device,
            "X-Attacca-Client-Instance": instance,
        }
        if project:
            headers["X-Attacca-Project"] = project
        if actor:
            headers["X-Attacca-Actor"] = actor
        if branch:
            headers[c.GIT_BRANCH_HEADER] = branch
        if revision:
            headers[c.GIT_REVISION_HEADER] = revision
        return headers

    def create_invitation(self, *, session=None, label="red-team invite",
                          projects=("alpha",), is_admin=False,
                          expires_at=None):
        body = {
            "label": label,
            "project_memberships": list(projects),
            "is_admin": is_admin,
        }
        if expires_at is not None:
            body["expires_at"] = expires_at
        return self.request(
            "POST", "/v1/auth/invitations", body,
            session or self.alice)

    def activate(self, enabled=True):
        return self.request("POST", "/v1/auth/activation", {
            "confirmed": True, "enabled": enabled,
        }, self.alice)

    def actor_state(self):
        conn = c.connect(self.db)
        try:
            return {
                "agents": [tuple(row) for row in conn.execute(
                    "SELECT project_id,agent_id,display_name,role,runtime,"
                    "owner,actor_type,registered_at FROM agents"
                    " ORDER BY project_id,agent_id")],
                "leads": [tuple(row) for row in conn.execute(
                    "SELECT project_id,lead_director FROM projects"
                    " ORDER BY project_id")],
            }
        finally:
            conn.close()

    def mcp_initialize(self, headers, name="redteam-client"):
        request_headers = {
            **headers, "Accept": "application/json, text/event-stream"}
        response = self.request("POST", "/mcp", {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": name, "version": "redteam"},
            },
        }, request_headers)
        self.assertEqual(response["status"], 200, response["body"])
        session_id = response["headers"].get("Mcp-Session-Id")
        self.assertTrue(session_id)
        return session_id, request_headers

    def mcp_call(self, headers, session_id, name, arguments=None):
        return self.request("POST", "/mcp", {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }, {**headers, "Mcp-Session-Id": session_id})

    def test_account_session_csrf_membership_and_logout_fail_closed(self):
        wrong = self.request("POST", "/v1/auth/login", {
            "username": "bob", "password": "wrong-password"})
        self.assertEqual(wrong["status"], 401, wrong["body"])

        listed = self.request("GET", "/v1/projects", headers=self.bob)
        self.assertEqual(listed["status"], 200, listed["body"])
        self.assertEqual(
            [item["project_id"] for item in listed["body"]["projects"]],
            ["alpha"])
        self.assertEqual(self.request(
            "GET", "/v1/projects/beta/status",
            headers=self.bob)["status"], 403)

        cookie_only = {"Cookie": self.bob["Cookie"]}
        csrf_denied = self.request(
            "POST", "/v1/projects/alpha/room",
            {"body": "CSRF must not land"}, cookie_only)
        self.assertEqual(csrf_denied["status"], 403, csrf_denied["body"])

        human_token = self.request("POST", "/v1/auth/tokens", {
            "label": "Bob human API", "actor_type": "human",
        }, self.bob)
        self.assertEqual(human_token["status"], 201, human_token["body"])
        token_headers = {
            "Authorization": "Bearer " + human_token["body"]["token"]}
        token_projects = self.request(
            "GET", "/v1/projects", headers=token_headers)
        self.assertEqual(
            [item["project_id"] for item in token_projects["body"]["projects"]],
            ["alpha"])
        self.assertEqual(self.request(
            "GET", "/v1/projects/beta/status",
            headers=token_headers)["status"], 403)

        temporary = self.request("POST", "/v1/auth/login", {
            "username": "bob", "password": "bob-password"})
        temporary_headers = self.session_headers(temporary)
        logged_out = self.request(
            "POST", "/v1/auth/logout", {}, temporary_headers)
        self.assertEqual(logged_out["status"], 200, logged_out["body"])
        after = self.request(
            "GET", "/v1/auth/status", headers=temporary_headers)
        self.assertFalse(after["body"]["authenticated"])
        # Access readiness is intentionally public before enforcement, but a
        # logged-out cookie receives no account-owned secrets or records.
        sanitized = self.request(
            "GET", "/v1/auth/access", headers=temporary_headers)
        self.assertEqual(sanitized["status"], 200, sanitized["body"])
        self.assertEqual(sanitized["body"]["client_keys"], [])
        self.assertEqual(sanitized["body"]["invitations"], [])

    def test_project_creation_and_concurrent_actor_creation_have_one_owner(self):
        created = self.request("POST", "/v1/projects", {
            "project_id": "bob-new", "name": "Bob New",
        }, self.bob)
        self.assertEqual(created["status"], 200, created["body"])
        relisted = self.request("GET", "/v1/projects", headers=self.bob)
        self.assertEqual(
            {item["project_id"] for item in relisted["body"]["projects"]},
            {"alpha", "bob-new"})

        conn = c.connect(self.db)
        try:
            c.auth_create_user(
                conn, "charlie", "charlie-password", display_name="Charlie")
            charlie = conn.execute(
                "SELECT * FROM auth_users WHERE username='charlie'").fetchone()
            c.auth_grant_project_membership(
                conn, dict(charlie), "alpha", granted_by="alice")
        finally:
            conn.close()
        charlie_session = self.login("charlie", "charlie-password")
        actor_id = "alpha.worker.race"
        barrier = threading.Barrier(3)
        responses = []
        lock = threading.Lock()

        def create(headers):
            barrier.wait(timeout=10)
            response = self.request(
                "POST", "/v1/projects/alpha/agents", {
                    "agent_id": actor_id, "display_name": "Race Worker",
                    "role": "worker", "runtime": "race",
                }, headers)
            with lock:
                responses.append(response)

        workers = [threading.Thread(target=create, args=(headers,))
                   for headers in (self.bob, charlie_session)]
        for worker in workers:
            worker.start()
        barrier.wait(timeout=10)
        for worker in workers:
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive())
        self.assertEqual(sorted(item["status"] for item in responses),
                         [200, 403], responses)
        conn = c.connect(self.db)
        try:
            rows = conn.execute(
                "SELECT owner,role,runtime FROM agents"
                " WHERE project_id='alpha' AND agent_id=?", (actor_id,)
            ).fetchall()
            self.assertEqual(len(rows), 1)
            self.assertIn(rows[0]["owner"], ("bob", "charlie"))
            self.assertEqual((rows[0]["role"], rows[0]["runtime"]),
                             ("worker", "race"))
        finally:
            conn.close()

    def test_member_cannot_take_over_or_reauthor_existing_actor(self):
        victim = "alpha.director.codex"
        before = self.actor_state()
        for body in (
                {"agent_id": victim, "display_name": "forged owner",
                 "role": "director", "runtime": "codex"},
                {"agent_id": victim, "role": "worker", "runtime": "kimi"},
                {"agent_id": "codex", "canonical_identity": True,
                 "role": "director", "runtime": "codex"}):
            denied = self.request(
                "POST", "/v1/projects/alpha/agents", body, self.bob)
            self.assertEqual(denied["status"], 403, denied["body"])
        self.assertEqual(self.actor_state(), before)

        own = {
            "agent_id": "alpha.worker.bob-new", "display_name": "Bob New",
            "role": "worker", "runtime": "codex",
        }
        first = self.request(
            "POST", "/v1/projects/alpha/agents", own, self.bob)
        second = self.request(
            "POST", "/v1/projects/alpha/agents", own, self.bob)
        self.assertEqual(first["status"], 200, first["body"])
        self.assertEqual(second["status"], 200, second["body"])
        self.assertFalse(first["body"]["already_registered"])
        self.assertTrue(second["body"]["already_registered"])
        changed = self.request(
            "POST", "/v1/projects/alpha/agents",
            {**own, "role": "advisor"}, self.bob)
        self.assertEqual(changed["status"], 403, changed["body"])

        bob_client = self.create_client(
            session=self.bob, instance="client-bob")
        self.assertEqual(bob_client["status"], 201, bob_client["body"])
        self.activate()
        stolen = self.request(
            "GET", "/v1/projects/alpha/status",
            headers=self.client_headers(
                bob_client["body"], victim, instance="client-bob"))
        self.assertEqual(stolen["status"], 403, stolen["body"])
        self.assertEqual(self.actor_state()["leads"], before["leads"])

    def test_one_client_key_selects_owned_actors_without_binding_or_rewrite(self):
        before = self.actor_state()
        created = self.create_client(
            projects=("alpha", "beta"), device="home-device")
        self.assertEqual(created["status"], 201, created["body"])
        result = created["body"]
        raw = result["token"]
        token_id = result["record"]["token_id"]
        self.assertTrue(raw.startswith("atkey_"))
        self.assertNotIn(raw, json.dumps(self.request(
            "GET", "/v1/auth/client-keys", headers=self.alice)["body"]))
        conn = c.connect(self.db)
        try:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM auth_token_actor_bindings"
                " WHERE token_id=?", (token_id,)).fetchone()["n"], 0)
            dump = "\n".join(conn.iterdump())
            self.assertNotIn(raw, dump)
            self.assertIn(c.sha256_hex(raw), dump)
        finally:
            conn.close()

        self.assertEqual(self.activate()["status"], 200)
        actors = (
            ("alpha", "alpha.director.codex"),
            ("alpha", "alpha.director.claude"),
            ("alpha", "alpha.worker.kimi"),
            ("beta", "beta.director.codex"),
        )
        for project, actor in actors:
            with self.subTest(project=project, actor=actor):
                response = self.request(
                    "GET", "/v1/projects/%s/status" % project,
                    headers=self.client_headers(
                        result, actor, project=project,
                        device="home-device"))
                self.assertEqual(response["status"], 200, response["body"])
        self.assertEqual(self.actor_state(), before)

        wrong_instance = self.client_headers(
            result, "alpha.director.codex", instance="other-client",
            device="home-device")
        self.assertEqual(self.request(
            "GET", "/v1/projects/alpha/status",
            headers=wrong_instance)["status"], 403)
        wrong_device = self.client_headers(
            result, "alpha.director.codex", device="other-device")
        self.assertEqual(self.request(
            "GET", "/v1/projects/alpha/status",
            headers=wrong_device)["status"], 403)
        bob_actor = self.client_headers(
            result, "alpha.worker.bob", device="home-device")
        self.assertEqual(self.request(
            "GET", "/v1/projects/alpha/status",
            headers=bob_actor)["status"], 403)

        posted = self.request(
            "POST", "/v1/projects/alpha/room", {
                "body": "immutable client attribution", "msg_type": "status",
            }, self.client_headers(
                result, "alpha.director.claude", device="home-device",
                owner="forged-owner", branch="feature/redteam",
                revision="abc123def"))
        self.assertEqual(posted["status"], 200, posted["body"])
        conn = c.connect(self.db)
        try:
            event = conn.execute(
                "SELECT * FROM events WHERE project_id='alpha'"
                " AND event_type='room.message'"
                " AND payload LIKE '%immutable client attribution%'"
                " ORDER BY seq DESC LIMIT 1").fetchone()
            self.assertEqual(event["actor_id"], "alpha.director.claude")
            self.assertEqual(event["owner"], "alice")
            self.assertEqual(event["device_id"],
                             "home-device/client-alice")
            self.assertEqual(event["git_branch"], "feature/redteam")
            self.assertEqual(event["base_revision"], "abc123def")
        finally:
            conn.close()

    def test_membership_expiry_disable_and_revocation_are_dynamic(self):
        created = self.create_client()
        self.assertEqual(created["status"], 201, created["body"])
        result = created["body"]
        token_id = result["record"]["token_id"]
        headers = self.client_headers(result, "alpha.director.codex")
        self.activate()
        self.assertEqual(self.request(
            "GET", "/v1/projects/alpha/status", headers=headers)["status"],
            200)

        conn = c.connect(self.db)
        try:
            alice = conn.execute(
                "SELECT user_id FROM auth_users WHERE username='alice'"
            ).fetchone()["user_id"]
            conn.execute(
                "UPDATE auth_project_memberships SET revoked_at=?"
                " WHERE user_id=? AND project_id='alpha'",
                (c.now_iso(), alice))
        finally:
            conn.close()
        denied = self.request(
            "GET", "/v1/projects/alpha/status", headers=headers)
        self.assertEqual(denied["status"], 403, denied["body"])

        conn = c.connect(self.db)
        try:
            conn.execute(
                "UPDATE auth_project_memberships SET revoked_at=NULL"
                " WHERE user_id=(SELECT user_id FROM auth_users"
                " WHERE username='alice') AND project_id='alpha'")
            conn.execute(
                "UPDATE auth_tokens SET expires_at=? WHERE token_id=?",
                ("2000-01-01T00:00:00.000Z", token_id))
        finally:
            conn.close()
        self.assertEqual(self.request(
            "GET", "/v1/projects/alpha/status", headers=headers)["status"],
            401)

        replacement = self.create_client(instance="client-replacement")
        self.assertEqual(replacement["status"], 201, replacement["body"])
        replacement_headers = self.client_headers(
            replacement["body"], "alpha.director.codex",
            instance="client-replacement")
        conn = c.connect(self.db)
        try:
            conn.execute(
                "UPDATE auth_users SET disabled_at=? WHERE username='alice'",
                (c.now_iso(),))
        finally:
            conn.close()
        self.assertEqual(self.request(
            "GET", "/v1/projects/alpha/status",
            headers=replacement_headers)["status"], 401)

    def test_client_key_mcp_requires_exact_project_actor_and_stays_attributed(self):
        created = self.create_client(device="mcp-device")
        self.assertEqual(created["status"], 201, created["body"])
        self.activate()
        headers = self.client_headers(
            created["body"], "alpha.director.codex",
            device="mcp-device", branch="feature/mcp",
            revision="feedface")
        session_id, mcp_headers = self.mcp_initialize(headers)
        sent = self.mcp_call(mcp_headers, session_id, "room_send", {
            "body": "D-17 MCP exact actor",
        })
        self.assertEqual(sent["status"], 200, sent["body"])
        self.assertFalse(sent["body"]["result"]["isError"], sent["body"])

        conn = c.connect(self.db)
        try:
            event = conn.execute(
                "SELECT * FROM events WHERE project_id='alpha'"
                " AND event_type='room.message'"
                " AND payload LIKE '%D-17 MCP exact actor%'"
                " ORDER BY seq DESC LIMIT 1").fetchone()
            self.assertEqual(event["actor_id"], "alpha.director.codex")
            self.assertEqual(event["owner"], "alice")
            self.assertEqual(event["git_branch"], "feature/mcp")
            self.assertEqual(event["base_revision"], "feedface")
        finally:
            conn.close()

        missing_actor = dict(headers)
        missing_actor.pop("X-Attacca-Actor")
        denied = self.request("POST", "/mcp", {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18",
                       "capabilities": {},
                       "clientInfo": {"name": "missing", "version": "1"}},
        }, {**missing_actor,
            "Accept": "application/json, text/event-stream"})
        self.assertEqual(denied["status"], 403, denied["body"])

    def test_bridge_governance_requires_both_workspace_authorities(self):
        alpha_actor = "alpha.director.codex"
        limited = self.create_client(projects=("alpha",))
        self.assertEqual(limited["status"], 201, limited["body"])
        denied = self.request(
            "POST", "/v1/projects/alpha/bridges", {
                "other_project": "beta",
            }, self.client_headers(limited["body"], alpha_actor))
        self.assertEqual(denied["status"], 403, denied["body"])
        self.assertIn("outside key scope", denied["body"]["error"])

        dual = self.create_client(
            instance="client-dual", projects=("alpha", "beta"))
        self.assertEqual(dual["status"], 201, dual["body"])
        dual_headers = self.client_headers(
            dual["body"], alpha_actor, instance="client-dual")
        created = self.request(
            "POST", "/v1/projects/alpha/bridges", {
                "other_project": "beta",
            }, dual_headers)
        self.assertEqual(created["status"], 200, created["body"])
        updated = self.request(
            "PUT", "/v1/projects/alpha/bridges/beta", {
                "relationship": "advisor", "principal": "alpha",
            }, dual_headers)
        self.assertEqual(updated["status"], 200, updated["body"])

        bob_denied = self.request(
            "DELETE", "/v1/projects/alpha/bridges/beta", headers=self.bob)
        self.assertEqual(bob_denied["status"], 403, bob_denied["body"])
        conn = c.connect(self.db)
        try:
            bob = conn.execute(
                "SELECT * FROM auth_users WHERE username='bob'").fetchone()
            c.auth_grant_project_membership(
                conn, dict(bob), "beta", granted_by="alice")
        finally:
            conn.close()
        removed = self.request(
            "DELETE", "/v1/projects/alpha/bridges/beta", headers=self.bob)
        self.assertEqual(removed["status"], 200, removed["body"])

    def test_invitations_are_owner_scoped_one_time_and_secret_safe(self):
        self.assertEqual(self.create_invitation(
            session=self.bob)["status"], 403)
        self.assertEqual(self.create_invitation(
            session=self.admin2, is_admin=True)["status"], 403)
        created = self.create_invitation(label="Carol alpha")
        self.assertEqual(created["status"], 201, created["body"])
        raw = created["body"]["invitation_token"]
        invitation_id = created["body"]["record"]["invitation_id"]
        self.assertTrue(raw.startswith("ati_"))
        listed = self.request(
            "GET", "/v1/auth/invitations", headers=self.alice)
        self.assertNotIn(raw, json.dumps(listed["body"], sort_keys=True))
        conn = c.connect(self.db)
        try:
            dump = "\n".join(conn.iterdump())
            self.assertNotIn(raw, dump)
            self.assertIn(c.sha256_hex(raw), dump)
        finally:
            conn.close()

        self.activate()
        accepted = self.request(
            "POST", "/v1/auth/invitations/accept", {
                "invitation_token": raw, "username": "carol",
                "password": "carol-password", "display_name": "Carol",
                "project_memberships": ["beta"], "is_admin": True,
            })
        self.assertEqual(accepted["status"], 201, accepted["body"])
        self.assertEqual(accepted["body"]["project_memberships"], ["alpha"])
        self.assertFalse(accepted["body"]["user"]["is_admin"])
        replay = self.request(
            "POST", "/v1/auth/invitations/accept", {
                "invitation_token": raw, "username": "replay",
                "password": "replay-password",
            })
        self.assertEqual(replay["status"], 401, replay["body"])
        conn = c.connect(self.db)
        try:
            row = conn.execute(
                "SELECT * FROM auth_invitations WHERE invitation_id=?",
                (invitation_id,)).fetchone()
            self.assertIsNotNone(row["accepted_at"])
        finally:
            conn.close()

    def test_invitation_collision_expiry_and_concurrent_replay_are_atomic(self):
        collision = self.create_invitation(label="collision")
        raw = collision["body"]["invitation_token"]
        duplicate = self.request(
            "POST", "/v1/auth/invitations/accept", {
                "invitation_token": raw, "username": "alice",
                "password": "new-password",
            })
        self.assertEqual(duplicate["status"], 400, duplicate["body"])
        retry = self.request(
            "POST", "/v1/auth/invitations/accept", {
                "invitation_token": raw, "username": "dave",
                "password": "dave-password",
            })
        self.assertEqual(retry["status"], 201, retry["body"])

        expired = self.create_invitation(label="expired")
        conn = c.connect(self.db)
        try:
            conn.execute(
                "UPDATE auth_invitations SET expires_at=?"
                " WHERE invitation_id=?",
                ("2000-01-01T00:00:00.000Z",
                 expired["body"]["record"]["invitation_id"]))
        finally:
            conn.close()
        self.assertEqual(self.request(
            "POST", "/v1/auth/invitations/accept", {
                "invitation_token": expired["body"]["invitation_token"],
                "username": "expired", "password": "expired-password",
            })["status"], 401)

        concurrent = self.create_invitation(label="concurrent")
        token = concurrent["body"]["invitation_token"]
        barrier = threading.Barrier(3)
        results = []
        lock = threading.Lock()

        def accept(name):
            barrier.wait(timeout=10)
            response = self.request(
                "POST", "/v1/auth/invitations/accept", {
                    "invitation_token": token, "username": name,
                    "password": name + "-password",
                })
            with lock:
                results.append(response)

        workers = [threading.Thread(target=accept, args=(name,))
                   for name in ("race-one", "race-two")]
        for worker in workers:
            worker.start()
        barrier.wait(timeout=10)
        for worker in workers:
            worker.join(timeout=15)
            self.assertFalse(worker.is_alive())
        self.assertEqual(sorted(item["status"] for item in results),
                         [201, 401], results)

    def test_bound_service_is_exact_scoped_attributed_and_secret_safe(self):
        actor = "alpha.director.codex"
        before = self.actor_state()
        created = self.create_service(actors=(actor,))
        self.assertEqual(created["status"], 201, created["body"])
        result = created["body"]
        raw = result["token"]
        token_id = result["record"]["token_id"]
        self.assertTrue(raw.startswith("atsvc_"))
        self.assertEqual(self.actor_state(), before)
        listed = self.request(
            "GET", "/v1/auth/service-keys", headers=self.alice)
        self.assertNotIn(raw, json.dumps(listed["body"], sort_keys=True))

        headers = self.service_headers(
            result, project="alpha", actor=actor,
            owner="forged-human", instance="service-one",
            branch="feature/service", revision="abc123")
        posted = self.request(
            "POST", "/v1/projects/alpha/room", {
                "body": "bound service attribution", "msg_type": "status",
            }, headers)
        self.assertEqual(posted["status"], 200, posted["body"])
        conn = c.connect(self.db)
        try:
            event = conn.execute(
                "SELECT * FROM events WHERE project_id='alpha'"
                " AND event_type='room.message'"
                " AND payload LIKE '%bound service attribution%'"
                " ORDER BY seq DESC LIMIT 1").fetchone()
            self.assertEqual(event["actor_id"], actor)
            self.assertEqual(event["owner"], "alice")
            self.assertEqual(event["device_id"],
                             "service-device/service-one")
        finally:
            conn.close()

        wrong_actor = self.service_headers(
            result, project="alpha", actor="alpha.worker.kimi")
        self.assertEqual(self.request(
            "GET", "/v1/projects/alpha/status",
            headers=wrong_actor)["status"], 403)
        wrong_project = self.service_headers(
            result, project="beta", actor=actor)
        self.assertEqual(self.request(
            "GET", "/v1/projects/beta/status",
            headers=wrong_project)["status"], 403)
        self.assertEqual(self.create_service(
            session=self.bob, actors=(actor,))["status"], 403)
        self.assertEqual(self.request(
            "DELETE", "/v1/auth/service-keys/%s" % token_id,
            headers=self.bob)["status"], 403)
        revoked = self.request(
            "DELETE", "/v1/auth/service-keys/%s" % token_id,
            headers=self.alice)
        self.assertEqual(revoked["status"], 200, revoked["body"])
        self.assertEqual(self.request(
            "GET", "/v1/projects/alpha/status", headers=headers)["status"],
            401)

    def test_unbound_service_is_read_only_and_cannot_escalate(self):
        created = self.create_service(actors=())
        self.assertEqual(created["status"], 201, created["body"])
        result = created["body"]
        scoped = self.service_headers(result, project="alpha")
        self.assertEqual(self.request(
            "GET", "/v1/projects/alpha/status",
            headers=scoped)["status"], 200)
        conn = c.connect(self.db)
        try:
            before_events = conn.execute(
                "SELECT COUNT(*) AS n FROM events"
            ).fetchone()["n"]
            before_cursors = conn.execute(
                "SELECT COUNT(*) AS n FROM inbox_cursors"
            ).fetchone()["n"]
        finally:
            conn.close()
        inbox = self.request(
            "GET", "/v1/projects/alpha/inbox", headers=scoped)
        self.assertEqual(inbox["status"], 200, inbox["body"])

        forbidden = (
            ("GET", "/v1/projects/alpha/export", None, scoped),
            ("GET", "/v1/auth/client-keys", None, scoped),
            ("GET", "/v1/auth/service-keys", None, scoped),
            ("POST", "/v1/auth/client-keys", {
                "label": "nested", "client_instance": "nested",
            }, scoped),
            ("POST", "/v1/auth/activation", {
                "confirmed": True, "enabled": True,
            }, scoped),
            ("POST", "/v1/projects", {
                "project_id": "service-escape", "name": "Escape",
            }, self.service_headers(result)),
            ("POST", "/v1/projects/alpha/room", {
                "body": "service write must not land",
            }, scoped),
            ("POST", "/v1/projects/alpha/tasks", {
                "title": "service task must not land",
            }, scoped),
        )
        for method, path, body, headers in forbidden:
            with self.subTest(method=method, path=path):
                response = self.request(method, path, body, headers)
                self.assertIn(response["status"], (401, 403), response)
        conn = c.connect(self.db)
        try:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM events").fetchone()["n"],
                before_events)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM inbox_cursors").fetchone()["n"],
                before_cursors)
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM projects WHERE project_id='service-escape'"
            ).fetchone())
        finally:
            conn.close()

    def test_unbound_service_sync_projection_is_read_only(self):
        created = self.create_service(actors=())
        self.assertEqual(created["status"], 201, created["body"])
        headers = self.service_headers(created["body"], project="alpha")
        snapshot = self.request(
            "GET", "/v1/projects/alpha/sync/snapshot", headers=headers)
        self.assertEqual(snapshot["status"], 200, snapshot["body"])
        protocol.validate_snapshot(snapshot["body"])
        self.assertEqual(snapshot["body"]["scope"]["actor_type"], "tool")
        self.assertEqual(snapshot["body"]["scope"]["role"], "unassigned")

        mutation = protocol.make_client_mutation(
            snapshot["body"]["scope"], "service_mutation_0001",
            "service-instance", "service-device", 1, "room.send",
            {"body": "must not push"}, snapshot["body"]["cursor"])
        envelope = protocol.make_push_request(
            snapshot["body"]["scope"],
            snapshot["body"]["visibility_fingerprint"],
            "service-instance", "service-device", [mutation])
        denied = self.request(
            "POST", "/v1/projects/alpha/sync/push", envelope, headers)
        self.assertEqual(denied["status"], 403, denied["body"])

    def test_activated_global_settings_are_owner_browser_session_only(self):
        self.assertEqual(self.activate()["status"], 200)
        before = self.request("GET", "/v1/settings", headers=self.alice)
        self.assertEqual(before["status"], 200, before["body"])
        for session in (self.bob, self.admin2):
            denied = self.request(
                "PUT", "/v1/settings", {"verbose": True}, session)
            self.assertEqual(denied["status"], 403, denied["body"])

        client = self.create_client(
            instance="settings-client", projects=("alpha",))
        self.assertEqual(client["status"], 201, client["body"])
        client_headers = self.client_headers(
            client["body"], "alpha.director.codex",
            instance="settings-client")
        self.assertEqual(self.request(
            "GET", "/v1/settings", headers=client_headers)["status"], 200)
        self.assertEqual(self.request(
            "PUT", "/v1/settings", {"verbose": True},
            client_headers)["status"], 403)

        changed = self.request(
            "PUT", "/v1/settings", {"verbose": True}, self.alice)
        self.assertEqual(changed["status"], 200, changed["body"])
        self.assertTrue(changed["body"]["verbose"])

    def test_room_origin_header_cannot_escape_membership_or_forge_actor(self):
        conn = c.connect(self.db)
        try:
            before = [tuple(row) for row in conn.execute(
                "SELECT * FROM events ORDER BY project_id,seq")]
        finally:
            conn.close()
        forged = self.request(
            "POST", "/v1/projects/alpha/room", {
                "body": "forged beta origin", "msg_type": "chat",
            }, {**self.bob,
                "X-Attacca-Project": "beta",
                "X-Attacca-Actor": "alpha.director.codex",
                "X-Attacca-Owner": "alice"})
        self.assertEqual(forged["status"], 403, forged["body"])
        self.assertIn("rest_project_header_mismatch", forged["body"]["error"])
        unknown = self.request(
            "POST", "/v1/projects/alpha/room", {
                "body": "unknown origin", "msg_type": "chat",
            }, {**self.bob, "X-Attacca-Project": "secret-unknown"})
        self.assertEqual(unknown["status"], 403, unknown["body"])
        self.assertNotIn("Known projects", unknown["body"]["error"])
        conn = c.connect(self.db)
        try:
            self.assertEqual([tuple(row) for row in conn.execute(
                "SELECT * FROM events ORDER BY project_id,seq")], before)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
