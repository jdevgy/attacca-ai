"""Independent black-box red-team for human-owned terminal credentials.

Every server in this file binds to loopback port 0 and every database lives in
a TemporaryDirectory.  The suite deliberately has no code path for discovering
or contacting an installed/live Attacca server.
"""

import http.client
import http.cookies
import hmac
import importlib.util
import json
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_terminal_auth_redteam_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)
FLOW_SPEC = importlib.util.spec_from_file_location(
    "attacca_terminal_auth_redteam_client", ROOT / "terminal_flow.py")
flow_client = importlib.util.module_from_spec(FLOW_SPEC)
sys.modules[FLOW_SPEC.name] = flow_client
FLOW_SPEC.loader.exec_module(flow_client)


class TerminalAuthRedTeam(unittest.TestCase):
    """Exercise the public HTTP boundary, not backend helper return values."""

    ALPHA_ACTORS = (
        ("alpha.director.codex-exact", "director", "codex", "alice"),
        ("alpha.director.claude-exact", "director", "claude", "alice"),
        ("alpha.worker.kimi-exact", "worker", "kimi", "alice"),
        ("alpha.worker.codex-unbound", "worker", "codex", "alice"),
        ("alpha.worker.claude-bob", "worker", "claude", "bob"),
    )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "redteam.db"
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
            c.set_current_owner("alice")
            c.project_init(
                conn, "web.alice", "human",
                path=Path(self.temp.name) / "alpha", project_id="alpha",
                name="Alpha")
            c.project_init(
                conn, "web.alice", "human",
                path=Path(self.temp.name) / "beta", project_id="beta",
                name="Beta")
            for actor_id, role, runtime, owner in self.ALPHA_ACTORS:
                c.set_current_owner(owner)
                c.agent_register(
                    conn, "alpha", "web.%s" % owner, "human",
                    agent_id=actor_id, display_name=actor_id,
                    role=role, runtime=runtime)
            c.set_current_owner("alice")
            c.agent_register(
                conn, "beta", "web.alice", "human",
                agent_id="beta.director.codex-exact",
                display_name="Beta Codex", role="director", runtime="codex")
            c.set_lead_director(
                conn, "alpha", "web.alice", "human",
                "alpha.director.codex-exact")
            c.set_lead_director(
                conn, "beta", "web.alice", "human",
                "beta.director.codex-exact")
            bob = conn.execute(
                "SELECT user_id FROM auth_users WHERE username='bob'"
            ).fetchone()
            conn.execute(
                "INSERT INTO auth_project_memberships"
                " (user_id,project_id,granted_at,granted_by)"
                " VALUES (?,?,?,?)",
                (bob["user_id"], "alpha", c.now_iso(), "alice"))
        finally:
            c.set_current_owner(None)
            conn.close()
        self.server = None
        self.thread = None
        self._start(auth=True, auth_mode="auto")
        self.alice = self._login("alice", "alice-password")
        self.bob = self._login("bob", "bob-password")
        self.admin2 = self._login("admin2", "admin2-password")

    def tearDown(self):
        self._stop()
        c.set_current_owner(None)
        self.temp.cleanup()

    def _start(self, *, auth=False, auth_mode="auto"):
        self.server = c.AttaccaServer(
            ("127.0.0.1", 0), self.db, auth=auth, auth_mode=auth_mode)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

    def _stop(self):
        if self.server is None:
            return
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())
        self.server = None
        self.thread = None

    def _restart(self, *, auth=False, auth_mode="auto"):
        self._stop()
        self._start(auth=auth, auth_mode=auth_mode)

    def _request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(
            self.host, self.port, timeout=10)
        raw_body = None if body is None else json.dumps(body).encode("utf-8")
        merged = {"Accept": "application/json", **(headers or {})}
        if raw_body is not None:
            merged["Content-Type"] = "application/json"
        connection.request(method, path, body=raw_body, headers=merged)
        response = connection.getresponse()
        raw = response.read()
        content_type = response.headers.get("Content-Type") or ""
        parsed = json.loads(raw) if raw and "json" in content_type \
            else raw.decode("utf-8", "replace") if raw else {}
        result = {"status": response.status,
                  "headers": response.headers, "body": parsed}
        connection.close()
        return result

    @staticmethod
    def _session_headers(response):
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

    def _login(self, username, password):
        response = self._request("POST", "/v1/auth/login", {
            "username": username, "password": password})
        self.assertEqual(response["status"], 200, response["body"])
        return self._session_headers(response)

    @staticmethod
    def _bindings(*actor_ids):
        return [{"project_id": actor_id.split(".", 1)[0],
                 "actor_id": actor_id} for actor_id in actor_ids]

    def _start_flow(self, *actors, device="home-device",
                    instance="bootstrap-instance", credential=None):
        headers = {}
        supersede = None
        if credential is not None:
            headers = self._terminal_headers(
                credential, actors[0], instance=instance)
            supersede = credential["token_id"]
        response = self._request("POST", "/v1/auth/device/start", {
            "device_id": device,
            "client_label": "Home terminal",
            "client_instance": instance,
            "requested_bindings": self._bindings(*actors),
            "supersede_token_id": supersede,
        }, headers)
        self.assertEqual(response["status"], 201, response["body"])
        return response["body"]

    def _approve(self, flow, *actors, session=None, expires_at=None):
        memberships = sorted({actor.split(".", 1)[0] for actor in actors})
        response = self._request(
            "POST", "/v1/auth/terminal-enrollments/%s/approve" %
            urllib.parse.quote(flow["user_code"], safe=""), {
                "project_memberships": memberships,
                "actor_bindings": self._bindings(*actors),
                "expires_at": expires_at,
            }, session or self.alice)
        return response

    def _poll(self, flow, *, device="home-device",
              instance="bootstrap-instance"):
        return self._request("POST", "/v1/auth/device/poll", {
            "device_code": flow["device_code"],
            "device_id": device,
            "client_instance": instance,
        })

    def _issue(self, *actors, device="home-device",
               instance="bootstrap-instance", session=None, expires_at=None,
               credential=None):
        flow = self._start_flow(
            *actors, device=device, instance=instance, credential=credential)
        approval = self._approve(
            flow, *actors, session=session, expires_at=expires_at)
        self.assertEqual(approval["status"], 200, approval["body"])
        issued = self._poll(flow, device=device, instance=instance)
        self.assertEqual(issued["status"], 200, issued["body"])
        self.assertEqual(issued["body"]["status"], "approved")
        return flow, issued["body"]["credential"]

    @staticmethod
    def _terminal_headers(credential, actor, *, project=None,
                          instance="runtime-instance", owner="mallory",
                          branch=None, revision=None):
        headers = {
            "Authorization": "Bearer " + credential["token"],
            "X-Attacca-Device-ID": credential["device_id"],
            "X-Attacca-Actor": actor,
            "X-Attacca-Client-Instance": instance,
            # Must be ignored for authenticated attribution.
            "X-Attacca-Owner": owner,
        }
        if project:
            headers["X-Attacca-Project"] = project
        if branch:
            headers[c.GIT_BRANCH_HEADER] = branch
        if revision:
            headers[c.GIT_REVISION_HEADER] = revision
        return headers

    def _create_service(self, *, session=None, label="red-team service",
                        projects=("alpha",), actors=(), expires_at=None):
        body = {
            "label": label,
            "project_memberships": list(projects),
            "actor_bindings": self._bindings(*actors),
        }
        if expires_at is not None:
            body["expires_at"] = expires_at
        return self._request(
            "POST", "/v1/auth/service-keys", body,
            session or self.alice)

    @staticmethod
    def _service_headers(result, *, project=None, actor=None,
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

    def _create_invitation(self, *, session=None, label="red-team invite",
                           projects=("alpha",), is_admin=False,
                           expires_at=None):
        body = {
            "label": label,
            "project_memberships": list(projects),
            "is_admin": is_admin,
        }
        if expires_at is not None:
            body["expires_at"] = expires_at
        return self._request(
            "POST", "/v1/auth/invitations", body,
            session or self.alice)

    def _force_temp_enforcement(self):
        """Flip only this test's TemporaryDirectory database fail-closed."""
        conn = c.connect(self.db)
        try:
            c.server_settings_store(conn, {
                "auth.activation_requested": True,
                "auth.activated": True,
                "auth.activated_by": "redteam-temp-only",
            })
        finally:
            conn.close()

    def _actor_lead_bytes(self):
        conn = c.connect(self.db)
        try:
            return {
                "agents": [tuple(row) for row in conn.execute(
                    "SELECT * FROM agents ORDER BY project_id,agent_id")],
                "projects": [tuple(row) for row in conn.execute(
                    "SELECT * FROM projects ORDER BY project_id")],
            }
        finally:
            conn.close()

    def _mcp_initialize(self, credential, actor, *, project="alpha",
                        instance="mcp-instance"):
        headers = self._terminal_headers(
            credential, actor, project=project, instance=instance)
        return self._mcp_initialize_headers(headers, instance=instance)

    def _mcp_initialize_headers(self, headers, *, instance="mcp-instance"):
        headers["Accept"] = "application/json, text/event-stream"
        response = self._request("POST", "/mcp", {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": instance, "version": "redteam"},
            },
        }, headers)
        self.assertEqual(response["status"], 200, response["body"])
        session_id = response["headers"].get("Mcp-Session-Id")
        self.assertTrue(session_id)
        return session_id, headers

    def _mcp_call(self, headers, session_id, name, arguments=None):
        return self._request("POST", "/mcp", {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }, {**headers, "Mcp-Session-Id": session_id})

    def _actor_lead_identity(self):
        conn = c.connect(self.db)
        try:
            return {
                "agents": [tuple(row) for row in conn.execute(
                    "SELECT project_id,agent_id,display_name,role,runtime,owner,"
                    "actor_type,registered_at FROM agents"
                    " ORDER BY project_id,agent_id")],
                "leads": [tuple(row) for row in conn.execute(
                    "SELECT project_id,lead_director FROM projects"
                    " ORDER BY project_id")],
            }
        finally:
            conn.close()

    def test_nonadmin_human_membership_scopes_project_rest_and_mcp(self):
        """A human login/token may see and enter only granted workspaces."""
        listed = self._request("GET", "/v1/projects", headers=self.bob)
        self.assertEqual(listed["status"], 200, listed["body"])
        self.assertEqual(
            [item["project_id"] for item in listed["body"]["projects"]],
            ["alpha"])
        self.assertEqual(self._request(
            "GET", "/v1/projects/alpha/status",
            headers=self.bob)["status"], 200)

        conn = c.connect(self.db)
        try:
            beta_events = conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE project_id='beta'"
            ).fetchone()["n"]
        finally:
            conn.close()
        denied_read = self._request(
            "GET", "/v1/projects/beta/status", headers=self.bob)
        denied_write = self._request(
            "POST", "/v1/projects/beta/room", {
                "body": "membership escape must not land",
                "msg_type": "status",
            }, self.bob)
        self.assertEqual(denied_read["status"], 403, denied_read["body"])
        self.assertEqual(denied_write["status"], 403, denied_write["body"])
        self.assertIn("project_membership_required",
                      denied_write["body"]["error"])
        conn = c.connect(self.db)
        try:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE project_id='beta'"
            ).fetchone()["n"], beta_events)
        finally:
            conn.close()

        mcp_body = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "bob-browser", "version": "redteam"},
            },
        }
        denied_mcp = self._request("POST", "/mcp", mcp_body, {
            **self.bob,
            "Accept": "application/json, text/event-stream",
            "X-Attacca-Project": "beta",
            "X-Attacca-Device-ID": "bob-browser-device",
        })
        self.assertEqual(denied_mcp["status"], 403, denied_mcp["body"])
        self.assertIn("project_membership_required",
                      denied_mcp["body"]["error"])
        allowed_mcp_headers = {
            **self.bob,
            "Accept": "application/json, text/event-stream",
            "X-Attacca-Project": "alpha",
            "X-Attacca-Device-ID": "bob-browser-device",
        }
        allowed_mcp = self._request(
            "POST", "/mcp", mcp_body, allowed_mcp_headers)
        self.assertEqual(allowed_mcp["status"], 200, allowed_mcp["body"])
        mcp_projects = self._mcp_call(
            allowed_mcp_headers,
            allowed_mcp["headers"].get("Mcp-Session-Id"), "list_projects")
        self.assertEqual(mcp_projects["status"], 200, mcp_projects["body"])
        listed_over_mcp = json.loads(
            mcp_projects["body"]["result"]["content"][0]["text"])
        self.assertEqual(
            [item["project_id"] for item in listed_over_mcp["projects"]],
            ["alpha"])

        # Human API credentials inherit the account memberships, not global
        # browser/admin visibility.
        token = self._request("POST", "/v1/auth/tokens", {
            "label": "Bob human API", "actor_type": "human",
        }, self.bob)
        self.assertEqual(token["status"], 201, token["body"])
        token_headers = {
            "Authorization": "Bearer " + token["body"]["token"],
        }
        token_list = self._request(
            "GET", "/v1/projects", headers=token_headers)
        self.assertEqual(token_list["status"], 200, token_list["body"])
        self.assertEqual(
            [item["project_id"] for item in
             token_list["body"]["projects"]], ["alpha"])
        self.assertEqual(self._request(
            "GET", "/v1/projects/beta/status",
            headers=token_headers)["status"], 403)
        self.assertEqual(self._request(
            "GET", "/v1/projects/alpha/status",
            headers=token_headers)["status"], 200)

        # Project creation remains the deliberate exception and grants only
        # the newly created workspace to its authenticated creator.
        created = self._request("POST", "/v1/projects", {
            "project_id": "bob-new", "name": "Bob New",
        }, self.bob)
        self.assertEqual(created["status"], 200, created["body"])
        relisted = self._request("GET", "/v1/projects", headers=self.bob)
        self.assertEqual(
            {item["project_id"] for item in relisted["body"]["projects"]},
            {"alpha", "bob-new"})
        self.assertEqual(self._request(
            "GET", "/v1/projects/bob-new/status",
            headers=self.bob)["status"], 200)

        admin_list = self._request("GET", "/v1/projects", headers=self.alice)
        self.assertEqual(admin_list["status"], 200, admin_list["body"])
        self.assertTrue({"alpha", "beta", "bob-new"}.issubset(
            {item["project_id"] for item in
             admin_list["body"]["projects"]}))
        self.assertEqual(self._request(
            "GET", "/v1/projects/beta/status",
            headers=self.alice)["status"], 200)

    def test_new_direct_human_project_grants_only_verified_matching_creator(self):
        conn = c.connect(self.db)
        try:
            bob = conn.execute(
                "SELECT user_id FROM auth_users WHERE username='bob'"
            ).fetchone()["user_id"]
            c.set_current_owner("bob")
            created = c.project_init(
                conn, "web.bob", "human",
                path=Path(self.temp.name) / "direct-bob",
                project_id="direct-bob", name="Direct Bob")
            self.assertFalse(created["already_existed"])
            self.assertIsNotNone(conn.execute(
                "SELECT 1 FROM auth_project_memberships"
                " WHERE user_id=? AND project_id='direct-bob'"
                " AND revoked_at IS NULL", (bob,)).fetchone())

            # Existing-project attach/retry cannot grant a new member.
            c.project_init(
                conn, "web.bob", "human",
                path=Path(self.temp.name) / "beta",
                project_id="beta", name="Beta")
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM auth_project_memberships"
                " WHERE user_id=? AND project_id='beta'"
                " AND revoked_at IS NULL", (bob,)).fetchone())

            # Owner metadata alone is insufficient when the canonical human
            # actor does not match, and an unknown user can never be granted.
            c.project_init(
                conn, "api-client", "human",
                path=Path(self.temp.name) / "header-only",
                project_id="header-only", name="Header Only")
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM auth_project_memberships"
                " WHERE user_id=? AND project_id='header-only'", (bob,)
            ).fetchone())
            c.set_current_owner("ghost")
            c.project_init(
                conn, "web.ghost", "human",
                path=Path(self.temp.name) / "unknown-owner",
                project_id="unknown-owner", name="Unknown Owner")
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM auth_project_memberships"
                " WHERE project_id='unknown-owner'"
            ).fetchone()["n"], 0)
        finally:
            c.set_current_owner(None)
            conn.close()

        header_spoof = self._request(
            "POST", "/v1/projects", {
                "project_id": "http-header-spoof",
                "name": "HTTP Header Spoof",
            }, {
                "X-Attacca-Owner": "bob",
                "X-Attacca-Actor": "web.bob",
                "X-Attacca-Actor-Type": "human",
            })
        self.assertEqual(header_spoof["status"], 200,
                         header_spoof["body"])
        conn = c.connect(self.db)
        try:
            bob = conn.execute(
                "SELECT user_id FROM auth_users WHERE username='bob'"
            ).fetchone()["user_id"]
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM auth_project_memberships"
                " WHERE user_id=? AND project_id='http-header-spoof'",
                (bob,)).fetchone())
        finally:
            conn.close()

    def test_member_cannot_take_over_or_reauthor_existing_actor(self):
        victim = "alpha.director.codex-exact"
        before = self._actor_lead_identity()

        # Even an apparently idempotent write cannot claim an actor owned by
        # another human, and an explicit role/runtime rewrite is also denied.
        foreign_idempotent = self._request(
            "POST", "/v1/projects/alpha/agents", {
                "agent_id": victim, "display_name": "forged owner",
                "role": "director", "runtime": "codex",
            }, self.bob)
        foreign_rewrite = self._request(
            "POST", "/v1/projects/alpha/agents", {
                "agent_id": victim, "role": "worker", "runtime": "kimi",
            }, self.bob)
        self.assertEqual(foreign_idempotent["status"], 403,
                         foreign_idempotent["body"])
        self.assertEqual(foreign_rewrite["status"], 403,
                         foreign_rewrite["body"])
        self.assertIn("agent_owner_mismatch",
                      foreign_idempotent["body"]["error"])

        # Canonical migration is not a bypass: it would otherwise merge and
        # delete the foreign bespoke actor before the ownership check.
        canonical_takeover = self._request(
            "POST", "/v1/projects/alpha/agents", {
                "agent_id": "codex", "canonical_identity": True,
                "role": "director", "runtime": "codex",
            }, self.bob)
        self.assertEqual(canonical_takeover["status"], 403,
                         canonical_takeover["body"])
        self.assertEqual(self._actor_lead_identity(), before)

        flow = self._start_flow(victim, device="bob-takeover-device")
        approval = self._approve(flow, victim, session=self.bob)
        self.assertEqual(approval["status"], 403, approval["body"])

        # A member can create an absent actor in its granted workspace and can
        # retry exactly; subsequent authority changes are admin-only.
        own_actor = "alpha.worker.codex-bob-new"
        body = {
            "agent_id": own_actor, "display_name": "Bob Worker",
            "role": "worker", "runtime": "codex",
        }
        created = self._request(
            "POST", "/v1/projects/alpha/agents", body, self.bob)
        repeated = self._request(
            "POST", "/v1/projects/alpha/agents", body, self.bob)
        self.assertEqual(created["status"], 200, created["body"])
        self.assertFalse(created["body"]["already_registered"])
        self.assertEqual(repeated["status"], 200, repeated["body"])
        self.assertTrue(repeated["body"]["already_registered"])
        for changes in (
                {**body, "role": "advisor"},
                {**body, "runtime": "claude"}):
            denied = self._request(
                "POST", "/v1/projects/alpha/agents", changes, self.bob)
            self.assertEqual(denied["status"], 403, denied["body"])
            self.assertIn("agent_registration_not_idempotent",
                          denied["body"]["error"])
        conn = c.connect(self.db)
        try:
            row = conn.execute(
                "SELECT owner,role,runtime FROM agents"
                " WHERE project_id='alpha' AND agent_id=?", (own_actor,)
            ).fetchone()
            self.assertEqual(tuple(row), ("bob", "worker", "codex"))
        finally:
            conn.close()

    def test_concurrent_member_actor_and_project_creation_have_one_owner(self):
        conn = c.connect(self.db)
        try:
            c.auth_create_user(
                conn, "charlie", "charlie-password", display_name="Charlie")
            charlie = conn.execute(
                "SELECT user_id FROM auth_users WHERE username='charlie'"
            ).fetchone()["user_id"]
            conn.execute(
                "INSERT INTO auth_project_memberships"
                " (user_id,project_id,granted_at,granted_by)"
                " VALUES (?,?,?,?)",
                (charlie, "alpha", c.now_iso(), "redteam"))
        finally:
            conn.close()
        charlie_session = self._login("charlie", "charlie-password")

        def race(path, body):
            barrier = threading.Barrier(3)
            responses = []

            def send(headers):
                barrier.wait(timeout=10)
                responses.append(self._request(
                    "POST", path, body, headers))

            threads = [
                threading.Thread(target=send, args=(self.bob,)),
                threading.Thread(target=send, args=(charlie_session,)),
            ]
            for thread in threads:
                thread.start()
            barrier.wait(timeout=10)
            for thread in threads:
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())
            self.assertEqual(sorted(item["status"] for item in responses),
                             [200, 403], responses)
            return responses

        actor_id = "alpha.worker.codex-member-race"
        race("/v1/projects/alpha/agents", {
            "agent_id": actor_id, "display_name": "Race Worker",
            "role": "worker", "runtime": "codex",
        })
        conn = c.connect(self.db)
        try:
            actors = conn.execute(
                "SELECT owner,role,runtime FROM agents"
                " WHERE project_id='alpha' AND agent_id=?", (actor_id,)
            ).fetchall()
            self.assertEqual(len(actors), 1)
            self.assertIn(actors[0]["owner"], ("bob", "charlie"))
            self.assertEqual(
                (actors[0]["role"], actors[0]["runtime"]),
                ("worker", "codex"))
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE project_id='alpha'"
                " AND event_type='agent.registered'"
                " AND payload LIKE ?", ("%%%s%%" % actor_id,)
            ).fetchone()["n"], 1)
        finally:
            conn.close()

        race("/v1/projects", {
            "project_id": "member-create-race", "name": "Member Create Race",
        })
        conn = c.connect(self.db)
        try:
            memberships = conn.execute(
                "SELECT u.username FROM auth_project_memberships m"
                " JOIN auth_users u ON u.user_id=m.user_id"
                " WHERE m.project_id='member-create-race'"
                " AND m.revoked_at IS NULL"
            ).fetchall()
            self.assertEqual(len(memberships), 1)
            self.assertIn(memberships[0]["username"], ("bob", "charlie"))
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM events"
                " WHERE project_id='member-create-race'"
                " AND event_type='project.created'"
            ).fetchone()["n"], 1)
        finally:
            conn.close()

    def test_only_activation_owner_sees_account_wide_migration_details(self):
        conn = c.connect(self.db)
        try:
            c.auth_migration_target_upsert(
                conn, "alpha", "alpha.director.codex-exact",
                "private-owner-device", selected_by="alice", required=True)
        finally:
            conn.close()

        owner_access = self._request(
            "GET", "/v1/auth/access", headers=self.alice)
        member_access = self._request(
            "GET", "/v1/auth/access", headers=self.bob)
        other_admin_access = self._request(
            "GET", "/v1/auth/access", headers=self.admin2)
        for response in (owner_access, member_access, other_admin_access):
            self.assertEqual(response["status"], 200, response["body"])
            # Non-sensitive readiness stays available to every account.
            self.assertIn("ready", response["body"]["compatibility"])
            self.assertIn("readiness_version",
                          response["body"]["compatibility"])
        self.assertIn(
            "migration_targets", owner_access["body"]["compatibility"])
        owner_serialized = json.dumps(owner_access["body"], sort_keys=True)
        self.assertIn("private-owner-device", owner_serialized)
        for response in (member_access, other_admin_access):
            compatibility = response["body"]["compatibility"]
            self.assertNotIn("migration_targets", compatibility)
            self.assertNotIn("uncovered_clients", compatibility)
            self.assertNotIn(
                "private-owner-device",
                json.dumps(response["body"], sort_keys=True))

    def test_activated_global_settings_are_owner_session_only(self):
        self._force_temp_enforcement()
        before = self._request("GET", "/v1/settings", headers=self.alice)
        self.assertEqual(before["status"], 200, before["body"])
        for session in (self.bob, self.admin2):
            denied = self._request(
                "PUT", "/v1/settings", {"verbose": True}, session)
            self.assertEqual(denied["status"], 403, denied["body"])
        unchanged = self._request("GET", "/v1/settings", headers=self.alice)
        self.assertEqual(unchanged["body"]["verbose"],
                         before["body"]["verbose"])
        changed = self._request(
            "PUT", "/v1/settings", {"verbose": True}, self.alice)
        self.assertEqual(changed["status"], 200, changed["body"])
        self.assertTrue(changed["body"]["verbose"])

    def test_bridge_governance_requires_both_workspace_authorities(self):
        alpha_actor = "alpha.director.codex-exact"
        beta_actor = "beta.director.codex-exact"

        # A member of only the route workspace cannot make a durable change
        # to the peer workspace through bridge add/update/remove.
        denied_add = self._request(
            "POST", "/v1/projects/alpha/bridges", {
                "other_project": "beta",
            }, self.bob)
        self.assertEqual(denied_add["status"], 403, denied_add["body"])
        self.assertIn("bridge_peer_membership_required",
                      denied_add["body"]["error"])
        conn = c.connect(self.db)
        try:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM bridges"
            ).fetchone()["n"], 0)
            legacy = c.auth_token_create(
                conn, "alice", "single-project actor",
                actor_id=alpha_actor, actor_type="agent",
                project_id="alpha", runtime="codex")
        finally:
            conn.close()

        # MCP applies the same secondary-workspace gate and its unscoped
        # project discovery is membership-filtered.
        sid, mcp_headers = self._mcp_initialize_headers({
            **self.bob,
            "X-Attacca-Project": "alpha",
            "X-Attacca-Device-ID": "bob-bridge-mcp-device",
        }, instance="bob-bridge-mcp")
        mcp_denied = self._mcp_call(
            mcp_headers, sid, "bridge_add", {"other_project": "beta"})
        self.assertEqual(mcp_denied["status"], 200, mcp_denied["body"])
        self.assertTrue(mcp_denied["body"]["result"]["isError"])
        self.assertIn(
            "bridge_peer_membership_required",
            mcp_denied["body"]["result"]["content"][0]["text"])

        actor_denied = self._request(
            "POST", "/v1/projects/alpha/bridges", {
                "other_project": "beta",
            }, {
                "Authorization": "Bearer " + legacy["token"],
                "X-Attacca-Project": "alpha",
                "X-Attacca-Actor": alpha_actor,
                "X-Attacca-Device-ID": "legacy-actor-device",
            })
        self.assertEqual(actor_denied["status"], 403,
                         actor_denied["body"])
        self.assertIn("bridge_peer_actor_binding_required",
                      actor_denied["body"]["error"])

        _single_flow, single_terminal = self._issue(
            alpha_actor, device="single-bridge-terminal")
        terminal_denied = self._request(
            "POST", "/v1/projects/alpha/bridges", {
                "other_project": "beta",
            }, self._terminal_headers(
                single_terminal, alpha_actor, project="alpha",
                instance="single-bridge-client"))
        self.assertEqual(terminal_denied["status"], 403,
                         terminal_denied["body"])
        self.assertIn("bridge_peer_actor_binding_required",
                      terminal_denied["body"]["error"])
        single_sid, single_mcp_headers = self._mcp_initialize(
            single_terminal, alpha_actor, project="alpha",
            instance="single-bridge-mcp")
        single_mcp_denied = self._mcp_call(
            single_mcp_headers, single_sid, "bridge_add", {
                "other_project": "beta",
            })
        self.assertTrue(
            single_mcp_denied["body"]["result"]["isError"],
            single_mcp_denied["body"])
        self.assertIn(
            "bridge_peer_actor_binding_required",
            single_mcp_denied["body"]["result"]["content"][0]["text"])

        single_service = self._create_service(
            projects=("alpha",), actors=(alpha_actor,))
        self.assertEqual(single_service["status"], 201,
                         single_service["body"])
        service_denied = self._request(
            "POST", "/v1/projects/alpha/bridges", {
                "other_project": "beta",
            }, self._service_headers(
                single_service["body"], project="alpha", actor=alpha_actor))
        self.assertEqual(service_denied["status"], 403,
                         service_denied["body"])

        # An admin human may create the relationship. A single-workspace
        # member still cannot update or remove it.
        created = self._request(
            "POST", "/v1/projects/alpha/bridges", {
                "other_project": "beta",
            }, self.alice)
        self.assertEqual(created["status"], 200, created["body"])
        same_source = self._request(
            "POST", "/v1/projects/alpha/room", {
                "body": "canonical same-project header",
                "msg_type": "chat",
            }, {**self.bob, "X-Attacca-Project": "alpha"})
        self.assertEqual(same_source["status"], 200, same_source["body"])
        conn = c.connect(self.db)
        try:
            same_event = conn.execute(
                "SELECT payload FROM events WHERE project_id='alpha'"
                " AND event_type='room.message'"
                " AND payload LIKE '%canonical same-project header%'"
                " ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            self.assertIsNotNone(same_event)
            self.assertIsNone(
                json.loads(same_event["payload"]).get("origin_project"))
        finally:
            conn.close()
        conn = c.connect(self.db)
        try:
            before_forged_origin = [tuple(row) for row in conn.execute(
                "SELECT * FROM events ORDER BY project_id,seq")]
        finally:
            conn.close()
        forged_origin = self._request(
            "POST", "/v1/projects/alpha/room", {
                "body": "forged beta origin must not land",
                "msg_type": "chat",
            }, {**self.bob, "X-Attacca-Project": "beta"})
        self.assertEqual(forged_origin["status"], 403,
                         forged_origin["body"])
        self.assertIn("rest_project_header_mismatch",
                      forged_origin["body"]["error"])
        conn = c.connect(self.db)
        try:
            self.assertEqual(
                [tuple(row) for row in conn.execute(
                    "SELECT * FROM events ORDER BY project_id,seq")],
                before_forged_origin)
        finally:
            conn.close()
        unknown_origin = self._request(
            "POST", "/v1/projects/alpha/room", {
                "body": "unknown source must not enumerate or land",
                "msg_type": "chat",
            }, {**self.bob, "X-Attacca-Project": "unknown-private-project"})
        self.assertEqual(unknown_origin["status"], 403,
                         unknown_origin["body"])
        self.assertNotIn("Known projects", unknown_origin["body"]["error"])
        conn = c.connect(self.db)
        try:
            self.assertEqual(
                [tuple(row) for row in conn.execute(
                    "SELECT * FROM events ORDER BY project_id,seq")],
                before_forged_origin)
        finally:
            conn.close()
        denied_update = self._request(
            "PUT", "/v1/projects/alpha/bridges/beta", {
                "relationship": "advisor", "principal": "alpha",
            }, self.bob)
        denied_remove = self._request(
            "DELETE", "/v1/projects/alpha/bridges/beta", headers=self.bob)
        self.assertEqual(denied_update["status"], 403,
                         denied_update["body"])
        self.assertEqual(denied_remove["status"], 403,
                         denied_remove["body"])

        # Bridge-targeted room delivery remains intentionally governed by the
        # existing bridge participation policy, not direct peer membership.
        delivered = self._request(
            "POST", "/v1/projects/alpha/room", {
                "body": "permitted bridge delivery without beta membership",
                "msg_type": "chat", "target_project": "beta",
            }, self.bob)
        self.assertEqual(delivered["status"], 200, delivered["body"])
        conn = c.connect(self.db)
        try:
            mirrored = conn.execute(
                "SELECT * FROM events WHERE project_id='beta'"
                " AND event_type='room.message'"
                " AND payload LIKE '%permitted bridge delivery%'"
                " ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            self.assertIsNotNone(mirrored)
            self.assertEqual(mirrored["owner"], "bob")
        finally:
            conn.close()

        # A terminal/service credential may govern the peer only when this
        # same runtime is separately registered and exactly bound as Director
        # in both workspaces.
        _dual_flow, dual_terminal = self._issue(
            alpha_actor, beta_actor, device="dual-bridge-terminal")
        terminal_update = self._request(
            "PUT", "/v1/projects/alpha/bridges/beta", {
                "relationship": "advisor", "principal": "alpha",
            }, self._terminal_headers(
                dual_terminal, alpha_actor, project="alpha",
                instance="dual-bridge-client"))
        self.assertEqual(terminal_update["status"], 200,
                         terminal_update["body"])
        dual_sid, dual_mcp_headers = self._mcp_initialize(
            dual_terminal, alpha_actor, project="alpha",
            instance="dual-bridge-mcp")
        terminal_mcp_update = self._mcp_call(
            dual_mcp_headers, dual_sid, "bridge_update_access", {
                "other_project": "beta",
                "participation": "directors_advisors",
            })
        self.assertFalse(
            terminal_mcp_update["body"]["result"]["isError"],
            terminal_mcp_update["body"])

        dual_service = self._create_service(
            projects=("alpha", "beta"), actors=(alpha_actor, beta_actor))
        self.assertEqual(dual_service["status"], 201, dual_service["body"])
        service_update = self._request(
            "PUT", "/v1/projects/alpha/bridges/beta", {
                "participation": "directors",
            }, self._service_headers(
                dual_service["body"], project="alpha", actor=alpha_actor))
        self.assertEqual(service_update["status"], 200,
                         service_update["body"])

        removed = self._request(
            "DELETE", "/v1/projects/alpha/bridges/beta", headers=self.alice)
        self.assertEqual(removed["status"], 200, removed["body"])
        terminal_add = self._request(
            "POST", "/v1/projects/alpha/bridges", {
                "other_project": "beta",
            }, self._terminal_headers(
                dual_terminal, alpha_actor, project="alpha",
                instance="dual-bridge-client"))
        self.assertEqual(terminal_add["status"], 200, terminal_add["body"])

        # Membership changes are read dynamically by an already-open MCP
        # session; after both grants Bob may manage both endpoints.
        conn = c.connect(self.db)
        try:
            bob = conn.execute(
                "SELECT * FROM auth_users WHERE username='bob'"
            ).fetchone()
            c.auth_grant_project_membership(
                conn, dict(bob), "beta", granted_by="redteam")
        finally:
            conn.close()
        bob_removed = self._request(
            "DELETE", "/v1/projects/alpha/bridges/beta", headers=self.bob)
        self.assertEqual(bob_removed["status"], 200, bob_removed["body"])
        mcp_added = self._mcp_call(
            mcp_headers, sid, "bridge_add", {"other_project": "beta"})
        self.assertFalse(mcp_added["body"]["result"]["isError"],
                         mcp_added["body"])
        mcp_removed = self._mcp_call(
            mcp_headers, sid, "bridge_remove", {"other_project": "beta"})
        self.assertFalse(mcp_removed["body"]["result"]["isError"],
                         mcp_removed["body"])

    def test_auto_compatibility_then_one_terminal_spans_runtimes_and_instances(self):
        status = self._request("GET", "/v1/auth/status")["body"]
        self.assertFalse(status["authentication_required"])
        self.assertTrue(status["compatibility_active"])
        self.assertEqual(status["effective_authentication"], "optional")
        self.assertEqual(self._request(
            "GET", "/v1/projects",
            headers={"Authorization": "Bearer stale-before-migration"}
        )["status"], 200)
        # Compatibility accepts only stale legacy actor-style bearers. Known
        # modern terminal/service/session prefixes must fail closed even when
        # no matching row ever existed, otherwise a revoked or typoed modern
        # credential could silently regain anonymous compatibility access.
        for invalid_modern in (
                "atd_missing-redteam", "atsvc_missing-redteam",
                "ats_missing-redteam"):
            rejected = self._request(
                "GET", "/v1/projects/alpha/status", headers={
                    "Authorization": "Bearer " + invalid_modern,
                })
            self.assertEqual(rejected["status"], 401,
                             (invalid_modern, rejected["body"]))

        before = self._actor_lead_bytes()
        actors = (
            "alpha.director.codex-exact",
            "alpha.director.claude-exact",
            "alpha.worker.kimi-exact",
            "beta.director.codex-exact",
        )
        _flow, credential = self._issue(*actors)
        for actor, instance in (
                (actors[0], "codex-one"),
                (actors[0], "codex-two"),
                (actors[1], "claude-one"),
                (actors[2], "kimi-one")):
            response = self._request(
                "GET", "/v1/projects/alpha/status",
                headers=self._terminal_headers(
                    credential, actor, project="alpha", instance=instance))
            self.assertEqual(response["status"], 200, response["body"])

        beta = self._request(
            "GET", "/v1/projects/beta/status",
            headers=self._terminal_headers(
                credential, actors[3], project="beta",
                instance="codex-beta"))
        self.assertEqual(beta["status"], 200, beta["body"])

        sessions = []
        for actor, instance in (
                (actors[0], "mcp-codex-one"),
                (actors[0], "mcp-codex-two"),
                (actors[1], "mcp-claude"),
                (actors[2], "mcp-kimi")):
            sid, headers = self._mcp_initialize(
                credential, actor, instance=instance)
            listed = self._mcp_call(headers, sid, "attacca_status")
            self.assertEqual(listed["status"], 200, listed["body"])
            self.assertIn("result", listed["body"])
            sessions.append((actor, sid, headers))

        # Session ids are pinned to the exact actor as well as user/device.
        replay_headers = self._terminal_headers(
            credential, actors[1], project="alpha", instance="mcp-codex-one")
        replay_headers["Accept"] = "application/json, text/event-stream"
        replay = self._mcp_call(
            replay_headers, sessions[0][1], "attacca_status")
        self.assertEqual(replay["status"], 403, replay["body"])

        # Enrollment and credential selection themselves never rewrite actor
        # or lead rows. A later real ledger write is expected to advance the
        # actor's last_seen_at and the project's context_version only.
        self.assertEqual(self._actor_lead_bytes(), before)
        immutable_identity = self._actor_lead_identity()

        mcp_actor, mcp_sid, mcp_headers = sessions[1]
        mcp_headers = {
            **mcp_headers,
            c.GIT_BRANCH_HEADER: "feature/mcp-redteam",
            c.GIT_REVISION_HEADER: "fedcba9876543210",
        }
        mcp_posted = self._mcp_call(
            mcp_headers, mcp_sid, "room_send", {
                "body": "red-team MCP attribution probe",
                "msg_type": "status",
            })
        self.assertEqual(mcp_posted["status"], 200, mcp_posted["body"])
        self.assertFalse(mcp_posted["body"]["result"]["isError"],
                         mcp_posted["body"])
        conn = c.connect(self.db)
        try:
            mcp_event = conn.execute(
                "SELECT * FROM events WHERE project_id='alpha'"
                " AND event_type='room.message'"
                " AND payload LIKE '%red-team MCP attribution probe%'"
                " ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            self.assertIsNotNone(mcp_event)
            self.assertEqual(mcp_event["actor_id"], mcp_actor)
            self.assertEqual(mcp_event["owner"], "alice")
            self.assertEqual(mcp_event["device_id"],
                             "home-device/mcp-codex-two")
            self.assertEqual(mcp_event["git_branch"], "feature/mcp-redteam")
            self.assertEqual(mcp_event["base_revision"], "fedcba9876543210")
        finally:
            conn.close()

        posted = self._request(
            "POST", "/v1/projects/alpha/room", {
                "body": "red-team attribution probe", "msg_type": "status",
            }, self._terminal_headers(
                credential, actors[1], project="alpha",
                instance="claude-two", branch="feature/auth-redteam",
                revision="0123456789abcdef"))
        self.assertEqual(posted["status"], 200, posted["body"])
        conn = c.connect(self.db)
        try:
            event = conn.execute(
                "SELECT * FROM events WHERE project_id='alpha'"
                " AND event_type='room.message' ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            self.assertEqual(event["actor_id"], actors[1])
            self.assertEqual(event["owner"], "alice")
            self.assertEqual(event["device_id"], "home-device/claude-two")
            self.assertEqual(event["git_branch"], "feature/auth-redteam")
            self.assertEqual(event["base_revision"], "0123456789abcdef")
        finally:
            conn.close()
        self.assertEqual(self._actor_lead_identity(), immutable_identity)

    def test_exact_actor_selector_rejects_unbound_same_runtime_actor(self):
        """An exact actor header must never degrade to a runtime hint."""
        _flow, credential = self._issue("alpha.director.codex-exact")
        response = self._request(
            "GET", "/v1/projects/alpha/status",
            headers=self._terminal_headers(
                credential, "alpha.worker.codex-unbound", project="alpha"))
        self.assertEqual(response["status"], 403, response["body"])

    def test_orphaned_actor_binding_never_becomes_provisional_human(self):
        actor = "alpha.director.claude-exact"
        _flow, credential = self._issue(actor)
        conn = c.connect(self.db)
        try:
            # Simulate an actor rename/removal racing an older credential. The
            # durable binding row intentionally remains, so this is not a
            # genuine zero-binding setup terminal.
            conn.execute(
                "DELETE FROM agents WHERE project_id='alpha' AND agent_id=?",
                (actor,))
            raw_bindings = conn.execute(
                "SELECT COUNT(*) AS n FROM auth_token_actor_bindings"
                " WHERE token_id=? AND revoked_at IS NULL",
                (credential["token_id"],)).fetchone()["n"]
            self.assertEqual(raw_bindings, 1)
        finally:
            conn.close()
        requested = self._request(
            "GET", "/v1/projects/alpha/status",
            headers=self._terminal_headers(
                credential, actor, project="alpha"))
        self.assertEqual(requested["status"], 403, requested["body"])
        cross_project = self._request(
            "GET", "/v1/projects/beta/status",
            headers=self._terminal_headers(
                credential, actor, project="beta"))
        self.assertEqual(cross_project["status"], 403,
                         cross_project["body"])

    def test_non_admin_can_open_and_approve_only_an_exact_owned_enrollment(self):
        own_actor = "alpha.worker.claude-bob"
        own_flow = self._start_flow(
            own_actor, device="bob-device", instance="bob-client")

        # Non-admins cannot enumerate the server-wide pending queue, but a
        # verification URI may disclose exactly its one short-lived code.
        collection = self._request(
            "GET", "/v1/auth/terminal-enrollments", headers=self.bob)
        self.assertEqual(collection["status"], 403, collection["body"])
        exact = self._request(
            "GET", "/v1/auth/terminal-enrollments/%s" %
            urllib.parse.quote(own_flow["user_code"], safe=""),
            headers=self.bob)
        self.assertEqual(exact["status"], 200, exact["body"])
        self.assertEqual(exact["body"]["user_code"], own_flow["user_code"])
        self.assertEqual(exact["body"]["requested_bindings"],
                         self._bindings(own_actor))
        serialized = json.dumps(exact["body"], sort_keys=True)
        self.assertNotIn(own_flow["device_code"], serialized)
        self.assertNotIn("device_code_hash", serialized)

        approval = self._approve(
            own_flow, own_actor, session=self.bob)
        self.assertEqual(approval["status"], 200, approval["body"])
        issued = self._poll(
            own_flow, device="bob-device", instance="bob-client")
        self.assertEqual(issued["status"], 200, issued["body"])
        own_headers = self._terminal_headers(
            issued["body"]["credential"], own_actor, project="alpha",
            instance="bob-claude")
        own_status = self._request(
            "GET", "/v1/auth/status", headers=own_headers)
        self.assertEqual(own_status["status"], 200, own_status["body"])
        self.assertEqual(own_status["body"]["user"]["username"], "bob")
        self.assertEqual(self._request(
            "GET", "/v1/projects/alpha/status",
            headers=own_headers)["status"], 200)

        other_actor = "alpha.director.codex-exact"
        other_flow = self._start_flow(
            other_actor, device="alice-device", instance="alice-client")
        # Knowing an exact code does not grant its requested actor's authority.
        other_exact = self._request(
            "GET", "/v1/auth/terminal-enrollments/%s" %
            urllib.parse.quote(other_flow["user_code"], safe=""),
            headers=self.bob)
        self.assertEqual(other_exact["status"], 200, other_exact["body"])
        denied = self._approve(
            other_flow, other_actor, session=self.bob)
        self.assertEqual(denied["status"], 403, denied["body"])
        pending = self._poll(
            other_flow, device="alice-device", instance="alice-client")
        self.assertEqual(pending["status"], 200, pending["body"])
        self.assertEqual(pending["body"]["status"], "pending")

    def test_public_invitations_are_owner_scoped_one_time_and_secret_safe(self):
        access = self._request("GET", "/v1/auth/access", headers=self.alice)
        self.assertEqual(access["status"], 200, access["body"])
        self.assertTrue(access["body"]["capabilities"]["invitations"])

        denied_member = self._create_invitation(session=self.bob)
        self.assertEqual(denied_member["status"], 403, denied_member["body"])
        denied_admin = self._create_invitation(
            session=self.admin2, is_admin=True)
        self.assertEqual(denied_admin["status"], 403, denied_admin["body"])

        created = self._create_invitation(label="Carol alpha")
        self.assertEqual(created["status"], 201, created["body"])
        invitation = created["body"]
        raw = invitation["invitation_token"]
        invitation_id = invitation["record"]["invitation_id"]
        self.assertTrue(raw.startswith("ati_"))

        listed = self._request(
            "GET", "/v1/auth/invitations", headers=self.alice)
        self.assertEqual(listed["status"], 200, listed["body"])
        self.assertNotIn(raw, json.dumps(listed["body"], sort_keys=True))
        conn = c.connect(self.db)
        try:
            dump = "\n".join(conn.iterdump())
            self.assertNotIn(raw, dump)
            self.assertIn(c.sha256_hex(raw), dump)
        finally:
            conn.close()

        # Invitation acceptance remains deliberately public after this
        # temporary server is fail-closed. The acceptor cannot widen the
        # invitation's workspace or administrator scope in the request body.
        self._force_temp_enforcement()
        accepted = self._request("POST", "/v1/auth/invitations/accept", {
            "invitation_token": raw,
            "username": "carol",
            "password": "carol-password",
            "display_name": "Carol",
            "project_memberships": ["beta"],
            "is_admin": True,
        })
        self.assertEqual(accepted["status"], 201, accepted["body"])
        self.assertEqual(accepted["body"]["project_memberships"], ["alpha"])
        self.assertFalse(accepted["body"]["user"]["is_admin"])
        replay = self._request("POST", "/v1/auth/invitations/accept", {
            "invitation_token": raw,
            "username": "replay-user",
            "password": "replay-password",
        })
        self.assertEqual(replay["status"], 401, replay["body"])

        conn = c.connect(self.db)
        try:
            carol = conn.execute(
                "SELECT * FROM auth_users WHERE username='carol'").fetchone()
            self.assertIsNotNone(carol)
            memberships = [row["project_id"] for row in conn.execute(
                "SELECT project_id FROM auth_project_memberships"
                " WHERE user_id=? AND revoked_at IS NULL ORDER BY project_id",
                (carol["user_id"],)).fetchall()]
            self.assertEqual(memberships, ["alpha"])
            row = conn.execute(
                "SELECT * FROM auth_invitations WHERE invitation_id=?",
                (invitation_id,)).fetchone()
            self.assertEqual(row["accepted_user_id"], carol["user_id"])
            self.assertIsNotNone(row["accepted_at"])
        finally:
            conn.close()

        admin_invite = self._create_invitation(
            label="Owner-created admin", is_admin=True)
        self.assertEqual(admin_invite["status"], 201, admin_invite["body"])
        revoked = self._request(
            "DELETE", "/v1/auth/invitations/%s" %
            admin_invite["body"]["record"]["invitation_id"],
            headers=self.admin2)
        self.assertEqual(revoked["status"], 200, revoked["body"])
        denied_revoked = self._request(
            "POST", "/v1/auth/invitations/accept", {
                "invitation_token": admin_invite["body"]["invitation_token"],
                "username": "revoked-admin",
                "password": "revoked-password",
            })
        self.assertEqual(denied_revoked["status"], 401,
                         denied_revoked["body"])

    def test_invitation_collision_expiry_and_concurrent_replay_are_atomic(self):
        collision = self._create_invitation(label="collision")
        self.assertEqual(collision["status"], 201, collision["body"])
        collision_token = collision["body"]["invitation_token"]
        duplicate = self._request(
            "POST", "/v1/auth/invitations/accept", {
                "invitation_token": collision_token,
                "username": "alice", "password": "new-password",
            })
        self.assertEqual(duplicate["status"], 400, duplicate["body"])
        retry = self._request(
            "POST", "/v1/auth/invitations/accept", {
                "invitation_token": collision_token,
                "username": "dave", "password": "dave-password",
            })
        self.assertEqual(retry["status"], 201, retry["body"])

        expired = self._create_invitation(label="expired")
        self.assertEqual(expired["status"], 201, expired["body"])
        conn = c.connect(self.db)
        try:
            conn.execute(
                "UPDATE auth_invitations SET expires_at=?"
                " WHERE invitation_id=?",
                ("2000-01-01T00:00:00.000Z",
                 expired["body"]["record"]["invitation_id"]))
        finally:
            conn.close()
        denied_expired = self._request(
            "POST", "/v1/auth/invitations/accept", {
                "invitation_token": expired["body"]["invitation_token"],
                "username": "expired-user", "password": "expired-password",
            })
        self.assertEqual(denied_expired["status"], 401,
                         denied_expired["body"])

        concurrent = self._create_invitation(label="concurrent")
        self.assertEqual(concurrent["status"], 201, concurrent["body"])
        concurrent_token = concurrent["body"]["invitation_token"]
        barrier = threading.Barrier(3)
        results = []
        lock = threading.Lock()

        def accept(name):
            barrier.wait(timeout=10)
            response = self._request(
                "POST", "/v1/auth/invitations/accept", {
                    "invitation_token": concurrent_token,
                    "username": name,
                    "password": "%s-password" % name,
                })
            with lock:
                results.append(response)

        threads = [threading.Thread(target=accept, args=(name,))
                   for name in ("race-one", "race-two")]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=15)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sorted(item["status"] for item in results),
                         [201, 401], results)
        conn = c.connect(self.db)
        try:
            accepted_count = conn.execute(
                "SELECT COUNT(*) AS n FROM auth_users"
                " WHERE username IN ('race-one','race-two')"
            ).fetchone()["n"]
            self.assertEqual(accepted_count, 1)
        finally:
            conn.close()

    def test_bound_service_is_exact_scoped_attributed_and_secret_safe(self):
        actor = "alpha.director.codex-exact"
        before = self._actor_lead_identity()
        created = self._create_service(actors=(actor,))
        self.assertEqual(created["status"], 201, created["body"])
        result = created["body"]
        raw = result["token"]
        token_id = result["record"]["token_id"]
        self.assertTrue(raw.startswith("atsvc_"))
        self.assertEqual(
            [item["actor_id"] for item in result["record"]["actor_bindings"]],
            [actor])
        self.assertEqual(self._actor_lead_identity(), before)

        listed = self._request(
            "GET", "/v1/auth/service-keys", headers=self.alice)
        self.assertEqual(listed["status"], 200, listed["body"])
        self.assertNotIn(raw, json.dumps(listed["body"], sort_keys=True))
        conn = c.connect(self.db)
        try:
            dump = "\n".join(conn.iterdump())
            self.assertNotIn(raw, dump)
            self.assertIn(c.sha256_hex(raw), dump)
        finally:
            conn.close()

        headers = self._service_headers(
            result, project="alpha", actor=actor,
            owner="forged-human", instance="codex-service-one",
            branch="feature/service-redteam", revision="abc123def456")
        posted = self._request(
            "POST", "/v1/projects/alpha/room", {
                "body": "bound service attribution probe",
                "msg_type": "status",
            }, headers)
        self.assertEqual(posted["status"], 200, posted["body"])
        conn = c.connect(self.db)
        try:
            event = conn.execute(
                "SELECT * FROM events WHERE project_id='alpha'"
                " AND event_type='room.message'"
                " AND payload LIKE '%bound service attribution probe%'"
                " ORDER BY seq DESC LIMIT 1").fetchone()
            self.assertIsNotNone(event)
            self.assertEqual(event["actor_id"], actor)
            self.assertEqual(event["actor_type"], "agent")
            self.assertEqual(event["owner"], "alice")
            self.assertEqual(event["device_id"],
                             "service-device/codex-service-one")
            self.assertEqual(event["git_branch"], "feature/service-redteam")
            self.assertEqual(event["base_revision"], "abc123def456")
        finally:
            conn.close()

        wrong_actor = self._request(
            "GET", "/v1/projects/alpha/status",
            headers=self._service_headers(
                result, project="alpha",
                actor="alpha.worker.codex-unbound"))
        self.assertEqual(wrong_actor["status"], 403, wrong_actor["body"])
        wrong_project = self._request(
            "GET", "/v1/projects/beta/status",
            headers=self._service_headers(
                result, project="beta", actor=actor))
        self.assertEqual(wrong_project["status"], 403, wrong_project["body"])

        mcp_sid, mcp_headers = self._mcp_initialize_headers(
            self._service_headers(
                result, project="alpha", actor=actor,
                instance="service-mcp"),
            instance="service-mcp")
        mcp_status = self._mcp_call(
            mcp_headers, mcp_sid, "attacca_status")
        self.assertEqual(mcp_status["status"], 200, mcp_status["body"])
        self.assertFalse(mcp_status["body"]["result"]["isError"],
                         mcp_status["body"])

        ambiguous = self._create_service(actors=(
            actor, "alpha.director.claude-exact"))
        self.assertEqual(ambiguous["status"], 201, ambiguous["body"])
        no_exact_actor = self._request(
            "GET", "/v1/projects/alpha/status",
            headers=self._service_headers(
                ambiguous["body"], project="alpha"))
        self.assertEqual(no_exact_actor["status"], 403,
                         no_exact_actor["body"])

        worker_actor = "alpha.worker.kimi-exact"
        worker_service = self._create_service(actors=(worker_actor,))
        self.assertEqual(worker_service["status"], 201,
                         worker_service["body"])
        current_handoff = self._request(
            "GET", "/v1/projects/alpha/handoff",
            headers=self._service_headers(
                worker_service["body"], project="alpha",
                actor=worker_actor))
        self.assertEqual(current_handoff["status"], 200,
                         current_handoff["body"])
        worker_handoff = self._request(
            "PUT", "/v1/projects/alpha/handoff", {
                "objective": "worker service must retain worker authority",
                "expected_context_version":
                    current_handoff["body"]["context_version"],
            }, self._service_headers(
                worker_service["body"], project="alpha",
                actor=worker_actor))
        self.assertEqual(worker_handoff["status"], 400,
                         worker_handoff["body"])

        bob_scope = self._create_service(
            session=self.bob, actors=(actor,))
        self.assertEqual(bob_scope["status"], 403, bob_scope["body"])
        bob_revoke = self._request(
            "DELETE", "/v1/auth/service-keys/%s" % token_id,
            headers=self.bob)
        self.assertEqual(bob_revoke["status"], 403, bob_revoke["body"])
        revoked = self._request(
            "DELETE", "/v1/auth/service-keys/%s" % token_id,
            headers=self.alice)
        self.assertEqual(revoked["status"], 200, revoked["body"])
        # A recognized modern credential stays fail-closed even before the
        # temporary server leaves compatibility mode. It must never degrade
        # to caller-controlled legacy headers after revocation.
        compatibility_stale = self._request(
            "GET", "/v1/projects/alpha/status", headers=headers)
        self.assertEqual(compatibility_stale["status"], 401,
                         compatibility_stale["body"])
        revoked_write = self._request(
            "POST", "/v1/projects/alpha/room", {
                "body": "revoked service must not degrade",
                "msg_type": "status",
            }, headers)
        self.assertEqual(revoked_write["status"], 401,
                         revoked_write["body"])

        expiring = self._create_service(
            label="expiring", actors=(actor,))
        self.assertEqual(expiring["status"], 201, expiring["body"])
        conn = c.connect(self.db)
        try:
            conn.execute(
                "UPDATE auth_tokens SET expires_at=? WHERE token_id=?",
                ("2000-01-01T00:00:00.000Z",
                 expiring["body"]["record"]["token_id"]))
        finally:
            conn.close()
        expired_headers = self._service_headers(
            expiring["body"], project="alpha", actor=actor)
        compatibility_expired = self._request(
            "GET", "/v1/projects/alpha/status", headers=expired_headers)
        self.assertEqual(compatibility_expired["status"], 401,
                         compatibility_expired["body"])
        expired_write = self._request(
            "POST", "/v1/projects/alpha/room", {
                "body": "expired service must not degrade",
                "msg_type": "status",
            }, expired_headers)
        self.assertEqual(expired_write["status"], 401,
                         expired_write["body"])

        self._force_temp_enforcement()
        stale = self._request(
            "GET", "/v1/projects/alpha/status", headers=headers)
        self.assertEqual(stale["status"], 401, stale["body"])
        expired = self._request(
            "GET", "/v1/projects/alpha/status",
            headers=expired_headers)
        self.assertEqual(expired["status"], 401, expired["body"])

    def test_unbound_service_is_read_only_and_cannot_escalate_to_human(self):
        created = self._create_service(actors=())
        self.assertEqual(created["status"], 201, created["body"])
        result = created["body"]
        scoped = self._service_headers(
            result, project="alpha", owner="forged-owner")
        self.assertEqual(self._request(
            "GET", "/v1/projects/alpha/status",
            headers=scoped)["status"], 200)

        # "Read-only" must include GET routes whose ordinary interactive
        # semantics have a durable side effect.  In particular, the inbox
        # endpoint defaults to mark_read=1 for agents/humans; an unbound
        # service must not manufacture or advance a persisted inbox cursor.
        broadcast = self._request(
            "POST", "/v1/projects/alpha/room", {
                "body": "read-only service cursor probe",
                "msg_type": "chat",
            }, self.alice)
        self.assertEqual(broadcast["status"], 200, broadcast["body"])
        conn = c.connect(self.db)
        try:
            cursor_rows_before = conn.execute(
                "SELECT COUNT(*) AS n FROM inbox_cursors"
            ).fetchone()["n"]
        finally:
            conn.close()
        service_inbox = self._request(
            "GET", "/v1/projects/alpha/inbox", headers=scoped)
        self.assertEqual(service_inbox["status"], 200,
                         service_inbox["body"])
        conn = c.connect(self.db)
        try:
            cursor_rows_after = conn.execute(
                "SELECT COUNT(*) AS n FROM inbox_cursors"
            ).fetchone()["n"]
        finally:
            conn.close()
        self.assertEqual(cursor_rows_after, cursor_rows_before)

        unbound_mcp = self._request("POST", "/mcp", {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "unbound", "version": "redteam"},
            },
        }, {**scoped, "Accept": "application/json, text/event-stream"})
        self.assertEqual(unbound_mcp["status"], 403, unbound_mcp["body"])

        # A scope-only service may read its declared workspace, but cannot
        # inherit browser/account/server powers from its creating human.
        forbidden = [
            ("GET", "/v1/projects/alpha/export", None, scoped),
            ("GET", "/v1/auth/tokens", None, scoped),
            ("GET", "/v1/auth/service-keys", None, scoped),
            ("GET", "/v1/auth/invitations", None, scoped),
            ("POST", "/v1/auth/service-keys", {
                "label": "nested escalation",
                "project_memberships": ["alpha"],
            }, scoped),
            ("POST", "/v1/auth/invitations", {
                "label": "nested invitation",
                "project_memberships": ["alpha"],
            }, scoped),
            ("POST", "/v1/auth/activation", {
                "confirmed": True, "expected_readiness_version": "forged",
            }, scoped),
            ("PUT", "/v1/settings", {
                "update_interval_seconds": 60,
            }, self._service_headers(result)),
            ("POST", "/v1/projects", {
                "project_id": "service-escape",
                "name": "Service Escape",
            }, self._service_headers(result)),
            ("POST", "/v1/projects/alpha/room", {
                "body": "forged binding directive", "msg_type": "directive",
            }, scoped),
            ("POST", "/v1/projects/alpha/tasks", {
                "title": "forged service task",
            }, scoped),
            ("POST", "/v1/projects/alpha/decisions", {
                "title": "forged service decision",
                "summary": "must not be written",
            }, scoped),
            ("POST", "/v1/projects/alpha/rules", {
                "title": "forged service rule",
                "body": "must not be written",
            }, scoped),
        ]
        for method, path, body, headers in forbidden:
            response = self._request(method, path, body, headers)
            self.assertIn(response["status"], (401, 403),
                          (method, path, response))

        handoff = self._request(
            "GET", "/v1/projects/alpha/handoff", headers=scoped)
        self.assertEqual(handoff["status"], 200, handoff["body"])
        overwritten = self._request(
            "PUT", "/v1/projects/alpha/handoff", {
                "objective": "service must not become a human/director",
                "expected_context_version": handoff["body"]["context_version"],
            }, scoped)
        self.assertIn(overwritten["status"], (401, 403), overwritten["body"])

        conn = c.connect(self.db)
        try:
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM projects WHERE project_id='service-escape'"
            ).fetchone())
            self.assertNotEqual(
                c.server_settings_load(conn).get("update_interval_seconds"),
                60)
            latest = c.get_handoff(conn, "alpha")
            self.assertNotEqual(
                latest.get("handoff", {}).get("objective"),
                "service must not become a human/director")
        finally:
            conn.close()

    def test_failed_migration_scope_request_is_atomic(self):
        access = self._request("GET", "/v1/auth/access", headers=self.alice)
        self.assertEqual(access["status"], 200, access["body"])
        version = access["body"]["compatibility"]["readiness_version"]
        rejected = self._request("POST", "/v1/auth/migration-scope", {
            "expected_readiness_version": version,
            "required_clients": [
                {"project_id": "alpha",
                 "actor_id": "alpha.director.codex-exact",
                 "device_id": "device-valid"},
                {"project_id": "alpha",
                 "actor_id": "alpha.worker.does-not-exist",
                 "device_id": "device-invalid"},
            ],
            "exclusions": [],
        }, self.alice)
        self.assertEqual(rejected["status"], 400, rejected["body"])
        conn = c.connect(self.db)
        try:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM auth_migration_targets"
            ).fetchone()["n"], 0)
        finally:
            conn.close()

    def test_dropped_poll_retry_hash_only_and_atomic_a_to_a_plus_b_supersede(self):
        actor_a = "alpha.director.codex-exact"
        actor_b = "alpha.director.claude-exact"
        flow, old = self._issue(actor_a)
        retry = self._poll(flow)
        self.assertEqual(retry["status"], 200, retry["body"])
        self.assertEqual(retry["body"]["status"], "approved")
        self.assertTrue(hmac.compare_digest(
            retry["body"]["credential"]["token"], flow["device_code"]),
            "retry returned a different promoted device secret")
        self.assertEqual(retry["body"]["credential"]["token_id"],
                         old["token_id"])

        replacement_flow, new = self._issue(
            actor_a, actor_b, instance="replacement-instance",
            credential=old)
        self.assertNotEqual(new["token_id"], old["token_id"])
        self.assertEqual(
            {binding["actor_id"] for binding in new["bindings"]},
            {actor_a, actor_b})
        self.assertEqual(self._poll(
            replacement_flow, instance="replacement-instance"
        )["body"]["credential"]["token_id"], new["token_id"])

        conn = c.connect(self.db)
        try:
            old_row = conn.execute(
                "SELECT * FROM auth_tokens WHERE token_id=?",
                (old["token_id"],)).fetchone()
            new_row = conn.execute(
                "SELECT * FROM auth_tokens WHERE token_id=?",
                (new["token_id"],)).fetchone()
            self.assertIsNotNone(old_row["revoked_at"])
            self.assertIsNone(new_row["revoked_at"])
            dump = "\n".join(conn.iterdump())
            self.assertFalse(flow["device_code"] in dump,
                             "first plaintext device secret leaked into DB")
            self.assertFalse(replacement_flow["device_code"] in dump,
                             "replacement plaintext device secret leaked into DB")
            self.assertIn(c.sha256_hex(flow["device_code"]), dump)
            self.assertIn(c.sha256_hex(replacement_flow["device_code"]), dump)
        finally:
            conn.close()
        access = self._request("GET", "/v1/auth/access", headers=self.alice)
        serialized = json.dumps(access["body"], sort_keys=True)
        self.assertFalse(old["token"] in serialized,
                         "old terminal bearer leaked through access metadata")
        self.assertFalse(new["token"] in serialized,
                         "new terminal bearer leaked through access metadata")

    def test_supersede_approval_cannot_cross_human_owners(self):
        victim_actor = "alpha.director.codex-exact"
        attacker_actor = "alpha.worker.claude-bob"
        flow, original = self._issue(victim_actor)
        replacement = self._start_flow(
            victim_actor, instance="victim-replacement", credential=original)

        # The short approval code is not authority to revoke a different
        # human's terminal. A member may approve only a fresh flow as themself;
        # superseding A must remain owned by A's authenticated human.
        stolen_approval = self._approve(
            replacement, attacker_actor, session=self.bob)
        self.assertEqual(stolen_approval["status"], 403,
                         stolen_approval["body"])
        still_valid = self._request(
            "GET", "/v1/projects/alpha/status",
            headers=self._terminal_headers(
                original, victim_actor, project="alpha"))
        self.assertEqual(still_valid["status"], 200, still_valid["body"])
        conn = c.connect(self.db)
        try:
            row = conn.execute(
                "SELECT revoked_at FROM auth_tokens WHERE token_id=?",
                (original["token_id"],)).fetchone()
            self.assertIsNone(row["revoked_at"])
        finally:
            conn.close()
        pending = self._poll(
            replacement, instance="victim-replacement")
        self.assertEqual(pending["status"], 200, pending["body"])
        self.assertEqual(pending["body"]["status"], "pending")

    def test_supersede_server_preserves_old_binding_union(self):
        old_actors = (
            "alpha.director.codex-exact",
            "alpha.worker.kimi-exact",
        )
        added = "alpha.director.claude-exact"
        _flow, original = self._issue(*old_actors)
        # Deliberately simulate a stale/buggy client that sends only B. The
        # server, not merely the current helper implementation, owns the
        # no-binding-loss invariant for A+C -> A+B+C replacement.
        replacement = self._start_flow(
            added, instance="stale-client-replacement", credential=original)
        exact = self._request(
            "GET", "/v1/auth/terminal-enrollments/%s" %
            urllib.parse.quote(replacement["user_code"], safe=""),
            headers=self.alice)
        self.assertEqual(exact["status"], 200, exact["body"])
        requested = {
            item["actor_id"] for item in exact["body"]["requested_bindings"]}
        self.assertEqual(requested, {*old_actors, added})

        drop_attempt = self._approve(replacement, added)
        self.assertEqual(drop_attempt["status"], 403, drop_attempt["body"])
        approved = self._approve(replacement, *old_actors, added)
        self.assertEqual(approved["status"], 200, approved["body"])
        issued = self._poll(
            replacement, instance="stale-client-replacement")
        self.assertEqual(issued["status"], 200, issued["body"])
        self.assertEqual({item["actor_id"] for item in
                          issued["body"]["credential"]["bindings"]},
                         {*old_actors, added})
        conn = c.connect(self.db)
        try:
            old = conn.execute(
                "SELECT revoked_at FROM auth_tokens WHERE token_id=?",
                (original["token_id"],)).fetchone()
            self.assertIsNotNone(old["revoked_at"])
        finally:
            conn.close()

    def test_real_shared_client_flow_can_be_finished_by_another_runtime_instance(self):
        """A shared machine flow cannot depend on the starter waking again."""
        state = Path(self.temp.name) / "terminal-flow.json"
        credentials = Path(self.temp.name) / "credentials.json"
        base_url = "http://%s:%s" % (self.host, self.port)
        actor_a = "alpha.director.codex-exact"
        actor_b = "alpha.director.claude-exact"
        binding_a = self._bindings(actor_a)
        binding_b = self._bindings(actor_b)

        started = flow_client.start_device_flow(
            base_url, device_id="shared-device", client_label="Codex",
            requested_bindings=binding_a, state_path=state,
            client_instance_id="codex-instance")
        self.assertEqual(started["status"], "started")
        approved = self._approve(started, actor_a)
        self.assertEqual(approved["status"], 200, approved["body"])

        # Claude is the active process after browser approval. It has access to
        # the same private machine state and must be able to finish Codex's flow.
        finished = flow_client.poll_device_flow(
            base_url, device_id="shared-device", state_path=state,
            credentials_path=credentials, force=True,
            client_instance_id="claude-instance")
        self.assertEqual(finished["status"], "approved")
        self.assertIsNotNone(flow_client.load_terminal_credential(
            base_url, device_id="shared-device", project_id="alpha",
            actor_id=actor_a, runtime="codex",
            credentials_path=credentials))

        # Extending A -> A+B is likewise finishable by a third active runtime;
        # the final one credential must preserve the complete union.
        replacement = flow_client.advance_device_flow(
            base_url, device_id="shared-device", client_label="Claude",
            requested_bindings=binding_b, state_path=state,
            credentials_path=credentials, force_poll=True,
            client_instance_id="claude-instance")
        self.assertEqual(replacement["status"], "started")
        approved = self._approve(replacement, actor_a, actor_b)
        self.assertEqual(approved["status"], 200, approved["body"])
        extended = flow_client.poll_device_flow(
            base_url, device_id="shared-device", state_path=state,
            credentials_path=credentials, force=True,
            client_instance_id="kimi-instance")
        self.assertEqual(extended["status"], "approved")
        record = json.loads(credentials.read_text())["servers"] \
            [flow_client.canonical_server_url(base_url)]["terminal_credential"]
        self.assertEqual(
            {(item["project_id"], item["actor_id"])
             for item in record["bindings"]},
            {("alpha", actor_a), ("alpha", actor_b)})
        self.assertEqual(credentials.stat().st_mode & 0o777, 0o600)
        self.assertEqual(state.stat().st_mode & 0o777, 0o600)

    def test_wrong_device_project_user_expiry_and_revocation_are_isolated(self):
        actor = "alpha.director.codex-exact"
        _flow, credential = self._issue(actor)
        good = self._terminal_headers(
            credential, actor, project="alpha")

        wrong_device = dict(good)
        wrong_device["X-Attacca-Device-ID"] = "office-device"
        self.assertEqual(self._request(
            "GET", "/v1/projects/alpha/status",
            headers=wrong_device)["status"], 403)
        wrong_project = dict(good)
        wrong_project["X-Attacca-Project"] = "beta"
        self.assertEqual(self._request(
            "GET", "/v1/projects/beta/status",
            headers=wrong_project)["status"], 403)

        bob_revoke = self._request(
            "DELETE", "/v1/auth/terminals/%s" % credential["token_id"],
            headers=self.bob)
        self.assertEqual(bob_revoke["status"], 403, bob_revoke["body"])
        self.assertEqual(self._request(
            "GET", "/v1/projects/alpha/status", headers=good)["status"], 200)

        conn = c.connect(self.db)
        try:
            conn.execute(
                "UPDATE auth_tokens SET expires_at=? WHERE token_id=?",
                ("2000-01-01T00:00:00.000Z", credential["token_id"]))
        finally:
            conn.close()
        expired = self._request(
            "GET", "/v1/projects/alpha/status", headers=good)
        self.assertEqual(expired["status"], 401, expired["body"])
        expired_write = self._request(
            "POST", "/v1/projects/alpha/room", {
                "body": "expired modern terminal must never degrade",
                "msg_type": "status",
            }, good)
        self.assertEqual(expired_write["status"], 401,
                         expired_write["body"])

        _flow2, credential2 = self._issue(actor, device="second-device")
        revoked = self._request(
            "DELETE", "/v1/auth/terminals/%s" % credential2["token_id"],
            headers=self.alice)
        self.assertEqual(revoked["status"], 200, revoked["body"])
        stale = self._request(
            "GET", "/v1/projects/alpha/status",
            headers=self._terminal_headers(
                credential2, actor, project="alpha"))
        self.assertEqual(stale["status"], 401, stale["body"])

    def test_temp_activation_flips_fail_closed_and_explicit_rollback_restores(self):
        actor = "alpha.director.codex-exact"
        compatibility_headers = {
            "Authorization": "Bearer stale-legacy-token",
            "X-Attacca-Actor": actor,
            "X-Attacca-Device-ID": "home-device",
            "X-Attacca-Client-Instance": "legacy-instance",
        }
        self.assertEqual(self._request(
            "GET", "/v1/projects/alpha/sync/snapshot",
            headers=compatibility_headers)["status"], 200)
        _flow, credential = self._issue(actor)
        _expiry_flow, expiry_credential = self._issue(
            actor, device="expiry-device", instance="expiry-instance")
        conn = c.connect(self.db)
        try:
            c.auth_record_qa_evidence(
                conn, c.auth_source_sha256(),
                {"passed": True, "suite": "redteam-acceptance",
                 "result": "passed"},
                {"passed": True, "suite": "redteam-regression",
                 "result": "passed"})
            readiness = c.auth_activation_readiness(conn)
            self.assertTrue(readiness["ready"], readiness["blockers"])
            self.assertFalse(c._auth_setting(conn, "auth.activated", False))
        finally:
            conn.close()

        missing_confirm = self._request("POST", "/v1/auth/activation", {
            "confirmed": False,
            "expected_readiness_version": readiness["readiness_version"],
        }, self.alice)
        self.assertEqual(missing_confirm["status"], 400,
                         missing_confirm["body"])
        stale_version = self._request("POST", "/v1/auth/activation", {
            "confirmed": True, "expected_readiness_version": "stale",
        }, self.alice)
        self.assertEqual(stale_version["status"], 403, stale_version["body"])
        non_admin = self._request("POST", "/v1/auth/activation", {
            "confirmed": True,
            "expected_readiness_version": readiness["readiness_version"],
        }, self.bob)
        self.assertEqual(non_admin["status"], 403, non_admin["body"])
        non_owner_admin = self._request("POST", "/v1/auth/activation", {
            "confirmed": True,
            "expected_readiness_version": readiness["readiness_version"],
        }, self.admin2)
        self.assertEqual(non_owner_admin["status"], 403,
                         non_owner_admin["body"])
        non_owner_scope = self._request(
            "POST", "/v1/auth/migration-scope", {
                "expected_readiness_version": readiness["readiness_version"],
                "required_clients": [], "exclusions": [],
            }, self.admin2)
        self.assertEqual(non_owner_scope["status"], 403,
                         non_owner_scope["body"])
        activated = self._request("POST", "/v1/auth/activation", {
            "confirmed": True,
            "expected_readiness_version": readiness["readiness_version"],
        }, self.alice)
        self.assertEqual(activated["status"], 200, activated["body"])

        status = self._request("GET", "/v1/auth/status")["body"]
        self.assertTrue(status["authentication_required"])
        self.assertFalse(status["compatibility_active"])
        self.assertEqual(self._request(
            "GET", "/v1/projects/alpha/status")["status"], 401)
        self.assertEqual(self._request(
            "GET", "/v1/projects/alpha/sync/snapshot",
            headers=compatibility_headers)["status"], 401)
        valid = self._request(
            "GET", "/v1/projects/alpha/status",
            headers=self._terminal_headers(
                credential, actor, project="alpha"))
        self.assertEqual(valid["status"], 200, valid["body"])

        revoked = self._request(
            "DELETE", "/v1/auth/terminals/%s" % credential["token_id"],
            headers=self.alice)
        self.assertEqual(revoked["status"], 200, revoked["body"])
        self.assertEqual(self._request(
            "GET", "/v1/auth/status",
            headers=self._terminal_headers(
                credential, actor, project="alpha"))["status"], 401)
        conn = c.connect(self.db)
        try:
            conn.execute(
                "UPDATE auth_tokens SET expires_at=? WHERE token_id=?",
                ("2000-01-01T00:00:00.000Z",
                 expiry_credential["token_id"]))
        finally:
            conn.close()
        self.assertEqual(self._request(
            "GET", "/v1/auth/status",
            headers=self._terminal_headers(
                expiry_credential, actor, project="alpha"))["status"], 401)

        self._restart(auth=False, auth_mode="auto")
        self.assertTrue(self._request(
            "GET", "/v1/auth/status")["body"]["authentication_required"])
        self._restart(auth=False, auth_mode="compatibility")
        rollback = self._request("GET", "/v1/auth/status")["body"]
        self.assertFalse(rollback["authentication_required"])
        self.assertTrue(rollback["compatibility_active"])
        self.assertEqual(self._request(
            "GET", "/v1/projects/alpha/sync/snapshot",
            headers=compatibility_headers)["status"], 200)

    def test_unbound_service_sync_projection_is_read_only_and_cannot_push(self):
        """A read-only service can mirror state but cannot mutate or queue it."""
        created = self._create_service(actors=())
        self.assertEqual(created["status"], 201, created["body"])
        token_id = created["body"]["record"]["token_id"]
        headers = self._service_headers(
            created["body"], project="alpha",
            device="service-sync-device", instance="service-sync-client")

        # Authentication normally records a throttled last-used timestamp.
        # Prime that explicitly so the snapshots below prove the project and
        # sync GET handlers themselves perform no durable write at all.
        conn = c.connect(self.db)
        try:
            conn.execute(
                "UPDATE auth_tokens SET last_used_at=? WHERE token_id=?",
                (c.now_iso(), token_id))
        finally:
            conn.close()

        def database_state():
            current = c.connect(self.db)
            try:
                tables = [row["name"] for row in current.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                    " AND name NOT LIKE 'sqlite_%' ORDER BY name")]
                return {
                    table: [tuple(row) for row in current.execute(
                        'SELECT * FROM "%s" ORDER BY rowid' % table)]
                    for table in tables
                }
            finally:
                current.close()

        before_snapshot = database_state()
        snapshot = self._request(
            "GET", "/v1/projects/alpha/sync/snapshot", headers=headers)
        self.assertEqual(snapshot["status"], 200, snapshot["body"])
        self.assertEqual(snapshot["body"]["scope"]["actor_type"], "tool")
        self.assertEqual(snapshot["body"]["scope"]["role"], "unassigned")
        self.assertEqual(database_state(), before_snapshot)

        cursor = snapshot["body"]["cursor"]
        query = urllib.parse.urlencode({
            "after_seq": cursor["event_seq"],
            "after_hash": cursor["event_hash"],
            "context_version": cursor["context_version"],
            "visibility_fingerprint":
                snapshot["body"]["visibility_fingerprint"],
        })
        before_pull = database_state()
        pulled = self._request(
            "GET", "/v1/projects/alpha/sync/pull?" + query,
            headers=headers)
        self.assertEqual(pulled["status"], 200, pulled["body"])
        self.assertEqual(database_state(), before_pull)

        before_denials = database_state()
        denied_push = self._request(
            "POST", "/v1/projects/alpha/sync/push", {}, headers)
        denied_room = self._request(
            "POST", "/v1/projects/alpha/room", {
                "body": "unbound service must not write",
                "msg_type": "status",
            }, headers)
        denied_mcp = self._request("POST", "/mcp", {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18",
                       "capabilities": {},
                       "clientInfo": {"name": "unbound-service",
                                      "version": "redteam"}},
        }, headers)
        self.assertEqual(denied_push["status"], 403, denied_push["body"])
        self.assertEqual(denied_room["status"], 403, denied_room["body"])
        self.assertEqual(denied_mcp["status"], 403, denied_mcp["body"])
        self.assertEqual(database_state(), before_denials)

    def test_activation_readiness_check_and_flip_are_toctou_atomic(self):
        actor = "alpha.director.codex-exact"
        self._issue(actor)
        conn = c.connect(self.db)
        try:
            c.auth_record_qa_evidence(
                conn, c.auth_source_sha256(),
                {"passed": True, "suite": "toctou-acceptance",
                 "result": "passed"},
                {"passed": True, "suite": "toctou-regression",
                 "result": "passed"})
            readiness = c.auth_activation_readiness(conn)
            self.assertTrue(readiness["ready"], readiness["blockers"])
        finally:
            conn.close()

        entered = threading.Event()
        release = threading.Event()
        writer_done = threading.Event()
        activation_result = []
        writer_errors = []
        original_readiness = c.auth_activation_readiness

        def gated_readiness(*args, **kwargs):
            result = original_readiness(*args, **kwargs)
            if not entered.is_set():
                entered.set()
                if not release.wait(timeout=10):
                    raise RuntimeError("red-team activation gate timed out")
            return result

        def activate_over_http():
            activation_result.append(self._request(
                "POST", "/v1/auth/activation", {
                    "confirmed": True,
                    "expected_readiness_version":
                        readiness["readiness_version"],
                }, self.alice))

        def race_scope_writer():
            other = c.connect(self.db)
            try:
                c.auth_migration_target_upsert(
                    other, "alpha", actor, "late-racing-device",
                    selected_by="redteam", required=True)
            except Exception as error:  # surfaced on the main test thread
                writer_errors.append(error)
            finally:
                other.close()
                writer_done.set()

        c.auth_activation_readiness = gated_readiness
        try:
            activation_thread = threading.Thread(target=activate_over_http)
            activation_thread.start()
            self.assertTrue(entered.wait(timeout=10))
            writer_thread = threading.Thread(target=race_scope_writer)
            writer_thread.start()
            # BEGIN IMMEDIATE around readiness+flip must hold off this second
            # writer; otherwise migration state can change inside the check.
            self.assertFalse(writer_done.wait(timeout=0.25))
            release.set()
            activation_thread.join(timeout=10)
            writer_thread.join(timeout=10)
            self.assertFalse(activation_thread.is_alive())
            self.assertFalse(writer_thread.is_alive())
        finally:
            release.set()
            c.auth_activation_readiness = original_readiness
        self.assertFalse(writer_errors, writer_errors)
        self.assertEqual(len(activation_result), 1)
        self.assertEqual(activation_result[0]["status"], 200,
                         activation_result[0]["body"])
        conn = c.connect(self.db)
        try:
            self.assertTrue(c._auth_setting(conn, "auth.activated", False))
            late = conn.execute(
                "SELECT * FROM auth_migration_targets"
                " WHERE device_id='late-racing-device'").fetchone()
            self.assertIsNotNone(late)
        finally:
            conn.close()

    def test_room_origin_header_cannot_escape_human_workspace_membership(self):
        bridge = self._request(
            "POST", "/v1/projects/alpha/bridges", {
                "other_project": "beta",
                "boss": "alpha",
            }, self.alice)
        self.assertEqual(bridge["status"], 200, bridge["body"])

        def durable_state():
            conn = c.connect(self.db)
            try:
                return {
                    "events": [tuple(row) for row in conn.execute(
                        "SELECT * FROM events ORDER BY project_id,seq")],
                    "projects": [tuple(row) for row in conn.execute(
                        "SELECT * FROM projects ORDER BY project_id")],
                }
            finally:
                conn.close()

        before = durable_state()
        headers = {**self.bob, "X-Attacca-Project": "beta"}
        escaped = self._request(
            "POST", "/v1/projects/alpha/room", {
                "body": "must not be written into unauthorized beta",
                "msg_type": "chat",
            }, headers)
        self.assertEqual(escaped["status"], 403, escaped["body"])
        self.assertEqual(durable_state(), before)


if __name__ == "__main__":
    unittest.main()
