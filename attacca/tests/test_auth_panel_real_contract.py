"""Temp-server integration for the Control Panel authentication contract.

The server binds only to loopback port 0 and the database exists only inside a
TemporaryDirectory.  This suite never discovers, contacts, or mutates a live
Attacca instance and deliberately never calls the activation endpoint.
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
    "attacca_auth_panel_contract_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class AuthPanelRealContractTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "panel-contract.db"
        conn = c.connect(self.db)
        try:
            c.auth_create_user(
                conn, "owner", "owner-password", display_name="Owner",
                is_admin=True, bootstrap=True)
            c.auth_create_user(
                conn, "member", "member-password", display_name="Member")
            c.auth_create_user(
                conn, "admin2", "admin2-password", display_name="Admin Two",
                is_admin=True)
            c.set_current_owner("owner")
            c.project_init(
                conn, "web.owner", "human",
                path=Path(self.temp.name) / "alpha", project_id="alpha",
                name="Alpha")
            c.agent_register(
                conn, "alpha", "web.owner", "human",
                agent_id="alpha.director.codex", display_name="Alpha Codex",
                role="director", runtime="codex")
            member = conn.execute(
                "SELECT user_id FROM auth_users WHERE username='member'"
            ).fetchone()
            conn.execute(
                "INSERT INTO auth_project_memberships"
                " (user_id,project_id,granted_at,granted_by)"
                " VALUES (?,?,?,?)",
                (member["user_id"], "alpha", c.now_iso(), "owner"))
            c.set_current_owner("member")
            c.agent_register(
                conn, "alpha", "web.member", "human",
                agent_id="alpha.worker.codex-member",
                display_name="Member Codex", role="worker", runtime="codex")
        finally:
            c.set_current_owner(None)
            conn.close()

        self.server = c.AttaccaServer(
            ("127.0.0.1", 0), self.db, auth=True, auth_mode="auto")
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

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
        parsed = json.loads(raw) if raw and "json" in content_type \
            else raw.decode("utf-8", "replace")
        result = {
            "status": response.status, "headers": response.headers,
            "body": parsed,
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

    def test_served_panel_matches_real_terminal_service_and_invite_contract(self):
        panel = self.request("GET", "/app", headers={"Accept": "text/html"})
        self.assertEqual(panel["status"], 200)
        for marker in (
                'data-form="create-service-key"',
                'data-form="invite-human"',
                'data-form="accept-human-invitation"',
                "/v1/auth/terminal-enrollments/",
                "/v1/auth/service-keys",
                "/v1/auth/invitations/accept"):
            self.assertIn(marker, panel["body"])

        owner = self.login("owner", "owner-password")
        member = self.login("member", "member-password")
        admin2 = self.login("admin2", "admin2-password")
        owner_status = self.request("GET", "/v1/auth/status", headers=owner)
        member_status = self.request("GET", "/v1/auth/status", headers=member)
        admin_status = self.request("GET", "/v1/auth/status", headers=admin2)
        self.assertIs(owner_status["body"]["user"]["is_owner"], True)
        self.assertIs(member_status["body"]["user"]["is_owner"], False)
        self.assertIs(admin_status["body"]["user"]["is_admin"], True)
        self.assertIs(admin_status["body"]["user"]["is_owner"], False)

        access = self.request("GET", "/v1/auth/access", headers=owner)
        self.assertEqual(access["status"], 200, access["body"])
        for capability in (
                "terminal_enrollment", "migration_scope", "activation",
                "service_keys", "invitations"):
            self.assertIs(access["body"]["capabilities"][capability], True)

        flow = self.request("POST", "/v1/auth/device/start", {
            "device_id": "member-device",
            "client_label": "Member terminal",
            "client_instance": "panel-contract-instance",
            "requested_bindings": [{
                "project_id": "alpha",
                "actor_id": "alpha.worker.codex-member",
            }],
        })
        self.assertEqual(flow["status"], 201, flow["body"])
        user_code = flow["body"]["user_code"]
        member_access = self.request("GET", "/v1/auth/access", headers=member)
        self.assertEqual(member_access["status"], 200, member_access["body"])
        self.assertEqual(member_access["body"]["terminal_enrollments"], [])
        targeted = self.request(
            "GET", "/v1/auth/terminal-enrollments/%s" %
            urllib.parse.quote(user_code, safe=""), headers=member)
        self.assertEqual(targeted["status"], 200, targeted["body"])
        self.assertEqual(targeted["body"]["user_code"], user_code)
        self.assertEqual(targeted["body"]["device_id"], "member-device")
        self.assertNotIn("device_code", targeted["body"])

        service_body = {
            "label": "Panel automation",
            "project_memberships": ["alpha"],
            "actor_bindings": [{
                "project_id": "alpha", "actor_id": "alpha.director.codex",
            }],
        }
        created_service = self.request(
            "POST", "/v1/auth/service-keys", service_body, owner)
        self.assertEqual(
            created_service["status"], 201, created_service["body"])
        service_secret = created_service["body"]["token"]
        self.assertTrue(service_secret.startswith("atsvc_"))
        self.assertEqual(
            created_service["body"]["record"]["project_memberships"],
            ["alpha"])
        listed_services = self.request(
            "GET", "/v1/auth/service-keys", headers=owner)
        self.assertEqual(listed_services["status"], 200)
        self.assertNotIn(service_secret, json.dumps(listed_services["body"]))
        self.assertNotIn("token", listed_services["body"]["service_keys"][0])

        invitation_body = {
            "label": "Panel teammate",
            "project_memberships": ["alpha"],
            "is_admin": False,
        }
        created_invitation = self.request(
            "POST", "/v1/auth/invitations", invitation_body, owner)
        self.assertEqual(
            created_invitation["status"], 201,
            created_invitation["body"])
        invitation_secret = created_invitation["body"]["invitation_token"]
        self.assertTrue(invitation_secret.startswith("ati_"))
        self.assertTrue(
            created_invitation["body"]["verification_uri"].endswith(
                "/app#settings"))
        listed_invitations = self.request(
            "GET", "/v1/auth/invitations", headers=owner)
        self.assertEqual(listed_invitations["status"], 200)
        self.assertNotIn(
            invitation_secret, json.dumps(listed_invitations["body"]))

        accepted = self.request("POST", "/v1/auth/invitations/accept", {
            "invitation_token": invitation_secret,
            "username": "invitee",
            "password": "invitee-password",
            "display_name": "Invited Human",
        })
        self.assertEqual(accepted["status"], 201, accepted["body"])
        self.assertIs(accepted["body"]["accepted"], True)
        self.assertIs(accepted["body"]["login_required"], True)
        self.assertEqual(accepted["body"]["login_endpoint"],
                         "/v1/auth/login")
        invitee = self.login("invitee", "invitee-password")
        invitee_status = self.request(
            "GET", "/v1/auth/status", headers=invitee)
        self.assertEqual(invitee_status["body"]["user"]["username"],
                         "invitee")
        self.assertIs(invitee_status["body"]["user"]["is_owner"], False)
        replay = self.request("POST", "/v1/auth/invitations/accept", {
            "invitation_token": invitation_secret,
            "username": "replay",
            "password": "replay-password",
        })
        self.assertEqual(replay["status"], 401, replay["body"])
        self.assertIn("invalid_invitation", replay["body"]["error"])

        forbidden_admin_invite = self.request(
            "POST", "/v1/auth/invitations", {
                "label": "Privilege attempt",
                "project_memberships": ["alpha"],
                "is_admin": True,
            }, admin2)
        self.assertEqual(
            forbidden_admin_invite["status"], 403,
            forbidden_admin_invite["body"])
        self.assertIn(
            "server_owner_required", forbidden_admin_invite["body"]["error"])


if __name__ == "__main__":
    unittest.main()
