"""D-17 client-key authentication and durable workflow-guard acceptance."""

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
    "attacca_d17_workflow_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class D17ClientKeyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "d17.db"
        self.conn = c.connect(self.db)
        c.auth_create_user(
            self.conn, "jack", "jack-password", display_name="Jack",
            is_admin=True, bootstrap=True)
        c.auth_create_user(
            self.conn, "other", "other-password", display_name="Other")
        c.set_current_owner("jack")
        c.project_init(
            self.conn, "web.jack", "human",
            path=Path(self.temp.name) / "repo", project_id="proj",
            name="Project")
        jack = self.conn.execute(
            "SELECT * FROM auth_users WHERE username='jack'").fetchone()
        other = self.conn.execute(
            "SELECT * FROM auth_users WHERE username='other'").fetchone()
        for user in (jack, other):
            self.conn.execute(
                "INSERT OR IGNORE INTO auth_project_memberships"
                " (user_id,project_id,granted_at,granted_by) VALUES (?,?,?,?)",
                (user["user_id"], "proj", c.now_iso(), "jack"))
        for actor, runtime in (
                ("proj.director.codex", "codex"),
                ("proj.director.claude", "claude")):
            c.agent_register(
                self.conn, "proj", "web.jack", "human", agent_id=actor,
                display_name=actor, role="director", runtime=runtime,
                registration_username="jack")
        c.set_current_owner("other")
        c.agent_register(
            self.conn, "proj", "web.other", "human",
            agent_id="proj.worker.other", display_name="Other Worker",
            role="worker", runtime="other", registration_username="other")
        self.principal = c._auth_principal(
            self.conn, jack, "session", session_hash="test")

    def tearDown(self):
        c.set_current_owner(None)
        c.set_current_git_context()
        self.conn.close()
        self.temp.cleanup()

    def test_one_install_key_selects_multiple_owned_actors_without_bindings(self):
        with self.assertRaisesRegex(c.AttaccaError, "safe"):
            c.auth_client_key_create(
                self.conn, self.principal, "Bad install", "bad\nheader",
                memberships=["proj"])
        with self.assertRaisesRegex(c.AttaccaError, "safe"):
            c.auth_client_key_create(
                self.conn, self.principal, "Bad device", "valid-install",
                memberships=["proj"], device_id="bad\rdevice")
        created = c.auth_client_key_create(
            self.conn, self.principal, "Home install", "client-home",
            memberships=["proj"], device_id="home-device")
        self.assertTrue(created["token"].startswith("atkey_"))
        token_id = created["record"]["token_id"]
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS n FROM auth_token_actor_bindings"
            " WHERE token_id=?", (token_id,)).fetchone()["n"], 0)

        token_principal = c.auth_token_principal(
            self.conn, created["token"])
        self.assertEqual(token_principal["username"], "jack")
        self.assertFalse(token_principal["is_admin"])
        codex = c.auth_client_principal_scope(
            self.conn, token_principal, "proj", "proj.director.codex")
        claude = c.auth_client_principal_scope(
            self.conn, token_principal, "proj", "proj.director.claude")
        self.assertEqual(codex["role"], "director")
        self.assertEqual(claude["runtime"], "claude")
        with self.assertRaisesRegex(c.AuthorizationError,
                                    "client_actor_denied"):
            c.auth_client_principal_scope(
                self.conn, token_principal, "proj", "proj.worker.other")

        other_row = self.conn.execute(
            "SELECT * FROM auth_users WHERE username='other'").fetchone()
        other_principal = c._auth_principal(
            self.conn, other_row, "session", session_hash="other-test")
        other_key = c.auth_client_key_create(
            self.conn, other_principal, "Other install", "client-other",
            memberships=["proj"])
        other_token = c.auth_token_principal(
            self.conn, other_key["token"])
        c.auth_client_principal_scope(
            self.conn, other_token, "proj", "proj.worker.other")
        with self.assertRaisesRegex(c.AuthorizationError,
                                    "client_actor_denied"):
            c.auth_client_principal_scope(
                self.conn, other_token, "proj", "proj.director.codex")

        c.auth_client_key_revoke(self.conn, self.principal, token_id)
        self.assertIsNone(c.auth_token_principal(
            self.conn, created["token"]))

    def test_owner_toggle_has_no_terminal_migration_or_qa_gate(self):
        readiness = c.auth_activation_readiness(self.conn)
        self.assertTrue(readiness["ready"])
        self.assertEqual(readiness["terminal_count"], 0)
        activated = c.auth_activate(
            self.conn, self.principal, True, enabled=True)
        self.assertTrue(activated["activated"])
        disabled = c.auth_activate(
            self.conn, self.principal, True, enabled=False)
        self.assertFalse(disabled["activated"])


class D17ClientKeyHttpTest(unittest.TestCase):
    """Exercise the real protected HTTP boundary and immutable attribution."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "d17-http.db"
        self.server = c.AttaccaServer(("127.0.0.1", 0), self.db, auth=True)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address
        self.session = self.request("POST", "/v1/auth/bootstrap", {
            "username": "jack", "display_name": "Jack",
            "password": "jack-password",
        })
        self.assertEqual(self.session["status"], 201, self.session["body"])
        conn = c.connect(self.db)
        try:
            c.auth_create_user(
                conn, "other", "other-password", display_name="Other")
            jack = conn.execute(
                "SELECT * FROM auth_users WHERE username='jack'").fetchone()
            other = conn.execute(
                "SELECT * FROM auth_users WHERE username='other'").fetchone()
            c.set_current_owner("jack")
            c.project_init(
                conn, "web.jack", "human", path=Path(self.temp.name) / "repo",
                project_id="proj", name="Project")
            for user in (jack, other):
                conn.execute(
                    "INSERT OR IGNORE INTO auth_project_memberships"
                    " (user_id,project_id,granted_at,granted_by)"
                    " VALUES (?,?,?,?)",
                    (user["user_id"], "proj", c.now_iso(), "jack"))
            for actor, runtime in (
                    ("proj.director.codex", "codex"),
                    ("proj.director.claude", "claude")):
                c.agent_register(
                    conn, "proj", "web.jack", "human", agent_id=actor,
                    role="director", runtime=runtime,
                    registration_username="jack")
            c.set_current_owner("other")
            c.agent_register(
                conn, "proj", "web.other", "human",
                agent_id="proj.worker.other", role="worker", runtime="other",
                registration_username="other")
        finally:
            c.set_current_owner(None)
            conn.close()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(
            self.host, self.port, timeout=5)
        payload = json.dumps(body).encode() if body is not None else None
        request_headers = {"Accept": "application/json", **(headers or {})}
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        connection.request(
            method, path, body=payload, headers=request_headers)
        response = connection.getresponse()
        raw = response.read()
        result = {
            "status": response.status,
            "headers": response.headers,
            "body": json.loads(raw) if raw else {},
        }
        connection.close()
        return result

    def session_headers(self):
        cookies = {}
        for line in self.session["headers"].get_all("Set-Cookie") or []:
            parsed = http.cookies.SimpleCookie()
            parsed.load(line)
            cookies.update({key: item.value for key, item in parsed.items()})
        return {
            "Cookie": "; ".join("%s=%s" % item for item in cookies.items()),
            "X-Attacca-CSRF": cookies["attacca_csrf"],
        }

    def client_headers(self, actor, instance="install-home"):
        return {
            "Authorization": "Bearer " + self.token,
            "X-Attacca-Client-Instance": instance,
            "X-Attacca-Device": "device-home",
            "X-Attacca-Project": "proj",
            "X-Attacca-Actor": actor,
            "X-Attacca-Git-Branch": "feature/d17",
            "X-Attacca-Git-Revision": "abc1234",
        }

    def test_enforced_key_selects_multiple_ais_and_keeps_human_separate(self):
        created = self.request(
            "POST", "/v1/auth/client-keys", {
                "label": "Home install",
                "client_instance": "install-home",
                "device_id": "device-home",
                "project_memberships": ["proj"],
            }, self.session_headers())
        self.assertEqual(created["status"], 201, created["body"])
        self.token = created["body"]["token"]
        token_id = created["body"]["record"]["token_id"]

        activated = self.request(
            "POST", "/v1/auth/activation",
            {"enabled": True, "confirmed": True}, self.session_headers())
        self.assertEqual(activated["status"], 200, activated["body"])
        self.assertTrue(activated["body"]["activated"])
        self.assertEqual(
            self.request("GET", "/v1/projects/proj/status")["status"], 401)

        for actor in ("proj.director.codex", "proj.director.claude"):
            with self.subTest(actor=actor):
                result = self.request(
                    "GET", "/v1/projects/proj/status",
                    headers=self.client_headers(actor))
                self.assertEqual(result["status"], 200, result["body"])
        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/status",
            headers=self.client_headers(
                "proj.director.codex", instance="other-install"))["status"],
            403)
        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/status",
            headers=self.client_headers("proj.worker.other"))["status"], 403)
        self.assertEqual(self.request(
            "GET", "/v1/settings",
            headers=self.client_headers("proj.director.codex"))["status"],
            200)
        self.assertEqual(self.request(
            "PUT", "/v1/settings", {"update_interval_seconds": 60},
            self.client_headers("proj.director.codex"))["status"], 403)

        sent = self.request(
            "POST", "/v1/projects/proj/room", {"body": "D-17 proof"},
            self.client_headers("proj.director.codex"))
        self.assertEqual(sent["status"], 200, sent["body"])
        event_id = sent["body"]["event"]["event_id"]
        conn = c.connect(self.db)
        try:
            row = conn.execute(
                "SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
            self.assertEqual(row["actor_id"], "proj.director.codex")
            self.assertEqual(row["owner"], "jack")
            self.assertEqual(row["git_branch"], "feature/d17")
            self.assertEqual(row["base_revision"], "abc1234")
        finally:
            conn.close()

        revoked = self.request(
            "DELETE", "/v1/auth/client-keys/%s" % token_id,
            headers=self.session_headers())
        self.assertEqual(revoked["status"], 200, revoked["body"])
        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/status",
            headers=self.client_headers("proj.director.codex"))["status"],
            401)


class D17LegacyOwnerAliasTest(unittest.TestCase):
    def test_single_account_claims_legacy_label_without_rewriting_actor(self):
        with tempfile.TemporaryDirectory() as directory:
            conn = c.connect(Path(directory) / "legacy-owner.db")
            try:
                c.auth_create_user(
                    conn, "jack", "jack-password", display_name="Jdevgy",
                    is_admin=True, bootstrap=True)
                jack = conn.execute(
                    "SELECT * FROM auth_users WHERE username='jack'").fetchone()
                principal = c._auth_principal(
                    conn, jack, "session", session_hash="legacy-test")
                c.set_current_owner("legacy-shell")
                c.project_init(
                    conn, "legacy-shell", "human",
                    path=Path(directory) / "repo", project_id="legacy",
                    name="Legacy")
                c.agent_register(
                    conn, "legacy", "legacy-shell", "human",
                    agent_id="legacy.director.codex", role="director",
                    runtime="codex")
                c.set_current_owner("jack")
                activated = c.auth_activate(
                    conn, principal, True, enabled=True)
                self.assertEqual(
                    activated["claimed_legacy_owner_aliases"],
                    ["legacy-shell"])
                created = c.auth_client_key_create(
                    conn, principal, "Legacy install", "legacy-install",
                    memberships=["legacy"])
                token_principal = c.auth_token_principal(
                    conn, created["token"])
                selected = c.auth_client_principal_scope(
                    conn, token_principal, "legacy",
                    "legacy.director.codex")
                self.assertEqual(selected["role"], "director")
                row = conn.execute(
                    "SELECT owner FROM agents WHERE project_id='legacy'"
                    " AND agent_id='legacy.director.codex'").fetchone()
                self.assertEqual(row["owner"], "legacy-shell")
            finally:
                c.set_current_owner(None)
                conn.close()


class WorkflowGuardTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.conn = c.connect(Path(self.temp.name) / "workflow.db")
        c.set_current_owner("jack")
        c.project_init(
            self.conn, "setup", "human", path=Path(self.temp.name) / "a",
            project_id="a", name="A")
        c.project_init(
            self.conn, "setup", "human", path=Path(self.temp.name) / "b",
            project_id="b", name="B")
        for project in ("a", "b"):
            for actor, runtime in (
                    (f"{project}.director.codex", "codex"),
                    (f"{project}.director.claude", "claude")):
                c.agent_register(
                    self.conn, project, "setup", "human", agent_id=actor,
                    role="director", runtime=runtime,
                    registration_username="jack")
        c.bridge_add(
            self.conn, "a", "a.director.codex", "agent", "b")

    def tearDown(self):
        c.set_current_owner(None)
        c.set_current_git_context()
        self.conn.close()
        self.temp.cleanup()

    def test_room_send_reports_every_delivery_truthfully(self):
        sent = c.room_send(
            self.conn, "a", "a.director.codex", "agent", "feedback",
            target_project="b")
        self.assertEqual(sent["delivered_to"], "a")
        self.assertEqual(sent["delivered_to_projects"], ["a", "b"])
        self.assertEqual(sent["mirrored_to"], ["b"])
        local = c.room_send(
            self.conn, "a", "a.director.codex", "agent", "local")
        self.assertEqual(local["delivered_to_projects"], ["a"])
        self.assertEqual(local["mirrored_to"], [])

    def test_evidenceless_done_stays_unverified_in_review(self):
        task_id = c.task_create(
            self.conn, "a", "a.director.codex", "agent", "Do it")["task_id"]
        c.task_claim(
            self.conn, "a", "a.director.codex", "agent", task_id)
        result = c.task_report(
            self.conn, "a", "a.director.codex", "agent", task_id,
            "Trust me", evidence=[], requested_state="done")
        self.assertEqual(result["requested_state"], "done")
        self.assertEqual(result["status"], "review")
        self.assertEqual(result["verification_status"], "unverified")
        shown = c.task_show(self.conn, "a", task_id)
        self.assertEqual(shown["status"], "review")
        self.assertEqual(shown["verification_status"], "unverified")

    def test_read_cursor_does_not_clear_addressed_work(self):
        sent = c.room_send(
            self.conn, "a", "a.director.claude", "agent", "Please verify",
            mentions=["a.director.codex"])
        first = c.inbox_read(
            self.conn, "a", "a.director.codex", mark_read=True)
        self.assertEqual(first["unread_total"], 1)
        self.assertEqual(first["pending_disposition_total"], 1)
        second = c.inbox_read(
            self.conn, "a", "a.director.codex", mark_read=True)
        self.assertEqual(second["unread_total"], 0)
        self.assertEqual(second["pending_disposition_total"], 1)
        disposed = c.message_dispose(
            self.conn, "a", "a.director.codex", "agent",
            sent["event"]["event_id"], "acknowledged")
        self.assertEqual(disposed["pending_disposition_total"], 0)

        c.room_send(
            self.conn, "a", "a.director.claude", "agent", "FYI everyone")
        directive = c.room_send(
            self.conn, "a", "a.director.claude", "agent", "Do this",
            msg_type="directive")
        pending = c.inbox_read(
            self.conn, "a", "a.director.codex", mark_read=False)
        ids = {item["event_id"] for item in pending["pending_dispositions"]}
        self.assertEqual(ids, {directive["event"]["event_id"]})

    def test_checkout_and_expired_claim_warnings(self):
        c.set_current_git_context("main", "old", "device/client")
        c.append_event(
            self.conn, "a", "a.director.codex", "agent", "note.test", {})
        c.set_current_git_context("main", "new", "device/client")
        warnings = c.workflow_warnings(
            self.conn, "a", "a.director.codex", "agent")
        self.assertIn("off_board_repository_mutation",
                      {item["code"] for item in warnings})
        task_id = c.task_create(
            self.conn, "a", "a.director.codex", "agent", "Tracked")["task_id"]
        c.task_claim(
            self.conn, "a", "a.director.codex", "agent", task_id)
        warnings = c.workflow_warnings(
            self.conn, "a", "a.director.codex", "agent")
        self.assertNotIn("off_board_repository_mutation",
                         {item["code"] for item in warnings})
        self.conn.execute(
            "UPDATE tasks SET lease_until='2000-01-01T00:00:00.000Z'"
            " WHERE project_id='a' AND task_id=?", (task_id,))
        warnings = c.workflow_warnings(
            self.conn, "a", "a.director.codex", "agent")
        self.assertIn("stale_task_ownership",
                      {item["code"] for item in warnings})


if __name__ == "__main__":
    unittest.main()
