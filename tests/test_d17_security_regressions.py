"""Focused regressions for the D-17 security and workflow boundaries."""

import contextlib
import http.client
import http.cookies
import importlib.util
import json
import sqlite3
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import terminal_flow as flow  # noqa: E402


SPEC = importlib.util.spec_from_file_location(
    "attacca_d17_security_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class D17SecurityHttpTest(unittest.TestCase):
    """Exercise client-install credentials at the real protected boundary."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "d17-security-http.db"
        self.server = c.AttaccaServer(("127.0.0.1", 0), self.db, auth=True)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address
        self.url = "http://%s:%d" % (self.host, self.port)
        self.session = self.request("POST", "/v1/auth/bootstrap", {
            "username": "jack",
            "display_name": "Jack",
            "password": "jack-password",
        })
        self.assertEqual(self.session["status"], 201, self.session["body"])

        conn = c.connect(self.db)
        try:
            jack = conn.execute(
                "SELECT * FROM auth_users WHERE username='jack'").fetchone()
            c.set_current_owner("jack")
            c.project_init(
                conn, "web.jack", "human", path=self.root / "checkout",
                project_id="proj", name="Project")
            conn.execute(
                "INSERT OR IGNORE INTO auth_project_memberships"
                " (user_id,project_id,granted_at,granted_by)"
                " VALUES (?,?,?,?)",
                (jack["user_id"], "proj", c.now_iso(), "jack"))
            c.agent_register(
                conn, "proj", "web.jack", "human",
                agent_id="proj.director.codex", role="director",
                runtime="codex", registration_username="jack")
        finally:
            c.set_current_owner(None)
            conn.close()

    def tearDown(self):
        c.set_current_owner(None)
        c.set_current_git_context()
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

    def create_key(self, instance="install-home", memberships=None):
        if memberships is None:
            memberships = ["proj"]
        result = self.request(
            "POST", "/v1/auth/client-keys", {
                "label": "D-17 install",
                "client_instance": instance,
                "project_memberships": memberships,
            }, self.session_headers())
        self.assertEqual(result["status"], 201, result["body"])
        return result["body"]["token"]

    def activate(self):
        result = self.request(
            "POST", "/v1/auth/activation",
            {"enabled": True, "confirmed": True}, self.session_headers())
        self.assertEqual(result["status"], 200, result["body"])
        self.assertTrue(result["body"]["activated"])

    @staticmethod
    def client_headers(token, instance="install-home", actor=None):
        headers = {
            "Authorization": "Bearer " + token,
            "X-Attacca-Client-Instance": instance,
        }
        if actor:
            headers.update({
                "X-Attacca-Project": "proj",
                "X-Attacca-Actor": actor,
            })
        return headers

    def test_explicit_scope_loses_visibility_and_access_after_membership_revoke(self):
        token = self.create_key()
        self.activate()
        list_headers = self.client_headers(token)
        actor_headers = self.client_headers(
            token, actor="proj.director.codex")
        before = self.request("GET", "/v1/projects", headers=list_headers)
        self.assertEqual(before["status"], 200, before["body"])
        self.assertEqual(
            {item["project_id"] for item in before["body"]["projects"]},
            {"proj"})
        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/status",
            headers=actor_headers)["status"], 200)

        conn = c.connect(self.db)
        try:
            conn.execute(
                "UPDATE auth_project_memberships SET revoked_at=?"
                " WHERE project_id='proj'", (c.now_iso(),))
            principal = c.auth_token_principal(conn, token)
            self.assertIsNotNone(principal)
            self.assertEqual(c.auth_visible_project_ids(conn, principal), set())
        finally:
            conn.close()

        after = self.request("GET", "/v1/projects", headers=list_headers)
        self.assertEqual(after["status"], 200, after["body"])
        self.assertEqual(after["body"]["projects"], [])
        denied = self.request(
            "GET", "/v1/projects/proj/status", headers=actor_headers)
        self.assertEqual(denied["status"], 403, denied["body"])

    def test_client_key_create_rejects_non_array_membership_shapes(self):
        invalid_values = (
            ("nonempty-dict", {"proj": True}),
            ("empty-dict", {}),
            ("nonempty-string", "proj"),
            ("empty-string", ""),
            ("true", True),
            ("false", False),
            ("one", 1),
            ("zero", 0),
        )
        for index, (label, value) in enumerate(invalid_values):
            with self.subTest(label=label):
                result = self.request(
                    "POST", "/v1/auth/client-keys", {
                        "label": label,
                        "client_instance": "bad-shape-%d" % index,
                        "project_memberships": value,
                    }, self.session_headers())
                self.assertEqual(result["status"], 400, result["body"])
                self.assertIn("must be an array", result["body"]["error"])

        listed = self.request(
            "GET", "/v1/auth/client-keys", headers=self.session_headers())
        self.assertEqual(listed["status"], 200, listed["body"])
        self.assertEqual(listed["body"]["client_keys"], [])

        valid_account_scopes = (
            ("omitted", {}),
            ("empty-array", {"project_memberships": []}),
        )
        for index, (label, extra) in enumerate(valid_account_scopes):
            with self.subTest(valid=label):
                body = {
                    "label": label,
                    "client_instance": "account-scope-%d" % index,
                    **extra,
                }
                created = self.request(
                    "POST", "/v1/auth/client-keys", body,
                    self.session_headers())
                self.assertEqual(created["status"], 201, created["body"])
                record = created["body"]["record"]
                self.assertEqual(record["scope_mode"], "account_memberships")
                self.assertEqual(record["project_memberships"], [])
                visible = self.request(
                    "GET", "/v1/projects", headers=self.client_headers(
                        created["body"]["token"],
                        instance=body["client_instance"]))
                self.assertEqual(visible["status"], 200, visible["body"])
                self.assertEqual(
                    {item["project_id"]
                     for item in visible["body"]["projects"]}, {"proj"})

    def test_alias_owned_actor_repairs_idempotently_but_cannot_escalate(self):
        actor_id = "proj.worker.legacy"
        conn = c.connect(self.db)
        try:
            jack = conn.execute(
                "SELECT user_id FROM auth_users WHERE username='jack'").fetchone()
            conn.execute(
                "INSERT INTO auth_user_owner_aliases"
                " (alias_key,alias,user_id,created_at,created_by)"
                " VALUES (?,?,?,?,?)",
                ("legacy-shell", "Legacy-Shell", jack["user_id"],
                 c.now_iso(), "jack"))
            c.set_current_owner("Legacy-Shell")
            c.agent_register(
                conn, "proj", "legacy.setup", "human", agent_id=actor_id,
                display_name="Legacy Worker", role="worker",
                runtime="legacy")
        finally:
            c.set_current_owner(None)
            conn.close()

        token = self.create_key()
        self.activate()
        headers = self.client_headers(token, actor=actor_id)
        repaired = self.request(
            "POST", "/v1/projects/proj/agents", {
                "agent_id": actor_id,
                "display_name": "Legacy Worker",
                "role": "worker",
                "runtime": "legacy",
            }, headers)
        self.assertEqual(repaired["status"], 200, repaired["body"])
        self.assertTrue(repaired["body"]["already_registered"])
        self.assertEqual(repaired["body"]["agent_id"], actor_id)

        escalations = (
            {"agent_id": actor_id, "role": "director",
             "runtime": "legacy"},
            {"agent_id": actor_id, "role": "worker",
             "runtime": "other-runtime"},
        )
        for body in escalations:
            with self.subTest(body=body):
                denied = self.request(
                    "POST", "/v1/projects/proj/agents", body, headers)
                self.assertEqual(denied["status"], 403, denied["body"])
                self.assertIn(
                    "agent_registration_not_idempotent",
                    denied["body"]["error"])

        conn = c.connect(self.db)
        try:
            row = conn.execute(
                "SELECT owner,role,runtime FROM agents"
                " WHERE project_id='proj' AND agent_id=?", (actor_id,)
            ).fetchone()
            self.assertEqual(dict(row), {
                "owner": "Legacy-Shell",
                "role": "worker",
                "runtime": "legacy",
            })
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM agents WHERE project_id='proj'"
                " AND runtime IN ('legacy','other-runtime')"
            ).fetchone()["n"], 1)
        finally:
            conn.close()

    def test_fresh_runtime_persists_install_key_before_exact_registration(self):
        token = self.create_key(instance="shared-install")
        self.activate()
        actor_id = "proj.director.claude"
        credentials = self.root / "second-runtime-credentials.json"
        conn = c.connect(self.db)
        try:
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM agents WHERE project_id='proj' AND agent_id=?",
                (actor_id,)).fetchone())
        finally:
            conn.close()

        class RecordingTransport:
            def __init__(self):
                self.delegate = flow.UrllibJsonTransport()
                self.calls = []

            def request(self, method, url, *, headers, payload=None, timeout=5):
                self.calls.append({
                    "method": method, "url": url, "headers": dict(headers)})
                return self.delegate.request(
                    method, url, headers=headers, payload=payload,
                    timeout=timeout)

        transport = RecordingTransport()

        @contextlib.contextmanager
        def hidden_tty():
            yield object()

        with mock.patch.object(flow, "_read_hidden_line", return_value=token):
            saved = flow.paste_client_api_key(
                self.url, client_instance="shared-install",
                project_id="proj", actor_id=actor_id,
                credentials_path=credentials, transport=transport,
                tty_opener=hidden_tty)
        self.assertEqual(saved["status"], "ready")
        self.assertNotIn(token, json.dumps(saved))
        self.assertEqual(len(transport.calls), 1)
        self.assertNotIn(flow.PROJECT_HEADER, transport.calls[0]["headers"])
        self.assertNotIn(flow.ACTOR_HEADER, transport.calls[0]["headers"])
        self.assertEqual(stat.S_IMODE(credentials.stat().st_mode), 0o600)
        self.assertEqual(flow.load_client_api_key(
            self.url, client_instance="shared-install", project_id="proj",
            credentials_path=credentials), token)

        headers = flow.client_request_headers(
            self.url, client_instance="shared-install", project_id="proj",
            actor_id=actor_id, credentials_path=credentials)
        denied = self.request(
            "POST", "/v1/projects/proj/room",
            {"body": "setup credentials are not actor authority"}, headers)
        self.assertEqual(denied["status"], 403, denied["body"])
        registered = self.request(
            "POST", "/v1/projects/proj/agents", {
                "agent_id": actor_id,
                "display_name": "Project Claude",
                "role": "director",
                "runtime": "claude",
            }, headers)
        self.assertEqual(registered["status"], 200, registered["body"])
        self.assertEqual(registered["body"]["agent_id"], actor_id)
        self.assertFalse(registered["body"]["already_registered"])
        exact = self.request(
            "GET", "/v1/projects/proj/status", headers=headers)
        self.assertEqual(exact["status"], 200, exact["body"])

        conn = c.connect(self.db)
        try:
            actor = conn.execute(
                "SELECT owner,role,runtime FROM agents"
                " WHERE project_id='proj' AND agent_id=?", (actor_id,)
            ).fetchone()
            self.assertEqual(dict(actor), {
                "owner": "jack", "role": "director", "runtime": "claude"})
        finally:
            conn.close()

    def test_fresh_runtime_setup_discovery_is_strictly_read_only(self):
        token = self.create_key(instance="discovery-install")
        self.activate()
        actor_id = "proj.worker.fresh-runtime"
        headers = self.client_headers(
            token, instance="discovery-install", actor=actor_id)
        conn = c.connect(self.db)
        try:
            before_cursors = [tuple(row) for row in conn.execute(
                "SELECT project_id,actor_id,last_read_seq FROM inbox_cursors"
                " ORDER BY project_id,actor_id").fetchall()]
        finally:
            conn.close()

        allowed = (
            "/v1/projects/proj/status",
            "/v1/projects/proj/agents",
            "/v1/projects/proj/bridges",
            "/v1/projects/proj/inbox",
        )
        for path in allowed:
            with self.subTest(allowed=path):
                result = self.request("GET", path, headers=headers)
                self.assertEqual(result["status"], 200, result["body"])

        denied_gets = (
            "/v1/projects/proj/room",
            "/v1/projects/proj/tasks",
            "/v1/projects/proj/handoff",
            "/v1/projects/proj/sync/snapshot",
        )
        for path in denied_gets:
            with self.subTest(denied=path):
                result = self.request("GET", path, headers=headers)
                self.assertEqual(result["status"], 403, result["body"])
        mutation = self.request(
            "POST", "/v1/projects/proj/room",
            {"body": "fresh setup must not mutate"}, headers)
        self.assertEqual(mutation["status"], 403, mutation["body"])
        mcp = self.request("POST", "/mcp", {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "fresh-runtime", "version": "1"},
            },
        }, headers)
        self.assertEqual(mcp["status"], 403, mcp["body"])

        conn = c.connect(self.db)
        try:
            after_cursors = [tuple(row) for row in conn.execute(
                "SELECT project_id,actor_id,last_read_seq FROM inbox_cursors"
                " ORDER BY project_id,actor_id").fetchall()]
            self.assertEqual(after_cursors, before_cursors)
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM agents WHERE project_id='proj' AND agent_id=?",
                (actor_id,)).fetchone())
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM events"
                " WHERE payload LIKE '%fresh setup must not mutate%'"
            ).fetchone()["n"], 0)
        finally:
            conn.close()


class D17AliasNamespaceTest(unittest.TestCase):
    def test_alias_username_collisions_fail_closed_and_block_new_accounts(self):
        with tempfile.TemporaryDirectory() as directory:
            conn = c.connect(Path(directory) / "alias-namespace.db")
            try:
                c.auth_create_user(
                    conn, "jack", "jack-password", display_name="Jack",
                    is_admin=True, bootstrap=True)
                c.auth_create_user(
                    conn, "bob", "bob-password", display_name="Bob")
                users = {row["username"]: row for row in conn.execute(
                    "SELECT * FROM auth_users")}
                principals = {
                    name: c._auth_principal(
                        conn, row, "session", session_hash=name)
                    for name, row in users.items()
                }
                c.set_current_owner("jack")
                c.project_init(
                    conn, "web.jack", "human", path=Path(directory) / "repo",
                    project_id="proj", name="Project")
                for row in users.values():
                    conn.execute(
                        "INSERT OR IGNORE INTO auth_project_memberships"
                        " (user_id,project_id,granted_at,granted_by)"
                        " VALUES (?,?,?,?)",
                        (row["user_id"], "proj", c.now_iso(), "jack"))

                # Simulate a legacy/external database containing a collision:
                # Bob's username and Jack's alias resolve to the same label.
                conn.execute(
                    "INSERT INTO auth_user_owner_aliases"
                    " (alias_key,alias,user_id,created_at,created_by)"
                    " VALUES (?,?,?,?,?)",
                    ("bob", "Bob", users["jack"]["user_id"],
                     c.now_iso(), "jack"))
                c.set_current_owner("Bob")
                c.agent_register(
                    conn, "proj", "legacy.setup", "human",
                    agent_id="proj.worker.collision", role="worker",
                    runtime="collision")
                self.assertIsNone(c._auth_owner_label_user_id(conn, "BOB"))

                for username in ("jack", "bob"):
                    created = c.auth_client_key_create(
                        conn, principals[username], username + " install",
                        "install-" + username, memberships=["proj"])
                    token_principal = c.auth_token_principal(
                        conn, created["token"])
                    with self.subTest(username=username):
                        with self.assertRaisesRegex(
                                c.AuthorizationError,
                                "client_actor_denied"):
                            c.auth_client_principal_scope(
                                conn, token_principal, "proj",
                                "proj.worker.collision")

                conn.execute(
                    "INSERT INTO auth_user_owner_aliases"
                    " (alias_key,alias,user_id,created_at,created_by)"
                    " VALUES (?,?,?,?,?)",
                    ("legacyreserved", "LegacyReserved",
                     users["jack"]["user_id"], c.now_iso(), "jack"))
                with self.assertRaisesRegex(c.AttaccaError, "reserved"):
                    c.auth_create_user(
                        conn, "legacyreserved", "new-password")

                invitation = c.auth_invitation_create(
                    conn, principals["jack"], "Join project", ["proj"])
                with self.assertRaisesRegex(c.AttaccaError, "reserved"):
                    c.auth_invitation_accept(
                        conn, invitation["invitation_token"],
                        "legacyreserved", "invite-password")
                row = conn.execute(
                    "SELECT accepted_at,accepted_user_id FROM auth_invitations"
                    " WHERE invitation_id=?",
                    (invitation["record"]["invitation_id"],)).fetchone()
                self.assertIsNone(row["accepted_at"])
                self.assertIsNone(row["accepted_user_id"])
            finally:
                c.set_current_owner(None)
                conn.close()


class D17WorkflowRegressionTest(unittest.TestCase):
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

    def create_claimed_task(self, title):
        task_id = c.task_create(
            self.conn, "a", "a.director.codex", "agent", title)["task_id"]
        c.task_claim(
            self.conn, "a", "a.director.codex", "agent", task_id)
        return task_id

    def test_message_disposition_cannot_substitute_unrelated_linked_task(self):
        linked = c.task_create(
            self.conn, "a", "a.director.claude", "agent", "Linked")["task_id"]
        unrelated = c.task_create(
            self.conn, "a", "a.director.claude", "agent",
            "Unrelated")["task_id"]
        message = c.room_send(
            self.conn, "a", "a.director.claude", "agent", "Please act",
            mentions=["a.director.codex"], task_id=linked)
        event_id = message["event"]["event_id"]

        with self.assertRaisesRegex(c.AttaccaError, "cannot substitute"):
            c.message_dispose(
                self.conn, "a", "a.director.codex", "agent", event_id,
                "acknowledged", task_id=unrelated)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS n FROM message_dispositions"
            " WHERE project_id='a' AND message_event_id=?", (event_id,)
        ).fetchone()["n"], 0)

        accepted = c.message_dispose(
            self.conn, "a", "a.director.codex", "agent", event_id,
            "acknowledged")
        self.assertEqual(accepted["task_id"], linked)

    def test_done_requires_meaningful_identified_passing_evidence(self):
        empty_task = self.create_claimed_task("Reject empty evidence object")
        with self.assertRaisesRegex(c.AttaccaError, "meaningful non-empty"):
            c.task_report(
                self.conn, "a", "a.director.codex", "agent", empty_task,
                "Done", evidence=[{}], requested_state="done")
        untouched = c.task_show(self.conn, "a", empty_task)
        self.assertEqual(untouched["status"], "claimed")
        self.assertIsNone(untouched["last_report"])

        cases = (
            ("Failing check", [{"kind": "test", "name": "pytest focused",
                                "result": "failed"}], "failed"),
            ("Missing verdict", [{"kind": "test", "name": "pytest focused"}],
             "unverified"),
        )
        for title, evidence, verification in cases:
            with self.subTest(title=title):
                task_id = self.create_claimed_task(title)
                result = c.task_report(
                    self.conn, "a", "a.director.codex", "agent", task_id,
                    "Attempted completion", evidence=evidence,
                    requested_state="done")
                self.assertEqual(result["requested_state"], "done")
                self.assertEqual(result["status"], "review")
                self.assertEqual(result["verification_status"], verification)
                shown = c.task_show(self.conn, "a", task_id)
                self.assertEqual(shown["status"], "review")
                self.assertEqual(shown["verification_status"], verification)
                self.assertEqual(shown["last_report"]["evidence"], evidence)

        passing = [{"kind": "test", "name": "pytest focused",
                    "result": "pass"}]
        passed_task = self.create_claimed_task("Credible passing check")
        result = c.task_report(
            self.conn, "a", "a.director.codex", "agent", passed_task,
            "Verified completion", evidence=passing, requested_state="done")
        self.assertEqual(result["status"], "done")
        self.assertEqual(result["verification_status"], "verified")
        shown = c.task_show(self.conn, "a", passed_task)
        self.assertEqual(shown["status"], "done")
        self.assertEqual(shown["last_report"]["evidence"], passing)

    def test_bridge_destination_failure_rolls_back_source_atomically(self):
        before_events = {
            project: [tuple(row) for row in self.conn.execute(
                "SELECT event_id,seq,hash FROM events WHERE project_id=?"
                " ORDER BY seq", (project,)).fetchall()]
            for project in ("a", "b")
        }
        before_seen = self.conn.execute(
            "SELECT last_seen_at FROM agents WHERE project_id='a'"
            " AND agent_id='a.director.codex'").fetchone()["last_seen_at"]
        self.conn.execute(
            "CREATE TRIGGER fail_bridge_destination BEFORE INSERT ON events"
            " WHEN NEW.project_id='b' AND NEW.event_type='room.message'"
            " BEGIN SELECT RAISE(ABORT,"
            " 'injected destination append failure'); END")
        with self.assertRaisesRegex(
                sqlite3.IntegrityError, "destination append failure"):
            c.room_send(
                self.conn, "a", "a.director.codex", "agent",
                "must be atomic", target_project="b")

        for project in ("a", "b"):
            after = [tuple(row) for row in self.conn.execute(
                "SELECT event_id,seq,hash FROM events WHERE project_id=?"
                " ORDER BY seq", (project,)).fetchall()]
            self.assertEqual(after, before_events[project])
        after_seen = self.conn.execute(
            "SELECT last_seen_at FROM agents WHERE project_id='a'"
            " AND agent_id='a.director.codex'").fetchone()["last_seen_at"]
        self.assertEqual(after_seen, before_seen)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS n FROM events"
            " WHERE payload LIKE '%must be atomic%'"
        ).fetchone()["n"], 0)

    def test_same_revision_branch_change_warns_without_active_claim(self):
        c.set_current_git_context("main", "same-sha", "device/client")
        c.append_event(
            self.conn, "a", "a.director.codex", "agent", "note.test", {})
        c.set_current_git_context(
            "feature/security", "same-sha", "device/client")
        warning = next(item for item in c.workflow_warnings(
            self.conn, "a", "a.director.codex", "agent")
            if item["code"] == "off_board_repository_mutation")
        self.assertEqual(warning["from_revision"], "same-sha")
        self.assertEqual(warning["to_revision"], "same-sha")
        self.assertEqual(warning["from_branch"], "main")
        self.assertEqual(warning["to_branch"], "feature/security")

    def test_offline_disposition_overlay_is_cursor_independent_and_in_parity(self):
        actor_id = "a.director.codex"
        message_id = "ev_offline_assignment"
        message = {
            "event_id": message_id,
            "project_id": "a",
            "seq": 5,
            "actor": "a.director.claude",
            "actor_type": "agent",
            "body": "Offline assignment",
            "msg_type": "directive",
            "mentions": [actor_id],
            "reply_to": None,
        }
        snapshot = {
            "scope": {
                "project_id": "a",
                "principal_id": "jack",
                "actor_id": actor_id,
                "actor_type": "agent",
                "role": "director",
            },
            "cursor": {"event_seq": 5, "context_version": 1},
            "records": [],
            "projection": {
                "project": {
                    "project_id": "a", "name": "A", "context_version": 1,
                    "lead_director": actor_id,
                },
                "room_messages": [message],
                "message_dispositions": [],
                # The hosted cursor is already past the assignment. Pending
                # disposition state must be computed independently from it.
                "inbox_cursor": {"last_read_seq": 99},
                "handoffs": [],
                "tasks": [],
                "decisions": [],
                "bridges": [],
                "full_log": [],
                "cloud_context": None,
            },
        }

        class FakeAdapter:
            def __init__(self):
                self.overlays = []

            def pending_overlays(self, section=None):
                if section and section != "message_dispositions":
                    return []
                return [dict(item) for item in self.overlays]

            def status(self):
                return {
                    "mode": "offline",
                    "pending_sync": bool(self.overlays),
                    "pending_count": len(self.overlays),
                    "conflict_count": 0,
                    "convergence_awaiting_count": 0,
                }

            @staticmethod
            def rules_for_role(_role):
                return []

        adapter = FakeAdapter()
        proof = {
            "mirror_stale": False,
            "mirror_verified_at": "2026-08-26T00:00:00.000Z",
            "cursor": snapshot["cursor"],
        }
        session = c.OfflineProxySession(
            "https://offline.invalid", lambda: "a", self.temp.name,
            "codex", "codex", "device-offline")

        def read_pending():
            inbox = session._read(
                "check_inbox", {"mark_read": False, "limit": 50},
                adapter, snapshot, proof)
            handoff = session._read(
                "get_handoff", {}, adapter, snapshot, proof)
            return inbox, handoff["your_inbox"]

        inbox, handoff = read_pending()
        self.assertEqual(inbox["unread_total"], 0)
        self.assertEqual(inbox["read_cursor"], 99)
        for view in (inbox, handoff):
            self.assertEqual(view["pending_disposition_total"], 1)
            self.assertEqual(
                view["pending_dispositions"][0]["event_id"], message_id)

        adapter.overlays = [{
            "resource": "message_dispositions",
            "client_mutation_id": "cm_dispose_blocked",
            "operation": "message.dispose",
            "payload": {
                "event_id": message_id,
                "disposition": "blocked",
                "note": "Waiting for reconnect",
            },
            "metadata": {},
            "sync_state": "ready",
        }]
        inbox, handoff = read_pending()
        for view in (inbox, handoff):
            self.assertEqual(view["pending_disposition_total"], 1)
            disposition = view["pending_dispositions"][0]["disposition"]
            self.assertEqual(disposition["disposition"], "blocked")
            self.assertTrue(disposition["pending_sync"])
            self.assertTrue(disposition["local_only"])

        adapter.overlays[0]["client_mutation_id"] = "cm_dispose_ack"
        adapter.overlays[0]["payload"] = {
            "event_id": message_id,
            "disposition": "acknowledged",
        }
        inbox, handoff = read_pending()
        for view in (inbox, handoff):
            self.assertEqual(view["pending_disposition_total"], 0)
            self.assertEqual(view["pending_dispositions"], [])


if __name__ == "__main__":
    unittest.main()
