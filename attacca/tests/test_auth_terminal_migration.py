"""Terminal credential and fail-open migration authentication regressions.

All servers bind to loopback port 0 and all databases are temporary.  This
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
    "attacca_terminal_migration_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)
protocol, _sync_server = c._sync_runtime()


class TerminalMigrationTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "terminal-migration.db"
        conn = c.connect(self.db)
        c.auth_create_user(
            conn, "alice", "correct-horse", display_name="Alice",
            is_admin=True, bootstrap=True)
        c.auth_create_user(
            conn, "bob", "battery-staple", display_name="Bob")
        c.set_current_owner("alice")
        c.project_init(
            conn, "web.alice", "human", path=Path(self.tmp.name) / "project",
            project_id="proj", name="Project")
        # Deliberately non-canonical historical id. Credential enrollment must
        # never rewrite this row or attribute new actions to a derived id.
        c.agent_register(
            conn, "proj", "web.alice", "human",
            agent_id="proj.director.codex-legacy", display_name="Historic Director",
            role="director", runtime="codex")
        c.agent_register(
            conn, "proj", "web.alice", "human",
            agent_id="proj.worker.codex-legacy", display_name="Historic Worker",
            role="worker", runtime="codex")
        c.set_lead_director(
            conn, "proj", "web.alice", "human", "proj.director.codex-legacy")
        c.set_current_owner(None)
        conn.close()
        self.server = None
        self.thread = None
        self.start_server(auth=True, auth_mode="auto")
        self.admin = self.login("alice", "correct-horse")

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
        result = {
            "status": response.status,
            "headers": response.headers,
            "body": (json.loads(raw) if raw and "json" in content_type
                     else raw.decode("utf-8", "replace") if raw else {}),
        }
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

    @staticmethod
    def terminal_headers(credential, actor=None):
        result = {
            "Authorization": "Bearer " + credential["token"],
            "X-Attacca-Device-ID": credential["device_id"],
            "X-Attacca-Client-Instance": credential["client_instance"],
        }
        if actor:
            result["X-Attacca-Actor"] = actor
        return result

    def actor_state(self):
        conn = c.connect(self.db)
        try:
            agents = [tuple(row) for row in conn.execute(
                "SELECT * FROM agents ORDER BY project_id,agent_id")]
            project = tuple(conn.execute(
                "SELECT * FROM projects WHERE project_id='proj'").fetchone())
            ledger = [tuple(row) for row in conn.execute(
                "SELECT * FROM events WHERE project_id='proj' ORDER BY seq")]
            return agents, project, ledger
        finally:
            conn.close()

    def start_flow(self, device="device-one", client_instance="client-one",
                   bindings=None, headers=None, supersede=None):
        response = self.request("POST", "/v1/auth/device/start", {
            "device_id": device,
            "client_label": "Codex terminal",
            "client_instance": client_instance,
            "requested_bindings": bindings or [{
                "project_id": "proj", "actor_id": "proj.director.codex-legacy"}],
            "supersede_token_id": supersede,
        }, headers)
        self.assertEqual(response["status"], 201, response["body"])
        return response["body"]

    def approve_flow(self, flow, bindings=None, headers=None):
        response = self.request(
            "POST", "/v1/auth/terminal-enrollments/%s/approve" %
            urllib.parse.quote(flow["user_code"], safe=""), {
                "project_memberships": ["proj"],
                "actor_bindings": bindings or [{
                    "project_id": "proj",
                    "actor_id": "proj.director.codex-legacy",
                }],
            }, headers or self.admin)
        return response

    def poll_flow(self, flow, device="device-one",
                  client_instance="client-one"):
        return self.request("POST", "/v1/auth/device/poll", {
            "device_code": flow["device_code"],
            "device_id": device,
            "client_instance": client_instance,
        })

    def issue_terminal(self):
        flow = self.start_flow()
        approved = self.approve_flow(flow)
        self.assertEqual(approved["status"], 200, approved["body"])
        issued = self.poll_flow(flow)
        self.assertEqual(issued["status"], 200, issued["body"])
        self.assertEqual(issued["body"]["status"], "approved")
        return flow, issued["body"]["credential"]

    def compatibility_headers(self, actor="proj.director.codex-legacy",
                              device="device-one"):
        headers = {
            "Authorization": "Bearer stale-legacy-token",
            "X-Attacca-Device-ID": device,
            "X-Attacca-Client-Instance": "compat-client",
        }
        if actor is not None:
            headers["X-Attacca-Actor"] = actor
        return headers

    def test_fresh_bootstrapped_restart_is_compatibility_and_qa_blocked(self):
        status = self.request("GET", "/v1/auth/status")
        self.assertEqual(status["status"], 200)
        self.assertFalse(status["body"]["authentication_required"])
        self.assertEqual(status["body"]["effective_authentication"], "optional")
        self.assertTrue(status["body"]["compatibility_active"])
        self.assertEqual(self.request(
            "GET", "/v1/projects",
            headers={"Authorization": "Bearer stale"})["status"], 200)
        access = self.request("GET", "/v1/auth/access", headers=self.admin)
        qa = access["body"]["compatibility"]["qa_evidence"]
        self.assertFalse(qa["acceptance"]["passed"])
        self.assertFalse(qa["regression"]["passed"])
        self.assertIn("both required QA passes must be recorded",
                      access["body"]["compatibility"]["blockers"])

        conn = c.connect(self.db)
        try:
            c.server_settings_store(conn, {
                "test.true": True, "test.false": False,
                "test.dict": {"nested": [1, 2]},
            })
            self.assertIs(c._auth_setting(conn, "test.true"), True)
            self.assertIs(c._auth_setting(conn, "test.false"), False)
            self.assertEqual(c._auth_setting(conn, "test.dict"),
                             {"nested": [1, 2]})
        finally:
            conn.close()

    def test_qa_fingerprint_covers_every_security_critical_package_file(self):
        guided_auth_files = {
            "skills/update/SKILL.md",
            "kimi-commands/setup.md",
            "kimi-commands/update.md",
            "kimi-skills/session/SKILL.md",
        }
        self.assertTrue(
            guided_auth_files.issubset(set(c.AUTH_ARTIFACT_FILES)))
        self.assertTrue(
            set(c.AUTH_ARTIFACT_FILES).issubset(set(c.PLUGIN_FILES)))
        package = Path(self.tmp.name) / "fingerprint-package"
        for relative in c.AUTH_ARTIFACT_FILES:
            target = package / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fixture:%s\n" % relative)
        with mock.patch.object(
                c, "script_path", return_value=str(package / "attacca.py")):
            before = c.auth_source_sha256()
            for relative in sorted(guided_auth_files):
                target = package / relative
                original = target.read_text()
                target.write_text(original + "changed auth guidance\n")
                self.assertNotEqual(before, c.auth_source_sha256(), relative)
                target.write_text(original)
            (package / "web" / "admin.html").unlink()
            self.assertIsNone(c.auth_source_sha256())

    def test_compatibility_snapshot_pull_push_is_exact_actor_and_device(self):
        headers = self.compatibility_headers()
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
            "GET", "/v1/projects/proj/sync/pull?" + query,
            headers=headers)
        self.assertEqual(pulled["status"], 200, pulled["body"])
        protocol.validate_pull_result(pulled["body"])

        mutation = protocol.make_client_mutation(
            snapshot["scope"], "compat_room_send_0001", "compat-client",
            "device-one", 1, "room.send", {"body": "migration bridge"},
            snapshot["cursor"], metadata={
                "git_branch": "feature/migration",
                "git_revision": "deadbeef",
            })
        envelope = protocol.make_push_request(
            snapshot["scope"], snapshot["visibility_fingerprint"],
            "compat-client", "device-one", [mutation])
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
            self.assertEqual(event["actor_id"], "proj.director.codex-legacy")
            self.assertEqual(event["owner"], "alice")
            self.assertEqual(event["device_id"],
                             "device-one/compat-client")
            self.assertEqual(event["git_branch"], "feature/migration")
            target = conn.execute(
                "SELECT * FROM auth_migration_targets WHERE project_id='proj'"
                " AND actor_id='proj.director.codex-legacy'"
                " AND device_id='device-one'").fetchone()
            self.assertIsNotNone(target)
        finally:
            conn.close()

        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/sync/snapshot",
            headers=self.compatibility_headers(actor=None))["status"], 401)
        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/sync/snapshot",
            headers=self.compatibility_headers(actor="unknown"))["status"], 403)
        # Both registered actors use codex, so a short runtime is ambiguous.
        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/sync/snapshot",
            headers=self.compatibility_headers(actor="codex"))["status"], 403)
        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/sync/snapshot",
            headers=self.compatibility_headers(device=""))["status"], 401)

    def test_device_delivery_is_retry_safe_hash_only_and_preserves_actors(self):
        before = self.actor_state()
        flow = self.start_flow()
        self.assertEqual(
            flow["verification_uri_complete"],
            "http://%s:%s/app?user_code=%s#settings" % (
                self.host, self.port,
                urllib.parse.quote(flow["user_code"], safe="")))
        approved = self.approve_flow(flow)
        self.assertEqual(approved["status"], 200, approved["body"])
        first = self.poll_flow(flow)
        retry = self.poll_flow(flow)
        self.assertEqual(first["body"]["status"], "approved")
        self.assertEqual(retry["body"]["status"], "approved")
        first_credential = first["body"]["credential"]
        retry_credential = retry["body"]["credential"]
        self.assertEqual(first_credential["token"], flow["device_code"])
        self.assertEqual(retry_credential["token"], flow["device_code"])
        self.assertEqual(first_credential["token_id"],
                         retry_credential["token_id"])
        self.assertEqual(first_credential["client_instance"], "client-one")
        self.assertEqual(first_credential["bindings"][0]["actor_id"],
                         "proj.director.codex-legacy")
        self.assertEqual(first_credential["bindings"][0]
                         ["operational_actor_id"], "proj.director.codex-legacy")

        conn = c.connect(self.db)
        try:
            dump = "\n".join(conn.iterdump())
            self.assertNotIn(flow["device_code"], dump)
            self.assertIn(c.sha256_hex(flow["device_code"]), dump)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM auth_tokens"
                " WHERE token_kind='terminal'").fetchone()["n"], 1)
        finally:
            conn.close()

        status = self.request(
            "GET", "/v1/auth/status",
            headers=self.terminal_headers(first_credential,
                                          "proj.director.codex-legacy"))
        self.assertEqual(status["status"], 200, status["body"])
        principal = status["body"]["principal"]
        self.assertEqual(principal["token_kind"], "terminal")
        self.assertEqual(principal["token_id"], first_credential["token_id"])
        self.assertEqual(principal["device_id"], "device-one")
        self.assertEqual(principal["client_instance"], "client-one")
        self.assertEqual(principal["bindings"][0]["actor_id"],
                         "proj.director.codex-legacy")
        self.assertEqual(self.poll_flow(flow)["body"]["status"], "consumed")
        wrong_device = self.terminal_headers(first_credential)
        wrong_device["X-Attacca-Device-ID"] = "different-device"
        self.assertEqual(self.request(
            "GET", "/v1/auth/status", headers=wrong_device)["status"], 403)
        wrong_actor = self.terminal_headers(
            first_credential, "proj.worker.codex-legacy")
        self.assertEqual(self.request(
            "GET", "/v1/projects/proj/status",
            headers=wrong_actor)["status"], 403)
        self.assertEqual(self.actor_state(), before)

    def test_managed_law_refresh_uses_bound_terminal_when_auth_is_enforced(self):
        _flow, credential = self.issue_terminal()
        conn = c.connect(self.db)
        try:
            c.server_settings_store(conn, {"auth.activated": True})
        finally:
            conn.close()

        path = "/v1/managed-law?project=proj"
        anonymous = self.request("GET", path)
        self.assertEqual(anonymous["status"], 401, anonymous["body"])

        headers = self.terminal_headers(
            credential, "proj.director.codex-legacy")
        headers["X-Attacca-Actor-Type"] = "agent"
        headers["X-Attacca-Project"] = "proj"
        authenticated = self.request("GET", path, headers=headers)
        self.assertEqual(
            authenticated["status"], 200, authenticated["body"])
        self.assertEqual(
            authenticated["body"]["version"], c.MANAGED_BLOCK_VERSION)
        self.assertIn(
            "project=proj", authenticated["body"]["block"].splitlines()[0])

        other = self.request(
            "GET", "/v1/managed-law?project=other", headers=headers)
        self.assertEqual(other["status"], 403, other["body"])
        self.assertIn("bound to workspace 'proj'", other["body"]["error"])

    def test_extension_supersedes_old_token_and_preserves_binding_union(self):
        _old_flow, old = self.issue_terminal()
        union = [
            {"project_id": "proj", "actor_id": "proj.director.codex-legacy"},
            {"project_id": "proj", "actor_id": "proj.worker.codex-legacy"},
        ]
        replacement = self.start_flow(
            bindings=union,
            headers=self.terminal_headers(old),
            supersede=old["token_id"])
        approved = self.approve_flow(replacement, bindings=union)
        self.assertEqual(approved["status"], 200, approved["body"])
        response = self.poll_flow(replacement)
        self.assertEqual(response["body"]["status"], "approved")
        new = response["body"]["credential"]
        self.assertEqual(
            {item["actor_id"] for item in new["bindings"]},
            {"proj.director.codex-legacy", "proj.worker.codex-legacy"})
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
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) AS n FROM auth_tokens"
                " WHERE token_kind='terminal' AND revoked_at IS NULL"
            ).fetchone()["n"], 1)
        finally:
            conn.close()

    def test_member_cannot_bind_another_users_director(self):
        conn = c.connect(self.db)
        try:
            bob = conn.execute(
                "SELECT * FROM auth_users WHERE username='bob'").fetchone()
            conn.execute(
                "INSERT INTO auth_project_memberships"
                " (user_id,project_id,granted_at,granted_by) VALUES (?,?,?,?)",
                (bob["user_id"], "proj", c.now_iso(), "alice"))
        finally:
            conn.close()
        bob_headers = self.login("bob", "battery-staple")
        flow = self.start_flow(device="bob-device", client_instance="bob-one")
        rejected = self.approve_flow(flow, headers=bob_headers)
        self.assertEqual(rejected["status"], 403, rejected["body"])
        self.assertIn("not explicitly assigned", rejected["body"]["error"])

    def test_request_hot_path_skips_readiness_hashing_and_poll_has_no_ledger_write(self):
        conn = c.connect(self.db)
        try:
            before = conn.execute(
                "SELECT COUNT(*) AS n FROM events").fetchone()["n"]
        finally:
            conn.close()
        with mock.patch.object(
                c, "auth_activation_readiness",
                side_effect=AssertionError("readiness scan reached hot path")), \
                mock.patch.object(
                    c, "auth_source_sha256",
                    side_effect=AssertionError("artifact hash reached hot path")):
            projects = self.request(
                "GET", "/v1/projects",
                headers={"Authorization": "Bearer stale-legacy-token"})
            self.assertEqual(projects["status"], 200, projects["body"])
            snapshot = self.request(
                "GET", "/v1/projects/proj/sync/snapshot",
                headers=self.compatibility_headers())
            self.assertEqual(snapshot["status"], 200, snapshot["body"])
            cursor = snapshot["body"]["cursor"]
            query = urllib.parse.urlencode({
                "after_seq": cursor["event_seq"],
                "after_hash": cursor["event_hash"],
                "context_version": cursor["context_version"],
                "visibility_fingerprint":
                    snapshot["body"]["visibility_fingerprint"],
            })
            pulled = self.request(
                "GET", "/v1/projects/proj/sync/pull?" + query,
                headers=self.compatibility_headers())
            self.assertEqual(pulled["status"], 200, pulled["body"])
        conn = c.connect(self.db)
        try:
            after = conn.execute(
                "SELECT COUNT(*) AS n FROM events").fetchone()["n"]
            self.assertEqual(after, before)
        finally:
            conn.close()

    def test_activation_readiness_check_and_persist_are_one_write_transaction(self):
        self.issue_terminal()
        setup = c.connect(self.db)
        try:
            c.auth_record_qa_evidence(
                setup, c.auth_source_sha256(),
                {"passed": True, "suite": "atomic-acceptance",
                 "result": "passed"},
                {"passed": True, "suite": "atomic-regression",
                 "result": "passed"})
            readiness = c.auth_activation_readiness(
                setup, server=self.server, include_details=False)
            self.assertTrue(readiness["ready"], readiness["blockers"])
            user = setup.execute(
                "SELECT * FROM auth_users WHERE username='alice'").fetchone()
            principal = c._auth_principal(setup, user, "session")
        finally:
            setup.close()

        activation_conn = c.connect(self.db)
        entered = threading.Event()
        revoke_attempted = threading.Event()
        revoke_finished = threading.Event()
        original = c.auth_activation_readiness

        def guarded_readiness(conn, *args, **kwargs):
            if conn is activation_conn:
                self.assertTrue(conn.in_transaction)
                entered.set()
                self.assertTrue(revoke_attempted.wait(timeout=5))
                # The competing writer has attempted BEGIN IMMEDIATE but must
                # remain blocked until activation's setting writes commit.
                threading.Event().wait(0.1)
                self.assertFalse(revoke_finished.is_set())
            return original(conn, *args, **kwargs)

        def revoke_terminal():
            self.assertTrue(entered.wait(timeout=5))
            # Signal immediately before opening the competing connection;
            # connect() itself performs idempotent schema/settings writes and
            # is therefore already blocked by activation's write transaction.
            revoke_attempted.set()
            conn = c.connect(self.db)
            try:
                with c.write_tx(conn):
                    conn.execute(
                        "UPDATE auth_tokens SET revoked_at=?"
                        " WHERE token_kind='terminal' AND revoked_at IS NULL",
                        (c.now_iso(),))
            finally:
                conn.close()
                revoke_finished.set()

        thread = threading.Thread(target=revoke_terminal, daemon=True)
        thread.start()
        try:
            with mock.patch.object(
                    c, "auth_activation_readiness",
                    side_effect=guarded_readiness):
                result = c.auth_activate(
                    activation_conn, principal, True,
                    readiness["readiness_version"], server=self.server)
            self.assertTrue(result["activated"])
        finally:
            activation_conn.close()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertTrue(revoke_finished.is_set())
        conn = c.connect(self.db)
        try:
            self.assertTrue(c._auth_setting(conn, "auth.activated", False))
        finally:
            conn.close()

    def test_activation_is_explicit_and_auto_enforces_while_rollback_does_not(self):
        # Observe the active legacy client and then cover that exact actor and
        # device with a human-owned terminal credential.
        snapshot = self.request(
            "GET", "/v1/projects/proj/sync/snapshot",
            headers=self.compatibility_headers())
        self.assertEqual(snapshot["status"], 200, snapshot["body"])
        _flow, _terminal = self.issue_terminal()
        conn = c.connect(self.db)
        try:
            before = c.auth_activation_readiness(conn)
            self.assertFalse(before["ready"])
            self.assertFalse(c._auth_setting(
                conn, "auth.activation_requested", False))
            c.auth_record_qa_evidence(
                conn, c.auth_source_sha256(),
                {"passed": True, "suite": "acceptance-pass",
                 "result": "ok", "recorded_at": c.now_iso()},
                {"passed": True, "suite": "regression-pass",
                 "result": "ok", "recorded_at": c.now_iso()})
            ready = c.auth_activation_readiness(conn)
            self.assertTrue(ready["ready"], ready["blockers"])
            self.assertFalse(c._auth_setting(
                conn, "auth.activation_requested", False))
        finally:
            conn.close()

        # A package change after process launch invalidates this readiness
        # version even if the database contains green evidence for disk bytes.
        with mock.patch.object(c, "auth_source_sha256", return_value="f" * 64):
            changed = self.request("POST", "/v1/auth/activation", {
                "confirmed": True,
                "expected_readiness_version": ready["readiness_version"],
            }, self.admin)
            self.assertEqual(changed["status"], 403, changed["body"])
        conn = c.connect(self.db)
        try:
            self.assertFalse(c._auth_setting(conn, "auth.activated", False))
        finally:
            conn.close()

        activated = self.request("POST", "/v1/auth/activation", {
            "confirmed": True,
            "expected_readiness_version": ready["readiness_version"],
        }, self.admin)
        self.assertEqual(activated["status"], 200, activated["body"])
        status = self.request("GET", "/v1/auth/status")
        self.assertTrue(status["body"]["authentication_required"])
        self.assertFalse(status["body"]["compatibility_active"])
        rejected = self.request(
            "GET", "/v1/projects/proj/sync/snapshot",
            headers=self.compatibility_headers())
        self.assertEqual(rejected["status"], 401, rejected["body"])

        self.restart_server(auth=False, auth_mode="auto")
        status = self.request("GET", "/v1/auth/status")
        self.assertTrue(status["body"]["authentication_required"])
        self.assertFalse(status["body"]["compatibility_active"])
        self.restart_server(auth=False, auth_mode="compatibility")
        rollback = self.request("GET", "/v1/auth/status")
        self.assertFalse(rollback["body"]["authentication_required"])
        self.assertTrue(rollback["body"]["compatibility_active"])
        restored = self.request(
            "GET", "/v1/projects/proj/sync/snapshot",
            headers=self.compatibility_headers())
        self.assertEqual(restored["status"], 200, restored["body"])


if __name__ == "__main__":
    unittest.main()
