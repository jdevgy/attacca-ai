"""Authenticated HTTP integration for schema-v1 offline synchronization.

Every server binds to port 0 and every database lives in a TemporaryDirectory;
this suite never discovers or contacts a configured/live Attacca service.
"""

import concurrent.futures
import importlib.util
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import offline_sync as offline
import sync_client as sync_client

SPEC = importlib.util.spec_from_file_location(
    "attacca_sync_http_test_runtime", ROOT / "attacca.py")
attacca = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(attacca)
protocol, _sync_server = attacca._sync_runtime()


class SyncHttpFixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "sync-http.db"
        conn = attacca.connect(self.db)
        attacca.auth_create_user(
            conn, "owner1", "password123", display_name="Owner One",
            is_admin=True, bootstrap=True)
        attacca.auth_create_user(
            conn, "stranger", "password456", display_name="Stranger")
        attacca.set_current_owner("owner1")
        for project_id in ("proj", "peer"):
            root = Path(self.temp.name) / project_id
            root.mkdir()
            attacca.project_init(
                conn, "web.owner1", "human", path=str(root),
                project_id=project_id, name=project_id.title())
        attacca.agent_register(
            conn, "proj", "web.owner1", "human",
            agent_id="proj.director.codex", display_name="Director Codex",
            role="director", runtime="codex")
        attacca.agent_register(
            conn, "proj", "web.owner1", "human",
            agent_id="proj.worker.cline", display_name="Worker Cline",
            role="worker", runtime="cline")
        attacca.agent_register(
            conn, "peer", "web.owner1", "human",
            agent_id="peer.director.claude", display_name="Peer Director",
            role="director", runtime="claude")
        self.director_token = attacca.auth_token_create(
            conn, "owner1", "director", actor_id="proj.director.codex",
            actor_type="agent", project_id="proj", runtime="codex")["token"]
        self.worker_token = attacca.auth_token_create(
            conn, "owner1", "worker", actor_id="proj.worker.cline",
            actor_type="agent", project_id="proj", runtime="cline")["token"]
        self.peer_token = attacca.auth_token_create(
            conn, "owner1", "peer", actor_id="peer.director.claude",
            actor_type="agent", project_id="peer", runtime="claude")["token"]
        self.stranger_token = attacca.auth_token_create(
            conn, "stranger", "human", actor_type="human")["token"]
        self.owner_human_token = attacca.auth_token_create(
            conn, "owner1", "human", actor_type="human")["token"]
        attacca.bridge_add(
            conn, "proj", "web.owner1", "human", "peer",
            participation="directors", peer_participation="all")
        attacca.rule_create(
            conn, "proj", "web.owner1", "human", "Everyone", "Always log",
            scope="everyone")
        attacca.rule_create(
            conn, "proj", "web.owner1", "human", "Director", "Direct work",
            scope="director")
        attacca.rule_create(
            conn, "proj", "web.owner1", "human", "Worker", "Do assigned work",
            scope="worker")
        attacca.room_send(
            conn, "proj", "web.owner1", "human", "local visible")
        restricted = attacca.room_send(
            conn, "peer", "peer.director.claude", "agent",
            "restricted bridge body", target_project="proj")
        self.restricted_seq = conn.execute(
            "SELECT MAX(seq) AS seq FROM events WHERE project_id='proj'"
        ).fetchone()["seq"]
        conn.execute(
            "INSERT INTO inbox_cursors(project_id,actor_id,last_read_seq,updated_at)"
            " VALUES ('proj','proj.director.codex',3,?)", (attacca.now_iso(),))
        conn.execute(
            "INSERT INTO inbox_cursors(project_id,actor_id,last_read_seq,updated_at)"
            " VALUES ('proj','proj.worker.cline',5,?)", (attacca.now_iso(),))
        conn.close()
        self.server = attacca.AttaccaServer(("127.0.0.1", 0), self.db)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.running = True
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def pause(self):
        """Stop serving while retaining the same isolated loopback socket."""
        if not self.running:
            return
        self.server.shutdown()
        self.thread.join(timeout=10)
        self.running = False

    def resume(self):
        if self.running:
            return
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.running = True

    def close(self):
        if self.running:
            self.server.shutdown()
            self.thread.join(timeout=10)
            self.running = False
        self.server.server_close()
        self.temp.cleanup()

    def request(self, method, path, token=None, body=None, device="device_a",
                extra_headers=None):
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        if device:
            headers["X-Attacca-Device-ID"] = device
        headers.update(extra_headers or {})
        data = None
        if body is not None:
            data = protocol.canonical_json_bytes(body)
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None, \
                    dict(response.headers)
        except urllib.error.HTTPError as error:
            raw = error.read()
            return error.code, json.loads(raw) if raw else None, \
                dict(error.headers)

    def snapshot(self, token=None):
        return self.request(
            "GET", "/v1/projects/proj/sync/snapshot",
            token=self.director_token if token is None else token)

    @staticmethod
    def mutation(snapshot, mutation_id, sequence, operation, payload,
                 device="device_a", metadata=None):
        return protocol.make_client_mutation(
            snapshot["scope"], mutation_id, "client_a", device, sequence,
            operation, payload, snapshot["cursor"], metadata=metadata or {})

    @staticmethod
    def push_envelope(snapshot, mutations, device="device_a"):
        return protocol.make_push_request(
            snapshot["scope"], snapshot["visibility_fingerprint"],
            "client_a", device, mutations)


class SyncHttpTestCase(unittest.TestCase):
    def setUp(self):
        self.fx = SyncHttpFixture()

    def tearDown(self):
        self.fx.close()

    def test_snapshot_is_principal_role_and_bridge_filtered(self):
        status, director, headers = self.fx.snapshot(self.fx.director_token)
        self.assertEqual(status, 200)
        protocol.validate_snapshot(director)
        self.assertEqual(director["scope"]["actor_id"],
                         "proj.director.codex")
        self.assertEqual(director["scope"]["role"], "director")
        self.assertEqual(
            {rule["scope"] for rule in director["projection"]["rules"]},
            {"everyone", "director"})
        self.assertEqual([item["with"] for item in
                          director["projection"]["bridges"]], ["peer"])
        self.assertIn(
            "restricted bridge body",
            [item["body"] for item in director["projection"]["room_messages"]])
        self.assertEqual(
            director["projection"]["inbox_cursor"]["actor_id"],
            "proj.director.codex")
        self.assertIn("no-store", headers.get("Cache-Control", ""))

        status, worker, _ = self.fx.snapshot(self.fx.worker_token)
        self.assertEqual(status, 200)
        protocol.validate_snapshot(worker)
        self.assertEqual(worker["scope"]["actor_id"], "proj.worker.cline")
        self.assertEqual(
            {rule["scope"] for rule in worker["projection"]["rules"]},
            {"everyone", "worker"})
        self.assertEqual(worker["projection"]["bridges"], [])
        self.assertNotIn(
            "restricted bridge body",
            [item["body"] for item in worker["projection"]["room_messages"]])
        restricted = next(
            item for item in worker["records"]
            if item["seq"] == self.fx.restricted_seq)
        self.assertEqual(restricted["kind"], "redacted")
        self.assertEqual(worker["cursor"], director["cursor"])
        serialized = json.dumps(worker)
        for secret in ("password_hash", "auth_tokens", "session_hash",
                       self.fx.worker_token):
            self.assertNotIn(secret, serialized)

    def test_snapshot_requires_auth_and_human_project_access(self):
        status, body, _ = self.fx.snapshot(token="")
        self.assertEqual(status, 401)
        self.assertTrue(body["login_required"])
        status, body, _ = self.fx.snapshot(self.fx.stranger_token)
        self.assertEqual(status, 403)
        self.assertIn("project_membership_required", body["error"])
        status, owner, _ = self.fx.snapshot(self.fx.owner_human_token)
        self.assertEqual(status, 200)
        self.assertEqual(owner["scope"]["actor_type"], "human")
        self.assertEqual(owner["scope"]["role"], "human")
        self.assertEqual(owner["scope"]["principal_id"], "owner1")
        self.assertEqual(
            {rule["scope"] for rule in owner["projection"]["rules"]},
            {"everyone", "director", "worker"})
        status, body, _ = self.fx.request(
            "GET", "/v1/projects/missing/sync/snapshot",
            token=self.fx.stranger_token)
        # A non-member receives the same denial for a missing and an existing
        # inaccessible workspace, so project identifiers are not enumerable.
        self.assertEqual(status, 403)
        self.assertIn("project_membership_required", body["error"])

    def test_pull_advances_hidden_rows_and_visibility_change_resets(self):
        _, initial, _ = self.fx.snapshot(self.fx.worker_token)
        conn = attacca.connect(self.fx.db)
        attacca.set_current_owner("owner1")
        attacca.room_send(
            conn, "peer", "peer.director.claude", "agent",
            "second restricted body", target_project="proj")
        conn.close()
        cursor = initial["cursor"]
        query = urllib.parse.urlencode({
            "after_seq": cursor["event_seq"],
            "after_hash": cursor["event_hash"],
            "context_version": cursor["context_version"],
            "visibility_fingerprint": initial["visibility_fingerprint"],
            "limit": 50,
        })
        status, pulled, _ = self.fx.request(
            "GET", "/v1/projects/proj/sync/pull?" + query,
            token=self.fx.worker_token)
        self.assertEqual(status, 200)
        protocol.validate_pull_result(pulled)
        self.assertEqual(pulled["records"][0]["kind"], "redacted")
        self.assertGreater(pulled["next_cursor"]["event_seq"],
                           cursor["event_seq"])
        self.assertNotIn(
            "second restricted body",
            [item["body"] for item in
             pulled["changes"]["room_messages"]])

        next_cursor = pulled["next_cursor"]
        divergent_query = urllib.parse.urlencode({
            "after_seq": next_cursor["event_seq"],
            "after_hash": "0" * 64,
            "context_version": next_cursor["context_version"],
            "visibility_fingerprint": pulled["visibility_fingerprint"],
            "limit": 50,
        })
        status, divergent, _ = self.fx.request(
            "GET", "/v1/projects/proj/sync/pull?" + divergent_query,
            token=self.fx.worker_token)
        self.assertEqual(status, 200)
        self.assertEqual(divergent["status"], "reset_required")
        self.assertEqual(divergent["reason_code"], "cursor_diverged")

        conn = attacca.connect(self.fx.db)
        attacca.set_current_owner("owner1")
        attacca.bridge_update_access(
            conn, "proj", "web.owner1", "human", "peer",
            participation="all")
        conn.close()
        query = urllib.parse.urlencode({
            "after_seq": next_cursor["event_seq"],
            "after_hash": next_cursor["event_hash"],
            "context_version": next_cursor["context_version"],
            "visibility_fingerprint": pulled["visibility_fingerprint"],
            "limit": 50,
        })
        status, reset, _ = self.fx.request(
            "GET", "/v1/projects/proj/sync/pull?" + query,
            token=self.fx.worker_token)
        self.assertEqual(status, 200)
        self.assertEqual(reset["status"], "reset_required")
        self.assertEqual(reset["reason_code"], "visibility_changed")
        protocol.validate_pull_result(reset)

    def test_push_is_exactly_once_and_preserves_trusted_attribution(self):
        _, snapshot, _ = self.fx.snapshot()
        mutation = self.fx.mutation(
            snapshot, "cm_task_create_0001", 1, "task.create",
            {"title": "Offline task", "risk_level": "high"},
            metadata={"git_branch": "feature/offline",
                      "git_revision": "abc123"})
        envelope = self.fx.push_envelope(snapshot, [mutation])
        status, first, _ = self.fx.request(
            "POST", "/v1/projects/proj/sync/push",
            token=self.fx.director_token, body=envelope,
            extra_headers={"X-Attacca-Owner": "spoofed",
                           "X-Attacca-Actor": "proj.worker.cline"})
        # A token-bound canonical actor cannot be overridden at HTTP auth.
        self.assertEqual(status, 403)

        status, first, _ = self.fx.request(
            "POST", "/v1/projects/proj/sync/push",
            token=self.fx.director_token, body=envelope,
            extra_headers={"X-Attacca-Owner": "spoofed"})
        self.assertEqual(status, 200)
        applied = first["results"][0]
        self.assertEqual(applied["status"], "applied")
        self.assertTrue(applied["result"]["canonical_event_id"])
        self.assertIsInstance(applied["result"]["canonical_event_seq"], int)
        status, second, _ = self.fx.request(
            "POST", "/v1/projects/proj/sync/push",
            token=self.fx.director_token, body=envelope)
        self.assertEqual(status, 200)
        self.assertEqual(second["results"][0]["status"], "duplicate")

        changed = self.fx.mutation(
            snapshot, "cm_task_create_0001", 1, "task.create",
            {"title": "Different body"})
        status, conflict, _ = self.fx.request(
            "POST", "/v1/projects/proj/sync/push",
            token=self.fx.director_token,
            body=self.fx.push_envelope(snapshot, [changed]))
        self.assertEqual(status, 200)
        self.assertEqual(conflict["results"][0]["status"], "conflict")

        conn = attacca.connect(self.fx.db)
        tasks = conn.execute(
            "SELECT * FROM tasks WHERE project_id='proj' AND title='Offline task'"
        ).fetchall()
        self.assertEqual(len(tasks), 1)
        event = conn.execute(
            "SELECT * FROM events WHERE event_id=?",
            (applied["result"]["canonical_event_id"],)).fetchone()
        self.assertEqual(event["actor_id"], "proj.director.codex")
        self.assertEqual(event["owner"], "owner1")
        self.assertEqual(event["device_id"], "device_a")
        self.assertEqual(event["git_branch"], "feature/offline")
        self.assertEqual(event["base_revision"], "abc123")
        conn.close()

    def test_push_rejects_identity_and_device_overrides(self):
        _, snapshot, _ = self.fx.snapshot()
        mutation = self.fx.mutation(
            snapshot, "cm_reserved_0001", 1, "room.send",
            {"body": "no", "owner": "spoofed", "project": "peer"})
        status, body, _ = self.fx.request(
            "POST", "/v1/projects/proj/sync/push",
            token=self.fx.director_token,
            body=self.fx.push_envelope(snapshot, [mutation]))
        self.assertEqual(status, 200)
        self.assertEqual(body["results"][0]["status"], "rejected")
        self.assertEqual(body["results"][0]["code"],
                         "reserved_identity_field")
        status, body, _ = self.fx.request(
            "POST", "/v1/projects/proj/sync/push",
            token=self.fx.director_token,
            body=self.fx.push_envelope(snapshot, [mutation]),
            device="another_device")
        self.assertEqual(status, 400)
        self.assertEqual(body["code"], "cross_device_push")
        status, body, _ = self.fx.request(
            "POST", "/v1/projects/proj/sync/push",
            token=self.fx.worker_token,
            body=self.fx.push_envelope(snapshot, [mutation]))
        self.assertEqual(status, 400)
        self.assertEqual(body["code"], "cross_principal_scope")

    def test_concurrent_duplicate_and_crash_retry_are_atomic(self):
        _, snapshot, _ = self.fx.snapshot()
        mutation = self.fx.mutation(
            snapshot, "cm_concurrent_0001", 1, "task.create",
            {"title": "Concurrent once"})
        envelope = self.fx.push_envelope(snapshot, [mutation])

        def push():
            return self.fx.request(
                "POST", "/v1/projects/proj/sync/push",
                token=self.fx.director_token, body=envelope)[1]

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = [future.result() for future in
                       [pool.submit(push), pool.submit(push)]]
        self.assertEqual(
            sorted(item["results"][0]["status"] for item in results),
            ["applied", "duplicate"])

        _, newer, _ = self.fx.snapshot()
        crash_mutation = self.fx.mutation(
            newer, "cm_crash_retry_0001", 2, "task.create",
            {"title": "Crash retry"})
        crash_envelope = self.fx.push_envelope(newer, [crash_mutation])
        fired = []

        def fault(stage, request):
            if stage == "after_apply_before_receipt" and not fired:
                fired.append(stage)
                raise RuntimeError("simulated crash window")

        self.fx.server.sync_fault_injector = fault
        status, failed, _ = self.fx.request(
            "POST", "/v1/projects/proj/sync/push",
            token=self.fx.director_token, body=crash_envelope)
        self.assertEqual(status, 500)
        self.assertIn("simulated crash window", failed["error"])
        self.fx.server.sync_fault_injector = None
        status, retried, _ = self.fx.request(
            "POST", "/v1/projects/proj/sync/push",
            token=self.fx.director_token, body=crash_envelope)
        self.assertEqual(status, 200)
        self.assertEqual(retried["results"][0]["status"], "applied")
        conn = attacca.connect(self.fx.db)
        self.assertEqual(conn.execute(
            "SELECT COUNT(*) AS n FROM tasks WHERE project_id='proj'"
            " AND title='Concurrent once'").fetchone()["n"], 1)
        self.assertEqual(conn.execute(
            "SELECT COUNT(*) AS n FROM tasks WHERE project_id='proj'"
            " AND title='Crash retry'").fetchone()["n"], 1)
        conn.close()

    def test_real_offline_client_converges_through_authenticated_routes(self):
        _, snapshot, _ = self.fx.snapshot()
        cache = Path(self.fx.temp.name) / "offline-cache"
        engine = offline.OfflineProjectSync(
            cache, self.fx.base, snapshot["scope"], "client_a", "device_a",
            visibility_fingerprint=None)
        client = sync_client.AuthenticatedSyncHttpClient(
            self.fx.base, "proj", snapshot["scope"], None,
            "client_a", "device_a", lambda: self.fx.director_token)
        initialized = engine.synchronize(client)
        self.assertEqual(initialized["status"], "online")
        mutation = engine.queue_mutation(
            "room.send", {"body": "real route convergence"},
            client_mutation_id="cm_real_route_0001",
            git_branch="feature/real-route", git_revision="fedcba")
        synchronized = engine.synchronize(client)
        self.assertEqual(synchronized["status"], "online")
        self.assertEqual(synchronized["applied"], [
            mutation["client_mutation_id"]])
        self.assertEqual(synchronized["converged"], [
            mutation["client_mutation_id"]])
        self.assertTrue(engine.search_local("real route convergence"))
        proof = offline.validate_convergence_proof(
            synchronized["convergence_proof"], require_online=True)
        self.assertEqual(proof["scope"], snapshot["scope"])

    def test_two_devices_disconnect_queue_and_reconnect_exactly_once(self):
        """Two computers retain separate outboxes and converge through HTTP."""
        _, snapshot, _ = self.fx.snapshot()
        cache = Path(self.fx.temp.name) / "two-device-cache"
        engine_a = offline.OfflineProjectSync(
            cache, self.fx.base, snapshot["scope"], "client_home",
            "device_home",
            visibility_fingerprint=snapshot["visibility_fingerprint"])
        engine_b = offline.OfflineProjectSync(
            cache, self.fx.base, snapshot["scope"], "client_office",
            "device_office",
            visibility_fingerprint=snapshot["visibility_fingerprint"])
        client_a = sync_client.AuthenticatedSyncHttpClient(
            self.fx.base, "proj", snapshot["scope"],
            snapshot["visibility_fingerprint"],
            "client_home", "device_home",
            lambda: self.fx.director_token, timeout_seconds=0.2)
        client_b = sync_client.AuthenticatedSyncHttpClient(
            self.fx.base, "proj", snapshot["scope"],
            snapshot["visibility_fingerprint"],
            "client_office", "device_office",
            lambda: self.fx.director_token, timeout_seconds=0.2)
        self.assertEqual(engine_a.synchronize(client_a)["status"], "online")
        self.assertEqual(engine_b.synchronize(client_b)["status"], "online")

        self.fx.pause()
        self.assertEqual(engine_a.synchronize(client_a)["status"], "offline")
        self.assertEqual(engine_b.synchronize(client_b)["status"], "offline")
        mutation_a = engine_a.queue_mutation(
            "room.send", {"body": "home computer offline write"},
            client_mutation_id="cm_home_offline_0001",
            git_branch="feature/home", git_revision="home123")
        mutation_b = engine_b.queue_mutation(
            "room.send", {"body": "office computer offline write"},
            client_mutation_id="cm_office_offline_0001",
            git_branch="feature/office", git_revision="office456")
        self.assertEqual(
            [item["client_mutation_id"] for item in
             engine_a.pending_mutations()], [mutation_a["client_mutation_id"]])
        self.assertEqual(
            [item["client_mutation_id"] for item in
             engine_b.pending_mutations()], [mutation_b["client_mutation_id"]])
        self.assertNotEqual(engine_a.outbox_directory,
                            engine_b.outbox_directory)

        self.fx.resume()
        synced_a = engine_a.synchronize(client_a)
        synced_b = engine_b.synchronize(client_b)
        final_a = engine_a.synchronize(client_a)
        final_b = engine_b.synchronize(client_b)
        self.assertEqual(synced_a["status"], "online")
        self.assertEqual(synced_b["status"], "online")
        self.assertEqual(synced_a["applied"], [mutation_a["client_mutation_id"]])
        self.assertEqual(synced_a["converged"], [
            mutation_a["client_mutation_id"]])
        self.assertEqual(synced_b["applied"], [mutation_b["client_mutation_id"]])
        self.assertEqual(synced_b["converged"], [
            mutation_b["client_mutation_id"]])
        self.assertEqual(final_a["status"], "online")
        self.assertEqual(final_b["status"], "online")
        for engine in (engine_a, engine_b):
            projection = engine.local_projection()
            bodies = [item["body"] for item in projection["room_messages"]]
            self.assertIn("home computer offline write", bodies)
            self.assertIn("office computer offline write", bodies)
            status = engine.status()
            self.assertEqual(status["pending_count"], 0)
            self.assertEqual(status["convergence_awaiting_count"], 0)
            offline.validate_convergence_proof(
                status["convergence_proof"], require_online=True)

        # Shared project data crosses devices; private journal receipts do not.
        records_a = "\n".join(
            path.read_text() for path in engine_a.journal_directory.glob("*.json"))
        records_b = "\n".join(
            path.read_text() for path in engine_b.journal_directory.glob("*.json"))
        self.assertIn(mutation_a["client_mutation_id"], records_a)
        self.assertNotIn(mutation_b["client_mutation_id"], records_a)
        self.assertIn(mutation_b["client_mutation_id"], records_b)
        self.assertNotIn(mutation_a["client_mutation_id"], records_b)
        self.assertIn(
            '"audit_device_id":"device_home/client_home"', records_a)
        self.assertIn(
            '"audit_device_id":"device_office/client_office"', records_b)

        conn = attacca.connect(self.fx.db)
        rows = conn.execute(
            "SELECT * FROM events WHERE project_id='proj'"
            " AND event_type='room.message' AND (payload LIKE ? OR payload LIKE ?)"
            " ORDER BY seq",
            ("%home computer offline write%",
             "%office computer offline write%"),).fetchall()
        self.assertEqual(len(rows), 2)
        by_device = {row["device_id"]: row for row in rows}
        home_device = "device_home/client_home"
        office_device = "device_office/client_office"
        self.assertEqual(set(by_device), {home_device, office_device})
        self.assertEqual(by_device[home_device]["actor_id"],
                         "proj.director.codex")
        self.assertEqual(by_device[home_device]["owner"], "owner1")
        self.assertEqual(by_device[home_device]["git_branch"],
                         "feature/home")
        self.assertEqual(by_device[home_device]["base_revision"], "home123")
        self.assertEqual(by_device[office_device]["actor_id"],
                         "proj.director.codex")
        self.assertEqual(by_device[office_device]["owner"], "owner1")
        self.assertEqual(by_device[office_device]["git_branch"],
                         "feature/office")
        self.assertEqual(by_device[office_device]["base_revision"],
                         "office456")
        conn.close()

    def test_authenticated_mcp_owner_device_and_session_are_principal_bound(self):
        initialize = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "codex", "version": "1"}},
        }
        headers = {
            "X-Attacca-Project": "proj",
            "X-Attacca-Actor": "proj.director.codex",
            "X-Attacca-Owner": "spoofed",
            "X-Attacca-Git-Branch": "mcp-branch",
            "X-Attacca-Git-Revision": "def456",
        }
        status, initialized, response_headers = self.fx.request(
            "POST", "/mcp", token=self.fx.director_token,
            body=initialize, extra_headers=headers)
        self.assertEqual(status, 200)
        self.assertIn("result", initialized)
        sid = response_headers["Mcp-Session-Id"]
        call = {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "room_send",
                       "arguments": {"body": "authenticated mcp"}},
        }
        headers["Mcp-Session-Id"] = sid
        headers.pop("X-Attacca-Owner")
        headers.pop("X-Attacca-Git-Branch")
        headers.pop("X-Attacca-Git-Revision")
        status, result, _ = self.fx.request(
            "POST", "/mcp", token=self.fx.director_token,
            body=call, extra_headers=headers)
        self.assertEqual(status, 200)
        self.assertFalse(result["result"]["isError"])
        status, denied, _ = self.fx.request(
            "POST", "/mcp", token=self.fx.worker_token,
            body=call, extra_headers=headers)
        self.assertEqual(status, 403)
        conn = attacca.connect(self.fx.db)
        event = conn.execute(
            "SELECT * FROM events WHERE project_id='proj'"
            " AND event_type='room.message' AND payload LIKE ?",
            ('%authenticated mcp%',)).fetchone()
        self.assertEqual(event["actor_id"], "proj.director.codex")
        self.assertEqual(event["owner"], "owner1")
        self.assertEqual(event["device_id"], "device_a")
        self.assertEqual(event["git_branch"], "mcp-branch")
        self.assertEqual(event["base_revision"], "def456")
        conn.close()


if __name__ == "__main__":
    unittest.main()
