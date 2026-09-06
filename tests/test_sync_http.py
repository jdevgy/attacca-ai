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
from unittest import mock


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


class SyncProjectionShapeTest(unittest.TestCase):
    """T-94 · the mirror projection carries each plan revision exactly once.

    Measured on a live workspace before this change: one identity projection
    was 51.4 MB, of which 23.7 MB were tasks (23.5 MB of that being
    ``tasks[].plan_revisions``) and another 23.5 MB were the SAME revisions
    repeated under ``task_plans``.  Everything here is one temporary
    database; no server and no configured host is involved.
    """

    SECTION_BODY = "immutable plan section body. " * 900  # ~25 KB

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "projection.db"
        checkout = Path(self.temp.name) / "repo"
        checkout.mkdir()
        self.conn = attacca.connect(self.db)
        self.addCleanup(self.conn.close)
        attacca.set_current_owner(None)
        attacca.project_init(
            self.conn, "setup", "human", path=str(checkout),
            project_id="proj", name="Projection")
        attacca.agent_register(
            self.conn, "proj", "setup", "human",
            agent_id="proj.director.codex", role="director", runtime="codex")
        self.task_ids = []
        for index in range(2):
            task_id = attacca.task_create(
                self.conn, "proj", "proj.director.codex", "agent",
                "Plan heavy task %d" % index)["task_id"]
            self.task_ids.append(task_id)
            for version in range(3):
                attacca.task_plan_set(
                    self.conn, "proj", task_id, "proj.director.codex",
                    "agent", "Plan v%d" % (version + 1),
                    "overview revision %d" % version,
                    [{"section_id": "s%d" % number,
                      "title": "Section %d" % number,
                      "body": self.SECTION_BODY} for number in range(6)],
                    expected_version=None if version == 0 else version)
        self.scope = {
            "server_id": "srv_projection", "project_id": "proj",
            "principal_id": "usr_owner", "actor_id": "proj.director.codex",
            "actor_type": "agent", "role": "director",
        }

    def test_projection_carries_each_plan_revision_once(self):
        projection = attacca._sync_projection(self.conn, self.scope)
        for task in projection["tasks"]:
            self.assertNotIn("plan_revisions", task)
        self.assertEqual(len(projection["task_plans"]), 6)

        exporter = attacca._project_export_module()
        export = exporter.build_project_export(
            self.conn, "proj", log_renderer=attacca.render_log_line)
        # The administrative export deliberately keeps both shapes.
        self.assertEqual(
            len(export["tasks"][0]["plan_revisions"]), 3)
        before = dict(projection)
        before["tasks"] = export["tasks"]
        before["task_plans"] = [
            plan for task in export["tasks"]
            for plan in task.get("plan_revisions", [])]
        before_bytes = len(protocol.canonical_json_bytes(before))
        after_bytes = len(protocol.canonical_json_bytes(projection))
        print("MEASURED · T-94 sync projection · before %d B · after %d B"
              % (before_bytes, after_bytes))
        self.assertLess(after_bytes * 4, before_bytes)

    def test_only_the_latest_plan_revision_carries_its_sections(self):
        projection = attacca._sync_projection(self.conn, self.scope)
        for task_id in self.task_ids:
            revisions = sorted(
                (plan for plan in projection["task_plans"]
                 if plan["task_id"] == task_id),
                key=lambda item: item["version"])
            self.assertEqual([item["version"] for item in revisions],
                             [1, 2, 3])
            latest = revisions[-1]
            self.assertEqual(len(latest["sections"]), 6)
            self.assertNotIn("sections_omitted", latest)
            for older in revisions[:-1]:
                self.assertNotIn("sections", older)
                self.assertTrue(older["sections_omitted"])
                self.assertEqual(older["section_count"], 6)
                for field in ("task_id", "version", "title", "status",
                              "content_sha256", "authored_by", "authored_at",
                              "updated_at", "overview"):
                    self.assertIn(field, older)

    def test_offline_plan_read_reports_an_omitted_body_instead_of_crashing(self):
        projection = attacca._sync_projection(self.conn, self.scope)
        snapshot = {"scope": self.scope, "projection": projection,
                    "records": []}
        task_id = self.task_ids[0]
        latest = attacca._offline_proxy_plan(snapshot, task_id)
        self.assertEqual(latest["plan"]["version"], 3)
        self.assertEqual(len(latest["plan"]["sections"]), 6)
        older = attacca._offline_proxy_plan(snapshot, task_id, version=1)
        self.assertEqual(older["plan"]["version"], 1)
        self.assertEqual(older["plan"]["sections"], [])
        self.assertTrue(older["plan"]["sections_omitted"])
        self.assertIn("hosted", older["plan"]["sections_hint"])
        counts = {item["version"]: item["section_count"]
                  for item in older["revisions"]}
        self.assertEqual(counts, {1: 6, 2: 6, 3: 6})

    def test_a_narrowed_projection_returns_only_those_resources(self):
        narrowed = attacca._sync_projection(
            self.conn, self.scope, resources=["tasks"])
        self.assertEqual(set(narrowed), {"tasks"})
        self.assertEqual(len(narrowed["tasks"]), 2)
        self.assertEqual(
            attacca._sync_projection(self.conn, self.scope, resources=[]), {})


class SyncDeltaResourceSelectionTest(unittest.TestCase):
    """T-94 · a delta carries only what its window can change."""

    @staticmethod
    def window(*event_types):
        return [{"seq": index + 1, "event_type": name}
                for index, name in enumerate(event_types)]

    def test_each_event_type_selects_its_own_resources(self):
        always = set(attacca.SYNC_ALWAYS_DELTA_RESOURCES)
        cases = {
            "task.created": {"tasks", "task_plans"},
            "task.plan.submitted": {"tasks", "task_plans"},
            "decision.resolved": {"decisions"},
            "room.message": {"room_messages"},
            "room.message_disposition": {"room_messages"},
            "handoff.updated": {"project_handoffs", "identity_handoffs",
                                "handoffs"},
            "identity_handoff.updated": {"identity_handoffs", "handoffs",
                                         "project_handoffs"},
            "rule.updated": {"rules"},
            "cloud_context.updated": {"cloud_context"},
            "agent.registered": {"agents", "persona_reservations",
                                 "actor_aliases"},
            "bridge.created": {"bridges"},
            "role_scope.updated": {"role_scopes", "project"},
            "project.lead_changed": {"project", "agents", "role_scopes"},
        }
        for event_type, expected in cases.items():
            self.assertEqual(
                attacca._sync_delta_resources(self.window(event_type)),
                expected | always, event_type)
        self.assertEqual(
            attacca._sync_delta_resources(
                self.window("task.created", "decision.proposed")),
            {"tasks", "task_plans", "decisions"} | always)

    def test_unknown_or_empty_windows_fall_back_to_the_whole_projection(self):
        # A custom append_event type, an identity migration that rewrites
        # already projected attribution, and a context-version-only advance
        # are all unbounded: the safe answer is the complete projection.
        for window in ([],
                       self.window("note.custom"),
                       self.window("git.commit"),
                       self.window("task.created", "note.custom"),
                       self.window("agent.identity_migrated"),
                       self.window("bridge.access_identity_migrated")):
            self.assertIsNone(attacca._sync_delta_resources(window))

    def test_every_mapped_resource_is_a_negotiable_projection_resource(self):
        known = set(protocol.current_projection_capabilities()["resources"])
        mapped = set(attacca.SYNC_ALWAYS_DELTA_RESOURCES)
        for _prefix, resources in attacca.SYNC_EVENT_TYPE_RESOURCES:
            mapped.update(resources)
        self.assertLessEqual(mapped, known)
        # Nothing a client mirrors may be unreachable through the map.
        self.assertEqual(known - mapped, set())


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

    def negotiated_snapshot(self, token=None):
        query = urllib.parse.urlencode(
            protocol.projection_capabilities_query())
        status, snapshot, _ = self.fx.request(
            "GET", "/v1/projects/proj/sync/snapshot?" + query,
            token=token or self.fx.director_token)
        self.assertEqual(status, 200)
        return snapshot

    def pull_query(self, cursor, fingerprint, resources=None,
                   capabilities=True, limit=50):
        query = {
            "after_seq": cursor["event_seq"],
            "after_hash": cursor["event_hash"],
            "context_version": cursor["context_version"],
            "visibility_fingerprint": fingerprint,
            "limit": limit,
        }
        if capabilities:
            query.update(protocol.projection_capabilities_query())
        if resources is not None:
            query["projection_pull_resources"] = ",".join(resources)
        return "/v1/projects/proj/sync/pull?" + urllib.parse.urlencode(query)

    def write(self, action):
        conn = attacca.connect(self.fx.db)
        attacca.set_current_owner("owner1")
        try:
            return action(conn)
        finally:
            conn.close()

    def test_delta_pull_carries_only_resources_the_window_can_change(self):
        # T-94 · before this change every pull answered with the COMPLETE
        # identity projection, so one 51 MB workspace could never advance its
        # cursor through a 16 MB ceiling.
        snapshot = self.negotiated_snapshot()
        self.write(lambda conn: attacca.task_create(
            conn, "proj", "proj.director.codex", "agent", "Delta task"))
        status, pulled, _ = self.fx.request(
            "GET", self.pull_query(
                snapshot["cursor"], snapshot["visibility_fingerprint"]),
            token=self.fx.director_token)
        self.assertEqual(status, 200)
        protocol.validate_pull_result(pulled)
        self.assertEqual(pulled["status"], "ok")
        self.assertEqual(
            set(pulled["changes"]),
            {"tasks", "task_plans", "full_log", "inbox_cursor",
             "message_dispositions"})
        self.assertIn(
            "Delta task",
            [item["title"] for item in pulled["changes"]["tasks"]])
        # A narrowed delta must not look like a new projection generation.
        self.assertEqual(pulled["visibility_fingerprint"],
                         snapshot["visibility_fingerprint"])

        self.write(lambda conn: attacca.room_send(
            conn, "proj", "proj.director.codex", "agent", "delta chat"))
        status, second, _ = self.fx.request(
            "GET", self.pull_query(
                pulled["next_cursor"], pulled["visibility_fingerprint"]),
            token=self.fx.director_token)
        self.assertEqual(status, 200)
        self.assertEqual(
            set(second["changes"]),
            {"room_messages", "full_log", "inbox_cursor",
             "message_dispositions"})
        self.assertIn(
            "delta chat",
            [item["body"] for item in second["changes"]["room_messages"]])

    def test_pull_honours_a_requested_projection_resource_subset(self):
        snapshot = self.negotiated_snapshot()
        # A pull whose cursor is already the head is valid: its window is
        # empty, so the requested resources come back complete.
        for wanted in (["tasks"], ["rules", "agents"]):
            status, pulled, _ = self.fx.request(
                "GET", self.pull_query(
                    snapshot["cursor"], snapshot["visibility_fingerprint"],
                    resources=wanted),
                token=self.fx.director_token)
            self.assertEqual(status, 200)
            protocol.validate_pull_result(pulled)
            self.assertEqual(pulled["status"], "ok")
            self.assertEqual(set(pulled["changes"]), set(wanted))
            self.assertEqual(pulled["next_cursor"], pulled["from_cursor"])
            # The capability offer, and therefore the negotiated shape and
            # its fingerprint, is unchanged by a narrowed request.
            self.assertEqual(pulled["visibility_fingerprint"],
                             snapshot["visibility_fingerprint"])
        self.assertEqual(
            {rule["scope"] for rule in pulled["changes"]["rules"]},
            {"everyone", "director"})

        status, body, _ = self.fx.request(
            "GET", self.pull_query(
                snapshot["cursor"], snapshot["visibility_fingerprint"],
                resources=["not_a_resource"]),
            token=self.fx.director_token)
        self.assertEqual(status, 400)
        self.assertEqual(body["code"], "unsupported_projection_resource")

        # A legacy (unnegotiated) client cannot request a schema-v2 resource.
        _, legacy, _ = self.fx.snapshot()
        status, body, _ = self.fx.request(
            "GET", self.pull_query(
                legacy["cursor"], legacy["visibility_fingerprint"],
                resources=["cloud_context"], capabilities=False),
            token=self.fx.director_token)
        self.assertEqual(status, 400)
        self.assertEqual(body["code"], "unnegotiated_projection_resource")

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

    def test_an_oversized_delta_converges_through_resource_chunked_pulls(self):
        """T-94 · the whole loop: real client, real routes, lowered ceiling."""
        _, snapshot, _ = self.fx.snapshot()
        cache = Path(self.fx.temp.name) / "chunked-cache"
        engine = offline.OfflineProjectSync(
            cache, self.fx.base, snapshot["scope"], "client_chunk",
            "device_chunk", visibility_fingerprint=None)
        client = sync_client.AuthenticatedSyncHttpClient(
            self.fx.base, "proj", snapshot["scope"], None,
            "client_chunk", "device_chunk", lambda: self.fx.director_token)
        self.assertEqual(engine.synchronize(client)["status"], "online")

        filler = "wide task description. " * 900
        self.write(lambda conn: [
            attacca.task_create(
                conn, "proj", "proj.director.codex", "agent",
                "Wide task %d" % index, description=filler)
            for index in range(3)])
        self.write(lambda conn: attacca.room_send(
            conn, "proj", "proj.director.codex", "agent",
            "wide chat " + filler))

        # Measure the real envelopes, then put the ceiling between one chunk
        # and the whole delta, so the RECOVERY PATH is what is under test.
        cursor = engine.status()["mirror_cursor"]
        fingerprint = engine.visibility_fingerprint

        def size(resources=None):
            return len(protocol.canonical_json_bytes(client.pull(
                cursor=cursor, visibility_fingerprint=fingerprint,
                resources=resources)))

        negotiated = engine.projection_capabilities["resources"]
        large = [name for name in protocol.LARGE_PROJECTION_RESOURCES
                 if name in negotiated]
        small = [name for name in negotiated if name not in large]
        chunks = [size(small)] + [size([name]) for name in large]
        ceiling = max(chunks) + 1024
        whole = size()
        self.assertLess(ceiling, whole)

        with mock.patch.object(protocol, "MAX_PULL_BYTES", ceiling):
            report = engine.synchronize(client)

        self.assertEqual(report["status"], "online")
        self.assertIsNone(report["error"])
        _, current, _ = self.fx.snapshot()
        self.assertEqual(engine.status()["mirror_cursor"], current["cursor"])
        self.assertFalse(engine.status()["mirror_stale"])
        projection = engine.local_projection()
        self.assertEqual(
            len([item for item in projection["tasks"]
                 if str(item.get("title", "")).startswith("Wide task")]), 3)
        self.assertTrue(any(
            str(item.get("body", "")).startswith("wide chat")
            for item in projection["room_messages"]))
        # A narrowed request is not a visibility change: no reset happened.
        self.assertEqual(engine.visibility_fingerprint, fingerprint)

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
