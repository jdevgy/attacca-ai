"""Forward-compatibility and non-auth offline-sync regressions."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from attacca import offline_sync as offline
from attacca import sync_client as client_module
from attacca import sync_protocol as protocol
from attacca import sync_server as server_module
from attacca.tests.test_offline_sync import FakeRemote, identity
from attacca.tests.test_sync_server import Harness


def projection(scope, *, cloud=False, dispositions=False):
    value = {
        "project": {
            "project_id": scope["project_id"], "name": "Agentg",
            "context_version": 0,
        },
        "handoffs": [], "rules": [], "tasks": [], "decisions": [],
        "room_messages": [], "agents": [], "bridges": [],
        "inbox_cursor": {
            "actor_id": scope["actor_id"], "last_read_seq": 0,
        },
        "task_plans": [], "full_log": [], "actor_aliases": [],
    }
    if cloud:
        value["cloud_context"] = {
            "content": "# Agentg", "version": 8,
            "sha256": "a" * 64,
        }
    if dispositions:
        value["message_dispositions"] = [{
            "project_id": scope["project_id"],
            "event_id": "evt_0001", "disposition": "acknowledged",
        }]
    return value


def empty_snapshot(scope, capabilities, *, cloud=False, dispositions=False):
    policy = protocol.projection_visibility_policy(
        {"role": scope["role"], "generation": 0}, capabilities)
    return protocol.make_snapshot(
        scope, protocol.visibility_fingerprint(scope, policy),
        protocol.make_cursor(0, protocol.GENESIS_HASH, 0),
        projection(
            scope, cloud=cloud, dispositions=dispositions), [])


class RecordingTransport:
    def __init__(self, response, status=200):
        self.response = response
        self.status = status
        self.calls = []

    def request(self, method, url, *, headers, body, timeout,
                max_response_bytes):
        self.calls.append({"method": method, "url": url,
                           "headers": dict(headers), "body": body})
        return client_module.JsonHttpResponse(
            self.status, {"content-type": "application/json"},
            protocol.canonical_json_bytes(self.response))


class ProjectionCapabilityTests(unittest.TestCase):
    def test_absent_offer_is_legacy_and_future_offer_is_known_intersection(self):
        legacy = protocol.projection_capabilities_from_query()
        current = protocol.current_projection_capabilities()
        self.assertEqual(legacy["schema_version"], 1)
        self.assertNotIn("cloud_context", legacy["resources"])
        self.assertNotIn("message_dispositions", legacy["resources"])
        self.assertEqual(current["schema_version"], 2)
        self.assertIn("cloud_context", current["resources"])
        self.assertIn("message_dispositions", current["resources"])

        future = dict(current)
        future["schema_version"] = 99
        future["resources"] = list(future["resources"]) + ["future_notes"]
        selected = protocol.negotiate_projection_capabilities(future)
        self.assertEqual(selected, current)
        self.assertNotIn("future_notes", selected["resources"])

    def test_malformed_or_unnegotiated_resources_fail_closed(self):
        legacy = protocol.legacy_projection_capabilities()
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            protocol.validate_projection_for_capabilities(
                projection(identity(), cloud=True), identity(), legacy)
        self.assertEqual(
            raised.exception.code, "unnegotiated_projection_resource")
        with self.assertRaises(protocol.SyncProtocolError):
            protocol.projection_capabilities_from_query("2", "project,project")
        with self.assertRaises(protocol.SyncProtocolError):
            protocol.projection_capabilities_from_query("2", "project,$bad")


class ServerNegotiationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.connection = sqlite3.connect(
            Path(self.temporary.name) / "server.db",
            isolation_level=None)
        self.addCleanup(self.connection.close)
        self.harness = Harness()
        self.harness.create_schema(self.connection)
        original = self.harness.visibility_projector

        def projector(conn, scope, mode, start, through, events):
            result = original(conn, scope, mode, start, through, events)
            if mode == "snapshot":
                result["projection"]["cloud_context"] = {
                    "content": "full current context", "version": 8,
                }
                result["projection"]["message_dispositions"] = [{
                    "project_id": scope["project_id"],
                    "event_id": "evt_0001",
                    "disposition": "acknowledged",
                }]
            return result

        self.harness.visibility_projector = projector
        adapters = server_module.SyncServerAdapters(
            authorize=self.harness.authorize,
            head_cursor=self.harness.head_cursor,
            read_events=self.harness.read_events,
            visibility_projector=self.harness.visibility_projector,
            apply_mutation=self.harness.apply_mutation,
            check_precondition=self.harness.check_precondition,
            fault_injector=self.harness.fault_injector,
        )
        self.engine = server_module.SyncServerEngine(
            self.connection, adapters)
        self.scope = identity(principal="usr_jack")

    def test_legacy_client_never_receives_new_field_current_client_does(self):
        legacy = self.engine.snapshot(self.scope)
        current_capabilities = protocol.current_projection_capabilities()
        current = self.engine.snapshot(
            self.scope, projection_capabilities=current_capabilities)
        self.assertNotIn("cloud_context", legacy["projection"])
        self.assertNotIn("message_dispositions", legacy["projection"])
        self.assertEqual(
            current["projection"]["cloud_context"]["version"], 8)
        self.assertEqual(
            current["projection"]["message_dispositions"][0]["event_id"],
            "evt_0001")
        self.assertNotEqual(
            legacy["visibility_fingerprint"],
            current["visibility_fingerprint"])
        protocol.validate_projection_for_capabilities(
            legacy["projection"], self.scope,
            protocol.legacy_projection_capabilities())
        protocol.validate_projection_for_capabilities(
            current["projection"], self.scope, current_capabilities)


class ClientNegotiationTests(unittest.TestCase):
    def setUp(self):
        self.scope = identity()

    def client(self, transport, capabilities, visibility):
        return client_module.AuthenticatedSyncHttpClient(
            "https://example.test", "agentg", self.scope, visibility,
            "client_home", "device_home", lambda: "token",
            transport=transport, projection_capabilities=capabilities)

    def test_client_advertises_capabilities_and_rejects_unnegotiated_field(self):
        current = protocol.current_projection_capabilities()
        snapshot = empty_snapshot(self.scope, current, cloud=True)
        transport = RecordingTransport(snapshot)
        checked = self.client(
            transport, current,
            snapshot["visibility_fingerprint"]).fetch_snapshot()
        self.assertIn("cloud_context", checked["projection"])
        query = parse_qs(urlsplit(transport.calls[0]["url"]).query)
        self.assertEqual(query["projection_schema_version"], ["2"])
        self.assertIn("cloud_context", query["projection_resources"][0])

        legacy = protocol.legacy_projection_capabilities()
        legacy_transport = RecordingTransport(
            empty_snapshot(self.scope, legacy, cloud=True))
        with self.assertRaises(
                client_module.SyncSchemaCompatibilityError) as raised:
            self.client(
                legacy_transport, legacy,
                legacy_transport.response[
                    "visibility_fingerprint"]).fetch_snapshot()
        self.assertEqual(
            raised.exception.protocol_code,
            "unnegotiated_projection_resource")
        self.assertNotIsInstance(
            raised.exception, client_module.SyncAuthenticationError)

    def test_http_400_schema_code_is_not_auth_and_visibility_has_own_type(self):
        legacy = protocol.legacy_projection_capabilities()
        schema_error = RecordingTransport({
            "error": "client projection is newer",
            "code": "unsupported_projection_schema",
        }, status=400)
        with self.assertRaises(
                client_module.SyncSchemaCompatibilityError) as raised:
            self.client(schema_error, legacy, None).fetch_snapshot()
        self.assertEqual(raised.exception.http_status, 400)
        self.assertNotIsInstance(
            raised.exception, client_module.SyncAuthenticationError)

        first = empty_snapshot(self.scope, legacy)
        changed = json.loads(json.dumps(first))
        changed["visibility_fingerprint"] = \
            protocol.visibility_fingerprint(
                self.scope, {"role": "director", "generation": 2})
        # The visibility value is not covered by projection_sha256.
        protocol.validate_snapshot(changed)
        with self.assertRaises(client_module.SyncVisibilityChangedError):
            self.client(
                RecordingTransport(changed), legacy,
                first["visibility_fingerprint"]).fetch_snapshot()

    def test_only_hosted_401_or_403_sets_authentication_http_status(self):
        legacy = protocol.legacy_projection_capabilities()
        rejected = RecordingTransport({"error": "revoked"}, status=403)
        with self.assertRaises(
                client_module.SyncAuthenticationError) as hosted:
            self.client(rejected, legacy, None).fetch_snapshot()
        self.assertEqual(hosted.exception.http_status, 403)

        local = client_module.AuthenticatedSyncHttpClient(
            "https://example.test", "agentg", self.scope, None,
            "client_home", "device_home", lambda: None,
            transport=RecordingTransport({}),
            projection_capabilities=legacy)
        with self.assertRaises(
                client_module.SyncAuthenticationError) as missing:
            local.fetch_snapshot()
        self.assertIsNone(missing.exception.http_status)

    def test_push_advertises_the_same_projection_capabilities(self):
        current = protocol.current_projection_capabilities()
        snapshot = empty_snapshot(
            self.scope, current, cloud=True, dispositions=True)
        mutation = protocol.make_client_mutation(
            self.scope, "cm_push_caps_0001", "client_home", "device_home",
            1, "room.send", {"body": "capability-bound push"},
            snapshot["cursor"])
        applied = protocol.applied_result(
            self.scope, mutation, {
                "canonical_event_id": "evt_push_caps_0001",
                "canonical_event_seq": 1,
            }, snapshot["cursor"])
        response = protocol.make_push_result(
            self.scope, snapshot["visibility_fingerprint"], [applied],
            snapshot["cursor"])
        transport = RecordingTransport(response)
        checked = self.client(
            transport, current,
            snapshot["visibility_fingerprint"]).push(
                mutations=[mutation], known_receipts=[])
        self.assertEqual(checked["results"][0]["status"], "applied")
        query = parse_qs(urlsplit(transport.calls[0]["url"]).query)
        self.assertEqual(query["projection_schema_version"], ["2"])
        self.assertIn(
            "message_dispositions", query["projection_resources"][0])


class CapabilityRemote(FakeRemote):
    def __init__(self):
        super().__init__()
        self.capabilities = protocol.current_projection_capabilities()
        self.drop_schema_response_once = False

    def visibility(self):
        policy = protocol.projection_visibility_policy({
            "role": self.scope["role"],
            "generation": self.policy_generation,
        }, self.capabilities)
        return protocol.visibility_fingerprint(self.scope, policy)

    def projection(self):
        value = super().projection()
        value["cloud_context"] = {
            "content": "capability-aware context", "version": 8,
        }
        value["message_dispositions"] = []
        return value

    def push(self, *, mutations, known_receipts):
        result = super().push(
            mutations=mutations, known_receipts=known_receipts)
        if self.drop_schema_response_once:
            self.drop_schema_response_once = False
            raise client_module.SyncSchemaCompatibilityError(
                "push response uses a newer projection schema",
                http_status=400,
                protocol_code="unsupported_projection_schema")
        return result


class OfflineCapabilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scope = identity()

    def engine(self, capabilities, visibility=None):
        return offline.OfflineProjectSync(
            self.root / "cache", "https://example.test", self.scope,
            "client_shared", "device_shared",
            visibility_fingerprint=visibility,
            projection_capabilities=capabilities)

    def test_mirrors_partition_by_capability_but_outbox_stays_exact_identity(self):
        legacy_caps = protocol.legacy_projection_capabilities()
        current_caps = protocol.current_projection_capabilities()
        legacy_snapshot = empty_snapshot(self.scope, legacy_caps)
        current_snapshot = empty_snapshot(
            self.scope, current_caps, cloud=True)
        legacy = self.engine(
            legacy_caps, legacy_snapshot["visibility_fingerprint"])
        legacy.install_snapshot(legacy_snapshot)
        mutation = legacy.queue_mutation(
            "room.send", {"body": "survives projection upgrade"},
            client_mutation_id="cm_upgrade_0001")

        current = self.engine(
            current_caps, current_snapshot["visibility_fingerprint"])
        self.assertNotEqual(legacy.mirror_path, current.mirror_path)
        self.assertEqual(legacy.outbox_directory, current.outbox_directory)
        current.install_snapshot(current_snapshot)
        self.assertEqual(
            [item["client_mutation_id"]
             for item in current.pending_mutations()],
            [mutation["client_mutation_id"]])
        proof = current.convergence_proof()
        self.assertEqual(
            proof["projection_capabilities"], current_caps)

    def test_verified_schema_v1_mirror_migrates_stale_without_server(self):
        capabilities = protocol.current_projection_capabilities()
        snapshot = empty_snapshot(
            self.scope, protocol.legacy_projection_capabilities(), cloud=True)
        bootstrap = self.engine(
            capabilities, snapshot["visibility_fingerprint"])
        legacy_key = bootstrap._legacy_identity_key(self.scope)
        legacy_path = bootstrap.mirrors_directory / legacy_key / \
            "snapshot.json"
        legacy_path.parent.mkdir(parents=True, exist_ok=True)
        legacy_wrapper = {
            "format": offline.MIRROR_FORMAT,
            "schema_version": offline.OFFLINE_SYNC_SCHEMA_VERSION,
            "normalized_server_url": bootstrap.normalized_server_url,
            "storage_key": bootstrap.storage_key,
            "mirror_key": legacy_key,
            "scope_fingerprint": protocol.scope_fingerprint(self.scope),
            "scope": self.scope,
            "visibility_fingerprint": snapshot["visibility_fingerprint"],
            "verified_at": "2026-08-25T12:00:00.000Z",
            "reset_reason": None,
            "snapshot_sha256": offline._sha256(snapshot),
            "snapshot": snapshot,
        }
        original_bytes = protocol.canonical_json_bytes(legacy_wrapper)
        legacy_path.write_bytes(original_bytes)

        migrated = self.engine(
            capabilities, snapshot["visibility_fingerprint"])
        self.assertTrue(migrated.has_mirror())
        self.assertEqual(
            migrated.read_section("cloud_context")["version"], 8)
        status = migrated.status()
        self.assertEqual(status["mode"], "pending")
        self.assertTrue(status["mirror_stale"])
        self.assertTrue(status["pending_sync"])
        self.assertFalse(status["convergence_proof"]["online"])
        self.assertEqual(legacy_path.read_bytes(), original_bytes)

    def test_schema_failure_after_commit_uses_cache_and_exact_retry(self):
        remote = CapabilityRemote()
        engine = self.engine(remote.capabilities)
        self.assertEqual(engine.synchronize(remote)["status"], "online")
        mutation = engine.queue_mutation(
            "message.dispose", {
                "event_id": "evt_0001", "disposition": "acknowledged",
            },
            client_mutation_id="cm_schema_0001")
        pending = engine.read_section(
            "message_dispositions", include_pending=True)
        self.assertEqual(pending["pending"][0]["resource"],
                         "message_dispositions")
        self.assertEqual(pending["pending"][0]["operation"],
                         "message.dispose")
        remote.drop_schema_response_once = True
        failed = engine.synchronize(remote)
        self.assertEqual(failed["status"], "offline")
        self.assertEqual(failed["failure_kind"], "schema_incompatible")
        self.assertFalse(failed["authentication_required"])
        self.assertTrue(failed["offline_usable"])
        self.assertEqual(engine.status()["pending_count"], 1)

        retried = engine.synchronize(remote)
        self.assertEqual(retried["status"], "online")
        self.assertEqual(retried["duplicates"], [
            mutation["client_mutation_id"]])
        self.assertEqual(retried["converged"], [
            mutation["client_mutation_id"]])
        self.assertEqual(
            remote.applied_ids.count(mutation["client_mutation_id"]), 1)

    def test_verified_offline_resources_and_fsynced_writes_replay_once(self):
        remote = CapabilityRemote()
        engine = self.engine(remote.capabilities)
        self.assertEqual(engine.synchronize(remote)["status"], "online")

        remote.online = False
        unavailable = engine.synchronize(remote)
        self.assertEqual(unavailable["status"], "offline")
        self.assertEqual(
            engine.read_section("handoff")["content"]["objective"],
            "Continue offline safely")
        self.assertEqual(engine.read_section("full_log"), [
            "identity-filtered log line"])
        self.assertEqual(engine.read_section("rules")[0]["rule_id"],
                         "R-everyone")
        self.assertEqual(engine.read_section("decisions")[0]["decision_id"],
                         "D-1")
        self.assertEqual(engine.read_section("tasks")[0]["task_id"], "T-1")
        self.assertEqual(engine.read_section("cloud_context")["version"], 8)

        queued = []
        for number, (operation, payload) in enumerate((
                ("room.send", {"body": "offline room update"}),
                ("task.create", {"title": "Offline task"}),
                ("decision.propose", {"title": "Offline decision"}),
                ("rule.create", {"title": "Offline rule"}),
                ("handoff.update", {"notes": "Offline handoff"}),
        ), start=1):
            queued.append(engine.queue_mutation(
                operation, payload,
                client_mutation_id="cm_offline_%04d" % number))

        # A fresh process can validate every fsynced journal record while the
        # server remains unavailable; no in-memory queue is required.
        restarted = self.engine(
            remote.capabilities, engine.visibility_fingerprint)
        self.assertEqual(
            [item["client_mutation_id"]
             for item in restarted.pending_mutations()],
            [item["client_mutation_id"] for item in queued])
        self.assertEqual(restarted.status()["journal_records"], len(queued))

        remote.online = True
        replayed = restarted.synchronize(remote)
        self.assertEqual(replayed["status"], "online")
        self.assertEqual(replayed["applied"], [
            item["client_mutation_id"] for item in queued])
        self.assertEqual(replayed["converged"], [
            item["client_mutation_id"] for item in queued])
        self.assertEqual(restarted.status()["pending_count"], 0)
        for item in queued:
            self.assertEqual(
                remote.applied_ids.count(item["client_mutation_id"]), 1)


if __name__ == "__main__":
    unittest.main()
