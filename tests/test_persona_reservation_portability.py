"""Portable never-reuse registry contracts for named Attacca identities.

Every database, mirror, and HOME-like storage root in this module is
temporary.  Nothing contacts a configured or live Attacca server.
"""

import copy
import json
import sqlite3
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path

import attacca as core
import project_export
# This path-loaded fixture intentionally establishes the repository's
# standalone ``sync_protocol`` module before the three runtime modules below.
# Keeping this import order avoids creating two exception-class identities in
# a combined unittest process.
from tests.test_sync_server import Harness
import offline_sync
import sync_protocol as protocol
import sync_server


def identity():
    return {
        "server_id": "srv_isolated",
        "project_id": "portable",
        "principal_id": "human_fixture",
        "actor_id": "portable.director.codex.gibbs",
        "actor_type": "agent",
        "role": "director",
    }


def reservation_projection(scope=None):
    scope = scope or identity()
    return {
        "project": {
            "project_id": scope["project_id"],
            "name": "Portable",
            "context_version": 1,
        },
        "handoffs": [],
        "identity_handoffs": [],
        "role_scopes": [],
        "rules": [],
        "tasks": [],
        "decisions": [],
        "room_messages": [],
        "agents": [{
            "project_id": scope["project_id"],
            "agent_id": scope["actor_id"],
            "role": scope["role"],
        }],
        "bridges": [],
        "inbox_cursor": {
            "actor_id": scope["actor_id"], "last_read_seq": 0,
        },
        "task_plans": [],
        "full_log": [],
        "actor_aliases": [],
        "cloud_context": None,
        "message_dispositions": [],
        # Deliberately no reserved_actor_id or source: those are complete
        # administrative-export fields, not identity-mirror data.
        "persona_reservations": [{
            "project_id": scope["project_id"],
            "persona": "gibbs",
            "persona_name": "Gibbs",
            "reserved_at": "2026-08-31T00:00:00.000Z",
        }, {
            "project_id": scope["project_id"],
            "persona": "turing",
            "persona_name": "Turing",
            "reserved_at": "2026-08-31T00:00:01.000Z",
        }],
    }


class PersonaReservationExportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = core.connect(self.root / "source.db")
        self.addCleanup(self.source.close)
        workspace = self.root / "source-workspace"
        workspace.mkdir()
        core.project_init(
            self.source, "human.fixture", "human", path=workspace,
            project_id="portable", name="Portable")
        for persona, actor, at, source in (
                ("gibbs", "portable.director.codex.gibbs",
                 "2026-08-31T00:00:00.000Z", "agent.automatic_name"),
                ("turing", "portable.worker.claude.turing",
                 "2026-08-31T00:00:01.000Z", "historical:events.actor_id")):
            self.source.execute(
                "INSERT INTO agent_persona_reservations "
                "(project_id,persona,persona_name,reserved_actor_id,"
                "reserved_at,source) VALUES (?,?,?,?,?,?)",
                ("portable", persona, persona.title(), actor, at, source))

    def build(self):
        return project_export.build_project_export(
            self.source, "portable", log_renderer=core.render_log_line)

    def destination(self, name):
        connection = core.connect(self.root / (name + ".db"))
        workspace = self.root / (name + "-workspace")
        workspace.mkdir()
        core.project_init(
            connection, "human.fixture", "human", path=workspace,
            project_id="portable", name="Portable restore")
        return connection

    def test_schema_v2_json_zip_and_atomic_restore_preserve_all_names(self):
        exported = self.build()
        self.assertEqual(exported["manifest"]["schema_version"], 2)
        self.assertEqual(
            exported["manifest"]["counts"][
                "agent_persona_reservations"], 2)
        self.assertEqual(
            [row["persona"]
             for row in exported["agent_persona_reservations"]],
            ["gibbs", "turing"])
        self.assertEqual(
            exported["agent_persona_reservations"][1]["reserved_actor_id"],
            "portable.worker.claude.turing")
        coverage = exported["manifest"]["compatibility"][
            "agent_persona_reservations"]["coverage"]
        self.assertEqual(
            exported["manifest"]["compatibility"]
            ["agent_persona_reservations"]["kind"],
            "append_only_server_unique_name_registry_slice")
        self.assertTrue(coverage["complete"])
        self.assertEqual(
            coverage["method"], "durable_identity_history_scan_v1")
        self.assertEqual(len(coverage["registry_sha256"]), 64)
        self.assertTrue(project_export.validate_project_export(exported)["ok"])
        with zipfile.ZipFile(BytesIO(
                project_export.project_export_zip_bytes(exported))) as archive:
            restored_json = json.loads(archive.read("project-export.json"))
        self.assertEqual(
            restored_json["agent_persona_reservations"],
            exported["agent_persona_reservations"])

        destination = self.destination("destination")
        self.addCleanup(destination.close)
        first = project_export.restore_exported_persona_reservations(
            destination, exported)
        second = project_export.restore_exported_persona_reservations(
            destination, exported)
        self.assertEqual(first, {
            "project_id": "portable", "inserted": 2,
            "preserved": 0, "total": 2,
        })
        self.assertEqual(second["inserted"], 0)
        self.assertEqual(second["preserved"], 2)
        # The target has no current named agent rows.  The imported registry
        # alone is sufficient to prevent either historic name being reused.
        self.assertEqual(
            core.next_agent_persona(
                destination, "portable", "director", "codex"),
            "hopper")

        conflict = self.destination("conflict")
        self.addCleanup(conflict.close)
        conflict.execute(
            "INSERT INTO agent_persona_reservations "
            "(project_id,persona,persona_name,reserved_actor_id,"
            "reserved_at,source) VALUES (?,?,?,?,?,?)",
            ("portable", "gibbs", "Gibbs",
             "portable.worker.claude.gibbs",
             "2026-08-30T00:00:00.000Z", "conflicting.restore"))
        with self.assertRaisesRegex(
                project_export.ProjectExportError, "conflicting reservation"):
            project_export.restore_exported_persona_reservations(
                conflict, exported)
        self.assertIsNone(conflict.execute(
            "SELECT 1 FROM agent_persona_reservations "
            "WHERE project_id='portable' AND persona='turing'").fetchone())

    def test_restore_atomically_rejects_name_reserved_by_another_project(self):
        exported = self.build()
        destination = self.destination("global-conflict")
        self.addCleanup(destination.close)
        other_workspace = self.root / "other-workspace"
        other_workspace.mkdir()
        core.project_init(
            destination, "human.fixture", "human", path=other_workspace,
            project_id="other", name="Other")
        destination.execute(
            "INSERT INTO agent_persona_reservations "
            "(project_id,persona,persona_name,reserved_actor_id,"
            "reserved_at,source) VALUES (?,?,?,?,?,?)",
            ("other", "gibbs", "Gibbs", "other.director.codex.gibbs",
             "2026-08-30T00:00:00.000Z", "existing.global.name"))

        with self.assertRaisesRegex(
                project_export.ProjectExportError,
                "already reserves @Gibbs in project other"):
            project_export.restore_exported_persona_reservations(
                destination, exported)
        self.assertIsNone(destination.execute(
            "SELECT 1 FROM agent_persona_reservations "
            "WHERE project_id='portable' AND persona IN ('gibbs','turing')"
        ).fetchone())

    def test_v1_remains_readable_but_cannot_claim_complete_name_restore(self):
        legacy = copy.deepcopy(self.build())
        legacy.pop("agent_persona_reservations")
        legacy["manifest"]["schema_version"] = 1
        legacy["manifest"]["counts"].pop("agent_persona_reservations")
        legacy["manifest"]["compatibility"].pop(
            "agent_persona_reservations")
        body = {key: value for key, value in legacy.items()
                if key != "manifest"}
        legacy["manifest"]["content_sha256"] = project_export._sha256(
            project_export._json_bytes(body, pretty=False))
        self.assertTrue(project_export.validate_project_export(legacy)["ok"])
        self.assertTrue(project_export.project_export_json_bytes(legacy))

        destination = self.destination("legacy-destination")
        self.addCleanup(destination.close)
        with self.assertRaisesRegex(
                project_export.ProjectExportError,
                "no complete agent persona reservation registry"):
            project_export.restore_exported_persona_reservations(
                destination, legacy)

    def test_v2_validation_rejects_missing_malformed_or_duplicate_registry(self):
        exported = self.build()
        missing = copy.deepcopy(exported)
        missing.pop("agent_persona_reservations")
        with self.assertRaisesRegex(
                project_export.ProjectExportError,
                "requires agent_persona_reservations"):
            project_export.validate_project_export(missing)

        stale_name = copy.deepcopy(exported)
        stale_name["agent_persona_reservations"][0]["persona_name"] = "Other"
        with self.assertRaisesRegex(
                project_export.ProjectExportError, "stale persona_name"):
            project_export.validate_project_export(stale_name)

        duplicate = copy.deepcopy(exported)
        duplicate["agent_persona_reservations"][1]["persona"] = "gibbs"
        duplicate["agent_persona_reservations"][1]["persona_name"] = "Gibbs"
        with self.assertRaisesRegex(
                project_export.ProjectExportError, "duplicate persona"):
            project_export.validate_project_export(duplicate)

    def test_export_refuses_raw_unmigrated_or_post_marker_history_gaps(self):
        nowi = core.now_iso()
        self.source.execute(
            "INSERT INTO agents"
            " (project_id,agent_id,display_name,role,runtime,owner,actor_type,"
            " registered_at,last_seen_at) VALUES"
            " ('portable','portable.advisor.kimi.hopper','Old Hopper',"
            " 'advisor','kimi','fixture','agent',?,?)",
            (nowi, nowi))
        with self.assertRaisesRegex(
                project_export.ProjectExportError,
                "reservation coverage is incomplete.*@Hopper"):
            self.build()

        # A raw pre-migration connection cannot silently emit schema-v2 with
        # an empty section and a false completeness label.
        self.source.execute("DROP TABLE agent_persona_reservations")
        with self.assertRaisesRegex(
                project_export.ProjectExportError,
                "requires the migrated agent persona reservation registry"):
            self.build()

    def test_export_rejects_unicode_and_mismatched_reservation_actors(self):
        exported = self.build()
        unicode_row = copy.deepcopy(exported)
        unicode_row["agent_persona_reservations"][0].update({
            "persona": "gíbbs",
            "persona_name": "Gíbbs",
            "reserved_actor_id": "portable.director.codex.gíbbs",
        })
        with self.assertRaisesRegex(
                project_export.ProjectExportError, "invalid persona"):
            project_export.validate_project_export(unicode_row)

        cross_project = copy.deepcopy(exported)
        cross_project["agent_persona_reservations"][0][
            "reserved_actor_id"] = "other.director.codex.gibbs"
        with self.assertRaisesRegex(
                project_export.ProjectExportError,
                "canonical same-project actor"):
            project_export.validate_project_export(cross_project)

        wrong_suffix = copy.deepcopy(exported)
        wrong_suffix["agent_persona_reservations"][0][
            "reserved_actor_id"] = "portable.director.codex.curie"
        with self.assertRaisesRegex(
                project_export.ProjectExportError, "ending in .gibbs"):
            project_export.validate_project_export(wrong_suffix)

    def test_restore_rolls_back_and_releases_on_base_exception(self):
        exported = self.build()
        destination = self.destination("interrupted")
        self.addCleanup(destination.close)

        class InterruptingConnection:
            def __init__(self, connection):
                self.connection = connection
                self.inserts = 0

            def execute(self, sql, params=()):
                if sql.startswith(
                        "INSERT INTO agent_persona_reservations"):
                    self.inserts += 1
                    if self.inserts == 2:
                        raise KeyboardInterrupt("fixture interruption")
                return self.connection.execute(sql, params)

        wrapped = InterruptingConnection(destination)
        with self.assertRaises(KeyboardInterrupt):
            project_export.restore_exported_persona_reservations(
                wrapped, exported)
        self.assertEqual(destination.execute(
            "SELECT COUNT(*) AS n FROM agent_persona_reservations"
            " WHERE project_id='portable'").fetchone()["n"], 0)
        self.assertFalse(destination.in_transaction)

    def test_restore_project_check_is_inside_clean_savepoint(self):
        exported = self.build()
        destination = core.connect(self.root / "missing-project.db")
        self.addCleanup(destination.close)
        with self.assertRaisesRegex(
                project_export.ProjectExportError,
                "destination does not contain project portable"):
            project_export.restore_exported_persona_reservations(
                destination, exported)
        self.assertFalse(destination.in_transaction)


class PersonaReservationSyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scope = identity()
        self.capabilities = protocol.current_projection_capabilities()
        policy = protocol.projection_visibility_policy(
            {"role": "director", "generation": 1}, self.capabilities)
        self.visibility = protocol.visibility_fingerprint(self.scope, policy)

    def test_capability_is_optional_for_old_clients_and_rows_are_redacted(self):
        self.assertIn(
            "persona_reservations", self.capabilities["resources"])
        prior_resources = [
            resource for resource in self.capabilities["resources"]
            if resource not in {"persona_reservations", "project_handoffs"}]
        prior = protocol.make_projection_capabilities(2, prior_resources)
        self.assertNotIn(
            "persona_reservations",
            protocol.negotiate_projection_capabilities(prior)["resources"])

        checked = protocol.validate_projection_for_capabilities(
            reservation_projection(self.scope), self.scope,
            self.capabilities)
        encoded = json.dumps(checked["persona_reservations"], sort_keys=True)
        self.assertNotIn("reserved_actor_id", encoded)
        self.assertNotIn("source", encoded)
        self.assertNotIn("portable.worker", encoded)

        leaked = reservation_projection(self.scope)
        leaked["persona_reservations"][0]["reserved_actor_id"] = \
            "portable.worker.claude.retired"
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            protocol.validate_projection_for_capabilities(
                leaked, self.scope, self.capabilities)
        self.assertEqual(raised.exception.code, "unknown_field")

        # Filtering for an older client still validates the raw current
        # projector before dropping the unnegotiated resource.
        with self.assertRaises(protocol.SyncProtocolError):
            protocol.filter_projection_for_capabilities(
                leaked, self.scope, prior)
        filtered = protocol.filter_projection_for_capabilities(
            reservation_projection(self.scope), self.scope, prior)
        self.assertNotIn("persona_reservations", filtered)

    def test_verified_offline_mirror_reads_names_and_rejects_forged_rows(self):
        snapshot = protocol.make_snapshot(
            self.scope, self.visibility,
            protocol.make_cursor(0, protocol.GENESIS_HASH, 1),
            reservation_projection(self.scope), [],
            generated_at="2026-08-31T00:00:02.000Z")
        mirror = offline_sync.OfflineProjectSync(
            self.root / "mirror", "https://isolated.invalid", self.scope,
            "client_isolated", "device_isolated",
            visibility_fingerprint=self.visibility,
            projection_capabilities=self.capabilities)
        mirror.install_snapshot(snapshot)
        self.assertEqual(
            [row["persona"] for row in mirror.read_section("personas")],
            ["gibbs", "turing"])

        forged_projection = reservation_projection(self.scope)
        forged_projection["persona_reservations"][0]["project_id"] = "other"
        with self.assertRaises(protocol.SyncProtocolError):
            protocol.make_snapshot(
                self.scope, self.visibility,
                protocol.make_cursor(0, protocol.GENESIS_HASH, 1),
                forged_projection, [])

    def test_named_agents_require_complete_negotiated_registry(self):
        missing = reservation_projection(self.scope)
        missing["persona_reservations"] = [
            row for row in missing["persona_reservations"]
            if row["persona"] != "gibbs"]
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            protocol.validate_projection_for_capabilities(
                missing, self.scope, self.capabilities)
        self.assertEqual(
            raised.exception.code, "incomplete_persona_reservations")

        absent = reservation_projection(self.scope)
        absent.pop("persona_reservations")
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            protocol.validate_projection_for_capabilities(
                absent, self.scope, self.capabilities)
        self.assertEqual(raised.exception.code, "missing_persona_reservations")

        unicode_agent = reservation_projection(self.scope)
        unicode_agent["agents"][0]["agent_id"] = \
            "portable.director.codex.gíbbs"
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            protocol.validate_projection_for_capabilities(
                unicode_agent, self.scope, self.capabilities)
        self.assertEqual(raised.exception.code, "invalid_agent_persona")

    def test_offline_mirror_never_persists_incomplete_named_registry(self):
        incomplete = reservation_projection(self.scope)
        incomplete["persona_reservations"] = []
        snapshot = protocol.make_snapshot(
            self.scope, self.visibility,
            protocol.make_cursor(0, protocol.GENESIS_HASH, 1),
            incomplete, [], generated_at="2026-08-31T00:00:02.000Z")
        mirror = offline_sync.OfflineProjectSync(
            self.root / "incomplete", "https://isolated.invalid", self.scope,
            "client_isolated", "device_isolated",
            visibility_fingerprint=self.visibility,
            projection_capabilities=self.capabilities)
        with self.assertRaises(offline_sync.OfflineMirrorError):
            mirror.install_snapshot(snapshot)
        self.assertFalse(mirror.has_mirror())

    def test_server_authorizes_before_projecting_and_negotiates_resource(self):
        connection = sqlite3.connect(
            self.root / "sync.db", isolation_level=None)
        self.addCleanup(connection.close)
        harness = Harness()
        harness.create_schema(connection)
        calls = []

        def projector(conn, scope, mode, start, through, events):
            calls.append(mode)
            result = harness.visibility_projector(
                conn, scope, mode, start, through, events)
            if mode != "policy":
                result["projection"]["identity_handoffs"] = []
                result["projection"]["role_scopes"] = []
                result["projection"]["cloud_context"] = None
                result["projection"]["message_dispositions"] = []
                result["projection"]["persona_reservations"] = \
                    reservation_projection(self.scope)[
                        "persona_reservations"]
            return result

        allowed = {"value": False}

        def authorize(conn, scope, action, operation):
            return allowed["value"]

        engine = sync_server.SyncServerEngine(
            connection, sync_server.SyncServerAdapters(
                authorize=authorize,
                head_cursor=harness.head_cursor,
                read_events=harness.read_events,
                visibility_projector=projector,
                apply_mutation=harness.apply_mutation,
                check_precondition=harness.check_precondition))
        with self.assertRaises(sync_server.SyncServerAuthorizationError):
            engine.snapshot(
                self.scope, projection_capabilities=self.capabilities)
        self.assertEqual(calls, [])

        allowed["value"] = True
        current = engine.snapshot(
            self.scope, projection_capabilities=self.capabilities)
        self.assertEqual(
            current["projection"]["persona_reservations"][0][
                "persona_name"], "Gibbs")
        prior = protocol.make_projection_capabilities(2, [
            resource for resource in self.capabilities["resources"]
            if resource not in {"persona_reservations", "project_handoffs"}])
        older = engine.snapshot(
            self.scope, projection_capabilities=prior)
        self.assertNotIn("persona_reservations", older["projection"])


if __name__ == "__main__":
    unittest.main()
