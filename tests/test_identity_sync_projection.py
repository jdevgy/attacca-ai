"""T-75 exact-identity mirror and role-scope security contracts.

All storage and server fixtures are temporary and isolated.  These tests never
contact a configured Attacca host or inspect a real machine credential.
"""

import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import offline_sync
import sync_protocol as protocol
import sync_server
import attacca as core
from tests.test_sync_server import Harness


def actor_scope(persona="red", role="director"):
    return {
        "server_id": "srv_isolated",
        "project_id": "agentg",
        "principal_id": "jack",
        "actor_id": "agentg.%s.codex.%s" % (role, persona),
        "actor_type": "agent",
        "role": role,
    }


def identity_handoff(scope, version=1, objective="Continue safely"):
    return {
        "project_id": scope["project_id"],
        "actor_id": scope["actor_id"],
        "version": version,
        "content": {"objective": objective},
        "updated_by": scope["actor_id"],
        "updated_owner": scope["principal_id"],
        "updated_at": "2026-08-31T00:00:00.000Z",
        "event_id": "ev_handoff_%04d" % version,
        "legacy_source_version": None,
    }


def project_handoff(scope, version=1, objective="Coordinate the project",
                    updated_by=None):
    return {
        "project_id": scope["project_id"],
        "version": version,
        "content": {"objective": objective},
        "updated_by": updated_by if updated_by is not None else
        scope["actor_id"],
        "updated_at": "2026-08-31T00:00:00.000Z",
    }


def role_scope(scope, role=None, version=1):
    selected = role or scope["role"]
    return {
        "project_id": scope["project_id"],
        "role": selected,
        "version": version,
        "content": "%s durable context" % selected,
        "updated_by": "agentg.director.claude.red",
        "updated_owner": scope["principal_id"],
        "updated_at": "2026-08-31T00:00:00.000Z",
        "event_id": "ev_role_%s_%04d" % (selected, version),
    }


def projection(scope, *, handoffs=None, project_handoffs=None, scopes=None,
               lead=None):
    handoffs = list(handoffs if handoffs is not None else [
        identity_handoff(scope)])
    persona = scope["actor_id"].rsplit(".", 1)[-1]
    return {
        "project": {
            "project_id": scope["project_id"],
            "name": "Agentg",
            "context_version": 4,
            "lead_director": lead,
        },
        # Schema-v1 compatibility is an exact alias, not the old global rows.
        "handoffs": copy.deepcopy(handoffs),
        "identity_handoffs": copy.deepcopy(handoffs),
        "project_handoffs": copy.deepcopy(
            project_handoffs if project_handoffs is not None else [
                project_handoff(scope)]),
        "role_scopes": list(scopes if scopes is not None else [
            role_scope(scope)]),
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
        "persona_reservations": [{
            "project_id": scope["project_id"],
            "persona": persona,
            "persona_name": persona[:1].upper() + persona[1:],
            "reserved_at": "2026-08-30T00:00:00.000Z",
        }],
    }


class IdentityProjectionProtocolTests(unittest.TestCase):
    def setUp(self):
        self.scope = actor_scope()
        self.capabilities = protocol.current_projection_capabilities()

    def validate(self, value):
        return protocol.validate_projection_for_capabilities(
            value, self.scope, self.capabilities)

    def test_current_projection_requires_exact_history_and_applicable_scope(self):
        checked = self.validate(projection(self.scope))
        self.assertEqual(
            checked["identity_handoffs"][0]["actor_id"],
            "agentg.director.codex.red")
        self.assertEqual(checked["handoffs"], checked["identity_handoffs"])
        self.assertEqual(
            checked["project_handoffs"][0]["content"]["objective"],
            "Coordinate the project")
        self.assertEqual(checked["role_scopes"][0]["role"], "director")
        self.assertIn("identity_handoffs", self.capabilities["resources"])
        self.assertIn("project_handoffs", self.capabilities["resources"])
        self.assertIn("role_scopes", self.capabilities["resources"])

    def test_shared_history_is_project_bound_and_retains_human_writers(self):
        history = [
            project_handoff(
                self.scope, 1, "Historical human state", "web.jack"),
            project_handoff(self.scope, 2, "Current Director state"),
        ]
        checked = self.validate(projection(
            self.scope, project_handoffs=history))
        self.assertEqual(
            [row["updated_by"] for row in checked["project_handoffs"]],
            ["web.jack", self.scope["actor_id"]])

        cross_project = copy.deepcopy(history)
        cross_project[0]["project_id"] = "other"
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            self.validate(projection(
                self.scope, project_handoffs=cross_project))
        self.assertEqual(raised.exception.code, "cross_project_projection")

        reversed_history = list(reversed(history))
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            self.validate(projection(
                self.scope, project_handoffs=reversed_history))
        self.assertEqual(raised.exception.code, "invalid_project_handoff")

    def test_other_persona_global_rows_and_false_attribution_fail_closed(self):
        blue = actor_scope("blue")
        cross_actor = projection(
            self.scope, handoffs=[identity_handoff(blue)])
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            self.validate(cross_actor)
        self.assertEqual(raised.exception.code, "cross_actor_handoff")

        global_row = identity_handoff(self.scope)
        global_row.pop("actor_id")
        global_projection = projection(self.scope, handoffs=[global_row])
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            self.validate(global_projection)
        self.assertEqual(raised.exception.code, "invalid_identity_handoff")

        forged = projection(self.scope)
        forged["identity_handoffs"][0]["updated_by"] = blue["actor_id"]
        forged["handoffs"] = copy.deepcopy(forged["identity_handoffs"])
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            self.validate(forged)
        self.assertEqual(raised.exception.code, "cross_actor_handoff")

    def test_compatibility_alias_cannot_diverge_or_reorder_history(self):
        rows = [identity_handoff(self.scope, 1),
                identity_handoff(self.scope, 2)]
        checked = self.validate(projection(self.scope, handoffs=rows))
        self.assertEqual([row["version"] for row in checked["handoffs"]],
                         [1, 2])

        divergent = projection(self.scope, handoffs=rows)
        divergent["handoffs"] = divergent["handoffs"][:1]
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            self.validate(divergent)
        self.assertEqual(raised.exception.code, "invalid_projection")

        reversed_rows = projection(
            self.scope, handoffs=list(reversed(rows)))
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            self.validate(reversed_rows)
        self.assertEqual(raised.exception.code, "invalid_identity_handoff")

    def test_role_scope_is_role_bound_and_lead_overlay_is_exact(self):
        wrong_role = projection(
            self.scope, scopes=[role_scope(self.scope, "worker")])
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            self.validate(wrong_role)
        self.assertEqual(raised.exception.code, "cross_role_scope")

        lead_row = role_scope(self.scope, "lead_director")
        not_lead = projection(self.scope, scopes=[
            role_scope(self.scope), lead_row])
        with self.assertRaises(protocol.SyncProtocolError) as raised:
            self.validate(not_lead)
        self.assertEqual(raised.exception.code, "cross_role_scope")

        lead = projection(
            self.scope,
            scopes=[role_scope(self.scope), lead_row],
            lead=self.scope["actor_id"])
        checked = self.validate(lead)
        self.assertEqual(
            [row["role"] for row in checked["role_scopes"]],
            ["director", "lead_director"])

    def test_older_explicit_v2_offer_keeps_its_smaller_resource_shape(self):
        old_resources = [
            item for item in self.capabilities["resources"]
            if item not in {
                "identity_handoffs", "role_scopes", "project_handoffs"}
        ]
        older = protocol.make_projection_capabilities(2, old_resources)
        negotiated = protocol.negotiate_projection_capabilities(older)
        self.assertNotIn("identity_handoffs", negotiated["resources"])
        self.assertNotIn("role_scopes", negotiated["resources"])
        self.assertNotIn("project_handoffs", negotiated["resources"])

        # Current clients also tolerate an older server omitting optional new
        # fields, while still rejecting any non-empty project-global handoff
        # row through the exact-actor checks.
        older_projection = projection(self.scope, handoffs=[], scopes=[])
        older_projection.pop("identity_handoffs")
        older_projection.pop("role_scopes")
        older_projection.pop("project_handoffs")
        protocol.validate_projection_for_capabilities(
            older_projection, self.scope, self.capabilities)


class IdentityProjectionOfflineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scope = actor_scope()
        self.capabilities = protocol.current_projection_capabilities()
        policy = protocol.projection_visibility_policy(
            {"role": "director", "generation": 1}, self.capabilities)
        self.visibility = protocol.visibility_fingerprint(self.scope, policy)

    def mirror(self, suffix="red"):
        return offline_sync.OfflineProjectSync(
            self.root / suffix, "https://isolated.invalid", self.scope,
            "client_%s" % suffix, "device_%s" % suffix,
            visibility_fingerprint=self.visibility,
            projection_capabilities=self.capabilities)

    def snapshot(self, value):
        return protocol.make_snapshot(
            self.scope, self.visibility,
            protocol.make_cursor(0, protocol.GENESIS_HASH, 4),
            value, [], generated_at="2026-08-31T00:00:00.000Z")

    def test_verified_mirror_exposes_only_exact_identity_resources(self):
        mirror = self.mirror()
        mirror.install_snapshot(self.snapshot(projection(self.scope)))
        self.assertEqual(
            mirror.read_section("identity_handoff")["actor_id"],
            self.scope["actor_id"])
        self.assertEqual(
            mirror.read_section("handoff")["content"]["objective"],
            "Coordinate the project")
        self.assertEqual(
            mirror.read_section("shared_handoff"),
            mirror.read_section("project_handoff"))
        self.assertEqual(
            mirror.read_section("handoffs"),
            mirror.read_section("identity_handoffs"))
        self.assertEqual(
            mirror.read_section("role_scopes")[0]["role"], "director")
        mirror.queue_mutation(
            "handoff.update", {"notes": "Shared offline change"},
            client_mutation_id="cm_project_handoff_0001")
        self.assertEqual(
            mirror.pending_overlays("handoff")[0]["resource"],
            "project_handoffs")

        forged = projection(
            self.scope, handoffs=[identity_handoff(actor_scope("blue"))])
        with self.assertRaises(offline_sync.OfflineMirrorError):
            self.mirror("forged").install_snapshot(self.snapshot(forged))

    def test_legacy_global_handoff_is_not_migrated_or_cloned(self):
        bootstrap = self.mirror("legacy")
        legacy_key = bootstrap._legacy_identity_key(self.scope)
        legacy_path = bootstrap.mirrors_directory / legacy_key / \
            "snapshot.json"
        legacy_path.parent.mkdir(parents=True, exist_ok=True)
        legacy_projection = projection(self.scope)
        legacy_projection.pop("identity_handoffs")
        legacy_projection.pop("role_scopes")
        legacy_projection.pop("project_handoffs")
        legacy_projection["handoffs"] = [{
            "project_id": "agentg", "version": 91,
            "content": {"objective": "retired global state"},
        }]
        legacy_snapshot = self.snapshot(legacy_projection)
        wrapper = {
            "format": offline_sync.MIRROR_FORMAT,
            "schema_version": offline_sync.OFFLINE_SYNC_SCHEMA_VERSION,
            "normalized_server_url": bootstrap.normalized_server_url,
            "storage_key": bootstrap.storage_key,
            "mirror_key": legacy_key,
            "scope_fingerprint": protocol.scope_fingerprint(self.scope),
            "scope": self.scope,
            "visibility_fingerprint": self.visibility,
            "verified_at": "2026-08-31T00:00:00.000Z",
            "reset_reason": None,
            "snapshot_sha256": offline_sync._sha256(legacy_snapshot),
            "snapshot": legacy_snapshot,
        }
        legacy_path.write_bytes(protocol.canonical_json_bytes(wrapper))

        reloaded = self.mirror("legacy")
        self.assertFalse(reloaded.has_mirror())
        self.assertTrue(legacy_path.is_file())


class IdentityProjectionServerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.connection = sqlite3.connect(
            Path(self.temporary.name) / "server.db", isolation_level=None)
        self.addCleanup(self.connection.close)
        self.harness = Harness()
        self.harness.create_schema(self.connection)
        self.scope = actor_scope()

    def engine(self, forged=False):
        original = self.harness.visibility_projector

        def projector(conn, scope, mode, start, through, events):
            result = original(conn, scope, mode, start, through, events)
            if mode != "policy":
                selected = actor_scope("blue") if forged else self.scope
                rows = [identity_handoff(selected)]
                result["projection"]["handoffs"] = copy.deepcopy(rows)
                result["projection"]["identity_handoffs"] = rows
                result["projection"]["project_handoffs"] = [
                    project_handoff(self.scope)]
                result["projection"]["role_scopes"] = [
                    role_scope(self.scope)]
                result["projection"]["persona_reservations"] = \
                    projection(self.scope)["persona_reservations"]
            return result

        return sync_server.SyncServerEngine(
            self.connection,
            sync_server.SyncServerAdapters(
                authorize=self.harness.authorize,
                head_cursor=self.harness.head_cursor,
                read_events=self.harness.read_events,
                visibility_projector=projector,
                apply_mutation=self.harness.apply_mutation,
                check_precondition=self.harness.check_precondition,
            ))

    def test_server_filters_current_projection_at_exact_actor_boundary(self):
        snapshot = self.engine().snapshot(
            self.scope, projection_capabilities=
            protocol.current_projection_capabilities())
        self.assertEqual(
            snapshot["projection"]["identity_handoffs"][0]["actor_id"],
            self.scope["actor_id"])

        with self.assertRaises(protocol.SyncProtocolError) as raised:
            self.engine(forged=True).snapshot(
                self.scope, projection_capabilities=
                protocol.current_projection_capabilities())
        self.assertEqual(raised.exception.code, "cross_actor_handoff")


class ProductProjectionIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.connection = core.connect(self.root / "attacca.db")
        self.addCleanup(self.connection.close)
        core.set_current_owner("jack")
        self.addCleanup(core.set_current_owner, None)
        core.project_init(
            self.connection, "web.jack", "human", path=self.workspace,
            project_id="agentg", name="Agentg")
        self.red = "agentg.director.codex.red"
        self.blue = "agentg.director.codex.blue"
        for actor, persona in ((self.red, "red"), (self.blue, "blue")):
            core.agent_register(
                self.connection, "agentg", actor, "agent",
                agent_id=actor, role="director", runtime="codex",
                persona=persona, canonical_identity=True,
                distinct_identity=True)
            core.update_identity_handoff(
                self.connection, "agentg", actor, "agent",
                {"objective": "%s private continuity" % persona})
        core.update_handoff(
            self.connection, "agentg", self.red, "agent",
            {"objective": "Shared project continuity"})
        core.set_lead_director(
            self.connection, "agentg", "web.jack", "human", self.red)
        core.role_scope_set(
            self.connection, "agentg", "web.jack", "human", "director",
            "Shared Director context")
        core.role_scope_set(
            self.connection, "agentg", "web.jack", "human",
            "lead_director", "Lead-only coordination context")

    @staticmethod
    def scope(actor):
        return {
            "server_id": "srv_product_fixture", "project_id": "agentg",
            "principal_id": "jack", "actor_id": actor,
            "actor_type": "agent", "role": "director",
        }

    def test_real_projector_separates_personas_and_applies_lead_overlay(self):
        red_scope = self.scope(self.red)
        red = core._sync_projection(self.connection, red_scope)
        protocol.validate_projection_for_capabilities(
            red, red_scope, protocol.current_projection_capabilities())
        self.assertEqual(
            {row["actor_id"] for row in red["identity_handoffs"]},
            {self.red})
        self.assertEqual(red["handoffs"], red["identity_handoffs"])
        self.assertEqual(
            red["project_handoffs"][-1]["project_id"], "agentg")
        self.assertEqual(
            [row["role"] for row in red["role_scopes"]],
            ["director", "lead_director"])

        blue_scope = self.scope(self.blue)
        blue = core._sync_projection(self.connection, blue_scope)
        protocol.validate_projection_for_capabilities(
            blue, blue_scope, protocol.current_projection_capabilities())
        self.assertEqual(
            {row["actor_id"] for row in blue["identity_handoffs"]},
            {self.blue})
        self.assertNotIn(
            self.red,
            json.dumps(blue["identity_handoffs"], sort_keys=True))
        self.assertEqual(
            [row["role"] for row in blue["role_scopes"]], ["director"])


if __name__ == "__main__":
    unittest.main()
