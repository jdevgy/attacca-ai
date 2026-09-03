"""Standalone project-export and offline-baseline contract tests."""

import copy
import hashlib
import importlib.util
import json
import os
import stat
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path


os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c = load_module("attacca_export_fixture_core", ROOT / "attacca.py")
exporter = load_module("attacca_project_export", ROOT / "project_export.py")


class ProjectExportTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.conn = c.connect(self.root / "attacca.db")
        repo = self.root / "primary"
        peer_repo = self.root / "peer"
        repo.mkdir()
        peer_repo.mkdir()
        c.project_init(
            self.conn, "owner", "human", path=repo,
            project_id="p1", name="Project One")
        c.project_init(
            self.conn, "owner", "human", path=peer_repo,
            project_id="peer", name="Peer")

        c.agent_register(
            self.conn, "p1", "director", "agent", agent_id="director",
            display_name="Director", role="director", runtime="codex")
        c.agent_register(
            self.conn, "p1", "worker", "agent", agent_id="worker",
            display_name="Worker", role="worker", runtime="claude")
        c.agent_register(
            self.conn, "peer", "ghost-peer", "agent", agent_id="ghost-peer",
            display_name="Peer Worker", role="worker", runtime="claude")
        task = c.task_create(
            self.conn, "p1", "director", "agent", "Portable export",
            description="Keep every durable project record",
            expected_scope=["**"], dependencies=[],
            risk_level="medium", plan_required=True)
        self.task_id = task["task_id"]
        c.task_plan_set(
            self.conn, "p1", self.task_id, "owner", "human",
            "Export plan", "First pass",
            [{"section_id": "shape", "title": "Shape",
              "body": "Include the ledger."}])
        c.task_plan_set(
            self.conn, "p1", self.task_id, "owner", "human",
            "Export plan", "Second pass",
            [{"section_id": "shape", "title": "Shape",
              "body": "Include the ledger and cache."}],
            expected_version=1, submit_for_review=True)
        c.task_plan_review(
            self.conn, "p1", self.task_id, "owner", "human",
            expected_version=2, action="approve",
            note="Export fixture plan approved.")
        c.task_claim(
            self.conn, "p1", "director", "agent", self.task_id,
            expected_scope=["project_export.py"])
        c.task_report(
            self.conn, "p1", "director", "agent", self.task_id,
            "Implementation ready", evidence=[
                {"kind": "test", "name": "export QA", "result": "pass"}],
            requested_state="review")

        c.update_handoff(
            self.conn, "p1", "director", "agent",
            {"objective": "Create a portable export"})
        c.update_handoff(
            self.conn, "p1", "director", "agent",
            {"what_changed": "Added deterministic ZIP output"})
        c.update_identity_handoff(
            self.conn, "p1", "director", "agent",
            {"objective": "Direct the portable export"})
        c.update_identity_handoff(
            self.conn, "p1", "worker", "agent",
            {"objective": "Verify the portable export"})
        # Preserve pre-upgrade human-owned exact rows as audit/export history.
        # The operational API no longer creates or selects these rows.
        self.conn.executemany(
            "INSERT INTO identity_handoffs "
            "(project_id,actor_id,version,content,updated_by,updated_owner,"
            "updated_at,event_id,legacy_source_version) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            [
                ("p1", "owner", 1,
                 c.canonical_json({"objective": "Historical human state"}),
                 "owner", "owner", "2026-08-23T00:00:00.000Z", None, None),
                ("p1", "owner", 2,
                 c.canonical_json({"what_changed": "Historical update"}),
                 "owner", "owner", "2026-08-23T01:00:00.000Z", None, None),
            ])
        c.role_scope_set(
            self.conn, "p1", "owner", "human", "director",
            "Directors preserve release and governance context.")
        c.role_scope_set(
            self.conn, "p1", "owner", "human", "director",
            "Directors preserve release, governance, and QA context.",
            expected_version=1)
        c.role_scope_set(
            self.conn, "p1", "owner", "human", "worker",
            "Workers preserve implementation and verification context.")
        decision = c.decision_propose(
            self.conn, "p1", "director", "agent",
            "Keep exact payload JSON", rationale="Preserve ledger hashes")
        c.decision_resolve(
            self.conn, "p1", "owner", "human",
            decision["decision_id"], "accepted")
        c.rule_create(
            self.conn, "p1", "owner", "human", "Two QA passes",
            "Run two independent checks before completion.", priority=1)
        c.room_send(
            self.conn, "p1", "worker", "agent",
            "chat body line one\nchat body line two", msg_type="chat",
            task_id=self.task_id, target_project="p1")
        directive = c.room_send(
            self.conn, "p1", "director", "agent",
            "Durable export directive", msg_type="directive",
            mentions=["worker"], task_id=self.task_id,
            target_project="p1")
        c.message_dispose(
            self.conn, "p1", "worker", "agent",
            directive["event"]["event_id"], "acknowledged")
        c.cloud_context_set(
            self.conn, "p1", "director", "agent",
            "# Durable cloud context\n\nExport this too.")
        c.bridge_add(
            self.conn, "p1", "owner", "human", "peer",
            participation="directors", peer_participation="selected_agents",
            peer_selected_agents=["ghost-peer"])

        now = "2026-08-24T00:00:00.000Z"
        # These rows are project-scoped state but do not have dedicated public
        # mutation helpers, so install them directly as a storage fixture.
        self.conn.execute(
            "INSERT INTO actor_aliases "
            "(project_id, legacy_actor_id, canonical_actor_id, migrated_at) "
            "VALUES (?,?,?,?)",
            ("p1", "legacy.codex", "director", now))
        # Reconciliation baselines are durable project-authored state.  One
        # belongs to an actor that also keeps a read cursor; the other belongs
        # to an actor whose ONLY durable row is the baseline, so no other
        # exported section can stand in for it.
        c.pending_message_dispositions(
            self.conn, "p1", "director", "agent",
            allow_baseline_write=True, baseline_source_seq=1)
        c.pending_message_dispositions(
            self.conn, "p1", "auditor", "agent",
            allow_baseline_write=True, baseline_source_seq=2)
        latest_seq = self.conn.execute(
            "SELECT MAX(seq) AS seq FROM events WHERE project_id='p1'"
        ).fetchone()["seq"]
        self.conn.execute(
            "INSERT INTO inbox_cursors "
            "(project_id, actor_id, last_read_seq, updated_at) VALUES (?,?,?,?)",
            ("p1", "director", latest_seq, now))
        self.conn.execute(
            "INSERT INTO agent_clients "
            "(project_id, agent_id, device_id, device_label, runtime, owner, "
            "client_version, git_branch, git_revision, first_seen_at, "
            "last_seen_at, enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("p1", "director", "device-1", "Workstation", "codex", "owner",
             "0.4.4", "main", "abcdef", now, now, 1))

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def build(self):
        return exporter.build_project_export(
            self.conn, "p1", log_renderer=c.render_log_line)

    def restore(self, project_export):
        """Import the portable rows into a fresh, empty temp database.

        ``project_export.py`` deliberately exposes no general import path --
        only the narrow append-only persona registry restore -- so this helper
        replays the exact exported rows and never invents a domain write.
        """
        conn = c.connect(self.root / "restored.db")
        self.addCleanup(conn.close)
        cloud_context = project_export.get("cloud_context")
        sections = (
            ("projects", [project_export["project"]]),
            ("message_disposition_baselines",
             project_export["message_disposition_baselines"]),
            ("project_cloud_context",
             [cloud_context] if cloud_context is not None else []),
        )
        for table, rows in sections:
            for row in rows:
                columns = sorted(row)
                conn.execute(
                    "INSERT INTO %s (%s) VALUES (%s)" % (
                        table, ",".join(columns),
                        ",".join("?" for _ in columns)),
                    [row[column] for column in columns])
        conn.commit()
        return conn

    def test_complete_export_is_deterministic_and_read_only(self):
        event_count = self.conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE project_id='p1'"
        ).fetchone()["n"]
        first = self.build()
        second = self.build()

        self.assertEqual(first, second)
        self.assertEqual(first["manifest"]["format"], exporter.EXPORT_FORMAT)
        self.assertEqual(first["project"]["project_id"], "p1")
        self.assertTrue(first["ledger"]["verification"]["ok"])
        self.assertEqual(len(first["ledger"]["events"]), event_count)
        self.assertEqual(len(first["full_log"]), event_count)
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE project_id='p1'"
            ).fetchone()["n"],
            event_count,
        )

        for event in first["ledger"]["events"]:
            self.assertIn("payload_json", event)
            self.assertEqual(
                hashlib.sha256(event["payload_json"].encode()).hexdigest(),
                event["payload_hash"],
            )
        self.assertTrue(any(
            "chat body line one\nchat body line two" in line
            for line in first["full_log"]))
        self.assertEqual(
            [message["body"] for message in first["room_messages"]][-2:],
            ["chat body line one\nchat body line two",
             "Durable export directive"],
        )
        task = next(item for item in first["tasks"]
                    if item["task_id"] == self.task_id)
        self.assertEqual(
            [plan["version"] for plan in task["plan_revisions"]], [1, 2])
        self.assertIsInstance(task["plan_revisions"][1]["sections"], list)
        self.assertEqual(
            [(row["version"], row["updated_by"])
             for row in first["handoffs"]],
            [(1, "director"), (2, "director")])
        self.assertEqual(first["legacy_handoffs"], first["handoffs"])
        self.assertEqual(
            first["manifest"]["compatibility"]["handoffs"]["kind"],
            "shared_project_handoff_history")
        self.assertEqual(
            first["manifest"]["compatibility"]["handoffs"]
            ["canonical_section"], "handoffs")
        self.assertEqual(len(first["identity_handoffs"]), 4)
        self.assertEqual(
            [(row["actor_id"], row["version"])
             for row in first["identity_handoffs"]],
            [("director", 1), ("owner", 1), ("owner", 2), ("worker", 1)])
        self.assertEqual(
            first["identity_handoffs"][0]["updated_by"], "director")
        self.assertIsInstance(
            first["identity_handoffs"][0]["content"], dict)
        self.assertEqual(
            [(row["role"], row["version"])
             for row in first["role_scope_revisions"]],
            [("director", 1), ("director", 2), ("worker", 1)])
        self.assertEqual(
            first["manifest"]["counts"]["identity_handoffs"], 4)
        self.assertEqual(first["manifest"]["counts"]["handoffs"], 2)
        self.assertEqual(
            first["manifest"]["counts"]["role_scope_revisions"], 3)
        self.assertEqual(len(first["decisions"]), 1)
        self.assertEqual(len(first["rules"]), 2)
        self.assertEqual(
            {rule["rule_id"] for rule in first["rules"]}, {"R-0", "R-1"})
        self.assertEqual(len(first["agents"]), 2)
        self.assertEqual(first["actor_aliases"][0]["legacy_actor_id"],
                         "legacy.codex")
        self.assertEqual(first["inbox_cursors"][0]["last_read_seq"], latest(
            first["ledger"]["events"]))
        self.assertEqual(first["agent_clients"][0]["device_id"], "device-1")
        self.assertEqual(
            first["message_dispositions"][0]["disposition"],
            "acknowledged")
        self.assertEqual(first["cloud_context"]["version"], 1)
        self.assertIn("Durable cloud context",
                      first["cloud_context"]["content"])
        self.assertEqual(first["bridges"][0]["access_a"]["preset"],
                         "directors")
        self.assertIn("auth_tokens",
                      first["manifest"]["excluded_server_tables"])
        self.assertNotIn("auth_tokens", first)

        # The current verifier continues to accept exports emitted while the
        # same shared table carried the retired-archive compatibility marker.
        older = copy.deepcopy(first)
        older["manifest"]["compatibility"]["handoffs"] = {
            "canonical_section": "legacy_handoffs",
            "kind": "retired_project_global_archive",
            "read_only": True,
        }
        older["manifest"]["compatibility"][
            "agent_persona_reservations"].update({
                "kind": "append_only_workspace_name_registry",
                "import_policy": "insert_or_reject_conflict",
            })
        self.assertTrue(exporter.validate_project_export(older)["ok"])

    def test_json_and_zip_artifacts_are_exact_and_reproducible(self):
        project_export = self.build()
        json_one = exporter.project_export_json_bytes(project_export)
        json_two = exporter.project_export_json_bytes(project_export)
        self.assertEqual(json_one, json_two)
        self.assertEqual(json.loads(json_one), project_export)

        zip_one = exporter.project_export_zip_bytes(project_export)
        zip_two = exporter.project_export_zip_bytes(project_export)
        self.assertEqual(zip_one, zip_two)
        with zipfile.ZipFile(BytesIO(zip_one)) as archive:
            self.assertEqual(archive.namelist(), [
                "manifest.json", "project-export.json", "ledger.ndjson",
                "full-log.txt",
            ])
            self.assertTrue(all(
                info.date_time == (1980, 1, 1, 0, 0, 0)
                for info in archive.infolist()))
            self.assertEqual(
                json.loads(archive.read("project-export.json")), project_export)
            ledger_bytes = archive.read("ledger.ndjson")
            log_bytes = archive.read("full-log.txt")
            artifacts = project_export["manifest"]["artifacts"]
            self.assertEqual(hashlib.sha256(ledger_bytes).hexdigest(),
                             artifacts["ledger.ndjson"]["sha256"])
            self.assertEqual(hashlib.sha256(log_bytes).hexdigest(),
                             artifacts["full-log.txt"]["sha256"])
            records = [json.loads(line) for line in ledger_bytes.splitlines()]
            self.assertEqual(records, project_export["ledger"]["events"])

    def test_ledger_corruption_is_exported_but_marked_and_cache_rejects_it(self):
        first_event = self.conn.execute(
            "SELECT event_id FROM events WHERE project_id='p1' ORDER BY seq LIMIT 1"
        ).fetchone()["event_id"]
        self.conn.execute(
            "UPDATE events SET payload=? WHERE event_id=?",
            ('{"tampered":true}', first_event))
        project_export = self.build()
        self.assertFalse(project_export["ledger"]["verification"]["ok"])
        self.assertTrue(any(
            "tampered" in problem
            for problem in project_export["ledger"]["verification"]["problems"]))
        # Recovery/download remains possible, but a corrupt chain cannot
        # become the trusted baseline for incremental offline sync.
        self.assertTrue(exporter.project_export_zip_bytes(project_export))
        with self.assertRaises(exporter.ProjectExportError):
            exporter.build_offline_cache(project_export)

    def test_offline_cache_persists_and_only_advances_same_chain(self):
        baseline_export = self.build()
        cache = exporter.build_offline_cache(baseline_export)
        original_cursor = exporter.offline_cache_cursor(cache)
        path = self.root / "offline" / "p1.json"
        exporter.save_offline_cache(path, cache)
        loaded = exporter.load_offline_cache(path, expected_project_id="p1")
        self.assertEqual(loaded, cache)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

        c.append_event(
            self.conn, "p1", "director", "agent", "note.after-export",
            {"body": "new durable work"})
        newer_export = self.build()
        advanced = exporter.advance_offline_cache(loaded, newer_export)
        advanced_cursor = exporter.offline_cache_cursor(advanced)
        self.assertGreater(advanced_cursor["event_seq"],
                           original_cursor["event_seq"])
        self.assertEqual(
            newer_export["ledger"]["events"][original_cursor["event_seq"] - 1]["hash"],
            original_cursor["event_hash"],
        )
        with self.assertRaisesRegex(exporter.OfflineCacheError, "backwards"):
            exporter.advance_offline_cache(advanced, baseline_export)

        fork_conn = c.connect(self.root / "fork.db")
        try:
            fork_repo = self.root / "fork"
            fork_repo.mkdir()
            c.project_init(
                fork_conn, "other", "human", path=fork_repo,
                project_id="p1", name="Forked Project One")
            while fork_conn.execute(
                    "SELECT COUNT(*) AS n FROM events WHERE project_id='p1'"
                    ).fetchone()["n"] <= advanced_cursor["event_seq"]:
                c.append_event(
                    fork_conn, "p1", "other", "human", "note.fork",
                    {"branch": "different"})
            fork_export = exporter.build_project_export(fork_conn, "p1")
            with self.assertRaisesRegex(exporter.OfflineCacheError,
                                        "fork detected"):
                exporter.advance_offline_cache(advanced, fork_export)
        finally:
            fork_conn.close()

        modified = copy.deepcopy(advanced)
        modified["baseline"]["project"]["name"] = "Undetected mutation"
        with self.assertRaisesRegex(exporter.OfflineCacheError, "digest"):
            exporter.validate_offline_cache(modified)
        with self.assertRaises(exporter.OfflineCacheError):
            exporter.load_offline_cache(path, expected_project_id="other")

    def test_unknown_project_and_plain_tuple_connections(self):
        with self.assertRaisesRegex(exporter.ProjectExportError,
                                    "unknown project"):
            exporter.build_project_export(self.conn, "missing")
        self.conn.row_factory = None
        project_export = exporter.build_project_export(self.conn, "p1")
        self.assertEqual(project_export["project"]["name"], "Project One")
        self.assertTrue(project_export["ledger"]["verification"]["ok"])

    def test_baselines_and_cloud_context_round_trip_to_fresh_db(self):
        first = self.build()
        second = self.build()
        self.assertEqual(
            exporter.project_export_json_bytes(first),
            exporter.project_export_json_bytes(second))

        baselines = first["message_disposition_baselines"]
        self.assertEqual([row["actor_id"] for row in baselines],
                         ["auditor", "director"])
        self.assertEqual(
            first["manifest"]["counts"]["message_disposition_baselines"],
            len(baselines))
        self.assertEqual(first["manifest"]["counts"]["cloud_context"], 1)
        for row in baselines:
            self.assertEqual(row["project_id"], "p1")
            self.assertEqual(row["source"], "upgrade")
            self.assertIsInstance(row["baseline_seq"], int)
            self.assertEqual(row["set_by"], row["actor_id"])
        self.assertEqual(first["cloud_context"]["project_id"], "p1")
        self.assertEqual(first["cloud_context"]["version"], 1)

        restored = self.restore(first)
        self.assertEqual(
            [dict(row) for row in restored.execute(
                "SELECT * FROM message_disposition_baselines"
                " WHERE project_id='p1' ORDER BY actor_id")],
            baselines)
        self.assertEqual(
            dict(restored.execute(
                "SELECT * FROM project_cloud_context WHERE project_id='p1'"
            ).fetchone()),
            first["cloud_context"])

        # Re-exporting the imported database reproduces both sections exactly.
        again = exporter.build_project_export(restored, "p1")
        self.assertEqual(again["message_disposition_baselines"], baselines)
        self.assertEqual(again["cloud_context"], first["cloud_context"])
        self.assertEqual(
            again["manifest"]["counts"]["message_disposition_baselines"],
            len(baselines))
        self.assertTrue(exporter.validate_project_export(again)["ok"])

    def test_baseline_survives_without_a_cursor_or_disposition_row(self):
        first = self.build()
        lone = next(row for row in first["message_disposition_baselines"]
                    if row["actor_id"] == "auditor")
        self.assertEqual(lone["baseline_seq"], 2)
        # Nothing else in the export mentions this identity, so the baseline
        # cannot be folded into the cursor or disposition sections.
        self.assertNotIn("auditor",
                         [row["actor_id"] for row in first["inbox_cursors"]])
        self.assertNotIn(
            "auditor",
            [row["actor_id"] for row in first["message_dispositions"]])

        # Losing the row would re-baseline the identity from a newer cursor
        # and silently close history that is genuinely still open.
        restored = self.restore(first)
        self.assertEqual(
            restored.execute(
                "SELECT baseline_seq FROM message_disposition_baselines"
                " WHERE project_id='p1' AND actor_id='auditor'"
            ).fetchone()["baseline_seq"],
            2)

    def test_new_sections_are_validated_and_leak_no_server_tables(self):
        first = self.build()
        self.assertIn("message_disposition_baselines", first)
        self.assertNotIn("server_settings", first)
        self.assertEqual(
            [key for key in first if key.startswith("auth_")], [])
        for table in ("auth_sessions", "auth_tokens", "auth_users",
                      "server_settings"):
            self.assertIn(table,
                          first["manifest"]["excluded_server_tables"])

        outside = copy.deepcopy(first)
        outside["message_disposition_baselines"][0]["project_id"] = "peer"
        with self.assertRaisesRegex(exporter.ProjectExportError,
                                    "outside project p1"):
            exporter.validate_project_export(outside)

        negative = copy.deepcopy(first)
        negative["message_disposition_baselines"][0]["baseline_seq"] = -1
        with self.assertRaisesRegex(exporter.ProjectExportError,
                                    "invalid baseline_seq"):
            exporter.validate_project_export(negative)

        miscounted = copy.deepcopy(first)
        miscounted["manifest"]["counts"][
            "message_disposition_baselines"] = 99
        with self.assertRaisesRegex(
                exporter.ProjectExportError,
                "count does not match message_disposition_baselines"):
            exporter.validate_project_export(miscounted)

        stale_cloud_count = copy.deepcopy(first)
        stale_cloud_count["manifest"]["counts"]["cloud_context"] = 0
        with self.assertRaisesRegex(exporter.ProjectExportError,
                                    "count does not match cloud_context"):
            exporter.validate_project_export(stale_cloud_count)

        bad_cloud_version = copy.deepcopy(first)
        bad_cloud_version["cloud_context"]["version"] = 0
        with self.assertRaisesRegex(exporter.ProjectExportError,
                                    "cloud_context has an invalid version"):
            exporter.validate_project_export(bad_cloud_version)

    def test_baseline_rows_join_the_named_identity_coverage_scan(self):
        # A persona that exists only on a baseline row must still be covered
        # by the exported append-only reservation registry.
        self.conn.execute(
            "INSERT INTO message_disposition_baselines"
            " (project_id,actor_id,baseline_seq,source,set_by,set_owner,"
            "note,at) VALUES (?,?,?,?,?,?,?,?)",
            ("p1", "p1.director.codex.hopper", 3, "manual",
             "p1.director.codex.hopper", "owner", None,
             "2026-08-24T00:00:00.000Z"))
        with self.assertRaisesRegex(exporter.ProjectExportError,
                                    "coverage is incomplete.*@Hopper"):
            self.build()


def latest(events):
    return events[-1]["seq"] if events else 0


if __name__ == "__main__":
    unittest.main()
