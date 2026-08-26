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
            expected_scope=["attacca/**"], dependencies=[],
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
            expected_scope=["attacca/project_export.py"])
        c.task_report(
            self.conn, "p1", "director", "agent", self.task_id,
            "Implementation ready", evidence=[
                {"kind": "test", "name": "export QA", "result": "pass"}],
            requested_state="review")

        c.update_handoff(
            self.conn, "p1", "owner", "human",
            {"objective": "Create a portable export"})
        c.update_handoff(
            self.conn, "p1", "owner", "human",
            {"what_changed": "Added deterministic ZIP output"})
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
        c.room_send(
            self.conn, "p1", "director", "agent",
            "Durable export directive", msg_type="directive",
            mentions=["worker"], task_id=self.task_id,
            target_project="p1")
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
        self.assertEqual(len(first["handoffs"]), 2)
        self.assertEqual(len(first["decisions"]), 1)
        self.assertEqual(len(first["rules"]), 1)
        self.assertEqual(len(first["agents"]), 2)
        self.assertEqual(first["actor_aliases"][0]["legacy_actor_id"],
                         "legacy.codex")
        self.assertEqual(first["inbox_cursors"][0]["last_read_seq"], latest(
            first["ledger"]["events"]))
        self.assertEqual(first["agent_clients"][0]["device_id"], "device-1")
        self.assertEqual(first["bridges"][0]["access_a"]["preset"],
                         "directors")
        self.assertIn("auth_tokens",
                      first["manifest"]["excluded_server_tables"])
        self.assertNotIn("auth_tokens", first)

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


def latest(events):
    return events[-1]["seq"] if events else 0


if __name__ == "__main__":
    unittest.main()
