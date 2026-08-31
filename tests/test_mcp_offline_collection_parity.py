"""MCP/offline paging parity and strict collection selectors.

All state is an in-memory SQLite database or a synthetic verified-projection
shape.  This module never discovers or contacts the configured Attacca host.
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_mcp_offline_collection_parity", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


def stamp(index):
    return "2026-08-31T00:%02d:%02d.000Z" % divmod(index, 60)


class FakeAdapter:
    def __init__(self, projection, pending=None):
        self.projection = projection
        self.pending = list(pending or [])

    def rules_for_role(self, _role):
        return list(self.projection.get("rules") or [])

    def pending_overlays(self, section=None):
        if section:
            return []
        return list(self.pending)

    def status(self):
        return {"mode": "offline", "pending_sync": bool(self.pending),
                "pending_count": len(self.pending), "conflict_count": 0,
                "convergence_awaiting_count": 0}


class McpOfflineCollectionParityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "parity.db"
        self.conn = c.connect(self.db)
        self.addCleanup(self.conn.close)
        checkout = Path(self.temp.name) / "checkout"
        checkout.mkdir()
        c.project_init(self.conn, "fixture", "human", path=checkout,
                       project_id="p", name="Parity")
        self.actor = "p.director.codex.gibbs"
        c.agent_register(
            self.conn, "p", "fixture", "human", agent_id=self.actor,
            role="director", runtime="codex", persona="gibbs")

    def test_mcp_read_schemas_offer_full_page_controls(self):
        tools = {item["name"]: item for item in c.MCP_TOOLS}
        for name in ("bridge_list", "decision_list", "rule_list",
                     "agent_list", "list_projects", "get_project_log",
                     "search"):
            properties = tools[name]["inputSchema"]["properties"]
            query_name = "query" if name == "search" else "q"
            for field in (query_name, "limit", "offset", "sort"):
                self.assertIn(field, properties, (name, field))
        self.assertIn(
            "status", tools["decision_list"]["inputSchema"]["properties"])
        self.assertIn(
            "status", tools["rule_list"]["inputSchema"]["properties"])

    def test_mcp_dispatch_filters_before_bounded_slicing(self):
        for index in range(75):
            at = stamp(index)
            self.conn.execute(
                "INSERT INTO agents"
                " (project_id,agent_id,display_name,role,runtime,owner,"
                " actor_type,registered_at,last_seen_at)"
                " VALUES ('p',?,?, 'worker','legacy','fixture','agent',?,?)",
                ("legacy-%03d" % index,
                 "Parity marker agent %03d" % index, at, at))
            self.conn.execute(
                "INSERT INTO decisions"
                " (project_id,decision_id,title,detail,rationale,status,"
                " proposed_by,created_at) VALUES ('p',?,?,?,?,'accepted',?,?)",
                ("D-%d" % (100 + index),
                 "Parity marker decision %03d" % index,
                 "Complete search body", "bounded", self.actor, at))
            self.conn.execute(
                "INSERT INTO project_rules"
                " (project_id,rule_id,title,body,scope,priority,enabled,"
                " version,created_by,created_at,updated_by,updated_at)"
                " VALUES ('p',?,?,?,'everyone',100,1,1,?,?,?,?)",
                ("R-%d" % (100 + index),
                 "Parity marker rule %03d" % index, "Complete rule body",
                 self.actor, at, self.actor, at))
            peer = "peer-%03d" % index
            self.conn.execute(
                "INSERT INTO projects"
                " (project_id,name,created_by,created_at) VALUES (?,?,?,?)",
                (peer, "Parity marker workspace %03d" % index,
                 self.actor, at))
            self.conn.execute(
                "INSERT INTO bridges"
                " (project_a,project_b,relation,principal,access_a,access_b,"
                " created_by,created_at) VALUES (?,?, 'peer',NULL,?,?,?,?)",
                ("p", peer, '{"preset":"all","agents":[]}',
                 '{"preset":"all","agents":[]}', self.actor, at))
            c.append_event(
                self.conn, "p", self.actor, "agent", "note.pagination",
                {"body": "Log parity marker %03d" % index})

        session = c.McpSession(
            self.db, default_project="p", actor=self.actor,
            actor_type="agent", detect_cwd=False, owner="fixture",
            preserve_actor_identity=True)
        try:
            cases = (
                ("bridge_list", "bridges", {"q": "peer"}),
                ("decision_list", "decisions",
                 {"q": "parity marker", "status": "accepted"}),
                ("rule_list", "rules",
                 {"q": "parity marker", "include_all": True}),
                ("agent_list", "agents", {"q": "parity marker"}),
                ("list_projects", "projects", {"q": "parity marker"}),
                ("get_project_log", "entries", {"q": "log parity marker"}),
            )
            for name, key, extra in cases:
                with self.subTest(name=name):
                    first = session.dispatch_tool(
                        name, dict(extra, limit=999, sort="oldest"))
                    self.assertEqual(first["total"], 75)
                    self.assertEqual(first["limit"], 60)
                    self.assertEqual(len(first[key]), 60)
                    self.assertTrue(first["has_more"])
                    if name == "rule_list":
                        # Exact enabled inventory is computed before the
                        # query/page; the default authority rule also counts.
                        self.assertEqual(first["enabled_total"], 76)
                    second = session.dispatch_tool(
                        name, dict(extra, limit=60, offset=60,
                                   sort="oldest"))
                    self.assertEqual(len(second[key]), 15)
                    self.assertFalse(second["has_more"])
            searched = session.dispatch_tool(
                "search", {"query": "parity marker", "limit": 999})
            self.assertGreater(searched["total"], 60)
            self.assertEqual(len(searched["results"]), 60)
            self.assertTrue(searched["has_more"])
        finally:
            if session.conn is not None:
                session.conn.close()

    def _offline_fixture(self):
        rows = []
        for index in range(75):
            at = stamp(index)
            rows.append({"index": index, "marker": "offline parity marker",
                         "created_at": at, "updated_at": at})
        events = [{
            "event_id": "ev_%03d" % index, "seq": index + 1,
            "project_id": "p", "event_type": "note.parity",
            "created_at": stamp(index), "actor_id": self.actor,
            "actor_type": "agent", "owner": "fixture", "task_id": None,
            "payload": {"body": "offline parity marker %03d" % index},
        } for index in range(75)]
        projection = {
            "project": {"project_id": "p", "name": "Parity",
                        "context_version": 1},
            "bridges": [dict(item, **{"with": "peer-%03d" % item["index"]})
                        for item in rows],
            "tasks": [dict(item, task_id="T-%d" % (item["index"] + 1),
                           title="Offline parity marker task",
                           status="queued") for item in rows],
            "decisions": [dict(item, decision_id="D-%d" %
                               (item["index"] + 1),
                               title="Offline parity marker decision",
                               status="accepted") for item in rows],
            "rules": [dict(item, rule_id="R-%d" % (item["index"] + 1),
                           title="Offline parity marker rule", enabled=True,
                           scope="everyone", priority=100) for item in rows],
            "agents": [dict(item, agent_id="legacy-%03d" % item["index"],
                            display_name="Offline parity marker agent",
                            registered_at=item["created_at"])
                       for item in rows],
            "identity_handoffs": [], "handoffs": [], "role_scopes": [],
            "persona_reservations": [], "task_plans": [],
            "room_messages": [], "message_dispositions": [],
            "inbox_cursor": {"last_read_seq": 0},
            "full_log": [
                "%s actor NOTE log offline parity marker %03d" %
                (stamp(index), index) for index in range(75)],
            "cloud_context": None,
        }
        snapshot = {
            "scope": {"project_id": "p", "principal_id": "fixture",
                      "actor_id": self.actor, "actor_type": "agent",
                      "role": "director"},
            "cursor": {"event_seq": 75, "context_version": 1},
            "projection": projection,
            "records": [{"kind": "event", "seq": event["seq"],
                         "event": event} for event in events],
        }
        proof = {"mirror_stale": False,
                 "mirror_verified_at": "2026-08-31T00:00:00.000Z",
                 "cursor": snapshot["cursor"]}
        return snapshot, FakeAdapter(projection), proof

    def test_offline_collections_and_search_share_hosted_page_contract(self):
        snapshot, adapter, proof = self._offline_fixture()
        session = c.OfflineProxySession(
            "https://offline.invalid", lambda: "p", self.temp.name,
            "codex", "codex", "device-parity")
        for name, key in (("bridge_list", "bridges"),
                          ("task_list", "tasks"),
                          ("decision_list", "decisions"),
                          ("rule_list", "rules"),
                          ("agent_list", "agents"),
                          ("get_project_log", "entries")):
            with self.subTest(name=name):
                page = session._read(
                    name, {"q": "offline parity marker", "limit": 999,
                           "offset": 10, "sort": "oldest"},
                    adapter, snapshot, proof)
                self.assertEqual(page["total"], 75)
                self.assertEqual(page["unfiltered_total"], 75)
                self.assertEqual(page["limit"], 60)
                self.assertEqual(len(page[key]), 60)
                self.assertTrue(page["has_more"])
                if name == "rule_list":
                    self.assertEqual(page["enabled_total"], 75)

        search = session._read(
            "search", {"query": "offline parity marker", "limit": 999,
                       "sort": "newest"}, adapter, snapshot, proof)
        # The four searchable mirrored categories match, but the response is
        # one page rather than four independently capped slices.
        self.assertEqual(search["total_hits"], 300)
        self.assertEqual(search["total"], 300)
        self.assertEqual(search["unfiltered_total"], 300)
        self.assertEqual(len(search["results"]), 60)
        self.assertEqual(sum(len(search[key]) for key in (
            "events", "tasks", "decisions", "rules")),
            sum(1 for item in search["results"]
                if item["kind"] in {"event", "task", "decision", "rule"}))
        self.assertTrue(search["has_more"])

    def test_sort_mentions_and_persona_side_data_fail_or_scope_exactly(self):
        with self.assertRaisesRegex(c.AttaccaError, "newest or oldest"):
            c.task_list(self.conn, "p", limit=5, sort="sideways")
        with self.assertRaisesRegex(c.AttaccaError, "newest or oldest"):
            c.room_history(self.conn, "p", actor_id=self.actor,
                           sort="sideways")
        with self.assertRaisesRegex(c.AttaccaError, "newest or oldest"):
            c.activity_history(self.conn, "p", actor_id=self.actor,
                               sort="sideways")
        with self.assertRaisesRegex(c.AttaccaError, "exact current"):
            c.resolve_room_mentions(
                self.conn, "p", "unknown", mentions=["not-registered"])

        self.conn.execute(
            "INSERT INTO agents"
            " (project_id,agent_id,display_name,role,runtime,owner,"
            " actor_type,registered_at,last_seen_at)"
            " VALUES ('p','legacy-current','Legacy','worker','legacy',"
            " 'fixture','agent',?,?)", (stamp(1), stamp(1)))
        self.assertEqual(
            c.resolve_room_mentions(
                self.conn, "p", "hello", mentions=["legacy-current"]),
            ["legacy-current"])

        ordinary = c.agent_list(self.conn, "p")
        paged = c.agent_list(self.conn, "p", limit=60, sort="newest")
        setup = c.agent_list(self.conn, "p", options=True)
        self.assertNotIn("persona_names_reserved", ordinary)
        self.assertNotIn("persona_names_reserved", paged)
        self.assertIn("persona_names_reserved", setup)

    def test_auth_inventory_helper_caps_and_reports_exact_counts(self):
        rows = [{"token_id": "tok_%03d" % index,
                 "label": "Key %03d" % index,
                 "created_at": stamp(index)} for index in range(75)]
        page = c._auth_collection_page(
            rows, "tokens", {"limit": "999", "offset": "10",
                             "sort": "oldest"})
        self.assertEqual(page["total"], 75)
        self.assertEqual(page["unfiltered_total"], 75)
        self.assertEqual(page["limit"], 60)
        self.assertEqual(page["offset"], 10)
        self.assertEqual(len(page["tokens"]), 60)
        self.assertTrue(page["has_more"])
        with self.assertRaisesRegex(c.AttaccaError, "newest or oldest"):
            c._auth_collection_page(rows, "tokens", {"sort": "sideways"})


if __name__ == "__main__":
    unittest.main()
