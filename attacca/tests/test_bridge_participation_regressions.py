"""Focused regressions for role-scoped bridge-room participation.

This module deliberately exercises the storage/core API plus the two public
custom-event transports.  It is isolated from the older bridge tests so a
privacy regression remains obvious even while compatibility tests evolve.
"""

import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path


os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "attacca.py")

spec = importlib.util.spec_from_file_location(
    "attacca_bridge_participation_regressions", ROOT / "attacca.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class _ServerFixture:
    def __init__(self, db):
        env = dict(os.environ)
        env.pop("ATTACCA_ACTOR", None)
        env.pop("ATTACCA_PROJECT", None)
        env["ATTACCA_DB"] = str(db)
        self.proc = subprocess.Popen(
            [sys.executable, SCRIPT, "serve", "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=env)
        line = self.proc.stdout.readline()
        match = re.search(r"http://127\.0\.0\.1:(\d+)", line)
        assert match, "server did not report its port: %r" % line
        self.base = "http://127.0.0.1:%s" % match.group(1)

    def request(self, method, path, body=None, actor=None,
                actor_type="agent"):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            self.base + path, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if actor:
            request.add_header("X-Attacca-Actor", actor)
        if actor_type:
            request.add_header("X-Attacca-Actor-Type", actor_type)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raw = error.read()
            return error.code, json.loads(raw) if raw else None

    def close(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.proc.stdout.close()
        self.proc.stderr.close()


class _McpClient:
    def __init__(self, db, project, actor):
        env = dict(os.environ)
        env["ATTACCA_DB"] = str(db)
        env["ATTACCA_PROJECT"] = project
        env["ATTACCA_ACTOR"] = actor
        self.proc = subprocess.Popen(
            [sys.executable, SCRIPT, "mcp"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=env)
        self.next_id = 1

    def _request(self, method, params=None):
        request_id = self.next_id
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()
        response = json.loads(self.proc.stdout.readline())
        assert response["id"] == request_id
        return response

    def initialize(self):
        response = self._request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "bridge-privacy-test", "version": "0"},
        })
        self.proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "method": "notifications/initialized",
        }) + "\n")
        self.proc.stdin.flush()
        return response

    def call_tool(self, name, arguments):
        response = self._request(
            "tools/call", {"name": name, "arguments": arguments})
        return response["result"]

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        finally:
            self.proc.stdout.close()
            self.proc.stderr.close()


class BridgeParticipationRegressionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "participation.db"
        self.conn = c.connect(self.db)
        for project in ("alpha", "beta"):
            root = Path(self.tmp.name) / project
            root.mkdir()
            c.project_init(
                self.conn, "setup", "human", path=str(root),
                project_id=project, name=project.title())

        self.actors = {
            "alpha": {
                "director": "alpha.director.codex",
                "advisor": "alpha.advisor.claude",
                "worker": "alpha.worker.cline",
                "selected": "alpha.worker.windsurf",
            },
            "beta": {
                "director": "beta.director.gemini",
                "advisor": "beta.advisor.cursor",
                "worker": "beta.worker.kimi",
                "selected": "beta.worker.glm",
            },
        }
        for project, identities in self.actors.items():
            for role_name, actor_id in identities.items():
                role = role_name if role_name != "selected" else "worker"
                runtime = actor_id.rsplit(".", 1)[-1]
                c.agent_register(
                    self.conn, project, "setup", "human",
                    agent_id=actor_id, role=role, runtime=runtime)
        self.servers = []
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            client.close()
        for server in self.servers:
            server.close()
        self.conn.close()
        self.tmp.cleanup()

    def _bridge(self, participation="all", peer_participation="all",
                selected_agents=None, peer_selected_agents=None):
        return c.bridge_add(
            self.conn, "alpha", "operator", "human", "beta",
            participation=participation,
            peer_participation=peer_participation,
            selected_agents=selected_agents,
            peer_selected_agents=peer_selected_agents)

    def _mirror_seq(self, project, marker):
        rows = self.conn.execute(
            "SELECT seq, payload FROM events WHERE project_id=?"
            " AND event_type='room.message' ORDER BY seq", (project,))
        matches = [row["seq"] for row in rows
                   if marker in json.loads(row["payload"]).get("body", "")]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_legacy_bridge_schema_migrates_both_sides_to_all(self):
        legacy_db = Path(self.tmp.name) / "legacy.db"
        raw = sqlite3.connect(str(legacy_db))
        raw.execute(
            "CREATE TABLE bridges ("
            "project_a TEXT NOT NULL, project_b TEXT NOT NULL,"
            "relation TEXT NOT NULL DEFAULT 'peer', principal TEXT,"
            "created_by TEXT, created_at TEXT NOT NULL,"
            "PRIMARY KEY (project_a, project_b))")
        raw.execute(
            "INSERT INTO bridges VALUES (?,?,?,?,?,?)",
            ("alpha", "beta", "peer", None, "legacy", "2025-01-01Z"))
        raw.commit()
        raw.close()

        migrated = c.connect(legacy_db)
        try:
            for project in ("alpha", "beta"):
                root = Path(self.tmp.name) / ("legacy-" + project)
                root.mkdir()
                c.project_init(
                    migrated, "setup", "human", path=str(root),
                    project_id=project, name=project.title())
            columns = {row["name"]: row for row in migrated.execute(
                "PRAGMA table_info(bridges)")}
            for name in ("access_a", "access_b"):
                self.assertEqual(columns[name]["notnull"], 1)
                self.assertIn('"preset":"all"', columns[name]["dflt_value"])
            row = migrated.execute(
                "SELECT access_a, access_b FROM bridges").fetchone()
            self.assertEqual(json.loads(row["access_a"]),
                             {"preset": "all", "agents": []})
            self.assertEqual(json.loads(row["access_b"]),
                             {"preset": "all", "agents": []})
            alpha = c.bridge_list(migrated, "alpha")["bridges"][0]
            beta = c.bridge_list(migrated, "beta")["bridges"][0]
            self.assertEqual((alpha["participation"],
                              alpha["peer_participation"]), ("all", "all"))
            self.assertEqual((beta["participation"],
                              beta["peer_participation"]), ("all", "all"))
        finally:
            migrated.close()

    def test_all_four_participation_modes_are_asymmetric(self):
        cases = [
            ("all", "directors"),
            ("directors_advisors", "selected_agents"),
            ("directors", "all"),
            ("selected_agents", "directors_advisors"),
        ]

        def selected(project, preset):
            return ([self.actors[project]["selected"]]
                    if preset == "selected_agents" else None)

        def expected(project, preset, actor_name):
            if preset == "all":
                return True
            if preset == "directors_advisors":
                return actor_name in ("director", "advisor")
            if preset == "directors":
                return actor_name == "director"
            return actor_name == "selected"

        for local_mode, peer_mode in cases:
            with self.subTest(local=local_mode, peer=peer_mode):
                self._bridge(
                    local_mode, peer_mode,
                    selected("alpha", local_mode),
                    selected("beta", peer_mode))
                alpha = c.bridge_list(self.conn, "alpha")["bridges"][0]
                beta = c.bridge_list(self.conn, "beta")["bridges"][0]
                self.assertEqual(
                    (alpha["participation"], alpha["peer_participation"]),
                    (local_mode, peer_mode))
                self.assertEqual(
                    (beta["participation"], beta["peer_participation"]),
                    (peer_mode, local_mode))
                self.assertEqual(
                    alpha["allowed_agents"],
                    selected("alpha", local_mode) or [])
                self.assertEqual(
                    beta["allowed_agents"],
                    selected("beta", peer_mode) or [])
                for project, other, preset in (
                        ("alpha", "beta", local_mode),
                        ("beta", "alpha", peer_mode)):
                    for actor_name, actor_id in self.actors[project].items():
                        self.assertEqual(
                            c._bridge_actor_can_participate(
                                self.conn, project, other, actor_id, "agent"),
                            expected(project, preset, actor_name),
                            (project, preset, actor_name))
                    self.assertEqual(
                        c._bridge_actor_can_participate(
                            self.conn, project, other, "unregistered", "agent"),
                        preset == "all")
                    self.assertTrue(c._bridge_actor_can_participate(
                        self.conn, project, other, "operator", "human"))
                c.bridge_remove(
                    self.conn, "alpha", "operator", "human", "beta")

    def test_only_a_local_manager_can_change_each_side(self):
        self._bridge()
        alpha = self.actors["alpha"]
        beta = self.actors["beta"]

        changed = c.bridge_update_access(
            self.conn, "alpha", alpha["director"], "agent", "beta",
            participation="directors")
        self.assertEqual(changed["participation"], "directors")

        for unauthorized in (alpha["advisor"], alpha["worker"],
                             beta["director"]):
            with self.subTest(actor=unauthorized):
                with self.assertRaisesRegex(
                        c.AttaccaError, "human or registered Director"):
                    c.bridge_update_access(
                        self.conn, "alpha", unauthorized, "agent", "beta",
                        participation="all")

        with self.assertRaisesRegex(
                c.AttaccaError, "human or registered Director"):
            c.bridge_update_access(
                self.conn, "alpha", alpha["director"], "agent", "beta",
                peer_participation="directors")

        c.bridge_update_access(
            self.conn, "alpha", "operator", "human", "beta",
            peer_participation="selected_agents",
            peer_selected_agents=[beta["selected"]])
        c.bridge_update_access(
            self.conn, "beta", beta["director"], "agent", "alpha",
            participation="directors_advisors")
        view = c.bridge_list(self.conn, "alpha")["bridges"][0]
        self.assertEqual(view["participation"], "directors")
        self.assertEqual(view["peer_participation"], "directors_advisors")

    def test_selected_agents_are_validated_and_follow_role_migration(self):
        selected = self.actors["alpha"]["selected"]
        invalid = [
            {"participation": "selected_agents"},
            {"participation": "selected_agents",
             "selected_agents": ["alpha.worker.unknown"]},
            {"participation": "all", "selected_agents": [selected]},
            {"participation": "not-a-policy"},
        ]
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                with self.assertRaises(c.AttaccaError):
                    self._bridge(**arguments)

        legacy_id = "alpha.worker.aider"
        c.agent_register(
            self.conn, "alpha", "setup", "human", agent_id=legacy_id,
            role="worker", runtime="aider")
        self._bridge("selected_agents", "all", [legacy_id], None)
        self.assertTrue(c._bridge_actor_can_participate(
            self.conn, "alpha", "beta", legacy_id, "agent"))

        migration = c.agent_register(
            self.conn, "alpha", legacy_id, "agent", role="director",
            runtime="aider", canonical_identity=True)
        canonical_id = "alpha.director.aider"
        self.assertEqual(migration["agent_id"], canonical_id)
        view = c.bridge_list(self.conn, "alpha")["bridges"][0]
        observed = {
            "allowed_agents": view["allowed_agents"],
            "canonical_can_participate": c._bridge_actor_can_participate(
                self.conn, "alpha", "beta", canonical_id, "agent"),
            "legacy_alias_can_participate": c._bridge_actor_can_participate(
                self.conn, "alpha", "beta", legacy_id, "agent"),
        }
        self.assertEqual(observed, {
            "allowed_agents": [canonical_id],
            "canonical_can_participate": True,
            "legacy_alias_can_participate": True,
        })

    def test_explicit_bridge_privacy_covers_every_core_read_surface(self):
        alpha = self.actors["alpha"]
        beta = self.actors["beta"]
        self._bridge("directors", "directors")
        baseline = c.get_project(self.conn, "beta")["context_version"]
        c.update_handoff(
            self.conn, "beta", beta["director"], "agent",
            {"notes": "advance the privacy freshness baseline"},
            expected_context_version=baseline)

        local_marker = "localonlyworkprobe"
        local = c.room_send(
            self.conn, "alpha", alpha["worker"], "agent", local_marker,
            msg_type="status")
        self.assertNotIn("mirrored_to_bridged_projects", local)
        with self.assertRaisesRegex(c.AttaccaError, "not allowed to participate"):
            c.room_send(
                self.conn, "alpha", alpha["worker"], "agent",
                "deniedcrossprojectprobe", target_project="beta")
        with self.assertRaisesRegex(c.AttaccaError, "not allowed to participate"):
            c.room_send(
                self.conn, "beta", beta["worker"], "agent",
                "deniedreverseprobe", target_project="alpha")

        marker = "bridgedirectiveprivacyprobe"
        sent = c.room_send(
            self.conn, "alpha", alpha["director"], "agent", marker,
            msg_type="directive",
            mentions=[beta["director"], beta["worker"]],
            target_project="beta")
        self.assertEqual(sent["mirrored_to_bridged_projects"], ["beta"])

        beta_allowed_room = c.room_read(
            self.conn, "beta", actor_id=beta["director"],
            actor_type="agent")
        beta_denied_room = c.room_read(
            self.conn, "beta", actor_id=beta["worker"],
            actor_type="agent")
        alpha_denied_room = c.room_read(
            self.conn, "alpha", actor_id=alpha["worker"],
            actor_type="agent")
        self.assertIn(marker, json.dumps(beta_allowed_room))
        self.assertNotIn(marker, json.dumps(beta_denied_room))
        self.assertNotIn(marker, json.dumps(alpha_denied_room))
        self.assertIn(local_marker, json.dumps(alpha_denied_room))

        allowed_handoff = c.get_handoff(
            self.conn, "beta", beta["director"], "agent")
        denied_handoff = c.get_handoff(
            self.conn, "beta", beta["worker"], "agent")
        self.assertTrue(allowed_handoff["bridges"][0]["can_participate"])
        self.assertFalse(denied_handoff["bridges"][0]["can_participate"])
        self.assertIn(marker, json.dumps(allowed_handoff["recent_activity"]))
        self.assertNotIn(marker, json.dumps(denied_handoff))

        allowed_inbox = c.inbox_read(
            self.conn, "beta", beta["director"], mark_read=False,
            actor_type="agent")
        denied_inbox = c.inbox_read(
            self.conn, "beta", beta["worker"], mark_read=False,
            actor_type="agent")
        self.assertIn(marker, json.dumps(allowed_inbox))
        self.assertNotIn(marker, json.dumps(denied_inbox))
        self.assertEqual(denied_inbox["unread_broadcasts"], 0)

        allowed_log = c.project_log(
            self.conn, "beta", actor_id=beta["director"],
            actor_type="agent")
        denied_log = c.project_log(
            self.conn, "beta", actor_id=beta["worker"],
            actor_type="agent")
        self.assertIn(marker, json.dumps(allowed_log))
        self.assertNotIn(marker, json.dumps(denied_log))

        allowed_search = c.search_project(
            self.conn, "beta", marker, actor_id=beta["director"],
            actor_type="agent")
        denied_search = c.search_project(
            self.conn, "beta", marker, actor_id=beta["worker"],
            actor_type="agent")
        self.assertIn(marker, json.dumps(allowed_search["events"]))
        self.assertEqual(denied_search["events"], [])
        self.assertEqual(denied_search["total_hits"], 0)

        allowed_freshness = c.check_freshness(
            self.conn, "beta", baseline, actor_id=beta["director"],
            actor_type="agent")
        denied_freshness = c.check_freshness(
            self.conn, "beta", baseline, actor_id=beta["worker"],
            actor_type="agent")
        self.assertTrue(allowed_freshness["stale"])
        self.assertIn(marker, json.dumps(allowed_freshness))
        self.assertNotIn(marker, json.dumps(denied_freshness))
        beta_rows = self.conn.execute(
            "SELECT payload FROM events WHERE project_id='beta'"
            " AND event_type='room.message'").fetchall()
        self.assertFalse(any(local_marker in row["payload"] for row in beta_rows))

    def test_hidden_room_and_inbox_rows_advance_their_cursors(self):
        alpha = self.actors["alpha"]
        beta = self.actors["beta"]
        self._bridge("directors", "directors")
        hidden_marker = "hiddencursorprobe"
        visible_marker = "visiblecursorprobe"
        c.room_send(
            self.conn, "alpha", alpha["director"], "agent", hidden_marker,
            mentions=[beta["worker"]], target_project="beta")
        hidden_seq = self._mirror_seq("beta", hidden_marker)
        c.room_send(
            self.conn, "beta", "operator", "human", visible_marker,
            mentions=[beta["worker"]], target_project="beta")

        first_room = c.room_read(
            self.conn, "beta", since_seq=hidden_seq - 1, limit=1,
            actor_id=beta["worker"], actor_type="agent")
        self.assertEqual(first_room["messages"], [])
        self.assertEqual(first_room["next_since_seq"], hidden_seq)
        second_room = c.room_read(
            self.conn, "beta", since_seq=first_room["next_since_seq"],
            limit=1, actor_id=beta["worker"], actor_type="agent")
        self.assertIn(visible_marker, json.dumps(second_room))

        first_inbox = c.inbox_read(
            self.conn, "beta", beta["worker"], mark_read=True, limit=1,
            actor_type="agent")
        self.assertIn(visible_marker, json.dumps(first_inbox))
        self.assertGreater(first_inbox["read_cursor"], hidden_seq)
        self.assertFalse(first_inbox["may_have_more"])

    def test_initial_room_page_backfills_past_hidden_newer_rows(self):
        alpha = self.actors["alpha"]
        beta = self.actors["beta"]
        self._bridge("directors", "directors")
        visible_marker = "olderlocalvisibleprobe"
        hidden_marker = "newerbridgehiddenprobe"
        c.room_send(
            self.conn, "beta", beta["worker"], "agent", visible_marker)
        c.room_send(
            self.conn, "alpha", alpha["director"], "agent", hidden_marker,
            target_project="beta")

        first_page = c.room_read(
            self.conn, "beta", limit=1, actor_id=beta["worker"],
            actor_type="agent")
        self.assertEqual(
            [message["body"] for message in first_page["messages"]],
            [visible_marker])
        self.assertNotIn(hidden_marker, json.dumps(first_page))

    def test_new_local_marker_prevents_legacy_inference_collision(self):
        alpha = self.actors["alpha"]
        self._bridge("directors", "directors")
        marker = "identicaltargetedandlocalprobe"

        c.room_send(
            self.conn, "alpha", alpha["director"], "agent", marker,
            target_project="beta")
        local = c.room_send(
            self.conn, "alpha", alpha["director"], "agent", marker)
        local_seq = local["event"]["seq"]

        stored = self.conn.execute(
            "SELECT seq,payload FROM events WHERE project_id='alpha'"
            " AND event_type='room.message' ORDER BY seq").fetchall()
        matching = [
            (row["seq"], json.loads(row["payload"])) for row in stored
            if json.loads(row["payload"]).get("body") == marker
        ]
        self.assertEqual(len(matching), 2)
        self.assertEqual(matching[0][1]["mirrored_to"], ["beta"])
        self.assertEqual(matching[1], (
            local_seq,
            {"body": marker, "mirrored_to": [], "msg_type": "chat"},
        ))

        room = c.room_read(
            self.conn, "alpha", actor_id=alpha["worker"],
            actor_type="agent")
        inbox = c.inbox_read(
            self.conn, "alpha", alpha["worker"], mark_read=False,
            actor_type="agent")
        for surface in (room["messages"], inbox["messages"]):
            visible = [message for message in surface
                       if message.get("body") == marker]
            self.assertEqual([message["seq"] for message in visible],
                             [local_seq])
            self.assertEqual(visible[0]["mirrored_to"], [])
            self.assertNotIn("mirrored_to_inferred", visible[0])

    def test_removed_bridge_does_not_declassify_legacy_source_message(self):
        alpha = self.actors["alpha"]
        self._bridge("directors", "directors")
        marker = "removedbridgelegacyprivacyprobe"
        source_payload = {
            "msg_type": "directive", "body": marker,
            "mentions": [], "reply_to": None,
        }
        c.append_event(
            self.conn, "alpha", alpha["director"], "agent",
            "room.message", source_payload)
        c.append_event(
            self.conn, "beta", alpha["director"], "agent",
            "room.message", dict(source_payload, origin_project="alpha"))

        c.bridge_remove(
            self.conn, "alpha", "operator", "human", "beta")
        scope = {
            "project_id": "alpha", "actor_id": alpha["worker"],
            "actor_type": "agent", "role": "worker",
            "principal_id": "owner",
        }
        search = c.search_project(
            self.conn, "alpha", marker, limit=100,
            actor_id=alpha["worker"], actor_type="agent")
        self.assertEqual(search["events"], [])
        self.assertEqual(search["total_hits"], 0)
        surfaces = {
            "room": c.room_read(
                self.conn, "alpha", actor_id=alpha["worker"],
                actor_type="agent"),
            "inbox": c.inbox_read(
                self.conn, "alpha", alpha["worker"], mark_read=False,
                actor_type="agent"),
            "handoff": c.get_handoff(
                self.conn, "alpha", alpha["worker"], "agent"),
            "project_log": c.project_log(
                self.conn, "alpha", limit=100,
                actor_id=alpha["worker"], actor_type="agent"),
            "search_events": search["events"],
            "events_api": c._api_events_sync(
                self.conn, "alpha", after=0, limit=1000,
                actor_id=alpha["worker"], actor_type="agent"),
            "sync_projection": c._sync_projection(self.conn, scope),
        }
        for name, surface in surfaces.items():
            with self.subTest(surface=name):
                self.assertNotIn(marker, json.dumps(surface))

    def test_multi_peer_legacy_routes_hide_denied_destination_metadata(self):
        alpha = self.actors["alpha"]
        gamma_root = Path(self.tmp.name) / "gamma"
        gamma_root.mkdir()
        c.project_init(
            self.conn, "setup", "human", path=str(gamma_root),
            project_id="gamma", name="Gamma")
        c.agent_register(
            self.conn, "gamma", "setup", "human",
            agent_id="gamma.director.codex", role="director",
            runtime="codex")

        self._bridge("all", "all")
        c.bridge_add(
            self.conn, "alpha", "operator", "human", "gamma",
            participation="directors", peer_participation="all")
        marker = "multipeerlegacymetadataprobe"
        source_payload = {
            "msg_type": "directive", "body": marker,
            "mentions": [], "reply_to": None,
        }
        c.append_event(
            self.conn, "alpha", alpha["director"], "agent",
            "room.message", source_payload)
        for peer in ("beta", "gamma"):
            c.append_event(
                self.conn, peer, alpha["director"], "agent",
                "room.message", dict(source_payload, origin_project="alpha"))

        scope = {
            "project_id": "alpha", "actor_id": alpha["worker"],
            "actor_type": "agent", "role": "worker",
            "principal_id": "owner",
        }
        room = c.room_read(
            self.conn, "alpha", actor_id=alpha["worker"],
            actor_type="agent")
        inbox = c.inbox_read(
            self.conn, "alpha", alpha["worker"], mark_read=False,
            actor_type="agent")
        events_api = c._api_events_sync(
            self.conn, "alpha", after=0, limit=1000,
            actor_id=alpha["worker"], actor_type="agent")
        projection = c._sync_projection(self.conn, scope)
        search = c.search_project(
            self.conn, "alpha", marker, limit=100,
            actor_id=alpha["worker"], actor_type="agent")

        routed_views = {
            "room": next(message for message in room["messages"]
                         if message.get("body") == marker),
            "inbox": next(message for message in inbox["messages"]
                          if message.get("body") == marker),
            "events_api": next(
                event["payload"] for event in events_api["events"]
                if event["event_type"] == "room.message"
                and event["payload"].get("body") == marker),
            "sync_projection": next(
                message for message in projection["room_messages"]
                if message.get("body") == marker),
            "search": next(event for event in search["events"]
                           if event.get("body") == marker),
        }
        for name, view in routed_views.items():
            with self.subTest(surface=name):
                self.assertEqual(view["mirrored_to"], ["beta"])
                self.assertNotIn("gamma", json.dumps(view))

    def test_legacy_route_inference_is_batched_across_core_surfaces(self):
        alpha = self.actors["alpha"]
        for index in range(50):
            c.append_event(
                self.conn, "alpha", alpha["director"], "agent",
                "room.message",
                {"msg_type": "directive",
                 "body": "legacybatchprobe%02d" % index})

        def counterpart_query_count(callback):
            statements = []

            def trace(statement):
                compact = " ".join(statement.lower().split())
                if compact.startswith(
                        "select * from events where project_id<>'alpha' "
                        "and event_type='room.message'"):
                    statements.append(compact)

            self.conn.set_trace_callback(trace)
            try:
                callback()
            finally:
                self.conn.set_trace_callback(None)
            return len(statements)

        scope = {
            "project_id": "alpha", "actor_id": alpha["worker"],
            "actor_type": "agent", "role": "worker",
            "principal_id": "owner",
        }
        counts = {
            "room": counterpart_query_count(lambda: c.room_read(
                self.conn, "alpha", limit=100,
                actor_id=alpha["worker"], actor_type="agent")),
            "inbox": counterpart_query_count(lambda: c.inbox_read(
                self.conn, "alpha", alpha["worker"], mark_read=False,
                limit=100, actor_type="agent")),
            "project_log": counterpart_query_count(lambda: c.project_log(
                self.conn, "alpha", limit=100,
                actor_id=alpha["worker"], actor_type="agent")),
            "search": counterpart_query_count(lambda: c.search_project(
                self.conn, "alpha", "legacy batch probe", limit=100,
                actor_id=alpha["worker"], actor_type="agent")),
            "sync_projection": counterpart_query_count(
                lambda: c._sync_projection(self.conn, scope)),
        }
        self.assertEqual(counts, {
            "room": 1,
            "inbox": 1,
            "project_log": 1,
            "search": 1,
            "sync_projection": 1,
        })

    def test_rest_bridge_policies_are_actor_scoped_and_relationship_safe(self):
        alpha = self.actors["alpha"]
        beta = self.actors["beta"]
        server = _ServerFixture(self.db)
        self.servers.append(server)

        status, added = server.request(
            "POST", "/v1/projects/alpha/bridges",
            {"other_project": "beta", "participation": "directors",
             "peer_participation": "selected_agents",
             "peer_selected_agents": [beta["selected"]]},
            actor="operator", actor_type="human")
        self.assertEqual(status, 200)
        self.assertEqual(
            (added["participation"], added["peer_participation"]),
            ("directors", "selected_agents"))
        self.assertIsInstance(added["context_version"], int)

        status, allowed = server.request(
            "GET", "/v1/projects/alpha/bridges",
            actor=alpha["director"])
        self.assertEqual(status, 200)
        self.assertTrue(allowed["bridges"][0]["can_participate"])
        _, denied = server.request(
            "GET", "/v1/projects/alpha/bridges", actor=alpha["worker"])
        self.assertFalse(denied["bridges"][0]["can_participate"])

        denied_status, denied_update = server.request(
            "PUT", "/v1/projects/alpha/bridges/beta",
            {"participation": "all"}, actor=alpha["worker"])
        self.assertEqual(denied_status, 400)
        self.assertIn("human or registered Director",
                      denied_update["error"])

        status, updated = server.request(
            "PUT", "/v1/projects/alpha/bridges/beta",
            {"participation": "selected_agents",
             "selected_agents": [alpha["selected"]],
             "peer_participation": "directors_advisors"},
            actor="operator", actor_type="human")
        self.assertEqual(status, 200)
        self.assertEqual(updated["allowed_agents"], [alpha["selected"]])
        self.assertEqual(updated["peer_participation"],
                         "directors_advisors")

        status, relation = server.request(
            "PUT", "/v1/projects/alpha/bridges/beta",
            {"relationship": "master", "principal": "beta"},
            actor=alpha["director"])
        self.assertEqual(status, 200)
        self.assertEqual((relation["relation"], relation["principal"]),
                         ("master", "beta"))
        self.assertEqual(relation["participation"], "selected_agents")
        self.assertEqual(relation["allowed_agents"], [alpha["selected"]])
        self.assertEqual(relation["peer_participation"],
                         "directors_advisors")

    def test_guided_relationship_change_preserves_both_access_policies(self):
        alpha = self.actors["alpha"]
        beta = self.actors["beta"]
        self._bridge(
            "selected_agents", "directors_advisors",
            [alpha["selected"]], None)
        server = _ServerFixture(self.db)
        self.servers.append(server)

        result = c.apply_remote_network_setup(
            server.base, "alpha", alpha["director"], "agent",
            role="keep", lead="keep", bridge="beta",
            relationship="advisor", principal_side="other")
        action = result["actions"][-1]
        self.assertEqual(action["relationship"], "advisor")
        self.assertFalse(action["unchanged"])
        view = c.bridge_list(self.conn, "alpha")["bridges"][0]
        self.assertEqual((view["relation"], view["principal"]),
                         ("advisor", "beta"))
        self.assertEqual(view["participation"], "selected_agents")
        self.assertEqual(view["allowed_agents"], [alpha["selected"]])
        self.assertEqual(view["peer_participation"],
                         "directors_advisors")

    def test_mcp_bridge_mutations_honor_policies_and_drift_guard(self):
        alpha = self.actors["alpha"]
        client = _McpClient(self.db, "alpha", alpha["director"])
        self.clients.append(client)
        client.initialize()
        brief = client.call_tool("get_handoff", {"project": "alpha"})
        self.assertFalse(brief.get("isError"))

        added_result = client.call_tool("bridge_add", {
            "project": "alpha", "other_project": "beta",
            "participation": "directors",
        })
        self.assertFalse(added_result.get("isError"))
        added = json.loads(added_result["content"][0]["text"])
        self.assertEqual(added["participation"], "directors")
        self.assertIsInstance(added["context_version"], int)

        updated_result = client.call_tool("bridge_update_access", {
            "project": "alpha", "other_project": "beta",
            "participation": "selected_agents",
            "selected_agents": [alpha["selected"]],
        })
        self.assertFalse(updated_result.get("isError"))
        updated = json.loads(updated_result["content"][0]["text"])
        self.assertEqual(updated["allowed_agents"], [alpha["selected"]])
        self.assertNotIn("stale_context_warning", updated)

        advisor = _McpClient(
            self.db, "alpha", self.actors["alpha"]["advisor"])
        self.clients.append(advisor)
        advisor.initialize()
        denied = advisor.call_tool("bridge_update_access", {
            "project": "alpha", "other_project": "beta",
            "participation": "all",
        })
        self.assertTrue(denied.get("isError"))
        self.assertIn("human or registered Director",
                      denied["content"][0]["text"])

    def test_sync_events_are_private_progress_and_room_events_are_guarded(self):
        alpha = self.actors["alpha"]
        beta = self.actors["beta"]
        self._bridge("directors", "directors")
        marker = "eventfeedprivacyprobe"
        c.room_send(
            self.conn, "alpha", alpha["director"], "agent", marker,
            target_project="beta")
        hidden_seq = self._mirror_seq("beta", marker)
        visible = c.append_event(
            self.conn, "beta", beta["worker"], "agent",
            "qa.visible", {"body": "visibleafterhidden"})
        visible_seq = visible["seq"]

        server = _ServerFixture(self.db)
        self.servers.append(server)
        allowed_status, allowed = server.request(
            "GET", "/v1/projects/beta/events?after=%d&limit=1" %
            (hidden_seq - 1), actor=beta["director"])
        denied_status, denied = server.request(
            "GET", "/v1/projects/beta/events?after=%d&limit=1" %
            (hidden_seq - 1), actor=beta["worker"])
        self.assertEqual((allowed_status, denied_status), (200, 200))
        self.assertIn(marker, json.dumps(allowed["events"]))
        self.assertEqual(denied["events"], [])
        self.assertEqual(denied["next_after"], hidden_seq)

        next_status, next_page = server.request(
            "GET", "/v1/projects/beta/events?after=%d&limit=1" % hidden_seq,
            actor=beta["worker"])
        self.assertEqual(next_status, 200)
        self.assertEqual(next_page["events"][0]["seq"], visible_seq)
        self.assertIn("visibleafterhidden", json.dumps(next_page))

        before = self.conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE project_id='beta'"
            " AND event_type='room.message'").fetchone()["n"]
        rest_status, rest_error = server.request(
            "POST", "/v1/projects/beta/events",
            {"event_type": "room.message",
             "payload": {"body": "forged-rest-room-message"}},
            actor=beta["worker"])
        self.assertEqual(rest_status, 400)
        self.assertIn("room_send", json.dumps(rest_error))

        client = _McpClient(self.db, "beta", beta["worker"])
        self.clients.append(client)
        client.initialize()
        mcp_result = client.call_tool("append_event", {
            "project": "beta", "event_type": "room.message",
            "payload": {"body": "forged-mcp-room-message"},
        })
        self.assertTrue(mcp_result["isError"])
        self.assertIn("room_send", mcp_result["content"][0]["text"])
        after = self.conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE project_id='beta'"
            " AND event_type='room.message'").fetchone()["n"]
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
