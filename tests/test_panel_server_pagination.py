"""Server-backed pagination contracts for every Control Panel collection.

The fixture is deliberately large (137 rows per long collection), but fully
isolated: one temporary SQLite database and one loopback server on port 0.  It
never discovers or contacts a configured Attacca host, reads machine
credentials, starts a watcher, or writes outside the temporary directory.
"""

from __future__ import annotations

import datetime as dt
import http.client
import http.cookies
import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "attacca_panel_server_pagination_core", ROOT / "attacca.py")
core = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(core)


PAGE_SIZE = 60
ROW_COUNT = 137
DIRECTOR = "hub.director.codex.red"
WORKER = "hub.worker.codex.blue"
MAIL_RECIPIENT = "mailbox.worker.codex.red"


def stamp(index: int) -> str:
    value = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(
        seconds=index
    )
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def terms_match(value: object, query: str) -> bool:
    haystack = json.dumps(value, sort_keys=True).casefold()
    return all(term in haystack for term in query.casefold().split())


class PanelServerPaginationContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.temp.name) / "panel-pagination.db"
        conn = core.connect(cls.db)
        try:
            cls._seed_projects(conn)
            cls._seed_auth(conn)
            cls._seed_agents(conn)
            cls._seed_collections(conn)
            cls._seed_hub_events(conn)
            cls._seed_mailbox(conn)
        finally:
            conn.close()

        cls.server = core.AttaccaServer(
            ("127.0.0.1", 0), cls.db, auth_mode="compatibility"
        )
        cls.thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True
        )
        cls.thread.start()
        cls.host, cls.port = cls.server.server_address
        cls.viewer_session = cls._login("viewer", "viewer-password")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        if cls.thread.is_alive():
            raise AssertionError("isolated pagination server did not stop")
        cls.temp.cleanup()

    @classmethod
    def _seed_projects(cls, conn) -> None:
        cls.peer_rows = []
        base = [
            ("hub", "Hub", stamp(-20)),
            ("mailbox", "Mailbox", stamp(-19)),
            ("mail-hidden", "Mail Hidden", stamp(-18)),
            ("hidden-peer", "Hidden Peer", stamp(-17)),
        ]
        for project_id, name, created_at in base:
            conn.execute(
                "INSERT INTO projects"
                " (project_id,name,root_path,repository_fingerprint,created_by,"
                " created_at,context_version,lead_director)"
                " VALUES (?,?,NULL,NULL,'fixture',?,1,NULL)",
                (project_id, name, created_at),
            )
        conn.execute(
            "UPDATE projects SET repository_fingerprint=?, lead_director=?"
            " WHERE project_id='hub'",
            ("fixture-hub-fingerprint", DIRECTOR),
        )
        for index in range(ROW_COUNT):
            marker = "cobalt" if index % 7 == 0 else "plain"
            project_id = "space-%s-%03d" % (marker, index)
            row = {
                "project_id": project_id,
                "name": "Workspace %s %03d" % (marker.title(), index),
                "created_at": stamp(index),
            }
            cls.peer_rows.append(row)
            conn.execute(
                "INSERT INTO projects"
                " (project_id,name,root_path,repository_fingerprint,created_by,"
                " created_at,context_version,lead_director)"
                " VALUES (?,?,NULL,NULL,'fixture',?,1,NULL)",
                (row["project_id"], row["name"], row["created_at"]),
            )

    @classmethod
    def _seed_auth(cls, conn) -> None:
        core.auth_create_user(
            conn, "owner", "owner-password", is_admin=True, bootstrap=True
        )
        core.auth_create_user(conn, "viewer", "viewer-password")
        owner_row = conn.execute(
            "SELECT * FROM auth_users WHERE username='owner'"
        ).fetchone()
        viewer_row = conn.execute(
            "SELECT * FROM auth_users WHERE username='viewer'"
        ).fetchone()
        cls.owner_principal = core._auth_principal(
            conn, owner_row, "session", session_hash="fixture-owner"
        )
        cls.viewer_principal = core._auth_principal(
            conn, viewer_row, "session", session_hash="fixture-viewer"
        )

        cls.authorized_project_ids = ["hub", "mailbox"] + [
            row["project_id"] for row in cls.peer_rows[:125]
        ]
        for project_id in cls.authorized_project_ids:
            core.auth_grant_project_membership(
                conn, cls.viewer_principal, project_id, granted_by="owner"
            )

        cls.viewer_key_rows = []
        for index in range(ROW_COUNT):
            marker = "cobalt" if index % 7 == 0 else "plain"
            created = core.auth_client_key_create(
                conn,
                cls.viewer_principal,
                "Client %s %03d" % (marker.title(), index),
                "viewer-client-%03d" % index,
            )
            token_id = created["record"]["token_id"]
            conn.execute(
                "UPDATE auth_tokens SET created_at=? WHERE token_id=?",
                (stamp(index), token_id),
            )
            cls.viewer_key_rows.append(
                {
                    "token_id": token_id,
                    "label": "Client %s %03d" % (marker.title(), index),
                    "created_at": stamp(index),
                    "revoked": index % 2 == 0,
                }
            )
            if index % 2 == 0:
                conn.execute(
                    "UPDATE auth_tokens SET revoked_at=? WHERE token_id=?",
                    (stamp(1000 + index), token_id),
                )
        for index in range(11):
            core.auth_client_key_create(
                conn,
                cls.owner_principal,
                "Owner private key %03d" % index,
                "owner-client-%03d" % index,
            )

    @classmethod
    def _seed_agents(cls, conn) -> None:
        cls.agent_rows = []
        for index in range(ROW_COUNT):
            if index == 0:
                actor_id, role, runtime = DIRECTOR, "director", "codex"
            elif index == 1:
                actor_id, role, runtime = WORKER, "worker", "codex"
            else:
                actor_id = "hub.worker.bot%03d.%s" % (
                    index,
                    "cobalt" if index % 7 == 0 else "plain",
                )
                role, runtime = "worker", "bot%03d" % index
            # The request actor's last_seen_at is legitimately touched by the
            # HTTP request itself. Keep that mutable actor out of the dated
            # sort fixture so the expected order tests server paging rather
            # than session-presence bookkeeping.
            marker = "Cobalt" if index > 1 and index % 7 == 0 else "Plain"
            row = {
                "agent_id": actor_id,
                "display_name": "Agent %s %03d" % (marker, index),
                "role": role,
                "runtime": runtime,
                "registered_at": stamp(index),
            }
            cls.agent_rows.append(row)
            conn.execute(
                "INSERT INTO agents"
                " (project_id,agent_id,display_name,role,runtime,owner,"
                " actor_type,registered_at,last_seen_at)"
                " VALUES ('hub',?,?,?,?,NULL,'agent',?,?)",
                (
                    row["agent_id"],
                    row["display_name"],
                    row["role"],
                    row["runtime"],
                    row["registered_at"],
                    row["registered_at"],
                ),
            )
        for project_id, actor_id, role in (
            ("mailbox", MAIL_RECIPIENT, "worker"),
            ("mailbox", "mailbox.director.allowed", "director"),
            ("mailbox", "mailbox.worker.sender", "worker"),
        ):
            conn.execute(
                "INSERT INTO agents"
                " (project_id,agent_id,display_name,role,runtime,owner,"
                " actor_type,registered_at,last_seen_at)"
                " VALUES (?,?,?,?,?,'owner','agent',?,?)",
                (
                    project_id,
                    actor_id,
                    actor_id,
                    role,
                    actor_id.rsplit(".", 1)[-1],
                    stamp(-10),
                    stamp(-10),
                ),
            )

    @classmethod
    def _seed_collections(cls, conn) -> None:
        cls.task_rows = []
        cls.decision_rows = []
        cls.rule_rows = []
        cls.handoff_rows = []
        for index in range(ROW_COUNT):
            marker = "cobalt" if index % 7 == 0 else "plain"
            task = {
                "task_id": "T-%d" % (index + 1),
                "title": "Task %s %03d" % (marker.title(), index),
                "description": "unified amber record %03d" % index,
                "status": "done" if index % 2 == 0 else "queued",
                "updated_at": stamp(index),
            }
            cls.task_rows.append(task)
            conn.execute(
                "INSERT INTO tasks"
                " (project_id,task_id,title,description,status,risk_level,"
                " expected_scope,dependencies,plan_required,created_by,"
                " created_at,updated_at)"
                " VALUES ('hub',?,?,?,?, 'medium','[]','[]',0,'fixture',?,?)",
                (
                    task["task_id"],
                    task["title"],
                    task["description"],
                    task["status"],
                    task["updated_at"],
                    task["updated_at"],
                ),
            )

            decision = {
                "decision_id": "D-%d" % (index + 1),
                "title": "Decision %s %03d" % (marker.title(), index),
                "status": "accepted" if index % 2 == 0 else "proposed",
                "updated_at": stamp(index),
            }
            cls.decision_rows.append(decision)
            conn.execute(
                "INSERT INTO decisions"
                " (project_id,decision_id,title,detail,rationale,status,"
                " proposed_by,resolved_by,created_at,resolved_at)"
                " VALUES ('hub',?,?,?,NULL,?,'fixture',?,?,?)",
                (
                    decision["decision_id"],
                    decision["title"],
                    "Decision detail %s" % marker,
                    decision["status"],
                    "fixture" if decision["status"] != "proposed" else None,
                    decision["updated_at"],
                    decision["updated_at"]
                    if decision["status"] != "proposed"
                    else None,
                ),
            )

            rule = {
                "rule_id": "R-%d" % (index + 1),
                "title": "Rule %s %03d" % (marker.title(), index),
                "enabled": index % 2 == 1,
                "updated_at": stamp(index),
            }
            cls.rule_rows.append(rule)
            conn.execute(
                "INSERT INTO project_rules"
                " (project_id,rule_id,title,body,scope,priority,enabled,version,"
                " created_by,created_owner,created_at,updated_by,updated_owner,"
                " updated_at) VALUES ('hub',?,?,?,'everyone',?, ?,1,'fixture',"
                " 'owner',?,'fixture','owner',?)",
                (
                    rule["rule_id"],
                    rule["title"],
                    "Rule body %s" % marker,
                    index,
                    int(rule["enabled"]),
                    rule["updated_at"],
                    rule["updated_at"],
                ),
            )

            handoff = {
                "version": index + 1,
                "content": {
                    "objective": "Handoff %s %03d" % (marker.title(), index)
                },
                "updated_at": stamp(index),
            }
            cls.handoff_rows.append(handoff)
            conn.execute(
                "INSERT INTO identity_handoffs"
                " (project_id,actor_id,version,content,updated_by,updated_owner,"
                " updated_at,event_id,legacy_source_version)"
                " VALUES ('hub',?,?,?,?, 'owner',?,NULL,NULL)",
                (
                    DIRECTOR,
                    handoff["version"],
                    json.dumps(handoff["content"]),
                    DIRECTOR,
                    handoff["updated_at"],
                ),
            )

        cls.bridge_rows = []
        for index, project in enumerate(cls.peer_rows):
            row = {
                "with": project["project_id"],
                "relation": "advisor" if index % 2 == 0 else "peer",
                "created_at": stamp(index),
            }
            cls.bridge_rows.append(row)
            cls._insert_bridge(conn, "hub", row["with"], row["created_at"])
        cls._insert_bridge(
            conn,
            "hub",
            "hidden-peer",
            stamp(1000),
            hub_access={"preset": "directors", "agents": []},
        )

    @classmethod
    def _insert_bridge(
        cls, conn, left, right, created_at, hub_access=None, mailbox_access=None
    ) -> None:
        project_a, project_b = sorted((left, right))
        access_left = hub_access or mailbox_access or {
            "preset": "all",
            "agents": [],
        }
        access_right = {"preset": "all", "agents": []}
        access_a = access_left if project_a == left else access_right
        access_b = access_right if project_b == right else access_left
        conn.execute(
            "INSERT INTO bridges"
            " (project_a,project_b,relation,principal,access_a,access_b,"
            " created_by,created_at) VALUES (?,?,'peer',NULL,?,?,?,?)",
            (
                project_a,
                project_b,
                json.dumps(access_a, sort_keys=True),
                json.dumps(access_b, sort_keys=True),
                "fixture",
                created_at,
            ),
        )

    @classmethod
    def _seed_hub_events(cls, conn) -> None:
        cls.local_room_sequences = []
        cls.audit_sequences = []
        cls.hidden_room_sequences = []
        for index in range(ROW_COUNT):
            marker = "cobalt" if index % 7 == 0 else "plain"
            event = core.append_event(
                conn,
                "hub",
                "hub.worker.sender",
                "agent",
                "room.message",
                {
                    "msg_type": "chat",
                    "body": "Room %s %03d" % (marker.title(), index),
                    "mentions": [],
                    "reply_to": None,
                    "origin_project": None,
                    "mirrored_to": [],
                },
            )
            cls.local_room_sequences.append(event["seq"])
        for index in range(70):
            event = core.append_event(
                conn,
                "hub",
                "hidden-peer.worker.sender",
                "agent",
                "room.message",
                {
                    "msg_type": "chat",
                    "body": "Secret bridge traffic %03d" % index,
                    "mentions": [],
                    "reply_to": None,
                    "origin_project": "hidden-peer",
                    "mirrored_to": [],
                },
            )
            cls.hidden_room_sequences.append(event["seq"])
        for index in range(ROW_COUNT):
            marker = "cobalt" if index % 7 == 0 else "plain"
            event = core.append_event(
                conn,
                "hub",
                DIRECTOR,
                "agent",
                "audit.record",
                {"body": "Audit %s %03d" % (marker.title(), index)},
            )
            cls.audit_sequences.append(event["seq"])

    @classmethod
    def _seed_mailbox(cls, conn) -> None:
        cls._insert_bridge(
            conn,
            "mailbox",
            "mail-hidden",
            stamp(2000),
            mailbox_access={"preset": "directors", "agents": []},
        )
        for index in range(ROW_COUNT):
            core.append_event(
                conn,
                "mailbox",
                "mailbox.worker.sender",
                "agent",
                "room.message",
                {
                    "msg_type": "chat",
                    "body": "Inbox visible %03d" % index,
                    "mentions": [],
                    "reply_to": None,
                    "origin_project": None,
                    "mirrored_to": [],
                },
            )
        for index in range(23):
            core.append_event(
                conn,
                "mailbox",
                MAIL_RECIPIENT,
                "agent",
                "room.message",
                {
                    "msg_type": "chat",
                    "body": "Recipient self message %03d" % index,
                    "mentions": [],
                    "reply_to": None,
                    "origin_project": None,
                    "mirrored_to": [],
                },
            )
        for index in range(71):
            core.append_event(
                conn,
                "mailbox",
                "mail-hidden.worker.sender",
                "agent",
                "room.message",
                {
                    "msg_type": "chat",
                    "body": "Inbox hidden %03d" % index,
                    "mentions": [],
                    "reply_to": None,
                    "origin_project": "mail-hidden",
                    "mirrored_to": [],
                },
            )

    @classmethod
    def request(cls, method, path, headers=None):
        connection = http.client.HTTPConnection(cls.host, cls.port, timeout=10)
        connection.request(
            method, path, headers={"Accept": "application/json", **(headers or {})}
        )
        response = connection.getresponse()
        raw = response.read()
        body = json.loads(raw) if raw else {}
        result = {"status": response.status, "body": body, "headers": response.headers}
        connection.close()
        return result

    @classmethod
    def _login(cls, username, password):
        connection = http.client.HTTPConnection(cls.host, cls.port, timeout=10)
        payload = json.dumps({"username": username, "password": password})
        connection.request(
            "POST",
            "/v1/auth/login",
            body=payload,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        body = json.loads(response.read())
        if response.status != 200:
            raise AssertionError("isolated login failed: %r" % body)
        cookies = {}
        for line in response.headers.get_all("Set-Cookie") or []:
            parsed = http.cookies.SimpleCookie()
            parsed.load(line)
            cookies.update({name: morsel.value for name, morsel in parsed.items()})
        connection.close()
        return {
            "Cookie": "; ".join("%s=%s" % item for item in cookies.items()),
            "X-Attacca-CSRF": cookies["attacca_csrf"],
        }

    @staticmethod
    def actor_headers(actor=DIRECTOR):
        return {
            "X-Attacca-Actor": actor,
            "X-Attacca-Actor-Type": "agent",
        }

    def get_json(self, path, headers=None):
        response = self.request("GET", path, headers=headers)
        self.assertEqual(response["status"], 200, response["body"])
        return response["body"]

    def assert_page(
        self,
        body,
        key,
        *,
        total,
        unfiltered,
        limit,
        offset,
        has_more,
    ):
        self.assertIn(key, body)
        self.assertLessEqual(len(body[key]), PAGE_SIZE)
        self.assertEqual(body["total"], total)
        self.assertEqual(body["unfiltered_total"], unfiltered)
        self.assertEqual(body["limit"], limit)
        self.assertEqual(body["offset"], offset)
        self.assertIs(body["has_more"], has_more)

    def test_projects_filter_sort_paging_options_and_authorization_counts(self):
        body = self.get_json(
            "/v1/projects?limit=999&offset=0&sort=newest",
            self.viewer_session,
        )
        self.assert_page(
            body,
            "projects",
            total=len(self.authorized_project_ids),
            unfiltered=len(self.authorized_project_ids),
            limit=PAGE_SIZE,
            offset=0,
            has_more=True,
        )
        self.assertEqual(
            [row["project_id"] for row in body["projects"][:3]],
            [row["project_id"] for row in reversed(self.peer_rows[:125])][:3],
        )

        matches = [
            row
            for row in self.peer_rows[:125]
            if terms_match(row, "workspace cobalt")
        ]
        filtered = self.get_json(
            "/v1/projects?q=workspace+cobalt&limit=11&offset=3&sort=oldest",
            self.viewer_session,
        )
        self.assert_page(
            filtered,
            "projects",
            total=len(matches),
            unfiltered=len(self.authorized_project_ids),
            limit=11,
            offset=3,
            has_more=3 + len(filtered["projects"]) < len(matches),
        )
        self.assertEqual(
            [row["project_id"] for row in filtered["projects"]],
            [row["project_id"] for row in matches[3:14]],
        )

        options = self.get_json("/v1/projects?options=1", self.viewer_session)
        self.assertEqual(len(options["projects"]), len(self.authorized_project_ids))
        for item in options["projects"]:
            self.assertTrue({
                "project_id", "name", "repository_fingerprint",
                "lead_director",
            }.issubset(item))
            self.assertFalse(
                {"root_path", "events", "open_tasks"}.intersection(item))
        hub = next(item for item in options["projects"]
                   if item["project_id"] == "hub")
        self.assertEqual(
            hub["repository_fingerprint"], "fixture-hub-fingerprint")
        self.assertEqual(hub["lead_director"], DIRECTOR)

    def test_invalid_collection_sorts_are_client_errors_not_newest_fallbacks(self):
        cases = (
            ("/v1/projects?sort=sideways", self.viewer_session),
            ("/v1/projects/hub/tasks?sort=sideways", self.actor_headers()),
            ("/v1/projects/hub/room/history?sort=sideways",
             self.actor_headers()),
            ("/v1/projects/hub/activity?sort=sideways",
             self.actor_headers()),
            ("/v1/projects/hub/decisions?sort=sideways",
             self.actor_headers()),
            ("/v1/projects/hub/agents?sort=sideways",
             self.actor_headers()),
        )
        for path, headers in cases:
            with self.subTest(path=path):
                response = self.request("GET", path, headers=headers)
                self.assertEqual(response["status"], 400, response["body"])
                self.assertIn("newest or oldest", response["body"]["error"])

    def test_setup_discovery_uses_complete_option_directories_past_sixty(self):
        checkout = Path(self.temp.name) / "setup-directory-checkout"
        home = Path(self.temp.name) / "setup-directory-home"
        checkout.mkdir(exist_ok=True)
        home.mkdir(exist_ok=True)
        discovered = core.discover_remote_setup(
            "http://%s:%s" % (self.host, self.port), path=checkout,
            here=True, actor_id=DIRECTOR, actor_type="agent",
            selected_project_id="hub", home=home)
        self.assertEqual(discovered["network"]["workspace_id"], "hub")
        self.assertEqual(discovered["network"]["lead_director"], DIRECTOR)
        self.assertEqual(
            len(discovered["workspaces"]), ROW_COUNT + 4)
        self.assertIn(
            "space-cobalt-000",
            {row["project_id"] for row in discovered["workspaces"]})

    def test_handoff_history_filters_and_sorts_before_offset(self):
        query = "handoff cobalt"
        matches = [row for row in self.handoff_rows if terms_match(row, query)]
        body = self.get_json(
            "/v1/projects/hub/handoff/history?target_actor_id=%s&q=%s"
            "&limit=9&offset=4&sort=oldest"
            % (urllib.parse.quote(DIRECTOR), urllib.parse.quote_plus(query)),
            self.actor_headers(),
        )
        self.assert_page(
            body,
            "versions",
            total=len(matches),
            unfiltered=ROW_COUNT,
            limit=9,
            offset=4,
            has_more=4 + len(body["versions"]) < len(matches),
        )
        self.assertEqual(
            [row["version"] for row in body["versions"]],
            [row["version"] for row in matches[4:13]],
        )
        capped = self.get_json(
            "/v1/projects/hub/handoff/history?target_actor_id=%s&limit=999"
            % urllib.parse.quote(DIRECTOR),
            self.actor_headers(),
        )
        self.assertEqual(capped["limit"], PAGE_SIZE)
        self.assertEqual(len(capped["versions"]), PAGE_SIZE)

    def test_bridges_filter_sort_paging_and_complete_options(self):
        query = "space cobalt"
        matches = [row for row in self.bridge_rows if terms_match(row, query)]
        body = self.get_json(
            "/v1/projects/hub/bridges?q=%s&limit=8&offset=2&sort=newest"
            % urllib.parse.quote_plus(query),
            self.actor_headers(WORKER),
        )
        self.assert_page(
            body,
            "bridges",
            total=len(matches),
            unfiltered=ROW_COUNT + 1,
            limit=8,
            offset=2,
            has_more=2 + len(body["bridges"]) < len(matches),
        )
        self.assertEqual(
            [row["with"] for row in body["bridges"]],
            [row["with"] for row in list(reversed(matches))[2:10]],
        )
        options = self.get_json(
            "/v1/projects/hub/bridges?options=1", self.actor_headers(WORKER)
        )
        self.assertEqual(len(options["bridges"]), ROW_COUNT + 1)
        self.assertTrue(all("with" in row and "relation" in row for row in options["bridges"]))
        hidden = next(row for row in options["bridges"] if row["with"] == "hidden-peer")
        self.assertIs(hidden["can_participate"], False)

    def test_tasks_search_status_sort_and_cap_are_server_side(self):
        query = "task cobalt"
        matches = [
            row
            for row in self.task_rows
            if row["status"] == "done" and terms_match(row, query)
        ]
        body = self.get_json(
            "/v1/projects/hub/tasks?q=%s&status=done&limit=7&offset=2&sort=oldest"
            % urllib.parse.quote_plus(query),
            self.actor_headers(),
        )
        self.assert_page(
            body,
            "tasks",
            total=len(matches),
            unfiltered=ROW_COUNT,
            limit=7,
            offset=2,
            has_more=2 + len(body["tasks"]) < len(matches),
        )
        self.assertEqual(
            [row["task_id"] for row in body["tasks"]],
            [row["task_id"] for row in matches[2:9]],
        )
        capped = self.get_json(
            "/v1/projects/hub/tasks?status=all&limit=999", self.actor_headers()
        )
        self.assertEqual((capped["limit"], len(capped["tasks"])), (PAGE_SIZE, PAGE_SIZE))

    def test_decisions_search_status_sort_and_paging_are_global(self):
        query = "decision cobalt"
        matches = [
            row
            for row in self.decision_rows
            if row["status"] == "accepted" and terms_match(row, query)
        ]
        body = self.get_json(
            "/v1/projects/hub/decisions?q=%s&status=accepted"
            "&limit=6&offset=1&sort=newest" % urllib.parse.quote_plus(query),
            self.actor_headers(),
        )
        self.assert_page(
            body,
            "decisions",
            total=len(matches),
            unfiltered=ROW_COUNT,
            limit=6,
            offset=1,
            has_more=1 + len(body["decisions"]) < len(matches),
        )
        self.assertEqual(
            [row["decision_id"] for row in body["decisions"]],
            [row["decision_id"] for row in list(reversed(matches))[1:7]],
        )

    def test_agents_search_sort_cap_and_options_use_full_directory(self):
        query = "agent cobalt"
        matches = [row for row in self.agent_rows if terms_match(row, query)]
        body = self.get_json(
            "/v1/projects/hub/agents?q=%s&limit=5&offset=2&sort=oldest"
            % urllib.parse.quote_plus(query),
            self.actor_headers(),
        )
        self.assert_page(
            body,
            "agents",
            total=len(matches),
            unfiltered=ROW_COUNT,
            limit=5,
            offset=2,
            has_more=2 + len(body["agents"]) < len(matches),
        )
        self.assertEqual(
            [row["agent_id"] for row in body["agents"]],
            [row["agent_id"] for row in matches[2:7]],
        )
        options = self.get_json(
            "/v1/projects/hub/agents?options=1", self.actor_headers()
        )
        self.assertEqual(len(options["agents"]), ROW_COUNT)
        for item in options["agents"]:
            self.assertTrue({"agent_id", "display_name", "role", "runtime"}.issubset(item))
            self.assertNotIn("last_seen_at", item)

    def test_rules_search_enabled_status_sort_and_cap_use_all_managed_rows(self):
        query = "rule cobalt"
        matches = [
            row
            for row in self.rule_rows
            if not row["enabled"] and terms_match(row, query)
        ]
        body = self.get_json(
            "/v1/projects/hub/rules?include_all=1&include_disabled=1"
            "&status=disabled&q=%s&limit=7&offset=2&sort=newest"
            % urllib.parse.quote_plus(query),
            self.actor_headers(),
        )
        self.assert_page(
            body,
            "rules",
            total=len(matches),
            unfiltered=ROW_COUNT + 1,
            limit=7,
            offset=2,
            has_more=2 + len(body["rules"]) < len(matches),
        )
        self.assertEqual(
            [row["rule_id"] for row in body["rules"]],
            [row["rule_id"] for row in list(reversed(matches))[2:9]],
        )
        capped = self.get_json(
            "/v1/projects/hub/rules?include_all=1&include_disabled=1&limit=999",
            self.actor_headers(),
        )
        self.assertEqual((capped["limit"], len(capped["rules"])), (PAGE_SIZE, PAGE_SIZE))

    def test_project_log_is_searchable_sorted_and_paged_over_all_significant_rows(self):
        query = "audit cobalt"
        expected = [
            seq
            for index, seq in enumerate(self.audit_sequences)
            if index % 7 == 0
        ]
        body = self.get_json(
            "/v1/projects/hub/log?q=%s&limit=8&offset=3&sort=newest"
            % urllib.parse.quote_plus(query),
            self.actor_headers(WORKER),
        )
        self.assert_page(
            body,
            "entries",
            total=len(expected),
            unfiltered=ROW_COUNT + 1,
            limit=8,
            offset=3,
            has_more=3 + len(body["entries"]) < len(expected),
        )
        self.assertEqual(
            [row["seq"] for row in body["entries"]],
            list(reversed(expected))[3:11],
        )
        self.assertTrue(all("line" in row and "created_at" in row for row in body["entries"]))

    def test_unified_search_pages_across_categories_in_one_date_order(self):
        body = self.get_json(
            "/v1/projects/hub/search?q=unified+amber&limit=999"
            "&offset=60&sort=oldest",
            self.actor_headers(),
        )
        self.assert_page(
            body,
            "results",
            total=ROW_COUNT,
            unfiltered=ROW_COUNT,
            limit=PAGE_SIZE,
            offset=60,
            has_more=True,
        )
        self.assertTrue(all(row["kind"] == "task" for row in body["results"]))
        self.assertEqual(
            [row["id"] for row in body["results"]],
            [row["task_id"] for row in self.task_rows[60:120]],
        )
        tail = self.get_json(
            "/v1/projects/hub/search?q=unified+amber&limit=60"
            "&offset=120&sort=oldest",
            self.actor_headers(),
        )
        self.assertEqual((len(tail["results"]), tail["has_more"]), (17, False))

    def test_client_keys_are_authorized_filtered_sorted_and_paged(self):
        query = "client cobalt"
        matches = [
            row
            for row in self.viewer_key_rows
            if row["revoked"] and terms_match(row, query)
        ]
        body = self.get_json(
            "/v1/auth/client-keys?q=%s&status=revoked&limit=6"
            "&offset=2&sort=oldest" % urllib.parse.quote_plus(query),
            self.viewer_session,
        )
        self.assert_page(
            body,
            "client_keys",
            total=len(matches),
            unfiltered=ROW_COUNT,
            limit=6,
            offset=2,
            has_more=2 + len(body["client_keys"]) < len(matches),
        )
        self.assertEqual(
            [row["token_id"] for row in body["client_keys"]],
            [row["token_id"] for row in matches[2:8]],
        )
        serialized = json.dumps(body)
        self.assertNotIn("Owner private key", serialized)
        capped = self.get_json(
            "/v1/auth/client-keys?limit=999", self.viewer_session
        )
        self.assertEqual((capped["limit"], len(capped["client_keys"])), (PAGE_SIZE, PAGE_SIZE))
        self.assertEqual(capped["unfiltered_total"], ROW_COUNT)

    def test_room_history_filters_full_conversation_and_counts_after_visibility(self):
        query = "room cobalt"
        expected = [
            seq
            for index, seq in enumerate(self.local_room_sequences)
            if index % 7 == 0
        ]
        body = self.get_json(
            "/v1/projects/hub/room/history?conversation=local&q=%s"
            "&limit=8&offset=3&sort=oldest" % urllib.parse.quote_plus(query),
            self.actor_headers(WORKER),
        )
        self.assert_page(
            body,
            "messages",
            total=len(expected),
            unfiltered=ROW_COUNT,
            limit=8,
            offset=3,
            has_more=3 + len(body["messages"]) < len(expected),
        )
        self.assertEqual(
            [row["seq"] for row in body["messages"]], expected[3:11]
        )
        denied = self.get_json(
            "/v1/projects/hub/room/history?conversation=hidden-peer&limit=999",
            self.actor_headers(WORKER),
        )
        self.assert_page(
            denied,
            "messages",
            total=0,
            unfiltered=0,
            limit=PAGE_SIZE,
            offset=0,
            has_more=False,
        )
        allowed = self.get_json(
            "/v1/projects/hub/room/history?conversation=hidden-peer&limit=999",
            self.actor_headers(DIRECTOR),
        )
        self.assert_page(
            allowed,
            "messages",
            total=70,
            unfiltered=70,
            limit=PAGE_SIZE,
            offset=0,
            has_more=True,
        )

    def test_activity_filters_authorized_ledger_before_exact_counts_and_offset(self):
        worker_total = ROW_COUNT + ROW_COUNT + 1
        director_total = worker_total + len(self.hidden_room_sequences)
        denied = self.get_json(
            "/v1/projects/hub/activity?q=secret+bridge&limit=999",
            self.actor_headers(WORKER),
        )
        self.assert_page(
            denied,
            "events",
            total=0,
            unfiltered=worker_total,
            limit=PAGE_SIZE,
            offset=0,
            has_more=False,
        )
        allowed = self.get_json(
            "/v1/projects/hub/activity?q=secret+bridge&limit=999&sort=oldest",
            self.actor_headers(DIRECTOR),
        )
        self.assert_page(
            allowed,
            "events",
            total=len(self.hidden_room_sequences),
            unfiltered=director_total,
            limit=PAGE_SIZE,
            offset=0,
            has_more=True,
        )
        self.assertEqual(
            [row["seq"] for row in allowed["events"]],
            self.hidden_room_sequences[:PAGE_SIZE],
        )

    def test_inbox_badge_is_exact_and_mark_all_drains_60_row_pages(self):
        headers = self.actor_headers(MAIL_RECIPIENT)
        peek = self.get_json(
            "/v1/projects/mailbox/inbox?mark_read=0&limit=999", headers
        )
        self.assertEqual(peek["limit"], PAGE_SIZE)
        self.assertEqual(len(peek["messages"]), PAGE_SIZE)
        self.assertEqual((peek["unread_total"], peek["total"]), (ROW_COUNT, ROW_COUNT))
        self.assertIs(peek["may_have_more"], True)
        self.assertIs(peek["has_more"], True)

        remaining = []
        page_lengths = []
        for _ in range(3):
            page = self.get_json(
                "/v1/projects/mailbox/inbox?mark_read=1&limit=60", headers
            )
            remaining.append(page["unread_total"])
            page_lengths.append(len(page["messages"]))
        self.assertEqual(remaining, [137, 77, 17])
        self.assertEqual(page_lengths, [60, 60, 17])
        drained = self.get_json(
            "/v1/projects/mailbox/inbox?mark_read=1&limit=60", headers
        )
        self.assertEqual((drained["unread_total"], drained["total"]), (0, 0))
        self.assertEqual(drained["messages"], [])
        self.assertIs(drained["may_have_more"], False)
        self.assertIs(drained["has_more"], False)


if __name__ == "__main__":
    unittest.main()
