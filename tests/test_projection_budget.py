"""T-86 · compact default read projections and their measured budgets.

Consumers reported that ``get_handoff``/``task_list``/``task_show``/
``check_inbox``/``room_read`` exceeded client tool-response limits and forced
file offloading, because every row embedded nested identity and attribution
records a follow-up call can fetch.  These tests pin the two halves of the
fix: the DEFAULT tool/REST projection is small enough to act on, and
``detail='full'`` still reproduces the complete pre-change shape so no client
loses information.

All state is one temporary SQLite database plus temporary HOME/watcher
directories.  This module never discovers or contacts a configured Attacca
host, never starts a watcher process, and never writes outside its temporary
directory.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "attacca_projection_budget_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)

HOOK_SPEC = importlib.util.spec_from_file_location(
    "attacca_projection_budget_hook", ROOT / "hooks" / "session_start.py")
hook = importlib.util.module_from_spec(HOOK_SPEC)
HOOK_SPEC.loader.exec_module(hook)


PROJECT = "budget"
DIRECTOR = "budget.director.codex"
WORKER = "budget.worker.claude"
PEER = "budget.director.claude"

# Measured ceilings for the fixture below (25 decisions, 20 tasks with up to
# six lifecycle actions each, 30 room messages, 3 pending dispositions).
# room_read carries 22_000 rather than the planned 20_000: plan D requires the
# COMPLETE message body on every row and all six attention flags, and on this
# fixture those two mandated payloads are the entire residual.  Compaction
# still removes the nested identity/attribution/ledger_actor duplication that
# caused the reported overflow (38.9 KB -> 21.2 KB here).
BUDGETS = {
    "get_handoff": 25_000,
    "task_list": 20_000,
    "task_show": 12_000,
    "check_inbox": 8_000,
    "room_read": 22_000,
}

LOREM = ("The compact default projection must carry what an agent needs to "
         "act without forcing a file offload; every nested identity block "
         "that a follow-up call can fetch is removed from the default. ")

# Key sets captured from HEAD (release 0.5.4) BEFORE this change, so
# ``detail='full'`` can be proven to still carry every field it used to.
# Additive keys are allowed; a missing key is a compatibility break.
HEAD_KEY_SETS = json.loads(r"""
{
 "check_inbox": {
  ".": ["actor", "disposition_baseline_seq", "has_more", "hint", "limit",
        "may_have_more", "messages", "messages_include_all_visible", "offset",
        "page_unread_total", "pending_disposition_may_have_more",
        "pending_disposition_total", "pending_dispositions", "project",
        "read_cursor", "scanned_through_seq", "total", "unread_addressed",
        "unread_broadcasts", "unread_direct", "unread_everyone",
        "unread_group_context", "unread_total"],
  "pending_dispositions[]": ["actor", "actor_type", "addressed_to_you", "at",
        "attribution", "authority", "body", "broadcast_to_everyone",
        "directed_to_you", "disposition", "event_id", "group_context",
        "identity", "ledger_actor", "mentioned_to_you", "mentions",
        "mirrored_to", "msg_type", "origin_project", "owner", "reply_to",
        "reply_to_you", "requires_disposition", "seq", "task_id"],
  "pending_dispositions[].identity": ["actor_id", "ledger_actor_id", "owner",
        "persona", "role", "runtime", "workspace"]
 },
 "get_handoff": {
  ".": ["bridges", "cloud_context", "context_version", "decisions", "git",
        "governance", "handoff", "handoff_actor", "handoff_attribution",
        "handoff_scope", "handoff_updated_at", "handoff_updated_by",
        "handoff_updated_owner", "handoff_version", "hint",
        "identity_handoff", "identity_handoff_actor",
        "identity_handoff_updated_at", "identity_handoff_updated_by",
        "identity_handoff_updated_owner", "identity_handoff_version",
        "lead_director", "open_tasks", "project", "project_rules",
        "recent_activity", "role_scope", "shared_handoff", "workflow_warnings",
        "your_inbox"],
  "your_inbox": ["hint", "may_have_more", "messages_include_all_visible",
        "pending_disposition_total", "pending_dispositions", "unread_everyone",
        "unread_group_context", "unread_addressed_to_you", "unread_total"],
  "open_tasks[]": ["attribution", "claimed_by", "risk_level", "status",
        "task_id", "title"],
  "decisions[]": ["attribution", "decision_id", "proposed_owner",
        "resolved_owner", "status", "title"],
  "cloud_context": ["content", "sha256", "updated_at", "updated_by",
        "updated_owner", "version"]
 },
 "task_list": {
  ".": ["has_more", "limit", "offset", "project", "tasks", "total",
        "unfiltered_total"],
  "tasks[]": ["actions", "actions_compacted", "actions_total", "attribution",
        "base_revision", "claimed_by", "created_at", "created_by",
        "dependencies", "description", "expected_scope", "last_report",
        "lease_until", "plan", "plan_required", "project_id", "risk_level",
        "status", "task_id", "title", "updated_at", "verification_status"],
  "tasks[].attribution": ["claimed", "created", "current_claimant", "latest",
        "released", "reported", "resolved", "status_changed"]
 },
 "task_show": {
  ".": ["actions", "actions_compacted", "actions_pagination", "actions_total",
        "attribution", "base_revision", "claimed_by", "created_at",
        "created_by", "dependencies", "description", "expected_scope",
        "history", "history_pagination", "last_report", "lease_until", "plan",
        "plan_required", "project_id", "risk_level", "status", "task_id",
        "title", "updated_at", "verification_status"],
  "actions[]": ["actor_id", "actor_type", "at", "attribution",
        "context_version", "device_id", "event_id", "event_type",
        "git_branch", "git_revision", "operational_actor_id", "owner",
        "payload", "seq"],
  "actions[].attribution": ["actor_id", "actor_type", "human_user",
        "identity", "ledger_actor_id", "run_by_user"]
 },
 "room_read": {
  ".": ["hint", "may_have_more", "messages", "next_since_seq",
        "older_messages_available", "project"],
  "messages[]": ["actor", "actor_type", "addressed_to_you", "at",
        "attribution", "authority", "body", "broadcast_to_everyone",
        "directed_to_you", "event_id", "group_context", "identity",
        "ledger_actor", "mentioned_to_you", "mentions", "mirrored_to",
        "msg_type", "origin_project", "owner", "reply_to", "reply_to_you",
        "seq", "task_id"]
 },
 "room_history": {
  ".": ["conversation", "has_more", "latest_seq", "limit", "messages",
        "new_count", "offset", "project", "total", "unfiltered_total"]
 }
}
""")


def size(value) -> int:
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8"))


def key_paths(value, prefix="", out=None, depth=0):
    """Sorted dotted key paths; lists collapse to one representative shape."""
    out = {} if out is None else out
    if depth > 6:
        return out
    if isinstance(value, dict):
        out.setdefault(prefix or ".", set()).update(value.keys())
        for key, item in value.items():
            key_paths(item, "%s.%s" % (prefix, key) if prefix else key,
                      out, depth + 1)
    elif isinstance(value, list):
        for item in value[:3]:
            key_paths(item, "%s[]" % prefix, out, depth + 1)
    return out


class ProjectionBudgetTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        checkout = root / "checkout"
        checkout.mkdir()
        cls.checkout = checkout
        cls.conn = c.connect(root / "budget.db")
        cls.db = root / "budget.db"
        conn = cls.conn
        c.project_init(conn, "jack", "human", path=checkout,
                       project_id=PROJECT, name="Budget")
        for actor, role, runtime in ((DIRECTOR, "director", "codex"),
                                     (WORKER, "worker", "claude"),
                                     (PEER, "director", "claude")):
            c.agent_register(conn, PROJECT, "jack", "human", agent_id=actor,
                             role=role, runtime=runtime)
        c.cloud_context_set(conn, PROJECT, DIRECTOR, "agent", LOREM * 220)
        for index in range(4):
            c.rule_create(conn, PROJECT, DIRECTOR, "agent",
                          "Budget rule %02d" % index, LOREM * 2,
                          scope="everyone" if index % 2 else "director")
        c.role_scope_set(conn, PROJECT, DIRECTOR, "agent", "director",
                         LOREM * 8)
        for index in range(25):
            proposed = c.decision_propose(
                conn, PROJECT, DIRECTOR, "agent",
                "Budget decision %02d about the compact projection" % index,
                detail=LOREM * 3, rationale=LOREM * 3)
            if index % 3 == 0:
                c.decision_resolve(conn, PROJECT, DIRECTOR, "agent",
                                   proposed["decision_id"], "accepted",
                                   rationale=LOREM)
        for index in range(20):
            task_id = c.task_create(
                conn, PROJECT, DIRECTOR, "agent",
                "Budget task %02d for the compact read projection" % index,
                description=LOREM * 2,
                expected_scope=(
                    ["attacca.py", "tests/test_%02d.py" % index,
                     "web/admin.html", "README.md",
                     "hooks/session_start.py", "docs/LOG.md",
                     "sync_client.py", "x%02d.py" % index,
                     "y%02d.py" % index] if index < 4 else
                    ["attacca.py", "tests/test_%02d.py" % index,
                     "README.md"]),
                dependencies=["T-%d" % (index or 1)],
                risk_level="high" if index % 4 == 0 else "medium")["task_id"]
            # Up to six lifecycle actions per task: created, claimed,
            # reported (half the board), status_changed, claimed again,
            # released.
            c.task_claim(conn, PROJECT, WORKER, "agent", task_id)
            if index % 2 == 0:
                c.task_report(conn, PROJECT, WORKER, "agent", task_id,
                              "Budget report %02d. %s" % (index, LOREM * 2),
                              evidence=[{"kind": "test", "detail": LOREM}],
                              requested_state="review")
            c.task_set_status(conn, PROJECT, DIRECTOR, "agent", task_id,
                              "queued", reason="rework %02d" % index)
            c.task_claim(conn, PROJECT, WORKER, "agent", task_id)
            c.task_release(conn, PROJECT, WORKER, "agent", task_id,
                           reason="handing back %02d" % index)
        addressed = []
        for index in range(30):
            mention = index % 10 == 0 or index == 5
            sent = c.room_send(
                conn, PROJECT, PEER if index % 2 else DIRECTOR, "agent",
                "Budget room message %02d. %s" % (index, LOREM),
                msg_type="directive" if mention else "chat",
                mentions=[WORKER] if mention else None)
            if mention:
                addressed.append(sent["event"]["event_id"])
        # One addressed row carries an explicit outcome so the compact
        # disposition shape is exercised; three stay pending.
        cls.disposed_event_id = addressed[-1]
        c.message_dispose(conn, PROJECT, WORKER, "agent",
                          cls.disposed_event_id, "acknowledged",
                          note="read and answered in the room. " + LOREM)
        # Drain the reader's cursor so the fixture is exactly 3 pending
        # dispositions and 0 unread, per the T-86 measurement.
        c.inbox_read(conn, PROJECT, WORKER, mark_read=True, limit=500)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.temp.cleanup()

    # --------------------------------------------------------------- helpers
    def responses(self, **kw):
        conn = self.conn
        return {
            "get_handoff": c.get_handoff(
                conn, PROJECT, actor_id=WORKER, actor_type="agent", **kw),
            "task_list": c.task_list(conn, PROJECT, limit=20, **kw),
            "task_show": c.task_show(conn, PROJECT, "T-5", **kw),
            "check_inbox": c.inbox_read(
                conn, PROJECT, WORKER, mark_read=False, limit=50, **kw),
            "room_read": c.room_read(
                conn, PROJECT, limit=30, actor_id=WORKER,
                actor_type="agent", **kw),
            "room_history": c.room_history(
                conn, PROJECT, actor_id=WORKER, actor_type="agent",
                limit=30, **kw),
        }

    def session(self, actor=WORKER):
        return c.McpSession(self.db, default_project=PROJECT, actor=actor,
                            actor_type="agent", detect_cwd=False,
                            owner="jack", preserve_actor_identity=True)

    # ----------------------------------------------------------------- tests
    def test_fixture_matches_the_measured_shape(self):
        inbox = c.inbox_read(self.conn, PROJECT, WORKER, mark_read=False,
                             limit=50)
        self.assertEqual(inbox["unread_total"], 0)
        self.assertEqual(inbox["pending_disposition_total"], 3)
        board = c.task_list(self.conn, PROJECT, limit=20)
        self.assertEqual(len(board["tasks"]), 20)
        self.assertEqual(board["total"], 20)
        # Six lifecycle writes on a reported task collapse to one latest
        # row per event kind (the second claim supersedes the first).
        reported = next(item for item in board["tasks"]
                        if item["task_id"] == "T-1")
        self.assertEqual(len(reported["actions"]), 5)
        self.assertEqual(reported["actions_total"], 6)
        handoff = c.get_handoff(self.conn, PROJECT, actor_id=WORKER,
                                actor_type="agent")
        self.assertEqual(len(handoff["decisions"]), 25)
        self.assertEqual(len(handoff["open_tasks"]), 20)
        self.assertEqual(
            len(c.room_read(self.conn, PROJECT, limit=30,
                            actor_id=WORKER)["messages"]), 30)

    def test_compact_defaults_fit_the_client_tool_budget(self):
        compact = self.responses(detail="compact")
        full = self.responses()
        measured = []
        for surface, ceiling in BUDGETS.items():
            observed = size(compact[surface])
            measured.append("%s %d B (full %d B, limit %d B)" % (
                surface, observed, size(full[surface]), ceiling))
            self.assertLess(
                observed, ceiling,
                "%s compact projection is %d bytes, over its %d byte budget"
                % (surface, observed, ceiling))
            # Every surface must be a real reduction, not a rename.
            self.assertLess(observed, size(full[surface]))
        print("\nMEASURED · T-86 compact projections · " + " · ".join(measured))

    def test_full_detail_reproduces_the_pre_change_key_sets(self):
        full = self.responses()
        for surface, golden in HEAD_KEY_SETS.items():
            observed = key_paths(full[surface])
            for path, keys in golden.items():
                with self.subTest(surface=surface, path=path):
                    self.assertIn(path, observed)
                    self.assertEqual(
                        set(keys) - observed[path], set(),
                        "detail='full' dropped keys from %s %s"
                        % (surface, path))

    def test_compact_task_rows_keep_ids_state_owner_and_run_by_user(self):
        board = c.task_list(self.conn, PROJECT, limit=20, detail="compact")
        self.assertEqual(board["detail"], "compact")
        self.assertEqual(board["total"], 20)
        self.assertEqual(board["limit"], 20)
        row = next(item for item in board["tasks"] if item["task_id"] == "T-1")
        for key in ("task_id", "title", "status", "risk_level", "claimed_by",
                    "lease_until", "plan_required", "plan_version",
                    "updated_at", "dependencies", "expected_scope",
                    "last_report", "created_by", "verification_status",
                    "attribution"):
            self.assertIn(key, row)
        # Six nested lifecycle attribution blocks collapse to ONE compact
        # record for the latest action, and never lose the human operator.
        self.assertEqual(
            sorted(row["attribution"]),
            ["actor_id", "actor_type", "at", "persona", "role",
             "run_by_user", "runtime"])
        self.assertEqual(row["attribution"]["actor_id"], WORKER)
        self.assertEqual(row["attribution"]["role"], "worker")
        self.assertEqual(row["attribution"]["runtime"], "claude")
        self.assertNotIn("actions", row)
        self.assertNotIn("description", row)
        # A long declared scope reports its own total instead of every path.
        self.assertEqual(len(row["expected_scope"]),
                         c.TASK_COMPACT_SCOPE_CAP)
        self.assertEqual(row["expected_scope_total"], 9)
        self.assertLessEqual(len(row["last_report"]["summary"]),
                             c.TASK_COMPACT_SUMMARY_CHARS)
        self.assertTrue(row["last_report"]["summary_truncated"])
        self.assertEqual(row["last_report"]["requested_state"], "review")
        # Evidence alone does not verify: the board keeps the server's
        # verification state rather than inventing one.
        self.assertEqual(row["verification_status"], "unverified")

    def test_compact_task_show_pages_and_full_restores_nested_attribution(self):
        compact = c.task_show(self.conn, PROJECT, "T-5", detail="compact")
        self.assertEqual(compact["detail"], "compact")
        self.assertEqual(len(compact["actions"]), 6)  # fewer than the cap
        self.assertEqual(compact["actions_pagination"]["unfiltered_total"], 6)
        self.assertEqual(len(compact["history"]), 6)
        self.assertIn("description", compact)
        action = compact["actions"][0]
        self.assertIn("run_by_user", action["attribution"])
        self.assertNotIn("identity", action["attribution"])
        # Explicit paging still reaches the complete immutable history.
        paged = c.task_show(self.conn, PROJECT, "T-5", detail="compact",
                            action_limit=2, action_sort="oldest")
        self.assertEqual(len(paged["actions"]), 2)
        self.assertEqual(paged["actions"][0]["event_type"], "task.created")
        self.assertTrue(paged["actions_pagination"]["has_more"])
        full = c.task_show(self.conn, PROJECT, "T-5")
        self.assertEqual(full["actions_pagination"]["limit"], 60)
        self.assertEqual(len(full["actions"]), 6)
        self.assertIn("identity", full["actions"][0]["attribution"])
        self.assertIn("created", full["attribution"])

    def test_compact_messages_keep_full_bodies_cursors_and_totals(self):
        full = c.room_read(self.conn, PROJECT, limit=30, actor_id=WORKER,
                           actor_type="agent")
        compact = c.room_read(self.conn, PROJECT, limit=30, actor_id=WORKER,
                              actor_type="agent", detail="compact")
        self.assertEqual(compact["next_since_seq"], full["next_since_seq"])
        self.assertEqual(compact["may_have_more"], full["may_have_more"])
        self.assertEqual(compact["older_messages_available"],
                         full["older_messages_available"])
        self.assertEqual([item["body"] for item in compact["messages"]],
                         [item["body"] for item in full["messages"]])
        row = compact["messages"][0]
        for key in ("event_id", "seq", "at", "actor", "msg_type", "mentions",
                    "reply_to", "task_id", "body", "origin_project",
                    "authority"):
            self.assertIn(key, row)
        for dropped in ("identity", "attribution", "ledger_actor"):
            self.assertNotIn(dropped, row)
        # Differential: compaction removes ONLY the nested identity trio.
        # Every attention flag the full row carries must survive, including
        # the two that distinguish a mention from a reply.
        for full_row, compact_row in zip(full["messages"],
                                         compact["messages"]):
            for flag in ("mentioned_to_you", "reply_to_you",
                         "directed_to_you", "broadcast_to_everyone",
                         "addressed_to_you", "group_context"):
                self.assertEqual(flag in compact_row, flag in full_row, flag)
                if flag in full_row:
                    self.assertEqual(compact_row[flag], full_row[flag], flag)
            self.assertEqual(
                set(full_row) - set(compact_row),
                {"identity", "attribution", "ledger_actor"})
        # The canonical actor survives; only its duplicated projection goes.
        self.assertEqual(row["actor"], full["messages"][0]["actor"])

        inbox = c.inbox_read(self.conn, PROJECT, WORKER, mark_read=False,
                             limit=50, detail="compact")
        self.assertEqual(inbox["pending_disposition_total"], 3)
        pending = inbox["pending_dispositions"][0]
        for dropped in ("identity", "attribution", "ledger_actor"):
            self.assertNotIn(dropped, pending)
        self.assertTrue(pending["requires_disposition"])
        self.assertIn(LOREM.strip()[:40], pending["body"])
        # A row that is still open carries no outcome yet.
        self.assertIsNone(pending["disposition"])
        # The explicitly disposed row keeps its decisive fields and a
        # bounded note instead of the full durable row.
        closed = next(item for item in compact["messages"]
                      if item["event_id"] == self.disposed_event_id)
        self.assertEqual(closed["disposition"]["disposition"], "acknowledged")
        self.assertIs(closed["disposition"]["implicit"], False)
        self.assertLessEqual(len(closed["disposition"]["note"]),
                             c.MESSAGE_COMPACT_NOTE_CHARS)
        self.assertTrue(closed["disposition"]["note_truncated"])
        self.assertIn("updated_at", closed["disposition"])

    def test_compact_handoff_caps_collections_and_keeps_inbox_counters(self):
        compact = c.get_handoff(self.conn, PROJECT, actor_id=WORKER,
                                actor_type="agent", detail="compact")
        self.assertEqual(compact["detail"], "compact")
        self.assertEqual(compact["open_tasks_total"], 20)
        self.assertEqual(compact["decisions_total"], 25)
        self.assertLessEqual(len(compact["open_tasks"]),
                             c.HANDOFF_COMPACT_TASK_CAP)
        self.assertLessEqual(len(compact["decisions"]),
                             c.HANDOFF_COMPACT_DECISION_CAP)
        self.assertEqual(sorted(compact["decisions"][0]),
                         ["decision_id", "status", "title"])
        inbox = compact["your_inbox"]
        for key in ("unread_total", "unread_addressed_to_you",
                    "unread_direct", "unread_everyone",
                    "unread_group_context", "may_have_more",
                    "messages_include_all_visible",
                    "pending_disposition_total"):
            self.assertIn(key, inbox)
        self.assertEqual(inbox["pending_disposition_total"], 3)
        self.assertLessEqual(len(inbox["first_page"]),
                             c.HANDOFF_COMPACT_INBOX_PAGE)
        self.assertEqual(inbox["first_page_of"], "pending_dispositions")
        head = inbox["first_page"][0]
        self.assertLessEqual(len(head["body"]),
                             c.HANDOFF_COMPACT_BODY_CHARS)
        self.assertIn("body_truncated", head)
        self.assertTrue(head["requires_disposition"])
        for flag in ("mentioned_to_you", "reply_to_you", "directed_to_you",
                     "broadcast_to_everyone", "addressed_to_you",
                     "group_context"):
            self.assertIn(flag, head)
        long_row = c._compact_inbox_row(
            {"event_id": "ev_x", "seq": 9, "body": "x" * 5_000})
        self.assertEqual(len(long_row["body"]),
                         c.HANDOFF_COMPACT_BODY_CHARS)
        self.assertTrue(long_row["body_truncated"])
        # The bridge/role-scope compaction never drops the binding law.
        self.assertIn("effective_content", compact["role_scope"])
        self.assertIsNotNone(compact["project_rules"])
        self.assertEqual(len(compact["project_rules"]),
                         len(c.get_handoff(
                             self.conn, PROJECT, actor_id=WORKER,
                             actor_type="agent")["project_rules"]))

    def test_cloud_context_body_is_gated_by_the_callers_sha(self):
        record = c.cloud_context_get(self.conn, PROJECT)["cloud_context"]
        sha = record["sha256"]
        default = c.get_handoff(self.conn, PROJECT, actor_id=WORKER,
                                actor_type="agent", detail="compact")
        self.assertIs(default["cloud_context"]["content_included"], False)
        self.assertEqual(default["cloud_context"]["sha256"], sha)
        self.assertEqual(default["cloud_context"]["content_chars"],
                         len(record["content"]))
        unchanged = c.get_handoff(self.conn, PROJECT, actor_id=WORKER,
                                  actor_type="agent", detail="compact",
                                  cloud_context_sha=sha)
        self.assertIs(unchanged["cloud_context"]["content_included"], False)
        changed = c.get_handoff(self.conn, PROJECT, actor_id=WORKER,
                                actor_type="agent", detail="compact",
                                cloud_context_sha="0" * 64)
        self.assertIs(changed["cloud_context"]["content_included"], True)
        self.assertEqual(changed["cloud_context"]["content"],
                         record["content"])
        asked = c.get_handoff(self.conn, PROJECT, actor_id=WORKER,
                              actor_type="agent", detail="compact",
                              cloud_context="full")
        self.assertEqual(asked["cloud_context"]["content"], record["content"])
        self.assertEqual(
            c.get_handoff(self.conn, PROJECT, actor_id=WORKER,
                          actor_type="agent")["cloud_context"]["content"],
            record["content"])
        with self.assertRaisesRegex(c.AttaccaError, "cloud_context must be"):
            c.get_handoff(self.conn, PROJECT, actor_id=WORKER,
                          actor_type="agent", detail="compact",
                          cloud_context="sideways")

    def test_invalid_detail_is_rejected_on_every_read_surface(self):
        for call in (
            lambda: c.get_handoff(self.conn, PROJECT, actor_id=WORKER,
                                  detail="tiny"),
            lambda: c.task_list(self.conn, PROJECT, detail="tiny"),
            lambda: c.task_show(self.conn, PROJECT, "T-5", detail="tiny"),
            lambda: c.inbox_read(self.conn, PROJECT, WORKER, mark_read=False,
                                 detail="tiny"),
            lambda: c.room_read(self.conn, PROJECT, actor_id=WORKER,
                                detail="tiny"),
            lambda: c.room_history(self.conn, PROJECT, actor_id=WORKER,
                                   detail="tiny"),
        ):
            with self.assertRaisesRegex(c.AttaccaError, "detail must be one"):
                call()

    def test_fields_allow_list_narrows_task_rows(self):
        board = c.task_list(self.conn, PROJECT, limit=5, detail="compact",
                            fields="status,claimed_by")
        self.assertEqual(sorted(board["tasks"][0]),
                         ["claimed_by", "status", "task_id"])
        detailed = c.task_show(self.conn, PROJECT, "T-5",
                               fields="status,title")
        for key in ("task_id", "status", "title"):
            self.assertIn(key, detailed)
        self.assertNotIn("expected_scope", detailed)
        # Paging metadata is response envelope, not a row field.
        self.assertIn("actions_pagination", detailed)

    def test_mcp_tools_default_to_compact_and_expose_the_flags(self):
        tools = {item["name"]: item for item in c.MCP_TOOLS}
        for name in ("get_handoff", "task_list", "task_show", "check_inbox",
                     "room_read"):
            properties = tools[name]["inputSchema"]["properties"]
            self.assertIn("detail", properties, name)
            self.assertEqual(properties["detail"]["enum"],
                             list(c.READ_DETAIL_LEVELS), name)
        for name in ("task_list", "task_show"):
            self.assertIn("fields",
                          tools[name]["inputSchema"]["properties"], name)
        for key in ("cloud_context", "cloud_context_sha"):
            self.assertIn(
                key, tools["get_handoff"]["inputSchema"]["properties"])

        session = self.session()
        try:
            board = session.dispatch_tool("task_list", {"limit": 20})
            self.assertEqual(board["detail"], "compact")
            self.assertNotIn("actions", board["tasks"][0])
            self.assertLess(size(board), BUDGETS["task_list"])
            explicit = session.dispatch_tool(
                "task_list", {"limit": 20, "detail": "full"})
            self.assertIn("actions", explicit["tasks"][0])
            brief = session.dispatch_tool("get_handoff", {})
            self.assertEqual(brief["detail"], "compact")
            self.assertLess(size(brief), BUDGETS["get_handoff"])
            self.assertIs(brief["cloud_context"]["content_included"], False)
            room = session.dispatch_tool("room_read", {"limit": 30})
            self.assertEqual(room["detail"], "compact")
            self.assertNotIn("identity", room["messages"][0])
            mail = session.dispatch_tool(
                "check_inbox", {"mark_read": False, "limit": 50})
            self.assertEqual(mail["detail"], "compact")
            self.assertLess(size(mail), BUDGETS["check_inbox"])
            opened = session.dispatch_tool("task_show", {"task_id": "T-5"})
            self.assertEqual(opened["detail"], "compact")
            self.assertLess(size(opened), BUDGETS["task_show"])
            with self.assertRaisesRegex(c.AttaccaError, "detail must be one"):
                session.dispatch_tool("task_list", {"detail": "tiny"})
        finally:
            if session.conn is not None:
                session.conn.close()

    def test_control_panel_asks_for_full_detail_where_it_renders_identity(self):
        panel = (ROOT / "web" / "admin.html").read_text(encoding="utf-8")
        for marker in (
            '`/inbox?mark_read=1&limit=${PANEL_PAGE_SIZE}&detail=full`',
            'sharedHandoff: pathFor("/handoff") + "?detail=full"',
            'overviewHandoff: pathFor("/handoff") + "?detail=full"',
            'status: state.taskFilter, detail: "full"',
            '`/inbox?mark_read=0&limit=${PANEL_PAGE_SIZE}&detail=full`',
            'q: state.roomFilter,\n              detail: "full"',
            '/tasks?limit=7&offset=0&sort=newest&status=active&detail=full',
        ):
            self.assertIn(marker, panel)

    def test_readme_documents_the_compact_default(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("detail", readme)
        self.assertIn("compact", readme)


class HookCompactConsumptionTests(unittest.TestCase):
    """The SessionStart brief must consume the compact shapes unchanged."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.environment = mock.patch.dict(os.environ, {
            "HOME": str(self.root / "home"),
            "ATTACCA_WATCHER_DIR": str(self.root / "watcher"),
            "ATTACCA_RUNTIME": "codex",
            "ATTACCA_DEVICE_ID": "projection-budget-device",
        }, clear=False)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.status = {
            "status": "linked",
            "project_id": PROJECT,
            "root": str(self.checkout),
            "link_path": str(self.checkout / ".attacca" / "project.json"),
            "state_path": str(self.root / "setup-prompts.json"),
        }
        self.config = {"url": "http://attacca.test:4173",
                       "actor": "codex", "owner": "jack"}
        self.key = hook._register_watcher_subscription(
            self.status, ROOT, self.config, runtime="codex", now=0)

    def test_checkout_cloud_context_sha_is_read_only_for_this_project(self):
        self.assertIsNone(hook._checkout_cloud_context_sha(self.status))
        sha = "a" * 64
        (self.checkout / "CLAUDE.md").write_text(
            "local notes\n"
            "<!-- ATTACCA_CLOUD_CONTEXT:BEGIN v=3 sha=%s project=%s "
            "do_not_edit=true -->\nbody\n"
            "<!-- ATTACCA_CLOUD_CONTEXT:END -->\n" % (sha, PROJECT),
            encoding="utf-8")
        self.assertEqual(hook._checkout_cloud_context_sha(self.status), sha)
        (self.checkout / "CLAUDE.md").write_text(
            "<!-- ATTACCA_CLOUD_CONTEXT:BEGIN v=3 sha=%s project=other "
            "do_not_edit=true -->\nbody\n"
            "<!-- ATTACCA_CLOUD_CONTEXT:END -->\n" % sha, encoding="utf-8")
        self.assertIsNone(hook._checkout_cloud_context_sha(self.status))

    def test_omitted_cloud_context_body_is_never_rendered_as_empty(self):
        omitted = hook._compact_cloud_context({
            "version": 3, "sha256": "b" * 64, "content_chars": 31_000,
            "content_included": False,
            "content_hint": "body omitted: your checkout holds sha256 bbb"})
        self.assertIsNone(omitted["content"])
        self.assertTrue(omitted["content_omitted"])
        self.assertIn("omitted", omitted["content_next_action"])
        present = hook._compact_cloud_context({
            "version": 3, "sha256": "b" * 64, "content": "durable context"})
        self.assertEqual(present["content"], "durable context")
        self.assertNotIn("content_omitted", present)

    def test_reconciled_rows_are_reported_once_per_subscription(self):
        snapshot = {"inbox": {"reconciled_count": 7}}
        first = hook._disposition_reconciled_notice(self.key, snapshot)
        self.assertIsNotNone(first)
        self.assertIn("7 pending rows", first["context"])
        self.assertIn("reconciled on upgrade", first["context"])
        self.assertIsNone(
            hook._disposition_reconciled_notice(self.key, snapshot))
        self.assertIsNone(
            hook._disposition_reconciled_notice(self.key, {}))
        self.assertIsNone(hook._disposition_reconciled_notice(
            self.key, {"inbox": {"reconciled_count": 0}}))

    def test_reconciled_count_is_read_from_either_read_surface(self):
        self.assertEqual(hook._snapshot_reconciled_count(
            {"handoff": {"your_inbox": {"reconciled_count": 4}}}), 4)
        self.assertEqual(hook._snapshot_reconciled_count(
            {"inbox": {"reconciled_count": 0},
             "handoff": {"your_inbox": {"reconciled_count": 2}}}), 2)
        self.assertEqual(hook._snapshot_reconciled_count({}), 0)
        self.assertEqual(hook._snapshot_reconciled_count(None), 0)

    def test_poll_baseline_decisions_are_projection_independent(self):
        legacy = [{"decision_id": "D-1", "title": "Legacy", "status": "accepted",
                   "proposed_owner": "jack", "resolved_owner": "jack",
                   "attribution": {"actor_id": DIRECTOR}}]
        compact = [{"decision_id": "D-1", "title": "Legacy",
                    "status": "accepted"}]
        self.assertEqual(hook._poll_decision_rows(legacy),
                         hook._poll_decision_rows(compact))
        # An upgrade that only narrows the projection must not manufacture a
        # delta on the first periodic poll after it.
        previous = {"decisions": legacy}
        snapshot = {"inbox": {"messages": []}}
        unchanged = hook._change_summary(
            self.status, previous, {"decisions": compact}, snapshot, 60)
        self.assertNotIn("Decisions:", json.dumps(unchanged or ""))
        moved = {"decisions": [dict(compact[0], status="superseded")]}
        changed = hook._change_summary(
            self.status, previous, moved, snapshot, 60)
        self.assertIn("Decisions:", json.dumps(changed or ""))

    def test_watcher_inbox_projection_is_identical_from_either_shape(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        db = Path(temp.name) / "watch.db"
        checkout = Path(temp.name) / "checkout"
        checkout.mkdir()
        conn = c.connect(db)
        self.addCleanup(conn.close)
        c.project_init(conn, "jack", "human", path=checkout,
                       project_id=PROJECT, name="Budget")
        for actor, role, runtime in ((DIRECTOR, "director", "codex"),
                                     (WORKER, "worker", "claude")):
            c.agent_register(conn, PROJECT, "jack", "human", agent_id=actor,
                             role=role, runtime=runtime)
        first = c.room_send(conn, PROJECT, DIRECTOR, "agent",
                            "Directive for the worker. " + LOREM,
                            msg_type="directive", mentions=[WORKER])
        c.room_send(conn, PROJECT, DIRECTOR, "agent",
                    "Broadcast directive. " + LOREM, msg_type="directive")
        c.room_send(conn, PROJECT, WORKER, "agent", "worker reply",
                    reply_to=first["event"]["event_id"])
        c.room_send(conn, PROJECT, DIRECTOR, "agent",
                    "reply to the worker", reply_to=(
                        c.room_read(conn, PROJECT, limit=5,
                                    actor_id=DIRECTOR)["messages"][-1]
                        ["event_id"]))

        def projected(**kw):
            page = c.inbox_read(conn, PROJECT, WORKER, mark_read=False,
                                limit=50, **kw)
            key = hook._register_watcher_subscription(
                self.status, ROOT, self.config,
                runtime="codex-%s" % (kw.get("detail") or "full"), now=0)
            hook._watcher_replace_pending_dispositions(key, page)
            hook._watcher_stage_attention(
                key, [row for row in (
                    hook._watcher_attention_projection(item, {})
                    for item in page["messages"]) if row])
            entry = json.loads(
                hook._watcher_state_path().read_text())["subscriptions"][key]

            def stable(rows):
                return [{k: v for k, v in row.items()
                         if k not in ("staged_at",)} for row in rows]

            return (stable(entry["pending_dispositions"]),
                    stable(entry["attention"]),
                    entry["pending_disposition_total"])

        full_rows = projected()
        compact_rows = projected(detail="compact")
        self.assertTrue(full_rows[0])
        self.assertTrue(full_rows[1])
        self.assertEqual(compact_rows, full_rows)

    def test_session_brief_is_byte_identical_from_compact_projections(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        db = Path(temp.name) / "brief.db"
        checkout = Path(temp.name) / "checkout"
        checkout.mkdir()
        conn = c.connect(db)
        self.addCleanup(conn.close)
        c.project_init(conn, "jack", "human", path=checkout,
                       project_id=PROJECT, name="Budget")
        for actor, role, runtime in ((DIRECTOR, "director", "codex"),
                                     (WORKER, "worker", "claude")):
            c.agent_register(conn, PROJECT, "jack", "human", agent_id=actor,
                             role=role, runtime=runtime)
        c.cloud_context_set(conn, PROJECT, DIRECTOR, "agent", LOREM * 4)
        c.rule_create(conn, PROJECT, DIRECTOR, "agent", "Brief rule", LOREM)
        for index in range(4):
            decision = c.decision_propose(
                conn, PROJECT, DIRECTOR, "agent", "Brief decision %d" % index,
                detail=LOREM, rationale=LOREM)
            if index % 2:
                c.decision_resolve(conn, PROJECT, DIRECTOR, "agent",
                                   decision["decision_id"], "accepted")
        for index in range(4):
            task_id = c.task_create(
                conn, PROJECT, DIRECTOR, "agent", "Brief task %d" % index,
                description=LOREM,
                expected_scope=["attacca.py", "README.md"])["task_id"]
            c.task_claim(conn, PROJECT, WORKER, "agent", task_id)
            c.task_report(conn, PROJECT, WORKER, "agent", task_id,
                          "Brief report %d" % index,
                          evidence=[{"kind": "test", "detail": "ok"}])
        for index in range(6):
            c.room_send(conn, PROJECT, DIRECTOR, "agent",
                        "Brief room message %d. %s" % (index, LOREM),
                        msg_type="directive" if index % 3 == 0 else "chat",
                        mentions=[WORKER] if index % 3 == 0 else None)

        def snapshot(**kw):
            return {
                "project": PROJECT,
                "checked_at": "2026-09-03T00:00:00+00:00",
                "agents": c.agent_list(conn, PROJECT),
                "rules": c.rule_list(conn, PROJECT, actor_id=WORKER,
                                     actor_type="agent"),
                "cloud_context": c.cloud_context_get(conn, PROJECT),
                "role_scope": c.role_scope_get(conn, PROJECT,
                                               actor_id=WORKER,
                                               actor_type="agent"),
                "handoff": c.get_handoff(conn, PROJECT, actor_id=WORKER,
                                         actor_type="agent", **kw),
                "log": c.project_log(conn, PROJECT, actor_id=WORKER,
                                     actor_type="agent"),
                "inbox": c.inbox_read(conn, PROJECT, WORKER, mark_read=False,
                                      limit=12, **kw),
                "room": c.room_read(conn, PROJECT, limit=50, actor_id=WORKER,
                                    actor_type="agent", **kw),
                "tasks": c.task_list(conn, PROJECT, **kw),
                "status": c.project_status(conn, PROJECT, WORKER, "agent",
                                           str(db)),
            }

        def render(**kw):
            return json.dumps(hook._compact_snapshot(snapshot(**kw)),
                              indent=2, ensure_ascii=False)

        self.assertEqual(render(detail="compact"), render())


if __name__ == "__main__":
    unittest.main()
