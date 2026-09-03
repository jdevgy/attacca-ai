"""T-80: implicit disposition resolution, upgrade baseline, and bulk resolve.

Every fixture uses a temporary database.  These tests never contact a
configured Attacca host, watcher state, or machine credential.
"""

import tempfile
import unittest
from pathlib import Path

import attacca as c


PANEL = Path(__file__).resolve().parents[1] / "web" / "admin.html"


class DispositionFixture(unittest.TestCase):
    """Two registered Directors in one temporary workspace."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "dispositions.db"
        self.conn = c.connect(self.db)
        self.addCleanup(self.conn.close)
        checkout = Path(self.temp.name) / "checkout"
        checkout.mkdir()
        c.project_init(self.conn, "fixture", "human", path=checkout,
                       project_id="p", name="Dispositions")
        self.sender = "p.director.claude"
        self.actor = "p.director.codex"
        for actor_id, runtime in ((self.sender, "claude"),
                                  (self.actor, "codex")):
            c.agent_register(self.conn, "p", "fixture", "human",
                             agent_id=actor_id, role="director",
                             runtime=runtime)

    # -- helpers ------------------------------------------------------------
    def send(self, body, sender=None, mention=True, **kwargs):
        if mention and "mentions" not in kwargs:
            kwargs["mentions"] = [self.actor]
        return c.room_send(self.conn, "p", sender or self.sender, "agent",
                           body, **kwargs)["event"]

    def reply(self, event_id, body="handled", actor=None):
        return c.room_send(self.conn, "p", actor or self.actor, "agent", body,
                           reply_to=event_id)["event"]

    def pending(self, actor=None, **kwargs):
        return c.pending_message_dispositions(
            self.conn, "p", actor or self.actor, actor_type="agent", **kwargs)

    def pending_ids(self, actor=None, **kwargs):
        return [item["event_id"]
                for item in self.pending(actor, **kwargs)["pending"]]

    def baseline_row(self, actor=None):
        return c._message_disposition_baseline_row(
            self.conn, "p", actor or self.actor)

    def baseline_events(self, actor=None):
        return self.conn.execute(
            "SELECT * FROM events WHERE project_id='p'"
            " AND event_type='room.disposition_baseline' AND actor_id=?"
            " ORDER BY seq", (actor or self.actor,)).fetchall()

    def bulk_events(self, actor=None):
        return self.conn.execute(
            "SELECT * FROM events WHERE project_id='p'"
            " AND event_type='room.message_dispositions_bulk' AND actor_id=?"
            " ORDER BY seq", (actor or self.actor,)).fetchall()

    def set_read_cursor(self, seq, actor=None):
        """Simulate a pre-upgrade read cursor with no disposition history."""
        self.conn.execute(
            "INSERT INTO inbox_cursors (project_id, actor_id, last_read_seq,"
            " updated_at) VALUES ('p',?,?,?)"
            " ON CONFLICT(project_id, actor_id) DO UPDATE SET"
            " last_read_seq=excluded.last_read_seq",
            (actor or self.actor, int(seq), c.now_iso()))


class ImplicitResolutionTests(DispositionFixture):
    def test_self_reply_implies_acknowledged(self):
        message = self.send("Please verify the export")
        self.assertEqual(self.pending_ids(), [message["event_id"]])
        self.reply(message["event_id"])
        state = self.pending()
        self.assertEqual(state["pending_total"], 0)
        record = state["dispositions"][message["event_id"]]
        self.assertEqual(record["disposition"], "acknowledged")
        self.assertTrue(record["implicit"])
        self.assertEqual(record["reason"], "answered_in_room")

    def test_implicitly_resolved_row_stays_readable(self):
        message = self.send("Please verify the export")
        self.reply(message["event_id"])
        room = c.room_read(self.conn, "p", since_seq=0, actor_id=self.actor)
        shown = next(item for item in room["messages"]
                     if item["event_id"] == message["event_id"])
        self.assertTrue(shown["requires_disposition"])
        self.assertEqual(shown["disposition"]["disposition"], "acknowledged")
        self.assertTrue(shown["disposition"]["implicit"])
        inbox = c.inbox_read(self.conn, "p", self.actor, mark_read=False)
        delivered = next(item for item in inbox["messages"]
                         if item["event_id"] == message["event_id"])
        self.assertTrue(delivered["disposition"]["implicit"])
        # The Control Panel room feed reads room_history, so its badge needs
        # the same annotation.
        history = c.room_history(self.conn, "p", actor_id=self.actor,
                                 actor_type="agent")
        listed = next(item for item in history["messages"]
                      if item["event_id"] == message["event_id"])
        self.assertTrue(listed["requires_disposition"])
        self.assertEqual(listed["disposition"]["reason"], "answered_in_room")

    def test_retraction_implies_not_actionable(self):
        message = self.send("Ignore this after all")
        self.assertEqual(self.pending_ids(), [message["event_id"]])
        c.append_event(self.conn, "p", self.sender, "agent",
                       c.MESSAGE_RETRACTION_EVENT_TYPE,
                       {"message_event_id": message["event_id"],
                        "reason": "sent by mistake"})
        state = self.pending()
        self.assertEqual(state["pending_total"], 0)
        record = state["dispositions"][message["event_id"]]
        self.assertEqual(record["disposition"], "not_actionable")
        self.assertEqual(record["reason"], "retracted")

    def test_done_or_cancelled_task_implies_completed(self):
        done_task = c.task_create(
            self.conn, "p", self.sender, "agent", "Ship the export")["task_id"]
        cancelled_task = c.task_create(
            self.conn, "p", self.sender, "agent", "Drop the old flow")[
                "task_id"]
        open_task = c.task_create(
            self.conn, "p", self.sender, "agent", "Still open")["task_id"]
        done_message = self.send("Finish it", task_id=done_task)
        cancelled_message = self.send("Handle it", task_id=cancelled_task)
        open_message = self.send("Work on it", task_id=open_task)
        # A reply inherits the task carried by the message it answers.
        thread_root = self.send("Thread root", task_id=done_task, mention=False,
                                msg_type="directive")
        threaded = c.room_send(
            self.conn, "p", self.sender, "agent", "and one more here",
            reply_to=thread_root["event_id"])["event"]
        self.assertEqual(
            set(self.pending_ids()),
            {done_message["event_id"], cancelled_message["event_id"],
             open_message["event_id"], thread_root["event_id"]})
        c.task_set_status(self.conn, "p", self.sender, "agent", done_task,
                          "done", reason="shipped")
        c.task_set_status(self.conn, "p", self.sender, "agent",
                          cancelled_task, "cancelled", reason="dropped")
        state = self.pending()
        self.assertEqual(self.pending_ids(), [open_message["event_id"]])
        self.assertEqual(
            state["dispositions"][done_message["event_id"]]["reason"],
            "linked_task_done")
        self.assertEqual(
            state["dispositions"][cancelled_message["event_id"]]["reason"],
            "linked_task_cancelled")
        self.assertIsNone(state["dispositions"][open_message["event_id"]])
        # ``threaded`` is a reply to the sender's own root, so it is group
        # context for this actor and is not tracked at all.
        self.assertNotIn(threaded["event_id"], state["dispositions"])

    def test_only_the_sender_or_a_human_can_retract_a_message(self):
        intruder = "p.worker.kimi"
        c.agent_register(self.conn, "p", "fixture", "human",
                         agent_id=intruder, role="worker", runtime="kimi")
        message = self.send("Still your job")
        c.append_event(self.conn, "p", intruder, "agent",
                       c.MESSAGE_RETRACTION_EVENT_TYPE,
                       {"message_event_id": message["event_id"]})
        self.assertEqual(self.pending_ids(), [message["event_id"]])
        c.append_event(self.conn, "p", "fixture", "human",
                       c.MESSAGE_RETRACTION_EVENT_TYPE,
                       {"message_event_id": message["event_id"]})
        self.assertEqual(self.pending_ids(), [])

    def test_addressed_message_after_the_baseline_stays_pending(self):
        old = self.send("Old assignment")
        self.set_read_cursor(old["seq"])
        fresh = self.send("New assignment")
        state = self.pending(allow_baseline_write=True)
        self.assertEqual([item["event_id"] for item in state["pending"]],
                         [fresh["event_id"]])
        self.assertEqual(state["baseline_seq"], old["seq"])

    def test_explicit_row_beats_every_implicit_rule(self):
        deferred = self.send("Deferred on purpose")
        retracted = self.send("Retracted later")
        c.message_dispose(self.conn, "p", self.actor, "agent",
                          deferred["event_id"], "deferred",
                          note="waiting on review")
        c.message_dispose(self.conn, "p", self.actor, "agent",
                          retracted["event_id"], "acknowledged")
        self.reply(deferred["event_id"])
        c.append_event(self.conn, "p", self.sender, "agent",
                       c.MESSAGE_RETRACTION_EVENT_TYPE,
                       {"message_event_id": retracted["event_id"]})
        state = self.pending()
        self.assertEqual([item["event_id"] for item in state["pending"]],
                         [deferred["event_id"]])
        held = state["dispositions"][deferred["event_id"]]
        self.assertEqual(held["disposition"], "deferred")
        self.assertNotIn("implicit", held)
        closed = state["dispositions"][retracted["event_id"]]
        self.assertEqual(closed["disposition"], "acknowledged")
        self.assertNotIn("implicit", closed)

    def test_explicit_deferred_below_a_baseline_stays_pending(self):
        deferred = self.send("Deferred on purpose")
        later = self.send("Also addressed")
        c.message_dispose(self.conn, "p", self.actor, "agent",
                          deferred["event_id"], "deferred",
                          note="waiting on review")
        c._record_message_disposition_baseline(
            self.conn, "p", self.actor, "agent", later["seq"], "manual",
            note="reconciled by hand")
        state = self.pending()
        self.assertEqual([item["event_id"] for item in state["pending"]],
                         [deferred["event_id"]])
        self.assertEqual(
            state["dispositions"][deferred["event_id"]]["disposition"],
            "deferred")


class UpgradeBaselineTests(DispositionFixture):
    def test_upgrade_baseline_is_recorded_once_from_the_read_cursor(self):
        messages = [self.send("Assignment %d" % index) for index in range(5)]
        self.set_read_cursor(messages[2]["seq"])
        first = c.inbox_read(self.conn, "p", self.actor, mark_read=True)
        self.assertEqual(first["pending_disposition_total"], 2)
        self.assertEqual(first["disposition_baseline_seq"],
                         messages[2]["seq"])
        row = self.baseline_row()
        self.assertEqual(int(row["baseline_seq"]), messages[2]["seq"])
        self.assertEqual(row["source"], "upgrade")
        events = self.baseline_events()
        self.assertEqual(len(events), 1)
        payload = c.json.loads(events[0]["payload"])
        self.assertEqual(payload["resolved_count"], 3)
        self.assertEqual(payload["source"], "upgrade")
        # The cursor has now moved past every message; the baseline must not.
        second = c.inbox_read(self.conn, "p", self.actor, mark_read=True)
        self.assertEqual(second["pending_disposition_total"], 2)
        self.assertEqual(len(self.baseline_events()), 1)
        self.assertEqual(int(self.baseline_row()["baseline_seq"]),
                         messages[2]["seq"])

    def test_read_only_surfaces_never_persist_a_baseline(self):
        messages = [self.send("Assignment %d" % index) for index in range(3)]
        self.set_read_cursor(messages[1]["seq"])
        peek = c.inbox_read(self.conn, "p", self.actor, mark_read=False)
        self.assertEqual(peek["pending_disposition_total"], 1)
        self.assertEqual(peek["disposition_baseline_seq"], messages[1]["seq"])
        c.get_handoff(self.conn, "p", actor_id=self.actor, actor_type="agent")
        c.room_read(self.conn, "p", since_seq=0, actor_id=self.actor)
        self.assertIsNone(self.baseline_row())
        self.assertEqual(self.baseline_events(), [])
        c.inbox_read(self.conn, "p", self.actor, mark_read=True)
        self.assertIsNotNone(self.baseline_row())
        self.assertEqual(len(self.baseline_events()), 1)

    def test_actor_with_its_own_dispositions_is_never_auto_baselined(self):
        first = self.send("First assignment")
        c.message_dispose(self.conn, "p", self.actor, "agent",
                          first["event_id"], "acknowledged")
        self.assertIsNone(self.baseline_row())
        historical = self.send("Historical assignment")
        self.set_read_cursor(historical["seq"])
        state = c.inbox_read(self.conn, "p", self.actor, mark_read=True)
        self.assertIsNone(self.baseline_row())
        self.assertEqual(self.baseline_events(), [])
        self.assertEqual([item["event_id"]
                          for item in state["pending_dispositions"]],
                         [historical["event_id"]])

    def test_baseline_only_moves_forward(self):
        c._record_message_disposition_baseline(
            self.conn, "p", self.actor, "agent", 9, "manual", note="first")
        with self.assertRaises(c.AttaccaError):
            c._record_message_disposition_baseline(
                self.conn, "p", self.actor, "agent", 4, "manual",
                note="backwards")
        unchanged = c._record_message_disposition_baseline(
            self.conn, "p", self.actor, "agent", 9, "manual", note="same")
        self.assertFalse(unchanged["changed"])
        self.assertIsNone(unchanged["event"])
        self.assertEqual(len(self.baseline_events()), 1)
        moved = c._record_message_disposition_baseline(
            self.conn, "p", self.actor, "agent", 12, "manual", note="forward")
        self.assertTrue(moved["changed"])
        self.assertEqual(int(self.baseline_row()["baseline_seq"]), 12)
        self.assertEqual(len(self.baseline_events()), 2)

    def test_vocalfy_shaped_upgrade_leaves_only_genuinely_open_work(self):
        historical = [self.send("Historical assignment %d" % index)
                      for index in range(61)]
        self.set_read_cursor(historical[-1]["seq"])
        open_work = [self.send("Open assignment %d" % index)
                     for index in range(3)]
        state = c.inbox_read(self.conn, "p", self.actor, mark_read=True)
        self.assertEqual(state["pending_disposition_total"], 3)
        self.assertEqual([item["event_id"]
                          for item in state["pending_dispositions"]],
                         [item["event_id"] for item in open_work])
        events = self.baseline_events()
        self.assertEqual(len(events), 1)
        payload = c.json.loads(events[0]["payload"])
        self.assertEqual(payload["baseline_seq"], historical[-1]["seq"])
        self.assertEqual(payload["resolved_count"], 61)
        self.assertEqual(int(self.baseline_row()["baseline_seq"]),
                         historical[-1]["seq"])


class BulkDispositionTests(DispositionFixture):
    def test_bulk_by_ids_writes_one_event_and_reports_skips(self):
        first = self.send("First assignment")
        second = self.send("Second assignment")
        group = self.send("Just chatting", mention=False)
        result = c.message_dispose_bulk(
            self.conn, "p", self.actor, "agent", "acknowledged",
            note="reconciled after the upgrade",
            event_ids=[first["event_id"], second["event_id"],
                       group["event_id"], "ev_missing"])
        self.assertEqual(result["disposed"],
                         [first["event_id"], second["event_id"]])
        self.assertEqual(
            {item["event_id"]: item["reason"] for item in result["skipped"]},
            {group["event_id"]: "group_context",
             "ev_missing": "unknown_message"})
        self.assertEqual(result["remaining_pending"], 0)
        self.assertEqual(len(self.bulk_events()), 1)
        payload = c.json.loads(self.bulk_events()[0]["payload"])
        self.assertEqual(payload["message_event_ids"],
                         [first["event_id"], second["event_id"]])
        self.assertEqual(payload["note"], "reconciled after the upgrade")
        self.assertIsNone(payload["filter"])
        rows = self.conn.execute(
            "SELECT * FROM message_dispositions WHERE project_id='p'"
            " ORDER BY message_event_id").fetchall()
        self.assertEqual({row["actor_id"] for row in rows}, {self.actor})
        self.assertEqual({row["disposition"] for row in rows},
                         {"acknowledged"})

    def test_bulk_validates_disposition_note_and_bounds(self):
        message = self.send("Assignment")
        with self.assertRaises(c.AttaccaError):
            c.message_dispose_bulk(self.conn, "p", self.actor, "agent",
                                   "completed", note="needs a task",
                                   event_ids=[message["event_id"]])
        with self.assertRaises(c.AttaccaError):
            c.message_dispose_bulk(self.conn, "p", self.actor, "agent",
                                   "acknowledged", note="   ",
                                   event_ids=[message["event_id"]])
        with self.assertRaises(c.AttaccaError):
            c.message_dispose_bulk(
                self.conn, "p", self.actor, "agent", "acknowledged",
                note="too many",
                event_ids=["ev_%d" % index for index in range(101)])
        with self.assertRaises(c.AttaccaError):
            c.message_dispose_bulk(
                self.conn, "p", self.actor, "agent", "acknowledged",
                note="ambiguous", event_ids=[message["event_id"]],
                message_filter={"before_seq": 2})
        with self.assertRaises(c.AttaccaError):
            c.message_dispose_bulk(self.conn, "p", self.actor, "agent",
                                   "acknowledged", note="nothing selected")
        with self.assertRaises(c.AttaccaError):
            c.message_dispose_bulk(
                self.conn, "p", self.actor, "agent", "acknowledged",
                note="unsupported filter",
                message_filter={"before_seq": 2, "everything": True})
        self.assertEqual(self.pending_ids(), [message["event_id"]])
        self.assertEqual(self.bulk_events(), [])

    def test_bulk_filter_sets_the_manual_baseline_and_keeps_new_work(self):
        older = [self.send("Older assignment %d" % index) for index in range(3)]
        newer = self.send("Newer assignment")
        result = c.message_dispose_bulk(
            self.conn, "p", self.actor, "agent", "not_actionable",
            note="historical mail, already handled in chat",
            message_filter={"before_seq": older[-1]["seq"]})
        self.assertEqual(result["disposed"],
                         [item["event_id"] for item in older])
        self.assertEqual(result["baseline_seq"], older[-1]["seq"])
        self.assertEqual(result["remaining_pending"], 1)
        self.assertEqual(self.pending_ids(), [newer["event_id"]])
        row = self.baseline_row()
        self.assertEqual(row["source"], "manual")
        self.assertEqual(int(row["baseline_seq"]), older[-1]["seq"])
        with self.assertRaises(c.AttaccaError):
            c.message_dispose_bulk(
                self.conn, "p", self.actor, "agent", "acknowledged",
                note="backwards", message_filter={"before_seq": 1})

    def test_bulk_filter_supports_task_state_and_age(self):
        task_id = c.task_create(self.conn, "p", self.sender, "agent",
                                "Cancelled work")["task_id"]
        linked = self.send("Linked to a task", task_id=task_id)
        loose = self.send("Not linked to any task")
        result = c.message_dispose_bulk(
            self.conn, "p", self.actor, "agent", "acknowledged",
            note="only the task-linked mail",
            message_filter={"before_seq": loose["seq"], "task_state": "any"})
        self.assertEqual(result["disposed"], [linked["event_id"]])
        self.assertEqual(
            [item["reason"] for item in result["skipped"]],
            ["task_state_mismatch"])
        # A narrowing filter closes only what it selected.  Moving the
        # baseline would silently close the row the caller excluded.
        self.assertEqual(result["remaining_pending"], 1)
        self.assertEqual(self.pending_ids(), [loose["event_id"]])
        self.assertEqual(result["baseline_seq"], 0)
        self.assertEqual(int(self.baseline_row()["baseline_seq"]), 0)

    def test_bulk_caps_at_one_hundred_messages(self):
        messages = [self.send("Assignment %d" % index) for index in range(105)]
        result = c.message_dispose_bulk(
            self.conn, "p", self.actor, "agent", "acknowledged",
            note="bounded reconciliation",
            message_filter={"before_seq": messages[-1]["seq"]})
        self.assertEqual(len(result["disposed"]),
                         c.MAX_BULK_MESSAGE_DISPOSITIONS)
        self.assertEqual(len(result["skipped"]), 5)
        self.assertEqual({item["reason"] for item in result["skipped"]},
                         {"bulk_cap_reached"})
        # The baseline covers the whole range, so nothing is left pending and
        # the skipped rows are reconciled rather than silently forgotten.
        self.assertEqual(result["remaining_pending"], 0)
        self.assertEqual(len(self.bulk_events()), 1)

    def test_bulk_never_touches_another_identity(self):
        other = "p.worker.kimi"
        c.agent_register(self.conn, "p", "fixture", "human", agent_id=other,
                         role="worker", runtime="kimi")
        mine = self.send("For codex")
        theirs = c.room_send(self.conn, "p", self.sender, "agent",
                             "For kimi", mentions=[other])["event"]
        c.message_dispose_bulk(
            self.conn, "p", self.actor, "agent", "acknowledged",
            note="mine only", message_filter={"before_seq": theirs["seq"]})
        rows = self.conn.execute(
            "SELECT * FROM message_dispositions WHERE project_id='p'"
        ).fetchall()
        self.assertEqual([(row["actor_id"], row["message_event_id"])
                          for row in rows],
                         [(self.actor, mine["event_id"])])
        self.assertEqual(self.pending_ids(actor=other), [theirs["event_id"]])
        self.assertIsNone(self.baseline_row(actor=other))


    def test_narrowing_filter_may_not_regress_below_the_baseline_check(self):
        older = self.send("Older assignment")
        newer = self.send("Newer assignment")
        c._record_message_disposition_baseline(
            self.conn, "p", self.actor, "agent", newer["seq"], "manual",
            note="already reconciled")
        # A narrowing filter never touches the baseline, so an older
        # before_seq is a selection bound rather than a rejected regression.
        result = c.message_dispose_bulk(
            self.conn, "p", self.actor, "agent", "acknowledged",
            note="task-linked only",
            message_filter={"before_seq": older["seq"], "task_state": "any"})
        self.assertEqual(result["disposed"], [])
        self.assertEqual(int(self.baseline_row()["baseline_seq"]),
                         newer["seq"])


class BulkDispositionInterfaceTests(DispositionFixture):
    def test_mcp_schema_and_dispatch(self):
        tool = next(item for item in c.MCP_TOOLS
                    if item["name"] == "message_dispose_bulk")
        properties = tool["inputSchema"]["properties"]
        for field in ("event_ids", "filter", "disposition", "note"):
            self.assertIn(field, properties)
        self.assertEqual(tool["inputSchema"]["required"],
                         ["disposition", "note"])
        self.assertIn("message_dispose_bulk", c.SYNC_OPERATION_TO_TOOL.values())
        self.assertEqual(
            c.OFFLINE_PROXY_WRITE_OPERATIONS["message_dispose_bulk"],
            "message.dispose_bulk")
        self.assertIn(c.OFFLINE_PROXY_WRITE_OPERATIONS[
            "message_dispose_bulk"], c.SYNC_OPERATION_TO_TOOL)
        first = self.send("First assignment")
        second = self.send("Second assignment")
        session = c.McpSession(
            self.db, default_project="p", actor=self.actor,
            actor_type="agent", detect_cwd=False, owner="fixture",
            preserve_actor_identity=True)
        try:
            result = session.dispatch_tool("message_dispose_bulk", {
                "project": "p", "disposition": "acknowledged",
                "note": "handled in the room",
                "event_ids": [first["event_id"], second["event_id"]]})
        finally:
            if session.conn is not None:
                session.conn.close()
        self.assertEqual(result["disposed"],
                         [first["event_id"], second["event_id"]])
        self.assertEqual(result["remaining_pending"], 0)

    def test_rest_route_is_registered_and_disposes(self):
        message = self.send("Assignment")
        route = next(
            (handler for method, pattern, handler in c.ROUTES
             if method == "POST"
             and pattern.match("/v1/projects/p/messages/dispose-bulk")), None)
        self.assertIs(route, c._r_message_dispose_bulk)
        match = next(pattern.match("/v1/projects/p/messages/dispose-bulk")
                     for method, pattern, handler in c.ROUTES
                     if handler is c._r_message_dispose_bulk)
        replies = []
        conn = self.conn
        actor = self.actor

        class Handler:
            def _actor(self):
                return actor, "agent"

            def _body_json(self):
                return {"disposition": "not_actionable",
                        "note": "already handled",
                        "event_ids": [message["event_id"]]}

            def _conn(self):
                return conn

            def _reply_json(self, status, payload):
                replies.append((status, payload))

        c._r_message_dispose_bulk(Handler(), match, {})
        self.assertEqual(replies[0][0], 200)
        self.assertEqual(replies[0][1]["disposed"], [message["event_id"]])
        self.assertEqual(self.pending_ids(), [])


class DispositionPanelContractTests(unittest.TestCase):
    """The Control Panel exposes bulk resolution and implicit badges."""

    @classmethod
    def setUpClass(cls):
        cls.panel = PANEL.read_text()

    def test_panel_renders_pending_assignments_and_implicit_badges(self):
        self.assertIn('id="pending-dispositions"', self.panel)
        self.assertIn("function dispositionChip(message)", self.panel)
        self.assertIn("auto · ", self.panel)
        self.assertIn("needs disposition", self.panel)
        self.assertIn("renderPendingDispositions(inbox)", self.panel)

    def test_panel_bulk_action_previews_confirms_and_posts(self):
        self.assertIn('data-form="bulk-dispose"', self.panel)
        self.assertIn("Resolve all before #", self.panel)
        self.assertIn('id="bulk-dispose-preview"', self.panel)
        self.assertIn('id="bulk-dispose-note"', self.panel)
        handler_start = self.panel.index('if (kind === "bulk-dispose")')
        handler = self.panel[handler_start:
                             self.panel.index('if (kind === "propose-decision")',
                                              handler_start)]
        self.assertIn("confirm(", handler)
        self.assertIn("/messages/dispose-bulk", handler)
        self.assertIn("before_seq: before", handler)
        self.assertIn("A bulk resolution requires a note", handler)
        for option in ("acknowledged", "not_actionable", "deferred"):
            self.assertIn(option, self.panel)
        self.assertNotIn("claimed and completed are available in bulk",
                         self.panel)


if __name__ == "__main__":
    unittest.main()
