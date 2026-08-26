"""Regression contract for project-room group visibility and attention.

Every participation-visible room message is shared context for every member of
that conversation.  ``mentions`` and ``reply_to`` select the expected
responder; they are not privacy filters.  The only visibility boundary tested
here is explicit bridge participation.
"""

import importlib.util
import json
import os
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from pathlib import Path


os.environ["ATTACCA_OWNER"] = ""
ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_group_room_contract_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class GroupRoomContractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.conn = c.connect(self.root / "attacca.db")

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _project(self, project_id):
        checkout = self.root / project_id
        checkout.mkdir()
        c.project_init(
            self.conn, "owner", "human", path=str(checkout),
            project_id=project_id, name=project_id)
        return checkout

    def _agent(self, project_id, role, runtime):
        actor = c.canonical_agent_id(project_id, role, runtime)
        c.agent_register(
            self.conn, project_id, actor, "agent", role=role,
            runtime=runtime)
        return actor

    @staticmethod
    def _messages_by_body(result):
        return {message["body"]: message for message in result["messages"]}

    def test_pre_registration_everyone_broadcast_is_delivered_with_body(self):
        project = "pre-registration"
        self._project(project)
        c.room_send(
            self.conn, project, "existing-human", "human",
            "broadcast created before this AI registered", msg_type="chat")

        newcomer = self._agent(project, "worker", "codex")
        inbox = c.inbox_read(
            self.conn, project, newcomer, mark_read=False,
            actor_type="agent")

        self.assertEqual(
            [message["body"] for message in inbox["messages"]],
            ["broadcast created before this AI registered"])
        message = inbox["messages"][0]
        self.assertTrue(message["broadcast_to_everyone"])
        self.assertTrue(message["addressed_to_you"])
        self.assertFalse(message["group_context"])
        self.assertEqual(inbox["unread_total"], 1)

    def test_directed_messages_remain_visible_group_context_to_others(self):
        project = "directed-group"
        self._project(project)
        sender = self._agent(project, "director", "claude")
        target = self._agent(project, "worker", "codex")
        observer = self._agent(project, "advisor", "kimi")

        target_question = c.room_send(
            self.conn, project, target, "agent", "question from target")
        c.room_send(
            self.conn, project, sender, "agent", "mention for target",
            mentions=[target])
        c.room_send(
            self.conn, project, sender, "agent", "reply for target",
            reply_to=target_question["event"]["event_id"])

        target_inbox = self._messages_by_body(c.inbox_read(
            self.conn, project, target, mark_read=False,
            actor_type="agent"))
        observer_inbox = self._messages_by_body(c.inbox_read(
            self.conn, project, observer, mark_read=False,
            actor_type="agent"))
        sender_inbox = self._messages_by_body(c.inbox_read(
            self.conn, project, sender, mark_read=False,
            actor_type="agent"))

        self.assertEqual(
            set(target_inbox), {"mention for target", "reply for target"})
        for body in ("mention for target", "reply for target"):
            self.assertTrue(target_inbox[body]["addressed_to_you"])
            self.assertFalse(target_inbox[body]["group_context"])

        self.assertEqual(
            set(observer_inbox),
            {"question from target", "mention for target", "reply for target"})
        for body in ("mention for target", "reply for target"):
            self.assertFalse(observer_inbox[body]["addressed_to_you"])
            self.assertFalse(observer_inbox[body]["broadcast_to_everyone"])
            self.assertTrue(observer_inbox[body]["group_context"])

        # An author does not receive its own rows as unread, but still receives
        # other participants' group-wide messages.
        self.assertEqual(set(sender_inbox), {"question from target"})

    def test_unrouted_chat_and_directive_are_everyone_actionable(self):
        project = "everyone-routing"
        self._project(project)
        sender = self._agent(project, "director", "claude")
        reader = self._agent(project, "worker", "codex")

        c.room_send(
            self.conn, project, sender, "agent", "chat for everyone",
            msg_type="chat")
        c.room_send(
            self.conn, project, sender, "agent", "directive for everyone",
            msg_type="directive")
        c.room_send(
            self.conn, project, sender, "agent", "status for group context",
            msg_type="status")

        messages = self._messages_by_body(c.inbox_read(
            self.conn, project, reader, mark_read=False,
            actor_type="agent"))
        self.assertEqual(set(messages), {
            "chat for everyone", "directive for everyone",
            "status for group context",
        })
        for body in ("chat for everyone", "directive for everyone"):
            self.assertTrue(messages[body]["broadcast_to_everyone"])
            self.assertTrue(messages[body]["addressed_to_you"])
            self.assertFalse(messages[body]["group_context"])
        status = messages["status for group context"]
        self.assertFalse(status["broadcast_to_everyone"])
        self.assertFalse(status["addressed_to_you"])
        self.assertTrue(status["group_context"])

    def test_peek_consume_and_raw_cursor_pagination_have_no_gaps_or_duplicates(self):
        project = "cursor-contract"
        self._project(project)
        sender = self._agent(project, "director", "claude")
        reader = self._agent(project, "worker", "codex")

        c.room_send(self.conn, project, sender, "agent", "first")
        c.room_send(self.conn, project, reader, "agent", "reader own row")
        c.room_send(self.conn, project, sender, "agent", "second")
        c.room_send(self.conn, project, sender, "agent", "third")

        first_peek = c.inbox_read(
            self.conn, project, reader, mark_read=False, limit=1,
            actor_type="agent")
        repeated_peek = c.inbox_read(
            self.conn, project, reader, mark_read=False, limit=1,
            actor_type="agent")
        self.assertEqual(
            [message["seq"] for message in first_peek["messages"]],
            [message["seq"] for message in repeated_peek["messages"]])
        self.assertEqual(first_peek["read_cursor"], 0)
        self.assertEqual(repeated_peek["read_cursor"], 0)

        seen_bodies = []
        seen_sequences = []
        cursors = []
        for _ in range(10):
            page = c.inbox_read(
                self.conn, project, reader, mark_read=True, limit=1,
                actor_type="agent")
            seen_bodies.extend(message["body"] for message in page["messages"])
            seen_sequences.extend(message["seq"] for message in page["messages"])
            cursors.append(page["read_cursor"])
            if not page["may_have_more"]:
                break
        else:
            self.fail("group inbox cursor did not converge")

        self.assertEqual(seen_bodies, ["first", "second", "third"])
        self.assertEqual(len(seen_sequences), len(set(seen_sequences)))
        self.assertEqual(cursors, sorted(set(cursors)))
        drained = c.inbox_read(
            self.conn, project, reader, mark_read=True, limit=1,
            actor_type="agent")
        self.assertEqual(drained["messages"], [])
        self.assertEqual(drained["read_cursor"], cursors[-1])

    def test_poll_status_flags_directed_to_other_and_everyone_group_mail(self):
        project = "poll-group"
        self._project(project)
        sender = self._agent(project, "director", "claude")
        other_target = self._agent(project, "advisor", "kimi")
        reader = self._agent(project, "worker", "codex")

        c.room_send(
            self.conn, project, sender, "agent", "directed to another AI",
            mentions=[other_target])
        directed = c.poll_status(
            self.conn, project, actor_id=reader, actor_type="agent")
        self.assertTrue(directed["mail"]["has_new_mail"])
        self.assertEqual(directed["mail"]["unread_total"], 1)

        consumed = c.inbox_read(
            self.conn, project, reader, mark_read=True, actor_type="agent")
        self.assertEqual(
            [message["body"] for message in consumed["messages"]],
            ["directed to another AI"])
        self.assertFalse(c.poll_status(
            self.conn, project, actor_id=reader,
            actor_type="agent")["mail"]["has_new_mail"])

        c.room_send(
            self.conn, project, sender, "agent", "new everyone directive",
            msg_type="directive")
        everyone = c.poll_status(
            self.conn, project, actor_id=reader, actor_type="agent")
        self.assertTrue(everyone["mail"]["has_new_mail"])
        self.assertEqual(everyone["mail"]["unread_total"], 1)

    def test_bridge_participation_is_visibility_boundary_not_mentions(self):
        alpha = "bridge-alpha"
        beta = "bridge-beta"
        self._project(alpha)
        self._project(beta)
        alpha_sender = self._agent(alpha, "director", "claude")
        beta_target = self._agent(beta, "director", "codex")
        beta_observer = self._agent(beta, "advisor", "kimi")
        beta_denied = self._agent(beta, "worker", "cline")

        c.bridge_add(
            self.conn, alpha, "owner", "human", beta,
            participation="all", peer_participation="directors_advisors")
        c.room_send(
            self.conn, alpha, alpha_sender, "agent",
            "bridge message mentioning only the director",
            mentions=[beta_target], target_project=beta)

        target = c.inbox_read(
            self.conn, beta, beta_target, mark_read=False,
            actor_type="agent")
        observer = c.inbox_read(
            self.conn, beta, beta_observer, mark_read=False,
            actor_type="agent")
        denied = c.inbox_read(
            self.conn, beta, beta_denied, mark_read=False,
            actor_type="agent")

        self.assertEqual(
            [message["body"] for message in target["messages"]],
            ["bridge message mentioning only the director"])
        self.assertTrue(target["messages"][0]["addressed_to_you"])
        self.assertEqual(
            [message["body"] for message in observer["messages"]],
            ["bridge message mentioning only the director"])
        self.assertFalse(observer["messages"][0]["addressed_to_you"])
        self.assertTrue(observer["messages"][0]["group_context"])
        self.assertEqual(denied["messages"], [])
        self.assertEqual(denied["unread_total"], 0)

        self.assertIn(
            "bridge message mentioning only the director",
            [message["body"] for message in c.room_read(
                self.conn, beta, actor_id=beta_observer,
                actor_type="agent")["messages"]])
        self.assertNotIn(
            "bridge message mentioning only the director",
            [message["body"] for message in c.room_read(
                self.conn, beta, actor_id=beta_denied,
                actor_type="agent")["messages"]])

    def test_handoff_reports_group_totals_without_consuming_inbox(self):
        project = "handoff-peek"
        self._project(project)
        sender = self._agent(project, "director", "claude")
        reader = self._agent(project, "worker", "codex")
        other = self._agent(project, "advisor", "kimi")
        c.room_send(self.conn, project, sender, "agent", "for everyone")
        c.room_send(
            self.conn, project, sender, "agent", "for the other actor",
            mentions=[other])

        def cursor_row():
            return self.conn.execute(
                "SELECT last_read_seq FROM inbox_cursors"
                " WHERE project_id=? AND actor_id=?", (project, reader)
            ).fetchone()

        self.assertIsNone(cursor_row())
        first = c.get_handoff(
            self.conn, project, actor_id=reader, actor_type="agent")
        second = c.get_handoff(
            self.conn, project, actor_id=reader, actor_type="agent")
        expected = {
            "unread_total": 2,
            "unread_addressed_to_you": 1,
            "unread_everyone": 1,
            "unread_group_context": 1,
            "may_have_more": False,
            "messages_include_all_visible": True,
        }
        for key, value in expected.items():
            self.assertEqual(first["your_inbox"][key], value)
            self.assertEqual(second["your_inbox"][key], value)
        self.assertIsNone(cursor_row())

    def test_legacy_aliases_resolve_mentions_replies_and_self_rows(self):
        project = "alias-routing"
        self._project(project)
        reader = self._agent(project, "worker", "codex")
        sender = self._agent(project, "director", "claude")
        legacy = "old-owner.codex-worker"
        self.conn.execute(
            "INSERT INTO actor_aliases (project_id, legacy_actor_id,"
            " canonical_actor_id, migrated_at) VALUES (?,?,?,?)",
            (project, legacy, reader, c.now_iso()))

        original = c.room_send(
            self.conn, project, legacy, "agent", "legacy author's question")
        c.room_send(
            self.conn, project, sender, "agent", "mention via old identity",
            mentions=[legacy])
        c.room_send(
            self.conn, project, sender, "agent", "reply via old identity",
            reply_to=original["event"]["event_id"])

        messages = self._messages_by_body(c.inbox_read(
            self.conn, project, reader, mark_read=False,
            actor_type="agent"))
        self.assertEqual(
            set(messages), {"mention via old identity", "reply via old identity"})
        self.assertTrue(messages["mention via old identity"]["mentioned_to_you"])
        self.assertFalse(messages["mention via old identity"]["reply_to_you"])
        self.assertTrue(messages["reply via old identity"]["reply_to_you"])
        self.assertFalse(messages["reply via old identity"]["mentioned_to_you"])
        self.assertTrue(messages["reply via old identity"]["directed_to_you"])

    def test_room_read_exposes_attention_metadata_for_every_member(self):
        project = "room-routing"
        self._project(project)
        sender = self._agent(project, "director", "claude")
        target = self._agent(project, "worker", "codex")
        observer = self._agent(project, "advisor", "kimi")
        c.room_send(
            self.conn, project, sender, "agent", "targeted room message",
            mentions=[target])
        c.room_send(
            self.conn, project, sender, "agent", "everyone room directive",
            msg_type="directive")

        target_room = self._messages_by_body(c.room_read(
            self.conn, project, actor_id=target, actor_type="agent"))
        observer_room = self._messages_by_body(c.room_read(
            self.conn, project, actor_id=observer, actor_type="agent"))
        self.assertTrue(target_room["targeted room message"]["directed_to_you"])
        self.assertFalse(target_room["targeted room message"]["group_context"])
        self.assertFalse(
            observer_room["targeted room message"]["directed_to_you"])
        self.assertTrue(observer_room["targeted room message"]["group_context"])
        for room in (target_room, observer_room):
            everyone = room["everyone room directive"]
            self.assertTrue(everyone["broadcast_to_everyone"])
            self.assertTrue(everyone["addressed_to_you"])

    def test_hidden_rows_are_scanned_without_hiding_later_visible_mail(self):
        alpha = "hidden-alpha"
        beta = "hidden-beta"
        self._project(alpha)
        self._project(beta)
        alpha_sender = self._agent(alpha, "director", "claude")
        beta_worker = self._agent(beta, "worker", "codex")
        c.bridge_add(
            self.conn, alpha, "owner", "human", beta,
            participation="all", peer_participation="directors")
        c.room_send(
            self.conn, alpha, alpha_sender, "agent", "hidden bridge row",
            target_project=beta)
        c.room_send(
            self.conn, beta, "local-human", "human", "visible local row")
        rows = self.conn.execute(
            "SELECT seq,payload FROM events WHERE project_id=?"
            " AND event_type='room.message' ORDER BY seq", (beta,)).fetchall()
        sequences = {json.loads(row["payload"])["body"]: row["seq"]
                     for row in rows}

        page = c.inbox_read(
            self.conn, beta, beta_worker, mark_read=True, limit=1,
            actor_type="agent")
        self.assertEqual(
            [message["body"] for message in page["messages"]],
            ["visible local row"])
        self.assertEqual(page["unread_total"], 1)
        self.assertEqual(page["read_cursor"], sequences["visible local row"])
        self.assertEqual(
            page["scanned_through_seq"], sequences["visible local row"])
        self.assertFalse(page["may_have_more"])
        self.assertEqual(c.inbox_read(
            self.conn, beta, beta_worker, mark_read=True, limit=1,
            actor_type="agent")["messages"], [])

    def test_nonmutating_peek_scans_past_self_rows_to_visible_mail(self):
        project = "peek-past-self"
        self._project(project)
        reader = self._agent(project, "worker", "codex")
        sender = self._agent(project, "director", "claude")
        c.room_send(self.conn, project, reader, "agent", "self one")
        c.room_send(self.conn, project, reader, "agent", "self two")
        c.room_send(self.conn, project, sender, "agent", "visible after self")

        first = c.inbox_read(
            self.conn, project, reader, mark_read=False, limit=2,
            actor_type="agent")
        second = c.inbox_read(
            self.conn, project, reader, mark_read=False, limit=2,
            actor_type="agent")
        self.assertEqual(
            [message["body"] for message in first["messages"]],
            ["visible after self"])
        self.assertEqual(first, second)
        self.assertEqual(first["read_cursor"], 0)
        self.assertFalse(first["may_have_more"])

    def test_initial_room_snapshot_advertises_older_history_without_bad_cursor(self):
        project = "room-latest-page"
        self._project(project)
        sender = self._agent(project, "director", "claude")
        reader = self._agent(project, "worker", "codex")
        for index in range(5):
            c.room_send(
                self.conn, project, sender, "agent", "room-%d" % index)

        latest = c.room_read(
            self.conn, project, limit=2, actor_id=reader,
            actor_type="agent")
        self.assertEqual(
            [message["body"] for message in latest["messages"]],
            ["room-3", "room-4"])
        self.assertTrue(latest["older_messages_available"])
        self.assertFalse(latest["may_have_more"])
        self.assertIn("since_seq=0", latest["hint"])

        seen = []
        cursor = 0
        while True:
            page = c.room_read(
                self.conn, project, since_seq=cursor, limit=2,
                actor_id=reader, actor_type="agent")
            seen.extend(message["body"] for message in page["messages"])
            cursor = page["next_since_seq"]
            if not page["may_have_more"]:
                break
        self.assertEqual(seen, ["room-%d" % index for index in range(5)])

    def test_poll_peek_classifies_mail_and_preserves_cursor_with_more(self):
        project = "poll-peek"
        self._project(project)
        sender = self._agent(project, "director", "claude")
        reader = self._agent(project, "worker", "codex")
        other = self._agent(project, "advisor", "kimi")
        c.room_send(
            self.conn, project, sender, "agent", "everyone first",
            msg_type="directive")
        c.room_send(
            self.conn, project, sender, "agent", "directed elsewhere",
            mentions=[other])
        for index in range(199):
            c.room_send(
                self.conn, project, sender, "agent", "context-%03d" % index,
                msg_type="status")

        def cursor_row():
            return self.conn.execute(
                "SELECT last_read_seq FROM inbox_cursors"
                " WHERE project_id=? AND actor_id=?", (project, reader)
            ).fetchone()

        self.assertIsNone(cursor_row())
        first = c.poll_status(
            self.conn, project, actor_id=reader, actor_type="agent")["mail"]
        second = c.poll_status(
            self.conn, project, actor_id=reader, actor_type="agent")["mail"]
        self.assertEqual(first, second)
        self.assertEqual(first["unread_total"], 200)
        self.assertEqual(first["unread_addressed"], 1)
        self.assertEqual(first["unread_direct"], 0)
        self.assertEqual(first["unread_everyone"], 1)
        self.assertEqual(first["unread_group_context"], 199)
        self.assertTrue(first["may_have_more"])
        self.assertTrue(first["messages_include_all_visible"])
        self.assertTrue(first["has_new_mail"])
        self.assertIsNone(cursor_row())

    def test_rest_poll_query_cannot_override_header_actor_identity(self):
        project = "rest-poll-identity"
        self._project(project)
        sender = self._agent(project, "director", "claude")
        reader = self._agent(project, "worker", "codex")
        target = self._agent(project, "advisor", "kimi")
        c.room_send(
            self.conn, project, sender, "agent", "target only",
            mentions=[target])

        server = c.AttaccaServer(("127.0.0.1", 0), self.root / "attacca.db")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            query = urllib.parse.urlencode({
                "actor": target,
                "actor_type": "human",
            })
            url = "http://127.0.0.1:%d/v1/projects/%s/poll-status?%s" % (
                server.server_port, urllib.parse.quote(project, safe=""), query)
            request = urllib.request.Request(url, headers={
                "X-Attacca-Actor": reader,
                "X-Attacca-Actor-Type": "agent",
            })
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.load(response)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(payload["mail"]["unread_total"], 1)
        self.assertEqual(payload["mail"]["unread_direct"], 0)
        self.assertEqual(payload["mail"]["unread_group_context"], 1)
        self.assertIsNone(self.conn.execute(
            "SELECT last_read_seq FROM inbox_cursors"
            " WHERE project_id=? AND actor_id=?", (project, reader)
        ).fetchone())


if __name__ == "__main__":
    unittest.main()
