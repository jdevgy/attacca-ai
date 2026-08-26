"""Regression contract for project-room group visibility and attention.

Every participation-visible room message is shared context for every member of
that conversation.  ``mentions`` and ``reply_to`` select the expected
responder; they are not privacy filters.  The only visibility boundary tested
here is explicit bridge participation.
"""

import importlib.util
import os
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
