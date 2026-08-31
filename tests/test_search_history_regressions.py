"""Focused regressions for T-38 history-search semantics and privacy."""
import importlib.util
import os
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from tests.test_http import ServerFixture
from tests.test_mcp import McpClient


# Keep event attribution independent from the developer machine running tests.
os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "attacca_search_history_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class SearchHistoryRegressionTest(unittest.TestCase):
    """Exercise the store and both public transports against isolated state."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "search-history.db"
        self.conn = c.connect(self.db)
        hub_root = Path(self.tmp.name) / "hub"
        hub_root.mkdir()
        c.project_init(
            self.conn, "setup", "human", path=str(hub_root),
            project_id="hub", name="Hub")
        self.clients = []
        self.server = None

    def tearDown(self):
        for client in self.clients:
            client.close()
        if self.server is not None:
            self.server.stop()
        c.set_current_owner(None)
        self.conn.close()
        self.tmp.cleanup()

    def _seed_restricted_bridge(self):
        peer_root = Path(self.tmp.name) / "feedback"
        peer_root.mkdir()
        c.project_init(
            self.conn, "setup", "human", path=str(peer_root),
            project_id="feedback", name="Feedback")
        for project, actor, role, runtime in (
                ("hub", "hub.director.codex", "director", "codex"),
                ("hub", "hub.worker.cline", "worker", "cline"),
                ("feedback", "feedback.director.codex", "director", "codex"),
                ("feedback", "feedback.worker.cline", "worker", "cline")):
            c.agent_register(
                self.conn, project, actor, "agent", role=role,
                runtime=runtime)
        c.bridge_add(
            self.conn, "hub", "owner", "human", "feedback",
            participation="directors", peer_participation="directors")
        body = (
            "bridge-secret launch feedback: "
            + "the complete private body must survive transport unchanged; "
            + ("privacy-boundary " * 40)
            + "END-OF-BODY")
        c.room_send(
            self.conn, "hub", "hub.director.codex", "agent", body,
            msg_type="chat", target_project="feedback")
        return body

    def _mcp_client(self, actor):
        client = McpClient(self.db, project="hub", actor=actor)
        self.clients.append(client)
        client.initialize()
        return client

    def test_punctuation_normalization_ands_terms_within_one_record(self):
        expected = c.task_create(
            self.conn, "hub", "owner", "human",
            "Implement the MAGIC-link flow",
            description="Guest checkout must create a durable claim")
        c.task_create(
            self.conn, "hub", "owner", "human",
            "Implement another magic-link flow",
            description="Guest checkout attachment only")
        c.task_create(
            self.conn, "hub", "owner", "human",
            "Implement a claim flow",
            description="Guest checkout attachment only")
        c.room_send(
            self.conn, "hub", "owner", "human",
            "magic appears here, but the other required terms do not")

        result = c.search_project(
            self.conn, "hub", "MAGIC—link, / claim!")

        self.assertEqual(result["query_terms"], ["magic", "link", "claim"])
        self.assertEqual(result["term_semantics"], "AND")
        self.assertEqual(
            [task["task_id"] for task in result["tasks"]],
            [expected["task_id"]])
        self.assertEqual(result["events"], [])

    def test_chat_status_and_directive_matches_keep_full_body_and_attribution(self):
        c.set_current_owner("qa-owner")
        bodies = {}
        for msg_type in ("chat", "status", "directive"):
            body = (
                "history-beacon %s: " % msg_type
                + ("full-body-segment " * 45)
                + "END-%s" % msg_type.upper())
            bodies[msg_type] = body
            c.room_send(
                self.conn, "hub", "qa-speaker", "agent", body,
                msg_type=msg_type)

        result = c.search_project(self.conn, "hub", "history / beacon")
        messages = {
            event["msg_type"]: event for event in result["events"]
            if event["event_type"] == "room.message"
        }

        self.assertEqual(set(messages), set(bodies))
        for msg_type, body in bodies.items():
            event = messages[msg_type]
            self.assertEqual(event["body"], body)
            self.assertTrue(event["line"].endswith(body))
            self.assertEqual(event["actor_type"], "agent")
            self.assertEqual(event["owner"], "qa-owner")
            self.assertEqual(
                event["attribution"]["ledger_actor_id"], "qa-speaker")
            self.assertEqual(
                event["attribution"]["run_by_user"], "qa-owner")

    def test_store_search_enforces_bridge_participation_on_both_sides(self):
        body = self._seed_restricted_bridge()

        hub_allowed = c.search_project(
            self.conn, "hub", "bridge / secret",
            actor_id="hub.director.codex", actor_type="agent")
        hub_denied = c.search_project(
            self.conn, "hub", "bridge / secret",
            actor_id="hub.worker.cline", actor_type="agent")
        peer_allowed = c.search_project(
            self.conn, "feedback", "bridge / secret",
            actor_id="feedback.director.codex", actor_type="agent")
        peer_denied = c.search_project(
            self.conn, "feedback", "bridge / secret",
            actor_id="feedback.worker.cline", actor_type="agent")

        self.assertEqual([event["body"] for event in hub_allowed["events"]],
                         [body])
        self.assertEqual(hub_allowed["events"][0]["mirrored_to"],
                         ["feedback"])
        self.assertEqual(hub_denied["events"], [])
        self.assertEqual([event["body"] for event in peer_allowed["events"]],
                         [body])
        self.assertEqual(peer_allowed["events"][0]["origin_project"], "hub")
        self.assertEqual(peer_denied["events"], [])

    def test_mcp_and_rest_propagate_actor_privacy_and_complete_results(self):
        body = self._seed_restricted_bridge()

        allowed_mcp = self._mcp_client("codex")
        denied_mcp = self._mcp_client("cline")
        is_error, _, mcp_allowed = allowed_mcp.call_tool(
            "search", {"query": "bridge / secret"})
        self.assertFalse(is_error)
        is_error, _, mcp_denied = denied_mcp.call_tool(
            "search", {"query": "bridge / secret"})
        self.assertFalse(is_error)
        self.assertEqual(mcp_allowed["query_terms"], ["bridge", "secret"])
        self.assertEqual(mcp_allowed["term_semantics"], "AND")
        self.assertEqual([event["body"] for event in mcp_allowed["events"]],
                         [body])
        self.assertIn("attribution", mcp_allowed["events"][0])
        self.assertEqual(mcp_denied["events"], [])

        self.server = ServerFixture(self.db)
        query = urllib.parse.urlencode({"q": "bridge / secret"})
        status, rest_allowed, _ = self.server.request(
            "GET", "/v1/projects/hub/search?" + query,
            headers={"X-Attacca-Actor": "hub.director.codex",
                     "X-Attacca-Actor-Type": "agent"})
        self.assertEqual(status, 200)
        status, rest_denied, _ = self.server.request(
            "GET", "/v1/projects/hub/search?" + query,
            headers={"X-Attacca-Actor": "hub.worker.cline",
                     "X-Attacca-Actor-Type": "agent"})
        self.assertEqual(status, 200)
        self.assertEqual(rest_allowed["query_terms"], ["bridge", "secret"])
        self.assertEqual(rest_allowed["term_semantics"], "AND")
        self.assertEqual([event["body"] for event in rest_allowed["events"]],
                         [body])
        self.assertIn("attribution", rest_allowed["events"][0])
        self.assertEqual(rest_denied["events"], [])


if __name__ == "__main__":
    unittest.main()
