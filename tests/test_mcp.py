"""MCP protocol tests: drive the stdio server as a real client would."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Isolate tests from any machine identity (~/.attacca/identity.json)
os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "attacca.py")

spec = importlib.util.spec_from_file_location("attacca", ROOT / "attacca.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class McpClient:
    """Minimal newline-delimited JSON-RPC client over a subprocess."""

    def __init__(self, db, project=None, actor=None, extra_env=None):
        env = dict(os.environ)
        env.pop("ATTACCA_ACTOR", None)
        env.pop("ATTACCA_PROJECT", None)
        env["ATTACCA_DB"] = str(db)
        if project:
            env["ATTACCA_PROJECT"] = project
        if actor:
            env["ATTACCA_ACTOR"] = actor
        env.update(extra_env or {})
        self.proc = subprocess.Popen(
            [sys.executable, SCRIPT, "mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env)
        self.next_id = 1

    def send_raw(self, text):
        self.proc.stdin.write(text + "\n")
        self.proc.stdin.flush()

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.send_raw(json.dumps(msg))

    def request(self, method, params=None, msg_id=None):
        mid = self.next_id if msg_id is None else msg_id
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": mid, "method": method}
        if params is not None:
            msg["params"] = params
        self.send_raw(json.dumps(msg))
        line = self.proc.stdout.readline()
        assert line, "server closed stdout unexpectedly"
        resp = json.loads(line)
        assert resp.get("id") == mid, "response id mismatch: %r" % resp
        return resp

    def initialize(self, protocol="2025-06-18", client_name="unittest-client"):
        resp = self.request("initialize", {
            "protocolVersion": protocol, "capabilities": {},
            "clientInfo": {"name": client_name, "version": "0"}})
        self.notify("notifications/initialized")
        return resp

    def call_tool(self, name, arguments=None):
        resp = self.request("tools/call",
                            {"name": name, "arguments": arguments or {}})
        result = resp["result"]
        text = result["content"][0]["text"]
        parsed = None
        if not result.get("isError"):
            parsed = json.loads(text)
        return result.get("isError", False), text, parsed

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        finally:
            self.proc.stderr.close()
            self.proc.stdout.close()


class McpTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "mcp.db"
        conn = c.connect(self.db)
        proj = Path(self.tmp.name) / "repo"
        proj.mkdir()
        c.project_init(conn, "setup", "human", path=str(proj),
                       project_id="proj", name="MCP Test Project")
        conn.close()
        self.clients = []

    def client(self, **kw):
        client = McpClient(self.db, project="proj", **kw)
        self.clients.append(client)
        return client

    def tearDown(self):
        for client in self.clients:
            client.close()
        self.tmp.cleanup()

    def test_initialize_echoes_supported_protocol(self):
        client = self.client(actor="a1")
        resp = client.initialize(protocol="2024-11-05")
        self.assertEqual(resp["result"]["protocolVersion"], "2024-11-05")
        self.assertEqual(resp["result"]["serverInfo"]["name"], "attacca")
        self.assertIn("instructions", resp["result"])
        self.assertIn("tools", resp["result"]["capabilities"])

    def test_initialize_unknown_protocol_falls_back(self):
        client = self.client(actor="a1")
        resp = client.initialize(protocol="1999-01-01")
        self.assertEqual(resp["result"]["protocolVersion"], c.MCP_DEFAULT_PROTOCOL)

    def test_tools_list_schemas(self):
        client = self.client(actor="a1")
        client.initialize()
        resp = client.request("tools/list")
        tools = resp["result"]["tools"]
        self.assertGreaterEqual(len(tools), 15)
        names = set()
        for tool in tools:
            self.assertRegex(tool["name"], r"^[a-zA-Z0-9_-]{1,64}$")
            self.assertNotIn(tool["name"], names)
            names.add(tool["name"])
            self.assertTrue(tool["description"])
            self.assertEqual(tool["inputSchema"]["type"], "object")
            for req in tool["inputSchema"].get("required", []):
                self.assertIn(req, tool["inputSchema"]["properties"])
        for expected in ("get_handoff", "room_send", "room_read", "task_claim",
                         "task_report", "update_handoff",
                         "get_identity_handoff", "update_identity_handoff",
                         "identity_handoff_history", "decision_propose",
                         "check_freshness", "list_projects", "bridge_remove"):
            self.assertIn(expected, names)

    def test_bridge_remove_via_mcp_is_bidirectional_and_repeat_safe(self):
        conn = c.connect(self.db)
        other_root = Path(self.tmp.name) / "peer"
        other_root.mkdir()
        c.project_init(conn, "setup", "human", path=str(other_root),
                       project_id="peer", name="Peer")
        c.bridge_add(conn, "proj", "setup", "human", "peer")
        c.agent_register(
            conn, "proj", "setup", "human",
            agent_id="proj.director.codex", role="director",
            runtime="codex")
        conn.close()
        client = self.client(actor="proj.director.codex")
        client.initialize(client_name="codex")
        is_err, _, removed = client.call_tool(
            "bridge_remove", {"other_project": "peer"})
        self.assertFalse(is_err)
        self.assertEqual(set(removed["removed"]), {"proj", "peer"})
        conn = c.connect(self.db)
        self.assertEqual(c.bridge_list(conn, "proj")["bridges"], [])
        self.assertEqual(c.bridge_list(conn, "peer")["bridges"], [])
        conn.close()
        is_err, text, _ = client.call_tool(
            "bridge_remove", {"other_project": "peer"})
        self.assertTrue(is_err)
        self.assertIn("not bridged", text)

    def test_tool_calls_and_shared_state(self):
        alice = self.client(actor="alice")
        alice.initialize()
        is_err, _, task = alice.call_tool("task_create", {
            "title": "Shared task", "expected_scope": ["src/**"]})
        self.assertFalse(is_err)
        is_err, _, claim = alice.call_tool("task_claim", {"task_id": task["task_id"]})
        self.assertFalse(is_err)
        alice.call_tool("room_send", {"body": "claimed the shared task",
                                      "msg_type": "claim",
                                      "task_id": task["task_id"]})
        # A second, completely separate MCP session sees everything.
        bob = self.client(actor="bob")
        bob.initialize()
        is_err, _, board = bob.call_tool("task_list", {})
        self.assertFalse(is_err)
        self.assertEqual(board["tasks"][0]["claimed_by"],
                         "proj.unassigned.alice")
        is_err, _, room = bob.call_tool("room_read", {})
        self.assertIn("claimed the shared task",
                      [m["body"] for m in room["messages"]])
        # Bob cannot steal the claim.
        is_err, text, _ = bob.call_tool("task_claim", {"task_id": task["task_id"]})
        self.assertTrue(is_err)
        self.assertIn("not claimable", text)

    def test_task_report_evidence_verdict_vocabulary_over_mcp(self):
        alice = self.client(actor="alice")
        alice.initialize()
        resp = alice.request("tools/list")
        described = next(tool["description"] for tool in resp["result"]["tools"]
                         if tool["name"] == "task_report")
        # the vocabulary is documented where a reporting AI actually reads it
        self.assertIn("pass/passed/ok/success/succeeded/green/done", described)
        self.assertIn("fail/failed/error/red/broken", described)
        self.assertIn("skipped/skip/blocked/waived/partial/unknown", described)
        self.assertIn("'PASS exit0'", described)
        self.assertIn("'27/27 PASS'", described)

        def report(title, evidence):
            _, _, task = alice.call_tool("task_create", {"title": title})
            alice.call_tool("task_claim", {"task_id": task["task_id"]})
            is_err, text, result = alice.call_tool("task_report", {
                "task_id": task["task_id"], "summary": "ran the suite",
                "evidence": evidence, "requested_state": "done"})
            self.assertFalse(is_err, text)
            _, _, shown = alice.call_tool(
                "task_show", {"task_id": task["task_id"], "detail": "full"})
            return result, shown["last_report"]["evidence"]

        # the descriptive strings from #907/#908 now finish the task
        for value in ("PASS exit0", "27/27 PASS", "27/27 passed"):
            with self.subTest(result=value):
                result, stored = report("descriptive pass: %s" % value, [
                    {"kind": "test", "name": "unittest discover",
                     "result": value}])
                self.assertEqual(result["status"], "done")
                self.assertEqual(result["verification_status"], "verified")
                self.assertEqual(result["warnings"], [])
                self.assertNotIn("accepted_results", result)
                self.assertEqual(stored[0]["result"], value)

        for value in ("26/27 PASS", "FAIL 2 errors"):
            with self.subTest(result=value):
                result, stored = report("descriptive failure: %s" % value, [
                    {"kind": "test", "name": "unittest discover",
                     "result": value}])
                self.assertEqual(result["status"], "review")
                self.assertEqual(result["verification_status"], "failed")
                self.assertFalse(any("is not a recognized verdict" in w
                                     for w in result["warnings"]))
                self.assertEqual(stored[0]["result"], value)

        result, stored = report("boolean pass", [
            {"kind": "test", "name": "unittest discover", "result": True}])
        self.assertEqual(result["verification_status"], "verified")
        self.assertIs(stored[0]["result"], True)

        result, stored = report("unreadable verdict", [
            {"kind": "test", "name": "unittest discover", "result": "meh"}])
        self.assertEqual(result["status"], "review")
        self.assertEqual(result["verification_status"], "unverified")
        self.assertIn(
            "evidence[0].result 'meh' is not a recognized verdict; use one "
            "of pass/fail/skipped/blocked/waived/partial (case-insensitive; "
            "'PASS exit0' and '27/27 PASS' style values are accepted)",
            result["warnings"])
        self.assertIn("skipped", result["accepted_results"])
        self.assertFalse(any("no credible passing evidence" in w
                             for w in result["warnings"]))
        self.assertEqual(stored[0]["result"], "meh")

    def test_stale_context_warning_via_mcp(self):
        alice = self.client(actor="alice")
        alice.initialize()
        _, _, handoff = alice.call_tool("get_handoff", {})
        _, _, task = alice.call_tool("task_create", {"title": "work"})
        _, _, _ = alice.call_tool("task_claim", {"task_id": task["task_id"]})
        # Someone else advances project context after alice's briefing.
        bob = self.client(actor="bob")
        bob.initialize()
        bob.call_tool(
            "update_identity_handoff", {"objective": "new objective"})
        # Alice's next write carries a drift warning.
        is_err, _, report = alice.call_tool("task_report", {
            "task_id": task["task_id"], "summary": "done"})
        self.assertFalse(is_err)
        self.assertIn("stale_context_warning", report)
        # check_freshness agrees
        _, _, fresh = alice.call_tool("check_freshness", {
            "context_version": handoff["context_version"]})
        self.assertTrue(fresh["stale"])

    def test_actor_defaults_to_client_info(self):
        client = self.client()  # no ATTACCA_ACTOR
        client.initialize(client_name="My IDE Tool")
        _, _, sent = client.call_tool("room_send", {"body": "who am I"})
        self.assertEqual(sent["event"]["actor_id"],
                         "proj.unassigned.my-ide-tool")

    def test_unscoped_project_list_reports_effective_ai_identity_for_setup(self):
        client = self.client(
            actor="codex_director", extra_env={"ATTACCA_OWNER": "jack"})
        client.initialize(client_name="codex")
        is_err, _, projects = client.call_tool("list_projects", {})
        self.assertFalse(is_err)
        self.assertEqual(projects["you"]["actor_id"], "codex_director")
        self.assertEqual(projects["you"]["actor_type"], "agent")
        self.assertEqual(projects["you"]["runtime"], "codex")
        self.assertEqual(projects["you"]["owner"], "jack")
        self.assertTrue(projects["you"]["identity_pending"])

    def test_notifications_get_no_response_and_ping_works(self):
        client = self.client(actor="a1")
        client.initialize()
        client.notify("notifications/cancelled", {"requestId": 42})
        client.notify("notifications/progress", {})
        resp = client.request("ping")
        self.assertEqual(resp["result"], {})

    def test_id_zero_is_a_valid_request_id(self):
        client = self.client(actor="a1")
        resp = client.request("ping", msg_id=0)
        self.assertEqual(resp["id"], 0)

    def test_unknown_method_and_parse_error(self):
        client = self.client(actor="a1")
        client.initialize()
        resp = client.request("bogus/method")
        self.assertEqual(resp["error"]["code"], -32601)
        client.send_raw("this is not json")
        line = client.proc.stdout.readline()
        err = json.loads(line)
        self.assertEqual(err["error"]["code"], -32700)
        # server still alive afterwards
        resp = client.request("ping")
        self.assertEqual(resp["result"], {})

    def test_unknown_tool_is_tool_error_not_crash(self):
        client = self.client(actor="a1")
        client.initialize()
        is_err, text, _ = client.call_tool("no_such_tool", {})
        self.assertTrue(is_err)
        self.assertIn("unknown tool", text)

    def test_clean_exit_on_eof(self):
        client = self.client(actor="a1")
        client.initialize()
        client.proc.stdin.close()
        self.assertEqual(client.proc.wait(timeout=10), 0)

    def test_no_spurious_stale_warning_on_own_bump(self):
        alice = self.client(actor="alice")
        alice.initialize()
        alice.call_tool("get_handoff", {})
        _, _, task = alice.call_tool("task_create", {"title": "solo work"})
        _, _, claim = alice.call_tool("task_claim", {"task_id": task["task_id"]})
        self.assertNotIn("stale_context_warning", claim)
        is_err, _, report = alice.call_tool("task_report", {
            "task_id": task["task_id"], "summary": "done solo",
            "requested_state": "done"})
        self.assertFalse(is_err)
        # her own done-bump must not read as drift, now or on the next write
        self.assertNotIn("stale_context_warning", report)
        _, _, handoff = alice.call_tool(
            "update_identity_handoff", {"what_changed": "solo"})
        self.assertNotIn("stale_context_warning", handoff)

    def test_exact_identity_revision_stays_stale_until_rebrief(self):
        alice = self.client(actor="alice")
        alice.initialize()
        alice.call_tool("get_handoff", {})
        bob = self.client(actor="bob")
        bob.initialize()
        is_err, _, bob_write = bob.call_tool(
            "update_identity_handoff", {"objective": "bob's new direction"})
        self.assertFalse(is_err)

        # Bob's independent identity handoff version does not stale Alice's v0.
        is_err, _, first = alice.call_tool(
            "update_identity_handoff", {"risks": "some risk"})
        self.assertFalse(is_err)
        self.assertEqual(first["handoff_version"], 1)
        self.assertNotEqual(first["handoff_actor"],
                            bob_write["handoff_actor"])

        # Two processes intentionally selecting Alice's exact actor share its
        # version. A peer briefed at v1 must conflict after Alice advances v2.
        alice_peer = self.client(actor="alice")
        alice_peer.initialize()
        _, _, peer_brief = alice_peer.call_tool("get_handoff", {})
        self.assertEqual(peer_brief["identity_handoff_version"], 1)
        is_err, _, second = alice.call_tool(
            "update_identity_handoff", {"blockers": "none"})
        self.assertFalse(is_err)
        self.assertEqual(second["handoff_version"], 2)
        is_err, stale, _ = alice_peer.call_tool(
            "update_identity_handoff", {"notes": "stale peer"})
        self.assertTrue(is_err)
        self.assertIn("identity handoff conflict", stale)
        is_err, stale_again, _ = alice_peer.call_tool(
            "update_identity_handoff", {"notes": "still stale"})
        self.assertTrue(is_err)
        self.assertIn("identity handoff conflict", stale_again)
        # Re-briefing supplies the new expected version and permits the write.
        alice_peer.call_tool("get_handoff", {})
        is_err, _, third = alice_peer.call_tool(
            "update_identity_handoff", {"notes": "ok"})
        self.assertFalse(is_err)
        self.assertEqual(third["updated_fields"], ["notes"])

    def test_worker_owns_an_exact_handoff_over_mcp(self):
        conn = c.connect(self.db)
        try:
            c.agent_register(conn, "proj", "director", "agent",
                             role="director", runtime="test")
            c.agent_register(conn, "proj", "worker", "agent",
                             role="worker", runtime="test")
            c.set_lead_director(
                conn, "proj", "admin", "human", "director")
        finally:
            conn.close()
        worker = self.client(actor="worker")
        worker.initialize()
        _, _, brief = worker.call_tool("get_handoff", {})
        is_err, _, written = worker.call_tool(
            "update_identity_handoff",
            {"notes": "worker exact continuity",
             "expected_handoff_version": brief["identity_handoff_version"]})
        self.assertFalse(is_err)
        self.assertEqual(written["handoff_actor"],
                         brief["identity_handoff_actor"])
        self.assertEqual(written["handoff_version"], 1)
        _, _, current = worker.call_tool("get_handoff", {})
        self.assertEqual(current["identity_handoff"]["notes"],
                         "worker exact continuity")
        # The shared project handoff stays Director-only over MCP.
        is_err, refused, _ = worker.call_tool(
            "update_handoff", {"notes": "worker shared overwrite"})
        self.assertTrue(is_err)
        self.assertIn("registered Director", refused)

    def test_director_owns_the_shared_project_handoff_over_mcp(self):
        director = self.client(actor="director")
        director.initialize()
        # The first call registers this session's exact canonical actor; the
        # shared handoff then depends only on its registered workspace role.
        _, _, who = director.call_tool("attacca_status", {})
        conn = c.connect(self.db)
        try:
            conn.execute(
                "UPDATE agents SET role='director' WHERE project_id='proj'"
                " AND agent_id=?", (who["you"]["actor_id"],))
            conn.commit()
        finally:
            conn.close()
        _, _, brief = director.call_tool("get_handoff", {})
        self.assertIsNone(brief["handoff_actor"])
        self.assertEqual(brief["handoff_scope"], "project")
        is_err, message, written = director.call_tool(
            "update_handoff", {"objective": "one shared objective"})
        self.assertFalse(is_err, message)
        self.assertIsNone(written["handoff_actor"])
        self.assertEqual(written["handoff_version"], 1)
        # A stale shared version is rejected, and the identity version is
        # tracked independently of it.
        is_err, stale, _ = director.call_tool(
            "update_handoff", {"objective": "stale shared",
                               "expected_handoff_version": 0})
        self.assertTrue(is_err)
        self.assertIn("shared handoff conflict", stale)
        is_err, _, identity = director.call_tool(
            "update_identity_handoff", {"objective": "my own continuity"})
        self.assertFalse(is_err)
        self.assertEqual(identity["handoff_version"], 1)

        worker = self.client(actor="worker")
        worker.initialize()
        _, _, seen = worker.call_tool("get_handoff", {})
        self.assertEqual(seen["handoff"]["objective"], "one shared objective")
        self.assertIsNone(seen["identity_handoff"]["objective"])

    def test_batch_request_gets_array_response(self):
        client = self.client(actor="batcher")
        client.initialize()
        client.send_raw(json.dumps([
            {"jsonrpc": "2.0", "id": 101, "method": "ping"},
            {"jsonrpc": "2.0", "method": "notifications/whatever"},
            {"jsonrpc": "2.0", "id": 102, "method": "tools/call",
             "params": {"name": "attacca_status", "arguments": {}}},
        ]))
        batch = json.loads(client.proc.stdout.readline())
        self.assertIsInstance(batch, list)
        self.assertEqual({r["id"] for r in batch}, {101, 102})
        # server still healthy afterwards
        self.assertEqual(client.request("ping")["result"], {})

    def test_invalid_utf8_does_not_kill_server(self):
        env = dict(os.environ, ATTACCA_DB=str(self.db),
                   ATTACCA_PROJECT="proj", ATTACCA_ACTOR="bin")
        proc = subprocess.Popen(
            [sys.executable, SCRIPT, "mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env)  # binary pipes
        try:
            proc.stdin.write(b'\xff\xfe garbage bytes \xff\n')
            proc.stdin.write(json.dumps(
                {"jsonrpc": "2.0", "id": 7, "method": "ping"}).encode() + b"\n")
            proc.stdin.flush()
            first = json.loads(proc.stdout.readline())
            self.assertEqual(first["error"]["code"], -32700)
            second = json.loads(proc.stdout.readline())
            self.assertEqual(second, {"jsonrpc": "2.0", "id": 7, "result": {}})
        finally:
            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=10), 0)
            proc.stdout.close()
            proc.stderr.close()

    def test_inbox_autoregister_and_owner_via_mcp(self):
        # A legacy selector is accepted only after it exactly identifies a
        # current registered actor; arbitrary future strings must not create
        # unreachable addressed mail.
        bob = self.client(actor="codex_director",
                          extra_env={"ATTACCA_OWNER": "mia"})
        bob.initialize(client_name="codex-cli")
        bob.call_tool("agent_list", {})  # first scoped call registers Bob
        alice = self.client(actor="claude_director",
                            extra_env={"ATTACCA_OWNER": "jack"})
        alice.initialize(client_name="claude-code")
        alice.call_tool("room_send", {"body": "ping bob",
                                      "mentions": ["mia.codex_director"]})
        is_err, _, inbox = bob.call_tool("check_inbox", {})
        self.assertFalse(is_err)
        self.assertEqual([m["body"] for m in inbox["messages"]], ["ping bob"])
        self.assertEqual(inbox["messages"][0]["actor"],
                         "proj.unassigned.claude")
        # cursor: second check is empty
        _, _, again = bob.call_tool("check_inbox", {})
        self.assertEqual(again["messages"], [])
        # both agents were auto-registered with runtime + owner
        _, _, agents = bob.call_tool("agent_list", {})
        by_id = {a["agent_id"]: a for a in agents["agents"]}
        self.assertEqual(by_id["proj.unassigned.claude"]["runtime"],
                         "claude")
        self.assertEqual(by_id["proj.unassigned.claude"]["owner"], "jack")
        self.assertEqual(by_id["proj.unassigned.codex"]["owner"], "mia")
        # events carry the owner key
        conn = c.connect(self.db)
        row = conn.execute(
            "SELECT owner FROM events WHERE event_type='room.message'").fetchone()
        conn.close()
        self.assertEqual(row["owner"], "jack")

    def test_cross_project_messaging_via_mcp(self):
        conn = c.connect(self.db)
        c.project_init(conn, "setup", "human",
                       path=str(Path(self.tmp.name) / "repo2"),
                       project_id="proj2", name="Second Project")
        c.bridge_add(conn, "proj", "setup", "human", "proj2")
        conn.close()
        client = self.client(actor="messenger")
        client.initialize()
        is_err, _, sent = client.call_tool("room_send", {
            "body": "hello other project", "project": "proj2"})
        self.assertFalse(is_err)
        self.assertEqual(sent["delivered_to"], "proj")
        self.assertEqual(sent["mirrored_to_bridged_projects"], ["proj2"])
        _, _, projects = client.call_tool("list_projects", {})
        self.assertEqual({p["project_id"] for p in projects["projects"]},
                         {"proj", "proj2"})
        _, _, room2 = client.call_tool("room_read", {"project": "proj2"})
        self.assertEqual(room2["messages"][-1]["body"], "hello other project")
        self.assertEqual(room2["messages"][-1]["origin_project"], "proj")


if __name__ == "__main__":
    unittest.main()
