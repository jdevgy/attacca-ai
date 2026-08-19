"""MCP protocol tests: drive the stdio server as a real client would."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Isolate tests from any machine identity (~/.continuity/identity.json)
os.environ["CONTINUITY_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "continuity.py")

spec = importlib.util.spec_from_file_location("continuity", ROOT / "continuity.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class McpClient:
    """Minimal newline-delimited JSON-RPC client over a subprocess."""

    def __init__(self, db, project=None, actor=None, extra_env=None):
        env = dict(os.environ)
        env.pop("CONTINUITY_ACTOR", None)
        env.pop("CONTINUITY_PROJECT", None)
        env["CONTINUITY_DB"] = str(db)
        if project:
            env["CONTINUITY_PROJECT"] = project
        if actor:
            env["CONTINUITY_ACTOR"] = actor
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
        self.assertEqual(resp["result"]["serverInfo"]["name"], "continuity")
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
                         "task_report", "update_handoff", "decision_propose",
                         "check_freshness", "list_projects"):
            self.assertIn(expected, names)

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
        self.assertEqual(board["tasks"][0]["claimed_by"], "alice")
        is_err, _, room = bob.call_tool("room_read", {})
        self.assertIn("claimed the shared task",
                      [m["body"] for m in room["messages"]])
        # Bob cannot steal the claim.
        is_err, text, _ = bob.call_tool("task_claim", {"task_id": task["task_id"]})
        self.assertTrue(is_err)
        self.assertIn("not claimable", text)

    def test_stale_context_warning_via_mcp(self):
        alice = self.client(actor="alice")
        alice.initialize()
        _, _, handoff = alice.call_tool("get_handoff", {})
        _, _, task = alice.call_tool("task_create", {"title": "work"})
        _, _, _ = alice.call_tool("task_claim", {"task_id": task["task_id"]})
        # Someone else advances project context after alice's briefing.
        bob = self.client(actor="bob")
        bob.initialize()
        bob.call_tool("update_handoff", {"objective": "new objective"})
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
        client = self.client()  # no CONTINUITY_ACTOR
        client.initialize(client_name="My IDE Tool")
        _, _, sent = client.call_tool("room_send", {"body": "who am I"})
        self.assertEqual(sent["event"]["actor_id"], "my-ide-tool")

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
        _, _, handoff = alice.call_tool("update_handoff", {"what_changed": "solo"})
        self.assertNotIn("stale_context_warning", handoff)

    def test_stale_writer_stays_stale_until_rebrief(self):
        alice = self.client(actor="alice")
        alice.initialize()
        alice.call_tool("get_handoff", {})
        bob = self.client(actor="bob")
        bob.initialize()
        bob.call_tool("update_handoff", {"objective": "bob's new direction"})
        # alice overwrites the handoff while stale: warned, and STAYS stale
        _, _, first = alice.call_tool("update_handoff", {"risks": "some risk"})
        self.assertIn("stale_context_warning", first)
        _, _, second = alice.call_tool("update_handoff", {"blockers": "none"})
        self.assertIn("stale_context_warning", second)
        # re-briefing clears it
        alice.call_tool("get_handoff", {})
        _, _, third = alice.call_tool("update_handoff", {"notes": "ok"})
        self.assertNotIn("stale_context_warning", third)

    def test_batch_request_gets_array_response(self):
        client = self.client(actor="batcher")
        client.initialize()
        client.send_raw(json.dumps([
            {"jsonrpc": "2.0", "id": 101, "method": "ping"},
            {"jsonrpc": "2.0", "method": "notifications/whatever"},
            {"jsonrpc": "2.0", "id": 102, "method": "tools/call",
             "params": {"name": "continuity_status", "arguments": {}}},
        ]))
        batch = json.loads(client.proc.stdout.readline())
        self.assertIsInstance(batch, list)
        self.assertEqual({r["id"] for r in batch}, {101, 102})
        # server still healthy afterwards
        self.assertEqual(client.request("ping")["result"], {})

    def test_invalid_utf8_does_not_kill_server(self):
        env = dict(os.environ, CONTINUITY_DB=str(self.db),
                   CONTINUITY_PROJECT="proj", CONTINUITY_ACTOR="bin")
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
        alice = self.client(actor="claude_director",
                            extra_env={"CONTINUITY_OWNER": "jack"})
        alice.initialize(client_name="claude-code")
        alice.call_tool("room_send", {"body": "ping bob",
                                      "mentions": ["mia.codex_director"]})
        bob = self.client(actor="codex_director",
                          extra_env={"CONTINUITY_OWNER": "mia"})
        bob.initialize(client_name="codex-cli")
        is_err, _, inbox = bob.call_tool("check_inbox", {})
        self.assertFalse(is_err)
        self.assertEqual([m["body"] for m in inbox["messages"]], ["ping bob"])
        self.assertEqual(inbox["messages"][0]["actor"], "jack.claude_director")
        # cursor: second check is empty
        _, _, again = bob.call_tool("check_inbox", {})
        self.assertEqual(again["messages"], [])
        # both agents were auto-registered with runtime + owner
        _, _, agents = bob.call_tool("agent_list", {})
        by_id = {a["agent_id"]: a for a in agents["agents"]}
        self.assertEqual(by_id["jack.claude_director"]["runtime"], "claude-code")
        self.assertEqual(by_id["jack.claude_director"]["owner"], "jack")
        self.assertEqual(by_id["mia.codex_director"]["owner"], "mia")
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
        conn.close()
        client = self.client(actor="messenger")
        client.initialize()
        is_err, _, sent = client.call_tool("room_send", {
            "body": "hello other project", "project": "proj2"})
        self.assertFalse(is_err)
        self.assertEqual(sent["delivered_to"], "proj2")
        _, _, projects = client.call_tool("list_projects", {})
        self.assertEqual({p["project_id"] for p in projects["projects"]},
                         {"proj", "proj2"})
        _, _, room2 = client.call_tool("room_read", {"project": "proj2"})
        self.assertEqual(room2["messages"][-1]["body"], "hello other project")
        self.assertEqual(room2["messages"][-1]["origin_project"], "proj")


if __name__ == "__main__":
    unittest.main()
