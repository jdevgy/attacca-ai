"""Hosted-server tests: REST API + MCP over streamable HTTP.

Starts one real `continuity.py serve` subprocess per test class and drives it
with stdlib urllib — the same wire surface Claude Code / Codex / curl use.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

# Isolate tests from any machine identity (~/.continuity/identity.json)
os.environ["CONTINUITY_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "continuity.py")

spec = importlib.util.spec_from_file_location("continuity", ROOT / "continuity.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class ServerFixture:
    def __init__(self, db):
        env = dict(os.environ)
        for k in ("CONTINUITY_ACTOR", "CONTINUITY_PROJECT"):
            env.pop(k, None)
        env["CONTINUITY_DB"] = str(db)
        self.proc = subprocess.Popen(
            [sys.executable, SCRIPT, "serve", "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        line = self.proc.stdout.readline()
        match = re.search(r"http://127\.0\.0\.1:(\d+)", line)
        assert match, "server did not report its port: %r" % line
        self.base = "http://127.0.0.1:%s" % match.group(1)

    def request(self, method, path, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read()
                parsed = json.loads(raw) if raw else None
                return resp.status, parsed, dict(resp.headers)
        except urllib.error.HTTPError as err:
            raw = err.read()
            parsed = json.loads(raw) if raw else None
            return err.code, parsed, dict(err.headers)

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.proc.stdout.close()
        self.proc.stderr.close()


class HttpTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "http.db"
        conn = c.connect(cls.db)
        proj = Path(cls.tmp.name) / "repo"
        proj.mkdir()
        c.project_init(conn, "setup", "human", path=str(proj),
                       project_id="hub", name="Hub")
        conn.close()
        cls.server = ServerFixture(cls.db)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tmp.cleanup()

    def rest(self, method, path, body=None, actor=None):
        headers = {"X-Continuity-Actor": actor} if actor else {}
        return self.server.request(method, path, body, headers)

    # -- REST ---------------------------------------------------------------

    def test_healthz(self):
        status, body, _ = self.rest("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

    def test_plugin_distribution_endpoints(self):
        import urllib.request as rq
        import zipfile as zf
        import io as iolib
        with rq.urlopen(self.server.base + "/", timeout=10) as resp:
            landing = resp.read().decode()
        self.assertIn("/install.sh", landing)
        with rq.urlopen(self.server.base + "/install.sh", timeout=10) as resp:
            script = resp.read().decode()
        self.assertIn('BASE="%s"' % self.server.base, script)
        self.assertIn("plugin.zip", script)
        with rq.urlopen(self.server.base + "/plugin.zip", timeout=10) as resp:
            blob = resp.read()
        archive = zf.ZipFile(iolib.BytesIO(blob))
        names = set(archive.namelist())
        for required in ("continuity.py", ".claude-plugin/plugin.json",
                         "plugin-mcp.json", "commands/brief.md"):
            self.assertIn(required, names)
        # the downloaded plugin is pre-wired to the server it came from
        cfg = json.loads(archive.read("plugin-mcp.json"))
        self.assertEqual(cfg["mcpServers"]["continuity"]["env"]["CONTINUITY_URL"],
                         self.server.base)

    def test_unknown_route_404_and_bad_json_400(self):
        status, body, _ = self.rest("GET", "/v1/nope")
        self.assertEqual(status, 404)
        req = urllib.request.Request(self.server.base + "/v1/projects",
                                     data=b"{not json", method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
            self.fail("expected 400")
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code, 400)

    def test_project_create_without_root(self):
        status, body, _ = self.rest("POST", "/v1/projects",
                                    {"project_id": "cloudy", "name": "Cloud Only"},
                                    actor="admin")
        self.assertEqual(status, 200)
        self.assertIsNone(body["root_path"])
        status, body, _ = self.rest("GET", "/v1/projects")
        self.assertIn("cloudy", [p["project_id"] for p in body["projects"]])

    def test_room_over_rest_with_actor_attribution(self):
        status, sent, _ = self.rest("POST", "/v1/projects/hub/room",
                                    {"body": "rest hello", "msg_type": "chat"},
                                    actor="rest_bot")
        self.assertEqual(status, 200)
        self.assertEqual(sent["event"]["actor_id"], "rest_bot")
        status, room, _ = self.rest("GET", "/v1/projects/hub/room")
        self.assertIn("rest hello", [m["body"] for m in room["messages"]])
        # cursor polling over REST
        status, empty, _ = self.rest(
            "GET", "/v1/projects/hub/room?since_seq=%d" % room["next_since_seq"])
        self.assertEqual(empty["messages"], [])

    def test_task_lifecycle_and_claim_guard_over_rest(self):
        _, task, _ = self.rest("POST", "/v1/projects/hub/tasks",
                               {"title": "http task",
                                "expected_scope": ["src/http/**"]},
                               actor="alice")
        tid = task["task_id"]
        status, claim, _ = self.rest("POST", "/v1/projects/hub/tasks/%s/claim" % tid,
                                     {}, actor="alice")
        self.assertEqual(status, 200)
        self.assertEqual(claim["claimed_by"], "alice")
        # bob cannot report alice's active claim
        status, err, _ = self.rest("POST", "/v1/projects/hub/tasks/%s/report" % tid,
                                   {"summary": "hijack"}, actor="bob")
        self.assertEqual(status, 400)
        self.assertIn("claimant", err["error"])
        status, report, _ = self.rest(
            "POST", "/v1/projects/hub/tasks/%s/report" % tid,
            {"summary": "done over rest",
             "evidence": [{"kind": "test", "result": "pass"}],
             "requested_state": "done"}, actor="alice")
        self.assertEqual(status, 200)
        _, shown, _ = self.rest("GET", "/v1/projects/hub/tasks/%s" % tid)
        self.assertEqual(shown["status"], "done")

    def test_handoff_freshness_verify_and_sync(self):
        _, before, _ = self.rest("GET", "/v1/projects/hub/handoff")
        _, updated, _ = self.rest("POST", "/v1/projects/hub/handoff",
                                  {"objective": "serve the world"}, actor="alice")
        _, handoff, _ = self.rest("GET", "/v1/projects/hub/handoff")
        self.assertEqual(handoff["handoff"]["objective"], "serve the world")
        _, fresh, _ = self.rest(
            "GET", "/v1/projects/hub/freshness?context_version=%d"
            % before["context_version"])
        self.assertTrue(fresh["stale"])
        _, verify, _ = self.rest("GET", "/v1/projects/hub/verify")
        self.assertTrue(verify["ok"], verify["problems"])
        _, sync, _ = self.rest("GET", "/v1/projects/hub/events?after=0&limit=5")
        self.assertTrue(sync["events"])
        self.assertEqual(sync["events"][0]["seq"], 1)
        self.assertIsInstance(sync["events"][0]["payload"], dict)

    # -- MCP over streamable HTTP -------------------------------------------

    def mcp(self, msg, session=None, actor=None, project="hub"):
        headers = {"Accept": "application/json, text/event-stream"}
        if session:
            headers["Mcp-Session-Id"] = session
        if actor:
            headers["X-Continuity-Actor"] = actor
        if project:
            headers["X-Continuity-Project"] = project
        return self.server.request("POST", "/mcp", msg, headers)

    def mcp_init(self, actor=None, client="http-test"):
        status, resp, headers = self.mcp(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": client, "version": "0"}}},
            actor=actor)
        return status, resp, headers.get("Mcp-Session-Id")

    def test_mcp_initialize_and_session(self):
        status, resp, sid = self.mcp_init(actor="mcp_alice")
        self.assertEqual(status, 200)
        self.assertTrue(sid)
        self.assertEqual(resp["result"]["serverInfo"]["name"], "continuity")
        status, tools, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session=sid)
        self.assertGreaterEqual(len(tools["result"]["tools"]), 15)

    def test_mcp_notification_202_get_405_delete_204(self):
        _, _, sid = self.mcp_init(actor="x")
        status, body, _ = self.mcp(
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            session=sid)
        self.assertEqual(status, 202)
        self.assertIsNone(body)
        status, _, headers = self.server.request("GET", "/mcp")
        self.assertEqual(status, 405)
        self.assertIn("POST", headers.get("Allow", ""))
        req_status, _, _ = self.server.request(
            "DELETE", "/mcp", headers={"Mcp-Session-Id": sid})
        self.assertEqual(req_status, 204)

    def test_mcp_tool_call_and_shared_state_with_rest(self):
        _, _, sid = self.mcp_init(actor="mcp_worker")
        status, resp, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
             "params": {"name": "room_send",
                        "arguments": {"body": "hello from MCP over HTTP"}}},
            session=sid, actor="mcp_worker")
        self.assertEqual(status, 200)
        self.assertFalse(resp["result"]["isError"])
        sent = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(sent["event"]["actor_id"], "mcp_worker")
        _, room, _ = self.rest("GET", "/v1/projects/hub/room?limit=100")
        self.assertIn("hello from MCP over HTTP",
                      [m["body"] for m in room["messages"]])

    def test_mcp_sessionless_request_still_works(self):
        status, resp, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
             "params": {"name": "continuity_status", "arguments": {}}},
            actor="ephemeral")
        self.assertEqual(status, 200)
        body = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(body["you"]["actor_id"], "ephemeral")

    def test_mcp_batch_and_parse_error(self):
        _, _, sid = self.mcp_init(actor="batcher")
        status, resp, _ = self.mcp(
            [{"jsonrpc": "2.0", "id": 21, "method": "ping"},
             {"jsonrpc": "2.0", "method": "notifications/x"},
             {"jsonrpc": "2.0", "id": 22, "method": "tools/list"}],
            session=sid)
        self.assertEqual(status, 200)
        self.assertIsInstance(resp, list)
        self.assertEqual({r["id"] for r in resp}, {21, 22})
        req = urllib.request.Request(self.server.base + "/mcp",
                                     data=b"not json at all", method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
            self.fail("expected 400")
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code, 400)
            self.assertEqual(json.loads(err.read())["error"]["code"], -32700)

    def test_mcp_drift_guard_state_survives_across_posts(self):
        _, _, sid = self.mcp_init(actor="stateful")
        status, resp, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 31, "method": "tools/call",
             "params": {"name": "get_handoff", "arguments": {}}},
            session=sid, actor="stateful")
        self.assertFalse(resp["result"]["isError"])
        # someone else advances the context via REST
        self.rest("POST", "/v1/projects/hub/handoff",
                  {"objective": "moved underneath"}, actor="other")
        _, task, _ = self.rest("POST", "/v1/projects/hub/tasks",
                               {"title": "drift probe"}, actor="stateful")
        status, resp, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 32, "method": "tools/call",
             "params": {"name": "task_claim",
                        "arguments": {"task_id": task["task_id"]}}},
            session=sid, actor="stateful")
        claim = json.loads(resp["result"]["content"][0]["text"])
        self.assertIn("stale_context_warning", claim)

    def test_mcp_project_header_selects_project(self):
        self.rest("POST", "/v1/projects",
                  {"project_id": "sidecar", "name": "Sidecar"}, actor="admin")
        status, resp, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 41, "method": "tools/call",
             "params": {"name": "continuity_status", "arguments": {}}},
            actor="router", project="sidecar")
        body = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(body["project"], "sidecar")


class HttpHardeningTestCase(unittest.TestCase):
    """Regressions for the HTTP-layer review findings."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "hard.db"
        conn = c.connect(cls.db)
        proj = Path(cls.tmp.name) / "repo"
        proj.mkdir()
        c.project_init(conn, "setup", "human", path=str(proj),
                       project_id="hub", name="Hub")
        conn.close()
        cls.server = ServerFixture(cls.db)
        cls.host = cls.server.base.split("//")[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tmp.cleanup()

    def _conn(self):
        import http.client
        host, port = self.host.split(":")
        return http.client.HTTPConnection(host, int(port), timeout=10)

    def test_mcp_session_shared_across_live_connections(self):
        # The critical finding: a session's SQLite conn was bound to the first
        # request thread. Park connection A while B uses the same session.
        conn_a, conn_b = self._conn(), self._conn()
        try:
            init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "a", "version": "0"}}}
            conn_a.request("POST", "/mcp", json.dumps(init),
                           {"Content-Type": "application/json",
                            "X-Continuity-Project": "hub",
                            "X-Continuity-Actor": "threaded"})
            resp = conn_a.getresponse()
            sid = resp.getheader("Mcp-Session-Id")
            resp.read()
            self.assertTrue(sid)
            call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "continuity_status", "arguments": {}}}
            headers = {"Content-Type": "application/json", "Mcp-Session-Id": sid}
            conn_a.request("POST", "/mcp", json.dumps(call), headers)
            resp = conn_a.getresponse()
            first = json.loads(resp.read())
            self.assertFalse(first["result"]["isError"])
            # conn_a stays OPEN (its handler thread is alive/parked) while a
            # different connection/thread reuses the session.
            call["id"] = 3
            conn_b.request("POST", "/mcp", json.dumps(call), headers)
            resp = conn_b.getresponse()
            second = json.loads(resp.read())
            self.assertFalse(second["result"].get("isError"),
                             second["result"]["content"][0]["text"])
        finally:
            conn_a.close()
            conn_b.close()

    def test_keep_alive_survives_404_with_body(self):
        conn = self._conn()
        try:
            conn.request("POST", "/v1/projects/hub/log",
                         json.dumps({"hello": "world"}),
                         {"Content-Type": "application/json"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 404)
            resp.read()
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)  # was 501 garbage before fix
            self.assertTrue(json.loads(resp.read())["ok"])
        finally:
            conn.close()

    def test_keep_alive_survives_mcp_delete_with_body(self):
        conn = self._conn()
        try:
            conn.request("DELETE", "/mcp", json.dumps({"why": "not"}),
                         {"Content-Type": "application/json",
                          "Mcp-Session-Id": "deadbeef" * 4})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 204)
            resp.read()
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
        finally:
            conn.close()

    def test_chunked_body_rejected_with_411(self):
        conn = self._conn()
        try:
            conn.putrequest("POST", "/mcp")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Transfer-Encoding", "chunked")
            conn.endheaders()
            payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
            conn.send(b"%x\r\n%s\r\n0\r\n\r\n" % (len(payload), payload))
            resp = conn.getresponse()
            self.assertEqual(resp.status, 411)
        finally:
            conn.close()

    def test_url_encoded_project_id_reaches_route(self):
        status, body, _ = self.server.request("GET", "/v1/projects/hu%62/handoff")
        self.assertEqual(status, 200)
        self.assertEqual(body["project"], "hub")

    def test_api_project_id_is_slugified(self):
        status, body, _ = self.server.request(
            "POST", "/v1/projects", {"project_id": "My Fancy App!!"})
        self.assertEqual(status, 200)
        self.assertEqual(body["project_id"], "my-fancy-app")

    def test_head_and_options(self):
        conn = self._conn()
        try:
            conn.request("HEAD", "/healthz")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read(), b"")
            self.assertGreater(int(resp.getheader("Content-Length")), 0)
            conn.request("OPTIONS", "/v1/projects")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 204)
            self.assertIn("POST", resp.getheader("Allow"))
            resp.read()
        finally:
            conn.close()

    def test_batch_of_invalid_elements_gets_error_entries(self):
        status, resp, _ = self.server.request(
            "POST", "/mcp", [1, "nonsense"],
            {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        self.assertEqual(len(resp), 2)
        for entry in resp:
            self.assertEqual(entry["error"]["code"], -32600)

    def test_unknown_session_id_gets_404(self):
        status, body, _ = self.server.request(
            "POST", "/mcp",
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"Mcp-Session-Id": "0" * 32})
        self.assertEqual(status, 404)
        self.assertIn("re-initialize", body["error"])


class AutoRegisterTestCase(unittest.TestCase):
    """Zero-setup: X-Continuity-Root auto-registers projects server-side."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "auto.db"
        c.connect(cls.db).close()
        cls.server = ServerFixture(cls.db)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tmp.cleanup()

    def _status_via_root(self, root):
        status, resp, _ = self.server.request(
            "POST", "/mcp",
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "continuity_status", "arguments": {}}},
            {"X-Continuity-Root": str(root), "X-Continuity-Actor": "auto"})
        assert status == 200, (status, resp)
        body = resp["result"]["content"][0]["text"]
        assert not resp["result"].get("isError"), body
        return json.loads(body)

    def test_root_header_registers_and_reuses_project(self):
        root = Path(self.tmp.name) / "shiny-app"
        root.mkdir()
        first = self._status_via_root(root)
        self.assertEqual(first["project"], "shiny-app")
        again = self._status_via_root(root)
        self.assertEqual(again["project"], "shiny-app")
        # nested dir maps to the same project
        nested = root / "src" / "deep"
        nested.mkdir(parents=True)
        self.assertEqual(self._status_via_root(nested)["project"], "shiny-app")

    def test_same_basename_different_root_gets_suffixed_id(self):
        a = Path(self.tmp.name) / "alpha" / "api"
        b = Path(self.tmp.name) / "beta" / "api"
        a.mkdir(parents=True)
        b.mkdir(parents=True)
        first = self._status_via_root(a)["project"]
        second = self._status_via_root(b)["project"]
        self.assertEqual(first, "api")
        self.assertEqual(second, "api-2")
        # stable on re-contact
        self.assertEqual(self._status_via_root(b)["project"], "api-2")


class ConnectProxyTestCase(unittest.TestCase):
    """The `connect` stdio<->HTTP proxy the plugin spawns."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "proxy.db"
        c.connect(cls.db).close()
        cls.server = ServerFixture(cls.db)
        cls.proj = Path(cls.tmp.name) / "proxied-app"
        cls.proj.mkdir()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tmp.cleanup()

    def _proxy(self, url=None, cwd=None):
        env = dict(os.environ)
        env.pop("CLAUDE_PROJECT_DIR", None)
        env.pop("CONTINUITY_PROJECT", None)
        env["CONTINUITY_DB"] = str(self.db)
        env["CONTINUITY_URL"] = url or self.server.base
        env["CONTINUITY_ACTOR"] = "proxy_actor"
        env["CONTINUITY_AUTOSTART"] = "0"
        return subprocess.Popen(
            [sys.executable, SCRIPT, "connect"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env,
            cwd=str(cwd or self.proj))

    def _rpc(self, proc, msg):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        assert line, "proxy closed stdout"
        return json.loads(line)

    def test_full_session_through_proxy(self):
        proc = self._proxy()
        try:
            init = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "proxy-test", "version": "0"}}})
            self.assertEqual(init["result"]["serverInfo"]["name"], "continuity")
            # notification: forwarded, no local echo
            proc.stdin.write(json.dumps(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()
            status = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "continuity_status", "arguments": {}}})
            body = json.loads(status["result"]["content"][0]["text"])
            # project auto-registered from the proxy's cwd; actor from env
            self.assertEqual(body["project"], "proxied-app")
            self.assertEqual(body["you"]["actor_id"], "proxy_actor")
            # drift-guard session state survives the proxy hop
            handoff = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "get_handoff", "arguments": {}}})
            self.assertFalse(handoff["result"]["isError"])
        finally:
            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=10), 0)
            proc.stdout.close()
            proc.stderr.close()

    def test_proxy_reports_unreachable_server(self):
        proc = self._proxy(url="http://127.0.0.1:9")  # nothing listens there
        try:
            resp = self._rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
            self.assertIn("unreachable", resp["error"]["message"])
            # proxy survives and answers again
            resp = self._rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "ping"})
            self.assertEqual(resp["id"], 2)
        finally:
            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=10), 0)
            proc.stdout.close()
            proc.stderr.close()

    def test_proxy_parse_error_local(self):
        proc = self._proxy()
        try:
            proc.stdin.write("garbage line\n")
            proc.stdin.flush()
            err = json.loads(proc.stdout.readline())
            self.assertEqual(err["error"]["code"], -32700)
        finally:
            proc.stdin.close()
            proc.wait(timeout=10)
            proc.stdout.close()
            proc.stderr.close()


class OneShotSetupTestCase(unittest.TestCase):
    def test_one_shot_setup_writes_everything_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "s.db"
            conn = c.connect(db)
            proj = Path(tmp) / "app"
            proj.mkdir()
            home = Path(tmp) / "home"
            home.mkdir()
            # pre-existing .mcp.json with another server must survive the merge
            (proj / ".mcp.json").write_text(json.dumps(
                {"mcpServers": {"other": {"command": "x"}}}))
            info = c.one_shot_setup(conn, "me", "human", db, path=str(proj),
                                    manage_server=False, home=str(home))
            self.assertTrue(info["project_created"])
            self.assertEqual(info["mode"], "server")
            merged = json.loads((proj / ".mcp.json").read_text())
            self.assertIn("other", merged["mcpServers"])
            entry = merged["mcpServers"]["continuity"]
            self.assertEqual(entry["type"], "http")
            self.assertTrue(entry["url"].endswith("/mcp"))
            self.assertEqual(entry["headers"]["X-Continuity-Project"],
                             info["project_id"])
            self.assertTrue((proj / "CLAUDE.md").exists())
            self.assertTrue((proj / "AGENTS.md").exists())
            # empty fake home: nothing detected, nothing configured
            self.assertEqual(info["configured_tools"], [])
            self.assertIn("codex", info["not_detected"])
            again = c.one_shot_setup(conn, "me", "human", db, path=str(proj),
                                     manage_server=False, home=str(home))
            self.assertFalse(again["project_created"])
            self.assertEqual(again["project_id"], info["project_id"])
            # stdio variant writes a command-style entry
            c.one_shot_setup(conn, "me", "human", db, path=str(proj),
                             stdio=True, manage_server=False, home=str(home))
            entry = json.loads((proj / ".mcp.json").read_text())[
                "mcpServers"]["continuity"]
            self.assertIn("command", entry)
            conn.close()

    def test_setup_here_forces_nested_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "s.db"
            conn = c.connect(db)
            parent = Path(tmp) / "parent"
            nested = parent / "sub"
            nested.mkdir(parents=True)
            home = Path(tmp) / "home"
            home.mkdir()
            c.project_init(conn, "me", "human", path=str(parent),
                           project_id="parent")
            attached = c.one_shot_setup(conn, "me", "human", db,
                                        path=str(nested), manage_server=False,
                                        home=str(home))
            self.assertEqual(attached["project_id"], "parent")
            self.assertTrue(attached["cwd_inside_root"])
            own = c.one_shot_setup(conn, "me", "human", db, path=str(nested),
                                   here=True, manage_server=False,
                                   home=str(home))
            self.assertEqual(own["project_id"], "sub")
            self.assertFalse(own["cwd_inside_root"])
            conn.close()


class UniversalConnectTestCase(unittest.TestCase):
    """connect_tools against a fake $HOME with several tools 'installed'."""

    def test_connect_tools_detection_and_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "proj"
            root.mkdir()
            db = Path(tmp) / "c.db"
            # "install" codex, cursor, cline, windsurf, gemini, vscode
            (home / ".codex").mkdir(parents=True)
            (home / ".codex" / "config.toml").write_text(
                '[model]\nname = "gpt"\n')
            (home / ".cursor").mkdir()
            (home / ".cursor" / "mcp.json").write_text(json.dumps(
                {"mcpServers": {"existing": {"url": "http://x/"}}}))
            cline_dir = home / (".config/Code/User/globalStorage/"
                                "saoudrizwan.claude-dev/settings")
            cline_dir.mkdir(parents=True)
            (home / ".codeium" / "windsurf").mkdir(parents=True)
            (home / ".gemini").mkdir()
            (root / ".vscode").mkdir()
            configured, missing = c.connect_tools(
                "proj", str(root), db, url="http://127.0.0.1:9999",
                home=str(home))
            tools = {entry["tool"] for entry in configured}
            self.assertEqual(tools, {"codex", "cline", "cursor", "windsurf",
                                     "gemini", "vscode"})
            self.assertIn("opencode", missing)
            # codex: original content preserved, connect-proxy block appended,
            # backup kept — one GLOBAL config, project auto-detected per cwd
            codex = (home / ".codex" / "config.toml").read_text()
            self.assertIn('[model]', codex)
            self.assertIn("[mcp_servers.continuity]", codex)
            self.assertIn('"connect"', codex)
            self.assertIn('"CONTINUITY_URL" = "http://127.0.0.1:9999"', codex)
            self.assertTrue((home / ".codex" / "config.toml.continuity-backup").exists())
            # rerun replaces (idempotent), not duplicates
            c.connect_tools("proj", str(root), db,
                            url="http://127.0.0.1:8888", home=str(home))
            codex = (home / ".codex" / "config.toml").read_text()
            self.assertEqual(codex.count("[mcp_servers.continuity]"), 1)
            self.assertIn('"CONTINUITY_URL" = "http://127.0.0.1:8888"', codex)
            # cursor: existing entry preserved, connect proxy with actor env
            cursor = json.loads((home / ".cursor" / "mcp.json").read_text())
            self.assertIn("existing", cursor["mcpServers"])
            entry = cursor["mcpServers"]["continuity"]
            self.assertIn("connect", entry["args"])
            self.assertEqual(entry["env"]["CONTINUITY_ACTOR"], "cursor_worker")
            # cline gets the stdio form (portable across cline versions)
            cline = json.loads(
                (cline_dir / "cline_mcp_settings.json").read_text())
            self.assertIn("command", cline["mcpServers"]["continuity"])
            # vscode uses the "servers" key
            vscode = json.loads((root / ".vscode" / "mcp.json").read_text())
            self.assertIn("continuity", vscode["servers"])
            # gemini project settings written
            gemini = json.loads(
                (root / ".gemini" / "settings.json").read_text())
            self.assertIn("httpUrl", gemini["mcpServers"]["continuity"])
            # skip filter respected
            configured, _ = c.connect_tools(
                "proj", str(root), db, home=str(home),
                skip={"codex", "cline", "cursor", "windsurf", "gemini",
                      "vscode", "opencode"})
            self.assertEqual(configured, [])


class EnsureServerTestCase(unittest.TestCase):
    def test_ensure_server_running_starts_and_reuses(self):
        import socket, signal
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "auto.db"
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            sock.close()
            url = "http://127.0.0.1:%d" % port
            first = c.ensure_server_running(url, db)
            try:
                self.assertTrue(first["started"])
                self.assertTrue(first["pid"])
                self.assertTrue(Path(first["log"]).exists())
                self.assertTrue(c.server_alive(url))
                second = c.ensure_server_running(url, db)
                self.assertFalse(second["started"])  # reused, not respawned
            finally:
                os.kill(first["pid"], signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
