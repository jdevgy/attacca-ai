"""D-21 black-box identity selection through the real connect proxy.

The hosted server, SQLite database, checkout, HOME, device, client key, and
machine binding are all throwaway fixtures.  Nothing discovers or contacts a
configured Attacca service, and the real watcher is disabled.
"""

import importlib.util
import json
import os
import select
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "attacca.py")
SPEC = importlib.util.spec_from_file_location(
    "attacca_temporary_identity_proxy_runtime", ROOT / "attacca.py")
core = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(core)


class TemporaryIdentityProxyContractTest(unittest.TestCase):
    """One installed client has one durable actor plus a proxy-local override."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.db = self.root / "attacca.db"
        self.client_instance = "codex-install-isolated"
        self.device_id = "device-isolated"
        self.permanent_actor = "proj.director.codex.red"
        self.compatibility_actor = "proj.director.codex"
        self.processes = []

        conn = core.connect(self.db)
        try:
            core.auth_create_user(
                conn, "jack", "temporary-password", display_name="Jack",
                is_admin=True, bootstrap=True)
            core.set_current_owner("jack")
            core.project_init(
                conn, "web.jack", "human", path=self.checkout,
                project_id="proj", name="Proxy identity fixture")
            user = conn.execute(
                "SELECT * FROM auth_users WHERE username='jack'").fetchone()
            conn.execute(
                "INSERT OR IGNORE INTO auth_project_memberships"
                " (user_id,project_id,granted_at,granted_by)"
                " VALUES (?,?,?,?)",
                (user["user_id"], "proj", core.now_iso(), "jack"))
            core.agent_register(
                conn, "proj", "web.jack", "human",
                agent_id=self.permanent_actor,
                display_name="Red Codex Director", role="director",
                runtime="codex", registration_username="jack")
            core.agent_register(
                conn, "proj", "web.jack", "human",
                agent_id=self.compatibility_actor,
                display_name="Existing compatibility identity",
                role="director", runtime="codex",
                registration_username="jack")
            principal = core._auth_principal(
                conn, user, "session", session_hash="isolated-session")
            created = core.auth_client_key_create(
                conn, principal, "Isolated Codex", self.client_instance,
                memberships=["proj"], device_id=self.device_id)
            self.token = created["token"]
            core.auth_activate(conn, principal, True, enabled=True)
        finally:
            conn.close()
            core.set_current_owner(None)
        core.write_project_link(self.checkout, "proj")

        self.server = core.AttaccaServer(("127.0.0.1", 0), self.db)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]
        self.assertNotEqual(self.server.server_address[1], 4173)
        core.machine_actor_binding_set(
            self.base, "proj", "codex", self.permanent_actor,
            client_instance=self.client_instance, home=self.home)

    def tearDown(self):
        for process in list(self.processes):
            self._stop_proxy(process, check=False)
        self.server.shutdown()
        self.thread.join(timeout=10)
        self.server.server_close()
        core.set_current_owner(None)
        self.temporary.cleanup()

    def _environment(self):
        environment = dict(os.environ)
        for name in (
                "CLAUDE_PROJECT_DIR", "CODEX_HOME", "ATTACCA_PROJECT",
                "ATTACCA_CONFIG", "ATTACCA_MACHINE_CONFIG",
                "ATTACCA_CLIENT_INSTANCE_FILE", "ATTACCA_AUTH_REQUIRED"):
            environment.pop(name, None)
        environment.update({
            "HOME": str(self.home),
            "ATTACCA_DB": str(self.db),
            "ATTACCA_URL": self.base,
            "ATTACCA_API_TOKEN": self.token,
            "ATTACCA_ACTOR": "codex",
            "ATTACCA_ACTOR_TYPE": "agent",
            "ATTACCA_OWNER": "jack",
            "ATTACCA_DEVICE_ID": self.device_id,
            "ATTACCA_CLIENT_INSTANCE": self.client_instance,
            "ATTACCA_AUTOSTART": "0",
            "ATTACCA_DISABLE_WATCHER": "1",
            "ATTACCA_CONNECT_TIMEOUT_SECONDS": "3",
            "ATTACCA_WATCHER_DIR": str(self.root / "watcher-disabled"),
        })
        return environment

    def _start_proxy(self):
        process = subprocess.Popen(
            [sys.executable, SCRIPT, "connect", "--url", self.base],
            cwd=str(self.checkout), env=self._environment(),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        self.processes.append(process)
        initialized = self._rpc(process, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {
                "name": "temporary-identity-proxy-test", "version": "1",
            },
        }, request_id=1)
        self.assertIn("result", initialized, initialized)
        process.stdin.write(json.dumps({
            "jsonrpc": "2.0", "method": "notifications/initialized",
        }) + "\n")
        process.stdin.flush()
        return process

    def _stop_proxy(self, process, check=True):
        if process not in self.processes:
            return
        try:
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            returncode = process.wait(timeout=10)
            if check:
                self.assertEqual(returncode, 0, process.stderr.read())
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
            if check:
                self.fail("connect proxy did not exit after stdin EOF")
        finally:
            for stream in (process.stdout, process.stderr):
                if stream and not stream.closed:
                    stream.close()
            self.processes.remove(process)

    def _rpc(self, process, method, params=None, request_id=10, timeout=10):
        request = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            request["params"] = params
        process.stdin.write(json.dumps(request) + "\n")
        process.stdin.flush()
        readable, _, _ = select.select([process.stdout], [], [], timeout)
        if not readable:
            stderr = process.stderr.read() if process.poll() is not None else ""
            self.fail("connect proxy produced no reply: %s" % stderr)
        line = process.stdout.readline()
        self.assertTrue(line, "connect proxy closed stdout before replying")
        response = json.loads(line)
        self.assertEqual(response.get("jsonrpc"), "2.0", response)
        self.assertEqual(response.get("id"), request_id, response)
        return response

    def _tool(self, process, name, arguments=None, request_id=10):
        response = self._rpc(process, "tools/call", {
            "name": name, "arguments": arguments or {},
        }, request_id=request_id)
        self.assertIn("result", response, response)
        result = response["result"]
        self.assertFalse(result.get("isError"), result)
        self.assertTrue(result.get("content"), result)
        return json.loads(result["content"][0]["text"])

    def _status_actor(self, process, request_id):
        status = self._tool(
            process, "attacca_status", request_id=request_id)
        return status["you"]["actor_id"]

    def _binding_actor(self):
        binding = core.machine_actor_binding_get(
            self.base, "proj", "codex",
            client_instance=self.client_instance, home=self.home)
        self.assertIsNotNone(binding)
        return binding["actor_id"]

    def test_temporary_identity_is_proxy_local_and_never_rebinds_installation(self):
        proxy = self._start_proxy()
        self.assertEqual(self._status_actor(proxy, 2), self.permanent_actor)

        selected = self._tool(proxy, "agent_register", {
            "role": "director", "runtime": "codex",
            "identity_mode": "temporary",
        }, request_id=3)
        temporary_actor = selected["agent_id"]
        self.assertEqual(temporary_actor, "proj.director.codex.gibbs")
        self.assertEqual(self._binding_actor(), self.permanent_actor)

        # The same long-running stdio proxy adopts the temporary actor after
        # the selecting call. It must not wait for setup to rewrite MCP config.
        self.assertEqual(self._status_actor(proxy, 4), temporary_actor)
        self.assertEqual(self._binding_actor(), self.permanent_actor)

        # A different/new Codex process in the same installation has no access
        # to the other proxy's in-memory override and silently uses Red again.
        restarted = self._start_proxy()
        self.assertEqual(
            self._status_actor(restarted, 5), self.permanent_actor)
        self.assertEqual(self._binding_actor(), self.permanent_actor)

    def test_shell_setup_cannot_claim_to_activate_parent_proxy_temporary_actor(self):
        with mock.patch.object(core, "remote_json") as remote:
            with self.assertRaisesRegex(
                    core.AttaccaError,
                    "temporary_identity_requires_current_mcp"):
                core.apply_remote_network_setup(
                    "http://127.0.0.1:9", "proj", "codex", "agent",
                    role="director", identity_mode="temporary")
            remote.assert_not_called()

        skill = (ROOT / "skills" / "setup" / "SKILL.md").read_text(
            encoding="utf-8")
        self.assertIn("current Attacca MCP proxy", skill)
        self.assertIn("identity_mode=temporary", skill)
        self.assertIn("do not offer temporary", skill)
        self.assertIn("valid binding", skill)
        self.assertNotIn(
            "`--identity-mode new|reuse|temporary`", skill)

        # The public CLI must fail before it opens/creates a database, links
        # the checkout, performs authentication, or changes machine state.
        # Port 9 is intentionally unreachable; reaching it would prove the
        # guard ran too late.
        blocked_checkout = self.root / "blocked-cli-checkout"
        blocked_checkout.mkdir()
        before_home = {
            str(path.relative_to(self.home)): path.read_bytes()
            for path in self.home.rglob("*") if path.is_file()
        }
        blocked_db = self.root / "must-not-exist.db"
        environment = self._environment()
        environment["ATTACCA_DB"] = str(blocked_db)
        environment["ATTACCA_URL"] = "http://127.0.0.1:9"
        completed = subprocess.run(
            [sys.executable, SCRIPT, "setup", "--url",
             "http://127.0.0.1:9", "--here", "--attach", "proj",
             "--role", "director", "--identity-mode", "temporary",
             "--no-server"],
            cwd=str(blocked_checkout), env=environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False)
        self.assertEqual(completed.returncode, 2, completed)
        self.assertIn(
            "temporary_identity_requires_current_mcp", completed.stderr)
        self.assertIn("native guided setup", completed.stderr)
        self.assertIn("agent_register", completed.stderr)
        self.assertNotIn("--identity-mode defer", completed.stderr)
        self.assertFalse(blocked_db.exists())
        self.assertFalse((blocked_checkout / ".attacca").exists())
        after_home = {
            str(path.relative_to(self.home)): path.read_bytes()
            for path in self.home.rglob("*") if path.is_file()
        }
        self.assertEqual(after_home, before_home)

    def test_unlinked_proxy_fallback_uses_parsed_project_id_key(self):
        source = (ROOT / "attacca.py").read_text(encoding="utf-8")
        self.assertIn(
            'context.get("project") or parsed["project_id"]', source)
        self.assertNotIn(
            'context.get("project") or parsed["workspace"]', source)

    def test_new_and_reuse_modes_rebind_then_survive_proxy_restart(self):
        proxy = self._start_proxy()
        self.assertEqual(self._status_actor(proxy, 2), self.permanent_actor)

        created = self._tool(proxy, "agent_register", {
            "role": "director", "runtime": "codex",
            "identity_mode": "new",
        }, request_id=3)
        new_actor = created["agent_id"]
        self.assertEqual(new_actor, "proj.director.codex.gibbs")
        self.assertEqual(self._status_actor(proxy, 4), new_actor)
        self.assertEqual(self._binding_actor(), new_actor)

        after_new_restart = self._start_proxy()
        self.assertEqual(self._status_actor(after_new_restart, 5), new_actor)

        reused = self._tool(proxy, "agent_register", {
            "agent_id": self.permanent_actor,
            "role": "director", "runtime": "codex", "persona": "red",
            "identity_mode": "reuse",
        }, request_id=6)
        self.assertEqual(reused["agent_id"], self.permanent_actor)
        self.assertEqual(self._status_actor(proxy, 7), self.permanent_actor)
        self.assertEqual(self._binding_actor(), self.permanent_actor)

        after_reuse_restart = self._start_proxy()
        self.assertEqual(
            self._status_actor(after_reuse_restart, 8), self.permanent_actor)

        compatibility = self._tool(proxy, "agent_register", {
            "agent_id": self.compatibility_actor,
            "role": "director", "runtime": "codex",
            "identity_mode": "reuse",
        }, request_id=9)
        self.assertEqual(
            compatibility["agent_id"], self.compatibility_actor)
        self.assertEqual(
            self._status_actor(proxy, 10), self.compatibility_actor)
        self.assertEqual(self._binding_actor(), self.compatibility_actor)

        after_compatibility_restart = self._start_proxy()
        self.assertEqual(
            self._status_actor(after_compatibility_restart, 11),
            self.compatibility_actor)


if __name__ == "__main__":
    unittest.main()
