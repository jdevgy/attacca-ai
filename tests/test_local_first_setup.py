"""Real local-first CLI/HTTP onboarding, isolated from installed clients and servers."""

import http.client
import http.cookies
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "attacca.py"


class LocalFirstSetupCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="attacca-local-first-cli-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        git = shutil.which("git")
        if not git:
            self.skipTest("git is required for isolated source CLI setup")
        (self.bin / "git").symlink_to(git)
        self.db = self.root / "server.sqlite"
        # No real machine credentials, workspace selection, or native-client
        # config paths may leak into either source CLI process.
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("ATTACCA_", "CODEX_", "CLAUDE_", "KIMI_"))
        }
        self.env.update({
            "HOME": str(self.home), "USERPROFILE": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_DATA_HOME": str(self.home / ".local" / "share"),
            "ATTACCA_DISABLE_WATCHER": "1", "ATTACCA_AUTOSTART": "0",
            "ATTACCA_DISABLE_SESSION_WAKE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            # Only Git is discoverable: a machine-wide crontab, browser
            # opener, or installed coding client cannot be started by setup.
            "PATH": str(self.bin), "USER": "test-operator",
        })
        subprocess.run(["git", "init", "-q", str(self.checkout)],
                       env=self.env, check=True, capture_output=True)
        self.server = None
        self.reader = None
        self.addCleanup(self.stop_server)
        self.start_server()

    def start_server(self):
        self.server = subprocess.Popen(
            [sys.executable, "-B", str(SCRIPT), "--db", str(self.db),
             "serve", "--host", "127.0.0.1", "--port", "0"],
            cwd=str(self.root), env=self.env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        lines = queue.Queue()

        def collect():
            for line in self.server.stdout:
                lines.put(line)
            lines.put(None)

        self.reader = threading.Thread(target=collect, daemon=True)
        self.reader.start()
        observed = []
        while True:
            try:
                line = lines.get(timeout=20)
            except queue.Empty:
                self.fail("source server did not announce its ephemeral port: " + "".join(observed))
            if line is None:
                self.fail("source server exited before startup: " + "".join(observed))
            observed.append(line)
            match = re.search(r"attacca server listening on http://127\.0\.0\.1:(\d+)", line)
            if match:
                self.port = int(match.group(1))
                self.url = "http://127.0.0.1:%d" % self.port
                break

    def stop_server(self):
        if self.server is None:
            return
        if self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=5)
        if self.reader is not None:
            self.reader.join(timeout=3)
        self.server.stdout.close()
        self.server = None

    def restart_server(self):
        self.stop_server()
        self.start_server()

    def request(self, method, path, body=None, headers=None):
        request_headers = {"Accept": "application/json", **(headers or {})}
        payload = None
        if body is not None:
            request_headers["Content-Type"] = "application/json"
            payload = json.dumps(body)
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            connection.request(method, path, payload, request_headers)
            response = connection.getresponse()
            raw = response.read()
            data = json.loads(raw) if "application/json" in response.getheader("Content-Type", "") else raw
            return response.status, data, response.headers
        finally:
            connection.close()

    def auth_status(self):
        status, data, _ = self.request("GET", "/v1/auth/status")
        self.assertEqual(status, 200, data)
        return data

    @staticmethod
    def session_headers(response_headers):
        cookies = http.cookies.SimpleCookie()
        for header in response_headers.get_all("Set-Cookie") or []:
            cookies.load(header)
        return {"Cookie": "; ".join("%s=%s" % (name, item.value) for name, item in cookies.items()),
                "X-Attacca-CSRF": cookies["attacca_csrf"].value}

    def setup_cli(self, *args, json_output=True):
        completed = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--db", str(self.root / "client.sqlite"),
             "--actor", "codex", "--actor-type", "agent", "--json", "setup",
             "--url", self.url, *args], cwd=str(self.checkout), env=self.env,
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=45)
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        return json.loads(completed.stdout) if json_output else completed.stdout

    def test_fresh_local_console_and_real_cli_discovery_apply_without_login(self):
        fresh = self.auth_status()
        self.assertTrue(fresh["setup_required"])
        self.assertEqual(fresh["access_mode"], "pending")
        self.assertTrue(fresh["setup_allowed"])
        self.assertFalse(fresh["network_exposed"])
        chosen, local, _ = self.request("POST", "/v1/setup", {"mode": "local", "confirmed": True})
        self.assertEqual(chosen, 200, local)
        self.assertFalse(local["setup_required"])
        self.assertFalse(local["authenticated"])
        self.assertTrue(local["anonymous_access"])
        self.assertFalse(local["bootstrap_required"])
        root_status, root_html, _ = self.request("GET", "/")
        app_status, app_html, _ = self.request("GET", "/app")
        self.assertEqual((root_status, app_status), (200, 200))
        self.assertEqual(root_html, app_html)
        self.assertIn(b'data-form="server-setup"', root_html)
        self.assertIn(b"Attacca Control Room", root_html)
        discovery = self.setup_cli("--discover")
        self.assertEqual(discovery["action"], "create_first_workspace")
        self.assertEqual(discovery["workspaces"], [])
        applied = self.setup_cli("--create", "Local Example", "--role", "director",
                                 "--lead", "current", "--skip-tools", "all", "--no-server",
                                 json_output=False)
        self.assertIn("project: local-example", applied)
        self.assertTrue((self.checkout / ".attacca" / "project.json").is_file())
        self.assertTrue((self.checkout / "AGENTS.md").is_file())
        self.assertFalse((self.home / ".codex" / "config.toml").exists())
        linked = self.setup_cli("--discover")
        self.assertEqual(linked["action"], "already_linked")
        self.assertEqual(linked["linked_project_id"], "local-example")
        agent_status, agents, _ = self.request("GET", "/v1/projects/local-example/agents?options=1")
        self.assertEqual(agent_status, 200, agents)
        registered = [agent for agent in agents["agents"] if agent.get("role") == "director"]
        self.assertTrue(registered)
        self.assertTrue(any(agent["agent_id"].startswith("local-example.director.codex.") for agent in registered))
        self.assertFalse(self.auth_status()["authenticated"])
        self.restart_server()
        resumed = self.auth_status()
        self.assertEqual(resumed["access_mode"], "local")
        self.assertFalse(resumed["setup_required"])
        self.assertTrue(resumed["anonymous_access"])
        self.assertEqual(self.setup_cli("--discover")["action"], "already_linked")

    def test_protected_first_run_creates_session_and_persists_without_downgrade(self):
        created, protected, headers = self.request("POST", "/v1/setup", {
            "mode": "protected", "confirmed": True,
            "username": "operator", "password": "test-only-password"})
        self.assertEqual(created, 201, protected)
        self.assertTrue(protected["authenticated"])
        self.assertTrue(protected["authentication_required"])
        self.assertEqual(protected["access_mode"], "protected")
        session = self.session_headers(headers)
        self.assertEqual(self.request("GET", "/v1/projects", headers=session)[0], 200)
        self.assertEqual(self.request("GET", "/v1/projects")[0], 401)
        self.restart_server()
        status = self.auth_status()
        self.assertEqual(status["access_mode"], "protected")
        self.assertFalse(status["setup_required"])
        self.assertTrue(status["authentication_required"])
        self.assertFalse(status["anonymous_access"])
        self.assertEqual(self.request("GET", "/v1/projects")[0], 401)
        rejected, _, _ = self.request("POST", "/v1/setup", {"mode": "local", "confirmed": True})
        self.assertIn(rejected, (401, 403))
        signed_in, payload, _ = self.request("POST", "/v1/auth/login", {
            "username": "operator", "password": "test-only-password"})
        self.assertEqual(signed_in, 200, payload)
        self.assertTrue(payload["authenticated"])

    def test_existing_account_installation_does_not_reenter_setup_on_restart(self):
        created, old_style, headers = self.request("POST", "/v1/auth/bootstrap", {
            "username": "existing", "password": "test-existing-password"})
        self.assertEqual(created, 201, old_style)
        session = self.session_headers(headers)
        activated, result, _ = self.request("POST", "/v1/auth/activation", {
            "enabled": True, "confirmed": True}, headers=session)
        self.assertEqual(activated, 200, result)
        self.restart_server()
        preserved = self.auth_status()
        self.assertEqual(preserved["access_mode"], "protected")
        self.assertFalse(preserved["setup_required"])
        self.assertTrue(preserved["authentication_required"])
        self.assertFalse(preserved["anonymous_access"])
        self.assertEqual(self.request("GET", "/v1/projects")[0], 401)
        signed_in, payload, _ = self.request("POST", "/v1/auth/login", {
            "username": "existing", "password": "test-existing-password"})
        self.assertEqual(signed_in, 200, payload)
        self.assertEqual(payload["user"]["username"], "existing")
        self.assertTrue(payload["user"]["is_admin"])

    def test_existing_optional_auth_is_not_silently_converted_to_local_mode(self):
        created, payload, _ = self.request("POST", "/v1/auth/bootstrap", {
            "username": "existing", "password": "test-existing-password"})
        self.assertEqual(created, 201, payload)
        self.assertFalse(payload["authentication_required"])
        self.restart_server()
        status = self.auth_status()
        self.assertEqual(status["access_mode"], "legacy")
        self.assertFalse(status["setup_required"])
        self.assertFalse(status["authentication_required"])
        self.assertFalse(status["anonymous_access"])
        self.assertTrue(status["bootstrapped"])
        rejected, _, _ = self.request("POST", "/v1/setup", {"mode": "local", "confirmed": True})
        self.assertEqual(rejected, 403)


if __name__ == "__main__":
    unittest.main()
