"""Machine-wide hosted Attacca URL switching regressions.

Every test uses a temporary HOME/CODEX_HOME and either skips the reachability
probe explicitly or binds an ephemeral loopback health server.  The live
development server is never contacted.
"""

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock


os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "attacca.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "attacca_server_switch_core", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c = load_module()


LINE_14_DUPLICATE_ENV = """# unrelated user comment
model = "gpt-5"

[projects."/work/app"]
trust_level = "trusted"

[mcp_servers.attacca]
command = "python3"
args = ["/old/attacca.py", "connect"]
env = { ATTACCA_ACTOR = "codex", ATTACCA_URL = "http://old.test:4173" }

# stale descendant from the previous installer
# duplicate table is deliberately line 14
[mcp_servers.attacca.env]
ATTACCA_ACTOR = "codex"
ATTACCA_URL = "http://older.test:4173"

[mcp_servers.other]
command = "keep"
"""


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        body = json.dumps({"ok": True, "version": "test"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class _JsonResponse:
    def __init__(self, value):
        self.data = json.dumps(value).encode()
        self.status = 200
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.data

    def getcode(self):
        return 200


class MachineServerSwitchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name) / "home"
        self.home.mkdir()
        self.old_url = "http://old.test:4173"
        self.new_url = "http://new.test:4173"

    def write_json(self, path, value):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2) + "\n")
        return path

    def build_installed_machine(self):
        identity = self.write_json(
            self.home / ".attacca" / "identity.json",
            {"owner": "jack", "device_id": "device-home"})
        credentials = self.write_json(
            self.home / ".attacca" / "credentials.json", {
                "version": 1,
                "servers": {
                    self.old_url: {"tokens": {"codex": "old-secret"}},
                    self.new_url: {"tokens": {"codex": "new-secret"}},
                },
            })

        codex = self.home / ".codex" / "config.toml"
        codex.parent.mkdir(parents=True)
        codex.write_text(LINE_14_DUPLICATE_ENV)

        cursor = self.write_json(self.home / ".cursor" / "mcp.json", {
            "theme": "keep-me",
            "mcpServers": {
                "other": {"command": "other"},
                "attacca": {
                    "command": "python3",
                    "args": ["/stable/attacca.py", "connect"],
                    "env": {"ATTACCA_ACTOR": "cursor",
                            "ATTACCA_URL": self.old_url},
                },
            },
        })

        plugin = self.home / ".attacca" / "plugin" / "attacca"
        plugin.mkdir(parents=True)
        (plugin / "attacca.py").write_text("# installed marker\n")
        for name, actor in ((".mcp.json", "codex"),
                            (".codex-plugin/plugin.json", "codex"),
                            ("plugin-mcp.json", "claude"),
                            ("kimi.plugin.json", "kimi")):
            self.write_json(plugin / name, {
                "unrelated": {"preserve": True},
                "mcpServers": {"attacca": {
                    "command": "python3",
                    "args": ["./attacca.py", "connect"],
                    "env": {"ATTACCA_ACTOR": actor,
                            "ATTACCA_URL": self.old_url}
                    if actor != "claude" else {"ATTACCA_ACTOR": actor},
                }},
            })

        checkout = self.home / "work" / "project"
        link = self.write_json(checkout / ".attacca" / "project.json", {
            "schema_version": 1, "project_id": "alpha"})
        project_mcp = self.write_json(checkout / ".mcp.json", {
            "otherSetting": 9,
            "mcpServers": {
                "other": {"url": "http://unrelated/mcp"},
                "attacca": {
                    "type": "http", "url": self.old_url + "/mcp",
                    "headers": {"X-Attacca-Project": "alpha"},
                },
            },
        })
        entry = {
            "server_url": self.old_url,
            "project_id": "alpha",
            "runtime": "codex",
            "actor": "codex",
            "owner": "jack",
            "device_id": "device-home",
            "root": str(checkout),
            "plugin_root": str(plugin),
            "pending": [{"summary": "already delivered from old server"}],
            "event_cursor": 99,
            "event_cursor_initialized": True,
            "snapshot": {"counts": {"events": 99}},
            "last_error": "old outage",
            "next_poll_at_epoch": 999,
        }
        old_key = c._watcher_subscription_key_for_url(entry, self.old_url)
        entry["key"] = old_key
        watcher = self.write_json(
            self.home / ".attacca" / "watcher" / "watcher-state.json",
            {"daemon": {"pid": 123, "nonce": "preserve"},
             "subscriptions": {old_key: entry}})

        # A representative URL-scoped outbox. Switching must report and retain
        # it, never copy it into the new server partition.
        storage = watcher.parent / "offline" / "old-storage"
        self.write_json(
            storage / "mirrors" / "identity" / "snapshot.json", {
                "normalized_server_url": self.old_url})
        records = storage / "outboxes" / "device" / "records"
        self.write_json(records / "00000000000000000001.json", {
            "kind": "mutation", "client_mutation_id": "mut_old_1"})

        return {
            "identity": identity, "credentials": credentials,
            "codex": codex, "cursor": cursor, "plugin": plugin,
            "checkout": checkout, "link": link, "project_mcp": project_mcp,
            "watcher": watcher, "old_key": old_key, "records": records,
        }

    @unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
    def test_switch_repairs_all_clients_preserves_identity_and_is_3x_idempotent(self):
        paths = self.build_installed_machine()
        identity_before = paths["identity"].read_bytes()
        credentials_before = paths["credentials"].read_bytes()
        link_before = paths["link"].read_bytes()

        first = c.machine_server_set(
            self.new_url + "/", home=self.home, validate=False)
        tracked = [
            paths["codex"], paths["cursor"], paths["project_mcp"],
            paths["watcher"], c.machine_config_path(self.home),
            paths["plugin"] / ".mcp.json",
            paths["plugin"] / ".codex-plugin" / "plugin.json",
            paths["plugin"] / "plugin-mcp.json",
            paths["plugin"] / "kimi.plugin.json",
        ]
        first_bytes = {path: path.read_bytes() for path in tracked}
        second = c.machine_server_set(
            self.new_url, home=self.home, validate=False)
        third = c.machine_server_set(
            self.new_url, home=self.home, validate=False)

        self.assertTrue(first["changed"])
        self.assertFalse(second["changed"])
        self.assertFalse(third["changed"])
        self.assertEqual(
            {path: path.read_bytes() for path in tracked}, first_bytes)
        self.assertEqual(paths["identity"].read_bytes(), identity_before)
        self.assertEqual(paths["credentials"].read_bytes(), credentials_before)
        self.assertEqual(paths["link"].read_bytes(), link_before)
        self.assertTrue(first["url_scoped_credentials_preserved"])
        self.assertEqual(first["old_server_outbox"]["pending_mutations"], 1)
        self.assertTrue(
            (paths["records"] / "00000000000000000001.json").is_file())

        parsed = tomllib.loads(paths["codex"].read_text())
        self.assertEqual(parsed["model"], "gpt-5")
        self.assertEqual(parsed["mcp_servers"]["other"]["command"], "keep")
        self.assertEqual(
            parsed["mcp_servers"]["attacca"]["env"]["ATTACCA_URL"],
            self.new_url)
        self.assertNotIn("[mcp_servers.attacca.env]",
                         paths["codex"].read_text())
        cursor = json.loads(paths["cursor"].read_text())
        self.assertEqual(cursor["theme"], "keep-me")
        self.assertEqual(cursor["mcpServers"]["other"], {"command": "other"})
        self.assertEqual(
            cursor["mcpServers"]["attacca"]["env"]["ATTACCA_URL"],
            self.new_url)
        project_mcp = json.loads(paths["project_mcp"].read_text())
        self.assertEqual(project_mcp["otherSetting"], 9)
        self.assertEqual(
            project_mcp["mcpServers"]["attacca"]["url"],
            self.new_url + "/mcp")

        state = json.loads(paths["watcher"].read_text())
        self.assertEqual(state["daemon"], {"pid": 123, "nonce": "preserve"})
        self.assertEqual(len(state["subscriptions"]), 1)
        new_key, entry = next(iter(state["subscriptions"].items()))
        self.assertNotEqual(new_key, paths["old_key"])
        self.assertEqual(entry["key"], new_key)
        self.assertEqual(entry["server_url"], self.new_url)
        self.assertEqual(entry["project_id"], "alpha")
        self.assertEqual(entry["actor"], "codex")
        self.assertEqual(entry["device_id"], "device-home")
        self.assertEqual(entry["pending"], [
            {"summary": "already delivered from old server"}])
        self.assertEqual(entry["next_poll_at_epoch"], 0)
        for removed in ("event_cursor", "snapshot", "last_error"):
            self.assertNotIn(removed, entry)
        self.assertEqual(first["watcher_subscriptions_rewired"], 1)

        with mock.patch.dict(os.environ, {"ATTACCA_URL": self.old_url}):
            shown = c.machine_server_show(home=self.home)
        self.assertEqual(shown["source"], "machine")
        self.assertEqual(shown["server_url"], self.new_url)

    def test_failure_after_codex_repair_rolls_every_file_back(self):
        paths = self.build_installed_machine()
        watched = [paths["codex"], paths["cursor"], paths["project_mcp"],
                   paths["watcher"], paths["identity"], paths["credentials"]]
        before = {path: path.read_bytes() for path in watched}
        real_write = c._atomic_switch_write
        injected = {"done": False}

        def fail_once(path, data, mode=None):
            if Path(path) == paths["cursor"] and not injected["done"]:
                injected["done"] = True
                raise OSError("simulated client config failure")
            return real_write(path, data, mode=mode)

        with mock.patch.object(c, "_atomic_switch_write", side_effect=fail_once):
            with self.assertRaisesRegex(c.AttaccaError, "rolled back"):
                c.machine_server_set(
                    self.new_url, home=self.home, validate=False)

        self.assertTrue(injected["done"])
        self.assertEqual({path: path.read_bytes() for path in watched}, before)
        self.assertFalse(c.machine_config_path(self.home).exists())
        self.assertFalse((paths["codex"].with_name(
            "config.toml.attacca-backup")).exists())

    @unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
    def test_cli_process_concurrency_keeps_one_consistent_final_url(self):
        paths = self.build_installed_machine()
        urls = ["http://one.test:4173", "http://two.test:4173"] * 3
        env = dict(os.environ)
        env.update({"HOME": str(self.home), "ATTACCA_OWNER": "",
                    "ATTACCA_AUTOSTART": "0"})
        processes = [subprocess.Popen(
            [sys.executable, str(SCRIPT), "--json", "server", "set", url,
             "--no-check"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env) for url in urls]
        outputs = [process.communicate(timeout=30) for process in processes]
        self.assertEqual([process.returncode for process in processes],
                         [0] * len(processes), outputs)

        machine = json.loads(c.machine_config_path(self.home).read_text())
        final_url = machine["server_url"]
        self.assertIn(final_url, set(urls))
        codex = tomllib.loads(paths["codex"].read_text())
        self.assertEqual(
            codex["mcp_servers"]["attacca"]["env"]["ATTACCA_URL"],
            final_url)
        cursor = json.loads(paths["cursor"].read_text())
        self.assertEqual(
            cursor["mcpServers"]["attacca"]["env"]["ATTACCA_URL"],
            final_url)
        before = {path: path.read_bytes() for path in (
            paths["codex"], paths["cursor"], paths["watcher"],
            c.machine_config_path(self.home))}
        for _ in range(3):
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "server", "set", final_url,
                 "--no-check"], capture_output=True, text=True, env=env,
                timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual({path: path.read_bytes() for path in before}, before)

    @unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
    def test_effective_codex_home_override_is_repaired_by_real_cli_path(self):
        custom_codex = Path(self.temporary.name) / "custom-codex"
        custom_codex.mkdir()
        target = custom_codex / "config.toml"
        target.write_text(LINE_14_DUPLICATE_ENV)
        with mock.patch.dict(os.environ, {
                "HOME": str(self.home), "CODEX_HOME": str(custom_codex)},
                clear=False):
            result = c.machine_server_set(
                self.new_url, home=None, validate=False)
        parsed = tomllib.loads(target.read_text())
        self.assertEqual(
            parsed["mcp_servers"]["attacca"]["env"]["ATTACCA_URL"],
            self.new_url)
        self.assertFalse((self.home / ".codex" / "config.toml").exists())
        self.assertIn(str(target), [item["path"] for item in result["rewired"]])

    def test_effective_kimi_and_watcher_root_overrides_are_rewired(self):
        kimi_root = Path(self.temporary.name) / "custom-kimi"
        watcher_root = Path(self.temporary.name) / "custom-watcher"
        kimi = self.write_json(kimi_root / "mcp.json", {
            "mcpServers": {"attacca": {
                "command": "python3", "args": ["attacca.py", "connect"],
                "env": {"ATTACCA_ACTOR": "kimi",
                        "ATTACCA_URL": self.old_url}}}})
        entry = {
            "server_url": self.old_url, "project_id": "alpha",
            "runtime": "kimi", "actor": "kimi", "device_id": "device-k",
            "root": str(self.home / "work"), "pending": []}
        key = c._watcher_subscription_key_for_url(entry, self.old_url)
        entry["key"] = key
        watcher = self.write_json(watcher_root / "watcher-state.json", {
            "subscriptions": {key: entry}})
        with mock.patch.dict(os.environ, {
                "HOME": str(self.home), "KIMI_CODE_HOME": str(kimi_root),
                "ATTACCA_WATCHER_DIR": str(watcher_root)}, clear=False):
            result = c.machine_server_set(
                self.new_url, home=None, validate=False)
        self.assertEqual(json.loads(kimi.read_text())[
            "mcpServers"]["attacca"]["env"]["ATTACCA_URL"], self.new_url)
        subscriptions = json.loads(watcher.read_text())["subscriptions"]
        self.assertEqual(len(subscriptions), 1)
        self.assertEqual(next(iter(subscriptions.values()))["server_url"],
                         self.new_url)
        self.assertEqual(result["watcher_state"], str(watcher))

    def test_default_health_validation_uses_only_ephemeral_target(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _HealthHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = "http://127.0.0.1:%d" % server.server_address[1]
        result = c.machine_server_set(url, home=self.home)
        self.assertEqual(result["server_url"], url)
        self.assertEqual(result["health"]["version"], "test")

    def test_connect_precedence_explicit_then_machine_then_env_then_package(self):
        self.write_json(c.machine_config_path(self.home), {
            "version": 1, "server_url": self.new_url})
        captured = []

        def fake_open(request, timeout=None):
            captured.append(request.full_url)
            return _JsonResponse({"jsonrpc": "2.0", "id": 1, "result": {}})

        request_stream = "\n".join([
            json.dumps({"jsonrpc": "2.0", "id": 1,
                        "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "id": 2,
                        "method": "tools/call", "params": {
                            "name": "attacca_status", "arguments": {}}}),
        ]) + "\n"
        initialize = io.StringIO(request_stream)
        with mock.patch.dict(os.environ, {
                "HOME": str(self.home), "ATTACCA_URL": self.old_url,
                "ATTACCA_AUTOSTART": "0"}, clear=False), \
                mock.patch("urllib.request.urlopen", side_effect=fake_open):
            c.run_connect_proxy(stdin=initialize, stdout=io.StringIO())
        self.assertEqual(captured[-1], self.new_url + "/mcp")

        captured.clear()
        initialize = io.StringIO(request_stream)
        explicit = "http://explicit.test:4173"
        with mock.patch.dict(os.environ, {
                "HOME": str(self.home), "ATTACCA_URL": self.old_url,
                "ATTACCA_AUTOSTART": "0"}, clear=False), \
                mock.patch("urllib.request.urlopen", side_effect=fake_open):
            c.run_connect_proxy(
                url=explicit, stdin=initialize, stdout=io.StringIO())
        self.assertEqual(captured[-1], explicit + "/mcp")

        c.machine_config_path(self.home).unlink()
        with mock.patch.dict(os.environ, {
                "HOME": str(self.home), "ATTACCA_URL": self.old_url},
                clear=False):
            self.assertEqual(c.configured_server_url(), self.old_url)
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}, clear=True), \
                mock.patch.object(c, "_packaged_server_url",
                                  return_value="http://packaged.test:4173"):
            self.assertEqual(
                c.configured_server_url(), "http://packaged.test:4173")
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}, clear=True), \
                mock.patch.object(c, "_packaged_server_url", return_value=None):
            self.assertEqual(c.configured_server_url(), c.DEFAULT_URL)

    def test_loaded_connect_process_hot_switches_machine_url(self):
        config = c.machine_config_path(self.home)
        self.write_json(config, {"version": 1, "server_url": self.old_url})
        captured = []

        def fake_open(request, timeout=None):
            captured.append(request.full_url)
            message = json.loads(request.data)
            if message.get("method") == "initialize":
                result = {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "switch-test", "version": "1"},
                }
            else:
                result = {"content": [{"type": "text", "text": "{}"}],
                          "isError": False}
            return _JsonResponse({"jsonrpc": "2.0",
                                  "id": message.get("id"),
                                  "result": result})

        lines = [
            json.dumps({"jsonrpc": "2.0", "id": 1,
                        "method": "initialize", "params": {}}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 2,
                        "method": "tools/call", "params": {
                            "name": "attacca_status", "arguments": {}}}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 3,
                        "method": "tools/call", "params": {
                            "name": "attacca_status", "arguments": {}}}) + "\n",
        ]
        outer = self

        class SwitchingInput:
            index = 0

            def readline(self):
                if self.index == 2:
                    outer.write_json(
                        config, {"version": 1,
                                 "server_url": outer.new_url})
                if self.index >= len(lines):
                    return ""
                value = lines[self.index]
                self.index += 1
                return value

        credentials = self.home / ".attacca" / "credentials.json"
        self.write_json(credentials, {"version": 1, "servers": {}})
        credentials.chmod(0o600)
        environment = {
            "HOME": str(self.home),
            "ATTACCA_AUTOSTART": "0",
            "ATTACCA_ACTOR": "codex",
            "ATTACCA_PROJECT": "alpha",
            "ATTACCA_DEVICE_ID": "switch-device",
            "ATTACCA_CLIENT_INSTANCE": "switch-client",
        }
        output = io.StringIO()
        with mock.patch.dict(os.environ, environment, clear=False), \
                mock.patch.object(c, "CREDENTIALS_FILE", credentials), \
                mock.patch("urllib.request.urlopen", side_effect=fake_open):
            c.run_connect_proxy(
                stdin=SwitchingInput(), stdout=output)

        self.assertEqual(
            captured[:2], [self.old_url + "/mcp"] * 2,
            output.getvalue())
        self.assertEqual(
            captured[2:], [self.new_url + "/mcp"] * 2,
            output.getvalue())


if __name__ == "__main__":
    unittest.main()
