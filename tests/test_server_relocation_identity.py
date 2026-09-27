"""Explicit endpoint relocation preserves identity without trusting unknown IPs."""

import importlib.util
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("relocation_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class RelocationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()
        self.old = "http://192.0.2.10:4173"
        self.actor = "sample.director.codex.gibbs"
        self.instance = "client-relocation-test"
        self.flow = c._terminal_flow_runtime()
        self.credentials = self.flow.default_credentials_path(self.home)
        self.db = Path(self.tmp.name) / "test.db"
        conn = c.connect(self.db)
        try:
            c.project_init(conn, "setup", "human", project_id="sample",
                           path=Path(self.tmp.name) / "checkout", name="Sample")
            c.set_current_owner("alice")
            c.agent_register(conn, "sample", self.actor, "agent",
                             agent_id=self.actor, role="director", runtime="codex",
                             registration_username="alice")
            c.auth_create_user(conn, "alice", "test-password-123",
                               is_admin=True, bootstrap=True)
            row = conn.execute("SELECT * FROM auth_users WHERE username='alice'").fetchone()
            principal = c._auth_principal(conn, row, "session", actor_type="human")
            conn.execute("INSERT OR IGNORE INTO auth_project_memberships "
                         "(user_id, project_id, granted_at, granted_by) VALUES (?,?,?,?)",
                         (row["user_id"], "sample", c.now_iso(), "alice"))
            self.key = c.auth_client_key_create(
                conn, principal, "Test", self.instance, memberships=["sample"])
            c.server_settings_store(conn, {"auth.activated": True})
        finally:
            c.set_current_owner(None)
            conn.close()
        self.server = c.AttaccaServer(("127.0.0.1", 0), self.db, auth=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.new = "http://127.0.0.1:%d" % self.server.server_address[1]
        self.flow.save_client_api_key(self.old, self.key,
                                      client_instance=self.instance,
                                      credentials_path=self.credentials)
        c.machine_server_set(self.old, home=self.home, validate=False)
        c.machine_actor_binding_set(self.old, "sample", "codex", self.actor,
                                    client_instance=self.instance, home=self.home)

    def relocate(self, **kwargs):
        return c.machine_server_set(self.new, home=self.home, same_server=True, **kwargs)

    def saved_bytes(self):
        return (c.machine_config_path(self.home).read_bytes(),
                self.credentials.read_bytes())

    def test_live_relocation_preserves_exact_actor_and_client_installation(self):
        old_credential = self.flow.read_credentials_store(self.credentials)["servers"][self.old]
        result = self.relocate()
        self.assertEqual(result["same_server_relocation"]["client_keys"], 1)
        self.assertEqual(result["same_server_relocation"]["actor_bindings"], 1)
        for url in (self.old, self.new):
            binding = c.machine_actor_binding_get(url, "sample", "codex",
                client_instance=self.instance, home=self.home)
            self.assertEqual(binding["actor_id"], self.actor)
            self.assertEqual(self.flow.load_client_api_key(url,
                client_instance=self.instance, credentials_path=self.credentials), self.key["token"])
        store = self.flow.read_credentials_store(self.credentials)
        self.assertEqual(store["servers"][self.old], old_credential)
        self.assertEqual(self.credentials.stat().st_mode & 0o777, 0o600)
        before = self.saved_bytes()
        self.assertFalse(self.relocate()["changed"])
        self.assertEqual(self.saved_bytes(), before)
        self.assertNotIn(self.key["token"], json.dumps(result))

    def test_plain_switch_never_forwards_secret_or_binding(self):
        before = self.credentials.read_bytes()
        c.machine_server_set(self.new, home=self.home)
        self.assertEqual(self.credentials.read_bytes(), before)
        self.assertIsNone(self.flow.load_client_api_key(self.new,
            client_instance=self.instance, credentials_path=self.credentials))
        self.assertIsNone(c.machine_actor_binding_get(self.new, "sample", "codex",
            client_instance=self.instance, home=self.home))

    def test_explicit_old_url_repairs_an_already_switched_install(self):
        c.machine_server_set(self.new, home=self.home)
        self.relocate(from_url=self.old)
        self.assertEqual(c.machine_actor_binding_get(self.new, "sample", "codex",
            client_instance=self.instance, home=self.home)["actor_id"], self.actor)

    def test_rejected_key_leaves_all_local_state_untouched(self):
        conn = c.connect(self.db)
        try:
            conn.execute("UPDATE auth_tokens SET revoked_at=?", (c.now_iso(),))
        finally:
            conn.close()
        before = self.saved_bytes()
        with self.assertRaisesRegex(c.AttaccaError, "relocation rejected"):
            self.relocate()
        self.assertEqual(self.saved_bytes(), before)

    def test_unregistered_exact_actor_rejected_before_local_change(self):
        c.machine_actor_binding_set(self.old, "sample", "codex",
            "sample.worker.codex.other", client_instance=self.instance, home=self.home)
        before = self.saved_bytes()
        with self.assertRaisesRegex(c.AttaccaError, "relocation rejected"):
            self.relocate()
        self.assertEqual(self.saved_bytes(), before)

    def test_target_actor_conflict_not_overwritten(self):
        c.machine_actor_binding_set(self.new, "sample", "codex",
            "sample.worker.codex.other", client_instance=self.instance, home=self.home)
        before = self.saved_bytes()
        with self.assertRaisesRegex(c.AttaccaError, "another actor"):
            self.relocate()
        self.assertEqual(self.saved_bytes(), before)

    def test_target_credential_conflict_not_overwritten(self):
        other = dict(self.key, token="atkey_another-target-credential")
        self.flow.save_client_api_key(self.new, other, client_instance=self.instance,
                                      credentials_path=self.credentials)
        before = self.saved_bytes()
        with self.assertRaisesRegex(c.AttaccaError, "another client credential"):
            self.relocate()
        self.assertEqual(self.saved_bytes(), before)

    def test_invalid_flags_fail_before_network_or_writes(self):
        before = self.saved_bytes()
        for args in ({"same_server": True, "validate": False},
                     {"from_url": self.old}):
            with self.assertRaises(c.AttaccaError):
                c.machine_server_set(self.new, home=self.home, **args)
        self.assertEqual(self.saved_bytes(), before)

    def test_https_downgrade_is_rejected(self):
        before = self.saved_bytes()
        with self.assertRaisesRegex(c.AttaccaError, "downgrade"):
            self.relocate(from_url="https://old.example")
        self.assertEqual(self.saved_bytes(), before)

    def test_credential_commit_failure_rolls_back_config_and_bindings(self):
        before = self.saved_bytes()
        with mock.patch.object(self.flow, "_atomic_private_json",
                               side_effect=OSError("disk full")):
            with self.assertRaisesRegex(c.AttaccaError, "rolled back"):
                self.relocate()
        self.assertEqual(self.saved_bytes(), before)

    def test_missing_key_does_not_turn_protected_server_anonymous(self):
        self.flow.forget_client_api_key(self.old, client_instance=self.instance,
                                        credentials_path=self.credentials)
        before = self.saved_bytes()
        with self.assertRaisesRegex(c.AttaccaError, "reinstallation is not required"):
            self.relocate()
        self.assertEqual(self.saved_bytes(), before)

    def test_watcher_drops_old_url_scope_and_latch_but_preserves_mail(self):
        path = c._watcher_state_path_for_home(self.home)
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"server_url": self.old, "project_id": "sample", "runtime": "codex",
                 "actor": self.actor, "canonical_actor_id": self.actor,
                 "device_id": "device-test", "root": str(self.home),
                 "client_instance": self.instance,
                 "sync_scope": {"normalized_server_url": self.old},
                 "sync_visibility_fingerprint": "old-hash",
                 "auth_required": True, "last_auth_error_fingerprint": "old-error",
                 "pending": [{"summary": "durable pending project mail"}]}
        path.write_text(json.dumps({"subscriptions": {"old-key": entry}}))
        self.relocate()
        new_entry = next(iter(json.loads(path.read_text())["subscriptions"].values()))
        self.assertEqual(new_entry["server_url"], self.new)
        self.assertEqual(new_entry["canonical_actor_id"], self.actor)
        self.assertEqual(new_entry["pending"], entry["pending"])
        for key in ("sync_scope", "sync_visibility_fingerprint", "auth_required",
                    "last_auth_error_fingerprint"):
            self.assertNotIn(key, new_entry)

    def test_colliding_subscriptions_keep_all_pending_mail_without_a_50_row_cap(self):
        base = {"project_id": "sample", "runtime": "codex", "actor": self.actor,
                "device_id": "device-test", "root": str(self.home)}
        old = dict(base, server_url=self.old,
                   pending=[{"message_id": index} for index in range(80)])
        current = dict(base, server_url=self.new,
                       pending=[{"message_id": index} for index in range(60, 120)])
        state = {"subscriptions": {
            c._watcher_subscription_key_for_url(old, self.old): old,
            c._watcher_subscription_key_for_url(current, self.new): current,
        }}
        c._retarget_watcher_state(state, self.new)
        self.assertEqual(len(state["subscriptions"]), 1)
        merged = next(iter(state["subscriptions"].values()))
        self.assertEqual([row["message_id"] for row in merged["pending"]],
                         list(range(120)))

    def test_local_no_login_relocation_verifies_existing_actor(self):
        db = Path(self.tmp.name) / "local.db"
        conn = c.connect(db)
        try:
            c.project_init(conn, "setup", "human", project_id="sample", name="Sample")
            c.agent_register(conn, "sample", self.actor, "agent",
                             agent_id=self.actor, role="director", runtime="codex")
            c.server_settings_store(conn, {"server.setup_mode": "local"})
        finally:
            conn.close()
        server = c.AttaccaServer(("127.0.0.1", 0), db)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.new = "http://127.0.0.1:%d" % server.server_address[1]
        self.flow.forget_client_api_key(self.old, client_instance=self.instance,
                                        credentials_path=self.credentials)
        result = self.relocate()
        self.assertEqual(result["same_server_relocation"]["actor_bindings"], 1)
        self.assertEqual(result["same_server_relocation"]["client_keys"], 0)

    def test_deleted_native_cache_and_stale_environment_use_new_machine_url(self):
        self.relocate()
        spec = importlib.util.spec_from_file_location(
            "relocation_hook", ROOT / "hooks/session_start.py")
        hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hook)
        missing = self.home / "deleted-native-cache"
        with mock.patch.dict(os.environ, {"PLUGIN_ROOT": str(missing),
                             "ATTACCA_URL": self.old}, clear=True), \
                mock.patch.object(hook.Path, "home", return_value=self.home):
            root, config = hook._plugin_and_config()
            self.assertEqual(root, ROOT.resolve())
            self.assertEqual(config["url"], self.new)
            self.assertEqual(config["actor"], "codex")
            self.assertFalse(missing.exists())

    def test_bearer_verification_does_not_follow_redirects(self):
        received = []

        class Redirect(BaseHTTPRequestHandler):
            def do_GET(handler):
                received.append(handler.path)
                if handler.path == "/healthz":
                    raw = b'{"ok":true,"version":"test"}'
                    handler.send_response(200)
                    handler.send_header("Content-Length", str(len(raw)))
                    handler.end_headers()
                    handler.wfile.write(raw)
                else:
                    handler.send_response(302)
                    handler.send_header("Location", "/credential-leak-target")
                    handler.send_header("Content-Length", "0")
                    handler.end_headers()

            def log_message(handler, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.new = "http://127.0.0.1:%d" % server.server_address[1]
        before = self.saved_bytes()
        with self.assertRaisesRegex(c.AttaccaError, "relocation rejected"):
            self.relocate()
        self.assertNotIn("/credential-leak-target", received)
        self.assertEqual(self.saved_bytes(), before)

    def test_running_stdio_proxy_reloads_url_key_and_exact_actor_without_restart(self):
        self.relocate()
        server = c.AttaccaServer(("127.0.0.1", 0), self.db, auth=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        next_url = "http://127.0.0.1:%d" % server.server_address[1]
        lines = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "attacca_status", "arguments": {"project": "sample"}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "attacca_status", "arguments": {"project": "sample"}}},
        ]
        outer = self

        class Input:
            index = 0

            def readline(stream):
                if stream.index == 2:
                    c.machine_server_set(next_url, home=outer.home, same_server=True)
                if stream.index >= len(lines):
                    return ""
                value = json.dumps(lines[stream.index]) + "\n"
                stream.index += 1
                return value

        output = io.StringIO()
        with mock.patch.dict(os.environ, {
                "HOME": str(self.home), "ATTACCA_AUTOSTART": "0",
                "ATTACCA_CLIENT_INSTANCE": self.instance,
                "ATTACCA_ACTOR": "codex", "ATTACCA_PROJECT": "sample",
                "ATTACCA_DEVICE_ID": "relocation-test-device", "ATTACCA_OWNER": "",
            }, clear=True), mock.patch.object(c, "CREDENTIALS_FILE", self.credentials):
            c.run_connect_proxy(stdin=Input(), stdout=output)
        replies = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(replies), 3, replies)
        for reply in replies[1:]:
            self.assertNotIn("error", reply)
            self.assertFalse(reply["result"].get("isError"), reply)
            body = json.loads(reply["result"]["content"][0]["text"])
            self.assertEqual(body["you"]["actor_id"], self.actor)
        self.assertEqual(c.configured_server_url(home=self.home), next_url)


if __name__ == "__main__":
    unittest.main()
