"""Focused D-17 client-install authorization tests (no live server)."""

import contextlib
import json
import os
import stat
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from attacca import terminal_flow as flow


class FakeTransport:
    def __init__(self, response=None):
        self.calls = []
        self.response = response

    def request(self, method, url, *, headers, payload=None, timeout=5):
        self.calls.append({
            "method": method, "url": url, "headers": dict(headers),
            "payload": payload, "timeout": timeout,
        })
        if self.response is not None:
            return self.response
        instance = headers[flow.CLIENT_INSTANCE_HEADER]
        return flow.JsonResponse(200, {}, {
            "authenticated": True,
            "user": {"username": "jack"},
            "principal": {
                "token_kind": "client", "token_id": "key_1",
                "client_instance": instance,
                "project_memberships": ["alpha"],
                "scope_mode": "selected_workspaces",
                "client_label": "Office client",
            },
        })


class ClientAuthorizationFlowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.credentials = self.root / "credentials.json"
        self.identity = self.root / "identity.json"
        self.client = self.root / "client.json"
        self.server = "https://attacca.test/tenant"
        self.instance = flow.load_client_instance_id(
            storage_path=self.client, runtime="codex")
        self.token = "atkey_key_1.this-is-a-high-entropy-test-secret"

    def tearDown(self):
        self.temp.cleanup()

    def record(self, **overrides):
        value = {
            "token": self.token,
            "token_kind": "client",
            "token_id": "key_1",
            "client_instance": self.instance,
            "username": "jack",
            "project_memberships": ["alpha"],
            "scope_mode": "selected_workspaces",
            "label": "Office client",
            "created_at": "2026-08-26T00:00:00Z",
        }
        value.update(overrides)
        return value

    def test_client_instance_is_private_stable_and_not_an_actor(self):
        second = flow.load_client_instance_id(
            storage_path=self.client, runtime="claude")
        self.assertEqual(second, self.instance)
        self.assertTrue(self.instance.startswith("client_"))
        self.assertNotIn("codex", self.instance)
        self.assertNotIn("claude", self.instance)
        self.assertEqual(stat.S_IMODE(self.client.stat().st_mode), 0o600)

    def test_runtime_configuration_roots_make_distinct_installations(self):
        with mock.patch.dict(os.environ, {
                "CODEX_HOME": str(self.root / "codex-a")}, clear=False):
            codex_a = flow.load_client_instance_id(runtime="codex")
        with mock.patch.dict(os.environ, {
                "CODEX_HOME": str(self.root / "codex-b")}, clear=False):
            codex_b = flow.load_client_instance_id(runtime="codex")
        with mock.patch.dict(os.environ, {
                "CLAUDE_CONFIG_DIR": str(self.root / "claude")}, clear=False):
            claude = flow.load_client_instance_id(runtime="claude")
        with mock.patch.dict(os.environ, {
                "KIMI_CODE_HOME": str(self.root / "kimi")}, clear=False):
            kimi = flow.load_client_instance_id(runtime="kimi")
        self.assertEqual(len({codex_a, codex_b, claude, kimi}), 4)
        for path in (
                self.root / "codex-a" / "attacca-client.json",
                self.root / "codex-b" / "attacca-client.json",
                self.root / "claude" / "attacca-client.json",
                self.root / "kimi" / "attacca-client.json"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_environment_override_does_not_write_identity_file(self):
        target = self.root / "unused.json"
        with mock.patch.dict(os.environ, {
                "ATTACCA_CLIENT_INSTANCE": "client_external_42"}, clear=False):
            self.assertEqual(
                flow.load_client_instance_id(target, runtime="generic"),
                "client_external_42")
        self.assertFalse(target.exists())
        with mock.patch.dict(os.environ, {
                "ATTACCA_CLIENT_INSTANCE": "c" * 121}, clear=False):
            with self.assertRaises(flow.TerminalFlowProtocolError):
                flow.load_client_instance_id(target, runtime="generic")

    def test_save_load_status_and_forget_are_install_scoped(self):
        public = flow.save_client_api_key(
            self.server, self.record(), client_instance=self.instance,
            credentials_path=self.credentials)
        self.assertEqual(public["status"], "ready")
        self.assertNotIn(self.token, json.dumps(public))
        self.assertEqual(
            flow.load_client_api_key(
                self.server, client_instance=self.instance,
                project_id="alpha", credentials_path=self.credentials),
            self.token)
        self.assertIsNone(flow.load_client_api_key(
            self.server, client_instance="client_other",
            credentials_path=self.credentials))
        self.assertEqual(
            flow.client_api_key_status(
                self.server, client_instance=self.instance,
                project_id="beta", credentials_path=self.credentials)["status"],
            "wrong_workspace")
        flow.forget_client_api_key(
            self.server, client_instance=self.instance,
            credentials_path=self.credentials)
        self.assertIsNone(flow.load_client_api_key(
            self.server, client_instance=self.instance,
            credentials_path=self.credentials))

    def test_empty_membership_list_tracks_human_account_memberships(self):
        flow.save_client_api_key(
            self.server, self.record(project_memberships=[],
                                     scope_mode="account_memberships"),
            client_instance=self.instance, credentials_path=self.credentials)
        self.assertEqual(
            flow.load_client_api_key(
                self.server, client_instance=self.instance,
                project_id="future-workspace",
                credentials_path=self.credentials), self.token)

    def test_expired_key_never_loads(self):
        expired = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        flow.save_client_api_key(
            self.server, self.record(expires_at=expired),
            client_instance=self.instance, credentials_path=self.credentials)
        status = flow.client_api_key_status(
            self.server, client_instance=self.instance,
            credentials_path=self.credentials)
        self.assertEqual(status["status"], "expired")
        self.assertIsNone(flow.load_client_api_key(
            self.server, client_instance=self.instance,
            credentials_path=self.credentials))

    def test_request_headers_keep_human_key_and_ai_selector_separate(self):
        flow.save_client_api_key(
            self.server, self.record(), client_instance=self.instance,
            credentials_path=self.credentials)
        codex = flow.client_request_headers(
            self.server, client_instance=self.instance, project_id="alpha",
            actor_id="alpha.director.codex",
            credentials_path=self.credentials)
        claude = flow.client_request_headers(
            self.server, client_instance=self.instance, project_id="alpha",
            actor_id="alpha.director.claude",
            credentials_path=self.credentials)
        self.assertEqual(codex["Authorization"], claude["Authorization"])
        self.assertEqual(codex[flow.CLIENT_INSTANCE_HEADER], self.instance)
        self.assertEqual(codex[flow.PROJECT_HEADER], "alpha")
        self.assertEqual(codex[flow.ACTOR_HEADER], "alpha.director.codex")
        self.assertEqual(claude[flow.ACTOR_HEADER], "alpha.director.claude")

    def test_project_and_actor_headers_are_an_atomic_pair(self):
        for project_id, actor_id in (("alpha", None),
                                     (None, "alpha.director.codex")):
            with self.subTest(project_id=project_id, actor_id=actor_id):
                with self.assertRaises(flow.TerminalFlowProtocolError):
                    flow.client_request_headers(
                        self.server, token=self.token,
                        client_instance=self.instance,
                        project_id=project_id, actor_id=actor_id)

    def test_verify_checks_server_kind_instance_human_and_scope(self):
        transport = FakeTransport()
        checked = flow.verify_client_api_key(
            self.server, self.token, client_instance=self.instance,
            project_id="alpha", actor_id="alpha.director.codex",
            transport=transport)
        self.assertEqual(checked["token_kind"], "client")
        self.assertEqual(checked["username"], "jack")
        request = transport.calls[0]
        self.assertTrue(request["url"].endswith("/tenant/v1/auth/status"))
        self.assertEqual(request["headers"][flow.PROJECT_HEADER], "alpha")
        self.assertEqual(
            request["headers"][flow.ACTOR_HEADER], "alpha.director.codex")

    def test_hidden_paste_verifies_stores_and_returns_no_secret(self):
        transport = FakeTransport()

        @contextlib.contextmanager
        def tty():
            yield object()

        with mock.patch.object(flow, "_read_hidden_line", return_value=self.token):
            result = flow.paste_client_api_key(
                self.server, client_instance=self.instance,
                project_id="alpha", actor_id="alpha.director.codex",
                credentials_path=self.credentials, transport=transport,
                tty_opener=tty)
        self.assertEqual(result["status"], "ready")
        self.assertNotIn(self.token, json.dumps(result))
        self.assertEqual(flow.load_client_api_key(
            self.server, client_instance=self.instance,
            credentials_path=self.credentials), self.token)

    def test_authorize_opens_settings_and_defers_without_tty(self):
        opened = []
        transport = FakeTransport(flow.JsonResponse(201, {}, {
            "status": "pending", "pairing_secret": "secret_pair_1234",
            "pairing_code": "ABCD-1234",
            "verification_uri_complete": self.server + "/app#pair=ABCD-1234",
            "interval": 5,
        }))

        result = flow.authorize_client(
            self.server, client_instance=self.instance,
            client_label="Laptop Codex", credentials_path=self.credentials,
            browser_open=lambda url: opened.append(url) or True,
            transport=transport)
        self.assertEqual(result["status"], "pending")
        self.assertTrue(result["hot_reload"])
        self.assertEqual(opened, [result["authorization_url"]])
        self.assertIn("#pair=ABCD-1234", opened[0])
        self.assertNotIn("atkey_", opened[0])
        self.assertNotIn("restart", json.dumps(result).lower())
        self.assertEqual(transport.calls[0]["payload"]["label"],
                         "Laptop Codex")
        self.assertNotIn("actor", transport.calls[0]["payload"])
        stored = flow.read_credentials_store(self.credentials)
        pairing = flow._pairing_record(stored, self.server, self.instance)
        self.assertEqual(pairing["pairing_secret"], "secret_pair_1234")

    def test_silent_poll_persists_approved_key_and_forgets_pairing_secret(self):
        start = FakeTransport(flow.JsonResponse(201, {}, {
            "status": "pending", "pairing_secret": "secret_pair_1234",
            "pairing_code": "ABCD-1234",
            "verification_uri_complete": self.server + "/app#pair=ABCD-1234",
            "interval": 5,
        }))
        flow.start_client_pairing(
            self.server, client_instance=self.instance,
            credentials_path=self.credentials, transport=start,
            open_browser=False)
        approved = FakeTransport(flow.JsonResponse(200, {}, {
            "status": "approved", "credential": {
                "token": self.token,
                "record": {key: value for key, value in self.record().items()
                           if key != "token"},
            },
        }))
        result = flow.poll_client_pairing(
            self.server, client_instance=self.instance,
            credentials_path=self.credentials, transport=approved)
        self.assertEqual(result["status"], "ready")
        self.assertNotIn(self.token, json.dumps(result))
        self.assertEqual(flow.load_client_api_key(
            self.server, client_instance=self.instance,
            credentials_path=self.credentials), self.token)
        stored = flow.read_credentials_store(self.credentials)
        self.assertIsNone(flow._pairing_record(
            stored, self.server, self.instance))

    def test_authorize_ready_does_not_open_browser_or_prompt(self):
        flow.save_client_api_key(
            self.server, self.record(), client_instance=self.instance,
            credentials_path=self.credentials)
        opened = []
        result = flow.authorize_client(
            self.server, client_instance=self.instance,
            credentials_path=self.credentials,
            browser_open=lambda url: opened.append(url) or True)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(opened, [])

    def test_legacy_credential_is_reported_but_never_promoted(self):
        legacy = {
            "schema": 1,
            "servers": {self.server: {
                "terminal_credential": {
                    "token": "atd_old.secret", "token_kind": "terminal"}}},
        }
        self.credentials.write_text(json.dumps(legacy), encoding="utf-8")
        os.chmod(self.credentials, 0o600)
        status = flow.client_api_key_status(
            self.server, client_instance=self.instance,
            credentials_path=self.credentials)
        self.assertEqual(status["status"], "authorization_required")
        self.assertTrue(status["legacy_credential_present"])
        self.assertIsNone(flow.load_terminal_credential(
            self.server, device_id="device_old",
            client_instance_id=self.instance,
            credentials_path=self.credentials))

    def test_concurrent_updates_preserve_both_server_records(self):
        barrier = threading.Barrier(2)
        errors = []

        def save(server, token_id):
            try:
                barrier.wait(timeout=5)
                flow.save_client_api_key(
                    server, self.record(
                        token="atkey_%s.secret-value" % token_id,
                        token_id=token_id),
                    client_instance=self.instance,
                    credentials_path=self.credentials)
            except Exception as error:  # pragma: no cover - asserted below
                errors.append(error)

        threads = [
            threading.Thread(target=save, args=("https://a.test", "key_a")),
            threading.Thread(target=save, args=("https://b.test", "key_b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(errors, [])
        data = flow.read_credentials_store(self.credentials)
        self.assertEqual(set(data["servers"]), {
            "https://a.test", "https://b.test"})

    def test_device_id_is_audit_only_private_and_stable(self):
        first = flow.load_device_id(self.identity)
        second = flow.load_device_id(self.identity)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("device_"))
        self.assertEqual(stat.S_IMODE(self.identity.stat().st_mode), 0o600)

    def test_public_message_requires_ai_initiation_not_user_command(self):
        message = flow.format_authorization_message({
            "status": "authorization_required",
            "authorization_url": self.server + "/app#settings",
        }, self.server, "alpha")
        lowered = message.lower()
        self.assertIn("active ai opened", lowered)
        self.assertIn("polls silently", lowered)
        self.assertIn("never paste", lowered)
        self.assertIn("no coding-client restart", lowered)
        self.assertNotIn("run `", lowered)
        self.assertNotIn("setup --", lowered)


if __name__ == "__main__":
    unittest.main()
