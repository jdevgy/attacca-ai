"""Adversarial tests for the D-17 per-client API-key boundary."""

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from attacca import terminal_flow as flow


class StaticTransport:
    def __init__(self, status, value):
        self.status = status
        self.value = value
        self.calls = []

    def request(self, method, url, *, headers, payload=None, timeout=5):
        self.calls.append((method, url, dict(headers), payload))
        return flow.JsonResponse(self.status, {}, self.value)


class ClientAuthorizationRedTeamTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.credentials = self.root / "credentials.json"
        self.client_file = self.root / "client.json"
        self.instance = flow.load_client_instance_id(
            self.client_file, runtime="generic")
        self.server = "https://attacca.test/base"
        self.token = "atkey_key_redteam.abcdefghijklmnopqrstuvwxyz012345"

    def tearDown(self):
        self.temp.cleanup()

    def response(self, **principal_overrides):
        principal = {
            "token_kind": "client", "token_id": "key_redteam",
            "client_instance": self.instance,
            "project_memberships": ["alpha"],
        }
        principal.update(principal_overrides)
        return {
            "authenticated": True,
            "user": {"username": "jack"},
            "principal": principal,
        }

    def record(self, **overrides):
        result = {
            "token": self.token, "token_kind": "client",
            "token_id": "key_redteam", "client_instance": self.instance,
            "username": "jack", "project_memberships": ["alpha"],
        }
        result.update(overrides)
        return result

    def test_url_canonicalization_is_tenant_exact_and_rejects_traversal(self):
        self.assertEqual(
            flow.canonical_server_url("HTTPS://Attacca.Test:443/base/"),
            self.server)
        rejected = (
            "https://attacca.test/base/../other",
            "https://attacca.test/base/%2e%2e/other",
            "https://attacca.test/base//other",
            "https://attacca.test/base\\other",
            "https://user:secret@attacca.test/base",
            "https://attacca.test/base?token=oops",
            "file:///tmp/attacca",
        )
        for value in rejected:
            with self.subTest(value=value):
                with self.assertRaises(flow.TerminalFlowProtocolError):
                    flow.canonical_server_url(value)

    def test_settings_url_is_same_tenant_and_contains_no_secret(self):
        url = flow.client_key_settings_url(
            self.server, self.instance, "Office / Codex")
        self.assertTrue(url.startswith(self.server + "/app#settings&"))
        self.assertIn("client_instance=", url)
        self.assertIn("client_label=", url)
        self.assertNotIn("atkey_", url)
        self.assertNotIn("token", url.lower())

    def test_only_atkey_values_can_enter_modern_store(self):
        for secret in (
                "atd_old.secret", "atsvc_old.secret", "atc_actor.secret",
                "plain", "atkey_ bad", "atkey_bad\nleak", ""):
            with self.subTest(secret=secret):
                with self.assertRaises(flow.TerminalFlowProtocolError):
                    flow.save_client_api_key(
                        self.server, self.record(token=secret),
                        client_instance=self.instance,
                        credentials_path=self.credentials)

    def test_wrong_kind_instance_human_or_scope_is_rejected(self):
        cases = (
            self.response(token_kind="terminal"),
            self.response(client_instance="client_other"),
            {"authenticated": True, "user": {},
             "principal": self.response()["principal"]},
            self.response(project_memberships=["beta"]),
        )
        for response in cases:
            with self.subTest(response=response):
                with self.assertRaises(flow.TerminalFlowProtocolError):
                    flow.verify_client_api_key(
                        self.server, self.token,
                        client_instance=self.instance,
                        project_id="alpha", actor_id="alpha.worker.codex",
                        transport=StaticTransport(200, response))

    def test_unauthorized_revoked_or_malformed_server_response_never_saves(self):
        cases = (
            StaticTransport(401, {"error": "invalid_credential"}),
            StaticTransport(403, {"error": "client_actor_denied"}),
            StaticTransport(500, {"error": "boom"}),
            StaticTransport(200, {"authenticated": "yes"}),
        )
        for transport in cases:
            with self.subTest(status=transport.status, value=transport.value):
                with self.assertRaises(flow.TerminalFlowProtocolError):
                    flow.verify_client_api_key(
                        self.server, self.token,
                        client_instance=self.instance, transport=transport)
                self.assertFalse(self.credentials.exists())

    def test_symlink_and_insecure_credentials_are_rejected_before_secret_read(self):
        real = self.root / "real.json"
        real.write_text(json.dumps({
            "schema": 2, "servers": {self.server: {
                "client_api_keys": {self.instance: self.record()}}}}),
            encoding="utf-8")
        os.chmod(real, 0o600)
        linked = self.root / "linked.json"
        linked.symlink_to(real)
        with self.assertRaises(flow.TerminalFlowProtocolError):
            flow.load_client_api_key(
                self.server, client_instance=self.instance,
                credentials_path=linked)
        os.chmod(real, 0o644)
        with self.assertRaises(flow.TerminalFlowProtocolError):
            flow.load_client_api_key(
                self.server, client_instance=self.instance,
                credentials_path=real)

    def test_symlinked_client_identity_is_rejected(self):
        real = self.root / "real-client.json"
        real.write_text(json.dumps({
            "schema": 1, "client_instance": "client_stolen"}),
            encoding="utf-8")
        os.chmod(real, 0o600)
        linked = self.root / "linked-client.json"
        linked.symlink_to(real)
        with self.assertRaises(flow.TerminalFlowProtocolError):
            flow.load_client_instance_id(linked, runtime="generic")
        with mock.patch.dict(os.environ, {
                "ATTACCA_CLIENT_INSTANCE_FILE": str(linked)}):
            with self.assertRaises(flow.TerminalFlowProtocolError):
                flow.load_client_instance_id(runtime="generic")

    def test_corrupt_and_oversized_private_state_fails_closed(self):
        self.credentials.write_text("not json", encoding="utf-8")
        os.chmod(self.credentials, 0o600)
        with self.assertRaises(flow.TerminalFlowProtocolError):
            flow.read_credentials_store(self.credentials)
        self.credentials.write_bytes(b"x" * (flow.MAX_CREDENTIALS_BYTES + 1))
        os.chmod(self.credentials, 0o600)
        with self.assertRaises(flow.TerminalFlowProtocolError):
            flow.read_credentials_store(self.credentials)

    def test_redirects_are_never_followed_with_bearer(self):
        handler = flow._RejectRedirects()
        self.assertIsNone(handler.redirect_request(
            object(), None, 302, "redirect", {}, "https://evil.test"))

    def test_authorization_public_result_and_message_never_reflect_key(self):
        opened = []
        poll_secret = "poll_secret_never_reflect_12345"
        request_token = "D" * 43
        transport = StaticTransport(201, {
            "status": "pending", "poll_secret": poll_secret,
            "authorization_request": request_token,
            "verification_uri_complete":
                self.server +
                "/app#settings&authorization_request=" + request_token,
            "expires_in": 600, "interval": 5,
        })

        result = flow.authorize_client(
            self.server, client_instance=self.instance,
            credentials_path=self.credentials,
            browser_open=lambda value: opened.append(value) or True,
            transport=transport)
        message = flow.format_authorization_message(result, self.server)
        serialized = json.dumps(result) + message + "".join(opened)
        self.assertNotIn(self.token, serialized)
        self.assertNotIn(poll_secret, serialized)
        self.assertNotIn("device code", serialized.lower())
        self.assertNotIn("actor binding", serialized.lower())
        self.assertNotIn("run attacca", serialized.lower())
        self.assertEqual(len(transport.calls), 1)
        payload = transport.calls[0][3]
        self.assertNotIn("actor", payload)
        self.assertNotIn("project", payload)
        self.assertNotIn("runtime", payload)

    def test_hidden_paste_does_not_accept_ordinary_stdin(self):
        fake = io.StringIO(self.token)
        self.assertFalse(fake.isatty())

        @contextlib.contextmanager
        def opener():
            yield fake

        with self.assertRaises(flow.ControllingTerminalUnavailable):
            flow.paste_client_api_key(
                self.server, client_instance=self.instance,
                credentials_path=self.credentials, tty_opener=opener)

    def test_compatibility_wrappers_never_call_retired_endpoints(self):
        request_token = "E" * 43
        transport = StaticTransport(201, {
            "status": "pending",
            "poll_secret": "poll_secret_wrapper_12345",
            "authorization_request": request_token,
            "verification_uri_complete":
                self.server +
                "/app#settings&authorization_request=" + request_token,
            "expires_in": 600, "interval": 5,
        })
        result = flow.start_device_flow(
            self.server, device_id="device_a", client_instance_id=self.instance,
            requested_bindings=[{
                "project_id": "alpha", "actor_id": "alpha.worker.codex"}],
            credentials_path=self.credentials, transport=transport,
            open_browser=False)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(len(transport.calls), 1)
        method, url, _headers, payload = transport.calls[0]
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/v1/auth/client-authorizations"))
        self.assertNotIn("actor", payload)
        self.assertNotIn("project", payload)
        self.assertNotIn("runtime", payload)
        self.assertNotIn("/terminal/", url)
        self.assertNotIn("device-code", url)
        self.assertNotIn("device_code", json.dumps(result))
        self.assertNotIn("user_code", json.dumps(result))

    def test_cli_exposes_no_token_argv_or_device_enrollment_action(self):
        source = Path(flow.__file__).read_text(encoding="utf-8")
        main = source[source.index("def main("):]
        self.assertIn('choices=("authorize", "open", "paste", "status")', main)
        self.assertNotIn('"--token"', main)
        self.assertNotIn('"--device-code"', main)
        self.assertNotIn('"--binding"', main)

    def test_credentials_mode_remains_private_after_replacement(self):
        flow.save_client_api_key(
            self.server, self.record(), client_instance=self.instance,
            credentials_path=self.credentials)
        first_inode = self.credentials.stat().st_ino
        flow.save_client_api_key(
            self.server, self.record(label="Replacement"),
            client_instance=self.instance, credentials_path=self.credentials)
        self.assertEqual(stat.S_IMODE(self.credentials.stat().st_mode), 0o600)
        self.assertNotEqual(first_inode, self.credentials.stat().st_ino)


if __name__ == "__main__":
    unittest.main()
