"""Isolated terminal/device authorization tests; no live server or database."""

import contextlib
import io
import json
import os
import stat
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import terminal_flow as flow  # noqa: E402


SERVER = "https://attacca.test/base"
DEVICE = "dev_test_machine"
INSTANCE = "client_codex_install"
DEVICE_CODE = "device-secret-" + "x" * 52


def binding(project, actor, runtime):
    return {"project_id": project, "actor_id": actor, "runtime": runtime}


A = binding("project-a", "project-a.director.codex", "codex")
B = binding("project-b", "project-b.director.claude", "claude")
C = binding("project-c", "project-c.worker.kimi", "kimi")


def start_payload(device_code=DEVICE_CODE, *, base=SERVER):
    return {
        "device_code": device_code,
        "user_code": "ABCD-1234",
        "verification_uri": base + "/terminal",
        "verification_uri_complete": base + "/terminal?code=ABCD-1234",
        "expires_in": 600,
        "interval": 5,
    }


def principal(bindings, token_id="terminal-token-1"):
    return {
        "token_kind": "terminal",
        "token_id": token_id,
        "device_id": DEVICE,
        "bindings": bindings,
        "created_at": "2026-08-24T00:00:00+00:00",
    }


class QueueTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []
        self.lock = threading.Lock()

    def request(self, method, url, *, headers, payload=None, timeout=5):
        with self.lock:
            self.calls.append({
                "method": method, "url": url, "headers": dict(headers),
                "payload": payload, "timeout": timeout,
            })
            if not self.responses:
                raise AssertionError("unexpected terminal-flow request")
            response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        status, value = response if isinstance(response, tuple) else (200, response)
        return flow.JsonResponse(status, {"content-type": "application/json"}, value)


class TerminalFlowTest(unittest.TestCase):
    def paths(self, temporary):
        root = Path(temporary)
        return root / "terminal-flow.json", root / "credentials.json"

    def start(self, state, transport, *, bindings=(A,), server=SERVER,
              now=100, open_browser=False, browser_open=None,
              instance=INSTANCE):
        return flow.start_device_flow(
            server, device_id=DEVICE, client_label="Attacca terminal test",
            requested_bindings=list(bindings), state_path=state,
            transport=transport, now=now, open_browser=open_browser,
            browser_open=browser_open, client_instance_id=instance)

    def test_start_keeps_device_code_private_and_opens_only_when_requested(self):
        with TemporaryDirectory() as temporary:
            state, _ = self.paths(temporary)
            transport = QueueTransport(start_payload())
            result = self.start(state, transport)
            public = json.dumps(result)
            self.assertEqual(result["status"], "started")
            self.assertNotIn(DEVICE_CODE, public)
            self.assertNotIn("device_code", public)
            saved = json.loads(state.read_text())
            self.assertEqual(saved["flows"][SERVER]["device_code"], DEVICE_CODE)
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)
            call = transport.calls[0]
            self.assertEqual(call["headers"]["X-Attacca-Device-ID"], DEVICE)
            self.assertEqual(
                call["headers"]["X-Attacca-Client-Instance"], INSTANCE)

    def test_active_retry_opens_existing_pending_url_without_second_start(self):
        with TemporaryDirectory() as temporary:
            state, credentials = self.paths(temporary)
            transport = QueueTransport(start_payload())
            self.start(state, transport)
            opened = []
            result = flow.advance_device_flow(
                SERVER, device_id=DEVICE, client_label="Attacca terminal test",
                requested_bindings=[A], state_path=state,
                credentials_path=credentials, transport=transport, now=101,
                open_browser=True,
                browser_open=lambda url, new=0: opened.append((url, new)) or True,
                client_instance_id=INSTANCE)
            self.assertEqual(result["status"], "pending")
            self.assertTrue(result["browser_opened"])
            self.assertEqual(opened, [(start_payload()[
                "verification_uri_complete"], 2)])
            self.assertEqual(len(transport.calls), 1)
            repeated = flow.advance_device_flow(
                SERVER, device_id=DEVICE, client_label="Attacca terminal test",
                requested_bindings=[A], state_path=state,
                credentials_path=credentials, transport=transport, now=102,
                open_browser=True,
                browser_open=lambda url, new=0: opened.append((url, new)) or True,
                client_instance_id=INSTANCE)
            self.assertEqual(repeated["status"], "pending")
            self.assertFalse(repeated["browser_opened"])
            self.assertEqual(len(opened), 1)

    def test_default_ports_compare_equal_but_base_path_escape_is_rejected(self):
        cases = (
            ("http://example.test/base", "http://example.test:80/base/auth"),
            ("https://example.test/base", "https://example.test:443/base/auth"),
        )
        for index, (server, verification) in enumerate(cases):
            with self.subTest(server=server), TemporaryDirectory() as temporary:
                state, _ = self.paths(temporary)
                payload = start_payload(base=server)
                payload["verification_uri"] = verification
                payload["verification_uri_complete"] = verification + "?c=1"
                result = self.start(
                    state, QueueTransport(payload), server=server,
                    instance="client_port_%d" % index)
                self.assertEqual(result["status"], "started")
        with TemporaryDirectory() as temporary:
            state, _ = self.paths(temporary)
            payload = start_payload()
            payload["verification_uri"] = "https://attacca.test/other/auth"
            with self.assertRaises(flow.TerminalFlowProtocolError):
                self.start(state, QueueTransport(payload))

    def test_real_ephemeral_http_start_accepts_created_201(self):
        captured = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                captured.append({
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": json.loads(self.rfile.read(length).decode("utf-8")),
                })
                host = self.headers["Host"]
                body = json.dumps(start_payload(
                    base="http://%s/tenant" % host)).encode("utf-8")
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.assertNotEqual(server.server_address[1], 4173)
            base = "http://127.0.0.1:%d/tenant" % server.server_address[1]
            with TemporaryDirectory() as temporary:
                state, _ = self.paths(temporary)
                result = flow.start_device_flow(
                    base, device_id=DEVICE, client_label="Attacca E2E",
                    requested_bindings=[A], state_path=state,
                    client_instance_id=INSTANCE)
            self.assertEqual(result["status"], "started")
            self.assertEqual(captured[0]["path"],
                             "/tenant/v1/auth/device/start")
            self.assertEqual(captured[0]["body"]["device_id"], DEVICE)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)

    def test_cross_runtime_advances_creator_bound_flow_over_real_http(self):
        """Claude can finish a Codex-started shared device enrollment."""
        observed_instances = []
        creator = "client_codex_creator"
        follower = "client_claude_follower"

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def reply(self, status, value):
                body = json.dumps(value).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(
                    self.rfile.read(length).decode("utf-8"))
                instance = self.headers.get("X-Attacca-Client-Instance")
                observed_instances.append((self.path, instance))
                if self.path == flow.DEVICE_START_PATH:
                    self.server.creator_instance = instance
                    base = "http://%s" % self.headers["Host"]
                    self.reply(201, start_payload(base=base))
                    return
                if self.path == flow.DEVICE_POLL_PATH:
                    if instance != self.server.creator_instance:
                        self.reply(401, {"error": "client instance mismatch"})
                        return
                    self.assert_device_payload(payload)
                    self.reply(200, {
                        "status": "approved",
                        "credential": {
                            "token": DEVICE_CODE,
                            **principal([A]),
                        },
                    })
                    return
                self.reply(404, {})

            @staticmethod
            def assert_device_payload(payload):
                if payload != {"device_code": DEVICE_CODE,
                               "device_id": DEVICE}:
                    raise AssertionError("unexpected device poll payload")

            def do_GET(self):
                instance = self.headers.get("X-Attacca-Client-Instance")
                observed_instances.append((self.path, instance))
                if self.path != flow.AUTH_STATUS_PATH \
                        or instance != self.server.creator_instance \
                        or self.headers.get("Authorization") != \
                        "Bearer " + DEVICE_CODE:
                    self.reply(401, {"authenticated": False})
                    return
                self.reply(200, {
                    "authenticated": True,
                    "principal": principal([A]),
                })

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.creator_instance = None
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.assertNotEqual(server.server_address[1], 4173)
            base = "http://127.0.0.1:%d" % server.server_address[1]
            with TemporaryDirectory() as temporary:
                state, credentials = self.paths(temporary)
                started = flow.start_device_flow(
                    base, device_id=DEVICE,
                    client_label="Attacca shared terminal",
                    requested_bindings=[A], state_path=state,
                    now=100, client_instance_id=creator)
                self.assertNotIn(creator, json.dumps(started))
                private = json.loads(state.read_text())["flows"][base]
                self.assertEqual(private["client_instance_id"], creator)

                completed = flow.advance_device_flow(
                    base, device_id=DEVICE,
                    client_label="Attacca shared terminal",
                    requested_bindings=[A], state_path=state,
                    credentials_path=credentials, now=110,
                    force_poll=True, client_instance_id=follower)
                self.assertEqual(completed["status"], "approved")
                self.assertNotIn(DEVICE_CODE, json.dumps(completed))
                self.assertEqual(flow.load_terminal_credential(
                    base, device_id=DEVICE,
                    project_id=A["project_id"], actor_id=A["actor_id"],
                    runtime=A["runtime"],
                    credentials_path=credentials), DEVICE_CODE)
            self.assertEqual([item[1] for item in observed_instances],
                             [creator, creator, creator])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)

    def test_approved_and_consumed_are_retry_safe_and_secret_free(self):
        for returned_state in ("approved", "consumed"):
            with self.subTest(returned_state=returned_state), \
                    TemporaryDirectory() as temporary:
                state, credentials = self.paths(temporary)
                credentials.write_text(json.dumps({
                    "version": 1,
                    "servers": {SERVER: {"agent_tokens": {
                        "project-a": {"legacy": {"token": "legacy-secret"}}
                    }}},
                }))
                os.chmod(credentials, 0o600)
                self.start(state, QueueTransport(start_payload()))
                poll_value = {"status": returned_state}
                if returned_state == "approved":
                    poll_value["credential"] = {
                        "token": DEVICE_CODE,
                        **principal([A]),
                    }
                transport = QueueTransport(
                    poll_value,
                    {"authenticated": True, "principal": principal([A])})
                result = flow.poll_device_flow(
                    SERVER, device_id=DEVICE, state_path=state,
                    credentials_path=credentials, transport=transport,
                    now=110, force=True, client_instance_id=INSTANCE)
                self.assertEqual(result["status"], "approved")
                self.assertNotIn(DEVICE_CODE, json.dumps(result))
                saved = json.loads(credentials.read_text())
                server = saved["servers"][SERVER]
                self.assertIn("agent_tokens", server)
                self.assertEqual(server["terminal_credential"]["token"], DEVICE_CODE)
                self.assertEqual(stat.S_IMODE(credentials.stat().st_mode), 0o600)
                self.assertNotIn(SERVER, json.loads(state.read_text())["flows"])
                self.assertEqual(
                    transport.calls[1]["headers"]["Authorization"],
                    "Bearer " + DEVICE_CODE)

    def test_approved_response_must_promote_exact_device_code(self):
        with TemporaryDirectory() as temporary:
            state, credentials = self.paths(temporary)
            self.start(state, QueueTransport(start_payload()))
            transport = QueueTransport({
                "status": "approved",
                "credential": {"token": "different-secret", **principal([A])},
            })
            with self.assertRaises(flow.TerminalFlowProtocolError):
                flow.poll_device_flow(
                    SERVER, device_id=DEVICE, state_path=state,
                    credentials_path=credentials, transport=transport,
                    now=110, force=True, client_instance_id=INSTANCE)
            self.assertIn(SERVER, json.loads(state.read_text())["flows"])
            self.assertFalse(credentials.exists())

    def test_extension_requests_union_and_preserves_a_when_adding_b(self):
        with TemporaryDirectory() as temporary:
            state, credentials = self.paths(temporary)
            flow.save_terminal_credential(
                SERVER, {"token": "old-terminal", **principal([A], "old-id")},
                device_id=DEVICE, credentials_path=credentials)
            partial = flow.terminal_credential_status(
                SERVER, device_id=DEVICE, requested_bindings=[A, B],
                credentials_path=credentials)
            self.assertEqual(partial["status"], "binding_missing")
            transport = QueueTransport(start_payload())
            result = flow.advance_device_flow(
                SERVER, device_id=DEVICE, client_label="Attacca terminal test",
                requested_bindings=[B], state_path=state,
                credentials_path=credentials, transport=transport, now=100,
                client_instance_id="client_claude_install")
            self.assertEqual(result["status"], "started")
            requested = transport.calls[0]["payload"]["requested_bindings"]
            self.assertEqual(requested, [B, A])
            self.assertEqual(
                transport.calls[0]["payload"]["supersede_token_id"], "old-id")
            self.assertEqual(
                transport.calls[0]["headers"]["Authorization"],
                "Bearer old-terminal")
            private_state = state.read_text()
            self.assertNotIn("old-terminal", private_state)
            approved = QueueTransport(
                {"status": "approved", "credential": {
                    "token": DEVICE_CODE, **principal([A, B], "new-id")}},
                {"authenticated": True, "principal": principal([A, B], "new-id")})
            flow.poll_device_flow(
                SERVER, device_id=DEVICE, state_path=state,
                credentials_path=credentials, transport=approved,
                now=110, force=True,
                client_instance_id="client_claude_install")
            token_a = flow.load_terminal_credential(
                SERVER, device_id=DEVICE, project_id=A["project_id"],
                actor_id=A["actor_id"], runtime=A["runtime"],
                credentials_path=credentials)
            token_b = flow.load_terminal_credential(
                SERVER, device_id=DEVICE, project_id=B["project_id"],
                actor_id=B["actor_id"], runtime=B["runtime"],
                credentials_path=credentials)
            self.assertEqual(token_a, DEVICE_CODE)
            self.assertEqual(token_b, DEVICE_CODE)

    def test_provisional_zero_binding_is_human_only_until_exact_extension(self):
        with TemporaryDirectory() as temporary:
            state, credentials = self.paths(temporary)
            self.start(state, QueueTransport(start_payload()), bindings=())
            provisional = principal([], "provisional-terminal")
            transport = QueueTransport(
                {"status": "approved", "credential": {
                    "token": DEVICE_CODE, **provisional}},
                {"authenticated": True, "principal": provisional})
            result = flow.poll_device_flow(
                SERVER, device_id=DEVICE, state_path=state,
                credentials_path=credentials, transport=transport,
                now=110, force=True, client_instance_id=INSTANCE)
            self.assertEqual(result["status"], "approved")
            self.assertEqual(result["binding_count"], 0)
            self.assertEqual(flow.load_terminal_credential(
                SERVER, device_id=DEVICE,
                credentials_path=credentials), DEVICE_CODE)
            self.assertIsNone(flow.load_terminal_credential(
                SERVER, device_id=DEVICE, project_id=A["project_id"],
                actor_id=A["actor_id"], runtime=A["runtime"],
                credentials_path=credentials))

            extension_code = "extension-device-" + "y" * 52
            extension = QueueTransport(start_payload(extension_code))
            started = flow.advance_device_flow(
                SERVER, device_id=DEVICE,
                client_label="Attacca shared terminal",
                requested_bindings=[A], state_path=state,
                credentials_path=credentials, transport=extension,
                now=120, client_instance_id="client_setup_apply")
            self.assertEqual(started["status"], "started")
            call = extension.calls[0]
            self.assertEqual(call["payload"]["requested_bindings"], [A])
            self.assertEqual(call["payload"]["supersede_token_id"],
                             "provisional-terminal")
            self.assertEqual(call["headers"]["Authorization"],
                             "Bearer " + DEVICE_CODE)
            self.assertNotIn(DEVICE_CODE, state.read_text())

    def test_binding_helper_verifies_and_resaves_same_bearer_without_leak(self):
        with TemporaryDirectory() as temporary:
            _, credentials = self.paths(temporary)
            provisional = principal([], "terminal/provisional")
            flow.save_terminal_credential(
                SERVER, {"token": "provisional-bearer", **provisional},
                device_id=DEVICE, credentials_path=credentials)
            bound = principal([A], "terminal/provisional")
            transport = QueueTransport(
                {"ok": True, "record": bound},
                {"authenticated": True, "principal": bound})
            result = flow.add_terminal_binding(
                SERVER, device_id=DEVICE,
                project_id=A["project_id"], actor_id=A["actor_id"],
                runtime=A["runtime"], credentials_path=credentials,
                transport=transport, client_instance_id=INSTANCE)
            self.assertEqual(result["status"], "bound")
            self.assertEqual(result["binding_count"], 1)
            self.assertNotIn("provisional-bearer", json.dumps(result))
            self.assertTrue(transport.calls[0]["url"].endswith(
                "/v1/auth/terminals/terminal%2Fprovisional/bindings"))
            self.assertEqual(transport.calls[0]["payload"], {
                "project_id": A["project_id"],
                "actor_id": A["actor_id"],
            })
            for call in transport.calls:
                self.assertEqual(
                    call["headers"]["X-Attacca-Device-ID"], DEVICE)
                self.assertEqual(
                    call["headers"]["X-Attacca-Client-Instance"], INSTANCE)
            self.assertEqual(flow.load_terminal_credential(
                SERVER, device_id=DEVICE,
                project_id=A["project_id"], actor_id=A["actor_id"],
                runtime=A["runtime"],
                credentials_path=credentials), "provisional-bearer")
            self.assertEqual(stat.S_IMODE(credentials.stat().st_mode), 0o600)

    def test_binding_helper_never_saves_unverified_actor_metadata(self):
        with TemporaryDirectory() as temporary:
            _, credentials = self.paths(temporary)
            provisional = principal([], "provisional-terminal")
            flow.save_terminal_credential(
                SERVER, {"token": "provisional-bearer", **provisional},
                device_id=DEVICE, credentials_path=credentials)
            transport = QueueTransport({"ok": True, "record": provisional})
            with self.assertRaises(flow.TerminalFlowProtocolError):
                flow.add_terminal_binding(
                    SERVER, device_id=DEVICE,
                    project_id=A["project_id"], actor_id=A["actor_id"],
                    runtime=A["runtime"], credentials_path=credentials,
                    transport=transport, client_instance_id=INSTANCE)
            saved = json.loads(credentials.read_text())[
                "servers"][SERVER]["terminal_credential"]
            self.assertEqual(saved["bindings"], [])
            self.assertEqual(saved["token"], "provisional-bearer")

    def test_revoked_supersede_bearer_falls_back_to_public_browser_start(self):
        with TemporaryDirectory() as temporary:
            state, credentials = self.paths(temporary)
            flow.save_terminal_credential(
                SERVER, {"token": "revoked-terminal",
                         **principal([A], "revoked-id")},
                device_id=DEVICE, credentials_path=credentials)
            transport = QueueTransport((401, {}), (201, start_payload()))
            result = flow.advance_device_flow(
                SERVER, device_id=DEVICE,
                client_label="Attacca terminal test",
                requested_bindings=[B], state_path=state,
                credentials_path=credentials, transport=transport, now=100,
                client_instance_id=INSTANCE)
            self.assertEqual(result["status"], "started")
            self.assertEqual(len(transport.calls), 2)
            self.assertEqual(
                transport.calls[0]["headers"]["Authorization"],
                "Bearer revoked-terminal")
            self.assertEqual(
                transport.calls[0]["payload"]["supersede_token_id"],
                "revoked-id")
            self.assertNotIn("Authorization", transport.calls[1]["headers"])
            self.assertNotIn("supersede_token_id",
                             transport.calls[1]["payload"])
            self.assertEqual(
                transport.calls[1]["payload"]["requested_bindings"], [B, A])
            self.assertNotIn("revoked-terminal", state.read_text())

    def test_one_credential_authorizes_codex_claude_kimi_but_not_spoof(self):
        with TemporaryDirectory() as temporary:
            _, credentials = self.paths(temporary)
            flow.save_terminal_credential(
                SERVER, {"token": "shared-terminal", **principal([A, B, C])},
                device_id=DEVICE, credentials_path=credentials)
            for expected in (A, B, C):
                self.assertEqual(flow.load_terminal_credential(
                    SERVER, device_id=DEVICE,
                    project_id=expected["project_id"],
                    actor_id=expected["actor_id"],
                    runtime=expected["runtime"],
                    credentials_path=credentials), "shared-terminal")
            self.assertIsNone(flow.load_terminal_credential(
                SERVER, device_id=DEVICE, project_id=A["project_id"],
                actor_id="project-a.worker.evil", runtime="codex",
                credentials_path=credentials))
            self.assertIsNone(flow.load_terminal_credential(
                SERVER, device_id="dev_other", project_id=A["project_id"],
                actor_id=A["actor_id"], runtime="codex",
                credentials_path=credentials))

    def test_same_runtime_instances_share_one_flow_and_have_stable_audit_ids(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, credentials = self.paths(temporary)
            transport = QueueTransport(start_payload())
            results = []

            def invoke(instance):
                results.append(flow.advance_device_flow(
                    SERVER, device_id=DEVICE,
                    client_label="Attacca terminal test",
                    requested_bindings=[A], state_path=state,
                    credentials_path=credentials, transport=transport, now=100,
                    client_instance_id=instance))

            threads = [threading.Thread(target=invoke, args=(name,)) for name in
                       ("client_codex_2", "client_codex_3")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(transport.calls), 1)
            self.assertEqual({item["status"] for item in results},
                             {"started", "pending"})
            install_a = root / "install-a.json"
            install_b = root / "install-b.json"
            first = flow.load_client_instance_id(install_a, "codex")
            self.assertEqual(first, flow.load_client_instance_id(
                install_a, "codex"))
            self.assertNotEqual(first, flow.load_client_instance_id(
                install_b, "codex"))
            self.assertEqual(stat.S_IMODE(install_a.stat().st_mode), 0o600)

    def test_denied_expired_text_never_delegates_a_recovery_command(self):
        for state in ("denied", "expired"):
            message = flow.format_recovery_message({"status": state}, SERVER)
            lowered = message.lower()
            self.assertIn("active ai", lowered)
            self.assertIn("next retry", lowered)
            self.assertNotIn("setup --", lowered)
            self.assertNotIn("paste-token", lowered)
            self.assertNotIn("run ", lowered)

    def test_hidden_paste_has_no_secret_argument_and_requires_real_tty(self):
        with mock.patch.object(flow.os, "open", side_effect=OSError("no tty")):
            with self.assertRaises(flow.ControllingTerminalUnavailable):
                with flow.open_controlling_terminal():
                    self.fail("unavailable TTY must fail closed")
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
            flow.main(["--help"])
        help_text = output.getvalue().lower()
        self.assertNotIn("--token", help_text)
        self.assertNotIn("--password", help_text)

    def test_hidden_paste_verifies_binding_and_returns_no_secret(self):
        @contextlib.contextmanager
        def verified_tty():
            yield object()

        with TemporaryDirectory() as temporary:
            _, credentials = self.paths(temporary)
            transport = QueueTransport({
                "authenticated": True,
                "principal": principal([A]),
            })
            with mock.patch.object(
                    flow, "_read_hidden_line", return_value="pasted-terminal"):
                result = flow.paste_from_controlling_tty(
                    SERVER, device_id=DEVICE, requested_bindings=[A],
                    credentials_path=credentials, transport=transport,
                    tty_opener=verified_tty,
                    client_instance_id=INSTANCE)
            self.assertNotIn("pasted-terminal", json.dumps(result))
            self.assertEqual(flow.load_terminal_credential(
                SERVER, device_id=DEVICE, project_id=A["project_id"],
                actor_id=A["actor_id"], runtime=A["runtime"],
                credentials_path=credentials), "pasted-terminal")

    def test_machine_device_id_is_private_and_restart_stable(self):
        with TemporaryDirectory() as temporary:
            identity = Path(temporary) / "identity.json"
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("ATTACCA_DEVICE_ID", None)
                first = flow.load_device_id(identity)
                second = flow.load_device_id(identity)
            self.assertEqual(first, second)
            self.assertTrue(first.startswith("dev_"))
            self.assertEqual(stat.S_IMODE(identity.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
