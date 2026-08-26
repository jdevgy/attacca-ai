"""Adversarial client-only checks for shared terminal authentication.

No test in this file starts a server or discovers an installed Attacca URL.
Every secret-bearing file lives in a TemporaryDirectory and every HTTP result
comes from an in-memory transport.
"""

import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent

CORE_SPEC = importlib.util.spec_from_file_location(
    "attacca_terminal_client_redteam_core", ROOT / "attacca.py")
core = importlib.util.module_from_spec(CORE_SPEC)
CORE_SPEC.loader.exec_module(core)

FLOW_SPEC = importlib.util.spec_from_file_location(
    "attacca_terminal_client_redteam_flow", ROOT / "terminal_flow.py")
flow = importlib.util.module_from_spec(FLOW_SPEC)
sys.modules[FLOW_SPEC.name] = flow
FLOW_SPEC.loader.exec_module(flow)

HOOK_SPEC = importlib.util.spec_from_file_location(
    "attacca_terminal_client_redteam_hook", ROOT / "hooks" /
    "session_start.py")
hook = importlib.util.module_from_spec(HOOK_SPEC)
sys.modules[HOOK_SPEC.name] = hook
HOOK_SPEC.loader.exec_module(hook)


SERVER = "https://attacca.test/tenant"
DEVICE = "dev_client_redteam"
ACTOR = "alpha.director.codex"
OTHER_SAME_RUNTIME_ACTOR = "alpha.worker.codex"
BINDING = {
    "project_id": "alpha",
    "actor_id": ACTOR,
    "runtime": "codex",
}
SECOND_BINDING = {
    "project_id": "alpha",
    "actor_id": "alpha.worker.kimi",
    "runtime": "kimi",
}


def credential(token="atd_client-redteam-secret"):
    return {
        "token": token,
        "token_kind": "terminal",
        "token_id": "tok_client-redteam",
        "device_id": DEVICE,
        "bindings": [BINDING],
    }


class StaticStartTransport:
    def __init__(self, value):
        self.value = value

    def request(self, *_args, **_kwargs):
        return flow.JsonResponse(status=201, headers={}, value=self.value)


class JsonMcpResponse:
    def __init__(self):
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    @staticmethod
    def read():
        return b'{"jsonrpc":"2.0","id":1,"result":{}}'


class ReplacementStartTransport:
    """Reject a stale supersede bearer, then accept public reenrollment."""

    def __init__(self):
        self.private_device_code = "atd_" + "r" * 48
        self.calls = []

    def request(self, method, url, *, headers, payload=None, timeout=None):
        del timeout
        self.calls.append({
            "method": method,
            "url": url,
            "authorized": "Authorization" in headers,
            "payload": json.loads(json.dumps(payload or {})),
        })
        if len(self.calls) == 1:
            return flow.JsonResponse(
                status=401, headers={}, value={"error": "invalid_credential"})
        return flow.JsonResponse(status=201, headers={}, value={
            "device_code": self.private_device_code,
            "user_code": "SAFE-1234",
            "verification_uri": SERVER + "/app",
            "verification_uri_complete":
                SERVER + "/app?user_code=SAFE-1234#settings",
            "expires_in": 600,
            "interval": 5,
        })


class TerminalFlowClientRedTeam(unittest.TestCase):
    def test_base_path_traversal_is_rejected_before_storage_or_browser(self):
        unsafe_bases = (
            "https://attacca.test/tenant/../other",
            "https://attacca.test/tenant/%2e%2e/other",
        )
        for value in unsafe_bases:
            with self.subTest(base=value), self.assertRaises(
                    flow.TerminalFlowProtocolError):
                flow.canonical_server_url(value)

        unsafe_verification_urls = (
            "https://attacca.test/tenant/../other/app",
            "https://attacca.test/tenant/%2e%2e/other/app",
            "https://attacca.test/tenant//../other/app",
        )
        for value in unsafe_verification_urls:
            with self.subTest(verification=value), self.assertRaises(
                    flow.TerminalFlowProtocolError):
                flow._same_server_verification_url(
                    SERVER, value, "verification_uri_complete")

    def test_core_and_flow_use_one_default_port_credential_key(self):
        for value in (
                "http://Example.test:80/tenant",
                "https://Example.test:443/tenant"):
            with self.subTest(url=value):
                self.assertEqual(
                    core._credential_server_key(value),
                    flow.canonical_server_url(value))
        encoded = flow.canonical_server_url(
            "https://attacca.test/tenant/%7Eteam")
        lower_encoded = flow.canonical_server_url(
            "https://attacca.test/tenant/%7eteam")
        literal = flow.canonical_server_url(
            "https://attacca.test/tenant/~team")
        self.assertEqual(encoded, literal)
        self.assertEqual(lower_encoded, literal)

    def test_equivalent_legacy_default_port_key_is_not_stranded(self):
        with tempfile.TemporaryDirectory() as temporary:
            credentials = Path(temporary) / "credentials.json"
            legacy_key = "https://attacca.test:443/tenant"
            credentials.write_text(json.dumps({
                "version": 1,
                "servers": {
                    legacy_key: {
                        "agent_tokens": {
                            "alpha": {
                                ACTOR: {
                                    "token": "atc_legacy-exact",
                                    "runtime": "codex",
                                },
                            },
                        },
                    },
                },
            }))
            os.chmod(credentials, 0o600)
            with mock.patch.object(core, "CREDENTIALS_FILE", credentials):
                self.assertEqual(core.load_api_token(
                    "https://attacca.test:443/tenant", runtime="codex",
                    project_id="alpha", actor_id=ACTOR),
                    "atc_legacy-exact")

    def test_insecure_or_symlinked_credentials_never_release_raw_bearer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            credentials = root / "credentials.json"
            flow.save_terminal_credential(
                SERVER, credential(), device_id=DEVICE,
                credentials_path=credentials)
            os.chmod(credentials, 0o644)
            loaded = flow.load_terminal_credential(
                SERVER, device_id=DEVICE, project_id="alpha",
                actor_id=ACTOR, runtime="codex",
                credentials_path=credentials)
            mode = stat.S_IMODE(credentials.stat().st_mode)
            self.assertTrue(
                loaded is None or mode == 0o600,
                "a raw bearer was returned while its file remained non-private")

            private_target = root / "private-target.json"
            os.replace(credentials, private_target)
            os.chmod(private_target, 0o600)
            credentials.symlink_to(private_target)
            self.assertIsNone(flow.load_terminal_credential(
                SERVER, device_id=DEVICE, project_id="alpha",
                actor_id=ACTOR, runtime="codex",
                credentials_path=credentials))

    def test_existing_malformed_credentials_are_not_silently_destroyed(self):
        with tempfile.TemporaryDirectory() as temporary:
            credentials = Path(temporary) / "credentials.json"
            original = (
                b'{"version":1,"servers":{"legacy":{"agent_tokens":'
                b'{"alpha":{"alpha.director.codex":')
            credentials.write_bytes(original)
            os.chmod(credentials, 0o600)
            with self.assertRaises((flow.TerminalFlowError, OSError,
                                    ValueError, TypeError)):
                flow.save_terminal_credential(
                    SERVER, credential(), device_id=DEVICE,
                    credentials_path=credentials)
            self.assertEqual(credentials.read_bytes(), original)

    def test_owner_update_cannot_destroy_malformed_device_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            identity = Path(temporary) / "identity.json"
            original = b'{"device_id":"dev_preserve","owner":'
            identity.write_bytes(original)
            os.chmod(identity, 0o600)
            with mock.patch.object(core, "IDENTITY_FILE", identity), \
                    self.assertRaises(core.AttaccaError):
                core.save_owner("alice")
            self.assertEqual(identity.read_bytes(), original)

    def test_concurrent_device_load_and_owner_save_preserve_both_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            identity = Path(temporary) / "identity.json"
            barrier = threading.Barrier(3)
            device_ids = []
            failures = []

            def load_devices():
                try:
                    barrier.wait()
                    for _ in range(64):
                        device_ids.append(core.load_device_id())
                except BaseException as error:  # retain thread evidence
                    failures.append(error)

            def save_owners():
                try:
                    barrier.wait()
                    for _ in range(64):
                        core.save_owner("alice")
                except BaseException as error:  # retain thread evidence
                    failures.append(error)

            with mock.patch.dict(os.environ, {
                    "HOME": temporary,
            }, clear=True), \
                    mock.patch.object(core, "IDENTITY_FILE", identity):
                device_thread = threading.Thread(target=load_devices)
                owner_thread = threading.Thread(target=save_owners)
                device_thread.start()
                owner_thread.start()
                barrier.wait()
                device_thread.join(timeout=10)
                owner_thread.join(timeout=10)
                self.assertFalse(device_thread.is_alive())
                self.assertFalse(owner_thread.is_alive())
                self.assertEqual(failures, [])
                final_device = core.load_device_id()
                saved = flow.read_identity_store(identity)

            self.assertEqual(saved["owner"], "alice")
            self.assertEqual(saved["device_id"], final_device)
            self.assertEqual(set(device_ids), {final_device})
            self.assertEqual(stat.S_IMODE(identity.stat().st_mode), 0o600)

    def test_core_terminal_lookup_never_runtime_falls_back_for_dotted_actor(self):
        with tempfile.TemporaryDirectory() as temporary:
            credentials = Path(temporary) / "credentials.json"
            identity = Path(temporary) / "identity.json"
            identity.write_text(json.dumps({"device_id": DEVICE}))
            os.chmod(identity, 0o600)
            with mock.patch.object(core, "CREDENTIALS_FILE", credentials), \
                    mock.patch.object(core, "IDENTITY_FILE", identity):
                flow.save_terminal_credential(
                    SERVER, credential(), device_id=DEVICE,
                    credentials_path=credentials)
                self.assertEqual(core.load_api_token(
                    SERVER, runtime="codex", project_id="alpha",
                    actor_id=ACTOR), credential()["token"])
                self.assertIsNone(core.load_api_token(
                    SERVER, runtime="codex", project_id="alpha",
                    actor_id=OTHER_SAME_RUNTIME_ACTOR))
                identity.write_text(json.dumps({"device_id": "dev_other"}))
                os.chmod(identity, 0o600)
                self.assertIsNone(core.load_api_token(
                    SERVER, runtime="codex", project_id="alpha",
                    actor_id=ACTOR))

    def test_present_invalid_expiry_is_not_treated_as_no_expiry(self):
        with tempfile.TemporaryDirectory() as temporary:
            credentials = Path(temporary) / "credentials.json"
            flow.save_terminal_credential(
                SERVER, credential(), device_id=DEVICE,
                credentials_path=credentials)
            data = json.loads(credentials.read_text())
            data["servers"][SERVER]["terminal_credential"][
                "expires_at"] = "not-a-timestamp"
            credentials.write_text(json.dumps(data))
            os.chmod(credentials, 0o600)
            status = flow.terminal_credential_status(
                SERVER, device_id=DEVICE, credentials_path=credentials)
            self.assertEqual(status["status"], "invalid")
            self.assertIsNone(flow.load_terminal_credential(
                SERVER, device_id=DEVICE, credentials_path=credentials))

    def test_watcher_known_expired_credential_is_auth_not_network_offline(self):
        class ExpiredTerminal:
            @staticmethod
            def terminal_credential_status(*_args, **_kwargs):
                return {"status": "expired", "credential_present": True}

            @staticmethod
            def load_terminal_credential(*_args, **_kwargs):
                return None

        entry = {
            "server_url": SERVER,
            "runtime": "codex",
            "project_id": "alpha",
            "canonical_actor_id": ACTOR,
            "actor": "codex",
            "device_id": DEVICE,
            "plugin_root": str(ROOT),
        }
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(hook, "_terminal_flow_module",
                                  return_value=ExpiredTerminal()), \
                mock.patch.object(hook.Path, "home",
                                  return_value=Path(temporary)):
            with self.assertRaises(hook.HostedAuthenticationRequired):
                hook._watcher_api_token(entry)

    def test_hook_hot_reloads_machine_url_over_inherited_client_url(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            plugin = root / "plugin"
            (home / ".attacca").mkdir(parents=True)
            plugin.mkdir()
            machine_url = "https://new.attacca.test/tenant"
            stale_url = "https://old.attacca.test/tenant"
            (home / ".attacca" / "config.json").write_text(json.dumps({
                "version": 1, "server_url": machine_url,
            }))
            (plugin / "plugin-mcp.json").write_text(json.dumps({
                "mcpServers": {"attacca": {
                    "env": {"ATTACCA_URL": stale_url},
                }},
            }))
            with mock.patch.dict(os.environ, {
                    "HOME": str(home), "ATTACCA_URL": stale_url,
                    "ATTACCA_RUNTIME": "codex",
            }, clear=False):
                self.assertEqual(
                    hook._connection_config(plugin)["url"], machine_url)

    def test_hook_device_identity_uses_hardened_loader_not_direct_json(self):
        class SecureIdentity:
            @staticmethod
            def load_device_id(*_args, **_kwargs):
                return "dev_secure_loader"

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / ".attacca").mkdir()
            identity = home / ".attacca" / "identity.json"
            identity.write_text(json.dumps({"device_id": "dev_untrusted"}))
            os.chmod(identity, 0o644)
            with mock.patch.dict(os.environ, {"HOME": str(home)},
                                 clear=False), \
                    mock.patch.object(hook, "_terminal_flow_module",
                                      return_value=SecureIdentity()):
                os.environ.pop("ATTACCA_DEVICE_ID", None)
                self.assertEqual(
                    hook._local_device_id(), "dev_secure_loader")

    def test_hook_and_core_share_runtime_keyed_client_instance_identity(self):
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.dict(os.environ, {
                    "HOME": temporary,
                    "ATTACCA_RUNTIME": "codex",
                }, clear=True):
            hook_codex = hook._client_instance_id()
            core_codex = core.load_client_instance_id("codex")
            self.assertEqual(hook_codex, core_codex)

            os.environ["ATTACCA_RUNTIME"] = "claude"
            hook_claude = hook._client_instance_id()
            core_claude = core.load_client_instance_id("claude")
            self.assertEqual(hook_claude, core_claude)
            self.assertNotEqual(hook_codex, hook_claude)

            os.environ["ATTACCA_CLIENT_INSTANCE"] = "client_explicit"
            self.assertEqual(hook._client_instance_id(), "client_explicit")
            self.assertEqual(
                core.load_client_instance_id("claude"), "client_explicit")

            instance_file = Path(temporary) / ".attacca" / \
                "client-instance.json"
            self.assertEqual(
                stat.S_IMODE(instance_file.stat().st_mode), 0o600)

    def test_hook_auth_latch_forces_bound_terminal_reenrollment(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            credentials = home / ".attacca" / "credentials.json"
            saved = credential()
            saved["bindings"] = [BINDING, SECOND_BINDING]
            flow.save_terminal_credential(
                SERVER, saved, device_id=DEVICE,
                credentials_path=credentials)
            transport = ReplacementStartTransport()
            status = {"project_id": "alpha"}
            config = {"url": SERVER}
            entry = {
                "key": "auth-latched-redteam",
                "project_id": "alpha",
                "runtime": "codex",
                "canonical_actor_id": ACTOR,
                "auth_required": True,
                "plugin_root": str(ROOT),
            }
            with mock.patch.dict(os.environ, {
                    "HOME": temporary,
                    "ATTACCA_RUNTIME": "codex",
            }, clear=True), \
                    mock.patch.object(hook, "_terminal_flow_module",
                                      return_value=flow), \
                    mock.patch.object(hook, "_local_device_id",
                                      return_value=DEVICE), \
                    mock.patch.object(hook, "_client_instance_id",
                                      return_value="client_hook_redteam"), \
                    mock.patch.object(flow, "UrllibJsonTransport",
                                      return_value=transport):
                result = hook._terminal_flow_progress(
                    status, config, entry, force_poll=True,
                    open_browser=False)

            self.assertEqual(result["status"], "started")
            self.assertEqual(len(transport.calls), 2)
            self.assertTrue(transport.calls[0]["authorized"])
            self.assertFalse(transport.calls[1]["authorized"])
            for call in transport.calls:
                self.assertEqual({item["actor_id"] for item in
                                  call["payload"]["requested_bindings"]},
                                 {BINDING["actor_id"],
                                  SECOND_BINDING["actor_id"]})
            public = json.dumps(result, sort_keys=True)
            self.assertNotIn(saved["token"], public)
            self.assertNotIn(transport.private_device_code, public)
            self.assertEqual(
                stat.S_IMODE((home / ".attacca" /
                              "terminal-flow.json").stat().st_mode), 0o600)

    def test_setup_host_rejection_forces_bound_terminal_reenrollment(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            credentials = home / "credentials.json"
            identity = home / "identity.json"
            saved = credential()
            saved["bindings"] = [BINDING, SECOND_BINDING]
            flow.save_terminal_credential(
                SERVER, saved, device_id=DEVICE,
                credentials_path=credentials)
            identity.write_text(json.dumps({"device_id": DEVICE}))
            os.chmod(identity, 0o600)
            transport = ReplacementStartTransport()

            def rejected_status(_url, _method, _path, **kwargs):
                if kwargs.get("use_auth") is False:
                    return {"authentication_required": True}
                raise core.AuthenticationError(
                    "invalid_credential: bearer is revoked")

            with mock.patch.dict(os.environ, {
                    "HOME": temporary,
                    "ATTACCA_RUNTIME": "codex",
            }, clear=True), \
                    mock.patch.object(core, "CREDENTIALS_FILE", credentials), \
                    mock.patch.object(core, "IDENTITY_FILE", identity), \
                    mock.patch.object(core, "_TERMINAL_FLOW_RUNTIME", flow), \
                    mock.patch.object(core, "remote_json",
                                      side_effect=rejected_status), \
                    mock.patch.object(core, "find_project_link",
                                      return_value={"project_id": "alpha"}), \
                    mock.patch.object(flow, "UrllibJsonTransport",
                                      return_value=transport):
                core._remote_setup_auth.context = None
                with self.assertRaises(core.AuthenticationError) as caught:
                    core.ensure_remote_setup_auth(
                        SERVER, ACTOR, interactive=False)

            self.assertIn("terminal_enrollment_pending", str(caught.exception))
            self.assertIn("SAFE-1234", str(caught.exception))
            self.assertNotIn(saved["token"], str(caught.exception))
            self.assertNotIn(
                transport.private_device_code, str(caught.exception))
            self.assertEqual(len(transport.calls), 2)
            for call in transport.calls:
                self.assertEqual({item["actor_id"] for item in
                                  call["payload"]["requested_bindings"]},
                                 {BINDING["actor_id"],
                                  SECOND_BINDING["actor_id"]})

    def test_connect_generates_client_instance_header_when_env_is_absent(self):
        captured = []

        def fake_open(request, timeout=None):
            del timeout
            captured.append({key.lower(): value
                             for key, value in request.header_items()})
            return JsonMcpResponse()

        request = io.StringIO(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {},
        }) + "\n")
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.dict(os.environ, {
                    "HOME": temporary,
                    "ATTACCA_DEVICE_ID": DEVICE,
                    "ATTACCA_CLIENT_INSTANCE": "",
                    "ATTACCA_AUTOSTART": "0",
                }, clear=False), \
                mock.patch("urllib.request.urlopen", side_effect=fake_open):
            core.run_connect_proxy(
                url=SERVER, actor=ACTOR, actor_type="agent",
                project="alpha", stdin=request, stdout=io.StringIO())
        self.assertEqual(len(captured), 1)
        self.assertRegex(
            captured[0].get("x-attacca-client-instance", ""),
            r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$")

    def test_known_bad_terminal_never_reaches_proxy_rest_or_offline_io(self):
        cases = (
            ("expired", DEVICE),
            ("wrong_device", "dev_other_machine"),
        )
        for expected_status, current_device in cases:
            with self.subTest(status=expected_status), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                credentials = root / "credentials.json"
                identity = root / "identity.json"
                saved = credential()
                if expected_status == "expired":
                    saved["expires_at"] = "2000-01-01T00:00:00Z"
                flow.save_terminal_credential(
                    SERVER, saved, device_id=DEVICE,
                    credentials_path=credentials)
                identity.write_text(json.dumps({
                    "device_id": current_device,
                }))
                os.chmod(identity, 0o600)
                request = io.StringIO(json.dumps({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {},
                }) + "\n")
                output = io.StringIO()
                with mock.patch.dict(os.environ, {
                        "HOME": temporary,
                        "ATTACCA_DEVICE_ID": current_device,
                        "ATTACCA_CLIENT_INSTANCE": "client_redteam",
                        "ATTACCA_OWNER": "",
                        "ATTACCA_AUTOSTART": "0",
                }, clear=True), \
                        mock.patch.object(core, "CREDENTIALS_FILE",
                                          credentials), \
                        mock.patch.object(core, "IDENTITY_FILE", identity), \
                        mock.patch(
                            "urllib.request.urlopen",
                            side_effect=AssertionError(
                                "known-bad credential attempted HTTP")) \
                        as opened, \
                        mock.patch.object(
                            core.OfflineProxySession, "process_message",
                            autospec=True,
                            side_effect=AssertionError(
                                "known-bad credential entered offline mode")) \
                        as offline:
                    core.run_connect_proxy(
                        url=SERVER, actor=ACTOR, actor_type="agent",
                        project="alpha", stdin=request, stdout=output)
                    replies = [json.loads(line) for line in
                               output.getvalue().splitlines() if line]
                    self.assertEqual(len(replies), 1)
                    self.assertEqual(
                        replies[0]["error"]["data"], {
                            "http_status": 401,
                            "category": "authentication_required",
                        })
                    self.assertIn(
                        expected_status, replies[0]["error"]["message"])

                    # The REST setup helper uses the same fail-closed latch.
                    # Exercise it independently so a future proxy-only guard
                    # cannot reintroduce anonymous setup traffic.
                    core._remote_setup_auth.context = None
                    with self.assertRaises(core.AuthenticationError) as caught:
                        core.remote_json(
                            SERVER, "GET", "/v1/projects/alpha/status",
                            actor=ACTOR, actor_type="agent",
                            project_id="alpha")
                    self.assertIn(expected_status, str(caught.exception))
                    opened.assert_not_called()
                    offline.assert_not_called()

    def test_device_code_cannot_be_reflected_into_public_verification_url(self):
        secret = "atd_" + "x" * 48
        response = {
            "device_code": secret,
            "user_code": "ABCD-1234",
            "verification_uri": SERVER + "/app",
            "verification_uri_complete": (
                SERVER + "/app?device_code=" + secret + "#settings"),
            "expires_in": 600,
            "interval": 5,
        }
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "terminal-flow.json"
            with self.assertRaises(flow.TerminalFlowProtocolError):
                flow.start_device_flow(
                    SERVER, device_id=DEVICE, client_label="red-team",
                    state_path=state, transport=StaticStartTransport(response),
                    now=1, client_instance_id="client_redteam")
            if state.exists():
                self.assertNotIn(secret, state.read_text())


if __name__ == "__main__":
    unittest.main()
