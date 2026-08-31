"""Authenticated HTTP adapter framing, identity, and token safety tests."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlsplit
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import offline_sync as offline  # noqa: E402
import sync_client as client_module  # noqa: E402
import sync_protocol as protocol  # noqa: E402
try:  # Package-qualified run.
    from tests.test_offline_sync import FakeRemote, identity  # noqa: E402
except ModuleNotFoundError:  # ``unittest discover -s tests``.
    from test_offline_sync import FakeRemote, identity  # noqa: E402


class RecordingTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, *, headers, body, timeout,
                max_response_bytes):
        self.calls.append({
            "method": method, "url": url, "headers": dict(headers),
            "body": body, "timeout": timeout,
            "max_response_bytes": max_response_bytes,
        })
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        body_value, status = response if isinstance(response, tuple) \
            else (response, 200)
        raw = protocol.canonical_json_bytes(body_value)
        return client_module.JsonHttpResponse(
            status=status, headers={"content-type": "application/json"},
            body=raw)


class RemoteProtocolTransport:
    """Route-level fake; delegates envelope creation to ``FakeRemote``."""

    def __init__(self, remote, valid_tokens):
        self.remote = remote
        self.valid_tokens = set(valid_tokens)
        self.calls = []

    def request(self, method, url, *, headers, body, timeout,
                max_response_bytes):
        parsed = urlsplit(url)
        self.calls.append((method, parsed.path, headers.get("Authorization")))
        token = str(headers.get("Authorization") or "").removeprefix("Bearer ")
        if token not in self.valid_tokens:
            return client_module.JsonHttpResponse(
                401, {"content-type": "application/json"}, b"{}")
        if parsed.path.endswith("/snapshot") and method == "GET":
            value = self.remote.fetch_snapshot()
        elif parsed.path.endswith("/pull") and method == "GET":
            query = parse_qs(parsed.query)
            cursor = protocol.make_cursor(
                int(query["after_seq"][0]), query["after_hash"][0],
                int(query["context_version"][0]))
            value = self.remote.pull(
                cursor=cursor,
                visibility_fingerprint=query["visibility_fingerprint"][0],
                limit=int(query["limit"][0]))
        elif parsed.path.endswith("/push") and method == "POST":
            envelope = json.loads(body.decode("utf-8"))
            protocol.validate_push_request(
                envelope, expected_scope=self.remote.scope,
                expected_visibility=self.remote.visibility(),
                known_receipts=self.remote.receipts)
            value = self.remote.push(
                mutations=envelope["mutations"],
                known_receipts=list(self.remote.receipts))
        else:
            return client_module.JsonHttpResponse(
                404, {"content-type": "application/json"}, b"{}")
        return client_module.JsonHttpResponse(
            200, {"content-type": "application/json; charset=utf-8"},
            protocol.canonical_json_bytes(value))


class SyncHttpClientTest(unittest.TestCase):
    def setUp(self):
        self.remote = FakeRemote()
        self.scope = self.remote.scope
        self.visibility = self.remote.visibility()

    def mutation(self, mutation_id="cm_client_0001"):
        return protocol.make_client_mutation(
            self.scope, mutation_id, "client_home", "device_home", 1,
            "task.create", {"title": "Offline task"}, self.remote.head(),
            metadata={"git_branch": "offline"})

    def test_exact_routes_rotating_tokens_and_strict_envelopes(self):
        snapshot = self.remote.fetch_snapshot()
        pull = self.remote.pull(
            cursor=snapshot["cursor"],
            visibility_fingerprint=self.visibility, limit=200)
        mutation = self.mutation()
        applied = protocol.applied_result(
            self.scope, mutation,
            {"canonical_event_id": "ev_9999"}, self.remote.head())
        push = protocol.make_push_result(
            self.scope, self.visibility, [applied], self.remote.head())
        transport = RecordingTransport([snapshot, pull, push])
        tokens = iter(["token-one", "token-two", "token-three"])
        client = client_module.AuthenticatedSyncHttpClient(
            "HTTPS://EXAMPLE.test:443/", "agentg", self.scope,
            self.visibility, "client_home", "device_home",
            lambda: next(tokens), transport=transport)

        self.assertEqual(client.fetch_snapshot(), snapshot)
        self.assertEqual(
            client.pull(
                cursor=snapshot["cursor"],
                visibility_fingerprint=self.visibility)["status"], "ok")
        self.assertEqual(
            client.push(mutations=[mutation], known_receipts=[])["status"],
            "ok")

        self.assertEqual(
            [call["method"] for call in transport.calls],
            ["GET", "GET", "POST"])
        paths = [urlsplit(call["url"]).path for call in transport.calls]
        self.assertEqual(paths, [
            "/v1/projects/agentg/sync/snapshot",
            "/v1/projects/agentg/sync/pull",
            "/v1/projects/agentg/sync/push",
        ])
        query = parse_qs(urlsplit(transport.calls[1]["url"]).query)
        self.assertEqual(query["after_seq"], ["3"])
        self.assertEqual(query["after_hash"], [snapshot["cursor"]["event_hash"]])
        self.assertEqual(query["context_version"], ["3"])
        self.assertEqual(query["visibility_fingerprint"], [self.visibility])
        self.assertEqual(query["limit"], ["200"])
        self.assertIsNone(transport.calls[0]["body"])
        self.assertIsNone(transport.calls[1]["body"])
        pushed = json.loads(transport.calls[2]["body"].decode("utf-8"))
        self.assertEqual(pushed["format"], protocol.PUSH_REQUEST_FORMAT)
        self.assertEqual(
            [call["headers"]["Authorization"] for call in transport.calls],
            ["Bearer token-one", "Bearer token-two", "Bearer token-three"])
        for call in transport.calls:
            self.assertEqual(call["headers"]["X-Attacca-Project"], "agentg")
            self.assertEqual(
                call["headers"]["X-Attacca-Actor"], self.scope["actor_id"])
            self.assertEqual(call["headers"]["X-Attacca-Actor-Type"],
                             self.scope["actor_type"])
            self.assertEqual(call["headers"]["X-Attacca-Device-ID"],
                             "device_home")
            self.assertEqual(call["headers"]["X-Attacca-Client-Instance"],
                             "client_home")
        self.assertNotIn("token-one", repr(client.__dict__))

    def test_no_token_compatibility_mode_requires_fresh_status_and_exact_headers(self):
        snapshot = self.remote.fetch_snapshot()
        pull = self.remote.pull(
            cursor=snapshot["cursor"],
            visibility_fingerprint=self.visibility, limit=200)
        mutation = protocol.make_client_mutation(
            self.scope, "cm_compat_0001", "client_compat", "device_compat", 1,
            "task.create", {"title": "Compatibility task"},
            self.remote.head(), metadata={"git_branch": "compat"})
        applied = protocol.applied_result(
            self.scope, mutation, {"canonical_event_id": "ev_compat"},
            self.remote.head())
        push = protocol.make_push_result(
            self.scope, self.visibility, [applied], self.remote.head())
        transport = RecordingTransport([
            {"authentication_mode": "auto",
             "authentication_required": False,
             "effective_authentication": "optional",
             "compatibility_active": True},
            snapshot, pull, push,
        ])
        client = client_module.AuthenticatedSyncHttpClient(
            "https://example.test", "agentg", self.scope, self.visibility,
            "client_compat", "device_compat", lambda: None,
            transport=transport, client_instance_id="codex_install_2",
            compatibility_optional_auth=True)
        self.assertEqual(client.fetch_snapshot(), snapshot)
        self.assertEqual(client.pull(
            cursor=snapshot["cursor"],
            visibility_fingerprint=self.visibility)["status"], "ok")
        self.assertEqual(client.push(
            mutations=[mutation], known_receipts=[])["status"], "ok")
        self.assertEqual(urlsplit(transport.calls[0]["url"]).path,
                         "/v1/auth/status")
        for call in transport.calls:
            self.assertNotIn("Authorization", call["headers"])
            self.assertEqual(call["headers"]["X-Attacca-Project"], "agentg")
            self.assertEqual(
                call["headers"]["X-Attacca-Actor"], self.scope["actor_id"])
            self.assertEqual(call["headers"]["X-Attacca-Device-ID"],
                             "device_compat")
            self.assertEqual(call["headers"]["X-Attacca-Client-Instance"],
                             "codex_install_2")

    def test_no_token_never_downgrades_auto_or_enforced_auth(self):
        for mode, required in (("auto", False), ("enforced", True)):
            with self.subTest(mode=mode):
                transport = RecordingTransport([{
                    "authentication_mode": mode,
                    "authentication_required": required,
                    "effective_authentication": (
                        "required" if required else "optional"),
                    "compatibility_active": False,
                }])
                client = client_module.AuthenticatedSyncHttpClient(
                        "https://example.test", "agentg", self.scope,
                        self.visibility, "client_secure", "device_secure",
                        lambda: None, transport=transport,
                        compatibility_optional_auth=True)
                with self.assertRaises(client_module.SyncAuthenticationError):
                    client.fetch_snapshot()

    def test_compatibility_is_cleared_after_server_activation_rejection(self):
        transport = RecordingTransport([
            {"authentication_mode": "compatibility",
             "authentication_required": False,
             "effective_authentication": "optional",
             "compatibility_active": True},
            ({}, 401),
        ])
        client = client_module.AuthenticatedSyncHttpClient(
            "https://example.test", "agentg", self.scope, self.visibility,
            "client_transition", "device_transition", lambda: None,
            transport=transport, compatibility_optional_auth=True)
        with self.assertRaises(client_module.SyncAuthenticationError):
            client.fetch_snapshot()
        self.assertFalse(client._compatibility_optional_auth)
        with self.assertRaises(client_module.SyncAuthenticationError):
            client.fetch_snapshot()
        self.assertEqual(len(transport.calls), 2)

    def test_missing_device_or_actor_never_enters_compatibility_mode(self):
        with self.assertRaises(client_module.SyncClientError):
            client_module.AuthenticatedSyncHttpClient(
                "https://example.test", "agentg", self.scope,
                self.visibility, "client_bad", "", lambda: None,
                transport=RecordingTransport([]),
                compatibility_optional_auth=True)
        malformed_scope = dict(self.scope)
        malformed_scope["actor_id"] = ""
        with self.assertRaises((client_module.SyncClientError,
                                protocol.SyncProtocolError)):
            client_module.AuthenticatedSyncHttpClient(
                "https://example.test", "agentg", malformed_scope,
                self.visibility, "client_bad", "device_bad", lambda: None,
                transport=RecordingTransport([]),
                compatibility_optional_auth=True)

    def test_cross_principal_tampering_and_auth_errors_are_rejected(self):
        other = FakeRemote(identity(principal="usr_mallory"))
        transport = RecordingTransport([other.fetch_snapshot()])
        client = client_module.AuthenticatedSyncHttpClient(
            "https://example.test", "agentg", self.scope, self.visibility,
            "client_home", "device_home", lambda: "super-secret-token",
            transport=transport)
        with self.assertRaises(client_module.SyncIdentityChangedError):
            client.fetch_snapshot(allow_scope_change=True)

        unauthorized = RecordingTransport([({}, 401)])
        client = client_module.AuthenticatedSyncHttpClient(
            "https://example.test", "agentg", self.scope, self.visibility,
            "client_home", "device_home", lambda: "super-secret-token",
            transport=unauthorized)
        with self.assertRaises(client_module.SyncAuthenticationError) as raised:
            client.fetch_snapshot()
        self.assertNotIn("super-secret-token", str(raised.exception))

        malformed = dict(self.remote.fetch_snapshot())
        malformed["projection_sha256"] = "sha256:" + "f" * 64
        client = client_module.AuthenticatedSyncHttpClient(
            "https://example.test", "agentg", self.scope, self.visibility,
            "client_home", "device_home", lambda: "token",
            transport=RecordingTransport([malformed]))
        with self.assertRaises(client_module.SyncResponseError):
            client.fetch_snapshot()

        def secret_bearing_loader():
            raise RuntimeError("loader accidentally mentioned secret-value")

        client = client_module.AuthenticatedSyncHttpClient(
            "https://example.test", "agentg", self.scope, self.visibility,
            "client_home", "device_home", secret_bearing_loader,
            transport=RecordingTransport([]))
        with self.assertRaises(client_module.SyncAuthenticationError) as raised:
            client.fetch_snapshot()
        self.assertIsNone(raised.exception.__cause__)
        self.assertNotIn("secret-value", repr(raised.exception))

        oversized = client_module.JsonHttpResponse(
            200, {"content-type": "application/json"},
            b" " * (protocol.MAX_SNAPSHOT_BYTES + 1))
        client = client_module.AuthenticatedSyncHttpClient(
            "https://example.test", "agentg", self.scope, self.visibility,
            "client_home", "device_home", lambda: "token",
            transport=RecordingTransport([]))
        client._transport.request = lambda *args, **kwargs: oversized
        with self.assertRaises(client_module.SyncResponseError):
            client.fetch_snapshot()

    def test_role_change_requires_valid_snapshot_then_explicit_binding(self):
        changed = FakeRemote(identity(role="advisor", runtime="claude"))
        changed.policy_generation = 4
        client = client_module.AuthenticatedSyncHttpClient(
            "https://example.test", "agentg", self.scope, self.visibility,
            "client_home", "device_home", lambda: "token",
            transport=RecordingTransport([
                changed.fetch_snapshot(), changed.fetch_snapshot()]))
        with self.assertRaises(client_module.SyncIdentityChangedError):
            client.fetch_snapshot()
        snapshot = client.fetch_snapshot(allow_scope_change=True)
        client.bind_verified_identity(
            snapshot["scope"], snapshot["visibility_fingerprint"])
        self.assertEqual(client.scope["role"], "advisor")
        self.assertEqual(
            client.visibility_fingerprint, changed.visibility())

    def test_offline_engine_runs_end_to_end_through_injected_route_transport(self):
        transport = RemoteProtocolTransport(
            self.remote, {"token-home", "token-office"})
        with TemporaryDirectory() as temporary:
            engine = offline.OfflineProjectSync(
                Path(temporary) / "cache", "https://example.test",
                self.scope, "client_home", "device_home", None)
            client = client_module.AuthenticatedSyncHttpClient(
                "https://example.test", "agentg", self.scope,
                None, "client_home", "device_home",
                lambda: "token-home", transport=transport)
            initialized = engine.synchronize(client)
            self.assertEqual(initialized["status"], "online")
            self.assertEqual(engine.visibility_fingerprint, self.visibility)
            self.assertEqual(client.visibility_fingerprint, self.visibility)
            mutation = engine.queue_mutation(
                "room.send", {"body": "route-level offline message"},
                client_mutation_id="cm_route_0001")
            synced = engine.synchronize(client)
            self.assertEqual(synced["status"], "online")
            self.assertEqual(synced["applied"], [
                mutation["client_mutation_id"]])
            self.assertEqual(synced["converged"], [
                mutation["client_mutation_id"]])
            self.assertTrue(engine.search_local("route level offline message"))
            self.assertEqual(
                offline.validate_convergence_proof(
                    synced["convergence_proof"], require_online=True)["scope"],
                self.scope)
        self.assertTrue(all(
            path.startswith("/v1/projects/agentg/sync/")
            for _, path, _ in transport.calls))


class IsolatedHttpRouteTest(unittest.TestCase):
    def test_real_http_uses_ephemeral_port_and_loads_token_per_request(self):
        remote = FakeRemote()
        captured = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def _send(self, value):
                body = protocol.canonical_json_bytes(value)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urlsplit(self.path)
                captured.append((
                    "GET", parsed.path, self.headers.get("Authorization")))
                if parsed.path.endswith("/snapshot"):
                    self._send(remote.fetch_snapshot())
                    return
                query = parse_qs(parsed.query)
                cursor = protocol.make_cursor(
                    int(query["after_seq"][0]), query["after_hash"][0],
                    int(query["context_version"][0]))
                self._send(remote.pull(
                    cursor=cursor,
                    visibility_fingerprint=query[
                        "visibility_fingerprint"][0],
                    limit=int(query["limit"][0])))

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        tokens = iter(["ephemeral-one", "ephemeral-two"])
        client = client_module.AuthenticatedSyncHttpClient(
            "http://127.0.0.1:%d" % server.server_address[1], "agentg",
            remote.scope, remote.visibility(), "client_http", "device_http",
            lambda: next(tokens), timeout_seconds=2)
        snapshot = client.fetch_snapshot()
        result = client.pull(
            cursor=snapshot["cursor"],
            visibility_fingerprint=remote.visibility())
        self.assertEqual(result["status"], "ok")
        self.assertNotEqual(server.server_address[1], 4173)
        self.assertEqual([item[2] for item in captured], [
            "Bearer ephemeral-one", "Bearer ephemeral-two"])

    def test_real_http_does_not_forward_bearer_token_through_redirect(self):
        redirected_headers = []

        class TargetHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def do_GET(self):
                redirected_headers.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")

        target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        target_thread = threading.Thread(
            target=target.serve_forever, daemon=True)
        target_thread.start()
        self.addCleanup(target_thread.join, 5)
        self.addCleanup(target.server_close)
        self.addCleanup(target.shutdown)

        class RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def do_GET(self):
                self.send_response(302)
                self.send_header(
                    "Location", "http://127.0.0.1:%d/stolen" %
                    target.server_address[1])
                self.end_headers()

        redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        redirect_thread = threading.Thread(
            target=redirect.serve_forever, daemon=True)
        redirect_thread.start()
        self.addCleanup(redirect_thread.join, 5)
        self.addCleanup(redirect.server_close)
        self.addCleanup(redirect.shutdown)

        remote = FakeRemote()
        client = client_module.AuthenticatedSyncHttpClient(
            "http://127.0.0.1:%d" % redirect.server_address[1], "agentg",
            remote.scope, remote.visibility(), "client_http", "device_http",
            lambda: "must-not-leak", timeout_seconds=2)
        with self.assertRaises(client_module.SyncResponseError):
            client.fetch_snapshot()
        self.assertEqual(redirected_headers, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
