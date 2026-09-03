"""Outage correctness for live hosted writes made through the connect proxy.

Three separate guarantees are exercised here:

* a dead host is proven undelivered and its write is queued, never dropped;
* a write whose reply was lost is recorded as ambiguous and later reconciled
  against hosted receipts, so it is neither lost nor applied twice;
* a hosted write that changes the inbox refuses a cached read from a mirror
  older than that write instead of answering with stale rows.

Every server binds an ephemeral loopback port and every database, mirror,
watcher state file, credential, and checkout lives below a TemporaryDirectory.
The live development server is never discovered or used.
"""

import errno
import hashlib
import json
import os
import select
import socket
import subprocess
import sys
import threading
import time
import unittest
import unittest.mock
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import offline_sync as offline  # noqa: E402
import sync_client  # noqa: E402
from tests.test_sync_http import (  # noqa: E402
    SyncHttpFixture,
    attacca,
    protocol,
)


SCRIPT = str(ROOT / "attacca.py")
# A documentation-only address that black-holes packets: connecting to it
# times out while still connecting, which must classify as undelivered.
UNREACHABLE_URL = "http://192.0.2.1:9"


class TransportFailureClassificationTests(unittest.TestCase):
    """``classify_transport_failure`` is the single outage arbiter."""

    def test_phase_is_authoritative_for_every_failure(self):
        error = socket.timeout("timed out")
        table = {
            ("connect", "connect"): sync_client.UNDELIVERED,
            ("send", "send"): sync_client.UNDELIVERED,
            ("response", "response"): sync_client.AMBIGUOUS,
            ("upper", "RESPONSE"): sync_client.AMBIGUOUS,
            ("padded", "  connect "): sync_client.UNDELIVERED,
        }
        for (label, phase), expected in table.items():
            self.assertEqual(
                sync_client.classify_transport_failure(error, phase),
                expected, label)

    def test_connect_phase_errors_are_undelivered_by_construction(self):
        cases = [
            ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
            socket.gaierror(socket.EAI_NONAME, "name or service not known"),
            OSError(errno.EHOSTUNREACH, "no route to host"),
            OSError(errno.ENETUNREACH, "network is unreachable"),
            OSError(errno.ENETDOWN, "network is down"),
            urllib.error.URLError(
                OSError(errno.EHOSTUNREACH, "no route to host")),
            urllib.error.URLError(socket.gaierror(-2, "name")),
            urllib.error.URLError(ConnectionRefusedError(111, "refused")),
        ]
        for error in cases:
            self.assertEqual(
                sync_client.classify_transport_failure(error),
                sync_client.UNDELIVERED, repr(error))
            self.assertTrue(sync_client.proves_request_undelivered(error))

    def test_response_phase_and_unknown_errors_stay_ambiguous(self):
        cases = [
            socket.timeout("timed out"),
            TimeoutError("urlopen timed out"),
            ConnectionResetError(errno.ECONNRESET, "reset by peer"),
            urllib.error.URLError(socket.timeout("timed out")),
            RuntimeError("unclassified failure"),
        ]
        for error in cases:
            self.assertEqual(
                sync_client.classify_transport_failure(error),
                sync_client.AMBIGUOUS, repr(error))
        # An explicit response phase always wins over a hopeful exception.
        self.assertEqual(
            sync_client.classify_transport_failure(
                ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
                "response"),
            sync_client.AMBIGUOUS)

    def test_recorded_phase_travels_with_the_exception(self):
        error = socket.timeout("timed out")
        self.assertEqual(
            sync_client.annotate_transport_failure(error, "response"),
            sync_client.AMBIGUOUS)
        self.assertEqual(
            getattr(error, sync_client.PHASE_ATTRIBUTE), "response")
        # A later classification with no phase argument reuses that record.
        self.assertEqual(
            sync_client.classify_transport_failure(error),
            sync_client.AMBIGUOUS)

    def test_phase_tracking_opener_records_the_real_phase(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                if self.path == "/stall":
                    time.sleep(3)
                    return
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        opener = sync_client.PhaseTrackingOpener()

        def post(path, timeout):
            return opener.open(urllib.request.Request(
                "http://127.0.0.1:%d%s" % (port, path), data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST"), timeout=timeout)

        try:
            with post("/ok", 5) as response:
                self.assertEqual(response.status, 200)
            with self.assertRaises(Exception) as caught:
                post("/stall", 0.2)
            self.assertEqual(
                getattr(caught.exception, sync_client.PHASE_ATTRIBUTE),
                "response")
            self.assertEqual(
                getattr(
                    caught.exception, sync_client.CLASSIFICATION_ATTRIBUTE),
                sync_client.AMBIGUOUS)
        finally:
            server.shutdown()
            thread.join(timeout=10)
            server.server_close()

        with self.assertRaises(Exception) as caught:
            post("/ok", 1)
        self.assertEqual(
            getattr(caught.exception, sync_client.PHASE_ATTRIBUTE), "connect")
        self.assertEqual(
            getattr(caught.exception, sync_client.CLASSIFICATION_ATTRIBUTE),
            sync_client.UNDELIVERED)


class ProxyClassificationFallbackTests(unittest.TestCase):
    """The proxy stays fail-safe when phase tracking is unavailable."""

    def setUp(self):
        import attacca as core
        self.core = core

    def test_missing_tracker_falls_back_to_proof_by_exception(self):
        original = self.core._sync_client_runtime

        def unavailable():
            raise self.core.AttaccaError("sync client is missing")

        self.core._sync_client_runtime = unavailable
        self.addCleanup(setattr, self.core, "_sync_client_runtime", original)
        # Without a tracker there is no trustworthy phase, so only an
        # exception that proves nothing was delivered may queue a write.
        self.assertEqual(
            self.core._offline_proxy_transport_classification(
                socket.timeout("timed out"), None),
            "ambiguous")
        self.assertFalse(self.core._offline_proxy_safe_unavailable(
            socket.timeout("timed out"), None))
        self.assertTrue(self.core._offline_proxy_safe_unavailable(
            ConnectionRefusedError(errno.ECONNREFUSED, "refused"), None))
        self.assertTrue(self.core._offline_proxy_safe_unavailable(
            urllib.error.URLError(
                OSError(errno.EHOSTUNREACH, "no route to host")), None))

    def test_recorded_phase_still_wins_when_the_tracker_is_present(self):
        self.assertEqual(
            self.core._offline_proxy_transport_classification(
                ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
                "response"),
            "ambiguous")
        self.assertEqual(
            self.core._offline_proxy_transport_classification(
                socket.timeout("timed out"), "connect"),
            "undelivered")


class UnjournaledAmbiguousFallbackTests(unittest.TestCase):
    """A journal that refuses the record must not silence the write."""

    class _Adapter:
        """Stands in for the outbox: journalling fails, tracing works."""

        def __init__(self, trace_ok=True):
            self.trace_ok = trace_ok
            self.traced = []

        def record_ambiguous_live_write(self, *_, **__):
            raise RuntimeError("outbox record could not be created")

        def record_unjournaled_ambiguous_write(self, mutation_id, tool,
                                               **details):
            self.traced.append((mutation_id, tool, details))
            return self.trace_ok

    def _record(self, adapter):
        import attacca as core
        session = core.OfflineProxySession.__new__(core.OfflineProxySession)
        session.root = str(Path(__file__).resolve().parent)
        snapshot = {"scope": {
            "server_id": "srv", "project_id": "proj",
            "principal_id": "owner1", "actor_id": "proj.director.codex",
            "actor_type": "agent", "role": "director",
        }}
        with self.assertRaises(core.AttaccaError) as raised:
            session._record_ambiguous(
                "room_send",
                {"project": "proj", "body": "unknown outcome",
                 core.LIVE_IDEMPOTENCY_ARGUMENT: "cm_proxy_fallback_0001"},
                adapter, snapshot, {"phase": "response"})
        return str(raised.exception)

    def test_the_last_resort_trace_is_written_and_reported(self):
        adapter = self._Adapter()
        message = self._record(adapter)
        self.assertEqual(len(adapter.traced), 1)
        mutation_id, tool, details = adapter.traced[0]
        self.assertEqual(mutation_id, "cm_proxy_fallback_0001")
        self.assertEqual(tool, "room_send")
        self.assertEqual(details["operation"], "room.send")
        self.assertEqual(details["phase"], "response")
        self.assertEqual(
            details["request_sha256"],
            protocol.live_request_sha256("room_send", {"body": "unknown "
                                                               "outcome",
                                                       "project": "proj"}))
        self.assertIn("outbox record could not be created", details["error"])
        # The user is still told to verify the hosted workspace by hand.
        self.assertIn("ambiguous", message)
        self.assertIn("unjournaled-ambiguous", message)
        self.assertIn("ambiguous_unjournaled_count", message)
        self.assertIn("verify the hosted workspace", message)
        self.assertNotIn("Nothing could be written locally", message)

    def test_a_failed_trace_is_reported_as_no_local_record_at_all(self):
        message = self._record(self._Adapter(trace_ok=False))
        self.assertIn("Nothing could be written locally either.", message)
        self.assertIn("verify the hosted workspace", message)


class _ForwardingShim:
    """A loopback stand-in for the hosted server that can lose one reply."""

    def __init__(self, target):
        self.target = target.rstrip("/")
        self.drop_tool = None
        self.dropped = threading.Event()
        shim = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                return

            def _forward(self, method):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else None
                headers = {key: value for key, value in self.headers.items()
                           if key.lower() not in (
                               "host", "connection", "content-length")}
                request = urllib.request.Request(
                    shim.target + self.path, data=body, headers=headers,
                    method=method)
                drop = shim._should_drop(body)
                try:
                    with urllib.request.urlopen(request, timeout=10) as reply:
                        status = reply.status
                        payload = reply.read()
                        reply_headers = list(reply.headers.items())
                except urllib.error.HTTPError as error:
                    status = error.code
                    payload = error.read()
                    reply_headers = list(error.headers.items()) \
                        if error.headers else []
                if drop:
                    # The hosted workspace has committed the write; only its
                    # reply is lost.  That is exactly an ambiguous outcome.
                    shim.dropped.set()
                    self.close_connection = True
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return
                self.send_response(status)
                for key, value in reply_headers:
                    if key.lower() in ("transfer-encoding", "connection",
                                       "content-length", "date", "server"):
                        continue
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload or b"")))
                self.end_headers()
                if payload:
                    try:
                        self.wfile.write(payload)
                    except (BrokenPipeError, ConnectionResetError):
                        # The client gave up first; that is the outage under
                        # test, not a shim failure.
                        self.close_connection = True

            def do_GET(self):
                self._forward("GET")

            def do_POST(self):
                self._forward("POST")

            def do_DELETE(self):
                self._forward("DELETE")

        class Quiet(ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                return

        self.server = Quiet(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.url = "http://127.0.0.1:%d" % self.port
        self.thread = None
        self.running = False

    def _should_drop(self, body):
        if not self.drop_tool or not body:
            return False
        try:
            message = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return False
        if not isinstance(message, dict) \
                or message.get("method") != "tools/call":
            return False
        return (message.get("params") or {}).get("name") == self.drop_tool

    def start(self):
        if self.running:
            return
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.running = True

    def stop(self):
        if not self.running:
            return
        self.server.shutdown()
        self.thread.join(timeout=10)
        self.running = False

    def close(self):
        self.stop()
        self.server.server_close()


class OfflineProxyAmbiguityTests(unittest.TestCase):
    """End-to-end outage behaviour of ``attacca.py connect``."""

    maxDiff = None

    def setUp(self):
        self.fx = SyncHttpFixture()
        self.shim = _ForwardingShim(self.fx.base)
        self.shim.start()
        self.processes = []
        self.temp = Path(self.fx.temp.name)
        self.home = self.temp / "ambiguity-home"
        self.home.mkdir()
        self.watcher = self.temp / "ambiguity-watcher"
        self.watcher.mkdir(mode=0o700)
        self.checkout = self.temp / "ambiguity-checkout"
        self.checkout.mkdir()
        attacca.write_project_link(self.checkout, "proj")
        self.addressed_event_id = self._seed_addressed_message()
        status, self.snapshot, _ = self.fx.request(
            "GET", "/v1/projects/proj/sync/snapshot",
            token=self.fx.director_token, device="device_primary")
        self.assertEqual(status, 200)
        protocol.validate_snapshot(self.snapshot)
        self.entry = self._seed_subscription()
        self.engine = self._offline_engine()
        self.engine.install_snapshot(self.snapshot)

    def tearDown(self):
        for process in list(self.processes):
            self._stop_process(process, check=False)
        self.shim.close()
        self.fx.close()

    # -- fixtures ---------------------------------------------------------

    def _seed_addressed_message(self):
        conn = attacca.connect(self.fx.db)
        try:
            attacca.set_current_owner("owner1")
            sent = attacca.room_send(
                conn, "proj", "web.owner1", "human",
                "Please acknowledge the outage drill",
                mentions=["proj.director.codex"])
            return sent["event"]["event_id"]
        finally:
            conn.close()

    @property
    def _subscription_key(self):
        material = json.dumps([
            offline.normalize_server_url(self.shim.url), "proj", "codex",
            "codex", "device_primary", str(self.checkout.resolve()),
        ], separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    @property
    def _client_id(self):
        material = json.dumps([
            self._subscription_key, "codex", "codex", "device_primary",
        ], separators=(",", ":"), ensure_ascii=False)
        return "watcher_" + hashlib.sha256(
            material.encode("utf-8")).hexdigest()[:32]

    def _seed_subscription(self):
        entry = {
            "key": self._subscription_key,
            "server_url": offline.normalize_server_url(self.shim.url),
            "project_id": "proj",
            "runtime": "codex",
            "actor": "codex",
            "owner": "owner1",
            "device_id": "device_primary",
            "root": str(self.checkout.resolve()),
            "link_path": str(
                self.checkout.resolve() / ".attacca" / "project.json"),
            "plugin_root": str(ROOT.resolve()),
            "offline_directory": str(self.watcher / "offline"),
            "canonical_actor_id": "proj.director.codex",
            "actor_role": "director",
            "sync_schema_version": 1,
            "sync_scope": self.snapshot["scope"],
            "sync_visibility_fingerprint": self.snapshot[
                "visibility_fingerprint"],
            "pending": [],
            "next_poll_at_epoch": 0,
        }
        state = {"subscriptions": {entry["key"]: entry}}
        path = self.watcher / "watcher-state.json"
        path.write_text(json.dumps(state, sort_keys=True) + "\n")
        path.chmod(0o600)
        return entry

    def _offline_engine(self):
        return offline.OfflineProjectSync(
            self.watcher / "offline", self.shim.url, self.snapshot["scope"],
            self._client_id, "device_primary",
            visibility_fingerprint=self.snapshot["visibility_fingerprint"])

    def _refresh_subscription_visibility(self):
        """Mimic the watcher: adopt the fingerprint a sync just verified."""
        path = self.watcher / "watcher-state.json"
        state = json.loads(path.read_text())
        entry = state["subscriptions"][self.entry["key"]]
        entry["sync_visibility_fingerprint"] = self.engine.status()[
            "visibility_fingerprint"]
        path.write_text(json.dumps(state, sort_keys=True) + "\n")
        path.chmod(0o600)

    def _remote(self):
        return sync_client.AuthenticatedSyncHttpClient(
            self.shim.url, "proj", self.snapshot["scope"],
            self.snapshot["visibility_fingerprint"], self._client_id,
            "device_primary", lambda: self.fx.director_token,
            timeout_seconds=10)

    def _environment(self, url=None, timeout=None):
        environment = dict(os.environ)
        environment.update({
            "HOME": str(self.home),
            "ATTACCA_URL": url or self.shim.url,
            "ATTACCA_ACTOR": "codex",
            "ATTACCA_ACTOR_TYPE": "agent",
            "ATTACCA_OWNER": "owner1",
            "ATTACCA_DEVICE_ID": "device_primary",
            "ATTACCA_WATCHER_DIR": str(self.watcher),
            "ATTACCA_AUTOSTART": "0",
            "ATTACCA_API_TOKEN": self.fx.director_token,
        })
        if timeout is not None:
            environment["ATTACCA_CONNECT_TIMEOUT_SECONDS"] = str(timeout)
        environment.pop("CLAUDE_PROJECT_DIR", None)
        environment.pop("ATTACCA_PROJECT", None)
        return environment

    def _start_proxy(self, url=None, timeout=None):
        process = subprocess.Popen(
            [sys.executable, SCRIPT, "connect"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, cwd=str(self.checkout),
            env=self._environment(url=url, timeout=timeout), bufsize=1)
        self.processes.append(process)
        return process

    def _rpc(self, process, method, params=None, request_id=1, timeout=15):
        request = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            request["params"] = params
        process.stdin.write(json.dumps(request) + "\n")
        process.stdin.flush()
        readable, _, _ = select.select([process.stdout], [], [], timeout)
        if not readable:
            stderr = process.stderr.read() if process.poll() is not None else ""
            self.fail("proxy produced no reply within %ss: %s"
                      % (timeout, stderr))
        line = process.stdout.readline()
        self.assertTrue(line, "proxy closed stdout before replying")
        response = json.loads(line)
        self.assertEqual(response.get("id"), request_id)
        return response

    def _initialize(self, process, request_id=1):
        return self._rpc(process, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "ambiguity-black-box", "version": "1"},
        }, request_id=request_id)

    def _tool(self, process, name, arguments=None, request_id=10,
              expect_error=False, timeout=15):
        response = self._rpc(process, "tools/call", {
            "name": name, "arguments": arguments or {},
        }, request_id=request_id, timeout=timeout)
        self.assertIn("result", response, response)
        result = response["result"]
        self.assertEqual(
            bool(result.get("isError")), bool(expect_error), result)
        text = result["content"][0]["text"]
        if expect_error:
            return text
        return json.loads(text)

    def _stop_process(self, process, check=True):
        if process not in self.processes:
            return
        try:
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            code = process.wait(timeout=15)
            if check:
                self.assertEqual(code, 0, process.stderr.read())
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        finally:
            for stream in (process.stdout, process.stderr):
                if stream and not stream.closed:
                    stream.close()
            self.processes.remove(process)

    def _room_bodies(self):
        conn = attacca.connect(self.fx.db)
        try:
            rows = conn.execute(
                "SELECT payload FROM events WHERE project_id='proj'"
                " AND event_type='room.message' ORDER BY seq").fetchall()
            return [json.loads(row["payload"]).get("body") for row in rows]
        finally:
            conn.close()

    def _tasks_titled(self, title):
        conn = attacca.connect(self.fx.db)
        try:
            return conn.execute(
                "SELECT COUNT(*) AS n FROM tasks WHERE project_id='proj'"
                " AND title=?", (title,)).fetchone()["n"]
        finally:
            conn.close()

    # -- tests ------------------------------------------------------------

    def test_dead_host_queues_the_write_instead_of_dropping_it(self):
        """A refused or unreachable host provably delivered nothing."""
        self.shim.stop()  # the port now refuses every connection
        process = self._start_proxy(timeout=2)
        self.assertIn("result", self._initialize(process))
        refused = self._tool(
            process, "task_create",
            {"title": "Queued after connection refused"}, request_id=2)
        self._stop_process(process)
        self.assertTrue(refused.get("pending_sync"), refused)
        self.assertTrue(refused.get("offline"), refused)

        # An unreachable network address times out while still connecting.
        # That is undelivered by construction, never ambiguous.
        entry = dict(self.entry)
        entry["server_url"] = offline.normalize_server_url(UNREACHABLE_URL)
        material = json.dumps([
            offline.normalize_server_url(UNREACHABLE_URL), "proj", "codex",
            "codex", "device_primary", str(self.checkout.resolve()),
        ], separators=(",", ":"), ensure_ascii=False)
        entry["key"] = hashlib.sha256(material.encode("utf-8")).hexdigest()
        state = json.loads((self.watcher / "watcher-state.json").read_text())
        state["subscriptions"][entry["key"]] = entry
        (self.watcher / "watcher-state.json").write_text(json.dumps(state))
        unreachable_engine = offline.OfflineProjectSync(
            self.watcher / "offline", UNREACHABLE_URL,
            self.snapshot["scope"],
            "watcher_" + hashlib.sha256(json.dumps([
                entry["key"], "codex", "codex", "device_primary",
            ], separators=(",", ":"),
                ensure_ascii=False).encode("utf-8")).hexdigest()[:32],
            "device_primary",
            visibility_fingerprint=self.snapshot["visibility_fingerprint"])
        unreachable_engine.install_snapshot(self.snapshot)
        process = self._start_proxy(url=UNREACHABLE_URL, timeout=1)
        self.assertIn("result", self._initialize(process))
        queued = self._tool(
            process, "task_create",
            {"title": "Queued after host unreachable"}, request_id=3,
            timeout=30)
        self._stop_process(process)
        self.assertTrue(queued.get("pending_sync"), queued)
        self.assertEqual(
            [item["payload"]["title"]
             for item in unreachable_engine.pending_mutations()],
            ["Queued after host unreachable"])
        self.assertEqual(unreachable_engine.ambiguous_records(), [])
        # Neither write may be recorded as ambiguous: nothing was delivered.
        self.assertEqual(self.engine.ambiguous_records(), [])
        self.assertEqual(
            [item["payload"]["title"]
             for item in self.engine.pending_mutations()],
            ["Queued after connection refused"])

    def test_lost_reply_is_recorded_ambiguous_and_reconciles_as_landed(self):
        """The hosted write committed; only its receipt was lost."""
        self.shim.drop_tool = "room_send"
        process = self._start_proxy(timeout=3)
        self.assertIn("result", self._initialize(process))
        # ``project`` is an addressing argument the offline payload drops but
        # the hosted request hash includes, so both sides must agree on it.
        error = self._tool(
            process, "room_send",
            {"body": "landed during the outage", "project": "proj"},
            request_id=2, expect_error=True, timeout=30)
        self._stop_process(process)
        self.shim.drop_tool = None
        self.assertTrue(self.shim.dropped.is_set())

        lowered = error.lower()
        self.assertIn("ambiguous", lowered)
        self.assertIn("recorded", lowered)
        self.assertIn("ambiguous_pending_reconcile", lowered)
        self.assertIn("do not resend", lowered)
        self.assertNotIn("not queued", lowered)

        records = self.engine.ambiguous_records()
        self.assertEqual(len(records), 1, records)
        mutation_id = records[0]["client_mutation_id"]
        detail = records[0]["ambiguous"]
        self.assertEqual(detail["tool"], "room_send")
        self.assertEqual(detail["operation"], "room.send")
        self.assertEqual(detail["phase"], "response")
        self.assertTrue(detail["replayable"])
        self.assertNotIn("project", detail["payload"])
        self.assertIn(mutation_id, error)
        self.assertEqual(self.engine.pending_mutations(), [])
        status = self.engine.status()
        self.assertEqual(
            status["ambiguous_pending_reconcile"], [mutation_id])
        self.assertFalse(status["convergence_proof"]["online"])

        # The hosted ledger really did accept it exactly once.
        self.assertEqual(
            self._room_bodies().count("landed during the outage"), 1)

        report = self.engine.synchronize(self._remote())
        self.assertEqual(report["ambiguous_landed"], [mutation_id], report)
        self.assertEqual(report["ambiguous_replayed"], [])
        self.assertEqual(report["applied"], [])
        self.assertTrue(report["receipt_lookup_supported"])
        self.assertEqual(
            report["outage_summary"]["ambiguous_landed"], [mutation_id])
        self.assertEqual(
            report["outage_summary"]["unresolved_ambiguous"], [])
        # Reconciliation must never re-apply what already landed.
        self.assertEqual(
            self._room_bodies().count("landed during the outage"), 1)
        self.assertEqual(self.engine.ambiguous_records(), [])
        self.assertEqual(
            self.engine.status()["ambiguous_pending_reconcile"], [])

    def test_undelivered_write_replays_exactly_once_after_reconnect(self):
        """A queued outage write applies once, with no ambiguity record."""
        self.shim.stop()
        process = self._start_proxy(timeout=2)
        self.assertIn("result", self._initialize(process))
        queued = self._tool(
            process, "room_send", {"body": "queued during the outage"},
            request_id=2)
        self._stop_process(process)
        self.assertTrue(queued.get("pending_sync"))
        self.assertEqual(
            self._room_bodies().count("queued during the outage"), 0)

        self.shim.start()
        report = self.engine.synchronize(self._remote())
        self.assertEqual(
            report["applied"], [queued["client_mutation_id"]], report)
        self.assertEqual(report["ambiguous_landed"], [])
        self.assertEqual(
            report["outage_summary"]["queued_replayed"],
            [queued["client_mutation_id"]])
        self.assertEqual(
            self._room_bodies().count("queued during the outage"), 1)

        # A second synchronize must not resend anything.
        again = self.engine.synchronize(self._remote())
        self.assertEqual(again["applied"], [])
        self.assertEqual(
            self._room_bodies().count("queued during the outage"), 1)

    def test_live_disposition_refuses_a_stale_cached_read_until_pulled(self):
        """A mirror older than this device's own hosted write is not served."""
        process = self._start_proxy(timeout=10)
        self.assertIn("result", self._initialize(process))
        disposed = self._tool(process, "message_dispose", {
            "event_id": self.addressed_event_id,
            "disposition": "acknowledged",
            "note": "handled live during the drill",
        }, request_id=2)
        self.assertNotIn("_attacca_receipt", disposed)
        self._stop_process(process)

        live_cursor = self.engine.live_cursor()
        self.assertIsNotNone(live_cursor, "hosted receipt did not advance")
        self.assertTrue(offline.OfflineProjectSync.cursor_behind(
            self.engine.local_snapshot()["cursor"], live_cursor))
        self.assertTrue(
            self.engine.status()["mirror_stale_below_live_cursor"])

        # The hosted endpoint is now unreachable, so the mirror is the only
        # possible answer -- and it provably predates the write above.
        self.shim.stop()
        process = self._start_proxy(timeout=2)
        self.assertIn("result", self._initialize(process))
        stale = self._tool(
            process, "check_inbox", {"limit": 10}, request_id=3,
            expect_error=True)
        status = self._tool(process, "attacca_status", request_id=4)
        self._stop_process(process)
        lowered = stale.lower()
        self.assertIn("stale", lowered)
        self.assertIn("unreachable", lowered)
        # Status stays readable precisely so the staleness can be explained.
        self.assertTrue(
            status["sync"]["mirror_stale_below_live_cursor"], status)

        # After the watcher pulls, the very same read reflects the hosted
        # disposition instead of reporting it as still pending.
        self.shim.start()
        report = self.engine.synchronize(self._remote())
        self.assertIn(report["status"], ("online", "pending"), report)
        self.assertFalse(
            self.engine.status()["mirror_stale_below_live_cursor"])
        self._refresh_subscription_visibility()
        self.shim.stop()
        process = self._start_proxy(timeout=2)
        self.assertIn("result", self._initialize(process))
        inbox = self._tool(process, "check_inbox", {"limit": 10},
                           request_id=5)
        self._stop_process(process)
        self.assertEqual(inbox["read_source"], "verified_local_mirror")
        self.assertEqual(
            inbox["offline_mirror_cursor"],
            self.engine.local_snapshot()["cursor"])
        pending_ids = {item.get("event_id")
                       for item in inbox["pending_dispositions"]}
        self.assertNotIn(self.addressed_event_id, pending_ids)

    def test_reserved_or_unsupported_receipts_keep_the_write_ambiguous(self):
        """Unknown is never treated as absent, so nothing is replayed."""
        mutation_id = protocol.new_client_mutation_id(
            self._client_id, "device_primary")
        payload = {"body": "unknown outcome sentinel"}
        self.engine.record_ambiguous_live_write(
            mutation_id, "room_send", payload, operation="room.send",
            request_sha256=protocol.live_request_sha256("room_send", payload),
            phase="response")

        # An older hosted server has no receipt route at all.
        class NoReceiptRemote:
            def __init__(self, inner):
                self._inner = inner

            def fetch_snapshot(self, allow_scope_change=False):
                return self._inner.fetch_snapshot(
                    allow_scope_change=allow_scope_change)

            def pull(self, **kwargs):
                return self._inner.pull(**kwargs)

            def push(self, **kwargs):
                return self._inner.push(**kwargs)

        report = self.engine.reconcile_ambiguous(NoReceiptRemote(
            self._remote()))
        self.assertFalse(report["supported"])
        self.assertEqual(report["unknown"], [mutation_id])
        self.assertEqual(report["replayed"], [])
        self.assertEqual(
            self.engine.status()["ambiguous_pending_reconcile"],
            [mutation_id])

        # A reserved hosted row means "started, never recorded": still
        # unknown, and still never replayed.
        conn = attacca.connect(self.fx.db)
        try:
            engine = attacca._live_receipt_engine(conn)
            engine.live_reserve(
                self.snapshot["scope"], "device_primary", mutation_id,
                "room_send",
                protocol.live_request_sha256("room_send", payload))
        finally:
            conn.close()
        status, value, _ = self.fx.request(
            "GET", "/v1/projects/proj/sync/receipts?ids=" + mutation_id,
            token=self.fx.director_token, device="device_primary")
        self.assertEqual(status, 200)
        self.assertEqual(
            value["receipts"][mutation_id]["status"], "reserved")
        report = self.engine.reconcile_ambiguous(self._remote())
        self.assertTrue(report["supported"])
        self.assertEqual(report["unknown"], [mutation_id])
        self.assertEqual(report["replayed"], [])
        self.assertEqual(report["landed"], [])
        self.assertEqual(self.engine.pending_mutations(), [])
        self.assertEqual(
            self._room_bodies().count("unknown outcome sentinel"), 0)

    def _crash_after_apply(self, mutation_id, payload, *, marked=False,
                           age_seconds=3600):
        """Rehearse a host that applied a live write and died before its receipt.

        The reservation is claimed, the tool really runs, and no receipt is
        ever stored.  ``marked=False`` reproduces the generation that
        committed the domain write in its own transaction, which is exactly
        the row shape this recovery path exists for.
        """
        scope = self.snapshot["scope"]
        request_sha = protocol.live_request_sha256("room_send", payload)
        conn = attacca.connect(self.fx.db)
        try:
            engine = attacca._live_receipt_engine(conn)
            reserved = engine.live_reserve(
                scope, "device_primary", mutation_id, "room_send",
                request_sha)
            self.assertEqual(reserved["status"], "reserved")
            attacca.set_current_owner(scope["principal_id"])
            attacca.set_current_git_context(None, None, "device_primary")
            applied = attacca.room_send(
                conn, "proj", scope["actor_id"], "agent", payload["body"])
            stale = (time.time() - age_seconds)
            stamp = time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(stale)) + ".000Z"
            conn.execute(
                "UPDATE sync_live_operations SET created_at=?%s"
                " WHERE client_mutation_id=?"
                % ("" if marked else ", reserved_at_seq=NULL"),
                (stamp, mutation_id))
            conn.commit()
            return applied["event"]
        finally:
            attacca.set_current_git_context(None, None, None)
            conn.close()

    def _receipt_lookup(self, mutation_id):
        status, value, _ = self.fx.request(
            "GET", "/v1/projects/proj/sync/receipts?ids=" + mutation_id,
            token=self.fx.director_token, device="device_primary")
        self.assertEqual(status, 200)
        return value

    def test_a_crashed_live_write_is_recovered_from_the_hosted_ledger(self):
        """Reserve -> apply -> crash stops meaning 'unknown' for ever."""
        mutation_id = protocol.new_client_mutation_id(
            self._client_id, "device_primary")
        payload = {"body": "applied but never receipted"}
        self.engine.record_ambiguous_live_write(
            mutation_id, "room_send", payload, operation="room.send",
            request_sha256=protocol.live_request_sha256("room_send", payload),
            phase="response")
        landed = self._crash_after_apply(mutation_id, payload)

        value = self._receipt_lookup(mutation_id)
        receipt = value["receipts"][mutation_id]
        self.assertEqual(receipt["status"], "applied")
        self.assertEqual(receipt["canonical_event_id"], landed["event_id"])
        self.assertEqual(receipt["canonical_event_seq"], landed["seq"])
        self.assertEqual(
            receipt["request_sha256"],
            protocol.live_request_sha256("room_send", payload))
        self.assertTrue(receipt["result"]["recovered"])
        # The retention policy these receipts live under is part of the
        # answer, so a client can see how long a proof is kept.
        self.assertEqual(value["live_retention"]["applied_rows"],
                         "tombstoned")
        self.assertEqual(value["live_retention"]["reserved_rows"], "retained")

        # Reconciliation now converges instead of reporting unknown, and the
        # write is never replayed.
        report = self.engine.reconcile_ambiguous(self._remote())
        self.assertEqual(report["landed"], [mutation_id], report)
        self.assertEqual(report["replayed"], [])
        self.assertEqual(report["unknown"], [])
        self.assertEqual(self.engine.pending_mutations(), [])
        self.assertEqual(
            self._room_bodies().count("applied but never receipted"), 1)
        self.assertEqual(
            self.engine.status()["ambiguous_pending_reconcile"], [])

    def test_a_crash_before_the_write_is_reported_absent_and_replayed(self):
        """The same recovery must not invent a write that never happened."""
        mutation_id = protocol.new_client_mutation_id(
            self._client_id, "device_primary")
        payload = {"body": "reserved but never applied"}
        self.engine.record_ambiguous_live_write(
            mutation_id, "room_send", payload, operation="room.send",
            request_sha256=protocol.live_request_sha256("room_send", payload),
            phase="response")
        scope = self.snapshot["scope"]
        conn = attacca.connect(self.fx.db)
        try:
            attacca._live_receipt_engine(conn).live_reserve(
                scope, "device_primary", mutation_id, "room_send",
                protocol.live_request_sha256("room_send", payload))
            stamp = time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 3600)) \
                + ".000Z"
            conn.execute(
                "UPDATE sync_live_operations SET created_at=?"
                " WHERE client_mutation_id=?", (stamp, mutation_id))
            conn.commit()
        finally:
            conn.close()

        # The reservation carries the atomicity marker, so its survival is
        # proof that nothing was applied: absent, not unknown.
        receipt = self._receipt_lookup(mutation_id)["receipts"][mutation_id]
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(
            self._room_bodies().count("reserved but never applied"), 0)

        report = self.engine.synchronize(self._remote())
        self.assertEqual(report["ambiguous_replayed"], [mutation_id], report)
        self.assertEqual(
            self._room_bodies().count("reserved but never applied"), 1)
        # And exactly once: the replay owns the id from here on.
        self.engine.synchronize(self._remote())
        self.assertEqual(
            self._room_bodies().count("reserved but never applied"), 1)

    def test_an_unstorable_receipt_still_records_the_write_it_applied(self):
        """The one way a committed live write can survive as 'reserved'.

        Apply and receipt share a transaction, so a *marked* reservation
        normally proves nothing applied.  When ``live_commit`` itself fails
        the write is still committed on purpose (reporting it honestly beats
        inviting a duplicate), so the canonical event must be stamped on the
        row -- otherwise recovery would later read that same row as "never
        applied" and the client would replay an applied write.
        """
        scope = self.snapshot["scope"]
        mutation_id = protocol.new_client_mutation_id(
            self._client_id, "device_primary")
        body = "receipt storage failed but the write landed"
        session = attacca.McpSession(
            str(self.fx.db), default_project="proj",
            actor=scope["actor_id"], actor_type="agent", detect_cwd=False,
            owner=scope["principal_id"], device_id="device_primary",
            authorized_project="proj", preserve_actor_identity=True)
        self.addCleanup(
            lambda: session.conn.close() if session.conn else None)
        _, server_module = attacca._sync_runtime()
        with unittest.mock.patch.object(
                server_module.SyncServerEngine, "live_commit",
                side_effect=server_module.SyncServerStateError(
                    "receipt store is unavailable")):
            answer = attacca._live_idempotent_dispatch(
                session, {"scope": scope, "device_id": "device_primary"},
                "room_send", {"project": "proj", "body": body}, mutation_id)

        receipt = answer[attacca.LIVE_RECEIPT_RESULT_KEY]
        self.assertEqual(receipt["status"], "unrecorded")
        self.assertEqual(receipt["client_mutation_id"], mutation_id)
        self.assertEqual(receipt["applied_event_record"], "stamped")
        # The write really did apply, exactly once.
        self.assertEqual(self._room_bodies().count(body), 1)

        conn = attacca.connect(self.fx.db)
        try:
            row = conn.execute(
                "SELECT state, applied_event_id, applied_event_seq"
                " FROM sync_live_operations WHERE client_mutation_id=?",
                (mutation_id,)).fetchone()
            self.assertEqual(row["state"], "reserved")
            self.assertEqual(row["applied_event_id"],
                             answer["event"]["event_id"])
            stamp = time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 3600)) \
                + ".000Z"
            conn.execute(
                "UPDATE sync_live_operations SET created_at=?"
                " WHERE client_mutation_id=?", (stamp, mutation_id))
            conn.commit()
        finally:
            conn.close()

        # Recovery must read the stamp, never the "marked reservation means
        # nothing applied" shortcut.
        recovered = self._receipt_lookup(mutation_id)["receipts"][mutation_id]
        self.assertEqual(recovered["status"], "applied")
        self.assertEqual(recovered["canonical_event_id"],
                         answer["event"]["event_id"])
        self.assertEqual(recovered["result"]["recovery_source"],
                         "apply_stamp")
        self.assertEqual(self._room_bodies().count(body), 1)

    def test_absent_receipt_requeues_the_write_under_its_original_id(self):
        """Provably absent means safe to replay -- once, under the same id."""
        mutation_id = protocol.new_client_mutation_id(
            self._client_id, "device_primary")
        payload = {"title": "Requeued after an ambiguous outage"}
        self.engine.record_ambiguous_live_write(
            mutation_id, "task_create", payload, operation="task.create",
            request_sha256=protocol.live_request_sha256(
                "task_create", payload),
            phase="response")
        report = self.engine.synchronize(self._remote())
        self.assertEqual(report["ambiguous_replayed"], [mutation_id], report)
        self.assertEqual(report["applied"], [mutation_id])
        self.assertEqual(report["ambiguous_landed"], [])
        self.assertEqual(
            report["outage_summary"]["ambiguous_replayed"], [mutation_id])
        self.assertEqual(report["outage_summary"]["queued_replayed"], [])
        self.assertEqual(
            self._tasks_titled("Requeued after an ambiguous outage"), 1)
        self.assertEqual(self.engine.ambiguous_records(), [])

        again = self.engine.synchronize(self._remote())
        self.assertEqual(again["applied"], [])
        self.assertEqual(
            self._tasks_titled("Requeued after an ambiguous outage"), 1)

    def test_authority_changing_ambiguous_write_is_never_replayed(self):
        """Fail-closed rules survive the reconnect path unchanged."""
        mutation_id = protocol.new_client_mutation_id(
            self._client_id, "device_primary")
        payload = {"agent_id": "proj.director.claude", "role": "director"}
        record = self.engine.record_ambiguous_live_write(
            mutation_id, "agent_register", payload, operation=None,
            request_sha256=protocol.live_request_sha256(
                "agent_register", payload),
            phase="response", replayable=False)
        self.assertFalse(record["ambiguous"]["replayable"])
        report = self.engine.synchronize(self._remote())
        self.assertEqual(report["ambiguous_abandoned"], [mutation_id], report)
        self.assertEqual(report["ambiguous_replayed"], [])
        self.assertEqual(self.engine.pending_mutations(), [])
        conn = attacca.connect(self.fx.db)
        try:
            registered = conn.execute(
                "SELECT COUNT(*) AS n FROM agents WHERE project_id='proj'"
                " AND agent_id='proj.director.claude'").fetchone()["n"]
        finally:
            conn.close()
        self.assertEqual(registered, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
