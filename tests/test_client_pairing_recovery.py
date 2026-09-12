"""Recover client authorization without losing approvals to concurrent hooks."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import terminal_flow as flow


class PairingTransport:
    """Keep the server's delivery/ACK semantics, including lost ACK replies."""

    def __init__(self, case):
        self.case = case
        self.calls = []
        self.state = None
        self.starts = 0
        self.deliveries = 0
        self.acks = 0
        self.lose_ack = False
        self.auth_failure = None
        self.accept_old = False

    def request(self, method, url, *, headers, payload=None, timeout=5):
        self.calls.append((method, url, payload))
        if url.endswith(flow.AUTH_STATUS_PATH):
            if self.auth_failure is not None:
                if isinstance(self.auth_failure, Exception):
                    raise self.auth_failure
                return flow.JsonResponse(self.auth_failure, {}, {})
            token = headers.get("Authorization", "")[7:]
            if token != self.case.new_token and not (
                    self.accept_old and token == self.case.old_token):
                return flow.JsonResponse(401, {}, {"error": "invalid_credential"})
            return flow.JsonResponse(200, {}, {
                "authenticated": True,
                "principal": self.case.record(token),
            })
        if url.endswith(flow.CLIENT_AUTHORIZATIONS_PATH):
            self.starts += 1
            self.state = "pending"
            return flow.JsonResponse(201, {}, {
                "status": "pending", "poll_secret": self.case.new_token,
                "authorization_request": "R" * 43,
                "verification_uri_complete": self.case.url +
                    "/app#settings&authorization_request=" + "R" * 43,
                "interval": 1,
            })
        if payload.get("acknowledged") and self.state == "consumed":
            # The client must have installed this exact replacement first.
            stored = json.loads(self.case.credentials.read_text())
            record = flow._client_key_record(stored, self.case.url, self.case.instance)
            self.case.assertEqual(record["token"], self.case.new_token)
            pairing = flow._pairing_record(stored, self.case.url, self.case.instance)
            self.case.assertTrue(flow._pairing_delivery_matches(
                stored, self.case.url, self.case.instance, pairing))
            self.acks += 1
            if self.lose_ack:
                self.lose_ack = False
                raise flow.TerminalFlowTransportError("response lost")
            return flow.JsonResponse(200, {}, {"status": "ready", "acknowledged": True})
        if self.state == "pending":
            return flow.JsonResponse(202, {}, {"status": "pending"})
        if self.state == "expired":
            return flow.JsonResponse(400, {}, {"error": "client pairing code expired"})
        if self.acks:
            return flow.JsonResponse(401, {}, {"error": "already acknowledged"})
        if self.state in {"approved", "consumed"}:
            if self.state == "approved":
                self.deliveries += 1
            self.state = "consumed"
            return flow.JsonResponse(200, {}, {
                "status": "approved", "credential": self.case.record(self.case.new_token)})
        raise AssertionError("unexpected pairing request")


class PairingRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.credentials = Path(self.temp.name) / "credentials.json"
        self.url = "https://attacca.test"
        self.instance = "client_recovery"
        self.old_token = "atkey_old.rejected-credential"
        self.new_token = "atpair_" + "n" * 40
        self.transport = PairingTransport(self)
        flow.save_client_api_key(
            self.url, self.record(self.old_token), client_instance=self.instance,
            credentials_path=self.credentials)

    def record(self, token):
        return {"token": token, "token_kind": "client", "token_id": "key_new"
                if token == self.new_token else "key_old", "username": "owner",
                "client_instance": self.instance, "project_memberships": [],
                "scope_mode": "account_memberships"}

    def authorize(self):
        return flow.authorize_client(
            self.url, client_instance=self.instance, credentials_path=self.credentials,
            transport=self.transport, open_browser=False)

    def pairing(self):
        return flow._pairing_record(flow.read_credentials_store(self.credentials),
                                    self.url, self.instance)

    def start(self):
        return flow.start_client_pairing(
            self.url, client_instance=self.instance, credentials_path=self.credentials,
            transport=self.transport, open_browser=False)

    def test_old_key_and_pending_approval_survive_repeated_watcher_recovery(self):
        first = self.start()
        for _ in range(3):
            pending = flow.advance_device_flow(
                self.url, client_instance_id=self.instance,
                credentials_path=self.credentials, transport=self.transport,
                open_browser=False)
            self.assertEqual(pending["status"], "pending")
            self.assertEqual(pending["authorization_url"], first["authorization_url"])
        self.assertEqual(self.transport.starts, 1)
        self.assertEqual(self.transport.acks, 0)
        self.transport.state = "approved"
        ready = self.authorize()
        self.assertTrue(ready["authorized"])
        self.assertEqual(flow.load_client_api_key(
            self.url, client_instance=self.instance,
            credentials_path=self.credentials), self.new_token)
        self.assertIsNone(self.pairing())
        self.assertEqual(self.transport.deliveries, 1)

    def test_cached_ready_is_verified_and_rejected_key_is_preserved_until_delivery(self):
        self.assertEqual(self.authorize()["status"], "pending")
        self.assertTrue(self.transport.calls[0][1].endswith(flow.AUTH_STATUS_PATH))
        self.assertEqual(flow.load_client_api_key(
            self.url, client_instance=self.instance,
            credentials_path=self.credentials), self.old_token)
        self.assertEqual(self.transport.starts, 1)

    def test_authorization_outage_or_scope_denial_does_not_replace_the_key(self):
        for failure in (flow.TerminalFlowTransportError("offline"), 403, 503):
            with self.subTest(failure=failure):
                self.transport.auth_failure = failure
                with self.assertRaises(flow.TerminalFlowError):
                    self.authorize()
                self.assertEqual(self.transport.starts, 0)
                self.assertIsNone(self.pairing())

    def test_lost_ack_reply_retries_only_the_durable_matching_delivery(self):
        self.start()
        self.transport.state = "approved"
        self.transport.lose_ack = True
        self.assertTrue(self.authorize()["authorized"])
        self.assertIsNotNone(self.pairing())
        self.assertTrue(self.authorize()["authorized"])
        self.assertIsNone(self.pairing())
        self.assertEqual(self.transport.deliveries, 1)
        self.assertEqual(self.transport.acks, 2)

    def test_delivery_receipt_cannot_ack_another_stored_key(self):
        self.start()
        self.transport.state = "approved"
        self.transport.lose_ack = True
        self.authorize()
        flow.save_client_api_key(
            self.url, self.record(self.old_token), client_instance=self.instance,
            credentials_path=self.credentials)
        result = self.authorize()
        self.assertFalse(result["authorized"])
        self.assertEqual(self.transport.acks, 1)
        self.assertIsNotNone(self.pairing())

    def test_start_reuses_existing_pending_pairing(self):
        first = self.start()
        self.assertEqual(self.start()["authorization_url"], first["authorization_url"])
        self.assertEqual(self.transport.starts, 1)

    def test_expired_request_is_reported_then_a_later_recovery_can_replace_it(self):
        self.start()
        self.transport.state = "expired"
        self.assertEqual(self.authorize()["status"], "expired")
        self.assertIsNone(self.pairing())
        self.assertEqual(self.transport.starts, 1)
        self.assertEqual(self.authorize()["status"], "pending")
        self.assertEqual(self.transport.starts, 2)

    def test_concurrent_authorization_creates_one_request_and_receives_once(self):
        def parallel_authorize():
            results, errors = [], []
            barrier = threading.Barrier(3)

            def call():
                try:
                    barrier.wait(timeout=5)
                    results.append(self.authorize())
                except Exception as error:
                    errors.append(error)

            threads = [threading.Thread(target=call) for _ in range(2)]
            for thread in threads:
                thread.start()
            barrier.wait(timeout=5)
            for thread in threads:
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            return results

        self.assertEqual([r["status"] for r in parallel_authorize()], ["pending"] * 2)
        self.assertEqual(self.transport.starts, 1)
        self.transport.state = "approved"
        self.assertEqual([r["status"] for r in parallel_authorize()], ["ready"] * 2)
        self.assertEqual(self.transport.deliveries, 1)
        self.assertEqual(self.transport.acks, 1)


class PairingRecoveryHttpTest(unittest.TestCase):
    """Real hosted authentication and independent client processes, all isolated."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "attacca_pairing_recovery_core", ROOT / "attacca.py")
        cls.core = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.core)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.credentials = Path(self.temp.name) / "credentials.json"
        self.db = Path(self.temp.name) / "server.db"
        core = self.core
        conn = core.connect(self.db)
        try:
            core.auth_create_user(conn, "owner", "test-owner-password",
                                  is_admin=True, bootstrap=True)
        finally:
            conn.close()
        self.server = core.AttaccaServer(("127.0.0.1", 0), self.db, auth=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.url = "http://127.0.0.1:%s" % self.server.server_address[1]
        self.instance = "client_http_recovery"
        flow.save_client_api_key(self.url, {
            "token": "atkey_old.no-longer-accepted", "token_id": "key_old",
            "client_instance": self.instance, "username": "owner",
        }, client_instance=self.instance, credentials_path=self.credentials)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def approve(self):
        pairing = flow._pairing_record(flow.read_credentials_store(self.credentials),
                                       self.url, self.instance)
        conn = self.core.connect(self.db)
        try:
            user = conn.execute("SELECT * FROM auth_users WHERE username='owner'").fetchone()
            principal = self.core._auth_principal(conn, user, "session", session_hash="test")
            self.core.auth_client_pairing_decide(
                conn, pairing["authorization_request"], principal, True)
        finally:
            conn.close()

    def test_real_http_watcher_receives_replacement_after_pending_retry(self):
        kwargs = dict(client_instance_id=self.instance,
                      credentials_path=self.credentials, open_browser=False)
        first = flow.advance_device_flow(self.url, **kwargs)
        second = flow.advance_device_flow(self.url, **kwargs)
        self.assertEqual(first["authorization_url"], second["authorization_url"])
        self.approve()
        result = flow.advance_device_flow(self.url, **kwargs)
        self.assertEqual(result["status"], "ready")
        token = flow.load_client_api_key(
            self.url, client_instance=self.instance, credentials_path=self.credentials)
        checked = flow.verify_client_api_key(self.url, token, client_instance=self.instance)
        self.assertEqual(checked["username"], "owner")
        conn = self.core.connect(self.db)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM auth_tokens").fetchone()[0], 1)
            self.assertIsNotNone(conn.execute(
                "SELECT acknowledged_at FROM auth_client_authorizations").fetchone()[0])
        finally:
            conn.close()

    @unittest.skipIf(flow.fcntl is None, "cross-process file locking requires fcntl")
    def test_independent_processes_receive_the_same_approval_once(self):
        flow.start_client_pairing(
            self.url, client_instance=self.instance,
            credentials_path=self.credentials, open_browser=False)
        self.approve()
        command = [sys.executable, "-B", "-c", (
            "import sys,terminal_flow as f; "
            "r=f.authorize_client(sys.argv[1],client_instance=sys.argv[2],"
            "credentials_path=sys.argv[3],open_browser=False); "
            "print(r['status']); raise SystemExit(0 if r.get('authorized') else 1)"
        ), self.url, self.instance, str(self.credentials)]
        children = [subprocess.Popen(command, cwd=str(ROOT), stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True) for _ in range(3)]
        for child in children:
            try:
                output, error = child.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
                self.fail("concurrent authorization deadlocked")
            self.assertEqual(child.returncode, 0, error)
            self.assertEqual(output.strip(), "ready")
        conn = self.core.connect(self.db)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM auth_tokens").fetchone()[0], 1)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
