"""Secure browser authorization pairing for D-17 client-install keys."""

import importlib.util
import tempfile
import unittest
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_client_pairing_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class ClientPairingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.conn = c.connect(Path(self.temp.name) / "pairing.db")
        c.auth_create_user(
            self.conn, "owner", "owner-password", is_admin=True,
            bootstrap=True)
        user = self.conn.execute(
            "SELECT * FROM auth_users WHERE username='owner'").fetchone()
        self.principal = c._auth_principal(
            self.conn, user, "session", session_hash="session")
        c.set_current_owner("owner")
        c.project_init(
            self.conn, "web.owner", "human",
            path=Path(self.temp.name) / "repo", project_id="project")

    def tearDown(self):
        c.set_current_owner(None)
        self.conn.close()
        self.temp.cleanup()

    def test_authorize_promotes_secret_once_without_actor_binding(self):
        started = c.auth_client_pairing_start(
            self.conn, "http://server", "install-1", "Codex laptop",
            device_id="device-1")
        self.assertIn("/app#settings&authorization_request=",
                      started["verification_uri_complete"])
        self.assertNotIn("?authorization_request=",
                         started["verification_uri_complete"])
        secret = started["poll_secret"]
        # The approval link carries an opaque 256-bit base64url request token,
        # not a human-formatted pairing code.
        request = started["authorization_request"]
        self.assertRegex(request, r"^[A-Za-z0-9_-]{43}$")
        self.assertNotIn(secret, str(dict(c._auth_client_pairing_row(
            self.conn, request))))
        self.assertEqual(c.auth_client_pairing_poll(
            self.conn, secret, "install-1", "device-1")["status"],
            "pending")

        approved = c.auth_client_pairing_decide(
            self.conn, request, self.principal, True,
            memberships=["project"])
        self.assertEqual(approved["project_memberships"], ["project"])
        delivered = c.auth_client_pairing_poll(
            self.conn, secret, "install-1", "device-1")
        self.assertEqual(delivered["status"], "approved")
        self.assertEqual(delivered["credential"]["token"], secret)
        token_id = delivered["credential"]["record"]["token_id"]
        token = self.conn.execute(
            "SELECT * FROM auth_tokens WHERE token_id=?", (token_id,)
        ).fetchone()
        self.assertEqual(token["token_kind"], "client")
        self.assertIsNone(token["actor_id"])
        self.assertIsNone(token["project_id"])
        self.assertEqual(token["runtime"], "client")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS n FROM auth_token_actor_bindings"
            " WHERE token_id=?", (token_id,)).fetchone()["n"], 0)
        self.assertEqual(c.auth_token_project_bindings(
            self.conn, token_id), ["project"])
        repeated = c.auth_client_pairing_poll(
            self.conn, secret, "install-1", "device-1")
        self.assertEqual(repeated, delivered)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS n FROM auth_tokens"
            " WHERE token_id=?", (token_id,)).fetchone()["n"], 1)
        acknowledged = c.auth_client_pairing_poll(
            self.conn, secret, "install-1", "device-1", acknowledged=True)
        self.assertEqual(acknowledged,
                         {"status": "ready", "acknowledged": True})
        with self.assertRaisesRegex(c.AuthenticationError, "acknowledged"):
            c.auth_client_pairing_poll(
                self.conn, secret, "install-1", "device-1")

    def test_deny_and_install_binding_fail_closed(self):
        started = c.auth_client_pairing_start(
            self.conn, "http://server", "install-2", "Claude desktop")
        with self.assertRaisesRegex(c.AuthorizationError, "instance"):
            c.auth_client_pairing_poll(
                self.conn, started["poll_secret"], "another-install")
        denied = c.auth_client_pairing_decide(
            self.conn, started["authorization_request"], self.principal, False)
        self.assertEqual(denied["status"], "denied")
        self.assertEqual(c.auth_client_pairing_poll(
            self.conn, started["poll_secret"], "install-2")["status"],
            "denied")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS n FROM auth_tokens").fetchone()["n"], 0)

    def test_authorization_request_format_is_validated_before_lookup(self):
        # A non-opaque or wrong-length token is rejected on format alone,
        # before any database lookup (no lookup oracle for malformed input).
        with self.assertRaisesRegex(
                c.AttaccaError, "invalid client authorization request"):
            c._auth_client_pairing_row(self.conn, "AAAA-BBBB-CCCC")
        with self.assertRaisesRegex(
                c.AttaccaError, "invalid client authorization request"):
            c._auth_client_pairing_row(self.conn, "short-token")
        # A well-formed but unknown 43-char base64url token is reported unknown.
        with self.assertRaisesRegex(
                c.AttaccaError, "unknown client authorization request"):
            c._auth_client_pairing_row(self.conn, "A" * 43)

        started = c.auth_client_pairing_start(
            self.conn, "http://server", "install-legacy", "Legacy")
        row = c._auth_client_pairing_row(
            self.conn, started["authorization_request"])
        self.assertEqual(row["client_instance"], "install-legacy")
        self.assertEqual(row["status"], "pending")

    def test_failed_lookup_throttle_is_bounded_and_non_oracular(self):
        key = "user|127.0.0.1"
        with c._PAIRING_LOOKUP_FAILURES_LOCK:
            c._PAIRING_LOOKUP_FAILURES.pop(key, None)
        for _ in range(c._PAIRING_LOOKUP_MAX_FAILURES):
            c._auth_pairing_lookup_check(key)
            c._auth_pairing_lookup_failed(key)
        with self.assertRaisesRegex(c.AuthorizationError, "throttled"):
            c._auth_pairing_lookup_check(key)

    def test_authorize_and_deny_cannot_bypass_lookup_throttle(self):
        class Handler:
            def __init__(inner, address):
                inner.principal = self.principal
                inner.client_address = (address, 1234)

            def _conn(inner):
                return self.conn

            def _body_json(inner):
                return {}

            def _reply_json(inner, *_args, **_kwargs):
                self.fail("unknown pairing must not produce a reply")

        unknown = re.match(
            r"(.+)", "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-"
            "AAAA-AAAA-AAAA-AAAA-AAAA")
        for endpoint, address in (
                (c._r_auth_client_pairing_authorize, "192.0.2.10"),
                (c._r_auth_client_pairing_deny, "192.0.2.11")):
            handler = Handler(address)
            key = c._auth_pairing_lookup_throttle_key(
                handler, self.principal)
            with c._PAIRING_LOOKUP_FAILURES_LOCK:
                c._PAIRING_LOOKUP_FAILURES.pop(key, None)
            for _ in range(c._PAIRING_LOOKUP_MAX_FAILURES):
                with self.assertRaisesRegex(c.AttaccaError, "unavailable"):
                    endpoint(handler, unknown, {})
            with self.assertRaisesRegex(c.AuthorizationError, "throttled"):
                endpoint(handler, unknown, {})


if __name__ == "__main__":
    unittest.main()
