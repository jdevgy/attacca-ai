"""Secure browser authorization pairing for D-17 client-install keys."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


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
        secret = started["pairing_secret"]
        self.assertNotIn(secret, str(dict(c._auth_client_pairing_row(
            self.conn, started["pairing_code"]))))
        self.assertEqual(c.auth_client_pairing_poll(
            self.conn, secret, "install-1", "device-1")["status"],
            "pending")

        approved = c.auth_client_pairing_decide(
            self.conn, started["pairing_code"], self.principal, True,
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
        with self.assertRaisesRegex(c.AuthenticationError,
                                    "already delivered"):
            c.auth_client_pairing_poll(
                self.conn, secret, "install-1", "device-1")

    def test_deny_and_install_binding_fail_closed(self):
        started = c.auth_client_pairing_start(
            self.conn, "http://server", "install-2", "Claude desktop")
        with self.assertRaisesRegex(c.AuthorizationError, "instance"):
            c.auth_client_pairing_poll(
                self.conn, started["pairing_secret"], "another-install")
        denied = c.auth_client_pairing_decide(
            self.conn, started["pairing_code"], self.principal, False)
        self.assertEqual(denied["status"], "denied")
        self.assertEqual(c.auth_client_pairing_poll(
            self.conn, started["pairing_secret"], "install-2")["status"],
            "denied")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS n FROM auth_tokens").fetchone()["n"], 0)


if __name__ == "__main__":
    unittest.main()
