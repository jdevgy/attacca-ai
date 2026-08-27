"""Human login and identity use one canonical account name."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_single_human_name_core", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class SingleHumanAccountNameTest(unittest.TestCase):
    def test_creation_ignores_legacy_display_name_and_payload_omits_it(self):
        with tempfile.TemporaryDirectory() as directory:
            conn = c.connect(Path(directory) / "single-name.db")
            try:
                created = c.auth_create_user(
                    conn, "jack", "jack-password",
                    display_name="Jdevgy", bootstrap=True, is_admin=True)
                self.assertEqual(created["user"]["username"], "jack")
                self.assertNotIn("display_name", created["user"])
                row = conn.execute(
                    "SELECT * FROM auth_users WHERE username='jack'").fetchone()
                self.assertEqual(row["display_name"], "jack")
                principal = c._auth_principal(
                    conn, row, "session", session_hash="session")
                self.assertEqual(principal["username"], "jack")
                self.assertEqual(principal["display_name"], "jack")
            finally:
                conn.close()

    def test_connect_normalizes_existing_mismatched_compatibility_column(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.db"
            conn = c.connect(path)
            c.auth_create_user(
                conn, "jack", "jack-password", bootstrap=True,
                is_admin=True)
            conn.execute(
                "UPDATE auth_users SET display_name='Jdevgy'"
                " WHERE username='jack'")
            conn.close()

            reopened = c.connect(path)
            try:
                row = reopened.execute(
                    "SELECT * FROM auth_users WHERE username='jack'").fetchone()
                self.assertEqual(row["display_name"], "jack")
                self.assertNotIn("display_name", c._public_auth_user(row))
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
