"""Local-owner password recovery; all databases and homes are temporary."""

import contextlib
import importlib.util
import io
import json
import os
import select
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import warnings
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "attacca.py"
SPEC = importlib.util.spec_from_file_location("attacca_password_reset_cli", SCRIPT)
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class PasswordResetCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "server.db"
        self.conn = c.connect(self.db)
        c.auth_create_user(self.conn, "owner", "old-owner-password")
        c.auth_create_user(self.conn, "member", "old-member-password")
        self.owner = c.auth_verify_user(self.conn, "owner", "old-owner-password")
        self.member = c.auth_verify_user(self.conn, "member", "old-member-password")
        c.auth_create_session(self.conn, self.owner)
        c.auth_create_session(self.conn, self.owner)
        c.auth_create_session(self.conn, self.member)
        self.conn.execute(
            "INSERT INTO server_settings(setting_key,value,updated_at) VALUES "
            "('auth.activated','true',?),('server.setup_mode','\"protected\"',?)",
            (c.now_iso(), c.now_iso()))
        self.conn.execute(
            "INSERT INTO auth_tokens(token_id,user_id,label,token_prefix,"
            "token_hash,token_kind,client_instance,created_at)"
            " VALUES ('test-key',?,'test client','atpair_fixture',"
            "'fixture-verifier','client','fixture-install',?)",
            (self.owner["user_id"], c.now_iso()))
        self.env = dict(os.environ, HOME=str(self.root), ATTACCA_DB=str(self.db))
        self.env.pop("ATTACCA_API_TOKEN", None)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def snapshot(self):
        tables = [row[0] for row in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return {name: [tuple(row) for row in self.conn.execute(
            'SELECT * FROM "%s"' % name)] for name in tables}

    def run_interactive_mock(self, argv=None, passwords=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(c.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(c.getpass, "getpass", side_effect=(
                    passwords or ["new-owner-password", "new-owner-password"])), \
                mock.patch.object(c, "connect", side_effect=AssertionError(
                    "recovery must not initialize or migrate a database")), \
                mock.patch.object(c, "load_owner", side_effect=AssertionError(
                    "recovery must not inspect installed client state")), \
                contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            code = c.cli_main(argv or [
                "--db", str(self.db), "auth", "reset-password", "owner"])
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_unchanged_failure(self, message, passwords=None):
        before = self.snapshot()
        with self.assertRaisesRegex(c.AttaccaError, message):
            self.run_interactive_mock(passwords=passwords)
        self.assertEqual(before, self.snapshot())

    def test_reset_changes_only_target_password_and_target_browser_sessions(self):
        before = self.snapshot()
        code, output, error = self.run_interactive_mock()
        self.assertEqual(code, 0)
        self.assertIn("No server restart is required", output)
        self.assertIn(str(self.db), error)
        self.assertNotIn("new-owner-password", output + error)
        self.assertIsNone(c.auth_verify_user(
            self.conn, "owner", "old-owner-password"))
        self.assertIsNotNone(c.auth_verify_user(
            self.conn, "owner", "new-owner-password"))
        after = self.snapshot()
        for table in before:
            if table not in ("auth_users", "auth_sessions"):
                self.assertEqual(before[table], after[table], table)
        users = {row["username"]: dict(row) for row in self.conn.execute(
            "SELECT * FROM auth_users")}
        for field, value in dict(self.owner).items():
            if field not in ("password_salt", "password_hash"):
                self.assertEqual(value, users["owner"][field], field)
        self.assertEqual(dict(self.member), users["member"])
        sessions = list(self.conn.execute("SELECT * FROM auth_sessions"))
        self.assertEqual(sum(row["revoked_at"] is not None for row in sessions), 2)
        self.assertTrue(all(row["revoked_at"] is None for row in sessions
                            if row["user_id"] == self.member["user_id"]))

    def test_parser_supports_all_database_option_positions(self):
        for argv in (["--db", "example.db", "auth", "reset-password", "owner"],
                     ["auth", "--db", "example.db", "reset-password", "owner"],
                     ["auth", "reset-password", "owner", "--db", "example.db"]):
            with self.subTest(argv=argv):
                self.assertEqual(c.build_parser().parse_args(argv).db, "example.db")

    def test_environment_database_and_json_output(self):
        with mock.patch.dict(os.environ, {c.ENV_DB: str(self.db)}):
            code, output, error = self.run_interactive_mock([
                "--json", "auth", "reset-password", "OWNER"])
        result = json.loads(output)
        self.assertTrue(result["ok"])
        self.assertEqual(result["username"], "owner")
        self.assertTrue(result["sessions_revoked"])
        self.assertNotIn("new-owner-password", output + error)
        self.assertEqual(code, 0)

    def test_mismatch_is_atomic_and_does_not_echo_secrets(self):
        self.assert_unchanged_failure("passwords do not match", ["secret-first", "secret-other"])

    def test_short_password_is_rejected_without_mutation(self):
        self.assert_unchanged_failure("at least 8 characters", ["short", "short"])

    def test_session_revocation_failure_rolls_back_password_change(self):
        self.conn.execute(
            "CREATE TRIGGER reject_session_revocation BEFORE UPDATE ON auth_sessions "
            "BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END")
        self.assert_unchanged_failure("cannot reset password")

    def test_recovery_does_not_enable_login_for_optional_local_mode(self):
        self.conn.execute("UPDATE server_settings SET value='false' "
                          "WHERE setting_key='auth.activated'")
        self.conn.execute("UPDATE server_settings SET value='\"local\"' "
                          "WHERE setting_key='server.setup_mode'")
        before = self.snapshot()["server_settings"]
        self.run_interactive_mock()
        self.assertEqual(before, self.snapshot()["server_settings"])
        self.assertEqual(c.server_access_mode(self.conn), "local")

    def test_getpass_echo_fallback_is_an_error_before_stdin_read(self):
        def echo_fallback(*args, **kwargs):
            warnings.warn("echo unavailable", c.getpass.GetPassWarning)
            self.fail("echo fallback must not be reached")
        self.assert_unchanged_failure("hidden terminal prompt", echo_fallback)

    def test_cancelled_prompt_does_not_mutate(self):
        for interruption in (KeyboardInterrupt, EOFError):
            with self.subTest(interruption=interruption.__name__):
                self.assert_unchanged_failure("cancelled", interruption)

    def test_unknown_or_disabled_user_is_not_prompted_or_created(self):
        self.conn.execute("UPDATE auth_users SET disabled_at=? WHERE username='member'",
                          (c.now_iso(),))
        before = self.snapshot()
        for username in ("missing", "member"):
            with mock.patch.object(c.sys.stdin, "isatty", return_value=True), \
                    mock.patch.object(c.getpass, "getpass") as prompt:
                with self.assertRaisesRegex(c.AttaccaError, "unknown active"):
                    c.auth_reset_password_cli(self.db, username)
                prompt.assert_not_called()
        self.assertEqual(before, self.snapshot())

    def test_noninteractive_pipe_is_rejected_without_mutation_or_secret_output(self):
        before = self.snapshot()
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "auth", "reset-password", "owner"],
            input="never-echo-this-password\nnever-echo-this-password\n",
            capture_output=True, text=True, env=self.env, cwd=str(self.root), timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires an interactive terminal", result.stderr)
        self.assertNotIn("never-echo-this-password", result.stdout + result.stderr)
        self.assertEqual(before, self.snapshot())

    def test_missing_database_never_creates_file_or_parent_directory(self):
        missing = self.root / "missing-parent" / "mistyped.db"
        with self.assertRaisesRegex(c.AttaccaError, "existing server database"):
            c.auth_reset_password_cli(missing, "owner")
        self.assertFalse(missing.parent.exists())

    def test_directory_and_symlink_are_rejected(self):
        targets = [self.root]
        if hasattr(os, "symlink"):
            link = self.root / "database-link.db"
            link.symlink_to(self.db)
            targets.append(link)
        for path in targets:
            with self.subTest(path=path):
                with self.assertRaisesRegex(c.AttaccaError, "regular database file"):
                    c.auth_reset_password_cli(path, "owner")

    @unittest.skipUnless(hasattr(os, "geteuid"), "POSIX file ownership")
    def test_foreign_database_owner_is_rejected(self):
        before = self.snapshot()
        with mock.patch.object(c.os, "geteuid", return_value=self.db.stat().st_uid + 1000):
            with self.assertRaisesRegex(c.AttaccaError, "operating-system user"):
                c.auth_reset_password_cli(self.db, "owner")
        self.assertEqual(before, self.snapshot())

    def test_unrelated_database_is_not_initialized_or_migrated(self):
        unrelated = self.root / "unrelated.db"
        with sqlite3.connect(str(unrelated)) as conn:
            conn.execute("CREATE TABLE unrelated(value TEXT)")
        content = unrelated.read_bytes()
        with mock.patch.object(c.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(c.getpass, "getpass") as prompt:
            with self.assertRaisesRegex(c.AttaccaError, "existing Attacca database"):
                c.auth_reset_password_cli(unrelated, "owner")
            prompt.assert_not_called()
        self.assertEqual(content, unrelated.read_bytes())

    def test_database_uri_special_characters_are_quoted(self):
        alternate = self.root / "server?#name.db"
        with sqlite3.connect(str(alternate)) as conn:
            self.conn.backup(conn)
        code, _, _ = self.run_interactive_mock([
            "auth", "reset-password", "owner", "--db", str(alternate)])
        self.assertEqual(code, 0)
        self.assertIsNotNone(c.auth_verify_user(self.conn, "owner", "old-owner-password"))
        with sqlite3.connect(str(alternate)) as conn:
            conn.row_factory = sqlite3.Row
            self.assertIsNotNone(c.auth_verify_user(conn, "owner", "new-owner-password"))

    def test_help_exposes_recovery_without_database_access(self):
        missing = self.root / "absent.db"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--db", str(missing),
             "auth", "reset-password", "--help"],
            capture_output=True, text=True, env=self.env, cwd=str(self.root), timeout=15)
        self.assertEqual(result.returncode, 0)
        self.assertIn("username", result.stdout)
        self.assertIn("--db", result.stdout)
        self.assertNotIn("--password", result.stdout)
        self.assertFalse(missing.exists())

    @unittest.skipUnless(os.name == "posix", "real POSIX terminal")
    def test_real_cli_terminal_hides_both_password_prompts(self):
        import pty
        master, slave = pty.openpty()
        process = subprocess.Popen(
            [sys.executable, str(SCRIPT), "auth", "reset-password", "owner"],
            stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
            env=self.env, cwd=str(self.root))
        os.close(slave)
        output = b""
        prompts = [b"New password: ", b"Confirm new password: "]
        sent = 0
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk
                    if sent < len(prompts) and prompts[sent] in output:
                        os.write(master, b"pty-private-password\n")
                        sent += 1
                if process.poll() is not None and not ready:
                    break
            self.assertEqual(process.wait(timeout=3), 0, output.decode())
            self.assertEqual(sent, 2)
            self.assertNotIn(b"pty-private-password", output)
            self.assertIn(b"Password reset", output)
            self.assertIsNotNone(c.auth_verify_user(
                self.conn, "owner", "pty-private-password"))
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=3)
            os.close(master)


if __name__ == "__main__":
    unittest.main()
