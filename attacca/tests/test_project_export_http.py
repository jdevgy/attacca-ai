"""Authenticated HTTP, panel, and CLI contracts for full project backups.

Every HTTP check starts a throwaway server on an OS-assigned port.  Nothing in
this module reads or mutates the development server used by live agents.
"""

import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest import mock


os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "attacca.py")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c = load_module("attacca_export_http_core", ROOT / "attacca.py")
exporter = load_module("attacca_export_http_serializer",
                       ROOT / "project_export.py")


class BinaryServerFixture:
    def __init__(self, db):
        env = dict(os.environ)
        for key in ("ATTACCA_ACTOR", "ATTACCA_PROJECT", "ATTACCA_API_TOKEN"):
            env.pop(key, None)
        env["ATTACCA_DB"] = str(db)
        self.proc = subprocess.Popen(
            [sys.executable, SCRIPT, "serve", "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        line = self.proc.stdout.readline()
        match = re.search(r"http://127\.0\.0\.1:(\d+)", line)
        if not match:
            stderr = self.proc.stderr.read()
            self.stop()
            raise AssertionError(
                "isolated server did not report its port: %r %s" %
                (line, stderr))
        self.base = "http://127.0.0.1:%s" % match.group(1)

    def request(self, method, path, headers=None):
        request = urllib.request.Request(
            self.base + path, method=method,
            headers={key: value for key, value in (headers or {}).items()})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as error:
            return error.code, error.read(), error.headers

    def stop(self):
        if getattr(self, "proc", None) is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        self.proc.stdout.close()
        self.proc.stderr.close()
        self.proc = None


class ProjectExportHttpTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.db = cls.root / "export-http.db"
        repo = cls.root / "workspace"
        repo.mkdir()
        conn = c.connect(cls.db)
        try:
            # The first account is the server administrator by bootstrap
            # design; the workspace is deliberately created by a non-admin.
            c.auth_create_user(
                conn, "admin", "admin-password", "Server Admin")
            c.auth_create_user(
                conn, "owner", "owner-password", "Workspace Owner")
            c.auth_create_user(
                conn, "outsider", "outside-password", "Other User")

            c.set_current_owner("owner")
            c.set_current_git_context("feature/export", "abc123", "qa-device")
            c.project_init(
                conn, "web.owner", "human", path=repo,
                project_id="backup", name="Backup Workspace")
            c.agent_register(
                conn, "backup", "backup.director.codex", "agent",
                agent_id="backup.director.codex",
                display_name="Backup Workspace · Director · Codex",
                role="director", runtime="codex")
            task = c.task_create(
                conn, "backup", "backup.director.codex", "agent",
                "Ship full backup", description="Exercise export contents",
                expected_scope=["attacca/project_export.py"],
                plan_required=True)
            c.task_plan_set(
                conn, "backup", task["task_id"], "web.owner", "human",
                "Export plan", "One consistent snapshot",
                [{"section_id": "backup", "title": "Backup",
                  "body": "Include all project-scoped durable records."}])
            c.room_send(
                conn, "backup", "web.owner", "human",
                "Retain this full-log message", msg_type="directive")
            c.rule_create(
                conn, "backup", "web.owner", "human", "Backup rule",
                "Full exports are private human backups.")

            cls.admin_token = c.auth_token_create(
                conn, "admin", "admin backup", actor_type="human")["token"]
            cls.owner_token = c.auth_token_create(
                conn, "owner", "owner backup", actor_type="human")["token"]
            cls.outsider_token = c.auth_token_create(
                conn, "outsider", "outsider backup",
                actor_type="human")["token"]
            cls.agent_token = c.auth_token_create(
                conn, "owner", "agent runtime",
                actor_id="backup.director.codex", actor_type="agent",
                project_id="backup", runtime="codex")["token"]
            owner_row = conn.execute(
                "SELECT * FROM auth_users WHERE username='owner'").fetchone()
            cls.owner_session = c.auth_create_session(conn, owner_row)

            # Capture exact secret material that must never cross the endpoint.
            auth_user = conn.execute(
                "SELECT password_salt, password_hash FROM auth_users "
                "WHERE username='owner'").fetchone()
            cls.secrets = [
                cls.admin_token, cls.owner_token, cls.outsider_token,
                cls.agent_token, cls.owner_session["session"],
                cls.owner_session["csrf"], auth_user["password_salt"],
                auth_user["password_hash"],
            ]
        finally:
            c.set_current_owner(None)
            c.set_current_git_context()
            conn.close()
        cls.server = BinaryServerFixture(cls.db)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tmp.cleanup()

    @staticmethod
    def bearer(token):
        return {"Authorization": "Bearer %s" % token}

    def get_export(self, export_format, token=None, method="GET", headers=None):
        request_headers = dict(headers or {})
        if token:
            request_headers.update(self.bearer(token))
        return self.server.request(
            method, "/v1/projects/backup/export?format=%s" % export_format,
            request_headers)

    def direct_artifact(self, export_format):
        conn = c.connect(self.db)
        try:
            return c.build_project_export_artifact(
                conn, "backup", export_format)
        finally:
            conn.close()

    def test_export_requires_a_human_owner_or_admin(self):
        status, body, headers = self.get_export("json")
        self.assertEqual(status, 401)
        self.assertEqual(headers.get("WWW-Authenticate"), "Bearer")
        self.assertIn("login required", json.loads(body)["error"])

        status, body, _ = self.get_export("json", self.agent_token)
        self.assertEqual(status, 403)
        self.assertIn("agent API tokens cannot download", json.loads(body)["error"])

        status, body, _ = self.get_export("json", self.outsider_token)
        self.assertEqual(status, 403)
        self.assertIn("project_membership_required",
                      json.loads(body)["error"])

        for token in (self.owner_token, self.admin_token):
            status, body, _ = self.get_export("json", token)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["project"]["project_id"],
                             "backup")

        status, body, _ = self.get_export(
            "json", headers={
                "Cookie": "attacca_session=%s" %
                self.owner_session["session"]})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["manifest"]["project_id"], "backup")

        status, body, _ = self.server.request(
            "GET", "/v1/projects/missing/export?format=zip",
            self.bearer(self.owner_token))
        self.assertEqual(status, 403)
        self.assertIn("project_membership_required",
                      json.loads(body)["error"])

    def test_all_formats_are_deterministic_exact_and_downloadable(self):
        contracts = {
            "zip": ("application/zip", "attacca-backup-export.zip"),
            "json": ("application/json", "attacca-backup-export.json"),
            "ledger.ndjson": (
                "application/x-ndjson", "attacca-backup-ledger.ndjson"),
            "full-log.txt": (
                "text/plain", "attacca-backup-full-log.txt"),
        }
        for export_format, (content_type, filename) in contracts.items():
            with self.subTest(export_format=export_format):
                expected = self.direct_artifact(export_format)
                first_status, first, headers = self.get_export(
                    export_format, self.owner_token)
                second_status, second, _ = self.get_export(
                    export_format, self.owner_token)
                self.assertEqual((first_status, second_status), (200, 200))
                self.assertEqual(first, second)
                self.assertEqual(first, expected["data"])
                self.assertTrue(headers.get("Content-Type").startswith(
                    content_type))
                self.assertEqual(
                    headers.get("Content-Disposition"),
                    'attachment; filename="%s"' % filename)
                self.assertEqual(headers.get("Cache-Control"),
                                 "private, no-store, max-age=0")
                self.assertEqual(headers.get("X-Content-Type-Options"),
                                 "nosniff")
                self.assertEqual(headers.get("X-Attacca-Export-SHA256"),
                                 hashlib.sha256(first).hexdigest())
                self.assertEqual(
                    int(headers.get("X-Attacca-Export-Cursor")),
                    expected["snapshot"]["event_cursor"])
                self.assertEqual(headers.get("X-Attacca-Export-Head"),
                                 expected["snapshot"]["head_hash"])

        status, body, _ = self.get_export("csv", self.owner_token)
        self.assertEqual(status, 400)
        self.assertIn("zip, json, ledger.ndjson, full-log.txt",
                      json.loads(body)["error"])

        expected = self.direct_artifact("zip")
        status, body, headers = self.get_export(
            "zip", self.owner_token, method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(int(headers.get("Content-Length")),
                         len(expected["data"]))

    def test_export_never_contains_server_auth_or_global_secrets(self):
        bodies = {}
        for export_format in c.PROJECT_EXPORT_FORMATS:
            status, body, _ = self.get_export(export_format, self.admin_token)
            self.assertEqual(status, 200)
            bodies[export_format] = body

        decoded_zip = []
        with zipfile.ZipFile(io.BytesIO(bodies["zip"])) as archive:
            self.assertEqual(archive.namelist(), [
                "manifest.json", "project-export.json", "ledger.ndjson",
                "full-log.txt",
            ])
            decoded_zip.extend(archive.read(name) for name in archive.namelist())
            exported = json.loads(archive.read("project-export.json"))
        self.assertEqual(exported["manifest"]["excluded_server_tables"], [
            "auth_sessions", "auth_tokens", "auth_users", "server_settings",
        ])
        self.assertFalse(set(exported).intersection({
            "auth_sessions", "auth_tokens", "auth_users", "server_settings",
        }))
        inspected = list(bodies.values()) + decoded_zip
        for secret in self.secrets:
            with self.subTest(secret_prefix=secret[:8]):
                encoded = secret.encode()
                self.assertFalse(any(encoded in body for body in inspected))

    def test_export_sections_share_one_sqlite_snapshot_during_a_write(self):
        reader = c.connect(self.db)
        writer = c.connect(self.db)
        original_query = exporter._query_rows
        injected = {"done": False}

        def query_and_inject(conn, sql, params=()):
            rows = original_query(conn, sql, params)
            # _table_names is the snapshot's first read. Commit a new ledger
            # event immediately afterward from another WAL connection; every
            # remaining section must stay on the already-open reader view.
            if "sqlite_master" in sql and not injected["done"]:
                injected["done"] = True
                c.set_current_owner("owner")
                try:
                    c.append_event(
                        writer, "backup", "web.owner", "human",
                        "qa.concurrent_export_write", {"visible": "next export"})
                finally:
                    c.set_current_owner(None)
            return rows

        try:
            before = reader.execute(
                "SELECT COUNT(*) AS n FROM events WHERE project_id='backup'"
            ).fetchone()["n"]
            with mock.patch.object(exporter, "_query_rows",
                                   side_effect=query_and_inject):
                snapshot = exporter.build_project_export(
                    reader, "backup", log_renderer=c.render_log_line)
            after = writer.execute(
                "SELECT COUNT(*) AS n FROM events WHERE project_id='backup'"
            ).fetchone()["n"]
        finally:
            reader.close()
            writer.close()

        self.assertTrue(injected["done"])
        self.assertEqual(after, before + 1)
        self.assertEqual(len(snapshot["ledger"]["events"]), before)
        self.assertEqual(snapshot["manifest"]["counts"]["events"], before)
        self.assertEqual(snapshot["manifest"]["snapshot"]["event_cursor"],
                         before)
        self.assertTrue(exporter.validate_project_export(snapshot)["ok"])

    def test_cli_writes_private_exact_artifacts_and_streams_stdout(self):
        expected = self.direct_artifact("ledger.ndjson")["data"]
        output = self.root / "cli" / "backup.ndjson"
        command = [
            sys.executable, SCRIPT, "--db", str(self.db),
            "--project", "backup", "export", "--format", "ledger.ndjson",
            "--output", str(output),
        ]
        result = subprocess.run(command, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(output.read_bytes(), expected)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

        refused = subprocess.run(command, capture_output=True, timeout=30)
        self.assertEqual(refused.returncode, 2)
        self.assertIn(b"pass --force", refused.stderr)
        forced = subprocess.run(command + ["--force"], capture_output=True,
                                timeout=30)
        self.assertEqual(forced.returncode, 0, forced.stderr.decode())
        self.assertEqual(output.read_bytes(), expected)

        streamed = subprocess.run(
            [sys.executable, SCRIPT, "--db", str(self.db),
             "--project", "backup", "export", "--format", "full-log.txt",
             "--output", "-"], capture_output=True, timeout=30)
        self.assertEqual(streamed.returncode, 0, streamed.stderr.decode())
        self.assertEqual(
            streamed.stdout, self.direct_artifact("full-log.txt")["data"])

    def test_panel_offers_every_full_backup_with_visible_error_handling(self):
        panel = (ROOT / "web" / "admin.html").read_text()
        settings_start = panel.index("function renderAuthenticatedSettings()")
        settings_end = panel.index("async function openTaskPlan", settings_start)
        authenticated_settings = panel[settings_start:settings_end]
        self.assertIn('data-action="download-export"', authenticated_settings)
        self.assertNotIn('data-action="download-export"',
                         panel[:settings_start])
        for export_format in c.PROJECT_EXPORT_FORMATS:
            self.assertIn('data-format="%s"' % export_format,
                          authenticated_settings)
        self.assertIn("async function downloadProjectExport(format)", panel)
        self.assertIn("credentials: \"same-origin\"", panel)
        self.assertIn("if (!response.ok)", panel)
        self.assertIn("URL.createObjectURL(blob)", panel)
        self.assertIn("URL.revokeObjectURL(objectUrl)", panel)
        self.assertIn('action === "download-export"', panel)
        self.assertIn("button.textContent = \"Preparing…\"", panel)
        self.assertIn("private human backup, not the agent sync mirror", panel)
        self.assertIn("no empty placeholder file is saved", panel)


if __name__ == "__main__":
    unittest.main()
