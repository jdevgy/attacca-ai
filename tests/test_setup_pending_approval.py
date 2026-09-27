"""Setup collects replacement approvals before choosing a still-valid old key.

Real HTTP servers, accounts, pairing requests, and credential files are isolated
fixtures. Only transport failures and an invalid delivery envelope are injected.
"""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests import test_client_pairing_recovery as pairing


ROOT = pairing.ROOT
flow = pairing.flow


class SetupPendingApprovalHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pairing.PairingRecoveryHttpTest.setUpClass()
        cls.core = pairing.PairingRecoveryHttpTest.core

    def setUp(self):
        self.private_home = tempfile.TemporaryDirectory(prefix="attacca-setup-approval-")
        self.addCleanup(self.private_home.cleanup)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("ATTACCA_", "CODEX_", "CLAUDE_", "KIMI_"))}
        environment.update(HOME=self.private_home.name,
                           USERPROFILE=self.private_home.name,
                           ATTACCA_DISABLE_WATCHER="1", ATTACCA_AUTOSTART="0")
        patcher = mock.patch.dict(os.environ, environment, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        # Composition avoids inheriting and rerunning the fixture's own tests.
        self.fixture = pairing.PairingRecoveryHttpTest()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.url = self.fixture.url
        self.instance = self.fixture.instance
        self.credentials = self.fixture.credentials
        self.actor = "alpha.director.codex"
        self.assertNotEqual(self.fixture.server.server_address[1], 4173)
        core = self.core
        core._remote_setup_auth.context = None
        self.addCleanup(setattr, core._remote_setup_auth, "context", None)
        for name, value in (("CREDENTIALS_FILE", self.credentials),
                            ("IDENTITY_FILE", Path(self.private_home.name) / "identity.json")):
            patcher = mock.patch.object(core, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name, value in (("find_project_link", {"project_id": "alpha"}),
                            ("load_client_instance_id", self.instance),
                            ("load_device_id", "isolated-setup-device"),
                            ("load_owner", None),
                            ("_terminal_flow_runtime", flow)):
            patcher = mock.patch.object(core, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        browser = mock.patch.object(flow.webbrowser, "open")
        self.browser = browser.start()
        self.addCleanup(browser.stop)
        conn = core.connect(self.fixture.db)
        try:
            principal = self._principal(conn)
            for project in ("alpha", "beta"):
                core.project_init(conn, "web.owner", "human",
                                  path=Path(self.private_home.name) / project,
                                  project_id=project, name=project.title())
                core.auth_grant_project_membership(
                    conn, principal, project, granted_by="owner")
            core.agent_register(conn, "alpha", "web.owner", "human",
                                agent_id=self.actor, role="director", runtime="codex",
                                canonical_identity=False, registration_username="owner")
            created = core.auth_client_key_create(
                conn, principal, "Existing valid client", self.instance,
                memberships=["alpha"])
        finally:
            conn.close()
        self.old_token = created["token"]
        flow.save_client_api_key(self.url, created, client_instance=self.instance,
                                 credentials_path=self.credentials)
        # Establish independently that the old credential really works.
        self.assertTrue(core.remote_json(
            self.url, "GET", "/v1/auth/status", actor=self.actor,
            actor_type="agent", bearer_token=self.old_token,
            project_id="alpha")["authenticated"])

    def _principal(self, conn):
        user = conn.execute("SELECT * FROM auth_users WHERE username='owner'").fetchone()
        return self.core._auth_principal(conn, user, "session", session_hash="fixture")

    def _start(self):
        result = flow.start_client_pairing(
            self.url, client_instance=self.instance,
            credentials_path=self.credentials, open_browser=False)
        self.assertEqual(result["status"], "pending")
        return flow._pairing_record(flow.read_credentials_store(self.credentials),
                                    self.url, self.instance)

    def _decide(self, request, authorize=True, memberships=None):
        conn = self.core.connect(self.fixture.db)
        try:
            self.core.auth_client_pairing_decide(
                conn, request["authorization_request"], self._principal(conn),
                authorize, memberships=memberships)
        finally:
            conn.close()

    def _rows(self):
        conn = self.core.connect(self.fixture.db)
        try:
            return [dict(row) for row in conn.execute(
                "SELECT status,acknowledged_at FROM auth_client_authorizations")]
        finally:
            conn.close()

    def _setup(self):
        return self.core._ensure_client_setup_auth(self.url, self.actor)

    def _saved_key(self):
        return flow._client_key_record(flow.read_credentials_store(self.credentials),
                                       self.url, self.instance)

    def _assert_old_selected(self, result, expected_requests=1):
        self.assertTrue(result["authenticated"])
        self.assertEqual(self.core._remote_setup_auth.context["bearer_token"], self.old_token)
        self.assertEqual(self._saved_key()["token"], self.old_token)
        self.assertEqual(len(self._rows()), expected_requests)
        self.browser.assert_not_called()

    def _disable_fixture_login(self):
        conn = self.core.connect(self.fixture.db)
        try:
            self.core.auth_activate(conn, self._principal(conn), confirmed=True,
                                    server=self.fixture.server, enabled=False)
        finally:
            conn.close()
        status = self.core.remote_json(self.url, "GET", "/v1/auth/status",
                                       actor=self.actor, use_auth=False)
        self.assertTrue(status["anonymous_access"])

    def test_approved_replacement_supersedes_a_valid_saved_key(self):
        request = self._start()
        self._decide(request, memberships=["alpha"])
        result = self._setup()
        self.assertTrue(result["authenticated"])
        self.assertNotEqual(self._saved_key()["token"], self.old_token)
        self.assertEqual(self.core._remote_setup_auth.context["bearer_token"],
                         self._saved_key()["token"])
        self.assertIsNotNone(self._rows()[0]["acknowledged_at"])
        self.assertIsNone(flow._pairing_record(flow.read_credentials_store(self.credentials),
                                              self.url, self.instance))
        self.assertEqual(len(self._rows()), 1)
        self.browser.assert_not_called()

    def test_approved_replacement_supersedes_valid_environment_key_without_editing_env(self):
        request = self._start()
        self._decide(request, memberships=["alpha"])
        with mock.patch.dict(os.environ, {self.core.ENV_API_TOKEN: self.old_token}):
            result = self._setup()
            self.assertTrue(result["authenticated"])
            selected = self.core._remote_setup_auth.context["bearer_token"]
            self.assertNotEqual(selected, self.old_token)
            self.assertEqual(selected, self._saved_key()["token"])
            self.assertEqual(os.environ[self.core.ENV_API_TOKEN], self.old_token)
        self.assertIsNotNone(self._rows()[0]["acknowledged_at"])
        self.assertEqual(len(self._rows()), 1)
        self.browser.assert_not_called()

    def test_pending_request_preserves_working_key_without_new_enrollment(self):
        self._start()
        self._assert_old_selected(self._setup())
        self.assertEqual(self._rows()[0]["status"], "pending")
        self.assertIsNone(self._rows()[0]["acknowledged_at"])

    def test_collection_does_not_revoke_a_later_explicit_environment_override(self):
        request = self._start()
        self._decide(request, memberships=["alpha"])
        with mock.patch.dict(os.environ, {self.core.ENV_API_TOKEN: self.old_token}):
            self.assertTrue(self._setup()["authenticated"])
            received = self._saved_key()["token"]
            self.assertNotEqual(received, self.old_token)
            self.assertEqual(self.core._remote_setup_auth.context["bearer_token"], received)
            # No pending delivery: explicit process configuration still selects
            # its independently verified key. Collection must not revoke it or
            # silently rewrite that configuration or the new private record.
            result = self._setup()
            self.assertEqual(result["credential_source"], "environment")
            self.assertEqual(self.core._remote_setup_auth.context["bearer_token"],
                             self.old_token)
            self.assertEqual(self._saved_key()["token"], received)
            self.assertEqual(os.environ[self.core.ENV_API_TOKEN], self.old_token)
        self.assertEqual(len(self._rows()), 1)
        self.browser.assert_not_called()

    def test_denied_request_preserves_working_key_without_new_enrollment(self):
        request = self._start()
        self._decide(request, authorize=False)
        self._assert_old_selected(self._setup())
        self.assertEqual(self._rows()[0]["status"], "denied")
        self.assertIsNone(self._rows()[0]["acknowledged_at"])

    def test_transient_poll_failure_preserves_working_key_without_new_enrollment(self):
        self._start()
        original = flow.UrllibJsonTransport.request

        def outage(transport, method, url, **kwargs):
            if url.endswith(flow.CLIENT_AUTHORIZATIONS_PATH + "/poll"):
                raise flow.TerminalFlowTransportError("isolated poll outage")
            return original(transport, method, url, **kwargs)

        with mock.patch.object(flow.UrllibJsonTransport, "request", outage):
            self._assert_old_selected(self._setup())
        self.assertEqual(self._rows()[0]["status"], "pending")

    def test_no_pending_request_keeps_private_files_unchanged_and_never_polls(self):
        before = {str(path.relative_to(self.credentials.parent)): path.read_bytes()
                  for path in self.credentials.parent.rglob("*")
                  if path.is_file() and not path.name.startswith("server.db")}
        with mock.patch.object(flow.UrllibJsonTransport, "request",
                               side_effect=AssertionError("unexpected pairing HTTP")):
            self._assert_old_selected(self._setup(), expected_requests=0)
        after = {str(path.relative_to(self.credentials.parent)): path.read_bytes()
                 for path in self.credentials.parent.rglob("*")
                 if path.is_file() and not path.name.startswith("server.db")}
        self.assertEqual(before, after)

    def test_wrong_workspace_replacement_cannot_fall_back_to_env_key_or_local_access(self):
        self._assert_old_selected(self._setup(), expected_requests=0)
        self._disable_fixture_login()
        request = self._start()
        self._decide(request, memberships=["beta"])
        with mock.patch.dict(os.environ, {self.core.ENV_API_TOKEN: self.old_token}):
            with self.assertRaisesRegex(self.core.AuthenticationError,
                                        "client_authorization_scope_required") as failure:
                self._setup()
            self.assertEqual(os.environ[self.core.ENV_API_TOKEN], self.old_token)
        self.assertIsNone(self.core._remote_setup_auth.context)
        self.assertNotEqual(self._saved_key()["token"], self.old_token)
        self.assertEqual(self._saved_key()["project_memberships"], ["beta"])
        self.assertNotIn(self.old_token, str(failure.exception))
        self.assertNotIn(self._saved_key()["token"], str(failure.exception))
        self.assertIsNotNone(self._rows()[0]["acknowledged_at"])
        self.assertEqual(len(self._rows()), 1)
        self.browser.assert_not_called()

    def test_mismatched_installation_delivery_cannot_fall_back_to_env_key_or_local_access(self):
        self._assert_old_selected(self._setup(), expected_requests=0)
        self._disable_fixture_login()
        request = self._start()
        self._decide(request, memberships=["alpha"])
        original = flow.UrllibJsonTransport.request

        def wrong_instance(transport, method, url, **kwargs):
            response = original(transport, method, url, **kwargs)
            if url.endswith(flow.CLIENT_AUTHORIZATIONS_PATH + "/poll") and \
                    response.status == 200 and isinstance(response.value.get("credential"), dict):
                value = json.loads(json.dumps(response.value))
                value["credential"]["record"]["client_instance"] = "another-installation"
                return flow.JsonResponse(response.status, response.headers, value)
            return response

        with mock.patch.dict(os.environ, {self.core.ENV_API_TOKEN: self.old_token}), \
                mock.patch.object(flow.UrllibJsonTransport, "request", wrong_instance):
            with self.assertRaisesRegex(self.core.AuthenticationError,
                                        "client_authorization_collection_failed") as failure:
                self._setup()
            self.assertEqual(os.environ[self.core.ENV_API_TOKEN], self.old_token)
        self.assertIsNone(self.core._remote_setup_auth.context)
        preserved = self._saved_key()
        self.assertNotEqual(preserved["token"], self.old_token)
        self.assertEqual(preserved["client_instance"], "another-installation")
        self.assertNotIn(self.old_token, str(failure.exception))
        self.assertNotIn(preserved["token"], str(failure.exception))
        self.assertIsNone(self._rows()[0]["acknowledged_at"])
        self.assertEqual(len(self._rows()), 1)
        self.browser.assert_not_called()


if __name__ == "__main__":
    unittest.main()
