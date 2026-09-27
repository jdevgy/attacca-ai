"""A healthy idle watcher must collect an already approved replacement key."""

import contextlib
import copy
import hashlib
import io
import unittest
from unittest import mock

from tests import test_watcher_identity_recovery as fixture
from tests import test_session_wake as wake_fixture


hook = fixture.hook
core = fixture.core


class PendingApprovalWatcherTest(unittest.TestCase):
    # Reuse only the isolated HTTP fixture, not its inherited test methods.
    setUp = fixture.WatcherIdentityRecoveryTest.setUp
    save_credential = fixture.WatcherIdentityRecoveryTest.save_credential
    entry = fixture.WatcherIdentityRecoveryTest.entry
    update = fixture.WatcherIdentityRecoveryTest.update
    tick = fixture.WatcherIdentityRecoveryTest.tick

    def start_pending(self, approve=None, principal=None):
        self.assertNotEqual(self.server.server_address[1], 4173)
        self.assertTrue(self.tick()["ok"])
        result = self.terminal.start_client_pairing(
            self.url, client_instance=self.instance, runtime="codex",
            device_id="identity-test-device", open_browser=False)
        self.assertEqual(result["status"], "pending")
        pending = self.terminal._pairing_record(
            self.terminal.read_credentials_store(), self.url, self.instance)
        if approve is not None:
            connection = core.connect(self.db)
            try:
                core.auth_client_pairing_decide(
                    connection, pending["authorization_request"],
                    principal or self.principal, approve)
            finally:
                connection.close()
        return pending

    def current_token(self):
        return self.terminal.load_client_api_key(
            self.url, client_instance=self.instance, runtime="codex")

    def test_healthy_idle_tick_collects_approval_and_verifies_before_sync(self):
        pending = self.start_pending(approve=True)
        fingerprint = hashlib.sha256(pending["poll_secret"].encode()).hexdigest()
        original_delta = hook._watcher_event_delta

        def verified_delta(*args, **kwargs):
            current = self.entry()
            self.assertEqual(current["verified_credential_fingerprint"], fingerprint)
            self.assertFalse(current.get("identity_refresh_required"))
            self.assertEqual(current["canonical_actor_id"], self.actor)
            return original_delta(*args, **kwargs)

        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), \
                mock.patch.object(self.terminal.webbrowser, "open",
                                  side_effect=AssertionError("No browser")), \
                mock.patch.object(hook, "_mcp_snapshot",
                                  side_effect=AssertionError("No AI prompt")), \
                mock.patch.object(hook, "_watcher_fetch_sync_snapshot",
                                  wraps=hook._watcher_fetch_sync_snapshot) as fetch, \
                mock.patch.object(hook, "_watcher_event_delta", side_effect=verified_delta):
            result = self.tick(now=161)
        self.assertTrue(result["ok"], result)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(self.current_token(), pending["poll_secret"])
        self.assertNotEqual(self.current_token(), self.credential["token"])
        self.assertFalse(self.entry().get("auth_required"))
        self.assertIsNone(self.terminal._pairing_record(
            self.terminal.read_credentials_store(), self.url, self.instance))
        connection = core.connect(self.db)
        try:
            approvals = connection.execute(
                "SELECT status, acknowledged_at FROM auth_client_authorizations").fetchall()
            self.assertEqual(len(approvals), 1)
            self.assertEqual(approvals[0]["status"], "consumed")
            self.assertTrue(approvals[0]["acknowledged_at"])
        finally:
            connection.close()

    def test_not_due_tick_does_not_poll_pending_approval(self):
        self.start_pending(approve=True)
        with mock.patch.object(self.terminal, "collect_pending_client_pairing") as collect:
            result = self.tick(now=101)
        self.assertFalse(result["due"], result)
        collect.assert_not_called()
        self.assertEqual(self.current_token(), self.credential["token"])

    def test_paused_subscription_never_collects_even_when_forced(self):
        self.start_pending(approve=True)
        self.server.update_interval_seconds = 0
        with mock.patch.object(self.terminal, "collect_pending_client_pairing") as collect:
            for force in (False, True):
                result = hook._watcher_tick(
                    self.key, now=161, force=force, notifier=lambda *_: None)
                self.assertTrue(result["disabled"], result)
        collect.assert_not_called()
        self.assertEqual(self.current_token(), self.credential["token"])

    def test_pending_replacement_keeps_healthy_credential_and_cadence(self):
        self.start_pending()
        with mock.patch.object(hook, "_watcher_fetch_sync_snapshot",
                               side_effect=AssertionError("Unchanged key")), \
                mock.patch.object(self.terminal, "collect_pending_client_pairing",
                                  wraps=self.terminal.collect_pending_client_pairing) as collect:
            self.assertTrue(self.tick(now=161)["ok"])
            self.assertFalse(self.tick(now=162)["due"])
        self.assertEqual(collect.call_count, 1)
        self.assertEqual(self.current_token(), self.credential["token"])
        self.assertFalse(self.entry().get("auth_required"))
        self.assertEqual(self.entry()["pending_approval_status"], "pending")

    def test_denied_replacement_does_not_revoke_current_key(self):
        self.start_pending(approve=False)
        self.assertTrue(self.tick(now=161)["ok"])
        self.assertEqual(self.current_token(), self.credential["token"])
        self.assertFalse(self.entry().get("auth_required"))
        self.assertEqual(self.entry()["pending_approval_status"], "denied")
        self.assertIsNone(self.terminal._pairing_record(
            self.terminal.read_credentials_store(), self.url, self.instance))

    def test_expired_replacement_does_not_revoke_current_key(self):
        self.start_pending()
        connection = core.connect(self.db)
        try:
            connection.execute(
                "UPDATE auth_client_authorizations SET expires_at='2000-01-01T00:00:00+00:00'")
        finally:
            connection.close()
        self.assertTrue(self.tick(now=161)["ok"])
        self.assertEqual(self.current_token(), self.credential["token"])
        self.assertFalse(self.entry().get("auth_required"))
        self.assertEqual(self.entry()["pending_approval_status"], "expired")

    def test_another_installations_approval_is_not_collected(self):
        self.assertTrue(self.tick()["ok"])
        other_instance = "isolated-other-installation"
        self.terminal.start_client_pairing(
            self.url, client_instance=other_instance, runtime="claude",
            device_id="other-device", open_browser=False)
        pending = self.terminal._pairing_record(
            self.terminal.read_credentials_store(), self.url, other_instance)
        connection = core.connect(self.db)
        try:
            core.auth_client_pairing_decide(
                connection, pending["authorization_request"], self.principal, True)
        finally:
            connection.close()
        before = self.terminal.default_credentials_path().read_bytes()
        with mock.patch.object(self.terminal.UrllibJsonTransport, "request",
                               side_effect=AssertionError("Other installation pairing")) as poll:
            self.assertTrue(self.tick(now=161)["ok"])
        poll.assert_not_called()
        self.assertEqual(self.current_token(), self.credential["token"])
        self.assertEqual(self.terminal.default_credentials_path().read_bytes(), before)

    def test_poll_error_is_secret_free_and_not_current_key_rejection(self):
        self.start_pending()
        error_secret = "DO_NOT_EXPOSE_POLL_SECRET"
        with mock.patch.object(self.terminal, "collect_pending_client_pairing",
                               side_effect=RuntimeError("HTTP 401 " + error_secret)):
            result = self.tick(now=161)
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.current_token(), self.credential["token"])
        entry = self.entry()
        self.assertFalse(entry.get("auth_required"))
        self.assertEqual(entry["pending_approval_status"], "poll_failed")
        self.assertIn("automatic retries continue", entry["pending_approval_error"])
        self.assertNotIn(error_secret, hook._watcher_state_path().read_text())
        with mock.patch.object(self.terminal, "collect_pending_client_pairing", return_value=None):
            self.assertTrue(self.tick(now=222)["ok"])
        self.assertNotIn("pending_approval_error", self.entry())

    def test_collection_failure_and_recovery_wake_once_per_real_incident(self):
        self.start_pending()
        observer = wake_fixture.receiver.ChangeObserver()

        def failure(now):
            with mock.patch.object(self.terminal, "collect_pending_client_pairing",
                                   side_effect=RuntimeError("poll unavailable")):
                self.assertTrue(self.tick(now=now)["ok"])

        failure(161)
        failed = self.entry()
        first_rows = [row for row in failed["pending"]
                      if row.get("source") == "client_approval_collection"]
        self.assertEqual(len(first_rows), 1)
        self.assertEqual(first_rows[0]["kind"], "sync_error")
        self.assertIn("Do not reapprove", first_rows[0]["summary"])
        self.assertNotIn("unchanged", first_rows[0]["summary"])
        first = observer.prepare("approval-scope", failed)
        self.assertEqual(first["actionable_count"], 1)
        observer.accept(first)
        notice = hook._watcher_pending_notice(
            self.status, self.config, runtime="codex", event_name="UserPromptSubmit")
        self.assertIn("could not finish collection", notice["context"])
        self.assertIsNone(observer.prepare("approval-scope", self.entry()))

        failure(222)
        self.assertEqual(self.entry()["pending_approval_incident"], 1)
        self.assertFalse(any(row.get("source") == "client_approval_collection"
                             for row in self.entry()["pending"]))
        self.assertIsNone(observer.prepare("approval-scope", self.entry()))

        # Successful polling is not the same as an approved credential.
        self.assertTrue(self.tick(now=283)["ok"])
        recovered = self.entry()
        recovery_rows = [row for row in recovered["pending"]
                         if row.get("source") == "client_approval_collection"]
        self.assertEqual(len(recovery_rows), 1)
        self.assertEqual(recovery_rows[0]["kind"], "sync_recovered")
        self.assertIn("request is still pending", recovery_rows[0]["summary"])
        self.assertIn("does not prove", recovery_rows[0]["summary"])
        recovered_notice = observer.prepare("approval-scope", recovered)
        self.assertEqual(recovered_notice["actionable_count"], 1)
        observer.accept(recovered_notice)
        self.assertTrue(self.tick(now=344)["ok"])
        self.assertIsNone(observer.prepare("approval-scope", self.entry()))
        hook._watcher_pending_notice(
            self.status, self.config, runtime="codex", event_name="UserPromptSubmit")

        failure(405)
        second_rows = [row for row in self.entry()["pending"]
                       if row.get("source") == "client_approval_collection"]
        self.assertEqual(self.entry()["pending_approval_incident"], 2)
        self.assertEqual(len(second_rows), 1)
        self.assertNotEqual(second_rows[0]["fingerprint"], first_rows[0]["fingerprint"])
        self.assertEqual(observer.prepare("approval-scope", self.entry())["actionable_count"], 1)
        self.assertFalse(self.entry().get("auth_required"))

    def test_recovery_notice_distinguishes_collected_credential(self):
        pending = self.start_pending(approve=True)
        with mock.patch.object(self.terminal, "collect_pending_client_pairing",
                               side_effect=RuntimeError("temporary failure")):
            self.assertTrue(self.tick(now=161)["ok"])
        self.assertTrue(self.tick(now=222)["ok"])
        recovery = [row for row in self.entry()["pending"]
                    if row.get("source") == "client_approval_collection"
                    and row["kind"] == "sync_recovered"]
        self.assertEqual(len(recovery), 1)
        self.assertIn("approved credential was received and saved", recovery[0]["summary"])
        self.assertIn("verification is still required", recovery[0]["summary"])
        self.assertEqual(self.current_token(), pending["poll_secret"])

    def test_collection_notice_does_not_change_authority_or_delivery_receipts(self):
        self.start_pending()
        retained = {"auth_required": True, "offline_mode": "auth_required",
                    "identity_refresh_required": True,
                    "rendered": {"retained-mail": {"rendered_at": "earlier"}},
                    "attention": [{"event_id": "retained-mail", "seq": 7}],
                    "pending_dispositions": [{"event_id": "pending-work", "seq": 8}]}
        self.update(**retained)
        before = copy.deepcopy(self.entry())
        with mock.patch.object(self.terminal, "collect_pending_client_pairing",
                               side_effect=RuntimeError("failed")):
            hook._watcher_collect_pending_approval(self.key, self.entry(), 161)
        after = self.entry()
        for field in retained:
            self.assertEqual(after[field], before[field], field)
        with mock.patch.object(self.terminal, "collect_pending_client_pairing",
                               return_value={"status": "pending"}):
            hook._watcher_collect_pending_approval(self.key, self.entry(), 222)
        for field in retained:
            self.assertEqual(self.entry()[field], before[field], field)

    def test_unsuccessful_poll_results_are_collection_errors_not_key_rejections(self):
        self.start_pending()
        for result in ({"status": "authorization_required"},
                       {"status": "invalid_secret"}, {"status": {}}, {}):
            with self.subTest(result=result), \
                    mock.patch.object(self.terminal, "collect_pending_client_pairing",
                                      return_value=result):
                hook._watcher_collect_pending_approval(self.key, self.entry(), 161)
                self.assertEqual(self.entry()["pending_approval_status"], "poll_failed")
                self.assertFalse(self.entry().get("auth_required"))
        rows = [row for row in self.entry()["pending"]
                if row.get("source") == "client_approval_collection"]
        self.assertEqual(len(rows), 1)

    def test_failure_transition_and_notice_commit_atomically(self):
        self.start_pending()
        before = hook._watcher_state_path().read_bytes()
        with mock.patch.object(self.terminal, "collect_pending_client_pairing",
                               side_effect=RuntimeError("poll failed")), \
                mock.patch.object(hook, "_write_state", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                hook._watcher_collect_pending_approval(self.key, self.entry(), 161)
        self.assertEqual(hook._watcher_state_path().read_bytes(), before)
        with mock.patch.object(self.terminal, "collect_pending_client_pairing",
                               side_effect=RuntimeError("poll failed")):
            hook._watcher_collect_pending_approval(self.key, self.entry(), 222)
        self.assertEqual(self.entry()["pending_approval_incident"], 1)
        failed = hook._watcher_state_path().read_bytes()
        with mock.patch.object(self.terminal, "collect_pending_client_pairing",
                               return_value={"status": "pending"}), \
                mock.patch.object(hook, "_write_state", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                hook._watcher_collect_pending_approval(self.key, self.entry(), 283)
        self.assertEqual(hook._watcher_state_path().read_bytes(), failed)
        with mock.patch.object(self.terminal, "collect_pending_client_pairing",
                               return_value={"status": "pending"}):
            hook._watcher_collect_pending_approval(self.key, self.entry(), 344)
        rows = [row for row in self.entry()["pending"]
                if row.get("source") == "client_approval_collection"]
        self.assertEqual([row["kind"] for row in rows], ["sync_error", "sync_recovered"])

    def test_persisted_key_is_reloaded_even_if_collection_then_raises(self):
        pending = self.start_pending(approve=True)
        original = self.terminal.collect_pending_client_pairing

        def receipt_error(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("Simulated failure after credential persistence")

        with mock.patch.object(self.terminal, "collect_pending_client_pairing",
                               side_effect=receipt_error), \
                mock.patch.object(hook, "_watcher_fetch_sync_snapshot",
                                  wraps=hook._watcher_fetch_sync_snapshot) as fetch:
            result = self.tick(now=161)
        self.assertTrue(result["ok"], result)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(self.current_token(), pending["poll_secret"])
        self.assertEqual(self.entry()["verified_credential_fingerprint"],
                         hashlib.sha256(pending["poll_secret"].encode()).hexdigest())

    def test_new_key_without_project_access_blocks_before_old_mirror_or_writes(self):
        connection = core.connect(self.db)
        try:
            core.auth_create_user(connection, "other", "isolated-other-password")
            user = connection.execute(
                "SELECT * FROM auth_users WHERE username='other'").fetchone()
            other_principal = core._auth_principal(
                connection, user, "session", actor_type="human")
        finally:
            connection.close()
        pending = self.start_pending(approve=True, principal=other_principal)
        previous_fingerprint = self.entry()["verified_credential_fingerprint"]
        with mock.patch.object(hook, "_watcher_build_offline_adapter",
                               side_effect=AssertionError("Do not open old mirror")) as adapter, \
                mock.patch.object(hook, "_watcher_event_delta",
                                  side_effect=AssertionError("No old-scope delta")) as delta, \
                mock.patch.object(hook, "_terminal_flow_notice", return_value={
                    "message": "Scope denied", "result": {"status": "pending", "interval": 60}}):
            result = self.tick(now=161)
        self.assertFalse(result["ok"], result)
        self.assertTrue(result["authentication_required"], result)
        adapter.assert_not_called()
        delta.assert_not_called()
        self.assertEqual(self.current_token(), pending["poll_secret"])
        self.assertEqual(self.entry()["verified_credential_fingerprint"], previous_fingerprint)
        self.assertTrue(self.entry()["identity_refresh_required"])

    def test_no_pending_request_adds_no_auth_http_or_browser_work(self):
        self.assertTrue(self.tick()["ok"])
        credential_bytes = self.terminal.default_credentials_path().read_bytes()
        with mock.patch.object(self.terminal.UrllibJsonTransport, "request",
                               side_effect=AssertionError("No pairing HTTP")) as auth_http, \
                mock.patch.object(self.terminal, "_start_client_pairing",
                                  side_effect=AssertionError("No authorization request")) as start, \
                mock.patch.object(self.terminal.webbrowser, "open",
                                  side_effect=AssertionError("No browser")) as browser:
            result = self.tick(now=161)
        self.assertTrue(result["ok"], result)
        auth_http.assert_not_called()
        start.assert_not_called()
        browser.assert_not_called()
        self.assertEqual(self.terminal.default_credentials_path().read_bytes(), credential_bytes)
        self.assertNotIn("pending_approval_status", self.entry())


if __name__ == "__main__":
    unittest.main()
