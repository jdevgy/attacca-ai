"""Static regressions for the D-17 browser/client-key Settings contract."""

import re
import subprocess
import unittest
from pathlib import Path


PANEL = Path(__file__).resolve().parents[1] / "web" / "admin.html"


class AuthPanelTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = PANEL.read_text(encoding="utf-8")
        match = re.search(
            r"^  <script>\n(?P<script>.*)^  </script>$", cls.source,
            flags=re.DOTALL | re.MULTILINE)
        if not match:
            raise AssertionError("admin panel script not found")
        cls.script = match.group("script")

    @classmethod
    def effective_settings(cls):
        start = cls.script.rindex("function renderAuthenticatedSettings()")
        end = cls.script.index("async function openTaskPlan", start)
        return cls.script[start:end]

    @classmethod
    def client_surface(cls):
        start = cls.script.index("function renderClientKeyRow")
        end = cls.script.index("async function openTaskPlan", start)
        return cls.script[start:end]

    def test_panel_javascript_is_valid(self):
        checked = subprocess.run(
            ["node", "--check", "-"], input=self.script, text=True,
            capture_output=True, timeout=10, check=False)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_auth_status_gates_every_protected_bootstrap_request(self):
        start = self.script.index("async function bootstrap()")
        end = self.script.index("async function loadProjects()", start)
        bootstrap = self.script[start:end]
        auth = bootstrap.index('api("/v1/auth/status")')
        projects = bootstrap.index('api("/v1/projects")')
        settings = bootstrap.index('api("/v1/settings")')
        self.assertLess(auth, projects)
        self.assertLess(auth, settings)
        self.assertIn("state.auth.bootstrap_required", bootstrap)
        self.assertIn(
            "state.auth.authentication_required && !state.auth.authenticated",
            bootstrap)
        self.assertIn("renderAuth();", bootstrap)

    def test_browser_session_and_csrf_are_applied_centrally(self):
        start = self.script.index("async function api(")
        end = self.script.index("async function downloadProjectExport", start)
        source = self.script[start:end]
        self.assertIn('credentials: "same-origin"', source)
        self.assertIn(
            'headers["X-Attacca-CSRF"] = state.auth.csrf_token', source)
        self.assertIn('["GET", "HEAD", "OPTIONS"]', source)

    def test_effective_settings_advertises_only_browser_and_client_keys(self):
        settings = self.effective_settings()
        surface = self.client_surface()
        for value in (
                "Client API keys", 'data-form="create-client-key"',
                'data-action="revoke-client-key"',
                'data-action="delete-client-key"',
                'data-action="toggle-authentication"',
                "client installation", "Human owner:", "Run by user:"):
            self.assertIn(value, surface)
        for value in (
                "approve-terminal-enrollment", "start-terminal-enrollment",
                "actor_bindings", "save-migration-scope",
                "arm-auth-activation", "activate-authentication",
                "create-service-key", "device code"):
            self.assertNotIn(value, settings)

    def test_client_key_handlers_use_exact_endpoints_and_one_time_atkey(self):
        create_start = self.script.index('if (kind === "create-client-key")')
        create_end = self.script.index(
            'if (kind === "save-panel-behavior")', create_start)
        create = self.script[create_start:create_end]
        self.assertIn('api("/v1/auth/client-keys"', create)
        self.assertIn('result.token.startsWith("atkey_")', create)
        self.assertIn("client_instance: clientInstance", create)
        self.assertIn('formData.getAll("project_memberships")', create)
        self.assertNotIn("actor", create.lower())
        self.assertIn('kind: "client", secret: result.token', create)

        action_start = self.script.index(
            'if (action === "revoke-client-key")')
        action_end = self.script.index(
            'if (action === "select-project")', action_start)
        actions = self.script[action_start:action_end]
        self.assertIn('/v1/auth/client-keys/${encodeURIComponent', actions)
        self.assertIn('/permanent', actions)
        self.assertIn("Permanently delete this revoked", actions)
        self.assertIn(
            'body: { enabled, confirmed: true }', actions)
        self.assertNotIn("expected_readiness_version", actions)

    def test_authenticated_account_cannot_be_overridden_by_settings_form(self):
        settings = self.client_surface()
        self.assertIn("Signed in as", settings)
        self.assertIn("web.${h(account.username)}", settings)
        self.assertIn("Run by user: ${h(account.username)}", settings)
        self.assertNotIn('name="owner"', settings)
        self.assertNotIn('name="actor"', settings)
        self.assertIn("Canonical AI actors", settings)

    def test_refresh_and_expiry_reenter_auth_gate(self):
        refresh_start = self.script.index(
            '$("#refresh-button").addEventListener')
        refresh_end = self.script.index(
            'window.addEventListener("hashchange"', refresh_start)
        refresh = self.script[refresh_start:refresh_end]
        self.assertIn("await bootstrap()", refresh)
        self.assertNotIn('api("/v1/settings")', refresh)

        recovery_start = self.script.index(
            "async function recoverExpiredAuthentication")
        recovery_end = self.script.index(
            "async function downloadProjectExport", recovery_start)
        recovery = self.script[recovery_start:recovery_end]
        self.assertIn('fetch("/v1/auth/status"', recovery)
        self.assertIn("state.projects = []", recovery)
        self.assertIn("state.credentialAccess = null", recovery)
        self.assertIn("state.oneTimeCredential = null", recovery)
        self.assertIn("renderAuth();", recovery)

    def test_secret_is_escaped_memory_only_and_never_in_url(self):
        settings = self.client_surface()
        self.assertIn(
            'id="one-time-client-secret">${h(value.secret)}', settings)
        self.assertIn(
            "navigator.clipboard.writeText(state.oneTimeCredential.secret)",
            self.script)
        self.assertNotRegex(
            self.script,
            r"storageSet\([^)]*(?:oneTimeCredential|client.*secret)")
        self.assertNotRegex(
            self.script, r"console\.(?:log|info|debug|warn|error)")
        hint_start = self.script.index(
            "function clientAuthorizationHintsFromLocation")
        hint_end = self.script.index(
            "// TESTABLE_CLIENT_AUTHORIZATION_HINTS:END", hint_start)
        hints = self.script[hint_start:hint_end]
        self.assertIn('params.get("client_instance")', hints)
        self.assertIn('params.get("client_label")', hints)
        self.assertNotIn("token", hints.lower())


if __name__ == "__main__":
    unittest.main()
