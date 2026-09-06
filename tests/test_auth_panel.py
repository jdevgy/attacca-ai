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
    def auth_gate(cls):
        start = cls.script.index("function renderAuth()")
        end = cls.script.index("async function bootstrap()", start)
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
        # T-76 uses the complete, authorization-filtered options directory
        # for the workspace switcher.  It is still fetched only after the
        # public authentication status has admitted the session.
        projects = bootstrap.index('api("/v1/projects?options=1")')
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
                "Client API keys", "Authorize client installation",
                'data-action="authorize-client-authorization"',
                'data-action="deny-client-authorization"',
                'data-action="revoke-client-key"',
                'data-action="delete-client-key"',
                'data-action="toggle-authentication"',
                "client installation", "Human owner:", "Account name"):
            self.assertIn(value, surface)
        for value in (
                "approve-terminal-enrollment", "start-terminal-enrollment",
                "actor_bindings", "save-migration-scope",
                "arm-auth-activation", "activate-authentication",
                "create-service-key", "device code"):
            self.assertNotIn(value, settings)

    def test_client_authorization_requires_explicit_actions_and_post_bodies(self):
        action_start = self.script.index(
            'if (action === "revoke-client-key")')
        action_end = self.script.index(
            'if (action === "select-project")', action_start)
        actions = self.script[action_start:action_end]
        self.assertIn('/v1/auth/client-keys/${encodeURIComponent', actions)
        self.assertIn('/permanent', actions)
        self.assertIn("Permanently delete this revoked", actions)
        self.assertIn('action === "authorize-client-authorization"', actions)
        self.assertIn('action === "deny-client-authorization"', actions)
        self.assertIn('/v1/auth/client-authorizations/${authorize ?', actions)
        self.assertIn("authorization_request: authorizationRequest", actions)
        self.assertIn(
            'body: { enabled, confirmed: true }', actions)
        self.assertNotIn("expected_readiness_version", actions)
        bootstrap_start = self.script.index("async function bootstrap()")
        bootstrap_end = self.script.index("async function loadProjects()", bootstrap_start)
        self.assertNotIn("/authorize", self.script[bootstrap_start:bootstrap_end])
        self.assertNotIn("/deny", self.script[bootstrap_start:bootstrap_end])

    def test_authenticated_account_cannot_be_overridden_by_settings_form(self):
        settings = self.client_surface()
        self.assertIn("Signed in as", settings)
        self.assertIn("immutable account name", settings)
        self.assertIn("Account name", settings)
        self.assertNotIn("account.display_name", settings)
        self.assertNotIn("web.${h(account.username)}", settings)
        self.assertNotIn("Run by user: ${h(account.username)}", settings)
        self.assertNotIn('name="owner"', settings)
        self.assertNotIn('name="actor"', settings)
        self.assertIn("never renames or replaces an AI identity", settings)

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

    def test_authorization_request_is_fragment_only_erased_and_not_rendered(self):
        settings = self.client_surface()
        self.assertIn("browser never displays or asks you to copy an API key", settings)
        self.assertNotIn("one-time-client-secret", settings)
        self.assertNotIn("copy it into", self.script.lower())
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
        self.assertIn('params.get("authorization_request")', hints)
        self.assertIn('params.delete("authorization_request")', hints)
        self.assertIn("history.replaceState", hints)
        self.assertNotIn("location.search", hints)
        self.assertNotIn("pairing", hints.lower())
        self.assertNotIn("h(authorizationRequest)", settings)
        self.assertNotIn("data-authorization-request", settings)

    def test_sign_in_gate_offers_account_creation_only_when_the_server_opens_it(self):
        gate = self.auth_gate()
        # The panel mirrors the server setting; it never decides on its own.
        self.assertIn('state.auth?.self_registration === "open"', gate)
        # Invitation acceptance and first-run bootstrap keep priority.
        self.assertIn(
            "const registrationOpen = !acceptingInvitation && !bootstrapRequired &&",
            gate)
        self.assertIn(
            'const creatingAccount = registrationOpen && state.authMode === "register"',
            gate)
        # The login card links to the form only while sign-up is open.
        self.assertIn(
            '${registrationOpen ? `<button class="button quiet" type="button" '
            'data-action="show-account-registration">Create account</button>` : ""}',
            gate)
        self.assertIn('data-form="auth-register"', gate)
        self.assertIn('data-action="dismiss-account-registration"', gate)
        self.assertIn('name="confirm_password"', gate)
        # The account name is the immutable identity recorded on every
        # mutation and the store keeps no separate display name, so this form
        # offers none either -- exactly like bootstrap and invitation accept.
        self.assertNotIn('id="auth-display-name"', gate)
        # Bootstrap and invitation modes remain intact.
        self.assertIn('data-form="auth-bootstrap"', gate)
        self.assertIn('data-form="accept-human-invitation"', gate)
        self.assertIn('data-form="auth-login"', gate)

    def test_account_creation_submits_to_the_register_route_and_reloads(self):
        start = self.script.index('if (kind === "auth-register")')
        register = self.script[start:self.script.index(
            'if (kind === "accept-human-invitation")', start)]
        self.assertIn(
            'values.password !== values.confirm_password', register)
        self.assertIn('api("/v1/auth/register", { method: "POST"', register)
        # Same post-success path as sign-in: reset, re-read auth status through
        # bootstrap(), and report the result with the shared toast.
        self.assertIn("form.reset();", register)
        self.assertIn("await bootstrap();", register)
        self.assertIn("toast(", register)
        # No bespoke error rendering: registration failures fall through to the
        # shared submit catch that toasts the server's message, exactly like
        # a failed sign-in.
        self.assertNotIn("catch", register)
        self.assertIn(
            'if (state.auth?.self_registration !== "open") throw new Error(',
            self.script)


if __name__ == "__main__":
    unittest.main()
