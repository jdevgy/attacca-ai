"""Control Panel authentication and terminal-credential regressions."""

import re
import subprocess
import unittest
from pathlib import Path


PANEL = Path(__file__).resolve().parents[1] / "web" / "admin.html"


class AuthPanelTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = PANEL.read_text(encoding="utf-8")

    def test_panel_javascript_is_valid(self):
        script = re.search(
            r"^  <script>\n(?P<script>.*)^  </script>$", self.source,
            flags=re.DOTALL | re.MULTILINE)
        self.assertIsNotNone(script)
        checked = subprocess.run(
            ["node", "--check", "-"], input=script.group("script"),
            text=True, capture_output=True, timeout=10, check=False)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_auth_status_gates_every_protected_bootstrap_request(self):
        start = self.source.index("async function bootstrap()")
        end = self.source.index("async function loadProjects()", start)
        bootstrap = self.source[start:end]
        auth = bootstrap.index('api("/v1/auth/status")')
        projects = bootstrap.index('api("/v1/projects")')
        settings = bootstrap.index('api("/v1/settings")')
        self.assertLess(auth, projects)
        self.assertLess(auth, settings)
        self.assertIn("state.auth.bootstrap_required", bootstrap)
        self.assertIn("state.auth.authentication_required && !state.auth.authenticated",
                      bootstrap)
        self.assertIn("renderAuth();", bootstrap)
        self.assertIn("return;", bootstrap[:projects])
        self.assertIn("state.projects = []", bootstrap[:projects])

    def test_browser_session_and_csrf_are_applied_centrally(self):
        start = self.source.index("async function api(")
        end = self.source.index("async function downloadProjectExport", start)
        api = self.source[start:end]
        self.assertIn('credentials: "same-origin"', api)
        self.assertIn('headers["X-Attacca-CSRF"] = state.auth.csrf_token', api)
        self.assertIn('["GET", "HEAD", "OPTIONS"]', api)
        self.assertIn('method = (options.method || "GET").toUpperCase()', api)

    def test_human_login_terminal_service_and_invitation_controls_are_shipped(self):
        for form in ("auth-bootstrap", "auth-login",
                     "approve-terminal-enrollment",
                     "save-migration-scope", "create-service-key",
                     "invite-human", "accept-human-invitation"):
            self.assertIn('data-form="%s"' % form, self.source)
        for action in ("auth-logout", "revoke-auth-token",
                       "revoke-terminal", "deny-terminal-enrollment",
                       "revoke-service-key", "revoke-invitation",
                       "copy-one-time-secret", "dismiss-one-time-credential",
                       "arm-auth-activation", "activate-authentication"):
            self.assertIn('data-action="%s"' % action, self.source)
        for route in ("/v1/auth/bootstrap", "/v1/auth/login",
                      "/v1/auth/logout", "/v1/auth/tokens",
                      "/v1/auth/access", "/v1/auth/migration-scope",
                      "/v1/auth/service-keys", "/v1/auth/invitations",
                      "/v1/auth/invitations/accept",
                      "/v1/auth/activation"):
            self.assertIn(route, self.source)
        self.assertIn("long-lived credential is available only to the initiating terminal",
                      self.source)
        self.assertIn("Copy this service credential now", self.source)
        self.assertIn("Share this one-time invitation securely", self.source)
        self.assertIn("No raw key is rendered", self.source)
        self.assertNotIn('data-form="create-auth-token"', self.source)
        self.assertNotIn('data-action="copy-auth-token"', self.source)

    def test_authenticated_account_replaces_mutable_attribution_ui(self):
        start = self.source.index("function renderAuthenticatedSettings()")
        end = self.source.index("async function openTaskPlan", start)
        settings = self.source[start:end]
        self.assertIn("Signed in as", settings)
        self.assertIn("web.${h(account.username)}", settings)
        self.assertIn("Run by user: ${h(account.username)}", settings)
        self.assertNotIn('name="owner"', settings)
        self.assertNotIn('name="actor"', settings)
        self.assertIn("Browser identity headers cannot override", settings)

    def test_server_credential_metadata_and_one_time_values_are_html_escaped(self):
        start = self.source.index("function renderServiceKeyRow")
        end = self.source.index("function renderAuthenticatedSettings()", start)
        renderers = self.source[start:end]
        for expression in (
                'h(key.label || "Unnamed service")',
                'h(key.token_prefix || "unavailable")',
                "h(key.token_id)",
                'h(invitation.label || "Workspace invitation")',
                'h(invitation.token_prefix || "unavailable")',
                "h(invitation.invitation_id)",
                "h(value.secret)", "h(value.link)"):
            self.assertIn(expression, renderers)
        self.assertNotRegex(
            renderers,
            r'data-[a-z-]+="\$\{h\(value\.(?:secret|link)\)\}')
        self.assertNotIn("newToken.token", self.source)
        self.assertNotIn("state.newToken", self.source)

    def test_refresh_reenters_auth_gate_instead_of_fetching_settings_first(self):
        marker = '$("#refresh-button").addEventListener'
        start = self.source.index(marker)
        end = self.source.index('window.addEventListener("hashchange"', start)
        handler = self.source[start:end]
        self.assertIn("await bootstrap()", handler)
        self.assertNotIn('api("/v1/settings")', handler)
        self.assertNotIn('api("/v1/projects")', handler)

    def test_session_expiry_clears_protected_state_and_returns_to_login(self):
        start = self.source.index("async function recoverExpiredAuthentication")
        end = self.source.index("async function downloadProjectExport", start)
        recovery = self.source[start:end]
        self.assertIn('fetch("/v1/auth/status"', recovery)
        self.assertIn("state.projects = []", recovery)
        self.assertIn("state.data = {}", recovery)
        self.assertIn("state.authTokens = []", recovery)
        self.assertIn("state.credentialAccess = null", recovery)
        self.assertIn("state.oneTimeCredential = null", recovery)
        self.assertIn("state.activationArmedVersion = null", recovery)
        self.assertIn("renderAuth();", recovery)
        api_start = self.source.index("async function api(")
        api_end = self.source.index("async function recoverExpiredAuthentication",
                                    api_start)
        api = self.source[api_start:api_end]
        self.assertIn("response.status === 401", api)
        self.assertIn("await recoverExpiredAuthentication()", api)

        bootstrap_start = self.source.index("async function bootstrap()")
        bootstrap_end = self.source.index("async function loadProjects()",
                                          bootstrap_start)
        bootstrap = self.source[bootstrap_start:bootstrap_end]
        catch = bootstrap.index("} catch (error) {", bootstrap.index(
            'api("/v1/projects")'))
        retry = bootstrap.index('state.serverSettings = await api("/v1/settings")',
                                catch)
        guard = bootstrap.index("error.status === 401", catch)
        self.assertLess(guard, retry)
        self.assertIn("busy(false);\n            return;",
                      bootstrap[guard:retry])

    def test_every_protected_direct_fetch_recovers_expired_authentication(self):
        """The binary export path cannot bypass the central JSON API helper."""
        start = self.source.index("async function downloadProjectExport")
        end = self.source.index("async function bootstrap()", start)
        download = self.source[start:end]
        self.assertIn("response.status === 401", download)
        self.assertIn("await recoverExpiredAuthentication()", download)
        self.assertIn("failure.status = response.status", download)

        # Only the central helper, the deliberately public recovery status
        # probe, and this audited binary-download helper may fetch directly.
        fetch_sites = [match.start() for match in re.finditer(r"\bfetch\(", self.source)]
        self.assertEqual(len(fetch_sites), 3)

    def test_obsolete_unauthenticated_settings_are_removed(self):
        self.assertNotIn("No login in this prototype", self.source)
        self.assertNotIn("Authentication, persistent server configuration",
                         self.source)
        self.assertNotIn("function renderSettings()", self.source)


if __name__ == "__main__":
    unittest.main()
