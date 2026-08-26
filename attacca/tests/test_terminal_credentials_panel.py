"""Adversarial Control Panel regressions for terminal-owned authentication.

These tests intentionally inspect and execute the browser's small pure helpers.
They protect the human/AI identity boundary and the fail-closed migration gate
without requiring or mutating a live Attacca server.
"""

import json
import re
import subprocess
import unittest
from pathlib import Path


PANEL = Path(__file__).resolve().parents[1] / "web" / "admin.html"


class TerminalCredentialsPanelTestCase(unittest.TestCase):
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
    def marked(cls, name):
        begin = "// TESTABLE_%s:BEGIN" % name
        end = "// TESTABLE_%s:END" % name
        start = cls.script.index(begin) + len(begin)
        finish = cls.script.index(end, start)
        return cls.script[start:finish]

    def run_node(self, source):
        checked = subprocess.run(
            ["node", "-e", source], text=True, capture_output=True,
            timeout=10, check=False)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        return checked.stdout.strip()

    def test_panel_javascript_is_valid(self):
        checked = subprocess.run(
            ["node", "--check", "-"], input=self.script, text=True,
            capture_output=True, timeout=10, check=False)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_activation_gate_fails_closed_and_requires_two_exact_booleans(self):
        helpers = self.marked("EMPTY_CREDENTIAL_ACCESS") + self.marked(
            "CREDENTIAL_ACCESS_HELPERS")
        program = helpers + r"""
const account = {is_owner: true, is_admin: true};
function candidate(overrides = {}) {
  return normalizeCredentialAccess({
    capabilities: {activation: true},
    compatibility: {
      mode: "auto", effective_authentication: "optional",
      activated: false, ready: true, readiness_version: "v1",
      blockers: [], qa_evidence: {
        acceptance: {passed: true}, regression: {passed: true}
      }, ...overrides
    }
  });
}
const results = {
  green: activationEligibility(candidate(), account).allowed,
  compatibilityPinned: activationEligibility(candidate({mode: "compatibility"}), account).allowed,
  acceptanceMissing: activationEligibility(candidate({qa_evidence: {
    acceptance: {passed: false}, regression: {passed: true}}}), account).allowed,
  truthyStringRejected: activationEligibility(candidate({qa_evidence: {
    acceptance: {passed: "true"}, regression: {passed: true}}}), account).allowed,
  regressionMissing: activationEligibility(candidate({qa_evidence: {
    acceptance: {passed: true}, regression: {passed: false}}}), account).allowed,
  migrationMissing: activationEligibility(candidate({ready: false}), account).allowed,
  adminNotOwner: activationEligibility(candidate(), {is_admin: true, is_owner: false}).allowed,
  nonAdmin: activationEligibility(candidate(), {is_admin: false, is_owner: false}).allowed,
  alreadyActive: activationEligibility(candidate({activated: true}), account).allowed,
  noCapability: activationEligibility(normalizeCredentialAccess({
    compatibility: candidate().compatibility}), account).allowed
};
process.stdout.write(JSON.stringify(results));
"""
        result = json.loads(self.run_node(program))
        self.assertEqual(result, {
            "green": True,
            "compatibilityPinned": False,
            "acceptanceMissing": False,
            "truthyStringRejected": False,
            "regressionMissing": False,
            "migrationMissing": False,
            "adminNotOwner": False,
            "nonAdmin": False,
            "alreadyActive": False,
            "noCapability": False,
        })

    def test_activation_is_two_distinct_owner_actions_and_never_bootstrap(self):
        self.assertIn('data-action="arm-auth-activation"', self.source)
        self.assertIn('data-action="activate-authentication"', self.source)
        self.assertIn("state.activationArmedVersion", self.source)
        self.assertIn("expected_readiness_version: version", self.source)
        self.assertIn('api("/v1/auth/activation"', self.source)
        bootstrap = self.script[
            self.script.index("async function bootstrap()"):
            self.script.index("async function loadProjects()")]
        self.assertNotIn("/v1/auth/activation", bootstrap)
        activation_button = re.search(
            r'data-action="activate-authentication"(?P<tail>[^>]+)>',
            self.source)
        self.assertIsNotNone(activation_button)
        self.assertIn('armed ? "" : "disabled"', activation_button.group("tail"))
        self.assertIn("Creating the administrator does not activate protected mode",
                      self.source)

    def test_terminal_inventory_keeps_human_owner_and_ai_actor_separate(self):
        start = self.script.index("function renderTerminalRow")
        end = self.script.index("function renderServiceKeyRow", start)
        renderer = self.script[start:end]
        for phrase in (
                "Human owner:", "Device ID:", "Workspace membership",
                "Separate AI actors", "Last use:", "Expires:", "Revoked:"):
            self.assertIn(phrase, renderer)
        self.assertIn("credentialOwner(terminal, account)", renderer)
        self.assertIn("renderCredentialBindings(terminal)", renderer)
        self.assertNotIn("actor_id =", renderer)
        self.assertIn("AI actors", self.source)
        self.assertIn("remain separate, exact identities", self.source)

    def test_multi_workspace_approval_preselects_and_validates_exact_bindings(self):
        start = self.script.index("function renderPendingEnrollment")
        end = self.script.index("function renderMigrationTarget", start)
        renderer = self.script[start:end]
        self.assertIn("requestedProjects", renderer)
        self.assertIn("requestedBindings", renderer)
        self.assertIn("agentDirectory.map", renderer)
        self.assertIn("project_id: projectId", renderer)
        self.assertIn("requestedProjects.has(project.project_id)", renderer)
        self.assertIn("requestedBindings.has", renderer)

        handler = self.script[
            self.script.index('if (kind === "approve-terminal-enrollment")'):
            self.script.index('if (kind === "save-migration-scope")')]
        self.assertIn('formData.getAll("project_memberships")', handler)
        self.assertIn('formData.getAll("actor_bindings")', handler)
        self.assertIn("selectedMemberships.has(binding.project_id)", handler)
        self.assertIn("knownBindings.has", handler)
        self.assertIn("state.workspaceAgents", handler)
        self.assertNotIn("state.projectId, actor_id", handler)

        # The global text-input sizing rules must not turn checkbox chips into
        # full-width, 41px-tall controls in the rendered approval card.
        self.assertIn('input[type="checkbox"], input[type="radio"]', self.source)
        self.assertIn("min-height: 0", self.source)
        self.assertIn("label.chip { gap: 6px; cursor: pointer; }", self.source)

    def test_device_completion_url_is_safe_preserves_settings_hash_and_never_auto_approves(self):
        helper = self.marked("ENROLLMENT_URL_HELPER")
        program = helper + r"""
function consume(href) {
  global.location = {href};
  let replacement = null;
  global.history = {replaceState(_a, _b, value) { replacement = value; }};
  return {code: consumeEnrollmentCodeFromLocation(), replacement};
}
process.stdout.write(JSON.stringify({
  valid: consume("https://example.test/app?user_code=ABCD-1234#settings"),
  noHash: consume("https://example.test/app?user_code=NO-HASH"),
  unsafe: consume("https://example.test/app?keep=1&user_code=%3Cscript%3E#settings"),
  otherHash: consume("https://example.test/app?user_code=SAFE-9#room")
}));
"""
        result = json.loads(self.run_node(program))
        self.assertEqual(result["valid"], {
            "code": "ABCD-1234", "replacement": "/app#settings"})
        self.assertEqual(result["noHash"], {
            "code": "NO-HASH", "replacement": "/app#settings"})
        self.assertEqual(result["unsafe"], {
            "code": "", "replacement": "/app?keep=1#settings"})
        self.assertEqual(result["otherHash"], {
            "code": "", "replacement": "/app#room"})

        highlighter = self.script[
            self.script.index("const targetCode = state.targetedEnrollmentCode"):
            self.script.index("const directoryErrors", self.script.index(
                "const targetCode = state.targetedEnrollmentCode"))]
        self.assertIn("matches.length === 1", highlighter)
        self.assertIn('panel.dataset.enrollmentCode === targetCode', highlighter)
        self.assertIn('panel.parentElement.prepend(panel)', highlighter)
        self.assertIn('else state.targetedEnrollmentCode = ""', highlighter)
        self.assertNotIn(".submit(", highlighter)
        self.assertNotIn(".click(", highlighter)
        pending_start = self.script.index("function renderPendingEnrollment")
        pending_end = self.script.index("function renderMigrationTarget", pending_start)
        pending = self.script[pending_start:pending_end]
        self.assertGreaterEqual(
            pending.count('class="bridge-panel ${targeted ? "targeted" : ""}"'),
            2,
            "both approved and pending exact-code cards must render targeted styling")
        approval = self.script[
            self.script.index('if (kind === "approve-terminal-enrollment")'):
            self.script.index('if (kind === "save-migration-scope")')]
        self.assertIn("const code = form.dataset.code", approval)
        self.assertIn("encodeURIComponent(code)", approval)

    def test_exact_targeted_enrollment_is_fetched_and_merged_without_global_inventory(self):
        start = self.script.index("async function mergeTargetedTerminalEnrollment")
        end = self.script.index("async function loadWorkspaceAgentDirectory", start)
        helper = self.script[start:end]
        self.assertIn(
            "api(`/v1/auth/terminal-enrollments/${encodeURIComponent(code)}`)",
            helper)
        self.assertIn("returnedCode !== code", helper)
        self.assertIn("terminal_enrollments: [enrollment", helper)
        self.assertIn("enrollmentCode(item).toUpperCase() !== returnedCode", helper)
        self.assertNotIn('/v1/auth/terminal-enrollments"', helper)

        bootstrap = self.script[
            self.script.index("async function bootstrap()"):
            self.script.index("async function loadProjects()")]
        self.assertIn("await mergeTargetedTerminalEnrollment(", bootstrap)
        self.assertGreater(
            bootstrap.index("await mergeTargetedTerminalEnrollment("),
            bootstrap.index("loadCredentialAccess()"))

    def test_invitation_fragment_is_same_origin_consumed_and_erased(self):
        helper = self.marked("INVITATION_URL_HELPERS")
        program = "const VIEWS = ['overview', 'settings'];\n" + helper + r"""
function consume(href) {
  const parsed = new URL(href);
  global.location = {href, origin: parsed.origin, hash: parsed.hash};
  let replacement = null;
  global.history = {replaceState(_a, _b, value) { replacement = value; }};
  return {token: consumeInvitationTokenFromLocation(), replacement,
          view: viewFromLocationHash()};
}
global.location = {origin: "https://example.test"};
const raw = "ati_inv_abc.abcdefghijklmnopQRSTUV0123456789_-";
const link = invitationAcceptanceLink("https://example.test/app#settings", raw);
const external = invitationAcceptanceLink("https://evil.test/app#settings", raw);
const wrongPath = invitationAcceptanceLink("https://example.test/steal#settings", raw);
process.stdout.write(JSON.stringify({
  link, external, wrongPath,
  consumed: consume(link),
  unsafe: consume("https://example.test/app#settings&invitation_token=not-a-token"),
  queryOnly: consume("https://example.test/app?invitation_token=" + encodeURIComponent(raw) + "#settings")
}));
"""
        result = json.loads(self.run_node(program))
        self.assertEqual(
            result["link"],
            "https://example.test/app#settings&invitation_token="
            "ati_inv_abc.abcdefghijklmnopQRSTUV0123456789_-")
        self.assertEqual(result["external"], "")
        self.assertEqual(result["wrongPath"], "")
        self.assertEqual(result["consumed"], {
            "token": "ati_inv_abc.abcdefghijklmnopQRSTUV0123456789_-",
            "replacement": "/app#settings", "view": "settings"})
        self.assertEqual(result["unsafe"], {
            "token": "", "replacement": "/app#settings", "view": "settings"})
        self.assertEqual(result["queryOnly"], {
            "token": "", "replacement": "/app#settings", "view": "settings"})

        hash_handler = self.script[
            self.script.index('window.addEventListener("hashchange"'):
            self.script.index('document.addEventListener("visibilitychange"')]
        self.assertIn("consumeInvitationTokenFromLocation()", hash_handler)
        self.assertIn('state.view = "settings"', hash_handler)
        self.assertIn("renderAuth();", hash_handler)

    def test_browser_cannot_start_an_unbound_terminal_credential(self):
        self.assertNotIn('data-form="start-terminal-enrollment"', self.source)
        self.assertNotIn('if (kind === "start-terminal-enrollment")', self.script)
        self.assertNotIn('api("/v1/auth/device/start"', self.script)
        self.assertIn("The initiating terminal starts enrollment", self.source)
        self.assertIn("this panel never manufactures an unbound terminal credential",
                      self.source)

    def test_migration_scope_is_client_scoped_and_exclusion_needs_reason(self):
        handler = self.script[
            self.script.index('if (kind === "save-migration-scope")'):
            self.script.index('if (kind === "create-service-key")')]
        for field in ("project_id", "actor_id", "device_id"):
            self.assertIn(field, handler)
        self.assertIn("required_clients: requiredClients", handler)
        self.assertIn("exclusions", handler)
        self.assertIn("if (!reason)", handler)
        self.assertIn("expected_readiness_version", handler)
        self.assertNotIn("required_terminal_ids", handler)
        self.assertIn("Historical actors are not added automatically", self.source)
        settings = self.script[
            self.script.index("function renderAuthenticatedSettings"):
            self.script.index("async function openTaskPlan")]
        self.assertIn(
            "account.is_owner === true && access.capabilities.migration_scope === true",
            settings)

    def test_unsupported_future_capabilities_have_no_live_mutation_control(self):
        gates = self.script[
            self.script.index("function applyCredentialCapabilityGates"):
            self.script.index("function render(", self.script.index(
                "function applyCredentialCapabilityGates"))]
        self.assertIn('form[data-form="create-service-key"]', gates)
        self.assertIn('form[data-form="invite-human"]', gates)
        self.assertIn('form.hidden = true', gates)
        self.assertIn('capabilities.invitations !== true', gates)
        self.assertIn('data-action="revoke-invitation"', gates)
        settings = self.script[
            self.script.index("function renderAuthenticatedSettings"):
            self.script.index("async function openTaskPlan")]
        self.assertIn("access.capabilities.service_keys === true", settings)
        self.assertIn("access.capabilities.invitations !== true", settings)
        self.assertIn("No dead creation control is rendered", settings)
        self.assertIn("No dead invitation control is rendered", settings)
        service_handler = self.script[
            self.script.index('if (kind === "create-service-key")'):
            self.script.index('if (kind === "invite-human")')]
        invite_handler = self.script[
            self.script.index('if (kind === "invite-human")'):
            self.script.index('if (kind === "save-panel-behavior")')]
        self.assertIn("capabilities?.service_keys !== true", service_handler)
        self.assertIn("capabilities?.invitations !== true", invite_handler)
        self.assertIn("never creates a key that acts as the invitee", self.source)

    def test_one_time_service_and_invitation_secrets_are_memory_only(self):
        forbidden = (
            "newToken.token", "state.newToken", "oneTimeEnrollment",
            'id="new-api-token"', 'data-action="copy-auth-token"',
            'data-action="dismiss-auth-token"')
        for value in forbidden:
            self.assertNotIn(value, self.source)
        service_handler = self.script[
            self.script.index('if (kind === "create-service-key")'):
            self.script.index('if (kind === "invite-human")')]
        self.assertIn('api("/v1/auth/service-keys", { method: "POST", body })',
                      service_handler)
        self.assertIn('project_memberships: projectMemberships', service_handler)
        self.assertIn("actor_bindings", service_handler)
        self.assertIn('result.token.startsWith("atsvc_")', service_handler)
        self.assertIn('kind: "service", secret: result.token', service_handler)
        self.assertNotIn("loadCredentialAccess()", service_handler)
        self.assertLess(
            service_handler.index('kind: "service", secret: result.token'),
            service_handler.index("render({ force: true })"))

        invite_handler = self.script[
            self.script.index('if (kind === "invite-human")'):
            self.script.index('if (kind === "save-panel-behavior")')]
        self.assertIn('api("/v1/auth/invitations", { method: "POST", body })',
                      invite_handler)
        self.assertIn('project_memberships: projectMemberships', invite_handler)
        self.assertIn("is_admin: isAdmin", invite_handler)
        self.assertIn('result.invitation_token.startsWith("ati_")', invite_handler)
        self.assertIn('kind: "invitation", secret: result.invitation_token',
                      invite_handler)
        self.assertNotIn("loadCredentialAccess()", invite_handler)
        self.assertLess(
            invite_handler.index(
                'kind: "invitation", secret: result.invitation_token'),
            invite_handler.index("render({ force: true })"))

        self.assertNotRegex(
            self.script,
            r"storageSet\([^)]*(?:oneTimeCredential|pendingInvitationToken)")
        self.assertNotRegex(self.script, r"console\.(?:log|info|debug|warn|error)")
        self.assertIn('id="one-time-service-secret">${h(value.secret)}',
                      self.source)
        self.assertIn('id="one-time-invitation-secret">${h(value.secret)}',
                      self.source)
        self.assertIn('id="one-time-invitation-link">${h(value.link)}',
                      self.source)
        self.assertIn("state.oneTimeCredential = null", self.script)
        self.assertIn("navigator.clipboard.writeText(state.oneTimeCredential.secret)",
                      self.script)
        self.assertIn("function enrollmentCode", self.script)
        self.assertIn("payload?.user_code", self.script)
        self.assertNotIn("payload?.device_code", self.script)
        self.assertIn("long-lived credential is available only to the initiating terminal",
                      self.source)
        self.assertIn("browser storage, and logs", self.source)

    def test_invitation_acceptance_uses_anonymous_create_then_ordinary_login(self):
        handler = self.script[
            self.script.index('if (kind === "accept-human-invitation")'):
            self.script.index('if (kind === "approve-terminal-enrollment")')]
        self.assertIn('api("/v1/auth/invitations/accept"', handler)
        self.assertIn("invitation_token: invitationToken", handler)
        self.assertIn("username, password", handler)
        self.assertIn("display_name: values.display_name?.trim() || null", handler)
        self.assertIn('accepted.login_endpoint !== "/v1/auth/login"', handler)
        self.assertIn("state.auth = await api(accepted.login_endpoint", handler)
        self.assertIn("state.invitationAcceptanceError", handler)
        self.assertIn("consumed, expired, or revoked invitation cannot be replayed",
                      self.source)

    def test_settings_never_instruct_a_human_or_ai_to_run_auth_commands(self):
        settings = self.script[
            self.script.index("function renderAuthenticatedSettings"):
            self.script.index("async function openTaskPlan")]
        for forbidden in (
                "terminal_setup", "setupCards", "copy-setup",
                "attacca setup", "attacca server set", "actor-bound token",
                "paste an already", "Run <code>"):
            self.assertNotIn(forbidden, settings)
        self.assertIn("built-in connection settings", settings)
        self.assertIn("never tells a human or AI to paste shell commands", settings)


if __name__ == "__main__":
    unittest.main()
