"""Adversarial browser tests for per-client API keys and owner activation."""

import json
import re
import subprocess
import unittest
from pathlib import Path


PANEL = Path(__file__).resolve().parents[1] / "web" / "admin.html"


class ClientCredentialsPanelTestCase(unittest.TestCase):
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

    def run_node(self, source):
        completed = subprocess.run(
            ["node", "-e", source], text=True, capture_output=True,
            timeout=10, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout.strip()

    def test_client_fragment_hints_are_non_secret_strict_and_cross_view_safe(self):
        helper = self.marked("CLIENT_AUTHORIZATION_HINTS")
        program = helper + r"""
function parse(hash) {
  global.location = {hash};
  return clientAuthorizationHintsFromLocation();
}
process.stdout.write(JSON.stringify({
  valid: parse("#settings&pairing_code=AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-JJJJ-KKKK-LLLL-MMMM-NNNN"),
  legacy: parse("#settings&pairing_code=ABCD-2345"),
  badId: parse("#settings&pairing_code=%3Cscript%3E"),
  tooLong: parse("#settings&pairing_code=" + "c".repeat(129)),
  other: parse("#room&pairing_code=pair_abc"),
  secretLike: parse("#settings&pairing_code=AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-JJJJ-KKKK-LLLL-MMMM-NNNN&pairing_secret=atpair_leak")
}));
"""
        result = json.loads(self.run_node(program))
        canonical = ("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-JJJJ-"
                     "KKKK-LLLL-MMMM-NNNN")
        self.assertEqual(result["valid"], {"pairingCode": canonical})
        self.assertEqual(result["legacy"], {"pairingCode": "ABCD-2345"})
        self.assertEqual(result["badId"]["pairingCode"], "")
        self.assertEqual(result["tooLong"]["pairingCode"], "")
        self.assertEqual(result["other"], {"pairingCode": ""})
        self.assertEqual(result["secretLike"], {"pairingCode": canonical})

    def test_access_normalization_fails_closed_without_client_keys_array(self):
        helpers = self.marked("EMPTY_CREDENTIAL_ACCESS") + self.marked(
            "CREDENTIAL_ACCESS_HELPERS")
        program = "const state = {auth: {authentication_required: false}};\n" + helpers + r"""
const results = {
  empty: normalizeCredentialAccess(null),
  wrong: normalizeCredentialAccess({client_keys: {key: "not-array"}}),
  valid: normalizeCredentialAccess({client_keys: [{token_id: "key_1"}]})
};
process.stdout.write(JSON.stringify(results));
"""
        result = json.loads(self.run_node(program))
        self.assertIs(result["empty"]["supported"], False)
        self.assertIs(result["empty"]["capabilities"]["client_keys"], False)
        self.assertEqual(result["empty"]["client_keys"], [])
        self.assertIs(result["wrong"]["supported"], False)
        self.assertIs(result["valid"]["supported"], True)
        self.assertEqual(result["valid"]["client_keys"][0]["token_id"],
                         "key_1")

    def test_owner_toggle_has_no_migration_or_qa_gate(self):
        helpers = self.marked("EMPTY_CREDENTIAL_ACCESS") + self.marked(
            "CREDENTIAL_ACCESS_HELPERS")
        program = "const state = {auth: {authentication_required: false}};\n" + helpers + r"""
const access = normalizeCredentialAccess({client_keys: []});
process.stdout.write(JSON.stringify({
  owner: activationEligibility(access, {is_owner: true}),
  admin: activationEligibility(access, {is_owner: false, is_admin: true})
}));
"""
        result = json.loads(self.run_node(program))
        self.assertIs(result["owner"]["allowed"], True)
        self.assertIs(result["owner"]["enabled"], False)
        self.assertIs(result["admin"]["allowed"], False)
        self.assertIn("server owner", result["admin"]["reasons"][0])

        actions_start = self.script.index(
            'if (action === "revoke-client-key")')
        actions_end = self.script.index(
            'if (action === "select-project")', actions_start)
        actions = self.script[actions_start:actions_end]
        self.assertIn('body: { enabled, confirmed: true }', actions)
        self.assertNotIn("readiness", actions.lower())
        self.assertNotIn("qa", actions.lower())
        self.assertNotIn("armed", actions.lower())

    def test_effective_renderer_has_no_actor_key_binding_choice(self):
        settings = self.client_surface()
        self.assertIn("one human-owned key per authorized client", settings)
        self.assertIn("explicit human approval required", settings)
        self.assertIn("all workspaces available", settings)
        self.assertIn("AI actor, role, runtime, and Run by user", settings)
        self.assertNotIn("actor_bindings", settings)
        self.assertNotIn("allowed AI actor", settings)
        self.assertNotIn("migration", settings.lower())

    def test_pairing_handler_requires_explicit_review_without_plaintext(self):
        start = self.script.index(
            'if (action === "authorize-client-pairing"')
        end = self.script.index('if (action === "toggle-authentication")', start)
        handler = self.script[start:end]
        self.assertIn("Review its installation ID and workspace scope", handler)
        self.assertIn('/v1/auth/client-pairings/${encodeURIComponent', handler)
        self.assertIn('authorize ? "authorize" : "deny"', handler)
        bootstrap = self.script[
            self.script.index("async function bootstrap()"):self.script.index(
                "async function loadProjects()")]
        self.assertNotIn("/authorize", bootstrap)
        self.assertNotIn("/deny", bootstrap)
        settings = self.client_surface()
        self.assertIn("browser never displays or asks you to copy", settings)
        self.assertNotIn("one-time-client-secret", settings)
        self.assertNotIn('data-form="create-client-key"', settings)

    def test_key_list_never_contains_plaintext_property(self):
        start = self.script.index("function renderClientKeyRow")
        end = self.script.index("function renderPendingClientPairing", start)
        renderer = self.script[start:end]
        for expression in (
                'h(key.label || "Attacca client")',
                'h(key.client_instance || "not recorded")',
                'h(key.token_prefix || "atkey_")',
                "h(key.token_id)", "credentialOwner(key, account)"):
            self.assertIn(expression, renderer)
        self.assertNotRegex(renderer, r"key\.token(?![_a-z])")
        self.assertNotIn("key.secret", renderer)

    def test_authentication_is_not_implicitly_enabled(self):
        bootstrap_start = self.script.index("async function bootstrap()")
        bootstrap_end = self.script.index(
            "async function loadProjects()", bootstrap_start)
        bootstrap = self.script[bootstrap_start:bootstrap_end]
        self.assertNotIn("/v1/auth/activation", bootstrap)
        submit_start = self.script.index('if (kind === "auth-bootstrap")')
        submit_end = self.script.index('if (kind === "auth-login")',
                                       submit_start)
        submit = self.script[submit_start:submit_end]
        self.assertNotIn("/v1/auth/activation", submit)
        self.assertIn("enforcement remains off", submit)


if __name__ == "__main__":
    unittest.main()
