"""Execute the console's local-first gates and onboarding against isolated mocks."""

import re
import subprocess
import unittest
from pathlib import Path


PANEL = Path(__file__).resolve().parents[1] / "web" / "admin.html"


class LocalFirstPanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = PANEL.read_text(encoding="utf-8")
        cls.script = re.search(
            r"^  <script>\n(.*)^  </script>$", cls.source,
            re.DOTALL | re.MULTILINE).group(1)
        cls.helpers = cls.between(
            "// TESTABLE_LOCAL_ACCESS_HELPERS:BEGIN",
            "// TESTABLE_LOCAL_ACCESS_HELPERS:END")

    @classmethod
    def between(cls, start, end):
        begin = cls.script.index(start)
        return cls.script[begin:cls.script.index(end, begin)]

    def node(self, program):
        result = subprocess.run(
            ["node", "-e", 'const assert = require("node:assert/strict");\n' + program],
            text=True, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_javascript_parses(self):
        result = subprocess.run(["node", "--check", "-"], input=self.script,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_local_access_requires_explicit_mode_not_merely_auth_off(self):
        self.node(self.helpers + """
          const local = {access_mode:'local', anonymous_access:true,
            authentication_required:false, setup_required:false};
          assert.equal(localConsoleAccess(local), true);
          assert.equal(consoleAccessAllowed(local), true);
          for (const rejected of [null, {}, {authentication_required:false},
              {...local, anonymous_access:false}, {...local, access_mode:'legacy'},
              {...local, access_mode:'protected'}, {...local, setup_required:true},
              {...local, authentication_required:true}]) {
            assert.equal(localConsoleAccess(rejected), false);
            assert.equal(consoleAccessAllowed(rejected), false);
          }
          assert.equal(consoleAccessAllowed({authenticated:true}), true);
          assert.equal(consoleAccessAllowed({authenticated:true, setup_required:true}), false);
        """)

    def test_network_setup_defaults_protected_and_requires_second_local_ack(self):
        self.node(self.helpers + """
          const auth = {setup_allowed:true, network_exposed:true};
          assert.equal(setupChoice(auth, ''), 'protected');
          assert.equal(setupChoice({login_recommended:true}, ''), 'protected');
          assert.equal(setupChoice({}, ''), 'local');
          assert.equal(setupChoice(auth, 'local'), 'local');
          assert.throws(() => setupRequest({mode:'local'}, auth), /Confirm/);
          assert.deepEqual(setupRequest({mode:'local', acknowledge_network_risk:'on'}, auth),
            {mode:'local', confirmed:true, acknowledge_network_risk:true});
          assert.throws(() => setupRequest({mode:'local'}, {setup_allowed:false}), /local computer/);
          assert.throws(() => setupRequest({mode:'invalid'}, auth), /Choose/);
        """)

    def test_local_setup_excludes_credentials_and_protected_validates_confirmation(self):
        self.node(self.helpers + """
          const auth = {setup_allowed:true, network_exposed:false};
          assert.deepEqual(setupRequest({mode:'local', username:'ignored', password:'ignored'}, auth),
            {mode:'local', confirmed:true, acknowledge_network_risk:false});
          assert.throws(() => setupRequest({mode:'protected', username:'person',
            password:'long-password', confirm_password:'different'}, auth), /match/);
          assert.throws(() => setupRequest({mode:'protected', username:'person',
            password:'short', confirm_password:'short'}, auth), /8 characters/);
          assert.deepEqual(setupRequest({mode:'protected', username:' person ',
            password:'long-password', confirm_password:'long-password'}, auth),
            {mode:'protected', confirmed:true, username:'person', password:'long-password'});
        """)

    def bootstrap_program(self):
        return self.helpers + self.between(
            "async function bootstrap()", "async function loadProjects()") + """
          let status, calls, rendered;
          let state;
          const emptyCredentialAccess = () => ({});
          const busy = () => {};
          const updateChrome = () => {};
          const renderServerSetup = () => { rendered='setup'; };
          const renderAuth = () => { rendered='auth'; };
          const renderClientInstallGuide = () => { rendered='clients'; };
          const startPoller = () => {};
          const storageSet = () => {};
          const loadPendingClientAuthorization = async () => {};
          const loadWorkspaceAgentDirectory = async () => {};
          const loadCredentialAccess = async () => { calls.push('keys'); return {}; };
          const loadProjectPage = async () => { rendered='console'; };
          const loadProjectData = async () => { rendered='console'; };
          async function api(path) {
            calls.push(path);
            if (path === '/v1/auth/status') return status;
            if (path === '/v1/projects?options=1') return {projects:[]};
            return {};
          }
          async function boot(auth, extra={}) {
            status=auth; calls=[]; rendered='';
            state={projects:[], projectId:'', prefs:{actor:'web.stale', owner:'stale'}, ...extra};
            await bootstrap();
          }
        """

    def test_local_upgrade_requires_explicit_settings_origin(self):
        self.node(self.helpers + """
          const values={mode:'protected',username:'owner',password:'long-password',
            confirm_password:'long-password'};
          const local={setup_allowed:true, access_mode:'local', anonymous_access:true};
          assert.equal(setupRequest(values,local,true).upgrade_local,true);
          assert.equal(setupRequest(values,local).upgrade_local,undefined);
          assert.equal(setupRequest(values,{setup_allowed:true, access_mode:'pending'},true).upgrade_local,undefined);
        """)

    def test_fresh_server_and_legacy_gate_before_data_requests(self):
        self.node(self.bootstrap_program() + """
          (async () => {
            await boot({setup_required:true, setup_allowed:true});
            assert.equal(rendered,'setup');
            assert.deepEqual(calls,['/v1/auth/status']);
            for (const status of [{bootstrap_required:true},
                {bootstrapped:true, authenticated:false, authentication_required:false},
                {authentication_required:true, authenticated:false}, {}]) {
              await boot(status);
              assert.equal(rendered,'auth');
              assert.deepEqual(calls,['/v1/auth/status']);
            }
          })().catch(error => { process.stderr.write(error.stack); process.exitCode=1; });
        """)

    def test_local_console_uses_local_operator_and_never_fetches_account_keys(self):
        self.node(self.bootstrap_program() + """
          (async () => {
            await boot({access_mode:'local', anonymous_access:true, authentication_required:false});
            assert.equal(rendered,'console');
            assert.equal(state.prefs.actor,'web.local');
            assert.equal(state.prefs.actorType,'human');
            assert.equal(state.prefs.owner,'');
            assert.equal(calls.includes('/v1/projects?options=1'),true);
            assert.equal(calls.includes('/v1/auth/tokens'),false);
            assert.equal(calls.includes('keys'),false);
          })().catch(error => { process.stderr.write(error.stack); process.exitCode=1; });
        """)

    def test_protected_account_bootstrap_remains_authenticated(self):
        self.node(self.bootstrap_program() + """
          (async () => {
            await boot({access_mode:'protected', authenticated:true,
              authentication_required:true, user:{username:'person'}});
            assert.equal(rendered,'console');
            assert.equal(state.prefs.actor,'web.person');
            assert.equal(state.prefs.owner,'person');
            assert.equal(calls.includes('/v1/auth/tokens'),true);
            assert.equal(calls.includes('keys'),true);
            await boot({access_mode:'local', anonymous_access:true}, {setupWizard:'clients'});
            assert.equal(rendered,'clients');
            assert.deepEqual(calls,['/v1/auth/status']);
          })().catch(error => { process.stderr.write(error.stack); process.exitCode=1; });
        """)

    def test_setup_render_is_accessible_and_remote_browser_cannot_submit(self):
        render = self.between("function renderServerSetup()", "function renderAuth()")
        self.node(self.helpers + render + """
          const state={auth:{setup_required:true, setup_allowed:true, network_exposed:true}, setupMode:''};
          const content={innerHTML:'', setAttribute(){}};
          const pageHead=()=>'';
          renderServerSetup();
          assert.match(content.innerHTML, /strongly recommended/);
          assert.match(content.innerHTML, /label for="setup-password"/);
          assert.match(content.innerHTML, /value="protected" selected/);
          state.setupMode='local'; renderServerSetup();
          assert.match(content.innerHTML, /name="acknowledge_network_risk" required/);
          assert.doesNotMatch(content.innerHTML, /name="password"/);
          state.auth.setup_allowed=false; renderServerSetup();
          assert.match(content.innerHTML, /SSH loopback tunnel/);
          assert.doesNotMatch(content.innerHTML, /<form/);
          state.auth={setup_required:true, setup_allowed:true,
            network_exposed:false, login_recommended:true};
          state.setupMode=''; renderServerSetup();
          assert.match(content.innerHTML, /Login protection was requested/);
          assert.match(content.innerHTML, /value="protected" selected/);
          assert.doesNotMatch(content.innerHTML, /listening beyond localhost/);
        """)

    def test_install_guide_escapes_commands_and_never_runs_installer(self):
        render = self.between("function installClientInstructions()", "function renderServerSetup()")
        self.node(self.helpers + render + r"""
          const state={auth:{access_mode:'local', anonymous_access:true}};
          const location={origin:'http://127.0.0.1:12345'};
          const h=text=>String(text).replace(/&/g,'&amp;').replace(/</g,'&lt;');
          const html=installClientInstructions();
          assert.match(html,/http:\/\/127.0.0.1:12345\/install.sh/);
          assert.match(html,/\$attacca:setup/);
          assert.match(html,/\/attacca:setup/);
          assert.match(html,/does not ask for a browser login/);
          assert.match(html,/registered workspace identities and role checks/);
          assert.match(html,/outside the Attacca source checkout/);
        """)
        self.assertNotIn("fetch(", render)
        self.assertNotIn("api(", render)

    def test_local_settings_hide_account_only_controls_but_keep_normal_operations(self):
        render = self.between("function renderAuthenticatedSettings()", "async function reloadTaskPlan(")
        self.node(self.helpers + render + """
          const state={auth:{access_mode:'local', anonymous_access:true, setup_allowed:true},
            projects:[], prefs:{refreshSeconds:15}, serverSettings:{}, health:{ok:true}};
          const h=value=>String(value ?? '');
          const pageHead=(a,b,c,actions)=>actions;
          const emptyCredentialAccess=()=>({client_keys:[]});
          const activationEligibility=()=>({enabled:false,allowed:false,reasons:[]});
          const listPage=()=>({offset:0});
          const responsePage=()=>({unfilteredTotal:0});
          const statusBadge=value=>String(value);
          const renderPendingClientAuthorization=()=>{throw Error('account-only renderer called');};
          const html=renderAuthenticatedSettings();
          assert.match(html,/Local mode · no sign-in required/);
          assert.match(html,/protect-local-server/);
          assert.match(html,/show-client-install/);
          assert.match(html,/data-form="save-runtime"/);
          assert.match(html,/data-action="download-export"/);
          assert.doesNotMatch(html,/Signed in as/);
          assert.doesNotMatch(html,/Client API keys/);
          assert.doesNotMatch(html,/auth-logout/);
          state.auth.setup_allowed=false;
          assert.doesNotMatch(renderAuthenticatedSettings(),/data-action="protect-local-server"/);
        """)

    def test_setup_submission_verifies_server_response_and_does_not_persist_secrets(self):
        submit = self.between('if (kind === "server-setup")', 'if (kind === "auth-bootstrap")')
        self.assertIn('api("/v1/setup", { method: "POST", body })', submit)
        self.assertIn("result.access_mode !== body.mode", submit)
        self.assertIn("result.authenticated !== true", submit)
        self.assertIn("form.reset();", submit)
        self.assertNotIn("storageSet", submit)
        self.assertNotIn("localStorage", submit)
        self.assertNotIn("location.href", submit)


if __name__ == "__main__":
    unittest.main()
