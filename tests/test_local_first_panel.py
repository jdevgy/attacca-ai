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

    def test_disable_login_warns_and_acknowledges_network_access_only_when_needed(self):
        self.node(self.helpers + """
          const exposed={network_exposed:true};
          assert.match(loginProtectionConfirmation(false,exposed), /WARNING.*beyond localhost/);
          assert.match(loginProtectionConfirmation(false,exposed), /Anyone who can reach/);
          assert.match(loginProtectionConfirmation(false,exposed), /accounts, passwords, client keys, and AI identities are preserved/);
          assert.match(loginProtectionConfirmation(false,exposed), /actual IP address/);
          assert.deepEqual(loginProtectionRequest(false,exposed),
            {enabled:false,confirmed:true,acknowledge_network_risk:true});
          assert.deepEqual(loginProtectionRequest(false,{}),{enabled:false,confirmed:true});
          assert.deepEqual(loginProtectionRequest(true,exposed),{enabled:true,confirmed:true});
          assert.match(loginProtectionConfirmation(true,exposed), /must sign in/);
        """)

    def test_legacy_console_gate_offers_explicit_disable_without_claiming_api_enforcement(self):
        credential_helpers = self.between("function activationEligibility(",
                                          "function credentialMemberships(")
        self.node(self.helpers + credential_helpers + """
          const state={auth:{access_mode:'legacy',bootstrapped:true,
            authentication_required:false,authentication_activated:false}};
          const access={capabilities:{activation:true}};
          const owner={is_owner:true};
          let eligibility=activationEligibility(access,owner);
          assert.equal(eligibility.enabled,true);
          assert.equal(eligibility.enforcementEnabled,false);
          assert.equal(eligibility.allowed,true);
          state.auth={...state.auth,access_mode:'local',anonymous_access:true};
          eligibility=activationEligibility(access,owner);
          assert.equal(eligibility.enabled,false);
          state.auth={...state.auth,access_mode:'protected',authentication_required:true};
          eligibility=activationEligibility(access,owner);
          assert.equal(eligibility.enabled,true);
          assert.equal(eligibility.enforcementEnabled,true);
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

    def test_disabled_login_does_not_gate_existing_accounts_unless_sign_in_chosen(self):
        self.node(self.bootstrap_program() + """
          (async () => {
            const auth={access_mode:'local',anonymous_access:true,
              authentication_required:false,bootstrapped:true,authenticated:false};
            await boot(auth);
            assert.equal(rendered,'console');
            assert.equal(calls.includes('keys'),false);
            await boot(auth,{setupWizard:'sign-in'});
            assert.equal(rendered,'auth');
            assert.deepEqual(calls,['/v1/auth/status']);
            await boot(auth,{setupWizard:''});
            assert.equal(rendered,'console');
          })().catch(error => { process.stderr.write(error.stack); process.exitCode=1; });
        """)

    def test_optional_sign_in_has_escape_but_protected_login_does_not(self):
        render = self.between("function renderAuth()", "async function bootstrap()")
        self.node(self.helpers + render + """
          const state={auth:{access_mode:'local',anonymous_access:true,bootstrapped:true}};
          const content={innerHTML:'',setAttribute(){}};
          const h=value=>String(value ?? '');
          const pageHead=(eyebrow,title,description)=>title+' '+description;
          const renderServerSetup=()=>{throw Error('must not bootstrap existing account');};
          renderAuth();
          assert.match(content.innerHTML,/Optional account sign-in/);
          assert.match(content.innerHTML,/existing server owner/);
          assert.match(content.innerHTML,/Continue without signing in/);
          assert.match(content.innerHTML,/data-form="auth-login"/);
          assert.doesNotMatch(content.innerHTML,/data-form="auth-bootstrap"/);
          state.auth={access_mode:'protected',authentication_required:true,bootstrapped:true};
          renderAuth();
          assert.doesNotMatch(content.innerHTML,/dismiss-optional-sign-in/);
          assert.match(content.innerHTML,/Sign in to Attacca/);
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
          state.auth.bootstrapped=true;
          const existing=renderAuthenticatedSettings();
          assert.match(existing,/data-action="show-optional-sign-in"/);
          assert.match(existing,/existing accounts and passwords are unchanged/);
          assert.doesNotMatch(existing,/data-action="protect-local-server"/);
        """)

    def test_toggle_runs_only_after_confirmation_with_explicit_network_ack(self):
        action = self.between('if (action === "toggle-authentication")',
                              'if (action === "select-project")')
        self.node(self.helpers + """
          const state={auth:{network_exposed:true,user:{is_owner:true}}};
          let allow=true,confirmed=false,requests=[],notifications=[];
          const activationEligibility=()=>({allowed:allow,reasons:[]});
          const emptyCredentialAccess=()=>({});
          const confirm=message=>{ assert.match(message,/read and change/); return confirmed; };
          const api=async(path,options)=>{
            requests.push([path,options]);
            return {access_mode:'local',anonymous_access:true,network_exposed:true};
          };
          const reloadCredentialAccess=async()=>{};
          const toast=text=>notifications.push(text);
          async function act() {
            const action='toggle-authentication';
            const button={dataset:{enabled:'false'}};
        """ + action + """
          }
          (async()=>{
            await act(); assert.equal(requests.length,0);
            confirmed=true; await act();
            assert.equal(requests[0][0],'/v1/auth/activation');
            assert.deepEqual(requests[0][1],{method:'POST',body:{
              enabled:false,confirmed:true,acknowledge_network_risk:true}});
            assert.equal(requests[1][0],'/v1/auth/status');
            assert.match(notifications[0],/sign-in is no longer required/);
            allow=false; await assert.rejects(act,/Only the server owner/);
            assert.equal(requests.length,2);
          })().catch(error=>{process.stderr.write(error.stack);process.exitCode=1;});
        """)

    def test_optional_sign_in_cancel_and_logout_return_to_anonymous_console(self):
        optional_actions = self.between('if (action === "show-optional-sign-in")',
                                       'if (action === "list-previous")')
        logout = self.between('if (action === "auth-logout")',
                              'if (action === "revoke-auth-token")')
        self.node(self.bootstrap_program() + """
          const render=()=>{rendered='auth';};
          const toast=()=>{};
          async function act(action) {
        """ + optional_actions + logout + """
          }
          (async()=>{
            const auth={access_mode:'local',anonymous_access:true,bootstrapped:true};
            await boot(auth);
            await act('show-optional-sign-in');
            assert.equal(state.setupWizard,'sign-in');
            assert.equal(rendered,'auth');
            await act('dismiss-optional-sign-in');
            assert.equal(state.setupWizard,'');
            assert.equal(rendered,'console');
            state.auth={...auth,authenticated:true,user:{username:'owner'}};
            await act('auth-logout');
            assert.equal(rendered,'console');
            assert.equal(state.prefs.actor,'web.local');
            assert.equal(calls.includes('/v1/auth/logout'),true);
          })().catch(error=>{process.stderr.write(error.stack);process.exitCode=1;});
        """)

    def test_settings_offer_disable_for_legacy_and_enable_after_explicit_off(self):
        render = self.between("function renderAuthenticatedSettings()", "async function reloadTaskPlan(")
        eligibility = self.between("function activationEligibility(", "function credentialMemberships(")
        self.node(self.helpers + eligibility + render + """
          const state={auth:{access_mode:'legacy',bootstrapped:true,authenticated:true,
            user:{username:'owner',is_owner:true}},projects:[],prefs:{},errors:{},
            credentialAccess:{capabilities:{activation:true},client_keys:[],supported:true}};
          const h=value=>String(value ?? '');
          const pageHead=()=>'';
          const listPage=()=>({offset:0});
          const responsePage=()=>({unfilteredTotal:0});
          const statusBadge=value=>String(value);
          const renderPendingClientAuthorization=()=>'';
          const sortControl=()=>'';
          const pageToolbar=()=>'';
          let html=renderAuthenticatedSettings();
          assert.match(html,/Console sign-in is required; API authentication enforcement is not enabled/);
          assert.match(html,/data-enabled="false">Disable login/);
          state.auth={...state.auth,access_mode:'local',anonymous_access:true};
          html=renderAuthenticatedSettings();
          assert.match(html,/console and project API are available without signing in/);
          assert.match(html,/data-enabled="true">Enable login protection/);
          state.auth={...state.auth,access_mode:'protected',authentication_required:true};
          html=renderAuthenticatedSettings();
          assert.match(html,/Browser sessions or a valid client-install API key are required/);
          assert.match(html,/data-enabled="false">Disable login/);
        """)

    def test_expired_auth_recovery_keeps_explicit_local_access_open(self):
        recovery = self.between("async function recoverExpiredAuthentication()",
                                "async function downloadProjectExport(")
        self.node(self.helpers + recovery + """
          const state={prefs:{actor:'web.stale',owner:'stale'}};
          let status,rendered;
          const fetch=async()=>({ok:true,json:async()=>status});
          const updateChrome=()=>{};
          const render=()=>{rendered='console';};
          const renderAuth=()=>{rendered='auth';};
          (async()=>{
            status={access_mode:'local',anonymous_access:true,bootstrapped:true};
            await recoverExpiredAuthentication();
            assert.equal(rendered,'console');
            assert.equal(state.prefs.actor,'web.local');
            assert.equal(state.prefs.owner,'');
            assert.equal(state.authRecovery,null);
            status={access_mode:'protected',authentication_required:true};
            await recoverExpiredAuthentication();
            assert.equal(rendered,'auth');
          })().catch(error=>{process.stderr.write(error.stack);process.exitCode=1;});
        """)

    def test_optional_owner_login_never_enables_protection_implicitly(self):
        login = self.between('if (kind === "auth-login")', 'if (kind === "auth-register")')
        self.node("""
          const state={setupWizard:'sign-in',authMode:'sign-in'};
          const kind='auth-login';
          const values={username:' owner ',password:'example-password'};
          let reset=false,booted=false,calls=[];
          const form={reset:()=>{reset=true;}};
          const api=async(path,options)=>{
            calls.push([path,options]);
            return {authenticated:true,user:{username:'owner'}};
          };
          const bootstrap=async()=>{booted=true;assert.equal(state.setupWizard,'');};
          const toast=()=>{};
          (async()=>{
        """ + login + """
            assert.equal(reset,true);
            assert.equal(booted,true);
            assert.equal(state.auth.user.username,'owner');
            assert.deepEqual(calls,[['/v1/auth/login',{method:'POST',
              body:{username:'owner',password:'example-password'}}]]);
          })().catch(error=>{process.stderr.write(error.stack);process.exitCode=1;});
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
