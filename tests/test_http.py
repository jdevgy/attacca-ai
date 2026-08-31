"""Hosted-server tests: REST API + MCP over streamable HTTP.

Starts one real `attacca.py serve` subprocess per test class and drives it
with stdlib urllib — the same wire surface Claude Code / Codex / curl use.
"""
import importlib.util
import json
import os
import re
import select
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

# Isolate tests from any machine identity (~/.attacca/identity.json)
os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = str(ROOT / "attacca.py")

spec = importlib.util.spec_from_file_location("attacca", ROOT / "attacca.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class ServerFixture:
    def __init__(self, db):
        env = dict(os.environ)
        for k in ("ATTACCA_ACTOR", "ATTACCA_PROJECT"):
            env.pop(k, None)
        env["ATTACCA_DB"] = str(db)
        self.proc = subprocess.Popen(
            [sys.executable, SCRIPT, "serve", "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        line = self.proc.stdout.readline()
        match = re.search(r"http://127\.0\.0\.1:(\d+)", line)
        assert match, "server did not report its port: %r" % line
        self.base = "http://127.0.0.1:%s" % match.group(1)

    def request(self, method, path, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read()
                parsed = json.loads(raw) if raw else None
                return resp.status, parsed, dict(resp.headers)
        except urllib.error.HTTPError as err:
            raw = err.read()
            parsed = json.loads(raw) if raw else None
            return err.code, parsed, dict(err.headers)

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.proc.stdout.close()
        self.proc.stderr.close()


class HttpTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "http.db"
        conn = c.connect(cls.db)
        proj = Path(cls.tmp.name) / "repo"
        proj.mkdir()
        c.project_init(conn, "setup", "human", path=str(proj),
                       project_id="hub", name="Hub")
        conn.close()
        cls.server = ServerFixture(cls.db)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tmp.cleanup()

    def rest(self, method, path, body=None, actor=None, actor_type=None):
        headers = {"X-Attacca-Actor": actor} if actor else {}
        if actor_type:
            headers["X-Attacca-Actor-Type"] = actor_type
        return self.server.request(method, path, body, headers)

    # -- REST ---------------------------------------------------------------

    def test_healthz(self):
        status, body, _ = self.rest("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["version"], c.VERSION)
        self.assertEqual(body["managed_instructions"]["version"],
                         c.MANAGED_BLOCK_VERSION)
        self.assertEqual(body["managed_instructions"]["sha256"],
                         c.managed_instruction_metadata(
                             c._MANAGED_TEMPLATE_PROJECT)["law_sha256"])

    def test_web_panel_and_runtime_settings(self):
        import urllib.request as rq
        with rq.urlopen(self.server.base + "/app", timeout=10) as resp:
            panel = resp.read().decode()
            self.assertEqual(resp.headers["Cache-Control"],
                             "no-store, max-age=0")
            self.assertEqual(resp.headers["Pragma"], "no-cache")
        self.assertIn("Attacca", panel)
        self.assertIn("Settings", panel)
        self.assertIn("Inbox", panel)
        self.assertIn("Search project memory", panel)
        self.assertIn("AI Network", panel)
        self.assertIn("Source workspace", panel)
        self.assertIn("Local workspace room", panel)
        self.assertIn("Inter-project", panel)
        self.assertIn("↔", panel)
        self.assertIn("swap-room-workspace", panel)
        self.assertIn(
            "Every participation-visible non-self message appears here",
            panel)
        self.assertIn(
            "mentions and replies only assign attention", panel)
        self.assertIn("Mark group room read", panel)
        self.assertNotIn("This inbox belongs only to", panel)
        self.assertNotIn("other actors have separate inboxes", panel)
        self.assertIn("message.origin_project === activeBridge.with", panel)
        self.assertIn("includes(activeBridge.with)", panel)
        self.assertNotIn("All room activity", panel)
        self.assertNotIn("return bridges.length === 1", panel)
        self.assertIn("function actorDisplay(actorId)", panel)
        self.assertIn("function projectName(projectId)", panel)
        self.assertIn("const API_TIMEOUT_MS = 15000", panel)
        self.assertIn("new AbortController()", panel)
        self.assertNotIn("nameFor(", panel)
        self.assertIn('[workspace, role, runtime].map(identityPart).join(" · ")',
                      panel)
        self.assertIn("Workspace · Role · Runtime", panel)
        self.assertIn(
            "It authorizes clients but never renames or replaces an AI "
            "identity", panel)
        self.assertIn("immutable account name", panel)
        self.assertIn("Run by user", panel)
        self.assertNotIn('placeholder="analytics-admin.director.web"', panel)
        self.assertIn("Signed in: @${account.username}", panel)
        self.assertNotIn('id="auth-display-name"', panel)
        self.assertNotIn('id="invite-accept-display-name"', panel)
        self.assertIn('actor: `web.${state.auth.user.username}`', panel)
        self.assertIn("Browser identity headers cannot override", panel)
        self.assertNotIn('`${state.prefs.owner}.${state.prefs.actor}`', panel)
        self.assertIn("Attribution is recorded literally", panel)
        self.assertIn("they are not evidence that the VS Code AI", panel)
        self.assertIn("target_project", panel)
        self.assertIn("expected_context_version", panel)
        self.assertIn("AI update checks", panel)
        self.assertIn("default relationship: master", panel)
        self.assertIn("function storageGet(key, fallback", panel)
        self.assertIn("function storageSet(key, value)", panel)
        self.assertIn('projectId: storageGet("attacca.admin.project")', panel)
        self.assertIn("bootstrap().catch(error =>", panel)
        self.assertIn("Attacca could not finish loading", panel)
        self.assertNotIn(
            'projectId: localStorage.getItem("attacca.admin.project")', panel)
        status, settings, _ = self.rest("GET", "/v1/settings")
        self.assertEqual(status, 200)
        self.assertFalse(settings["authentication"])
        # Settings exposes the integrated per-install client-key contract, not
        # shell or chat commands that a human is expected to run. The active AI
        # invokes its native setup surface and the terminal/browser flow guides
        # the human from there.
        self.assertNotIn("setup", settings)
        self.assertNotIn("terminal_setup", settings)
        self.assertEqual(
            settings["client_authorization"]["api_keys_endpoint"],
            "/v1/auth/client-keys")
        self.assertEqual(
            settings["client_authorization"]["credential_model"],
            "browser-session-or-client-api-key")
        self.assertEqual(settings["update_interval_seconds"], 60)
        self.assertEqual(
            settings["installer"],
            "curl -fsSL %s/install.sh | sh" % self.server.base)
        try:
            status, changed, _ = self.rest(
                "PUT", "/v1/settings",
                {"default_project": "hub", "verbose": True,
                 "update_interval_seconds": 600})
            self.assertEqual(status, 200)
            self.assertEqual(changed["default_project"], "hub")
            self.assertTrue(changed["verbose"])
            self.assertEqual(changed["update_interval_seconds"], 600)
            restarted = c.AttaccaServer(("127.0.0.1", 0), self.db)
            try:
                self.assertEqual(restarted.default_project, "hub")
                self.assertTrue(restarted.verbose)
                self.assertEqual(restarted.update_interval_seconds, 600)
            finally:
                restarted.server_close()
            status, invalid, _ = self.rest(
                "PUT", "/v1/settings", {"update_interval_seconds": 5})
            self.assertEqual(status, 400)
            self.assertIn("60..3600", invalid["error"])
        finally:
            self.rest("PUT", "/v1/settings",
                      {"default_project": None, "verbose": False,
                       "update_interval_seconds": 60})

    def test_web_panel_attribution_source_contract(self):
        panel = (Path(__file__).resolve().parents[1] /
                 "web" / "admin.html").read_text()
        human_start = panel.index('if (type === "human")')
        human_end = panel.index("const runBy =", human_start)
        human_branch = panel[human_start:human_end]

        self.assertIn(
            'const type = String(projection?.actor_type || actorType || '
            '"agent").toLowerCase();', panel)
        self.assertIn(
            'const actor = projection?.actor_id || actorId || "unknown";',
            panel)
        self.assertIn('String(actorId || actor).split(".").pop()',
                      human_branch)
        self.assertIn('return `Human user: ${identityPart(raw)}`;',
                      human_branch)
        self.assertNotIn("Run by user", human_branch)
        self.assertIn(
            'const runBy = projection?.run_by_user ?? owner ?? '
            '"not recorded";', panel)
        self.assertIn(
            'return `AI: ${actorDisplay(actor)} · Run by user: ${runBy}`;',
            panel)

        self.assertIn("const claimant = attribution.current_claimant ||", panel)
        self.assertIn("const claimantText = taskClaimantText(task);", panel)
        self.assertNotIn("Claimant AI", panel)
        # D-18 renders each group message in the room feed and relationship
        # evidence; the former separate per-actor inbox renderer was removed.
        self.assertGreaterEqual(panel.count(
            "attributionText(message.actor, message.actor_type, "
            "message.owner, message.attribution)"), 2)
        self.assertIn(
            "attributionText(operational, event.actor_type, event.owner, "
            "event.attribution)", panel)
        self.assertNotIn("${ownerChip(message.owner)}", panel)

    def test_plugin_distribution_endpoints(self):
        import urllib.request as rq
        import zipfile as zf
        import io as iolib
        with rq.urlopen(self.server.base + "/", timeout=10) as resp:
            landing = resp.read().decode()
        self.assertIn(
            "curl -fsSL %s/install.sh | sh" % self.server.base, landing)
        self.assertIn("$attacca:setup", landing)
        self.assertIn("/attacca:setup", landing)
        self.assertIn("attacca setup --interactive", landing)
        self.assertIn("no MCP reconnect", landing)
        with rq.urlopen(self.server.base + "/install.sh", timeout=10) as resp:
            script = resp.read().decode()
        syntax = subprocess.run(["sh", "-n"], input=script, text=True,
                                capture_output=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertIn('BASE="%s"' % self.server.base, script)
        self.assertIn("#   curl -fsSL %s/install.sh | sh" % self.server.base,
                      script)
        self.assertIn("plugin.zip", script)
        self.assertIn('EXPECTED_VERSION="%s"' % c.VERSION, script)
        self.assertIn(".attacca-stage-", script)
        self.assertIn(".attacca-backup-", script)
        self.assertIn("plugin ZIP is incomplete", script)
        self.assertNotIn("claude plugin update", script)
        self.assertIn("for ATTACCA_CLAUDE_SCOPE in user project local", script)
        self.assertIn("claude plugin marketplace remove agentg", script)
        self.assertIn("plugin uninstall continuity@agentg", script)
        self.assertIn("uninstall_claude_scoped_attacca_plugins", script)
        self.assertIn("directory is missing", script)
        self.assertLess(
            script.index("uninstall_claude_scoped_attacca_plugins"),
            script.index("for ATTACCA_CLAUDE_SCOPE in user project local"))
        self.assertLess(
            script.index("for ATTACCA_CLAUDE_SCOPE in user project local"),
            script.index("claude plugin install attacca@agentg --scope user"))
        self.assertIn("Attacca checks automatically", script)
        self.assertNotIn("then run /attacca:setup", script)
        self.assertIn('codex plugin marketplace add "$DEST"', script)
        self.assertIn("codex plugin add attacca@attacca-local", script)
        self.assertIn("ATTACCA_CODEX_OLD_CACHE_VERSIONS", script)
        self.assertIn("preserved live hook compatibility", script)
        self.assertIn("open /hooks", script)
        self.assertIn("$attacca:setup", script)
        self.assertIn("/app", script)
        self.assertIn("setup --tools-only", script)
        self.assertIn("install_kimi_native_plugin", script)
        self.assertIn("--skip-tools kimi", script)
        self.assertIn("Attacca will stay inactive until you enable it", script)
        self.assertIn("__ATTACCA_KIMI_ENABLED", script)
        self.assertIn("Kimi native manual install/refresh alternative", script)
        self.assertLess(script.index("setup --tools-only"),
                        script.index('codex plugin marketplace add "$DEST"'))
        self.assertIn("codex mcp get attacca", script)
        with rq.urlopen(self.server.base + "/plugin.zip", timeout=10) as resp:
            blob = resp.read()
        archive = zf.ZipFile(iolib.BytesIO(blob))
        names = set(archive.namelist())
        for required in ("attacca.py", ".claude-plugin/plugin.json",
                         ".claude-plugin/marketplace.json",
                         ".codex-plugin/plugin.json", ".mcp.json",
                         ".agents/plugins/marketplace.json",
                         "skills/setup/SKILL.md",
                         "skills/msg/SKILL.md", "skills/update/SKILL.md",
                         "kimi-skills/session/SKILL.md",
                         "hooks/hooks.json", "hooks/session_start.py",
                         "web/admin.html",
                         "plugin-mcp.json", "kimi.plugin.json",
                         "commands/brief.md",
                         "kimi-commands/setup.md",
                         "kimi-commands/msg.md", "kimi-commands/update.md"):
            self.assertIn(required, names)
        claude_commands = {
            Path(name).stem for name in names
            if name.startswith("commands/") and name.endswith(".md")}
        claude_skills = {
            Path(name).parent.name for name in names
            if name.startswith("skills/") and name.endswith("/SKILL.md")}
        self.assertFalse(claude_commands.intersection(claude_skills))
        self.assertEqual(claude_commands | claude_skills,
                         {"brief", "inbox", "msg", "room", "setup",
                          "status", "tasks", "update"})
        self.assertEqual(
            sorted(name for name in names
                   if name.startswith("skills/") and "/setup/" in name),
            ["skills/setup/SKILL.md"])
        self.assertFalse(any("attacca-setup" in name for name in names))
        command_setup = archive.read("kimi-commands/setup.md").decode()
        codex_setup = archive.read("skills/setup/SKILL.md").decode()
        for setup_text in (command_setup, codex_setup):
            self.assertIn("list_projects", setup_text)
            self.assertIn("CURRENT_AI_ACTOR", setup_text)
            self.assertIn("Director + Lead Director", setup_text)
            self.assertIn("MASTER", setup_text)
            self.assertIn("CURRENT AI CONVERSATION", setup_text)
            self.assertIn("task_list", setup_text)
            self.assertIn("task_create", setup_text)
            self.assertIn("Never silently", setup_text)
        self.assertIn("ATTACCA_MANAGED_INBOX_LOOP_V1:", codex_setup)
        claude_inbox = archive.read("commands/inbox.md").decode()
        self.assertIn("ATTACCA_MANAGED_INBOX_LOOP_V1:", claude_inbox)
        self.assertIn("ATTACCA_CHANGED=false", claude_inbox)
        packaged_hook = archive.read("hooks/session_start.py").decode()
        self.assertIn("ATTACCA_MANAGED_INBOX_LOOP_V1:", packaged_hook)
        self.assertIn("CronCreate", packaged_hook)
        hook_manifest = json.loads(archive.read("hooks/hooks.json"))
        self.assertEqual(set(hook_manifest["hooks"]),
                         {"SessionStart", "UserPromptSubmit", "Stop"})
        # the downloaded plugin is pre-wired to the server it came from
        cfg = json.loads(archive.read("plugin-mcp.json"))
        self.assertEqual(cfg["mcpServers"]["attacca"]["env"]["ATTACCA_URL"],
                         self.server.base)
        kimi_manifest = json.loads(archive.read("kimi.plugin.json"))
        self.assertEqual(kimi_manifest["commands"], "./kimi-commands/")
        kimi_commands = {
            Path(name).stem for name in names
            if name.startswith("kimi-commands/") and name.endswith(".md")}
        self.assertEqual(len([name for name in kimi_commands
                              if name == "setup"]), 1)
        self.assertEqual(kimi_commands,
                         {"brief", "inbox", "msg", "room", "setup",
                          "status", "tasks", "update"})
        self.assertEqual(kimi_manifest["skills"], "./kimi-skills/")
        self.assertEqual(kimi_manifest["sessionStart"]["skill"],
                         "attacca-session")
        self.assertEqual(
            [hook["event"] for hook in kimi_manifest["hooks"]],
            ["UserPromptSubmit", "Stop"])
        self.assertFalse({"SessionStart", "SessionHeartbeat"}.intersection(
            hook["event"] for hook in kimi_manifest["hooks"]))
        self.assertTrue(all(
            hook["command"] == "python3 ./hooks/session_start.py"
            for hook in kimi_manifest["hooks"]))
        self.assertEqual(
            kimi_manifest["mcpServers"]["attacca"]["env"]["ATTACCA_URL"],
            self.server.base)
        self.assertEqual(
            kimi_manifest["mcpServers"]["attacca"]["env"]["ATTACCA_ACTOR"],
            "kimi")
        kimi_session = archive.read("kimi-skills/session/SKILL.md").decode()
        for required in ("name: attacca-session", "list_projects",
                         "get_handoff", "check_inbox", "room_read",
                         "task_list", "attacca_status", "agent_list",
                         "/attacca:setup", "Director + Lead Director",
                         "MASTER-DIRECTIVE", "stale_context_warning",
                         "task_report"):
            self.assertIn(required, kimi_session)
        manifest = json.loads(archive.read(".claude-plugin/plugin.json"))
        self.assertEqual(manifest["version"], c.VERSION)
        claude_marketplace = json.loads(
            archive.read(".claude-plugin/marketplace.json"))
        self.assertTrue(claude_marketplace["description"])
        codex_manifest = json.loads(
            archive.read(".codex-plugin/plugin.json"))
        self.assertTrue(codex_manifest["version"].startswith(
            c.VERSION + "+codex."))
        self.assertEqual(codex_manifest["mcpServers"], "./.mcp.json")
        codex_mcp = json.loads(archive.read(".mcp.json"))
        self.assertEqual(
            codex_mcp["mcpServers"]["attacca"]["env"]["ATTACCA_URL"],
            self.server.base)
        codex_marketplace = json.loads(
            archive.read(".agents/plugins/marketplace.json"))
        self.assertEqual(codex_marketplace["name"], "attacca-local")
        self.assertEqual(
            codex_marketplace["plugins"][0]["source"]["path"], "./")
        self.assertNotIn("skills/attacca-setup/SKILL.md", names)
        self.assertNotIn("codex/skills/setup/SKILL.md", names)
        claude_status = archive.read("commands/status.md").decode()
        for tool_name in ("attacca_status", "get_handoff", "task_list",
                          "room_read"):
            self.assertIn(tool_name, claude_status)
        self.assertNotIn("allowed-tools: Bash", claude_status)
        self.assertNotIn("attacca.py --json status", claude_status)
        self.assertNotIn("server auto-registers", claude_status)
        packaged_readme = archive.read("README.md").decode()
        self.assertIn(
            "curl -fsSL http://127.0.0.1:8722/install.sh | sh",
            packaged_readme)
        self.assertIn("Codex exposes the three packaged skills",
                      packaged_readme)
        for skill_name in ("$attacca:setup", "$attacca:msg",
                           "$attacca:update"):
            self.assertIn(skill_name, packaged_readme)
        self.assertNotIn("Codex uses the `$attacca:*` spelling",
                         packaged_readme)
        codex_skill = archive.read("skills/setup/SKILL.md").decode()
        self.assertIn("setup --discover", codex_skill)
        self.assertIn("numbered list", codex_skill)
        self.assertIn("codex mcp get attacca --json",
                      " ".join(codex_skill.split()))
        self.assertIn("transport.args", codex_skill)
        codex_python = [line.strip() for line in codex_skill.splitlines()
                        if line.strip().startswith("python3 ")]
        self.assertGreaterEqual(len(codex_python), 3)
        self.assertTrue(all(line.startswith(
            'python3 "ATTACCA_RUNTIME"') for line in codex_python))
        self.assertNotIn("native choice picker", codex_skill)
        hooks = json.loads(archive.read("hooks/hooks.json"))
        self.assertIn("SessionStart", hooks["hooks"])
        hook_command = hooks["hooks"]["SessionStart"][0]["hooks"][0]["command"]
        self.assertEqual(
            hook_command,
            'python3 "$HOME/.attacca/plugin/attacca/hooks/session_start.py"')
        setup_command = archive.read("kimi-commands/setup.md").decode()
        self.assertIn("setup --discover", setup_command)
        self.assertNotIn("setup --no-server", setup_command)
        runtime_fallback = (
            "${CLAUDE_PLUGIN_ROOT:-${KIMI_PLUGIN_ROOT:-"
            "${KIMI_CODE_HOME:-$HOME/.kimi-code}/plugins/managed/attacca}}")
        self.assertGreaterEqual(setup_command.count(runtime_fallback), 3)
        self.assertGreaterEqual(
            setup_command.count(
                'test -f "$ATTACCA_PLUGIN_ROOT/attacca.py"'), 3)
        kimi_python = [line.strip() for line in setup_command.splitlines()
                       if line.strip().startswith("python3 ")]
        self.assertGreaterEqual(len(kimi_python), 3)
        self.assertTrue(all(line.startswith(
            'python3 "$ATTACCA_PLUGIN_ROOT/attacca.py"')
            for line in kimi_python))
        self.assertRegex(
            setup_command,
            r"stop\s+and report the missing plugin runtime")

        # Validate in same-filesystem staging before replacing a working
        # plugin. A malformed download leaves the old bundle untouched.
        heredoc_start = script.index("<<'PYEOF'", script.index(
            'python3 - "$TMP/plugin.zip"')) + len("<<'PYEOF'\n")
        installer_python = script[heredoc_start:script.index(
            "\nPYEOF", heredoc_start)]

        def rewrite_zip_member(source_blob, member, transform):
            output = iolib.BytesIO()
            with zf.ZipFile(iolib.BytesIO(source_blob)) as source_archive:
                with zf.ZipFile(output, "w",
                                zf.ZIP_DEFLATED) as output_archive:
                    for info in source_archive.infolist():
                        payload = source_archive.read(info.filename)
                        if info.filename == member:
                            payload = transform(payload)
                        output_archive.writestr(info, payload)
            return output.getvalue()

        def manifest_version(payload, version):
            manifest_data = json.loads(payload)
            manifest_data["version"] = version
            return (json.dumps(manifest_data, indent=2) + "\n").encode()

        def runtime_version(payload):
            old = ('VERSION = "%s"' % c.VERSION).encode()
            self.assertIn(old, payload)
            return payload.replace(old, b'VERSION = "9.9.9"', 1)

        with tempfile.TemporaryDirectory() as install_tmp:
            install_root = Path(install_tmp)
            dest = install_root / "attacca"
            dest.mkdir()
            marker = dest / "working-version"
            marker.write_text("keep me")
            broken = install_root / "broken.zip"
            with zf.ZipFile(broken, "w", zf.ZIP_DEFLATED) as archive_out:
                archive_out.writestr("attacca.py", 'VERSION = "%s"\n' %
                                     c.VERSION)
            rejected = subprocess.run(
                [sys.executable, "-", str(broken), str(dest), c.VERSION],
                input=installer_python, text=True, capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(marker.read_text(), "keep me")

            mismatch_cases = (
                ("runtime", "attacca.py", runtime_version),
                ("claude", ".claude-plugin/plugin.json",
                 lambda payload: manifest_version(payload, "9.9.9")),
                ("kimi", "kimi.plugin.json",
                 lambda payload: manifest_version(payload, "9.9.9")),
                ("codex-base", ".codex-plugin/plugin.json",
                 lambda payload: manifest_version(
                     payload, "9.9.9+codex.release")),
                ("codex-no-cachebuster", ".codex-plugin/plugin.json",
                 lambda payload: manifest_version(payload, c.VERSION)),
                ("codex-wrong-build", ".codex-plugin/plugin.json",
                 lambda payload: manifest_version(
                     payload, c.VERSION + "+other.release")),
                ("codex-double-build", ".codex-plugin/plugin.json",
                 lambda payload: manifest_version(
                     payload, c.VERSION + "+codex.old+codex.new")),
            )
            for label, member, transform in mismatch_cases:
                case_root = install_root / label
                case_dest = case_root / "attacca"
                case_dest.mkdir(parents=True)
                case_marker = case_dest / "working-version"
                case_marker.write_text("keep %s" % label)
                candidate = case_root / "candidate.zip"
                candidate.write_bytes(
                    rewrite_zip_member(blob, member, transform))
                rejected = subprocess.run(
                    [sys.executable, "-", str(candidate), str(case_dest),
                     c.VERSION],
                    input=installer_python, text=True, capture_output=True)
                self.assertNotEqual(rejected.returncode, 0, label)
                self.assertEqual(case_marker.read_text(), "keep %s" % label)
                self.assertIn("VERSION mismatch", rejected.stderr, label)

            good = install_root / "good.zip"
            good.write_bytes(blob)
            installed = subprocess.run(
                [sys.executable, "-", str(good), str(dest), c.VERSION],
                input=installer_python, text=True, capture_output=True)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            self.assertFalse(marker.exists())
            self.assertTrue((dest / "hooks/session_start.py").is_file())

    def test_plugin_bundle_requires_every_declared_file_and_git_cache_is_content_addressed(self):
        with mock.patch.object(
                c, "PLUGIN_FILES", c.PLUGIN_FILES + ["missing-required.file"]):
            with self.assertRaisesRegex(FileNotFoundError,
                                        "missing-required.file"):
                c.build_plugin_zip("http://bundle.test")

        import io as iolib
        import zipfile as zf
        with tempfile.TemporaryDirectory() as tmp:
            base = "http://cache.test"
            with mock.patch.object(c.zipfile.time, "time",
                                   return_value=1700000000):
                first_blob = c.build_plugin_zip(base)
            with mock.patch.object(c.zipfile.time, "time",
                                   return_value=1800000000):
                second_blob = c.build_plugin_zip(base)
            self.assertEqual(first_blob, second_blob)
            self.assertEqual(c.hashlib.sha256(first_blob).digest(),
                             c.hashlib.sha256(second_blob).digest())
            with zf.ZipFile(iolib.BytesIO(first_blob)) as archive:
                for info in archive.infolist():
                    self.assertEqual(info.date_time, c._PLUGIN_ZIP_DATE_TIME)
                    self.assertEqual(info.create_system, 3)
                    self.assertEqual(info.external_attr >> 16, 0o100644)
                    self.assertEqual(info.compress_type, zf.ZIP_DEFLATED)
            with mock.patch.object(c, "build_plugin_zip",
                                   return_value=first_blob):
                first_repo = c.ensure_plugin_git_repo(base, tmp)
            with mock.patch.object(c, "build_plugin_zip",
                                   return_value=second_blob):
                same_repo = c.ensure_plugin_git_repo(base, tmp)
            self.assertEqual(first_repo, same_repo)
            with mock.patch.dict(os.environ, {
                    "GIT_AUTHOR_NAME": "ambient-author",
                    "GIT_AUTHOR_EMAIL": "ambient@example.invalid",
                    "GIT_AUTHOR_DATE": "2037-01-01T00:00:00+00:00",
                    "GIT_COMMITTER_NAME": "ambient-committer",
                    "GIT_COMMITTER_EMAIL": "ambient@example.invalid",
                    "GIT_COMMITTER_DATE": "2038-01-01T00:00:00+00:00",
            }):
                independent_repo = c.ensure_plugin_git_repo(
                    base, Path(tmp) / "independent",
                    plugin_blob=first_blob, version=c.VERSION)
            first_head = subprocess.check_output(
                ["git", "-C", str(first_repo), "rev-parse", "HEAD"],
                text=True).strip()
            independent_head = subprocess.check_output(
                ["git", "-C", str(independent_repo), "rev-parse", "HEAD"],
                text=True).strip()
            self.assertEqual(first_head, independent_head)
            changed_buffer = iolib.BytesIO()
            with zf.ZipFile(iolib.BytesIO(first_blob)) as source:
                with zf.ZipFile(changed_buffer, "w",
                                zf.ZIP_DEFLATED) as changed:
                    for info in source.infolist():
                        payload = source.read(info.filename)
                        if info.filename == "README.md":
                            payload += b"\ncontent-addressed-cache-proof\n"
                        changed.writestr(info, payload)
            changed_blob = changed_buffer.getvalue()
            self.assertNotEqual(c.hashlib.sha256(first_blob).digest(),
                                c.hashlib.sha256(changed_blob).digest())
            with mock.patch.object(
                    c, "build_plugin_zip",
                    return_value=changed_blob):
                second_repo = c.ensure_plugin_git_repo(base, tmp)
            self.assertNotEqual(first_repo, second_repo)
            shown = subprocess.run(
                ["git", "-C", str(second_repo), "show", "HEAD:README.md"],
                capture_output=True, text=True, check=True)
            self.assertIn("content-addressed-cache-proof", shown.stdout)

    def test_server_rejects_incoherent_distribution_before_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            for relative in c.PLUGIN_FILES:
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            db = root / "validation.db"
            c.connect(db).close()

            # Constructor validation happens before socket binding, including
            # invalid runtime options and source/manifest coherence failures.
            with self.assertRaisesRegex(c.AttaccaError, "auth_mode"):
                c.AttaccaServer(("127.0.0.1", 0), db,
                                auth_mode="not-a-mode")
            with mock.patch.object(
                    c, "script_path",
                    return_value=str(source / "attacca.py")):
                manifest_path = source / ".claude-plugin" / "plugin.json"
                manifest = json.loads(manifest_path.read_text())
                manifest["version"] = "9.9.9"
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(
                        c.AttaccaError, "VERSION mismatch"):
                    c.AttaccaServer(("127.0.0.1", 0), db)

                manifest["version"] = c.VERSION
                manifest_path.write_text(json.dumps(manifest))
                config_path = source / "plugin-mcp.json"
                config = json.loads(config_path.read_text())
                config["mcpServers"]["attacca"]["env"] = "not-an-object"
                config_path.write_text(json.dumps(config))
                with self.assertRaisesRegex(
                        c.AttaccaError, "env must be an object"):
                    c.AttaccaServer(("127.0.0.1", 0), db)

    def test_sigterm_cleans_lazy_distribution_git_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temp_root = root / "process-tmp"
            temp_root.mkdir()
            db = root / "sigterm.db"
            c.connect(db).close()
            env = dict(os.environ)
            env.update({"ATTACCA_DB": str(db), "ATTACCA_OWNER": "",
                        "TMPDIR": str(temp_root)})
            process = subprocess.Popen(
                [sys.executable, SCRIPT, "serve", "--port", "0"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env=env)
            try:
                line = process.stdout.readline()
                match = re.search(r"http://127\.0\.0\.1:(\d+)", line)
                self.assertIsNotNone(match, line)
                base = "http://127.0.0.1:%s" % match.group(1)
                with urllib.request.urlopen(
                        base + "/plugin.git/HEAD", timeout=10) as response:
                    self.assertEqual(response.status, 200)
                    self.assertIn(b"refs/heads/main", response.read())
                self.assertEqual(len(list(temp_root.glob(
                    "attacca-distribution-*"))), 1)
                process.terminate()
                process.wait(timeout=10)
                self.assertEqual(list(temp_root.glob(
                    "attacca-distribution-*")), [])
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                process.stdout.close()
                process.stderr.close()

    def test_running_server_freezes_distribution_startup_snapshot(self):
        """A release process never serves a mixture of two source trees."""
        import http.client
        import io as iolib
        import socket
        import zipfile as zf

        marker = "post-start-distribution-change"
        runtime_marker = "post-start-runtime-template"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            for relative in c.PLUGIN_FILES:
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())

            running = []

            def start_server(name):
                db = root / (name + ".db")
                conn = c.connect(db)
                conn.close()
                server = c.AttaccaServer(("127.0.0.1", 0), db)
                thread = threading.Thread(target=server.serve_forever,
                                          daemon=True)
                thread.start()
                running.append((server, thread))
                return server

            def fetch(server, path, host="Snapshot.EXAMPLE:443",
                      forwarded_proto="https"):
                address, port = server.server_address[:2]
                connection = http.client.HTTPConnection(
                    address, port, timeout=10)
                try:
                    connection.request(
                        "GET", path,
                        headers={"Host": host,
                                 "X-Forwarded-Proto": forwarded_proto})
                    response = connection.getresponse()
                    return (response.status, response.read(),
                            dict(response.getheaders()))
                finally:
                    connection.close()

            def raw_request(server, request):
                address = ("127.0.0.1", server.server_address[1])
                with socket.create_connection(address, timeout=10) as stream:
                    stream.sendall(request)
                    chunks = []
                    while True:
                        chunk = stream.recv(65536)
                        if not chunk:
                            return b"".join(chunks)
                        chunks.append(chunk)

            def mcp_version(server):
                address, port = server.server_address[:2]
                connection = http.client.HTTPConnection(
                    address, port, timeout=10)
                payload = json.dumps({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18",
                               "capabilities": {},
                               "clientInfo": {"name": "snapshot-test",
                                              "version": "1"}},
                })
                try:
                    connection.request(
                        "POST", "/mcp", payload,
                        {"Content-Type": "application/json",
                         "Host": "Snapshot.EXAMPLE:443",
                         "X-Forwarded-Proto": "https"})
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    body = json.loads(response.read())
                    return body["result"]["serverInfo"]["version"]
                finally:
                    connection.close()

            try:
                with mock.patch.object(
                        c, "script_path",
                        return_value=str(source / "attacca.py")):
                    startup_version = c.VERSION
                    old_server = start_server("old")
                    self.assertEqual(mcp_version(old_server), startup_version)
                    immutable_paths = (
                        "/", "/app", "/install.sh", "/plugin.zip",
                        "/plugin/marketplace.json")
                    startup = {}
                    for path in immutable_paths:
                        status, body, headers = fetch(old_server, path)
                        self.assertEqual(status, 200, path)
                        self.assertEqual(headers.get("Vary"),
                                         "X-Forwarded-Proto", path)
                        self.assertEqual(headers.get("Cache-Control"),
                                         "no-store, max-age=0", path)
                        startup[path] = body
                        self.assertEqual(fetch(old_server, path)[1], body,
                                         path)

                    canonical_base = "https://snapshot.example"
                    self.assertIn(
                        ('BASE="%s"' % canonical_base).encode(),
                        startup["/install.sh"])
                    with zf.ZipFile(iolib.BytesIO(
                            startup["/plugin.zip"])) as archive:
                        packaged_config = json.loads(
                            archive.read("plugin-mcp.json"))
                        self.assertEqual(
                            packaged_config["mcpServers"]["attacca"]["env"]
                            ["ATTACCA_URL"], canonical_base)
                    marketplace = json.loads(
                        startup["/plugin/marketplace.json"])
                    self.assertEqual(
                        marketplace["plugins"][0]["source"]["url"],
                        canonical_base + "/plugin.git")

                    duplicate_host = raw_request(
                        old_server,
                        b"GET /install.sh HTTP/1.1\r\n"
                        b"Host: first.example\r\nHost: second.example\r\n"
                        b"Connection: close\r\n\r\n")
                    self.assertIn(b"HTTP/1.1 400", duplicate_host[:32])
                    missing_host = raw_request(
                        old_server,
                        b"GET /install.sh HTTP/1.1\r\n"
                        b"Connection: close\r\n\r\n")
                    self.assertIn(b"HTTP/1.1 400", missing_host[:32])
                    duplicate_forwarded_proto = raw_request(
                        old_server,
                        b"GET /install.sh HTTP/1.1\r\n"
                        b"Host: snapshot.example\r\n"
                        b"X-Forwarded-Proto: http\r\n"
                        b"X-Forwarded-Proto: https\r\n"
                        b"Connection: close\r\n\r\n")
                    self.assertIn(
                        b"HTTP/1.1 400", duplicate_forwarded_proto[:32])
                    http_10 = raw_request(
                        old_server,
                        b"GET /install.sh HTTP/1.0\r\n"
                        b"Connection: close\r\n\r\n")
                    self.assertIn(b"HTTP/1.1 200", http_10[:32])

                    # Another valid request origin gets its own deterministic
                    # wiring over the identical frozen source payload.
                    alternate_base = "http://downloads.example:8443"
                    alternate_zip = fetch(
                        old_server, "/plugin.zip",
                        host="Downloads.EXAMPLE:8443",
                        forwarded_proto="http")[1]
                    self.assertEqual(
                        fetch(old_server, "/plugin.zip",
                              host="Downloads.EXAMPLE:8443",
                              forwarded_proto="http")[1], alternate_zip)
                    with zf.ZipFile(iolib.BytesIO(
                            startup["/plugin.zip"])) as primary_archive, \
                            zf.ZipFile(iolib.BytesIO(
                                alternate_zip)) as alternate_archive:
                        alternate_config = json.loads(
                            alternate_archive.read("plugin-mcp.json"))
                        self.assertEqual(
                            alternate_config["mcpServers"]["attacca"]["env"]
                            ["ATTACCA_URL"], alternate_base)
                        self.assertEqual(primary_archive.read("attacca.py"),
                                         alternate_archive.read("attacca.py"))

                    # Valid Host variation is supported but cannot amplify
                    # persistent disk use without bound.
                    for index in range(c._MAX_DISTRIBUTION_GIT_REPOS + 3):
                        status, head, _ = fetch(
                            old_server, "/plugin.git/HEAD",
                            host="cache-%d.example" % index,
                            forwarded_proto="http")
                        self.assertEqual(status, 200)
                        self.assertIn(b"refs/heads/main", head)
                    self.assertEqual(
                        len(old_server._distribution_git_repos),
                        c._MAX_DISTRIBUTION_GIT_REPOS)
                    cache_dirs = [
                        path for path in (
                            old_server._distribution_cache_root /
                            "plugin-git").iterdir()
                        if path.is_dir() and not path.name.startswith(".")]
                    self.assertLessEqual(
                        len(cache_dirs), c._MAX_DISTRIBUTION_GIT_REPOS)

                    # The Host value becomes shell and JSON data, so reject
                    # metacharacters instead of merely escaping one context.
                    status, rejected, _ = fetch(
                        old_server, "/install.sh",
                        host='safe.example";$(id)')
                    self.assertEqual(status, 400)
                    self.assertIn(b"invalid Host header", rejected)

                    # Mutate all three mutable input categories after startup:
                    # panel/source assets, release manifests/runtime bytes,
                    # and imported runtime metadata/templates.
                    with (source / "web" / "admin.html").open("a") as handle:
                        handle.write("\n<!-- %s -->\n" % marker)
                    with (source / "README.md").open("a") as handle:
                        handle.write("\n%s\n" % marker)
                    runtime_path = source / "attacca.py"
                    runtime_text = runtime_path.read_text()
                    new_version = "9.9.9"
                    old_assignment = 'VERSION = "%s"' % startup_version
                    self.assertIn(old_assignment, runtime_text)
                    runtime_path.write_text(runtime_text.replace(
                        old_assignment, 'VERSION = "%s"' % new_version, 1)
                        + "\n# %s\n" % marker)
                    for relative in (
                            ".claude-plugin/plugin.json",
                            ".codex-plugin/plugin.json",
                            "kimi.plugin.json"):
                        path = source / relative
                        manifest = json.loads(path.read_text())
                        manifest["snapshot_probe"] = marker
                        manifest["version"] = new_version + (
                            "+codex.snapshot" if relative.startswith(
                                ".codex-plugin/") else "")
                        path.write_text(json.dumps(manifest, indent=2) + "\n")

                    changed_install = c.INSTALL_SH_TEMPLATE + (
                        "\n# %s\n" % runtime_marker)
                    changed_landing = c.LANDING_TEMPLATE.replace(
                        "</body>", "<!-- %s --></body>" % runtime_marker)
                    with mock.patch.object(c, "VERSION", new_version), \
                            mock.patch.object(
                                c, "INSTALL_SH_TEMPLATE", changed_install), \
                            mock.patch.object(
                                c, "LANDING_TEMPLATE", changed_landing):
                        # Every old-server byte remains the exact startup byte,
                        # including base-wired ZIPs and marketplace metadata.
                        for path, expected in startup.items():
                            self.assertEqual(
                                fetch(old_server, path)[1], expected, path)
                        old_health = json.loads(
                            fetch(old_server, "/healthz")[1])
                        old_settings = json.loads(
                            fetch(old_server, "/v1/settings")[1])
                        self.assertEqual(old_health["version"],
                                         startup_version)
                        self.assertEqual(old_settings["version"],
                                         startup_version)
                        self.assertEqual(mcp_version(old_server),
                                         startup_version)
                        self.assertEqual(old_settings["server_url"],
                                         canonical_base)

                        new_server = start_server("new")
                        new_app = fetch(new_server, "/app")[1]
                        new_install = fetch(new_server, "/install.sh")[1]
                        new_landing = fetch(new_server, "/")[1]
                        new_zip = fetch(new_server, "/plugin.zip")[1]
                        self.assertIn(marker.encode(), new_app)
                        self.assertIn(runtime_marker.encode(), new_install)
                        self.assertIn(runtime_marker.encode(), new_landing)
                        self.assertIn(
                            ('EXPECTED_VERSION="%s"' % new_version).encode(),
                            new_install)
                        self.assertNotEqual(new_zip,
                                            startup["/plugin.zip"])
                        self.assertEqual(fetch(new_server, "/plugin.zip")[1],
                                         new_zip)
                        with zf.ZipFile(iolib.BytesIO(new_zip)) as archive:
                            runtime_payload = archive.read("attacca.py")
                            self.assertIn(marker.encode(), runtime_payload)
                            self.assertIn(
                                ('VERSION = "%s"' % new_version).encode(),
                                runtime_payload)
                            self.assertIn(
                                marker.encode(), archive.read("README.md"))
                            for relative in (
                                    ".claude-plugin/plugin.json",
                                    ".codex-plugin/plugin.json",
                                    "kimi.plugin.json"):
                                packaged_manifest = json.loads(
                                    archive.read(relative))
                                self.assertEqual(
                                    packaged_manifest["snapshot_probe"],
                                    marker)
                                expected_version = new_version + (
                                    "+codex.snapshot" if relative.startswith(
                                        ".codex-plugin/") else "")
                                self.assertEqual(
                                    packaged_manifest["version"],
                                    expected_version)
                        new_health = json.loads(
                            fetch(new_server, "/healthz")[1])
                        new_settings = json.loads(
                            fetch(new_server, "/v1/settings")[1])
                        self.assertEqual(new_health["version"], new_version)
                        self.assertEqual(new_settings["version"], new_version)
                        self.assertEqual(mcp_version(new_server), new_version)

                        # Native marketplace installs use /plugin.git rather
                        # than /plugin.zip.  Its repository must use the same
                        # frozen payload as the corresponding running server.
                        clones = []
                        for label, server in (("old-clone", old_server),
                                              ("new-clone", new_server)):
                            destination = root / label
                            url = "http://127.0.0.1:%d/plugin.git" % (
                                server.server_address[1],)
                            cloned = subprocess.run(
                                ["git", "clone", "-q", url,
                                 str(destination)],
                                capture_output=True, text=True, timeout=20)
                            self.assertEqual(cloned.returncode, 0,
                                             cloned.stderr)
                            clones.append(destination)
                        self.assertNotIn(
                            marker,
                            (clones[0] / "web" / "admin.html").read_text())
                        self.assertIn(
                            marker,
                            (clones[1] / "web" / "admin.html").read_text())
            finally:
                for server, thread in reversed(running):
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=10)
                    self.assertFalse(thread.is_alive())

    def test_unknown_route_404_and_bad_json_400(self):
        status, body, _ = self.rest("GET", "/v1/nope")
        self.assertEqual(status, 404)
        req = urllib.request.Request(self.server.base + "/v1/projects",
                                     data=b"{not json", method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
            self.fail("expected 400")
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code, 400)

    def test_project_create_without_root(self):
        status, body, _ = self.rest("POST", "/v1/projects",
                                    {"project_id": "cloudy", "name": "Cloud Only"},
                                    actor="admin")
        self.assertEqual(status, 200)
        self.assertIsNone(body["root_path"])
        status, body, _ = self.rest("GET", "/v1/projects")
        self.assertIn("cloudy", [p["project_id"] for p in body["projects"]])

    def test_project_create_retry_is_idempotent(self):
        status, first, _ = self.rest(
            "POST", "/v1/projects", {"name": "Retry Workspace"},
            actor="admin")
        self.assertEqual(status, 200)
        status, second, _ = self.rest(
            "POST", "/v1/projects", {"name": "Retry Workspace"},
            actor="admin")
        self.assertEqual(status, 200)
        self.assertEqual(first["project_id"], "retry-workspace")
        self.assertEqual(second["project_id"], "retry-workspace")
        self.assertTrue(second["already_existed"])
        status, body, _ = self.rest(
            "POST", "/v1/projects", {"name": "Retry-Workspace"},
            actor="admin")
        self.assertEqual(status, 400)
        self.assertIn("already belongs", body["error"])
        status, body, _ = self.rest(
            "POST", "/v1/projects",
            {"name": "Retry Workspace",
             "repository_fingerprint": "sha256:" + "d" * 64},
            actor="admin")
        self.assertEqual(status, 400)
        self.assertIn("choose it explicitly", body["error"])

    def test_explicit_project_id_rejects_another_projects_git_identity(self):
        fingerprint = "sha256:" + "c" * 64
        status, _, _ = self.rest(
            "POST", "/v1/projects",
            {"project_id": "fingerprint-owner",
             "repository_fingerprint": fingerprint}, actor="admin")
        self.assertEqual(status, 200)
        status, _, _ = self.rest(
            "POST", "/v1/projects", {"project_id": "explicit-target"},
            actor="admin")
        self.assertEqual(status, 200)
        status, body, _ = self.rest(
            "POST", "/v1/projects",
            {"project_id": "explicit-target",
             "repository_fingerprint": fingerprint}, actor="admin")
        self.assertEqual(status, 400)
        self.assertIn("fingerprint-owner", body["error"])

    def test_room_over_rest_with_actor_attribution(self):
        status, sent, _ = self.rest("POST", "/v1/projects/hub/room",
                                    {"body": "rest hello", "msg_type": "chat"},
                                    actor="rest_bot")
        self.assertEqual(status, 200)
        self.assertEqual(sent["event"]["actor_id"], "rest_bot")
        status, room, _ = self.rest("GET", "/v1/projects/hub/room")
        self.assertIn("rest hello", [m["body"] for m in room["messages"]])
        original = next(m for m in room["messages"]
                        if m["body"] == "rest hello")
        self.assertEqual(original["event_id"], sent["event"]["event_id"])
        # cursor polling over REST
        status, empty, _ = self.rest(
            "GET", "/v1/projects/hub/room?since_seq=%d" % room["next_since_seq"])
        self.assertEqual(empty["messages"], [])
        self.rest("POST", "/v1/projects/hub/room",
                  {"body": "rest reply", "msg_type": "chat",
                   "reply_to": original["event_id"]}, actor="reply_bot")
        _, replies, _ = self.rest(
            "GET", "/v1/projects/hub/room?since_seq=%d" % room["next_since_seq"])
        self.assertEqual(replies["messages"][0]["reply_to"],
                         original["event_id"])

        # A plain chat can target one connected workspace without leaking to
        # every bridge; both sides retain explicit source/destination labels.
        for project_id in ("room-target", "room-other"):
            self.rest("POST", "/v1/projects",
                      {"project_id": project_id, "name": project_id},
                      actor="admin", actor_type="human")
            self.rest("POST", "/v1/projects/hub/bridges",
                      {"other_project": project_id}, actor="admin",
                      actor_type="human")
        status, targeted, _ = self.rest(
            "POST", "/v1/projects/hub/room",
            {"body": "only target this connection", "msg_type": "chat",
             "target_project": "room-target"}, actor="rest_bot",
            actor_type="agent")
        self.assertEqual(status, 200)
        self.assertEqual(targeted["mirrored_to_bridged_projects"],
                         ["room-target"])
        _, source_room, _ = self.rest("GET", "/v1/projects/hub/room")
        source = next(message for message in source_room["messages"]
                      if message["body"] == "only target this connection")
        self.assertEqual(source["mirrored_to"], ["room-target"])
        _, target_room, _ = self.rest(
            "GET", "/v1/projects/room-target/room")
        mirrored = target_room["messages"][-1]
        self.assertEqual(mirrored["origin_project"], "hub")
        self.assertEqual(mirrored["identity"]["workspace"], "hub")
        self.assertTrue(mirrored["actor"].startswith("hub.unassigned."))
        _, target_events, _ = self.rest(
            "GET", "/v1/projects/room-target/events?after=0&limit=100")
        mirrored_event = next(
            event for event in target_events["events"]
            if event["event_type"] == "room.message"
            and event["payload"].get("body") ==
            "only target this connection")
        self.assertEqual(mirrored_event["identity"]["workspace"], "hub")
        self.assertEqual(mirrored_event["operational_actor_id"],
                         mirrored["actor"])
        _, other_room, _ = self.rest("GET", "/v1/projects/room-other/room")
        self.assertNotIn("only target this connection",
                         [message["body"] for message in
                          other_room["messages"]])

        # The panel sends the current workspace id for its explicit local-only
        # destination. Even structured messages and mentions must not fan out.
        status, local, _ = self.rest(
            "POST", "/v1/projects/hub/room",
            {"body": "keep this directive local", "msg_type": "directive",
             "mentions": ["rest_bot"], "target_project": "hub"},
            actor="panel-user", actor_type="human")
        self.assertEqual(status, 200)
        self.assertEqual(local.get("mirrored_to_bridged_projects", []), [])
        for project_id in ("room-target", "room-other"):
            _, remote_room, _ = self.rest(
                "GET", "/v1/projects/%s/room" % project_id)
            self.assertNotIn("keep this directive local",
                             [message["body"] for message in
                              remote_room["messages"]])

    def test_legacy_source_room_events_recover_the_exact_bridge_pair(self):
        source_id = "legacy-room-source"
        target_id = "legacy-room-target"
        unrelated_id = "legacy-room-unrelated"
        for project_id in (source_id, target_id, unrelated_id):
            self.rest("POST", "/v1/projects",
                      {"project_id": project_id, "name": project_id},
                      actor="admin", actor_type="human")
        for project_id in (target_id, unrelated_id):
            self.rest("POST", "/v1/projects/%s/bridges" % source_id,
                      {"other_project": project_id}, actor="admin",
                      actor_type="human")

        legacy_payload = {
            "msg_type": "status",
            "body": "legacy message sent only to one bridge",
            "mentions": ["legacy-worker"],
        }
        conn = c.connect(self.db)
        try:
            c.append_event(conn, source_id, "legacy-director", "agent",
                           "room.message", legacy_payload)
            c.append_event(
                conn, target_id, "legacy-director", "agent", "room.message",
                dict(legacy_payload, origin_project=source_id))
            c.append_event(
                conn, source_id, "legacy-director", "agent", "room.message",
                {"msg_type": "directive", "body": "local structured note"})
        finally:
            conn.close()

        status, room, _ = self.rest(
            "GET", "/v1/projects/%s/room?limit=100" % source_id)
        self.assertEqual(status, 200)
        legacy = next(message for message in room["messages"]
                      if message["body"] == legacy_payload["body"])
        local = next(message for message in room["messages"]
                     if message["body"] == "local structured note")
        self.assertEqual(legacy["mirrored_to"], [target_id])
        self.assertTrue(legacy["mirrored_to_inferred"])
        self.assertEqual(local["mirrored_to"], [])
        self.assertNotIn("mirrored_to_inferred", local)

    def test_panel_status_decisions_lead_and_bridges(self):
        status, overview, _ = self.rest("GET", "/v1/projects/hub/status",
                                        actor="panel-user")
        self.assertEqual(status, 200)
        self.assertEqual(overview["project"], "hub")
        self.assertIn("counts", overview)

        _, proposed, _ = self.rest(
            "POST", "/v1/projects/hub/decisions",
            {"title": "Panel decision", "detail": "visible in browser"},
            actor="panel-user")
        did = proposed["decision_id"]
        _, decisions, _ = self.rest("GET", "/v1/projects/hub/decisions")
        self.assertIn(did, [d["decision_id"] for d in decisions["decisions"]])
        _, resolved, _ = self.rest(
            "POST", "/v1/projects/hub/decisions/%s/resolve" % did,
            {"resolution": "accepted"}, actor="panel-user")
        self.assertEqual(resolved["status"], "accepted")
        _, search, _ = self.rest(
            "GET", "/v1/projects/hub/search?q=browser", actor="panel-user")
        self.assertIn(did, [d["decision_id"] for d in search["decisions"]])
        _, freshness, _ = self.rest(
            "GET", "/v1/projects/hub/freshness?context_version=0",
            actor="panel-user")
        self.assertTrue(freshness["stale"])

        self.rest("POST", "/v1/projects/hub/room",
                  {"body": "panel inbox message", "msg_type": "chat",
                   "mentions": ["panel-user"]}, actor="another-worker")
        _, inbox, _ = self.rest(
            "GET", "/v1/projects/hub/inbox?mark_read=0",
            actor="panel-user")
        self.assertIn("panel inbox message",
                      [message["body"] for message in inbox["messages"]])
        self.rest("GET", "/v1/projects/hub/inbox?mark_read=1",
                  actor="panel-user")
        _, read_inbox, _ = self.rest(
            "GET", "/v1/projects/hub/inbox?mark_read=0",
            actor="panel-user")
        self.assertEqual(read_inbox["messages"], [])

        _, registered_lead, _ = self.rest(
            "POST", "/v1/projects/hub/agents",
            {"agent_id": "panel-lead", "display_name": "Panel Lead",
             "role": "director", "runtime": "panel"}, actor="panel-user")
        panel_lead = registered_lead["agent_id"]
        _, lead, _ = self.rest("PUT", "/v1/projects/hub/lead",
                               {"agent_id": panel_lead}, actor="panel-user")
        self.assertEqual(lead["lead_director"], "hub.director.panel")
        _, cleared, _ = self.rest("PUT", "/v1/projects/hub/lead",
                                  {"agent_id": None}, actor="panel-user")
        self.assertIsNone(cleared["lead_director"])

        self.rest("POST", "/v1/projects",
                  {"project_id": "panel-sidecar", "name": "Panel Sidecar"},
                  actor="panel-user")
        _, added, _ = self.rest(
            "POST", "/v1/projects/hub/bridges",
            {"other_project": "panel-sidecar"}, actor="panel-user",
            actor_type="human")
        self.assertTrue(added["ok"])
        _, bridges, _ = self.rest(
            "GET", "/v1/projects/hub/bridges", actor="panel-user",
            actor_type="human")
        self.assertIn("panel-sidecar", [b["with"] for b in bridges["bridges"]])
        _, removed, _ = self.rest(
            "DELETE", "/v1/projects/hub/bridges/panel-sidecar",
            actor="panel-user", actor_type="human")
        self.assertTrue(removed["ok"])

    def test_task_lifecycle_and_claim_guard_over_rest(self):
        _, task, _ = self.rest("POST", "/v1/projects/hub/tasks",
                               {"title": "http task",
                                "expected_scope": ["src/http/**"]},
                               actor="alice")
        tid = task["task_id"]
        status, claim, _ = self.rest("POST", "/v1/projects/hub/tasks/%s/claim" % tid,
                                     {}, actor="alice")
        self.assertEqual(status, 200)
        self.assertEqual(claim["claimed_by"], "alice")
        # bob cannot report alice's active claim
        status, err, _ = self.rest("POST", "/v1/projects/hub/tasks/%s/report" % tid,
                                   {"summary": "hijack"}, actor="bob")
        self.assertEqual(status, 400)
        self.assertIn("claimant", err["error"])
        status, report, _ = self.rest(
            "POST", "/v1/projects/hub/tasks/%s/report" % tid,
            {"summary": "done over rest",
             "evidence": [{"kind": "test", "result": "pass"}],
             "requested_state": "done"}, actor="alice")
        self.assertEqual(status, 200)
        _, shown, _ = self.rest("GET", "/v1/projects/hub/tasks/%s" % tid)
        self.assertEqual(shown["status"], "done")

    def test_handoff_freshness_verify_and_sync(self):
        _, before, _ = self.rest("GET", "/v1/projects/hub/handoff")
        _, updated, _ = self.rest("POST", "/v1/projects/hub/handoff",
                                  {"objective": "serve the world"}, actor="alice")
        _, handoff, _ = self.rest("GET", "/v1/projects/hub/handoff")
        self.assertEqual(handoff["handoff"]["objective"], "serve the world")
        _, fresh, _ = self.rest(
            "GET", "/v1/projects/hub/freshness?context_version=%d"
            % before["context_version"])
        self.assertTrue(fresh["stale"])
        _, verify, _ = self.rest("GET", "/v1/projects/hub/verify")
        self.assertTrue(verify["ok"], verify["problems"])
        _, sync, _ = self.rest("GET", "/v1/projects/hub/events?after=0&limit=5")
        self.assertTrue(sync["events"])
        self.assertEqual(sync["events"][0]["seq"], 1)
        self.assertIsInstance(sync["events"][0]["payload"], dict)

    def test_rest_handoff_roles_and_optimistic_conflict(self):
        project = "governed-rest"
        self.rest("POST", "/v1/projects",
                  {"project_id": project, "name": "Governed REST"},
                  actor="admin", actor_type="human")
        for actor, role in (("director-a", "director"),
                            ("director-b", "director"),
                            ("worker", "worker")):
            status, _, _ = self.rest(
                "POST", "/v1/projects/%s/agents" % project,
                {"agent_id": actor, "role": role, "runtime": "test"},
                actor="admin", actor_type="human")
            self.assertEqual(status, 200)
        self.rest("PUT", "/v1/projects/%s/lead" % project,
                  {"agent_id": "director-a"}, actor="admin",
                  actor_type="human")
        _, brief, _ = self.rest(
            "GET", "/v1/projects/%s/handoff" % project,
            actor="director-a", actor_type="agent")
        expected = brief["context_version"]
        status, first, _ = self.rest(
            "PUT", "/v1/projects/%s/handoff" % project,
            {"what_changed": "first director",
             "expected_context_version": expected},
            actor="director-a", actor_type="agent")
        self.assertEqual(status, 200)
        status, conflict, _ = self.rest(
            "PUT", "/v1/projects/%s/handoff" % project,
            {"what_changed": "stale second director",
             "expected_context_version": expected},
            actor="director-b", actor_type="agent")
        self.assertEqual(status, 400)
        self.assertIn("handoff conflict", conflict["error"])
        status, denied, _ = self.rest(
            "PUT", "/v1/projects/%s/handoff" % project,
            {"notes": "worker write",
             "expected_context_version": first["context_version"]},
            actor="worker", actor_type="agent")
        self.assertEqual(status, 400)
        self.assertIn("director-only", denied["error"])
        _, final, _ = self.rest("GET", "/v1/projects/%s/handoff" % project)
        self.assertEqual(final["handoff"]["what_changed"], "first director")

    # -- MCP over streamable HTTP -------------------------------------------

    def mcp(self, msg, session=None, actor=None, project="hub"):
        headers = {"Accept": "application/json, text/event-stream"}
        if session:
            headers["Mcp-Session-Id"] = session
        if actor:
            headers["X-Attacca-Actor"] = actor
        if project:
            headers["X-Attacca-Project"] = project
        return self.server.request("POST", "/mcp", msg, headers)

    def mcp_init(self, actor=None, client="http-test"):
        status, resp, headers = self.mcp(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": client, "version": "0"}}},
            actor=actor)
        return status, resp, headers.get("Mcp-Session-Id")

    def test_mcp_initialize_and_session(self):
        status, resp, sid = self.mcp_init(actor="mcp_alice")
        self.assertEqual(status, 200)
        self.assertTrue(sid)
        self.assertEqual(resp["result"]["serverInfo"]["name"], "attacca")
        status, tools, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session=sid)
        self.assertGreaterEqual(len(tools["result"]["tools"]), 15)

    def test_unknown_project_initialize_creates_unbound_setup_session(self):
        stale_project = "deleted-workspace"
        status, initialized, headers = self.mcp(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "stale-link", "version": "0"}}},
            actor="mcp_stale", project=stale_project)
        sid = headers.get("Mcp-Session-Id")
        self.assertEqual(status, 200)
        self.assertTrue(sid)
        self.assertEqual(initialized["result"]["serverInfo"]["name"],
                         "attacca")

        status, tools, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            session=sid, project=stale_project)
        self.assertEqual(status, 200)
        self.assertIn("list_projects",
                      {tool["name"] for tool in tools["result"]["tools"]})

        status, projects, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "list_projects", "arguments": {}}},
            session=sid, project=stale_project)
        self.assertEqual(status, 200)
        self.assertFalse(projects["result"]["isError"])
        listed = json.loads(projects["result"]["content"][0]["text"])
        project_ids = {project["project_id"]
                       for project in listed["projects"]}
        self.assertIn("hub", project_ids)
        self.assertNotIn(stale_project, project_ids)

        status, project_tool, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "attacca_status", "arguments": {}}},
            session=sid, project=stale_project)
        self.assertEqual(status, 200)
        self.assertTrue(project_tool["result"]["isError"])
        error = project_tool["result"]["content"][0]["text"]
        self.assertIn("Attacca setup required", error)
        self.assertIn("unknown project '%s'" % stale_project, error)
        self.assertIn("$attacca:setup", error)
        self.assertIn("/attacca:setup", error)

    def test_mcp_notification_202_get_405_delete_204(self):
        _, _, sid = self.mcp_init(actor="x")
        status, body, _ = self.mcp(
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            session=sid)
        self.assertEqual(status, 202)
        self.assertIsNone(body)
        status, _, headers = self.server.request("GET", "/mcp")
        self.assertEqual(status, 405)
        self.assertIn("POST", headers.get("Allow", ""))
        req_status, _, _ = self.server.request(
            "DELETE", "/mcp", headers={"Mcp-Session-Id": sid})
        self.assertEqual(req_status, 204)

    def test_mcp_tool_call_and_shared_state_with_rest(self):
        _, _, sid = self.mcp_init(actor="mcp_worker")
        status, resp, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
             "params": {"name": "room_send",
                        "arguments": {"body": "hello from MCP over HTTP"}}},
            session=sid, actor="mcp_worker")
        self.assertEqual(status, 200)
        self.assertFalse(resp["result"]["isError"])
        sent = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(sent["event"]["actor_id"], "hub.unassigned.mcp")
        _, room, _ = self.rest("GET", "/v1/projects/hub/room?limit=100")
        self.assertIn("hello from MCP over HTTP",
                      [m["body"] for m in room["messages"]])

    def test_mcp_sessionless_request_still_works(self):
        status, resp, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
             "params": {"name": "attacca_status", "arguments": {}}},
            actor="ephemeral")
        self.assertEqual(status, 200)
        body = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(body["you"]["actor_id"],
                         "hub.unassigned.ephemeral")

    def test_mcp_batch_and_parse_error(self):
        _, _, sid = self.mcp_init(actor="batcher")
        status, resp, _ = self.mcp(
            [{"jsonrpc": "2.0", "id": 21, "method": "ping"},
             {"jsonrpc": "2.0", "method": "notifications/x"},
             {"jsonrpc": "2.0", "id": 22, "method": "tools/list"}],
            session=sid)
        self.assertEqual(status, 200)
        self.assertIsInstance(resp, list)
        self.assertEqual({r["id"] for r in resp}, {21, 22})
        req = urllib.request.Request(self.server.base + "/mcp",
                                     data=b"not json at all", method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
            self.fail("expected 400")
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code, 400)
            self.assertEqual(json.loads(err.read())["error"]["code"], -32700)

    def test_mcp_drift_guard_state_survives_across_posts(self):
        _, _, sid = self.mcp_init(actor="stateful")
        status, resp, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 31, "method": "tools/call",
             "params": {"name": "get_handoff", "arguments": {}}},
            session=sid, actor="stateful")
        self.assertFalse(resp["result"]["isError"])
        # someone else advances the context via REST
        self.rest("POST", "/v1/projects/hub/handoff",
                  {"objective": "moved underneath"}, actor="other")
        _, task, _ = self.rest("POST", "/v1/projects/hub/tasks",
                               {"title": "drift probe"}, actor="stateful")
        status, resp, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 32, "method": "tools/call",
             "params": {"name": "task_claim",
                        "arguments": {"task_id": task["task_id"]}}},
            session=sid, actor="stateful")
        claim = json.loads(resp["result"]["content"][0]["text"])
        self.assertIn("stale_context_warning", claim)

    def test_mcp_project_header_selects_project(self):
        self.rest("POST", "/v1/projects",
                  {"project_id": "sidecar", "name": "Sidecar"}, actor="admin")
        status, resp, _ = self.mcp(
            {"jsonrpc": "2.0", "id": 41, "method": "tools/call",
             "params": {"name": "attacca_status", "arguments": {}}},
            actor="router", project="sidecar")
        body = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(body["project"], "sidecar")


class HttpHardeningTestCase(unittest.TestCase):
    """Regressions for the HTTP-layer review findings."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "hard.db"
        conn = c.connect(cls.db)
        proj = Path(cls.tmp.name) / "repo"
        proj.mkdir()
        c.project_init(conn, "setup", "human", path=str(proj),
                       project_id="hub", name="Hub")
        conn.close()
        cls.server = ServerFixture(cls.db)
        cls.host = cls.server.base.split("//")[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tmp.cleanup()

    def _conn(self):
        import http.client
        host, port = self.host.split(":")
        return http.client.HTTPConnection(host, int(port), timeout=10)

    def test_mcp_session_shared_across_live_connections(self):
        # The critical finding: a session's SQLite conn was bound to the first
        # request thread. Park connection A while B uses the same session.
        conn_a, conn_b = self._conn(), self._conn()
        try:
            init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "a", "version": "0"}}}
            conn_a.request("POST", "/mcp", json.dumps(init),
                           {"Content-Type": "application/json",
                            "X-Attacca-Project": "hub",
                            "X-Attacca-Actor": "threaded"})
            resp = conn_a.getresponse()
            sid = resp.getheader("Mcp-Session-Id")
            resp.read()
            self.assertTrue(sid)
            call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "attacca_status", "arguments": {}}}
            headers = {"Content-Type": "application/json", "Mcp-Session-Id": sid}
            conn_a.request("POST", "/mcp", json.dumps(call), headers)
            resp = conn_a.getresponse()
            first = json.loads(resp.read())
            self.assertFalse(first["result"]["isError"])
            # conn_a stays OPEN (its handler thread is alive/parked) while a
            # different connection/thread reuses the session.
            call["id"] = 3
            conn_b.request("POST", "/mcp", json.dumps(call), headers)
            resp = conn_b.getresponse()
            second = json.loads(resp.read())
            self.assertFalse(second["result"].get("isError"),
                             second["result"]["content"][0]["text"])
        finally:
            conn_a.close()
            conn_b.close()

    def test_keep_alive_survives_404_with_body(self):
        conn = self._conn()
        try:
            conn.request("POST", "/v1/projects/hub/log",
                         json.dumps({"hello": "world"}),
                         {"Content-Type": "application/json"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 404)
            resp.read()
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)  # was 501 garbage before fix
            self.assertTrue(json.loads(resp.read())["ok"])
        finally:
            conn.close()

    def test_keep_alive_survives_mcp_delete_with_body(self):
        conn = self._conn()
        try:
            conn.request("DELETE", "/mcp", json.dumps({"why": "not"}),
                         {"Content-Type": "application/json",
                          "Mcp-Session-Id": "deadbeef" * 4})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 204)
            resp.read()
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
        finally:
            conn.close()

    def test_chunked_body_rejected_with_411(self):
        conn = self._conn()
        try:
            conn.putrequest("POST", "/mcp")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Transfer-Encoding", "chunked")
            conn.endheaders()
            payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
            conn.send(b"%x\r\n%s\r\n0\r\n\r\n" % (len(payload), payload))
            resp = conn.getresponse()
            self.assertEqual(resp.status, 411)
        finally:
            conn.close()

    def test_url_encoded_project_id_reaches_route(self):
        status, body, _ = self.server.request("GET", "/v1/projects/hu%62/handoff")
        self.assertEqual(status, 200)
        self.assertEqual(body["project"], "hub")

    def test_api_project_id_is_slugified(self):
        status, body, _ = self.server.request(
            "POST", "/v1/projects", {"project_id": "My Fancy App!!"})
        self.assertEqual(status, 200)
        self.assertEqual(body["project_id"], "my-fancy-app")

    def test_head_and_options(self):
        conn = self._conn()
        try:
            conn.request("HEAD", "/healthz")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read(), b"")
            self.assertGreater(int(resp.getheader("Content-Length")), 0)
            conn.request("OPTIONS", "/v1/projects")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 204)
            self.assertIn("POST", resp.getheader("Allow"))
            resp.read()
        finally:
            conn.close()

    def test_batch_of_invalid_elements_gets_error_entries(self):
        status, resp, _ = self.server.request(
            "POST", "/mcp", [1, "nonsense"],
            {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        self.assertEqual(len(resp), 2)
        for entry in resp:
            self.assertEqual(entry["error"]["code"], -32600)

    def test_unknown_session_id_gets_404(self):
        status, body, _ = self.server.request(
            "POST", "/mcp",
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"Mcp-Session-Id": "0" * 32})
        self.assertEqual(status, 404)
        self.assertIn("re-initialize", body["error"])


class AutoRegisterTestCase(unittest.TestCase):
    """Unknown roots and unconfirmed Git matches require setup."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "auto.db"
        c.connect(cls.db).close()
        cls.server = ServerFixture(cls.db)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tmp.cleanup()

    def _status_via_root(self, root, repository_fingerprint=None):
        headers = {"X-Attacca-Root": str(root),
                   "X-Attacca-Actor": "auto"}
        if repository_fingerprint:
            headers[c.REPOSITORY_FINGERPRINT_HEADER] = repository_fingerprint
        status, resp, _ = self.server.request(
            "POST", "/mcp",
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "attacca_status", "arguments": {}}},
            headers)
        if status != 200:
            return status, resp
        body = resp["result"]["content"][0]["text"]
        assert not resp["result"].get("isError"), body
        return status, json.loads(body)

    def test_unknown_root_requires_explicit_setup(self):
        root = Path(self.tmp.name) / "shiny-app"
        root.mkdir()
        conn = c.connect(self.db)
        before = conn.execute(
            "SELECT COUNT(*) AS n FROM projects").fetchone()["n"]
        conn.close()
        status, body = self._status_via_root(root)
        self.assertEqual(status, 400)
        self.assertIn("/attacca:setup", body["error"])
        self.assertIn("$attacca:setup", body["error"])
        conn = c.connect(self.db)
        count = conn.execute("SELECT COUNT(*) AS n FROM projects").fetchone()["n"]
        conn.close()
        self.assertEqual(count, before)

    def test_git_fingerprint_match_requires_confirmation(self):
        a = Path(self.tmp.name) / "computer-a" / "checkout"
        b = Path(self.tmp.name) / "computer-b" / "different-name"
        a.mkdir(parents=True)
        b.mkdir(parents=True)
        fingerprint = "sha256:" + "a" * 64
        conn = c.connect(self.db)
        c.project_init(conn, "setup", "human", path=str(a),
                       project_id="shared", repository_fingerprint=fingerprint)
        conn.close()
        status, body = self._status_via_root(b, fingerprint)
        self.assertEqual(status, 400)
        self.assertIn("matches Attacca workspace 'shared'", body["error"])
        self.assertIn("setup --attach shared", body["error"])


class ConnectProxyTestCase(unittest.TestCase):
    """The `connect` stdio<->HTTP proxy the plugin spawns."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "proxy.db"
        c.connect(cls.db).close()
        cls.server = ServerFixture(cls.db)
        cls.proj = Path(cls.tmp.name) / "proxied-app"
        cls.proj.mkdir()
        conn = c.connect(cls.db)
        c.project_init(conn, "setup", "human", path=str(cls.proj),
                       project_id="proxied-app")
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.tmp.cleanup()

    def _proxy(self, url=None, cwd=None):
        fixture_url = url or self.server.base
        env = dict(os.environ)
        env.pop("CLAUDE_PROJECT_DIR", None)
        env.pop("ATTACCA_PROJECT", None)
        env["ATTACCA_DB"] = str(self.db)
        env["ATTACCA_URL"] = fixture_url
        env["ATTACCA_ACTOR"] = "proxy_actor"
        env["ATTACCA_AUTOSTART"] = "0"
        return subprocess.Popen(
            [sys.executable, SCRIPT, "connect", "--url", fixture_url],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env,
            cwd=str(cwd or self.proj))

    def _rpc(self, proc, msg):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        assert line, "proxy closed stdout"
        return json.loads(line)

    def test_full_session_through_proxy(self):
        proc = self._proxy()
        try:
            init = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "proxy-test", "version": "0"}}})
            self.assertEqual(init["result"]["serverInfo"]["name"], "attacca")
            # notification: forwarded, no local echo
            proc.stdin.write(json.dumps(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()
            status = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "attacca_status", "arguments": {}}})
            body = json.loads(status["result"]["content"][0]["text"])
            # project auto-registered from the proxy's cwd; actor from env
            self.assertEqual(body["project"], "proxied-app")
            self.assertEqual(body["you"]["actor_id"],
                             "proxied-app.unassigned.proxy-actor")
            # drift-guard session state survives the proxy hop
            handoff = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "get_handoff", "arguments": {}}})
            self.assertFalse(handoff["result"]["isError"])
        finally:
            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=10), 0)
            proc.stdout.close()
            proc.stderr.close()

    def test_unlinked_client_starts_then_adopts_confirmed_setup_link(self):
        unlinked = Path(self.tmp.name) / "unlinked-startup"
        unlinked.mkdir()
        proc = self._proxy(cwd=unlinked)
        try:
            init = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18",
                           "capabilities": {},
                           "clientInfo": {"name": "unlinked", "version": "0"}}})
            self.assertEqual(init["result"]["serverInfo"]["name"], "attacca")
            tools = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 2, "method": "tools/list",
                "params": {}})
            self.assertIn("tools", tools["result"])
            before = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "attacca_status", "arguments": {}}})
            self.assertTrue(before["result"]["isError"])
            self.assertIn("not attached", before["result"]["content"][0]["text"])

            c.write_project_link(unlinked, "proxied-app")
            after = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": "attacca_status", "arguments": {}}})
            self.assertFalse(after["result"]["isError"])
            body = json.loads(after["result"]["content"][0]["text"])
            self.assertEqual(body["project"], "proxied-app")
        finally:
            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=10), 0)
            proc.stdout.close()
            proc.stderr.close()

    def test_stale_link_proxy_session_adopts_rewritten_link(self):
        checkout = Path(self.tmp.name) / "stale-link-startup"
        checkout.mkdir()
        c.write_project_link(checkout, "deleted-workspace")
        proc = self._proxy(cwd=checkout)
        try:
            init = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18",
                           "capabilities": {},
                           "clientInfo": {"name": "stale-link", "version": "0"}}})
            self.assertEqual(init["result"]["serverInfo"]["name"], "attacca")
            before = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "attacca_status", "arguments": {}}})
            self.assertTrue(before["result"]["isError"])
            self.assertIn("Attacca setup required",
                          before["result"]["content"][0]["text"])
            self.assertIn("deleted-workspace",
                          before["result"]["content"][0]["text"])

            c.write_project_link(checkout, "proxied-app")
            after = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "attacca_status", "arguments": {}}})
            self.assertFalse(after["result"]["isError"])
            body = json.loads(after["result"]["content"][0]["text"])
            self.assertEqual(body["project"], "proxied-app")
        finally:
            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=10), 0)
            proc.stdout.close()
            proc.stderr.close()

    def test_proxy_reports_unreachable_server(self):
        proc = self._proxy(url="http://127.0.0.1:9")  # nothing listens there
        try:
            resp = self._rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
            self.assertEqual(resp.get("result"), {})
            listed = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            self.assertIn("tools", listed["result"])
            # Protocol discovery stays alive; authority-bearing calls surface
            # the hosted outage and the same proxy answers later requests.
            status = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "attacca_status", "arguments": {}}})
            self.assertTrue(status["result"]["isError"])
            self.assertRegex(
                status["result"]["content"][0]["text"].lower(),
                r"(unreachable|offline mode|offline continuity)")
            again = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 4, "method": "ping"})
            self.assertEqual(again.get("result"), {})
        finally:
            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=10), 0)
            proc.stdout.close()
            proc.stderr.close()

    def test_proxy_parse_error_local(self):
        proc = self._proxy()
        try:
            proc.stdin.write("garbage line\n")
            proc.stdin.flush()
            err = json.loads(proc.stdout.readline())
            self.assertEqual(err["error"]["code"], -32700)
        finally:
            proc.stdin.close()
            proc.wait(timeout=10)
            proc.stdout.close()
            proc.stderr.close()

    def test_proxy_local_notification_batch_has_no_response(self):
        proc = self._proxy()
        try:
            notifications = [
                {"jsonrpc": "2.0", "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "method": "tools/list"},
                {"jsonrpc": "2.0", "method": "ping"},
                {"jsonrpc": "2.0",
                 "method": "notifications/initialized"},
            ]
            proc.stdin.write(json.dumps(notifications) + "\n")
            proc.stdin.flush()
            readable, _, _ = select.select([proc.stdout], [], [], 0.25)
            self.assertEqual(readable, [])
            # The process remains usable after swallowing all notifications.
            reply = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 9, "method": "ping"})
            self.assertEqual(reply.get("result"), {})
        finally:
            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=10), 0)
            proc.stdout.close()
            proc.stderr.close()

    def test_committed_link_reuses_project_from_unrelated_checkout(self):
        other = Path(self.tmp.name) / "computer-b" / "other-path"
        nested = other / "src" / "deep"
        nested.mkdir(parents=True)
        c.write_project_link(other, "proxied-app")
        proc = self._proxy(cwd=nested)
        try:
            init = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18",
                           "capabilities": {},
                           "clientInfo": {"name": "linked", "version": "0"}}})
            self.assertIn("result", init)
            status = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "attacca_status", "arguments": {}}})
            body = json.loads(status["result"]["content"][0]["text"])
            self.assertEqual(body["project"], "proxied-app")
            conn = c.connect(self.db)
            projects = c.list_projects(conn)["projects"]
            conn.close()
            self.assertEqual([p["project_id"] for p in projects],
                             ["proxied-app"])
        finally:
            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=10), 0)
            proc.stdout.close()
            proc.stderr.close()


class TwoCodexCheckoutFlowTestCase(unittest.TestCase):
    """Permanent end-to-end proof: two Codex checkouts share one room."""

    def setUp(self):
        # Setup is expected to launch the autonomous watcher in real use.  The
        # flow tests create throwaway HOME/checkouts, so letting that detached
        # process escape the test would strand it under a deleted /tmp tree.
        self._watcher_patch = mock.patch.dict(
            os.environ, {"ATTACCA_DISABLE_WATCHER": "1"})
        self._watcher_patch.start()

    def tearDown(self):
        self._watcher_patch.stop()

    def _proxy(self, server, db, cwd, actor):
        env = dict(os.environ)
        env.pop("CLAUDE_PROJECT_DIR", None)
        env.pop("ATTACCA_PROJECT", None)
        env["ATTACCA_DB"] = str(db)
        env["ATTACCA_URL"] = server.base
        env["ATTACCA_ACTOR"] = actor
        env["ATTACCA_AUTOSTART"] = "0"
        return subprocess.Popen(
            [sys.executable, SCRIPT, "connect", "--url", server.base],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=env, cwd=str(cwd))

    def _rpc(self, proc, msg):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        self.assertTrue(line, "Codex proxy closed stdout")
        return json.loads(line)

    def _initialize(self, proc, name):
        response = self._rpc(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": name, "version": "test"}}})
        self.assertEqual(response["result"]["serverInfo"]["name"], "attacca")
        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.flush()

    def _call(self, proc, request_id, tool, arguments=None):
        response = self._rpc(proc, {
            "jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments or {}}})
        self.assertNotIn("error", response)
        self.assertFalse(response["result"].get("isError"), response)
        return json.loads(response["result"]["content"][0]["text"])

    def test_two_directories_setup_and_bidirectional_room_communication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "shared.db"
            home = root / "home"
            home.mkdir()
            a = root / "computer-a" / "checkout-one"
            b = root / "computer-b" / "totally-different-path"
            a.mkdir(parents=True)
            b.mkdir(parents=True)
            for checkout in (a, b):
                subprocess.run(["git", "init", "-q"], cwd=str(checkout),
                               check=True)
                subprocess.run(
                    ["git", "remote", "add", "origin",
                     "git@github.com:example/two-codex-flow.git"],
                    cwd=str(checkout), check=True)
            c.connect(db).close()
            server = ServerFixture(db)
            first = second = None
            try:
                setup_a = c.one_shot_remote_setup(
                    "codex_a", "agent", db, url=server.base, path=str(a),
                    manage_server=False, manage_tools=False,
                    write_instructions=False, create_project="Two Codex Flow",
                    home=str(home))
                discovery_b = c.discover_remote_setup(
                    server.base, path=str(b), actor_id="codex_b",
                    actor_type="agent")
                self.assertEqual(discovery_b["action"], "confirm_git_match")
                self.assertEqual(discovery_b["suggested_project_id"],
                                 setup_a["project_id"])
                setup_b = c.one_shot_remote_setup(
                    "codex_b", "agent", db, url=server.base, path=str(b),
                    manage_server=False, manage_tools=False,
                    write_instructions=False,
                    attach_project=setup_a["project_id"], home=str(home))
                self.assertNotEqual(setup_a["root_path"], setup_b["root_path"])
                self.assertEqual(setup_a["project_id"], setup_b["project_id"])
                self.assertTrue((a / ".attacca" / "project.json").is_file())
                self.assertTrue((b / ".attacca" / "project.json").is_file())
                network_a = c.apply_remote_network_setup(
                    server.base, setup_a["project_id"], "codex_a", "agent",
                    role="director", lead="current")
                network_b = c.apply_remote_network_setup(
                    server.base, setup_a["project_id"], "codex_b", "agent",
                    role="worker")
                self.assertEqual(network_a["actor"],
                                 "two-codex-flow.director.codex")
                self.assertEqual(network_b["actor"],
                                 "two-codex-flow.worker.codex")

                first = self._proxy(server, db, a, "codex_a")
                second = self._proxy(server, db, b, "codex_b")
                self._initialize(first, "codex-a")
                self._initialize(second, "codex-b")
                status_a = self._call(first, 2, "attacca_status")
                status_b = self._call(second, 2, "attacca_status")
                self.assertEqual(status_a["project"], setup_a["project_id"])
                self.assertEqual(status_b["project"], setup_a["project_id"])
                self.assertEqual(status_a["you"]["actor_id"],
                                 "two-codex-flow.director.codex")
                self.assertEqual(status_b["you"]["actor_id"],
                                 "two-codex-flow.worker.codex")

                sent_a = self._call(
                    first, 3, "room_send",
                    {"body": "hello from checkout A",
                     "msg_type": "directive",
                     "mentions": ["two-codex-flow.worker.codex"]})
                seen_b = self._call(
                    second, 3, "check_inbox", {"mark_read": True})
                from_a = next(m for m in seen_b["messages"]
                              if m["body"] == "hello from checkout A")
                self.assertEqual(from_a["actor"],
                                 "two-codex-flow.director.codex")
                sent_b = self._call(
                    second, 4, "room_send",
                    {"body": "reply from checkout B", "msg_type": "chat",
                     "reply_to": sent_a["event"]["event_id"],
                     "mentions": ["two-codex-flow.director.codex"]})
                seen_a = self._call(
                    first, 4, "check_inbox", {"mark_read": True})
                from_b = next(m for m in seen_a["messages"]
                              if m["body"] == "reply from checkout B")
                self.assertEqual(from_b["actor"],
                                 "two-codex-flow.worker.codex")
                self.assertEqual(from_b["reply_to"],
                                 sent_a["event"]["event_id"])
                self.assertEqual(sent_b["delivered_to"], setup_a["project_id"])

                conn = c.connect(db)
                try:
                    self.assertEqual(len(c.list_projects(conn)["projects"]), 1)
                finally:
                    conn.close()
            finally:
                for proc in (first, second):
                    if proc is None:
                        continue
                    proc.stdin.close()
                    self.assertEqual(proc.wait(timeout=10), 0,
                                     proc.stderr.read())
                    proc.stdout.close()
                    proc.stderr.close()
                server.stop()


class OneShotSetupTestCase(unittest.TestCase):
    def setUp(self):
        # Keep production's autonomous default while ensuring every setup CLI
        # spawned by this test class remains process-contained.
        self._watcher_patch = mock.patch.dict(
            os.environ, {"ATTACCA_DISABLE_WATCHER": "1"})
        self._watcher_patch.start()

    def tearDown(self):
        self._watcher_patch.stop()

    def test_tools_only_installer_does_not_touch_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "project"
            checkout.mkdir()
            home = Path(tmp) / "home"
            home.mkdir()
            db = Path(tmp) / "tools-only.db"
            conn = c.connect(db)
            old_cwd = os.getcwd()
            try:
                os.chdir(checkout)
                info = c.one_shot_setup(
                    conn, "installer", "system", db,
                    url="http://127.0.0.1:4173", manage_server=False,
                    home=str(home), tools_only=True)
            finally:
                os.chdir(old_cwd)
                conn.close()
            self.assertTrue(info["tools_only"])
            self.assertFalse((checkout / ".attacca").exists())
            self.assertEqual(list(checkout.iterdir()), [])

    def test_interactive_stdio_creates_named_workspace_without_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "unrelated-local-folder"
            checkout.mkdir()
            home = Path(tmp) / "home"
            home.mkdir()
            db = Path(tmp) / "serverless.db"
            env = dict(os.environ)
            env["HOME"] = str(home)
            env["ATTACCA_DB"] = str(db)
            proc = subprocess.run(
                [sys.executable, SCRIPT, "--db", str(db), "setup",
                 "--interactive", "--stdio", "--url",
                 "http://127.0.0.1:9", "--no-instructions"],
                cwd=str(checkout), env=env, text=True,
                input="Wanted Name\nall\n", capture_output=True,
                timeout=15)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("kimi", proc.stdout)
            link = json.loads(
                (checkout / ".attacca" / "project.json").read_text())
            self.assertEqual(link["project_id"], "wanted-name")
            conn = c.connect(db)
            self.assertEqual(c.get_project(conn, "wanted-name")["name"],
                             "Wanted Name")
            conn.close()

    def test_one_shot_setup_writes_everything_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "s.db"
            conn = c.connect(db)
            proj = Path(tmp) / "app"
            proj.mkdir()
            home = Path(tmp) / "home"
            home.mkdir()
            # pre-existing .mcp.json with another server must survive the merge
            (proj / ".mcp.json").write_text(json.dumps(
                {"mcpServers": {"other": {"command": "x"}}}))
            info = c.one_shot_setup(conn, "me", "human", db, path=str(proj),
                                    manage_server=False, home=str(home))
            self.assertTrue(info["project_created"])
            self.assertEqual(info["mode"], "server")
            merged = json.loads((proj / ".mcp.json").read_text())
            self.assertIn("other", merged["mcpServers"])
            entry = merged["mcpServers"]["attacca"]
            self.assertIn("connect", entry["args"])
            self.assertEqual(entry["env"]["ATTACCA_PROJECT"],
                             info["project_id"])
            self.assertEqual(entry["env"]["ATTACCA_URL"],
                             c.DEFAULT_URL)
            link = json.loads((proj / ".attacca" / "project.json").read_text())
            self.assertEqual(link, {"schema_version": 1,
                                    "project_id": info["project_id"]})
            self.assertEqual(info["project_link"],
                             str(proj / ".attacca" / "project.json"))
            self.assertTrue((proj / "CLAUDE.md").exists())
            self.assertTrue((proj / "AGENTS.md").exists())
            # empty fake home: nothing detected, nothing configured
            self.assertEqual(info["configured_tools"], [])
            self.assertIn("codex", info["not_detected"])
            again = c.one_shot_setup(conn, "me", "human", db, path=str(proj),
                                     manage_server=False, home=str(home))
            self.assertFalse(again["project_created"])
            self.assertEqual(again["project_id"], info["project_id"])
            # stdio variant writes a command-style entry
            c.one_shot_setup(conn, "me", "human", db, path=str(proj),
                             stdio=True, manage_server=False, home=str(home))
            entry = json.loads((proj / ".mcp.json").read_text())[
                "mcpServers"]["attacca"]
            self.assertIn("command", entry)
            conn.close()

    def test_native_claude_plugin_removes_only_duplicate_checkout_mcp(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "native.db"
            checkout = Path(tmp) / "checkout"
            checkout.mkdir()
            home = Path(tmp) / "home"
            plugin_state = home / ".claude" / "plugins"
            plugin_state.mkdir(parents=True)
            (plugin_state / "installed_plugins.json").write_text(json.dumps({
                "version": 2,
                "plugins": {"attacca@agentg": [{"scope": "user"}]},
            }))
            (checkout / ".mcp.json").write_text(json.dumps({
                "mcpServers": {
                    "attacca": {"type": "http", "url": "http://old/mcp"},
                    "other": {"command": "keep-me"},
                },
                "projectSetting": True,
            }))
            conn = c.connect(db)
            try:
                info = c.one_shot_setup(
                    conn, "me", "human", db, path=str(checkout),
                    manage_server=False, manage_tools=False,
                    write_instructions=False, home=str(home))
            finally:
                conn.close()
            self.assertEqual(info["claude_connection"], "native_plugin")
            self.assertIsNone(info["mcp_json"])
            kept = json.loads((checkout / ".mcp.json").read_text())
            self.assertEqual(kept["mcpServers"], {
                "other": {"command": "keep-me"}})
            self.assertTrue(kept["projectSetting"])

    def test_installer_reconciles_native_claude_duplicate_in_linked_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "checkout"
            nested = checkout / "src"
            plugin_state = home / ".claude" / "plugins"
            plugin_state.mkdir(parents=True)
            nested.mkdir(parents=True)
            (plugin_state / "installed_plugins.json").write_text(json.dumps({
                "version": 2,
                "plugins": {"attacca@agentg": [{"scope": "user"}]},
            }))
            c.write_project_link(checkout, "linked")
            (checkout / ".mcp.json").write_text(json.dumps({
                "mcpServers": {
                    "attacca": {"type": "http", "url": "http://old/mcp"},
                    "other": {"command": "keep-me"},
                },
                "projectSetting": True,
            }))
            result = c.reconcile_native_claude_checkout(
                path=nested, home=home)
            self.assertTrue(result["changed"])
            self.assertEqual(result["root_path"], str(checkout))
            kept = json.loads((checkout / ".mcp.json").read_text())
            self.assertEqual(kept["mcpServers"], {
                "other": {"command": "keep-me"}})
            self.assertTrue(kept["projectSetting"])

    def test_claude_cross_directory_plugin_registrations_are_uninstalled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            project = root / "project with spaces"
            local = root / "local"
            missing = root / "deleted-project"
            project.mkdir(parents=True)
            local.mkdir()
            state = home / ".claude" / "plugins" / "installed_plugins.json"
            state.parent.mkdir(parents=True)
            original = {
                "version": 2,
                "plugins": {
                    "attacca@agentg": [
                        {"scope": "user", "installPath": "/keep/user"},
                        {"scope": "project", "projectPath": str(project)},
                        {"scope": "project", "projectPath": str(project)},
                        {"scope": "local", "projectPath": str(local)},
                        {"scope": "project", "projectPath": str(missing)},
                    ],
                    "unrelated@example": [
                        {"scope": "project", "projectPath": str(project)}],
                },
            }
            state.write_text(json.dumps(original))
            completed = subprocess.CompletedProcess([], 0, "", "")
            with mock.patch.object(c.subprocess, "run",
                                   return_value=completed) as run:
                result = c.uninstall_claude_scoped_attacca_plugins(
                    home=home, claude_executable="/fake/claude")

            self.assertTrue(result["ok"])
            self.assertEqual(result["missing"], [{
                "scope": "project",
                "project_path": str(missing.resolve()),
            }])
            self.assertEqual(
                [(call.kwargs["cwd"], call.args[0])
                 for call in run.call_args_list],
                [
                    (str(project.resolve()),
                     ["/fake/claude", "plugin", "uninstall",
                      "attacca@agentg", "--scope", "project",
                      "--keep-data", "-y"]),
                    (str(local.resolve()),
                     ["/fake/claude", "plugin", "uninstall",
                      "attacca@agentg", "--scope", "local",
                      "--keep-data", "-y"]),
                ])
            self.assertEqual(json.loads(state.read_text()), original)

    def test_claude_cross_directory_cleanup_reports_invalid_state_safely(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            state = home / ".claude" / "plugins" / "installed_plugins.json"
            state.parent.mkdir(parents=True)
            state.write_text(json.dumps({
                "version": 2,
                "plugins": {"attacca@agentg": [
                    {"scope": "project", "projectPath": "relative/path"},
                    {"scope": "local"},
                ]},
            }))
            with mock.patch.object(c.subprocess, "run") as run:
                result = c.uninstall_claude_scoped_attacca_plugins(home=home)
            self.assertFalse(result["ok"])
            self.assertEqual(len(result["invalid"]), 2)
            run.assert_not_called()

    def test_universal_installer_kimi_native_state_is_idempotent_and_deduped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            source = root / "downloaded-attacca"
            kimi = home / ".kimi-code"
            plugins = kimi / "plugins"
            source.mkdir(parents=True)
            plugins.mkdir(parents=True)
            (source / "kimi.plugin.json").write_text(json.dumps({
                "name": "attacca", "version": "9.9.9",
                "mcpServers": {"attacca": {"command": "python3"}},
            }))
            (source / "attacca.py").write_text("# managed plugin marker\n")
            (plugins / "installed.json").write_text(json.dumps({
                "version": 1,
                "plugins": [
                    {"id": "other", "root": "/keep/other", "enabled": True},
                    {"id": "attacca", "root": "/stale/attacca",
                     "source": "zip-url", "enabled": False,
                     "installedAt": "2026-01-01T00:00:00.000Z",
                     "capabilities": {"mcpServers": {
                         "attacca": {"enabled": True}}}},
                ],
            }))
            (kimi / "mcp.json").write_text(json.dumps({
                "mcpServers": {
                    "attacca": {"command": "old-global"},
                    "other": {"command": "keep-me"},
                },
                "setting": True,
            }))

            first = c.install_kimi_native_plugin(source, home=home)
            second = c.install_kimi_native_plugin(source, home=home)
            self.assertTrue(first["removed_global_mcp"])
            self.assertIsNone(second["removed_global_mcp"])
            installed = json.loads((plugins / "installed.json").read_text())
            entries = [item for item in installed["plugins"]
                       if item.get("id") == "attacca"]
            self.assertEqual(len(entries), 1)
            self.assertFalse(entries[0]["enabled"])
            self.assertEqual(entries[0]["installedAt"],
                             "2026-01-01T00:00:00.000Z")
            self.assertEqual(entries[0]["capabilities"], {
                "mcpServers": {"attacca": {"enabled": True}}})
            self.assertEqual(
                (Path(entries[0]["root"]) / "attacca.py").read_text(),
                "# managed plugin marker\n")
            self.assertEqual([item["id"] for item in installed["plugins"]],
                             ["other", "attacca"])
            remaining = json.loads((kimi / "mcp.json").read_text())
            self.assertEqual(remaining["mcpServers"], {
                "other": {"command": "keep-me"}})
            self.assertTrue(remaining["setting"])

    def test_kimi_managed_install_restores_previous_plugin_on_swap_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            source = root / "downloaded-attacca"
            managed_parent = home / ".kimi-code" / "plugins" / "managed"
            managed = managed_parent / "attacca"
            installed_path = managed_parent.parent / "installed.json"
            source.mkdir(parents=True)
            managed.mkdir(parents=True)
            (source / "kimi.plugin.json").write_text(json.dumps({
                "name": "attacca", "version": "9.9.9",
            }))
            (source / "attacca.py").write_text("# replacement\n")
            (managed / "attacca.py").write_text("# working version\n")
            original_state = {
                "version": 1,
                "plugins": [{
                    "id": "attacca", "root": str(managed),
                    "source": "local-path", "enabled": True,
                }],
            }
            installed_path.write_text(json.dumps(original_state))
            real_replace = os.replace
            failure_injected = [False]

            def fail_replacement_once(source_path, target_path):
                source_name = Path(source_path).name
                if (Path(target_path) == managed and
                        not source_name.startswith(".attacca-backup-") and
                        not failure_injected[0]):
                    failure_injected[0] = True
                    raise OSError("injected managed plugin swap failure")
                return real_replace(source_path, target_path)

            with mock.patch.object(c.os, "replace",
                                   side_effect=fail_replacement_once):
                with self.assertRaisesRegex(
                        OSError, "injected managed plugin swap failure"):
                    c.install_kimi_native_plugin(source, home=home)

            self.assertTrue(failure_injected[0])
            self.assertEqual((managed / "attacca.py").read_text(),
                             "# working version\n")
            self.assertEqual(json.loads(installed_path.read_text()),
                             original_state)
            self.assertEqual(
                sorted(path.name for path in managed_parent.iterdir()),
                ["attacca"])

    def test_guided_network_setup_sets_role_lead_master_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "network.db"
            current = Path(tmp) / "current"
            master = Path(tmp) / "master"
            current.mkdir()
            master.mkdir()
            conn = c.connect(db)
            c.project_init(conn, "admin", "human", path=str(current),
                           project_id="current", name="Current App")
            c.project_init(conn, "admin", "human", path=str(master),
                           project_id="master", name="Master Control")
            conn.close()
            server = ServerFixture(db)
            actor = "jack.codex_director"
            try:
                first = c.apply_remote_network_setup(
                    server.base, "current", actor, "agent",
                    role="director", lead="current", bridge="master",
                    relationship="master", principal_side="other")
                self.assertEqual(
                    [action["kind"] for action in first["actions"]],
                    ["role", "lead", "bridge"])
                second = c.apply_remote_network_setup(
                    server.base, "current", actor, "agent",
                    role="director", lead="current", bridge="master",
                    relationship="master", principal_side="other")
                bridge_action = next(
                    action for action in second["actions"]
                    if action["kind"] == "bridge")
                self.assertTrue(bridge_action["unchanged"])
                c.remote_json(
                    server.base, "POST", "/v1/projects/master/room",
                    {"body": "Please join the shared delivery room",
                     "msg_type": "directive", "mentions": [actor],
                     "target_project": "current"},
                    actor="master.director", actor_type="agent")
                discovery = c.discover_remote_setup(
                    server.base, path=str(current), actor_id=actor,
                    actor_type="agent", selected_project_id="current")
                network = discovery["network"]
                self.assertEqual(network["lead_director"],
                                 "current.director.codex")
                self.assertEqual(
                    network["current_actor_record"]["role"], "director")
                self.assertEqual(network["default_relationship"], "master")
                self.assertEqual(network["existing_relationships"][0]["with"],
                                 "master")
                self.assertEqual(
                    network["relationship_inbox"][-1]["origin_project"],
                    "master")
                removed = c.apply_remote_network_setup(
                    server.base, "current", actor, "agent", bridge="master",
                    relationship="none")
                self.assertEqual(removed["actions"][-1]["kind"],
                                 "bridge_removed")
            finally:
                server.stop()

    def test_one_command_setup_assigns_actual_ai_not_shell_user(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "guided.db"
            checkout = root / "checkout"
            home = root / "home"
            checkout.mkdir()
            home.mkdir()
            c.connect(db).close()
            bootstrap = c.connect(db)
            try:
                created = c.auth_create_user(
                    bootstrap, "owner", "owner-pass-1234",
                    display_name="Owner", is_admin=True, bootstrap=True)
                user = bootstrap.execute(
                    "SELECT * FROM auth_users WHERE user_id=?",
                    (created["user"]["user_id"],)).fetchone()
                principal = c._auth_principal(
                    bootstrap, user, "session")
                c.project_init(
                    bootstrap, "owner", "human", path=str(checkout),
                    project_id="current-app", name="Current App")
                c.auth_grant_project_membership(
                    bootstrap, principal, "current-app")
                client_instance = "client_setup_attribution_test"
                key = c.auth_client_key_create(
                    bootstrap, principal, "Setup test", client_instance,
                    memberships=[])["token"]
            finally:
                bootstrap.close()
            server = ServerFixture(db)
            env = dict(os.environ)
            env.update({"HOME": str(home), "USER": "vscode",
                        "ATTACCA_DB": str(root / "unused-client.db"),
                        "ATTACCA_OWNER": "",
                        "ATTACCA_API_TOKEN": key,
                        "ATTACCA_CLIENT_INSTANCE": client_instance})
            try:
                proc = subprocess.run(
                    [sys.executable, SCRIPT,
                     "--actor", "jack.codex_director",
                     "--actor-type", "agent", "setup",
                     "--url", server.base, "--no-server",
                     "--attach", "current-app", "--role", "director",
                     "--lead", "current", "--skip-tools", "all",
                     "--no-instructions"],
                    cwd=str(checkout), env=env, text=True,
                    capture_output=True, timeout=20)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn("AI Network", proc.stdout)
                self.assertIn("portable workspace link (safe to commit)",
                              proc.stdout)
                status, agents, _ = server.request(
                    "GET", "/v1/projects/current-app/agents")
                self.assertEqual(status, 200)
                self.assertEqual(
                    [(agent["agent_id"], agent["role"])
                     for agent in agents["agents"]],
                    [("current-app.director.codex", "director")])
                _, project_status, _ = server.request(
                    "GET", "/v1/projects/current-app/status",
                    headers={"X-Attacca-Actor": "auditor"})
                self.assertEqual(project_status["lead_director"],
                                 "current-app.director.codex")
                self.assertNotIn(
                    "vscode", [agent["agent_id"] for agent in agents["agents"]])
                watcher_state = json.loads(
                    (home / ".attacca" / "watcher" /
                     "watcher-state.json").read_text())
                self.assertNotIn("daemon", watcher_state)
                self.assertNotIn("daemon_launch", watcher_state)
            finally:
                server.stop()

    def test_setup_here_forces_nested_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "s.db"
            conn = c.connect(db)
            parent = Path(tmp) / "parent"
            nested = parent / "sub"
            nested.mkdir(parents=True)
            home = Path(tmp) / "home"
            home.mkdir()
            c.project_init(conn, "me", "human", path=str(parent),
                           project_id="parent")
            attached = c.one_shot_setup(conn, "me", "human", db,
                                        path=str(nested), manage_server=False,
                                        home=str(home))
            self.assertEqual(attached["project_id"], "parent")
            self.assertTrue(attached["cwd_inside_root"])
            own = c.one_shot_setup(conn, "me", "human", db, path=str(nested),
                                   here=True, manage_server=False,
                                   home=str(home))
            self.assertEqual(own["project_id"], "sub")
            self.assertFalse(own["cwd_inside_root"])
            conn.close()

    def test_remote_attach_writes_only_computer_b_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "remote.db"
            computer_a = Path(tmp) / "computer-a" / "repo"
            computer_b = Path(tmp) / "computer-b" / "different-dir"
            computer_a.mkdir(parents=True)
            computer_b.mkdir(parents=True)
            conn = c.connect(db)
            c.project_init(conn, "setup", "human", path=str(computer_a),
                           project_id="shared", name="Shared")
            conn.close()
            server = ServerFixture(db)
            home = Path(tmp) / "home"
            home.mkdir()
            try:
                info = c.one_shot_remote_setup(
                    "me", "human", db, url=server.base,
                    path=str(computer_b), manage_server=False,
                    manage_tools=False, write_instructions=False,
                    attach_project="shared", home=str(home))
                self.assertEqual(info["project_id"], "shared")
                self.assertEqual(info["root_path"], str(computer_b))
                self.assertTrue((computer_b / ".attacca" / "project.json").is_file())
                self.assertTrue((computer_b / ".mcp.json").is_file())
                self.assertFalse((computer_a / ".attacca").exists())
                conn = c.connect(db)
                stored = c.get_project(conn, "shared")
                conn.close()
                self.assertEqual(stored["root_path"], str(computer_a))
            finally:
                server.stop()

    def test_remote_setup_requires_explicit_choice(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "remote.db"
            checkout = Path(tmp) / "checkout"
            checkout.mkdir()
            server = ServerFixture(db)
            try:
                with self.assertRaisesRegex(c.AttaccaError,
                                            "create the first one"):
                    c.one_shot_remote_setup(
                        "me", "human", db, url=server.base,
                        path=str(checkout), manage_server=False,
                        manage_tools=False, write_instructions=False)
                self.assertFalse((checkout / ".attacca").exists())
                info = c.one_shot_remote_setup(
                    "me", "human", db, url=server.base,
                    path=str(checkout), manage_server=False,
                    manage_tools=False, write_instructions=False,
                    create_project="Chosen Workspace")
                self.assertEqual(info["project_id"], "chosen-workspace")
            finally:
                server.stop()

    def test_discovery_suggests_matching_git_workspace_for_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "remote.db"
            checkout = Path(tmp) / "any-local-directory"
            checkout.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=str(checkout),
                           check=True)
            subprocess.run(
                ["git", "remote", "add", "origin",
                 "git@github.com:acme/shared-app.git"], cwd=str(checkout),
                check=True)
            fingerprint = c.git_repository_fingerprint(checkout)
            conn = c.connect(db)
            c.project_init(conn, "setup", "human",
                           path=str(Path(tmp) / "computer-a"),
                           project_id="team-workspace",
                           repository_fingerprint=fingerprint)
            conn.close()
            server = ServerFixture(db)
            try:
                discovery = c.discover_remote_setup(
                    server.base, path=str(checkout), actor_id="me",
                    actor_type="human")
                self.assertEqual(discovery["git"]["remote"],
                                 "github.com/acme/shared-app")
                self.assertEqual(discovery["action"], "confirm_git_match")
                self.assertEqual(discovery["suggested_project_id"],
                                 "team-workspace")
                self.assertTrue(discovery["workspaces"][0]["git_match"])
            finally:
                server.stop()

    def test_discovery_reports_stale_link_and_normal_workspace_choices(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "remote.db"
            checkout = Path(tmp) / "checkout"
            checkout.mkdir()
            c.write_project_link(checkout, "deleted-workspace")
            conn = c.connect(db)
            c.project_init(conn, "setup", "human",
                           path=str(Path(tmp) / "shared-source"),
                           project_id="shared", name="Shared Workspace")
            conn.close()
            server = ServerFixture(db)
            try:
                discovery = c.discover_remote_setup(
                    server.base, path=str(checkout), actor_id="codex",
                    actor_type="agent")
                self.assertEqual(discovery["stale_link"], {
                    "project_id": "deleted-workspace",
                    "path": str(checkout / ".attacca" / "project.json"),
                })
                self.assertIsNone(discovery["linked_project_id"])
                self.assertEqual(discovery["action"], "choose_or_create")
                self.assertIsNone(discovery["suggested_project_id"])
                self.assertEqual(
                    [(workspace["project_id"], workspace["name"])
                     for workspace in discovery["workspaces"]],
                    [("shared", "Shared Workspace")])
                self.assertEqual(
                    json.loads((checkout / ".attacca" / "project.json").read_text())[
                        "project_id"],
                    "deleted-workspace")
            finally:
                server.stop()

    def test_discovery_defaults_non_git_folder_to_named_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "remote.db"
            checkout = Path(tmp) / "html"
            checkout.mkdir()
            conn = c.connect(db)
            for project_id in ("vscode", "agentg", "html"):
                c.project_init(conn, "setup", "human",
                               path=str(Path(tmp) / (project_id + "-source")),
                               project_id=project_id, name=project_id)
            conn.close()
            server = ServerFixture(db)
            try:
                discovery = c.discover_remote_setup(
                    server.base, path=str(checkout), actor_id="codex",
                    actor_type="agent")
                self.assertFalse(discovery["git"]["detected"])
                self.assertEqual(discovery["action"], "confirm_folder_match")
                self.assertEqual(discovery["suggested_project_id"], "html")
                self.assertEqual(discovery["match_reason"], "folder")
                self.assertEqual(discovery["suggested_new_name"], "html")
                html = next(p for p in discovery["workspaces"]
                            if p["project_id"] == "html")
                self.assertTrue(html["folder_match"])
            finally:
                server.stop()

    def test_discovery_suggests_current_folder_for_first_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "empty.db"
            checkout = Path(tmp) / "my-site"
            checkout.mkdir()
            c.connect(db).close()
            server = ServerFixture(db)
            try:
                discovery = c.discover_remote_setup(
                    server.base, path=str(checkout), actor_id="codex",
                    actor_type="agent")
                self.assertEqual(discovery["action"],
                                 "create_first_workspace")
                self.assertEqual(discovery["suggested_new_name"], "my-site")
            finally:
                server.stop()


class UniversalConnectTestCase(unittest.TestCase):
    """connect_tools against a fake $HOME with several tools 'installed'."""

    def test_connect_tools_detection_and_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "proj"
            root.mkdir()
            db = Path(tmp) / "c.db"
            # "install" codex, cursor, cline, windsurf, gemini, vscode
            (home / ".codex").mkdir(parents=True)
            (home / ".codex" / "config.toml").write_text(
                '[model]\nname = "gpt"\n')
            (home / ".cursor").mkdir()
            (home / ".cursor" / "mcp.json").write_text(json.dumps(
                {"mcpServers": {"existing": {"url": "http://x/"}}}))
            cline_dir = home / (".config/Code/User/globalStorage/"
                                "saoudrizwan.claude-dev/settings")
            cline_dir.mkdir(parents=True)
            (home / ".codeium" / "windsurf").mkdir(parents=True)
            (home / ".gemini").mkdir()
            (root / ".vscode").mkdir()
            (home / ".config" / "opencode").mkdir(parents=True)
            configured, missing = c.connect_tools(
                "proj", str(root), db, url="http://127.0.0.1:9999",
                home=str(home))
            tools = {entry["tool"] for entry in configured}
            self.assertEqual(tools, {"codex", "cline", "cursor", "windsurf",
                                     "gemini", "vscode", "opencode"})
            self.assertNotIn("opencode", missing)
            # codex: original content preserved, connect-proxy block appended,
            # backup kept — one GLOBAL config, project auto-detected per cwd
            codex = (home / ".codex" / "config.toml").read_text()
            self.assertIn('[model]', codex)
            self.assertIn("[mcp_servers.attacca]", codex)
            self.assertIn('"connect"', codex)
            self.assertIn('"ATTACCA_URL" = "http://127.0.0.1:9999"', codex)
            self.assertTrue((home / ".codex" / "config.toml.attacca-backup").exists())
            # rerun replaces (idempotent), not duplicates
            c.connect_tools("proj", str(root), db,
                            url="http://127.0.0.1:8888", home=str(home))
            codex = (home / ".codex" / "config.toml").read_text()
            self.assertEqual(codex.count("[mcp_servers.attacca]"), 1)
            self.assertIn('"ATTACCA_URL" = "http://127.0.0.1:8888"', codex)
            # cursor: existing entry preserved, connect proxy with actor env
            cursor = json.loads((home / ".cursor" / "mcp.json").read_text())
            self.assertIn("existing", cursor["mcpServers"])
            entry = cursor["mcpServers"]["attacca"]
            self.assertIn("connect", entry["args"])
            self.assertEqual(entry["env"]["ATTACCA_ACTOR"], "cursor")
            # cline gets the stdio form (portable across cline versions)
            cline = json.loads(
                (cline_dir / "cline_mcp_settings.json").read_text())
            self.assertIn("command", cline["mcpServers"]["attacca"])
            # vscode uses the "servers" key
            vscode = json.loads((root / ".vscode" / "mcp.json").read_text())
            self.assertIn("attacca", vscode["servers"])
            # gemini project settings written
            gemini = json.loads(
                (root / ".gemini" / "settings.json").read_text())
            gemini_entry = gemini["mcpServers"]["attacca"]
            self.assertIn("connect", gemini_entry["args"])
            self.assertEqual(gemini_entry["env"]["ATTACCA_PROJECT"], "proj")
            self.assertNotIn("httpUrl", gemini_entry)
            self.assertEqual(vscode["servers"]["attacca"]["type"], "stdio")
            self.assertIn("connect", vscode["servers"]["attacca"]["args"])
            opencode = json.loads((root / "opencode.json").read_text())
            opencode_entry = opencode["mcp"]["attacca"]
            self.assertEqual(opencode_entry["type"], "local")
            self.assertIn("connect", opencode_entry["command"])
            self.assertEqual(
                opencode_entry["environment"]["ATTACCA_PROJECT"], "proj")
            # skip filter respected
            configured, _ = c.connect_tools(
                "proj", str(root), db, home=str(home),
                skip={"codex", "cline", "cursor", "windsurf", "gemini",
                      "vscode", "opencode"})
            self.assertEqual(configured, [])

    def test_codex_home_override_is_respected(self):
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp) / "custom-codex-home"
            previous = os.environ.get("CODEX_HOME")
            os.environ["CODEX_HOME"] = str(codex_home)
            try:
                target = c.configure_codex(
                    None, "http://127.0.0.1:9999", Path(tmp) / "db")
            finally:
                if previous is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = previous
            self.assertEqual(target, str(codex_home / "config.toml"))
            text = (codex_home / "config.toml").read_text()
            self.assertIn("[mcp_servers.attacca]", text)


class EnsureServerTestCase(unittest.TestCase):
    def test_ensure_server_running_starts_and_reuses(self):
        import socket, signal
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "auto.db"
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            sock.close()
            url = "http://127.0.0.1:%d" % port
            first = c.ensure_server_running(url, db)
            try:
                self.assertTrue(first["started"])
                self.assertTrue(first["pid"])
                self.assertTrue(Path(first["log"]).exists())
                self.assertTrue(c.server_alive(url))
                second = c.ensure_server_running(url, db)
                self.assertFalse(second["started"])  # reused, not respawned
            finally:
                os.kill(first["pid"], signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
