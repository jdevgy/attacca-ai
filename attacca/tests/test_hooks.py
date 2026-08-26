"""Codex plugin lifecycle hook tests."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "session_start.py"
SPEC = importlib.util.spec_from_file_location("attacca_hooks_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)
HOOK_SPEC = importlib.util.spec_from_file_location(
    "attacca_session_hook_test", HOOK)
hook_module = importlib.util.module_from_spec(HOOK_SPEC)
HOOK_SPEC.loader.exec_module(hook_module)


def next_patch(version):
    core = str(version).split("+", 1)[0].split("-", 1)[0]
    major, minor, patch = (int(part) for part in core.split("."))
    return "%d.%d.%d" % (major, minor, patch + 1)


class CodexSessionStartHookTestCase(unittest.TestCase):
    def _server_advertising(self, addr, db, version):
        """Build a health-version test double without an incoherent bundle."""
        snapshot = dict(c._capture_distribution_snapshot())
        snapshot["version"] = version
        with mock.patch.object(
                c, "_capture_distribution_snapshot",
                return_value=c.MappingProxyType(snapshot)):
            return c.AttaccaServer(addr, db)

    def _actor_id(self, runtime="codex", project_id="shared", role=None):
        return c.canonical_agent_id(project_id, role, runtime)

    def _register_actor(self, conn, project_id, runtime, role):
        actor = self._actor_id(runtime, project_id, role)
        c.agent_register(conn, project_id, actor, "agent", role=role,
                         runtime="hook-test-%s" % runtime)
        return actor

    def _hook(self, cwd, data_dir, home, url=None, runtime="codex",
              event="SessionStart", stop_hook_active=False):
        env = dict(os.environ)
        if runtime == "codex":
            env["PLUGIN_ROOT"] = str(ROOT)
            env["PLUGIN_DATA"] = str(data_dir)
            env.pop("CLAUDE_PLUGIN_ROOT", None)
            env.pop("CLAUDE_PLUGIN_DATA", None)
            env.pop("KIMI_PLUGIN_ROOT", None)
        elif runtime == "claude":
            env.pop("PLUGIN_ROOT", None)
            env.pop("PLUGIN_DATA", None)
            env["CLAUDE_PLUGIN_ROOT"] = str(ROOT)
            env["CLAUDE_PLUGIN_DATA"] = str(data_dir)
            env.pop("KIMI_PLUGIN_ROOT", None)
        else:
            env.pop("PLUGIN_ROOT", None)
            env.pop("PLUGIN_DATA", None)
            env.pop("CLAUDE_PLUGIN_ROOT", None)
            env.pop("CLAUDE_PLUGIN_DATA", None)
            env["KIMI_PLUGIN_ROOT"] = str(ROOT)
            env["KIMI_CODE_HOME"] = str(Path(home) / ".kimi-code")
        env["HOME"] = str(home)
        env["ATTACCA_OWNER"] = ""
        env["ATTACCA_DISABLE_WATCHER"] = "1"
        env["ATTACCA_WATCHER_DIR"] = str(Path(home) / ".attacca-watcher-test")
        if runtime == "kimi":
            env.pop("ATTACCA_ACTOR", None)
        else:
            env["ATTACCA_ACTOR"] = runtime
        if url:
            env["ATTACCA_URL"] = url
        payload = {"cwd": str(cwd), "hook_event_name": event}
        if event == "SessionStart":
            payload["source"] = "startup"
        if event == "Stop":
            payload["stop_hook_active"] = stop_hook_active
        return subprocess.run(
            [sys.executable, str(HOOK)], cwd=str(cwd), env=env,
            input=json.dumps(payload),
            capture_output=True, text=True, timeout=10, check=True)

    def _poll_state(self, data_dir):
        return json.loads((Path(data_dir) / "setup-prompts.json").read_text())

    def _expire_polls(self, data_dir):
        path = Path(data_dir) / "setup-prompts.json"
        state = json.loads(path.read_text())
        self.assertTrue(state.get("polls"))
        for entry in state["polls"].values():
            entry["last_poll_at"] = 0
        path.write_text(json.dumps(state))

    def _startup_actor(self, result):
        payload = json.loads(result.stdout)
        context = payload["hookSpecificOutput"]["additionalContext"]
        return json.loads(context.rsplit("\n\n", 1)[1])["actor"]

    def test_terminal_recovery_distinguishes_foreground_browser_from_idle_poll(self):
        captured = []

        class TerminalModule:
            @staticmethod
            def safe_recovery_result(_server, operation):
                return operation()

            @staticmethod
            def advance_device_flow(server, **kwargs):
                captured.append((server, kwargs))
                return {
                    "status": "pending",
                    "verification_uri": "https://attacca.test/app",
                    "user_code": "ABCD-1234",
                }

        status = {"project_id": "shared"}
        config = {"url": "https://attacca.test", "actor": "codex"}
        entry = {
            "canonical_actor_id": "shared.director.codex",
            "runtime": "codex",
        }
        with mock.patch.object(
                hook_module, "_terminal_flow_module",
                return_value=TerminalModule()), \
             mock.patch.object(hook_module, "_local_device_id",
                               return_value="dev_test"), \
             mock.patch.object(hook_module, "_client_instance_id",
                               return_value="client_codex_test"):
            hook_module._terminal_flow_progress(
                status, config, entry, open_browser=True)
            hook_module._terminal_flow_progress(
                status, config, entry, open_browser=False)
        self.assertTrue(captured[0][1]["open_browser"])
        self.assertFalse(captured[1][1]["open_browser"])
        for _, kwargs in captured:
            self.assertEqual(kwargs["device_id"], "dev_test")
            self.assertEqual(kwargs["client_instance_id"],
                             "client_codex_test")
            self.assertIn("Attacca terminal", kwargs["client_label"])
            self.assertNotIn("Codex", kwargs["client_label"])
            self.assertNotIn("shared", kwargs["client_label"])
            self.assertEqual(kwargs["requested_bindings"], [{
                "project_id": "shared",
                "actor_id": "shared.director.codex",
                "runtime": "codex",
            }])

    def test_active_auth_output_opens_browser_but_background_notice_does_not(self):
        recovery = mock.Mock(return_value={
            "message": "Open https://attacca.test/app",
            "result": {"status": "pending"},
            "notice": {},
        })
        status = {"project_id": "shared"}
        config = {"url": "https://attacca.test", "actor": "codex"}
        entry = {"canonical_actor_id": "shared.director.codex"}
        with mock.patch.object(
                hook_module, "_watcher_subscription_entry",
                return_value=("key", entry)), \
             mock.patch.object(hook_module, "_terminal_flow_notice", recovery):
            hook_module._authentication_required_output(
                status, config, "UserPromptSubmit",
                hook_module.HostedAuthenticationRequired("revoked", 401))
            active = recovery.call_args
            recovery.reset_mock()
            hook_module._authentication_required_output(
                status, config, "Stop",
                hook_module.HostedAuthenticationRequired("revoked", 401))
            idle = recovery.call_args
        self.assertTrue(active.kwargs["open_browser"])
        self.assertFalse(idle.kwargs["open_browser"])

    def test_healthy_lifecycle_never_starts_optional_terminal_enrollment(self):
        """Healthy hooks do not even create an optional enrollment flow."""
        status = {"project_id": "shared"}
        config = {"url": "https://attacca.test", "actor": "codex"}
        entry = {
            "canonical_actor_id": "shared.director.codex",
            "runtime": "codex",
        }
        with mock.patch.object(
                hook_module, "_terminal_flow_progress") as progress, \
             mock.patch.object(
                 hook_module, "_terminal_flow_notice") as visible_notice:
            for event_name in ("SessionStart", "UserPromptSubmit", "Stop"):
                self.assertIsNone(hook_module._terminal_migration_notice(
                    status, config, event_name, entry))
        progress.assert_not_called()
        visible_notice.assert_not_called()

    def test_healthy_stop_creates_no_terminal_flow_or_server_enrollment(self):
        """A full compatibility lifecycle stays out of authentication state."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            data = root / "plugin-data"
            link_dir = checkout / ".attacca"
            home.mkdir()
            link_dir.mkdir(parents=True)
            (link_dir / "project.json").write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            db = root / "hook.db"
            conn = c.connect(db)
            c.project_init(conn, "setup", "human", path=str(checkout),
                           project_id="shared")
            self._register_actor(conn, "shared", "codex", "worker")
            conn.close()
            server = c.AttaccaServer(("127.0.0.1", 0), db)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]
                startup = self._hook(checkout, data, home, url=url)
                stopped = self._hook(
                    checkout, data, home, url=url, event="Stop")
                combined = startup.stdout + stopped.stdout
                self.assertNotIn(
                    "ATTACCA SECURE TERMINAL AUTHORIZATION", combined)
                self.assertFalse(
                    (home / ".attacca" / "terminal-flow.json").exists())
                conn = c.connect(db)
                enrollments = conn.execute(
                    "SELECT COUNT(*) FROM auth_device_enrollments").fetchone()[0]
                conn.close()
                self.assertEqual(enrollments, 0)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_hook_manifest_registers_all_active_update_boundaries(self):
        manifest = json.loads((ROOT / "hooks" / "hooks.json").read_text())
        hooks = manifest["hooks"]
        self.assertEqual(set(hooks),
                         {"SessionStart", "UserPromptSubmit", "Stop"})
        self.assertEqual(hooks["SessionStart"][0]["matcher"],
                         "startup|resume|clear|compact")
        commands = []
        for event in ("SessionStart", "UserPromptSubmit", "Stop"):
            command = hooks[event][0]["hooks"][0]
            self.assertEqual(command["type"], "command")
            self.assertGreaterEqual(command["timeout"], 8)
            self.assertIn("hooks/session_start.py", command["command"])
            self.assertEqual(
                command["command"],
                'python3 "$HOME/.attacca/plugin/attacca/hooks/session_start.py"')
            commands.append(command["command"])
        self.assertEqual(len(set(commands)), 1)

    def test_codex_marker_sets_identity_without_mixing_cached_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            claude_root = Path(tmp) / "claude-plugin"
            codex_root = Path(tmp) / "codex-cache"
            claude_root.mkdir()
            codex_root.mkdir()
            (codex_root / "attacca.py").write_text("VERSION = 'test'\n")
            (codex_root / ".mcp.json").write_text(json.dumps({
                "mcpServers": {"attacca": {"env": {
                    "ATTACCA_ACTOR": "codex"}}}}))
            with mock.patch.dict(os.environ, {
                    "PLUGIN_ROOT": str(codex_root),
                    "CLAUDE_PLUGIN_ROOT": str(claude_root),
                    "ATTACCA_URL": "http://attacca.test:4173",
                "ATTACCA_ACTOR": "codex"}, clear=True):
                self.assertEqual(hook_module._runtime_name(), "codex")
                plugin_root, config = hook_module._plugin_and_config()
                self.assertEqual(plugin_root, ROOT.resolve())
                self.assertEqual(config["actor"], "codex")
                self.assertEqual(
                    hook_module._runtime_actor(config, "shared")["runtime"],
                    "codex")

    def test_deleted_codex_cache_root_falls_back_to_stable_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = Path(tmp) / "deleted-codex-cache"
            stale_alias = Path(tmp) / "deleted-claude-alias"
            with mock.patch.dict(os.environ, {
                    "PLUGIN_ROOT": str(stale),
                    "CLAUDE_PLUGIN_ROOT": str(stale_alias),
                }, clear=True):
                self.assertEqual(hook_module._runtime_name(), "codex")
                plugin_root, config = hook_module._plugin_and_config()
                self.assertEqual(plugin_root, ROOT.resolve())
                self.assertEqual(config["actor"], "codex")
                output = hook_module._hook_output({
                    "folder": "repo", "root": str(Path(tmp) / "repo")})
                context = output["hookSpecificOutput"]["additionalContext"]
                self.assertIn("invoke `$attacca:setup`", context)
                self.assertIn("active AI invokes", context)
                self.assertNotIn("python3 ", context)
                self.assertNotIn(str(stale / "attacca.py"), context)

    def test_deleted_claude_cache_root_keeps_claude_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = Path(tmp) / "deleted-claude-cache"
            with mock.patch.dict(os.environ, {
                    "CLAUDE_PLUGIN_ROOT": str(stale),
                }, clear=True):
                self.assertEqual(hook_module._runtime_name(), "claude")
                plugin_root, config = hook_module._plugin_and_config()
                self.assertEqual(plugin_root, ROOT.resolve())
                self.assertEqual(config["actor"], "claude")
                self.assertEqual(
                    hook_module._runtime_actor(config, "shared")["runtime"],
                    "claude")

    def test_kimi_native_manifest_runtime_and_hook_output_contract(self):
        manifest = json.loads((ROOT / "kimi.plugin.json").read_text())
        self.assertEqual(manifest["commands"], "./kimi-commands/")
        self.assertEqual(manifest["skills"], "./kimi-skills/")
        self.assertEqual(manifest["sessionStart"]["skill"],
                         "attacca-session")
        events = [hook["event"] for hook in manifest["hooks"]]
        self.assertEqual(events, ["UserPromptSubmit", "Stop"])
        self.assertNotIn("SessionStart", events)
        self.assertNotIn("SessionHeartbeat", events)
        for hook in manifest["hooks"]:
            self.assertEqual(hook["command"],
                             "python3 ./hooks/session_start.py")

        with mock.patch.dict(os.environ, {
                "KIMI_PLUGIN_ROOT": str(ROOT),
                "CLAUDE_PLUGIN_ROOT": "/ignored/claude/plugin"}, clear=True):
            plugin_root, config = hook_module._plugin_and_config()
            self.assertEqual(plugin_root, ROOT.resolve())
            self.assertEqual(config["actor"], "kimi")
            expected_url = next(iter(
                manifest["mcpServers"].values()))["env"]["ATTACCA_URL"]
            self.assertEqual(config["url"], expected_url)
            self.assertEqual(hook_module._runtime_actor(
                config, "shared")["runtime"], "kimi")

            prompt = hook_module._event_context_output(
                "UserPromptSubmit", "changed", "shared update")
            self.assertEqual(prompt, {"message": "shared update"})
            stopped = hook_module._event_context_output(
                "Stop", "changed", "continue for shared update")
            self.assertEqual(stopped["message"],
                             "continue for shared update")
            self.assertEqual(stopped["hookSpecificOutput"], {
                "permissionDecision": "deny",
                "permissionDecisionReason": "continue for shared update",
            })
            self.assertNotIn("decision", stopped)

    def test_kimi_inline_hooks_emit_changed_updates_in_native_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            plugin_data = (home / ".attacca" / "plugin-data" /
                           "codex-attacca")
            link_dir = checkout / ".attacca"
            home.mkdir()
            link_dir.mkdir(parents=True)
            (link_dir / "project.json").write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            db = root / "hook.db"
            conn = c.connect(db)
            c.project_init(conn, "setup", "human", path=str(checkout),
                           project_id="shared")
            actor = self._register_actor(conn, "shared", "kimi", "worker")
            c.room_send(conn, "shared", "other", "human",
                        "Kimi prompt boundary update", mentions=[actor])
            conn.close()
            server = c.AttaccaServer(("127.0.0.1", 0), db)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]
                prompted = self._hook(
                    checkout, root / "unused", home, url=url,
                    runtime="kimi", event="UserPromptSubmit")
                prompt_payload = json.loads(prompted.stdout)
                self.assertEqual(set(prompt_payload), {"message"})
                self.assertIn("ATTACCA AUTOMATIC UPDATE",
                              prompt_payload["message"])
                self.assertIn("Kimi prompt boundary update",
                              prompt_payload["message"])

                conn = c.connect(db)
                c.room_send(conn, "shared", "other", "human",
                            "Kimi stop boundary update", mentions=[actor])
                conn.close()
                self._expire_polls(plugin_data)
                stopped = self._hook(
                    checkout, root / "unused", home, url=url,
                    runtime="kimi", event="Stop")
                stop_payload = json.loads(stopped.stdout)
                self.assertIn("Kimi stop boundary update",
                              stop_payload["message"])
                decision = stop_payload["hookSpecificOutput"]
                self.assertEqual(decision["permissionDecision"], "deny")
                self.assertIn("Kimi stop boundary update",
                              decision["permissionDecisionReason"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_unlinked_folder_asks_once_with_numbered_codex_choices(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "var" / "www" / "html"
            data = root / "plugin-data"
            home.mkdir()
            checkout.mkdir(parents=True)
            # Keep this setup-choice contract independent of any compatible
            # managed-law update advertised by a developer's running server.
            first = self._hook(
                checkout, data, home, url="http://127.0.0.1:1")
            payload = json.loads(first.stdout)
            self.assertIn("type 1 or 2", payload["systemMessage"])
            context = payload["hookSpecificOutput"]["additionalContext"]
            self.assertIn("type 1 or 2", context)
            self.assertIn("$attacca:setup", context)
            self.assertIn("active AI invokes", context)
            self.assertNotIn("python3 ", context)
            self.assertNotIn("native choice UI", context)
            self.assertIn("do not run a shell", context)

            # The trusted hook records that it showed the offer, so saying No
            # needs no second out-of-workspace shell approval.
            second = self._hook(
                checkout, data, home, url="http://127.0.0.1:1")
            self.assertEqual(second.stdout, "")
            status = subprocess.run(
                [sys.executable, str(HOOK), "--status", "--cwd",
                 str(checkout), "--data-dir", str(data)],
                env={**os.environ, "HOME": str(home)}, capture_output=True,
                text=True, timeout=10, check=True)
            self.assertEqual(json.loads(status.stdout)["status"], "offered")

            other = root / "another-project"
            other.mkdir()
            self.assertTrue(self._hook(other, data, home).stdout)

    def test_existing_project_link_runs_active_mcp_startup_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            nested = checkout / "src"
            link_dir = checkout / ".attacca"
            home.mkdir()
            nested.mkdir(parents=True)
            link_dir.mkdir()
            (link_dir / "project.json").write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            db = root / "hook.db"
            conn = c.connect(db)
            c.project_init(conn, "setup", "human", path=str(checkout),
                           project_id="shared")
            self._register_actor(conn, "shared", "codex", "worker")
            self._register_actor(conn, "shared", "claude", "director")
            c.update_handoff(conn, "shared", "setup", "human",
                             {"objective": "ship the panel"})
            c.rule_create(conn, "shared", "setup", "human",
                          "Build on v2", "Put new work in v2.",
                          scope="everyone", priority=10)
            c.room_send(conn, "shared", "other", "agent",
                        "please check this",
                        mentions=["shared.worker.codex",
                                  "shared.director.claude"])
            conn.close()
            server = c.AttaccaServer(("127.0.0.1", 0), db)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]
                result = self._hook(
                    nested, root / "plugin-data", home, url=url)
                claude_result = self._hook(
                    nested, root / "claude-plugin-data", home, url=url,
                    runtime="claude")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            payload = json.loads(result.stdout)
            self.assertIn("Attacca active", payload["systemMessage"])
            self.assertIn("MCP startup", payload["systemMessage"])
            context = payload["hookSpecificOutput"]["additionalContext"]
            self.assertIn("through the configured MCP connection", context)
            self.assertIn("ship the panel", context)
            self.assertIn("please check this", context)
            brief = json.loads(context.rsplit("\n\n", 1)[1])
            self.assertEqual(brief["actor"], "shared.worker.codex")
            self.assertEqual(brief["project_rules"][0]["title"],
                             "Build on v2")
            claude_payload = json.loads(claude_result.stdout)
            self.assertIn("Attacca active", claude_payload["systemMessage"])
            claude_context = claude_payload["hookSpecificOutput"]["additionalContext"]
            claude_brief = json.loads(claude_context.rsplit("\n\n", 1)[1])
            self.assertEqual(claude_brief["actor"],
                             "shared.director.claude")
            self.assertIn("please check this", claude_context)

    def test_newer_server_prompts_without_replacing_brief_and_persists_choice(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            data = root / "plugin-data"
            link_dir = checkout / ".attacca"
            home.mkdir()
            link_dir.mkdir(parents=True)
            (link_dir / "project.json").write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            db = root / "hook.db"
            conn = c.connect(db)
            c.project_init(conn, "setup", "human", path=str(checkout),
                           project_id="shared")
            self._register_actor(conn, "shared", "codex", "worker")
            c.update_handoff(conn, "shared", "setup", "human",
                             {"objective": "keep continuity loaded"})
            conn.close()
            original_version = c.VERSION
            available_version = next_patch(original_version)
            newer_version = next_patch(available_version)
            server = self._server_advertising(
                ("127.0.0.1", 0), db, available_version)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]
                first = self._hook(checkout, data, home, url=url)
                payload = json.loads(first.stdout)
                context = payload["hookSpecificOutput"]["additionalContext"]
                self.assertIn("ATTACCA UPDATE CHOICE", context)
                self.assertIn("1. Install now", context)
                self.assertIn("2. Later", context)
                self.assertIn("3. Skip this version", context)
                self.assertIn("Do not install silently", context)
                self.assertIn("keep continuity loaded", context)
                self.assertIn("mktemp", context)
                self.assertIn('curl -fsSL', context)
                self.assertIn('-o "$attacca_update_script"', context)
                self.assertNotIn("| sh", context)
                self.assertIn("open `/hooks`", context)

                state = self._poll_state(data)
                update = state["updates"][url][available_version]
                self.assertEqual(update["installed_version"],
                                 original_version)
                self.assertEqual(update["offer_count"], 1)
                self.assertTrue(state["polls"])

                # An unanswered offer is not repeated at another startup in
                # the same reminder window.
                repeated = self._hook(checkout, data, home, url=url)
                self.assertNotIn("ATTACCA UPDATE CHOICE", repeated.stdout)
                self.assertEqual(
                    self._poll_state(data)["updates"][url][available_version]
                    ["offer_count"], 1)

                recorded = subprocess.run(
                    [sys.executable, str(HOOK), "--data-dir", str(data),
                     "--update-choice", "skip", "--server-url", url + "/",
                     "--server-version", available_version],
                    env={**os.environ, "HOME": str(home)}, capture_output=True,
                    text=True, timeout=10, check=True)
                self.assertEqual(json.loads(recorded.stdout)["decision"],
                                 "skip")
                skipped = self._hook(checkout, data, home, url=url)
                skipped_context = json.loads(skipped.stdout)[
                    "hookSpecificOutput"]["additionalContext"]
                self.assertIn("ATTACCA ACTIVE SESSION BRIEF", skipped_context)
                self.assertNotIn("ATTACCA UPDATE CHOICE", skipped_context)

                # Skip applies only to that exact release.  A newly started
                # server at the same URL advertises the newer immutable
                # distribution snapshot and asks again; a running server may
                # not change VERSION underneath existing download bytes.
                port = server.server_address[1]
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                server = self._server_advertising(
                    ("127.0.0.1", port), db, newer_version)
                thread = threading.Thread(
                    target=server.serve_forever, daemon=True)
                thread.start()
                newer = self._hook(checkout, data, home, url=url)
                self.assertIn("Attacca %s is available" % newer_version,
                              newer.stdout)

                hook_module.set_update_choice(
                    data, url, newer_version, "later")
                later_session = self._hook(checkout, data, home, url=url)
                self.assertNotIn("ATTACCA UPDATE CHOICE",
                                 later_session.stdout)
                state_path = data / hook_module.STATE_NAME
                state = json.loads(state_path.read_text())
                snoozed = state["updates"][url][newer_version]
                snoozed["remind_after_epoch"] = 0
                snoozed["last_offered_epoch"] = 0
                state_path.write_text(json.dumps(state))
                reminded = self._hook(checkout, data, home, url=url)
                self.assertIn("Attacca %s is available" % newer_version,
                              reminded.stdout)

                # An install choice is not treated as proof of success while
                # the actual packaged VERSION is still older.
                hook_module.set_update_choice(
                    data, url, newer_version, "install")
                not_installed = self._hook(checkout, data, home, url=url)
                self.assertIn("Attacca %s is available" % newer_version,
                              not_installed.stdout)
            finally:
                c.VERSION = original_version
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_kimi_checks_updates_even_when_shared_poll_is_throttled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            plugin_data = (home / ".attacca" / "plugin-data" /
                           "codex-attacca")
            link_dir = checkout / ".attacca"
            home.mkdir()
            link_dir.mkdir(parents=True)
            (link_dir / "project.json").write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            db = root / "hook.db"
            conn = c.connect(db)
            c.project_init(conn, "setup", "human", path=str(checkout),
                           project_id="shared")
            self._register_actor(conn, "shared", "kimi", "worker")
            conn.close()
            original_version = c.VERSION
            available_version = next_patch(original_version)
            server = self._server_advertising(
                ("127.0.0.1", 0), db, available_version)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]
                first = self._hook(
                    checkout, root / "unused", home, url=url,
                    runtime="kimi", event="UserPromptSubmit")
                self.assertIn("ATTACCA UPDATE CHOICE", first.stdout)
                seeded = next(iter(
                    self._poll_state(plugin_data)["polls"].values()))
                seeded_at = seeded["last_poll_at"]

                # The second prompt is inside both the shared-state throttle
                # and the exact-release reminder window, so it stays silent.
                second = self._hook(
                    checkout, root / "unused", home, url=url,
                    runtime="kimi", event="UserPromptSubmit")
                self.assertEqual(second.stdout, "")
                still_seeded = next(iter(
                    self._poll_state(plugin_data)["polls"].values()))
                self.assertEqual(still_seeded["last_poll_at"], seeded_at)

                hook_module.set_update_choice(
                    plugin_data, url, available_version, "skip")
                skipped = self._hook(
                    checkout, root / "unused", home, url=url,
                    runtime="kimi", event="UserPromptSubmit")
                self.assertEqual(skipped.stdout, "")
            finally:
                c.VERSION = original_version
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_version_parser_rejects_malformed_semver(self):
        self.assertLess(hook_module._semver_key("1.2.3-alpha.2"),
                        hook_module._semver_key("1.2.3"))
        self.assertEqual(hook_module._semver_key("v1.2.3+codex.9"),
                         hook_module._semver_key("1.2.3"))
        for invalid in ("vv1.2.3", "01.2.3", "1.02.3", "1.2.03",
                        "1.0.0-01", "1.0.0-alpha..1", "1.0.0+",
                        "1.0.0+bad_meta"):
            self.assertIsNone(hook_module._semver_key(invalid), invalid)

    def test_equal_older_malformed_or_unreachable_release_is_advisory_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            status = {"state_path": str(data / hook_module.STATE_NAME)}
            config = {"url": "http://server"}
            local = c.VERSION
            major, minor, patch = (int(part) for part in local.split("."))
            older = "%d.%d.%d" % (major, minor, max(0, patch - 1))
            for available in (local, older, "not-a-version", None):
                with mock.patch.object(
                        hook_module, "_local_version", return_value=local), \
                     mock.patch.object(
                        hook_module, "_server_release",
                        return_value={"version": available,
                                      "managed_instructions": None}):
                    self.assertIsNone(hook_module._update_offer(
                        status, ROOT, config))
            with mock.patch.object(
                    hook_module, "_server_release",
                    side_effect=TimeoutError("health timed out")):
                self.assertIsNone(hook_module._update_offer(
                    status, ROOT, config))
            self.assertFalse(Path(status["state_path"]).exists())

    def test_equal_binary_version_law_change_never_offers_binary_reinstall(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            status = {"state_path": str(data / hook_module.STATE_NAME)}
            config = {"url": "http://server"}
            local_laws = {"version": c.MANAGED_BLOCK_VERSION,
                          "sha256": "a" * 64}
            server_laws = {"version": c.MANAGED_BLOCK_VERSION + 1,
                           "sha256": "b" * 64}
            with mock.patch.object(
                    hook_module, "_local_version", return_value=c.VERSION), \
                 mock.patch.object(
                    hook_module, "_local_managed_instructions",
                    return_value=local_laws), \
                 mock.patch.object(
                    hook_module, "_server_release",
                    return_value={"version": c.VERSION,
                                  "managed_instructions": server_laws}):
                self.assertIsNone(hook_module._update_offer(
                    status, ROOT, config))
            self.assertFalse(Path(status["state_path"]).exists())

            # Hash-only law changes also use the server-law refresh path; they
            # never create an executable install choice or restart request.
            server_laws["sha256"] = "c" * 64
            with mock.patch.object(
                    hook_module, "_local_version", return_value=c.VERSION), \
                 mock.patch.object(
                    hook_module, "_local_managed_instructions",
                    return_value=local_laws), \
                 mock.patch.object(
                    hook_module, "_server_release",
                    return_value={"version": c.VERSION,
                                  "managed_instructions": server_laws}):
                self.assertIsNone(hook_module._update_offer(
                    status, ROOT, config))
            self.assertFalse(Path(status["state_path"]).exists())

    def test_same_managed_law_version_changed_hash_never_offers_reinstall(self):
        with tempfile.TemporaryDirectory() as tmp:
            status = {"state_path": str(
                Path(tmp) / hook_module.STATE_NAME)}
            config = {"url": "http://server"}
            local_laws = {"version": c.MANAGED_BLOCK_VERSION,
                          "sha256": "a" * 64}
            server_laws = {"version": c.MANAGED_BLOCK_VERSION,
                           "sha256": "b" * 64}
            with mock.patch.object(
                    hook_module, "_local_version", return_value=c.VERSION), \
                 mock.patch.object(
                    hook_module, "_local_managed_instructions",
                    return_value=local_laws), \
                 mock.patch.object(
                    hook_module, "_server_release",
                    return_value={"version": c.VERSION,
                                  "managed_instructions": server_laws}):
                offer = hook_module._update_offer(status, ROOT, config)
            self.assertIsNone(offer)
            self.assertFalse(Path(status["state_path"]).exists())

    def test_older_server_managed_laws_never_offer_a_downgrade(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            status = {"state_path": str(data / hook_module.STATE_NAME)}
            config = {"url": "http://server"}
            local_laws = {"version": c.MANAGED_BLOCK_VERSION,
                          "sha256": "b" * 64}
            server_laws = {"version": c.MANAGED_BLOCK_VERSION - 1,
                           "sha256": "a" * 64}
            with mock.patch.object(
                    hook_module, "_local_version", return_value=c.VERSION), \
                 mock.patch.object(
                    hook_module, "_local_managed_instructions",
                    return_value=local_laws), \
                 mock.patch.object(
                    hook_module, "_server_release",
                    return_value={"version": c.VERSION,
                                  "managed_instructions": server_laws}):
                self.assertIsNone(hook_module._update_offer(
                    status, ROOT, config))
            self.assertFalse(Path(status["state_path"]).exists())

    def test_malformed_server_managed_law_metadata_is_advisory_only(self):
        invalid = (
            {"version": True, "sha256": "a" * 64},
            {"version": 0, "sha256": "a" * 64},
            {"version": -1, "sha256": "a" * 64},
            {"version": c.MANAGED_BLOCK_VERSION, "sha256": {"bad": "hash"}},
            {"version": c.MANAGED_BLOCK_VERSION, "sha256": 123},
            {"version": c.MANAGED_BLOCK_VERSION, "sha256": " "},
            {"version": c.MANAGED_BLOCK_VERSION, "sha256": "a" * 63},
            {"version": c.MANAGED_BLOCK_VERSION, "sha256": "A" * 64},
        )
        for index, server_laws in enumerate(invalid):
            with self.subTest(server_laws=server_laws), \
                    tempfile.TemporaryDirectory() as tmp:
                status = {"state_path": str(
                    Path(tmp) / hook_module.STATE_NAME)}
                config = {"url": "http://server-%d" % index}
                with mock.patch.object(
                        hook_module, "_local_version",
                        return_value=c.VERSION), \
                     mock.patch.object(
                        hook_module, "_local_managed_instructions",
                        return_value=None), \
                     mock.patch.object(
                        hook_module, "_server_release",
                        return_value={"version": c.VERSION,
                                      "managed_instructions": server_laws}):
                    self.assertIsNone(hook_module._update_offer(
                        status, ROOT, config))
                self.assertFalse(Path(status["state_path"]).exists())

    def test_damaged_local_hash_never_bypasses_law_version_ordering(self):
        cases = (
            ({"version": c.MANAGED_BLOCK_VERSION, "sha256": None},
             {"version": c.MANAGED_BLOCK_VERSION - 1,
              "sha256": "a" * 64}, False),
            ({"version": c.MANAGED_BLOCK_VERSION + 1,
              "sha256": "A" * 64},
             {"version": c.MANAGED_BLOCK_VERSION,
              "sha256": "a" * 64}, False),
            (None,
             {"version": c.MANAGED_BLOCK_VERSION,
              "sha256": "a" * 64}, False),
            ({"version": c.MANAGED_BLOCK_VERSION, "sha256": None},
             {"version": c.MANAGED_BLOCK_VERSION,
              "sha256": "a" * 64}, True),
        )
        for index, (local_laws, server_laws, expected) in enumerate(cases):
            with self.subTest(local_laws=local_laws,
                              server_laws=server_laws), \
                    tempfile.TemporaryDirectory() as tmp:
                status = {"state_path": str(
                    Path(tmp) / hook_module.STATE_NAME)}
                config = {"url": "http://server-%d" % index}
                with mock.patch.object(
                        hook_module, "_local_version",
                        return_value=c.VERSION), \
                     mock.patch.object(
                        hook_module, "_local_managed_instructions",
                        return_value=local_laws), \
                     mock.patch.object(
                        hook_module, "_server_release",
                        return_value={"version": c.VERSION,
                                      "managed_instructions": server_laws}):
                    offer = hook_module._update_offer(status, ROOT, config)
                self.assertIsNone(offer)
                self.assertFalse(Path(status["state_path"]).exists())

    def test_unlinked_project_offers_update_before_setup_and_then_honors_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            data = root / "plugin-data"
            home.mkdir()
            checkout.mkdir()
            db = root / "hook.db"
            c.connect(db).close()
            original_version = c.VERSION
            available_version = next_patch(original_version)
            server = self._server_advertising(
                ("127.0.0.1", 0), db, available_version)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]

                def restart_server(version):
                    nonlocal server, thread
                    port = server.server_address[1]
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)
                    self.assertFalse(thread.is_alive())
                    server = self._server_advertising(
                        ("127.0.0.1", port), db, version)
                    thread = threading.Thread(
                        target=server.serve_forever, daemon=True)
                    thread.start()

                first = self._hook(checkout, data, home, url=url)
                context = json.loads(first.stdout)[
                    "hookSpecificOutput"]["additionalContext"]
                self.assertLess(context.index("ATTACCA UPDATE CHOICE"),
                                context.index("ATTACCA FIRST-RUN CHOICE"))
                self.assertIn("after Later or Skip, continue", context)
                self.assertIn("--setup-cwd", context)
                self.assertEqual(hook_module.prompt_status(
                    checkout, data)["status"], "ask")

                # Install took priority, so it must not consume a setup offer
                # the user never answered. A restarted, updated client still
                # receives the first-run setup choice.
                hook_module.set_update_choice(
                    data, url, available_version, "install")
                self.assertEqual(hook_module.prompt_status(
                    checkout, data)["status"], "ask")
                restart_server(original_version)  # server/client now matching
                restarted = self._hook(checkout, data, home, url=url)
                restarted_context = json.loads(restarted.stdout)[
                    "hookSpecificOutput"]["additionalContext"]
                self.assertIn("ATTACCA FIRST-RUN CHOICE", restarted_context)

                # Once setup has genuinely been offered, release notification
                # stays independent and exact-version Skip suppresses it.
                restart_server(available_version)
                second = self._hook(checkout, data, home, url=url)
                second_context = json.loads(second.stdout)[
                    "hookSpecificOutput"]["additionalContext"]
                self.assertIn("ATTACCA UPDATE CHOICE", second_context)
                self.assertNotIn("ATTACCA FIRST-RUN CHOICE", second_context)
                hook_module.set_update_choice(
                    data, url, available_version, "skip")
                self.assertEqual(
                    self._hook(checkout, data, home, url=url).stdout, "")
            finally:
                c.VERSION = original_version
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_kimi_first_prompt_runs_unlinked_setup_once_without_sessionstart(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            home.mkdir()
            checkout.mkdir()
            db = root / "hook.db"
            c.connect(db).close()
            server = c.AttaccaServer(("127.0.0.1", 0), db)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]
                first = self._hook(
                    checkout, root / "unused", home, url=url,
                    runtime="kimi", event="UserPromptSubmit")
                self.assertIn("ATTACCA FIRST-RUN CHOICE", first.stdout)
                second = self._hook(
                    checkout, root / "unused", home, url=url,
                    runtime="kimi", event="UserPromptSubmit")
                self.assertEqual(second.stdout, "")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_update_choice_precedes_unassigned_role_setup_without_losing_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            link = root / ".attacca" / "project.json"
            link.parent.mkdir()
            link.write_text("{}")
            status = {
                "project_id": "shared", "root": str(root),
                "link_path": str(link),
                "state_path": str(root / "state.json"),
            }
            snapshot = {
                "project": "shared", "checked_at": "now",
                "handoff": {"context_version": 1, "handoff": {
                    "objective": "preserve this snapshot"}},
                "inbox": {"messages": [], "unread_broadcasts": 0},
                "room": {"messages": []}, "tasks": {"tasks": []},
                "status": {"name": "Shared", "lead_director": None,
                           "you": {"actor_id": "shared.unassigned.codex",
                                   "actor_type": "agent"}, "counts": {}},
                "agents": {"agents": [{
                    "agent_id": "shared.unassigned.codex", "role": None}]},
            }
            update = {
                "system_message": "new release",
                "context": ("ATTACCA UPDATE CHOICE\nSequence the work: after "
                            "Later or Skip, continue with the brief below."),
            }
            with mock.patch.object(
                    hook_module, "_plugin_and_config",
                    return_value=(ROOT, {"url": "http://server",
                                         "actor": "codex", "owner": ""})), \
                 mock.patch.object(
                    hook_module, "_ensure_background_watcher",
                    return_value={"ok": True, "already_running": True}), \
                 mock.patch.object(
                    hook_module, "_settings_interval", return_value=300), \
                 mock.patch.object(
                    hook_module, "_mcp_snapshot", return_value=snapshot), \
                 mock.patch.object(
                    hook_module, "_record_poll"), \
                 mock.patch.object(
                    hook_module, "_refresh_managed_laws", return_value=None), \
                 mock.patch.object(
                    hook_module, "_update_offer", return_value=update):
                payload = hook_module._active_output(status)
            context = payload["hookSpecificOutput"]["additionalContext"]
            self.assertLess(context.index("ATTACCA UPDATE CHOICE"),
                            context.index("ATTACCA FIRST-RUN ROLE SETUP"))
            self.assertIn("preserve this snapshot", context)

    def test_managed_law_adapter_notice_is_additive_and_reports_unsafe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout = root / "repo"
            nested = checkout / "src"
            link = checkout / ".attacca" / "project.json"
            nested.mkdir(parents=True)
            link.parent.mkdir()
            link.write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            status = {
                "project_id": "shared", "root": str(nested),
                "link_path": str(link),
            }
            result = {
                "files": [
                    {"file": str(checkout / "AGENTS.md"), "changed": True,
                     "status": "updated", "action": "updated managed block"},
                    {"file": str(checkout / "CLAUDE.md"), "changed": False,
                     "status": "unsafe_symlink", "action": "outside root"},
                ]}
            law = c.managed_law_payload("shared", None)
            with mock.patch.object(
                    hook_module, "_server_managed_law_adapter",
                    return_value=result) as adapter:
                notice = hook_module._refresh_managed_laws(
                    status, ROOT, config={"url": "http://server"},
                    fetcher=lambda config, project: law)
            adapter.assert_called_once_with(
                ROOT, "shared", str(checkout), law)
            self.assertIn("AGENTS.md", notice["context"])
            self.assertIn("outside root", notice["context"])
            base = hook_module._event_context_output(
                "SessionStart", "Attacca active", "AUTHORITATIVE BRIEF")
            combined = hook_module._append_notice(base, notice)
            self.assertIn("AUTHORITATIVE BRIEF", combined[
                "hookSpecificOutput"]["additionalContext"])
            self.assertIn("MANAGED LAWS REFRESHED", combined[
                "hookSpecificOutput"]["additionalContext"])

    def test_managed_law_refresh_preserves_every_byte_outside_owned_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout = root / "repo"
            nested = checkout / "src"
            link = checkout / ".attacca" / "project.json"
            nested.mkdir(parents=True)
            link.parent.mkdir()
            link.write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            before = "# User rules\n\nKeep this paragraph exactly.\n\n"
            after = "\n\n## User tail\nKeep this too.\n"
            desired = c.managed_instruction_block("shared", None)
            old = desired.replace(
                "MANAGED_ATTACCA:BEGIN v=%d" % c.MANAGED_BLOCK_VERSION,
                "MANAGED_ATTACCA:BEGIN v=1", 1).replace(
                    "The project owns the knowledge; your session is replaceable.",
                    "OLD MANAGED LAW", 1)
            agents = checkout / "AGENTS.md"
            agents.write_text(before + old + after)
            status = {
                "project_id": "shared", "root": str(nested),
                "link_path": str(link),
            }
            notice = hook_module._refresh_managed_laws(
                status, ROOT, config={"url": "http://server"},
                fetcher=lambda config, project: c.managed_law_payload(
                    project, None))
            self.assertIsNotNone(notice)
            self.assertEqual(agents.read_text(), before + desired + after)
            self.assertIn("AGENTS.md", notice["context"])

    def test_managed_law_v11_auto_refreshes_to_v12_without_touching_user_bytes(self):
        self.assertEqual(c.MANAGED_BLOCK_VERSION, 12)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout = root / "repo"
            checkout.mkdir()
            link = checkout / ".attacca" / "project.json"
            link.parent.mkdir()
            link.write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            desired = c.managed_instruction_block("shared", None)
            previous = desired.replace(
                "MANAGED_ATTACCA:BEGIN v=12",
                "MANAGED_ATTACCA:BEGIN v=11", 1).replace(
                    "Every directed assignment and broadcast directive must",
                    "Directed assignments should", 1)
            prefix = "# Human instructions\n\nKeep before byte-for-byte.\n\n"
            suffix = "\n\n## Human tail\nKeep after byte-for-byte.\n"
            agents = checkout / "AGENTS.md"
            agents.write_text(prefix + previous + suffix)
            status = {"project_id": "shared", "root": str(checkout),
                      "link_path": str(link)}

            notice = hook_module._refresh_managed_laws(
                status, ROOT, config={"url": "http://server"},
                fetcher=lambda config, project: c.managed_law_payload(
                    project, None))

            self.assertIsNotNone(notice)
            self.assertEqual(agents.read_text(), prefix + desired + suffix)
            self.assertIn("AGENTS.md", notice["context"])

    def test_parallel_update_decisions_do_not_lose_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "plugin-data"
            failures = []

            def choose(index):
                try:
                    hook_module.set_update_choice(
                        data, "http://server", "0.5.%d" % index, "skip")
                except Exception as err:  # pragma: no cover - assertion detail
                    failures.append(err)

            threads = [threading.Thread(target=choose, args=(index,))
                       for index in range(12)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
            self.assertEqual(failures, [])
            state = self._poll_state(data)
            self.assertEqual(len(state["updates"]["http://server"]), 12)

    def test_parallel_release_checks_claim_only_one_prompt_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / hook_module.STATE_NAME
            barrier = threading.Barrier(12)
            claims = []

            def claim():
                barrier.wait(timeout=5)
                claims.append(hook_module._claim_update_offer(
                    state_path, "http://server", next_patch(c.VERSION),
                    c.VERSION, release_fingerprint="one-release"))

            threads = [threading.Thread(target=claim) for _ in range(12)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
            self.assertEqual(claims.count(True), 1)
            state = json.loads(state_path.read_text())
            entry = state["updates"]["http://server"][next_patch(c.VERSION)]
            self.assertEqual(entry["offer_count"], 1)

    def test_claude_start_self_heals_legacy_project_mcp_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            nested = checkout / "src"
            link_dir = checkout / ".attacca"
            home.mkdir()
            nested.mkdir(parents=True)
            link_dir.mkdir()
            (link_dir / "project.json").write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            project_mcp = checkout / ".mcp.json"
            project_mcp.write_text(json.dumps({
                "mcpServers": {
                    "attacca": {"type": "http", "url": "http://old/mcp"},
                    "other": {"command": "keep-me"},
                },
                "projectSetting": True,
            }))
            db = root / "hook.db"
            conn = c.connect(db)
            c.project_init(conn, "setup", "human", path=str(checkout),
                           project_id="shared")
            self._register_actor(conn, "shared", "claude", "director")
            self._register_actor(conn, "shared", "codex", "worker")
            conn.close()
            server = c.AttaccaServer(("127.0.0.1", 0), db)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]
                # Codex must not delete a Claude-without-plugin project config.
                self._hook(nested, root / "codex-data", home, url=url)
                self.assertIn("attacca", json.loads(
                    project_mcp.read_text())["mcpServers"])

                diagnostic_env = dict(os.environ)
                diagnostic_env.update({
                    "HOME": str(home),
                    "CLAUDE_PLUGIN_ROOT": str(ROOT),
                    "ATTACCA_URL": url,
                    "ATTACCA_OWNER": "",
                })
                diagnostic_env.pop("PLUGIN_ROOT", None)
                diagnostic_env.pop("KIMI_PLUGIN_ROOT", None)
                diagnostic = subprocess.run(
                    [sys.executable, str(HOOK), "--status", "--cwd",
                     str(nested)], env=diagnostic_env, capture_output=True,
                    text=True, timeout=10, check=True)
                self.assertEqual(json.loads(diagnostic.stdout)["status"],
                                 "linked")
                self.assertIn("attacca", json.loads(
                    project_mcp.read_text())["mcpServers"])

                first = self._hook(
                    nested, root / "claude-data", home, url=url,
                    runtime="claude")
                payload = json.loads(first.stdout)
                self.assertIn("Attacca active", payload["systemMessage"])
                self.assertIn("removed the legacy project-level MCP entry",
                              payload["systemMessage"])
                self.assertIn("Restart Claude once",
                              payload["hookSpecificOutput"]["additionalContext"])
                kept = json.loads(project_mcp.read_text())
                self.assertEqual(kept["mcpServers"], {
                    "other": {"command": "keep-me"}})
                self.assertTrue(kept["projectSetting"])

                second = self._hook(
                    nested, root / "claude-data", home, url=url,
                    runtime="claude")
                self.assertNotIn("removed the legacy project-level MCP entry",
                                 second.stdout)

                malformed = "{not-json\n"
                project_mcp.write_text(malformed)
                warned = self._hook(
                    nested, root / "claude-data", home, url=url,
                    runtime="claude")
                warning_payload = json.loads(warned.stdout)
                self.assertIn("could not remove the legacy project MCP entry",
                              warning_payload["systemMessage"])
                self.assertIn("Attacca active", warning_payload["systemMessage"])
                self.assertEqual(project_mcp.read_text(), malformed)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_linked_unassigned_agents_get_lead_aware_role_setup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            link_dir = checkout / ".attacca"
            home.mkdir()
            link_dir.mkdir(parents=True)
            (link_dir / "project.json").write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            db = root / "hook.db"
            conn = c.connect(db)
            c.project_init(conn, "setup", "human", path=str(checkout),
                           project_id="shared", name="Shared Workspace")
            conn.close()
            server = c.AttaccaServer(("127.0.0.1", 0), db)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]
                codex = self._hook(
                    checkout, root / "codex-data", home, url=url)
                codex_payload = json.loads(codex.stdout)
                self.assertIn("role setup required",
                              codex_payload["systemMessage"])
                codex_context = codex_payload[
                    "hookSpecificOutput"]["additionalContext"]
                self.assertIn("ATTACCA FIRST-RUN ROLE SETUP", codex_context)
                self.assertIn("already linked", codex_context)
                self.assertIn("Workspace selection is already done",
                              codex_context)
                self.assertIn("single complete setup entry", codex_context)
                self.assertIn("`$attacca:setup`", codex_context)
                self.assertIn("must explicitly choose", codex_context)
                self.assertIn("Director + Lead Director", codex_context)
                self.assertIn("raw workspace IDs or actor IDs", codex_context)
                self.assertIn("relationship choices", codex_context)
                self.assertIn("detected tool and MCP wiring", codex_context)
                self.assertIn("lifecycle hook", codex_context)
                self.assertIn("task-import review", codex_context)

                conn = c.connect(db)
                codex_record = next(
                    agent for agent in c.agent_list(conn, "shared")["agents"]
                    if agent["agent_id"] == self._actor_id("codex"))
                self.assertIsNone(codex_record["role"])
                self.assertIsNone(c.get_project(conn, "shared")["lead_director"])
                c.agent_register(conn, "shared", "existing-lead", "agent",
                                 display_name="Existing Lead", role="director",
                                 runtime="test")
                c.set_lead_director(
                    conn, "shared", "admin", "human", "existing-lead")
                conn.close()

                claude = self._hook(
                    checkout, root / "claude-data", home, url=url,
                    runtime="claude")
                claude_payload = json.loads(claude.stdout)
                claude_context = claude_payload[
                    "hookSpecificOutput"]["additionalContext"]
                self.assertIn("ATTACCA FIRST-RUN ROLE SETUP", claude_context)
                self.assertIn("`/attacca:setup`", claude_context)
                self.assertIn("Another Lead Director already exists",
                              claude_context)
                self.assertIn("Join as another Director", claude_context)
                self.assertIn("keep Existing Lead as Lead Director",
                              claude_context)
                conn = c.connect(db)
                claude_record = next(
                    agent for agent in c.agent_list(conn, "shared")["agents"]
                    if agent["agent_id"] == self._actor_id("claude"))
                self.assertIsNone(claude_record["role"])
                self.assertEqual(c.get_project(
                    conn, "shared")["lead_director"], "existing-lead")
                conn.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_linked_configured_worker_and_director_skip_role_setup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            link_dir = checkout / ".attacca"
            home.mkdir()
            link_dir.mkdir(parents=True)
            (link_dir / "project.json").write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            db = root / "hook.db"
            conn = c.connect(db)
            c.project_init(conn, "setup", "human", path=str(checkout),
                           project_id="shared")
            worker = self._register_actor(
                conn, "shared", "codex", "worker")
            director = self._register_actor(
                conn, "shared", "claude", "director")
            c.set_lead_director(conn, "shared", "admin", "human", director)
            conn.close()
            server = c.AttaccaServer(("127.0.0.1", 0), db)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]
                codex = self._hook(
                    checkout, root / "codex-data", home, url=url)
                claude = self._hook(
                    checkout, root / "claude-data", home, url=url,
                    runtime="claude")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            for result, role, actor in (
                    (codex, "worker", worker),
                    (claude, "director", director)):
                payload = json.loads(result.stdout)
                self.assertIn("Attacca active", payload["systemMessage"])
                context = payload["hookSpecificOutput"]["additionalContext"]
                self.assertIn("ATTACCA ACTIVE SESSION BRIEF", context)
                self.assertNotIn("FIRST-RUN ROLE SETUP", context)
                brief = json.loads(context.rsplit("\n\n", 1)[1])
                self.assertEqual(brief["actor"], actor)
                self.assertEqual(brief["actor_role"], role)

    def test_reachable_server_with_stale_link_offers_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            link_dir = checkout / ".attacca"
            home.mkdir()
            link_dir.mkdir(parents=True)
            link_path = link_dir / "project.json"
            link_path.write_text(json.dumps({
                "schema_version": 1, "project_id": "deleted-workspace"}))
            db = root / "hook.db"
            conn = c.connect(db)
            c.project_init(conn, "setup", "human", path=str(root / "shared"),
                           project_id="shared", name="Shared Workspace")
            conn.close()
            original_version = c.VERSION
            available_version = next_patch(original_version)
            server = self._server_advertising(
                ("127.0.0.1", 0), db, available_version)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]
                result = self._hook(
                    checkout, root / "plugin-data", home, url=url)
            finally:
                c.VERSION = original_version
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            payload = json.loads(result.stdout)
            self.assertIn("needs repair", payload["systemMessage"])
            context = payload["hookSpecificOutput"]["additionalContext"]
            self.assertIn("saved workspace 'deleted-workspace' does not exist",
                          context)
            self.assertIn("Available workspaces: Shared Workspace", context)
            self.assertIn("Repair Attacca setup", context)
            self.assertIn("ATTACCA UPDATE CHOICE", context)
            self.assertIn("Attacca %s is available" % available_version,
                          context)
            self.assertIn("$attacca:setup", context)
            self.assertNotIn("STARTUP CHECK FAILED", context)
            self.assertNotIn("server is unreachable", context)
            self.assertEqual(json.loads(link_path.read_text())["project_id"],
                             "deleted-workspace")

    def test_linked_project_without_mirror_is_explicit_offline_uninitialized(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            link_dir = checkout / ".attacca"
            home.mkdir()
            link_dir.mkdir(parents=True)
            (link_dir / "project.json").write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))

            result = self._hook(
                checkout, root / "plugin-data", home,
                url="http://127.0.0.1:9")
            payload = json.loads(result.stdout)
            self.assertIn("offline_uninitialized", payload["systemMessage"])
            context = payload["hookSpecificOutput"]["additionalContext"]
            self.assertIn("ATTACCA OFFLINE STATE", context)
            self.assertIn("No valid identity-scoped local mirror", context)
            self.assertIn("role authority are NOT being supplied", context)
            self.assertNotIn("CONTINUE WORK", context)
            self.assertNotIn("Repair Attacca setup", context)

    def test_periodic_updates_disabled_by_server_setting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            data = root / "plugin-data"
            link_dir = checkout / ".attacca"
            home.mkdir()
            link_dir.mkdir(parents=True)
            (link_dir / "project.json").write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            db = root / "hook.db"
            conn = c.connect(db)
            c.project_init(conn, "setup", "human", path=str(checkout),
                           project_id="shared")
            self._register_actor(conn, "shared", "codex", "worker")
            conn.close()
            server = c.AttaccaServer(("127.0.0.1", 0), db)
            server.update_interval_seconds = 0
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]
                startup = self._hook(checkout, data, home, url=url)
                self.assertIn("Attacca active", startup.stdout)
                actor = self._startup_actor(startup)
                poll = next(iter(self._poll_state(data)["polls"].values()))
                self.assertEqual(poll["interval_seconds"], 0)

                conn = c.connect(db)
                c.room_send(conn, "shared", "other", "agent",
                            "disabled polling must not consume this",
                            mentions=[actor])
                self.assertEqual(len(c.inbox_read(
                    conn, "shared", actor, mark_read=False)["messages"]),
                    1)
                conn.close()
                periodic = self._hook(
                    checkout, data, home, url=url, event="UserPromptSubmit")
                self.assertEqual(periodic.stdout, "")
                conn = c.connect(db)
                unread = c.inbox_read(
                    conn, "shared", actor, mark_read=False)["messages"]
                conn.close()
                self.assertEqual([message["body"] for message in unread],
                                 ["disabled polling must not consume this"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_periodic_update_is_throttled_and_due_no_change_is_quiet(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            data = root / "plugin-data"
            link_dir = checkout / ".attacca"
            home.mkdir()
            link_dir.mkdir(parents=True)
            (link_dir / "project.json").write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            db = root / "hook.db"
            conn = c.connect(db)
            c.project_init(conn, "setup", "human", path=str(checkout),
                           project_id="shared")
            self._register_actor(conn, "shared", "codex", "worker")
            conn.close()
            server = c.AttaccaServer(("127.0.0.1", 0), db)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]
                self._hook(checkout, data, home, url=url)
                seeded = next(iter(self._poll_state(data)["polls"].values()))
                self.assertEqual(seeded["interval_seconds"], 60)
                seeded_at = seeded["last_poll_at"]

                throttled = self._hook(
                    checkout, data, home, url=url, event="UserPromptSubmit")
                self.assertEqual(throttled.stdout, "")
                still_seeded = next(iter(
                    self._poll_state(data)["polls"].values()))
                self.assertEqual(still_seeded["last_poll_at"], seeded_at)

                self._expire_polls(data)
                unchanged = self._hook(
                    checkout, data, home, url=url, event="UserPromptSubmit")
                self.assertEqual(unchanged.stdout, "")
                refreshed = next(iter(
                    self._poll_state(data)["polls"].values()))
                self.assertGreater(refreshed["last_poll_at"], 0)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_changed_periodic_output_and_recursive_stop_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            data = root / "plugin-data"
            link_dir = checkout / ".attacca"
            home.mkdir()
            link_dir.mkdir(parents=True)
            (link_dir / "project.json").write_text(json.dumps({
                "schema_version": 1, "project_id": "shared"}))
            db = root / "hook.db"
            conn = c.connect(db)
            c.project_init(conn, "setup", "human", path=str(checkout),
                           project_id="shared")
            self._register_actor(conn, "shared", "codex", "worker")
            c.agent_register(conn, "shared", "other", "agent",
                             role="director", runtime="hook-test-other")
            c.update_handoff(conn, "shared", "setup", "human",
                             {"objective": "initial objective"})
            conn.close()
            server = c.AttaccaServer(("127.0.0.1", 0), db)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d" % server.server_address[1]
                startup = self._hook(checkout, data, home, url=url)
                actor = self._startup_actor(startup)
                conn = c.connect(db)
                c.update_handoff(conn, "shared", "other", "agent",
                                 {"objective": "coordinate release"})
                c.room_send(conn, "shared", "other", "agent",
                            "review the release notes",
                            mentions=[actor])
                c.task_create(conn, "shared", "other", "agent",
                              "Verify release")
                conn.close()
                self._expire_polls(data)

                changed = self._hook(
                    checkout, data, home, url=url, event="UserPromptSubmit")
                payload = json.loads(changed.stdout)
                self.assertEqual(
                    payload["hookSpecificOutput"]["hookEventName"],
                    "UserPromptSubmit")
                context = payload["hookSpecificOutput"]["additionalContext"]
                self.assertIn("ATTACCA AUTOMATIC UPDATE", context)
                self.assertIn("coordinate release", context)
                self.assertIn("review the release notes", context)
                self.assertIn("T-1", context)
                self.assertIn("$attacca:update", context)
                self.assertIn("/attacca:update", context)
                self.assertIn("Attacca Settings", context)
                self.assertIn("watcher checked while the client was idle", context)
                self.assertIn("injecting it into the AI turn", context)
                conn = c.connect(db)
                self.assertEqual(c.inbox_read(
                    conn, "shared", actor, mark_read=False)["messages"],
                    [])

                c.room_send(conn, "shared", "other", "agent",
                            "stop boundary update",
                            mentions=[actor])
                conn.close()
                self._expire_polls(data)
                stopped = self._hook(
                    checkout, data, home, url=url, event="Stop")
                stop_payload = json.loads(stopped.stdout)
                self.assertEqual(stop_payload["decision"], "block")
                self.assertIn("stop boundary update", stop_payload["reason"])

                conn = c.connect(db)
                c.room_send(conn, "shared", "other", "agent",
                            "recursive stop must not consume this",
                            mentions=[actor])
                conn.close()
                recursive = self._hook(
                    checkout, data, home, url=url, event="Stop",
                    stop_hook_active=True)
                self.assertEqual(recursive.stdout, "")
                conn = c.connect(db)
                unread = c.inbox_read(
                    conn, "shared", actor, mark_read=False)["messages"]
                conn.close()
                self.assertEqual([message["body"] for message in unread],
                                 ["recursive stop must not consume this"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_home_directory_is_not_treated_as_a_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            result = self._hook(home, Path(tmp) / "plugin-data", home)
            self.assertEqual(result.stdout, "")

    def test_periodic_summary_labels_connected_workspace_source(self):
        message = {
            "event_id": "ev_connected", "seq": 8, "actor": "master.ai",
            "body": "new cross-workspace directive",
            "origin_project": "master-control",
            "authority": "master-directive",
        }
        snapshot = {
            "handoff": {"context_version": 2, "handoff": {}},
            "inbox": {"messages": [message]},
            "room": {"messages": [message]},
            "tasks": {"tasks": []}, "status": {"counts": {"events": 8}},
        }
        current = hook_module._poll_view(snapshot)
        summary = hook_module._change_summary(
            {"project_id": "current-app"}, None, current, snapshot, 300)
        self.assertIn("from master-control", summary)
        self.assertIn("[master-directive]", summary)


if __name__ == "__main__":
    unittest.main()
