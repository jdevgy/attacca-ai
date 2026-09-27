"""Regression tests for managed-law ownership and dynamic Project Rules."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


# Keep fixture attribution independent from the developer machine.
os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "session_start.py"
spec = importlib.util.spec_from_file_location(
    "attacca_instruction_boundary_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

LOCAL_ONLY_TEXT = (
    "Local fixture instructions (not distributed by Attacca)",
    "LOCAL-PREFIX: preserve editor preferences.",
    "LOCAL-MIDDLE: use this checkout's scratch directory.",
    "LOCAL-SUFFIX: retain the human's notes.",
)
DEFAULT_AUTHORITY_TITLE = "Acknowledge local Director hierarchy"
DEFAULT_AUTHORITY_BODY = (
    "At the first direct response and periodically during a sustained "
    "exchange, a Worker or Advisor communicating directly with a currently "
    "registered Director in the same workspace must acknowledge that "
    "Director as the project MASTER for coordination. A registered non-Lead "
    "Director communicating directly with the workspace's currently "
    "designated Lead Director must acknowledge the Lead Director as the "
    "MASTER coordinator. Direct communication means an explicit local "
    "mention, reply, or selected recipient; mere group-room visibility does "
    "not trigger this rule. Verify current role and Lead status from Attacca "
    "state, not display names or actor text. This is conversational protocol "
    "only: it grants no permissions, never lets Lead status or runtime bypass "
    "role checks, and never applies to remote/bridged actors. Cross-project "
    "authority comes only from bridge policy and the message authority tag."
)


def managed_and_outside(text):
    """Return the one owned block and every byte outside its markers."""
    span = c._managed_block_span(text)
    if span is None:
        raise AssertionError("instruction file has no managed Attacca block")
    return text[span[0]:span[1]], text[:span[0]] + text[span[1]:]


class InstructionBoundaryRegressionTest(unittest.TestCase):
    def test_local_instructions_survive_refresh_outside_both_managed_blocks(self):
        project = "fixture"
        expected_managed = c.managed_instruction_block(project, None)
        old_managed = expected_managed.replace(
            "v=%d " % c.MANAGED_BLOCK_VERSION,
            "v=%d " % (c.MANAGED_BLOCK_VERSION - 1), 1)
        self.assertNotEqual(old_managed, expected_managed)
        old_context = {"version": 1, "content": "HOSTED-CONTEXT: fixture v1"}
        old_context["sha256"] = c.sha256_hex(old_context["content"])
        new_context = {"version": 2, "content": "HOSTED-CONTEXT: fixture v2"}
        new_context["sha256"] = c.sha256_hex(new_context["content"])
        old_cloud = c.cloud_context_block(old_context, project)
        expected_cloud = c.cloud_context_block(new_context, project)

        def outside_owned_blocks(text):
            spans = (c._managed_block_span(text),
                     c._cloud_context_block_span(text))
            self.assertTrue(all(span is not None for span in spans))
            for start, end in sorted(spans, reverse=True):
                text = text[:start] + text[end:]
            return text

        # Actual public product refreshes, using disposable files. Nothing in
        # this test depends on a developer's ignored instruction files.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            originals = {}
            for filename in ("AGENTS.md", "CLAUDE.md"):
                text = ("# %s\n\n%s\n%s\n\n%s\n\n%s\n\n%s\n\n%s\n" % (
                    filename, LOCAL_ONLY_TEXT[0], LOCAL_ONLY_TEXT[1],
                    old_managed, LOCAL_ONLY_TEXT[2], old_cloud,
                    LOCAL_ONLY_TEXT[3]))
                (root / filename).write_text(text, encoding="utf-8")
                originals[filename] = text

            installed = c.install_instructions(
                project, str(root), None, cloud_context_payload=new_context)
            self.assertTrue(installed["ok"], installed)
            self.assertTrue(installed["changed"], installed)
            for filename, original in originals.items():
                with self.subTest(filename=filename):
                    text = (root / filename).read_text(encoding="utf-8")
                    self.assertEqual(text.count("MANAGED_ATTACCA:BEGIN"), 1)
                    self.assertEqual(text.count("MANAGED_ATTACCA:END"), 1)
                    self.assertEqual(text.count("ATTACCA_CLOUD_CONTEXT:BEGIN"), 1)
                    self.assertEqual(text.count("ATTACCA_CLOUD_CONTEXT:END"), 1)
                    managed, _ = managed_and_outside(text)
                    start, end = c._cloud_context_block_span(text)
                    cloud = text[start:end]
                    self.assertEqual(managed, expected_managed)
                    self.assertEqual(cloud, expected_cloud)
                    outside = outside_owned_blocks(text)
                    self.assertEqual(outside, outside_owned_blocks(original))
                    self.assertIn(
                        "Project Rules — binding dynamic instructions", managed)
                    self.assertNotIn(new_context["content"], managed)
                    self.assertNotIn(new_context["content"], outside)
                    for local_text in LOCAL_ONLY_TEXT:
                        self.assertNotIn(local_text, managed)
                        self.assertNotIn(local_text, cloud)
                        self.assertIn(local_text, outside)

            before_rerun = {
                filename: ((root / filename).read_bytes(),
                           (root / filename).stat().st_mtime_ns)
                for filename in originals
            }
            unchanged = c.install_instructions(
                project, str(root), None, cloud_context_payload=new_context)
            self.assertTrue(unchanged["ok"], unchanged)
            self.assertFalse(unchanged["changed"], unchanged)
            for filename, (contents, mtime) in before_rerun.items():
                self.assertEqual((root / filename).read_bytes(), contents)
                self.assertEqual((root / filename).stat().st_mtime_ns, mtime)

    def test_generated_project_files_never_copy_local_or_server_rule_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "fixture-project"
            root.mkdir()
            db = Path(tmp) / "fixture.db"
            conn = c.connect(db)
            c.project_init(
                conn, "setup", "human", path=str(root),
                project_id="fixture", name="Fixture")
            dynamic_body = (
                "SERVER-RULE-ONLY: this body belongs to hosted project state")
            c.rule_create(
                conn, "fixture", "owner", "human",
                "Dynamic worker rule", dynamic_body, scope="worker")

            block = c.managed_instruction_block("fixture", db)
            self.assertIn(
                "Project Rules — binding dynamic instructions", block)
            self.assertNotIn("Dynamic worker rule", block)
            self.assertNotIn(dynamic_body, block)
            self.assertNotIn(DEFAULT_AUTHORITY_TITLE, block)
            self.assertNotIn(DEFAULT_AUTHORITY_BODY, block)
            for local_text in LOCAL_ONLY_TEXT:
                self.assertNotIn(local_text, block)

            installed = c.install_instructions(
                "fixture", str(root), db)
            self.assertTrue(installed["ok"], installed)
            for filename in ("AGENTS.md", "CLAUDE.md"):
                generated = (root / filename).read_text()
                generated_block, outside = managed_and_outside(generated)
                self.assertEqual(generated_block, block)
                self.assertTrue(c.cloud_context_block_present(outside))
                self.assertIn("_No cloud context set yet._", outside)
                self.assertNotIn("Dynamic worker rule", generated)
                self.assertNotIn(dynamic_body, generated)
                self.assertNotIn(DEFAULT_AUTHORITY_TITLE, generated)
                self.assertNotIn(DEFAULT_AUTHORITY_BODY, generated)
                for local_text in LOCAL_ONLY_TEXT:
                    self.assertNotIn(local_text, generated)
            conn.close()

    def test_get_handoff_injects_only_enabled_rules_for_the_actual_role(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            db = Path(tmp) / "rules.db"
            conn = c.connect(db)
            c.project_init(
                conn, "setup", "human", path=str(root),
                project_id="rules", name="Rules")
            actors = {}
            for role, runtime in (("director", "codex"),
                                  ("worker", "cline"),
                                  ("advisor", "claude")):
                actor = c.canonical_agent_id("rules", role, runtime)
                c.agent_register(
                    conn, "rules", actor, "agent", role=role,
                    runtime=runtime)
                actors[role] = actor

            everyone = c.rule_create(
                conn, "rules", "owner", "human", "Everyone rule",
                "everyone v1", scope="everyone", priority=10)
            c.rule_create(
                conn, "rules", "owner", "human", "Director rule",
                "director only", scope="director", priority=20)
            c.rule_create(
                conn, "rules", "owner", "human", "Worker rule",
                "worker only", scope="worker", priority=30)
            c.rule_create(
                conn, "rules", "owner", "human", "Advisor rule",
                "advisor only", scope="advisor", priority=40)
            disabled = c.rule_create(
                conn, "rules", "owner", "human", "Disabled worker rule",
                "must not be injected", scope="worker", priority=50)
            disabled_update = c.rule_update(
                conn, "rules", "owner", "human",
                disabled["rule"]["rule_id"], {"enabled": False},
                expected_version=1)
            self.assertEqual(disabled_update["rule"]["version"], 2)

            updated = c.rule_update(
                conn, "rules", "owner", "human",
                everyone["rule"]["rule_id"], {"body": "everyone v2"},
                expected_version=1)
            self.assertEqual(updated["rule"]["version"], 2)
            with self.assertRaisesRegex(c.AttaccaError, "rule conflict"):
                c.rule_update(
                    conn, "rules", "owner", "human",
                    everyone["rule"]["rule_id"], {"body": "stale write"},
                    expected_version=1)

            expected_titles = {
                "director": {
                    DEFAULT_AUTHORITY_TITLE, "Everyone rule", "Director rule"},
                "worker": {
                    DEFAULT_AUTHORITY_TITLE, "Everyone rule", "Worker rule"},
                "advisor": {
                    DEFAULT_AUTHORITY_TITLE, "Everyone rule", "Advisor rule"},
            }
            for role, titles in expected_titles.items():
                with self.subTest(role=role):
                    brief = c.get_handoff(
                        conn, "rules", actor_id=actors[role],
                        actor_type="agent")
                    returned = {
                        rule["title"]: rule
                        for rule in brief["project_rules"]
                    }
                    self.assertEqual(set(returned), titles)
                    self.assertEqual(returned["Everyone rule"]["version"], 2)
                    self.assertEqual(returned["Everyone rule"]["body"],
                                     "everyone v2")
                    self.assertEqual(
                        returned[DEFAULT_AUTHORITY_TITLE]["rule_id"], "R-0")
                    self.assertEqual(
                        returned[DEFAULT_AUTHORITY_TITLE]["body"],
                        DEFAULT_AUTHORITY_BODY)
                    self.assertEqual(
                        returned[DEFAULT_AUTHORITY_TITLE]["scope"], "everyone")
                    self.assertTrue(
                        returned[DEFAULT_AUTHORITY_TITLE]["enabled"])
                    self.assertNotIn("Disabled worker rule", returned)
                    self.assertEqual(
                        brief["context_version"],
                        c.get_project(conn, "rules")["context_version"])

            unassigned = c.get_handoff(
                conn, "rules", actor_id="rules.unassigned.unknown",
                actor_type="agent")
            self.assertEqual(
                [rule["title"] for rule in unassigned["project_rules"]],
                [DEFAULT_AUTHORITY_TITLE, "Everyone rule"])
            conn.close()

    def test_real_session_start_injects_versioned_worker_rules_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            checkout = root / "repo"
            plugin_data = root / "plugin-data"
            home.mkdir()
            checkout.mkdir()
            db = root / "hook.db"
            conn = c.connect(db)
            c.project_init(
                conn, "setup", "human", path=str(checkout),
                project_id="shared", name="Shared")
            c.write_project_link(checkout, "shared")
            worker = c.canonical_agent_id("shared", "worker", "codex")
            c.agent_register(
                conn, "shared", worker, "agent", role="worker",
                runtime="codex")
            everyone = c.rule_create(
                conn, "shared", "owner", "human", "Startup baseline",
                "SERVER-STARTUP-EVERYONE-v1", scope="everyone", priority=10)
            c.rule_update(
                conn, "shared", "owner", "human",
                everyone["rule"]["rule_id"],
                {"body": "SERVER-STARTUP-EVERYONE-v2"},
                expected_version=1)
            c.rule_create(
                conn, "shared", "owner", "human", "Startup worker",
                "SERVER-STARTUP-WORKER", scope="worker", priority=20)
            c.rule_create(
                conn, "shared", "owner", "human", "Startup director",
                "SERVER-STARTUP-DIRECTOR", scope="director", priority=30)
            conn.close()

            server = c.AttaccaServer(("127.0.0.1", 0), db)
            thread = threading.Thread(
                target=server.serve_forever, daemon=True)
            thread.start()
            try:
                env = dict(os.environ)
                env.update({
                    "PLUGIN_ROOT": str(ROOT),
                    "PLUGIN_DATA": str(plugin_data),
                    "HOME": str(home),
                    "ATTACCA_OWNER": "",
                    "ATTACCA_ACTOR": "codex",
                    "ATTACCA_URL": "http://127.0.0.1:%d"
                                   % server.server_address[1],
                    "ATTACCA_AUTOSTART": "0",
                    "ATTACCA_DISABLE_WATCHER": "1",
                    "ATTACCA_WATCHER_DIR": str(root / "watcher"),
                })
                for key in ("ATTACCA_PROJECT", "CLAUDE_PLUGIN_ROOT",
                            "CLAUDE_PLUGIN_DATA", "KIMI_PLUGIN_ROOT",
                            "KIMI_PLUGIN_DATA"):
                    env.pop(key, None)
                result = subprocess.run(
                    [sys.executable, str(HOOK)], cwd=str(checkout), env=env,
                    input=json.dumps({
                        "cwd": str(checkout),
                        "hook_event_name": "SessionStart",
                        "source": "startup",
                    }), capture_output=True, text=True, timeout=10,
                    check=True)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            payload = json.loads(result.stdout)
            context = payload["hookSpecificOutput"]["additionalContext"]
            brief = json.loads(context[context.index("{"):])
            returned = {
                rule["title"]: rule for rule in brief["project_rules"]
            }
            self.assertEqual(
                set(returned), {
                    DEFAULT_AUTHORITY_TITLE,
                    "Startup baseline",
                    "Startup worker",
                })
            self.assertEqual(
                returned[DEFAULT_AUTHORITY_TITLE]["rule_id"], "R-0")
            self.assertEqual(
                returned[DEFAULT_AUTHORITY_TITLE]["body"],
                DEFAULT_AUTHORITY_BODY)
            self.assertEqual(returned["Startup baseline"]["version"], 2)
            self.assertEqual(
                returned["Startup baseline"]["body"],
                "SERVER-STARTUP-EVERYONE-v2")
            self.assertEqual(returned["Startup worker"]["scope"], "worker")
            self.assertNotIn("SERVER-STARTUP-DIRECTOR", context)
            for local_text in LOCAL_ONLY_TEXT:
                self.assertNotIn(local_text, context)


if __name__ == "__main__":
    unittest.main()
