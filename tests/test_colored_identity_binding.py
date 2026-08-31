"""D-21 colored actor identity and machine-binding contracts.

This suite is deliberately local-only: every database, machine configuration,
and client installation lives below a :class:`TemporaryDirectory`.  It never
discovers, contacts, restarts, or reconfigures the shared development server.

D-21 separates three concepts which used to be accidentally conflated:

* the durable AI actor is ``workspace.role.runtime.color``;
* the machine-local client installation chooses one exact actor; and
* a host-process/session id is transient transport state, never identity.

The first setup-created actor gets ``red`` even when a three-part compatibility
actor already exists.  A second independent installation gets ``blue``.  A
normal start from the same installation silently reuses its binding, while an
explicit setup can reuse an exact actor, allocate a new color, or select a
temporary current-process actor without persisting that choice.
"""

import concurrent.futures
import importlib.util
import json
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace


# Test attribution and state must not inherit the operator's real machine.
os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "attacca_colored_identity_binding_under_test", ROOT / "attacca.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


SERVER_A_INPUT = "HTTPS://Attacca.Example:443/tenant-a/"
SERVER_A = "https://attacca.example/tenant-a"
SERVER_B = "https://attacca.example/tenant-b"
PROJECT = "p1"


class ColoredIdentityBindingContractTest(unittest.TestCase):
    """Storage/setup contracts for more than one same-runtime AI."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.db = self.root / "attacca.db"
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.home_a = self.root / "home-a"
        self.home_b = self.root / "home-b"
        self.home_c = self.root / "home-c"
        self.conn = c.connect(self.db)
        c.project_init(
            self.conn, "setup", "human", path=str(self.repo),
            project_id=PROJECT, name="Colored identities")

    def tearDown(self):
        self.conn.close()
        c.set_current_owner(None)
        self.temporary.cleanup()

    def _require(self, name):
        value = getattr(c, name, None)
        self.assertTrue(
            callable(value),
            "%s is required by accepted D-21" % name)
        return value

    @staticmethod
    def _actors(conn):
        return [dict(row) for row in conn.execute(
            "SELECT * FROM agents WHERE project_id=? ORDER BY agent_id",
            (PROJECT,)).fetchall()]

    @staticmethod
    def _binding_actor(binding):
        return binding.get("actor_id") if isinstance(binding, dict) \
            else binding

    def _select(self, *, mode, role="director", runtime="codex",
                actor_id=None, client_instance="client-a", home=None,
                session=None):
        select = self._require("select_setup_identity")
        return select(
            self.conn, PROJECT, role, runtime, mode=mode,
            actor_id=actor_id, server_url=SERVER_A_INPUT,
            client_instance=client_instance,
            home=home or self.home_a, session=session)

    def test_palette_and_next_color_are_deterministic(self):
        palette = getattr(c, "AGENT_PERSONA_COLORS", None)
        self.assertIsInstance(
            palette, (tuple, list),
            "AGENT_PERSONA_COLORS is required by accepted D-21")
        self.assertGreaterEqual(len(palette), 4)
        self.assertEqual(list(palette[:3]), ["red", "blue", "green"])
        self.assertEqual(len(palette), len(set(palette)))
        for color in palette:
            self.assertEqual(c.normalize_agent_persona(color), color)

        next_persona = self._require("next_agent_persona")
        legacy = {"agent_id": "p1.director.codex", "role": "director",
                  "runtime": "codex"}
        red = {"agent_id": "p1.director.codex.red", "role": "director",
               "runtime": "codex"}
        blue = {"agent_id": "p1.director.codex.blue", "role": "director",
                "runtime": "codex"}
        other_role = {"agent_id": "p1.worker.codex.red", "role": "worker",
                      "runtime": "codex"}
        other_runtime = {
            "agent_id": "p1.director.claude.red", "role": "director",
            "runtime": "claude"}

        self.assertEqual(next_persona([], PROJECT, "director", "codex"),
                         "red")
        # Three-part compatibility actors and other role/runtime namespaces do
        # not consume this setup allocator's color sequence.
        self.assertEqual(next_persona(
            [legacy, other_role, other_runtime], PROJECT, "director",
            "codex"), "red")
        self.assertEqual(next_persona(
            [legacy, red], PROJECT, "director", "codex"), "blue")
        self.assertEqual(next_persona(
            [blue, red], PROJECT, "director", "codex"), "green")

    def test_first_and_second_new_installations_get_red_then_blue(self):
        first = self._select(
            mode="new", client_instance="client-install-a",
            home=self.home_a)
        second = self._select(
            mode="new", client_instance="client-install-b",
            home=self.home_b)

        self.assertEqual(first["actor_id"], "p1.director.codex.red")
        self.assertEqual(second["actor_id"], "p1.director.codex.blue")
        self.assertEqual(c.parse_canonical_agent_id(
            first["actor_id"], PROJECT)["persona"], "red")
        self.assertEqual(c.parse_canonical_agent_id(
            second["actor_id"], PROJECT)["persona"], "blue")
        self.assertTrue(first["binding_saved"])
        self.assertTrue(second["binding_saved"])
        self.assertFalse(first.get("temporary", False))
        self.assertFalse(second.get("temporary", False))
        self.assertEqual(
            {row["agent_id"] for row in self._actors(self.conn)},
            {"p1.director.codex.red", "p1.director.codex.blue"})

        binding_get = self._require("machine_actor_binding_get")
        self.assertEqual(self._binding_actor(binding_get(
            SERVER_A, PROJECT, "codex", "client-install-a",
            home=self.home_a)), first["actor_id"])
        self.assertEqual(self._binding_actor(binding_get(
            SERVER_A, PROJECT, "codex", "client-install-b",
            home=self.home_b)), second["actor_id"])

    def test_new_color_allocation_is_atomic_across_clients(self):
        """Two setup requests cannot both claim the same next color."""
        select = self._require("select_setup_identity")
        barrier = threading.Barrier(2)

        def allocate(index):
            conn = c.connect(self.db)
            try:
                barrier.wait(timeout=5)
                result = select(
                    conn, PROJECT, "director", "codex", mode="new",
                    server_url=SERVER_A,
                    client_instance="concurrent-client-%d" % index,
                    home=self.root / ("concurrent-home-%d" % index))
                return result["actor_id"]
            finally:
                conn.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            actors = set(pool.map(allocate, (1, 2)))
        self.assertEqual(
            actors,
            {"p1.director.codex.red", "p1.director.codex.blue"})

    def test_binding_scope_uses_full_url_workspace_runtime_and_installation(self):
        binding_set = self._require("machine_actor_binding_set")
        binding_get = self._require("machine_actor_binding_get")
        actor = "p1.director.codex.red"
        saved_a = binding_set(
            SERVER_A_INPUT, PROJECT, "codex", actor,
            client_instance="client-a", home=self.home_a)
        saved_b = binding_set(
            SERVER_B, PROJECT, "codex", "p1.director.codex.blue",
            client_instance="client-a", home=self.home_a)

        # Canonical URL spelling resolves the same record, while every other
        # dimension is an independent boundary.
        binding_a = binding_get(
            SERVER_A, PROJECT, "codex", "client-a", home=self.home_a)
        self.assertEqual(self._binding_actor(binding_a), actor)
        self.assertIsNone(binding_get(
            SERVER_A, PROJECT, "codex", "client-b", home=self.home_a))
        self.assertIsNone(binding_get(
            SERVER_A, "p2", "codex", "client-a", home=self.home_a))
        self.assertIsNone(binding_get(
            SERVER_A, PROJECT, "claude", "client-a", home=self.home_a))
        binding_b = binding_get(
            SERVER_B, PROJECT, "codex", "client-a", home=self.home_a)
        self.assertEqual(self._binding_actor(binding_b),
                         "p1.director.codex.blue")
        self.assertIsNone(binding_get(
            SERVER_A, PROJECT, "codex", "client-a", home=self.home_b))

        path = c.machine_config_path(self.home_a)
        self.assertTrue(path.is_file())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        payload = json.loads(path.read_text())
        bindings = payload.get("actor_bindings")
        self.assertIsInstance(bindings, dict)

        key_a = saved_a["binding_key"]
        key_b = saved_b["binding_key"]
        self.assertNotEqual(key_a, key_b)
        self.assertEqual(bindings[key_a]["actor_id"], actor)
        self.assertEqual(bindings[key_a]["server_url"], SERVER_A)
        self.assertEqual(bindings[key_a]["project_id"], PROJECT)
        self.assertEqual(bindings[key_a]["runtime"], "codex")
        self.assertEqual(bindings[key_a]["client_instance"], "client-a")
        self.assertEqual(binding_a["binding_key"], key_a)
        self.assertEqual(binding_b["binding_key"], key_b)

        # The integrity key changes for every scope dimension. This proves a
        # same-origin path deployment, another workspace/runtime, or another
        # client installation cannot collide with this binding.
        key_fn = self._require("_machine_actor_binding_key")
        scope_keys = {
            key_fn(SERVER_A, PROJECT, "codex", "client-a")[0],
            key_fn(SERVER_B, PROJECT, "codex", "client-a")[0],
            key_fn(SERVER_A, "p2", "codex", "client-a")[0],
            key_fn(SERVER_A, PROJECT, "claude", "client-a")[0],
            key_fn(SERVER_A, PROJECT, "codex", "client-b")[0],
        }
        self.assertEqual(len(scope_keys), 5)

        with self.assertRaises(c.AttaccaError):
            binding_set(
                SERVER_A, PROJECT, "codex", "p2.director.codex.red",
                client_instance="client-a", home=self.home_a)
        with self.assertRaises(c.AttaccaError):
            binding_set(
                SERVER_A, PROJECT, "codex", "p1.director.claude.red",
                client_instance="client-a", home=self.home_a)

    def test_same_machine_binding_silently_survives_new_host_sessions(self):
        created = self._select(
            mode="new", client_instance=None, home=self.home_a)
        actor = created["actor_id"]
        stable_instance = c._client_instance_for_runtime(
            "codex", home=self.home_a)

        binding_get = self._require("machine_actor_binding_get")
        for _new_or_resumed_host_process in range(3):
            self.assertEqual(self._binding_actor(binding_get(
                SERVER_A, PROJECT, "codex", stable_instance,
                home=self.home_a)), actor)

        # Setup discovery reports an automatic choice when the exact local
        # binding is still registered. It does not ask on every Codex resume.
        options_fn = self._require("setup_identity_options")
        options = options_fn(
            self._actors(self.conn), PROJECT, "director", "codex",
            bound_actor_id=actor)
        self.assertEqual(options["bound_actor_id"], actor)
        self.assertFalse(options["selection_required"])
        self.assertEqual(options["new_identity"]["mode"], "new")
        self.assertEqual(options["temporary_identity"]["mode"],
                         "temporary")
        self.assertIn(actor, [item["actor_id"]
                              for item in options["reusable_identities"]])

        # The static connection deliberately remains a runtime hint: the
        # long-running proxy hot-reads this private binding on every request,
        # so changing an identity never requires rewriting/reloading MCP.
        first = c.mcp_connect_config(
            "codex", SERVER_A, home=self.home_a, project_id=PROJECT)
        second = c.mcp_connect_config(
            "codex", SERVER_A, home=self.home_a, project_id=PROJECT)
        self.assertEqual(first["env"][c.ENV_ACTOR], "codex")
        self.assertEqual(first["env"][c.ENV_CLIENT_INSTANCE],
                         stable_instance)
        self.assertEqual(first, second)

    def test_separate_unbound_installation_requires_one_time_setup_choice(self):
        created = self._select(
            mode="new", client_instance="client-a", home=self.home_a)
        options_fn = self._require("setup_identity_options")

        unbound = options_fn(
            self._actors(self.conn), PROJECT, "director", "codex",
            bound_actor_id=None)
        self.assertTrue(unbound["selection_required"])
        self.assertIsNone(unbound["bound_actor_id"])
        self.assertEqual(unbound["new_identity"]["persona_preview"],
                         "blue")
        self.assertEqual(unbound["new_identity"]["actor_id_preview"],
                         "p1.director.codex.blue")
        self.assertIn(created["actor_id"], [
            item["actor_id"] for item in unbound["reusable_identities"]])

        binding_get = self._require("machine_actor_binding_get")
        self.assertIsNone(binding_get(
            SERVER_A, PROJECT, "codex", "client-container-b",
            home=self.home_b))

    def test_setup_reuse_new_and_temporary_modes_have_distinct_persistence(self):
        red = self._select(
            mode="new", client_instance="client-a", home=self.home_a)
        reused = self._select(
            mode="reuse", actor_id=red["actor_id"],
            client_instance="client-b", home=self.home_b)
        self.assertEqual(reused["actor_id"], red["actor_id"])
        self.assertTrue(reused["binding_saved"])
        self.assertFalse(reused.get("temporary", False))

        blue = self._select(
            mode="new", client_instance="client-c", home=self.home_c)
        self.assertEqual(blue["actor_id"], "p1.director.codex.blue")

        temporary_home = self.root / "temporary-home"
        session = SimpleNamespace(
            actor="codex", session_id="codex-session-never-durable-987")
        temporary = self._select(
            mode="temporary", client_instance="client-temp",
            home=temporary_home, session=session)
        parsed = c.parse_canonical_agent_id(temporary["actor_id"], PROJECT)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["role"], "director")
        self.assertEqual(parsed["runtime"], "codex")
        self.assertIn(parsed["persona"], c.AGENT_PERSONA_COLORS)
        self.assertTrue(temporary["temporary"])
        self.assertFalse(temporary["binding_saved"])
        self.assertEqual(session.actor, temporary["actor_id"])

        binding_get = self._require("machine_actor_binding_get")
        self.assertIsNone(binding_get(
            SERVER_A, PROJECT, "codex", "client-temp",
            home=temporary_home))
        # A fresh host process has no memory of a temporary selection.
        fresh_process = SimpleNamespace(actor="codex")
        self.assertEqual(fresh_process.actor, "codex")
        machine_path = c.machine_config_path(temporary_home)
        serialized_machine = machine_path.read_text() \
            if machine_path.exists() else ""
        self.assertNotIn(session.session_id, serialized_machine)
        self.assertNotIn(session.session_id, temporary["actor_id"])
        rows = self.conn.execute(
            "SELECT agent_id,display_name FROM agents WHERE project_id=?",
            (PROJECT,)).fetchall()
        self.assertNotIn(
            session.session_id,
            json.dumps([dict(row) for row in rows], sort_keys=True))

        with self.assertRaises(c.AttaccaError):
            self._select(
                mode="reuse", actor_id="p1.director.codex.missing",
                client_instance="client-missing",
                home=self.root / "missing-home")
        with self.assertRaises(c.AttaccaError):
            self._select(
                mode="reuse", actor_id="p1.worker.codex.red",
                client_instance="client-wrong-role",
                home=self.root / "wrong-role-home")

    def test_three_part_actor_is_explicit_compatibility_not_silent_default(self):
        legacy = "p1.director.codex"
        c.agent_register(
            self.conn, PROJECT, legacy, "agent", agent_id=legacy,
            display_name="Legacy Codex Director", role="director",
            runtime="codex", canonical_identity=False)

        options_fn = self._require("setup_identity_options")
        options = options_fn(
            self._actors(self.conn), PROJECT, "director", "codex",
            bound_actor_id=None)
        self.assertTrue(options["selection_required"])
        self.assertIsNone(options["bound_actor_id"])
        self.assertEqual(options["new_identity"]["persona_preview"],
                         "red")
        compatibility = [item for item in options["reusable_identities"]
                         if item["actor_id"] == legacy]
        self.assertEqual(len(compatibility), 1)
        self.assertTrue(compatibility[0]["compatibility_identity"])

        # Choosing New creates red without deleting, aliasing, or silently
        # rewriting the old three-part actor.
        new = self._select(
            mode="new", client_instance="client-new", home=self.home_a)
        self.assertEqual(new["actor_id"], "p1.director.codex.red")
        self.assertEqual(
            {row["agent_id"] for row in self._actors(self.conn)},
            {legacy, "p1.director.codex.red"})
        self.assertIsNone(self.conn.execute(
            "SELECT canonical_actor_id FROM actor_aliases"
            " WHERE project_id=? AND legacy_actor_id=?",
            (PROJECT, legacy)).fetchone())

        # Take over/reuse is allowed only because setup named the exact legacy
        # identity. It stays three-part until an explicit migration operation.
        reused = self._select(
            mode="reuse", actor_id=legacy,
            client_instance="client-legacy", home=self.home_b)
        self.assertEqual(reused["actor_id"], legacy)
        self.assertIsNone(c.parse_canonical_agent_id(
            reused["actor_id"], PROJECT)["persona"])
        self.assertEqual(self._binding_actor(
            self._require("machine_actor_binding_get")(
            SERVER_A, PROJECT, "codex", "client-legacy",
            home=self.home_b)), legacy)

    def test_role_alone_controls_authority_not_color_or_runtime(self):
        codex_director = self._select(
            mode="new", role="director", runtime="codex",
            client_instance="codex-director", home=self.home_a)
        claude_director = self._select(
            mode="new", role="director", runtime="claude",
            client_instance="claude-director", home=self.home_b)
        codex_worker = self._select(
            mode="new", role="worker", runtime="codex",
            client_instance="codex-worker", home=self.home_c)

        self.assertEqual(codex_director["actor_id"],
                         "p1.director.codex.red")
        self.assertEqual(claude_director["actor_id"],
                         "p1.director.claude.red")
        self.assertEqual(codex_worker["actor_id"],
                         "p1.worker.codex.red")
        self.assertEqual(c._registered_actor_role(
            self.conn, PROJECT, codex_director["actor_id"]), "director")
        self.assertEqual(c._registered_actor_role(
            self.conn, PROJECT, claude_director["actor_id"]), "director")
        self.assertEqual(c._registered_actor_role(
            self.conn, PROJECT, codex_worker["actor_id"]), "worker")

        # Runtime and color are audit/continuity dimensions only. Both
        # Directors can manage rules; the red Codex Worker cannot.
        c.rule_create(
            self.conn, PROJECT, codex_director["actor_id"], "agent",
            "Codex Director rule", "director authority")
        c.rule_create(
            self.conn, PROJECT, claude_director["actor_id"], "agent",
            "Claude Director rule", "same director authority")
        with self.assertRaisesRegex(c.AttaccaError, "registered Director"):
            c.rule_create(
                self.conn, PROJECT, codex_worker["actor_id"], "agent",
                "Worker escalation", "must not gain authority from color")


if __name__ == "__main__":
    unittest.main()
