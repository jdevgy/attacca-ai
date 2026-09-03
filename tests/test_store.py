"""Storage-layer semantics tests for attacca.py (stdlib unittest)."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Isolate tests from any machine identity (~/.attacca/identity.json)
os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("attacca", ROOT / "attacca.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        self.conn = c.connect(self.db)
        self.proj_dir = Path(self.tmp.name) / "repo"
        self.proj_dir.mkdir()
        c.project_init(self.conn, "tester", "human", path=str(self.proj_dir),
                       project_id="p1", name="Project One")

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _register_handoff_actor(self, actor, role="worker", runtime="store"):
        """Register one exact fixture identity before it owns continuity."""
        return c.agent_register(
            self.conn, "p1", actor, "agent", role=role, runtime=runtime)

    # -- events / ledger ----------------------------------------------------

    def test_event_seq_and_chain(self):
        for i in range(5):
            c.append_event(self.conn, "p1", "a", "agent", "note.test", {"i": i})
        rows = self.conn.execute(
            "SELECT seq, prev_hash, hash FROM events WHERE project_id='p1' ORDER BY seq"
        ).fetchall()
        self.assertEqual([r["seq"] for r in rows], list(range(1, len(rows) + 1)))
        for prev, cur in zip(rows, rows[1:]):
            self.assertEqual(cur["prev_hash"], prev["hash"])
        result = c.verify_ledger(self.conn, "p1")
        self.assertTrue(result["ok"], result["problems"])

    def test_verify_detects_tampering(self):
        c.append_event(self.conn, "p1", "a", "agent", "note.test", {"x": 1})
        self.conn.execute(
            "UPDATE events SET payload='{\"x\":999}' WHERE project_id='p1' AND event_type='note.test'")
        result = c.verify_ledger(self.conn, "p1")
        self.assertFalse(result["ok"])
        self.assertTrue(any("tampered" in p for p in result["problems"]))

    def test_verify_detects_seq_gap(self):
        for i in range(3):
            c.append_event(self.conn, "p1", "a", "agent", "note.test", {"i": i})
        self.conn.execute(
            "DELETE FROM events WHERE project_id='p1' AND event_type='note.test'"
            " AND seq=(SELECT MIN(seq) FROM events WHERE event_type='note.test')")
        result = c.verify_ledger(self.conn, "p1")
        self.assertFalse(result["ok"])
        self.assertTrue(any("gap" in p or "chain" in p for p in result["problems"]))

    # -- tasks --------------------------------------------------------------

    def test_task_lifecycle(self):
        created = c.task_create(self.conn, "p1", "a", "agent", "Do a thing",
                                expected_scope=["src/**"], risk_level="high")
        tid = created["task_id"]
        self.assertEqual(tid, "T-1")
        claim = c.task_claim(self.conn, "p1", "a", "agent", tid)
        self.assertEqual(claim["claimed_by"], "a")
        report = c.task_report(self.conn, "p1", "a", "agent", tid,
                               summary="did it",
                               evidence=[{"kind": "test", "result": "pass"}],
                               requested_state="done")
        self.assertEqual(report["status"], "done")
        self.assertIn("context_version", report)  # done bumps context
        task = c.task_show(self.conn, "p1", tid)
        self.assertEqual(task["status"], "done")
        self.assertEqual(task["last_report"]["summary"], "did it")
        self.assertTrue(task["history"])

    def test_claim_contention_and_lease(self):
        tid = c.task_create(self.conn, "p1", "a", "agent", "contended")["task_id"]
        c.task_claim(self.conn, "p1", "alice", "agent", tid)
        with self.assertRaises(c.AttaccaError):
            c.task_claim(self.conn, "p1", "bob", "agent", tid)
        # same claimant renews
        renewed = c.task_claim(self.conn, "p1", "alice", "agent", tid)
        self.assertTrue(renewed["renewed"])
        # expired lease is reclaimable by someone else
        self.conn.execute(
            "UPDATE tasks SET lease_until='2000-01-01T00:00:00.000Z'"
            " WHERE project_id='p1' AND task_id=?", (tid,))
        stolen = c.task_claim(self.conn, "p1", "bob", "agent", tid)
        self.assertEqual(stolen["claimed_by"], "bob")

    def test_report_without_evidence_warns(self):
        tid = c.task_create(self.conn, "p1", "a", "agent", "t")["task_id"]
        c.task_claim(self.conn, "p1", "a", "agent", tid)
        report = c.task_report(self.conn, "p1", "a", "agent", tid, summary="done-ish")
        self.assertTrue(any("evidence" in w for w in report["warnings"]))

    def test_release_and_set_status(self):
        tid = c.task_create(self.conn, "p1", "a", "agent", "t")["task_id"]
        c.task_claim(self.conn, "p1", "a", "agent", tid)
        released = c.task_release(self.conn, "p1", "a", "agent", tid, reason="nope")
        self.assertEqual(released["status"], "queued")
        with self.assertRaises(c.AttaccaError):
            c.task_release(self.conn, "p1", "a", "agent", tid)
        moved = c.task_set_status(self.conn, "p1", "rev", "human", tid, "done",
                                  reason="reviewed ok")
        self.assertEqual(moved["status"], "done")
        self.assertIn("context_version", moved)

    def test_scope_overlap(self):
        self.assertTrue(c._scopes_overlap(["src/auth/**"], ["src/auth/callback.ts"]))
        self.assertTrue(c._scopes_overlap(["src/auth"], ["src/auth/deep/file.ts"]))
        self.assertTrue(c._scopes_overlap(["a.ts"], ["a.ts"]))
        self.assertFalse(c._scopes_overlap(["src/auth/**"], ["docs/readme.md"]))
        self.assertFalse(c._scopes_overlap([], ["anything"]))

    def test_overlap_warning_on_claim(self):
        t1 = c.task_create(self.conn, "p1", "a", "agent", "one",
                           expected_scope=["src/auth/**"])["task_id"]
        t2 = c.task_create(self.conn, "p1", "b", "agent", "two",
                           expected_scope=["src/auth/session.ts"])["task_id"]
        c.task_claim(self.conn, "p1", "a", "agent", t1)
        claim2 = c.task_claim(self.conn, "p1", "b", "agent", t2)
        self.assertTrue(any("overlap" in w for w in claim2["warnings"]))

    def test_dependency_warning_on_claim(self):
        t1 = c.task_create(self.conn, "p1", "a", "agent", "first")["task_id"]
        t2 = c.task_create(self.conn, "p1", "a", "agent", "second",
                           dependencies=[t1])["task_id"]
        claim = c.task_claim(self.conn, "p1", "b", "agent", t2)
        self.assertTrue(any("dependency" in w for w in claim["warnings"]))

    # -- handoff / context version / freshness ------------------------------

    def test_identity_handoff_partial_merge_and_versions(self):
        self._register_handoff_actor("a")
        self._register_handoff_actor("b")
        c.update_identity_handoff(
            self.conn, "p1", "a", "agent",
            {"objective": "obj1", "risks": "r1"}, expected_version=0)
        second = c.update_identity_handoff(
            self.conn, "p1", "a", "agent", {"objective": "obj2"},
            expected_version=1)
        handoff = c.get_identity_handoff(
            self.conn, "p1", actor_id="a", actor_type="agent")
        self.assertEqual(handoff["handoff"]["objective"], "obj2")
        self.assertEqual(handoff["handoff"]["risks"], "r1")  # preserved
        self.assertEqual(handoff["handoff_updated_by"], "a")
        self.assertEqual(handoff["handoff_version"], 2)
        self.assertEqual(handoff["context_version"], second["context_version"])
        count = self.conn.execute(
            "SELECT COUNT(*) AS n FROM identity_handoffs"
            " WHERE project_id='p1' AND actor_id='a'").fetchone()["n"]
        self.assertEqual(count, 2)  # history preserved

        c.update_identity_handoff(
            self.conn, "p1", "b", "agent", {"objective": "b's own"},
            expected_version=0)
        other = c.get_identity_handoff(
            self.conn, "p1", actor_id="b", actor_type="agent")
        self.assertEqual(other["handoff"]["objective"], "b's own")
        self.assertIsNone(other["handoff"]["risks"])
        self.assertEqual(c.get_identity_handoff(
            self.conn, "p1", actor_id="a", actor_type="agent"
        )["handoff"]["objective"], "obj2")
        # The shared project handoff is a separate record and stays empty.
        self.assertIsNone(c.get_handoff(
            self.conn, "p1", actor_id="a",
            actor_type="agent")["handoff"]["objective"])

    def test_handoff_requires_a_field(self):
        with self.assertRaises(c.AttaccaError):
            c.update_handoff(self.conn, "p1", "a", "agent", {})
        with self.assertRaises(c.AttaccaError):
            c.update_identity_handoff(self.conn, "p1", "a", "agent", {})

    def test_shared_project_handoff_is_director_only_and_read_by_everyone(self):
        self._register_handoff_actor("shared-director", role="director")
        self._register_handoff_actor("shared-worker", role="worker")
        written = c.update_handoff(
            self.conn, "p1", "shared-director", "agent",
            {"objective": "one project objective"}, expected_version=0)
        self.assertIsNone(written["handoff_actor"])
        self.assertEqual(written["handoff_scope"], "project")
        self.assertEqual(written["handoff_version"], 1)
        for reader in ("shared-director", "shared-worker"):
            brief = c.get_handoff(
                self.conn, "p1", actor_id=reader, actor_type="agent")
            self.assertEqual(brief["handoff"]["objective"],
                             "one project objective")
            self.assertEqual(brief["shared_handoff"], brief["handoff"])
            self.assertEqual(brief["handoff_scope"], "project")
            self.assertIsNone(brief["handoff_actor"])
            self.assertEqual(brief["identity_handoff_actor"], reader)
        with self.assertRaisesRegex(
                c.AttaccaError, "may only be edited by a registered Director"):
            c.update_handoff(
                self.conn, "p1", "shared-worker", "agent",
                {"objective": "worker overwrite"}, expected_version=1)
        with self.assertRaisesRegex(
                c.AttaccaError, "may only be edited by a registered Director"):
            c.update_handoff(
                self.conn, "p1", "owner", "human",
                {"objective": "human overwrite"}, expected_version=1)

    def test_exact_identity_handoffs_are_role_independent_and_version_checked(self):
        for agent_id, role in (("director-a", "director"),
                               ("director-b", "director"),
                               ("advisor", "advisor"),
                               ("worker", "worker")):
            c.agent_register(self.conn, "p1", agent_id, "agent",
                             role=role, runtime="test")
        c.set_lead_director(
            self.conn, "p1", "admin", "human", "director-a")
        brief = c.get_handoff(
            self.conn, "p1", actor_id="director-a", actor_type="agent")
        expected = brief["context_version"]
        written = c.update_identity_handoff(
            self.conn, "p1", "director-a", "agent",
            {"what_changed": "director A wrote first"},
            expected_context_version=expected)
        with self.assertRaisesRegex(c.AttaccaError, "handoff conflict"):
            c.update_identity_handoff(
                self.conn, "p1", "director-b", "agent",
                {"what_changed": "stale director B overwrite"},
                expected_context_version=expected)
        self.assertEqual(
            c.get_identity_handoff(
                self.conn, "p1", actor_id="director-a",
                actor_type="agent")["handoff"]["what_changed"],
            "director A wrote first")
        current_context = written["context_version"]
        for agent_id in ("advisor", "worker"):
            own = c.update_identity_handoff(
                self.conn, "p1", agent_id, "agent",
                {"notes": "%s continuity" % agent_id},
                expected_context_version=current_context,
                expected_version=0)
            current_context = own["context_version"]
            self.assertEqual(c.get_identity_handoff(
                self.conn, "p1", actor_id=agent_id,
                actor_type="agent")["handoff"]["notes"],
                "%s continuity" % agent_id)
            self.assertIsNone(c.get_identity_handoff(
                self.conn, "p1", actor_id=agent_id,
                actor_type="agent")["handoff"]["what_changed"])
        # Humans and console identities own no identity handoff at all.
        with self.assertRaisesRegex(
                c.AttaccaError, "one exact registered AI"):
            c.update_identity_handoff(
                self.conn, "p1", "owner", "human", {"notes": "reviewed"},
                expected_context_version=current_context, expected_version=0)
        human_read = c.get_identity_handoff(
            self.conn, "p1", actor_id="owner", actor_type="human")
        self.assertIsNone(human_read["handoff_actor"])
        self.assertIsNone(human_read["handoff"]["notes"])

    def test_lead_director_cannot_be_registered_as_non_director(self):
        c.agent_register(self.conn, "p1", "worker", "agent",
                         role="worker", runtime="test")
        with self.assertRaisesRegex(c.AttaccaError, "role to director"):
            c.set_lead_director(
                self.conn, "p1", "admin", "human", "worker")
        with self.assertRaisesRegex(c.AttaccaError, "not registered"):
            c.set_lead_director(
                self.conn, "p1", "admin", "human", "ghost")
        c.agent_register(self.conn, "p1", "lead", "agent",
                         role="director", runtime="test")
        c.set_lead_director(self.conn, "p1", "admin", "human", "lead")
        with self.assertRaisesRegex(c.AttaccaError, "must keep the director"):
            c.agent_register(self.conn, "p1", "lead", "agent",
                             role="advisor", runtime="test")

    def test_freshness(self):
        self._register_handoff_actor("a")
        v0 = c.get_project(self.conn, "p1")["context_version"]
        fresh = c.check_freshness(self.conn, "p1", v0)
        self.assertFalse(fresh["stale"])
        c.update_identity_handoff(
            self.conn, "p1", "a", "agent", {"objective": "x"})
        stale = c.check_freshness(self.conn, "p1", v0)
        self.assertTrue(stale["stale"])
        self.assertTrue(stale["changes_since_your_briefing"])

    def test_decision_flow(self):
        dec = c.decision_propose(self.conn, "p1", "a", "agent", "Use PKCE",
                                 rationale="safer")
        did = dec["decision_id"]
        self.assertEqual(did, "D-1")
        v_before = c.get_project(self.conn, "p1")["context_version"]
        resolved = c.decision_resolve(self.conn, "p1", "h", "human", did, "accepted")
        self.assertEqual(resolved["context_version"], v_before + 1)
        with self.assertRaises(c.AttaccaError):
            c.decision_resolve(self.conn, "p1", "h", "human", did, "rejected")
        # superseding an already-resolved decision is allowed
        c.decision_resolve(self.conn, "p1", "h", "human", did, "superseded")

    # -- room ---------------------------------------------------------------

    def test_room_cursor(self):
        for i in range(3):
            c.room_send(self.conn, "p1", "a", "agent", "msg %d" % i)
        first = c.room_read(self.conn, "p1")
        self.assertEqual(len(first["messages"]), 3)
        cursor = first["next_since_seq"]
        empty = c.room_read(self.conn, "p1", since_seq=cursor)
        self.assertEqual(empty["messages"], [])
        c.room_send(self.conn, "p1", "b", "agent", "new one")
        newer = c.room_read(self.conn, "p1", since_seq=cursor)
        self.assertEqual(len(newer["messages"]), 1)
        self.assertEqual(newer["messages"][0]["body"], "new one")

    def test_cross_project_message(self):
        c.project_init(self.conn, "tester", "human",
                       path=str(Path(self.tmp.name) / "other"),
                       project_id="p2", name="Project Two")
        c.bridge_add(self.conn, "p1", "tester", "human", "p2")
        c.room_send(self.conn, "p2", "a", "agent", "hello p2",
                    origin_project="p1")
        msgs = c.room_read(self.conn, "p2")["messages"]
        self.assertEqual(msgs[-1]["origin_project"], "p1")
        source = c.room_read(self.conn, "p1")["messages"][-1]
        self.assertEqual(source["mirrored_to"], ["p2"])

    def test_room_rejects_bad_type(self):
        with self.assertRaises(c.AttaccaError):
            c.room_send(self.conn, "p1", "a", "agent", "x", msg_type="shout")
        with self.assertRaises(c.AttaccaError):
            c.room_send(self.conn, "p1", "a", "agent", "   ")

    # -- projects / resolution ----------------------------------------------

    def test_project_resolution(self):
        self.assertEqual(
            c.resolve_project_id(self.conn, cwd=str(self.proj_dir)), "p1")
        sub = self.proj_dir / "deep" / "nested"
        sub.mkdir(parents=True)
        self.assertEqual(c.resolve_project_id(self.conn, cwd=str(sub)), "p1")
        # single-project fallback when cwd is unrelated
        self.assertEqual(
            c.resolve_project_id(self.conn, cwd=self.tmp.name), "p1")
        c.project_init(self.conn, "t", "human",
                       path=str(Path(self.tmp.name) / "other"),
                       project_id="p2", name="Two")
        with self.assertRaises(c.AttaccaError):
            c.resolve_project_id(self.conn, cwd=self.tmp.name)
        self.assertEqual(
            c.resolve_project_id(self.conn, explicit="p2", cwd=self.tmp.name), "p2")

    def test_project_link_resolution_and_explicit_precedence(self):
        other_root = Path(self.tmp.name) / "other-project"
        checkout = Path(self.tmp.name) / "computer-b" / "checkout"
        nested = checkout / "src" / "deep"
        other_root.mkdir()
        nested.mkdir(parents=True)
        c.project_init(self.conn, "t", "human", path=str(other_root),
                       project_id="p2", name="Two")
        c.write_project_link(checkout, "p1")
        self.assertEqual(c.resolve_project_id(self.conn, cwd=str(nested)), "p1")
        self.assertEqual(c.resolve_project_id(
            self.conn, explicit="p2", cwd=str(nested)), "p2")

    def test_malformed_project_link_fails_loudly(self):
        checkout = Path(self.tmp.name) / "broken-link"
        link_dir = checkout / ".attacca"
        link_dir.mkdir(parents=True)
        (link_dir / "project.json").write_text("{not-json")
        with self.assertRaisesRegex(c.AttaccaError, "not valid JSON"):
            c.resolve_project_id(self.conn, cwd=str(checkout))

    def test_git_remote_normalization(self):
        expected = "github.com/jdevgy/attacca-ai"
        self.assertEqual(c.canonical_git_remote(
            "git@github.com:jdevgy/attacca-ai.git"), expected)
        self.assertEqual(c.canonical_git_remote(
            "https://token@github.com/jdevgy/attacca-ai.git"), expected)
        self.assertEqual(c.canonical_git_remote(
            "ssh://git@github.com/jdevgy/attacca-ai.git"), expected)

    def test_repository_fingerprint_cannot_move_between_projects(self):
        fingerprint = "sha256:" + "b" * 64
        c.remember_repository_fingerprint(
            self.conn, "p1", fingerprint, "me", "human")
        other = Path(self.tmp.name) / "other"
        other.mkdir()
        c.project_init(self.conn, "me", "human", path=str(other),
                       project_id="p2")
        with self.assertRaisesRegex(c.AttaccaError, "already linked"):
            c.remember_repository_fingerprint(
                self.conn, "p2", fingerprint, "me", "human")

    def test_unknown_project(self):
        with self.assertRaises(c.AttaccaError):
            c.get_project(self.conn, "nope")

    def test_agent_registry(self):
        first = c.agent_register(self.conn, "p1", "agt1", "agent",
                                 role="director", runtime="claude-code")
        self.assertFalse(first["already_registered"])
        again = c.agent_register(self.conn, "p1", "agt1", "agent")
        self.assertTrue(again["already_registered"])
        agents = c.agent_list(self.conn, "p1")["agents"]
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]["role"], "director")

    def test_late_role_assignment_is_audited_and_idempotent(self):
        c.agent_register(self.conn, "p1", "new-codex", "agent",
                         runtime="codex")
        assigned = c.agent_register(
            self.conn, "p1", "new-codex", "agent",
            role="advisor", runtime="codex")
        self.assertTrue(assigned["already_registered"])
        self.assertTrue(assigned["role_changed"])
        self.assertEqual(assigned["role"], "advisor")
        event = c.event_show(self.conn, "p1", assigned["event"]["seq"])
        self.assertEqual(event["event_type"], "agent.role_changed")
        self.assertEqual(event["payload"], {
            "agent_id": "new-codex", "from": None, "to": "advisor"})
        before = c.get_project(self.conn, "p1")["context_version"]
        again = c.agent_register(
            self.conn, "p1", "new-codex", "agent", role="advisor")
        self.assertNotIn("event", again)
        self.assertNotIn("role_changed", again)
        self.assertEqual(c.get_project(self.conn, "p1")["context_version"],
                         before)
        with self.assertRaisesRegex(c.AttaccaError, "agent role"):
            c.agent_register(self.conn, "p1", "new-codex", "agent",
                             role="boss")

    def test_worker_owns_handoff_but_cannot_issue_master_orders(self):
        subordinate = self._second_project("worker-subordinate")
        c.agent_register(self.conn, "p1", "only-worker", "agent",
                         role="worker", runtime="codex")
        own = c.update_identity_handoff(
            self.conn, "p1", "only-worker", "agent",
            {"what_changed": "worker continuity"}, expected_version=0)
        self.assertEqual(own["handoff_actor"], "only-worker")
        self.assertEqual(c.get_identity_handoff(
            self.conn, "p1", actor_id="only-worker",
            actor_type="agent")["handoff"]["what_changed"],
            "worker continuity")
        # A worker owns its identity handoff but never the shared one.
        with self.assertRaisesRegex(
                c.AttaccaError, "may only be edited by a registered Director"):
            c.update_handoff(
                self.conn, "p1", "only-worker", "agent",
                {"what_changed": "worker overwrite"}, expected_version=0)
        c.bridge_add(self.conn, "p1", "admin", "human", subordinate,
                     boss="p1")
        with self.assertRaisesRegex(c.AttaccaError, "only a Director"):
            c.room_send(self.conn, "p1", "only-worker", "agent",
                        "binding order", msg_type="directive",
                        target_project=subordinate)

    # -- review-workflow regression tests ------------------------------------

    def test_room_cursor_no_loss_on_truncation(self):
        for i in range(45):
            c.room_send(self.conn, "p1", "a", "agent", "msg-%02d" % i)
        got = []
        batch = c.room_read(self.conn, "p1", since_seq=0, limit=30)
        got += [m["body"] for m in batch["messages"]]
        self.assertTrue(batch["may_have_more"])
        while batch["may_have_more"]:
            batch = c.room_read(self.conn, "p1",
                                since_seq=batch["next_since_seq"], limit=30)
            got += [m["body"] for m in batch["messages"]]
        self.assertEqual(got, ["msg-%02d" % i for i in range(45)])

    def test_task_report_requires_active_claimant(self):
        tid = c.task_create(self.conn, "p1", "a", "agent", "guarded")["task_id"]
        c.task_claim(self.conn, "p1", "alice", "agent", tid)
        with self.assertRaises(c.AttaccaError):
            c.task_report(self.conn, "p1", "bob", "agent", tid, summary="hijack")
        # after lease expiry the reporter may take over
        self.conn.execute(
            "UPDATE tasks SET lease_until='2000-01-01T00:00:00.000Z'"
            " WHERE project_id='p1' AND task_id=?", (tid,))
        report = c.task_report(self.conn, "p1", "bob", "agent", tid,
                               summary="finishing abandoned work",
                               evidence=[{"kind": "test", "result": "pass"}],
                               requested_state="done")
        self.assertEqual(report["status"], "done")
        # duplicate done report is rejected, context version bumped only once
        version = c.get_project(self.conn, "p1")["context_version"]
        with self.assertRaises(c.AttaccaError):
            c.task_report(self.conn, "p1", "bob", "agent", tid, summary="again",
                          requested_state="done")
        self.assertEqual(c.get_project(self.conn, "p1")["context_version"], version)

    def test_task_report_queued_clears_claimant(self):
        tid = c.task_create(self.conn, "p1", "a", "agent", "giveback")["task_id"]
        c.task_claim(self.conn, "p1", "alice", "agent", tid)
        c.task_report(self.conn, "p1", "alice", "agent", tid,
                      summary="cannot finish", requested_state="queued")
        task = c._task_dict(c._task_row(self.conn, "p1", tid))
        self.assertEqual(task["status"], "queued")
        self.assertIsNone(task["claimed_by"])
        # and it is claimable again by anyone
        c.task_claim(self.conn, "p1", "bob", "agent", tid)

    def test_task_release_requires_claimant_while_lease_active(self):
        tid = c.task_create(self.conn, "p1", "a", "agent", "mine")["task_id"]
        c.task_claim(self.conn, "p1", "alice", "agent", tid)
        with self.assertRaises(c.AttaccaError):
            c.task_release(self.conn, "p1", "bob", "agent", tid)
        self.conn.execute(
            "UPDATE tasks SET lease_until='2000-01-01T00:00:00.000Z'"
            " WHERE project_id='p1' AND task_id=?", (tid,))
        c.task_release(self.conn, "p1", "bob", "agent", tid, reason="expired cleanup")

    def test_task_set_status_claimed_rejected(self):
        tid = c.task_create(self.conn, "p1", "a", "agent", "t")["task_id"]
        with self.assertRaises(c.AttaccaError):
            c.task_set_status(self.conn, "p1", "a", "agent", tid, "claimed")

    def test_zombie_claim_row_is_recoverable(self):
        tid = c.task_create(self.conn, "p1", "a", "agent", "zombie")["task_id"]
        self.conn.execute(
            "UPDATE tasks SET status='claimed', claimed_by=NULL, lease_until=NULL"
            " WHERE project_id='p1' AND task_id=?", (tid,))
        claim = c.task_claim(self.conn, "p1", "bob", "agent", tid)
        self.assertEqual(claim["claimed_by"], "bob")

    def test_project_init_root_move_guard(self):
        other = Path(self.tmp.name) / "elsewhere"
        other.mkdir()
        with self.assertRaises(c.AttaccaError):
            c.project_init(self.conn, "t", "human", path=str(other),
                           project_id="p1")
        moved = c.project_init(self.conn, "t", "human", path=str(other),
                               project_id="p1", move=True)
        self.assertEqual(moved["root_path"], str(other))
        self.assertTrue(moved["already_existed"])

    def test_array_argument_validation(self):
        with self.assertRaises(c.AttaccaError):
            c.task_create(self.conn, "p1", "a", "agent", "bad",
                          expected_scope="src/**")  # string, not list
        with self.assertRaises(c.AttaccaError):
            c.room_send(self.conn, "p1", "a", "agent", "hi",
                        mentions=[{"not": "a string"}])
        tid = c.task_create(self.conn, "p1", "a", "agent", "ev")["task_id"]
        c.task_claim(self.conn, "p1", "a", "agent", tid)
        with self.assertRaises(c.AttaccaError):
            c.task_report(self.conn, "p1", "a", "agent", tid, summary="x",
                          evidence="pytest passed")  # string, not list
        # a single evidence object is tolerated and wrapped
        report = c.task_report(self.conn, "p1", "a", "agent", tid, summary="x",
                               evidence={"kind": "test", "result": "pass"})
        self.assertEqual(report["warnings"], [])

    def test_freshness_report_includes_causing_event(self):
        briefed = c.get_project(self.conn, "p1")["context_version"]
        did = c.decision_propose(self.conn, "p1", "a", "agent",
                                 "Switch to uv")["decision_id"]
        c.decision_resolve(self.conn, "p1", "h", "human", did, "accepted")
        stale = c.check_freshness(self.conn, "p1", briefed)
        self.assertTrue(stale["stale"])
        joined = "\n".join(stale["changes_since_your_briefing"])
        self.assertIn("Switch to uv", joined)
        self.assertIn("accepted", joined)

    def test_room_send_decision_msg_warns(self):
        result = c.room_send(self.conn, "p1", "a", "agent",
                             "we should use PKCE", msg_type="decision")
        self.assertTrue(any("decision_propose" in w for w in result["warnings"]))

    def test_lease_minutes_zero_clamps_to_one_minute(self):
        tid = c.task_create(self.conn, "p1", "a", "agent", "short")["task_id"]
        claim = c.task_claim(self.conn, "p1", "a", "agent", tid, lease_minutes=0)
        self.assertLessEqual(claim["lease_until"], c.iso_in(2))

    def test_setup_config_always_pins_db(self):
        config = c.mcp_server_config("claude_director", "p1", self.db)
        self.assertEqual(config["env"][c.ENV_DB], str(self.db))

    # -- inbox / lead / bridges / identity / search --------------------------

    def test_inbox_mentions_replies_and_cursor(self):
        c.agent_register(
            self.conn, "p1", "admin", "human", agent_id="bob",
            display_name="Bob", role="worker", runtime="bob")
        c.room_send(self.conn, "p1", "alice", "agent", "hey bob",
                    mentions=["bob"])
        sent = c.room_send(self.conn, "p1", "bob", "agent", "what's up?")
        c.room_send(self.conn, "p1", "alice", "agent", "answering you",
                    reply_to=sent["event"]["event_id"])
        c.room_send(self.conn, "p1", "carol", "agent", "random broadcast")
        inbox = c.inbox_read(self.conn, "p1", "bob")
        bodies = [m["body"] for m in inbox["messages"]]
        self.assertEqual(
            bodies, ["hey bob", "answering you", "random broadcast"])
        self.assertEqual(inbox["unread_total"], 3)
        self.assertEqual(inbox["unread_everyone"], 1)
        self.assertTrue(inbox["messages"][-1]["broadcast_to_everyone"])
        self.assertEqual(inbox["unread_broadcasts"], 0)
        # cursor persisted: second read is empty
        again = c.inbox_read(self.conn, "p1", "bob")
        self.assertEqual(again["messages"], [])
        self.assertEqual(again["unread_broadcasts"], 0)
        # keep-unread peeks without advancing
        c.room_send(self.conn, "p1", "alice", "agent", "again bob",
                    mentions=["bob"])
        peek = c.inbox_read(self.conn, "p1", "bob", mark_read=False)
        self.assertEqual(len(peek["messages"]), 1)
        self.assertEqual(len(c.inbox_read(self.conn, "p1", "bob")["messages"]), 1)

    def test_lead_director_flow(self):
        c.agent_register(self.conn, "p1", "claude_director", "agent",
                         role="director", runtime="claude-code")
        result = c.set_lead_director(self.conn, "p1", "boss", "human",
                                     "claude_director")
        self.assertIn("context_version", result)
        self.assertEqual(
            c.get_project(self.conn, "p1")["lead_director"], "claude_director")
        handoff = c.get_handoff(
            self.conn, "p1", actor_id="claude_director",
            actor_type="agent")
        self.assertEqual(handoff["lead_director"], "claude_director")
        with self.assertRaises(c.AttaccaError):  # no-op set rejected
            c.set_lead_director(self.conn, "p1", "boss", "human",
                                "claude_director")
        c.set_lead_director(self.conn, "p1", "boss", "human", None)  # clear
        self.assertIsNone(c.get_project(self.conn, "p1")["lead_director"])

    def _second_project(self, pid="p2"):
        c.project_init(self.conn, "t", "human",
                       path=str(Path(self.tmp.name) / pid),
                       project_id=pid, name=pid)
        return pid

    def test_bridge_peer_mirroring_and_loop_protection(self):
        p2 = self._second_project()
        c.bridge_add(self.conn, "p1", "admin", "human", p2)
        # Cross-project delivery is explicit; local chat remains local.
        sent = c.room_send(self.conn, "p1", "eng_director", "agent",
                           "deploy at 5", msg_type="directive",
                           target_project=p2)
        self.assertEqual(sent["mirrored_to_bridged_projects"], [p2])
        c.room_send(self.conn, "p1", "eng_director", "agent", "just chatting")
        p2_msgs = c.room_read(self.conn, p2)["messages"]
        self.assertEqual(len(p2_msgs), 1)
        self.assertEqual(p2_msgs[0]["origin_project"], "p1")
        # mentions land in the bridged inbox
        c.agent_register(
            self.conn, p2, "admin", "human", agent_id="adm",
            display_name="Admin worker", role="worker", runtime="adm")
        c.room_send(self.conn, "p1", "eng_director", "agent",
                    "adm, please review", mentions=["adm"],
                    target_project=p2)
        inbox = c.inbox_read(self.conn, p2, "adm")
        self.assertEqual([m["body"] for m in inbox["messages"]],
                         ["deploy at 5", "adm, please review"])
        # mirrored copies never re-mirror (no ping-pong)
        self.assertEqual(
            len(c.room_read(self.conn, "p1", limit=100)["messages"]), 3)
        with self.assertRaises(c.AttaccaError):  # duplicate bridge
            c.bridge_add(self.conn, p2, "admin", "human", "p1")

    def test_targeted_room_chat_keeps_source_and_only_selected_destination(self):
        p2 = self._second_project("selected-room")
        p3 = self._second_project("other-room")
        c.bridge_add(self.conn, "p1", "admin", "human", p2)
        c.bridge_add(self.conn, "p1", "admin", "human", p3)
        sent = c.room_send(
            self.conn, "p1", "director", "agent", "hello selected room",
            target_project=p2)
        self.assertEqual(sent["mirrored_to_bridged_projects"], [p2])
        source = c.room_read(self.conn, "p1")["messages"][-1]
        target = c.room_read(self.conn, p2)["messages"][-1]
        self.assertEqual(source["mirrored_to"], [p2])
        self.assertEqual(target["origin_project"], "p1")
        self.assertEqual(c.room_read(self.conn, p3)["messages"], [])
        with self.assertRaisesRegex(c.AttaccaError, "not connected"):
            c.room_send(
                self.conn, p2, "director", "agent", "cannot jump",
                target_project=p3)

    def test_interproject_group_inbox_classifies_system_chat_and_status(self):
        p2 = self._second_project("inbox-target")
        c.bridge_add(self.conn, "p1", "admin", "human", p2)
        c.agent_register(
            self.conn, "p1", "legacy.claude_director", "agent",
            display_name="Source Director", role="director",
            runtime="claude-code")
        c.room_send(self.conn, "p1", "legacy.claude_director", "agent",
                    "schema changed", msg_type="system", target_project=p2)
        c.room_send(self.conn, "p1", "legacy.claude_director", "agent",
                    "hello", msg_type="chat", target_project=p2)
        c.room_send(self.conn, "p1", "legacy.claude_director", "agent",
                    "green", msg_type="status", target_project=p2)
        inbox = c.inbox_read(self.conn, p2, "p2.worker.codex",
                             mark_read=False)
        self.assertEqual([m["body"] for m in inbox["messages"]],
                         ["schema changed", "hello", "green"])
        self.assertEqual(inbox["unread_broadcasts"], 2)
        self.assertTrue(inbox["messages"][0]["group_context"])
        self.assertTrue(inbox["messages"][1]["broadcast_to_everyone"])
        self.assertTrue(inbox["messages"][2]["group_context"])
        structured = inbox["messages"][0]
        self.assertEqual(structured["actor"], "p1.director.claude")
        self.assertEqual(structured["ledger_actor"],
                         "legacy.claude_director")
        self.assertEqual(structured["identity"]["workspace"], "p1")
        mirrored = c.room_read(self.conn, p2, limit=100)["messages"]
        self.assertTrue(all(message["identity"]["workspace"] == "p1"
                            for message in mirrored))

    def test_explicit_current_room_prevents_structured_bridge_fanout(self):
        p2 = self._second_project("local-only-peer")
        p3 = self._second_project("local-only-master")
        c.bridge_add(self.conn, "p1", "owner", "human", p2)
        c.bridge_add(self.conn, "p1", "owner", "human", p3, boss="p1")
        c.agent_register(
            self.conn, "p1", "owner", "human", agent_id="local-worker",
            display_name="Local worker", role="worker", runtime="local")
        sent = c.room_send(
            self.conn, "p1", "director", "agent", "stay here",
            msg_type="directive", mentions=["local-worker"],
            target_project="p1")
        self.assertNotIn("mirrored_to_bridged_projects", sent)
        self.assertEqual(
            c.room_read(self.conn, "p1", limit=100)["messages"][-1]["body"],
            "stay here")
        for project_id in (p2, p3):
            self.assertNotIn("stay here", [
                message["body"] for message in
                c.room_read(self.conn, project_id, limit=100)["messages"]])

    def test_bridge_master_and_advisor_authority_tags(self):
        p2 = self._second_project("adminpanel")
        c.bridge_add(self.conn, "p1", "owner", "human", p2, boss="p1")
        c.room_send(self.conn, "p1", "eng_director", "agent",
                    "use schema v2", msg_type="directive", target_project=p2)
        c.room_send(self.conn, p2, "admin_director", "agent",
                    "could we get dark mode?", msg_type="directive",
                    target_project="p1")
        master_side = c.room_read(self.conn, p2)["messages"]
        self.assertEqual(master_side[0]["authority"], "master-directive")
        upstream = c.room_read(self.conn, "p1", limit=100)["messages"]
        self.assertEqual(upstream[-1]["authority"], "suggestion")
        gov = c.get_handoff(
            self.conn, p2, actor_id="owner", actor_type="human")["governance"]
        self.assertEqual(gov["follows"], ["p1"])
        self.assertEqual(c.get_handoff(
            self.conn, "p1", actor_id="owner",
            actor_type="human")["governance"]["rules_over"], [p2])
        # advisor relation
        p3 = self._second_project("consultants")
        c.bridge_add(self.conn, "p1", "owner", "human", p3, advisor=p3)
        c.room_send(self.conn, p3, "sage", "agent", "consider caching",
                    msg_type="directive", target_project="p1")
        advised = c.room_read(self.conn, "p1", limit=100)["messages"]
        self.assertEqual(advised[-1]["authority"], "advice")
        with self.assertRaises(c.AttaccaError):  # bad principal
            c.bridge_add(self.conn, p2, "x", "human", p3, boss="p1")

    def test_only_director_can_issue_governed_master_directive(self):
        subordinate = self._second_project("subordinate")
        c.bridge_add(
            self.conn, "p1", "owner", "human", subordinate, boss="p1")
        c.agent_register(self.conn, "p1", "lead", "agent",
                         role="director", runtime="test")
        c.agent_register(self.conn, "p1", "worker", "agent",
                         role="worker", runtime="test")
        c.set_lead_director(self.conn, "p1", "owner", "human", "lead")
        with self.assertRaisesRegex(c.AttaccaError, "only a Director"):
            c.room_send(self.conn, "p1", "worker", "agent", "do this",
                        msg_type="directive", target_project=subordinate)
        c.room_send(self.conn, "p1", "worker", "agent", "FYI",
                    msg_type="chat", target_project=subordinate)
        chat = c.room_read(self.conn, subordinate)["messages"][-1]
        self.assertIsNone(chat["authority"])
        c.room_send(self.conn, "p1", "lead", "agent", "do this",
                    msg_type="directive", target_project=subordinate)
        directive = c.room_read(self.conn, subordinate)["messages"][-1]
        self.assertEqual(directive["authority"], "master-directive")

    def test_owner_attribution_on_events_and_agents(self):
        c.set_current_owner("jack")
        try:
            event = c.append_event(self.conn, "p1", "jack.claude", "agent",
                                   "note.owned", {})
            self.assertEqual(event["owner"], "jack")
            row = self.conn.execute(
                "SELECT owner FROM events WHERE event_id=?",
                (event["event_id"],)).fetchone()
            self.assertEqual(row["owner"], "jack")
            c.agent_register(self.conn, "p1", "jack.claude", "agent",
                             runtime="claude-code")
            agent = c.agent_list(self.conn, "p1")["agents"][-1]
            self.assertEqual(agent["owner"], "jack")
        finally:
            c.set_current_owner(None)

    def test_qualify_actor(self):
        self.assertEqual(c.qualify_actor("claude_director", owner="Jack"),
                         "claude_director")
        self.assertEqual(c.qualify_actor("jack.claude_director", owner="Jack"),
                         "jack.claude_director")  # legacy value is untouched
        self.assertEqual(c.qualify_actor("claude_director", owner=None),
                         "claude_director")
        self.assertIsNone(c.qualify_actor(None, owner="Jack"))

    def test_canonical_identity_migrates_mutable_state_not_ledger(self):
        legacy = "jack.codex_director"
        c.set_current_owner("jack")
        try:
            c.agent_register(self.conn, "p1", legacy, "agent",
                             role="director", runtime="codex-cli")
            c.set_lead_director(
                self.conn, "p1", "admin", "human", legacy)
            task_id = c.task_create(
                self.conn, "p1", legacy, "agent", "Keep claim")["task_id"]
            c.task_claim(self.conn, "p1", legacy, "agent", task_id)
            self.conn.execute(
                "INSERT INTO inbox_cursors"
                " (project_id, actor_id, last_read_seq, updated_at)"
                " VALUES ('p1', ?, 7, ?)", (legacy, c.now_iso()))
            old_event = c.append_event(
                self.conn, "p1", legacy, "agent", "note.before_migration", {})
            # Reproduce an older MCP/CLI path that left mutable references but
            # no agents row. Guided setup must still adopt the claim/lead and
            # alias historical activity without rewriting ledger events.
            self.conn.execute(
                "DELETE FROM agents WHERE project_id='p1' AND agent_id=?",
                (legacy,))

            result = c.agent_register(
                self.conn, "p1", "codex", "agent", role="director",
                runtime="codex-cli", canonical_identity=True)
            canonical = "p1.director.codex"
            self.assertEqual(result["agent_id"], canonical)
            self.assertIn(legacy, result["migration"]["aliases"])
            self.assertEqual(
                c.get_project(self.conn, "p1")["lead_director"], canonical)
            self.assertEqual(
                c.task_show(self.conn, "p1", task_id)["claimed_by"], canonical)
            cursor = self.conn.execute(
                "SELECT last_read_seq FROM inbox_cursors"
                " WHERE project_id='p1' AND actor_id=?", (canonical,)).fetchone()
            self.assertEqual(cursor["last_read_seq"], 7)
            immutable = self.conn.execute(
                "SELECT actor_id FROM events WHERE event_id=?",
                (old_event["event_id"],)).fetchone()
            self.assertEqual(immutable["actor_id"], legacy)
            self.assertTrue(c.verify_ledger(self.conn, "p1")["ok"])

            # A later SessionStart sees the already-canonical cursor. It must
            # not manufacture another migration event or context bump.
            before_version = c.get_project(
                self.conn, "p1")["context_version"]
            before_events = self.conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE project_id='p1'") \
                .fetchone()["n"]
            repeated = c.agent_register(
                self.conn, "p1", "codex", "agent", runtime="codex-cli",
                canonical_identity=True)
            self.assertNotIn("event", repeated)
            self.assertEqual(
                c.get_project(self.conn, "p1")["context_version"],
                before_version)
            self.assertEqual(self.conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE project_id='p1'")
                .fetchone()["n"], before_events)
        finally:
            c.set_current_owner(None)

    def test_handoff_ownership_is_exact_while_governance_is_role_based(self):
        claude = "p1.director.claude"
        codex = "p1.director.codex"
        c.agent_register(self.conn, "p1", claude, "agent",
                         role="director", runtime="claude")
        c.agent_register(self.conn, "p1", codex, "agent",
                         role="director", runtime="codex")
        c.set_lead_director(self.conn, "p1", "admin", "human", claude)
        first = c.update_identity_handoff(
            self.conn, "p1", claude, "agent", {"objective": "from Claude"},
            expected_context_version=c.get_project(
                self.conn, "p1")["context_version"])
        second = c.update_identity_handoff(
            self.conn, "p1", codex, "agent", {"what_changed": "from Codex"},
            expected_context_version=first["context_version"])
        self.assertGreater(second["context_version"], first["context_version"])
        self.assertEqual(c.get_identity_handoff(
            self.conn, "p1", actor_id=claude,
            actor_type="agent")["handoff"]["objective"], "from Claude")
        self.assertIsNone(c.get_identity_handoff(
            self.conn, "p1", actor_id=claude,
            actor_type="agent")["handoff"]["what_changed"])
        self.assertEqual(c.get_identity_handoff(
            self.conn, "p1", actor_id=codex,
            actor_type="agent")["handoff"]["what_changed"], "from Codex")

        # Every registered role still owns its identity handoff. Lead status
        # does not preserve Director governance authority after the registry
        # role is changed or corrupted.
        self.conn.execute(
            "UPDATE agents SET role='worker' WHERE project_id='p1'"
            " AND agent_id=?", (claude,))
        third = c.update_identity_handoff(
            self.conn, "p1", claude, "agent", {"risks": "worker-owned"},
            expected_context_version=second["context_version"],
            expected_version=1)
        self.assertEqual(third["handoff_actor"], claude)
        # ... and it loses the Director-only shared handoff with that role.
        with self.assertRaisesRegex(
                c.AttaccaError, "may only be edited by a registered Director"):
            c.update_handoff(
                self.conn, "p1", claude, "agent",
                {"objective": "no longer a Director"})
        with self.assertRaisesRegex(
                c.AttaccaError, "human or registered Director"):
            c.role_scope_set(
                self.conn, "p1", claude, "agent", "worker",
                "must not govern shared role context", expected_version=0)

    def test_canonical_identity_conflicting_roles_require_explicit_choice(self):
        director = "jack.codex_director"
        worker = "mia.codex_worker"
        c.agent_register(self.conn, "p1", director, "agent",
                         role="director", runtime="codex-cli")
        c.agent_register(self.conn, "p1", worker, "agent",
                         role="worker", runtime="codex")
        c.set_lead_director(self.conn, "p1", "admin", "human", director)
        with self.assertRaisesRegex(c.AttaccaError, "conflicting existing roles"):
            c.agent_register(
                self.conn, "p1", "codex", "agent", runtime="codex",
                canonical_identity=True)
        self.assertEqual(c.get_project(self.conn, "p1")["lead_director"],
                         director)
        self.assertEqual(
            {(a["agent_id"], a["role"])
             for a in c.agent_list(self.conn, "p1")["agents"]},
            {(director, "director"), (worker, "worker")})

        chosen = c.agent_register(
            self.conn, "p1", "codex", "agent", role="worker",
            runtime="codex", canonical_identity=True)
        self.assertEqual(chosen["agent_id"], "p1.worker.codex")
        # Explicit worker selection migrates that worker persona, but does not
        # silently delete/demote the separate Director persona or its lead.
        self.assertEqual(c.get_project(self.conn, "p1")["lead_director"],
                         director)
        self.assertEqual(
            {(a["agent_id"], a["role"])
             for a in c.agent_list(self.conn, "p1")["agents"]},
            {(director, "director"), ("p1.worker.codex", "worker")})

    def test_search_everything(self):
        self._register_handoff_actor("a")
        c.room_send(self.conn, "p1", "a", "agent", "the flux capacitor broke",
                    msg_type="challenge")
        c.task_create(self.conn, "p1", "a", "agent", "Repair flux capacitor")
        c.decision_propose(self.conn, "p1", "a", "agent",
                           "Replace flux capacitor entirely")
        c.update_identity_handoff(
            self.conn, "p1", "a", "agent",
            {"blockers": "flux capacitor supply chain"})
        hits = c.search_project(self.conn, "p1", "flux capacitor")
        self.assertGreaterEqual(len(hits["events"]), 3)
        self.assertEqual(len(hits["tasks"]), 1)
        self.assertEqual(len(hits["decisions"]), 1)
        self.assertEqual(len(hits["handoff_versions"]), 1)
        self.assertEqual(c.search_project(self.conn, "p1", "zzznothing")
                         ["total_hits"], 0)

        # The Director-governed shared project handoff is project state every
        # role reads, so history search must find it too.
        self._register_handoff_actor("search-director", role="director")
        c.update_handoff(
            self.conn, "p1", "search-director", "agent",
            {"risks": "flux capacitor shared risk"})
        both = c.search_project(self.conn, "p1", "flux capacitor")
        self.assertEqual(len(both["handoff_versions"]), 2)
        found = {item["id"] for item in both["results"]
                 if item["kind"] == "handoff"}
        self.assertEqual(found, {"a:v1", "shared:v1"})
        shared_hit = next(item for item in both["results"]
                          if item["id"] == "shared:v1")
        self.assertIn("Shared project handoff", shared_hit["text"])
        self.assertEqual(shared_hit["data"]["handoff_scope"], "project")

    def test_search_normalizes_punctuation_and_never_hides_room_bodies(self):
        c.task_create(
            self.conn, "p1", "owner", "human",
            "Implement the magic-link claim flow",
            description="Guest checkout account attachment")
        c.task_create(
            self.conn, "p1", "owner", "human",
            "Unrelated magic rendering",
            description="Does not discuss the other required terms")
        natural = c.search_project(self.conn, "p1", "magic link claim")
        self.assertEqual(natural["query_terms"], ["magic", "link", "claim"])
        self.assertEqual(natural["term_semantics"], "AND")
        self.assertEqual(
            [task["title"] for task in natural["tasks"]],
            ["Implement the magic-link claim flow"])

        bodies = {
            "chat": "directive body retained from ordinary chat",
            "status": "directive body retained from a status update",
            "directive": "directive body retained from a directive",
        }
        for msg_type, body in bodies.items():
            c.room_send(self.conn, "p1", "same.actor", "agent", body,
                        msg_type=msg_type)
        results = c.search_project(self.conn, "p1", "directive body")
        messages = [event for event in results["events"]
                    if event["event_type"] == "room.message"]
        self.assertEqual({event["msg_type"] for event in messages},
                         set(bodies))
        self.assertEqual({event["body"] for event in messages},
                         set(bodies.values()))
        self.assertTrue(all(event["body"] in event["line"]
                            for event in messages))

    def test_handoff_history_and_event_show(self):
        self._register_handoff_actor("a")
        self._register_handoff_actor("b")
        self._register_handoff_actor("d", role="director")
        c.update_identity_handoff(
            self.conn, "p1", "a", "agent", {"objective": "one"},
            expected_version=0)
        c.update_identity_handoff(
            self.conn, "p1", "a", "agent", {"objective": "a two"},
            expected_version=1)
        c.update_identity_handoff(
            self.conn, "p1", "b", "agent", {"objective": "b one"},
            expected_version=0)
        c.update_handoff(
            self.conn, "p1", "d", "agent", {"objective": "shared one"},
            expected_version=0)
        history_a = c.identity_handoff_history(
            self.conn, "p1", actor_id="a", actor_type="agent")
        history_b = c.identity_handoff_history(
            self.conn, "p1", actor_id="b", actor_type="agent")
        self.assertEqual(
            [v["content"]["objective"] for v in history_a["versions"]],
            ["a two", "one"])
        self.assertEqual(
            [v["content"]["objective"] for v in history_b["versions"]],
            ["b one"])
        # The shared history is project-wide and identical for every reader.
        shared = c.handoff_history(
            self.conn, "p1", actor_id="b", actor_type="agent")
        self.assertEqual(shared["handoff_scope"], "project")
        self.assertEqual(
            [v["content"]["objective"] for v in shared["versions"]],
            ["shared one"])
        with self.assertRaisesRegex(
                c.AttaccaError, "identity_handoff_history"):
            c.handoff_history(
                self.conn, "p1", actor_id="b", actor_type="agent",
                target_actor_id="a")
        event = c.event_show(self.conn, "p1", 1)
        self.assertEqual(event["event_type"], "project.created")
        self.assertIsInstance(event["payload"], dict)
        with self.assertRaises(c.AttaccaError):
            c.event_show(self.conn, "p1", 99999)

    def test_claude_md_symlinks_to_agents_md(self):
        c.install_instructions("p1", str(self.proj_dir), self.db)
        claude_md = self.proj_dir / "CLAUDE.md"
        self.assertTrue(claude_md.is_symlink())
        self.assertEqual(os.readlink(claude_md), "AGENTS.md")
        self.assertIn("MANAGED_ATTACCA:BEGIN", claude_md.read_text())
        # a pre-existing REAL CLAUDE.md is never replaced by a link
        real_dir = Path(self.tmp.name) / "realclaude"
        real_dir.mkdir()
        (real_dir / "CLAUDE.md").write_text("# mine\n")
        c.project_init(self.conn, "t", "human", path=str(real_dir),
                       project_id="preal", name="Real")
        c.install_instructions("preal", str(real_dir), self.db)
        self.assertFalse((real_dir / "CLAUDE.md").is_symlink())
        text = (real_dir / "CLAUDE.md").read_text()
        self.assertIn("# mine", text)
        self.assertIn("MANAGED_ATTACCA:BEGIN", text)

    def test_managed_instruction_block_idempotent(self):
        result = c.install_instructions("p1", str(self.proj_dir), self.db)
        self.assertEqual(len(result["files"]), 2)
        claude_md = self.proj_dir / "CLAUDE.md"
        text1 = claude_md.read_text()
        self.assertIn("MANAGED_ATTACCA:BEGIN", text1)
        self.assertIn("lifecycle hooks are the primary continuity path", text1)
        self.assertIn("ATTACCA ACTIVE SESSION BRIEF", text1)
        self.assertIn("Messages are local by default", text1)
        self.assertIn("feedback bridge carries feedback", text1)
        self.assertIn(
            "MANAGED_ATTACCA:BEGIN v=%d" % c.MANAGED_BLOCK_VERSION, text1)
        self.assertNotIn("Maximum-effort completion and fan-out", text1)
        self.assertNotIn("Two QA passes before completion", text1)
        self.assertIn("minute by default (configurable)", text1)
        self.assertIn("background watcher", text1)
        self.assertIn("coding client is idle", text1)
        self.assertIn("Project Rules — binding dynamic instructions", text1)
        self.assertIn("History first", text1)
        self.assertIn("call `search`", text1)
        self.assertIn("Run by user", text1)
        self.assertIn("Git branch and revision", text1)
        self.assertIn("Tasks — owned, trackable work", text1)
        self.assertIn("Decisions — durable choices", text1)
        self.assertIn(
            "Shared handoff, identity handoff, and Role Scope", text1)
        self.assertIn("every exact registered identity", text1)
        self.assertIn("workspace.role.runtime.persona", text1)
        self.assertIn("legacy three-part", text1)
        self.assertIn("human and AI identities", text1)
        self.assertIn("identical permissions", text1)
        self.assertIn("another Attacca database/store", text1)
        self.assertNotIn("another database/store", text1)
        self.assertNotIn("install-hooks", text1)
        self.assertNotIn("CLI equivalents", text1)
        # user content above the block survives a re-run
        claude_md.write_text("# My own notes\n\n" + text1)
        c.install_instructions("p1", str(self.proj_dir), self.db)
        text2 = claude_md.read_text()
        self.assertIn("# My own notes", text2)
        self.assertEqual(text2.count("MANAGED_ATTACCA:BEGIN"), 1)

    def test_managed_instruction_metadata_is_deterministic(self):
        first = c.managed_instruction_metadata("p1", self.db)
        second = c.managed_instruction_metadata("p1", Path("/another/db"))
        other_project = c.managed_instruction_metadata("p2", self.db)
        self.assertEqual(first, second)
        self.assertEqual(first["version"], c.MANAGED_BLOCK_VERSION)
        self.assertEqual(first["project_id"], "p1")
        self.assertEqual(len(first["sha256"]), 64)
        self.assertEqual(first["law_sha256"], other_project["law_sha256"])
        self.assertNotEqual(first["sha256"], other_project["sha256"])

    def test_refresh_managed_instructions_is_atomic_and_preserves_outside(self):
        old_block = c.managed_instruction_block("old-project", self.db).replace(
            " v=%d " % c.MANAGED_BLOCK_VERSION, " v=1 ", 1)
        prefix = b"# User rules\r\n\r\n"
        suffix = b"\r\nUser tail without a final newline"
        agents = self.proj_dir / "AGENTS.md"
        agents.write_bytes(prefix + old_block.encode("utf-8") + suffix)
        claude = self.proj_dir / "CLAUDE.md"
        claude.symlink_to("AGENTS.md")
        old_inode = agents.stat().st_ino

        result = c.refresh_managed_instructions(
            "p1", str(self.proj_dir), self.db)

        self.assertTrue(result["ok"])
        self.assertTrue(result["changed"])
        self.assertTrue(claude.is_symlink())
        self.assertEqual(os.readlink(claude), "AGENTS.md")
        written = agents.read_bytes()
        desired = c.managed_instruction_block("p1", self.db).encode("utf-8")
        self.assertEqual(written, prefix + desired + suffix)
        self.assertNotEqual(agents.stat().st_ino, old_inode)
        self.assertFalse(list(self.proj_dir.glob(".AGENTS.md.*.tmp")))
        inspection = c.inspect_managed_instruction_file(
            agents, desired_project_id="p1", db_path=self.db)
        self.assertTrue(inspection["present"])
        self.assertTrue(inspection["matches_desired"])
        self.assertEqual(inspection["metadata"]["sha256"],
                         result["metadata"]["sha256"])
        self.assertEqual(result["files"][0]["version_change"],
                         "1→%d" % c.MANAGED_BLOCK_VERSION)

        current_inode = agents.stat().st_ino
        second = c.refresh_managed_instructions(
            "p1", str(self.proj_dir), self.db)
        self.assertFalse(second["changed"])
        self.assertEqual(agents.stat().st_ino, current_inode)

    def test_refresh_never_creates_or_appends_managed_instructions(self):
        agents = self.proj_dir / "AGENTS.md"
        original = b"# User-owned instructions only\n"
        agents.write_bytes(original)

        result = c.refresh_managed_instructions(
            "p1", str(self.proj_dir), self.db)

        self.assertTrue(result["ok"])
        self.assertFalse(result["changed"])
        self.assertEqual(agents.read_bytes(), original)
        self.assertFalse((self.proj_dir / "CLAUDE.md").exists())
        self.assertEqual([entry["status"] for entry in result["files"]],
                         ["missing", "missing"])

    def test_refresh_reports_malformed_block_without_writing(self):
        agents = self.proj_dir / "AGENTS.md"
        original = (b"# User rules\n\n"
                    b"<!-- MANAGED_ATTACCA:BEGIN v=1 project=p1 -->\n"
                    b"incomplete")
        agents.write_bytes(original)

        result = c.refresh_managed_instructions(
            "p1", str(self.proj_dir), self.db, files=["AGENTS.md"])

        self.assertFalse(result["ok"])
        self.assertFalse(result["changed"])
        self.assertEqual(result["files"][0]["status"], "malformed")
        self.assertEqual(agents.read_bytes(), original)

    def test_refresh_updates_real_claude_and_rejects_external_symlink(self):
        agents = self.proj_dir / "AGENTS.md"
        claude = self.proj_dir / "CLAUDE.md"
        agents.write_text(c.managed_instruction_block("old", self.db) + "\n")
        claude.write_text("# Claude only\n\n" +
                          c.managed_instruction_block("old", self.db) + "\n")

        result = c.refresh_managed_instructions(
            "p1", str(self.proj_dir), self.db)
        self.assertTrue(result["ok"])
        self.assertFalse(claude.is_symlink())
        self.assertIn("# Claude only", claude.read_text())
        self.assertIn("project=p1", claude.read_text())

        outside = Path(self.tmp.name) / "outside.md"
        outside.write_text(c.managed_instruction_block("old", self.db) + "\n")
        claude.unlink()
        claude.symlink_to(outside)
        original = outside.read_bytes()
        unsafe = c.refresh_managed_instructions(
            "p1", str(self.proj_dir), self.db)
        self.assertFalse(unsafe["ok"])
        self.assertEqual(unsafe["files"][1]["status"], "unsafe_symlink")
        self.assertEqual(outside.read_bytes(), original)

    def test_refresh_rejects_unowned_duplicate_and_non_utf8_blocks(self):
        agents = self.proj_dir / "AGENTS.md"
        unowned = c.managed_instruction_block("old", self.db).replace(
            " do_not_edit=true", "")
        agents.write_text("# mine\n" + unowned + "\n")
        before = agents.read_bytes()
        result = c.refresh_managed_instructions(
            "p1", str(self.proj_dir), self.db, files=["AGENTS.md"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["files"][0]["status"], "unmanaged")
        self.assertEqual(agents.read_bytes(), before)

        block = c.managed_instruction_block("old", self.db)
        agents.write_text(block + "\n" + block + "\n")
        duplicate = agents.read_bytes()
        result = c.refresh_managed_instructions(
            "p1", str(self.proj_dir), self.db, files=["AGENTS.md"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["files"][0]["status"], "malformed")
        self.assertEqual(agents.read_bytes(), duplicate)

        partial_extra = (c.managed_instruction_block("old", self.db) +
                         "\n<!-- MANAGED_ATTACCA:BEGIN broken\n")
        agents.write_text(partial_extra)
        result = c.refresh_managed_instructions(
            "p1", str(self.proj_dir), self.db, files=["AGENTS.md"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["files"][0]["status"], "malformed")
        self.assertEqual(agents.read_text(), partial_extra)

        agents.write_bytes(b"\xff\xfe<!-- MANAGED_ATTACCA:BEGIN -->")
        non_utf8 = agents.read_bytes()
        result = c.refresh_managed_instructions(
            "p1", str(self.proj_dir), self.db, files=["AGENTS.md"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["files"][0]["status"], "malformed")
        self.assertEqual(agents.read_bytes(), non_utf8)

    def test_refresh_rejects_end_before_begin_and_future_version(self):
        agents = self.proj_dir / "AGENTS.md"
        reversed_markers = (
            c.MANAGED_END + "\ntext\n" + c.MANAGED_BEGIN +
            " v=1 project=p1 do_not_edit=true -->\n")
        agents.write_text(reversed_markers)
        result = c.refresh_managed_instructions(
            "p1", str(self.proj_dir), self.db, files=["AGENTS.md"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["files"][0]["status"], "malformed")
        self.assertEqual(agents.read_text(), reversed_markers)

        future = c.managed_instruction_block("p1", self.db).replace(
            " v=%d " % c.MANAGED_BLOCK_VERSION, " v=999 ", 1)
        agents.write_text("# mine\n" + future + "\n")
        before = agents.read_bytes()
        result = c.refresh_managed_instructions(
            "p1", str(self.proj_dir), self.db, files=["AGENTS.md"])
        self.assertFalse(result["ok"])
        self.assertFalse(result["changed"])
        self.assertEqual(result["files"][0]["status"], "future")
        self.assertEqual(result["files"][0]["version_change"],
                         "999→%d refused" % c.MANAGED_BLOCK_VERSION)
        self.assertEqual(agents.read_bytes(), before)

    def test_refresh_rejects_agents_symlink_chain_outside_checkout(self):
        outside = Path(self.tmp.name) / "outside-agents.md"
        outside.write_text(c.managed_instruction_block("old", self.db) + "\n")
        agents = self.proj_dir / "AGENTS.md"
        claude = self.proj_dir / "CLAUDE.md"
        agents.symlink_to(outside)
        claude.symlink_to("AGENTS.md")
        before = outside.read_bytes()

        result = c.refresh_managed_instructions(
            "p1", str(self.proj_dir), self.db)

        self.assertFalse(result["ok"])
        self.assertEqual([entry["status"] for entry in result["files"]],
                         ["unsafe_symlink", "unsafe_symlink"])
        self.assertEqual(outside.read_bytes(), before)

    def test_refresh_preserves_mode_and_concurrent_calls_converge(self):
        agents = self.proj_dir / "AGENTS.md"
        old = c.managed_instruction_block("old", self.db)
        agents.write_text("# mine\n\n" + old + "\n")
        agents.chmod(0o444)

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(
                lambda _: c.refresh_managed_instructions(
                    "p1", str(self.proj_dir), self.db, files=["AGENTS.md"]),
                range(16)))

        self.assertTrue(all(result["ok"] for result in results))
        self.assertEqual(agents.stat().st_mode & 0o777, 0o444)
        self.assertEqual(agents.read_text(), "# mine\n\n" +
                         c.managed_instruction_block("p1", self.db) + "\n")
        self.assertFalse(list(self.proj_dir.glob(".AGENTS.md.*.tmp")))
        changed = [entry for result in results for entry in result["files"]
                   if entry["changed"]]
        self.assertTrue(changed)
        self.assertTrue(all(entry["version_change"] == "%d→%d" % (
                                c.MANAGED_BLOCK_VERSION,
                                c.MANAGED_BLOCK_VERSION)
                            for entry in changed))


if __name__ == "__main__":
    unittest.main()
