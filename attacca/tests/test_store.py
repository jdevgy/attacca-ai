"""Storage-layer semantics tests for attacca.py (stdlib unittest)."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
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

    def test_handoff_partial_merge_and_versions(self):
        c.update_handoff(self.conn, "p1", "a", "agent",
                         {"objective": "obj1", "risks": "r1"})
        second = c.update_handoff(self.conn, "p1", "b", "agent",
                                  {"objective": "obj2"})
        handoff = c.get_handoff(self.conn, "p1")
        self.assertEqual(handoff["handoff"]["objective"], "obj2")
        self.assertEqual(handoff["handoff"]["risks"], "r1")  # preserved
        self.assertEqual(handoff["handoff_updated_by"], "b")
        self.assertEqual(handoff["context_version"], second["context_version"])
        count = self.conn.execute(
            "SELECT COUNT(*) AS n FROM handoffs WHERE project_id='p1'").fetchone()["n"]
        self.assertEqual(count, 2)  # history preserved

    def test_handoff_requires_a_field(self):
        with self.assertRaises(c.AttaccaError):
            c.update_handoff(self.conn, "p1", "a", "agent", {})

    def test_freshness(self):
        v0 = c.get_project(self.conn, "p1")["context_version"]
        fresh = c.check_freshness(self.conn, "p1", v0)
        self.assertFalse(fresh["stale"])
        c.update_handoff(self.conn, "p1", "a", "agent", {"objective": "x"})
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
        c.room_send(self.conn, "p2", "a", "agent", "hello p2",
                    origin_project="p1")
        msgs = c.room_read(self.conn, "p2")["messages"]
        self.assertEqual(msgs[-1]["origin_project"], "p1")
        self.assertEqual(c.room_read(self.conn, "p1")["messages"], [])

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

    def test_git_hook_survives_hostile_commit_subjects(self):
        import subprocess
        repo = self.proj_dir
        run = lambda *cmd: subprocess.run(
            cmd, cwd=str(repo), capture_output=True, text=True, check=True)
        try:
            run("git", "init", "-q", ".")
        except Exception:
            self.skipTest("git unavailable")
        run("git", "-c", "user.email=t@t", "-c", "user.name=T e s t",
            "commit", "-q", "--allow-empty", "-m", "boring first commit")
        c.install_git_hook("p1", str(repo), self.db)
        nasty = 'fix "quoted" `backticks` $(rm -rf /) \'single\' \\ end'
        run("git", "-c", "user.email=t@t", "-c", "user.name=T e s t",
            "commit", "-q", "--allow-empty", "-m", nasty)
        rows = self.conn.execute(
            "SELECT payload FROM events WHERE project_id='p1'"
            " AND event_type='git.commit'").fetchall()
        self.assertEqual(len(rows), 1)
        payload = json.loads(rows[0]["payload"])
        self.assertEqual(payload["subject"], nasty)

    # -- inbox / lead / bridges / identity / search --------------------------

    def test_inbox_mentions_replies_and_cursor(self):
        c.room_send(self.conn, "p1", "alice", "agent", "hey bob",
                    mentions=["bob"])
        sent = c.room_send(self.conn, "p1", "bob", "agent", "what's up?")
        c.room_send(self.conn, "p1", "alice", "agent", "answering you",
                    reply_to=sent["event"]["event_id"])
        c.room_send(self.conn, "p1", "carol", "agent", "random broadcast")
        inbox = c.inbox_read(self.conn, "p1", "bob")
        bodies = [m["body"] for m in inbox["messages"]]
        self.assertEqual(bodies, ["hey bob", "answering you"])
        self.assertEqual(inbox["unread_broadcasts"], 1)
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
        result = c.set_lead_director(self.conn, "p1", "boss", "human",
                                     "claude_director")
        self.assertIn("context_version", result)
        self.assertEqual(
            c.get_project(self.conn, "p1")["lead_director"], "claude_director")
        handoff = c.get_handoff(self.conn, "p1")
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
        # structured message mirrors; chat does not
        sent = c.room_send(self.conn, "p1", "eng_director", "agent",
                           "deploy at 5", msg_type="directive")
        self.assertEqual(sent["mirrored_to_bridged_projects"], [p2])
        c.room_send(self.conn, "p1", "eng_director", "agent", "just chatting")
        p2_msgs = c.room_read(self.conn, p2)["messages"]
        self.assertEqual(len(p2_msgs), 1)
        self.assertEqual(p2_msgs[0]["origin_project"], "p1")
        # mentions land in the bridged inbox
        c.room_send(self.conn, "p1", "eng_director", "agent",
                    "adm, please review", mentions=["adm"])
        inbox = c.inbox_read(self.conn, p2, "adm")
        self.assertEqual(len(inbox["messages"]), 1)
        # mirrored copies never re-mirror (no ping-pong)
        self.assertEqual(
            len(c.room_read(self.conn, "p1", limit=100)["messages"]), 3)
        with self.assertRaises(c.AttaccaError):  # duplicate bridge
            c.bridge_add(self.conn, p2, "admin", "human", "p1")

    def test_bridge_master_and_advisor_authority_tags(self):
        p2 = self._second_project("adminpanel")
        c.bridge_add(self.conn, "p1", "owner", "human", p2, boss="p1")
        c.room_send(self.conn, "p1", "eng_director", "agent",
                    "use schema v2", msg_type="directive")
        c.room_send(self.conn, p2, "admin_director", "agent",
                    "could we get dark mode?", msg_type="directive")
        master_side = c.room_read(self.conn, p2)["messages"]
        self.assertEqual(master_side[0]["authority"], "master-directive")
        upstream = c.room_read(self.conn, "p1", limit=100)["messages"]
        self.assertEqual(upstream[-1]["authority"], "suggestion")
        gov = c.get_handoff(self.conn, p2)["governance"]
        self.assertEqual(gov["follows"], ["p1"])
        self.assertEqual(c.get_handoff(self.conn, "p1")["governance"]["rules_over"],
                         [p2])
        # advisor relation
        p3 = self._second_project("consultants")
        c.bridge_add(self.conn, "p1", "owner", "human", p3, advisor=p3)
        c.room_send(self.conn, p3, "sage", "agent", "consider caching",
                    msg_type="directive")
        advised = c.room_read(self.conn, "p1", limit=100)["messages"]
        self.assertEqual(advised[-1]["authority"], "advice")
        with self.assertRaises(c.AttaccaError):  # bad principal
            c.bridge_add(self.conn, p2, "x", "human", p3, boss="p1")

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
                         "jack.claude_director")
        self.assertEqual(c.qualify_actor("jack.claude_director", owner="Jack"),
                         "jack.claude_director")  # idempotent
        self.assertEqual(c.qualify_actor("claude_director", owner=None),
                         "claude_director")
        self.assertIsNone(c.qualify_actor(None, owner="Jack"))

    def test_search_everything(self):
        c.room_send(self.conn, "p1", "a", "agent", "the flux capacitor broke",
                    msg_type="challenge")
        c.task_create(self.conn, "p1", "a", "agent", "Repair flux capacitor")
        c.decision_propose(self.conn, "p1", "a", "agent",
                           "Replace flux capacitor entirely")
        c.update_handoff(self.conn, "p1", "a", "agent",
                         {"blockers": "flux capacitor supply chain"})
        hits = c.search_project(self.conn, "p1", "flux capacitor")
        self.assertGreaterEqual(len(hits["events"]), 3)
        self.assertEqual(len(hits["tasks"]), 1)
        self.assertEqual(len(hits["decisions"]), 1)
        self.assertEqual(len(hits["handoff_versions"]), 1)
        self.assertEqual(c.search_project(self.conn, "p1", "zzznothing")
                         ["total_hits"], 0)

    def test_handoff_history_and_event_show(self):
        c.update_handoff(self.conn, "p1", "a", "agent", {"objective": "one"})
        c.update_handoff(self.conn, "p1", "b", "agent", {"objective": "two"})
        history = c.handoff_history(self.conn, "p1")
        self.assertEqual([v["content"]["objective"] for v in history["versions"]],
                         ["two", "one"])
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
        # user content above the block survives a re-run
        claude_md.write_text("# My own notes\n\n" + text1)
        c.install_instructions("p1", str(self.proj_dir), self.db)
        text2 = claude_md.read_text()
        self.assertIn("# My own notes", text2)
        self.assertEqual(text2.count("MANAGED_ATTACCA:BEGIN"), 1)


if __name__ == "__main__":
    unittest.main()
