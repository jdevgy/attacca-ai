"""Multi-process concurrency tests: many workers, one SQLite ledger.

These simulate the real deployment shape: each AI tool (Claude Code, Codex,
GLM, ...) spawns its own MCP server process, all sharing one WAL-mode SQLite
database. Appends must never lose or duplicate a sequence number, and a task
claim must have exactly one winner.
"""
import importlib.util
import json
import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path

# Isolate tests from any machine identity (~/.attacca/identity.json)
os.environ["ATTACCA_OWNER"] = ""

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("attacca", ROOT / "attacca.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

WORKERS = 8
EVENTS_PER_WORKER = 20


def _append_worker(args):
    db, worker_id, count = args
    conn = c.connect(db)
    try:
        for i in range(count):
            c.append_event(conn, "stress", "worker-%d" % worker_id, "agent",
                           "note.stress", {"worker": worker_id, "i": i})
        return None
    except Exception as err:  # pragma: no cover - failure information
        return "worker %d: %r" % (worker_id, err)
    finally:
        conn.close()


def _claim_worker(args):
    db, worker_id, task_id, barrier = args if len(args) == 4 else (*args, None)
    conn = c.connect(db)
    try:
        c.task_claim(conn, "stress", "claimant-%d" % worker_id, "agent", task_id)
        return ("won", worker_id)
    except c.AttaccaError:
        return ("lost", worker_id)
    except Exception as err:  # pragma: no cover
        return ("error", "%r" % err)
    finally:
        conn.close()


def _mixed_worker(args):
    db, worker_id = args
    conn = c.connect(db)
    try:
        c.room_send(conn, "stress", "mixer-%d" % worker_id, "agent",
                    "hello from %d" % worker_id)
        c.task_create(conn, "stress", "mixer-%d" % worker_id, "agent",
                      "task from %d" % worker_id)
        c.decision_propose(conn, "stress", "mixer-%d" % worker_id, "agent",
                           "decision from %d" % worker_id)
        return None
    except Exception as err:  # pragma: no cover
        return "worker %d: %r" % (worker_id, err)
    finally:
        conn.close()


def _handoff_worker(db, actor_id, expected_version, value, barrier, outcomes):
    """Race one optimistic handoff write from an independent connection."""
    conn = c.connect(db)
    try:
        # Both directors have opened their own WAL connections and share the
        # same stale-able version before either is allowed to BEGIN IMMEDIATE.
        barrier.wait(timeout=10)
        result = c.update_handoff(
            conn, "stress", actor_id, "agent",
            {"what_changed": value},
            expected_context_version=expected_version)
        outcomes.put({"status": "won", "actor": actor_id, "value": value,
                      "context_version": result["context_version"]})
    except c.AttaccaError as err:
        text = str(err)
        outcomes.put({"status": "conflict" if "handoff conflict" in text
                      else "error", "actor": actor_id, "value": value,
                      "error": text})
    except Exception as err:  # pragma: no cover - failure information
        outcomes.put({"status": "error", "actor": actor_id, "value": value,
                      "error": repr(err)})
    finally:
        conn.close()


class ConcurrencyTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "stress.db")
        conn = c.connect(self.db)
        c.project_init(conn, "setup", "human", path=self.tmp.name,
                       project_id="stress", name="Stress")
        self.base_events = conn.execute(
            "SELECT COUNT(*) AS n FROM events").fetchone()["n"]
        conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_parallel_appends_keep_ledger_integrity(self):
        with multiprocessing.Pool(WORKERS) as pool:
            errors = pool.map(_append_worker,
                              [(self.db, i, EVENTS_PER_WORKER)
                               for i in range(WORKERS)])
        errors = [e for e in errors if e]
        self.assertEqual(errors, [])
        conn = c.connect(self.db)
        rows = conn.execute(
            "SELECT seq FROM events WHERE project_id='stress' ORDER BY seq").fetchall()
        seqs = [r["seq"] for r in rows]
        expected_total = self.base_events + WORKERS * EVENTS_PER_WORKER
        self.assertEqual(len(seqs), expected_total)
        self.assertEqual(seqs, list(range(1, expected_total + 1)))
        verify = c.verify_ledger(conn, "stress")
        self.assertTrue(verify["ok"], verify["problems"])
        conn.close()

    def test_competing_claims_have_exactly_one_winner(self):
        conn = c.connect(self.db)
        task_id = c.task_create(conn, "stress", "setup", "human",
                                "contended task")["task_id"]
        conn.close()
        with multiprocessing.Pool(12) as pool:
            outcomes = pool.map(_claim_worker,
                                [(self.db, i, task_id) for i in range(12)])
        wins = [o for o in outcomes if o[0] == "won"]
        losses = [o for o in outcomes if o[0] == "lost"]
        errors = [o for o in outcomes if o[0] == "error"]
        self.assertEqual(errors, [])
        self.assertEqual(len(wins), 1, outcomes)
        self.assertEqual(len(losses), 11)
        conn = c.connect(self.db)
        task = c._task_dict(c._task_row(conn, "stress", task_id))
        self.assertEqual(task["status"], "claimed")
        self.assertEqual(task["claimed_by"], "claimant-%d" % wins[0][1])
        conn.close()

    def test_parallel_identities_have_one_project_context_guard_winner(self):
        conn = c.connect(self.db)
        for actor in ("director-a", "director-b"):
            c.agent_register(conn, "stress", actor, "agent",
                             role="director", runtime="concurrency-test")
        c.set_lead_director(
            conn, "stress", "admin", "human", "director-a")
        seed_expected = c.get_handoff(
            conn, "stress", actor_id="director-a",
            actor_type="agent")["context_version"]
        c.update_handoff(
            conn, "stress", "director-a", "agent",
            {"objective": "shared objective", "notes": "seed is preserved"},
            expected_context_version=seed_expected)
        expected = c.get_handoff(
            conn, "stress", actor_id="director-a",
            actor_type="agent")["context_version"]
        baseline_seq = conn.execute(
            "SELECT COALESCE(MAX(seq), 0) AS seq FROM events "
            "WHERE project_id='stress'").fetchone()["seq"]
        baseline_handoffs = conn.execute(
            "SELECT COUNT(*) AS n FROM handoffs "
            "WHERE project_id='stress'").fetchone()["n"]
        conn.close()

        barrier = multiprocessing.Barrier(2)
        outcomes = multiprocessing.Queue()
        candidates = [
            ("director-a", "director A won the race"),
            ("director-b", "director B won the race"),
        ]
        processes = [multiprocessing.Process(
            target=_handoff_worker,
            args=(self.db, actor, expected, value, barrier, outcomes))
            for actor, value in candidates]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=15)
        hung = [process for process in processes if process.is_alive()]
        for process in hung:
            process.terminate()
            process.join(timeout=5)
        self.assertEqual(hung, [], "parallel handoff workers did not finish")
        self.assertEqual([process.exitcode for process in processes], [0, 0])

        results = [outcomes.get(timeout=5) for _ in processes]
        outcomes.close()
        outcomes.join_thread()
        winners = [result for result in results if result["status"] == "won"]
        conflicts = [result for result in results
                     if result["status"] == "conflict"]
        errors = [result for result in results if result["status"] == "error"]
        self.assertEqual(errors, [], results)
        self.assertEqual(len(winners), 1, results)
        self.assertEqual(len(conflicts), 1, results)
        self.assertIn("handoff conflict", conflicts[0]["error"])
        winner = winners[0]
        self.assertNotEqual(winner["actor"], conflicts[0]["actor"])
        self.assertEqual(winner["context_version"], expected + 1)

        conn = c.connect(self.db)
        final = c.get_handoff(
            conn, "stress", actor_id=winner["actor"],
            actor_type="agent")
        self.assertEqual(final["context_version"], expected + 1)
        # The shared project handoff has no owning identity; the losing
        # Director's write is rejected instead of merged.
        self.assertIsNone(final["handoff_actor"])
        self.assertEqual(final["handoff_scope"], "project")
        self.assertEqual(final["handoff_updated_by"], winner["actor"])
        self.assertEqual(final["handoff"]["what_changed"], winner["value"])
        self.assertEqual(final["handoff"]["objective"], "shared objective")
        self.assertEqual(final["handoff"]["notes"], "seed is preserved")
        self.assertNotEqual(final["handoff"]["what_changed"],
                            conflicts[0]["value"])
        handoff_count = conn.execute(
            "SELECT COUNT(*) AS n FROM handoffs "
            "WHERE project_id='stress'").fetchone()["n"]
        self.assertEqual(handoff_count, baseline_handoffs + 1)
        events = conn.execute(
            "SELECT actor_id, payload FROM events "
            "WHERE project_id='stress' AND seq>? "
            "AND event_type='handoff.updated' ORDER BY seq",
            (baseline_seq,)).fetchall()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["actor_id"], winner["actor"])
        event_payload = json.loads(events[0]["payload"])
        self.assertEqual(event_payload["handoff"]["what_changed"],
                         winner["value"])
        verify = c.verify_ledger(conn, "stress")
        self.assertTrue(verify["ok"], verify["problems"])
        conn.close()

    def test_mixed_parallel_workload(self):
        with multiprocessing.Pool(6) as pool:
            errors = pool.map(_mixed_worker, [(self.db, i) for i in range(6)])
        errors = [e for e in errors if e]
        self.assertEqual(errors, [])
        conn = c.connect(self.db)
        verify = c.verify_ledger(conn, "stress")
        self.assertTrue(verify["ok"], verify["problems"])
        tasks = c.task_list(conn, "stress")["tasks"]
        self.assertEqual(len(tasks), 6)
        self.assertEqual(len({t["task_id"] for t in tasks}), 6)  # unique ids
        decisions = c.decision_list(conn, "stress")["decisions"]
        self.assertEqual(len({d["decision_id"] for d in decisions}), 6)
        msgs = c.room_read(conn, "stress", limit=100)["messages"]
        self.assertEqual(len(msgs), 6)
        conn.close()


if __name__ == "__main__":
    unittest.main()
