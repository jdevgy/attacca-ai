"""Lifecycle token-budget regressions (T-82 / T-84).

Measured problem: every UserPromptSubmit injected ~28KB and every Stop blocked
with the same ~28KB reason, almost entirely pinned dispositions and staged
group mail re-sent IN FULL on every boundary even when nothing was new, and a
401'd client still received that flood plus loop/update chatter on top of the
login prompt. These tests pin the five product rules that fix it:

A1 auth gate      · only the login path on SessionStart/UserPromptSubmit/Stop
A2 show once=read · a pinned/staged row is delivered in full exactly once per
                    session; afterwards ONLY a count line remains (owner
                    ruling / D-24 — the per-item reminder lines are retired)
A3 Stop = delta   · Stop blocks only for never-delivered rows / real changes
A4 open collapse  · deferred/blocked/claimed rows count but never render
A5 long mail      · staged bridged mail leaves no excerpt after its first render
A7 no self-echo   · watcher deltas authored by the receiving actor are dropped
A8 coalesce       · entity updates arrive in one prompt-time injection
A9 outage once    · a hosted-unreachable notice is surfaced once per state
A10 pulse = ping  · a managed pulse injects only new mail + one marker line,
                    and its network probe backs off during an outage
A11 rules banner  · pinned every prompt turn, full only on change/start/10th
A13 compaction    · source parity, Kimi PostCompact rebrief, brief budget
"""

import contextlib
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "session_start.py"
SPEC = importlib.util.spec_from_file_location(
    "attacca_hook_token_budget_test", HOOK)
hook = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hook)


def disposition(index, body, state=None, actor="shared.director.claude"):
    return {
        "event_id": "ev_assign%03d" % index, "seq": 100 + index,
        "actor": actor, "msg_type": "directive", "body": body,
        "mentions": ["shared.director.codex"],
        "directed_to_you": True, "addressed_to_you": True,
        "broadcast_to_everyone": False, "group_context": False,
        "requires_disposition": True,
        "disposition": {"disposition": state} if state else None,
    }


def mail(index, body, seq=None, **extra):
    row = {
        "event_id": "ev_mail%03d" % index, "seq": seq or 500 + index,
        "actor": "peer.director.claude", "msg_type": "chat", "body": body,
        "directed_to_you": True, "addressed_to_you": True,
        "broadcast_to_everyone": False, "group_context": False,
    }
    row.update(extra)
    return row


def context_of(output, event_name, runtime="codex"):
    if runtime == "kimi":
        return output["message"]
    if event_name == "Stop":
        return output["reason"]
    return output["hookSpecificOutput"]["additionalContext"]


class TokenBudgetTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.environment = mock.patch.dict(os.environ, {
            "HOME": str(self.root / "home"),
            "ATTACCA_WATCHER_DIR": str(self.root / "watcher"),
            "ATTACCA_RUNTIME": "codex",
            "ATTACCA_DEVICE_ID": "token-budget-device",
        }, clear=False)
        self.environment.start()
        self.status = {
            "status": "linked",
            "project_id": "shared",
            "root": str(self.checkout),
            "link_path": str(self.checkout / ".attacca" / "project.json"),
            "state_path": str(self.root / "setup-prompts.json"),
        }
        self.config = {
            "url": "http://attacca.test:4173",
            "actor": "codex",
            "owner": "jack",
        }
        self.key = self.register("codex")

    def tearDown(self):
        self.environment.stop()
        self.tmp.cleanup()

    # ------------------------------------------------------------ fixtures
    def register(self, runtime):
        return hook._register_watcher_subscription(
            self.status, ROOT, self.config, runtime=runtime, now=0)

    def state(self):
        return json.loads(hook._watcher_state_path().read_text())

    def entry(self, key=None):
        return self.state()["subscriptions"][key or self.key]

    def stage_dispositions(self, rows, runtime="codex"):
        page = {
            "messages": [], "read_cursor": 0, "may_have_more": False,
            "pending_dispositions": rows,
            "pending_disposition_total": len(rows),
            "pending_disposition_may_have_more": False,
        }
        with mock.patch.dict(os.environ, {"ATTACCA_RUNTIME": runtime}), \
             mock.patch.object(
                 hook, "_watcher_inbox_page", side_effect=[page, page]):
            hook._watcher_refresh_inbox_attention(
                self.status, self.config, runtime=runtime)

    def stage_mail(self, rows, key=None, acknowledged=False):
        hook._watcher_stage_attention(
            key or self.key, rows, acknowledged=acknowledged)

    def notice(self, runtime="codex", **kwargs):
        with mock.patch.dict(os.environ, {"ATTACCA_RUNTIME": runtime}):
            return hook._watcher_attention_notice(
                self.status, self.config, **kwargs)

    @contextlib.contextmanager
    def lifecycle_mocks(self, runtime, watcher=None, refresh=None,
                        update=None, mcp=None, poll=None):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(
                os.environ, {"ATTACCA_RUNTIME": runtime}, clear=False))
            stack.enter_context(mock.patch.object(
                hook, "_plugin_and_config",
                return_value=(ROOT, self.config)))
            stack.enter_context(mock.patch.object(
                hook, "_ensure_background_watcher",
                return_value=watcher or {"ok": True,
                                         "already_running": True}))
            if refresh is None:
                stack.enter_context(mock.patch.object(
                    hook, "_watcher_refresh_inbox_attention",
                    return_value={"ok": True}))
            else:
                stack.enter_context(mock.patch.object(
                    hook, "_watcher_refresh_inbox_attention",
                    side_effect=refresh))
            stack.enter_context(mock.patch.object(
                hook, "_terminal_migration_notice", return_value=None))
            stack.enter_context(mock.patch.object(
                hook, "_update_offer", return_value=update))
            stack.enter_context(mock.patch.object(
                hook, "_settings_interval", return_value=60))
            stack.enter_context(mock.patch.object(
                hook, "_refresh_managed_laws", return_value=None))
            if isinstance(mcp, Exception):
                snapshot = stack.enter_context(mock.patch.object(
                    hook, "_mcp_snapshot", side_effect=mcp))
            else:
                snapshot = stack.enter_context(mock.patch.object(
                    hook, "_mcp_snapshot", return_value=mcp))
            stack.enter_context(mock.patch.object(
                hook, "_poll_entry",
                return_value=({"key": "actor", "runtime": runtime,
                               "actor": "codex"},
                              poll if poll is not None else
                              {"snapshot": {},
                               "last_poll_at": hook.time.time()})))
            yield snapshot

    def periodic(self, event_name, runtime="codex", payload=None, **mocks):
        with self.lifecycle_mocks(runtime, **mocks) as snapshot:
            output = hook._periodic_output(
                self.status, event_name, offline_adapter=object(),
                hook_payload=payload)
        self.snapshot_calls = snapshot.call_count
        return output

    def session_start(self, runtime="codex", payload=None, **mocks):
        with self.lifecycle_mocks(runtime, **mocks) as snapshot:
            output = hook._active_output(
                self.status, offline_adapter=object(), hook_payload=payload)
        self.snapshot_calls = snapshot.call_count
        return output

    def stage_entity(self, entity_key, summary,
                     actor="peer.director.claude", key=None):
        """Queue one supersedable CURRENT ENTITY UPDATE row (A7/A8)."""
        target = key or self.key

        def mutate(state):
            entry = state["subscriptions"][target]
            entry.setdefault("pending", []).append({
                "fingerprint": "fp-%s" % entity_key,
                "kind": "project_entity_delta",
                "entity_key": entity_key,
                "actor": actor,
                "summary": ("ATTACCA CURRENT ENTITY UPDATE · shared\n- %s"
                            % summary),
                "created_at": "2026-09-03T00:00:00+00:00",
            })

        hook._mutate_state(hook._watcher_state_path(), mutate)

    def set_entry_fields(self, key=None, **fields):
        target = key or self.key

        def mutate(state):
            state["subscriptions"][target].update(fields)

        hook._mutate_state(hook._watcher_state_path(), mutate)

    def pulse_payload(self, session_id="pulse-session"):
        return {"session_id": session_id,
                "prompt": "/attacca:inbox [%s:shared]" %
                          hook.MANAGED_PULSE_MARKER}

    def hosted_snapshot(self, rules=None, tasks=0, decisions=0, activity=0,
                        room=0):
        return {
            "project": "shared",
            "checked_at": "2026-09-03T00:00:00+00:00",
            "handoff": {
                "context_version": 7,
                "handoff": {"objective": "HANDOFF-OBJECTIVE-MUST-SURVIVE"},
                "decisions": [
                    {"decision_id": "D-%02d" % index, "status": "accepted",
                     "title": "Decision %02d" % index,
                     "rationale": "RATIONALE-%02d " % index + ("d" * 400)}
                    for index in range(decisions)],
                "recent_activity": [
                    {"event_id": "ev%03d" % index, "seq": index,
                     "event_type": "task.updated",
                     "actor": "peer.director.claude",
                     "summary": "ACTIVITY-%03d " % index + ("a" * 260)}
                    for index in range(activity)],
            },
            "rules": {"rules": rules or []},
            "inbox": {"messages": [], "unread_total": 0,
                      "may_have_more": False},
            "room": {"messages": [
                {"event_id": "room%03d" % index, "seq": index,
                 "actor": "peer.director.claude", "msg_type": "chat",
                 "body": "ROOM-%03d " % index + ("m" * 200)}
                for index in range(room)]},
            "tasks": {"tasks": [
                {"task_id": "T-%02d" % index, "status": "queued",
                 "title": "TASK-%02d " % index + ("t" * 300),
                 "claimed_by": None}
                for index in range(tasks)]},
            "status": {
                "counts": {"events": 12},
                "you": {"actor_id": "shared.director.codex",
                        "actor_type": "agent",
                        "identity": {"role": "director",
                                     "runtime": "codex"}},
            },
        }

    # ---------------------------------------------------------- A1 · auth
    def test_auth_gate_all_three_events_emit_only_login(self):
        update = {"system_message": "new release",
                  "context": "UPDATE-NOTICE-HIDDEN-WHILE-401 Install now"}
        loop_payload = {"session_id": "session-401", "session_crons": []}
        hidden = (
            "DISPOSITION REQUIRED", "PENDING DISPOSITIONS",
            "ASSIGNMENT-BODY-HIDDEN-WHILE-401", "MAIL-BODY-HIDDEN-WHILE-401",
            "ATTACCA CLAUDE SESSION LOOP", "CronCreate",
            "UPDATE-NOTICE-HIDDEN-WHILE-401", "INBOX CHECK FAILED",
            "BACKGROUND WATCHER", "AUTHORITATIVE VERIFIED LOCAL MIRROR",
            "CONTINUE WORK")

        def assert_login_only(output, context):
            serialized = json.dumps(output)
            self.assertIn("ATTACCA AUTHENTICATION REQUIRED", context)
            self.assertIn("HOST REACHABLE, CACHE BLOCKED", context)
            self.assertIn("/app", context)
            for marker in hidden:
                self.assertNotIn(marker, serialized)

        for runtime in ("claude", "codex", "kimi"):
            with self.subTest(runtime=runtime):
                key = self.register(runtime)
                self.stage_dispositions([disposition(
                    1, "ASSIGNMENT-BODY-HIDDEN-WHILE-401")], runtime=runtime)
                self.stage_mail([mail(1, "MAIL-BODY-HIDDEN-WHILE-401")],
                                key=key)
                # SessionStart: the proven 401 latches auth and injects only
                # the login path — no brief, loop, update, mail, or inbox
                # retry chatter.
                start = self.session_start(
                    runtime, payload=loop_payload, update=update,
                    refresh=RuntimeError("HTTP 401 inbox rejected"),
                    mcp=hook.HostedAuthenticationRequired(
                        "revoked client-install key", http_status=401))
                assert_login_only(
                    start, context_of(start, "SessionStart", runtime))
                self.assertIn("HTTP 401", json.dumps(start))
                entry = self.entry(key)
                self.assertTrue(entry["auth_required"])
                self.assertTrue(entry["auth_login_surfaced_at"])
                self.assertNotIn("rendered", entry)
                # UserPromptSubmit: the watcher latch alone gates the turn;
                # the hook does not even poll the host.
                prompt = self.periodic(
                    "UserPromptSubmit", runtime, payload=loop_payload,
                    update=update,
                    refresh=RuntimeError("HTTP 401 inbox rejected"))
                self.assertEqual(self.snapshot_calls, 0)
                assert_login_only(
                    prompt, context_of(prompt, "UserPromptSubmit", runtime))
                if runtime == "kimi":
                    self.assertNotIn("hookSpecificOutput", prompt)
                else:
                    self.assertNotIn("decision", prompt)
                # Stop: the login was already surfaced this session → quiet.
                self.assertIsNone(self.periodic(
                    "Stop", runtime, payload=loop_payload,
                    refresh=RuntimeError("HTTP 401 inbox rejected")))

                def forget(state, key=key):
                    state["subscriptions"][key].pop(
                        "auth_login_surfaced_at", None)
                hook._mutate_state(hook._watcher_state_path(), forget)
                # A latch that has not yet been surfaced blocks Stop exactly
                # once, with the login text alone.
                stop = self.periodic(
                    "Stop", runtime, payload=loop_payload,
                    refresh=RuntimeError("HTTP 401 inbox rejected"))
                if runtime == "kimi":
                    self.assertEqual(
                        stop["hookSpecificOutput"]["permissionDecision"],
                        "deny")
                else:
                    self.assertEqual(stop["decision"], "block")
                assert_login_only(stop, context_of(stop, "Stop", runtime))
                self.assertIsNone(self.periodic(
                    "Stop", runtime, payload=loop_payload,
                    refresh=RuntimeError("HTTP 401 inbox rejected")))
                # No-loss: the gate withheld rendering, not data.
                entry = self.entry(key)
                self.assertEqual(entry["pending_disposition_total"], 1)
                self.assertEqual(
                    [row["event_id"] for row in entry["attention"]],
                    ["ev_mail001"])
                self.assertNotIn("delivered_at", entry["attention"][0])

    def test_clearing_the_latch_forgets_the_surfaced_marker(self):
        entry = self.entry()
        hook._watcher_queue_auth_required(
            self.key, entry, hook.HostedAuthenticationRequired(
                "revoked", http_status=401), 0)
        hook._watcher_mark_auth_login_surfaced(self.key)
        self.assertTrue(self.entry()["auth_login_surfaced_at"])
        # SessionStart resets the once-per-session marker so a fresh session
        # sees the login prompt again on its own boundaries.
        self.assertTrue(hook._watcher_reset_session_rendering(
            self.status, self.config))
        self.assertNotIn("auth_login_surfaced_at", self.entry())
        self.assertTrue(self.entry()["auth_required"])
        self.assertFalse(hook._watcher_reset_session_rendering(
            self.status, self.config))

    # ------------------------------------------- A2 · show once = read
    def test_render_once_second_render_is_only_a_count_line(self):
        long_body = "DISPOSITION-HEAD " + ("directive filler " * 28) + \
            "DISPOSITION-TAIL"
        mail_body = "MAIL-HEAD " + ("mail filler " * 30) + "MAIL-TAIL"
        self.assertLessEqual(len(long_body.encode("utf-8")),
                             hook.WATCHER_ROOM_BODY_LIMIT)
        self.stage_dispositions([disposition(7, long_body)])
        self.stage_mail([mail(3, mail_body)])

        first = self.notice()
        self.assertIn("PENDING DISPOSITIONS: 1 total (1 new)",
                      first["context"])
        self.assertIn("UNREAD GROUP MAIL: 1 staged (1 new)",
                      first["context"])
        self.assertIn("- [DISPOSITION REQUIRED] Event ev_assign007 · Room "
                      "#107 · directive · shared.director.claude: " +
                      long_body, first["context"])
        self.assertIn("- [YOUR ATTENTION] Room #503 · chat · "
                      "peer.director.claude: " + mail_body, first["context"])

        # SHOW ONCE = READ: an already-injected row leaves NO per-item line.
        second = self.notice()
        self.assertIn("PENDING DISPOSITIONS: 1 total (0 new)",
                      second["context"])
        self.assertIn("UNREAD GROUP MAIL: 1 staged (0 new)",
                      second["context"])
        self.assertNotIn("DISPOSITION REQUIRED] Event", second["context"])
        self.assertNotIn("DISPOSITION-HEAD", second["context"])
        self.assertNotIn("DISPOSITION-TAIL", second["context"])
        self.assertNotIn("MAIL-HEAD", second["context"])
        self.assertNotIn("MAIL-TAIL", second["context"])
        self.assertNotIn("ev_assign007", second["context"])
        self.assertNotIn("ev_mail003", second["context"])
        self.assertEqual(
            [line for line in second["context"].splitlines()
             if line.startswith("- ")], [])
        self.assertLess(len(second["context"].encode("utf-8")), 400)
        self.assertLess(len(second["context"].encode("utf-8")),
                        len(first["context"].encode("utf-8")))
        self.assertEqual(self.notice()["context"], second["context"])

        # The ledger tracks disposition state + body hash; the durable data
        # is untouched (no-loss: rendering collapsed, rows did not).
        entry = self.entry()
        ledger = entry["rendered"]
        self.assertEqual(set(ledger), {"ev_assign007", "ev_mail003"})
        self.assertEqual(
            ledger["ev_assign007"]["body_sha256"],
            hashlib.sha256(long_body.encode("utf-8")).hexdigest())
        self.assertIsNone(ledger["ev_assign007"]["disposition_state"])
        self.assertEqual(entry["pending_dispositions"][0]["body"], long_body)
        self.assertEqual(entry["attention"][0]["body"], mail_body)
        self.assertFalse(entry["attention"][0]["acknowledged"])

    def test_new_row_behind_a_full_page_is_delivered_and_counted(self):
        # QA regression (Lead, 2026-09-03): 25 delivered rows filled the
        # page; a 26th, genuinely new row must still render at the next
        # boundary and be counted as new instead of hiding behind the page.
        old = [disposition(i, "OLD-%02d " % i + "filler " * 10)
               for i in range(1, 26)]
        self.stage_dispositions(old)
        first = self.notice()
        self.assertIn("PENDING DISPOSITIONS: 25 total (25 new)",
                      first["context"])
        self.assertIsNone(self.notice(fresh_only=True))

        new_body = "NEW-ROW-HEAD " + ("fresh " * 20) + "NEW-ROW-TAIL"
        self.stage_dispositions(old + [disposition(26, new_body)])
        stop = self.notice(fresh_only=True, delta_label="STOP DELTA")
        self.assertIsNotNone(stop)
        self.assertIn("PENDING DISPOSITIONS: 26 total (1 new)",
                      stop["context"])
        self.assertIn("ev_assign026", stop["context"])
        self.assertIn(new_body, stop["context"])
        self.assertNotIn("OLD-01", stop["context"])
        self.assertEqual(
            len([line for line in stop["context"].splitlines()
                 if line.startswith("- ")]), 1)
        self.assertIsNone(self.notice(fresh_only=True))
        self.assertIn("PENDING DISPOSITIONS: 26 total (0 new)",
                      self.notice()["context"])

    def test_more_new_rows_than_a_page_are_delivered_across_boundaries(self):
        rows = [disposition(i, "BULK-%02d " % i + "filler " * 5)
                for i in range(1, 31)]
        self.stage_dispositions(rows)
        first = self.notice()
        self.assertIn("PENDING DISPOSITIONS: 30 total (30 new)",
                      first["context"])
        self.assertIn("25 of the 30 new rows are shown here", first["context"])
        self.assertEqual(
            len([line for line in first["context"].splitlines()
                 if line.startswith("- ")]), hook.WATCHER_ATTENTION_PAGE_SIZE)
        second = self.notice(fresh_only=True)
        self.assertIsNotNone(second)
        self.assertIn("PENDING DISPOSITIONS: 30 total (5 new)",
                      second["context"])
        self.assertEqual(
            len([line for line in second["context"].splitlines()
                 if line.startswith("- ")]), 5)
        self.assertIsNone(self.notice(fresh_only=True))

    def test_session_start_renders_in_full_once_more(self):
        body = "SESSION-RESET-BODY " + ("filler " * 40)
        self.stage_dispositions([disposition(4, body)])
        self.notice()
        self.assertNotIn(body, self.notice()["context"])
        # A new/resumed/compacted session (SessionStart) has a fresh model
        # context: the pinned row is due in full exactly once more.
        output = self.session_start(mcp=ConnectionRefusedError("offline"))
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("- [DISPOSITION REQUIRED] Event ev_assign004", context)
        self.assertIn(body, context)
        self.assertIn("PENDING DISPOSITIONS: 1 total (1 new)", context)
        self.assertNotIn(body, self.notice()["context"])

    # ------------------------------------------------------- A3 · Stop delta
    def test_stop_is_quiet_when_nothing_is_new(self):
        body = "STOP-QUIET-BODY " + ("filler " * 40)
        self.stage_dispositions([disposition(1, body)])
        self.stage_mail([mail(1, "STOP-QUIET-MAIL " + ("filler " * 40))])
        prompt = self.periodic("UserPromptSubmit")
        context = context_of(prompt, "UserPromptSubmit")
        self.assertIn(body, context)
        self.assertIn("STOP-QUIET-MAIL filler", context)
        stop = self.periodic("Stop")
        self.assertTrue(stop is None or stop.get("decision") != "block",
                        stop)
        # The count still reaches the next prompt turn (no loss), with no
        # per-item line at all.
        again = context_of(self.periodic("UserPromptSubmit"),
                           "UserPromptSubmit")
        self.assertIn("PENDING DISPOSITIONS: 1 total (0 new)", again)
        self.assertIn("UNREAD GROUP MAIL: 1 staged (0 new)", again)
        self.assertNotIn("ev_assign001", again)
        self.assertNotIn("ev_mail001", again)
        self.assertNotIn(body, again)

    def test_stop_blocks_with_only_the_new_item(self):
        old_body = "OLD-ASSIGNMENT-BODY " + ("filler " * 40)
        new_body = "NEW-ASSIGNMENT-BODY " + ("filler " * 40)
        self.stage_dispositions([disposition(1, old_body)])
        self.periodic("UserPromptSubmit")
        self.stage_dispositions([disposition(1, old_body),
                                 disposition(2, new_body)])
        stop = self.periodic("Stop")
        self.assertEqual(stop["decision"], "block")
        reason = stop["reason"]
        self.assertIn("- [DISPOSITION REQUIRED] Event ev_assign002", reason)
        self.assertIn(new_body, reason)
        self.assertIn("PENDING DISPOSITIONS: 2 total (1 new)", reason)
        self.assertIn("STOP DELTA", reason)
        # Already-delivered rows are never repeated in a Stop reason, not
        # even as the one-line reminder.
        self.assertNotIn(old_body, reason)
        self.assertNotIn("ev_assign001", reason)
        self.assertIn("1 new pinned row", stop["systemMessage"])
        self.assertIsNone(self.periodic("Stop"))
        prompt = context_of(self.periodic("UserPromptSubmit"),
                            "UserPromptSubmit")
        self.assertIn("PENDING DISPOSITIONS: 2 total (0 new)", prompt)

    def test_stop_blocks_for_never_delivered_staged_mail_only(self):
        self.stage_mail([mail(1, "FIRST-MAIL " + ("filler " * 40))])
        first = self.periodic("Stop")
        self.assertEqual(first["decision"], "block")
        self.assertIn("FIRST-MAIL filler", first["reason"])
        self.assertIsNone(self.periodic("Stop"))
        self.stage_mail([mail(2, "SECOND-MAIL " + ("filler " * 40))])
        second = self.periodic("Stop")
        self.assertEqual(second["decision"], "block")
        self.assertIn("SECOND-MAIL filler", second["reason"])
        self.assertNotIn("FIRST-MAIL", second["reason"])
        self.assertNotIn("ev_mail001", second["reason"])

    # ------------------------------------------- A4 · open dispositions
    def test_open_dispositions_are_counted_and_never_rendered(self):
        filler = " " + ("detail " * 40) + "TAIL"
        rows = [
            disposition(1, "DEFERRED-BODY" + filler, state="deferred"),
            disposition(2, "CLAIMED-BODY" + filler, state="claimed"),
            disposition(3, "BLOCKED-BODY" + filler, state="blocked"),
            disposition(4, "OPEN-BODY" + filler),
        ]
        self.stage_dispositions(rows)
        first = self.notice()["context"]
        # Only the one open assignment renders; the three this actor already
        # deferred/claimed/blocked count toward the total and render nothing.
        self.assertIn("PENDING DISPOSITIONS: 4 total (1 new)", first)
        for index, head in ((1, "DEFERRED-BODY"), (2, "CLAIMED-BODY"),
                            (3, "BLOCKED-BODY")):
            self.assertNotIn("ev_assign%03d" % index, first)
            self.assertNotIn(head, first)
        self.assertIn("- [DISPOSITION REQUIRED] Event ev_assign004", first)
        self.assertIn("OPEN-BODY" + filler, first)
        self.assertEqual(first.count("DISPOSITION REQUIRED] Event"), 1)
        second = self.notice()["context"]
        self.assertIn("PENDING DISPOSITIONS: 4 total (0 new)", second)
        self.assertNotIn("ev_assign004", second)
        # A never-seen row that this actor already deferred is not a reason
        # to block Stop: it is being handled, so it only raises the count.
        self.stage_dispositions(rows + [
            disposition(5, "LATE-DEFERRED" + filler, state="deferred")])
        self.assertIsNone(self.periodic("Stop"))
        prompt = context_of(self.periodic("UserPromptSubmit"),
                            "UserPromptSubmit")
        self.assertIn("PENDING DISPOSITIONS: 5 total (0 new)", prompt)
        self.assertNotIn("ev_assign005", prompt)
        self.assertNotIn("LATE-DEFERRED", prompt)

    def test_changed_disposition_or_body_re_renders_in_full_once(self):
        body = "CHANGE-TRACKED-BODY " + ("filler " * 40)
        self.stage_dispositions([disposition(1, body)])
        self.assertIn(body, self.notice()["context"])
        self.assertNotIn(body, self.notice()["context"])
        # Host reports a different (non-open) disposition state → full once.
        self.stage_dispositions([disposition(1, body, state="acknowledged")])
        changed = self.notice()["context"]
        self.assertIn("PENDING DISPOSITIONS: 1 total (1 new)", changed)
        self.assertIn("- [DISPOSITION REQUIRED · current=acknowledged] Event "
                      "ev_assign001", changed)
        self.assertIn(body, changed)
        settled = self.notice()["context"]
        self.assertIn("PENDING DISPOSITIONS: 1 total (0 new)", settled)
        self.assertNotIn("ev_assign001", settled)
        self.assertNotIn(body, settled)
        # Body change → full once more.
        amended = body + " AMENDED-BODY"
        self.stage_dispositions([disposition(
            1, amended, state="acknowledged")])
        self.assertIn(amended, self.notice()["context"])
        self.assertNotIn(amended, self.notice()["context"])
        # A transition INTO an open disposition renders compact, never full.
        self.stage_dispositions([disposition(1, amended, state="deferred")])
        deferred = self.notice()["context"]
        self.assertIn("PENDING DISPOSITIONS: 1 total (0 new)", deferred)
        self.assertNotIn("DISPOSITION REQUIRED", deferred)
        self.assertNotIn("ev_assign001", deferred)
        self.assertNotIn(amended, deferred)
        self.assertEqual(
            self.entry()["rendered"]["ev_assign001"]["disposition_state"],
            "deferred")

    # ---------------------------------------------------- A5 · long mail
    def test_staged_long_mail_leaves_no_excerpt_after_its_first_render(self):
        body = "LONG-MAIL-HEAD " + ("🌍" * 1_500) + " LONG-MAIL-TAIL"
        self.stage_mail([mail(9, body, seq=909, origin_project="peer",
                              authority="master-directive")])
        first = self.notice()["context"]
        self.assertIn("- [BRIDGE][YOUR ATTENTION] Room #909 from peer "
                      "[master-directive] · chat · peer.director.claude: "
                      "LONG-MAIL-HEAD", first)
        self.assertIn("LONG-MAIL-TAIL", first)
        self.assertIn("ATTACCA COMPACTED TEXT", first)
        second = self.notice()["context"]
        # SHOW ONCE = READ: not even a truncated excerpt survives — the row
        # is one number in the count line.
        self.assertIn("UNREAD GROUP MAIL: 1 staged (0 new)", second)
        self.assertNotIn("ev_mail009", second)
        self.assertNotIn("LONG-MAIL-HEAD", second)
        self.assertNotIn("LONG-MAIL-TAIL", second)
        self.assertNotIn("🌍", second)
        self.assertNotIn("ATTACCA COMPACTED TEXT", second)
        self.assertLess(len(second.encode("utf-8")), 400)
        # The lossless FIFO still holds the exact body for room_read/recovery.
        self.assertEqual(self.entry()["attention"][0]["body"], body)

    # -------------------------------------------------------- measurement
    RULE = {"rule_id": "R-1", "version": 3, "priority": 1,
            "scope": "everyone", "title": "Coordinate before writing",
            "body": "RULE-BODY-FULL-TEXT " + ("rule detail " * 40),
            "enabled": True}

    def test_measurement_pinned_rows_entity_deltas_and_quiet_turns(self):
        rows = []
        for index in range(25):
            head = "PIN-%02d-HEAD" % index
            tail = "PIN-%02d-TAIL" % index
            filler = ("assignment detail " * 40)[
                :590 - len(head) - len(tail) - 2]
            body = head + " " + filler + " " + tail
            self.assertLessEqual(len(body.encode("utf-8")), 600)
            self.assertGreaterEqual(len(body.encode("utf-8")), 560)
            rows.append(disposition(index + 1, body))
        self.stage_dispositions(rows)
        self.set_entry_fields(canonical_actor_id="shared.director.codex")
        for index in range(3):
            self.stage_entity("task:T-%d" % index,
                              "PEER-ENTITY-%d task queued" % index)
        for index in range(2):
            self.stage_entity("task:S-%d" % index,
                              "SELF-ENTITY-%d task queued" % index,
                              actor="shared.director.codex")
        poll = {"snapshot": {"project_rules": [self.RULE],
                             "project_rules_omitted_count": 0,
                             "project_rules_omitted_ids": []},
                "last_poll_at": hook.time.time()}

        first = context_of(self.periodic("UserPromptSubmit", poll=poll),
                           "UserPromptSubmit")
        for row in rows:
            self.assertIn(row["body"], first)
        self.assertIn("PENDING DISPOSITIONS: 25 total (25 new)", first)
        self.assertIn("RULE-BODY-FULL-TEXT", first)
        # A8: every supersedable entity row arrives in ONE injection.
        for index in range(3):
            self.assertIn("PEER-ENTITY-%d" % index, first)
        self.assertNotIn("queued update(s) remain", first)
        # A7: the two rows this actor authored are never echoed back.
        self.assertNotIn("SELF-ENTITY", first)
        turn_one_bytes = len(first.encode("utf-8"))
        self.assertGreater(turn_one_bytes, 15_000)

        second_output = self.periodic("UserPromptSubmit", poll=poll)
        second = context_of(second_output, "UserPromptSubmit")
        quiet_prompt_bytes = len(second.encode("utf-8"))
        self.assertLess(quiet_prompt_bytes, 1_000)
        self.assertIn("PENDING DISPOSITIONS: 25 total (0 new)", second)
        self.assertIn("call rule_list for full text", second)
        self.assertNotIn("RULE-BODY-FULL-TEXT", second)
        self.assertNotIn("PEER-ENTITY", second)
        for row in rows:
            self.assertNotIn(row["body"], second)
            self.assertNotIn(row["body"][-40:], second)
        self.assertNotIn("decision", second_output)
        # Nothing was dropped: all 25 remain pinned and tracked.
        entry = self.entry()
        self.assertEqual(len(entry["pending_dispositions"]), 25)
        self.assertEqual(len(entry["rendered"]), 25)
        self.assertEqual(entry["pending"], [])

        stop = self.periodic("Stop", poll=poll)
        self.assertIsNone(stop)

        pulse_output = self.periodic(
            "UserPromptSubmit", payload=self.pulse_payload(), poll=poll)
        pulse = context_of(pulse_output, "UserPromptSubmit")
        pulse_bytes = len(pulse.encode("utf-8"))
        self.assertLess(pulse_bytes, 300)
        self.assertEqual(pulse.strip(), "ATTACCA_PULSE: nothing_new")
        print("\nMEASURED · turn-1 prompt %d B · turn-2 quiet prompt %d B · "
              "turn-2 Stop %d B · quiet pulse %d B" % (
                  turn_one_bytes, quiet_prompt_bytes,
                  len(json.dumps(stop or "").encode("utf-8")) if stop else 0,
                  pulse_bytes))

    # ------------------------------------------------------ A7 · self echo
    def test_watcher_never_echoes_this_actors_own_writes(self):
        self.set_entry_fields(canonical_actor_id="shared.director.codex",
                              actor_aliases=["legacy.codex"])
        entry = self.entry()
        self.assertTrue(hook._watcher_event_is_self(
            {"event_type": "task.updated",
             "operational_actor_id": "shared.director.codex"}, entry))
        self.assertTrue(hook._watcher_event_is_self(
            {"event_type": "task.updated",
             "actor_id": "legacy.codex"}, entry))
        self.assertFalse(hook._watcher_event_is_self(
            {"event_type": "task.updated",
             "operational_actor_id": "peer.director.claude"}, entry))

        # T-75: an identity handoff is a per-actor record, so its ledger
        # event must obey the same self-echo rule as every other write.
        self.assertTrue(hook._watcher_event_is_self(
            {"event_type": "identity_handoff.updated",
             "operational_actor_id": "shared.director.codex"}, entry))
        events = [
            {"seq": 11, "event_id": "ev-self", "event_type": "task.updated",
             "operational_actor_id": "shared.director.codex",
             "task_id": "T-1", "created_at": "2026-09-03T00:00:00+00:00",
             "payload": {"title": "SELF-TASK-EDIT"}},
            {"seq": 12, "event_id": "ev-peer", "event_type": "task.updated",
             "operational_actor_id": "peer.director.claude",
             "task_id": "T-2", "created_at": "2026-09-03T00:00:01+00:00",
             "payload": {"title": "PEER-TASK-EDIT"}},
            {"seq": 13, "event_id": "ev-self-handoff",
             "event_type": "identity_handoff.updated",
             "operational_actor_id": "shared.director.codex",
             "created_at": "2026-09-03T00:00:02+00:00",
             "payload": {"fields": ["objective"],
                         "handoff_actor": "shared.director.codex",
                         "handoff_version": 4,
                         "handoff": {"objective": "SELF-IDENTITY-HANDOFF"}}},
            {"seq": 14, "event_id": "ev-peer-handoff",
             "event_type": "identity_handoff.updated",
             "operational_actor_id": "peer.director.claude",
             "created_at": "2026-09-03T00:00:03+00:00",
             "payload": {"fields": ["objective"],
                         "handoff_actor": "peer.director.claude",
                         "handoff_version": 3,
                         "handoff": {"objective": "PEER-IDENTITY-HANDOFF"}}},
        ]
        with mock.patch.object(hook, "_settings_interval", return_value=60), \
             mock.patch.object(hook, "_watcher_refresh_inbox_entry",
                               return_value={"ok": True, "staged": 0}):
            hook._watcher_tick(
                self.key, now=0, force=True,
                delta_loader=lambda after: {
                    "events": [], "next_after": 0, "may_have_more": False},
                offline_factory=lambda *_: None, notifier=lambda *_: None)
            hook._watcher_tick(
                self.key, now=60, force=True,
                delta_loader=lambda after: {
                    "events": events, "next_after": 14,
                    "may_have_more": False},
                offline_factory=lambda *_: None, notifier=lambda *_: None)
        staged = json.dumps(self.entry()["pending"])
        self.assertIn("PEER-TASK-EDIT", staged)
        self.assertNotIn("SELF-TASK-EDIT", staged)
        # The peer's identity handoff renders as its own labeled line; this
        # actor's own identity handoff write is never echoed back to it.
        summaries = "\n".join(row["summary"]
                              for row in self.entry()["pending"])
        self.assertIn(
            "identity handoff updated \u00b7 peer.director.claude \u00b7 v3",
            summaries)
        self.assertNotIn("shared.director.codex", staged)
        self.assertIn("identity-handoff:peer.director.claude",
                      [row.get("entity_key")
                       for row in self.entry()["pending"]])
        self.assertEqual(
            hook._watcher_event_line(events[3]),
            "identity handoff updated \u00b7 peer.director.claude \u00b7 v3 "
            "(objective)")

        # A self-authored row already queued by an older build is dropped at
        # render and never blocks Stop.
        self.stage_entity("task:T-9", "STALE-SELF-ROW",
                          actor="shared.director.codex")
        self.assertIsNone(self.periodic("Stop"))
        prompt = context_of(self.periodic("UserPromptSubmit"),
                            "UserPromptSubmit")
        self.assertNotIn("STALE-SELF-ROW", prompt)
        self.assertIn("PEER-TASK-EDIT", prompt)

    # ------------------------------------------------ A8 · coalesced deltas
    def test_entity_updates_are_one_injection_and_never_block_stop(self):
        for index in range(6):
            self.stage_entity("rule:R-%d" % index,
                              "ENTITY-ROW-%d rule updated" % index)
        # Stop carries no entity row at all: it is not a new-mail delta.
        self.assertIsNone(self.periodic("Stop"))
        self.assertEqual(len(self.entry()["pending"]), 6)
        prompt = context_of(self.periodic("UserPromptSubmit"),
                            "UserPromptSubmit")
        for index in range(6):
            self.assertIn("ENTITY-ROW-%d" % index, prompt)
        self.assertNotIn("queued update(s) remain", prompt)
        self.assertEqual(self.entry()["pending"], [])

    # ----------------------------------------------------- A9 · outage once
    def test_hosted_outage_is_surfaced_once_per_state(self):
        outage = ConnectionRefusedError("hosted endpoint refused")
        # A Stop boundary drops status notices, so it must not consume the
        # once-per-state latch: the outage would otherwise never be shown.
        self.assertIsNone(self.periodic("Stop", refresh=outage))
        first = context_of(
            self.periodic("UserPromptSubmit", refresh=outage),
            "UserPromptSubmit")
        self.assertEqual(first.count("ATTACCA AUTOMATIC INBOX CHECK FAILED"),
                         1)
        self.assertIn("ATTACCA AUTOMATIC INBOX CHECK FAILED", first)
        for _ in range(3):
            repeat = self.periodic("UserPromptSubmit", refresh=outage)
            self.assertTrue(
                repeat is None or "INBOX CHECK FAILED" not in
                context_of(repeat, "UserPromptSubmit"), repeat)
        # A different error class is a different state and is reported once.
        changed = context_of(
            self.periodic("UserPromptSubmit",
                          refresh=RuntimeError("gateway rejected the probe")),
            "UserPromptSubmit")
        self.assertIn("ATTACCA AUTOMATIC INBOX CHECK FAILED", changed)
        self.assertIn("gateway rejected the probe", changed)
        # Recovery clears the latch and reports exactly once — and a Stop
        # that happens to see the recovery first cannot swallow that line.
        self.assertIsNone(self.periodic("Stop"))
        restored = context_of(self.periodic("UserPromptSubmit"),
                              "UserPromptSubmit")
        self.assertIn("ATTACCA HOSTED CONNECTION RESTORED", restored)
        again = self.periodic("UserPromptSubmit")
        self.assertTrue(
            again is None or "CONNECTION RESTORED" not in
            context_of(again, "UserPromptSubmit"), again)
        # Stop never carries the outage notice.
        self.assertIsNone(self.periodic("Stop", refresh=outage))

    def test_pulse_probe_backs_off_after_three_failures_and_resets(self):
        attempts = []

        def probe(*_args, **_kwargs):
            attempts.append(1)
            raise ConnectionRefusedError("hosted endpoint down")

        outage_lines = 0
        for _ in range(5):
            output = self.periodic(
                "UserPromptSubmit", payload=self.pulse_payload(),
                refresh=probe)
            context = context_of(output, "UserPromptSubmit")
            self.assertIn("ATTACCA_PULSE:", context)
            if "INBOX CHECK FAILED" in context:
                outage_lines += 1
        # Five pulses, three network probes: the fourth and fifth are backed
        # off, and the outage was reported exactly once (A9).
        self.assertEqual(len(attempts), hook.PULSE_PROBE_FAILURE_THRESHOLD)
        self.assertEqual(outage_lines, 1)
        entry = self.entry()
        self.assertEqual(entry["pulse_probe_failures"],
                         hook.PULSE_PROBE_FAILURE_THRESHOLD)
        self.assertGreater(entry["pulse_probe_next_at_epoch"],
                           hook.time.time())
        self.assertEqual(hook._pulse_probe_backoff_seconds(3), 60)
        self.assertEqual(hook._pulse_probe_backoff_seconds(4), 120)
        self.assertEqual(hook._pulse_probe_backoff_seconds(20),
                         hook.PULSE_PROBE_BACKOFF_MAX_SECONDS)

        # The backed-off window expires; the first success resets everything
        # and emits one restored line.
        self.set_entry_fields(pulse_probe_next_at_epoch=0)
        restored = context_of(
            self.periodic("UserPromptSubmit", payload=self.pulse_payload()),
            "UserPromptSubmit")
        self.assertIn("ATTACCA HOSTED CONNECTION RESTORED", restored)
        entry = self.entry()
        self.assertNotIn("pulse_probe_failures", entry)
        self.assertNotIn("outage_notice_signature", entry)

    # -------------------------------------------------------- A10 · pulse
    def test_managed_pulse_injects_only_new_items_and_one_marker(self):
        poll = {"snapshot": {"project_rules": [self.RULE],
                             "project_rules_omitted_count": 0,
                             "project_rules_omitted_ids": []},
                "last_poll_at": hook.time.time()}
        self.stage_dispositions([disposition(1, "PULSE-ASSIGNMENT-BODY")])
        self.stage_entity("task:T-5", "PULSE-ENTITY-ROW")
        payload = self.pulse_payload()

        first_output = self.periodic(
            "UserPromptSubmit", payload=payload, poll=poll)
        first = context_of(first_output, "UserPromptSubmit")
        # (a) never-shown mail/dispositions arrive in full, first sight.
        self.assertIn("PULSE-ASSIGNMENT-BODY", first)
        self.assertIn("ATTACCA_PULSE: new=1", first)
        self.assertEqual(first.count("ATTACCA_PULSE:"), 1)
        # No rules banner and no entity drip on a machine ping.
        self.assertNotIn("MANDATORY PROJECT RULES", first)
        self.assertNotIn("PULSE-ENTITY-ROW", first)
        self.assertEqual(self.snapshot_calls, 0)

        quiet_output = self.periodic(
            "UserPromptSubmit", payload=payload, poll=poll)
        quiet = context_of(quiet_output, "UserPromptSubmit")
        self.assertEqual(quiet.strip(), "ATTACCA_PULSE: nothing_new")
        self.assertNotIn("check_inbox", quiet)
        self.assertNotIn("MANDATORY PROJECT RULES", quiet)
        self.assertLess(len(quiet.encode("utf-8")), 300)
        # The pulse consumed nothing durable: the entity row still waits for
        # the next real prompt turn.
        self.assertIn("PULSE-ENTITY-ROW", json.dumps(self.entry()["pending"]))
        prompt = context_of(self.periodic("UserPromptSubmit", poll=poll),
                            "UserPromptSubmit")
        self.assertIn("PULSE-ENTITY-ROW", prompt)

    def test_session_loop_instruction_is_session_start_only(self):
        payload = {"session_id": "loop-session", "session_crons": []}
        start = self.session_start(
            "claude", payload=payload, mcp=ConnectionRefusedError("offline"))
        self.assertIn("ATTACCA CLAUDE SESSION LOOP",
                      json.dumps(start))
        for event_name in ("UserPromptSubmit", "Stop"):
            output = self.periodic(event_name, "claude", payload=payload)
            self.assertNotIn("ATTACCA CLAUDE SESSION LOOP",
                             json.dumps(output or {}))
        pulse = self.periodic(
            "UserPromptSubmit", "claude", payload=self.pulse_payload())
        self.assertNotIn("ATTACCA CLAUDE SESSION LOOP",
                         json.dumps(pulse or {}))

    # ------------------------------------------------- A11 · rules banner
    def test_rules_banner_is_compact_until_change_or_tenth_turn(self):
        poll = {"snapshot": {"project_rules": [self.RULE],
                             "project_rules_omitted_count": 0,
                             "project_rules_omitted_ids": []},
                "last_poll_at": hook.time.time()}

        def banner(**kwargs):
            return context_of(
                self.periodic("UserPromptSubmit", poll=poll, **kwargs),
                "UserPromptSubmit")

        first = banner()
        self.assertTrue(first.startswith(
            "===================== ATTACCA MANDATORY PROJECT RULES"))
        self.assertIn("RULE-BODY-FULL-TEXT", first)
        self.assertNotIn("call rule_list for full text", first)

        for turn in range(2, 11):
            compact = banner()
            self.assertTrue(compact.startswith(
                "===================== ATTACCA MANDATORY PROJECT RULES"),
                turn)
            self.assertIn("• R-1 · Coordinate before writing", compact)
            self.assertIn("call rule_list for full text", compact)
            self.assertNotIn("RULE-BODY-FULL-TEXT", compact)
            self.assertLess(len(compact.encode("utf-8")),
                            len(first.encode("utf-8")))
        # Every tenth prompt turn re-pins the complete binding text.
        self.assertIn("RULE-BODY-FULL-TEXT", banner())

        # A rule change always restores the full banner immediately.
        self.assertNotIn("RULE-BODY-FULL-TEXT", banner())
        changed_rule = dict(self.RULE, version=4,
                            body="RULE-BODY-V4 " + ("changed detail " * 20))
        poll = {"snapshot": {"project_rules": [changed_rule],
                             "project_rules_omitted_count": 0,
                             "project_rules_omitted_ids": []},
                "last_poll_at": hook.time.time()}
        self.assertIn("RULE-BODY-V4", banner())

    def test_compact_banner_keeps_the_omitted_rule_warning(self):
        fingerprint = hook._rules_fingerprint([self.RULE], ["R-9"])
        compact = hook._compact_rules_banner(
            [self.RULE], fingerprint, pre_omitted=1, pre_omitted_ids=["R-9"])
        self.assertIn("Omitted binding rule_ids: R-9", compact)
        self.assertIn("STOP before other work and call rule_list for those "
                      "exact rule_ids", compact)
        self.assertIn("version %s" % fingerprint, compact)
        # Full renders keep their existing truncation/omission guarantees.
        full = hook._mandatory_rules_banner(
            [self.RULE], pre_omitted=1, pre_omitted_ids=["R-9"])
        self.assertIn("RULE-BODY-FULL-TEXT", full)
        self.assertIn("Omitted binding rule_ids: R-9", full)
        self.assertNotEqual(
            hook._rules_fingerprint([self.RULE]),
            hook._rules_fingerprint([dict(self.RULE, body="edited")]))

    # -------------------------------------------------- A13 · compaction
    def test_session_start_brief_is_identical_for_every_source(self):
        snapshot = self.hosted_snapshot(rules=[self.RULE], tasks=2,
                                        decisions=1, activity=2, room=1)
        self.stage_dispositions([disposition(1, "COMPACT-SOURCE-BODY")])
        rendered = {}
        for source in ("startup", "resume", "clear", "compact", "fork"):
            output = self.session_start(
                payload={"source": source, "session_id": "s-%s" % source},
                mcp=snapshot)
            rendered[source] = output[
                "hookSpecificOutput"]["additionalContext"]
            self.assertIn("ATTACCA ACTIVE SESSION BRIEF", rendered[source])
            self.assertIn("COMPACT-SOURCE-BODY", rendered[source])
        self.assertEqual(len(set(rendered.values())), 1, rendered.keys())

    def test_kimi_compaction_marks_a_rebrief_for_the_next_prompt(self):
        payload = {"session_id": "kimi-session",
                   "hook_event_name": "PostCompact"}
        key = self.register("kimi")
        with mock.patch.dict(os.environ, {"ATTACCA_RUNTIME": "kimi"}), \
             mock.patch.object(hook, "_plugin_and_config",
                               return_value=(ROOT, self.config)):
            self.assertTrue(hook._mark_rebrief_pending(
                self.status, self.config, payload))
            self.assertIn("kimi-session",
                          self.entry(key)["rebrief_pending"])
            # A managed pulse must not consume a compaction rebrief.
            self.assertTrue(hook._consume_rebrief_pending(
                self.status, self.config, payload))
            self.assertFalse(hook._consume_rebrief_pending(
                self.status, self.config, payload))
        manifest = json.loads((ROOT / "kimi.plugin.json").read_text())
        events = [row["event"] for row in manifest["hooks"]]
        self.assertIn("PostCompact", events)
        self.assertEqual(
            [row["command"] for row in manifest["hooks"]
             if row["event"] == "PostCompact"],
            ["python3 ./hooks/session_start.py"])

    def test_rebriefed_prompt_turn_emits_the_full_session_brief(self):
        snapshot = self.hosted_snapshot(rules=[self.RULE], tasks=1)
        with self.lifecycle_mocks("kimi", mcp=snapshot):
            output = hook._active_output(
                self.status, offline_adapter=object(),
                hook_payload={"session_id": "kimi-session"},
                event_name="UserPromptSubmit")
        # Kimi's prompt hook shape, carrying the SessionStart assembly.
        self.assertIn("ATTACCA ACTIVE SESSION BRIEF", output["message"])
        self.assertIn("RULE-BODY-FULL-TEXT", output["message"])

    def test_session_brief_is_trimmed_to_the_client_budget(self):
        brief = {
            "project_rules": [self.RULE],
            "cloud_context": {"content": "CLOUD-MUST-SURVIVE"},
            "handoff": {"objective": "HANDOFF-MUST-SURVIVE"},
            "unread_room": [{"seq": 1, "body": "UNREAD-MUST-SURVIVE"}],
            "recent_activity": [{"summary": "ACTIVITY-" + "a" * 400}],
            "decisions": [{"decision_id": "D-1", "status": "accepted",
                           "rationale": "DECISION-" + "d" * 400}],
            "recent_room": [{"seq": 2, "body": "ROOM-" + "m" * 400}],
            "tasks": [{"task_id": "T-1", "status": "queued",
                       "claimed_by": None, "title": "TASK-" + "t" * 400}],
        }
        trimmed, sections = hook._fit_session_brief(brief, budget=1_500)
        self.assertEqual(sections,
                         ["recent_activity", "decisions_detail",
                          "recent_room", "tasks_detail"])
        for marker in ("CLOUD-MUST-SURVIVE", "HANDOFF-MUST-SURVIVE",
                       "UNREAD-MUST-SURVIVE", "RULE-BODY-FULL-TEXT"):
            self.assertIn(marker, json.dumps(trimmed))
        for marker in ("ACTIVITY-a", "DECISION-d", "ROOM-m", "TASK-t"):
            self.assertNotIn(marker, json.dumps(trimmed))
        self.assertEqual(trimmed["tasks"],
                         [{"task_id": "T-1", "status": "queued",
                           "claimed_by": None}])
        self.assertEqual(trimmed["decisions"],
                         [{"decision_id": "D-1", "status": "accepted"}])
        # An already-small brief is returned untouched.
        small = {"handoff": {"objective": "small"}}
        self.assertEqual(hook._fit_session_brief(small), (small, []))

        snapshot = self.hosted_snapshot(rules=[self.RULE], tasks=8,
                                        decisions=6, activity=8, room=8)
        with mock.patch.object(hook, "SESSION_BRIEF_MAX_BYTES", 2_000):
            context = self.session_start(mcp=snapshot)[
                "hookSpecificOutput"]["additionalContext"]
        brief = json.loads(context.rsplit("\n\n", 1)[1])
        self.assertIn("recent_activity", brief["brief_trimmed_sections"])
        self.assertEqual(brief["recent_activity"], [])
        self.assertIn("HANDOFF-OBJECTIVE-MUST-SURVIVE", context)
        self.assertIn("RULE-BODY-FULL-TEXT", context)

    def test_identity_handoff_change_surfaces_as_a_periodic_delta(self):
        """T-75: the caller's own identity handoff is tracked shared state."""
        snapshot = self.hosted_snapshot(rules=[self.RULE])
        snapshot["handoff"].update({
            "identity_handoff_actor": "shared.director.codex",
            "identity_handoff_version": 5,
            "identity_handoff": {"objective": "IDENTITY-DELTA-OBJECTIVE"},
        })
        current = hook._poll_view(snapshot)
        self.assertEqual(current["identity_handoff_version"], 5)
        self.assertEqual(current["identity_handoff_actor"],
                         "shared.director.codex")
        baseline = dict(current)
        baseline["identity_handoff_version"] = 4
        baseline["identity_handoff"] = {"objective": "the older note"}
        # Direct-poll fallback: only a boundary that actually polls the host
        # can compare the recorded baseline with current shared state.
        context = context_of(
            self.periodic("UserPromptSubmit", mcp=snapshot,
                          watcher={"ok": True},
                          poll={"snapshot": baseline,
                                "last_poll_at": hook.time.time() - 600}),
            "UserPromptSubmit")
        self.assertIn("Identity handoff shared.director.codex: v5", context)
        self.assertIn("IDENTITY-DELTA-OBJECTIVE", context)
        # A baseline recorded before identity handoffs were tracked must not
        # manufacture a delta line on the first turn after an upgrade.
        legacy = {key: value for key, value in current.items()
                  if not key.startswith("identity_handoff")}
        upgraded = context_of(
            self.periodic("UserPromptSubmit", mcp=snapshot,
                          watcher={"ok": True},
                          poll={"snapshot": legacy,
                                "last_poll_at": hook.time.time() - 600}),
            "UserPromptSubmit")
        self.assertNotIn("Identity handoff", upgraded)

    def test_fit_session_brief_never_trims_either_handoff_block(self):
        """T-75: both continuity records are resume-critical."""
        brief = hook._compact_snapshot(self.hosted_snapshot(
            rules=[self.RULE], tasks=8, decisions=6, activity=8, room=8))
        brief["identity_handoff_actor"] = "shared.director.codex"
        brief["identity_handoff_version"] = 5
        brief["identity_handoff"] = {
            "objective": "IDENTITY-OBJECTIVE-MUST-SURVIVE",
            "next_actions": "IDENTITY-NEXT-MUST-SURVIVE"}
        trimmed, sections = hook._fit_session_brief(brief, budget=1_200)
        self.assertTrue(sections)
        rendered = json.dumps(trimmed)
        for marker in ("HANDOFF-OBJECTIVE-MUST-SURVIVE",
                       "IDENTITY-OBJECTIVE-MUST-SURVIVE",
                       "IDENTITY-NEXT-MUST-SURVIVE",
                       "SHARED PROJECT HANDOFF", "IDENTITY HANDOFF"):
            self.assertIn(marker, rendered)
        self.assertEqual(trimmed["handoff"], brief["handoff"])
        self.assertEqual(trimmed["identity_handoff"],
                         brief["identity_handoff"])
        self.assertEqual(trimmed["identity_handoff_actor"],
                         "shared.director.codex")
        self.assertEqual(trimmed["identity_handoff_version"], 5)
        # The shared block keeps its own scope/version/attribution.
        self.assertEqual(trimmed["handoff_scope"], "project")
        # A real SessionStart under the same squeeze keeps both blocks.
        snapshot = self.hosted_snapshot(rules=[self.RULE], tasks=8,
                                        decisions=6, activity=8, room=8)
        snapshot["handoff"].update({
            "identity_handoff_actor": "shared.director.codex",
            "identity_handoff_version": 5,
            "identity_handoff": {
                "objective": "IDENTITY-OBJECTIVE-MUST-SURVIVE"},
        })
        with mock.patch.object(hook, "SESSION_BRIEF_MAX_BYTES", 2_000):
            context = self.session_start(mcp=snapshot)[
                "hookSpecificOutput"]["additionalContext"]
        self.assertIn("HANDOFF-OBJECTIVE-MUST-SURVIVE", context)
        self.assertIn("IDENTITY-OBJECTIVE-MUST-SURVIVE", context)
        self.assertIn("update_identity_handoff", context)

    def test_slow_or_failed_snapshot_falls_back_instead_of_emitting_nothing(
            self):
        snapshot = self.hosted_snapshot(rules=[self.RULE])
        with mock.patch.object(hook, "SESSION_BRIEF_DEADLINE_SECONDS", -1):
            output = self.session_start(mcp=snapshot)
        self.assertIsNotNone(output)
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertNotIn("ATTACCA ACTIVE SESSION BRIEF —", context)
        self.assertIn("ATTACCA OFFLINE STATE", context)
        # A live snapshot inside the deadline still produces the live brief.
        self.assertIn("ATTACCA ACTIVE SESSION BRIEF",
                      self.session_start(mcp=snapshot)[
                          "hookSpecificOutput"]["additionalContext"])

    # ------------------------------------------------------- hardening
    def test_offline_failure_auth_fallback_uses_the_once_marker_gate(self):
        hook._watcher_queue_auth_required(
            self.key, self.entry(),
            hook.HostedAuthenticationRequired("revoked", http_status=401), 0)
        entry = self.entry()
        self.assertTrue(entry["auth_required"])
        with mock.patch.object(hook, "_plugin_and_config",
                               return_value=(ROOT, self.config)):
            stop = hook._offline_failure_output(
                self.status, self.config, "Stop",
                ConnectionRefusedError("offline"), object(), entry=entry)
            self.assertEqual(stop["decision"], "block")
            self.assertIn("ATTACCA AUTHENTICATION REQUIRED", stop["reason"])
            self.assertTrue(self.entry()["auth_login_surfaced_at"])
            # Second Stop of the same session is silent, and the caller must
            # not replace it with a generic sync-failure notice.
            self.assertIsNone(hook._offline_failure_output(
                self.status, self.config, "Stop",
                ConnectionRefusedError("offline"), object(),
                entry=self.entry()))
            prompt = hook._offline_failure_output(
                self.status, self.config, "UserPromptSubmit",
                ConnectionRefusedError("offline"), object(),
                entry=self.entry())
        self.assertIn("ATTACCA AUTHENTICATION REQUIRED",
                      prompt["hookSpecificOutput"]["additionalContext"])
        self.assertIsNone(self.periodic("Stop"))


if __name__ == "__main__":
    unittest.main()
