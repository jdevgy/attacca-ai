"""Lifecycle token-budget regressions (T-82 / T-84).

Measured problem: every UserPromptSubmit injected ~28KB and every Stop blocked
with the same ~28KB reason, almost entirely pinned dispositions and staged
group mail re-sent IN FULL on every boundary even when nothing was new, and a
401'd client still received that flood plus loop/update chatter on top of the
login prompt. These tests pin the five product rules that fix it:

A1 auth gate      · only the login path on SessionStart/UserPromptSubmit/Stop
A2 render-once    · a pinned/staged row is delivered in full exactly once per
                    session, then as one reminder line
A3 Stop = delta   · Stop blocks only for never-delivered rows / real changes
A4 open collapse  · deferred/blocked/claimed rows are always the one-liner
A5 long mail      · staged bridged mail collapses to one line + room_read hint
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
                        update=None, mcp=None):
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
            if isinstance(refresh, Exception):
                stack.enter_context(mock.patch.object(
                    hook, "_watcher_refresh_inbox_attention",
                    side_effect=refresh))
            else:
                stack.enter_context(mock.patch.object(
                    hook, "_watcher_refresh_inbox_attention",
                    return_value={"ok": True}))
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
                return_value=({"key": "actor"},
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
        with self.lifecycle_mocks(runtime, **mocks):
            return hook._active_output(
                self.status, offline_adapter=object(), hook_payload=payload)

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

    # ---------------------------------------------------- A2 · render once
    def test_render_once_second_render_is_one_line(self):
        long_body = "DISPOSITION-HEAD " + ("directive filler " * 28) + \
            "DISPOSITION-TAIL"
        mail_body = "MAIL-HEAD " + ("mail filler " * 30) + "MAIL-TAIL"
        self.assertLessEqual(len(long_body.encode("utf-8")),
                             hook.WATCHER_ROOM_BODY_LIMIT)
        self.stage_dispositions([disposition(7, long_body)])
        self.stage_mail([mail(3, mail_body)])

        first = self.notice()
        self.assertIn("PENDING DISPOSITIONS (1 total · 1 new · 0 collapsed)",
                      first["context"])
        self.assertIn("UNREAD GROUP MAIL (1 staged · 1 new · 0 collapsed)",
                      first["context"])
        self.assertIn("- [DISPOSITION REQUIRED] Event ev_assign007 · Room "
                      "#107 · directive · shared.director.claude: " +
                      long_body, first["context"])
        self.assertIn("- [YOUR ATTENTION] Room #503 · chat · "
                      "peer.director.claude: " + mail_body, first["context"])
        self.assertNotIn("[PENDING ·", first["context"])

        second = self.notice()
        self.assertIn("PENDING DISPOSITIONS (1 total · 0 new · 1 collapsed)",
                      second["context"])
        self.assertIn("UNREAD GROUP MAIL (1 staged · 0 new · 1 collapsed)",
                      second["context"])
        self.assertNotIn("DISPOSITION REQUIRED", second["context"])
        self.assertNotIn("DISPOSITION-TAIL", second["context"])
        self.assertNotIn("MAIL-TAIL", second["context"])
        lines = second["context"].splitlines()
        assignment = [line for line in lines
                      if line.startswith("- [PENDING · none] ev_assign007")]
        self.assertEqual(len(assignment), 1)
        self.assertTrue(assignment[0].startswith(
            "- [PENDING · none] ev_assign007 · Room #107 · directive · "
            "shared.director.claude: DISPOSITION-HEAD directive filler"))
        self.assertIn("…", assignment[0])
        unread = [line for line in lines
                  if line.startswith("- [PENDING · none] ev_mail003")]
        self.assertEqual(len(unread), 1)
        self.assertTrue(unread[0].startswith(
            "- [PENDING · none] ev_mail003 · Room #503 · chat · "
            "peer.director.claude: MAIL-HEAD mail filler"))
        self.assertTrue(unread[0].endswith(
            "room_read since_seq=502 for the full body"))
        self.assertLess(len(second["context"].encode("utf-8")),
                        len(first["context"].encode("utf-8")))
        for line in (assignment[0], unread[0]):
            self.assertLessEqual(len(line.encode("utf-8")), 240)
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
        self.assertIn("PENDING DISPOSITIONS (1 total · 1 new · 0 collapsed)",
                      context)
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
        # The reminder still reaches the next prompt turn (no loss).
        again = context_of(self.periodic("UserPromptSubmit"),
                           "UserPromptSubmit")
        self.assertIn("- [PENDING · none] ev_assign001", again)
        self.assertIn("- [PENDING · none] ev_mail001", again)
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
        self.assertIn("PENDING DISPOSITIONS (2 total · 1 new · 1 collapsed)",
                      reason)
        self.assertIn("STOP DELTA", reason)
        # Already-delivered rows are never repeated in a Stop reason, not
        # even as the one-line reminder.
        self.assertNotIn(old_body, reason)
        self.assertNotIn("ev_assign001", reason)
        self.assertIn("1 new pinned row", stop["systemMessage"])
        self.assertIsNone(self.periodic("Stop"))
        prompt = context_of(self.periodic("UserPromptSubmit"),
                            "UserPromptSubmit")
        self.assertIn("PENDING DISPOSITIONS (2 total · 0 new · 2 collapsed)",
                      prompt)

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
    def test_open_dispositions_collapse_even_on_first_render(self):
        filler = " " + ("detail " * 40) + "TAIL"
        rows = [
            disposition(1, "DEFERRED-BODY" + filler, state="deferred"),
            disposition(2, "CLAIMED-BODY" + filler, state="claimed"),
            disposition(3, "BLOCKED-BODY" + filler, state="blocked"),
            disposition(4, "OPEN-BODY" + filler),
        ]
        self.stage_dispositions(rows)
        first = self.notice()["context"]
        self.assertIn("PENDING DISPOSITIONS (4 total · 4 new · 0 collapsed)",
                      first)
        for state, index, head in (("deferred", 1, "DEFERRED-BODY"),
                                   ("claimed", 2, "CLAIMED-BODY"),
                                   ("blocked", 3, "BLOCKED-BODY")):
            self.assertIn(
                "- [PENDING · %s] ev_assign%03d · Room #%d · directive · "
                "shared.director.claude: %s detail" % (
                    state, index, 100 + index, head), first)
            self.assertNotIn("current=%s" % state, first)
        self.assertNotIn("DEFERRED-BODY" + filler, first)
        self.assertNotIn("CLAIMED-BODY" + filler, first)
        self.assertNotIn("BLOCKED-BODY" + filler, first)
        self.assertIn("- [DISPOSITION REQUIRED] Event ev_assign004", first)
        self.assertIn("OPEN-BODY" + filler, first)
        self.assertEqual(first.count("DISPOSITION REQUIRED"), 1)
        second = self.notice()["context"]
        self.assertIn("PENDING DISPOSITIONS (4 total · 0 new · 4 collapsed)",
                      second)
        self.assertIn("- [PENDING · none] ev_assign004", second)
        # A never-seen row that this actor already deferred is not a reason
        # to block Stop: it is being handled, and only the reminder is due.
        self.stage_dispositions(rows + [
            disposition(5, "LATE-DEFERRED" + filler, state="deferred")])
        self.assertIsNone(self.periodic("Stop"))
        prompt = context_of(self.periodic("UserPromptSubmit"),
                            "UserPromptSubmit")
        self.assertIn("- [PENDING · deferred] ev_assign005", prompt)

    def test_changed_disposition_or_body_re_renders_in_full_once(self):
        body = "CHANGE-TRACKED-BODY " + ("filler " * 40)
        self.stage_dispositions([disposition(1, body)])
        self.assertIn(body, self.notice()["context"])
        self.assertNotIn(body, self.notice()["context"])
        # Host reports a different (non-open) disposition state → full once.
        self.stage_dispositions([disposition(1, body, state="acknowledged")])
        changed = self.notice()["context"]
        self.assertIn("PENDING DISPOSITIONS (1 total · 1 new · 0 collapsed)",
                      changed)
        self.assertIn("- [DISPOSITION REQUIRED · current=acknowledged] Event "
                      "ev_assign001", changed)
        self.assertIn(body, changed)
        settled = self.notice()["context"]
        self.assertIn("- [PENDING · acknowledged] ev_assign001", settled)
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
        self.assertIn("- [PENDING · deferred] ev_assign001", deferred)
        self.assertNotIn("DISPOSITION REQUIRED", deferred)
        self.assertNotIn(amended, deferred)
        self.assertEqual(
            self.entry()["rendered"]["ev_assign001"]["disposition_state"],
            "deferred")

    # ---------------------------------------------------- A5 · long mail
    def test_staged_long_mail_collapses_after_first_full_render(self):
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
        lines = [line for line in second.splitlines()
                 if line.startswith("- [PENDING · none] ev_mail009")]
        self.assertEqual(len(lines), 1)
        line = lines[0]
        self.assertTrue(line.startswith(
            "- [PENDING · none] ev_mail009 · Room #909 · chat · "
            "peer.director.claude: LONG-MAIL-HEAD 🌍"))
        self.assertTrue(line.endswith(
            "… · room_read since_seq=908 for the full body"))
        self.assertLessEqual(line.count("🌍"),
                             hook.WATCHER_COLLAPSED_BODY_CHARACTERS)
        self.assertNotIn("LONG-MAIL-TAIL", second)
        self.assertNotIn("ATTACCA COMPACTED TEXT", second)
        self.assertLess(len(second.encode("utf-8")), 1_200)
        # The lossless FIFO still holds the exact body for room_read/recovery.
        self.assertEqual(self.entry()["attention"][0]["body"], body)

    # -------------------------------------------------------- measurement
    def test_measurement_25_pinned_items_second_turn_under_3000_bytes(self):
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

        first = context_of(self.periodic("UserPromptSubmit"),
                           "UserPromptSubmit")
        for row in rows:
            self.assertIn(row["body"], first)
        self.assertIn("PENDING DISPOSITIONS (25 total · 25 new · 0 collapsed)",
                      first)
        self.assertGreater(len(first.encode("utf-8")), 15_000)

        second_output = self.periodic("UserPromptSubmit")
        second = context_of(second_output, "UserPromptSubmit")
        self.assertLess(len(second.encode("utf-8")), 3_000)
        self.assertIn("PENDING DISPOSITIONS (25 total · 0 new · 25 collapsed)",
                      second)
        for row in rows:
            self.assertNotIn(row["body"], second)
            self.assertNotIn(row["body"][-40:], second)
        self.assertIn("- [PENDING · none] ev_assign001 · Room #101", second)
        self.assertIn("check_inbox for the complete current set", second)
        self.assertNotIn("decision", second_output)
        # Nothing was dropped: all 25 remain pinned and tracked.
        entry = self.entry()
        self.assertEqual(len(entry["pending_dispositions"]), 25)
        self.assertEqual(len(entry["rendered"]), 25)
        self.assertIsNone(self.periodic("Stop"))
        third = context_of(self.periodic("UserPromptSubmit"),
                           "UserPromptSubmit")
        self.assertEqual(third, second)


if __name__ == "__main__":
    unittest.main()
