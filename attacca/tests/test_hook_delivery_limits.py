"""Adversarial lifecycle context-budget and watcher-delivery regressions."""

import copy
import importlib.util
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "session_start.py"
SPEC = importlib.util.spec_from_file_location(
    "attacca_hook_delivery_limits_test", HOOK)
hook = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hook)

MAX_CONTEXT_BYTES = 262_144
RULES_BANNER_PREFIX = (
    "===================== ATTACCA MANDATORY PROJECT RULES")


def event(seq, body):
    return {
        "event_id": "watch-event-%03d" % seq,
        "seq": seq,
        "event_type": "room.message",
        "actor_id": "shared.director.claude",
        "operational_actor_id": "shared.director.claude",
        "context_version": seq,
        "payload": {
            "msg_type": "chat",
            "body": body,
            "broadcast_to_everyone": True,
            "addressed_to_you": True,
        },
    }


def delta(events=None, next_after=None, may_have_more=False):
    rows = list(events or [])
    if next_after is None:
        next_after = rows[-1]["seq"] if rows else 0
    return {
        "events": rows,
        "next_after": next_after,
        "may_have_more": may_have_more,
    }


class HookBriefContextBudgetTestCase(unittest.TestCase):
    def _messages(self, count=100):
        rows = []
        for index in range(count):
            marker = "GROUP-MESSAGE-%03d-MUST-SURVIVE" % index
            body = marker + " " + ("message filler " * 45)
            if index == 0:
                body = marker + " LONG-HEAD " + ("💬" * 1_000) + \
                    " LONG-TAIL"
            rows.append({
                "event_id": "brief-event-%03d" % index,
                "seq": index + 1,
                "actor": "shared.worker.claude",
                "msg_type": "chat",
                "body": body,
                "mentions": [],
                "reply_to": None,
                "addressed_to_you": True,
                "broadcast_to_everyone": True,
                "group_context": False,
            })
        return rows

    def _snapshot(self, cloud_content, messages=None, rules=None):
        messages = list(messages or [])
        verbose = "verbose-state-" * 250
        return {
            "project": "shared",
            "checked_at": "2026-08-26T00:00:00+00:00",
            "handoff": {
                "context_version": 99,
                "lead_director": "shared.director.codex",
                "handoff": {
                    "objective": "Keep the authoritative objective. " + verbose,
                    "what_changed": verbose,
                    "active_work": verbose,
                    "blockers": verbose,
                    "risks": verbose,
                    "next_actions": verbose,
                },
                "cloud_context": {
                    "version": 8,
                    "content": cloud_content,
                },
                "decisions": [{
                    "decision_id": "D-%d" % index,
                    "title": "Verbose decision %d" % index,
                    "status": "accepted",
                    "detail": verbose,
                    "rationale": verbose,
                } for index in range(100)],
                "recent_activity": [{
                    "seq": index,
                    "summary": verbose,
                } for index in range(100)],
            },
            "inbox": {
                "messages": messages,
                "unread_total": len(messages),
                "unread_addressed": len(messages),
                "unread_direct": 0,
                "unread_everyone": len(messages),
                "unread_group_context": 0,
                "may_have_more": False,
            },
            "room": {"messages": list(messages)},
            "tasks": {"tasks": [{
                "task_id": "T-%d" % index,
                "title": "Verbose task %d %s" % (index, verbose),
                "status": "claimed",
                "claimed_by": "shared.worker.claude",
                "risk_level": "high",
            } for index in range(50)]},
            "status": {
                "you": {"actor_id": "shared.director.codex"},
                "counts": {"events": 50_000, "tasks": 50},
            },
            "agents": {"agents": [{
                "agent_id": "shared.director.codex",
                "role": "director",
            }]},
            "rules": {"rules": rules or [{
                "rule_id": "R-1",
                "title": "Retain the mandatory rule",
                "body": "MANDATORY-RULE-MUST-SURVIVE " + verbose,
                "scope": "everyone",
                "priority": 1,
                "enabled": True,
            }]},
        }

    def _active_context(self, snapshot, runtime="codex"):
        status = {
            "project_id": "shared",
            "root": "/workspace/shared",
            "link_path": "/workspace/shared/.attacca/project.json",
            "state_path": "/unused/setup-prompts.json",
        }
        config = {"url": "http://attacca.test", "actor": "codex",
                  "owner": "jack"}
        watcher_entry = {
            "project_id": "shared",
            "canonical_actor_id": "shared.director.codex",
        }
        with mock.patch.dict(os.environ, {
                "ATTACCA_RUNTIME": runtime,
                "PLUGIN_ROOT": str(ROOT),
        }, clear=False), \
             mock.patch.object(hook, "_plugin_and_config",
                               return_value=(ROOT, config)), \
             mock.patch.object(hook, "_ensure_background_watcher",
                               return_value={"ok": True}), \
             mock.patch.object(hook, "_watcher_subscription_entry",
                               return_value=("watch-key", watcher_entry)), \
             mock.patch.object(hook, "_settings_interval", return_value=60), \
             mock.patch.object(hook, "_watcher_pending_notice",
                               return_value=None), \
             mock.patch.object(hook, "_terminal_migration_notice",
                               return_value=None), \
             mock.patch.object(hook, "_update_offer", return_value=None), \
             mock.patch.object(hook, "_mcp_snapshot",
                               return_value=snapshot), \
             mock.patch.object(hook, "_watcher_activate_after_mcp"), \
             mock.patch.object(hook, "_poll_entry",
                               return_value=({"key": "actor"}, {})), \
             mock.patch.object(hook, "_record_poll"), \
             mock.patch.object(hook, "_needs_role_setup",
                               return_value=False), \
             mock.patch.object(hook, "_refresh_managed_laws",
                               return_value=None):
            output = hook._active_output(status, offline_adapter=object())
        return output.get("message") or \
            output["hookSpecificOutput"]["additionalContext"]

    def test_100k_ascii_cloud_and_paged_unread_are_lossless_and_bounded(self):
        cloud_head = "CLOUD-CONTEXT-HEAD-MUST-SURVIVE"
        cloud_tail = "CLOUD-CONTEXT-TAIL-MUST-SURVIVE"
        cloud_content = cloud_head + (
            "C" * (100_000 - len(cloud_head) - len(cloud_tail))) + cloud_tail
        messages = self._messages()
        snapshot = self._snapshot(cloud_content, messages)

        compact = hook._compact_snapshot(snapshot)
        self.assertEqual(compact["cloud_context"]["content"], cloud_content)
        self.assertNotIn("content_truncated", compact["cloud_context"])
        self.assertEqual(
            [row["seq"] for row in compact["unread_room"]],
            list(range(1, hook.STARTUP_INBOX_PAGE_SIZE + 1)))
        self.assertTrue(compact["unread_room_may_have_more"])
        self.assertIn("Call check_inbox again before other work",
                      compact["unread_room_next_action"])
        first_body = compact["unread_room"][0]
        self.assertTrue(first_body["body_truncated"])
        self.assertLessEqual(
            len(first_body["body"].encode("utf-8")),
            hook.STARTUP_UNREAD_BODY_LIMIT)
        self.assertIn("LONG-HEAD", first_body["body"])
        self.assertIn("LONG-TAIL", first_body["body"])
        self.assertIn("room_read with since_seq=0", first_body["body"])

        context = self._active_context(snapshot)
        self.assertLessEqual(len(context.encode("utf-8")), MAX_CONTEXT_BYTES)
        self.assertTrue(context.startswith(RULES_BANNER_PREFIX))
        self.assertIn("MANDATORY-RULE-MUST-SURVIVE", context)
        self.assertIn(cloud_content, context)
        first_page_markers = [
            "GROUP-MESSAGE-%03d-MUST-SURVIVE" % index
            for index in range(hook.STARTUP_INBOX_PAGE_SIZE)]
        positions = [context.index(marker) for marker in first_page_markers]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("GROUP-MESSAGE-025-MUST-SURVIVE", context)

        # A caller obeying may_have_more receives each subsequent page in FIFO
        # order; no page asks it to rely on a cursor that has already skipped a
        # message.
        recovered = []
        for offset in range(0, len(messages), hook.STARTUP_INBOX_PAGE_SIZE):
            page = copy.deepcopy(snapshot)
            page["inbox"]["messages"] = messages[
                offset:offset + hook.STARTUP_INBOX_PAGE_SIZE]
            page["inbox"]["may_have_more"] = (
                offset + hook.STARTUP_INBOX_PAGE_SIZE < len(messages))
            page_compact = hook._compact_snapshot(page)
            recovered.extend(row["seq"] for row in page_compact["unread_room"])
            self.assertEqual(
                page_compact["unread_room_may_have_more"],
                offset + hook.STARTUP_INBOX_PAGE_SIZE < len(messages))
        self.assertEqual(recovered, list(range(1, len(messages) + 1)))

    def test_emoji_cloud_context_compaction_is_utf8_bounded_and_recoverable(self):
        cloud_head = "EMOJI-CLOUD-HEAD-MUST-SURVIVE"
        cloud_tail = "EMOJI-CLOUD-TAIL-MUST-SURVIVE"
        cloud_content = cloud_head + ("🌍" * 50_000) + cloud_tail
        compact = hook._compact_cloud_context({
            "version": 9,
            "content": cloud_content,
        })

        rendered = compact["content"]
        self.assertTrue(compact["content_truncated"])
        self.assertLessEqual(len(rendered.encode("utf-8")), 100_000)
        self.assertIn(cloud_head, rendered)
        self.assertIn(cloud_tail, rendered)
        self.assertIn("ATTACCA COMPACTED TEXT", rendered)
        self.assertIn("call cloud_context_get", rendered)

    def test_utf8_budget_rules_first_and_notice_visible_for_each_hook_shape(self):
        rules_banner = hook._mandatory_rules_banner([{
            "rule_id": "R-CAP",
            "title": "Rules must remain literal-first",
            "body": "CAP-RULE-MUST-SURVIVE",
            "scope": "everyone",
            "priority": 1,
            "enabled": True,
        }])
        base = rules_banner + "\n\nBASE-HEAD\n" + ("🧱" * 150_000) + \
            "\nBASE-TAIL"
        notice = {
            "system_message": "Unicode lifecycle notice",
            "context": "NOTICE-MUST-BE-VISIBLE\n" + ("📣" * 50_000) +
                       "\nNOTICE-TAIL",
        }

        for runtime in ("codex", "kimi"):
            for event_name in ("UserPromptSubmit", "Stop"):
                with self.subTest(runtime=runtime, event=event_name), \
                     mock.patch.dict(os.environ, {
                         "ATTACCA_RUNTIME": runtime,
                     }, clear=False):
                    output = hook._event_context_output(
                        event_name, "base context", base)
                    output = hook._append_notice(output, notice)
                    if runtime == "kimi":
                        model_context = output["message"]
                    elif event_name == "Stop":
                        model_context = output["reason"]
                    else:
                        model_context = output[
                            "hookSpecificOutput"]["additionalContext"]
                    self.assertLessEqual(
                        len(model_context.encode("utf-8")), MAX_CONTEXT_BYTES)
                    self.assertTrue(
                        model_context.startswith(RULES_BANNER_PREFIX))
                    self.assertIn("CAP-RULE-MUST-SURVIVE", model_context)
                    self.assertIn("NOTICE-MUST-BE-VISIBLE", model_context)
                    if runtime == "kimi" and event_name == "Stop":
                        self.assertEqual(
                            output["hookSpecificOutput"]
                            ["permissionDecisionReason"], model_context)

    def test_rule_truncation_omission_and_cached_banner_remain_actionable(self):
        rules = [{
            "rule_id": "R-%03d" % index,
            "title": "Binding cached rule %03d" % index,
            "body": "RULE-%03d-BODY " % index + ("r" * 1_000),
            "scope": "everyone",
            "priority": index,
            "enabled": True,
        } for index in range(100)]
        banner = hook._mandatory_rules_banner(rules)
        self.assertLessEqual(
            len(banner.encode("utf-8")),
            hook.MANDATORY_RULES_BANNER_MAX_CHARACTERS)
        self.assertIn("[TRUNCATED — STOP and call rule_list before acting]",
                      banner)
        self.assertRegex(banner, r"\d+ additional binding rule\(s\)")
        self.assertIn("STOP before other work and call rule_list", banner)

        snapshot = self._snapshot("cached cloud", rules=rules)
        cached_poll = hook._poll_view(snapshot)
        omitted = cached_poll["project_rules_omitted_count"]
        self.assertGreater(omitted, 0)
        status = {
            "project_id": "shared",
            "root": "/workspace/shared",
            "state_path": "/unused/setup-prompts.json",
        }
        config = {"url": "http://attacca.test", "actor": "codex",
                  "owner": "jack"}
        notice = {
            "system_message": "cached watcher update",
            "context": "CACHED-NOTICE-MUST-SURVIVE",
        }
        for event_name in ("UserPromptSubmit", "Stop"):
            with self.subTest(cached_event=event_name), \
                 mock.patch.dict(os.environ, {
                     "ATTACCA_RUNTIME": "codex",
                     "PLUGIN_ROOT": str(ROOT),
                 }, clear=False), \
                 mock.patch.object(hook, "_plugin_and_config",
                                   return_value=(ROOT, config)), \
                 mock.patch.object(hook, "_ensure_background_watcher",
                                   return_value={
                                       "ok": True, "already_running": True}), \
                 mock.patch.object(hook, "_watcher_pending_notice",
                                   return_value=notice), \
                 mock.patch.object(hook, "_watcher_subscription_entry",
                                   return_value=("watch-key", {})), \
                 mock.patch.object(hook, "_terminal_migration_notice",
                                   return_value=None), \
                 mock.patch.object(hook, "_poll_entry", return_value=(
                     {"key": "actor"}, {"snapshot": cached_poll})):
                output = hook._periodic_output(
                    status, event_name, offline_adapter=object())
            context = output["reason"] if event_name == "Stop" else \
                output["hookSpecificOutput"]["additionalContext"]
            self.assertTrue(context.startswith(RULES_BANNER_PREFIX))
            self.assertIn(
                "%d additional binding rule(s)" % omitted, context)
            self.assertIn("STOP before other work and call rule_list", context)
            self.assertIn("CACHED-NOTICE-MUST-SURVIVE", context)


class WatcherNoLossDeliveryTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.environment = mock.patch.dict(os.environ, {
            "HOME": str(self.root / "home"),
            "ATTACCA_WATCHER_DIR": str(self.root / "watcher"),
            "ATTACCA_RUNTIME": "codex",
            "ATTACCA_DEVICE_ID": "delivery-test-device",
        }, clear=False)
        self.environment.start()
        self.status = {
            "status": "linked",
            "project_id": "shared",
            "root": str(self.checkout),
            "link_path": str(
                self.checkout / ".attacca" / "project.json"),
        }
        self.config = {
            "url": "http://attacca.test:4173",
            "actor": "codex",
            "owner": "jack",
        }

    def tearDown(self):
        self.environment.stop()
        self.tmp.cleanup()

    def state(self):
        return json.loads(hook._watcher_state_path().read_text())

    def test_unicode_room_bodies_survive_ten_by_two_notice_batches_fifo(self):
        self.assertEqual(hook.WATCHER_DELTA_CHUNK_SIZE, 10)
        self.assertEqual(hook.WATCHER_NOTICE_BATCH_SIZE, 2)
        key = hook._register_watcher_subscription(
            self.status, ROOT, self.config, runtime="codex", now=0)
        rows = [event(index, "WATCH-ROOM-%03d-🌍" % index)
                for index in range(1, 152)]

        with mock.patch.object(hook, "_settings_interval", return_value=60):
            baseline = hook._watcher_tick(
                key, now=0, force=True,
                delta_loader=lambda after: delta(next_after=after),
                notifier=lambda *_: None)
            queued = hook._watcher_tick(
                key, now=60, force=True,
                delta_loader=lambda after: delta(rows, next_after=151),
                notifier=lambda *_: None)

        self.assertTrue(baseline["cursor_initialized"])
        self.assertTrue(queued["queued"])
        self.assertEqual(queued["event_cursor"], 151)
        pending = self.state()["subscriptions"][key]["pending"]
        expected_chunks = (
            len(rows) + hook.WATCHER_DELTA_CHUNK_SIZE - 1
        ) // hook.WATCHER_DELTA_CHUNK_SIZE
        self.assertEqual(len(pending), expected_chunks)
        self.assertTrue(all(row["kind"] == "project_delta"
                            for row in pending))
        self.assertTrue(all(row["event_types"] == ["room.message"]
                            for row in pending))
        self.assertEqual([row["after"] for row in pending],
                         list(range(0, 151, 10)))
        self.assertEqual([row["through"] for row in pending],
                         list(range(10, 151, 10)) + [151])

        notices = []
        remaining_count = expected_chunks
        while remaining_count:
            notice = hook._watcher_pending_notice(self.status, self.config)
            notices.append(notice)
            delivered_count = min(
                hook.WATCHER_NOTICE_BATCH_SIZE, remaining_count)
            remaining_count -= delivered_count
            self.assertIn(
                "%d delivered, %d queued" % (
                    delivered_count, remaining_count),
                notice["system_message"])
            self.assertEqual(
                len(self.state()["subscriptions"][key]["pending"]),
                remaining_count)
        self.assertEqual(self.state()["subscriptions"][key]["pending"], [])
        self.assertIsNone(hook._watcher_pending_notice(
            self.status, self.config))

        all_context = "\n".join(notice["context"] for notice in notices)
        delivered = re.findall(
            r"WATCH-ROOM-(\d{3})",
            all_context)
        self.assertEqual(delivered,
                         ["%03d" % index for index in range(1, 152)])
        self.assertEqual(all_context.count("🌍"), len(rows))


if __name__ == "__main__":
    unittest.main()
