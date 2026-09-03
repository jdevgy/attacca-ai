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
        self.assertNotIn("TRUNCATED", banner)
        omitted_line = next(
            line for line in banner.splitlines()
            if line.startswith("• Omitted binding rule_ids:"))
        omitted_ids = {
            value.strip() for value in omitted_line.split(":", 1)[1].split(",")
        }
        rendered_ids = set(re.findall(r"^• \[(R-\d{3}) ·", banner,
                                       flags=re.MULTILINE))
        expected_ids = {"R-%03d" % index for index in range(100)}
        self.assertEqual(rendered_ids | omitted_ids, expected_ids)
        self.assertFalse(rendered_ids & omitted_ids)
        for rule_id in rendered_ids:
            index = int(rule_id.split("-")[1])
            self.assertIn(
                "RULE-%03d-BODY %s" % (index, "r" * 1_000), banner)
        self.assertIn(
            "STOP before other work and call rule_list for those exact "
            "rule_ids", banner)

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
            # Prompt turns carry the full rules banner + omission warning
            # (silent additionalContext). A Stop turn must not surface the
            # banner wall, but genuine cached coordination must still survive.
            if event_name == "Stop":
                self.assertFalse(context.startswith(RULES_BANNER_PREFIX))
            else:
                self.assertTrue(context.startswith(RULES_BANNER_PREFIX))
                self.assertIn("Omitted binding rule_ids:", context)
                for rule_id in (cached_poll["project_rules_omitted_ids"] or []):
                    self.assertIn(rule_id, context)
                self.assertIn(
                    "STOP before other work and call rule_list for those exact "
                    "rule_ids", context)
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

    def test_inbox_page_is_staged_before_ack_and_retries_failed_ack(self):
        key = hook._register_watcher_subscription(
            self.status, ROOT, self.config, runtime="codex", now=0)
        message = {
            "event_id": "mail-41", "seq": 41,
            "actor": "peer.director.claude", "msg_type": "directive",
            "body": "AUTOMATIC-MAIL-MUST-BE-SEEN",
            "mentions": ["shared.director.codex"],
            "directed_to_you": True, "addressed_to_you": True,
            "broadcast_to_everyone": False, "group_context": False,
            "origin_project": "peer",
        }
        peek = {"messages": [message], "read_cursor": 0,
                "may_have_more": False}

        with mock.patch.object(
                hook, "_watcher_inbox_page",
                side_effect=[peek, RuntimeError("ack offline")]):
            with self.assertRaisesRegex(RuntimeError, "ack offline"):
                hook._watcher_refresh_inbox_attention(
                    self.status, self.config)

        staged = self.state()["subscriptions"][key]["attention"]
        self.assertEqual(len(staged), 1)
        self.assertFalse(staged[0]["acknowledged"])
        first = hook._watcher_attention_notice(self.status, self.config)
        second = hook._watcher_attention_notice(self.status, self.config)
        self.assertIn("AUTOMATIC-MAIL-MUST-BE-SEEN", first["context"])
        # SHOW ONCE = READ (owner ruling / D-24): the second boundary keeps
        # the row pinned and counted, but repeats no body and no per-item
        # reminder line. The retired one-liner assertion is replaced by the
        # count line; the durable row itself is checked below.
        self.assertNotIn("AUTOMATIC-MAIL-MUST-BE-SEEN", second["context"])
        self.assertIn("UNREAD GROUP MAIL: 1 staged (0 new)",
                      second["context"])
        self.assertEqual(
            self.state()["subscriptions"][key]["attention"][0]["body"],
            "AUTOMATIC-MAIL-MUST-BE-SEEN")

        with mock.patch.object(
                hook, "_watcher_inbox_page",
                side_effect=[peek, dict(peek, read_cursor=41)]):
            refreshed = hook._watcher_refresh_inbox_attention(
                self.status, self.config)
        self.assertTrue(refreshed["ok"])
        acknowledged = self.state()["subscriptions"][key]["attention"]
        self.assertTrue(acknowledged[0]["acknowledged"])
        # It was already rendered while the hosted acknowledgement was
        # unavailable. Once that acknowledgement succeeds, both delivery and
        # hosted read are proven and the next boundary may remove it.
        self.assertIsNone(
            hook._watcher_attention_notice(self.status, self.config))

    def test_entity_revisions_coalesce_but_room_messages_never_do(self):
        key = hook._register_watcher_subscription(
            self.status, ROOT, self.config, runtime="codex", now=0)
        with mock.patch.object(hook, "_settings_interval", return_value=60):
            hook._watcher_tick(
                key, now=0, force=True,
                delta_loader=lambda after: delta(next_after=0),
                notifier=lambda *_: None)
            hook._watcher_tick(
                key, now=60, force=True,
                delta_loader=lambda after: delta([
                    event(1, "ROOM-ONE"),
                    {
                        "event_id": "rule-v3", "seq": 2,
                        "event_type": "rule.updated",
                        "actor_id": "shared.director.claude",
                        "operational_actor_id": "shared.director.claude",
                        "payload": {"rule_id": "R-X", "version": 3,
                                    "enabled": True, "title": "OLD-RULE"},
                    },
                    {
                        "event_id": "task-old", "seq": 3,
                        "event_type": "task.status_changed",
                        "actor_id": "shared.director.claude",
                        "operational_actor_id": "shared.director.claude",
                        "task_id": "T-X",
                        "payload": {"to": "claimed", "title": "OLD-TASK"},
                    },
                ], next_after=3), notifier=lambda *_: None)
            hook._watcher_tick(
                key, now=120, force=True,
                delta_loader=lambda after: delta([
                    event(4, "ROOM-TWO"),
                    {
                        "event_id": "rule-v5", "seq": 5,
                        "event_type": "rule.updated",
                        "actor_id": "shared.director.claude",
                        "operational_actor_id": "shared.director.claude",
                        "payload": {"rule_id": "R-X", "version": 5,
                                    "enabled": False, "title": "NEW-RULE"},
                    },
                    {
                        "event_id": "task-new", "seq": 6,
                        "event_type": "task.status_changed",
                        "actor_id": "shared.director.claude",
                        "operational_actor_id": "shared.director.claude",
                        "task_id": "T-X",
                        "payload": {"to": "done", "title": "NEW-TASK"},
                    },
                ], next_after=6), notifier=lambda *_: None)

        state = self.state()["subscriptions"][key]
        self.assertEqual([row["seq"] for row in state["attention"]], [1, 4])
        entities = {row["entity_key"]: row for row in state["pending"]
                    if row.get("kind") == "project_entity_delta"}
        self.assertEqual(set(entities), {"rule:R-X", "task:T-X"})
        self.assertIn("NEW-RULE", entities["rule:R-X"]["summary"])
        self.assertIn("CURRENTLY DISABLED", entities["rule:R-X"]["summary"])
        self.assertNotIn("OLD-RULE", entities["rule:R-X"]["summary"])
        self.assertIn("NEW-TASK", entities["task:T-X"]["summary"])
        self.assertNotIn("OLD-TASK", entities["task:T-X"]["summary"])

    def test_pending_disposition_survives_read_cursor_until_host_clears_it(self):
        key = hook._register_watcher_subscription(
            self.status, ROOT, self.config, runtime="codex", now=0)
        assignment = {
            "event_id": "assign-72", "seq": 72,
            "actor": "shared.director.claude", "msg_type": "directive",
            "body": "ASSIGNMENT-MUST-STAY-PINNED",
            "mentions": ["shared.director.codex"],
            "directed_to_you": True, "addressed_to_you": True,
            "broadcast_to_everyone": False, "group_context": False,
            "requires_disposition": True, "disposition": None,
        }
        current = {
            "messages": [], "read_cursor": 72, "may_have_more": False,
            "pending_dispositions": [assignment],
            "pending_disposition_total": 1,
            "pending_disposition_may_have_more": False,
        }
        with mock.patch.object(
                hook, "_watcher_inbox_page",
                side_effect=[current, current]):
            hook._watcher_refresh_inbox_attention(self.status, self.config)

        state = self.state()["subscriptions"][key]
        self.assertEqual(state["attention"], [])
        self.assertEqual(state["pending_disposition_total"], 1)
        # Render-once (T-82/T-84): the first boundary carries the full row.
        # Every later boundary keeps it pinned as ONE reminder line until
        # the host clears it; the old behaviour re-dumped the body each turn.
        first = hook._watcher_attention_notice(self.status, self.config)
        self.assertIn("PENDING DISPOSITIONS: 1 total (1 new)",
                      first["context"])
        self.assertIn("- [DISPOSITION REQUIRED] Event assign-72",
                      first["context"])
        self.assertIn("ASSIGNMENT-MUST-STAY-PINNED", first["context"])
        self.assertIn("message_dispose", first["context"])
        # The instruction must not tell an agent to disposition ordinary
        # EVERYONE/BRIDGE chat: the server accepts message_dispose only for
        # its requires_disposition rows, which render as DISPOSITION REQUIRED.
        self.assertIn("rows rendered as [DISPOSITION REQUIRED]",
                      first["context"])
        self.assertNotIn("disposition messages marked", first["context"])
        for _ in range(2):
            notice = hook._watcher_attention_notice(
                self.status, self.config)
            # SHOW ONCE = READ: no body, no per-item reminder line — one
            # count line is the whole remaining trace (retired assertion:
            # "- [PENDING · none] assign-72 …").
            self.assertIn(
                "PENDING DISPOSITIONS: 1 total (0 new)", notice["context"])
            self.assertNotIn("assign-72", notice["context"])
            self.assertNotIn("ASSIGNMENT-MUST-STAY-PINNED",
                             notice["context"])
            self.assertNotIn("DISPOSITION REQUIRED] Event",
                             notice["context"])
            self.assertIn("message_dispose", notice["context"])
            self.assertLess(len(notice["context"].encode("utf-8")), 400)
        self.assertIn("assign-72",
                      self.state()["subscriptions"][key]["rendered"])

        cleared = dict(
            current, pending_dispositions=[], pending_disposition_total=0)
        with mock.patch.object(
                hook, "_watcher_inbox_page",
                side_effect=[cleared, cleared]):
            hook._watcher_refresh_inbox_attention(self.status, self.config)
        self.assertIsNone(
            hook._watcher_attention_notice(self.status, self.config))

    def test_idle_daemon_tick_checks_inbox_without_a_client_turn(self):
        key = hook._register_watcher_subscription(
            self.status, ROOT, self.config, runtime="codex", now=0)
        with mock.patch.object(
                hook, "_settings_interval", return_value=60), \
             mock.patch.object(
                hook, "_watcher_refresh_inbox_entry",
                return_value={"ok": True, "staged": 1}) as refresh, \
             mock.patch.object(
                hook, "_watcher_event_delta",
                return_value=delta(next_after=0)):
            result = hook._watcher_tick(
                key, now=60, force=True,
                offline_factory=lambda *_: None,
                notifier=lambda *_: None)
        self.assertTrue(result["inbox_checked"])
        self.assertEqual(result["inbox_staged"], 1)
        refresh.assert_called_once()
        self.assertEqual(refresh.call_args.args[0], key)
        self.assertEqual(refresh.call_args.args[1]["client_instance"],
                         self.state()["subscriptions"][key][
                             "client_instance"])

    def test_only_proven_host_401_or_403_latches_auth(self):
        class HostedStatusError(RuntimeError):
            def __init__(self, status):
                super().__init__("host response")
                self.http_status = status

        class IdentitySchemaError(RuntimeError):
            pass

        self.assertTrue(hook._authentication_required_error(
            HostedStatusError(401)))
        self.assertTrue(hook._authentication_required_error(
            HostedStatusError(403)))
        self.assertFalse(hook._authentication_required_error(
            HostedStatusError(409)))
        self.assertFalse(hook._authentication_required_error(
            hook.HostedAuthenticationRequired("local key is missing")))
        self.assertFalse(hook._authentication_required_error(
            IdentitySchemaError("visibility changed")))

    def test_unread_mail_is_top_pinned_for_every_supported_turn_shape(self):
        rule = {
            "rule_id": "R-TOP", "title": "Rules remain first",
            "body": "RULE-BODY", "scope": "everyone", "priority": 1,
            "enabled": True,
        }
        cached_poll = {
            "project_rules": [rule], "project_rules_omitted_count": 0,
            "project_rules_omitted_ids": [],
        }
        for runtime in ("codex", "claude", "kimi"):
            for event_name in ("UserPromptSubmit", "Stop"):
                with self.subTest(runtime=runtime, event=event_name), \
                     mock.patch.dict(os.environ, {
                         "ATTACCA_RUNTIME": runtime,
                     }, clear=False):
                    key = hook._register_watcher_subscription(
                        self.status, ROOT, self.config, runtime=runtime, now=0)
                    hook._watcher_stage_attention(key, [{
                        "event_id": "top-%s-%s" % (runtime, event_name),
                        "seq": 100 + len(runtime) + len(event_name),
                        "actor": "peer.director.claude",
                        "msg_type": "directive",
                        "body": "TOP-MAIL-%s-%s" % (runtime, event_name),
                        "directed_to_you": True,
                        "addressed_to_you": True,
                        "broadcast_to_everyone": False,
                        "group_context": False,
                        "origin_project": "peer",
                    }], acknowledged=True)
                    with mock.patch.object(
                            hook, "_plugin_and_config",
                            return_value=(ROOT, self.config)), \
                         mock.patch.object(
                            hook, "_ensure_background_watcher",
                            return_value={"ok": True,
                                          "already_running": True}), \
                         mock.patch.object(
                            hook, "_watcher_refresh_inbox_attention",
                            return_value={"ok": True}), \
                         mock.patch.object(
                            hook, "_watcher_pending_notice",
                            return_value=None), \
                         mock.patch.object(
                            hook, "_terminal_migration_notice",
                            return_value=None), \
                         mock.patch.object(
                            hook, "_update_offer", return_value=None), \
                         mock.patch.object(
                            hook, "_settings_interval", return_value=60), \
                         mock.patch.object(
                            hook, "_poll_entry",
                            return_value=({"key": "actor"},
                                          {"snapshot": cached_poll,
                                           "last_poll_at": hook.time.time()})):
                        output = hook._periodic_output(
                            self.status, event_name,
                            offline_adapter=object())
                if runtime == "kimi":
                    context = output["message"]
                elif event_name == "Stop":
                    context = output["reason"]
                else:
                    context = output[
                        "hookSpecificOutput"]["additionalContext"]
                # The rules banner is pinned only on prompt turns (silent
                # additionalContext). A Stop turn must NOT surface the banner
                # wall in the client chat, but unread mail must still reach the
                # AI so it never goes idle on pending coordination (no-loss).
                if event_name == "Stop":
                    self.assertFalse(context.startswith(RULES_BANNER_PREFIX))
                else:
                    self.assertTrue(context.startswith(RULES_BANNER_PREFIX))
                    footer_at = context.index(
                        "==========================================================================")
                    mail_at = context.index(
                        "ATTACCA PENDING ASSIGNMENTS + UNREAD GROUP MAIL")
                    self.assertGreater(mail_at, footer_at)
                self.assertIn(
                    "TOP-MAIL-%s-%s" % (runtime, event_name), context)
                self.assertIn("no user needs to type", context)
                # message_dispose is accepted only for requires_disposition
                # rows. The brief must name that rendering, and must not tell
                # the agent to disposition EVERYONE/BRIDGE group chat.
                self.assertIn("rows rendered as [DISPOSITION REQUIRED]",
                              context)
                self.assertNotIn(
                    "disposition messages marked YOUR ATTENTION", context)

    def test_unicode_room_bodies_survive_attention_pages_fifo(self):
        self.assertEqual(hook.WATCHER_DELTA_CHUNK_SIZE, 10)
        self.assertEqual(hook.WATCHER_ATTENTION_PAGE_SIZE, 25)
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
        state = self.state()["subscriptions"][key]
        self.assertEqual(state["pending"], [])
        self.assertEqual(len(state["attention"]), len(rows))
        self.assertEqual([row["seq"] for row in state["attention"]],
                         list(range(1, 152)))

        # Persistent FIFO bodies are exact even when rendering later uses a
        # bounded head/tail view.
        long_body = "LONG-START-" + ("🌍" * 2_000) + "-LONG-END"
        hook._watcher_stage_attention(key, [{
            "event_id": "long-room", "seq": 152,
            "actor": "shared.director.claude", "msg_type": "chat",
            "body": long_body, "group_context": True,
        }])
        state = self.state()["subscriptions"][key]
        self.assertEqual(state["attention"][-1]["body"], long_body)
        # Keep this independent recovery row out of the 151-row drain below.
        def remove_long(value):
            value["subscriptions"][key]["attention"] = [
                row for row in value["subscriptions"][key]["attention"]
                if row.get("event_id") != "long-room"]

        hook._mutate_state(hook._watcher_state_path(), remove_long)

        # The raw event watcher never pretends delivery is a hosted read.
        # Simulate the automatic /inbox acknowledgement that follows durable
        # staging, then drain compact top-of-turn pages.
        hook._watcher_ack_attention_through(key, 151)

        notices = []
        remaining_count = len(rows)
        while remaining_count:
            notice = hook._watcher_attention_notice(self.status, self.config)
            notices.append(notice)
            delivered_count = min(
                hook.WATCHER_ATTENTION_PAGE_SIZE, remaining_count)
            remaining_count -= delivered_count
            self.assertIn(
                "%d unread shown, %d queued" % (
                    delivered_count, remaining_count),
                notice["system_message"])
        self.assertIsNone(hook._watcher_attention_notice(
            self.status, self.config))
        self.assertEqual(
            self.state()["subscriptions"][key]["attention"], [])

        all_context = "\n".join(notice["context"] for notice in notices)
        delivered = re.findall(
            r"WATCH-ROOM-(\d{3})",
            all_context)
        self.assertEqual(delivered,
                         ["%03d" % index for index in range(1, 152)])
        self.assertEqual(all_context.count("🌍"), len(rows))

    def _periodic_with_mocks(self, event_name, runtime="codex",
                             hook_payload=None):
        with mock.patch.dict(os.environ, {
                "ATTACCA_RUNTIME": runtime}, clear=False), \
             mock.patch.object(
                hook, "_plugin_and_config",
                return_value=(ROOT, self.config)), \
             mock.patch.object(
                hook, "_ensure_background_watcher",
                return_value={"ok": True, "already_running": True}), \
             mock.patch.object(
                hook, "_watcher_refresh_inbox_attention",
                side_effect=RuntimeError("HTTP 401 inbox rejected")), \
             mock.patch.object(
                hook, "_terminal_migration_notice", return_value=None), \
             mock.patch.object(hook, "_update_offer", return_value={
                 "system_message": "new release",
                 "context": "UPDATE-NOTICE-HIDDEN-WHILE-401"}), \
             mock.patch.object(hook, "_settings_interval", return_value=60), \
             mock.patch.object(hook, "_mcp_snapshot") as snapshot, \
             mock.patch.object(
                hook, "_poll_entry",
                return_value=({"key": "actor"},
                              {"snapshot": {},
                               "last_poll_at": hook.time.time()})):
            output = hook._periodic_output(
                self.status, event_name, offline_adapter=object(),
                hook_payload=hook_payload)
        snapshot.assert_not_called()
        return output

    def test_auth_latch_gates_prompt_and_stop_without_dropping_fifo(self):
        key = hook._register_watcher_subscription(
            self.status, ROOT, self.config, runtime="codex", now=0)
        hook._watcher_stage_attention(key, [{
            "event_id": "gate-mail-9", "seq": 9,
            "actor": "peer.director.claude", "msg_type": "directive",
            "body": "MAIL-BODY-HIDDEN-WHILE-401",
            "directed_to_you": True, "addressed_to_you": True,
            "broadcast_to_everyone": False, "group_context": False,
            "origin_project": "peer",
        }])
        pinned = {
            "messages": [], "read_cursor": 9, "may_have_more": False,
            "pending_dispositions": [{
                "event_id": "gate-assign-8", "seq": 8,
                "actor": "shared.director.claude", "msg_type": "directive",
                "body": "ASSIGNMENT-BODY-HIDDEN-WHILE-401",
                "directed_to_you": True, "addressed_to_you": True,
                "broadcast_to_everyone": False, "group_context": False,
                "requires_disposition": True, "disposition": None,
            }],
            "pending_disposition_total": 1,
            "pending_disposition_may_have_more": False,
        }
        with mock.patch.object(
                hook, "_watcher_inbox_page", side_effect=[pinned, pinned]):
            hook._watcher_refresh_inbox_attention(self.status, self.config)

        def queue_delta(state):
            state["subscriptions"][key]["pending"].append({
                "fingerprint": "delta-1", "kind": "project_entity_delta",
                "entity_key": "task:T-9",
                "summary": "QUEUED-DELTA-MUST-SURVIVE-THE-GATE",
                "created_at": "2026-09-02T00:00:00+00:00",
            })
        hook._mutate_state(hook._watcher_state_path(), queue_delta)
        hook._watcher_queue_auth_required(
            key, self.state()["subscriptions"][key],
            hook.HostedAuthenticationRequired(
                "revoked client-install key", http_status=401), 0)

        hidden = (
            "DISPOSITION REQUIRED", "PENDING DISPOSITIONS",
            "ASSIGNMENT-BODY-HIDDEN-WHILE-401", "MAIL-BODY-HIDDEN-WHILE-401",
            "QUEUED-DELTA-MUST-SURVIVE-THE-GATE", "INBOX CHECK FAILED",
            "UPDATE-NOTICE-HIDDEN-WHILE-401", "SESSION LOOP",
            "BACKGROUND WATCHER")
        prompt = self._periodic_with_mocks("UserPromptSubmit")
        context = prompt["hookSpecificOutput"]["additionalContext"]
        self.assertIn("ATTACCA AUTHENTICATION REQUIRED", context)
        self.assertIn("/app", context)
        for marker in hidden:
            self.assertNotIn(marker, json.dumps(prompt))
        # Stop blocks with the login text once per session, then stays quiet.
        first_stop = self._periodic_with_mocks("Stop")
        self.assertIsNone(first_stop)  # the prompt already surfaced it
        def forget_surfaced(state):
            state["subscriptions"][key].pop("auth_login_surfaced_at", None)
        hook._mutate_state(hook._watcher_state_path(), forget_surfaced)
        blocked = self._periodic_with_mocks("Stop")
        self.assertEqual(blocked["decision"], "block")
        self.assertIn("ATTACCA AUTHENTICATION REQUIRED", blocked["reason"])
        for marker in hidden:
            self.assertNotIn(marker, json.dumps(blocked))
        self.assertIsNone(self._periodic_with_mocks("Stop"))
        # No-loss: the gate withheld rendering only. The FIFO delta, the
        # staged mail row, and the pinned disposition all survive unrendered.
        entry = self.state()["subscriptions"][key]
        self.assertIn("QUEUED-DELTA-MUST-SURVIVE-THE-GATE",
                      json.dumps(entry["pending"]))
        self.assertEqual([row["event_id"] for row in entry["attention"]],
                         ["gate-mail-9"])
        self.assertNotIn("delivered_at", entry["attention"][0])
        self.assertEqual(entry["pending_disposition_total"], 1)
        self.assertNotIn("rendered", entry)

    def test_stop_is_quiet_once_pinned_rows_were_delivered(self):
        key = hook._register_watcher_subscription(
            self.status, ROOT, self.config, runtime="codex", now=0)
        hook._watcher_stage_attention(key, [{
            "event_id": "quiet-mail-3", "seq": 3,
            "actor": "peer.director.claude", "msg_type": "chat",
            "body": "QUIET-MAIL-BODY " + ("filler " * 60),
            "directed_to_you": True, "addressed_to_you": True,
            "broadcast_to_everyone": False, "group_context": False,
        }])
        with mock.patch.object(
                hook, "_plugin_and_config",
                return_value=(ROOT, self.config)), \
             mock.patch.object(
                hook, "_ensure_background_watcher",
                return_value={"ok": True, "already_running": True}), \
             mock.patch.object(
                hook, "_watcher_refresh_inbox_attention",
                return_value={"ok": True}), \
             mock.patch.object(
                hook, "_terminal_migration_notice", return_value=None), \
             mock.patch.object(hook, "_update_offer", return_value=None), \
             mock.patch.object(hook, "_settings_interval", return_value=60), \
             mock.patch.object(
                hook, "_poll_entry",
                return_value=({"key": "actor"},
                              {"snapshot": {},
                               "last_poll_at": hook.time.time()})):
            first_stop = hook._periodic_output(
                self.status, "Stop", offline_adapter=object())
            second_stop = hook._periodic_output(
                self.status, "Stop", offline_adapter=object())
            prompt = hook._periodic_output(
                self.status, "UserPromptSubmit", offline_adapter=object())
        self.assertEqual(first_stop["decision"], "block")
        self.assertIn("QUIET-MAIL-BODY filler filler", first_stop["reason"])
        self.assertIsNone(second_stop)
        context = prompt["hookSpecificOutput"]["additionalContext"]
        # SHOW ONCE = READ: the delivered row leaves one count line and no
        # per-item excerpt at all (retired assertion: the
        # "- [PENDING · none] quiet-mail-3 …" reminder).
        self.assertIn("UNREAD GROUP MAIL: 1 staged (0 new)", context)
        self.assertNotIn("quiet-mail-3", context)
        self.assertNotIn("QUIET-MAIL-BODY", context)
        self.assertNotIn("filler " * 2, context)
        self.assertLess(len(context.encode("utf-8")), 400)


if __name__ == "__main__":
    unittest.main()
