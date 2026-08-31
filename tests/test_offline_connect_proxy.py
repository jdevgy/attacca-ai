"""Black-box stdio QA for the connect proxy's verified offline fallback.

Every hosted server in this module binds an ephemeral loopback port and every
mirror, watcher state file, credential, checkout, and database lives below a
TemporaryDirectory.  The live development server is never discovered or used.
"""

import hashlib
import importlib.util
import json
import os
import select
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import offline_sync as offline  # noqa: E402
import sync_client  # noqa: E402
from attacca.tests.test_sync_http import (  # noqa: E402
    SyncHttpFixture,
    attacca,
    protocol,
)


SCRIPT = str(ROOT / "attacca.py")
HOOK_SPEC = importlib.util.spec_from_file_location(
    "attacca_offline_proxy_sequence_hook", ROOT / "hooks" / "session_start.py")
hook = importlib.util.module_from_spec(HOOK_SPEC)
HOOK_SPEC.loader.exec_module(hook)


class OfflineConnectProxyBlackBoxTests(unittest.TestCase):
    """Exercise the real ``attacca.py connect`` subprocess over JSON-RPC."""

    def setUp(self):
        self.fx = SyncHttpFixture()
        self.processes = []
        self.watcher = Path(self.fx.temp.name) / "watcher"
        self.watcher.mkdir(mode=0o700)
        self.home = Path(self.fx.temp.name) / "proxy-home"
        self.home.mkdir()
        self.checkout = self._checkout("primary")
        self.task_id = self._install_project_sentinels()
        status, self.snapshot, _ = self.fx.request(
            "GET", "/v1/projects/proj/sync/snapshot",
            token=self.fx.director_token, device="device_primary")
        self.assertEqual(status, 200)
        protocol.validate_snapshot(self.snapshot)
        self.primary = self._seed_subscription(
            self.checkout, "device_primary", self.snapshot)

    def tearDown(self):
        for process in list(self.processes):
            self._stop_process(process, check=False)
        self.fx.close()

    def _checkout(self, name):
        checkout = Path(self.fx.temp.name) / ("checkout-" + name)
        checkout.mkdir()
        attacca.write_project_link(checkout, "proj")
        return checkout

    def _install_project_sentinels(self):
        conn = attacca.connect(self.fx.db)
        try:
            attacca.set_current_owner("owner1")
            task = attacca.task_create(
                conn, "proj", "web.owner1", "human",
                "Cached sentinel task",
                description="Searchable task detail from the verified mirror")
            attacca.task_plan_set(
                conn, "proj", task["task_id"], "web.owner1", "human",
                "Cached sentinel plan", "Plan overview from the mirror",
                [{"section_id": "build", "title": "Build",
                  "body": "Cached plan section body"}])
            attacca.decision_propose(
                conn, "proj", "web.owner1", "human",
                "Cached sentinel decision",
                detail="Preserve the offline identity boundary")
            attacca.update_handoff(
                conn, "proj", "proj.director.codex", "agent",
                {"objective": "Cached sentinel handoff objective"})
            attacca.room_send(
                conn, "proj", "web.owner1", "human",
                "Cached addressed inbox sentinel",
                mentions=["proj.director.codex"])
            return task["task_id"]
        finally:
            conn.close()

    @staticmethod
    def _subscription_key(base, checkout, device, actor="codex"):
        material = json.dumps([
            offline.normalize_server_url(base), "proj", "codex", actor,
            device, str(Path(checkout).resolve()),
        ], separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    @staticmethod
    def _client_id(entry):
        material = json.dumps([
            entry["key"], entry["runtime"], entry["actor"],
            entry["device_id"],
        ], separators=(",", ":"), ensure_ascii=False)
        return "watcher_" + hashlib.sha256(
            material.encode("utf-8")).hexdigest()[:32]

    @property
    def _state_path(self):
        return self.watcher / "watcher-state.json"

    def _read_watcher_state(self, watcher=None):
        state_path = Path(watcher or self.watcher) / "watcher-state.json"
        try:
            return json.loads(state_path.read_text())
        except FileNotFoundError:
            return {}

    def _write_watcher_state(self, state, watcher=None):
        watcher = Path(watcher or self.watcher)
        watcher.mkdir(parents=True, exist_ok=True, mode=0o700)
        state_path = watcher / "watcher-state.json"
        temporary = state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, sort_keys=True) + "\n")
        temporary.chmod(0o600)
        os.replace(str(temporary), str(state_path))
        state_path.chmod(0o600)

    def _seed_subscription(self, checkout, device, snapshot, actor="codex",
                           install_mirror=True, watcher=None):
        watcher = Path(watcher or self.watcher)
        key = self._subscription_key(
            self.fx.base, checkout, device, actor=actor)
        entry = {
            "key": key,
            "server_url": offline.normalize_server_url(self.fx.base),
            "project_id": "proj",
            "runtime": "codex",
            "actor": actor,
            "owner": "owner1",
            "device_id": device,
            "root": str(Path(checkout).resolve()),
            "link_path": str(
                Path(checkout).resolve() / ".attacca" / "project.json"),
            "plugin_root": str(ROOT.resolve()),
            "offline_directory": str(watcher / "offline"),
            "canonical_actor_id": "proj.director.codex",
            "actor_role": "director",
            "sync_schema_version": 1,
            "sync_scope": snapshot["scope"],
            "sync_visibility_fingerprint": snapshot[
                "visibility_fingerprint"],
            "pending": [],
            "next_poll_at_epoch": 0,
        }
        state = self._read_watcher_state(watcher)
        state.setdefault("subscriptions", {})[key] = entry
        self._write_watcher_state(state, watcher)
        engine = offline.OfflineProjectSync(
            watcher / "offline", self.fx.base, snapshot["scope"],
            self._client_id(entry), device,
            visibility_fingerprint=snapshot["visibility_fingerprint"])
        if install_mirror:
            engine.install_snapshot(snapshot)
        return {"key": key, "entry": entry, "engine": engine,
                "checkout": Path(checkout), "device": device}

    def _environment(self, client=None, token=None, url=None):
        client = client or self.primary
        environment = dict(os.environ)
        environment.update({
            "HOME": str(self.home),
            "ATTACCA_URL": url or self.fx.base,
            "ATTACCA_ACTOR": client["entry"]["actor"],
            "ATTACCA_ACTOR_TYPE": "agent",
            "ATTACCA_OWNER": "owner1",
            "ATTACCA_DEVICE_ID": client["device"],
            "ATTACCA_WATCHER_DIR": str(client.get("watcher", self.watcher)),
            "ATTACCA_AUTOSTART": "0",
        })
        if token is False:
            environment.pop("ATTACCA_API_TOKEN", None)
        else:
            environment["ATTACCA_API_TOKEN"] = (
                self.fx.director_token if token is None else token)
        environment.pop("CLAUDE_PROJECT_DIR", None)
        environment.pop("ATTACCA_PROJECT", None)
        return environment

    def _start_proxy(self, client=None, token=None, url=None):
        client = client or self.primary
        process = subprocess.Popen(
            [sys.executable, SCRIPT, "connect"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
            cwd=str(client["checkout"]),
            env=self._environment(client, token=token, url=url), bufsize=1)
        self.processes.append(process)
        return process

    def _rpc(self, process, method, params=None, request_id=1, timeout=10):
        request = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            request["params"] = params
        process.stdin.write(json.dumps(request) + "\n")
        process.stdin.flush()
        readable, _, _ = select.select([process.stdout], [], [], timeout)
        if not readable:
            stderr = process.stderr.read() if process.poll() is not None else ""
            self.fail("proxy produced no JSON-RPC reply within %ss: %s" %
                      (timeout, stderr))
        line = process.stdout.readline()
        self.assertTrue(line, "proxy closed stdout before replying")
        response = json.loads(line)
        self.assertEqual(response.get("jsonrpc"), "2.0")
        self.assertEqual(response.get("id"), request_id)
        return response

    def _initialize(self, process, request_id=1):
        return self._rpc(process, "initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "offline-proxy-black-box",
                           "version": "1"},
        }, request_id=request_id)

    def _tool(self, process, name, arguments=None, request_id=10,
              expect_error=False):
        response = self._rpc(process, "tools/call", {
            "name": name, "arguments": arguments or {},
        }, request_id=request_id)
        self.assertIn("result", response, response)
        result = response["result"]
        self.assertEqual(bool(result.get("isError")), bool(expect_error), result)
        text = result["content"][0]["text"]
        if expect_error:
            self.assertIn("error", text.lower())
            return text
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            self.fail("offline tool result was not JSON: %r" % text)

    def _assert_offline_authority_refused(self, process, label):
        # MCP framing may initialize without project authority. The first
        # operation that needs the mirror must fail closed and never claim the
        # verified read source.
        initialized = self._initialize(process)
        self.assertIn("result", initialized, label)
        ping = self._rpc(process, "ping", {}, request_id=8)
        self.assertIn("error", ping, label)
        self.assertNotIn(
            "verified_local_mirror", self._serialized(ping), label)
        error = self._tool(
            process, "attacca_status", request_id=9, expect_error=True)
        self.assertNotIn("verified_local_mirror", error, label)
        return error

    def _stop_process(self, process, check=True):
        if process not in self.processes:
            return
        try:
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            code = process.wait(timeout=10)
            if check:
                self.assertEqual(code, 0, process.stderr.read())
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
            if check:
                self.fail("connect proxy did not exit after stdin EOF")
        finally:
            for stream in (process.stdout, process.stderr):
                if stream and not stream.closed:
                    stream.close()
            self.processes.remove(process)

    def _stop_hosted_server(self):
        if not self.fx.running:
            return
        self.fx.server.shutdown()
        self.fx.thread.join(timeout=10)
        self.assertFalse(self.fx.thread.is_alive())
        self.fx.server.server_close()
        self.fx.running = False

    def _restart_hosted_server(self):
        self.assertFalse(self.fx.running)
        port = int(self.fx.base.rsplit(":", 1)[1])
        self.fx.server = attacca.AttaccaServer(
            ("127.0.0.1", port), self.fx.db)
        self.fx.thread = threading.Thread(
            target=self.fx.server.serve_forever, daemon=True)
        self.fx.thread.start()
        self.fx.running = True
        deadline = time.time() + 5
        while time.time() < deadline:
            if self.fx.thread.is_alive():
                return
            time.sleep(0.01)
        self.fail("ephemeral Attacca server did not restart")

    def _sync_client(self, client):
        return sync_client.AuthenticatedSyncHttpClient(
            self.fx.base, "proj", self.snapshot["scope"],
            self.snapshot["visibility_fingerprint"],
            self._client_id(client["entry"]), client["device"],
            lambda: self.fx.director_token, timeout_seconds=2)

    def _clear_auth_latch_with_verified_watcher_sync(self):
        with mock.patch.dict(os.environ, {
                "ATTACCA_WATCHER_DIR": str(self.watcher),
                "ATTACCA_DEVICE_ID": self.primary["device"],
                "ATTACCA_RUNTIME": "codex",
        }, clear=False), mock.patch.object(
                hook, "_settings_interval", return_value=60):
            result = hook._watcher_tick(
                self.primary["key"], now=time.time(), force=True,
                offline_adapter=self.primary["engine"],
                remote_adapter=self._sync_client(self.primary),
                delta_loader=lambda after: {
                    "events": [], "next_after": after,
                    "may_have_more": False,
                },
                notifier=lambda *_: None)
        self.assertTrue(result.get("ok"), result)
        entry = self._read_watcher_state()["subscriptions"][
            self.primary["key"]]
        self.assertNotIn("auth_required", entry)
        self.assertNotIn("auth_required_at", entry)
        self.assertNotIn(
            "authentication_required",
            {item.get("kind") for item in entry.get("pending") or []})
        return result

    def _assert_latched_outage_blocks_cache_and_outbox(self):
        before = self.primary["engine"].pending_mutations()
        process = self._start_proxy()
        self.assertIn("result", self._initialize(process))
        status_error = self._tool(
            process, "attacca_status", request_id=70, expect_error=True)
        write_error = self._tool(
            process, "room_send", {"body": "must remain blocked by latch"},
            request_id=71, expect_error=True)
        self._stop_process(process)
        for error in (status_error, write_error):
            lowered = error.lower()
            self.assertRegex(
                lowered,
                r"(authentication|credential|revoked|expired|"
                r"terminal_enrollment_required|client_authorization_required)")
            self.assertIn("cached mirror", lowered)
            self.assertIn("blocked", lowered)
            self.assertIn("/app", lowered)
            self.assertNotIn("setup --interactive", lowered)
            self.assertNotIn("paste-token", lowered)
            self.assertNotIn("verified_local_mirror", lowered)
            self.assertNotIn("continue work", lowered)
        self.assertEqual(self.primary["engine"].pending_mutations(), before)

    def _assert_post_reauthentication_offline_continuity(self):
        self._stop_hosted_server()
        process = self._start_proxy()
        self.assertIn("result", self._initialize(process))
        status = self._tool(
            process, "attacca_status", request_id=80)
        queued = self._tool(
            process, "room_send", {
                "body": "post-reauthentication offline sentinel",
            }, request_id=81)
        self._stop_process(process)
        self.assertIn("verified_local_mirror", self._serialized(status))
        self.assertTrue(queued.get("pending_sync"), queued)
        self.assertEqual(
            [item["client_mutation_id"] for item in
             self.primary["engine"].pending_mutations()],
            [queued["client_mutation_id"]])

    @staticmethod
    def _serialized(value):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)

    def test_stdio_contract_and_all_verified_cached_read_families(self):
        self._stop_hosted_server()
        process = self._start_proxy()
        initialized = self._initialize(process)
        self.assertIn("result", initialized, initialized)
        self.assertIn("attacca", self._serialized(initialized).lower())
        ping = self._rpc(process, "ping", {}, request_id=2)
        self.assertEqual(ping.get("result"), {})
        listed = self._rpc(process, "tools/list", {}, request_id=3)
        names = {item["name"] for item in listed["result"]["tools"]}
        for name in (
                "attacca_status", "get_handoff", "check_inbox",
                "room_read", "search", "get_project_log", "task_list",
                "task_show", "task_plan_get", "rule_list", "decision_list",
                "agent_list", "bridge_list", "list_projects",
                "check_freshness"):
            self.assertIn(name, names)

        calls = [
            ("attacca_status", {}, "verified_local_mirror"),
            ("get_handoff", {}, "Cached sentinel handoff objective"),
            ("rule_list", {}, "Always log"),
            ("task_list", {}, "Cached sentinel task"),
            ("task_show", {"task_id": self.task_id},
             "Searchable task detail"),
            ("task_plan_get", {"task_id": self.task_id},
             "Cached plan section body"),
            ("decision_list", {}, "Cached sentinel decision"),
            ("room_read", {}, "Cached addressed inbox sentinel"),
            ("check_inbox", {}, "Cached addressed inbox sentinel"),
            ("search", {"query": "cached sentinel task"},
             "Cached sentinel task"),
            ("get_project_log", {}, "Cached sentinel task"),
            ("agent_list", {}, "proj.director.codex"),
            ("bridge_list", {}, "peer"),
            ("list_projects", {}, '"scope_limited": true'),
            ("check_freshness", {}, "offline"),
        ]
        for index, (name, arguments, sentinel) in enumerate(calls, start=10):
            body = self._tool(
                process, name, arguments, request_id=index)
            serialized = self._serialized(body)
            self.assertIn(sentinel, serialized, name)
            self.assertIn("verified_local_mirror", serialized, name)
            self.assertIn('"offline": true', serialized.lower(), name)
        self._stop_process(process)

    def test_offline_room_and_inbox_pagination_attention_and_handoff_parity(
            self):
        target = "proj.director.codex"
        other_target = "proj.worker.cline"
        bodies = {
            "anchor": "Offline reply anchor from this reader",
            "everyone": "Offline everyone broadcast",
            "mention": "Offline direct mention",
            "reply": "Offline reply to this reader",
            "other": "Offline group context for another reader",
        }
        conn = attacca.connect(self.fx.db)
        try:
            attacca.set_current_owner("owner1")
            anchor = attacca.room_send(
                conn, "proj", target, "agent", bodies["anchor"])
            attacca.room_send(
                conn, "proj", "web.owner1", "human", bodies["everyone"])
            attacca.room_send(
                conn, "proj", "web.owner1", "human", bodies["mention"],
                mentions=[target])
            attacca.room_send(
                conn, "proj", "web.owner1", "human", bodies["reply"],
                reply_to=anchor["event"]["event_id"])
            attacca.room_send(
                conn, "proj", "web.owner1", "human", bodies["other"],
                mentions=[other_target])
        finally:
            conn.close()

        status, snapshot, _ = self.fx.request(
            "GET", "/v1/projects/proj/sync/snapshot",
            token=self.fx.director_token, device="device_primary")
        self.assertEqual(status, 200)
        protocol.validate_snapshot(snapshot)
        self.snapshot = snapshot
        self.primary["engine"].install_snapshot(snapshot)
        cached_room = sorted(
            snapshot["projection"]["room_messages"],
            key=lambda item: item["seq"])
        expected_room_ids = [item["event_id"] for item in cached_room]

        self._stop_hosted_server()
        process = self._start_proxy()
        self.assertIn("result", self._initialize(process))

        latest = self._tool(
            process, "room_read", {"limit": 2}, request_id=100)
        self.assertEqual(
            [item["event_id"] for item in latest["messages"]],
            expected_room_ids[-2:])
        self.assertTrue(latest["older_messages_available"])
        self.assertFalse(latest["may_have_more"])
        self.assertEqual(
            latest["next_since_seq"], snapshot["cursor"]["event_seq"])
        self.assertIn("since_seq=0", latest["hint"])

        chronological = []
        since_seq = 0
        for page_number in range(1, len(cached_room) + 2):
            page = self._tool(
                process, "room_read",
                {"since_seq": since_seq, "limit": 2},
                request_id=100 + page_number)
            page_messages = page["messages"]
            page_sequences = [item["seq"] for item in page_messages]
            self.assertEqual(page_sequences, sorted(page_sequences))
            self.assertTrue(all(seq > since_seq for seq in page_sequences))
            self.assertFalse(page["older_messages_available"])
            chronological.extend(page_messages)
            self.assertEqual(
                page["next_since_seq"],
                page_sequences[-1] if page_sequences else since_seq)
            since_seq = page["next_since_seq"]
            if not page["may_have_more"]:
                break
        else:
            self.fail("offline room pagination did not converge")

        self.assertEqual(
            [item["event_id"] for item in chronological],
            expected_room_ids)
        self.assertEqual(
            len(expected_room_ids), len(set(expected_room_ids)))
        attention_fields = (
            "mentioned_to_you", "reply_to_you", "directed_to_you",
            "broadcast_to_everyone", "addressed_to_you", "group_context",
        )
        for message in chronological:
            for field in attention_fields:
                self.assertIsInstance(message[field], bool, (field, message))
        by_body = {item["body"]: item for item in chronological}
        self.assertEqual(
            {field: by_body[bodies["everyone"]][field]
             for field in attention_fields},
            {
                "mentioned_to_you": False,
                "reply_to_you": False,
                "directed_to_you": False,
                "broadcast_to_everyone": True,
                "addressed_to_you": True,
                "group_context": False,
            })
        self.assertEqual(
            {field: by_body[bodies["mention"]][field]
             for field in attention_fields},
            {
                "mentioned_to_you": True,
                "reply_to_you": False,
                "directed_to_you": True,
                "broadcast_to_everyone": False,
                "addressed_to_you": True,
                "group_context": False,
            })
        self.assertEqual(
            {field: by_body[bodies["reply"]][field]
             for field in attention_fields},
            {
                "mentioned_to_you": False,
                "reply_to_you": True,
                "directed_to_you": True,
                "broadcast_to_everyone": False,
                "addressed_to_you": True,
                "group_context": False,
            })
        self.assertEqual(
            {field: by_body[bodies["other"]][field]
             for field in attention_fields},
            {
                "mentioned_to_you": False,
                "reply_to_you": False,
                "directed_to_you": False,
                "broadcast_to_everyone": False,
                "addressed_to_you": False,
                "group_context": True,
            })

        hosted_cursor = int(
            snapshot["projection"]["inbox_cursor"]["last_read_seq"])
        expected_inbox_ids = [
            item["event_id"] for item in cached_room
            if item["seq"] > hosted_cursor and item["actor"] != target
        ]
        first_peek = self._tool(
            process, "check_inbox", {"mark_read": False, "limit": 2},
            request_id=200)
        repeated_peek = self._tool(
            process, "check_inbox", {"mark_read": False, "limit": 2},
            request_id=201)
        self.assertEqual(first_peek["messages"], repeated_peek["messages"])
        self.assertEqual(first_peek["read_cursor"], hosted_cursor)
        self.assertEqual(repeated_peek["read_cursor"], hosted_cursor)
        self.assertEqual(
            [item["event_id"] for item in first_peek["messages"]],
            expected_inbox_ids[:2])

        full_peek = self._tool(
            process, "check_inbox", {"mark_read": False, "limit": 500},
            request_id=202)
        handoff = self._tool(
            process, "get_handoff", request_id=203)
        inbox_summary = handoff["your_inbox"]
        self.assertEqual(
            inbox_summary["unread_total"], full_peek["unread_total"])
        self.assertEqual(
            inbox_summary["unread_addressed_to_you"],
            full_peek["unread_addressed"])
        self.assertEqual(
            inbox_summary["unread_everyone"],
            full_peek["unread_everyone"])
        self.assertEqual(
            inbox_summary["unread_group_context"],
            full_peek["unread_group_context"])
        self.assertEqual(
            inbox_summary["may_have_more"], full_peek["may_have_more"])
        self.assertTrue(inbox_summary["messages_include_all_visible"])
        after_handoff_peek = self._tool(
            process, "check_inbox", {"mark_read": False, "limit": 2},
            request_id=204)
        self.assertEqual(
            after_handoff_peek["messages"], first_peek["messages"])
        self.assertEqual(after_handoff_peek["read_cursor"], hosted_cursor)

        consumed = []
        read_cursors = []
        for page_number in range(1, len(expected_inbox_ids) + 2):
            page = self._tool(
                process, "check_inbox",
                {"mark_read": True, "limit": 2},
                request_id=204 + page_number)
            consumed.extend(page["messages"])
            read_cursors.append(page["read_cursor"])
            self.assertEqual(page["hosted_read_cursor"], hosted_cursor)
            if not page["may_have_more"]:
                break
        else:
            self.fail("offline inbox pagination did not converge")
        consumed_ids = [item["event_id"] for item in consumed]
        self.assertEqual(consumed_ids, expected_inbox_ids)
        self.assertEqual(len(consumed_ids), len(set(consumed_ids)))
        self.assertEqual(read_cursors, sorted(set(read_cursors)))
        for message in consumed:
            for field in attention_fields:
                self.assertIsInstance(message[field], bool, (field, message))

        drained = self._tool(
            process, "check_inbox", {"mark_read": True, "limit": 2},
            request_id=300)
        drained_peek = self._tool(
            process, "check_inbox", {"mark_read": False, "limit": 2},
            request_id=301)
        self.assertEqual(drained["messages"], [])
        self.assertFalse(drained["may_have_more"])
        self.assertEqual(drained_peek["messages"], [])
        self.assertEqual(drained_peek["read_cursor"], drained["read_cursor"])
        self._stop_process(process)

    def test_allowlisted_mutations_queue_and_unsupported_tools_fail_closed(self):
        self._stop_hosted_server()
        process = self._start_proxy()
        self.assertIn("result", self._initialize(process))
        initial_pending = self.primary["engine"].status()["pending_count"]
        queued_room = self._tool(
            process, "room_send", {"body": "queued proxy room sentinel"},
            request_id=20)
        queued_task = self._tool(
            process, "task_create", {"title": "Queued proxy task"},
            request_id=21)
        queued_plan = self._tool(
            process, "task_plan_set", {
                "task_id": self.task_id,
                "title": "Queued plan revision",
                "overview": "Queued while the hosted service is offline",
                "sections": [{
                    "section_id": "qa", "title": "QA",
                    "body": "Run the black-box proxy suite",
                }],
                "expected_version": 1,
            }, request_id=22)
        for body in (queued_room, queued_task, queued_plan):
            serialized = self._serialized(body).lower()
            self.assertIn('"offline": true', serialized)
            self.assertIn('"pending_sync": true', serialized)
            self.assertTrue(body.get("client_mutation_id"), body)

        mutation_ids = {
            queued_room["client_mutation_id"],
            queued_task["client_mutation_id"],
            queued_plan["client_mutation_id"],
        }
        read_matrix = [
            ("get_project_log", {}),
            ("room_read", {}),
            ("task_list", {}),
            ("task_plan_get", {"task_id": self.task_id}),
            ("decision_list", {}),
            ("rule_list", {}),
            ("get_handoff", {}),
        ]
        local_only_values = (
            "queued proxy room sentinel", "Queued proxy task",
            "Queued plan revision",
            "Queued while the hosted service is offline",
        )
        for index, (name, arguments) in enumerate(read_matrix, start=23):
            body = self._tool(
                process, name, arguments, request_id=index)
            overlays = body.get("pending_mutations")
            self.assertIsInstance(overlays, list, name)
            self.assertEqual(
                {item.get("client_mutation_id") for item in overlays},
                mutation_ids, name)
            for item in overlays:
                self.assertTrue(item.get("local_only"), (name, item))
                self.assertTrue(item.get("pending_sync"), (name, item))
                self.assertIn("not yet accepted", item.get("hint", ""))
            canonical = dict(body)
            canonical.pop("pending_mutations", None)
            canonical_text = self._serialized(canonical)
            for local_value in local_only_values:
                self.assertNotIn(local_value, canonical_text, name)

        for index, tool in enumerate(
                ("bridge_add", "agent_register", "set_lead_director",
                 "bridge_remove"), start=40):
            error = self._tool(
                process, tool, {}, request_id=index, expect_error=True)
            self.assertIn("offline", error.lower())
            self.assertIn("unavailable", error.lower())
        cross_project = self._tool(
            process, "room_send",
            {"body": "must not queue", "project": "peer"},
            request_id=40, expect_error=True)
        self.assertRegex(
            cross_project.lower(), r"(cross workspace|workspace bound|project)")
        self._stop_process(process)

        engine = offline.OfflineProjectSync(
            self.watcher / "offline", self.fx.base,
            self.snapshot["scope"], self._client_id(self.primary["entry"]),
            self.primary["device"], visibility_fingerprint=self.snapshot[
                "visibility_fingerprint"])
        pending = engine.pending_mutations()
        self.assertEqual(len(pending), initial_pending + 3)
        queued_by_id = {
            item["client_mutation_id"]: item for item in pending
            if item["client_mutation_id"] in {
                queued_room["client_mutation_id"],
                queued_task["client_mutation_id"],
                queued_plan["client_mutation_id"],
            }
        }
        self.assertEqual(len(queued_by_id), 3)
        self.assertEqual(
            queued_by_id[queued_room["client_mutation_id"]]["payload"]["body"],
            "queued proxy room sentinel")
        self.assertEqual(
            queued_by_id[queued_task["client_mutation_id"]]["payload"]["title"],
            "Queued proxy task")
        self.assertEqual(
            queued_by_id[queued_plan["client_mutation_id"]]["payload"]
            ["sections"][0]["section_id"], "qa")
        self.assertNotIn("must not queue", self._serialized(pending))

    def test_no_mirror_forged_scope_and_stale_checkout_are_refused(self):
        self._stop_hosted_server()

        no_mirror_checkout = self._checkout("no-mirror")
        no_mirror_watcher = Path(self.fx.temp.name) / "watcher-no-mirror"
        no_mirror = self._seed_subscription(
            no_mirror_checkout, "device_no_mirror", self.snapshot,
            install_mirror=False, watcher=no_mirror_watcher)
        no_mirror["watcher"] = no_mirror_watcher
        process = self._start_proxy(no_mirror)
        refused = self._assert_offline_authority_refused(
            process, "no mirror")
        self.assertIn("mirror", refused.lower())
        self._stop_process(process)

        forged_checkout = self._checkout("forged")
        forged = self._seed_subscription(
            forged_checkout, "device_forged", self.snapshot)
        state = self._read_watcher_state()
        state["subscriptions"][forged["key"]]["sync_scope"] = dict(
            self.snapshot["scope"], actor_id="proj.worker.cline",
            role="worker")
        self._write_watcher_state(state)
        process = self._start_proxy(forged)
        refused = self._assert_offline_authority_refused(
            process, "forged scope")
        self.assertRegex(refused.lower(), r"(scope|identity|mirror)")
        self._stop_process(process)

        stale_checkout = self._checkout("stale-root")
        stale = self._seed_subscription(
            stale_checkout, "device_stale", self.snapshot)
        state = self._read_watcher_state()
        state["subscriptions"][stale["key"]]["root"] = str(
            Path(self.fx.temp.name) / "another-checkout")
        self._write_watcher_state(state)
        process = self._start_proxy(stale)
        self._assert_offline_authority_refused(process, "stale root")
        self._stop_process(process)

        for label, altered in (
                ("device", {"device": "device_wrong"}),
                ("identity", {"entry_actor": "claude"})):
            client = dict(self.primary)
            client["entry"] = dict(self.primary["entry"])
            if "device" in altered:
                client["device"] = altered["device"]
            if "entry_actor" in altered:
                client["entry"]["actor"] = altered["entry_actor"]
            process = self._start_proxy(client)
            self._assert_offline_authority_refused(process, label)
            self._stop_process(process)

        wrong_project = Path(self.fx.temp.name) / "checkout-wrong-project"
        wrong_project.mkdir()
        attacca.write_project_link(wrong_project, "peer")
        client = dict(self.primary, checkout=wrong_project)
        process = self._start_proxy(client)
        self._assert_offline_authority_refused(process, "wrong project")
        self._stop_process(process)

    def test_http_auth_failure_never_downgrades_to_offline_cache(self):
        # A token with the modern device-credential prefix must always fail
        # closed.  Bare unknown strings remain migration-compatible legacy
        # actor tokens until the owner explicitly activates authentication.
        process = self._start_proxy(token="atd_invalid-token")
        denied = self._initialize(process)
        self.assertIn("error", denied)
        error_data = denied["error"].get("data") or {}
        self.assertEqual(error_data.get("http_status"), 401)
        self.assertEqual(
            error_data.get("category"), "authentication_required")
        serialized = self._serialized(denied).lower()
        self.assertRegex(serialized, r"(invalid|auth|token|login)")
        self.assertNotIn("verified_local_mirror", serialized)
        self._stop_process(process)

        entry = self._read_watcher_state()["subscriptions"][
            self.primary["key"]]
        self.assertTrue(entry.get("auth_required"), entry)
        self.assertEqual(entry.get("offline_mode"), "auth_required")
        self.assertEqual(
            {item.get("kind") for item in entry.get("pending") or []},
            {"authentication_required"})

        self._stop_hosted_server()
        self._assert_latched_outage_blocks_cache_and_outbox()

        self._restart_hosted_server()
        self._clear_auth_latch_with_verified_watcher_sync()
        self._assert_post_reauthentication_offline_continuity()

    def test_http_403_latch_survives_outage_until_verified_reauthentication(self):
        self._stop_hosted_server()

        class ForbiddenHandler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                request = json.loads(self.rfile.read(length))
                body = json.dumps({
                    "jsonrpc": "2.0", "id": request.get("id"),
                    "error": {
                        "code": -32000,
                        "message": "forbidden project-bound AI scope",
                        "data": {
                            "http_status": 403,
                            "category": "authentication_required",
                        },
                    },
                }).encode("utf-8")
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        port = int(self.fx.base.rsplit(":", 1)[1])
        server = ThreadingHTTPServer(("127.0.0.1", port), ForbiddenHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            process = self._start_proxy()
            denied = self._initialize(process)
            self.assertIn("error", denied)
            data = denied["error"].get("data") or {}
            self.assertEqual(data.get("http_status"), 403)
            self.assertEqual(data.get("category"), "authentication_required")
            self._stop_process(process)
        finally:
            server.shutdown()
            thread.join(timeout=10)
            server.server_close()

        entry = self._read_watcher_state()["subscriptions"][
            self.primary["key"]]
        self.assertTrue(entry.get("auth_required"), entry)
        self.assertIn("HTTP 403", entry.get("last_error", ""))
        self._assert_latched_outage_blocks_cache_and_outbox()

        self._restart_hosted_server()
        self._clear_auth_latch_with_verified_watcher_sync()
        self._assert_post_reauthentication_offline_continuity()

    def test_accepted_then_stalled_write_is_ambiguous_and_never_queued(self):
        self._stop_hosted_server()
        accepted = threading.Event()
        release = threading.Event()

        class StalledMutationHandler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                request = json.loads(self.rfile.read(length))
                if request.get("method") == "initialize":
                    body = json.dumps({
                        "jsonrpc": "2.0", "id": request.get("id"),
                        "result": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "stalled", "version": "1"},
                        },
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                accepted.set()
                # The hosted endpoint has received the complete mutation but
                # withholds its receipt.  A client timeout is therefore an
                # ambiguous outcome, never proof that replay is safe.
                release.wait(timeout=5)
                self.close_connection = True

        port = int(self.fx.base.rsplit(":", 1)[1])
        server = ThreadingHTTPServer(
            ("127.0.0.1", port), StalledMutationHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        process = None
        try:
            environment = self._environment()
            environment["ATTACCA_CONNECT_TIMEOUT_SECONDS"] = "0.1"
            process = subprocess.Popen(
                [sys.executable, SCRIPT, "connect"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
                cwd=str(self.primary["checkout"]), env=environment, bufsize=1)
            self.processes.append(process)
            self.assertIn("result", self._initialize(process))
            started = time.monotonic()
            error = self._tool(
                process, "room_send", {"body": "ambiguous timeout sentinel"},
                request_id=2, expect_error=True)
            elapsed = time.monotonic() - started
            self.assertTrue(accepted.is_set(), "server never accepted mutation")
            self.assertLess(elapsed, 1.5, error)
            self.assertIn("ambiguous", error.lower())
            self.assertIn("not queued", error.lower())
            self._stop_process(process)
            process = None
            self.assertEqual(self.primary["engine"].pending_mutations(), [])
        finally:
            release.set()
            if process is not None and process in self.processes:
                self._stop_process(process, check=False)
            server.shutdown()
            thread.join(timeout=10)
            server.server_close()

    def test_bearer_credentials_are_isolated_by_complete_server_base_path(self):
        observed = []

        class CaptureHandler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                request = json.loads(self.rfile.read(length))
                observed.append({
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                })
                body = json.dumps({
                    "jsonrpc": "2.0", "id": request.get("id"),
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "capture", "version": "1"},
                    },
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = "http://127.0.0.1:%d" % server.server_address[1]
        credentials = self.home / ".attacca" / "credentials.json"
        credentials.parent.mkdir(parents=True, exist_ok=True)

        def write_credentials(servers):
            credentials.write_text(json.dumps({
                "version": 1, "servers": servers,
            }) + "\n")
            credentials.chmod(0o600)

        try:
            write_credentials({
                origin + "/tenant-a": {
                    "agent_tokens": {"proj": {
                        "proj.director.codex": {
                            "token": "tenant-a-secret", "runtime": "codex",
                        },
                    }},
                },
                # A linked project must never use this unbound legacy token.
                origin + "/tenant-b": {
                    "tokens": {"codex": "legacy-runtime-secret"},
                },
            })
            project_client = dict(self.primary)
            project_client["entry"] = dict(
                self.primary["entry"], actor="proj.director.codex")
            process = self._start_proxy(
                project_client, token=False, url=origin + "/tenant-b")
            self.assertIn("result", self._initialize(process))
            self._stop_process(process)
            self.assertEqual(observed[-1]["path"], "/tenant-b/mcp")
            self.assertIsNone(observed[-1]["authorization"])

            write_credentials({
                origin + "/tenant-a": {
                    "agent_tokens": {"proj": {
                        "proj.director.codex": {
                            "token": "tenant-a-secret", "runtime": "codex",
                        },
                    }},
                },
                origin + "/tenant-b": {
                    "tokens": {"codex": "legacy-runtime-secret"},
                    "agent_tokens": {
                        "proj": {"proj.director.codex": {
                            "token": "tenant-b-secret", "runtime": "codex",
                        }},
                        "peer": {"peer.director.codex": {
                            "token": "peer-secret", "runtime": "codex",
                        }},
                    },
                },
            })
            process = self._start_proxy(
                project_client, token=False, url=origin + "/tenant-b")
            self.assertIn("result", self._initialize(process))
            self._stop_process(process)
            self.assertEqual(
                observed[-1]["authorization"], "Bearer tenant-b-secret")

            peer_checkout = self._checkout("credential-peer")
            attacca.write_project_link(peer_checkout, "peer")
            peer_client = dict(
                self.primary, checkout=peer_checkout,
                entry=dict(self.primary["entry"],
                           actor="peer.director.codex"))
            process = self._start_proxy(
                peer_client, token=False, url=origin + "/tenant-b")
            self.assertIn("result", self._initialize(process))
            self._stop_process(process)
            self.assertEqual(
                observed[-1]["authorization"], "Bearer peer-secret")
            serialized = self._serialized(observed)
            self.assertNotIn("tenant-a-secret", serialized)
            self.assertNotIn("legacy-runtime-secret", serialized)
        finally:
            server.shutdown()
            thread.join(timeout=10)
            server.server_close()

    def test_process_restart_preserves_one_mutation_and_replays_exactly_once(self):
        self._stop_hosted_server()
        first = self._start_proxy()
        self.assertIn("result", self._initialize(first))
        queued = self._tool(
            first, "room_send", {"body": "restart replay sentinel"},
            request_id=2)
        mutation_id = queued["client_mutation_id"]
        self._stop_process(first)

        second = self._start_proxy()
        self.assertIn("result", self._initialize(second))
        found = self._tool(
            second, "search", {"query": "restart replay sentinel"},
            request_id=3)
        self.assertIn(mutation_id, self._serialized(found))
        self._stop_process(second)

        engine = offline.OfflineProjectSync(
            self.watcher / "offline", self.fx.base,
            self.snapshot["scope"], self._client_id(self.primary["entry"]),
            self.primary["device"], visibility_fingerprint=self.snapshot[
                "visibility_fingerprint"])
        self.assertEqual(
            [item["client_mutation_id"] for item in engine.pending_mutations()],
            [mutation_id])
        self._restart_hosted_server()
        first_sync = engine.synchronize(self._sync_client(self.primary))
        second_sync = engine.synchronize(self._sync_client(self.primary))
        self.assertIn(mutation_id, first_sync["applied"])
        self.assertIn(mutation_id, first_sync["converged"])
        self.assertEqual(second_sync["applied"], [])
        self.assertEqual(engine.status()["pending_count"], 0)
        conn = attacca.connect(self.fx.db)
        try:
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE project_id='proj'"
                " AND event_type='room.message' AND payload LIKE ?",
                ("%restart replay sentinel%",)).fetchone()["n"]
            self.assertEqual(count, 1)
        finally:
            conn.close()

    def test_two_proxy_devices_keep_outboxes_isolated_then_converge(self):
        office_checkout = self._checkout("office")
        office = self._seed_subscription(
            office_checkout, "device_office", self.snapshot)
        self._stop_hosted_server()
        home_process = self._start_proxy(self.primary)
        office_process = self._start_proxy(office)
        self.assertIn("result", self._initialize(home_process, request_id=1))
        self.assertIn("result", self._initialize(office_process, request_id=1))
        home = self._tool(
            home_process, "room_send", {"body": "home proxy sentinel"},
            request_id=2)
        work = self._tool(
            office_process, "room_send", {"body": "office proxy sentinel"},
            request_id=2)
        self._stop_process(home_process)
        self._stop_process(office_process)

        home_engine = offline.OfflineProjectSync(
            self.watcher / "offline", self.fx.base,
            self.snapshot["scope"], self._client_id(self.primary["entry"]),
            self.primary["device"], visibility_fingerprint=self.snapshot[
                "visibility_fingerprint"])
        office_engine = offline.OfflineProjectSync(
            self.watcher / "offline", self.fx.base,
            self.snapshot["scope"], self._client_id(office["entry"]),
            office["device"], visibility_fingerprint=self.snapshot[
                "visibility_fingerprint"])
        self.assertNotEqual(home_engine.outbox_directory,
                            office_engine.outbox_directory)
        self.assertEqual(
            [item["client_mutation_id"] for item in
             home_engine.pending_mutations()], [home["client_mutation_id"]])
        self.assertEqual(
            [item["client_mutation_id"] for item in
             office_engine.pending_mutations()], [work["client_mutation_id"]])

        self._restart_hosted_server()
        for engine, client in (
                (home_engine, self.primary), (office_engine, office)):
            report = engine.synchronize(self._sync_client(client))
            self.assertEqual(report["status"], "online")
            self.assertEqual(engine.status()["pending_count"], 0)
        # A second pull gives both device mirrors the complete shared view.
        home_engine.synchronize(self._sync_client(self.primary))
        office_engine.synchronize(self._sync_client(office))
        for engine in (home_engine, office_engine):
            bodies = [item["body"] for item in
                      engine.local_projection()["room_messages"]]
            self.assertIn("home proxy sentinel", bodies)
            self.assertIn("office proxy sentinel", bodies)

        conn = attacca.connect(self.fx.db)
        try:
            rows = conn.execute(
                "SELECT * FROM events WHERE project_id='proj'"
                " AND event_type='room.message'"
                " AND (payload LIKE ? OR payload LIKE ?) ORDER BY seq",
                ("%home proxy sentinel%", "%office proxy sentinel%"),
            ).fetchall()
            self.assertEqual(len(rows), 2)
            home_device = (
                "device_primary/" + self._client_id(self.primary["entry"]))
            office_device = (
                "device_office/" + self._client_id(office["entry"]))
            self.assertEqual(
                {row["device_id"] for row in rows},
                {home_device, office_device})
            for row in rows:
                self.assertEqual(row["actor_id"], "proj.director.codex")
                self.assertEqual(row["owner"], "owner1")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
