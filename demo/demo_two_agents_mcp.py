#!/usr/bin/env python3
"""Two AI tools talking through the attacca layer — over real MCP.

Spawns two independent MCP server processes (exactly what Claude Code and
Codex do when they start a stdio MCP server) with different actor identities,
and drives a coordination conversation between them:

  MCP Demo · Director · Claude: creates a task and posts a directive
  MCP Demo · Worker · Codex: reads it, claims the task, reports with evidence
  MCP Demo · Director · Claude: sees the report, accepts the task, and updates
                                the handoff for the next worker

Everything flows through the shared SQLite ledger; the two processes never
talk to each other directly.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = str(HERE.parent / "attacca.py")

# Owner is separate attribution and deliberately blank in this demo.
os.environ["ATTACCA_OWNER"] = ""


class Tool:
    """A minimal MCP client, standing in for one AI coding tool."""

    def __init__(self, name, actor, db):
        env = dict(os.environ, ATTACCA_DB=db, ATTACCA_PROJECT="mcpdemo",
                   ATTACCA_ACTOR=actor)
        self.name = name
        self.proc = subprocess.Popen(
            [sys.executable, SCRIPT, "mcp"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        self.mid = 0
        self._rpc("initialize", {"protocolVersion": "2025-06-18",
                                 "capabilities": {},
                                 "clientInfo": {"name": name, "version": "1"}})
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.proc.stdin.flush()

    def _rpc(self, method, params):
        self.mid += 1
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": self.mid, "method": method,
             "params": params}) + "\n")
        self.proc.stdin.flush()
        resp = json.loads(self.proc.stdout.readline())
        assert "error" not in resp, resp
        return resp["result"]

    def call(self, tool, **arguments):
        result = self._rpc("tools/call", {"name": tool, "arguments": arguments})
        text = result["content"][0]["text"]
        if result.get("isError"):
            raise RuntimeError("%s failed in %s: %s" % (tool, self.name, text))
        return json.loads(text)

    def say(self, message):
        print("  [%s] %s" % (self.name, message))

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def main():
    tmp = tempfile.TemporaryDirectory()
    db = str(Path(tmp.name) / "attacca.db")
    subprocess.run([sys.executable, SCRIPT, "--db", db, "init",
                    "--project-id", "mcpdemo", "--name", "MCP Demo",
                    tmp.name], check=True, capture_output=True)

    print("== spawning two MCP server processes (one per 'tool') ==")
    claude = Tool("claude-code", "claude_director", db)
    codex = Tool("codex-cli", "codex_director", db)

    print("\n== MCP Demo · Director · Claude: brief + delegate work ==")
    handoff = claude.call("get_handoff")
    claude.say("briefed at context v%d" % handoff["context_version"])
    claude.call("agent_register", role="director", runtime="claude-code")
    task = claude.call("task_create", title="Add rate limiting to /token",
                       expected_scope=["src/api/token.ts"], risk_level="high")
    tid = task["task_id"]
    claude.call("room_send", msg_type="directive", task_id=tid,
                mentions=["mcpdemo.worker.codex"],
                body="Please take %s. Use a sliding window, 10 req/min per IP." % tid)
    cursor = claude.call("room_read")["next_since_seq"]
    claude.say("created %s and posted a directive; waiting for a reply" % tid)

    print("\n== MCP Demo · Worker · Codex: cold start in another tool ==")
    codex.call("agent_register", role="worker", runtime="codex-cli")
    briefing = codex.call("get_handoff")
    codex.say("briefed at context v%d, sees open tasks: %s"
              % (briefing["context_version"],
                 [(t["task_id"], t["title"]) for t in briefing["open_tasks"]]))
    room = codex.call("room_read")
    directive = [m for m in room["messages"] if m["msg_type"] == "directive"][-1]
    codex.say("read directive from %s: %r" % (directive["actor"], directive["body"]))
    claim = codex.call("task_claim", task_id=tid,
                       expected_scope=["src/api/token.ts"])
    codex.say("claimed %s (lease until %s)" % (tid, claim["lease_until"][:19]))
    codex.call("room_send", msg_type="claim", task_id=tid,
               body="Taking %s, will use sliding window as directed." % tid)
    codex.call("task_report", task_id=tid, requested_state="review",
               summary="Sliding-window limiter added, 10 req/min per IP.",
               evidence=[{"kind": "test", "name": "api:ratelimit", "result": "pass"}])
    codex.call("room_send", msg_type="handoff", task_id=tid,
               body="%s ready for review; limiter behind RATE_LIMIT flag." % tid)
    codex.say("reported %s -> review with test evidence" % tid)

    print("\n== MCP Demo · Director · Claude: receives the reply by polling ==")
    new_msgs = claude.call("room_read", since_seq=cursor)["messages"]
    for msg in new_msgs:
        claude.say("new message from %s (%s): %s"
                   % (msg["actor"], msg["msg_type"], msg["body"]))
    assert any(m["actor"] == "mcpdemo.worker.codex" for m in new_msgs), \
        "the Claude Director did not receive the Codex Worker's messages"
    board = claude.call("task_list", status="review")
    assert board["tasks"][0]["task_id"] == tid
    claude.call("task_set_status", task_id=tid, status="done",
                reason="review passed: evidence includes api:ratelimit pass")
    latest = claude.call("get_handoff")
    claude.call("update_handoff",
                expected_context_version=latest["context_version"],
                what_changed="Rate limiting added to /token (%s, by codex)" % tid,
                next_actions="Monitor limiter in staging; tune window if needed.")
    claude.say("accepted %s and updated the handoff" % tid)

    print("\n== the shared ledger both tools produced ==")
    log = claude.call("get_project_log", limit=30)
    for line in log["log"]:
        print("   " + line)

    verify = subprocess.run(
        [sys.executable, SCRIPT, "--db", db, "--project", "mcpdemo",
         "--json", "event", "verify"],
        capture_output=True, text=True, check=True)
    assert json.loads(verify.stdout)["ok"], verify.stdout

    claude.close()
    codex.close()
    tmp.cleanup()
    print("\nOK: two separate MCP sessions coordinated entirely through the "
          "shared attacca layer.")


if __name__ == "__main__":
    main()
