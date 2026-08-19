#!/usr/bin/env python3
"""
continuity.py — Local Project Continuity Layer (blueprint Phase 0 dogfood build).

One zero-dependency file (Python 3.8+, stdlib only) implementing the
"Project Continuity Layer" from the Multi-Agent Developer SaaS blueprint:

  * Append-only event ledger (SQLite, per-project sequence, hash-chained)
  * Project Room (structured messages: chat/directive/claim/handoff/...)
  * Tasks, work claims with leases, scope-overlap warnings, evidence reports
  * Decision records
  * Current handoff snapshot + context versioning (Drift Guard lite)
  * Agent identity registry
  * MCP stdio server so Claude Code / Codex / GLM / any MCP client share state
  * CLI for humans and non-MCP tools

No encryption in this build (deliberately deferred). No daemon: every tool
spawns its own MCP server process; SQLite in WAL mode is the coordination
point, so concurrent sessions across tools are safe.

Usage:
  continuity.py init [--project-id ID] [--name NAME] [PATH]
  continuity.py mcp                     # run MCP stdio server
  continuity.py status | log | handoff | room | task | decision | agent ...
  continuity.py setup [--write-mcp-json]   # per-tool config snippets
  continuity.py install-instructions       # managed CLAUDE.md/AGENTS.md block
Run `continuity.py --help` for everything.
"""

import argparse
import fnmatch
import hashlib
import io
import json
import os
import random
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import zipfile
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = "0.1.0"
MCP_SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18")
MCP_DEFAULT_PROTOCOL = "2025-06-18"

ENV_DB = "CONTINUITY_DB"
ENV_PROJECT = "CONTINUITY_PROJECT"
ENV_ACTOR = "CONTINUITY_ACTOR"
ENV_ACTOR_TYPE = "CONTINUITY_ACTOR_TYPE"

DEFAULT_DB = Path(os.environ.get(ENV_DB) or (Path.home() / ".continuity" / "continuity.db"))

GENESIS_HASH = "0" * 64

MSG_TYPES = ["chat", "directive", "claim", "handoff", "challenge",
             "decision", "approval", "status", "system"]
TASK_STATUSES = ["queued", "claimed", "blocked", "review", "done", "cancelled"]
RISK_LEVELS = ["low", "medium", "high"]
DECISION_RESOLUTIONS = ["accepted", "rejected", "superseded"]
HANDOFF_FIELDS = ["objective", "what_changed", "active_work", "blockers",
                  "risks", "next_actions", "notes"]

# Room chat/status noise is excluded from the curated project log.
LOG_EXCLUDED_MSG_TYPES = {"chat", "status"}

MANAGED_BEGIN = "<!-- MANAGED_CONTINUITY:BEGIN"
MANAGED_END = "<!-- MANAGED_CONTINUITY:END -->"


class ContinuityError(Exception):
    """User-facing error (bad input, unknown project, conflict...)."""


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

def now_dt():
    return datetime.now(timezone.utc)


def now_iso():
    return now_dt().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def iso_in(minutes):
    return (now_dt() + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_id(prefix):
    """Sortable-ish unique id: <prefix>_<ms hex><random>."""
    return "%s_%011x%s" % (prefix, int(time.time() * 1000), secrets.token_hex(4))


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def slugify(text):
    out = []
    for ch in text.lower():
        if ch.isalnum():
            out.append(ch)
        elif out and out[-1] != "-":
            out.append("-")
    slug = "".join(out).strip("-")
    return slug or "project"


ENV_OWNER = "CONTINUITY_OWNER"
IDENTITY_FILE = Path.home() / ".continuity" / "identity.json"


def load_owner():
    """Who is running this machine's tools — for attribution. Env overrides
    the identity file; an empty env value disables owner-prefixing."""
    env = os.environ.get(ENV_OWNER)
    if env is not None:
        return env.strip() or None
    try:
        data = json.loads(IDENTITY_FILE.read_text())
        return (data.get("owner") or "").strip() or None
    except Exception:
        return None


def save_owner(name):
    IDENTITY_FILE.parent.mkdir(parents=True, exist_ok=True)
    IDENTITY_FILE.write_text(json.dumps({"owner": str(name).strip()}, indent=2)
                             + "\n")
    return str(IDENTITY_FILE)


# Attribution context: entry layers (CLI, MCP dispatch, HTTP routes) declare
# who owns the acting client; append_event stamps it on every ledger row.
_owner_ctx = threading.local()


def set_current_owner(owner):
    _owner_ctx.value = (owner or "").strip() or None


def current_owner():
    return getattr(_owner_ctx, "value", None)


def qualify_actor(actor, owner=None):
    """Prefix an actor id with the machine owner's name so every log line
    reads owner.agent (who did what), and the same role used by two
    different people can never collide: jack.claude_director vs
    mia.claude_director."""
    owner = owner if owner is not None else load_owner()
    if not actor or not owner:
        return actor
    slug = slugify(owner)
    if actor == slug or actor.startswith(slug + "."):
        return actor
    return "%s.%s" % (slug, actor)


def git_head(root_path):
    """Short HEAD revision of the repo at root_path, or None."""
    if not root_path:
        return None
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root_path, capture_output=True, text=True, timeout=5)
        rev = proc.stdout.strip()
        return rev if proc.returncode == 0 and rev else None
    except Exception:
        return None


def git_branch(root_path):
    if not root_path:
        return None
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root_path, capture_output=True, text=True, timeout=5)
        br = proc.stdout.strip()
        return br if proc.returncode == 0 and br else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
  project_id      TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  root_path       TEXT,
  created_by      TEXT,
  created_at      TEXT NOT NULL,
  context_version INTEGER NOT NULL DEFAULT 1,
  lead_director   TEXT
);
CREATE TABLE IF NOT EXISTS bridges (
  project_a  TEXT NOT NULL,
  project_b  TEXT NOT NULL,
  relation   TEXT NOT NULL DEFAULT 'peer',
  principal  TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY (project_a, project_b)
);
CREATE TABLE IF NOT EXISTS inbox_cursors (
  project_id    TEXT NOT NULL,
  actor_id      TEXT NOT NULL,
  last_read_seq INTEGER NOT NULL DEFAULT 0,
  updated_at    TEXT,
  PRIMARY KEY (project_id, actor_id)
);
CREATE TABLE IF NOT EXISTS events (
  event_id        TEXT PRIMARY KEY,
  project_id      TEXT NOT NULL,
  seq             INTEGER NOT NULL,
  actor_id        TEXT NOT NULL,
  actor_type      TEXT NOT NULL,
  owner           TEXT,
  event_type      TEXT NOT NULL,
  payload         TEXT NOT NULL,
  payload_hash    TEXT NOT NULL,
  prev_hash       TEXT NOT NULL,
  hash            TEXT NOT NULL,
  context_version INTEGER,
  base_revision   TEXT,
  task_id         TEXT,
  created_at      TEXT NOT NULL,
  UNIQUE (project_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_events_proj_seq  ON events (project_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_proj_type ON events (project_id, event_type, seq);
CREATE TABLE IF NOT EXISTS tasks (
  project_id     TEXT NOT NULL,
  task_id        TEXT NOT NULL,
  title          TEXT NOT NULL,
  description    TEXT,
  status         TEXT NOT NULL DEFAULT 'queued',
  risk_level     TEXT NOT NULL DEFAULT 'medium',
  claimed_by     TEXT,
  lease_until    TEXT,
  base_revision  TEXT,
  expected_scope TEXT NOT NULL DEFAULT '[]',
  dependencies   TEXT NOT NULL DEFAULT '[]',
  last_report    TEXT,
  created_by     TEXT,
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL,
  PRIMARY KEY (project_id, task_id)
);
CREATE TABLE IF NOT EXISTS handoffs (
  project_id TEXT NOT NULL,
  version    INTEGER NOT NULL,
  content    TEXT NOT NULL,
  updated_by TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (project_id, version)
);
CREATE TABLE IF NOT EXISTS decisions (
  project_id  TEXT NOT NULL,
  decision_id TEXT NOT NULL,
  title       TEXT NOT NULL,
  detail      TEXT,
  rationale   TEXT,
  status      TEXT NOT NULL DEFAULT 'proposed',
  proposed_by TEXT,
  resolved_by TEXT,
  created_at  TEXT NOT NULL,
  resolved_at TEXT,
  PRIMARY KEY (project_id, decision_id)
);
CREATE TABLE IF NOT EXISTS agents (
  project_id    TEXT NOT NULL,
  agent_id      TEXT NOT NULL,
  display_name  TEXT,
  role          TEXT,
  runtime       TEXT,
  owner         TEXT,
  actor_type    TEXT NOT NULL DEFAULT 'agent',
  registered_at TEXT,
  last_seen_at  TEXT,
  PRIMARY KEY (project_id, agent_id)
);
"""


def connect(db_path):
    db_path = Path(db_path)
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: an HTTP MCP session's connection outlives
        # the request thread that created it. Safe because every shared use is
        # serialized (per-session lock in the HTTP server; stdio/CLI are
        # single-threaded; REST handlers use per-thread connections).
        conn = sqlite3.connect(str(db_path), isolation_level=None, timeout=10,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=8000")
        conn.execute("PRAGMA synchronous=NORMAL")
        # Schema is idempotent (IF NOT EXISTS) so concurrent first-open is safe.
        conn.executescript(SCHEMA)
        # Migrations for databases created before newer columns existed.
        for table, column in (("projects", "lead_director"),
                              ("events", "owner"), ("agents", "owner"),
                              ("bridges", "relation"), ("bridges", "principal")):
            cols = {r["name"] for r in
                    conn.execute("PRAGMA table_info(%s)" % table)}
            if column not in cols:
                try:
                    conn.execute("ALTER TABLE %s ADD COLUMN %s TEXT"
                                 % (table, column))
                except sqlite3.OperationalError:
                    pass  # another process migrated concurrently
    except (sqlite3.Error, OSError) as err:
        raise ContinuityError("cannot open database at %s: %s" % (db_path, err))
    return conn


def _require_str_list(name, value):
    """Validate an optional array-of-strings argument (MCP clients can send
    anything). Returns None for None, a list of str otherwise."""
    if value is None:
        return None
    if isinstance(value, str):
        raise ContinuityError(
            "%s must be an array of strings, not a string (got %r)" % (name, value))
    try:
        items = list(value)
    except TypeError:
        raise ContinuityError("%s must be an array of strings" % name)
    if not all(isinstance(item, str) for item in items):
        raise ContinuityError("%s must contain only strings" % name)
    return items


def _normalize_evidence(evidence):
    if evidence is None:
        return []
    if isinstance(evidence, dict):
        evidence = [evidence]
    if not isinstance(evidence, list) \
            or not all(isinstance(item, dict) for item in evidence):
        raise ContinuityError(
            'evidence must be an array of objects, e.g. '
            '[{"kind":"test","name":"pytest","result":"pass"}]')
    return evidence


class write_tx:
    """BEGIN IMMEDIATE ... COMMIT with retry/backoff on lock contention."""

    def __init__(self, conn, attempts=20):
        self.conn = conn
        self.attempts = attempts

    def __enter__(self):
        last_err = None
        for i in range(self.attempts):
            try:
                self.conn.execute("BEGIN IMMEDIATE")
                return self
            except sqlite3.OperationalError as err:
                msg = str(err).lower()
                if "locked" in msg or "busy" in msg:
                    last_err = err
                    time.sleep(min(0.05 * (i + 1), 0.5) + random.uniform(0, 0.05))
                    continue
                raise
        raise ContinuityError("database busy, could not begin transaction: %s" % last_err)

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.conn.execute("COMMIT")
        else:
            try:
                self.conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        return False


# ---------------------------------------------------------------------------
# Core operations. All mutating ops open their own write_tx unless in_tx=True.
# ---------------------------------------------------------------------------

def append_event(conn, project_id, actor_id, actor_type, event_type, payload,
                 task_id=None, base_revision=None, in_tx=False):
    """Append one hash-chained event; returns the stored event as a dict."""

    def _do():
        row = conn.execute(
            "SELECT seq, hash FROM events WHERE project_id=? ORDER BY seq DESC LIMIT 1",
            (project_id,)).fetchone()
        seq = (row["seq"] + 1) if row else 1
        prev_hash = row["hash"] if row else GENESIS_HASH
        created_at = now_iso()
        event_id = new_id("ev")
        payload_json = canonical_json(payload)
        payload_hash = sha256_hex(payload_json)
        ctx_row = conn.execute(
            "SELECT context_version FROM projects WHERE project_id=?",
            (project_id,)).fetchone()
        context_version = ctx_row["context_version"] if ctx_row else None
        chain_material = "|".join([
            prev_hash, payload_hash, project_id, str(seq), event_type,
            actor_id, created_at])
        ev_hash = sha256_hex(chain_material)
        owner = current_owner()
        conn.execute(
            "INSERT INTO events (event_id, project_id, seq, actor_id, actor_type,"
            " owner, event_type, payload, payload_hash, prev_hash, hash,"
            " context_version, base_revision, task_id, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, project_id, seq, actor_id, actor_type, owner, event_type,
             payload_json, payload_hash, prev_hash, ev_hash,
             context_version, base_revision, task_id, created_at))
        conn.execute(
            "UPDATE agents SET last_seen_at=? WHERE project_id=? AND agent_id=?",
            (created_at, project_id, actor_id))
        return {"event_id": event_id, "seq": seq, "event_type": event_type,
                "actor_id": actor_id, "owner": owner, "created_at": created_at,
                "context_version": context_version}

    if in_tx:
        return _do()
    with write_tx(conn):
        return _do()


def bump_context_version(conn, project_id, in_tx=True):
    """Advance project context version. Call inside an open write_tx."""
    assert in_tx
    conn.execute(
        "UPDATE projects SET context_version = context_version + 1 WHERE project_id=?",
        (project_id,))
    row = conn.execute(
        "SELECT context_version FROM projects WHERE project_id=?",
        (project_id,)).fetchone()
    return row["context_version"]


def get_project(conn, project_id):
    row = conn.execute(
        "SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
    if not row:
        known = [r["project_id"] for r in
                 conn.execute("SELECT project_id FROM projects ORDER BY project_id")]
        raise ContinuityError(
            "unknown project '%s'. Known projects: %s. Run `continuity.py init` "
            "in the project directory to register one." % (project_id, known or "none"))
    return dict(row)


def list_projects(conn):
    rows = conn.execute(
        "SELECT p.*, (SELECT COUNT(*) FROM events e WHERE e.project_id=p.project_id) AS events,"
        " (SELECT COUNT(*) FROM tasks t WHERE t.project_id=p.project_id"
        "   AND t.status NOT IN ('done','cancelled')) AS open_tasks"
        " FROM projects p ORDER BY p.created_at").fetchall()
    return {"projects": [dict(r) for r in rows]}


def resolve_project_id(conn, explicit=None, default=None, cwd=None, use_cwd=True):
    """Project resolution: explicit arg > configured default > cwd walk-up
    (local processes only — HTTP sessions disable it, since the server's cwd
    is meaningless to remote clients) > sole registered project."""
    if explicit:
        return get_project(conn, explicit)["project_id"]
    if default:
        return get_project(conn, default)["project_id"]
    if use_cwd:
        # CLAUDE_PROJECT_DIR: set by Claude Code for plugin-spawned MCP
        # servers, whose actual cwd may not be the project directory.
        candidates = [cwd or os.getcwd(), os.environ.get("CLAUDE_PROJECT_DIR")]
        rows = conn.execute(
            "SELECT project_id, root_path FROM projects WHERE root_path IS NOT NULL").fetchall()
        for candidate in candidates:
            if not candidate:
                continue
            candidate = Path(candidate).resolve()
            best = None
            for row in rows:
                try:
                    root = Path(row["root_path"]).resolve()
                except Exception:
                    continue
                if candidate == root or root in candidate.parents:
                    if best is None or len(str(root)) > len(str(best[1])):
                        best = (row["project_id"], root)
            if best:
                return best[0]
    all_rows = conn.execute("SELECT project_id FROM projects").fetchall()
    if len(all_rows) == 1:
        return all_rows[0]["project_id"]
    known = [r["project_id"] for r in all_rows]
    raise ContinuityError(
        "cannot determine project%s. Pass project explicitly, set %s (or the "
        "X-Continuity-Project header over HTTP), or run `continuity.py init` "
        "in the project directory. Known projects: %s"
        % ((" (cwd=%s)" % cwd) if use_cwd else "", ENV_PROJECT, known or "none"))


def project_init(conn, actor_id, actor_type, path=None, project_id=None,
                 name=None, move=False):
    root = Path(path or os.getcwd()).resolve()
    name = name or root.name
    # Normalize custom ids too: project ids live in URLs and env vars.
    project_id = slugify(project_id) if project_id else slugify(name)
    # Check-and-insert inside one BEGIN IMMEDIATE so two concurrent inits of
    # the same project id serialize instead of crashing on the PK.
    with write_tx(conn):
        existing = conn.execute(
            "SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
        if existing:
            if existing["root_path"] not in (None, str(root)):
                if not move:
                    raise ContinuityError(
                        "project '%s' is already registered at %s. Re-run with "
                        "--move to re-point it to %s (this affects every tool "
                        "using this project)."
                        % (project_id, existing["root_path"], root))
                conn.execute("UPDATE projects SET root_path=? WHERE project_id=?",
                             (str(root), project_id))
                append_event(conn, project_id, actor_id, actor_type,
                             "project.root_changed",
                             {"from": existing["root_path"], "to": str(root)},
                             in_tx=True)
            elif existing["root_path"] is None:
                conn.execute("UPDATE projects SET root_path=? WHERE project_id=?",
                             (str(root), project_id))
            return {"project_id": project_id, "name": existing["name"],
                    "root_path": str(root), "already_existed": True}
        conn.execute(
            "INSERT INTO projects (project_id, name, root_path, created_by, created_at)"
            " VALUES (?,?,?,?,?)",
            (project_id, name, str(root), actor_id, now_iso()))
        append_event(conn, project_id, actor_id, actor_type, "project.created",
                     {"name": name, "root_path": str(root)}, in_tx=True)
    return {"project_id": project_id, "name": name, "root_path": str(root),
            "already_existed": False}


# --- handoff ---------------------------------------------------------------

def _latest_handoff(conn, project_id):
    return conn.execute(
        "SELECT * FROM handoffs WHERE project_id=? ORDER BY version DESC LIMIT 1",
        (project_id,)).fetchone()


def _significant_events(conn, project_id, after_seq=0, limit=100):
    rows = conn.execute(
        "SELECT * FROM events WHERE project_id=? AND seq>? ORDER BY seq DESC LIMIT ?",
        (project_id, after_seq, limit)).fetchall()
    out = []
    for row in rows:
        line = render_log_line(row)
        if line:
            out.append(line)
    out.reverse()
    return out


def _task_brief(task):
    brief = {k: task[k] for k in
             ("task_id", "title", "status", "claimed_by", "risk_level")}
    if task["status"] == "claimed":
        brief["lease_until"] = task.get("lease_until")
        if task.get("lease_expired"):
            brief["lease_expired"] = True  # dead claim: reclaimable
    return brief


def get_handoff(conn, project_id, actor_id=None):
    project = get_project(conn, project_id)
    row = _latest_handoff(conn, project_id)
    content = json.loads(row["content"]) if row else {}
    handoff = {field: content.get(field) for field in HANDOFF_FIELDS}
    open_tasks = task_list(conn, project_id, status=None)["tasks"]
    open_tasks = [t for t in open_tasks if t["status"] not in ("done", "cancelled")]
    decisions = [d for d in decision_list(conn, project_id)["decisions"]
                 if d["status"] in ("proposed", "accepted")]
    recent = _significant_events(conn, project_id, limit=200)[-8:]
    your_inbox = None
    if actor_id:
        peek = inbox_read(conn, project_id, actor_id, mark_read=False, limit=200)
        your_inbox = {"unread_addressed_to_you": len(peek["messages"]),
                      "unread_broadcasts": peek["unread_broadcasts"],
                      "hint": "read with check_inbox / room_read"}
    bridges = _bridge_rows(conn, project_id)
    governance = None
    rules_over = [b["with"] for b in bridges
                  if b["relation"] == "master" and b["principal"] == project_id]
    follows = [b["principal"] for b in bridges
               if b["relation"] == "master" and b["principal"] != project_id]
    advised_by = [b["with"] for b in bridges
                  if b["relation"] == "advisor" and b["principal"] != project_id]
    if rules_over or follows or advised_by:
        governance = {"rules_over": rules_over, "follows": follows,
                      "advised_by": advised_by,
                      "hint": ("messages tagged [MASTER] from a project you "
                               "follow are binding directives; your outbound "
                               "messages to it arrive as suggestions")}
    return {
        "project": project_id,
        "context_version": project["context_version"],
        "lead_director": project.get("lead_director"),
        "your_inbox": your_inbox,
        "bridges": bridges,
        "governance": governance,
        "handoff": handoff,
        "handoff_updated_by": row["updated_by"] if row else None,
        "handoff_updated_at": row["updated_at"] if row else None,
        "open_tasks": [_task_brief(t) for t in open_tasks],
        "decisions": [{k: d[k] for k in ("decision_id", "title", "status")}
                      for d in decisions],
        "recent_activity": recent,
        "git": {"head": git_head(project.get("root_path")),
                "branch": git_branch(project.get("root_path"))},
        "hint": (None if row else
                 "No handoff written yet. After your first meaningful work, call "
                 "update_handoff so the next worker can resume cold."),
    }


def update_handoff(conn, project_id, actor_id, actor_type, updates):
    updates = {k: v for k, v in updates.items()
               if k in HANDOFF_FIELDS and v is not None}
    if not updates:
        raise ContinuityError(
            "update_handoff needs at least one of: %s" % ", ".join(HANDOFF_FIELDS))
    with write_tx(conn):
        get_project(conn, project_id)
        row = _latest_handoff(conn, project_id)
        content = json.loads(row["content"]) if row else {}
        content.update(updates)
        new_version = bump_context_version(conn, project_id)
        conn.execute(
            "INSERT INTO handoffs (project_id, version, content, updated_by, updated_at)"
            " VALUES (?,?,?,?,?)",
            (project_id, new_version, canonical_json(content), actor_id, now_iso()))
        event = append_event(conn, project_id, actor_id, actor_type,
                             "handoff.updated",
                             {"fields": sorted(updates.keys()),
                              "handoff": content}, in_tx=True)
    return {"ok": True, "context_version": new_version,
            "updated_fields": sorted(updates.keys()), "event": event}


# --- room ------------------------------------------------------------------

def room_send(conn, project_id, actor_id, actor_type, body, msg_type="chat",
              mentions=None, task_id=None, reply_to=None, origin_project=None):
    if not body or not str(body).strip():
        raise ContinuityError("room_send: body is required")
    msg_type = (msg_type or "chat").lower()
    if msg_type not in MSG_TYPES:
        raise ContinuityError(
            "room_send: msg_type must be one of %s" % ", ".join(MSG_TYPES))
    mentions = _require_str_list("mentions", mentions)
    payload = {"msg_type": msg_type, "body": str(body)}
    if mentions:
        payload["mentions"] = mentions
    if reply_to:
        payload["reply_to"] = reply_to
    if origin_project and origin_project != project_id:
        payload["origin_project"] = origin_project
    get_project(conn, project_id)
    event = append_event(conn, project_id, actor_id, actor_type,
                         "room.message", payload, task_id=task_id)
    # Bridges: mirror addressed/structured messages to linked projects so
    # their agents' rooms and inboxes receive them. Mirrored copies carry
    # origin_project and are never re-mirrored (loop protection).
    mirrored_to = []
    if "origin_project" not in payload and \
            (mentions or msg_type not in ("chat", "status")):
        for bridge in _bridge_rows(conn, project_id):
            authority = None
            if bridge["relation"] == "master":
                authority = "master-directive" \
                    if bridge["principal"] == project_id else "suggestion"
            elif bridge["relation"] == "advisor" \
                    and bridge["principal"] == project_id:
                authority = "advice"
            mirror = dict(payload, origin_project=project_id)
            if authority:
                mirror["authority"] = authority
            append_event(conn, bridge["with"], actor_id, actor_type,
                         "room.message", mirror)
            mirrored_to.append(bridge["with"])
    warnings = []
    if msg_type == "decision":
        warnings.append("room messages do not create durable decision records — "
                        "also call decision_propose / decision_resolve")
    if msg_type == "claim" and not task_id:
        warnings.append("claim messages should reference a task_id; use "
                        "task_claim to actually claim the work")
    result = {"ok": True, "delivered_to": project_id, "event": event}
    if mirrored_to:
        result["mirrored_to_bridged_projects"] = mirrored_to
    if warnings:
        result["warnings"] = warnings
    return result


def room_read(conn, project_id, since_seq=None, limit=30):
    get_project(conn, project_id)
    limit = max(1, min(int(limit or 30), 500))
    if since_seq is not None:
        rows = conn.execute(
            "SELECT * FROM events WHERE project_id=? AND seq>? AND event_type='room.message'"
            " ORDER BY seq ASC LIMIT ?", (project_id, int(since_seq), limit)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM events WHERE project_id=? AND event_type='room.message'"
            " ORDER BY seq DESC LIMIT ?", (project_id, limit)).fetchall()
        rows = list(reversed(rows))
    # The cursor is derived ONLY from the rows actually returned, so a
    # truncated batch can never skip undelivered messages (and there is no
    # TOCTOU with a separate MAX(seq) query).
    if rows:
        next_since = rows[-1]["seq"]
    elif since_seq is not None:
        next_since = int(since_seq)
    else:
        next_since = 0
    messages = [_room_message_dict(row) for row in rows]
    may_have_more = len(rows) == limit
    return {"project": project_id, "messages": messages,
            "next_since_seq": next_since,
            "may_have_more": may_have_more,
            "hint": ("more messages are waiting — poll again with "
                     "since_seq=next_since_seq now" if may_have_more else
                     "poll again with since_seq=next_since_seq to read only "
                     "new messages")}


# --- inbox -----------------------------------------------------------------

def _room_message_dict(row, payload=None):
    payload = payload if payload is not None else json.loads(row["payload"])
    return {"seq": row["seq"], "at": row["created_at"], "actor": row["actor_id"],
            "actor_type": row["actor_type"], "msg_type": payload.get("msg_type"),
            "body": payload.get("body"), "mentions": payload.get("mentions"),
            "task_id": row["task_id"], "reply_to": payload.get("reply_to"),
            "origin_project": payload.get("origin_project"),
            "authority": payload.get("authority")}


def inbox_read(conn, project_id, actor_id, mark_read=True, limit=50):
    """Per-actor inbox: room messages that mention you or reply to one of
    your messages, since your persisted read cursor. Other unread room
    traffic is reported as a count (read it with room_read)."""
    get_project(conn, project_id)
    limit = max(1, min(int(limit or 50), 500))
    row = conn.execute(
        "SELECT last_read_seq FROM inbox_cursors WHERE project_id=? AND actor_id=?",
        (project_id, actor_id)).fetchone()
    cursor = row["last_read_seq"] if row else 0
    rows = conn.execute(
        "SELECT * FROM events WHERE project_id=? AND seq>?"
        " AND event_type='room.message' ORDER BY seq ASC LIMIT ?",
        (project_id, cursor, limit + 1)).fetchall()
    may_have_more = len(rows) > limit
    rows = rows[:limit]
    messages, broadcasts = [], 0
    for r in rows:
        if r["actor_id"] == actor_id:
            continue  # your own messages are not inbox items
        payload = json.loads(r["payload"])
        addressed = actor_id in (payload.get("mentions") or [])
        if not addressed and payload.get("reply_to"):
            orig = conn.execute(
                "SELECT actor_id FROM events WHERE event_id=?",
                (payload["reply_to"],)).fetchone()
            addressed = bool(orig and orig["actor_id"] == actor_id)
        if addressed:
            messages.append(_room_message_dict(r, payload))
        else:
            broadcasts += 1
    new_cursor = rows[-1]["seq"] if rows else cursor
    if mark_read and new_cursor > cursor:
        with write_tx(conn):
            conn.execute(
                "INSERT INTO inbox_cursors (project_id, actor_id, last_read_seq,"
                " updated_at) VALUES (?,?,?,?)"
                " ON CONFLICT(project_id, actor_id) DO UPDATE SET"
                " last_read_seq=excluded.last_read_seq,"
                " updated_at=excluded.updated_at",
                (project_id, actor_id, new_cursor, now_iso()))
    return {"project": project_id, "actor": actor_id, "messages": messages,
            "unread_broadcasts": broadcasts, "may_have_more": may_have_more,
            "read_cursor": new_cursor if mark_read else cursor,
            "hint": ("more unread remains — call check_inbox again"
                     if may_have_more else
                     "unread_broadcasts counts room messages not addressed to "
                     "you; read them with room_read")}


BRIDGE_RELATIONS = ["peer", "master", "advisor"]


def _bridge_rows(conn, project_id):
    rows = conn.execute(
        "SELECT * FROM bridges WHERE project_a=? OR project_b=?",
        (project_id, project_id)).fetchall()
    out = []
    for r in rows:
        other = r["project_b"] if r["project_a"] == project_id else r["project_a"]
        out.append({"with": other, "relation": r["relation"] or "peer",
                    "principal": r["principal"]})
    return out


def _bridged_projects(conn, project_id):
    return [b["with"] for b in _bridge_rows(conn, project_id)]


def bridge_add(conn, project_id, actor_id, actor_type, other_project,
               boss=None, advisor=None):
    """Bridge two projects so agents reach each other's rooms/inboxes.
    Relationship between the two AI teams:
      peer (default)      — equals; messages mirror untagged.
      boss=<project_id>   — that project's directors RULE the other: their
                            mirrored messages arrive tagged [MASTER]; the
                            subordinate side's arrive as suggestions.
      advisor=<project_id>— that project advises: its messages arrive tagged
                            as advice, no authority either way."""
    get_project(conn, project_id)
    other = get_project(conn, other_project)["project_id"]
    if other == project_id:
        raise ContinuityError("cannot bridge a project to itself")
    if boss and advisor:
        raise ContinuityError("choose either boss or advisor, not both")
    principal = boss or advisor or None
    relation = "master" if boss else ("advisor" if advisor else "peer")
    if principal and principal not in (project_id, other):
        raise ContinuityError(
            "%s must be one of the bridged projects (%s, %s)"
            % ("boss" if boss else "advisor", project_id, other))
    a, b = sorted([project_id, other])
    with write_tx(conn):
        exists = conn.execute(
            "SELECT 1 FROM bridges WHERE project_a=? AND project_b=?",
            (a, b)).fetchone()
        if exists:
            raise ContinuityError(
                "%s and %s are already bridged (remove it first to change "
                "the relationship)" % (a, b))
        conn.execute(
            "INSERT INTO bridges (project_a, project_b, relation, principal,"
            " created_by, created_at) VALUES (?,?,?,?,?,?)",
            (a, b, relation, principal, actor_id, now_iso()))
        for side, peer in ((project_id, other), (other, project_id)):
            append_event(conn, side, actor_id, actor_type, "bridge.created",
                         {"with": peer, "relation": relation,
                          "principal": principal}, in_tx=True)
    return {"ok": True, "bridged": [project_id, other], "relation": relation,
            "principal": principal,
            "note": "room messages that are addressed (mentions) or structured "
                    "(directive/handoff/decision/approval/challenge/claim) now "
                    "mirror across; plain chat stays local"}


def bridge_remove(conn, project_id, actor_id, actor_type, other_project):
    other = get_project(conn, other_project)["project_id"]
    a, b = sorted([project_id, other])
    with write_tx(conn):
        cur = conn.execute(
            "DELETE FROM bridges WHERE project_a=? AND project_b=?", (a, b))
        if cur.rowcount != 1:
            raise ContinuityError("%s and %s are not bridged" % (a, b))
        for side, peer in ((project_id, other), (other, project_id)):
            append_event(conn, side, actor_id, actor_type, "bridge.removed",
                         {"with": peer}, in_tx=True)
    return {"ok": True, "removed": [project_id, other]}


def bridge_list(conn, project_id):
    get_project(conn, project_id)
    return {"project": project_id, "bridges": _bridge_rows(conn, project_id)}


def set_lead_director(conn, project_id, actor_id, actor_type, lead_id):
    """Blueprint §6.4 boss mode: designate the Lead Director whose directives
    assign work and break ties. Empty lead_id clears the role."""
    lead_id = (lead_id or "").strip() or None
    with write_tx(conn):
        project = get_project(conn, project_id)
        previous = project.get("lead_director")
        if previous == lead_id:
            raise ContinuityError("lead director is already %s" % (lead_id or "unset"))
        conn.execute("UPDATE projects SET lead_director=? WHERE project_id=?",
                     (lead_id, project_id))
        context_version = bump_context_version(conn, project_id)
        event = append_event(conn, project_id, actor_id, actor_type,
                             "project.lead_changed",
                             {"from": previous, "to": lead_id}, in_tx=True)
    return {"ok": True, "lead_director": lead_id, "previous": previous,
            "context_version": context_version, "event": event}


# --- tasks -----------------------------------------------------------------

def _next_counter_id(conn, table, id_col, project_id, prefix):
    row = conn.execute(
        "SELECT COALESCE(MAX(CAST(SUBSTR(%s, %d) AS INTEGER)), 0) AS n FROM %s"
        " WHERE project_id=?" % (id_col, len(prefix) + 1, table),
        (project_id,)).fetchone()
    return "%s%d" % (prefix, row["n"] + 1)


def _task_row(conn, project_id, task_id):
    row = conn.execute(
        "SELECT * FROM tasks WHERE project_id=? AND task_id=?",
        (project_id, task_id)).fetchone()
    if not row:
        raise ContinuityError("unknown task %s in project %s" % (task_id, project_id))
    return row


def _task_dict(row):
    task = dict(row)
    task["expected_scope"] = json.loads(task.get("expected_scope") or "[]")
    task["dependencies"] = json.loads(task.get("dependencies") or "[]")
    if task.get("last_report"):
        task["last_report"] = json.loads(task["last_report"])
    if task["status"] == "claimed" and task.get("lease_until") \
            and task["lease_until"] < now_iso():
        task["lease_expired"] = True
    return task


def task_create(conn, project_id, actor_id, actor_type, title, description=None,
                expected_scope=None, dependencies=None, risk_level="medium"):
    if not title or not str(title).strip():
        raise ContinuityError("task_create: title is required")
    risk_level = (risk_level or "medium").lower()
    if risk_level not in RISK_LEVELS:
        raise ContinuityError("risk_level must be one of %s" % ", ".join(RISK_LEVELS))
    expected_scope = _require_str_list("expected_scope", expected_scope) or []
    dependencies = _require_str_list("dependencies", dependencies) or []
    with write_tx(conn):
        get_project(conn, project_id)
        task_id = _next_counter_id(conn, "tasks", "task_id", project_id, "T-")
        created_at = now_iso()
        conn.execute(
            "INSERT INTO tasks (project_id, task_id, title, description, status,"
            " risk_level, expected_scope, dependencies, created_by, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (project_id, task_id, str(title), description, "queued", risk_level,
             canonical_json(expected_scope), canonical_json(dependencies),
             actor_id, created_at, created_at))
        event = append_event(conn, project_id, actor_id, actor_type, "task.created",
                             {"title": str(title), "risk_level": risk_level,
                              "expected_scope": expected_scope,
                              "dependencies": dependencies},
                             task_id=task_id, in_tx=True)
    return {"ok": True, "task_id": task_id, "status": "queued", "event": event}


def task_list(conn, project_id, status=None):
    get_project(conn, project_id)
    if status:
        if status not in TASK_STATUSES:
            raise ContinuityError("status must be one of %s" % ", ".join(TASK_STATUSES))
        rows = conn.execute(
            "SELECT * FROM tasks WHERE project_id=? AND status=? ORDER BY task_id",
            (project_id, status)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM tasks WHERE project_id=? ORDER BY "
            " CASE status WHEN 'claimed' THEN 0 WHEN 'review' THEN 1 WHEN 'blocked' THEN 2"
            "  WHEN 'queued' THEN 3 WHEN 'done' THEN 4 ELSE 5 END,"
            " CAST(SUBSTR(task_id,3) AS INTEGER)", (project_id,)).fetchall()
    return {"project": project_id, "tasks": [_task_dict(r) for r in rows]}


def task_show(conn, project_id, task_id):
    task = _task_dict(_task_row(conn, project_id, task_id))
    rows = conn.execute(
        "SELECT * FROM events WHERE project_id=? AND task_id=? ORDER BY seq",
        (project_id, task_id)).fetchall()
    task["history"] = [line for line in (render_log_line(r) for r in rows) if line]
    return task


def _scopes_overlap(scope_a, scope_b):
    for a in scope_a:
        for b in scope_b:
            if a == b or fnmatch.fnmatch(a, b) or fnmatch.fnmatch(b, a):
                return True
            a_dir, b_dir = a.rstrip("/") + "/", b.rstrip("/") + "/"
            if a.startswith(b_dir) or b.startswith(a_dir):
                return True
    return False


def _overlap_warnings(conn, project_id, task_id, scope):
    if not scope:
        return []
    warnings = []
    rows = conn.execute(
        "SELECT task_id, title, claimed_by, expected_scope, lease_until FROM tasks"
        " WHERE project_id=? AND status='claimed' AND task_id != ?",
        (project_id, task_id)).fetchall()
    for row in rows:
        if row["lease_until"] and row["lease_until"] < now_iso():
            continue
        other_scope = json.loads(row["expected_scope"] or "[]")
        if _scopes_overlap(scope, other_scope):
            warnings.append(
                "scope overlap with %s ('%s', claimed by %s): %s vs %s — coordinate "
                "in the room before editing shared files"
                % (row["task_id"], row["title"], row["claimed_by"],
                   other_scope, scope))
    return warnings


def task_claim(conn, project_id, actor_id, actor_type, task_id,
               expected_scope=None, lease_minutes=None):
    lease_minutes = 60 if lease_minutes is None else int(lease_minutes)
    lease_minutes = max(1, min(lease_minutes, 24 * 60))
    expected_scope = _require_str_list("expected_scope", expected_scope)
    project = get_project(conn, project_id)
    # git runs BEFORE the transaction so the global write lock is never held
    # across a subprocess call.
    base_revision = git_head(project.get("root_path"))
    with write_tx(conn):
        row = _task_row(conn, project_id, task_id)
        nowi = now_iso()
        lease_until = iso_in(lease_minutes)
        scope = expected_scope if expected_scope is not None \
            else json.loads(row["expected_scope"] or "[]")
        # Single conditional UPDATE: claimable if queued/blocked/review,
        # re-claimable by the same actor (lease renewal), or claimable when a
        # lease expired / a legacy row has no claimant or lease.
        cur = conn.execute(
            "UPDATE tasks SET status='claimed', claimed_by=?, lease_until=?,"
            " base_revision=?, expected_scope=?, updated_at=?"
            " WHERE project_id=? AND task_id=? AND ("
            "   status IN ('queued','blocked','review')"
            "   OR (status='claimed' AND (claimed_by=? OR claimed_by IS NULL"
            "       OR lease_until IS NULL OR lease_until<?)))",
            (actor_id, lease_until, base_revision, canonical_json(scope), nowi,
             project_id, task_id, actor_id, nowi))
        if cur.rowcount != 1:
            fresh = _task_row(conn, project_id, task_id)
            raise ContinuityError(
                "task %s not claimable: status=%s claimed_by=%s lease_until=%s"
                % (task_id, fresh["status"], fresh["claimed_by"], fresh["lease_until"]))
        renewal = row["status"] == "claimed" and row["claimed_by"] == actor_id
        event = append_event(
            conn, project_id, actor_id, actor_type,
            "task.lease_renewed" if renewal else "task.claimed",
            {"title": row["title"], "lease_until": lease_until,
             "expected_scope": scope},
            task_id=task_id, base_revision=base_revision, in_tx=True)
        warnings = _overlap_warnings(conn, project_id, task_id, scope)
        if renewal:
            warnings.append(
                "lease renewed — if a DIFFERENT session using the same actor id "
                "claimed this task, both sessions now share the lease; give each "
                "session a distinct %s" % ENV_ACTOR)
        deps = json.loads(row["dependencies"] or "[]")
        for dep in deps:
            dep_row = conn.execute(
                "SELECT status FROM tasks WHERE project_id=? AND task_id=?",
                (project_id, dep)).fetchone()
            if dep_row and dep_row["status"] not in ("done", "cancelled"):
                warnings.append("dependency %s is not done yet (status=%s)"
                                % (dep, dep_row["status"]))
    return {"ok": True, "task_id": task_id, "title": row["title"],
            "description": row["description"],
            "claimed_by": actor_id, "lease_until": lease_until,
            "base_revision": base_revision, "expected_scope": scope,
            "renewed": renewal, "warnings": warnings, "event": event}


def task_report(conn, project_id, actor_id, actor_type, task_id, summary,
                evidence=None, requested_state="review"):
    if not summary or not str(summary).strip():
        raise ContinuityError("task_report: summary is required")
    requested_state = (requested_state or "review").lower()
    if requested_state not in ("review", "done", "blocked", "queued"):
        raise ContinuityError("requested_state must be review|done|blocked|queued")
    evidence = _normalize_evidence(evidence)
    project = get_project(conn, project_id)
    base_revision = git_head(project.get("root_path"))
    with write_tx(conn):
        row = _task_row(conn, project_id, task_id)
        nowi = now_iso()
        report = {"summary": str(summary), "evidence": evidence,
                  "reported_by": actor_id, "reported_at": nowi,
                  "requested_state": requested_state,
                  "base_revision_at_claim": row["base_revision"],
                  "base_revision_at_report": base_revision}
        # Giving a task back clears the claimant; otherwise the reporter owns
        # the reported state.
        new_claimant = None if requested_state == "queued" else actor_id
        # Conditional UPDATE (mirrors task_claim): a report cannot destroy
        # another actor's active claim, and finished tasks cannot be
        # re-reported (reopen explicitly via task_set_status first).
        cur = conn.execute(
            "UPDATE tasks SET status=?, claimed_by=?, lease_until=NULL,"
            " last_report=?, updated_at=?"
            " WHERE project_id=? AND task_id=?"
            "   AND status NOT IN ('done','cancelled')"
            "   AND (status != 'claimed' OR claimed_by=? OR claimed_by IS NULL"
            "        OR lease_until IS NULL OR lease_until<?)",
            (requested_state, new_claimant, canonical_json(report), nowi,
             project_id, task_id, actor_id, nowi))
        if cur.rowcount != 1:
            fresh = _task_row(conn, project_id, task_id)
            if fresh["status"] in ("done", "cancelled"):
                raise ContinuityError(
                    "task %s is already %s; use task_set_status to reopen it "
                    "before reporting again" % (task_id, fresh["status"]))
            raise ContinuityError(
                "task %s is claimed by %s (lease until %s); only the claimant "
                "can report it while the lease is active"
                % (task_id, fresh["claimed_by"], fresh["lease_until"]))
        context_version = None
        if requested_state == "done":
            # Bump BEFORE appending so the causing events carry the new
            # context version and show up in check_freshness drift reports.
            context_version = bump_context_version(conn, project_id)
        event = append_event(conn, project_id, actor_id, actor_type, "task.reported",
                             report, task_id=task_id,
                             base_revision=base_revision, in_tx=True)
        if requested_state == "done":
            append_event(conn, project_id, actor_id, actor_type, "task.completed",
                         {"title": row["title"], "summary": str(summary)},
                         task_id=task_id, in_tx=True)
        warnings = []
        if row["base_revision"] and base_revision \
                and row["base_revision"] != base_revision \
                and not evidence:
            warnings.append(
                "repository moved from %s (claim) to %s (report) and no evidence "
                "was attached — attach tests/commits so reviewers can verify"
                % (row["base_revision"], base_revision))
        if not evidence:
            warnings.append("no evidence attached: completion is 'agent says done', "
                            "not verified (blueprint §8.4)")
    result = {"ok": True, "task_id": task_id, "status": requested_state,
              "warnings": warnings, "event": event}
    if context_version:
        result["context_version"] = context_version
    return result


def task_release(conn, project_id, actor_id, actor_type, task_id, reason=None):
    with write_tx(conn):
        get_project(conn, project_id)
        row = _task_row(conn, project_id, task_id)
        if row["status"] != "claimed":
            raise ContinuityError("task %s is not claimed (status=%s)"
                                  % (task_id, row["status"]))
        if row["claimed_by"] and row["claimed_by"] != actor_id \
                and row["lease_until"] and row["lease_until"] >= now_iso():
            raise ContinuityError(
                "task %s is claimed by %s (lease until %s); only the claimant "
                "can release an active claim"
                % (task_id, row["claimed_by"], row["lease_until"]))
        conn.execute(
            "UPDATE tasks SET status='queued', claimed_by=NULL, lease_until=NULL,"
            " updated_at=? WHERE project_id=? AND task_id=?",
            (now_iso(), project_id, task_id))
        event = append_event(conn, project_id, actor_id, actor_type, "task.released",
                             {"title": row["title"], "reason": reason,
                              "previous_claimant": row["claimed_by"]},
                             task_id=task_id, in_tx=True)
    return {"ok": True, "task_id": task_id, "status": "queued", "event": event}


def task_set_status(conn, project_id, actor_id, actor_type, task_id, status,
                    reason=None):
    status = (status or "").lower()
    if status not in TASK_STATUSES:
        raise ContinuityError("status must be one of %s" % ", ".join(TASK_STATUSES))
    if status == "claimed":
        raise ContinuityError(
            "use task_claim to claim tasks — set-status cannot create a claim "
            "with a claimant and lease")
    with write_tx(conn):
        get_project(conn, project_id)
        row = _task_row(conn, project_id, task_id)
        if row["status"] == status:
            raise ContinuityError("task %s already has status %s" % (task_id, status))
        conn.execute(
            "UPDATE tasks SET status=?, updated_at=?, lease_until=NULL,"
            " claimed_by=CASE WHEN ?='queued' THEN NULL ELSE claimed_by END"
            " WHERE project_id=? AND task_id=?",
            (status, now_iso(), status, project_id, task_id))
        context_version = None
        if status == "done":
            context_version = bump_context_version(conn, project_id)
        event = append_event(conn, project_id, actor_id, actor_type,
                             "task.status_changed",
                             {"title": row["title"], "from": row["status"],
                              "to": status, "reason": reason},
                             task_id=task_id, in_tx=True)
    result = {"ok": True, "task_id": task_id, "status": status, "event": event}
    if context_version:
        result["context_version"] = context_version
    return result


# --- decisions -------------------------------------------------------------

def decision_propose(conn, project_id, actor_id, actor_type, title, detail=None,
                     rationale=None):
    if not title or not str(title).strip():
        raise ContinuityError("decision_propose: title is required")
    with write_tx(conn):
        get_project(conn, project_id)
        decision_id = _next_counter_id(conn, "decisions", "decision_id",
                                       project_id, "D-")
        conn.execute(
            "INSERT INTO decisions (project_id, decision_id, title, detail,"
            " rationale, status, proposed_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (project_id, decision_id, str(title), detail, rationale, "proposed",
             actor_id, now_iso()))
        event = append_event(conn, project_id, actor_id, actor_type,
                             "decision.proposed",
                             {"decision_id": decision_id, "title": str(title),
                              "detail": detail, "rationale": rationale}, in_tx=True)
    return {"ok": True, "decision_id": decision_id, "status": "proposed",
            "event": event}


def decision_resolve(conn, project_id, actor_id, actor_type, decision_id,
                     resolution, rationale=None):
    resolution = (resolution or "").lower()
    if resolution not in DECISION_RESOLUTIONS:
        raise ContinuityError(
            "resolution must be one of %s" % ", ".join(DECISION_RESOLUTIONS))
    with write_tx(conn):
        get_project(conn, project_id)
        row = conn.execute(
            "SELECT * FROM decisions WHERE project_id=? AND decision_id=?",
            (project_id, decision_id)).fetchone()
        if not row:
            raise ContinuityError("unknown decision %s" % decision_id)
        if row["status"] != "proposed" and resolution != "superseded":
            raise ContinuityError(
                "decision %s already resolved (status=%s)" % (decision_id, row["status"]))
        conn.execute(
            "UPDATE decisions SET status=?, resolved_by=?, resolved_at=?,"
            " rationale=COALESCE(?, rationale) WHERE project_id=? AND decision_id=?",
            (resolution, actor_id, now_iso(), rationale, project_id, decision_id))
        context_version = None
        if resolution == "accepted":
            # Bump before appending so the resolution event carries the new
            # context version (visible in check_freshness drift reports).
            context_version = bump_context_version(conn, project_id)
        event = append_event(conn, project_id, actor_id, actor_type,
                             "decision.resolved",
                             {"decision_id": decision_id, "title": row["title"],
                              "resolution": resolution, "rationale": rationale},
                             in_tx=True)
    result = {"ok": True, "decision_id": decision_id, "status": resolution,
              "event": event}
    if context_version:
        result["context_version"] = context_version
    return result


def decision_list(conn, project_id, status=None):
    get_project(conn, project_id)
    if status:
        rows = conn.execute(
            "SELECT * FROM decisions WHERE project_id=? AND status=?"
            " ORDER BY CAST(SUBSTR(decision_id,3) AS INTEGER)",
            (project_id, status)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM decisions WHERE project_id=?"
            " ORDER BY CAST(SUBSTR(decision_id,3) AS INTEGER)",
            (project_id,)).fetchall()
    return {"project": project_id, "decisions": [dict(r) for r in rows]}


# --- agents ----------------------------------------------------------------

def agent_register(conn, project_id, actor_id, actor_type, agent_id=None,
                   display_name=None, role=None, runtime=None):
    agent_id = agent_id or actor_id
    with write_tx(conn):
        get_project(conn, project_id)
        row = conn.execute(
            "SELECT * FROM agents WHERE project_id=? AND agent_id=?",
            (project_id, agent_id)).fetchone()
        nowi = now_iso()
        owner = current_owner()
        if row:
            conn.execute(
                "UPDATE agents SET display_name=COALESCE(?, display_name),"
                " role=COALESCE(?, role), runtime=COALESCE(?, runtime),"
                " owner=COALESCE(?, owner), last_seen_at=?"
                " WHERE project_id=? AND agent_id=?",
                (display_name, role, runtime, owner, nowi,
                 project_id, agent_id))
            return {"ok": True, "agent_id": agent_id, "already_registered": True}
        conn.execute(
            "INSERT INTO agents (project_id, agent_id, display_name, role, runtime,"
            " owner, actor_type, registered_at, last_seen_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (project_id, agent_id, display_name or agent_id, role, runtime,
             owner, actor_type, nowi, nowi))
        event = append_event(conn, project_id, actor_id, actor_type,
                             "agent.registered",
                             {"agent_id": agent_id,
                              "display_name": display_name or agent_id,
                              "role": role, "runtime": runtime,
                              "owner": owner}, in_tx=True)
    return {"ok": True, "agent_id": agent_id, "already_registered": False,
            "event": event}


def agent_list(conn, project_id):
    get_project(conn, project_id)
    rows = conn.execute(
        "SELECT * FROM agents WHERE project_id=? ORDER BY registered_at",
        (project_id,)).fetchall()
    return {"project": project_id, "agents": [dict(r) for r in rows]}


# --- log / status / freshness / verify ------------------------------------

def render_log_line(row):
    """Human-readable one-liner for a ledger event, or None if it is noise."""
    payload = json.loads(row["payload"])
    etype = row["event_type"]
    at = row["created_at"][:19].replace("T", " ")
    actor = row["actor_id"]
    task = (" [%s]" % row["task_id"]) if row["task_id"] else ""

    if etype == "room.message":
        mtype = payload.get("msg_type", "chat")
        if mtype in LOG_EXCLUDED_MSG_TYPES:
            return None
        origin = payload.get("origin_project")
        origin_txt = (" (from %s)" % origin) if origin else ""
        authority = payload.get("authority")
        auth_txt = (" [%s]" % authority.upper()) if authority else ""
        return "%s  %s%s %s%s%s: %s" % (at, actor, origin_txt, mtype.upper(),
                                        auth_txt, task, payload.get("body", ""))
    if etype == "project.created":
        return "%s  %s created project '%s' at %s" % (
            at, actor, payload.get("name"), payload.get("root_path"))
    if etype == "agent.registered":
        role = payload.get("role") or "unspecified role"
        runtime = payload.get("runtime") or "unspecified runtime"
        owned = (", owned by %s" % payload["owner"]) if payload.get("owner") else ""
        return "%s  agent '%s' registered (%s, %s%s)" % (
            at, payload.get("agent_id"), role, runtime, owned)
    if etype == "task.created":
        return "%s  %s created task%s: %s (risk=%s)" % (
            at, actor, task, payload.get("title"), payload.get("risk_level"))
    if etype == "task.claimed":
        return "%s  %s claimed%s '%s' (lease until %s, scope %s)" % (
            at, actor, task, payload.get("title"),
            (payload.get("lease_until") or "")[:19],
            payload.get("expected_scope") or [])
    if etype == "task.lease_renewed":
        return "%s  %s renewed lease%s until %s" % (
            at, actor, task, (payload.get("lease_until") or "")[:19])
    if etype == "task.reported":
        n_evidence = len(payload.get("evidence") or [])
        return "%s  %s reported%s -> %s (%d evidence item%s): %s" % (
            at, actor, task, payload.get("requested_state"),
            n_evidence, "" if n_evidence == 1 else "s", payload.get("summary"))
    if etype == "task.completed":
        return "%s  %s completed%s: %s" % (at, actor, task, payload.get("title"))
    if etype == "task.released":
        return "%s  %s released%s back to queue (%s)" % (
            at, actor, task, payload.get("reason") or "no reason given")
    if etype == "task.status_changed":
        return "%s  %s moved%s %s -> %s (%s)" % (
            at, actor, task, payload.get("from"), payload.get("to"),
            payload.get("reason") or "no reason given")
    if etype == "decision.proposed":
        return "%s  %s proposed %s: %s" % (
            at, actor, payload.get("decision_id"), payload.get("title"))
    if etype == "decision.resolved":
        return "%s  %s marked %s %s: %s" % (
            at, actor, payload.get("decision_id"),
            payload.get("resolution"), payload.get("title"))
    if etype in ("bridge.created", "bridge.removed"):
        verb = "bridged with" if etype == "bridge.created" else "removed bridge to"
        rel = payload.get("relation")
        rel_txt = ""
        if rel == "master":
            rel_txt = " (master: %s)" % payload.get("principal")
        elif rel == "advisor":
            rel_txt = " (advisor: %s)" % payload.get("principal")
        return "%s  %s %s %s%s" % (at, actor, verb, payload.get("with"), rel_txt)
    if etype == "project.lead_changed":
        return "%s  %s set lead director: %s -> %s" % (
            at, actor, payload.get("from") or "(none)",
            payload.get("to") or "(none)")
    if etype == "handoff.updated":
        return "%s  %s updated handoff (%s) -> context v%s" % (
            at, actor, ", ".join(payload.get("fields", [])), row["context_version"])
    if etype == "git.commit":
        return "%s  git commit %s on %s: %s" % (
            at, payload.get("sha", "?")[:10], payload.get("branch", "?"),
            payload.get("subject", ""))
    # Custom/unknown events: show type, keep it short.
    body = canonical_json(payload)
    if len(body) > 160:
        body = body[:157] + "..."
    return "%s  %s %s%s %s" % (at, actor, etype, task, body)


def project_log(conn, project_id, limit=40):
    get_project(conn, project_id)
    limit = max(1, min(int(limit or 40), 1000))
    rows = conn.execute(
        "SELECT * FROM events WHERE project_id=? ORDER BY seq DESC LIMIT ?",
        (project_id, limit * 3)).fetchall()
    lines = []
    for row in rows:
        line = render_log_line(row)
        if line:
            lines.append(line)
        if len(lines) >= limit:
            break
    lines.reverse()
    return {"project": project_id, "log": lines}


def project_status(conn, project_id, actor_id, actor_type, db_path):
    project = get_project(conn, project_id)
    handoff_row = _latest_handoff(conn, project_id)
    counts = conn.execute(
        "SELECT"
        " (SELECT COUNT(*) FROM events WHERE project_id=:p) AS events,"
        " (SELECT COUNT(*) FROM events WHERE project_id=:p AND event_type='room.message') AS messages,"
        " (SELECT COUNT(*) FROM tasks WHERE project_id=:p AND status NOT IN ('done','cancelled')) AS open_tasks,"
        " (SELECT COUNT(*) FROM tasks WHERE project_id=:p AND status='claimed') AS claimed_tasks,"
        " (SELECT COUNT(*) FROM decisions WHERE project_id=:p AND status='proposed') AS open_decisions,"
        " (SELECT COUNT(*) FROM agents WHERE project_id=:p) AS agents",
        {"p": project_id}).fetchone()
    return {
        "project": project_id,
        "name": project["name"],
        "root_path": project["root_path"],
        "db": str(db_path),
        "you": {"actor_id": actor_id, "actor_type": actor_type},
        "context_version": project["context_version"],
        "lead_director": project.get("lead_director"),
        "handoff_updated_at": handoff_row["updated_at"] if handoff_row else None,
        "counts": dict(counts),
        "git": {"head": git_head(project.get("root_path")),
                "branch": git_branch(project.get("root_path"))},
    }


def check_freshness(conn, project_id, context_version):
    project = get_project(conn, project_id)
    current = project["context_version"]
    if context_version is None:
        return {"project": project_id, "current_context_version": current,
                "stale": None,
                "hint": "pass the context_version you were briefed at "
                        "(get_handoff returns it) to check for drift"}
    context_version = int(context_version)
    stale = context_version < current
    result = {"project": project_id, "current_context_version": current,
              "your_context_version": context_version, "stale": stale}
    if stale:
        row = conn.execute(
            "SELECT COALESCE(MAX(seq),0) AS s FROM events"
            " WHERE project_id=? AND context_version<=?",
            (project_id, context_version)).fetchone()
        result["changes_since_your_briefing"] = _significant_events(
            conn, project_id, after_seq=row["s"], limit=200)[-20:]
        result["action"] = ("Material project changes occurred after you were "
                            "briefed. Re-run get_handoff before writing (Drift "
                            "Guard, blueprint §11.3).")
    return result


def search_project(conn, project_id, query, limit=20):
    """Substring search across everything stored for a project."""
    get_project(conn, project_id)
    if not query or not str(query).strip():
        raise ContinuityError("search: query is required")
    like = "%" + str(query) + "%"
    limit = max(1, min(int(limit or 20), 100))
    events = []
    for row in conn.execute(
            "SELECT * FROM events WHERE project_id=? AND payload LIKE ?"
            " ORDER BY seq DESC LIMIT ?", (project_id, like, limit)):
        events.append({"seq": row["seq"], "event_type": row["event_type"],
                       "line": render_log_line(row) or
                       "%s by %s" % (row["event_type"], row["actor_id"])})
    tasks = [
        {"task_id": r["task_id"], "title": r["title"], "status": r["status"]}
        for r in conn.execute(
            "SELECT * FROM tasks WHERE project_id=? AND (title LIKE ? OR"
            " description LIKE ? OR last_report LIKE ?)"
            " ORDER BY updated_at DESC LIMIT ?",
            (project_id, like, like, like, limit))]
    decisions = [
        {"decision_id": r["decision_id"], "title": r["title"],
         "status": r["status"]}
        for r in conn.execute(
            "SELECT * FROM decisions WHERE project_id=? AND (title LIKE ? OR"
            " detail LIKE ? OR rationale LIKE ?)"
            " ORDER BY created_at DESC LIMIT ?",
            (project_id, like, like, like, limit))]
    handoffs = [
        {"version": r["version"], "updated_by": r["updated_by"],
         "updated_at": r["updated_at"]}
        for r in conn.execute(
            "SELECT * FROM handoffs WHERE project_id=? AND content LIKE ?"
            " ORDER BY version DESC LIMIT ?", (project_id, like, limit))]
    return {"project": project_id, "query": str(query),
            "events": events, "tasks": tasks, "decisions": decisions,
            "handoff_versions": handoffs,
            "total_hits": len(events) + len(tasks) + len(decisions) + len(handoffs)}


def handoff_history(conn, project_id, limit=20):
    get_project(conn, project_id)
    rows = conn.execute(
        "SELECT * FROM handoffs WHERE project_id=? ORDER BY version DESC LIMIT ?",
        (project_id, max(1, min(int(limit or 20), 200)))).fetchall()
    return {"project": project_id, "versions": [
        {"version": r["version"], "updated_by": r["updated_by"],
         "updated_at": r["updated_at"], "content": json.loads(r["content"])}
        for r in rows]}


def event_show(conn, project_id, seq):
    get_project(conn, project_id)
    row = conn.execute(
        "SELECT * FROM events WHERE project_id=? AND seq=?",
        (project_id, int(seq))).fetchone()
    if not row:
        raise ContinuityError("no event with seq %s in %s" % (seq, project_id))
    event = dict(row)
    event["payload"] = json.loads(event["payload"])
    return event


def verify_ledger(conn, project_id):
    get_project(conn, project_id)
    rows = conn.execute(
        "SELECT * FROM events WHERE project_id=? ORDER BY seq", (project_id,)).fetchall()
    problems = []
    prev_hash = GENESIS_HASH
    expected_seq = 1
    for row in rows:
        if row["seq"] != expected_seq:
            problems.append("seq gap: expected %d, found %d (event %s)"
                            % (expected_seq, row["seq"], row["event_id"]))
            expected_seq = row["seq"]
        if row["prev_hash"] != prev_hash:
            problems.append("chain break at seq %d: prev_hash mismatch" % row["seq"])
        if sha256_hex(row["payload"]) != row["payload_hash"]:
            problems.append("payload tampered at seq %d" % row["seq"])
        chain_material = "|".join([
            row["prev_hash"], row["payload_hash"], row["project_id"],
            str(row["seq"]), row["event_type"], row["actor_id"], row["created_at"]])
        if sha256_hex(chain_material) != row["hash"]:
            problems.append("event hash mismatch at seq %d" % row["seq"])
        prev_hash = row["hash"]
        expected_seq += 1
    return {"project": project_id, "events": len(rows),
            "ok": not problems, "problems": problems}


# ---------------------------------------------------------------------------
# MCP server (stdio, newline-delimited JSON-RPC 2.0)
# ---------------------------------------------------------------------------

def _s(desc, **kw):
    schema = {"type": "string", "description": desc}
    schema.update(kw)
    return schema


def _i(desc):
    return {"type": "integer", "description": desc}


def _arr(desc):
    return {"type": "array", "items": {"type": "string"}, "description": desc}


PROJECT_PROP = _s("Project id. Optional — defaults to the configured/detected project. "
                  "Set it to address another project (cross-project messaging).")

MCP_TOOLS = [
    {
        "name": "continuity_status",
        "description": "Who am I and where am I? Returns your actor identity, the resolved "
                       "project, context version, open task/decision counts and git state. "
                       "Cheap sanity check that the continuity layer is wired up.",
        "inputSchema": {"type": "object", "properties": {"project": PROJECT_PROP}},
    },
    {
        "name": "get_handoff",
        "description": "CALL THIS FIRST in every session. Returns the project's current "
                       "handoff (objective, what changed, active work, blockers, risks, "
                       "next actions), open tasks, standing decisions, recent activity and "
                       "the current context_version. This replaces re-discovering the "
                       "project or relying on stale chat memory.",
        "inputSchema": {"type": "object", "properties": {"project": PROJECT_PROP}},
    },
    {
        "name": "update_handoff",
        "description": "Update the current-state handoff for the next worker (any tool, any "
                       "model). Pass only the fields that changed; others are preserved. "
                       "Bumps the project context_version. Call before ending a work "
                       "session or after material changes.",
        "inputSchema": {"type": "object", "properties": {
            "project": PROJECT_PROP,
            "objective": _s("Current objective of the project/phase."),
            "what_changed": _s("What changed recently (merged, refactored, fixed)."),
            "active_work": _s("Work in progress and by whom."),
            "blockers": _s("Known blockers."),
            "risks": _s("Current risks."),
            "next_actions": _s("Concrete next actions for the next worker."),
            "notes": _s("Anything else the next worker must know."),
        }},
    },
    {
        "name": "get_project_log",
        "description": "Curated human-readable project log: tasks, claims, reports, "
                       "decisions, handoff updates, directives. Use to understand recent "
                       "history beyond the handoff.",
        "inputSchema": {"type": "object", "properties": {
            "project": PROJECT_PROP, "limit": _i("Max lines (default 40).")}},
    },
    {
        "name": "room_send",
        "description": "Post a message to the shared human+AI Project Room. All workers "
                       "across Claude Code / Codex / GLM / humans see it. Use msg_type: "
                       "chat (talk), directive (create instruction), claim (announce you "
                       "take work), handoff (state ready for others), challenge (dispute a "
                       "claim with evidence), decision, approval, status. Set project to "
                       "message another project's room.",
        "inputSchema": {"type": "object", "properties": {
            "body": _s("Message text."),
            "msg_type": _s("One of: %s (default chat)." % ", ".join(MSG_TYPES)),
            "mentions": _arr("Actor ids you are addressing, e.g. ['codex_director']."),
            "task_id": _s("Related task id, e.g. T-3."),
            "reply_to": _s("event_id of the message you reply to."),
            "project": PROJECT_PROP,
        }, "required": ["body"]},
    },
    {
        "name": "room_read",
        "description": "Read Project Room messages. First call: omit since_seq to get the "
                       "latest messages. Then poll with since_seq=next_since_seq from the "
                       "previous response to receive only new messages (your inbox).",
        "inputSchema": {"type": "object", "properties": {
            "since_seq": _i("Only messages with ledger seq greater than this."),
            "limit": _i("Max messages (default 30)."),
            "project": PROJECT_PROP,
        }},
    },
    {
        "name": "check_inbox",
        "description": "YOUR personal inbox: room messages that mention you or "
                       "reply to your messages, since your last check "
                       "(persistent per-actor read cursor — works across "
                       "sessions and tools). Marks them read by default; "
                       "mark_read=false to peek. Also reports how many other "
                       "unread room messages exist (read those with "
                       "room_read). Check at session start and periodically.",
        "inputSchema": {"type": "object", "properties": {
            "mark_read": {"type": "boolean",
                          "description": "Advance your read cursor (default true)."},
            "limit": _i("Max messages to scan (default 50)."),
            "project": PROJECT_PROP,
        }},
    },
    {
        "name": "set_lead_director",
        "description": "Designate or change the project's Lead Director — the "
                       "actor whose directives assign work and break ties "
                       "(boss mode). Pass an empty agent_id to clear it. "
                       "Bumps the context version.",
        "inputSchema": {"type": "object", "properties": {
            "agent_id": _s("Actor id to make lead, e.g. claude_director. "
                           "Empty string clears the lead."),
            "project": PROJECT_PROP,
        }, "required": ["agent_id"]},
    },
    {
        "name": "bridge_add",
        "description": "Bridge this project with another: addressed room "
                       "messages (mentions) and structured ones (directive/"
                       "handoff/decision/approval/challenge/claim) mirror "
                       "between both rooms and inboxes. Plain chat stays "
                       "local. Use for inter-project coordination.",
        "inputSchema": {"type": "object", "properties": {
            "other_project": _s("Project id to bridge with (see list_projects)."),
            "boss": _s("Optional: project id whose directors RULE the other "
                       "(master/subordinate relationship). Their messages "
                       "arrive tagged [MASTER]; the other side's arrive as "
                       "suggestions."),
            "advisor": _s("Optional: project id that ADVISES the other — its "
                          "messages arrive tagged as advice, no authority."),
            "project": PROJECT_PROP,
        }, "required": ["other_project"]},
    },
    {
        "name": "bridge_list",
        "description": "List the projects bridged with this one.",
        "inputSchema": {"type": "object", "properties": {"project": PROJECT_PROP}},
    },
    {
        "name": "search",
        "description": "Search everything stored for this project — ledger "
                       "events, room messages, tasks, decisions and handoff "
                       "history — for a text query. Use to find prior "
                       "discussions, decisions or work before starting.",
        "inputSchema": {"type": "object", "properties": {
            "query": _s("Text to search for (case-insensitive substring)."),
            "limit": _i("Max hits per category (default 20)."),
            "project": PROJECT_PROP,
        }, "required": ["query"]},
    },
    {
        "name": "task_create",
        "description": "Create a work item in the shared task board. Declare "
                       "expected_scope (files/dirs/globs likely to change) so parallel "
                       "workers get overlap warnings.",
        "inputSchema": {"type": "object", "properties": {
            "title": _s("Short task title."),
            "description": _s("Details, acceptance criteria."),
            "expected_scope": _arr("Paths/globs likely to change, e.g. ['src/auth/**']."),
            "dependencies": _arr("Task ids that must complete first, e.g. ['T-1']."),
            "risk_level": _s("low | medium | high (default medium)."),
            "project": PROJECT_PROP,
        }, "required": ["title"]},
    },
    {
        "name": "task_list",
        "description": "List tasks on the shared board (all workers see the same board). "
                       "Check this before starting work to avoid duplicating a claimed task.",
        "inputSchema": {"type": "object", "properties": {
            "status": _s("Filter: %s." % " | ".join(TASK_STATUSES)),
            "project": PROJECT_PROP,
        }},
    },
    {
        "name": "task_claim",
        "description": "Claim a task before working on it (soft lock with expiring lease). "
                       "Exactly one worker can hold a claim; expired leases are reclaimable. "
                       "Returns the task brief, git base_revision, and warnings if your "
                       "scope overlaps another active claim. Call again to renew your lease.",
        "inputSchema": {"type": "object", "properties": {
            "task_id": _s("Task to claim, e.g. T-3."),
            "expected_scope": _arr("Override/declare the paths you will touch."),
            "lease_minutes": _i("Lease duration (default 60, max 1440)."),
            "project": PROJECT_PROP,
        }, "required": ["task_id"]},
    },
    {
        "name": "task_report",
        "description": "Report the outcome of your task with evidence (tests run, commits, "
                       "outputs). requested_state: review (default), done, blocked, or "
                       "queued (give it back). Evidence-less 'done' is flagged — the "
                       "platform distinguishes 'agent says done' from verified completion.",
        "inputSchema": {"type": "object", "properties": {
            "task_id": _s("Task id, e.g. T-3."),
            "summary": _s("What you did and the outcome."),
            "evidence": {"type": "array", "items": {"type": "object"},
                         "description": "Evidence objects, e.g. "
                         "[{\"kind\":\"test\",\"name\":\"pytest tests/\",\"result\":\"pass\"},"
                         "{\"kind\":\"commit\",\"sha\":\"b81af94\"}]."},
            "requested_state": _s("review | done | blocked | queued (default review)."),
            "project": PROJECT_PROP,
        }, "required": ["task_id", "summary"]},
    },
    {
        "name": "task_release",
        "description": "Release a claimed task back to the queue (you stop working on it).",
        "inputSchema": {"type": "object", "properties": {
            "task_id": _s("Task id."), "reason": _s("Why you are releasing it."),
            "project": PROJECT_PROP,
        }, "required": ["task_id"]},
    },
    {
        "name": "task_set_status",
        "description": "Move a task to a status directly (e.g. reviewer accepts review -> "
                       "done, or reopens done -> queued). Prefer task_report for your own "
                       "work; use this for review verdicts and corrections.",
        "inputSchema": {"type": "object", "properties": {
            "task_id": _s("Task id."),
            "status": _s("One of: %s." % " | ".join(TASK_STATUSES)),
            "reason": _s("Why."),
            "project": PROJECT_PROP,
        }, "required": ["task_id", "status"]},
    },
    {
        "name": "decision_propose",
        "description": "Record a durable decision proposal (architecture, API, convention). "
                       "Decisions must live in the ledger, not only in chat. Another "
                       "worker or a human resolves it with decision_resolve.",
        "inputSchema": {"type": "object", "properties": {
            "title": _s("The decision, stated precisely."),
            "detail": _s("Full decision content."),
            "rationale": _s("Why / evidence."),
            "project": PROJECT_PROP,
        }, "required": ["title"]},
    },
    {
        "name": "decision_resolve",
        "description": "Resolve a proposed decision: accepted (bumps context version — all "
                       "workers get drift warnings until re-briefed), rejected, or "
                       "superseded.",
        "inputSchema": {"type": "object", "properties": {
            "decision_id": _s("e.g. D-2."),
            "resolution": _s("accepted | rejected | superseded."),
            "rationale": _s("Why."),
            "project": PROJECT_PROP,
        }, "required": ["decision_id", "resolution"]},
    },
    {
        "name": "decision_list",
        "description": "List decision records (proposed and resolved) for the project.",
        "inputSchema": {"type": "object", "properties": {
            "status": _s("Filter: proposed | accepted | rejected | superseded."),
            "project": PROJECT_PROP,
        }},
    },
    {
        "name": "agent_register",
        "description": "Register (or refresh) your agent identity for this project: role, "
                       "display name, runtime. Do this once when you first join a project.",
        "inputSchema": {"type": "object", "properties": {
            "agent_id": _s("Stable id (defaults to your configured actor id)."),
            "display_name": _s("Human-friendly name, e.g. 'Backend Director'."),
            "role": _s("e.g. director, backend, frontend, security_review."),
            "runtime": _s("e.g. claude-code, codex-cli, glm, human."),
            "project": PROJECT_PROP,
        }},
    },
    {
        "name": "agent_list",
        "description": "List the agents/humans registered in this project and when they "
                       "were last active.",
        "inputSchema": {"type": "object", "properties": {"project": PROJECT_PROP}},
    },
    {
        "name": "list_projects",
        "description": "List all projects registered in this continuity database (for "
                       "cross-project coordination/messaging).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "append_event",
        "description": "Append a custom structured event to the append-only project ledger "
                       "(e.g. note.observation, incident.opened, ci.result). Use the "
                       "dedicated task/decision/room tools when they fit.",
        "inputSchema": {"type": "object", "properties": {
            "event_type": _s("Namespaced type, e.g. 'note.observation'."),
            "payload": {"type": "object", "description": "Arbitrary JSON payload."},
            "task_id": _s("Related task id."),
            "project": PROJECT_PROP,
        }, "required": ["event_type"]},
    },
    {
        "name": "check_freshness",
        "description": "Drift Guard: check whether the context you were briefed at is still "
                       "current. If stale, you get the list of material changes since your "
                       "briefing. Call before high-impact writes.",
        "inputSchema": {"type": "object", "properties": {
            "context_version": _i("The context_version you were briefed at "
                                  "(from get_handoff). Defaults to the version of your "
                                  "last get_handoff call in this session."),
            "project": PROJECT_PROP,
        }},
    },
]

MCP_INSTRUCTIONS = """This server is the project's shared continuity layer (event ledger, task
board, decision records, handoff, and a human+AI project room) shared by ALL
workers across tools (Claude Code, Codex, GLM, humans).

Session protocol:
1. START: call get_handoff, then check_inbox (messages addressed to YOU from
   other AIs/humans — possibly from bridged projects). Do not rely on prior
   chat memory or re-discover the repo from scratch.
2. Claim a task (task_claim) before substantive work; create one if needed.
3. Announce intent / coordinate via room_send; poll check_inbox / room_read
   for replies. Messages tagged [MASTER-DIRECTIVE] come from a project whose
   directors rule this one — treat them as binding; [SUGGESTION]/[ADVICE]
   are input, not orders. search finds anything recorded before.
4. Record durable choices with decision_propose / decision_resolve.
5. FINISH: task_report with evidence, then update_handoff so the next worker
   (possibly a different tool/model) resumes cold without a rebrief.
If any response contains a stale_context warning, re-run get_handoff before
writing."""


class McpSession:
    """One MCP stdio session: newline-delimited JSON-RPC over stdin/stdout."""

    def __init__(self, db_path, default_project=None, actor=None,
                 actor_type=None, stdin=None, stdout=None, detect_cwd=True,
                 owner=None):
        self.db_path = db_path
        self.conn = None
        self.default_project = default_project
        self.actor = actor
        self.actor_type = actor_type or "agent"
        self.client_name = None
        self.detect_cwd = detect_cwd  # False for HTTP: server cwd is meaningless
        # detect_cwd doubles as "local session": stdio sessions read the
        # machine identity themselves; HTTP sessions get owner from a header.
        self.owner = owner if owner is not None else \
            (load_owner() if detect_cwd else None)
        self.briefed_versions = {}   # project_id -> context_version at last get_handoff
        self._registered = set()     # (project, actor) auto-registered pairs
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout

    # -- plumbing -----------------------------------------------------------

    def _send(self, obj):
        self.stdout.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False))
        self.stdout.write("\n")
        self.stdout.flush()

    @staticmethod
    def _res(msg_id, result):
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _err(msg_id, code, message):
        return {"jsonrpc": "2.0", "id": msg_id,
                "error": {"code": code, "message": message}}

    def serve(self):
        try:
            # Invalid UTF-8 from a client must not kill the server: replace
            # bad bytes so the line fails JSON parsing (-32700) instead.
            self.stdin.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
        while True:
            try:
                line = self.stdin.readline()
            except (KeyboardInterrupt, BrokenPipeError):
                return
            except UnicodeDecodeError:
                self._send({"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32700, "message": "parse error"}})
                continue
            if line == "":
                return  # EOF: client went away
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self._send({"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32700, "message": "parse error"}})
                continue
            if isinstance(msg, list):
                # JSON-RPC batch (allowed by some MCP revisions): serve each
                # element; responses go back as one array.
                if not msg:
                    self._send({"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32600,
                                          "message": "invalid request: empty batch"}})
                    continue
                batch = self.process_batch(msg)
                try:
                    if batch:
                        self.stdout.write(json.dumps(
                            batch, separators=(",", ":"), ensure_ascii=False) + "\n")
                        self.stdout.flush()
                except BrokenPipeError:
                    return
                continue
            if not isinstance(msg, dict):
                continue
            resp = self.process_safely(msg)
            if resp is not None:
                try:
                    self._send(resp)
                except BrokenPipeError:
                    return

    def process_batch(self, items):
        """Serve a JSON-RPC batch; invalid (non-dict) elements get -32600
        entries instead of being silently dropped."""
        responses = []
        for item in items:
            if isinstance(item, dict):
                resp = self.process_safely(item)
                if resp is not None:
                    responses.append(resp)
            else:
                responses.append(self._err(None, -32600, "invalid request"))
        return responses

    def process_safely(self, msg):
        """process() that can never raise; internal errors become -32603."""
        try:
            return self.process(msg)
        except Exception as err:  # never let the server die on one message
            sys.stderr.write("continuity mcp: internal error: %r\n" % err)
            sys.stderr.flush()
            if msg.get("id") is not None:
                return self._err(msg.get("id"), -32603, "internal error: %s" % err)
            return None

    def process(self, msg):
        """Handle one JSON-RPC message; returns the response dict, or None
        for notifications and client responses (which get no reply)."""
        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}

        if method is None:
            return None  # a response from the client; ignore
        if msg_id is None:
            return None  # notification: never respond
        if method == "initialize":
            client_info = params.get("clientInfo") or {}
            self.client_name = client_info.get("name")
            if not self.actor and self.client_name:
                self.actor = slugify(self.client_name)
            requested = params.get("protocolVersion")
            protocol = requested if requested in MCP_SUPPORTED_PROTOCOLS \
                else MCP_DEFAULT_PROTOCOL
            return self._res(msg_id, {
                "protocolVersion": protocol,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "continuity", "version": VERSION},
                "instructions": MCP_INSTRUCTIONS,
            })
        if method == "ping":
            return self._res(msg_id, {})
        if method == "tools/list":
            return self._res(msg_id, {"tools": MCP_TOOLS})
        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            try:
                result = self.dispatch_tool(name, args)
                text = json.dumps(result, indent=2, ensure_ascii=False)
                return self._res(msg_id, {
                    "content": [{"type": "text", "text": text}],
                    "isError": False})
            except ContinuityError as err:
                return self._res(msg_id, {
                    "content": [{"type": "text", "text": "error: %s" % err}],
                    "isError": True})
            except Exception as err:
                sys.stderr.write("continuity mcp: tool %s failed: %r\n" % (name, err))
                sys.stderr.flush()
                return self._res(msg_id, {
                    "content": [{"type": "text",
                                 "text": "unexpected error in %s: %s" % (name, err)}],
                    "isError": True})
        return self._err(msg_id, -32601, "method not found: %s" % method)

    # -- tool dispatch --------------------------------------------------------

    def _conn(self):
        if self.conn is None:
            self.conn = connect(self.db_path)
        return self.conn

    def _actor(self):
        base = self.actor or (slugify(self.client_name)
                              if self.client_name else "unknown-agent")
        return qualify_actor(base, owner=self.owner)

    def _auto_register(self, conn, project, actor):
        """First contact of this session with a project: record the agent's
        identity (runtime = the connecting client) so 'who did what, with
        which engine, owned by whom' is always answerable."""
        if (project, actor) in self._registered:
            return
        self._registered.add((project, actor))
        try:
            agent_register(conn, project, actor, self.actor_type,
                           runtime=self.client_name)
        except ContinuityError:
            pass

    def _project(self, args):
        project = resolve_project_id(self._conn(), explicit=args.get("project"),
                                     default=self.default_project,
                                     use_cwd=self.detect_cwd)
        self._auto_register(self._conn(), project, self._actor())
        return project

    def _guarded_write(self, project_id, op):
        """Drift Guard around a mutating op: staleness is judged BEFORE the
        write (so the actor's own bump never looks like drift). A fresh actor
        that bumps the context stays fresh; a stale one stays stale until it
        re-briefs via get_handoff / check_freshness."""
        briefed = self.briefed_versions.get(project_id)
        warning = None
        if briefed is not None:
            current = get_project(self._conn(), project_id)["context_version"]
            if current > briefed:
                warning = (
                    "Project context advanced from v%d (your briefing) to v%d "
                    "before this write. Call get_handoff / check_freshness "
                    "before further writes." % (briefed, current))
        result = op()
        if warning:
            result["stale_context_warning"] = warning
        elif briefed is not None and isinstance(result.get("context_version"), int):
            self.briefed_versions[project_id] = result["context_version"]
        return result

    def dispatch_tool(self, name, args):
        conn = self._conn()
        actor = self._actor()
        atype = self.actor_type
        set_current_owner(self.owner)

        if name == "list_projects":
            return list_projects(conn)

        if name == "continuity_status":
            project = self._project(args)
            return project_status(conn, project, actor, atype, self.db_path)

        if name == "get_handoff":
            project = self._project(args)
            result = get_handoff(conn, project, actor_id=actor)
            self.briefed_versions[project] = result["context_version"]
            return result

        if name == "check_inbox":
            project = self._project(args)
            mark = args.get("mark_read")
            return inbox_read(conn, project, actor,
                              mark_read=True if mark is None else bool(mark),
                              limit=args.get("limit") or 50)

        if name == "set_lead_director":
            project = self._project(args)
            return self._guarded_write(project, lambda: set_lead_director(
                conn, project, actor, atype, args.get("agent_id")))

        if name == "bridge_add":
            project = self._project(args)
            return bridge_add(conn, project, actor, atype,
                              args.get("other_project"),
                              boss=args.get("boss"),
                              advisor=args.get("advisor"))

        if name == "bridge_list":
            project = self._project(args)
            return bridge_list(conn, project)

        if name == "search":
            project = self._project(args)
            return search_project(conn, project, args.get("query"),
                                  limit=args.get("limit") or 20)

        if name == "update_handoff":
            project = self._project(args)
            updates = {k: args.get(k) for k in HANDOFF_FIELDS}
            return self._guarded_write(project, lambda: update_handoff(
                conn, project, actor, atype, updates))

        if name == "get_project_log":
            project = self._project(args)
            return project_log(conn, project, limit=args.get("limit") or 40)

        if name == "room_send":
            target = self._project(args)
            origin = None
            if args.get("project"):
                try:
                    origin = resolve_project_id(conn, default=self.default_project,
                                                use_cwd=self.detect_cwd)
                except ContinuityError:
                    origin = None
            return room_send(conn, target, actor, atype,
                             body=args.get("body"),
                             msg_type=args.get("msg_type") or "chat",
                             mentions=args.get("mentions"),
                             task_id=args.get("task_id"),
                             reply_to=args.get("reply_to"),
                             origin_project=origin)

        if name == "room_read":
            project = self._project(args)
            return room_read(conn, project, since_seq=args.get("since_seq"),
                             limit=args.get("limit") or 30)

        if name == "task_create":
            project = self._project(args)
            return task_create(conn, project, actor, atype,
                               title=args.get("title"),
                               description=args.get("description"),
                               expected_scope=args.get("expected_scope"),
                               dependencies=args.get("dependencies"),
                               risk_level=args.get("risk_level") or "medium")

        if name == "task_list":
            project = self._project(args)
            return task_list(conn, project, status=args.get("status"))

        if name == "task_claim":
            project = self._project(args)
            return self._guarded_write(project, lambda: task_claim(
                conn, project, actor, atype,
                task_id=args.get("task_id"),
                expected_scope=args.get("expected_scope"),
                lease_minutes=args.get("lease_minutes")))

        if name == "task_report":
            project = self._project(args)
            return self._guarded_write(project, lambda: task_report(
                conn, project, actor, atype,
                task_id=args.get("task_id"),
                summary=args.get("summary"),
                evidence=args.get("evidence"),
                requested_state=args.get("requested_state") or "review"))

        if name == "task_release":
            project = self._project(args)
            return task_release(conn, project, actor, atype,
                                task_id=args.get("task_id"),
                                reason=args.get("reason"))

        if name == "task_set_status":
            project = self._project(args)
            return self._guarded_write(project, lambda: task_set_status(
                conn, project, actor, atype,
                task_id=args.get("task_id"),
                status=args.get("status"),
                reason=args.get("reason")))

        if name == "decision_propose":
            project = self._project(args)
            return decision_propose(conn, project, actor, atype,
                                    title=args.get("title"),
                                    detail=args.get("detail"),
                                    rationale=args.get("rationale"))

        if name == "decision_resolve":
            project = self._project(args)
            return self._guarded_write(project, lambda: decision_resolve(
                conn, project, actor, atype,
                decision_id=args.get("decision_id"),
                resolution=args.get("resolution"),
                rationale=args.get("rationale")))

        if name == "decision_list":
            project = self._project(args)
            return decision_list(conn, project, status=args.get("status"))

        if name == "agent_register":
            project = self._project(args)
            return agent_register(conn, project, actor, atype,
                                  agent_id=args.get("agent_id"),
                                  display_name=args.get("display_name"),
                                  role=args.get("role"),
                                  runtime=args.get("runtime"))

        if name == "agent_list":
            project = self._project(args)
            return agent_list(conn, project)

        if name == "append_event":
            project = self._project(args)
            event_type = args.get("event_type")
            if not event_type:
                raise ContinuityError("append_event: event_type is required")
            payload = args.get("payload")
            if payload is not None and not isinstance(payload, dict):
                raise ContinuityError("append_event: payload must be a JSON object")
            return {"ok": True,
                    "event": append_event(conn, project, actor, atype,
                                          str(event_type), payload or {},
                                          task_id=args.get("task_id"))}

        if name == "check_freshness":
            project = self._project(args)
            version = args.get("context_version")
            if version is None:
                version = self.briefed_versions.get(project)
            result = check_freshness(conn, project, version)
            if not result.get("stale"):
                self.briefed_versions[project] = result["current_context_version"]
            return result

        raise ContinuityError("unknown tool: %s" % name)


# ---------------------------------------------------------------------------
# Hosted server: the app owns the state; tools are API clients.
# REST API (blueprint §22.1 shape) + MCP over streamable HTTP at /mcp.
# ---------------------------------------------------------------------------

DEFAULT_PORT = 8722
DEFAULT_URL = "http://127.0.0.1:%d" % DEFAULT_PORT


def _api_project_init(conn, actor_id, actor_type, body):
    """POST /v1/projects — root_path is optional for API-created projects."""
    root = body.get("root_path")
    if root:
        return project_init(conn, actor_id, actor_type, path=root,
                            project_id=body.get("project_id"),
                            name=body.get("name"), move=bool(body.get("move")))
    raw_id = body.get("project_id") or body.get("name")
    if not raw_id:
        raise ContinuityError("provide project_id or name (root_path optional)")
    project_id = slugify(str(raw_id))
    name = body.get("name") or project_id
    with write_tx(conn):
        existing = conn.execute(
            "SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
        if existing:
            return {"project_id": project_id, "name": existing["name"],
                    "root_path": existing["root_path"], "already_existed": True}
        conn.execute(
            "INSERT INTO projects (project_id, name, root_path, created_by, created_at)"
            " VALUES (?,?,NULL,?,?)", (project_id, name, actor_id, now_iso()))
        append_event(conn, project_id, actor_id, actor_type, "project.created",
                     {"name": name, "root_path": None}, in_tx=True)
    return {"project_id": project_id, "name": name, "root_path": None,
            "already_existed": False}


def _api_events_sync(conn, project_id, after, limit):
    """GET /v1/projects/{id}/events?after=N — the raw sync feed."""
    get_project(conn, project_id)
    limit = max(1, min(int(limit), 1000))
    rows = conn.execute(
        "SELECT * FROM events WHERE project_id=? AND seq>? ORDER BY seq LIMIT ?",
        (project_id, int(after), limit)).fetchall()
    events = []
    for row in rows:
        event = dict(row)
        event["payload"] = json.loads(event["payload"])
        events.append(event)
    next_after = rows[-1]["seq"] if rows else int(after)
    return {"project": project_id, "events": events, "next_after": next_after,
            "may_have_more": len(rows) == limit}


# Files that make up the downloadable plugin (paths relative to this script).
PLUGIN_FILES = [
    "continuity.py",
    "requirements.txt",
    "README.md",
    "plugin-mcp.json",
    ".claude-plugin/plugin.json",
    ".claude-plugin/marketplace.json",
    "commands/setup.md",
    "commands/status.md",
    "commands/brief.md",
    "commands/inbox.md",
    "commands/room.md",
    "commands/tasks.md",
]


def build_plugin_zip(base_url):
    """Zip the plugin, with plugin-mcp.json pre-wired to the serving host so
    a downloaded copy talks to the server it came from."""
    src_root = Path(script_path()).parent
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in PLUGIN_FILES:
            path = src_root / rel
            if not path.is_file():
                continue
            data = path.read_bytes()
            if rel == "plugin-mcp.json":
                cfg = json.loads(data)
                for server in cfg.get("mcpServers", {}).values():
                    server.setdefault("env", {})["CONTINUITY_URL"] = base_url
                data = (json.dumps(cfg, indent=2) + "\n").encode()
            zf.writestr(rel, data)
    return buf.getvalue()


INSTALL_SH_TEMPLATE = """#!/bin/sh
# continuity plugin installer — served by the continuity server itself.
set -e
BASE="{base}"
DEST="$HOME/.continuity/plugin/continuity"
TMP="$(mktemp -d)"
echo "downloading plugin from $BASE/plugin.zip ..."
if command -v curl >/dev/null 2>&1; then
  curl -fsS "$BASE/plugin.zip" -o "$TMP/plugin.zip"
else
  wget -qO "$TMP/plugin.zip" "$BASE/plugin.zip"
fi
python3 - "$TMP/plugin.zip" "$DEST" <<'PYEOF'
import os, shutil, sys, zipfile
zip_path, dest = sys.argv[1], sys.argv[2]
if os.path.isdir(dest):
    shutil.rmtree(dest)
os.makedirs(dest, exist_ok=True)
zipfile.ZipFile(zip_path).extractall(dest)
PYEOF
rm -rf "$TMP"
echo "plugin downloaded to $DEST (wired to $BASE)"
if command -v claude >/dev/null 2>&1; then
  claude plugin marketplace add "$DEST" >/dev/null 2>&1 \\
    || claude plugin marketplace update agentg >/dev/null 2>&1 || true
  if claude plugin install continuity@agentg --scope user >/dev/null 2>&1; then
    echo "installed: continuity plugin — restart Claude Code and open any project."
  else
    echo "marketplace added — finish inside Claude Code with: /plugin install continuity@agentg"
  fi
else
  echo "claude CLI not found — install later with:"
  echo "  claude plugin marketplace add $DEST"
  echo "  claude plugin install continuity@agentg --scope user"
fi
"""


LANDING_TEMPLATE = """continuity server {version}

Install the Claude Code plugin from this server:
  curl -s {base}/install.sh | sh

Endpoints:
  GET  /install.sh     one-line plugin installer
  GET  /plugin.zip     the plugin, pre-wired to this server
  GET  /healthz        health check
  /mcp                 MCP endpoint (streamable HTTP)
  /v1/projects ...     REST API (see README)
"""


class ContinuityServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, db_path, default_project=None, verbose=False):
        super().__init__(addr, ContinuityHandler)
        self.db_path = db_path
        self.default_project = default_project
        self.verbose = verbose
        self._local = threading.local()
        self._sessions_lock = threading.Lock()
        self._sessions = {}  # Mcp-Session-Id -> (McpSession, per-session Lock)

    def conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = connect(self.db_path)
            self._local.conn = conn
        return conn

    def create_session(self, session):
        sid = secrets.token_hex(16)
        with self._sessions_lock:
            while len(self._sessions) >= 256:  # drop oldest, dicts are ordered
                self._sessions.pop(next(iter(self._sessions)))
            self._sessions[sid] = (session, threading.Lock())
        return sid

    def get_session(self, sid):
        with self._sessions_lock:
            entry = self._sessions.pop(sid, None)
            if entry is not None:
                self._sessions[sid] = entry  # LRU touch: evict by last use
            return entry

    def drop_session(self, sid):
        with self._sessions_lock:
            self._sessions.pop(sid, None)


class _UnquotedMatch:
    """URL-decodes captured path segments after routing (decoding before the
    regex match would let %2F change which route matches)."""

    def __init__(self, match):
        self._groups = [urllib.parse.unquote(g) if g is not None else None
                        for g in match.groups()]

    def group(self, index):
        return self._groups[index - 1]


class ContinuityHandler(BaseHTTPRequestHandler):
    server_version = "continuity/" + VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if self.server.verbose:
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    # -- plumbing -----------------------------------------------------------

    def _drain_body(self):
        """Consume any unread request body so a keep-alive connection stays in
        sync — leftover bytes would be parsed as the NEXT request's start."""
        if getattr(self, "_body_consumed", False):
            return
        self._body_consumed = True
        length = int(self.headers.get("Content-Length") or 0)
        while length > 0:
            chunk = self.rfile.read(min(length, 65536))
            if not chunk:
                break
            length -= len(chunk)

    def _reply_json(self, code, obj, headers=None):
        self._drain_body()
        data = json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _reply_empty(self, code, headers=None):
        self._drain_body()
        self.send_response(code)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _raw_body(self):
        cached = getattr(self, "_body_cache", None)
        if cached is not None:
            return cached
        self._body_consumed = True
        length = int(self.headers.get("Content-Length") or 0)
        self._body_cache = self.rfile.read(length) if length else b""
        return self._body_cache

    def _body_json(self):
        raw = self._raw_body()
        if not raw:
            return {}
        try:
            body = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError as err:
            raise ContinuityError("request body must be valid JSON: %s" % err)
        if not isinstance(body, dict):
            raise ContinuityError("request body must be a JSON object")
        return body

    def _actor(self):
        return (self.headers.get("X-Continuity-Actor") or "api-client",
                self.headers.get("X-Continuity-Actor-Type") or "agent")

    def _conn(self):
        return self.server.conn()

    # -- HTTP verbs ---------------------------------------------------------

    def do_GET(self):
        self._route("GET")

    def do_HEAD(self):
        # _reply_json suppresses the body for HEAD but keeps the headers.
        self._route("GET")

    def do_OPTIONS(self):
        self._body_consumed = False  # drain an OPTIONS body too (keep-alive)
        self._body_cache = None
        self._reply_empty(204, {"Allow": "GET, HEAD, POST, PUT, DELETE, OPTIONS"})

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")

    def _route(self, http_method):
        self._body_consumed = False
        self._body_cache = None
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = {k: v[-1] for k, v in
                 urllib.parse.parse_qs(parsed.query).items()}
        set_current_owner(self.headers.get("X-Continuity-Owner"))
        try:
            if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                # We only read Content-Length-framed bodies; silently treating
                # a chunked body as empty would desync the connection.
                self.send_response(411)
                self.send_header("Content-Type", "application/json")
                body = b'{"error": "chunked bodies not supported; send Content-Length"}'
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True
                return
            if path == "/mcp":
                return self._handle_mcp(http_method)
            for method, pattern, fn in ROUTES:
                if method != http_method:
                    continue
                match = pattern.match(path)
                if match:
                    return fn(self, _UnquotedMatch(match), query)
            self._reply_json(404, {"error": "not found: %s %s"
                                   % (http_method, path)})
        except ContinuityError as err:
            self._reply_json(400, {"error": str(err)})
        except ValueError as err:
            self._reply_json(400, {"error": "bad parameter: %s" % err})
        except BrokenPipeError:
            pass
        except Exception as err:
            sys.stderr.write("continuity serve: internal error: %r\n" % err)
            sys.stderr.flush()
            try:
                self._reply_json(500, {"error": "internal error: %s" % err})
            except Exception:
                pass

    # -- MCP over streamable HTTP -------------------------------------------

    def _handle_mcp(self, http_method):
        if http_method == "GET":
            # We do not offer a server-initiated SSE stream.
            self._reply_empty(405, {"Allow": "POST, DELETE"})
            return
        if http_method == "DELETE":
            sid = self.headers.get("Mcp-Session-Id")
            if sid:
                self.server.drop_session(sid)
            self._reply_empty(204)
            return
        if http_method != "POST":
            self._reply_empty(405, {"Allow": "POST, DELETE"})
            return
        try:
            msg = json.loads(self._raw_body().decode("utf-8", "replace"))
        except json.JSONDecodeError:
            self._reply_json(400, {"jsonrpc": "2.0", "id": None,
                                   "error": {"code": -32700,
                                             "message": "parse error"}})
            return
        actor = self.headers.get("X-Continuity-Actor")
        actor_type = self.headers.get("X-Continuity-Actor-Type") or "agent"
        owner_header = self.headers.get("X-Continuity-Owner")
        default_project = self.headers.get("X-Continuity-Project") \
            or self.server.default_project
        if not default_project and self.headers.get("X-Continuity-Root"):
            # Zero-setup: the client declared its project root; register it
            # on first contact.
            default_project = resolve_or_register_root(
                self._conn(), self.headers["X-Continuity-Root"],
                actor or "system")
        extra_headers = {}
        is_init = isinstance(msg, dict) and msg.get("method") == "initialize"
        if is_init:
            session = McpSession(self.server.db_path,
                                 default_project=default_project,
                                 actor=actor, actor_type=actor_type,
                                 detect_cwd=False, owner=owner_header)
            sid = self.server.create_session(session)
            lock = self.server.get_session(sid)[1]
            extra_headers["Mcp-Session-Id"] = sid
        else:
            sid = self.headers.get("Mcp-Session-Id")
            if sid:
                entry = self.server.get_session(sid)
                if not entry:
                    # Spec: unknown/expired session -> 404 so the client
                    # re-initializes (an ephemeral fallback here would
                    # silently disarm Drift Guard state).
                    self._reply_json(404, {"error": "unknown Mcp-Session-Id; "
                                                    "re-initialize"})
                    return
                session, lock = entry
            else:
                # Lenient: serve session-less requests with an ephemeral
                # session (loses Drift Guard state, still fully functional).
                session = McpSession(self.server.db_path,
                                     default_project=default_project,
                                     actor=actor, actor_type=actor_type,
                                     detect_cwd=False, owner=owner_header)
                lock = threading.Lock()
        with lock:
            if isinstance(msg, list):
                if not msg:
                    self._reply_json(400, {"jsonrpc": "2.0", "id": None,
                                           "error": {"code": -32600,
                                                     "message": "empty batch"}})
                    return
                responses = session.process_batch(msg)
                if responses:
                    self._reply_json(200, responses, extra_headers)
                else:
                    self._reply_empty(202, extra_headers)
                return
            if not isinstance(msg, dict):
                self._reply_json(400, {"jsonrpc": "2.0", "id": None,
                                       "error": {"code": -32600,
                                                 "message": "invalid request"}})
                return
            resp = session.process_safely(msg)
            if resp is None:
                self._reply_empty(202, extra_headers)  # notification/response
            else:
                self._reply_json(200, resp, extra_headers)


# -- REST routes -------------------------------------------------------------

def _route_def(method, pattern):
    return method, re.compile("^%s$" % pattern)


def _r_healthz(h, m, q):
    h._reply_json(200, {"ok": True, "version": VERSION,
                        "db": str(h.server.db_path)})


def _base_url(h):
    host = h.headers.get("Host") or "127.0.0.1:%d" % h.server.server_address[1]
    return "http://%s" % host


def _reply_bytes(h, code, content_type, data, download_name=None):
    h._drain_body()
    h.send_response(code)
    h.send_header("Content-Type", content_type)
    h.send_header("Content-Length", str(len(data)))
    if download_name:
        h.send_header("Content-Disposition",
                      'attachment; filename="%s"' % download_name)
    h.end_headers()
    if h.command != "HEAD":
        h.wfile.write(data)


def _r_landing(h, m, q):
    _reply_bytes(h, 200, "text/plain; charset=utf-8",
                 LANDING_TEMPLATE.format(version=VERSION,
                                         base=_base_url(h)).encode())


def _r_install_sh(h, m, q):
    _reply_bytes(h, 200, "text/x-shellscript; charset=utf-8",
                 INSTALL_SH_TEMPLATE.format(base=_base_url(h)).encode())


def _r_plugin_zip(h, m, q):
    _reply_bytes(h, 200, "application/zip", build_plugin_zip(_base_url(h)),
                 download_name="continuity-plugin.zip")


def _r_marketplace_json(h, m, q):
    """Marketplace manifest for URL installs: the plugin source is this
    server's own git-over-HTTP endpoint, so `/plugin marketplace add <url>`
    followed by `/plugin install continuity@agentg` works natively."""
    base = _base_url(h)
    manifest = {
        "name": "agentg",
        "owner": {"name": "agentg"},
        "plugins": [{
            "name": "continuity",
            # Valid but version-gated in Claude Code: newer versions install
            # straight from this URL marketplace; older ones use /install.sh.
            "source": {"source": "git", "url": base + "/plugin.git"},
            "description": "Shared project memory for AI coding tools: "
                           "ledger, task claims, decisions, room, and "
                           "cold-start handoffs.",
        }],
    }
    _reply_bytes(h, 200, "application/json",
                 (json.dumps(manifest, indent=2) + "\n").encode())


_GIT_REPO_LOCK = threading.Lock()


def ensure_plugin_git_repo(base_url, cache_root):
    """Build (once per serving host) a bare git repo of the plugin, wired to
    base_url, ready for git's dumb-HTTP protocol (static file serving)."""
    key = sha256_hex(base_url)[:12]
    repo = Path(cache_root) / "plugin-git" / key / "plugin.git"
    with _GIT_REPO_LOCK:
        if (repo / "info" / "refs").exists():
            return repo
        import shutil
        import tempfile as tmpmod
        work = Path(tmpmod.mkdtemp(prefix="continuity-plugin-"))
        try:
            blob = build_plugin_zip(base_url)
            zipfile.ZipFile(io.BytesIO(blob)).extractall(work)
            git = ["git", "-c", "user.name=continuity",
                   "-c", "user.email=continuity@localhost"]
            subprocess.run(git + ["-C", str(work), "init", "-q"], check=True)
            subprocess.run(git + ["-C", str(work), "add", "-A"], check=True)
            subprocess.run(git + ["-C", str(work), "commit", "-q", "-m",
                                  "continuity plugin (wired to %s)" % base_url],
                           check=True)
            repo.parent.mkdir(parents=True, exist_ok=True)
            if repo.exists():
                shutil.rmtree(repo)
            subprocess.run(["git", "clone", "-q", "--bare", str(work),
                            str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "update-server-info"],
                           check=True)
            return repo
        finally:
            shutil.rmtree(work, ignore_errors=True)


def _r_plugin_git(h, m, q):
    """Serve the bare plugin repo statically (git dumb-HTTP protocol)."""
    try:
        repo = ensure_plugin_git_repo(_base_url(h),
                                      Path(h.server.db_path).resolve().parent)
    except (subprocess.CalledProcessError, FileNotFoundError) as err:
        h._reply_json(501, {"error": "git unavailable on the server: %s" % err})
        return
    rel = m.group(1) or "HEAD"
    target = (repo / rel).resolve()
    if repo.resolve() not in target.parents and target != repo.resolve():
        h._reply_json(403, {"error": "forbidden"})
        return
    if not target.is_file():
        h._reply_json(404, {"error": "not found: %s" % rel})
        return
    _reply_bytes(h, 200, "application/octet-stream", target.read_bytes())


def _r_projects_list(h, m, q):
    h._reply_json(200, list_projects(h._conn()))


def _r_projects_create(h, m, q):
    actor, atype = h._actor()
    h._reply_json(200, _api_project_init(h._conn(), actor, atype, h._body_json()))


def _r_handoff_get(h, m, q):
    h._reply_json(200, get_handoff(h._conn(), m.group(1)))


def _r_handoff_set(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    updates = {k: body.get(k) for k in HANDOFF_FIELDS}
    h._reply_json(200, update_handoff(h._conn(), m.group(1), actor, atype, updates))


def _r_log(h, m, q):
    h._reply_json(200, project_log(h._conn(), m.group(1),
                                   limit=int(q.get("limit") or 40)))


def _r_events_sync(h, m, q):
    h._reply_json(200, _api_events_sync(h._conn(), m.group(1),
                                        after=int(q.get("after") or 0),
                                        limit=int(q.get("limit") or 200)))


def _r_events_append(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    event_type = body.get("event_type")
    if not event_type:
        raise ContinuityError("event_type is required")
    payload = body.get("payload") or {}
    if not isinstance(payload, dict):
        raise ContinuityError("payload must be a JSON object")
    h._reply_json(200, {"ok": True, "event": append_event(
        h._conn(), m.group(1), actor, atype, str(event_type), payload,
        task_id=body.get("task_id"))})


def _r_room_read(h, m, q):
    since = q.get("since_seq")
    h._reply_json(200, room_read(h._conn(), m.group(1),
                                 since_seq=int(since) if since is not None else None,
                                 limit=int(q.get("limit") or 30)))


def _r_room_send(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    origin = h.headers.get("X-Continuity-Project")
    h._reply_json(200, room_send(
        h._conn(), m.group(1), actor, atype, body=body.get("body"),
        msg_type=body.get("msg_type") or "chat", mentions=body.get("mentions"),
        task_id=body.get("task_id"), reply_to=body.get("reply_to"),
        origin_project=origin if origin and origin != m.group(1) else None))


def _r_task_list(h, m, q):
    h._reply_json(200, task_list(h._conn(), m.group(1), status=q.get("status")))


def _r_task_create(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, task_create(
        h._conn(), m.group(1), actor, atype, title=body.get("title"),
        description=body.get("description"),
        expected_scope=body.get("expected_scope"),
        dependencies=body.get("dependencies"),
        risk_level=body.get("risk_level") or "medium"))


def _r_task_show(h, m, q):
    h._reply_json(200, task_show(h._conn(), m.group(1), m.group(2)))


def _r_task_claim(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, task_claim(
        h._conn(), m.group(1), actor, atype, m.group(2),
        expected_scope=body.get("expected_scope"),
        lease_minutes=body.get("lease_minutes")))


def _r_task_report(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, task_report(
        h._conn(), m.group(1), actor, atype, m.group(2),
        summary=body.get("summary"), evidence=body.get("evidence"),
        requested_state=body.get("requested_state") or "review"))


def _r_task_release(h, m, q):
    actor, atype = h._actor()
    h._reply_json(200, task_release(h._conn(), m.group(1), actor, atype,
                                    m.group(2),
                                    reason=h._body_json().get("reason")))


def _r_task_status(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, task_set_status(h._conn(), m.group(1), actor, atype,
                                       m.group(2), body.get("status"),
                                       reason=body.get("reason")))


def _r_decisions_list(h, m, q):
    h._reply_json(200, decision_list(h._conn(), m.group(1),
                                     status=q.get("status")))


def _r_decision_propose(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, decision_propose(
        h._conn(), m.group(1), actor, atype, title=body.get("title"),
        detail=body.get("detail"), rationale=body.get("rationale")))


def _r_decision_resolve(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, decision_resolve(
        h._conn(), m.group(1), actor, atype, m.group(2),
        body.get("resolution"), rationale=body.get("rationale")))


def _r_agents_list(h, m, q):
    h._reply_json(200, agent_list(h._conn(), m.group(1)))


def _r_agent_register(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, agent_register(
        h._conn(), m.group(1), actor, atype, agent_id=body.get("agent_id"),
        display_name=body.get("display_name"), role=body.get("role"),
        runtime=body.get("runtime")))


def _r_freshness(h, m, q):
    version = q.get("context_version")
    h._reply_json(200, check_freshness(
        h._conn(), m.group(1),
        int(version) if version is not None else None))


def _r_verify(h, m, q):
    h._reply_json(200, verify_ledger(h._conn(), m.group(1)))


_PID = "([^/]+)"
ROUTES = [
    (*_route_def("GET", "/"), _r_landing),
    (*_route_def("GET", "/install.sh"), _r_install_sh),
    (*_route_def("GET", "/plugin.zip"), _r_plugin_zip),
    (*_route_def("GET", "/plugin/marketplace.json"), _r_marketplace_json),
    (*_route_def("GET", "/plugin\\.git/(.+)"), _r_plugin_git),
    (*_route_def("GET", "/healthz"), _r_healthz),
    (*_route_def("GET", "/v1/projects"), _r_projects_list),
    (*_route_def("POST", "/v1/projects"), _r_projects_create),
    (*_route_def("GET", "/v1/projects/%s/handoff" % _PID), _r_handoff_get),
    (*_route_def("POST", "/v1/projects/%s/handoff" % _PID), _r_handoff_set),
    (*_route_def("PUT", "/v1/projects/%s/handoff" % _PID), _r_handoff_set),
    (*_route_def("GET", "/v1/projects/%s/log" % _PID), _r_log),
    (*_route_def("GET", "/v1/projects/%s/events" % _PID), _r_events_sync),
    (*_route_def("POST", "/v1/projects/%s/events" % _PID), _r_events_append),
    (*_route_def("GET", "/v1/projects/%s/room" % _PID), _r_room_read),
    (*_route_def("POST", "/v1/projects/%s/room" % _PID), _r_room_send),
    (*_route_def("GET", "/v1/projects/%s/tasks" % _PID), _r_task_list),
    (*_route_def("POST", "/v1/projects/%s/tasks" % _PID), _r_task_create),
    (*_route_def("GET", "/v1/projects/%s/tasks/%s" % (_PID, _PID)), _r_task_show),
    (*_route_def("POST", "/v1/projects/%s/tasks/%s/claim" % (_PID, _PID)), _r_task_claim),
    (*_route_def("POST", "/v1/projects/%s/tasks/%s/report" % (_PID, _PID)), _r_task_report),
    (*_route_def("POST", "/v1/projects/%s/tasks/%s/release" % (_PID, _PID)), _r_task_release),
    (*_route_def("POST", "/v1/projects/%s/tasks/%s/status" % (_PID, _PID)), _r_task_status),
    (*_route_def("GET", "/v1/projects/%s/decisions" % _PID), _r_decisions_list),
    (*_route_def("POST", "/v1/projects/%s/decisions" % _PID), _r_decision_propose),
    (*_route_def("POST", "/v1/projects/%s/decisions/%s/resolve" % (_PID, _PID)), _r_decision_resolve),
    (*_route_def("GET", "/v1/projects/%s/agents" % _PID), _r_agents_list),
    (*_route_def("POST", "/v1/projects/%s/agents" % _PID), _r_agent_register),
    (*_route_def("GET", "/v1/projects/%s/freshness" % _PID), _r_freshness),
    (*_route_def("GET", "/v1/projects/%s/verify" % _PID), _r_verify),
]


def run_server(db_path, host="127.0.0.1", port=DEFAULT_PORT,
               default_project=None, verbose=False):
    server = ContinuityServer((host, port), db_path,
                              default_project=default_project, verbose=verbose)
    real_port = server.server_address[1]
    base = "http://%s:%d" % (host, real_port)
    print("continuity server listening on %s" % base, flush=True)
    print("  db:   %s" % db_path, flush=True)
    print("  MCP:  %s/mcp    REST: %s/v1/projects" % (base, base), flush=True)
    print("  plugin install: curl -s %s/install.sh | sh" % base, flush=True)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("  WARNING: unauthenticated server bound to a non-localhost "
              "address (no encryption in this build)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def run_connect_proxy(url=None, actor=None, actor_type=None,
                      stdin=None, stdout=None):
    """`connect`: thin stdio<->HTTP MCP client of the hosted server.

    This is what the Claude Code plugin (and any stdio-only tool) spawns:
    it owns NO state and NO logic — it forwards JSON-RPC lines to the
    server's /mcp endpoint, declaring the project root so the server can
    auto-register the project on first contact. If the server is local and
    down, it boots it in the background (disable: CONTINUITY_AUTOSTART=0).
    """
    import urllib.error
    import urllib.request as urlreq
    url = (url or os.environ.get("CONTINUITY_URL") or DEFAULT_URL).rstrip("/")
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    root = str(Path(os.environ.get("CLAUDE_PROJECT_DIR")
                    or os.getcwd()).resolve())
    autostart = os.environ.get("CONTINUITY_AUTOSTART", "1") != "0"
    state = {"session": None, "ensured": False}

    def send_line(obj):
        stdout.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False))
        stdout.write("\n")
        stdout.flush()

    def post(body, retry=True):
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json",
                   "X-Continuity-Root": root}
        owner = load_owner()
        if owner:
            headers["X-Continuity-Owner"] = owner
        actor_id = qualify_actor(actor or os.environ.get(ENV_ACTOR),
                                 owner=owner)
        if actor_id:
            headers["X-Continuity-Actor"] = actor_id
        atype = actor_type or os.environ.get(ENV_ACTOR_TYPE)
        if atype:
            headers["X-Continuity-Actor-Type"] = atype
        project = os.environ.get(ENV_PROJECT)
        if project:
            headers["X-Continuity-Project"] = project
        if state["session"]:
            headers["Mcp-Session-Id"] = state["session"]
        req = urlreq.Request(url + "/mcp", data=body, headers=headers,
                             method="POST")
        try:
            with urlreq.urlopen(req, timeout=120) as resp:
                sid = resp.headers.get("Mcp-Session-Id")
                if sid:
                    state["session"] = sid
                return resp.status, resp.read()
        except urllib.error.HTTPError as err:
            data = err.read()
            if err.code == 404 and state["session"] and retry:
                # Server restarted and lost our session: continue sessionless.
                state["session"] = None
                return post(body, retry=False)
            return err.code, data

    while True:
        try:
            line = stdin.readline()
        except (KeyboardInterrupt, BrokenPipeError):
            return
        if line == "":
            return
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            send_line({"jsonrpc": "2.0", "id": None,
                       "error": {"code": -32700, "message": "parse error"}})
            continue
        expects_reply = isinstance(msg, list) or \
            (isinstance(msg, dict) and msg.get("id") is not None
             and msg.get("method") is not None)
        msg_id = msg.get("id") if isinstance(msg, dict) else None
        if not state["ensured"]:
            state["ensured"] = True
            if autostart and not server_alive(url):
                try:
                    ensure_server_running(
                        url, Path(os.environ.get(ENV_DB) or DEFAULT_DB))
                except Exception as err:
                    sys.stderr.write("continuity connect: autostart failed: "
                                     "%s\n" % err)
        try:
            status, data = post(line.encode("utf-8"))
        except Exception as err:
            if expects_reply:
                send_line({"jsonrpc": "2.0", "id": msg_id, "error": {
                    "code": -32000,
                    "message": "continuity server unreachable at %s (%s) — "
                               "start it with `python3 continuity.py serve`"
                               % (url, err)}})
            continue
        if status == 202 or not data:
            continue  # notification accepted; nothing to forward
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            if expects_reply:
                send_line({"jsonrpc": "2.0", "id": msg_id, "error": {
                    "code": -32603,
                    "message": "invalid response from server (HTTP %d)" % status}})
            continue
        if isinstance(payload, dict) and "jsonrpc" not in payload:
            # REST-style {"error": ...} from a non-MCP failure path.
            if expects_reply:
                send_line({"jsonrpc": "2.0", "id": msg_id, "error": {
                    "code": -32000,
                    "message": str(payload.get("error") or payload)}})
            continue
        try:
            send_line(payload)
        except BrokenPipeError:
            return


# ---------------------------------------------------------------------------
# Setup emitters: per-tool MCP config + managed instruction blocks + git hook
# ---------------------------------------------------------------------------

def script_path():
    return str(Path(__file__).resolve())


def mcp_server_config(actor, project_id, db_path):
    """Stdio (direct-DB) MCP config: the tool spawns a local shim."""
    # Always pin the DB path: the config already pins the absolute script
    # path, and the server may be spawned from any cwd/env.
    env = {ENV_ACTOR: actor, ENV_DB: str(db_path)}
    if project_id:
        env[ENV_PROJECT] = project_id
    return {"command": "python3", "args": [script_path(), "mcp"], "env": env}


def mcp_http_config(actor, project_id, url):
    """HTTP MCP config: the tool is a thin client of the hosted server."""
    headers = {"X-Continuity-Actor": actor}
    if project_id:
        headers["X-Continuity-Project"] = project_id
    return {"type": "http", "url": url.rstrip("/") + "/mcp", "headers": headers}


def mcp_connect_config(actor, url):
    """Stdio-shaped config that is still a pure server client: the tool
    spawns `continuity.py connect`, which forwards to the server and lets it
    auto-register the project from the tool's working directory."""
    return {"command": "python3", "args": [script_path(), "connect"],
            "env": {ENV_ACTOR: actor, "CONTINUITY_URL": url.rstrip("/")}}


def codex_http_toml(project_id, url):
    pairs = ['"X-Continuity-Actor" = "codex_director"']
    if project_id:
        pairs.append('"X-Continuity-Project" = "%s"' % project_id)
    return "\n".join([
        "[mcp_servers.continuity]",
        'url = "%s/mcp"' % url.rstrip("/"),
        "http_headers = { %s }" % ", ".join(pairs),
    ])


def codex_connect_toml(url):
    """Global Codex config: connect proxy, project auto-detected per cwd.
    Works on every Codex version (plain stdio server from Codex's view)."""
    return "\n".join([
        "[mcp_servers.continuity]",
        'command = "python3"',
        'args = ["%s", "connect"]' % script_path(),
        'env = { "%s" = "codex_director", "CONTINUITY_URL" = "%s" }'
        % (ENV_ACTOR, url.rstrip("/")),
    ])


def codex_stdio_toml(project_id, db_path):
    path = script_path()
    env_pairs = ['"%s" = "codex_director"' % ENV_ACTOR,
                 '"%s" = "%s"' % (ENV_DB, db_path)]
    if project_id:
        env_pairs.append('"%s" = "%s"' % (ENV_PROJECT, project_id))
    return "\n".join([
        "[mcp_servers.continuity]",
        'command = "python3"',
        'args = ["%s", "mcp"]' % path,
        "env = { %s }" % ", ".join(env_pairs),
    ])


def write_mcp_json_file(root_path, server_config):
    """Create or merge <root>/.mcp.json with the continuity server entry."""
    target = Path(root_path) / ".mcp.json"
    existing = {}
    if target.exists():
        try:
            existing = json.loads(target.read_text())
        except Exception:
            raise ContinuityError(
                "%s exists but is not valid JSON; fix it first" % target)
    if not isinstance(existing, dict) or \
            not isinstance(existing.get("mcpServers", {}), dict):
        raise ContinuityError(
            "%s exists but does not look like an MCP config (expected a "
            "JSON object with an optional mcpServers object)" % target)
    existing.setdefault("mcpServers", {})["continuity"] = server_config
    target.write_text(json.dumps(existing, indent=2) + "\n")
    return str(target)


def server_alive(url):
    try:
        import urllib.request as _rq
        with _rq.urlopen(url.rstrip("/") + "/healthz", timeout=2) as resp:
            return bool(json.loads(resp.read()).get("ok"))
    except Exception:
        return False


def ensure_server_running(url, db_path):
    """Start the continuity server in the background if it isn't up yet.
    Returns {"started": bool, "log": path|None, "pid": int|None}."""
    if server_alive(url):
        return {"started": False, "log": None, "pid": None}
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ContinuityError(
            "server at %s is not reachable, and it is not local so setup "
            "cannot start it for you — start it on that machine with "
            "`continuity.py serve`" % url)
    port = parsed.port or DEFAULT_PORT
    log_path = Path(db_path).resolve().parent / "server.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "ab") as log:
        proc = subprocess.Popen(
            [sys.executable, script_path(), "--db", str(db_path), "serve",
             "--host", host, "--port", str(port)],
            stdout=log, stderr=log, stdin=subprocess.DEVNULL,
            start_new_session=True)
    for _ in range(50):
        if server_alive(url):
            return {"started": True, "log": str(log_path), "pid": proc.pid}
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    raise ContinuityError(
        "tried to start the server but %s/healthz did not come up — "
        "see the log at %s" % (url, log_path))


def configure_codex(project_id, url, db_path, stdio=False, home=None):
    """Write the continuity block into ~/.codex/config.toml (with a one-time
    backup). Returns the config path, or None when Codex isn't installed."""
    codex_dir = Path(home or Path.home()) / ".codex"
    if not codex_dir.is_dir():
        return None
    block = codex_stdio_toml(project_id, db_path) if stdio \
        else codex_connect_toml(url)
    target = codex_dir / "config.toml"
    marker = "[mcp_servers.continuity]"
    if target.exists():
        text = target.read_text()
        backup = codex_dir / "config.toml.continuity-backup"
        if not backup.exists():
            backup.write_text(text)
        if marker in text:
            start = text.find(marker)
            rest = text[start + len(marker):]
            nxt = re.search(r"^\s*\[", rest, flags=re.M)
            end = start + len(marker) + (nxt.start() if nxt else len(rest))
            new_text = text[:start] + block + "\n" + text[end:]
        else:
            sep = "" if not text or text.endswith("\n\n") \
                else ("\n" if text.endswith("\n") else "\n\n")
            new_text = text + sep + block + "\n"
    else:
        new_text = block + "\n"
    target.write_text(new_text)
    return str(target)


def _merge_json_config(path, top_key, entry_name, value, backup=True):
    """Merge one entry into a JSON config file, keeping everything else."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    if path.exists():
        raw = path.read_text()
        try:
            data = json.loads(raw or "{}")
        except Exception:
            raise ContinuityError("%s exists but is not valid JSON; fix it first" % path)
        if not isinstance(data, dict):
            raise ContinuityError("%s is not a JSON object" % path)
        backup_path = path.with_name(path.name + ".continuity-backup")
        if backup and not backup_path.exists():
            backup_path.write_text(raw)
    section = data.setdefault(top_key, {})
    if not isinstance(section, dict):
        raise ContinuityError("%s: %r is not an object" % (path, top_key))
    section[entry_name] = value
    path.write_text(json.dumps(data, indent=2) + "\n")
    return str(path)


def _http_headers(actor, project_id):
    headers = {"X-Continuity-Actor": actor}
    if project_id:
        headers["X-Continuity-Project"] = project_id
    return headers


def connect_tools(project_id, root, db_path, url=DEFAULT_URL, stdio=False,
                  skip=None, home=None):
    """Universal installer: detect which MCP-capable tools are installed and
    write each one's config. Detection = the tool's config dir exists, so
    nothing is written for tools the user does not have. Claude Code's
    .mcp.json is handled separately by one_shot_setup.

    Returns (configured, not_detected): configured is a list of
    {tool, path}; not_detected is a list of tool names."""
    home = Path(home or Path.home())
    skip = set(skip or [])
    mcp_url = url.rstrip("/") + "/mcp"
    configured, missing = [], []

    def stdio_cfg(actor):
        return mcp_server_config(actor, project_id, db_path)

    def record(tool, path):
        configured.append({"tool": tool, "path": path})

    if "codex" not in skip:
        if (home / ".codex").is_dir():
            record("codex", configure_codex(project_id, url, db_path,
                                            stdio=stdio, home=home))
        else:
            missing.append("codex")

    if "cline" not in skip:
        candidates = [
            home / ".config/Code/User/globalStorage/saoudrizwan.claude-dev"
                   "/settings/cline_mcp_settings.json",
            home / ".config/Code - Insiders/User/globalStorage"
                   "/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
            home / "Library/Application Support/Code/User/globalStorage"
                   "/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        ]
        hit = next((c for c in candidates if c.parent.is_dir()), None)
        if hit:
            # stdio-shaped but still a server client (connect proxy)
            value = stdio_cfg("cline_worker") if stdio \
                else mcp_connect_config("cline_worker", url)
            record("cline", _merge_json_config(hit, "mcpServers", "continuity",
                                               value))
        else:
            missing.append("cline")

    if "cursor" not in skip:
        if (home / ".cursor").is_dir():
            # ~/.cursor/mcp.json is global: use the connect proxy so the
            # project is auto-detected per working directory.
            value = stdio_cfg("cursor_worker") if stdio \
                else mcp_connect_config("cursor_worker", url)
            record("cursor", _merge_json_config(home / ".cursor" / "mcp.json",
                                                "mcpServers", "continuity", value))
        else:
            missing.append("cursor")

    if "windsurf" not in skip:
        windsurf_dir = home / ".codeium" / "windsurf"
        if windsurf_dir.is_dir():
            value = stdio_cfg("windsurf_worker") if stdio \
                else mcp_connect_config("windsurf_worker", url)
            record("windsurf", _merge_json_config(
                windsurf_dir / "mcp_config.json", "mcpServers", "continuity",
                value))
        else:
            missing.append("windsurf")

    if "gemini" not in skip:
        if (home / ".gemini").is_dir() and root:
            value = stdio_cfg("gemini_worker") if stdio else \
                {"httpUrl": mcp_url,
                 "headers": _http_headers("gemini_worker", project_id)}
            record("gemini", _merge_json_config(
                Path(root) / ".gemini" / "settings.json", "mcpServers",
                "continuity", value, backup=False))
        else:
            missing.append("gemini")

    if "vscode" not in skip:
        if root and ((home / ".vscode").is_dir()
                     or (Path(root) / ".vscode").is_dir()):
            value = {"type": "stdio", **stdio_cfg("vscode_worker")} if stdio \
                else {"type": "http", "url": mcp_url,
                      "headers": _http_headers("vscode_worker", project_id)}
            record("vscode", _merge_json_config(
                Path(root) / ".vscode" / "mcp.json", "servers", "continuity",
                value, backup=False))
        else:
            missing.append("vscode")

    if "opencode" not in skip:
        if root and ((home / ".config" / "opencode").is_dir()
                     or (Path(root) / "opencode.json").exists()):
            if stdio:
                cfg = stdio_cfg("opencode_worker")
                value = {"type": "local",
                         "command": [cfg["command"]] + cfg["args"],
                         "environment": cfg["env"]}
            else:
                value = {"type": "remote", "url": mcp_url,
                         "headers": _http_headers("opencode_worker", project_id)}
            record("opencode", _merge_json_config(
                Path(root) / "opencode.json", "mcp", "continuity", value,
                backup=False))
        else:
            missing.append("opencode")

    return configured, missing


def resolve_or_register_root(conn, root, actor_id):
    """Server-side zero-setup: map a client's project root to a project,
    auto-registering it on first contact (unique slug from the dir name)."""
    root = str(Path(root).resolve())
    project_id = _project_for_cwd(conn, root)
    if project_id:
        return project_id
    base = slugify(Path(root).name)
    candidate = base
    for attempt in range(2, 12):
        row = conn.execute("SELECT root_path FROM projects WHERE project_id=?",
                           (candidate,)).fetchone()
        if row is None:
            try:
                return project_init(conn, actor_id, "system", path=root,
                                    project_id=candidate)["project_id"]
            except ContinuityError:
                pass  # lost a race for this id; try the next suffix
        elif row["root_path"] == root:
            return candidate
        candidate = "%s-%d" % (base, attempt)
    raise ContinuityError("could not register project for %s" % root)


def _project_for_cwd(conn, cwd):
    """Innermost registered project whose root contains cwd, or None."""
    cwd = Path(cwd).resolve()
    best = None
    for row in conn.execute("SELECT project_id, root_path FROM projects"
                            " WHERE root_path IS NOT NULL").fetchall():
        try:
            root = Path(row["root_path"]).resolve()
        except Exception:
            continue
        if cwd == root or root in cwd.parents:
            if best is None or len(str(root)) > len(str(best[1])):
                best = (row["project_id"], root)
    return best[0] if best else None


def one_shot_setup(conn, actor_id, actor_type, db_path, url=DEFAULT_URL,
                   stdio=False, write_instructions=True, path=None, here=False,
                   manage_server=True, manage_tools=True, skip_tools=None,
                   home=None):
    """`setup` with no arguments: make THIS directory a fully wired project.

    1. Registers the cwd as a project (if not already inside one; here=True
       forces the cwd to become its own project).
    2. Starts the continuity server in the background if it is not running
       (server mode only).
    3. Writes/merges .mcp.json — Claude Code and Claude-compatible CLIs
       (GLM etc.) pick it up automatically.
    4. Universal installer: writes the config of every DETECTED tool
       (codex, cline, cursor, windsurf, gemini, vscode, opencode), with
       one-time backups for global files.
    5. Writes the agent protocol block into CLAUDE.md / AGENTS.md.
    """
    cwd = Path(path or os.getcwd()).resolve()
    project_id = None if here else _project_for_cwd(conn, cwd)
    created = False
    if not project_id:
        result = project_init(conn, actor_id, actor_type, path=str(cwd))
        project_id = result["project_id"]
        created = not result["already_existed"]
    root = get_project(conn, project_id).get("root_path")
    server = {"started": False, "log": None, "pid": None,
              "managed": manage_server and not stdio}
    if server["managed"]:
        server.update(ensure_server_running(url, db_path))
    config = mcp_server_config("claude_director", project_id, db_path) \
        if stdio else mcp_http_config("claude_director", project_id, url)
    mcp_json = write_mcp_json_file(root, config)
    configured, not_detected = ([], [])
    if manage_tools:
        configured, not_detected = connect_tools(
            project_id, root, db_path, url=url, stdio=stdio,
            skip=skip_tools, home=home)
    instruction_files = []
    if write_instructions:
        instruction_files = [f["file"] for f in
                             install_instructions(project_id, root, db_path)["files"]]
    return {"project_id": project_id, "root_path": root,
            "project_created": created, "mode": "stdio" if stdio else "server",
            "cwd_inside_root": str(cwd) != str(root),
            "url": url, "server": server, "mcp_json": mcp_json,
            "configured_tools": configured, "not_detected": not_detected,
            "instruction_files": instruction_files}


def setup_details_text(project_id, db_path, url=DEFAULT_URL, tools=None):
    """`setup --details`: the full per-tool configuration reference."""
    path = script_path()
    out = []

    def stdio_config_json(actor):
        return json.dumps({"mcpServers": {
            "continuity": mcp_server_config(actor, project_id, db_path)}}, indent=2)

    out.append("Continuity configuration reference")
    out.append("=" * 60)
    out.append("Script:   %s" % path)
    out.append("Database: %s" % db_path)
    out.append("Server:   %s   (start with: python3 %s serve)" % (url, path))
    out.append("Project:  %s" % (project_id or "(none resolved)"))
    out.append("")
    out.append("Give each tool its own actor identity (X-Continuity-Actor header /")
    out.append("%s env) so the room shows who is who." % ENV_ACTOR)
    out.append("")

    selected = tools or ["claude", "codex", "gemini", "opencode", "glm", "cli"]

    if "claude" in selected:
        out.append("-- Claude Code (server mode, recommended) " + "-" * 18)
        out.append("  claude mcp add --transport http continuity %s/mcp \\" % url.rstrip("/"))
        out.append("    --header \"X-Continuity-Actor: claude_director\"%s"
                   % (" \\\n    --header \"X-Continuity-Project: %s\"" % project_id
                      if project_id else ""))
        out.append("or merge into <project>/.mcp.json (run `setup` to do this for you):")
        out.append(indent_block(json.dumps({"mcpServers": {"continuity":
                   mcp_http_config("claude_director", project_id, url)}}, indent=2)))
        out.append("-- Claude Code (stdio fallback, no server needed) " + "-" * 10)
        out.append(indent_block(stdio_config_json("claude_director")))
        out.append("")

    if "codex" in selected:
        out.append("-- Codex CLI " + "-" * 47)
        out.append("Global config (~/.codex/config.toml), works on every Codex")
        out.append("version; the server auto-detects the project per directory:")
        out.append(indent_block(codex_connect_toml(url)))
        out.append("Direct HTTP alternative (recent Codex; per-project header):")
        out.append(indent_block(codex_http_toml(project_id, url)))
        out.append("No-server stdio fallback:")
        out.append(indent_block(codex_stdio_toml(project_id, db_path)))
        out.append("")

    if "gemini" in selected:
        out.append("-- Gemini CLI " + "-" * 46)
        out.append("Merge into <project>/.gemini/settings.json (httpUrl = server mode):")
        gem = {"mcpServers": {"continuity": {
            "httpUrl": url.rstrip("/") + "/mcp",
            "headers": {"X-Continuity-Actor": "gemini_worker",
                        **({"X-Continuity-Project": project_id} if project_id else {})}}}}
        out.append(indent_block(json.dumps(gem, indent=2)))
        out.append("Stdio fallback:")
        out.append(indent_block(stdio_config_json("gemini_worker")))
        out.append("")

    if "opencode" in selected:
        out.append("-- opencode " + "-" * 48)
        oc = {"mcp": {"continuity": {
            "type": "remote", "url": url.rstrip("/") + "/mcp",
            "headers": {"X-Continuity-Actor": "opencode_worker",
                        **({"X-Continuity-Project": project_id} if project_id else {})}}}}
        out.append("Merge into opencode.json (remote = server mode):")
        out.append(indent_block(json.dumps(oc, indent=2)))
        out.append("")

    if "glm" in selected:
        out.append("-- GLM (Zhipu) " + "-" * 45)
        out.append("GLM coding plans are typically used through Claude-Code-compatible or")
        out.append("Codex-compatible CLIs (e.g. ANTHROPIC_BASE_URL pointed at Zhipu).")
        out.append("Those clients read the SAME configs as above — use the Claude Code")
        out.append(".mcp.json / Codex config.toml with actor glm_director.")
        out.append("")

    if "cli" in selected:
        out.append("-- Any other MCP client (Grok, Zed, Cline, ...) " + "-" * 12)
        out.append("HTTP (server mode):  url %s/mcp" % url.rstrip("/"))
        out.append("  headers: X-Continuity-Actor: <name>, X-Continuity-Project: %s"
                   % (project_id or "<project>"))
        out.append("Stdio (no server):   command python3, args [\"%s\", \"mcp\"]" % path)
        out.append("  env: %s=<name>, %s=%s, %s=%s"
                   % (ENV_ACTOR, ENV_DB, db_path, ENV_PROJECT,
                      project_id or "<project>"))
        out.append("REST API:  curl %s/v1/projects" % url.rstrip("/"))
        out.append("           curl %s/v1/projects/%s/handoff"
                   % (url.rstrip("/"), project_id or "<project>"))
        out.append("CLI (same store): python3 %s --actor my_agent status|room|task ..." % path)
        out.append("")

    out.append("Optional extras per project:")
    out.append("  python3 %s install-hooks   # git post-commit -> ledger" % path)
    return "\n".join(out)


def indent_block(text, pad="    "):
    return "\n".join(pad + line for line in text.splitlines())


def managed_instruction_block(project_id, db_path):
    path = script_path()
    lines = []
    lines.append("%s v=1 project=%s do_not_edit=true -->" % (MANAGED_BEGIN, project_id))
    lines.append("## Project Continuity Protocol (managed block)")
    lines.append("")
    lines.append("This project uses a local **Project Continuity Layer** shared by ALL")
    lines.append("workers — Claude Code, Codex, GLM, other agents and humans. It is the")
    lines.append("source of truth for project state: append-only event ledger, shared task")
    lines.append("board with work claims, decision records, a human+AI project room, and")
    lines.append("the current handoff. The project owns the knowledge; your session is")
    lines.append("replaceable.")
    lines.append("")
    lines.append("MCP server `continuity` exposes the tools (get_handoff, room_send,")
    lines.append("task_claim, ...; via the Claude Code plugin they appear under the")
    lines.append("mcp__plugin_continuity_continuity__ prefix). Follow this protocol:")
    lines.append("")
    lines.append("1. **Session start**: call `get_handoff`, then `check_inbox` (messages")
    lines.append("   addressed to you) and `room_read`. Do not rely on prior chat memory")
    lines.append("   and do not re-discover the repo from scratch. Inbox items tagged")
    lines.append("   [MASTER-DIRECTIVE] come from a project that rules this one — binding;")
    lines.append("   [SUGGESTION]/[ADVICE] are input, not orders.")
    lines.append("2. **Before working**: check `task_list`; `task_claim` an existing task")
    lines.append("   or `task_create` then claim it. Declare `expected_scope` paths.")
    lines.append("   Heed scope-overlap warnings — coordinate in the room first.")
    lines.append("3. **While working**: announce intent and ask questions with `room_send`")
    lines.append("   (msg_type directive/claim/challenge/chat); poll `room_read` with")
    lines.append("   `since_seq` for replies. Record durable choices via")
    lines.append("   `decision_propose` / `decision_resolve` — never only in chat.")
    lines.append("4. **Session end**: `task_report` with evidence (tests run, commits),")
    lines.append("   then `update_handoff` (objective / what_changed / active_work /")
    lines.append("   blockers / risks / next_actions) so the next worker — possibly a")
    lines.append("   different tool or model — resumes cold without a rebrief.")
    lines.append("5. **Drift Guard**: if any response carries a `stale_context_warning`,")
    lines.append("   re-run `get_handoff` before further writes.")
    lines.append("")
    lines.append("If MCP tools are unavailable in this session, use the CLI equivalents")
    lines.append("(same database, same room):")
    lines.append("`python3 %s status|handoff|room|task|decision|log --help`" % path)
    lines.append(MANAGED_END)
    return "\n".join(lines)


def install_instructions(project_id, root_path, db_path, files=None):
    if not root_path or not Path(root_path).is_dir():
        raise ContinuityError(
            "project root %s does not exist; re-run init in the project dir"
            % (root_path or "(unset)"))
    block = managed_instruction_block(project_id, db_path)
    results = []
    filenames = list(files or ["AGENTS.md", "CLAUDE.md"])
    for filename in filenames:
        target = Path(root_path) / filename
        # One source of truth: when writing the default pair, CLAUDE.md
        # becomes a symlink to AGENTS.md unless the user already has a real
        # CLAUDE.md (never clobber their content with a link).
        if filename == "CLAUDE.md" and "AGENTS.md" in filenames \
                and files is None:
            if target.is_symlink():
                results.append({"file": str(target),
                                "action": "already links to AGENTS.md"})
                continue
            if not target.exists():
                target.symlink_to("AGENTS.md")
                results.append({"file": str(target),
                                "action": "symlinked to AGENTS.md"})
                continue
        if target.exists():
            text = target.read_text()
            begin = text.find(MANAGED_BEGIN)
            end = text.find(MANAGED_END)
            if begin != -1 and end != -1:
                new_text = text[:begin] + block + text[end + len(MANAGED_END):]
                action = "updated managed block"
            else:
                sep = "" if text.endswith("\n\n") else ("\n" if text.endswith("\n") else "\n\n")
                new_text = text + sep + block + "\n"
                action = "appended managed block"
        else:
            new_text = block + "\n"
            action = "created with managed block"
        target.write_text(new_text)
        results.append({"file": str(target), "action": action})
    return {"ok": True, "files": results}


GIT_HOOK_TEMPLATE = """#!/bin/sh
# continuity post-commit hook (managed): record commits in the project ledger.
sha=$(git rev-parse --short HEAD)
branch=$(git rev-parse --abbrev-ref HEAD)
subject=$(git log -1 --pretty=%s)
author=$(git log -1 --pretty=%an)
# Build the JSON payload in Python so quotes/backticks/$() in branch names or
# commit subjects can never break out of the shell string.
payload=$(python3 -c 'import json,sys;print(json.dumps({{"sha":sys.argv[1],"branch":sys.argv[2],"subject":sys.argv[3]}}))' "$sha" "$branch" "$subject")
python3 "{script}" --db "{db}" --project "{project}" --actor "$author" \\
  --actor-type human event append --type git.commit --payload "$payload" \\
  >/dev/null 2>&1 || true
"""


def install_git_hook(project_id, root_path, db_path):
    git_dir = Path(root_path or ".") / ".git"
    if not git_dir.is_dir():
        raise ContinuityError("%s is not a git repository (no .git directory)" % root_path)
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "post-commit"
    content = GIT_HOOK_TEMPLATE.format(script=script_path(), db=db_path,
                                       project=project_id)
    if hook_path.exists():
        existing = hook_path.read_text()
        if "continuity post-commit hook" not in existing:
            raise ContinuityError(
                "%s already exists and is not managed by continuity; merge manually"
                % hook_path)
    hook_path.write_text(content)
    hook_path.chmod(0o755)
    return {"ok": True, "hook": str(hook_path)}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="continuity.py",
        description="Local Project Continuity Layer: shared event ledger, task "
                    "claims, decisions, project room and handoff for humans and "
                    "AI coding agents (Claude Code, Codex, GLM, ...).")
    parser.add_argument("--db", default=None,
                        help="database path (default $%s or %s)" % (ENV_DB, DEFAULT_DB))
    parser.add_argument("--project", default=None,
                        help="project id (default $%s or auto-detect by cwd)" % ENV_PROJECT)
    parser.add_argument("--actor", default=None,
                        help="actor id (default $%s or $USER)" % ENV_ACTOR)
    parser.add_argument("--actor-type", default=None,
                        choices=["human", "agent", "system"],
                        help="actor type (default $%s, else 'human' for CLI)" % ENV_ACTOR_TYPE)
    parser.add_argument("--json", action="store_true",
                        help="print raw JSON instead of human-readable output")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("init", help="register the current directory as a project")
    p.add_argument("path", nargs="?", default=None)
    p.add_argument("--project-id", default=None)
    p.add_argument("--name", default=None)
    p.add_argument("--move", action="store_true",
                   help="allow re-pointing an existing project id to a new root")

    sub.add_parser("projects", help="list projects in this continuity database")
    sub.add_parser("status", help="project + actor status")
    p = sub.add_parser("log", help="curated project log")
    p.add_argument("-n", "--limit", type=int, default=40)

    p = sub.add_parser("handoff", help="show or update the handoff")
    hsub = p.add_subparsers(dest="handoff_cmd")
    hsub.add_parser("show")
    ph = hsub.add_parser("history", help="all handoff versions")
    ph.add_argument("-n", "--limit", type=int, default=20)
    ps = hsub.add_parser("set", help="update handoff fields")
    for field in HANDOFF_FIELDS:
        ps.add_argument("--%s" % field.replace("_", "-"), dest=field, default=None)

    p = sub.add_parser("search", help="search everything: events, messages, "
                                      "tasks, decisions, handoffs")
    p.add_argument("query")
    p.add_argument("-n", "--limit", type=int, default=20)

    sub.add_parser("overview", help="one-screen tour of everything stored "
                                    "for this project")

    p = sub.add_parser("bridge", help="link projects so rooms/inboxes mirror")
    bsub = p.add_subparsers(dest="bridge_cmd")
    pb = bsub.add_parser("add")
    pb.add_argument("other_project")
    pb.add_argument("--boss", default=None,
                    help="project id whose directors rule the other "
                         "(master/subordinate)")
    pb.add_argument("--advisor", default=None,
                    help="project id that advises the other (no authority)")
    pb = bsub.add_parser("remove")
    pb.add_argument("other_project")
    bsub.add_parser("list")

    p = sub.add_parser("room", help="project room messaging")
    rsub = p.add_subparsers(dest="room_cmd")
    pr = rsub.add_parser("send")
    pr.add_argument("--type", dest="msg_type", default="chat", choices=MSG_TYPES)
    pr.add_argument("--body", required=True)
    pr.add_argument("--mentions", default=None, help="comma-separated actor ids")
    pr.add_argument("--task", dest="task_id", default=None)
    pr.add_argument("--to", dest="to_project", default=None,
                    help="target project id (cross-project message)")
    pr = rsub.add_parser("read")
    pr.add_argument("--since", dest="since_seq", type=int, default=None)
    pr.add_argument("-n", "--limit", type=int, default=30)
    pr = rsub.add_parser("tail", help="follow the room (poll loop)")
    pr.add_argument("--interval", type=float, default=2.0)

    p = sub.add_parser("inbox", help="your inbox: messages mentioning or "
                                     "replying to you (persistent read cursor)")
    p.add_argument("-n", "--limit", type=int, default=50)
    p.add_argument("--keep-unread", action="store_true",
                   help="peek without advancing your read cursor")

    p = sub.add_parser("lead", help="show or set the project's Lead Director")
    p.add_argument("agent_id", nargs="?", default=None,
                   help="actor id to make lead (omit to show current)")
    p.add_argument("--clear", action="store_true", help="remove the lead")

    p = sub.add_parser("task", help="task board")
    tsub = p.add_subparsers(dest="task_cmd")
    pt = tsub.add_parser("create")
    pt.add_argument("title")
    pt.add_argument("--description", default=None)
    pt.add_argument("--scope", default=None, help="comma-separated paths/globs")
    pt.add_argument("--depends-on", default=None, help="comma-separated task ids")
    pt.add_argument("--risk", default="medium", choices=RISK_LEVELS)
    pt = tsub.add_parser("list")
    pt.add_argument("--status", default=None, choices=TASK_STATUSES)
    pt = tsub.add_parser("show")
    pt.add_argument("task_id")
    pt = tsub.add_parser("claim")
    pt.add_argument("task_id")
    pt.add_argument("--scope", default=None, help="comma-separated paths/globs")
    pt.add_argument("--lease", type=int, default=60, help="lease minutes")
    pt = tsub.add_parser("report")
    pt.add_argument("task_id")
    pt.add_argument("--summary", required=True)
    pt.add_argument("--state", default="review",
                    choices=["review", "done", "blocked", "queued"])
    pt.add_argument("--evidence", default=None,
                    help="JSON array of evidence objects")
    pt = tsub.add_parser("release")
    pt.add_argument("task_id")
    pt.add_argument("--reason", default=None)
    pt = tsub.add_parser("set-status")
    pt.add_argument("task_id")
    pt.add_argument("status", choices=TASK_STATUSES)
    pt.add_argument("--reason", default=None)

    p = sub.add_parser("decision", help="decision records")
    dsub = p.add_subparsers(dest="decision_cmd")
    pd = dsub.add_parser("propose")
    pd.add_argument("title")
    pd.add_argument("--detail", default=None)
    pd.add_argument("--rationale", default=None)
    pd = dsub.add_parser("resolve")
    pd.add_argument("decision_id")
    pd.add_argument("resolution", choices=DECISION_RESOLUTIONS)
    pd.add_argument("--rationale", default=None)
    pd = dsub.add_parser("list")
    pd.add_argument("--status", default=None)

    p = sub.add_parser("agent", help="agent registry")
    asub = p.add_subparsers(dest="agent_cmd")
    pa = asub.add_parser("register")
    pa.add_argument("--id", dest="agent_id", default=None)
    pa.add_argument("--name", dest="display_name", default=None)
    pa.add_argument("--role", default=None)
    pa.add_argument("--runtime", default=None)
    asub.add_parser("list")

    p = sub.add_parser("event", help="raw ledger operations")
    esub = p.add_subparsers(dest="event_cmd")
    pe = esub.add_parser("append")
    pe.add_argument("--type", dest="event_type", required=True)
    pe.add_argument("--payload", default="{}", help="JSON object")
    pe.add_argument("--task", dest="task_id", default=None)
    pe = esub.add_parser("tail")
    pe.add_argument("-n", "--limit", type=int, default=20)
    pe = esub.add_parser("show", help="full detail of one ledger event")
    pe.add_argument("seq", type=int)
    esub.add_parser("verify", help="verify hash chain + sequence integrity")

    p = sub.add_parser("freshness", help="Drift Guard check")
    p.add_argument("--context-version", type=int, default=None)

    p = sub.add_parser("serve", help="host the continuity server "
                                     "(REST API + MCP over HTTP) — the app "
                                     "owns the state; tools are clients")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--verbose", action="store_true")

    p = sub.add_parser("connect", help="thin stdio MCP client of the hosted "
                                       "server (what the plugin and stdio-only "
                                       "tools spawn; auto-registers the project)")
    p.add_argument("--url", default=None,
                   help="server URL (default $CONTINUITY_URL or %s)" % DEFAULT_URL)

    p = sub.add_parser("mcp", help="run the MCP stdio server (direct-DB "
                                   "fallback for tools without HTTP MCP)")

    p = sub.add_parser("setup", help="one-shot project setup: register this "
                                     "directory, write .mcp.json, install the "
                                     "agent protocol block")
    p.add_argument("tools", nargs="*", default=None,
                   help="with --details: subset (claude codex gemini opencode glm cli)")
    p.add_argument("--url", default=DEFAULT_URL,
                   help="continuity server URL (default %s)" % DEFAULT_URL)
    p.add_argument("--stdio", action="store_true",
                   help="wire tools as local stdio shims instead of clients "
                        "of the hosted server")
    p.add_argument("--no-instructions", action="store_true",
                   help="skip writing CLAUDE.md/AGENTS.md")
    p.add_argument("--here", action="store_true",
                   help="register THIS directory as its own project even if "
                        "it sits inside another registered project")
    p.add_argument("--no-server", action="store_true",
                   help="do not auto-start the continuity server")
    p.add_argument("--skip-tools", default=None,
                   help="comma-separated tools NOT to configure "
                        "(codex,cline,cursor,windsurf,gemini,vscode,opencode); "
                        "'all' configures none of them")
    p.add_argument("-i", "--interactive", action="store_true",
                   help="ask questions: your identity, extra projects to "
                        "register, tools to wire, bridges + relationships")
    p.add_argument("--owner", default=None,
                   help="your name for attribution — every ledger event and "
                        "agent gets tagged with it, and actor ids become "
                        "<you>.<agent> so identities never collide")
    p.add_argument("--details", action="store_true",
                   help="print the full per-tool configuration reference "
                        "instead of running setup")

    p = sub.add_parser("install-instructions",
                       help="write managed continuity block into CLAUDE.md/AGENTS.md")
    p.add_argument("--files", default=None,
                   help="comma-separated filenames (default CLAUDE.md,AGENTS.md)")

    sub.add_parser("install-hooks", help="install git post-commit ledger hook")
    return parser


def human_print(result, command=None):
    """Render common result shapes in a terminal-friendly way."""
    if isinstance(result, dict) and "log" in result:
        for line in result["log"]:
            print(line)
        return
    if isinstance(result, dict) and "messages" in result:
        if not result["messages"] and "unread_broadcasts" in result:
            print("inbox empty")
        for msg in result["messages"]:
            origin = (" via %s" % msg["origin_project"]) if msg.get("origin_project") else ""
            task = (" [%s]" % msg["task_id"]) if msg.get("task_id") else ""
            auth = (" [%s]" % msg["authority"].upper()) if msg.get("authority") else ""
            mentions = (" @" + ",@".join(str(m) for m in msg["mentions"])) \
                if msg.get("mentions") else ""
            print("#%-4d %s  %s%s (%s)%s%s%s: %s" % (
                msg["seq"], msg["at"][:19].replace("T", " "), msg["actor"], origin,
                msg["msg_type"], auth, task, mentions, msg["body"]))
        if "next_since_seq" in result:
            print("-- next_since_seq: %s" % result["next_since_seq"])
        if "unread_broadcasts" in result:
            print("-- other unread room messages (not addressed to you): %d"
                  % result["unread_broadcasts"])
        return
    if isinstance(result, dict) and "query" in result and "events" in result:
        for hit in result["events"]:
            print("event #%-4d %s" % (hit["seq"], hit["line"]))
        for task in result["tasks"]:
            print("task  %-6s %-8s %s" % (task["task_id"], task["status"],
                                          task["title"]))
        for dec in result["decisions"]:
            print("decn  %-6s %-8s %s" % (dec["decision_id"], dec["status"],
                                          dec["title"]))
        for h in result["handoff_versions"]:
            print("hand  v%-5d by %s at %s" % (h["version"], h["updated_by"],
                                               (h["updated_at"] or "")[:19]))
        print("-- %d hit(s) for %r" % (result["total_hits"], result["query"]))
        return
    if isinstance(result, dict) and "tasks" in result:
        if not result["tasks"]:
            print("no tasks")
        for task in result["tasks"]:
            lease = ""
            if task["status"] == "claimed":
                lease = " by %s until %s%s" % (
                    task.get("claimed_by"), (task.get("lease_until") or "")[:19],
                    " (EXPIRED)" if task.get("lease_expired") else "")
            print("%-6s %-8s %s%s" % (task["task_id"], task["status"],
                                      task["title"], lease))
            if task.get("expected_scope"):
                print("       scope: %s" % ", ".join(task["expected_scope"]))
        return
    if isinstance(result, dict) and "decisions" in result and command == "decision":
        if not result["decisions"]:
            print("no decisions")
        for dec in result["decisions"]:
            print("%-6s %-10s %s" % (dec["decision_id"], dec["status"], dec["title"]))
            if dec.get("rationale"):
                print("       rationale: %s" % dec["rationale"])
        return
    if isinstance(result, dict) and "agents" in result:
        if not result["agents"]:
            print("no agents registered")
        for agent in result["agents"]:
            print("%-28s %-14s %-14s owner:%-10s last seen %s" % (
                agent["agent_id"], agent.get("role") or "-",
                agent.get("runtime") or "-", agent.get("owner") or "-",
                (agent.get("last_seen_at") or "-")[:19]))
        return
    print(json.dumps(result, indent=2, ensure_ascii=False))


def cli_main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    # Resolve to an absolute path: MCP servers and hooks may run from any cwd.
    db_path = Path(args.db or os.environ.get(ENV_DB) or DEFAULT_DB).expanduser().resolve()
    owner = load_owner()
    set_current_owner(owner)
    actor = args.actor or os.environ.get(ENV_ACTOR) or os.environ.get("USER") or "human"
    actor = qualify_actor(actor, owner=owner)
    actor_type = args.actor_type or os.environ.get(ENV_ACTOR_TYPE) or "human"
    default_project = args.project or os.environ.get(ENV_PROJECT)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "serve":
        run_server(db_path, host=args.host, port=args.port,
                   default_project=default_project, verbose=args.verbose)
        return 0

    if args.command == "connect":
        run_connect_proxy(url=args.url,
                          actor=args.actor or os.environ.get(ENV_ACTOR),
                          actor_type=args.actor_type
                          or os.environ.get(ENV_ACTOR_TYPE))
        return 0

    if args.command == "mcp":
        session = McpSession(db_path, default_project=default_project,
                             actor=args.actor or os.environ.get(ENV_ACTOR),
                             actor_type=args.actor_type
                             or os.environ.get(ENV_ACTOR_TYPE) or "agent")
        session.serve()
        return 0

    conn = connect(db_path)

    def project():
        return resolve_project_id(conn, explicit=None, default=default_project)

    result = None
    cmd = args.command

    if cmd == "init":
        result = project_init(conn, actor, actor_type, path=args.path,
                              project_id=args.project_id, name=args.name,
                              move=args.move)
    elif cmd == "projects":
        result = list_projects(conn)
    elif cmd == "status":
        result = project_status(conn, project(), actor, actor_type, db_path)
    elif cmd == "log":
        result = project_log(conn, project(), limit=args.limit)
    elif cmd == "handoff":
        if args.handoff_cmd == "set":
            updates = {field: getattr(args, field) for field in HANDOFF_FIELDS}
            result = update_handoff(conn, project(), actor, actor_type, updates)
        elif args.handoff_cmd == "history":
            result = handoff_history(conn, project(), limit=args.limit)
        else:
            result = get_handoff(conn, project(), actor_id=actor)
    elif cmd == "search":
        result = search_project(conn, project(), args.query, limit=args.limit)
    elif cmd == "overview":
        proj = project()
        print("== status ==")
        human_print(project_status(conn, proj, actor, actor_type, db_path))
        print("\n== open tasks ==")
        human_print(task_list(conn, proj), command="task")
        print("\n== decisions ==")
        human_print(decision_list(conn, proj), command="decision")
        print("\n== agents ==")
        human_print(agent_list(conn, proj))
        print("\n== bridges ==")
        bridges = bridge_list(conn, proj)["bridges"]
        if not bridges:
            print("none")
        for b in bridges:
            rel = "" if b["relation"] == "peer" else \
                " (%s: %s)" % (b["relation"], b["principal"])
            print("%s%s" % (b["with"], rel))
        print("\n== your inbox ==")
        human_print(inbox_read(conn, proj, actor, mark_read=False))
        print("\n== recent log ==")
        human_print(project_log(conn, proj, limit=15))
        print("\n== handoff ==")
        handoff = get_handoff(conn, proj)
        for field in HANDOFF_FIELDS:
            value = handoff["handoff"].get(field)
            if value:
                print("%-13s %s" % (field + ":", value))
        print("context version: v%d   lead: %s"
              % (handoff["context_version"],
                 handoff.get("lead_director") or "(none)"))
        return 0
    elif cmd == "bridge":
        if args.bridge_cmd == "add":
            result = bridge_add(conn, project(), actor, actor_type,
                                args.other_project, boss=args.boss,
                                advisor=args.advisor)
        elif args.bridge_cmd == "remove":
            result = bridge_remove(conn, project(), actor, actor_type,
                                   args.other_project)
        else:
            result = bridge_list(conn, project())
    elif cmd == "room":
        if args.room_cmd == "send":
            target = args.to_project or project()
            origin = None
            if args.to_project:
                try:
                    origin = project()
                except ContinuityError:
                    origin = None
            result = room_send(conn, target, actor, actor_type, body=args.body,
                               msg_type=args.msg_type,
                               mentions=args.mentions.split(",") if args.mentions else None,
                               task_id=args.task_id, origin_project=origin)
        elif args.room_cmd == "tail":
            proj = project()
            since = room_read(conn, proj, limit=15)
            human_print(since)
            cursor = since["next_since_seq"]
            print("-- following %s (Ctrl-C to stop) --" % proj)
            try:
                while True:
                    time.sleep(args.interval)
                    batch = room_read(conn, proj, since_seq=cursor, limit=100)
                    if batch["messages"]:
                        human_print(batch)
                    cursor = batch["next_since_seq"]
            except KeyboardInterrupt:
                return 0
        else:
            result = room_read(conn, project(),
                               since_seq=getattr(args, "since_seq", None),
                               limit=getattr(args, "limit", 30))
    elif cmd == "inbox":
        result = inbox_read(conn, project(), actor,
                            mark_read=not args.keep_unread, limit=args.limit)
    elif cmd == "lead":
        proj = project()
        if args.clear:
            result = set_lead_director(conn, proj, actor, actor_type, None)
        elif args.agent_id:
            result = set_lead_director(conn, proj, actor, actor_type,
                                       args.agent_id)
        else:
            result = {"project": proj,
                      "lead_director": get_project(conn, proj).get("lead_director")}
    elif cmd == "task":
        if args.task_cmd == "create":
            result = task_create(conn, project(), actor, actor_type,
                                 title=args.title, description=args.description,
                                 expected_scope=args.scope.split(",") if args.scope else None,
                                 dependencies=args.depends_on.split(",") if args.depends_on else None,
                                 risk_level=args.risk)
        elif args.task_cmd == "list":
            result = task_list(conn, project(), status=args.status)
        elif args.task_cmd == "show":
            result = task_show(conn, project(), args.task_id)
        elif args.task_cmd == "claim":
            result = task_claim(conn, project(), actor, actor_type, args.task_id,
                                expected_scope=args.scope.split(",") if args.scope else None,
                                lease_minutes=args.lease)
        elif args.task_cmd == "report":
            try:
                evidence = json.loads(args.evidence) if args.evidence else None
            except json.JSONDecodeError as err:
                raise ContinuityError(
                    "--evidence must be valid JSON (an array of objects): %s" % err)
            result = task_report(conn, project(), actor, actor_type, args.task_id,
                                 summary=args.summary, evidence=evidence,
                                 requested_state=args.state)
        elif args.task_cmd == "release":
            result = task_release(conn, project(), actor, actor_type, args.task_id,
                                  reason=args.reason)
        elif args.task_cmd == "set-status":
            result = task_set_status(conn, project(), actor, actor_type,
                                     args.task_id, args.status, reason=args.reason)
        else:
            result = task_list(conn, project())
    elif cmd == "decision":
        if args.decision_cmd == "propose":
            result = decision_propose(conn, project(), actor, actor_type,
                                      title=args.title, detail=args.detail,
                                      rationale=args.rationale)
        elif args.decision_cmd == "resolve":
            result = decision_resolve(conn, project(), actor, actor_type,
                                      args.decision_id, args.resolution,
                                      rationale=args.rationale)
        else:
            result = decision_list(conn, project(),
                                   status=getattr(args, "status", None))
    elif cmd == "agent":
        if args.agent_cmd == "register":
            result = agent_register(conn, project(), actor, actor_type,
                                    agent_id=args.agent_id,
                                    display_name=args.display_name,
                                    role=args.role, runtime=args.runtime)
        else:
            result = agent_list(conn, project())
    elif cmd == "event":
        if args.event_cmd == "append":
            try:
                payload = json.loads(args.payload)
            except json.JSONDecodeError as err:
                raise ContinuityError("--payload must be valid JSON: %s" % err)
            if not isinstance(payload, dict):
                raise ContinuityError("--payload must be a JSON object")
            result = {"ok": True,
                      "event": append_event(conn, project(), actor, actor_type,
                                            args.event_type, payload,
                                            task_id=args.task_id)}
        elif args.event_cmd == "show":
            result = event_show(conn, project(), args.seq)
        elif args.event_cmd == "verify":
            result = verify_ledger(conn, project())
        else:
            proj = project()
            rows = conn.execute(
                "SELECT * FROM events WHERE project_id=? ORDER BY seq DESC LIMIT ?",
                (proj, getattr(args, "limit", 20))).fetchall()
            result = {"project": proj, "log": [
                line for line in
                ("#%d %s" % (r["seq"], render_log_line(r) or
                             "%s %s" % (r["event_type"], r["actor_id"]))
                 for r in reversed(rows))]}
    elif cmd == "freshness":
        result = check_freshness(conn, project(), args.context_version)
    elif cmd == "setup":
        if args.details or args.tools:
            proj_id = None
            try:
                proj_id = project()
            except ContinuityError:
                pass
            print(setup_details_text(proj_id, db_path, url=args.url,
                                     tools=args.tools or None))
            return 0
        wanted_bridges = []
        if args.owner:
            save_owner(args.owner)
            owner = load_owner()
            set_current_owner(owner)
            actor = qualify_actor(args.actor or os.environ.get(ENV_ACTOR)
                                  or os.environ.get("USER") or "human",
                                  owner=owner)
            print("✔ identity: %s (stored in %s)" % (owner, IDENTITY_FILE))
        if args.interactive:
            def ask(prompt):
                try:
                    return input(prompt).strip()
                except EOFError:
                    return ""
            print("continuity interactive setup — press Enter to accept defaults")
            current = load_owner() or os.environ.get("USER") or ""
            name_in = ask("your name, for attribution in all logs [%s]: "
                          % (current or "none"))
            if name_in or not load_owner():
                save_owner(name_in or current or "user")
                owner = load_owner()
                set_current_owner(owner)
                actor = qualify_actor(args.actor or os.environ.get(ENV_ACTOR)
                                      or os.environ.get("USER") or "human",
                                      owner=owner)
                print("  identity: %s" % owner)
            url_in = ask("server URL [%s]: " % args.url)
            if url_in:
                args.url = url_in
            extra = ask("additional project dirs to register "
                        "(comma-separated paths, blank for none): ")
            for extra_path in filter(None, (s.strip() for s in extra.split(","))):
                registered = project_init(conn, actor, actor_type,
                                          path=extra_path)
                print("  registered: %s (%s)" % (registered["project_id"],
                                                 registered["root_path"]))
            skip_in = ask("tools to SKIP (codex,cline,cursor,windsurf,gemini,"
                          "vscode,opencode; blank = wire all detected): ")
            if skip_in:
                args.skip_tools = skip_in
            # The current project may not be registered yet (that happens in
            # one_shot_setup below), so ANY known project is a bridge target.
            known = [r["project_id"] for r in
                     conn.execute("SELECT project_id FROM projects")]
            if known:
                bridge_in = ask("bridge this project with others? "
                                "(comma-separated ids from %s, blank for none): "
                                % ", ".join(known))
                for other in (s.strip() for s in bridge_in.split(",")):
                    if not other:
                        continue
                    rel = ask("relationship with %s? [1] equal peers  "
                              "[2] THIS project is the boss  [3] %s is the "
                              "boss  [4] THIS project advises  [5] %s advises "
                              "(default 1): " % (other, other, other)) or "1"
                    wanted_bridges.append((other, rel.strip()))
        if not load_owner() and os.environ.get(ENV_OWNER) is None:
            default_owner = os.environ.get("USER") or "user"
            save_owner(default_owner)
            owner = load_owner()
            set_current_owner(owner)
            actor = qualify_actor(args.actor or os.environ.get(ENV_ACTOR)
                                  or default_owner, owner=owner)
            print("✔ identity: %s — tagged on every log entry "
                  "(change with: setup --owner NAME)" % owner)
        skip = None
        if args.skip_tools:
            skip = ({"codex", "cline", "cursor", "windsurf", "gemini",
                     "vscode", "opencode"} if args.skip_tools.strip() == "all"
                    else {t.strip() for t in args.skip_tools.split(",")})
        info = one_shot_setup(conn, actor, actor_type, db_path, url=args.url,
                              stdio=args.stdio, here=args.here,
                              manage_server=not args.no_server,
                              skip_tools=skip,
                              write_instructions=not args.no_instructions)
        script = script_path()
        inside = "  (this folder is inside it — use --here to make ./ its own project)" \
            if info["cwd_inside_root"] else ""
        print("✔ project: %s  root: %s%s"
              % (info["project_id"], info["root_path"], inside))
        for other, rel in wanted_bridges:
            try:
                me = info["project_id"]
                boss = me if rel == "2" else (other if rel == "3" else None)
                adv = me if rel == "4" else (other if rel == "5" else None)
                added = bridge_add(conn, me, actor, actor_type, other,
                                   boss=boss, advisor=adv)
                print("✔ bridged with %s (%s%s)"
                      % (other, added["relation"],
                         ": %s" % added["principal"] if added["principal"] else ""))
            except ContinuityError as err:
                print("· bridge with %s skipped: %s" % (other, err))
        if info["mode"] == "server":
            server = info["server"]
            if server["managed"]:
                print("✔ server: %s at %s%s"
                      % ("started" if server["started"] else "running",
                         info["url"],
                         ("  (log: %s)" % server["log"]) if server["log"] else ""))
            else:
                print("· server not started (--no-server) — start it with: "
                      "python3 %s serve" % script_path())
        print("✔ claude code (+ GLM via Claude-compatible CLIs): %s"
              % info["mcp_json"])
        for entry in info["configured_tools"]:
            print("✔ %s: %s" % (entry["tool"], entry["path"]))
        if info["instruction_files"]:
            print("✔ agent instructions: %s"
                  % ", ".join(Path(f).name for f in info["instruction_files"]))
        if info["not_detected"]:
            print("· not detected (skipped): %s" % ", ".join(info["not_detected"]))
        print()
        print("Done — restart your coding tools in this folder.")
        print("Any other MCP client (Grok, Zed, ...): `setup --details` prints "
              "generic configs. Live feed: python3 %s room tail" % script)
        return 0
    elif cmd == "install-instructions":
        proj_id = project()
        root = get_project(conn, proj_id).get("root_path")
        files = args.files.split(",") if args.files else None
        result = install_instructions(proj_id, root, db_path, files=files)
    elif cmd == "install-hooks":
        proj_id = project()
        root = get_project(conn, proj_id).get("root_path")
        result = install_git_hook(proj_id, root, db_path)
    else:
        parser.print_help()
        return 1

    if result is not None:
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            human_print(result, command=cmd)
    return 0


def main():
    try:
        sys.exit(cli_main())
    except ContinuityError as err:
        sys.stderr.write("error: %s\n" % err)
        sys.exit(2)
    except BrokenPipeError:
        sys.exit(0)


if __name__ == "__main__":
    main()
