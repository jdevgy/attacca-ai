#!/usr/bin/env python3
"""
attacca.py — Local Project Attacca Layer (blueprint Phase 0 dogfood build).

One zero-dependency file (Python 3.8+, stdlib only) implementing the
"Project Attacca Layer" from the Multi-Agent Developer SaaS blueprint:

  * Append-only event ledger (SQLite, per-project sequence, hash-chained)
  * Project Room (structured messages: chat/directive/claim/handoff/...)
  * Tasks, work claims with leases, scope-overlap warnings, evidence reports
  * Decision records
  * Current handoff snapshot + context versioning (Drift Guard lite)
  * Agent identity registry
  * Hosted HTTP MCP plus a stdio connect shim for coding-tool clients
  * CLI for humans and non-MCP tools

No encryption in this build (deliberately deferred). The hosted server owns
the shared SQLite state; installed tools spawn a small stdio client that
forwards MCP requests to that server.

Usage:
  attacca.py init [--project-id ID] [--name NAME] [PATH]
  attacca.py mcp                     # run MCP stdio server
  attacca.py status | log | handoff | room | task | decision | agent ...
  attacca.py setup [--write-mcp-json]   # per-tool config snippets
  attacca.py install-instructions       # managed CLAUDE.md/AGENTS.md block
Run `attacca.py --help` for everything.
"""

import argparse
import base64
import contextlib
import fnmatch
import getpass
import hashlib
import hmac
import http.cookies
import io
import importlib.util
import json
import os
import random
import re
import secrets
import signal
import shlex
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import MappingProxyType

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows keeps thread serialization
    fcntl = None

VERSION = "0.5.0"
MCP_SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18")
MCP_DEFAULT_PROTOCOL = "2025-06-18"
DEFAULT_UPDATE_INTERVAL_SECONDS = 60

_PAIRING_LOOKUP_FAILURES = {}
_PAIRING_LOOKUP_FAILURES_LOCK = threading.Lock()
_PAIRING_LOOKUP_WINDOW_SECONDS = 60
_PAIRING_LOOKUP_MAX_FAILURES = 5

ENV_DB = "ATTACCA_DB"
ENV_PROJECT = "ATTACCA_PROJECT"
ENV_ACTOR = "ATTACCA_ACTOR"
ENV_ACTOR_TYPE = "ATTACCA_ACTOR_TYPE"
ENV_API_TOKEN = "ATTACCA_API_TOKEN"
PROJECT_LINK_SCHEMA_VERSION = 1
PROJECT_LINK_DIR = ".attacca"
PROJECT_LINK_NAME = "project.json"
REPOSITORY_FINGERPRINT_HEADER = "X-Attacca-Repository"
GIT_BRANCH_HEADER = "X-Attacca-Git-Branch"
GIT_REVISION_HEADER = "X-Attacca-Git-Revision"
DEVICE_HEADER = "X-Attacca-Device"
SYNC_DEVICE_HEADER = "X-Attacca-Device-ID"
CLIENT_INSTANCE_HEADER = "X-Attacca-Client-Instance"
ENV_DEVICE = "ATTACCA_DEVICE_ID"
ENV_CLIENT_INSTANCE = "ATTACCA_CLIENT_INSTANCE"
_CLIENT_INSTALL_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,239}$")


def _migrate_legacy_state():
    """One-time rename for pre-Attacca installs: ~/.continuity -> ~/.attacca,
    and continuity.db -> attacca.db inside it. Skipped when ATTACCA_DB points
    somewhere explicit. If BOTH dirs exist (something recreated the legacy
    one), the legacy database is still moved over, provided the new home has
    no database of its own yet."""
    if os.environ.get(ENV_DB):
        return
    old_home = Path.home() / ".continuity"
    new_home = Path.home() / ".attacca"
    try:
        if old_home.is_dir() and not new_home.exists():
            old_home.rename(new_home)
        elif old_home.is_dir() and new_home.is_dir():
            for name in ("identity.json",):
                src, dst = old_home / name, new_home / name
                if src.exists() and not dst.exists():
                    src.rename(dst)
            for suffix in ("", "-wal", "-shm"):
                src = old_home / ("continuity.db" + suffix)
                dst = new_home / ("attacca.db" + suffix)
                if src.exists() and not dst.exists():
                    src.rename(dst)
        if new_home.is_dir():
            for suffix in ("", "-wal", "-shm"):
                src = new_home / ("continuity.db" + suffix)
                if src.exists():
                    src.rename(new_home / ("attacca.db" + suffix))
    except OSError:
        pass  # best effort; an explicit path still works via ATTACCA_DB


_migrate_legacy_state()

DEFAULT_DB = Path(os.environ.get(ENV_DB) or (Path.home() / ".attacca" / "attacca.db"))

GENESIS_HASH = "0" * 64

MSG_TYPES = ["chat", "directive", "claim", "handoff", "challenge",
             "decision", "approval", "status", "system"]
TASK_STATUSES = ["queued", "claimed", "blocked", "review", "done", "cancelled"]
RISK_LEVELS = ["low", "medium", "high"]
TASK_PLAN_STATUSES = ["draft", "in_review", "changes_requested", "approved"]
TASK_PLAN_REVIEW_TYPES = ["approval", "suggestion"]
TASK_PLAN_SUGGESTION_STATUSES = ["open", "addressed", "dismissed"]
DECISION_RESOLUTIONS = ["accepted", "rejected", "superseded"]
RULE_SCOPES = ["everyone", "director", "advisor", "worker"]
HANDOFF_FIELDS = ["objective", "what_changed", "active_work", "blockers",
                  "risks", "next_actions", "notes"]

# Room chat/status noise is excluded from the curated project log.
LOG_EXCLUDED_MSG_TYPES = {"chat", "status"}

MANAGED_BEGIN = "<!-- MANAGED_ATTACCA:BEGIN"
MANAGED_END = "<!-- MANAGED_ATTACCA:END -->"
MANAGED_BLOCK_VERSION = 12
_MANAGED_TEMPLATE_PROJECT = "attacca-project"
_MANAGED_BEGIN_LINE = re.compile(
    r"(?m)^<!-- MANAGED_ATTACCA:BEGIN\b[^\r\n]*-->[ \t]*\r?$")
_MANAGED_END_LINE = re.compile(
    r"(?m)^<!-- MANAGED_ATTACCA:END -->[ \t]*\r?$")


class AttaccaError(Exception):
    """User-facing error (bad input, unknown project, conflict...)."""


class AuthenticationError(AttaccaError):
    """Missing or invalid account/session/API token."""


class AuthorizationError(AttaccaError):
    """Authenticated account lacks permission for the operation."""


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


ENV_OWNER = "ATTACCA_OWNER"
IDENTITY_FILE = Path.home() / ".attacca" / "identity.json"
CREDENTIALS_FILE = Path.home() / ".attacca" / "credentials.json"
MACHINE_CONFIG_SCHEMA_VERSION = 1
MACHINE_CONFIG_NAME = "config.json"
_MACHINE_CONFIG_THREAD_LOCK = threading.RLock()


def machine_config_path(home=None):
    """Return the one machine-local source of truth for the hosted URL."""
    return Path(home or Path.home()).expanduser().resolve() / \
        ".attacca" / MACHINE_CONFIG_NAME


def load_owner():
    """Who is running this machine's tools — for attribution. Env overrides
    the identity file; an empty env value disables owner attribution."""
    env = os.environ.get(ENV_OWNER)
    if env is not None:
        return env.strip() or None
    try:
        data = _terminal_flow_runtime().read_identity_store(IDENTITY_FILE)
        return (data.get("owner") or "").strip() or None
    except Exception:
        return None


def _atomic_private_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".%s." % path.name,
                                     dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(path))
        os.chmod(str(path), 0o600)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def save_owner(name):
    def update(identity):
        identity["owner"] = str(name).strip()
        return identity

    try:
        _terminal_flow_runtime().update_identity_store(
            IDENTITY_FILE, update)
    except Exception as error:
        raise AttaccaError(
            "Attacca machine identity could not be updated safely: %s" %
            error) from None
    return str(IDENTITY_FILE)


def load_device_id():
    override = os.environ.get(ENV_DEVICE)
    if override is not None:
        return override.strip() or None
    try:
        return _terminal_flow_runtime().load_device_id(
            identity_path=IDENTITY_FILE)
    except Exception as error:
        raise AttaccaError(
            "Attacca machine identity is not safe to use: %s" % error
        ) from None


def load_client_instance_id(runtime=None):
    """Return one stable installed-client id when no env override exists."""
    try:
        return _terminal_flow_runtime().load_client_instance_id(
            runtime=normalize_agent_runtime(runtime))
    except Exception as error:
        raise AttaccaError(
            "Attacca client-instance identity is not safe to use: %s" % error
        ) from None


def _credential_server_key(url):
    """Scope credentials to the complete canonical hosted base URL.

    Path-bearing deployments on one origin are independent trust boundaries;
    a token for ``/tenant-a`` must never be offered to ``/tenant-b``.
    Origin-only legacy keys remain identical for servers without a base path.
    """
    return _normalize_hosted_server_url(url)


def load_api_token(url, runtime=None, project_id=None, actor_id=None,
                   allow_human=False):
    override = os.environ.get(ENV_API_TOKEN)
    if override is not None:
        return override.strip() or None
    try:
        terminal_flow = _terminal_flow_runtime()
        data = terminal_flow.read_credentials_store(CREDENTIALS_FILE)
        server = terminal_flow.server_record_for_url(data, url)
        runtime = normalize_agent_runtime(runtime, actor_id)
        project_id = str(project_id or "").strip() or None
        actor_id = str(actor_id or "").strip() or None
        # D-17: one human-owned key authenticates this installed client. The
        # request's exact workspace/actor headers remain separate selectors.
        client_token = terminal_flow.load_client_api_key(
            url, client_instance=load_client_instance_id(runtime),
            project_id=project_id, runtime=runtime,
            credentials_path=CREDENTIALS_FILE)
        if client_token:
            return client_token
        # Compatibility-only legacy lookup. Enforced servers reject every
        # actor/terminal credential; this lets old installations reach the
        # upgrade/login surface before the owner flips enforcement.
        by_project = server.get("agent_tokens") or {}
        candidates = []
        projects = [project_id] if project_id else list(by_project)
        for candidate_project in projects:
            records = by_project.get(candidate_project) or {}
            if actor_id and actor_id in records:
                record = records[actor_id]
                return record.get("token") if isinstance(record, dict) \
                    else record
            if actor_id and "." in actor_id:
                # A dotted/full claim is an exact authorization selector.
                # Never offer another same-runtime actor's secret and rely on
                # the server to reject it after disclosure.
                continue
            for candidate_actor, record in records.items():
                if not isinstance(record, dict):
                    record = {"token": record}
                candidate_runtime = normalize_agent_runtime(
                    record.get("runtime"), candidate_actor)
                if candidate_runtime == runtime and record.get("token"):
                    candidates.append(record["token"])
        # A short runtime hint is safe only when it identifies exactly one
        # actor credential in the selected workspace (or exactly one across
        # an as-yet-unlinked machine).
        if len(set(candidates)) == 1:
            return candidates[0]
        # A server-level human credential is deliberately separate.  A
        # linked AI that lacks its own workspace/actor token must fail closed
        # instead of silently acting as the human account that ran setup.
        if allow_human and not project_id and not actor_id \
                and server.get("api_token"):
            return server["api_token"]
        # Legacy runtime-only entries have no workspace binding.  Continue to
        # read one only for an unscoped client where there is no possibility
        # of silently selecting it for a different linked repository.
        legacy = server.get("tokens") or {}
        if project_id is None and len(legacy) == 1:
            return legacy.get(runtime) or next(iter(legacy.values()))
        return None
    except Exception:
        return None


def require_usable_terminal_credential(url, runtime=None, project_id=None,
                                       actor_id=None):
    """Fail before I/O when this client-install key is known unusable.

    A missing credential may still probe a server in pre-activation
    compatibility mode. A present expired/wrong-device/corrupt/unbound modern
    credential must never be converted into an anonymous request or a verified
    offline fallback merely because the bearer loader correctly returned None.
    """
    try:
        terminal_flow = _terminal_flow_runtime()
        normalized_runtime = normalize_agent_runtime(runtime, actor_id)
        status = terminal_flow.client_api_key_status(
            url, client_instance=load_client_instance_id(normalized_runtime),
            project_id=project_id, runtime=normalized_runtime,
            credentials_path=CREDENTIALS_FILE)
    except Exception as error:
        raise AuthenticationError(
            "client_authorization_required: local client identity is "
            "invalid (%s)" % error) from None
    state = str(status.get("status") or "invalid")
    if state not in ("ready", "authorization_required"):
        raise AuthenticationError(
            "client_authorization_required: local client API key is %s"
            % state)
    return status


def save_api_token(url, token, runtime=None, project_id=None, actor_id=None):
    def update(data):
        data.setdefault("version", 1)
        server = _terminal_flow_runtime().canonical_server_record_for_update(
            data, url)
        if project_id or actor_id:
            if not project_id or not actor_id:
                raise AttaccaError(
                    "agent credentials require both project_id and actor_id")
            normalized_runtime = normalize_agent_runtime(runtime, actor_id)
            record = server.setdefault("agent_tokens", {}).setdefault(
                str(project_id), {}).setdefault(str(actor_id), {})
            record.update({"token": str(token).strip(),
                           "runtime": normalized_runtime})
        elif runtime is None:
            # Kept only for pre-terminal migration/rollback compatibility.
            server["api_token"] = str(token).strip()
        else:
            raise AttaccaError(
                "new agent credentials require project_id and actor_id; "
                "runtime-only credentials are legacy read-only records")
        return data

    try:
        _terminal_flow_runtime().update_credentials_store(
            CREDENTIALS_FILE, update)
    except Exception as error:
        if isinstance(error, AttaccaError):
            raise
        raise AttaccaError(str(error)) from None
    return str(CREDENTIALS_FILE)


def save_terminal_credential(url, token, token_id, device_id, bindings,
                             created_at=None, expires_at=None,
                             client_label=None, client_instance=None):
    credential = {
        "token": str(token).strip(),
        "token_kind": "terminal",
        "token_id": str(token_id or "").strip(),
        "device_id": str(device_id or "").strip(),
        "client_label": str(client_label or "").strip() or None,
        "client_instance": str(client_instance or "").strip() or None,
        "bindings": list(bindings or []),
        "created_at": created_at,
        "expires_at": expires_at,
    }
    try:
        _terminal_flow_runtime().save_terminal_credential(
            url, credential, device_id=device_id,
            credentials_path=CREDENTIALS_FILE)
    except Exception as error:
        raise AttaccaError(str(error)) from None
    return str(CREDENTIALS_FILE)


def delete_api_token(url, runtime=None, project_id=None, actor_id=None):
    """Forget one URL-scoped local credential without echoing its value."""
    changed = False

    def update(data):
        nonlocal changed
        existing = terminal_flow.server_record_for_url(data, url)
        if not existing:
            return data
        server = terminal_flow.canonical_server_record_for_update(data, url)
        if project_id or actor_id:
            if not project_id or not actor_id:
                return data
            projects = server.get("agent_tokens") or {}
            records = projects.get(str(project_id)) or {}
            changed = records.pop(str(actor_id), None) is not None
            if not records:
                projects.pop(str(project_id), None)
            if not projects:
                server.pop("agent_tokens", None)
        elif runtime is None:
            changed = server.pop("api_token", None) is not None
        else:
            tokens = server.get("tokens") or {}
            changed = tokens.pop(
                normalize_agent_runtime(runtime), None) is not None
            if not tokens:
                server.pop("tokens", None)
        return data

    try:
        terminal_flow = _terminal_flow_runtime()
        terminal_flow.update_credentials_store(CREDENTIALS_FILE, update)
    except Exception:
        return False
    return changed


# Attribution context: entry layers (CLI, MCP dispatch, HTTP routes) declare
# who owns the acting client; append_event stamps it on every ledger row.
_owner_ctx = threading.local()


def set_current_owner(owner):
    _owner_ctx.value = (owner or "").strip() or None


def current_owner():
    return getattr(_owner_ctx, "value", None)


# A direct/local project_init is a trusted application call. HTTP creation is
# different: owner/actor headers are untrusted in compatibility mode, so the
# creation transaction needs to know whether an authenticated user was
# actually established for this request.
_request_auth_ctx = threading.local()


def set_current_request_auth_user(user_id=None, active=True):
    _request_auth_ctx.active = bool(active)
    _request_auth_ctx.user_id = str(user_id or "").strip() or None


def current_request_auth_user():
    return (bool(getattr(_request_auth_ctx, "active", False)),
            getattr(_request_auth_ctx, "user_id", None))


# Per-request Git origin. The hosted server must use the caller's checkout,
# not its own filesystem: home and office clients may be on different branches.
_git_ctx = threading.local()


def set_current_git_context(branch=None, revision=None, device_id=None):
    _git_ctx.branch = (branch or "").strip() or None
    _git_ctx.revision = (revision or "").strip() or None
    _git_ctx.device_id = (device_id or "").strip() or None


def current_git_context():
    return {"branch": getattr(_git_ctx, "branch", None),
            "revision": getattr(_git_ctx, "revision", None),
            "device_id": getattr(_git_ctx, "device_id", None)}


def qualify_actor(actor, owner=None):
    """Return the client actor unchanged.

    Owner attribution is a separate, first-class event/agent column. Older
    builds prefixed it into actor ids (``jack.claude_director``), which made a
    person's name look like a workspace and split one project role into many
    identities. Keep this compatibility entry point, but never create another
    owner-prefixed actor.
    """
    return actor


AGENT_ROLES = ("director", "advisor", "worker")
_KNOWN_RUNTIMES = (
    "claude", "codex", "kimi", "cline", "cursor", "windsurf", "gemini",
    "vscode", "opencode", "glm",
)


def normalize_agent_runtime(runtime=None, actor=None):
    """Collapse client/version/session labels to the AI tool used for audit.

    Runtime is intentionally not authority: ``codex`` and ``claude`` actors
    registered as Directors have the same permissions. It remains in the id
    only so the activity ledger can show which AI performed the action.
    """
    values = [runtime, actor]
    for value in values:
        text = slugify(str(value or ""))
        if not text:
            continue
        for known in _KNOWN_RUNTIMES:
            if known in text.split("-") or known in text.split(".") \
                    or known in text:
                return known
    # Unknown/custom clients use their explicit actor hint; clientInfo names
    # such as "unittest-client" or "mcp-client" are transport labels, not a
    # more authoritative identity.
    fallback = slugify(str(actor or runtime or "agent"))
    for suffix in ("-director", "-advisor", "-worker", "-agent"):
        if fallback.endswith(suffix):
            fallback = fallback[:-len(suffix)]
            break
    return fallback or "agent"


def canonical_agent_id(project_id, role, runtime):
    """Stable operational identity: workspace.role.runtime."""
    role = (role or "unassigned").lower()
    if role not in AGENT_ROLES + ("unassigned",):
        raise AttaccaError("unknown agent role %r" % role)
    return "%s.%s.%s" % (
        slugify(project_id), role, normalize_agent_runtime(runtime))


def parse_canonical_agent_id(actor_id, project_id=None):
    """Return canonical identity parts, or None for a legacy/raw actor id."""
    text = str(actor_id or "")
    parts = text.rsplit(".", 2)
    if len(parts) != 3 or parts[1] not in AGENT_ROLES + ("unassigned",):
        return None
    if project_id is not None and parts[0] != slugify(project_id):
        return None
    return {"project_id": parts[0], "role": parts[1],
            "runtime": normalize_agent_runtime(parts[2])}


def legacy_actor_role_hint(actor_id):
    """Return an explicit role token carried by a pre-canonical actor id.

    This is used only during a user-confirmed role migration.  Generic client,
    QA, and session ids intentionally return None so setup cannot collapse
    unrelated personas merely because they use the same runtime.
    """
    tokens = [token for token in re.split(
        r"[^a-z0-9]+", str(actor_id or "").lower()) if token]
    return next((role for role in AGENT_ROLES if role in tokens), None)


def _matching_runtime(agent, runtime):
    stored = agent.get("runtime")
    normalized = normalize_agent_runtime(stored) if stored else \
        normalize_agent_runtime(actor=agent.get("agent_id"))
    return normalized == runtime


def registered_agent_identity(agents, project_id, actor_id, runtime=None):
    """Resolve a raw/legacy client actor to the current project role.

    This pure helper is shared by MCP and setup discovery. Prefer a canonical
    role row, then the exact legacy row, then the most recently seen matching
    runtime. Owner never participates in the lookup or authorization.
    """
    runtime = normalize_agent_runtime(runtime) if runtime else \
        normalize_agent_runtime(actor=actor_id)
    role_rows = [a for a in agents if a.get("role") in AGENT_ROLES and
                 _matching_runtime(a, runtime)]
    roles = sorted({a.get("role") for a in role_rows})
    if len(roles) > 1:
        return {
            "project_id": project_id,
            "role": None,
            "runtime": runtime,
            "actor_id": canonical_agent_id(project_id, None, runtime),
            "record": None,
            "conflict_roles": roles,
        }
    exact = next((a for a in role_rows if a.get("agent_id") == actor_id), None)
    canonical = next((a for a in role_rows
                      if parse_canonical_agent_id(a.get("agent_id"), project_id)),
                     None)
    chosen = canonical or exact
    if chosen is None and role_rows:
        chosen = sorted(role_rows,
                        key=lambda a: a.get("last_seen_at") or "")[-1]
    role = chosen.get("role") if chosen else None
    return {
        "project_id": project_id,
        "role": role,
        "runtime": runtime,
        "actor_id": canonical_agent_id(project_id, role, runtime),
        "record": chosen,
        "conflict_roles": [],
    }


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


def git_worktree_root(path=None):
    """Return the checkout root containing *path*, or the resolved path.

    Using the Git top-level keeps project identity stable when a coding tool is
    launched from a nested directory. Non-Git folders retain the old cwd-based
    behavior.
    """
    start = Path(path or os.getcwd()).resolve()
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=str(start),
            capture_output=True, text=True, timeout=5)
        root = proc.stdout.strip()
        if proc.returncode == 0 and root:
            return Path(root).resolve()
    except Exception:
        pass
    return start


def canonical_git_remote(remote):
    """Normalize common Git remote URL forms without credentials or scheme."""
    raw = str(remote or "").strip()
    if not raw:
        return None
    host = None
    path = None
    # SCP-style SSH URL: git@github.com:owner/repo.git
    scp = re.match(r"^(?:[^@/]+@)?([^:/]+):(.+)$", raw)
    if scp and "://" not in raw:
        host, path = scp.group(1), scp.group(2)
    else:
        parsed = urllib.parse.urlparse(raw)
        if parsed.hostname:
            host = parsed.hostname
            port = parsed.port
            if port and not ((parsed.scheme == "ssh" and port == 22)
                             or (parsed.scheme == "https" and port == 443)
                             or (parsed.scheme == "http" and port == 80)):
                host = "%s:%d" % (host, port)
            path = parsed.path
    if not host or not path:
        return None
    path = urllib.parse.unquote(path).strip().strip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    if not path:
        return None
    return "%s/%s" % (host.lower(), path)


def git_repository_info(path=None):
    """Local Git identity used for setup discovery and clone matching."""
    root = git_worktree_root(path)
    try:
        proc = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"], cwd=str(root),
            capture_output=True, text=True, timeout=5)
        canonical = canonical_git_remote(proc.stdout.strip()) \
            if proc.returncode == 0 else None
    except Exception:
        canonical = None
    return {"root_path": str(root), "remote": canonical,
            "fingerprint": ("sha256:" + sha256_hex(canonical))
            if canonical else None}


def git_repository_fingerprint(path=None):
    """Privacy-preserving identity for clones of the same Git remote."""
    return git_repository_info(path)["fingerprint"]


def _validate_project_link(data, path):
    if not isinstance(data, dict):
        raise AttaccaError("%s must contain a JSON object" % path)
    version = data.get("schema_version")
    if version != PROJECT_LINK_SCHEMA_VERSION:
        raise AttaccaError(
            "%s has unsupported schema_version %r (expected %d)"
            % (path, version, PROJECT_LINK_SCHEMA_VERSION))
    project_id = data.get("project_id")
    if not isinstance(project_id, str) or not project_id.strip():
        raise AttaccaError("%s must contain a non-empty project_id" % path)
    project_id = project_id.strip()
    if slugify(project_id) != project_id:
        raise AttaccaError(
            "%s has invalid project_id %r (expected a lowercase slug)"
            % (path, project_id))
    return {"schema_version": version, "project_id": project_id,
            "path": str(path)}


def find_project_link(path=None):
    """Read the nearest .attacca/project.json, walking toward the root.

    A malformed file is an error: silently ignoring it could fork a project's
    history into a newly auto-created project.
    """
    start = Path(path or os.getcwd()).resolve()
    if start.is_file():
        start = start.parent
    for directory in (start,) + tuple(start.parents):
        target = directory / PROJECT_LINK_DIR / PROJECT_LINK_NAME
        if not target.exists():
            continue
        try:
            data = json.loads(target.read_text())
        except Exception as err:
            raise AttaccaError("%s is not valid JSON: %s" % (target, err))
        link = _validate_project_link(data, target)
        link["root_path"] = str(directory)
        return link
    return None


def write_project_link(root_path, project_id):
    """Persist a non-secret checkout -> server project mapping."""
    root = Path(root_path).resolve()
    project_id = str(project_id or "").strip()
    _validate_project_link(
        {"schema_version": PROJECT_LINK_SCHEMA_VERSION,
         "project_id": project_id}, root / PROJECT_LINK_DIR / PROJECT_LINK_NAME)
    directory = root / PROJECT_LINK_DIR
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / PROJECT_LINK_NAME
    if target.is_symlink():
        raise AttaccaError("refusing to overwrite symlinked project link %s" % target)
    body = json.dumps({"schema_version": PROJECT_LINK_SCHEMA_VERSION,
                       "project_id": project_id}, indent=2) + "\n"
    temporary = directory / (".%s.%d.tmp" % (PROJECT_LINK_NAME, os.getpid()))
    temporary.write_text(body)
    os.replace(str(temporary), str(target))
    return str(target)


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
  project_id      TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  root_path       TEXT,
  repository_fingerprint TEXT,
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
  access_a   TEXT NOT NULL DEFAULT '{"preset":"all","agents":[]}',
  access_b   TEXT NOT NULL DEFAULT '{"preset":"all","agents":[]}',
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
  hash_version    INTEGER NOT NULL DEFAULT 2,
  context_version INTEGER,
  base_revision   TEXT,
  git_branch      TEXT,
  device_id       TEXT,
  task_id         TEXT,
  created_at      TEXT NOT NULL,
  UNIQUE (project_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_events_proj_seq  ON events (project_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_proj_type ON events (project_id, event_type, seq);
CREATE TABLE IF NOT EXISTS message_dispositions (
  project_id    TEXT NOT NULL,
  actor_id      TEXT NOT NULL,
  message_event_id TEXT NOT NULL,
  disposition  TEXT NOT NULL,
  note         TEXT,
  task_id      TEXT,
  updated_by   TEXT NOT NULL,
  updated_owner TEXT,
  updated_at   TEXT NOT NULL,
  PRIMARY KEY (project_id, actor_id, message_event_id)
);
CREATE INDEX IF NOT EXISTS idx_message_dispositions_actor
  ON message_dispositions (project_id, actor_id, disposition, updated_at);
CREATE INDEX IF NOT EXISTS idx_events_type_time_project
    ON events (event_type, created_at, project_id);
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
  plan_required  INTEGER NOT NULL DEFAULT 0,
  created_by     TEXT,
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL,
  PRIMARY KEY (project_id, task_id)
);
CREATE TABLE IF NOT EXISTS task_plan_revisions (
  project_id     TEXT NOT NULL,
  task_id        TEXT NOT NULL,
  version        INTEGER NOT NULL,
  title          TEXT NOT NULL,
  overview       TEXT,
  sections       TEXT NOT NULL DEFAULT '[]',
  status         TEXT NOT NULL DEFAULT 'draft',
  content_sha256 TEXT NOT NULL,
  authored_by    TEXT NOT NULL,
  authored_owner TEXT,
  authored_at    TEXT NOT NULL,
  updated_at     TEXT NOT NULL,
  PRIMARY KEY (project_id, task_id, version)
);
CREATE INDEX IF NOT EXISTS idx_task_plan_latest
  ON task_plan_revisions (project_id, task_id, version DESC);
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
CREATE TABLE IF NOT EXISTS project_rules (
  project_id    TEXT NOT NULL,
  rule_id       TEXT NOT NULL,
  title         TEXT NOT NULL,
  body          TEXT NOT NULL,
  scope         TEXT NOT NULL DEFAULT 'everyone',
  priority      INTEGER NOT NULL DEFAULT 100,
  enabled       INTEGER NOT NULL DEFAULT 1,
  version       INTEGER NOT NULL DEFAULT 1,
  created_by    TEXT NOT NULL,
  created_owner TEXT,
  created_at    TEXT NOT NULL,
  updated_by    TEXT NOT NULL,
  updated_owner TEXT,
  updated_at    TEXT NOT NULL,
  PRIMARY KEY (project_id, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_project_rules_list
  ON project_rules (project_id, enabled, scope, priority, rule_id);
CREATE TABLE IF NOT EXISTS project_cloud_context (
  project_id    TEXT NOT NULL,
  content       TEXT NOT NULL DEFAULT '',
  version       INTEGER NOT NULL DEFAULT 1,
  updated_by    TEXT,
  updated_owner TEXT,
  updated_at    TEXT NOT NULL,
  PRIMARY KEY (project_id)
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
CREATE TABLE IF NOT EXISTS actor_aliases (
  project_id        TEXT NOT NULL,
  legacy_actor_id   TEXT NOT NULL,
  canonical_actor_id TEXT NOT NULL,
  migrated_at       TEXT NOT NULL,
  PRIMARY KEY (project_id, legacy_actor_id)
);
CREATE TABLE IF NOT EXISTS server_settings (
  setting_key TEXT PRIMARY KEY,
  value       TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sync_operations (
  schema_version      INTEGER NOT NULL,
  project_id          TEXT NOT NULL,
  principal_id        TEXT NOT NULL,
  actor_id            TEXT NOT NULL,
  device_id           TEXT NOT NULL,
  client_mutation_id  TEXT NOT NULL,
  client_id            TEXT NOT NULL,
  client_sequence      INTEGER NOT NULL,
  request_sha256       TEXT NOT NULL,
  mutation_json        TEXT NOT NULL,
  state                TEXT NOT NULL CHECK (state IN ('reserved', 'applied')),
  receipt_json         TEXT,
  created_at           TEXT NOT NULL,
  committed_at         TEXT,
  PRIMARY KEY (
    project_id, principal_id, actor_id, device_id, client_mutation_id
  )
);
CREATE INDEX IF NOT EXISTS idx_sync_operations_fifo
  ON sync_operations (
    project_id, principal_id, actor_id, device_id, client_id, client_sequence
  );
CREATE TABLE IF NOT EXISTS auth_users (
  user_id             TEXT PRIMARY KEY,
  username            TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name        TEXT NOT NULL,
  password_salt       TEXT NOT NULL,
  password_hash       TEXT NOT NULL,
  password_iterations INTEGER NOT NULL,
  is_admin            INTEGER NOT NULL DEFAULT 0,
  created_at          TEXT NOT NULL,
  disabled_at         TEXT
);
CREATE TABLE IF NOT EXISTS auth_user_owner_aliases (
  alias_key   TEXT PRIMARY KEY,
  alias       TEXT NOT NULL,
  user_id     TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  created_by  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_owner_aliases_user
  ON auth_user_owner_aliases (user_id, alias_key);
CREATE TABLE IF NOT EXISTS auth_tokens (
  token_id      TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL,
  label         TEXT NOT NULL,
  token_prefix  TEXT NOT NULL,
  token_hash    TEXT NOT NULL UNIQUE,
  token_kind    TEXT NOT NULL DEFAULT 'actor',
  actor_id      TEXT,
  actor_type    TEXT NOT NULL DEFAULT 'agent',
  project_id    TEXT,
  runtime       TEXT,
  device_id     TEXT,
  client_label  TEXT,
  client_instance TEXT,
  created_at    TEXT NOT NULL,
  last_used_at  TEXT,
  expires_at    TEXT,
  revoked_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_user
  ON auth_tokens (user_id, revoked_at, created_at);
CREATE TABLE IF NOT EXISTS auth_client_key_deletions (
  token_id         TEXT PRIMARY KEY,
  user_id          TEXT NOT NULL,
  label            TEXT NOT NULL,
  token_prefix     TEXT NOT NULL,
  client_instance  TEXT,
  created_at       TEXT NOT NULL,
  revoked_at       TEXT NOT NULL,
  deleted_at       TEXT NOT NULL,
  deleted_by_user  TEXT NOT NULL,
  deleted_by_name  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_client_key_deletions_user
  ON auth_client_key_deletions (user_id, deleted_at);
CREATE TABLE IF NOT EXISTS auth_client_pairings (
  pairing_secret_hash TEXT PRIMARY KEY,
  pairing_code        TEXT NOT NULL UNIQUE,
  client_instance     TEXT NOT NULL,
  client_label        TEXT NOT NULL,
  device_id           TEXT,
  status              TEXT NOT NULL DEFAULT 'pending',
  approved_user_id    TEXT,
  approved_by         TEXT,
  approved_at         TEXT,
  approved_projects   TEXT,
  denied_at           TEXT,
  issued_token_id     TEXT,
  delivered_at        TEXT,
  created_at          TEXT NOT NULL,
  expires_at          TEXT NOT NULL,
  last_polled_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_client_pairings_code
  ON auth_client_pairings (pairing_code, status, expires_at);
CREATE TABLE IF NOT EXISTS auth_client_authorizations (
  request_token_hash TEXT PRIMARY KEY,
  poll_secret_hash   TEXT NOT NULL UNIQUE,
  client_instance   TEXT NOT NULL,
  client_label      TEXT NOT NULL,
  device_id         TEXT,
  status            TEXT NOT NULL DEFAULT 'pending',
  approved_user_id  TEXT,
  approved_by       TEXT,
  approved_at       TEXT,
  approved_projects TEXT,
  denied_at         TEXT,
  issued_token_id   TEXT,
  delivered_at      TEXT,
  created_at        TEXT NOT NULL,
  expires_at        TEXT NOT NULL,
  last_polled_at    TEXT
);
CREATE TABLE IF NOT EXISTS auth_sessions (
  session_hash TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  csrf_hash    TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  revoked_at   TEXT
);
CREATE TABLE IF NOT EXISTS auth_project_memberships (
  user_id      TEXT NOT NULL,
  project_id   TEXT NOT NULL,
  granted_at   TEXT NOT NULL,
  granted_by   TEXT,
  revoked_at   TEXT,
  PRIMARY KEY (user_id, project_id)
);
CREATE INDEX IF NOT EXISTS idx_auth_memberships_project
  ON auth_project_memberships (project_id, revoked_at, user_id);
CREATE TABLE IF NOT EXISTS auth_token_actor_bindings (
  token_id     TEXT NOT NULL,
  project_id   TEXT NOT NULL,
  actor_id     TEXT NOT NULL,
  runtime      TEXT,
  created_at   TEXT NOT NULL,
  revoked_at   TEXT,
  PRIMARY KEY (token_id, project_id, actor_id)
);
CREATE INDEX IF NOT EXISTS idx_auth_bindings_actor
  ON auth_token_actor_bindings (project_id, actor_id, revoked_at, token_id);
CREATE TABLE IF NOT EXISTS auth_token_project_bindings (
  token_id     TEXT NOT NULL,
  project_id   TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  revoked_at   TEXT,
  PRIMARY KEY (token_id, project_id)
);
CREATE INDEX IF NOT EXISTS idx_auth_token_projects
  ON auth_token_project_bindings (project_id, revoked_at, token_id);
CREATE TABLE IF NOT EXISTS auth_device_enrollments (
  device_code_hash TEXT PRIMARY KEY,
  user_code        TEXT NOT NULL UNIQUE,
  device_id        TEXT NOT NULL,
  client_label     TEXT NOT NULL,
  client_instance  TEXT,
  supersede_token_id TEXT,
  requested_bindings TEXT NOT NULL DEFAULT '[]',
  status           TEXT NOT NULL DEFAULT 'pending',
  interval_seconds INTEGER NOT NULL DEFAULT 5,
  created_at       TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  last_polled_at   TEXT,
  approved_by      TEXT,
  approved_at      TEXT,
  approval_json    TEXT,
  issued_token_id  TEXT,
  denied_at        TEXT,
  consumed_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_device_user_code
  ON auth_device_enrollments (user_code, status, expires_at);
CREATE TABLE IF NOT EXISTS auth_migration_targets (
  target_id        TEXT PRIMARY KEY,
  project_id       TEXT NOT NULL,
  actor_id         TEXT NOT NULL,
  device_id        TEXT NOT NULL,
  selected_at      TEXT NOT NULL,
  selected_by      TEXT,
  last_seen_at     TEXT NOT NULL,
  migration_required INTEGER NOT NULL DEFAULT 1,
  excluded_at      TEXT,
  excluded_by      TEXT,
  exclusion_reason TEXT,
  UNIQUE (project_id, actor_id, device_id)
);
CREATE INDEX IF NOT EXISTS idx_auth_migration_required
  ON auth_migration_targets (migration_required, excluded_at, project_id);
CREATE TABLE IF NOT EXISTS auth_invitations (
  invitation_id      TEXT PRIMARY KEY,
  token_prefix       TEXT NOT NULL,
  token_hash         TEXT NOT NULL UNIQUE,
  label              TEXT,
  invited_by         TEXT NOT NULL,
  is_admin           INTEGER NOT NULL DEFAULT 0,
  project_memberships TEXT NOT NULL DEFAULT '[]',
  created_at         TEXT NOT NULL,
  expires_at         TEXT NOT NULL,
  accepted_at        TEXT,
  accepted_user_id   TEXT,
  revoked_at         TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_invitations_active
  ON auth_invitations (expires_at, accepted_at, revoked_at, created_at);
CREATE TABLE IF NOT EXISTS agent_clients (
  project_id    TEXT NOT NULL,
  agent_id      TEXT NOT NULL,
  device_id     TEXT NOT NULL,
  device_label  TEXT,
  runtime       TEXT,
  owner         TEXT,
  client_version TEXT,
  git_branch    TEXT,
  git_revision  TEXT,
  first_seen_at TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL,
  enabled       INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (project_id, agent_id, device_id)
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
        # Human-readable pairing codes were replaced by opaque request tokens.
        # They are short-lived, so expire any legacy pending approvals instead
        # of migrating a plaintext browser selector into the new table.
        conn.execute(
            "UPDATE auth_client_pairings SET status='expired'"
            " WHERE status IN ('pending','approved')")
        # Human login and identity are one canonical account name. Keep the
        # legacy column as a mirror so old databases cannot retain a second
        # human identity through auth payloads or client setup.
        conn.execute(
            "UPDATE auth_users SET display_name=username"
            " WHERE display_name IS NULL OR display_name<>username")
        # Migrations for databases created before newer columns existed.
        for table, column in (("projects", "lead_director"),
                              ("projects", "repository_fingerprint"),
                              ("events", "owner"), ("events", "git_branch"),
                              ("events", "device_id"),
                              ("agents", "owner"),
                              ("bridges", "relation"), ("bridges", "principal")):
            cols = {r["name"] for r in
                    conn.execute("PRAGMA table_info(%s)" % table)}
            if column not in cols:
                try:
                    conn.execute("ALTER TABLE %s ADD COLUMN %s TEXT"
                                 % (table, column))
                except sqlite3.OperationalError:
                    pass  # another process migrated concurrently
        event_cols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(events)")}
        if "hash_version" not in event_cols:
            try:
                # Existing hashes use the original v1 material. New writes
                # explicitly use v2, which also protects user/Git attribution.
                conn.execute(
                    "ALTER TABLE events ADD COLUMN hash_version INTEGER"
                    " NOT NULL DEFAULT 1")
            except sqlite3.OperationalError:
                pass
        task_cols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(tasks)")}
        if "plan_required" not in task_cols:
            try:
                conn.execute(
                    "ALTER TABLE tasks ADD COLUMN plan_required INTEGER"
                    " NOT NULL DEFAULT 0")
            except sqlite3.OperationalError:
                pass
        bridge_cols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(bridges)")}
        for column in ("access_a", "access_b"):
            if column not in bridge_cols:
                try:
                    conn.execute(
                        "ALTER TABLE bridges ADD COLUMN %s TEXT NOT NULL"
                        " DEFAULT '{\"preset\":\"all\",\"agents\":[]}'"
                        % column)
                except sqlite3.OperationalError:
                    pass
        token_cols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(auth_tokens)")}
        for column, declaration in (
                ("token_kind", "TEXT NOT NULL DEFAULT 'actor'"),
                ("device_id", "TEXT"),
                ("client_label", "TEXT"),
                ("client_instance", "TEXT")):
            if column not in token_cols:
                try:
                    conn.execute("ALTER TABLE auth_tokens ADD COLUMN %s %s" %
                                 (column, declaration))
                except sqlite3.OperationalError:
                    pass
        # Human tokens predate token_kind.  Preserve them as human account
        # credentials; every pre-existing agent row remains an actor-bound
        # token and continues through its original authorization path.
        conn.execute(
            "UPDATE auth_tokens SET token_kind=CASE"
            " WHEN actor_type='human' THEN 'human' ELSE 'actor' END"
            " WHERE token_kind IS NULL OR token_kind=''"
            " OR (token_kind='actor' AND actor_type='human')")
        enrollment_cols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(auth_device_enrollments)")}
        for column in ("issued_token_id", "client_instance",
                       "supersede_token_id"):
            if column not in enrollment_cols:
                try:
                    conn.execute(
                        "ALTER TABLE auth_device_enrollments"
                        " ADD COLUMN %s TEXT" % column)
                except sqlite3.OperationalError:
                    pass
        invitation_cols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(auth_invitations)")}
        if "is_admin" not in invitation_cols:
            try:
                conn.execute(
                    "ALTER TABLE auth_invitations ADD COLUMN is_admin INTEGER"
                    " NOT NULL DEFAULT 0")
            except sqlite3.OperationalError:
                pass
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_repository"
            " ON projects(repository_fingerprint)"
            " WHERE repository_fingerprint IS NOT NULL")
        owner_setting = conn.execute(
            "SELECT 1 FROM server_settings"
            " WHERE setting_key='auth.owner_user_id'").fetchone()
        if not owner_setting:
            first_admin = conn.execute(
                "SELECT user_id FROM auth_users WHERE is_admin=1"
                " ORDER BY created_at,user_id LIMIT 1").fetchone()
            if first_admin:
                conn.execute(
                    "INSERT INTO server_settings(setting_key,value,updated_at)"
                    " VALUES ('auth.owner_user_id',?,?)",
                    (json.dumps(first_admin["user_id"]), now_iso()))
        # Materialize the non-secret hosted identity during the ordinary
        # schema/migration open.  Sync snapshot GETs can then remain genuinely
        # read-only instead of lazily writing this setting on first access.
        _sync_server_id(conn)
    except (sqlite3.Error, OSError) as err:
        raise AttaccaError("cannot open database at %s: %s" % (db_path, err))
    return conn


# ---------------------------------------------------------------------------
# Hosted authentication (prototype accounts + browser sessions + API tokens)
# ---------------------------------------------------------------------------

PASSWORD_ITERATIONS = 210000
SESSION_HOURS = 24
DEVICE_ENROLLMENT_MINUTES = 10
DEVICE_ENROLLMENT_INTERVAL_SECONDS = 5
AUTH_MODES = ("auto", "compatibility")
AUTH_ARTIFACT_FILES = (
    "attacca.py",
    "terminal_flow.py",
    "sync_client.py",
    "sync_protocol.py",
    "sync_server.py",
    "offline_sync.py",
    "codex_hook_compat.py",
    "hooks/hooks.json",
    "hooks/session_start.py",
    "web/admin.html",
    "plugin-mcp.json",
    ".mcp.json",
    "kimi.plugin.json",
    ".codex-plugin/plugin.json",
    ".claude-plugin/plugin.json",
    "skills/setup/SKILL.md",
    "skills/update/SKILL.md",
    "kimi-commands/setup.md",
    "kimi-commands/update.md",
    "kimi-skills/session/SKILL.md",
)
# Release evidence is deliberately structured because activation readiness is
# consumed by both the browser and terminal clients.  These booleans describe
# the shipped backend contract; the task evidence still records the actual
# commands and outputs for each release.
AUTH_QA_EVIDENCE_DEFAULT = {
    "acceptance": {
        "passed": False,
        "suite": "terminal compatibility and activation acceptance",
    },
    "regression": {
        "passed": False,
        "suite": "auth, MCP, sync and migration regression",
    },
}


def _clean_username(value):
    username = str(value or "").strip().lower()
    if not re.match(r"^[a-z0-9][a-z0-9._-]{1,63}$", username):
        raise AttaccaError(
            "username must be 2-64 lowercase letters, numbers, dots, dashes or underscores")
    return username


def _password_hash(password, salt_hex, iterations=PASSWORD_ITERATIONS):
    if not isinstance(password, str) or len(password) < 8:
        raise AttaccaError("password must be at least 8 characters")
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex),
        int(iterations)).hex()


def _public_auth_user(row):
    return {"user_id": row["user_id"], "username": row["username"],
            "is_admin": bool(row["is_admin"]),
            "created_at": row["created_at"],
            "disabled": bool(row["disabled_at"])}


def auth_is_enabled(conn):
    """Whether accounts have been bootstrapped (not whether auth is enforced).

    The historical name remains for compatibility with callers and migrations.
    Enforcement is now an explicit activation state so creating the first
    account can never freeze already-running terminal clients.
    """
    return bool(conn.execute(
        "SELECT COUNT(*) AS n FROM auth_users WHERE disabled_at IS NULL"
    ).fetchone()["n"])


def _auth_setting(conn, key, default=None):
    row = conn.execute(
        "SELECT value FROM server_settings WHERE setting_key=?", (key,)
    ).fetchone()
    if not row:
        return default
    try:
        return json.loads(row["value"])
    except (TypeError, ValueError):
        return default


def auth_source_sha256():
    """Fingerprint the exact security-critical packaged artifact.

    The historical function name remains API-compatible, but evidence is no
    longer bound to backend bytes alone. Missing or unreadable package members
    return ``None`` so activation readiness fails closed.
    """
    digest = hashlib.sha256()
    digest.update(b"attacca-auth-artifact-v1\0")
    try:
        root = Path(script_path()).resolve().parent
        for relative in sorted(AUTH_ARTIFACT_FILES):
            data = (root / relative).read_bytes()
            name = relative.encode("utf-8")
            digest.update(len(name).to_bytes(4, "big"))
            digest.update(name)
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)
        return digest.hexdigest()
    except OSError:
        return None


def auth_qa_evidence(conn, expected_artifact_sha256=None):
    """Load release QA only when it is bound to these exact source bytes."""
    stored = _auth_setting(conn, "auth.qa_evidence", {})
    current_hash = expected_artifact_sha256 or auth_source_sha256()
    stored_hash = stored.get("artifact_sha256") \
        if isinstance(stored, dict) else None
    if stored_hash is None and isinstance(stored, dict):
        stored_hash = stored.get("source_sha256")
    if not isinstance(stored, dict) or not current_hash \
            or stored_hash != current_hash:
        result = json.loads(json.dumps(AUTH_QA_EVIDENCE_DEFAULT))
        result["source_sha256"] = current_hash
        result["artifact_sha256"] = current_hash
        result["recorded"] = False
        return result
    result = {
        name: dict(stored.get(name) or {})
        for name in ("acceptance", "regression")
    }
    for name in ("acceptance", "regression"):
        result[name].setdefault("passed", False)
        result[name].setdefault("suite", AUTH_QA_EVIDENCE_DEFAULT[name]["suite"])
    result["source_sha256"] = current_hash
    result["artifact_sha256"] = current_hash
    result["recorded"] = True
    result["recorded_at"] = stored.get("recorded_at")
    return result


def auth_record_qa_evidence(conn, source_sha256, acceptance, regression,
                            recorded_at=None):
    """Release/package hook: persist two exact-source QA results.

    This is intentionally not exposed as a browser endpoint; an admin cannot
    self-attest a green build from the activation screen.
    """
    current_hash = auth_source_sha256()
    if not current_hash or not hmac.compare_digest(
            str(source_sha256 or ""), current_hash):
        raise AttaccaError(
            "QA evidence artifact hash does not match this server package")
    values = {}
    for name, item in (("acceptance", acceptance),
                       ("regression", regression)):
        if not isinstance(item, dict) or item.get("passed") is not True \
                or not str(item.get("suite") or "").strip() \
                or not str(item.get("result") or "").strip():
            raise AttaccaError(
                "%s QA evidence requires passed=true, suite and result" % name)
        values[name] = {
            "passed": True,
            "suite": str(item["suite"]).strip(),
            "result": str(item["result"]).strip(),
            "recorded_at": str(item.get("recorded_at") or recorded_at
                               or now_iso()),
        }
    payload = {
        "source_sha256": current_hash,
        "artifact_sha256": current_hash,
        "recorded_at": str(recorded_at or now_iso()),
        "acceptance": values["acceptance"],
        "regression": values["regression"],
    }
    server_settings_store(conn, {"auth.qa_evidence": payload})
    return payload


def _auth_expiry(value):
    if value is None or str(value).strip() == "":
        return None
    raw_expiry = str(value).strip()
    try:
        expiry = datetime.fromisoformat(raw_expiry.replace("Z", "+00:00"))
    except ValueError:
        raise AttaccaError(
            "expires_at must be an ISO-8601 timestamp with timezone")
    if expiry.tzinfo is None:
        raise AttaccaError("expires_at must include a timezone")
    expiry = expiry.astimezone(timezone.utc)
    if expiry <= now_dt():
        raise AttaccaError("expires_at must be in the future")
    return expiry.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def auth_terminal_bindings(conn, token_id):
    rows = conn.execute(
        "SELECT b.*,a.role,a.display_name FROM auth_token_actor_bindings b"
        " JOIN agents a ON a.project_id=b.project_id AND a.agent_id=b.actor_id"
        " WHERE b.token_id=? AND b.revoked_at IS NULL"
        " ORDER BY b.project_id,b.actor_id", (token_id,)).fetchall()
    result = []
    for row in rows:
        runtime = normalize_agent_runtime(row["runtime"], row["actor_id"])
        role = row["role"] or "unassigned"
        result.append({
            "project_id": row["project_id"],
            # Credential login never migrates or rewrites an actor identity.
            # The exact registered id remains both the authorization target
            # and the ledger/sync actor until a separate explicit actor
            # migration creates an alias.
            "actor_id": row["actor_id"],
            "allowed_existing_actor_id": row["actor_id"],
            "operational_actor_id": row["actor_id"],
            "runtime": runtime,
            "role": role,
            "display_name": row["display_name"],
        })
    return result


def auth_terminal_record(conn, row):
    value = {key: row[key] for key in (
        "token_id", "label", "token_kind", "device_id", "client_label",
        "client_instance",
        "created_at", "last_used_at", "expires_at", "revoked_at")}
    value["bindings"] = auth_terminal_bindings(conn, row["token_id"])
    value["project_memberships"] = [item["project_id"] for item in
        conn.execute(
            "SELECT project_id FROM auth_project_memberships"
            " WHERE user_id=? AND revoked_at IS NULL ORDER BY project_id",
            (row["user_id"],)).fetchall()]
    return value


def auth_grant_project_membership(conn, principal, project_id,
                                  granted_by=None):
    """Grant a human account durable access to a workspace it just created."""
    if not principal or not principal.get("user_id"):
        return False
    project_id = get_project(conn, project_id)["project_id"]
    with write_tx(conn):
        conn.execute(
            "INSERT INTO auth_project_memberships"
            " (user_id,project_id,granted_at,granted_by,revoked_at)"
            " VALUES (?,?,?,?,NULL)"
            " ON CONFLICT(user_id,project_id) DO UPDATE SET"
            " revoked_at=NULL,granted_at=excluded.granted_at,"
            " granted_by=excluded.granted_by",
            (principal["user_id"], project_id, now_iso(),
             granted_by or principal.get("username")))
    return True


def auth_has_project_membership(conn, principal, project_id):
    if not principal:
        return False
    if principal.get("is_admin"):
        return True
    return bool(conn.execute(
        "SELECT 1 FROM auth_project_memberships"
        " WHERE user_id=? AND project_id=? AND revoked_at IS NULL",
        (principal.get("user_id"), project_id)).fetchone())


def auth_token_project_bindings(conn, token_id):
    return [row["project_id"] for row in conn.execute(
        "SELECT project_id FROM auth_token_project_bindings"
        " WHERE token_id=? AND revoked_at IS NULL ORDER BY project_id",
        (token_id,)).fetchall()]


def auth_visible_project_ids(conn, principal):
    """Return an authenticated principal's visible IDs, or ``None`` for all.

    Machine credentials are evaluated before account-admin status: a terminal
    or service bearer remains exactly scoped even when its owning human is the
    server owner.  Browser sessions and human API credentials derive access
    from memberships, with server admins as the only account-wide exception.
    """
    if not principal:
        return None
    token_kind = principal.get("token_kind")
    if token_kind == "client":
        memberships = {row["project_id"] for row in conn.execute(
            "SELECT project_id FROM auth_project_memberships"
            " WHERE user_id=? AND revoked_at IS NULL",
            (principal["user_id"],)).fetchall()}
        explicit = set(auth_token_project_bindings(
            conn, principal["token_id"]))
        if explicit:
            # A key's selected-workspace scope can only narrow the account's
            # current memberships. Revoking a human membership must revoke
            # every client install's access immediately; an old token binding
            # is never an independent authority grant.
            return explicit.intersection(memberships)
        return memberships
    if token_kind == "terminal" and not principal.get("provisional_human"):
        return {item["project_id"] for item in auth_terminal_bindings(
            conn, principal["token_id"])}
    if token_kind == "service":
        return set(auth_token_project_bindings(
            conn, principal["token_id"]))
    if token_kind == "actor" or (
            principal.get("actor_type") == "agent" and
            principal.get("project_id")):
        return ({principal["project_id"]}
                if principal.get("project_id") else set())
    if principal.get("is_admin"):
        return None
    if principal.get("user_id"):
        return {row["project_id"] for row in conn.execute(
            "SELECT project_id FROM auth_project_memberships"
            " WHERE user_id=? AND revoked_at IS NULL",
            (principal["user_id"],)).fetchall()}
    return set()


def _auth_owner_alias_key(value):
    return str(value or "").strip().casefold()


def _auth_owner_label_user_id(conn, owner_label):
    """Resolve one owner label to exactly one human account, fail closed.

    Usernames and legacy aliases share a single authorization namespace. Old
    or externally modified databases can contain a collision, so resolution
    deliberately returns no owner instead of allowing both accounts through.
    """
    key = _auth_owner_alias_key(owner_label)
    if not key:
        return None
    owners = {
        row["user_id"] for row in conn.execute(
            "SELECT user_id FROM auth_users WHERE username=? COLLATE NOCASE",
            (key,)).fetchall()
    }
    alias = conn.execute(
        "SELECT user_id FROM auth_user_owner_aliases WHERE alias_key=?",
        (key,)).fetchone()
    if alias:
        owners.add(alias["user_id"])
    return next(iter(owners)) if len(owners) == 1 else None


def auth_principal_owner_labels(conn, principal):
    """Return exact historical actor-owner labels assigned to one account."""
    if not principal or not principal.get("user_id"):
        return set()
    candidates = {_auth_owner_alias_key(principal.get("username"))}
    candidates.update(
        row["alias_key"] for row in conn.execute(
            "SELECT alias_key FROM auth_user_owner_aliases WHERE user_id=?",
            (principal["user_id"],)).fetchall())
    candidates.discard("")
    return {
        label for label in candidates
        if _auth_owner_label_user_id(conn, label) == principal["user_id"]
    }


def auth_principal_owns_label(conn, principal, owner_label):
    return bool(principal and principal.get("user_id") and
                _auth_owner_label_user_id(conn, owner_label) ==
                principal["user_id"])


def _auth_reject_username_alias_collision(conn, username):
    """Keep newly created usernames out of another account's alias space."""
    key = _auth_owner_alias_key(username)
    alias = conn.execute(
        "SELECT alias,user_id FROM auth_user_owner_aliases WHERE alias_key=?",
        (key,)).fetchone()
    if alias:
        raise AttaccaError(
            "Attacca username '%s' is reserved by legacy owner alias '%s'; "
            "an owner must explicitly migrate that alias before creating "
            "this account" % (username, alias["alias"]))


def auth_claim_single_user_legacy_owner_aliases(conn, principal):
    """Preserve legacy actor rows while attaching their labels to one owner.

    Prototype databases often recorded a shell username, display name, or
    placeholder in ``agents.owner`` before account authentication existed.
    If and only if the server has one active human account, activation may
    claim those exact labels for that immutable server owner. No actor row is
    rewritten and every later mutation still records both actor and account.
    """
    if not principal or not principal.get("is_owner"):
        raise AuthorizationError("server_owner_required: alias claim denied")
    users = conn.execute(
        "SELECT user_id FROM auth_users WHERE disabled_at IS NULL").fetchall()
    if len(users) != 1 or users[0]["user_id"] != principal["user_id"]:
        return []
    aliases = sorted({
        str(row["owner"] or "").strip()
        for row in conn.execute(
            "SELECT DISTINCT owner FROM agents WHERE owner IS NOT NULL")
        if str(row["owner"] or "").strip()
        and _auth_owner_alias_key(row["owner"]) !=
        _auth_owner_alias_key(principal.get("username"))
    }, key=str.casefold)
    claimed = []
    for alias in aliases:
        key = _auth_owner_alias_key(alias)
        username_owner = conn.execute(
            "SELECT user_id FROM auth_users WHERE username=? COLLATE NOCASE",
            (key,)).fetchone()
        if username_owner and username_owner["user_id"] != \
                principal["user_id"]:
            # Usernames are authoritative labels. Never claim a disabled or
            # active account's namespace as a compatibility alias.
            continue
        existing = conn.execute(
            "SELECT user_id FROM auth_user_owner_aliases WHERE alias_key=?",
            (key,)).fetchone()
        if existing:
            continue
        conn.execute(
            "INSERT INTO auth_user_owner_aliases"
            " (alias_key,alias,user_id,created_at,created_by)"
            " VALUES (?,?,?,?,?)",
            (key, alias, principal["user_id"], now_iso(),
             principal["username"]))
        claimed.append(alias)
    return claimed


def auth_grant_single_user_legacy_project_memberships(conn, principal):
    """Attach a prototype single-owner account to every existing workspace.

    Pre-auth Attacca databases had projects and actors but no human membership
    rows. During the one-account owner cutover, preserve those projects without
    weakening the steady-state rule that every client key requires an active
    account membership. Multi-account servers never receive this migration.
    """
    if not principal or not principal.get("is_owner"):
        raise AuthorizationError(
            "server_owner_required: legacy membership claim denied")
    users = conn.execute(
        "SELECT user_id FROM auth_users WHERE disabled_at IS NULL").fetchall()
    if len(users) != 1 or users[0]["user_id"] != principal["user_id"]:
        return []
    existing = {row["project_id"] for row in conn.execute(
        "SELECT project_id FROM auth_project_memberships"
        " WHERE user_id=? AND revoked_at IS NULL",
        (principal["user_id"],)).fetchall()}
    nowi = now_iso()
    granted = []
    for row in conn.execute(
            "SELECT project_id FROM projects ORDER BY project_id").fetchall():
        project_id = row["project_id"]
        if project_id in existing:
            continue
        conn.execute(
            "INSERT INTO auth_project_memberships"
            " (user_id,project_id,granted_at,granted_by,revoked_at)"
            " VALUES (?,?,?,?,NULL)"
            " ON CONFLICT(user_id,project_id) DO UPDATE SET"
            " revoked_at=NULL,granted_at=excluded.granted_at,"
            " granted_by=excluded.granted_by",
            (principal["user_id"], project_id, nowi,
             principal["username"]))
        granted.append(project_id)
    return granted


def _auth_validate_client_projects(conn, principal, memberships):
    """Validate the optional workspace scope for one client-install key.

    An empty list deliberately means "all workspaces this human account may
    access", including workspaces joined later.  This is still account scoped;
    it never inherits server-admin authority and it never selects an AI actor.
    """
    if memberships is None:
        memberships = []
    if not isinstance(memberships, list):
        raise AttaccaError("project_memberships must be an array")
    projects = []
    for value in memberships:
        project_id = get_project(conn, str(value or "").strip())["project_id"]
        if not auth_has_project_membership(conn, principal, project_id):
            raise AuthorizationError(
                "client_key_scope_denied: workspace membership is required")
        if project_id not in projects:
            projects.append(project_id)
    return projects


def auth_client_key_create(conn, principal, label, client_instance,
                           memberships=None, expires_at=None,
                           device_id=None):
    """Create a human-owned credential for one installed Attacca client.

    The credential authenticates the client installation only.  It contains
    no runtime, model, role, or actor binding; those are resolved independently
    from the exact registered actor sent on each project request.
    """
    label = str(label or "Attacca client").strip()
    if not label or len(label) > 120:
        raise AttaccaError("client key label must be 1-120 characters")
    client_instance = str(client_instance or "").strip()
    if not _CLIENT_INSTALL_ID_RE.fullmatch(client_instance) \
            or len(client_instance) > 120:
        raise AttaccaError(
            "client_instance must be a safe 1-120 character installation ID")
    device_id = str(device_id or "").strip() or None
    if device_id and not _CLIENT_INSTALL_ID_RE.fullmatch(device_id):
        raise AttaccaError(
            "device_id must be a safe 1-240 character device ID")
    projects = _auth_validate_client_projects(conn, principal, memberships)
    expires_at = _auth_expiry(expires_at)
    token_id = new_id("key")
    raw = "atkey_%s.%s" % (token_id, secrets.token_urlsafe(32))
    nowi = now_iso()
    with write_tx(conn):
        conn.execute(
            "INSERT INTO auth_tokens"
            " (token_id,user_id,label,token_prefix,token_hash,token_kind,"
            " actor_id,actor_type,project_id,runtime,device_id,client_label,"
            " client_instance,created_at,expires_at)"
            " VALUES (?,?,?,?,?,'client',NULL,'client',NULL,'client',?,?,?,?,?)",
            (token_id, principal["user_id"], label, raw[:22], sha256_hex(raw),
             device_id, label, client_instance, nowi, expires_at))
        for project_id in projects:
            conn.execute(
                "INSERT INTO auth_token_project_bindings"
                " (token_id,project_id,created_at,revoked_at)"
                " VALUES (?,?,?,NULL)", (token_id, project_id, nowi))
    row = conn.execute(
        "SELECT t.*,u.username FROM auth_tokens t JOIN auth_users u"
        " ON u.user_id=t.user_id WHERE t.token_id=?", (token_id,)).fetchone()
    return {
        "ok": True,
        "token": raw,
        "record": auth_client_key_record(conn, row),
        "warning": "API key plaintext is returned only in this response",
    }


def auth_client_key_record(conn, row):
    return {
        "token_id": row["token_id"],
        "label": row["label"],
        "token_prefix": row["token_prefix"],
        "token_kind": "client",
        "username": row["username"] if "username" in row.keys() else None,
        "client_instance": row["client_instance"],
        "device_id": row["device_id"],
        "project_memberships": auth_token_project_bindings(
            conn, row["token_id"]),
        "scope_mode": ("selected_workspaces" if
                       auth_token_project_bindings(conn, row["token_id"])
                       else "account_memberships"),
        "created_at": row["created_at"],
        "last_used_at": row["last_used_at"],
        "expires_at": row["expires_at"],
        "revoked_at": row["revoked_at"],
    }


def auth_client_key_list(conn, principal):
    if principal.get("is_admin"):
        rows = conn.execute(
            "SELECT t.*,u.username FROM auth_tokens t JOIN auth_users u"
            " ON u.user_id=t.user_id WHERE t.token_kind='client'"
            " ORDER BY t.created_at DESC").fetchall()
    else:
        rows = conn.execute(
            "SELECT t.*,u.username FROM auth_tokens t JOIN auth_users u"
            " ON u.user_id=t.user_id WHERE t.token_kind='client'"
            " AND t.user_id=? ORDER BY t.created_at DESC",
            (principal["user_id"],)).fetchall()
    return [auth_client_key_record(conn, row) for row in rows]


def auth_client_key_revoke(conn, principal, token_id):
    row = conn.execute(
        "SELECT * FROM auth_tokens WHERE token_id=? AND token_kind='client'",
        (token_id,)).fetchone()
    if not row or (row["user_id"] != principal.get("user_id")
                   and not principal.get("is_admin")):
        raise AuthorizationError("client_key_not_owned")
    nowi = now_iso()
    with write_tx(conn):
        conn.execute(
            "UPDATE auth_tokens SET revoked_at=? WHERE token_id=?"
            " AND revoked_at IS NULL", (nowi, token_id))
        conn.execute(
            "UPDATE auth_token_project_bindings SET revoked_at=?"
            " WHERE token_id=? AND revoked_at IS NULL", (nowi, token_id))
    return {"ok": True, "token_id": token_id, "revoked": True}


def auth_client_key_delete(conn, principal, token_id):
    """Permanently remove an already-revoked client credential.

    The verifier and all scope bindings are deleted.  A deliberately
    non-secret tombstone remains so operators can audit who deleted which
    revoked credential without retaining material that can authenticate.
    """
    row = conn.execute(
        "SELECT * FROM auth_tokens WHERE token_id=? AND token_kind='client'",
        (token_id,)).fetchone()
    if not row or (row["user_id"] != principal.get("user_id")
                   and not principal.get("is_admin")):
        raise AuthorizationError("client_key_not_owned")
    if not row["revoked_at"]:
        raise AttaccaError("client_key_must_be_revoked_before_delete")
    deleted_at = now_iso()
    with write_tx(conn):
        conn.execute(
            "INSERT INTO auth_client_key_deletions"
            " (token_id,user_id,label,token_prefix,client_instance,created_at,"
            " revoked_at,deleted_at,deleted_by_user,deleted_by_name)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (row["token_id"], row["user_id"], row["label"],
             row["token_prefix"], row["client_instance"], row["created_at"],
             row["revoked_at"], deleted_at, principal["user_id"],
             principal.get("username") or principal["user_id"]))
        conn.execute(
            "DELETE FROM auth_token_project_bindings WHERE token_id=?",
            (token_id,))
        conn.execute(
            "DELETE FROM auth_token_actor_bindings WHERE token_id=?",
            (token_id,))
        conn.execute("DELETE FROM auth_tokens WHERE token_id=?", (token_id,))
    return {"ok": True, "token_id": token_id, "deleted": True,
            "deleted_at": deleted_at}


def _auth_client_authorization_token(conn):
    for _ in range(20):
        token = secrets.token_urlsafe(32)
        if not conn.execute(
                "SELECT 1 FROM auth_client_authorizations"
                " WHERE request_token_hash=?", (sha256_hex(token),)).fetchone():
            return token
    raise AttaccaError("could not allocate a client authorization request")


def auth_client_pairing_start(conn, base_url, client_instance, label,
                              device_id=None):
    """Start a short-lived browser authorization for one client install."""
    client_instance = str(client_instance or "").strip()
    label = str(label or "Attacca client").strip()
    device_id = str(device_id or "").strip() or None
    if not _CLIENT_INSTALL_ID_RE.fullmatch(client_instance) \
            or len(client_instance) > 120:
        raise AttaccaError(
            "client_instance must be a safe 1-120 character installation ID")
    if not label or len(label) > 120:
        raise AttaccaError("client label must be 1-120 characters")
    if device_id and not _CLIENT_INSTALL_ID_RE.fullmatch(device_id):
        raise AttaccaError("device_id must be a safe 1-240 character device ID")
    poll_secret = "atpair_%s.%s" % (
        secrets.token_urlsafe(12), secrets.token_urlsafe(32))
    request_token = _auth_client_authorization_token(conn)
    created = now_iso()
    expires = (now_dt() + timedelta(minutes=10)).strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    with write_tx(conn):
        conn.execute(
            "UPDATE auth_client_authorizations SET status='superseded'"
            " WHERE client_instance=? AND COALESCE(device_id,'')=?"
            " AND status IN ('pending','approved')",
            (client_instance, device_id or ""))
        conn.execute(
            "INSERT INTO auth_client_authorizations"
            " (request_token_hash,poll_secret_hash,client_instance,client_label,"
            " device_id,status,created_at,expires_at)"
            " VALUES (?,?,?,?,?,'pending',?,?)",
            (sha256_hex(request_token), sha256_hex(poll_secret),
             client_instance, label,
             device_id, created, expires))
    base = base_url.rstrip("/")
    return {
        "poll_secret": poll_secret,
        "authorization_request": request_token,
        "verification_uri": base + "/app#settings",
        "verification_uri_complete": "%s/app#settings&authorization_request=%s" % (
            base, urllib.parse.quote(request_token, safe="")),
        "expires_in": 600,
        "interval": 5,
    }


def _auth_client_pairing_row(conn, authorization_request):
    token = str(authorization_request or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise AttaccaError("invalid client authorization request")
    row = conn.execute(
        "SELECT * FROM auth_client_authorizations WHERE request_token_hash=?",
        (sha256_hex(token),)
    ).fetchone()
    if not row:
        raise AttaccaError("unknown client authorization request")
    if row["expires_at"] <= now_iso() and row["status"] in (
            "pending", "approved"):
        with write_tx(conn):
            conn.execute(
                "UPDATE auth_client_authorizations SET status='expired'"
                " WHERE request_token_hash=?", (row["request_token_hash"],))
        raise AttaccaError("client authorization request expired")
    return row


def auth_client_pairing_record(conn, authorization_request):
    row = _auth_client_pairing_row(conn, authorization_request)
    record = {key: row[key] for key in (
        "client_instance", "client_label", "device_id",
        "status", "created_at", "expires_at")}
    record["project_memberships"] = json.loads(
        row["approved_projects"] or "[]")
    record["scope_mode"] = ("selected_workspaces" if
                            record["project_memberships"] else
                            "account_memberships")
    return record


def auth_client_pairing_decide(conn, authorization_request, principal, authorize,
                               memberships=None):
    row = _auth_client_pairing_row(conn, authorization_request)
    if row["status"] != "pending":
        raise AttaccaError("client pairing is already %s" % row["status"])
    nowi = now_iso()
    status = "approved" if authorize else "denied"
    projects = (_auth_validate_client_projects(
        conn, principal, memberships) if authorize else [])
    with write_tx(conn):
        if authorize:
            cur = conn.execute(
                "UPDATE auth_client_authorizations SET status='approved',"
                " approved_user_id=?,approved_by=?,approved_at=?,"
                " approved_projects=?"
                " WHERE request_token_hash=? AND status='pending'",
                (principal["user_id"], principal["username"], nowi,
                 canonical_json(projects),
                 row["request_token_hash"]))
        else:
            cur = conn.execute(
                "UPDATE auth_client_authorizations SET status='denied',"
                " approved_by=?,denied_at=?"
                " WHERE request_token_hash=? AND status='pending'",
                (principal["username"], nowi, row["request_token_hash"]))
        if cur.rowcount != 1:
            raise AttaccaError("client pairing decision raced; reload")
    return {"ok": True, "status": status, "project_memberships": projects,
            "scope_mode": ("selected_workspaces" if projects else
                           "account_memberships"),
            "credential_issued": False}


def auth_client_pairing_poll(conn, poll_secret, client_instance,
                             device_id=None):
    """Promote the device-held pairing secret into a client key exactly once."""
    raw = str(poll_secret or "").strip()
    row = conn.execute(
        "SELECT * FROM auth_client_authorizations WHERE poll_secret_hash=?",
        (sha256_hex(raw),)).fetchone() if raw else None
    if not row:
        raise AuthenticationError("invalid client pairing secret")
    if not hmac.compare_digest(
            str(client_instance or "").strip(), row["client_instance"]):
        raise AuthorizationError("client_pairing_instance_mismatch")
    expected_device = str(row["device_id"] or "")
    supplied_device = str(device_id or "").strip()
    if expected_device and (not supplied_device or not hmac.compare_digest(
            supplied_device, expected_device)):
        raise AuthorizationError("client_pairing_device_mismatch")
    if row["expires_at"] <= now_iso():
        raise AttaccaError("client pairing code expired")
    if row["status"] == "pending":
        conn.execute(
            "UPDATE auth_client_authorizations SET last_polled_at=?"
            " WHERE poll_secret_hash=?", (now_iso(), row["poll_secret_hash"]))
        return {"status": "pending", "interval": 5}
    if row["status"] == "denied":
        return {"status": "denied"}
    if row["status"] != "approved" or row["delivered_at"]:
        raise AuthenticationError("client pairing credential already delivered")
    user = conn.execute(
        "SELECT * FROM auth_users WHERE user_id=? AND disabled_at IS NULL",
        (row["approved_user_id"],)).fetchone()
    if not user:
        raise AuthenticationError("client pairing owner is unavailable")
    token_id = new_id("key")
    nowi = now_iso()
    with write_tx(conn):
        current = conn.execute(
            "SELECT * FROM auth_client_authorizations WHERE poll_secret_hash=?",
            (row["poll_secret_hash"],)).fetchone()
        if current["status"] != "approved" or current["delivered_at"]:
            raise AuthenticationError("client pairing credential already delivered")
        conn.execute(
            "INSERT INTO auth_tokens"
            " (token_id,user_id,label,token_prefix,token_hash,token_kind,"
            " actor_id,actor_type,project_id,runtime,device_id,client_label,"
            " client_instance,created_at)"
            " VALUES (?,?,?,?,?,'client',NULL,'client',NULL,'client',?,?,?,?)",
            (token_id, user["user_id"], row["client_label"], raw[:22],
             row["poll_secret_hash"], row["device_id"],
             row["client_label"], row["client_instance"], nowi))
        conn.execute(
            "UPDATE auth_client_authorizations SET status='consumed',"
            " issued_token_id=?,delivered_at=?,last_polled_at=?"
            " WHERE poll_secret_hash=? AND status='approved'"
            " AND delivered_at IS NULL",
            (token_id, nowi, nowi, row["poll_secret_hash"]))
        for project_id in json.loads(row["approved_projects"] or "[]"):
            conn.execute(
                "INSERT INTO auth_token_project_bindings"
                " (token_id,project_id,created_at,revoked_at)"
                " VALUES (?,?,?,NULL)", (token_id, project_id, nowi))
    token_row = conn.execute(
        "SELECT t.*,u.username FROM auth_tokens t JOIN auth_users u"
        " ON u.user_id=t.user_id WHERE t.token_id=?", (token_id,)).fetchone()
    return {"status": "approved", "credential": {
        "token": raw, "record": auth_client_key_record(conn, token_row)}}


def auth_client_project_access(conn, principal, project_id):
    """Validate one client key's account/workspace scope."""
    if principal.get("token_kind") != "client":
        raise AuthorizationError("credential is not a client API key")
    project_id = get_project(conn, project_id)["project_id"]
    if not auth_has_project_membership(conn, principal, project_id):
        raise AuthorizationError(
            "client_key_scope_denied: account has no workspace membership")
    explicit = auth_token_project_bindings(conn, principal["token_id"])
    if explicit and project_id not in explicit:
        raise AuthorizationError(
            "client_key_scope_denied: workspace is outside key scope")
    return project_id


def auth_client_principal_scope(conn, principal, project_id, claimed_actor):
    """Authorize one request actor without binding it into the client key.

    ``claimed_actor`` is request metadata, not credential identity.  Resolve an
    explicit migration alias before applying the registered actor's owner and
    role checks so an installed client survives an actor rename without ever
    acquiring an actor/role/runtime binding of its own.
    """
    project_id = auth_client_project_access(conn, principal, project_id)
    actor_id = str(claimed_actor or "").strip()
    if not actor_id:
        raise AuthorizationError(
            "client_actor_required: send the exact canonical X-Attacca-Actor")
    row = conn.execute(
        "SELECT * FROM agents WHERE project_id=? AND agent_id=?",
        (project_id, actor_id)).fetchone()
    if not row:
        alias = conn.execute(
            "SELECT canonical_actor_id FROM actor_aliases"
            " WHERE project_id=? AND legacy_actor_id=?",
            (project_id, actor_id)).fetchone()
        if alias:
            row = conn.execute(
                "SELECT * FROM agents WHERE project_id=? AND agent_id=?",
                (project_id, alias["canonical_actor_id"])).fetchone()
    if not row:
        raise AuthorizationError(
            "client_actor_not_registered: '%s' is not registered in '%s'" %
            (actor_id, project_id))
    if not auth_principal_owns_label(conn, principal, row["owner"]):
        raise AuthorizationError(
            "client_actor_denied: actor belongs to Attacca user '%s'" %
            (row["owner"] or "unassigned"))
    return {
        "project_id": project_id,
        "actor_id": row["agent_id"],
        "actor_type": "agent",
        "runtime": normalize_agent_runtime(row["runtime"], row["agent_id"]),
        "role": str(row["role"] or "unassigned").lower(),
    }


def authorize_authenticated_bridge_peer(conn, principal, project_id,
                                         actor_id, actor_type,
                                         other_project):
    """Authorize the second durable workspace touched by bridge governance.

    The path/default workspace has already been authorized by REST/MCP.  A
    bridge add/update/remove also writes the peer's context and ledger, so its
    authority must be proven independently.  Ordinary targeted room delivery
    deliberately does not call this helper; an existing bridge policy governs
    that separate operation.
    """
    if not principal:
        return None  # bounded legacy/stdio compatibility behavior
    other = str(other_project or "").strip()
    if not other:
        raise AttaccaError("other_project is required")
    if actor_type == "human":
        if principal.get("is_admin"):
            return "human-admin"
        if auth_has_project_membership(conn, principal, other):
            return "human-member"
        raise AuthorizationError(
            "bridge_peer_membership_required: Attacca user '%s' has no"
            " governance access to workspace '%s'" %
            (principal.get("username") or principal.get("user_id"), other))

    token_kind = principal.get("token_kind")
    if actor_type == "agent" and token_kind == "client":
        source = conn.execute(
            "SELECT * FROM agents WHERE project_id=? AND agent_id=?",
            (project_id, actor_id)).fetchone()
        if not source or source["role"] != "director":
            raise AuthorizationError(
                "bridge_peer_actor_required: selected source actor is not a"
                " registered Director")
        auth_client_project_access(conn, principal, other)
        runtime = normalize_agent_runtime(source["runtime"], source["agent_id"])
        rows = conn.execute(
            "SELECT * FROM agents WHERE project_id=? AND role='director'",
            (other,)).fetchall()
        peers = [row for row in rows
            if auth_principal_owns_label(conn, principal, row["owner"])
            if normalize_agent_runtime(row["runtime"], row["agent_id"])
            == runtime]
        if len(peers) != 1:
            raise AuthorizationError(
                "bridge_peer_actor_required: client owner needs one matching"
                " Director runtime in workspace '%s'" % other)
        _require_bridge_manager(conn, other, peers[0]["agent_id"], "agent")
        return peers[0]["agent_id"]
    if actor_type != "agent" or token_kind not in ("terminal", "service"):
        raise AuthorizationError(
            "bridge_peer_actor_binding_required: this credential has no exact"
            " Director binding for workspace '%s'" % other)
    bindings = auth_terminal_bindings(conn, principal.get("token_id"))
    primary = [item for item in bindings
               if item["project_id"] == project_id
               and item["actor_id"] == actor_id]
    if len(primary) != 1 or primary[0].get("role") != "director":
        raise AuthorizationError(
            "bridge_peer_actor_binding_required: the selected source actor"
            " is not one exact Director binding")
    runtime = primary[0].get("runtime")
    peer = [item for item in bindings
            if item["project_id"] == other
            and item.get("runtime") == runtime
            and item.get("role") == "director"]
    if len(peer) != 1:
        raise AuthorizationError(
            "bridge_peer_actor_binding_required: credential needs one exact"
            " registered Director binding for runtime '%s' in workspace '%s'"
            % (runtime, other))
    _require_bridge_manager(
        conn, other, peer[0]["actor_id"], "agent")
    return peer[0]["actor_id"]


def _auth_validate_service_access(conn, principal, memberships, bindings):
    if not isinstance(memberships, list) or not memberships:
        raise AttaccaError("service credential needs at least one workspace")
    projects = []
    for value in memberships:
        project_id = get_project(conn, str(value or "").strip())["project_id"]
        if project_id not in projects:
            projects.append(project_id)
        if not principal.get("is_admin") and not auth_has_project_membership(
                conn, principal, project_id):
            raise AuthorizationError(
                "service_scope_denied: workspace membership is required")
    if bindings is None:
        bindings = []
    if not isinstance(bindings, list):
        raise AttaccaError("actor_bindings must be an array")
    normalized = []
    seen = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            raise AttaccaError("actor_bindings must contain objects")
        project_id = get_project(
            conn, str(binding.get("project_id") or "").strip())["project_id"]
        actor_id = str(binding.get("actor_id") or "").strip()
        if project_id not in projects:
            raise AttaccaError(
                "service actor binding must be inside its workspace scope")
        agent = conn.execute(
            "SELECT * FROM agents WHERE project_id=? AND agent_id=?",
            (project_id, actor_id)).fetchone()
        if not agent:
            raise AttaccaError(
                "service actor binding is not an existing registered actor")
        if not principal.get("is_admin") and str(agent["owner"] or "") != \
                str(principal.get("username") or ""):
            raise AuthorizationError(
                "service_actor_denied: actor is assigned to another user")
        key = (project_id, actor_id)
        if key not in seen:
            seen.add(key)
            normalized.append({
                "project_id": project_id, "actor_id": actor_id,
                "runtime": normalize_agent_runtime(
                    agent["runtime"], agent["agent_id"]),
            })
    return projects, normalized


def auth_service_key_create(conn, principal, label, memberships,
                            bindings=None, expires_at=None):
    label = str(label or "Service credential").strip()
    if not label or len(label) > 120:
        raise AttaccaError("service credential label must be 1-120 characters")
    projects, bindings = _auth_validate_service_access(
        conn, principal, memberships, bindings)
    expires_at = _auth_expiry(expires_at)
    token_id = new_id("svc")
    raw = "atsvc_%s.%s" % (token_id, secrets.token_urlsafe(32))
    nowi = now_iso()
    with write_tx(conn):
        conn.execute(
            "INSERT INTO auth_tokens"
            " (token_id,user_id,label,token_prefix,token_hash,token_kind,"
            " actor_id,actor_type,project_id,runtime,created_at,expires_at)"
            " VALUES (?,?,?,?,?,'service',NULL,'service',NULL,'service',?,?)",
            (token_id, principal["user_id"], label, raw[:18],
             sha256_hex(raw), nowi, expires_at))
        for project_id in projects:
            conn.execute(
                "INSERT INTO auth_token_project_bindings"
                " (token_id,project_id,created_at,revoked_at)"
                " VALUES (?,?,?,NULL)", (token_id, project_id, nowi))
        for binding in bindings:
            conn.execute(
                "INSERT INTO auth_token_actor_bindings"
                " (token_id,project_id,actor_id,runtime,created_at,revoked_at)"
                " VALUES (?,?,?,?,?,NULL)",
                (token_id, binding["project_id"], binding["actor_id"],
                 binding["runtime"], nowi))
    row = conn.execute(
        "SELECT * FROM auth_tokens WHERE token_id=?", (token_id,)).fetchone()
    record = auth_service_key_record(conn, row)
    return {"ok": True, "token": raw, "record": record,
            "warning": "credential plaintext is returned only in this response"}


def auth_service_key_record(conn, row):
    return {
        "token_id": row["token_id"], "label": row["label"],
        "token_prefix": row["token_prefix"], "token_kind": "service",
        "username": row["username"] if "username" in row.keys() else None,
        "project_memberships": auth_token_project_bindings(
            conn, row["token_id"]),
        "actor_bindings": auth_terminal_bindings(conn, row["token_id"]),
        "created_at": row["created_at"], "last_used_at": row["last_used_at"],
        "expires_at": row["expires_at"], "revoked_at": row["revoked_at"],
    }


def auth_service_key_revoke(conn, principal, token_id):
    row = conn.execute(
        "SELECT * FROM auth_tokens WHERE token_id=? AND token_kind='service'",
        (token_id,)).fetchone()
    if not row or (row["user_id"] != principal.get("user_id")
                   and not principal.get("is_admin")):
        raise AuthorizationError("service_credential_not_owned")
    nowi = now_iso()
    with write_tx(conn):
        conn.execute(
            "UPDATE auth_tokens SET revoked_at=? WHERE token_id=?"
            " AND revoked_at IS NULL", (nowi, token_id))
        conn.execute(
            "UPDATE auth_token_project_bindings SET revoked_at=?"
            " WHERE token_id=? AND revoked_at IS NULL", (nowi, token_id))
        conn.execute(
            "UPDATE auth_token_actor_bindings SET revoked_at=?"
            " WHERE token_id=? AND revoked_at IS NULL", (nowi, token_id))
    return {"ok": True, "token_id": token_id, "revoked": True}


def auth_invitation_create(conn, principal, label, memberships,
                           expires_at=None, is_admin=False):
    is_admin = bool(is_admin)
    if is_admin and not principal.get("is_owner"):
        raise AuthorizationError(
            "server_owner_required: only owner may invite an administrator")
    if not isinstance(memberships, list) or not memberships:
        raise AttaccaError("human invitation needs at least one workspace")
    projects = []
    for value in memberships:
        project_id = get_project(conn, str(value or "").strip())["project_id"]
        if project_id not in projects:
            projects.append(project_id)
    if expires_at is None:
        expires_at = (now_dt() + timedelta(hours=48)).strftime(
            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    else:
        expires_at = _auth_expiry(expires_at)
    invitation_id = new_id("inv")
    raw = "ati_%s.%s" % (invitation_id, secrets.token_urlsafe(32))
    record = {
        "invitation_id": invitation_id,
        "label": str(label or "Workspace invitation").strip()[:120],
        "invited_by": principal["username"],
        "is_admin": is_admin,
        "project_memberships": projects,
        "created_at": now_iso(), "expires_at": expires_at,
    }
    with write_tx(conn):
        conn.execute(
            "INSERT INTO auth_invitations"
            " (invitation_id,token_prefix,token_hash,label,invited_by,"
            " is_admin,project_memberships,created_at,expires_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (invitation_id, raw[:18], sha256_hex(raw), record["label"],
             principal["username"], 1 if is_admin else 0,
             canonical_json(projects),
             record["created_at"], expires_at))
    record.update({"token_prefix": raw[:18], "accepted_at": None,
                   "accepted_user_id": None, "revoked_at": None})
    return {"ok": True, "invitation_token": raw, "record": record,
            "warning": "invitation plaintext is returned only in this response"}


def auth_invitation_record(row):
    try:
        projects = json.loads(row["project_memberships"] or "[]")
    except ValueError:
        projects = []
    return {
        "invitation_id": row["invitation_id"], "label": row["label"],
        "token_prefix": row["token_prefix"], "invited_by": row["invited_by"],
        "is_admin": bool(row["is_admin"]),
        "project_memberships": projects, "created_at": row["created_at"],
        "expires_at": row["expires_at"], "accepted_at": row["accepted_at"],
        "accepted_user_id": row["accepted_user_id"],
        "revoked_at": row["revoked_at"],
    }


def auth_invitation_revoke(conn, principal, invitation_id):
    with write_tx(conn):
        cur = conn.execute(
            "UPDATE auth_invitations SET revoked_at=?"
            " WHERE invitation_id=? AND revoked_at IS NULL"
            " AND accepted_at IS NULL", (now_iso(), invitation_id))
        if cur.rowcount != 1:
            raise AttaccaError("unknown active human invitation")
    return {"ok": True, "invitation_id": invitation_id, "revoked": True}


def auth_invitation_accept(conn, raw_token, username, password,
                           display_name=None):
    raw = str(raw_token or "").strip()
    row = conn.execute(
        "SELECT * FROM auth_invitations WHERE token_hash=?",
        (sha256_hex(raw),)).fetchone() if raw else None
    if not row or row["revoked_at"] or row["accepted_at"] \
            or row["expires_at"] <= now_iso():
        raise AuthenticationError(
            "invalid_invitation: invitation is invalid, expired or consumed")
    username = _clean_username(username)
    salt = secrets.token_hex(16)
    digest = _password_hash(password, salt)
    user_id = new_id("usr")
    nowi = now_iso()
    projects = json.loads(row["project_memberships"] or "[]")
    with write_tx(conn):
        current = conn.execute(
            "SELECT * FROM auth_invitations WHERE invitation_id=?",
            (row["invitation_id"],)).fetchone()
        if not current or current["revoked_at"] or current["accepted_at"] \
                or current["expires_at"] <= nowi:
            raise AuthenticationError("invalid_invitation: already consumed")
        _auth_reject_username_alias_collision(conn, username)
        try:
            conn.execute(
                "INSERT INTO auth_users"
                " (user_id,username,display_name,password_salt,password_hash,"
                " password_iterations,is_admin,created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (user_id, username, username, salt, digest,
                 PASSWORD_ITERATIONS, 1 if current["is_admin"] else 0, nowi))
        except sqlite3.IntegrityError:
            raise AttaccaError("Attacca user '%s' already exists" % username)
        for project_id in projects:
            conn.execute(
                "INSERT INTO auth_project_memberships"
                " (user_id,project_id,granted_at,granted_by,revoked_at)"
                " VALUES (?,?,?,?,NULL)",
                (user_id, project_id, nowi, current["invited_by"]))
        conn.execute(
            "UPDATE auth_invitations SET accepted_at=?,accepted_user_id=?"
            " WHERE invitation_id=? AND accepted_at IS NULL",
            (nowi, user_id, row["invitation_id"]))
    user = conn.execute(
        "SELECT * FROM auth_users WHERE user_id=?", (user_id,)).fetchone()
    return {"ok": True, "accepted": True, "user": _public_auth_user(user),
            "project_memberships": projects}


def auth_migration_target_upsert(conn, project_id, actor_id, device_id,
                                 selected_by=None, required=True,
                                 exclusion_reason=None, in_tx=False):
    """Record only an observed/admin-selected client, never every old actor."""
    project_id = get_project(conn, project_id)["project_id"]
    actor_id = str(actor_id or "").strip()
    device_id = str(device_id or "").strip()
    if not actor_id or not device_id:
        raise AttaccaError("migration targets require actor_id and device_id")
    row = conn.execute(
        "SELECT 1 FROM agents WHERE project_id=? AND agent_id=?",
        (project_id, actor_id)).fetchone()
    if not row:
        raise AttaccaError(
            "migration target actor '%s' is not registered in workspace '%s'"
            % (actor_id, project_id))
    reason = str(exclusion_reason or "").strip() or None
    if not required and not reason:
        raise AttaccaError("an excluded migration client requires a reason")
    nowi = now_iso()
    existing = conn.execute(
        "SELECT * FROM auth_migration_targets"
        " WHERE project_id=? AND actor_id=? AND device_id=?",
        (project_id, actor_id, device_id)).fetchone()
    target_id = existing["target_id"] if existing else new_id("amt")
    if existing and selected_by == "compatibility-sync" \
            and bool(existing["migration_required"]) == bool(required) \
            and (existing["exclusion_reason"] or None) == reason:
        threshold = (now_dt() - timedelta(seconds=60)).strftime(
            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        if existing["last_seen_at"] and existing["last_seen_at"] > threshold:
            return target_id

    def apply():
        conn.execute(
            "INSERT INTO auth_migration_targets"
            " (target_id,project_id,actor_id,device_id,selected_at,selected_by,"
            " last_seen_at,migration_required,excluded_at,excluded_by,"
            " exclusion_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(project_id,actor_id,device_id) DO UPDATE SET"
            " last_seen_at=excluded.last_seen_at,"
            " migration_required=excluded.migration_required,"
            " excluded_at=excluded.excluded_at,"
            " excluded_by=excluded.excluded_by,"
            " exclusion_reason=excluded.exclusion_reason",
            (target_id, project_id, actor_id, device_id, nowi, selected_by,
             nowi, 1 if required else 0, None if required else nowi,
             None if required else selected_by, reason))

    if in_tx:
        apply()
    else:
        with write_tx(conn):
            apply()
    return target_id


def _auth_target_coverage(conn, target):
    rows = conn.execute(
        "SELECT DISTINCT t.token_id FROM auth_tokens t"
        " JOIN auth_token_actor_bindings b ON b.token_id=t.token_id"
        " JOIN agents a ON a.project_id=b.project_id AND a.agent_id=b.actor_id"
        " JOIN auth_project_memberships m ON m.user_id=t.user_id"
        "  AND m.project_id=b.project_id"
        " JOIN auth_users u ON u.user_id=t.user_id"
        " WHERE t.token_kind='terminal' AND t.revoked_at IS NULL"
        " AND (t.expires_at IS NULL OR t.expires_at>?)"
        " AND t.device_id=? AND b.project_id=? AND b.actor_id=?"
        " AND b.revoked_at IS NULL AND m.revoked_at IS NULL"
        " AND u.disabled_at IS NULL ORDER BY t.token_id",
        (now_iso(), target["device_id"], target["project_id"],
         target["actor_id"])).fetchall()
    return [row["token_id"] for row in rows]


def auth_activation_readiness(conn, server=None, include_details=True):
    """Return the simple D-17 enforcement state.

    Creating/revoking client keys and flipping enforcement are deliberately
    separate owner actions.  There is no device-code enrollment, actor-binding
    migration inventory, source-hash latch, or test-result gate in the product
    API.  Release QA remains a development responsibility, not a login mode.
    """
    nowi = now_iso()
    bootstrapped = auth_is_enabled(conn)
    client_count = conn.execute(
        "SELECT COUNT(*) AS n FROM auth_tokens t JOIN auth_users u"
        " ON u.user_id=t.user_id WHERE t.token_kind='client'"
        " AND t.revoked_at IS NULL"
        " AND (t.expires_at IS NULL OR t.expires_at>?)"
        " AND u.disabled_at IS NULL", (nowi,)).fetchone()["n"]
    blockers = [] if bootstrapped else [
        "create the first administrator account"]
    state_material = {
        "bootstrapped": bootstrapped,
        "client_key_count": client_count,
        "activated": bool(_auth_setting(conn, "auth.activated", False)),
    }
    readiness_version = sha256_hex(canonical_json(state_material))[:24]
    persisted_requested = bool(_auth_setting(
        conn, "auth.activation_requested", False) or
        _auth_setting(conn, "authentication", False))
    activated = bool(_auth_setting(conn, "auth.activated", False))
    runtime_requested = bool(getattr(server, "auth_requested", False)) \
        if server is not None else False
    mode = getattr(server, "auth_mode", "auto") if server is not None \
        else "auto"
    result = {
        "mode": mode,
        "effective_authentication": (
            "optional" if mode == "compatibility" or not activated
            else "required"),
        "activation_requested": persisted_requested or runtime_requested,
        "activated": activated,
        "ready": not blockers,
        "readiness_version": readiness_version,
        "blockers": blockers,
        "client_key_count": client_count,
        # Deprecated response keys stay zero-valued for one release so old
        # panels fail harmlessly while the unsafe flows themselves disappear.
        "terminal_count": 0,
        "selected_client_count": 0,
        "uncovered_client_count": 0,
        "qa_evidence": None,
        "launch_artifact_sha256": None,
        "disk_artifact_sha256": None,
        "artifact_unchanged": None,
    }
    if include_details:
        result["migration_targets"] = []
        result["uncovered_clients"] = []
    return result


def auth_compatibility_active(conn, server):
    """Whether legacy clients may use the bounded migration bridge.

    A normal restart must remain fail-open-for-migration until the owner has
    explicitly activated enforcement.  Selecting compatibility mode keeps the
    same bridge available even after activation data exists.
    """
    return bool(getattr(server, "auth_mode", "auto") == "compatibility" or
                not _auth_setting(conn, "auth.activated", False))


def auth_create_user(conn, username, password, display_name=None,
                     is_admin=False, bootstrap=False):
    username = _clean_username(username)
    salt = secrets.token_hex(16)
    digest = _password_hash(password, salt)
    with write_tx(conn):
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM auth_users").fetchone()["n"]
        if bootstrap and count:
            raise AttaccaError("authentication is already bootstrapped")
        user_id = new_id("usr")
        _auth_reject_username_alias_collision(conn, username)
        try:
            conn.execute(
                "INSERT INTO auth_users (user_id, username, display_name,"
                " password_salt, password_hash, password_iterations, is_admin,"
                " created_at) VALUES (?,?,?,?,?,?,?,?)",
                (user_id, username, username, salt, digest,
                 PASSWORD_ITERATIONS, 1 if (is_admin or not count) else 0,
                 now_iso()))
        except sqlite3.IntegrityError:
            raise AttaccaError("Attacca user '%s' already exists" % username)
        if not count:
            conn.execute(
                "INSERT INTO server_settings(setting_key,value,updated_at)"
                " VALUES ('auth.owner_user_id',?,?)"
                " ON CONFLICT(setting_key) DO NOTHING",
                (json.dumps(user_id), now_iso()))
        row = conn.execute(
            "SELECT * FROM auth_users WHERE user_id=?", (user_id,)).fetchone()
    return {"ok": True, "user": _public_auth_user(row)}


def auth_reset_password(conn, username, password):
    username = _clean_username(username)
    salt = secrets.token_hex(16)
    digest = _password_hash(password, salt)
    with write_tx(conn):
        cur = conn.execute(
            "UPDATE auth_users SET password_salt=?, password_hash=?,"
            " password_iterations=? WHERE username=? AND disabled_at IS NULL",
            (salt, digest, PASSWORD_ITERATIONS, username))
        if cur.rowcount != 1:
            raise AttaccaError("unknown active Attacca user '%s'" % username)
        conn.execute(
            "UPDATE auth_sessions SET revoked_at=? WHERE user_id=(SELECT user_id"
            " FROM auth_users WHERE username=?) AND revoked_at IS NULL",
            (now_iso(), username))
    return {"ok": True, "username": username, "sessions_revoked": True}


def auth_verify_user(conn, username, password):
    try:
        username = _clean_username(username)
    except AttaccaError:
        return None
    row = conn.execute(
        "SELECT * FROM auth_users WHERE username=? AND disabled_at IS NULL",
        (username,)).fetchone()
    if not row:
        # Spend roughly the same work for unknown accounts.
        _password_hash("invalid-password", "00" * 16)
        return None
    try:
        supplied = _password_hash(
            str(password or ""), row["password_salt"],
            row["password_iterations"])
    except AttaccaError:
        return None
    return row if hmac.compare_digest(supplied, row["password_hash"]) else None


def auth_create_session(conn, user_row):
    raw = "ats_" + secrets.token_urlsafe(32)
    csrf = "csrf_" + secrets.token_urlsafe(24)
    created = now_iso()
    expires = (now_dt() + timedelta(hours=SESSION_HOURS)).strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    with write_tx(conn):
        conn.execute(
            "INSERT INTO auth_sessions (session_hash, user_id, csrf_hash,"
            " created_at, last_seen_at, expires_at) VALUES (?,?,?,?,?,?)",
            (sha256_hex(raw), user_row["user_id"], sha256_hex(csrf),
             created, created, expires))
    return {"session": raw, "csrf": csrf, "expires_at": expires,
            "user": _public_auth_user(user_row)}


def _auth_principal(conn, user_row, kind, **extra):
    result = {"user_id": user_row["user_id"],
              "username": user_row["username"],
              "display_name": user_row["username"],
              "is_admin": bool(user_row["is_admin"]),
              "is_owner": bool(user_row["user_id"] == _auth_setting(
                  conn, "auth.owner_user_id", None)),
              "auth_kind": kind}
    result.update(extra)
    return result


def auth_is_activation_owner(conn, principal):
    """Whether this authenticated account is the one canonical server owner.

    Migration-target detail is account-wide activation governance data.  It
    must not become visible merely because a user is logged in or was granted
    server-admin status; ownership is the immutable user-id stored at initial
    bootstrap (or its explicit server migration).
    """
    return bool(
        principal and principal.get("user_id") and
        principal["user_id"] == _auth_setting(
            conn, "auth.owner_user_id", None))


def auth_session_principal(conn, raw_session):
    if not raw_session:
        return None
    row = conn.execute(
        "SELECT s.*, u.* FROM auth_sessions s JOIN auth_users u"
        " ON u.user_id=s.user_id WHERE s.session_hash=?"
        " AND s.revoked_at IS NULL AND s.expires_at>?"
        " AND u.disabled_at IS NULL",
        (sha256_hex(raw_session), now_iso())).fetchone()
    if not row:
        return None
    conn.execute("UPDATE auth_sessions SET last_seen_at=? WHERE session_hash=?",
                 (now_iso(), sha256_hex(raw_session)))
    return _auth_principal(
        conn, row, "session", session_hash=sha256_hex(raw_session),
        csrf_hash=row["csrf_hash"], actor_type="human")


def auth_token_create(conn, username, label, actor_id=None,
                      actor_type="agent", project_id=None, runtime=None,
                      expires_at=None):
    username = _clean_username(username)
    expires_at = _auth_expiry(expires_at)
    label = str(label or "API token").strip()
    if not label:
        raise AttaccaError("token label is required")
    if len(label) > 120:
        raise AttaccaError("token label must be 120 characters or fewer")
    actor_type = str(actor_type or "agent").lower()
    if actor_type not in ("agent", "human"):
        raise AttaccaError("token actor_type must be agent or human")
    user = conn.execute(
        "SELECT * FROM auth_users WHERE username=? AND disabled_at IS NULL",
        (username,)).fetchone()
    if not user:
        raise AttaccaError("unknown active Attacca user '%s'" % username)
    if actor_type == "agent":
        if not project_id or not actor_id:
            raise AttaccaError("agent tokens require project_id and actor_id")
        agent = conn.execute(
            "SELECT * FROM agents WHERE project_id=? AND agent_id=?",
            (project_id, actor_id)).fetchone()
        if not agent:
            raise AttaccaError(
                "create/register agent '%s' in workspace '%s' before its token"
                % (actor_id, project_id))
        if agent["owner"] and agent["owner"] != username \
                and not bool(user["is_admin"]):
            raise AuthorizationError(
                "agent '%s' belongs to Attacca user '%s'" %
                (actor_id, agent["owner"]))
        runtime = normalize_agent_runtime(runtime or agent["runtime"], actor_id)
    else:
        actor_id = None
        project_id = None
        runtime = normalize_agent_runtime(runtime or "cli")
    token_id = new_id("tok")
    raw = "atc_%s.%s" % (token_id, secrets.token_urlsafe(32))
    with write_tx(conn):
        conn.execute(
            "INSERT INTO auth_tokens (token_id, user_id, label, token_prefix,"
            " token_hash,token_kind,actor_id,actor_type,project_id,runtime,"
            " created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (token_id, user["user_id"], label, raw[:18], sha256_hex(raw),
             "actor" if actor_type == "agent" else "human", actor_id,
             actor_type, project_id, runtime, now_iso(), expires_at))
    return {"ok": True, "token": raw,
            "warning": "copy this token now; Attacca stores only its hash",
            "record": {"token_id": token_id, "label": label,
                       "token_prefix": raw[:18], "actor_id": actor_id,
                       "actor_type": actor_type, "project_id": project_id,
                       "token_kind": ("actor" if actor_type == "agent"
                                      else "human"),
                       "runtime": runtime, "created_at": now_iso(),
                       "expires_at": expires_at, "revoked_at": None}}


def auth_token_principal(conn, raw_token):
    if not raw_token:
        return None
    row = conn.execute(
        "SELECT t.*, u.username, u.display_name, u.is_admin, u.disabled_at"
        " FROM auth_tokens t JOIN auth_users u ON u.user_id=t.user_id"
        " WHERE t.token_hash=? AND t.revoked_at IS NULL"
        " AND (t.expires_at IS NULL OR t.expires_at>?)"
        " AND u.disabled_at IS NULL",
        (sha256_hex(raw_token), now_iso())).fetchone()
    if not row:
        return None
    used_at = now_iso()
    threshold = (now_dt() - timedelta(seconds=60)).strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    conn.execute(
        "UPDATE auth_tokens SET last_used_at=? WHERE token_id=?"
        " AND (last_used_at IS NULL OR last_used_at<?)",
        (used_at, row["token_id"], threshold))
    principal = _auth_principal(
        conn, row, "token", token_id=row["token_id"],
        token_kind=row["token_kind"], device_id=row["device_id"],
        client_label=row["client_label"],
        client_instance=row["client_instance"],
        expires_at=row["expires_at"],
        actor_id=row["actor_id"], actor_type=row["actor_type"],
        project_id=row["project_id"], runtime=row["runtime"])
    if row["token_kind"] in ("client", "service"):
        # A human owns and is attributed on a client/service credential, but
        # a bearer never inherits account-admin/server-owner authority.  A
        # client key receives only the separately registered actor's project
        # role selected on the current request.
        principal["owner_is_admin"] = principal["is_admin"]
        principal["owner_is_owner"] = principal["is_owner"]
        principal["is_admin"] = False
        principal["is_owner"] = False
    return principal


def auth_token_list(conn, username):
    username = _clean_username(username)
    rows = conn.execute(
        "SELECT t.* FROM auth_tokens t JOIN auth_users u ON u.user_id=t.user_id"
        " WHERE u.username=? ORDER BY t.created_at DESC", (username,)).fetchall()
    records = []
    for row in rows:
        record = {key: row[key] for key in
                  ("token_id", "label", "token_prefix", "token_kind",
                   "actor_id", "actor_type", "project_id", "runtime",
                   "device_id", "client_label", "created_at", "last_used_at",
                   "expires_at", "revoked_at")}
        if row["token_kind"] == "terminal":
            record["bindings"] = auth_terminal_bindings(conn, row["token_id"])
        elif row["token_kind"] == "client":
            record["project_memberships"] = auth_token_project_bindings(
                conn, row["token_id"])
        records.append(record)
    return {"username": username, "tokens": records}


def auth_token_revoke(conn, username, token_id):
    username = _clean_username(username)
    with write_tx(conn):
        cur = conn.execute(
            "UPDATE auth_tokens SET revoked_at=? WHERE token_id=?"
            " AND user_id=(SELECT user_id FROM auth_users WHERE username=?)"
            " AND revoked_at IS NULL", (now_iso(), token_id, username))
        if cur.rowcount != 1:
            raise AttaccaError("unknown active token %s for %s"
                               % (token_id, username))
    return {"ok": True, "token_id": token_id, "revoked": True}


def _auth_device_code():
    return "atd_" + secrets.token_urlsafe(32)


def _auth_user_code(conn):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    for _ in range(20):
        raw = "".join(secrets.choice(alphabet) for _ in range(8))
        code = raw[:4] + "-" + raw[4:]
        if not conn.execute(
                "SELECT 1 FROM auth_device_enrollments WHERE user_code=?",
                (code,)).fetchone():
            return code
    raise AttaccaError("could not allocate a terminal enrollment code")


def auth_device_start(conn, base_url, device_id, client_label,
                      requested_bindings=None, client_instance=None,
                      supersede_token_id=None, principal=None):
    device_id = str(device_id or "").strip()
    client_label = str(client_label or "").strip()
    if not device_id or len(device_id) > 200:
        raise AttaccaError("device_id is required and must be 200 characters or fewer")
    if not client_label or len(client_label) > 120:
        raise AttaccaError(
            "client_label is required and must be 120 characters or fewer")
    client_instance = str(client_instance or "").strip() or None
    if client_instance and len(client_instance) > 120:
        raise AttaccaError("client_instance must be 120 characters or fewer")
    supersede_token_id = str(supersede_token_id or "").strip() or None
    if supersede_token_id:
        if not principal or principal.get("token_kind") != "terminal" \
                or principal.get("token_id") != supersede_token_id \
                or principal.get("device_id") != device_id:
            raise AuthorizationError(
                "superseded terminal credential must authenticate this device")
    requested = requested_bindings or []
    if not isinstance(requested, list) or any(
            not isinstance(item, dict) for item in requested):
        raise AttaccaError("requested_bindings must be an array of objects")
    compact = []
    for item in requested:
        project_id = str(item.get("project_id") or "").strip()
        actor_id = str(item.get("actor_id") or "").strip()
        if not project_id or not actor_id:
            raise AttaccaError(
                "each requested binding needs project_id and actor_id")
        compact.append({"project_id": project_id, "actor_id": actor_id})
    if supersede_token_id:
        # The server, not a possibly stale/buggy client, owns replacement
        # continuity. Preserve every still-active exact binding from the old
        # device credential and let the approval add to that union.
        known = {(item["project_id"], item["actor_id"])
                 for item in compact}
        for binding in auth_terminal_bindings(conn, supersede_token_id):
            key = (binding["project_id"], binding["actor_id"])
            if key not in known:
                known.add(key)
                compact.append({"project_id": key[0], "actor_id": key[1]})
    raw_code = _auth_device_code()
    user_code = _auth_user_code(conn)
    created = now_iso()
    expires = (now_dt() + timedelta(
        minutes=DEVICE_ENROLLMENT_MINUTES)).strftime(
            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    with write_tx(conn):
        conn.execute(
            "INSERT INTO auth_device_enrollments"
            " (device_code_hash,user_code,device_id,client_label,client_instance,"
            " supersede_token_id,"
            " requested_bindings,status,interval_seconds,created_at,expires_at)"
            " VALUES (?,?,?,?,?,?,?,'pending',?,?,?)",
            (sha256_hex(raw_code), user_code, device_id, client_label,
             client_instance, supersede_token_id,
             canonical_json(compact), DEVICE_ENROLLMENT_INTERVAL_SECONDS,
             created, expires))
    verification_uri = base_url.rstrip("/") + "/app#settings"
    verification_uri_complete = "%s/app?user_code=%s#settings" % (
        base_url.rstrip("/"), urllib.parse.quote(user_code, safe=""))
    return {
        "device_code": raw_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete,
        "expires_in": DEVICE_ENROLLMENT_MINUTES * 60,
        "interval": DEVICE_ENROLLMENT_INTERVAL_SECONDS,
    }


def _auth_device_row(conn, user_code):
    code = str(user_code or "").strip().upper()
    row = conn.execute(
        "SELECT * FROM auth_device_enrollments WHERE user_code=?", (code,)
    ).fetchone()
    if not row:
        raise AttaccaError("unknown terminal enrollment code")
    if row["expires_at"] <= now_iso() and row["status"] in (
            "pending", "approved"):
        with write_tx(conn):
            conn.execute(
                "UPDATE auth_device_enrollments SET status='expired'"
                " WHERE device_code_hash=?",
                (row["device_code_hash"],))
        raise AttaccaError("terminal enrollment code expired")
    return row


def _auth_validate_enrollment_access(conn, principal, memberships, bindings):
    if not isinstance(memberships, list):
        raise AttaccaError("project_memberships must be an array")
    if not memberships and not principal.get("is_admin"):
        raise AttaccaError(
            "a non-admin provisional terminal needs a project membership")
    normalized_memberships = []
    for project_id in memberships:
        resolved = get_project(conn, str(project_id or "").strip())["project_id"]
        if resolved not in normalized_memberships:
            normalized_memberships.append(resolved)
    if not isinstance(bindings, list):
        raise AttaccaError("actor_bindings must be an array")
    normalized_bindings = []
    seen = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            raise AttaccaError("actor_bindings must contain objects")
        project_id = get_project(
            conn, str(binding.get("project_id") or "").strip())["project_id"]
        actor_id = str(binding.get("actor_id") or "").strip()
        if project_id not in normalized_memberships:
            raise AttaccaError(
                "actor binding workspace '%s' is not a granted membership" %
                project_id)
        agent = conn.execute(
            "SELECT * FROM agents WHERE project_id=? AND agent_id=?",
            (project_id, actor_id)).fetchone()
        if not agent:
            raise AttaccaError(
                "actor '%s' is not registered in workspace '%s'" %
                (actor_id, project_id))
        if not principal.get("is_admin") \
                and str(agent["owner"] or "").strip().lower() != \
                str(principal.get("username") or "").strip().lower():
            raise AuthorizationError(
                "actor '%s' is not explicitly assigned to this Attacca user" %
                actor_id)
        key = (project_id, actor_id)
        if key in seen:
            continue
        seen.add(key)
        normalized_bindings.append({
            "project_id": project_id,
            "actor_id": actor_id,
            "runtime": normalize_agent_runtime(
                agent["runtime"], agent["agent_id"]),
        })
    if not principal.get("is_admin"):
        for project_id in normalized_memberships:
            if not conn.execute(
                    "SELECT 1 FROM auth_project_memberships"
                    " WHERE user_id=? AND project_id=? AND revoked_at IS NULL",
                    (principal["user_id"], project_id)).fetchone():
                raise AuthorizationError(
                    "only an administrator may grant a new project membership")
    return normalized_memberships, normalized_bindings


def auth_device_approve(conn, user_code, principal, memberships, bindings,
                        expires_at=None):
    row = _auth_device_row(conn, user_code)
    if row["status"] != "pending":
        raise AttaccaError(
            "terminal enrollment is already %s" % row["status"])
    if row["supersede_token_id"]:
        superseded = conn.execute(
            "SELECT * FROM auth_tokens WHERE token_id=?"
            " AND token_kind='terminal' AND revoked_at IS NULL"
            " AND (expires_at IS NULL OR expires_at>?)",
            (row["supersede_token_id"], now_iso())).fetchone()
        if not superseded or superseded["user_id"] != principal.get("user_id") \
                or superseded["device_id"] != row["device_id"]:
            raise AuthorizationError(
                "terminal_replacement_owner_required: only the current"
                " credential owner may approve its replacement")
    memberships, bindings = _auth_validate_enrollment_access(
        conn, principal, memberships, bindings)
    requested = json.loads(row["requested_bindings"] or "[]")
    approved_keys = {(item["project_id"], item["actor_id"])
                     for item in bindings}
    missing = [item for item in requested
               if (get_project(conn, item.get("project_id"))["project_id"],
                   str(item.get("actor_id") or "").strip()) not in approved_keys]
    if missing:
        raise AuthorizationError(
            "terminal_requested_binding_missing: approval must preserve every"
            " actor binding requested by the device")
    expires_at = _auth_expiry(expires_at)
    approval = {
        "user_id": principal["user_id"],
        "username": principal["username"],
        "project_memberships": memberships,
        "actor_bindings": bindings,
        "expires_at": expires_at,
    }
    nowi = now_iso()
    with write_tx(conn):
        current = conn.execute(
            "SELECT status FROM auth_device_enrollments"
            " WHERE device_code_hash=?", (row["device_code_hash"],)
        ).fetchone()
        if not current or current["status"] != "pending":
            raise AttaccaError(
                "terminal enrollment is already %s" % (
                    current["status"] if current else "unavailable"))
        cur = conn.execute(
            "UPDATE auth_device_enrollments SET status='approved',"
            " approved_by=?,approved_at=?,approval_json=?"
            " WHERE device_code_hash=? AND status='pending'",
            (principal["username"], nowi, canonical_json(approval),
             row["device_code_hash"]))
        if cur.rowcount != 1:
            raise AttaccaError("terminal enrollment approval raced; reload")
    return {
        "ok": True, "status": "approved", "user_code": row["user_code"],
        "device_id": row["device_id"], "client_label": row["client_label"],
        "project_memberships": memberships, "actor_bindings": bindings,
        "credential_issued": False,
        "note": ("the device-held secret is promoted on poll; retries are "
                 "idempotent until verified use"),
    }


def auth_device_deny(conn, user_code, principal):
    row = _auth_device_row(conn, user_code)
    if row["status"] != "pending":
        raise AttaccaError(
            "terminal enrollment is already %s" % row["status"])
    with write_tx(conn):
        current = conn.execute(
            "SELECT status FROM auth_device_enrollments"
            " WHERE device_code_hash=?", (row["device_code_hash"],)
        ).fetchone()
        if not current or current["status"] != "pending":
            raise AttaccaError(
                "terminal enrollment is already %s" % (
                    current["status"] if current else "unavailable"))
        cur = conn.execute(
            "UPDATE auth_device_enrollments SET status='denied',denied_at=?,"
            " approved_by=? WHERE device_code_hash=? AND status='pending'",
            (now_iso(), principal["username"], row["device_code_hash"]))
        if cur.rowcount != 1:
            raise AttaccaError("terminal enrollment denial raced; reload")
    return {"ok": True, "status": "denied", "user_code": row["user_code"]}


def _auth_issue_terminal_from_flow(conn, row, raw_device_code):
    approval = json.loads(row["approval_json"] or "{}")
    user = conn.execute(
        "SELECT * FROM auth_users WHERE user_id=? AND disabled_at IS NULL",
        (approval.get("user_id"),)).fetchone()
    if not user:
        raise AuthenticationError("terminal enrollment owner is unavailable")
    raw = str(raw_device_code or "").strip()
    if not raw or not hmac.compare_digest(
            sha256_hex(raw), row["device_code_hash"]):
        raise AuthenticationError("invalid terminal device enrollment")
    token_id = row["issued_token_id"] or new_id("tok")
    nowi = now_iso()
    with write_tx(conn):
        current = conn.execute(
            "SELECT * FROM auth_device_enrollments WHERE device_code_hash=?",
            (row["device_code_hash"],)).fetchone()
        if current["issued_token_id"]:
            token_id = current["issued_token_id"]
        else:
            conn.execute(
                "INSERT INTO auth_tokens"
                " (token_id,user_id,label,token_prefix,token_hash,token_kind,"
                " actor_id,actor_type,project_id,runtime,device_id,client_label,"
                " client_instance,created_at,expires_at)"
                " VALUES (?,?,?,?,?,'terminal',NULL,'agent',NULL,NULL,?,?,?,?,?)",
                (token_id, user["user_id"], row["client_label"], raw[:18],
                 row["device_code_hash"], row["device_id"],
                 row["client_label"], row["client_instance"], nowi,
                 approval.get("expires_at")))
            for project_id in approval.get("project_memberships") or []:
                conn.execute(
                    "INSERT INTO auth_project_memberships"
                    " (user_id,project_id,granted_at,granted_by,revoked_at)"
                    " VALUES (?,?,?,?,NULL)"
                    " ON CONFLICT(user_id,project_id) DO UPDATE SET"
                    " revoked_at=NULL,granted_at=excluded.granted_at,"
                    " granted_by=excluded.granted_by",
                    (user["user_id"], project_id, nowi, row["approved_by"]))
            for binding in approval.get("actor_bindings") or []:
                conn.execute(
                    "INSERT INTO auth_token_actor_bindings"
                    " (token_id,project_id,actor_id,runtime,created_at,revoked_at)"
                    " VALUES (?,?,?,?,?,NULL)",
                    (token_id, binding["project_id"], binding["actor_id"],
                     binding.get("runtime"), nowi))
                auth_migration_target_upsert(
                    conn, binding["project_id"], binding["actor_id"],
                    row["device_id"], selected_by=row["approved_by"],
                    required=True, in_tx=True)
            # Do not consume here: delivery is not proven.  The first valid
            # authenticated use of this already-held device secret marks the
            # enrollment consumed.  Until then, retries deterministically
            # return the same bearer without storing its plaintext.
            conn.execute(
                "UPDATE auth_device_enrollments SET issued_token_id=?"
                " WHERE device_code_hash=? AND issued_token_id IS NULL",
                (token_id, row["device_code_hash"]))
            if row["supersede_token_id"]:
                old = conn.execute(
                    "SELECT * FROM auth_tokens WHERE token_id=?"
                    " AND token_kind='terminal' AND revoked_at IS NULL"
                    " AND (expires_at IS NULL OR expires_at>?)",
                    (row["supersede_token_id"], now_iso())).fetchone()
                if not old or old["user_id"] != user["user_id"] \
                        or old["device_id"] != row["device_id"]:
                    raise AuthorizationError(
                        "terminal replacement owner/device mismatch")
                conn.execute(
                    "UPDATE auth_tokens SET revoked_at=? WHERE token_id=?"
                    " AND revoked_at IS NULL", (nowi, old["token_id"]))
                conn.execute(
                    "UPDATE auth_token_actor_bindings SET revoked_at=?"
                    " WHERE token_id=? AND revoked_at IS NULL",
                    (nowi, old["token_id"]))
    record_row = conn.execute(
        "SELECT * FROM auth_tokens WHERE token_id=?", (token_id,)).fetchone()
    record = auth_terminal_record(conn, record_row)
    record["token"] = raw
    return record


def auth_device_poll(conn, device_code, device_id, client_instance=None):
    raw_code = str(device_code or "").strip()
    device_id = str(device_id or "").strip()
    client_instance = str(client_instance or "").strip() or None
    if client_instance and len(client_instance) > 120:
        raise AttaccaError("client_instance must be 120 characters or fewer")
    row = conn.execute(
        "SELECT * FROM auth_device_enrollments WHERE device_code_hash=?",
        (sha256_hex(raw_code),)).fetchone()
    if not row or not hmac.compare_digest(row["device_id"], device_id):
        raise AuthenticationError("invalid terminal device enrollment")
    if row["client_instance"] and not client_instance:
        raise AuthenticationError("terminal enrollment client instance missing")
    if row["client_instance"] and not hmac.compare_digest(
            row["client_instance"], client_instance):
        raise AuthenticationError("terminal enrollment client instance mismatch")
    if client_instance and not row["client_instance"]:
        with write_tx(conn):
            conn.execute(
                "UPDATE auth_device_enrollments SET client_instance=?"
                " WHERE device_code_hash=? AND client_instance IS NULL",
                (client_instance, row["device_code_hash"]))
        row = conn.execute(
            "SELECT * FROM auth_device_enrollments WHERE device_code_hash=?",
            (row["device_code_hash"],)).fetchone()
    nowi = now_iso()
    if row["expires_at"] <= nowi and row["status"] in (
            "pending", "approved"):
        with write_tx(conn):
            conn.execute(
                "UPDATE auth_device_enrollments SET status='expired'"
                " WHERE device_code_hash=?", (row["device_code_hash"],))
        return {"status": "expired"}
    # Rate-limit only a still-pending authorization.  Once approved, replaying
    # the response must be immediate so a dropped HTTP response cannot strand
    # a device that already holds the promoted high-entropy code.
    if row["status"] == "pending" and row["last_polled_at"]:
        last = datetime.fromisoformat(row["last_polled_at"].replace("Z", "+00:00"))
        if (now_dt() - last).total_seconds() < row["interval_seconds"]:
            return {"status": "slow_down", "interval": row["interval_seconds"]}
    with write_tx(conn):
        conn.execute(
            "UPDATE auth_device_enrollments SET last_polled_at=?"
            " WHERE device_code_hash=?", (nowi, row["device_code_hash"]))
    if row["status"] == "pending":
        return {"status": "pending", "interval": row["interval_seconds"]}
    if row["status"] in ("denied", "expired"):
        return {"status": row["status"]}
    if row["status"] == "consumed" or row["consumed_at"]:
        return {"status": "consumed"}
    if row["status"] != "approved":
        raise AttaccaError("invalid terminal enrollment state")
    credential = _auth_issue_terminal_from_flow(conn, row, raw_code)
    return {"status": "approved", "credential": credential}


def auth_terminal_principal_binding(conn, principal, project_id,
                                    claimed_actor=None):
    if principal.get("token_kind") != "terminal":
        raise AuthorizationError("credential is not a terminal token")
    project_id = get_project(conn, project_id)["project_id"]
    if not conn.execute(
            "SELECT 1 FROM auth_project_memberships"
            " WHERE user_id=? AND project_id=? AND revoked_at IS NULL",
            (principal["user_id"], project_id)).fetchone():
        raise AuthorizationError(
            "terminal credential has no membership in workspace '%s'" %
            project_id)
    bindings = auth_terminal_bindings(conn, principal["token_id"])
    candidates = [item for item in bindings
                  if item["project_id"] == project_id]
    claimed = str(claimed_actor or "").strip()
    if claimed:
        exact = [item for item in candidates if item["actor_id"] == claimed]
        if exact:
            candidates = exact
        elif "." in claimed:
            # A full actor claim is an authorization claim, never a runtime
            # hint. Do not silently act as bound actor A when the request
            # explicitly names unbound same-runtime actor B.
            candidates = []
        else:
            runtime = normalize_agent_runtime(actor=claimed)
            candidates = [item for item in candidates
                          if item["runtime"] == runtime]
    if len(candidates) != 1:
        raise AuthorizationError(
            "terminal credential requires one exact allowed actor binding"
            " for workspace '%s'" % project_id)
    return candidates[0]


def auth_terminal_add_binding(conn, principal, token_id, project_id, actor_id):
    token = conn.execute(
        "SELECT * FROM auth_tokens WHERE token_id=? AND token_kind='terminal'"
        " AND revoked_at IS NULL", (token_id,)).fetchone()
    if not token or (token["user_id"] != principal.get("user_id")
                     and not principal.get("is_admin")):
        raise AuthorizationError("terminal_credential_not_owned")
    if conn.execute(
            "SELECT 1 FROM auth_token_actor_bindings WHERE token_id=? LIMIT 1",
            (token_id,)).fetchone():
        raise AuthorizationError(
            "terminal_binding_extension_requires_enrollment: direct self-binding"
            " is limited to a zero-binding provisional terminal")
    project_id = get_project(conn, project_id)["project_id"]
    actor_id = str(actor_id or "").strip()
    agent = conn.execute(
        "SELECT * FROM agents WHERE project_id=? AND agent_id=?",
        (project_id, actor_id)).fetchone()
    if not agent:
        raise AttaccaError(
            "terminal_binding_actor_missing: exact registered actor required")
    if not principal.get("is_admin") and str(agent["owner"] or "") != \
            str(principal.get("username") or ""):
        raise AuthorizationError(
            "terminal_binding_actor_denied: actor is assigned to another user")
    if not principal.get("is_admin") and not auth_has_project_membership(
            conn, principal, project_id):
        raise AuthorizationError("terminal_project_membership_required")
    nowi = now_iso()
    with write_tx(conn):
        if principal.get("is_admin"):
            conn.execute(
                "INSERT INTO auth_project_memberships"
                " (user_id,project_id,granted_at,granted_by,revoked_at)"
                " VALUES (?,?,?,?,NULL)"
                " ON CONFLICT(user_id,project_id) DO UPDATE SET"
                " revoked_at=NULL,granted_at=excluded.granted_at,"
                " granted_by=excluded.granted_by",
                (token["user_id"], project_id, nowi,
                 principal.get("username")))
        conn.execute(
            "INSERT INTO auth_token_actor_bindings"
            " (token_id,project_id,actor_id,runtime,created_at,revoked_at)"
            " VALUES (?,?,?,?,?,NULL)"
            " ON CONFLICT(token_id,project_id,actor_id) DO UPDATE SET"
            " runtime=excluded.runtime,created_at=excluded.created_at,"
            " revoked_at=NULL",
            (token_id, project_id, actor_id,
             normalize_agent_runtime(agent["runtime"], actor_id), nowi))
        auth_migration_target_upsert(
            conn, project_id, actor_id, token["device_id"],
            selected_by=principal.get("username"), required=True, in_tx=True)
        append_event(
            conn, project_id, "web.%s" % principal["username"], "human",
            "auth.terminal_binding_added", {
                "token_id": token_id, "device_id": token["device_id"],
                "actor_id": actor_id,
            }, in_tx=True)
    row = conn.execute(
        "SELECT * FROM auth_tokens WHERE token_id=?", (token_id,)).fetchone()
    return {"ok": True, "record": auth_terminal_record(conn, row)}


def auth_service_principal_scope(conn, principal, project_id,
                                 claimed_actor=None):
    if principal.get("token_kind") != "service":
        raise AuthorizationError("credential is not a service credential")
    project_id = get_project(conn, project_id)["project_id"]
    if project_id not in auth_token_project_bindings(
            conn, principal["token_id"]):
        raise AuthorizationError(
            "service_scope_denied: workspace is outside credential scope")
    bindings = [item for item in auth_terminal_bindings(
        conn, principal["token_id"]) if item["project_id"] == project_id]
    claimed = str(claimed_actor or "").strip()
    if claimed:
        bindings = [item for item in bindings if item["actor_id"] == claimed]
        if len(bindings) != 1:
            raise AuthorizationError(
                "service_actor_denied: exact actor binding is required")
        return {"project_id": project_id, "actor_binding": bindings[0]}
    if len(bindings) == 1:
        return {"project_id": project_id, "actor_binding": bindings[0]}
    if len(bindings) > 1:
        raise AuthorizationError(
            "service_actor_required: select one exact actor binding")
    return {
        "project_id": project_id, "actor_binding": None,
        "service_actor_id": "%s.service.service-%s" % (
            slugify(project_id), slugify(principal["token_id"])),
    }


def auth_access_payload(conn, principal=None, server=None):
    readiness = auth_activation_readiness(
        conn, server=server,
        include_details=auth_is_activation_owner(conn, principal))
    terminals = []
    enrollments = []
    service_keys = []
    client_keys = []
    invitations = []
    if principal:
        if principal.get("is_admin"):
            rows = conn.execute(
                "SELECT t.*,u.username FROM auth_tokens t JOIN auth_users u"
                " ON u.user_id=t.user_id WHERE t.token_kind='terminal'"
                " ORDER BY t.created_at DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT t.*,u.username FROM auth_tokens t JOIN auth_users u"
                " ON u.user_id=t.user_id WHERE t.token_kind='terminal'"
                " AND t.user_id=? ORDER BY t.created_at DESC",
                (principal["user_id"],)).fetchall()
        for row in rows:
            item = auth_terminal_record(conn, row)
            item["username"] = row["username"]
            terminals.append(item)
        if principal.get("is_admin"):
            for row in conn.execute(
                    "SELECT * FROM auth_device_enrollments"
                    " WHERE status IN ('pending','approved')"
                    " ORDER BY created_at DESC"):
                item = {key: row[key] for key in (
                    "user_code", "device_id", "client_label", "status",
                    "created_at", "expires_at", "approved_by", "approved_at")}
                try:
                    item["requested_bindings"] = json.loads(
                        row["requested_bindings"] or "[]")
                except ValueError:
                    item["requested_bindings"] = []
                enrollments.append(item)
        if principal.get("is_admin"):
            service_rows = conn.execute(
                "SELECT t.*,u.username FROM auth_tokens t JOIN auth_users u"
                " ON u.user_id=t.user_id WHERE t.token_kind='service'"
                " ORDER BY t.created_at DESC").fetchall()
        else:
            service_rows = conn.execute(
                "SELECT t.*,u.username FROM auth_tokens t JOIN auth_users u"
                " ON u.user_id=t.user_id WHERE t.token_kind='service'"
                " AND t.user_id=? ORDER BY t.created_at DESC",
                (principal["user_id"],)).fetchall()
        service_keys = [auth_service_key_record(conn, row)
                        for row in service_rows]
        client_keys = auth_client_key_list(conn, principal)
        if principal.get("is_admin"):
            invitations = [auth_invitation_record(row) for row in conn.execute(
                "SELECT * FROM auth_invitations ORDER BY created_at DESC")]
    return {
        "capabilities": {
            "client_keys": True,
            "terminal_enrollment": False,
            "migration_scope": False,
            "activation": True,
            "service_keys": True,
            "invitations": True,
        },
        "compatibility": readiness,
        "terminals": terminals,
        "terminal_enrollments": enrollments,
        "client_keys": client_keys,
        "service_keys": service_keys,
        "invitations": invitations,
    }


def auth_migration_scope_update(conn, principal, required_clients,
                                exclusions, expected_readiness_version,
                                server=None):
    if not isinstance(required_clients, list) or not isinstance(exclusions, list):
        raise AttaccaError("required_clients and exclusions must be arrays")
    target_ids = []
    with write_tx(conn):
        current = auth_activation_readiness(
            conn, server=server, include_details=False)
        if str(expected_readiness_version or "") != \
                current["readiness_version"]:
            raise AuthorizationError(
                "authentication readiness changed; reload before updating scope")
        for item, required in [(item, True) for item in required_clients] + \
                [(item, False) for item in exclusions]:
            if not isinstance(item, dict):
                raise AttaccaError("migration scope entries must be objects")
            target_ids.append(auth_migration_target_upsert(
                conn, item.get("project_id"), item.get("actor_id"),
                item.get("device_id"), selected_by=principal["username"],
                required=required,
                exclusion_reason=item.get("reason") if not required else None,
                in_tx=True))
    return {"ok": True, "target_ids": target_ids,
            "compatibility": auth_activation_readiness(conn, server=server)}


def auth_activate(conn, principal, confirmed, expected_readiness_version=None,
                  server=None, enabled=True):
    """Owner-only D-17 authentication enforcement toggle.

    ``expected_readiness_version`` is accepted but intentionally ignored for
    one compatibility release.  Client migration and QA evidence no longer
    form an authentication state machine.
    """
    if not principal.get("is_owner"):
        raise AuthorizationError("server_owner_required: activation denied")
    if confirmed is not True:
        raise AttaccaError("authentication toggle requires confirmed=true")
    if enabled not in (True, False):
        raise AttaccaError("enabled must be true or false")
    with write_tx(conn):
        claimed_owner_aliases = auth_claim_single_user_legacy_owner_aliases(
            conn, principal) if enabled else []
        claimed_project_memberships = \
            auth_grant_single_user_legacy_project_memberships(
                conn, principal) if enabled else []
        readiness = auth_activation_readiness(
            conn, server=server, include_details=False)
        if enabled and not readiness["ready"]:
            raise AuthorizationError(
                "authentication cannot activate before account bootstrap")
        nowi = now_iso()
        for key, value in {
                "auth.activation_requested": bool(enabled),
                "auth.activated": bool(enabled),
                "auth.activated_by": principal["username"] if enabled else None,
                "auth.activated_at": nowi if enabled else None,
                "auth.deactivated_by": (principal["username"]
                                         if not enabled else None),
                "auth.deactivated_at": nowi if not enabled else None}.items():
            conn.execute(
                "INSERT INTO server_settings(setting_key,value,updated_at)"
                " VALUES (?,?,?) ON CONFLICT(setting_key) DO UPDATE SET"
                " value=excluded.value,updated_at=excluded.updated_at",
                (key, json.dumps(value, separators=(",", ":")), nowi))
    return {"ok": True, "activated": bool(enabled),
            "changed_by": principal["username"],
            "claimed_legacy_owner_aliases": claimed_owner_aliases,
            "claimed_legacy_project_memberships":
                claimed_project_memberships,
            "readiness_version": readiness["readiness_version"]}


def auth_logout_session(conn, session_hash):
    if not session_hash:
        return {"ok": True}
    conn.execute("UPDATE auth_sessions SET revoked_at=? WHERE session_hash=?",
                 (now_iso(), session_hash))
    return {"ok": True}


def _require_str_list(name, value):
    """Validate an optional array-of-strings argument (MCP clients can send
    anything). Returns None for None, a list of str otherwise."""
    if value is None:
        return None
    if isinstance(value, str):
        raise AttaccaError(
            "%s must be an array of strings, not a string (got %r)" % (name, value))
    try:
        items = list(value)
    except TypeError:
        raise AttaccaError("%s must be an array of strings" % name)
    if not all(isinstance(item, str) for item in items):
        raise AttaccaError("%s must contain only strings" % name)
    return items


def _normalize_evidence(evidence):
    if evidence is None:
        return []
    if isinstance(evidence, dict):
        evidence = [evidence]
    if not isinstance(evidence, list) \
            or not all(isinstance(item, dict) for item in evidence):
        raise AttaccaError(
            'evidence must be an array of objects, e.g. '
            '[{"kind":"test","name":"pytest","result":"pass"}]')
    for item in evidence:
        if not item or not any(
                value is False or value == 0 or bool(value)
                for value in item.values()):
            raise AttaccaError(
                "evidence objects must contain meaningful non-empty fields")
    return evidence


_EVIDENCE_VERDICT_KEYS = {
    "result", "status", "outcome", "passed", "success", "ok",
    "verified", "exit_code", "returncode", "exit_status",
}
_EVIDENCE_PASS_VALUES = {
    "pass", "passed", "success", "succeeded", "successful", "ok",
    "green", "verified", "complete", "completed",
}
_EVIDENCE_FAIL_VALUES = {
    "fail", "failed", "failure", "error", "errored", "red",
    "blocked", "cancelled", "canceled", "timeout", "timed_out",
}


def _evidence_verification(evidence):
    """Classify structured task evidence without trusting mere object count."""
    credible_pass = False
    explicit_failure = False
    for item in evidence:
        identifying = any(
            key not in _EVIDENCE_VERDICT_KEYS and
            (value is False or value == 0 or bool(value))
            for key, value in item.items())
        item_pass = False
        item_failure = False
        for key, value in item.items():
            normalized_key = str(key).strip().lower()
            if normalized_key not in _EVIDENCE_VERDICT_KEYS:
                continue
            if normalized_key in {"passed", "success", "ok", "verified"}:
                if value is True:
                    item_pass = True
                elif value is False:
                    item_failure = True
                continue
            if normalized_key in {"exit_code", "returncode", "exit_status"}:
                try:
                    code = int(value)
                except (TypeError, ValueError):
                    continue
                item_pass = item_pass or code == 0
                item_failure = item_failure or code != 0
                continue
            verdict = str(value or "").strip().lower().replace("-", "_")
            if verdict in _EVIDENCE_PASS_VALUES:
                item_pass = True
            elif verdict in _EVIDENCE_FAIL_VALUES:
                item_failure = True
        explicit_failure = explicit_failure or item_failure
        credible_pass = credible_pass or (identifying and item_pass and
                                           not item_failure)
    if explicit_failure:
        return "failed"
    if credible_pass:
        return "verified"
    return "unverified"


class write_tx:
    """BEGIN IMMEDIATE ... COMMIT with retry/backoff on lock contention."""

    def __init__(self, conn, attempts=20):
        self.conn = conn
        self.attempts = attempts
        self.savepoint = None

    def __enter__(self):
        # Sync applies the canonical domain mutation and its idempotency
        # receipt in one outer transaction.  Existing mutators deliberately
        # own their transaction, so make that ownership composable with an
        # internal savepoint instead of trying to BEGIN inside BEGIN.
        if self.conn.in_transaction:
            self.savepoint = "attacca_write_%x" % id(self)
            self.conn.execute("SAVEPOINT %s" % self.savepoint)
            return self
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
        raise AttaccaError("database busy, could not begin transaction: %s" % last_err)

    def __exit__(self, exc_type, exc, tb):
        if self.savepoint:
            if exc_type is None:
                self.conn.execute("RELEASE %s" % self.savepoint)
            else:
                try:
                    self.conn.execute("ROLLBACK TO %s" % self.savepoint)
                finally:
                    self.conn.execute("RELEASE %s" % self.savepoint)
            return False
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
        owner = current_owner()
        git_origin = current_git_context()
        stored_revision = base_revision or git_origin["revision"]
        git_branch_name = git_origin["branch"]
        device_id = git_origin["device_id"]
        hash_version = 2
        chain_material = "|".join([
            prev_hash, payload_hash, project_id, str(seq), event_type,
            actor_id, created_at, actor_type, owner or "",
            str(context_version or ""), stored_revision or "",
            git_branch_name or "", device_id or "", task_id or ""])
        ev_hash = sha256_hex(chain_material)
        conn.execute(
            "INSERT INTO events (event_id, project_id, seq, actor_id, actor_type,"
            " owner, event_type, payload, payload_hash, prev_hash, hash,"
            " hash_version, context_version, base_revision, git_branch, device_id,"
            " task_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, project_id, seq, actor_id, actor_type, owner, event_type,
             payload_json, payload_hash, prev_hash, ev_hash, hash_version,
             context_version, stored_revision, git_branch_name, device_id, task_id,
             created_at))
        conn.execute(
            "UPDATE agents SET last_seen_at=? WHERE project_id=? AND agent_id=?",
            (created_at, project_id, actor_id))
        return {"event_id": event_id, "seq": seq, "event_type": event_type,
                "actor_id": actor_id, "actor_type": actor_type,
                "owner": owner, "created_at": created_at,
                "git_branch": git_branch_name,
                "git_revision": stored_revision,
                "device_id": device_id,
                "hash_version": hash_version,
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
        raise AttaccaError(
            "unknown project '%s'. Known projects: %s. Run `attacca.py init` "
            "in the project directory to register one." % (project_id, known or "none"))
    return dict(row)


def list_projects(conn):
    rows = conn.execute(
        "SELECT p.*, (SELECT COUNT(*) FROM events e WHERE e.project_id=p.project_id) AS events,"
        " (SELECT COUNT(*) FROM tasks t WHERE t.project_id=p.project_id"
        "   AND t.status NOT IN ('done','cancelled')) AS open_tasks"
        " FROM projects p ORDER BY p.created_at").fetchall()
    return {"projects": [dict(r) for r in rows]}


def _validated_repository_fingerprint(value):
    if value is None:
        return None
    value = str(value).strip().lower()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise AttaccaError("invalid Git repository fingerprint")
    return value


def _project_for_repository(conn, fingerprint):
    fingerprint = _validated_repository_fingerprint(fingerprint)
    if not fingerprint:
        return None
    row = conn.execute(
        "SELECT project_id FROM projects WHERE repository_fingerprint=?",
        (fingerprint,)).fetchone()
    return row["project_id"] if row else None


def remember_repository_fingerprint(conn, project_id, fingerprint,
                                    actor_id="system", actor_type="system"):
    """Bind a Git identity once; never move it between logical projects."""
    fingerprint = _validated_repository_fingerprint(fingerprint)
    if not fingerprint:
        return project_id
    with write_tx(conn):
        project = conn.execute(
            "SELECT repository_fingerprint FROM projects WHERE project_id=?",
            (project_id,)).fetchone()
        if not project:
            get_project(conn, project_id)  # raises the standard useful error
        current = project["repository_fingerprint"]
        if current:
            if current != fingerprint:
                raise AttaccaError(
                    "project '%s' is already linked to a different Git repository"
                    % project_id)
            return project_id
        other = conn.execute(
            "SELECT project_id FROM projects WHERE repository_fingerprint=?",
            (fingerprint,)).fetchone()
        if other and other["project_id"] != project_id:
            raise AttaccaError(
                "this Git repository is already linked to project '%s'"
                % other["project_id"])
        conn.execute(
            "UPDATE projects SET repository_fingerprint=? WHERE project_id=?",
            (fingerprint, project_id))
        append_event(conn, project_id, actor_id, actor_type,
                     "project.repository_linked",
                     {"repository_fingerprint": fingerprint}, in_tx=True)
    return project_id


def resolve_project_id(conn, explicit=None, default=None, cwd=None, use_cwd=True):
    """Project resolution: explicit arg > configured default > checkout link
    > cwd walk-up
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
        for candidate in candidates:
            if not candidate:
                continue
            link = find_project_link(candidate)
            if link:
                return get_project(conn, link["project_id"])["project_id"]
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
    raise AttaccaError(
        "cannot determine project%s. Pass project explicitly, set %s (or the "
        "X-Attacca-Project header over HTTP), or run `attacca.py init` "
        "in the project directory. Known projects: %s"
        % ((" (cwd=%s)" % cwd) if use_cwd else "", ENV_PROJECT, known or "none"))


def _grant_new_project_creator_membership_in_tx(
        conn, project_id, actor_id, actor_type):
    """Grant only a canonical, active human creator inside an open write tx."""
    owner = str(current_owner() or "").strip().lower()
    if actor_type != "human" or not owner \
            or str(actor_id or "").strip().lower() != "web.%s" % owner:
        return False
    user = conn.execute(
        "SELECT user_id FROM auth_users"
        " WHERE username=? AND disabled_at IS NULL", (owner,)
    ).fetchone()
    if not user:
        return False
    request_active, request_user_id = current_request_auth_user()
    if request_active and request_user_id != user["user_id"]:
        return False
    conn.execute(
        "INSERT INTO auth_project_memberships"
        " (user_id,project_id,granted_at,granted_by,revoked_at)"
        " VALUES (?,?,?,?,NULL)"
        " ON CONFLICT(user_id,project_id) DO UPDATE SET"
        " revoked_at=NULL,granted_at=excluded.granted_at,"
        " granted_by=excluded.granted_by",
        (user["user_id"], project_id, now_iso(), owner))
    return True


def project_init(conn, actor_id, actor_type, path=None, project_id=None,
                 name=None, move=False, repository_fingerprint=None):
    root = Path(path or os.getcwd()).resolve()
    name = name or root.name
    repository_fingerprint = _validated_repository_fingerprint(
        repository_fingerprint)
    # Normalize custom ids too: project ids live in URLs and env vars.
    project_id = slugify(project_id) if project_id else slugify(name)
    # Check-and-insert inside one BEGIN IMMEDIATE so two concurrent inits of
    # the same project id serialize instead of crashing on the PK.
    with write_tx(conn):
        existing = conn.execute(
            "SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
        if existing:
            if repository_fingerprint:
                other = conn.execute(
                    "SELECT project_id FROM projects"
                    " WHERE repository_fingerprint=? AND project_id<>?",
                    (repository_fingerprint, project_id)).fetchone()
                if other:
                    raise AttaccaError(
                        "this Git repository is already linked to project '%s'"
                        % other["project_id"])
                if existing["repository_fingerprint"] \
                        and existing["repository_fingerprint"] != repository_fingerprint:
                    raise AttaccaError(
                        "project '%s' is already linked to a different Git repository"
                        % project_id)
                if not existing["repository_fingerprint"]:
                    conn.execute(
                        "UPDATE projects SET repository_fingerprint=?"
                        " WHERE project_id=?", (repository_fingerprint, project_id))
                    append_event(conn, project_id, actor_id, actor_type,
                                 "project.repository_linked",
                                 {"repository_fingerprint": repository_fingerprint},
                                 in_tx=True)
            if existing["root_path"] not in (None, str(root)):
                if not move:
                    raise AttaccaError(
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
            "INSERT INTO projects (project_id, name, root_path,"
            " repository_fingerprint, created_by, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (project_id, name, str(root), repository_fingerprint,
             actor_id, now_iso()))
        append_event(conn, project_id, actor_id, actor_type, "project.created",
                     {"name": name, "root_path": str(root),
                      "repository_fingerprint": repository_fingerprint}, in_tx=True)
        # Direct/local setup may create the project without passing through
        # the REST wrapper that normally grants the authenticated creator its
        # membership.  Preserve that creator access atomically, but only for
        # the canonical human identity matching the active current owner.
        # Merely supplying an owner header with an unrelated actor is never a
        # grant, nor are attach/retry, agent/tool, unknown, or disabled users.
        _grant_new_project_creator_membership_in_tx(
            conn, project_id, actor_id, actor_type)
    return {"project_id": project_id, "name": name, "root_path": str(root),
            "already_existed": False}


# --- handoff ---------------------------------------------------------------

def _latest_handoff(conn, project_id):
    return conn.execute(
        "SELECT * FROM handoffs WHERE project_id=? ORDER BY version DESC LIMIT 1",
        (project_id,)).fetchone()


def _event_visible_to_actor(conn, project_id, row, actor_id=None,
                            actor_type="agent"):
    if row["event_type"] != "room.message" or actor_id is None:
        return True
    return _bridge_message_visible(
        conn, project_id, _room_policy_payload(conn, project_id, row),
        actor_id, actor_type)


def _event_visibility_flags(conn, project_id, rows, actor_id=None,
                            actor_type="agent"):
    """Batch bridge-policy checks for one ordered event page."""
    rows = list(rows or [])
    if actor_id is None:
        return [True] * len(rows)
    room_rows = [row for row in rows
                 if row["event_type"] == "room.message"]
    room_payloads = _room_policy_payloads(conn, project_id, room_rows)
    visible_by_id = {
        row["event_id"]: _bridge_message_visible(
            conn, project_id, payload, actor_id, actor_type)
        for row, payload in zip(room_rows, room_payloads)}
    return [visible_by_id.get(row["event_id"], True) for row in rows]


def _significant_events(conn, project_id, after_seq=0, limit=100,
                        actor_id=None, actor_type="agent"):
    out = []
    target = max(1, min(int(limit or 100), 1000))
    batch_size = max(100, min(1000, target * 2))
    before_seq = None
    while len(out) < target:
        sql = ("SELECT * FROM events WHERE project_id=? AND seq>?" +
               (" AND seq<?" if before_seq is not None else "") +
               " ORDER BY seq DESC LIMIT ?")
        params = [project_id, after_seq]
        if before_seq is not None:
            params.append(before_seq)
        params.append(batch_size)
        rows = conn.execute(sql, params).fetchall()
        if not rows:
            break
        flags = _event_visibility_flags(
            conn, project_id, rows, actor_id, actor_type)
        for row, visible in zip(rows, flags):
            if not visible:
                continue
            line = render_log_line(row)
            if line:
                out.append(line)
            if len(out) >= target:
                break
        before_seq = rows[-1]["seq"]
        if len(rows) < batch_size:
            break
    out.reverse()
    return out


def _task_brief(task):
    brief = {k: task[k] for k in
             ("task_id", "title", "status", "claimed_by", "risk_level")}
    brief["attribution"] = task.get("attribution") or {}
    if task["status"] == "claimed":
        brief["lease_until"] = task.get("lease_until")
        if task.get("lease_expired"):
            brief["lease_expired"] = True  # dead claim: reclaimable
    return brief


def workflow_warnings(conn, project_id, actor_id=None, actor_type="agent"):
    """Return cheap board-vs-checkout drift warnings for hooks and status.

    These are advisory: Git can move for legitimate reasons, but a coding AI
    should not silently mutate a checkout with no active board claim, nor keep
    treating an expired lease as ownership.
    """
    if actor_type != "agent" or not actor_id:
        return []
    nowi = now_iso()
    warnings = []
    expired = conn.execute(
        "SELECT task_id,title,lease_until FROM tasks WHERE project_id=?"
        " AND status='claimed' AND claimed_by=? AND lease_until IS NOT NULL"
        " AND lease_until<? ORDER BY task_id",
        (project_id, actor_id, nowi)).fetchall()
    for row in expired:
        warnings.append({
            "code": "stale_task_ownership",
            "task_id": row["task_id"],
            "message": ("Claim %s expired at %s; renew/reclaim it before"
                        " continuing mutations." %
                        (row["task_id"], row["lease_until"])),
        })
    active = conn.execute(
        "SELECT task_id,title,base_revision,lease_until FROM tasks"
        " WHERE project_id=? AND status='claimed' AND claimed_by=?"
        " AND (lease_until IS NULL OR lease_until>=?) ORDER BY task_id",
        (project_id, actor_id, nowi)).fetchall()
    git_ctx = current_git_context()
    revision = git_ctx.get("revision")
    branch = git_ctx.get("branch")
    if revision and not active:
        device_id = git_ctx.get("device_id")
        params = [project_id, actor_id]
        sql = (
            "SELECT base_revision,git_branch,seq,task_id FROM events"
            " WHERE project_id=? AND actor_id=? AND base_revision IS NOT NULL")
        if device_id:
            sql += " AND device_id=?"
            params.append(device_id)
        sql += " ORDER BY seq DESC LIMIT 1"
        previous = conn.execute(sql, params).fetchone()
        revision_moved = bool(
            previous and previous["base_revision"] != revision)
        branch_moved = bool(
            previous and branch and previous["git_branch"] and
            previous["git_branch"] != branch)
        if previous and (revision_moved or branch_moved):
            warnings.append({
                "code": "off_board_repository_mutation",
                "from_revision": previous["base_revision"],
                "to_revision": revision,
                "from_branch": previous["git_branch"],
                "to_branch": branch,
                "message": (
                    "Checkout moved from %s@%s to %s@%s while this AI has "
                    "no active claimed task; claim/create the work before "
                    "further mutations." %
                    (previous["git_branch"] or "unknown",
                     previous["base_revision"], branch or "unknown",
                     revision)),
            })
    return warnings


def get_handoff(conn, project_id, actor_id=None, actor_type="agent"):
    project = get_project(conn, project_id)
    row = _latest_handoff(conn, project_id)
    handoff_event = None
    if row:
        handoff_event = conn.execute(
            "SELECT * FROM events WHERE project_id=?"
            " AND event_type='handoff.updated' AND context_version=?"
            " ORDER BY seq DESC LIMIT 1",
            (project_id, row["version"])).fetchone()
    handoff_attribution = _ledger_action(
        handoff_event, conn, project_id) if handoff_event else None
    content = json.loads(row["content"]) if row else {}
    handoff = {field: content.get(field) for field in HANDOFF_FIELDS}
    open_tasks = task_list(conn, project_id, status=None)["tasks"]
    open_tasks = [t for t in open_tasks if t["status"] not in ("done", "cancelled")]
    decisions = [d for d in decision_list(conn, project_id)["decisions"]
                 if d["status"] in ("proposed", "accepted")]
    applicable_rules = rule_list(
        conn, project_id, actor_id=actor_id, actor_type=actor_type)["rules"]
    recent = _significant_events(
        conn, project_id, limit=200, actor_id=actor_id,
        actor_type=actor_type)[-8:]
    your_inbox = None
    if actor_id:
        peek = inbox_read(conn, project_id, actor_id, mark_read=False,
                          limit=200, actor_type=actor_type)
        your_inbox = {
            "unread_total": peek["unread_total"],
            "unread_addressed_to_you": peek["unread_addressed"],
            "unread_everyone": peek["unread_everyone"],
            "unread_group_context": peek["unread_group_context"],
            "pending_disposition_total": peek.get(
                "pending_disposition_total", 0),
            "pending_dispositions": peek.get("pending_dispositions", []),
            "may_have_more": peek["may_have_more"],
            "messages_include_all_visible": True,
            "hint": ("read every message with check_inbox; mentions/replies "
                     "assign attention, not visibility"),
        }
    bridges = _bridge_rows(
        conn, project_id, actor_id=actor_id, actor_type=actor_type)
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
        "workflow_warnings": workflow_warnings(
            conn, project_id, actor_id, actor_type),
        "project_rules": applicable_rules,
        "cloud_context": cloud_context_get(conn, project_id)["cloud_context"],
        "handoff": handoff,
        "handoff_updated_by": row["updated_by"] if row else None,
        "handoff_updated_owner": (handoff_attribution or {}).get("owner"),
        "handoff_attribution": handoff_attribution,
        "handoff_updated_at": row["updated_at"] if row else None,
        "open_tasks": [_task_brief(t) for t in open_tasks],
        "decisions": [{k: d.get(k) for k in
                       ("decision_id", "title", "status", "proposed_owner",
                        "resolved_owner", "attribution")}
                      for d in decisions],
        "recent_activity": recent,
        "git": {"head": git_head(project.get("root_path")),
                "branch": git_branch(project.get("root_path"))},
        "hint": (None if row else
                 "No handoff written yet. After your first meaningful work, call "
                 "update_handoff so the next worker can resume cold."),
    }


def update_handoff(conn, project_id, actor_id, actor_type, updates,
                   expected_context_version=None):
    updates = {k: v for k, v in updates.items()
               if k in HANDOFF_FIELDS and v is not None}
    if not updates:
        raise AttaccaError(
            "update_handoff needs at least one of: %s" % ", ".join(HANDOFF_FIELDS))
    with write_tx(conn):
        project = get_project(conn, project_id)
        lead = project.get("lead_director")
        if actor_type == "agent":
            actor_row = conn.execute(
                "SELECT role FROM agents WHERE project_id=? AND agent_id=?",
                (project_id, actor_id)).fetchone()
            assigned_role_count = conn.execute(
                "SELECT COUNT(*) AS n FROM agents WHERE project_id=? "
                "AND role IN ('director','advisor','worker')",
                (project_id,)).fetchone()["n"]
            # Legacy projects without role governance keep working until their
            # first director/lead is designated. Once governed, only directors
            # write the canonical handoff; workers/advisors report through the
            # multi-writer task board and room instead.
            governed = bool(lead or assigned_role_count)
            # Lead is coordination/tie-break metadata, never an authority
            # bypass. Every AI permission comes from its role in THIS
            # workspace; Claude and Codex Directors are therefore peers.
            is_director = bool(actor_row and actor_row["role"] == "director")
            if governed and not is_director:
                raise AttaccaError(
                    "handoff is director-only; agent '%s' is not a director. "
                    "Use task_report/room_send or ask a director to update the "
                    "canonical handoff" % actor_id)
        if expected_context_version is not None:
            try:
                expected = int(expected_context_version)
            except (TypeError, ValueError):
                raise AttaccaError("expected_context_version must be an integer")
            if project["context_version"] != expected:
                raise AttaccaError(
                    "handoff conflict: expected context v%d but project is now "
                    "v%d; reload get_handoff and reconcile before writing"
                    % (expected, project["context_version"]))
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
              mentions=None, task_id=None, reply_to=None, origin_project=None,
              target_project=None):
    # Older HTTP/MCP clients addressed the destination as ``project`` and put
    # their real workspace in X-Attacca-Project/origin_project. Never trust
    # that marker as proof that a message was already mirrored: doing so
    # bypasses both the bridge lookup and its participation policy. Translate
    # the legacy shape into the same validated source -> target operation.
    if origin_project and origin_project != project_id:
        source = get_project(conn, origin_project)["project_id"]
        return room_send(
            conn, source, actor_id, actor_type, body, msg_type=msg_type,
            mentions=mentions, task_id=task_id, reply_to=reply_to,
            target_project=project_id)
    if not body or not str(body).strip():
        raise AttaccaError("room_send: body is required")
    msg_type = (msg_type or "chat").lower()
    if msg_type not in MSG_TYPES:
        raise AttaccaError(
            "room_send: msg_type must be one of %s" % ", ".join(MSG_TYPES))
    mentions = _require_str_list("mentions", mentions)
    # Persist an explicit empty destination list for new local-only rows.
    # Absence of this key is reserved for the historic source-side bridge
    # schema and is what activates counterpart inference on read.
    payload = {"msg_type": msg_type, "body": str(body), "mirrored_to": []}
    if mentions:
        payload["mentions"] = mentions
    if reply_to:
        payload["reply_to"] = reply_to
    local_only = False
    if target_project:
        target_project = get_project(conn, target_project)["project_id"]
        if target_project == project_id:
            target_project = None
            local_only = True
    get_project(conn, project_id)
    bridge_targets = []
    if not local_only:
        rows = _bridge_rows(conn, project_id)
        if target_project:
            selected = next((b for b in rows
                             if b["with"] == target_project), None)
            if not selected:
                raise AttaccaError(
                    "workspace '%s' is not connected to '%s'; create an AI "
                    "Network relationship first" % (target_project, project_id))
            if not _bridge_actor_can_participate(
                    conn, project_id, target_project, actor_id, actor_type):
                raise AttaccaError(
                    "AI '%s' is not allowed to participate in the %s <-> %s "
                    "room; ask a human or Director to change that bridge's "
                    "participation policy" %
                    (actor_id, project_id, target_project))
            bridge_targets = [selected]
        # No implicit bridge fan-out. A task claim, status, handoff, or local
        # mention belongs to this workspace unless the caller names one exact
        # target_project. This prevents routine project work from leaking into
        # a scoped feedback/advisory bridge merely because it is structured.
    if actor_type == "agent" and msg_type == "directive" and any(
            bridge["relation"] == "master" and
            bridge.get("principal") == project_id
            for bridge in bridge_targets):
        project = get_project(conn, project_id)
        registered = conn.execute(
            "SELECT role FROM agents WHERE project_id=? AND agent_id=?",
            (project_id, actor_id)).fetchone()
        assigned_role_count = conn.execute(
            "SELECT COUNT(*) AS n FROM agents WHERE project_id=? "
            "AND role IN ('director','advisor','worker')",
            (project_id,)).fetchone()["n"]
        governed = bool(project.get("lead_director") or assigned_role_count)
        is_director = bool(registered and registered["role"] == "director")
        if governed and not is_director:
            raise AttaccaError(
                "only a Director may send binding directives from master "
                "workspace '%s'; use chat/status or ask a Director"
                % project_id)
    if bridge_targets:
        # Stored on the source event so the console can separate each
        # connected-workspace conversation instead of flattening every message
        # into one indistinguishable feed.
        payload["mirrored_to"] = [b["with"] for b in bridge_targets]
    # Source persistence and every exact destination copy form one delivery
    # contract. A destination failure must roll the source back as well; a
    # raised call can never leave a message that callers believe was unsent.
    mirrored_to = []
    with write_tx(conn):
        event = append_event(
            conn, project_id, actor_id, actor_type, "room.message", payload,
            task_id=task_id, in_tx=True)
        # An explicitly targeted bridge message is retained in both linked
        # rooms. Mirrored copies carry origin_project and are never re-mirrored
        # (loop protection).
        for bridge in bridge_targets:
            authority = None
            if bridge["relation"] == "master":
                if bridge["principal"] == project_id:
                    authority = "master-directive" \
                        if msg_type == "directive" else None
                else:
                    authority = "suggestion"
            elif bridge["relation"] == "advisor" \
                    and bridge["principal"] == project_id:
                authority = "advice"
            mirror = dict(payload, origin_project=project_id)
            mirror.pop("mirrored_to", None)
            if authority:
                mirror["authority"] = authority
            append_event(conn, bridge["with"], actor_id, actor_type,
                         "room.message", mirror, in_tx=True)
            mirrored_to.append(bridge["with"])
    warnings = []
    if msg_type == "decision":
        warnings.append("room messages do not create durable decision records — "
                        "also call decision_propose / decision_resolve")
    if msg_type == "claim" and not task_id:
        warnings.append("claim messages should reference a task_id; use "
                        "task_claim to actually claim the work")
    delivered_projects = [project_id] + list(mirrored_to)
    result = {
        "ok": True,
        # Backward-compatible scalar retained for 0.4.x callers.
        "delivered_to": project_id,
        # Canonical truthful contract: local persistence plus every exact
        # destination copy.  ``mirrored_to`` is always present, including []
        # for local-only sends, so callers never infer delivery from absence.
        "delivered_to_projects": delivered_projects,
        "mirrored_to": list(mirrored_to),
        "event": event,
    }
    if mirrored_to:
        result["mirrored_to_bridged_projects"] = mirrored_to
    if warnings:
        result["warnings"] = warnings
    return result


def _actor_alias_ids(conn, project_id, actor_id):
    if not actor_id:
        return set()
    rows = conn.execute(
        "SELECT legacy_actor_id FROM actor_aliases WHERE project_id=?"
        " AND canonical_actor_id=?", (project_id, actor_id)).fetchall()
    return {actor_id} | {row["legacy_actor_id"] for row in rows}


def room_read(conn, project_id, since_seq=None, limit=30, actor_id=None,
              actor_type="agent"):
    get_project(conn, project_id)
    limit = max(1, min(int(limit or 30), 500))
    if since_seq is not None:
        rows = conn.execute(
            "SELECT * FROM events WHERE project_id=? AND seq>? AND event_type='room.message'"
            " ORDER BY seq ASC LIMIT ?", (project_id, int(since_seq), limit)).fetchall()
    else:
        # Initial reads promise the latest *visible* messages. Filtering only
        # after a raw LIMIT lets denied bridge traffic consume the page and
        # can falsely render an empty room despite older local/allowed rows.
        # Read the room history, apply policy, then retain the latest visible
        # page. Forward polling remains raw-page/cursor based below so hidden
        # rows always advance a caller and can never cause an infinite loop.
        rows = conn.execute(
            "SELECT * FROM events WHERE project_id=? AND event_type='room.message'"
            " ORDER BY seq ASC", (project_id,)).fetchall()
    # The cursor is derived ONLY from the rows actually returned, so a
    # truncated batch can never skip undelivered messages (and there is no
    # TOCTOU with a separate MAX(seq) query).
    if rows:
        next_since = rows[-1]["seq"]
    elif since_seq is not None:
        next_since = int(since_seq)
    else:
        next_since = 0
    visible_messages = []
    actor_ids = _actor_alias_ids(conn, project_id, actor_id)
    policy_payloads = _room_policy_payloads(conn, project_id, rows)
    for row, payload in zip(rows, policy_payloads):
        # Preserve the immutable payload's key-presence distinction here.
        # New local-only rows explicitly store ``mirrored_to: []``; only old
        # rows with no such key may use counterpart inference. Normalizing all
        # rows first loses that distinction and can misclassify a new local
        # message as bridged when it happens to share a body/signature with a
        # nearby outgoing message.
        message = _room_message_dict(row, payload)
        if not _bridge_message_visible(
                conn, project_id, message, actor_id, actor_type):
            continue
        if message.get("mirrored_to") and actor_id is not None:
            message["mirrored_to"] = _visible_bridge_peers(
                conn, project_id, message, actor_id, actor_type)
        # Mirrored rows retain the sender's original workspace.  Project the
        # actor through that workspace's role registry, not through the room
        # currently being read, or a remote Director is mislabeled as a local
        # unassigned agent.
        identity_project = message.get("origin_project") or project_id
        attribution = immutable_event_attribution(
            conn, identity_project, message["actor"], message["actor_type"],
            message.get("owner"))
        message["ledger_actor"] = message["actor"]
        message["actor"] = attribution["actor_id"]
        message["identity"] = attribution["identity"]
        message["attribution"] = attribution
        message.update(_inbox_message_attention(conn, actor_ids, message))
        visible_messages.append(message)
    if since_seq is None:
        older_messages_available = len(visible_messages) > limit
        visible_messages = visible_messages[-limit:]
        # This is a latest-page snapshot, not the first page of a forward
        # cursor walk. Do not claim that next_since_seq can recover older rows.
        may_have_more = False
    else:
        older_messages_available = False
        may_have_more = len(rows) == limit
    return {"project": project_id, "messages": visible_messages,
            "next_since_seq": next_since,
            "may_have_more": may_have_more,
            "older_messages_available": older_messages_available,
            "hint": (("latest page shown; call room_read with since_seq=0 "
                      "to page chronologically from the beginning")
                     if older_messages_available else
                     ("more messages are waiting — poll again with "
                     "since_seq=next_since_seq now" if may_have_more else
                     "poll again with since_seq=next_since_seq to read only "
                     "new messages"))}


# --- inbox -----------------------------------------------------------------

def _room_message_dict(row, payload=None):
    payload = payload if payload is not None else json.loads(row["payload"])
    result = {"event_id": row["event_id"], "seq": row["seq"],
              "at": row["created_at"], "actor": row["actor_id"],
              "actor_type": row["actor_type"],
              "owner": row["owner"] if "owner" in row.keys() else None,
              "msg_type": payload.get("msg_type"),
              "body": payload.get("body"),
              "mentions": payload.get("mentions"),
              "task_id": row["task_id"],
              "reply_to": payload.get("reply_to"),
              "origin_project": payload.get("origin_project"),
              "authority": payload.get("authority"),
              "mirrored_to": payload.get("mirrored_to") or []}
    if payload.get("mirrored_to_inferred"):
        result["mirrored_to_inferred"] = True
    return result


def _inbox_message_attention(conn, actor_ids, payload):
    """Classify response routing without turning it into a privacy filter.

    The project room is a group conversation.  Every participation-visible
    non-self message is an inbox item.  Mentions and replies merely identify
    the expected responder; an untargeted chat/directive is addressed to the
    whole group.  Other visible traffic remains required group context.
    """
    mentions = set(payload.get("mentions") or [])
    mentioned = bool(actor_ids.intersection(mentions))
    replied = False
    reply_to = payload.get("reply_to")
    if reply_to:
        original = conn.execute(
            "SELECT actor_id FROM events WHERE event_id=?", (reply_to,)
        ).fetchone()
        replied = bool(original and original["actor_id"] in actor_ids)
    broadcast = bool(
        payload.get("msg_type") in ("chat", "directive")
        and not mentions and not reply_to)
    direct = mentioned or replied
    addressed = direct or broadcast
    return {
        "mentioned_to_you": mentioned,
        "reply_to_you": replied,
        "directed_to_you": direct,
        "broadcast_to_everyone": broadcast,
        "addressed_to_you": addressed,
        "group_context": not addressed,
    }


MESSAGE_DISPOSITIONS = (
    "acknowledged", "claimed", "deferred", "blocked", "completed",
    "not_actionable",
)
UNRESOLVED_MESSAGE_DISPOSITIONS = {"claimed", "deferred", "blocked"}


def _message_requires_disposition(attention, payload):
    """Direct attention and broadcast directives require an explicit outcome."""
    return bool(attention.get("directed_to_you") or (
        attention.get("broadcast_to_everyone") and
        payload.get("msg_type") == "directive"))


def pending_message_dispositions(conn, project_id, actor_id,
                                 actor_type="agent", limit=100):
    """Return addressed work that was read but never explicitly disposed."""
    get_project(conn, project_id)
    limit = max(1, min(int(limit or 100), 500))
    actor_ids = _actor_alias_ids(conn, project_id, actor_id)
    rows = conn.execute(
        "SELECT * FROM events WHERE project_id=?"
        " AND event_type='room.message' ORDER BY seq",
        (project_id,)).fetchall()
    candidate_rows = [row for row in rows if row["actor_id"] not in actor_ids]
    payloads = _room_policy_payloads(conn, project_id, candidate_rows)
    disposition_rows = conn.execute(
        "SELECT * FROM message_dispositions WHERE project_id=? AND actor_id=?",
        (project_id, actor_id)).fetchall()
    dispositions = {row["message_event_id"]: dict(row)
                    for row in disposition_rows}
    pending = []
    for row, payload in zip(candidate_rows, payloads):
        if not _bridge_message_visible(
                conn, project_id, payload, actor_id, actor_type):
            continue
        attention = _inbox_message_attention(conn, actor_ids, payload)
        if not _message_requires_disposition(attention, payload):
            continue
        disposition = dispositions.get(row["event_id"])
        if disposition and disposition["disposition"] not in \
                UNRESOLVED_MESSAGE_DISPOSITIONS:
            continue
        message = _room_message_dict(row, payload)
        message.update(attention)
        identity_project = message.get("origin_project") or project_id
        attribution = immutable_event_attribution(
            conn, identity_project, message["actor"], message["actor_type"],
            message.get("owner"))
        message["ledger_actor"] = message["actor"]
        message["actor"] = attribution["actor_id"]
        message["identity"] = attribution["identity"]
        message["attribution"] = attribution
        message["requires_disposition"] = True
        message["disposition"] = disposition
        pending.append(message)
    has_more = len(pending) > limit
    return {
        "pending": pending[:limit],
        "pending_total": len(pending),
        "may_have_more": has_more,
    }


def message_dispose(conn, project_id, actor_id, actor_type, event_id,
                    disposition, note=None, task_id=None):
    """Record one durable outcome for an addressed room assignment/message."""
    disposition = str(disposition or "").strip().lower()
    if disposition not in MESSAGE_DISPOSITIONS:
        raise AttaccaError(
            "disposition must be one of %s" %
            ", ".join(MESSAGE_DISPOSITIONS))
    note = str(note or "").strip() or None
    if disposition in ("deferred", "blocked", "not_actionable") and not note:
        raise AttaccaError("%s disposition requires a note" % disposition)
    row = conn.execute(
        "SELECT * FROM events WHERE project_id=? AND event_id=?"
        " AND event_type='room.message'", (project_id, event_id)).fetchone()
    if not row:
        raise AttaccaError("unknown room message %s" % event_id)
    actor_ids = _actor_alias_ids(conn, project_id, actor_id)
    if row["actor_id"] in actor_ids:
        raise AttaccaError("cannot disposition your own room message")
    payload = _room_policy_payload(conn, project_id, row)
    if not _bridge_message_visible(
            conn, project_id, payload, actor_id, actor_type):
        raise AuthorizationError("room message is not visible to this actor")
    attention = _inbox_message_attention(conn, actor_ids, payload)
    if not _message_requires_disposition(attention, payload):
        raise AttaccaError(
            "message is group context, not assigned/addressed work")
    event_task = str(row["task_id"] or "").strip() or None
    supplied_task = str(task_id or "").strip() or None
    if event_task and supplied_task and supplied_task != event_task:
        raise AttaccaError(
            "message is linked to task %s; disposition cannot substitute "
            "unrelated task %s" % (event_task, supplied_task))
    effective_task = event_task or supplied_task
    if effective_task:
        task = _task_row(conn, project_id, effective_task)
    else:
        task = None
    if disposition in ("claimed", "completed") and not task:
        raise AttaccaError(
            "%s disposition requires a linked task_id" % disposition)
    if disposition == "claimed" and (
            task["status"] != "claimed" or task["claimed_by"] != actor_id):
        raise AttaccaError(
            "claimed disposition requires an active task claim by this actor")
    if disposition == "completed" and task["status"] != "done":
        raise AttaccaError(
            "completed disposition requires the linked task to be done")
    nowi = now_iso()
    with write_tx(conn):
        conn.execute(
            "INSERT INTO message_dispositions"
            " (project_id,actor_id,message_event_id,disposition,note,task_id,"
            " updated_by,updated_owner,updated_at) VALUES (?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(project_id,actor_id,message_event_id) DO UPDATE SET"
            " disposition=excluded.disposition,note=excluded.note,"
            " task_id=excluded.task_id,updated_by=excluded.updated_by,"
            " updated_owner=excluded.updated_owner,updated_at=excluded.updated_at",
            (project_id, actor_id, event_id, disposition, note,
             effective_task, actor_id, current_owner(), nowi))
        event = append_event(
            conn, project_id, actor_id, actor_type,
            "room.message_disposition", {
                "message_event_id": event_id,
                "disposition": disposition,
                "note": note,
                "task_id": effective_task,
            }, task_id=effective_task, in_tx=True)
    pending = pending_message_dispositions(
        conn, project_id, actor_id, actor_type=actor_type, limit=1)
    return {
        "ok": True,
        "message_event_id": event_id,
        "disposition": disposition,
        "task_id": effective_task,
        "pending_disposition_total": pending["pending_total"],
        "event": event,
    }


def _room_message_signature(message):
    """Fields retained unchanged on both sides of a mirrored room event."""
    return (message.get("actor"), message.get("actor_type"),
            message.get("msg_type"), message.get("body"),
            tuple(message.get("mentions") or []), message.get("reply_to"))


def _room_message_time(value):
    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _infer_legacy_room_mirrors(conn, project_id, messages):
    """Recover destinations omitted by older source-side room events.

    Older Attacca builds labelled the mirrored copy with ``origin_project``
    but did not retain ``mirrored_to`` on the source event.  The panel cannot
    then distinguish an outgoing bridge conversation from local workspace
    traffic.  Match those immutable counterpart events by their unchanged
    message fields and near-identical timestamp.  New events already carry
    ``mirrored_to`` and bypass this compatibility path.
    """
    unresolved = [message for message in messages
                  if not message.get("origin_project")
                  and not message.get("mirrored_to")]
    if not unresolved:
        return
    source_times = [_room_message_time(message.get("at"))
                    for message in unresolved]
    source_times = [value for value in source_times if value is not None]
    time_clause = ""
    time_params = []
    if source_times:
        lower = datetime.fromtimestamp(
            min(source_times) - 5, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        upper = datetime.fromtimestamp(
            max(source_times) + 5, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        time_clause = " AND created_at>=? AND created_at<=?"
        time_params = [lower, upper]

    counterparts = {}
    # Routing history outlives the current bridge relationship.  Searching
    # only active bridge rows declassified a legacy source event as local as
    # soon as its bridge was removed.  The mirrored counterpart is durable
    # ledger evidence: it names ``origin_project`` and its own destination
    # project, so use that evidence even after relationship removal.  Current
    # participation lookup then fails closed for AIs when no bridge remains;
    # human owners retain their explicit inspection authority.
    rows = conn.execute(
        "SELECT * FROM events WHERE project_id<>?"
        " AND event_type='room.message'" + time_clause,
        [project_id] + time_params).fetchall()
    for row in rows:
        try:
            payload = json.loads(row["payload"])
        except (TypeError, ValueError):
            continue
        if payload.get("origin_project") != project_id:
            continue
        other = row["project_id"]
        target = _room_message_dict(row, payload)
        counterparts.setdefault(
            _room_message_signature(target), []).append(
                (other, _room_message_time(target.get("at"))))

    for message in unresolved:
        source_time = _room_message_time(message.get("at"))
        inferred = []
        for other, target_time in counterparts.get(
                _room_message_signature(message), []):
            if source_time is not None and target_time is not None \
                    and abs(source_time - target_time) > 5:
                continue
            if other not in inferred:
                inferred.append(other)
        if inferred:
            message["mirrored_to"] = inferred
            message["mirrored_to_inferred"] = True


def _room_policy_payload(conn, project_id, row, payload=None):
    """Return room routing metadata with legacy destinations reconstructed.

    Old source-side bridge rows did not persist ``mirrored_to``.  Visibility
    must not depend on which read surface happens to inspect such a row, so
    every policy path reconstructs that destination before applying bridge
    participation.  The immutable stored payload is never rewritten.
    """
    return _room_policy_payloads(
        conn, project_id, [row],
        payloads=[payload] if payload is not None else None)[0]


def _room_policy_payloads(conn, project_id, rows, payloads=None):
    """Batch routing reconstruction while preserving payload key presence."""
    rows = list(rows or [])
    if payloads is not None and len(payloads) != len(rows):
        raise ValueError("room payload batch length differs from rows")
    enriched_rows = []
    unresolved = []
    unresolved_indexes = []
    for index, row in enumerate(rows):
        payload = payloads[index] if payloads is not None else None
        if payload is None:
            raw = row["payload"] if "payload" in row.keys() else None
            if isinstance(raw, dict):
                payload = raw
            else:
                payload = json.loads(raw or "{}")
        enriched = dict(payload or {})
        enriched_rows.append(enriched)
        # New senders persist the key even for local-only traffic. Only its
        # absence identifies legacy source-side schema needing recovery.
        if not enriched.get("origin_project") \
                and "mirrored_to" not in enriched:
            unresolved.append(_room_message_dict(row, enriched))
            unresolved_indexes.append(index)
    if unresolved:
        _infer_legacy_room_mirrors(conn, project_id, unresolved)
        for index, message in zip(unresolved_indexes, unresolved):
            if message.get("mirrored_to"):
                enriched_rows[index]["mirrored_to"] = list(
                    message["mirrored_to"])
                enriched_rows[index]["mirrored_to_inferred"] = True
    return enriched_rows


def inbox_read(conn, project_id, actor_id, mark_read=True, limit=50,
               actor_type="agent"):
    """Return every unread group-room message visible to this participant.

    Bridge participation is the visibility boundary. Mentions/replies are
    attention metadata only, and chat/directive messages without either are
    broadcasts to every participant. The raw ledger cursor still advances
    across self or bridge-hidden rows so polling cannot loop on invisible data.
    """
    get_project(conn, project_id)
    limit = max(1, min(int(limit or 50), 500))
    actor_ids = _actor_alias_ids(conn, project_id, actor_id)
    row = conn.execute(
        "SELECT last_read_seq FROM inbox_cursors WHERE project_id=? AND actor_id=?",
        (project_id, actor_id)).fetchone()
    cursor = row["last_read_seq"] if row else 0
    messages = []
    counts = {"addressed": 0, "direct": 0, "everyone": 0,
              "group_context": 0}
    # Scan raw ledger pages until either one complete *visible* inbox page plus
    # a look-ahead row is found or history is exhausted. A raw SQL LIMIT made
    # self/bridge-hidden rows saturate non-mutating peeks, so poll_status and
    # get_handoff could report no mail even though a visible message sat just
    # behind them. Cursor advancement still stops at the last returned visible
    # row when another visible row remains, so nothing can be skipped.
    scan_cursor = cursor
    batch_size = max(100, min(1000, limit * 2))
    while len(messages) <= limit:
        rows = conn.execute(
            "SELECT * FROM events WHERE project_id=? AND seq>?"
            " AND event_type='room.message' ORDER BY seq ASC LIMIT ?",
            (project_id, scan_cursor, batch_size)).fetchall()
        if not rows:
            break
        stop_after_page = False
        candidate_rows = [r for r in rows if r["actor_id"] not in actor_ids]
        policy_payloads = _room_policy_payloads(
            conn, project_id, candidate_rows)
        payload_by_event = {
            r["event_id"]: payload
            for r, payload in zip(candidate_rows, policy_payloads)}
        for r in rows:
            scan_cursor = r["seq"]
            if r["actor_id"] in actor_ids:
                continue  # your own messages are not inbox items
            payload = payload_by_event[r["event_id"]]
            if not _bridge_message_visible(
                    conn, project_id, payload, actor_id, actor_type):
                continue
            attention = _inbox_message_attention(conn, actor_ids, payload)
            message = _room_message_dict(r, payload)
            message.update(attention)
            if message.get("mirrored_to") and actor_id is not None:
                message["mirrored_to"] = _visible_bridge_peers(
                    conn, project_id, message, actor_id, actor_type)
            identity_project = message.get("origin_project") or project_id
            attribution = immutable_event_attribution(
                conn, identity_project, message["actor"],
                message["actor_type"], message.get("owner"))
            message["ledger_actor"] = message["actor"]
            message["actor"] = attribution["actor_id"]
            message["identity"] = attribution["identity"]
            message["attribution"] = attribution
            messages.append(message)
            if len(messages) > limit:
                stop_after_page = True
                break
        if stop_after_page or len(rows) < batch_size:
            break
    may_have_more = len(messages) > limit
    messages = messages[:limit]
    if may_have_more and messages:
        new_cursor = messages[-1]["seq"]
    else:
        new_cursor = scan_cursor
    for message in messages:
        counts["addressed"] += int(message["addressed_to_you"])
        counts["direct"] += int(message["directed_to_you"])
        counts["everyone"] += int(message["broadcast_to_everyone"])
        counts["group_context"] += int(message["group_context"])
    if mark_read and new_cursor > cursor:
        with write_tx(conn):
            conn.execute(
                "INSERT INTO inbox_cursors (project_id, actor_id, last_read_seq,"
                " updated_at) VALUES (?,?,?,?)"
                " ON CONFLICT(project_id, actor_id) DO UPDATE SET"
                " last_read_seq=excluded.last_read_seq,"
                " updated_at=excluded.updated_at",
                (project_id, actor_id, new_cursor, now_iso()))
    disposition_state = pending_message_dispositions(
        conn, project_id, actor_id, actor_type=actor_type, limit=limit)
    return {
        "project": project_id,
        "actor": actor_id,
        "messages": messages,
        "messages_include_all_visible": True,
        "unread_total": len(messages),
        "unread_addressed": counts["addressed"],
        "unread_direct": counts["direct"],
        "unread_everyone": counts["everyone"],
        "unread_group_context": counts["group_context"],
        # Compatibility name. These rows are INCLUDED in messages; callers
        # must use unread_total rather than adding this field to len(messages).
        "unread_broadcasts": counts["group_context"],
        "may_have_more": may_have_more,
        "read_cursor": new_cursor if mark_read else cursor,
        "scanned_through_seq": new_cursor,
        "pending_dispositions": disposition_state["pending"],
        "pending_disposition_total": disposition_state["pending_total"],
        "pending_disposition_may_have_more": disposition_state["may_have_more"],
        "hint": ("more unread group messages remain — call check_inbox again"
                 if may_have_more else
                 "all participation-visible unread room messages are included; "
                 "mentions/replies assign attention, not visibility"),
    }


BRIDGE_RELATIONS = ["peer", "master", "advisor"]
BRIDGE_PARTICIPATION_PRESETS = {
    "all": None,
    "directors_advisors": {"director", "advisor"},
    "directors": {"director"},
    "selected_agents": set(),
}
DEFAULT_BRIDGE_PARTICIPATION = {"preset": "all", "agents": []}


def _canonical_bridge_participation_preset(value):
    aliases = {
        "all_roles": "all", "everyone": "all",
        "director_advisor": "directors_advisors",
        "directors+advisors": "directors_advisors",
        "director": "directors", "directors_only": "directors",
        "selected": "selected_agents", "agents": "selected_agents",
    }
    preset = str(value or "all").strip().lower().replace("-", "_")
    return aliases.get(preset, preset)


def _stored_bridge_participation(value):
    """Decode a bridge-side policy, preserving old rows as ``all``.

    Participation is deliberately independent from the bridge's authority
    relationship.  Master/Peer/Advisor answers *whose instructions carry
    weight*; this policy answers *which local AIs may enter that conversation*.
    Humans retain access so an owner can always inspect or repair the network.
    """
    try:
        raw = json.loads(value) if isinstance(value, str) else dict(value or {})
    except (TypeError, ValueError):
        raw = {}
    preset = str(raw.get("preset") or "all").strip().lower()
    if preset not in BRIDGE_PARTICIPATION_PRESETS:
        preset = "all"
    agents = raw.get("agents") if isinstance(raw.get("agents"), list) else []
    return {"preset": preset,
            "agents": sorted({str(item).strip() for item in agents
                              if str(item).strip()})}


def _registered_bridge_agent_id(conn, project_id, actor_id):
    raw = str(actor_id or "").strip()
    if not raw:
        return None
    alias = conn.execute(
        "SELECT canonical_actor_id FROM actor_aliases WHERE project_id=?"
        " AND legacy_actor_id=?", (project_id, raw)).fetchone()
    candidate = alias["canonical_actor_id"] if alias else raw
    row = conn.execute(
        "SELECT agent_id FROM agents WHERE project_id=? AND agent_id=?",
        (project_id, candidate)).fetchone()
    if row:
        return row["agent_id"]
    identity = project_actor_identity(
        conn, project_id, raw, "agent", owner=None)["actor_id"]
    row = conn.execute(
        "SELECT agent_id FROM agents WHERE project_id=? AND agent_id=?",
        (project_id, identity)).fetchone()
    return row["agent_id"] if row else None


def _normalize_bridge_participation(conn, project_id, value=None,
                                    selected_agents=None):
    if isinstance(value, dict):
        selected_agents = value.get("agents", selected_agents)
        value = value.get("preset")
    preset = _canonical_bridge_participation_preset(value)
    if preset not in BRIDGE_PARTICIPATION_PRESETS:
        raise AttaccaError(
            "bridge participation must be all, directors_advisors, "
            "directors, or selected_agents")
    selected_agents = _require_str_list(
        "selected_agents", selected_agents) or []
    if preset != "selected_agents" and selected_agents:
        raise AttaccaError(
            "selected_agents may only be supplied with selected_agents "
            "participation")
    canonical = []
    if preset == "selected_agents":
        if not selected_agents:
            raise AttaccaError(
                "selected_agents participation needs at least one registered "
                "AI actor id")
        for actor_id in selected_agents:
            registered = _registered_bridge_agent_id(
                conn, project_id, actor_id)
            if not registered:
                raise AttaccaError(
                    "'%s' is not a registered AI in workspace '%s'"
                    % (actor_id, project_id))
            canonical.append(registered)
    return {"preset": preset, "agents": sorted(set(canonical))}


def _bridge_row(conn, project_id, other_project):
    a, b = sorted([project_id, other_project])
    return conn.execute(
        "SELECT * FROM bridges WHERE project_a=? AND project_b=?",
        (a, b)).fetchone()


def _bridge_side_participation(row, project_id):
    column = "access_a" if row["project_a"] == project_id else "access_b"
    return _stored_bridge_participation(row[column])


def _bridge_actor_can_participate(conn, project_id, other_project,
                                  actor_id, actor_type="agent"):
    if actor_type == "human":
        return True
    if actor_type != "agent" or not actor_id:
        return False
    row = _bridge_row(conn, project_id, other_project)
    if not row:
        return False
    access = _bridge_side_participation(row, project_id)
    preset = access["preset"]
    if preset == "all":
        return True
    if preset == "selected_agents":
        registered = _registered_bridge_agent_id(
            conn, project_id, actor_id)
        return bool(registered and registered in access["agents"])
    role = _registered_actor_role(conn, project_id, actor_id)
    return role in BRIDGE_PARTICIPATION_PRESETS[preset]


def _bridge_message_peers(project_id, payload):
    origin = payload.get("origin_project")
    if origin and origin != project_id:
        return [origin]
    return [peer for peer in (payload.get("mirrored_to") or [])
            if peer and peer != project_id]


def _bridge_message_visible(conn, project_id, payload, actor_id=None,
                            actor_type="agent"):
    peers = _bridge_message_peers(project_id, payload)
    if not peers or actor_id is None:
        return True
    return any(_bridge_actor_can_participate(
        conn, project_id, peer, actor_id, actor_type) for peer in peers)


def _visible_bridge_peers(conn, project_id, payload, actor_id=None,
                          actor_type="agent"):
    peers = _bridge_message_peers(project_id, payload)
    if actor_id is None:
        return peers
    return [peer for peer in peers if _bridge_actor_can_participate(
        conn, project_id, peer, actor_id, actor_type)]


def _require_bridge_manager(conn, project_id, actor_id, actor_type):
    if actor_type == "human":
        return "human"
    role = _registered_actor_role(conn, project_id, actor_id) \
        if actor_type == "agent" else "unassigned"
    if actor_type == "agent" and role != "director":
        # A cross-workspace setup call carries the source workspace actor id.
        # It may manage the peer side only when the same runtime is separately
        # registered as a Director in that peer workspace.
        records = [dict(row) for row in conn.execute(
            "SELECT * FROM agents WHERE project_id=?", (project_id,))]
        identity = registered_agent_identity(
            records, project_id, actor_id,
            runtime=normalize_agent_runtime(actor=actor_id))
        role = identity.get("role") or role
    if actor_type != "agent" or role != "director":
        raise AttaccaError(
            "AI Network relationships and participation may only be changed "
            "by a human or registered Director; '%s' is %s"
            % (actor_id, role))
    return role


def _bridge_rows(conn, project_id, actor_id=None, actor_type="agent"):
    rows = conn.execute(
        "SELECT * FROM bridges WHERE project_a=? OR project_b=?",
        (project_id, project_id)).fetchall()
    out = []
    for row in rows:
        other = row["project_b"] \
            if row["project_a"] == project_id else row["project_a"]
        local_access = _bridge_side_participation(row, project_id)
        peer_access = _bridge_side_participation(row, other)
        item = {"with": other, "relation": row["relation"] or "peer",
                "principal": row["principal"],
                "participation": local_access["preset"],
                "allowed_agents": local_access["agents"],
                "peer_participation": peer_access["preset"],
                "peer_allowed_agents": peer_access["agents"]}
        if actor_id is not None:
            item["can_participate"] = _bridge_actor_can_participate(
                conn, project_id, other, actor_id, actor_type)
        out.append(item)
    return out


def _bridged_projects(conn, project_id):
    return [b["with"] for b in _bridge_rows(conn, project_id)]


def bridge_add(conn, project_id, actor_id, actor_type, other_project,
               boss=None, advisor=None, participation="all",
               peer_participation=None, selected_agents=None,
               peer_selected_agents=None):
    """Bridge two projects so agents reach each other's rooms/inboxes.
    Relationship between the two AI teams:
      peer (default)      — equals; messages mirror untagged.
      boss=<project_id>   — that project's directors RULE the other: their
                            mirrored messages arrive tagged [MASTER]; the
                            subordinate side's arrive as suggestions.
      advisor=<project_id>— that project advises: its messages arrive tagged
                            as advice, no authority either way."""
    get_project(conn, project_id)
    _require_bridge_manager(conn, project_id, actor_id, actor_type)
    other = get_project(conn, other_project)["project_id"]
    if other == project_id:
        raise AttaccaError("cannot bridge a project to itself")
    if boss and advisor:
        raise AttaccaError("choose either boss or advisor, not both")
    principal = boss or advisor or None
    relation = "master" if boss else ("advisor" if advisor else "peer")
    if principal and principal not in (project_id, other):
        raise AttaccaError(
            "%s must be one of the bridged projects (%s, %s)"
            % ("boss" if boss else "advisor", project_id, other))
    if actor_type == "agent" and (peer_participation is not None or
                                  peer_selected_agents is not None):
        _require_bridge_manager(conn, other, actor_id, actor_type)
    local_access = _normalize_bridge_participation(
        conn, project_id, participation, selected_agents)
    peer_access = _normalize_bridge_participation(
        conn, other, peer_participation or "all", peer_selected_agents)
    a, b = sorted([project_id, other])
    access_a = local_access if a == project_id else peer_access
    access_b = peer_access if b == other else local_access
    with write_tx(conn):
        exists = conn.execute(
            "SELECT 1 FROM bridges WHERE project_a=? AND project_b=?",
            (a, b)).fetchone()
        if exists:
            raise AttaccaError(
                "%s and %s are already bridged; update the existing "
                "relationship or participation policy without deleting it"
                % (a, b))
        conn.execute(
            "INSERT INTO bridges (project_a, project_b, relation, principal,"
            " access_a, access_b, created_by, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (a, b, relation, principal, canonical_json(access_a),
             canonical_json(access_b), actor_id, now_iso()))
        context_version = None
        for side, peer in ((project_id, other), (other, project_id)):
            version = bump_context_version(conn, side)
            if side == project_id:
                context_version = version
            side_access = local_access if side == project_id else peer_access
            far_access = peer_access if side == project_id else local_access
            append_event(conn, side, actor_id, actor_type, "bridge.created",
                         {"with": peer, "relation": relation,
                          "principal": principal,
                          "participation": side_access,
                          "peer_participation": far_access}, in_tx=True)
    return {"ok": True, "bridged": [project_id, other], "relation": relation,
            "principal": principal,
            "participation": local_access["preset"],
            "allowed_agents": local_access["agents"],
            "peer_participation": peer_access["preset"],
            "peer_allowed_agents": peer_access["agents"],
            "context_version": context_version,
            "note": "all messages stay local unless target_project explicitly "
                    "names this connected workspace"}


def bridge_update_access(conn, project_id, actor_id, actor_type,
                         other_project, participation=None,
                         peer_participation=None, selected_agents=None,
                         peer_selected_agents=None):
    """Atomically update who may join each side of an existing bridge.

    This intentionally does not alter Peer/Master/Advisor. A Director can
    therefore make a bridge Director-to-Director without deleting it or
    changing either workspace's authority over the other.
    """
    get_project(conn, project_id)
    _require_bridge_manager(conn, project_id, actor_id, actor_type)
    other = get_project(conn, other_project)["project_id"]
    row = _bridge_row(conn, project_id, other)
    if not row:
        raise AttaccaError("%s and %s are not bridged" %
                           tuple(sorted([project_id, other])))
    if participation is None and peer_participation is None \
            and selected_agents is None and peer_selected_agents is None:
        raise AttaccaError(
            "provide participation and/or peer_participation")
    local_access = _bridge_side_participation(row, project_id)
    peer_access = _bridge_side_participation(row, other)
    if participation is not None or selected_agents is not None:
        wanted = _canonical_bridge_participation_preset(
            participation or local_access["preset"])
        wanted_agents = selected_agents if selected_agents is not None else (
            local_access["agents"] if wanted == "selected_agents" else [])
        local_access = _normalize_bridge_participation(
            conn, project_id, wanted, wanted_agents)
    if peer_participation is not None or peer_selected_agents is not None:
        if actor_type == "agent":
            _require_bridge_manager(conn, other, actor_id, actor_type)
        wanted_peer = _canonical_bridge_participation_preset(
            peer_participation or peer_access["preset"])
        wanted_peer_agents = peer_selected_agents \
            if peer_selected_agents is not None else (
                peer_access["agents"]
                if wanted_peer == "selected_agents" else [])
        peer_access = _normalize_bridge_participation(
            conn, other, wanted_peer, wanted_peer_agents)
    a, b = sorted([project_id, other])
    access_a = local_access if a == project_id else peer_access
    access_b = peer_access if b == other else local_access
    previous_local = _bridge_side_participation(row, project_id)
    previous_peer = _bridge_side_participation(row, other)
    if local_access == previous_local and peer_access == previous_peer:
        return {"ok": True, "with": other, "unchanged": True,
                "participation": local_access["preset"],
                "allowed_agents": local_access["agents"],
                "peer_participation": peer_access["preset"],
                "peer_allowed_agents": peer_access["agents"],
                "context_version": get_project(
                    conn, project_id)["context_version"]}
    with write_tx(conn):
        conn.execute(
            "UPDATE bridges SET access_a=?, access_b=?"
            " WHERE project_a=? AND project_b=?",
            (canonical_json(access_a), canonical_json(access_b), a, b))
        context_version = None
        for side, peer in ((project_id, other), (other, project_id)):
            version = bump_context_version(conn, side)
            if side == project_id:
                context_version = version
            side_access = local_access if side == project_id else peer_access
            far_access = peer_access if side == project_id else local_access
            append_event(
                conn, side, actor_id, actor_type, "bridge.access_updated",
                {"with": peer, "participation": side_access,
                 "peer_participation": far_access}, in_tx=True)
    return {"ok": True, "with": other, "unchanged": False,
            "participation": local_access["preset"],
            "allowed_agents": local_access["agents"],
            "peer_participation": peer_access["preset"],
            "peer_allowed_agents": peer_access["agents"],
            "context_version": context_version}


def bridge_update_relationship(conn, project_id, actor_id, actor_type,
                               other_project, relationship, principal=None):
    """Change authority without destroying either participation policy."""
    get_project(conn, project_id)
    _require_bridge_manager(conn, project_id, actor_id, actor_type)
    other = get_project(conn, other_project)["project_id"]
    row = _bridge_row(conn, project_id, other)
    if not row:
        raise AttaccaError("%s and %s are not bridged" %
                           tuple(sorted([project_id, other])))
    relationship = str(relationship or "").strip().lower()
    if relationship not in BRIDGE_RELATIONS:
        raise AttaccaError("relationship must be peer, master, or advisor")
    principal = str(principal or "").strip() or None
    if relationship == "peer":
        if principal:
            raise AttaccaError("peer relationships do not have a principal")
    elif principal not in (project_id, other):
        raise AttaccaError(
            "principal must be one of the bridged projects (%s, %s)" %
            (project_id, other))
    local_access = _bridge_side_participation(row, project_id)
    peer_access = _bridge_side_participation(row, other)
    if row["relation"] == relationship and row["principal"] == principal:
        return {"ok": True, "with": other, "unchanged": True,
                "relation": relationship, "principal": principal,
                "participation": local_access["preset"],
                "allowed_agents": local_access["agents"],
                "peer_participation": peer_access["preset"],
                "peer_allowed_agents": peer_access["agents"],
                "context_version": get_project(
                    conn, project_id)["context_version"]}
    a, b = sorted([project_id, other])
    with write_tx(conn):
        conn.execute(
            "UPDATE bridges SET relation=?, principal=?"
            " WHERE project_a=? AND project_b=?",
            (relationship, principal, a, b))
        context_version = None
        for side, peer in ((project_id, other), (other, project_id)):
            version = bump_context_version(conn, side)
            if side == project_id:
                context_version = version
            append_event(
                conn, side, actor_id, actor_type,
                "bridge.relationship_updated",
                {"with": peer, "from": row["relation"],
                 "from_principal": row["principal"],
                 "relation": relationship, "principal": principal,
                 "participation": (local_access if side == project_id
                                   else peer_access),
                 "peer_participation": (peer_access if side == project_id
                                        else local_access)}, in_tx=True)
    return {"ok": True, "with": other, "unchanged": False,
            "relation": relationship, "principal": principal,
            "participation": local_access["preset"],
            "allowed_agents": local_access["agents"],
            "peer_participation": peer_access["preset"],
            "peer_allowed_agents": peer_access["agents"],
            "context_version": context_version}


def bridge_remove(conn, project_id, actor_id, actor_type, other_project):
    get_project(conn, project_id)
    _require_bridge_manager(conn, project_id, actor_id, actor_type)
    other = get_project(conn, other_project)["project_id"]
    a, b = sorted([project_id, other])
    with write_tx(conn):
        cur = conn.execute(
            "DELETE FROM bridges WHERE project_a=? AND project_b=?", (a, b))
        if cur.rowcount != 1:
            raise AttaccaError("%s and %s are not bridged" % (a, b))
        context_version = None
        for side, peer in ((project_id, other), (other, project_id)):
            version = bump_context_version(conn, side)
            if side == project_id:
                context_version = version
            append_event(conn, side, actor_id, actor_type, "bridge.removed",
                         {"with": peer}, in_tx=True)
    return {"ok": True, "removed": [project_id, other],
            "context_version": context_version}


def bridge_list(conn, project_id, actor_id=None, actor_type="agent"):
    get_project(conn, project_id)
    return {"project": project_id,
            "bridges": _bridge_rows(
                conn, project_id, actor_id=actor_id, actor_type=actor_type)}


def set_lead_director(conn, project_id, actor_id, actor_type, lead_id):
    """Blueprint §6.4 boss mode: designate the Lead Director whose directives
    assign work and break ties. Empty lead_id clears the role."""
    lead_id = (lead_id or "").strip() or None
    with write_tx(conn):
        project = get_project(conn, project_id)
        previous = project.get("lead_director")
        if previous == lead_id:
            raise AttaccaError("lead director is already %s" % (lead_id or "unset"))
        if lead_id:
            registered = conn.execute(
                "SELECT role FROM agents WHERE project_id=? AND agent_id=?",
                (project_id, lead_id)).fetchone()
            if not registered:
                raise AttaccaError(
                    "lead director '%s' is not registered in workspace '%s'; "
                    "register this AI as a director first" %
                    (lead_id, project_id))
            if registered["role"] != "director":
                raise AttaccaError(
                    "lead director '%s' is registered as %s; change that AI's "
                    "role to director first" %
                    (lead_id, registered["role"] or "unassigned"))
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
        raise AttaccaError("unknown task %s in project %s" % (task_id, project_id))
    return row


def _ledger_action(row, conn=None, project_id=None):
    """Return one immutable event as a UI/API attribution record.

    Actor identity answers which workspace/role/runtime acted. ``owner`` is
    deliberately separate and answers which human ran that actor. Historical
    events with no owner remain ``None``; callers must not guess from the
    actor's current registry row.
    """
    payload = json.loads(row["payload"] or "{}")
    operational_actor = row["actor_id"]
    attribution = None
    if conn is not None and project_id:
        attribution = immutable_event_attribution(
            conn, project_id, row["actor_id"], row["actor_type"],
            row["owner"] if "owner" in row.keys() else None)
        operational_actor = attribution["actor_id"]
    return {
        "event_id": row["event_id"],
        "seq": row["seq"],
        "event_type": row["event_type"],
        "actor_id": row["actor_id"],
        "operational_actor_id": operational_actor,
        "actor_type": row["actor_type"],
        "owner": row["owner"] if "owner" in row.keys() else None,
        "at": row["created_at"],
        "git_branch": row["git_branch"] if "git_branch" in row.keys() else None,
        "git_revision": row["base_revision"],
        "device_id": row["device_id"] if "device_id" in row.keys() else None,
        "context_version": row["context_version"],
        "payload": payload,
        "attribution": attribution,
    }


def _task_attribution(actions):
    result = {"created": None, "claimed": None, "reported": None,
              "resolved": None, "status_changed": None,
              "released": None, "latest": None}
    for action in actions:
        result["latest"] = action
        event_type = action["event_type"]
        if event_type == "task.created":
            result["created"] = action
        elif event_type in ("task.claimed", "task.lease_renewed"):
            result["claimed"] = action
        elif event_type == "task.reported":
            result["reported"] = action
            if action["payload"].get("requested_state") == "done":
                result["resolved"] = action
        elif event_type == "task.completed":
            result["resolved"] = action
        elif event_type == "task.status_changed":
            result["status_changed"] = action
            if action["payload"].get("to") in ("done", "cancelled"):
                result["resolved"] = action
        elif event_type == "task.released":
            result["released"] = action
    return result


def _task_current_claimant(task, actions, conn=None, project_id=None):
    """Project the event that owns the task's current scalar claimant.

    Reporting a task transfers ``claimed_by`` to the reporter, so the most
    recent explicit ``task.claimed`` event is not necessarily the current
    claimant. Replay only events that mutate that scalar and then reconcile
    against the stored value. This preserves historical claim attribution
    while preventing the UI from pairing a new claimant with an old owner.
    """
    current = None
    for action in actions:
        event_type = action["event_type"]
        payload = action.get("payload") or {}
        if event_type in ("task.claimed", "task.lease_renewed"):
            current = action
        elif event_type == "task.reported":
            current = None if payload.get("requested_state") == "queued" \
                else action
        elif event_type == "task.released" or (
                event_type == "task.status_changed" and
                payload.get("to") == "queued"):
            current = None
    claimant = task.get("claimed_by")
    if not claimant:
        return None
    if current and claimant in {
            current.get("actor_id"), current.get("operational_actor_id")}:
        return current
    for action in reversed(actions):
        if claimant in {action.get("actor_id"),
                        action.get("operational_actor_id")}:
            return action
    report = task.get("last_report") if isinstance(
        task.get("last_report"), dict) else {}
    actor_type = report.get("reported_actor_type") or "agent"
    owner = report.get("reported_owner")
    attribution = immutable_event_attribution(
        conn, project_id, claimant, actor_type, owner) \
        if conn is not None and project_id else None
    return {
        "event_id": None, "seq": None, "event_type": "task.claimant",
        "actor_id": claimant,
        "operational_actor_id": (attribution or {}).get(
            "actor_id", claimant),
        "actor_type": actor_type, "owner": owner, "at": None,
        "git_branch": None, "git_revision": None, "device_id": None,
        "context_version": None, "payload": {},
        "attribution": attribution,
    }


def _task_plan_summary(row):
    if not row:
        return None
    return {
        "version": row["version"], "status": row["status"],
        "title": row["title"],
        "section_count": len(json.loads(row["sections"] or "[]")),
        "content_sha256": row["content_sha256"],
        "authored_by": row["authored_by"],
        "authored_owner": row["authored_owner"],
        "authored_at": row["authored_at"], "updated_at": row["updated_at"],
    }


def _task_dict(row, event_rows=None, conn=None, project_id=None,
               plan_row=None):
    task = dict(row)
    task["expected_scope"] = json.loads(task.get("expected_scope") or "[]")
    task["dependencies"] = json.loads(task.get("dependencies") or "[]")
    task["plan_required"] = bool(task.get("plan_required"))
    task["plan"] = _task_plan_summary(plan_row)
    actions = [_ledger_action(item, conn, project_id) for item in (event_rows or [])
               if item["event_type"].startswith("task.")]
    task["actions"] = actions
    task["attribution"] = _task_attribution(actions)
    if task.get("last_report"):
        task["last_report"] = json.loads(task["last_report"])
        reported = task["attribution"].get("reported") or {}
        task["last_report"].setdefault("reported_owner", reported.get("owner"))
        task["last_report"].setdefault("reported_actor_type",
                                       reported.get("actor_type"))
        task["verification_status"] = task["last_report"].get(
            "verification_status") or (
                "verified" if task["last_report"].get("evidence")
                else "unverified")
    elif task.get("status") == "done":
        task["verification_status"] = "unverified"
    else:
        task["verification_status"] = "not_reported"
    task["attribution"]["current_claimant"] = _task_current_claimant(
        task, actions, conn, project_id)
    if task["status"] == "claimed" and task.get("lease_until") \
            and task["lease_until"] < now_iso():
        task["lease_expired"] = True
    return task


def task_create(conn, project_id, actor_id, actor_type, title, description=None,
                expected_scope=None, dependencies=None, risk_level="medium",
                plan_required=False):
    if not title or not str(title).strip():
        raise AttaccaError("task_create: title is required")
    risk_level = (risk_level or "medium").lower()
    if risk_level not in RISK_LEVELS:
        raise AttaccaError("risk_level must be one of %s" % ", ".join(RISK_LEVELS))
    expected_scope = _require_str_list("expected_scope", expected_scope) or []
    dependencies = _require_str_list("dependencies", dependencies) or []
    if not isinstance(plan_required, bool):
        raise AttaccaError("plan_required must be true or false")
    with write_tx(conn):
        get_project(conn, project_id)
        task_id = _next_counter_id(conn, "tasks", "task_id", project_id, "T-")
        created_at = now_iso()
        conn.execute(
            "INSERT INTO tasks (project_id, task_id, title, description, status,"
            " risk_level, expected_scope, dependencies, plan_required,"
            " created_by, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (project_id, task_id, str(title), description, "queued", risk_level,
             canonical_json(expected_scope), canonical_json(dependencies),
             int(plan_required), actor_id, created_at, created_at))
        event = append_event(conn, project_id, actor_id, actor_type, "task.created",
                             {"title": str(title), "risk_level": risk_level,
                              "expected_scope": expected_scope,
                              "dependencies": dependencies,
                              "plan_required": plan_required},
                             task_id=task_id, in_tx=True)
    return {"ok": True, "task_id": task_id, "status": "queued",
            "plan_required": plan_required, "event": event}


def task_list(conn, project_id, status=None):
    get_project(conn, project_id)
    if status:
        if status not in TASK_STATUSES:
            raise AttaccaError("status must be one of %s" % ", ".join(TASK_STATUSES))
        rows = conn.execute(
            "SELECT * FROM tasks WHERE project_id=? AND status=? ORDER BY task_id",
            (project_id, status)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM tasks WHERE project_id=? ORDER BY "
            " CASE status WHEN 'claimed' THEN 0 WHEN 'review' THEN 1 WHEN 'blocked' THEN 2"
            "  WHEN 'queued' THEN 3 WHEN 'done' THEN 4 ELSE 5 END,"
            " CAST(SUBSTR(task_id,3) AS INTEGER)", (project_id,)).fetchall()
    task_events = conn.execute(
        "SELECT * FROM events WHERE project_id=? AND task_id IS NOT NULL"
        " AND event_type LIKE 'task.%' ORDER BY seq", (project_id,)).fetchall()
    by_task = {}
    for event in task_events:
        by_task.setdefault(event["task_id"], []).append(event)
    plan_rows = conn.execute(
        "SELECT p.* FROM task_plan_revisions p WHERE p.project_id=?"
        " AND p.version=(SELECT MAX(q.version) FROM task_plan_revisions q"
        " WHERE q.project_id=p.project_id AND q.task_id=p.task_id)",
        (project_id,)).fetchall()
    plans = {row["task_id"]: row for row in plan_rows}
    return {"project": project_id,
            "tasks": [_task_dict(row, by_task.get(row["task_id"], []),
                                 conn, project_id, plans.get(row["task_id"]))
                      for row in rows]}


def task_show(conn, project_id, task_id):
    rows = conn.execute(
        "SELECT * FROM events WHERE project_id=? AND task_id=? ORDER BY seq",
        (project_id, task_id)).fetchall()
    plan_row = conn.execute(
        "SELECT * FROM task_plan_revisions WHERE project_id=? AND task_id=?"
        " ORDER BY version DESC LIMIT 1", (project_id, task_id)).fetchone()
    task = _task_dict(_task_row(conn, project_id, task_id), rows,
                      conn, project_id, plan_row)
    task["history"] = [line for line in (render_log_line(r) for r in rows) if line]
    return task


# --- detailed task plans --------------------------------------------------

def _validate_plan_sections(sections):
    if not isinstance(sections, list):
        raise AttaccaError("plan sections must be an ordered array")
    result, seen = [], set()
    for index, raw in enumerate(sections, 1):
        if not isinstance(raw, dict):
            raise AttaccaError("plan section %d must be an object" % index)
        section_id = str(raw.get("section_id") or raw.get("id") or "").strip()
        title = str(raw.get("title") or "").strip()
        body = raw.get("body")
        if not section_id or not re.match(r"^[A-Za-z0-9._-]+$", section_id):
            raise AttaccaError(
                "plan section %d needs a stable section_id using letters, "
                "numbers, dots, dashes or underscores" % index)
        if section_id in seen:
            raise AttaccaError("duplicate plan section_id %s" % section_id)
        if not title:
            raise AttaccaError("plan section %s needs a title" % section_id)
        if not isinstance(body, str) or not body.strip():
            raise AttaccaError("plan section %s needs a body" % section_id)
        seen.add(section_id)
        result.append({"section_id": section_id, "title": title,
                       "body": body})
    if not result:
        raise AttaccaError("a detailed plan needs at least one section")
    return result


def _latest_task_plan_row(conn, project_id, task_id, version=None):
    _task_row(conn, project_id, task_id)
    if version is None:
        return conn.execute(
            "SELECT * FROM task_plan_revisions WHERE project_id=? AND task_id=?"
            " ORDER BY version DESC LIMIT 1", (project_id, task_id)).fetchone()
    try:
        version = int(version)
    except (TypeError, ValueError):
        raise AttaccaError("plan version must be an integer")
    row = conn.execute(
        "SELECT * FROM task_plan_revisions WHERE project_id=? AND task_id=?"
        " AND version=?", (project_id, task_id, version)).fetchone()
    if not row:
        raise AttaccaError("task %s has no plan version %s" % (task_id, version))
    return row


def _plan_content(title, overview, sections):
    content = {"title": str(title).strip(),
               "overview": str(overview or ""), "sections": sections}
    digest = hashlib.sha256(canonical_json(content).encode("utf-8")).hexdigest()
    return content, digest


def _plan_actor_id(conn, project_id, actor_id, actor_type):
    if actor_type != "agent":
        return actor_id
    return project_actor_identity(
        conn, project_id, actor_id, actor_type,
        owner=current_owner())["actor_id"]


def _require_plan_editor(conn, project_id, task_id, actor_id, actor_type):
    if actor_type == "human":
        return actor_id
    effective = _plan_actor_id(
        conn, project_id, actor_id, actor_type)
    role = _registered_actor_role(conn, project_id, effective) \
        if actor_type == "agent" else "unassigned"
    task = _task_row(conn, project_id, task_id)
    lease_live = not task["lease_until"] or task["lease_until"] >= now_iso()
    if role == "director" or (
            actor_type == "agent" and task["claimed_by"] == effective and
            task["status"] == "claimed" and lease_live):
        return effective
    raise AttaccaError(
        "task plans may be edited by a human, registered Director, or the "
        "task's active claimant; '%s' is %s" % (effective, role))


def _require_plan_approver(conn, project_id, actor_id, actor_type):
    if actor_type == "human":
        return actor_id
    effective = _plan_actor_id(conn, project_id, actor_id, actor_type)
    role = _registered_actor_role(conn, project_id, effective) \
        if actor_type == "agent" else "unassigned"
    if actor_type == "agent" and role == "director":
        return effective
    raise AttaccaError(
        "plan approval requires a human or registered Director; '%s' is %s"
        % (effective, role))


def _require_plan_reviewer(conn, project_id, actor_id, actor_type):
    """Return a trusted reviewer identity for suggestions and comments."""
    if actor_type == "human":
        return actor_id
    if actor_type != "agent":
        raise AttaccaError("only humans and registered AIs may review plans")
    effective = _plan_actor_id(conn, project_id, actor_id, actor_type)
    registered = conn.execute(
        "SELECT 1 FROM agents WHERE project_id=? AND agent_id=?",
        (project_id, effective)).fetchone()
    if not registered:
        raise AttaccaError(
            "plan suggestions and comments require a registered AI; '%s' "
            "is not registered in workspace '%s'" % (effective, project_id))
    return effective


def _task_plan_event_rows(conn, project_id, task_id, version=None):
    rows = conn.execute(
        "SELECT * FROM events WHERE project_id=? AND task_id=?"
        " AND event_type LIKE 'task.plan.%' ORDER BY seq",
        (project_id, task_id)).fetchall()
    if version is None:
        return rows
    return [row for row in rows
            if json.loads(row["payload"] or "{}").get("plan_version") == version]


def _task_plan_dict(row, events=None, conn=None, project_id=None):
    plan = dict(row)
    plan["sections"] = json.loads(plan["sections"] or "[]")
    actions = [_ledger_action(item, conn, project_id) for item in (events or [])]
    plan["actions"] = actions
    plan["approvals"] = [action for action in actions
                         if action["event_type"] == "task.plan.approved"]
    plan["suggestions"] = [action for action in actions
                           if action["event_type"] == "task.plan.suggested"]
    plan["comments"] = [action for action in actions
                        if action["event_type"] == "task.plan.commented"]
    return plan


def task_plan_get(conn, project_id, task_id, version=None):
    selected = _latest_task_plan_row(
        conn, project_id, task_id, version=version)
    revisions = conn.execute(
        "SELECT * FROM task_plan_revisions WHERE project_id=? AND task_id=?"
        " ORDER BY version DESC", (project_id, task_id)).fetchall()
    if not selected:
        return {"project": project_id, "task_id": task_id,
                "plan": None, "revisions": []}
    events = _task_plan_event_rows(
        conn, project_id, task_id, selected["version"])
    return {
        "project": project_id, "task_id": task_id,
        "plan": _task_plan_dict(selected, events, conn, project_id),
        "revisions": [_task_plan_summary(row) for row in revisions],
    }


def task_plan_set(conn, project_id, task_id, actor_id, actor_type,
                  title, overview, sections, expected_version=None,
                  submit_for_review=False):
    if not title or not str(title).strip():
        raise AttaccaError("task_plan_set: title is required")
    if not isinstance(submit_for_review, bool):
        raise AttaccaError("submit_for_review must be true or false")
    sections = _validate_plan_sections(sections)
    content, digest = _plan_content(title, overview, sections)
    with write_tx(conn):
        effective = _require_plan_editor(
            conn, project_id, task_id, actor_id, actor_type)
        latest = _latest_task_plan_row(conn, project_id, task_id)
        latest_version = latest["version"] if latest else 0
        if latest and expected_version is None:
            raise AttaccaError(
                "revising a task plan requires expected_version=%d"
                % latest_version)
        if expected_version is not None:
            try:
                expected_version = int(expected_version)
            except (TypeError, ValueError):
                raise AttaccaError("expected_version must be an integer")
            if expected_version != latest_version:
                raise AttaccaError(
                    "stale task plan: expected v%d, current is v%d"
                    % (expected_version, latest_version))
        version = latest_version + 1
        status = "in_review" if submit_for_review else "draft"
        nowi = now_iso()
        conn.execute(
            "INSERT INTO task_plan_revisions (project_id, task_id, version,"
            " title, overview, sections, status, content_sha256, authored_by,"
            " authored_owner, authored_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (project_id, task_id, version, content["title"],
             content["overview"], canonical_json(sections), status, digest,
             effective, current_owner(), nowi, nowi))
        conn.execute(
            "UPDATE tasks SET updated_at=?"
            " WHERE project_id=? AND task_id=?", (nowi, project_id, task_id))
        context_version = bump_context_version(conn, project_id)
        event = append_event(
            conn, project_id, effective, actor_type,
            "task.plan.created" if version == 1 else "task.plan.revised",
            {"plan_version": version, "title": content["title"],
             "status": status, "section_count": len(sections),
             "content_sha256": digest}, task_id=task_id, in_tx=True)
    return {"ok": True, "context_version": context_version,
            "plan": task_plan_get(conn, project_id, task_id)["plan"],
            "event": event}


def task_plan_submit(conn, project_id, task_id, actor_id, actor_type,
                     expected_version):
    with write_tx(conn):
        effective = _require_plan_editor(
            conn, project_id, task_id, actor_id, actor_type)
        latest = _latest_task_plan_row(conn, project_id, task_id)
        if not latest:
            raise AttaccaError("task %s has no plan to submit" % task_id)
        try:
            expected_version = int(expected_version)
        except (TypeError, ValueError):
            raise AttaccaError("task_plan_submit requires expected_version")
        if latest["version"] != expected_version:
            raise AttaccaError(
                "stale task plan: expected v%d, current is v%d"
                % (expected_version, latest["version"]))
        if latest["status"] == "in_review":
            return {"ok": True, "already_submitted": True,
                    "plan": task_plan_get(conn, project_id, task_id)["plan"]}
        if latest["status"] != "draft":
            raise AttaccaError(
                "create a new revision before submitting a %s plan"
                % latest["status"])
        nowi = now_iso()
        conn.execute(
            "UPDATE task_plan_revisions SET status='in_review', updated_at=?"
            " WHERE project_id=? AND task_id=? AND version=?",
            (nowi, project_id, task_id, latest["version"]))
        context_version = bump_context_version(conn, project_id)
        event = append_event(
            conn, project_id, effective, actor_type, "task.plan.submitted",
            {"plan_version": latest["version"], "status": "in_review",
             "content_sha256": latest["content_sha256"]},
            task_id=task_id, in_tx=True)
    return {"ok": True, "context_version": context_version,
            "plan": task_plan_get(conn, project_id, task_id)["plan"],
            "event": event}


def task_plan_review(conn, project_id, task_id, actor_id, actor_type,
                     expected_version, action, section_id=None, note=None):
    action = str(action or "").strip().lower()
    if action not in ("approve", "suggest_edit", "comment"):
        raise AttaccaError(
            "plan review action must be approve, suggest_edit, or comment")
    with write_tx(conn):
        latest = _latest_task_plan_row(conn, project_id, task_id)
        if not latest:
            raise AttaccaError("task %s has no plan to review" % task_id)
        try:
            expected_version = int(expected_version)
        except (TypeError, ValueError):
            raise AttaccaError("task_plan_review requires expected_version")
        if latest["version"] != expected_version:
            raise AttaccaError(
                "stale task plan: expected v%d, current is v%d"
                % (expected_version, latest["version"]))
        if action in ("approve", "suggest_edit") \
                and latest["status"] != "in_review":
            raise AttaccaError(
                "plan must be in_review before approval or edit suggestions")
        sections = json.loads(latest["sections"] or "[]")
        section_ids = {item["section_id"] for item in sections}
        section_id = str(section_id or "").strip() or None
        if section_id and section_id not in section_ids:
            raise AttaccaError("unknown plan section %s" % section_id)
        note = str(note or "").strip() or None
        if action in ("suggest_edit", "comment") and not note:
            raise AttaccaError("%s requires a note" % action)
        if action == "approve":
            effective = _require_plan_approver(
                conn, project_id, actor_id, actor_type)
        else:
            effective = _require_plan_reviewer(
                conn, project_id, actor_id, actor_type)
        new_status = latest["status"]
        event_type = {"approve": "task.plan.approved",
                      "suggest_edit": "task.plan.suggested",
                      "comment": "task.plan.commented"}[action]
        if action == "approve" and section_id is None:
            new_status = "approved"
        elif action == "suggest_edit":
            new_status = "changes_requested"
        nowi = now_iso()
        if new_status != latest["status"]:
            conn.execute(
                "UPDATE task_plan_revisions SET status=?, updated_at=?"
                " WHERE project_id=? AND task_id=? AND version=?",
                (new_status, nowi, project_id, task_id, latest["version"]))
        context_version = bump_context_version(conn, project_id) \
            if action != "comment" else get_project(
                conn, project_id)["context_version"]
        event = append_event(
            conn, project_id, effective, actor_type, event_type,
            {"plan_version": latest["version"], "action": action,
             "section_id": section_id, "note": note,
             "status": new_status,
             "content_sha256": latest["content_sha256"]},
            task_id=task_id, in_tx=True)
    return {"ok": True, "context_version": context_version,
            "plan": task_plan_get(conn, project_id, task_id)["plan"],
            "event": event}


def _require_approved_task_plan(conn, project_id, task_id, target_status):
    """Gate review/completion when a task explicitly requires a plan."""
    if target_status not in ("review", "done"):
        return
    task = _task_row(conn, project_id, task_id)
    if not bool(task["plan_required"]):
        return
    latest = _latest_task_plan_row(conn, project_id, task_id)
    plan_status = latest["status"] if latest else "missing"
    if plan_status != "approved":
        raise AttaccaError(
            "task %s requires an approved detailed plan before moving to %s; "
            "latest plan status is %s" %
            (task_id, target_status, plan_status))


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
            raise AttaccaError(
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
        raise AttaccaError("task_report: summary is required")
    requested_state = (requested_state or "review").lower()
    if requested_state not in ("review", "done", "blocked", "queued"):
        raise AttaccaError("requested_state must be review|done|blocked|queued")
    evidence = _normalize_evidence(evidence)
    requested_target = requested_state
    verification_status = _evidence_verification(evidence)
    # A bare assertion, ambiguous evidence, or an explicit failed check cannot
    # create a green/done board state. Preserve the report and evidence in
    # review so the missing/failing verification remains visible.
    if requested_state == "done" and verification_status != "verified":
        requested_state = "review"
    project = get_project(conn, project_id)
    base_revision = git_head(project.get("root_path"))
    with write_tx(conn):
        row = _task_row(conn, project_id, task_id)
        _require_approved_task_plan(
            conn, project_id, task_id, requested_state)
        nowi = now_iso()
        report = {"summary": str(summary), "evidence": evidence,
                  "reported_by": actor_id, "reported_at": nowi,
                  "reported_owner": current_owner(),
                  "reported_actor_type": actor_type,
                  "requested_state": requested_target,
                  "effective_state": requested_state,
                  "verification_status": verification_status,
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
                raise AttaccaError(
                    "task %s is already %s; use task_set_status to reopen it "
                    "before reporting again" % (task_id, fresh["status"]))
            raise AttaccaError(
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
                and verification_status != "verified":
            warnings.append(
                "repository moved from %s (claim) to %s (report) without "
                "verified passing evidence — attach identified checks with "
                "an explicit passing result"
                % (row["base_revision"], base_revision))
        if verification_status == "failed":
            warnings.append(
                "evidence contains an explicit failed check: completion "
                "remains in review until passing verification is reported")
        elif verification_status != "verified":
            warnings.append(
                "no credible passing evidence attached: completion remains "
                "unverified and cannot enter done; identify the check and "
                "include an explicit passing result")
    result = {"ok": True, "task_id": task_id, "status": requested_state,
              "requested_state": requested_target,
              "verification_status": verification_status,
              "warnings": warnings, "event": event}
    if context_version:
        result["context_version"] = context_version
    return result


def task_release(conn, project_id, actor_id, actor_type, task_id, reason=None):
    with write_tx(conn):
        get_project(conn, project_id)
        row = _task_row(conn, project_id, task_id)
        if row["status"] != "claimed":
            raise AttaccaError("task %s is not claimed (status=%s)"
                                  % (task_id, row["status"]))
        if row["claimed_by"] and row["claimed_by"] != actor_id \
                and row["lease_until"] and row["lease_until"] >= now_iso():
            raise AttaccaError(
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
        raise AttaccaError("status must be one of %s" % ", ".join(TASK_STATUSES))
    if status == "claimed":
        raise AttaccaError(
            "use task_claim to claim tasks — set-status cannot create a claim "
            "with a claimant and lease")
    with write_tx(conn):
        get_project(conn, project_id)
        row = _task_row(conn, project_id, task_id)
        if row["status"] == status:
            raise AttaccaError("task %s already has status %s" % (task_id, status))
        _require_approved_task_plan(conn, project_id, task_id, status)
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
        raise AttaccaError("decision_propose: title is required")
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
        raise AttaccaError(
            "resolution must be one of %s" % ", ".join(DECISION_RESOLUTIONS))
    with write_tx(conn):
        get_project(conn, project_id)
        row = conn.execute(
            "SELECT * FROM decisions WHERE project_id=? AND decision_id=?",
            (project_id, decision_id)).fetchone()
        if not row:
            raise AttaccaError("unknown decision %s" % decision_id)
        if row["status"] != "proposed" and resolution != "superseded":
            raise AttaccaError(
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


def _decision_dict(row, event_rows, conn, project_id):
    decision = dict(row)
    actions = [_ledger_action(event, conn, project_id) for event in event_rows]
    proposed = next((action for action in actions
                     if action["event_type"] == "decision.proposed"), None)
    resolved = next((action for action in reversed(actions)
                     if action["event_type"] == "decision.resolved"), None)
    decision["actions"] = actions
    decision["attribution"] = {
        "proposed": proposed,
        "resolved": resolved,
        "latest": actions[-1] if actions else None,
    }
    decision["proposed_owner"] = proposed.get("owner") if proposed else None
    decision["resolved_owner"] = resolved.get("owner") if resolved else None
    return decision


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
    event_rows = conn.execute(
        "SELECT * FROM events WHERE project_id=? AND event_type IN "
        "('decision.proposed','decision.resolved') ORDER BY seq",
        (project_id,)).fetchall()
    by_decision = {}
    for event in event_rows:
        payload = json.loads(event["payload"] or "{}")
        decision_id = payload.get("decision_id")
        if decision_id:
            by_decision.setdefault(decision_id, []).append(event)
    return {"project": project_id,
            "decisions": [_decision_dict(
                row, by_decision.get(row["decision_id"], []), conn, project_id)
                for row in rows]}


# --- project rules ---------------------------------------------------------

def _registered_actor_role(conn, project_id, actor_id):
    row = conn.execute(
        "SELECT role FROM agents WHERE project_id=? AND agent_id=?",
        (project_id, actor_id)).fetchone()
    if not row:
        alias = conn.execute(
            "SELECT canonical_actor_id FROM actor_aliases WHERE project_id=?"
            " AND legacy_actor_id=?", (project_id, actor_id)).fetchone()
        if alias:
            row = conn.execute(
                "SELECT role FROM agents WHERE project_id=? AND agent_id=?",
                (project_id, alias["canonical_actor_id"])).fetchone()
    return (row["role"] or "unassigned") if row else "unassigned"


def _require_rule_manager(conn, project_id, actor_id, actor_type):
    if actor_type == "human":
        return "human"
    role = _registered_actor_role(conn, project_id, actor_id) \
        if actor_type == "agent" else "unassigned"
    if actor_type != "agent" or role != "director":
        raise AttaccaError(
            "project rules may only be managed by a human or registered "
            "Director; '%s' is %s" % (actor_id, role))
    return role


def _rule_row(conn, project_id, rule_id):
    row = conn.execute(
        "SELECT * FROM project_rules WHERE project_id=? AND rule_id=?",
        (project_id, rule_id)).fetchone()
    if not row:
        raise AttaccaError("unknown project rule %s in project %s"
                           % (rule_id, project_id))
    return row


def _rule_dict(row):
    rule = dict(row)
    rule["enabled"] = bool(rule["enabled"])
    return rule


def _rule_priority(value):
    try:
        priority = int(value)
    except (TypeError, ValueError):
        raise AttaccaError("rule priority must be an integer from 0 to 1000")
    if priority < 0 or priority > 1000:
        raise AttaccaError("rule priority must be an integer from 0 to 1000")
    return priority


def _rule_scope(value):
    scope = str(value or "everyone").strip().lower()
    if scope not in RULE_SCOPES:
        raise AttaccaError("rule scope must be one of %s"
                           % ", ".join(RULE_SCOPES))
    return scope


def rule_list(conn, project_id, actor_id=None, actor_type="agent",
              include_disabled=False, include_all=False):
    """List the rules applicable to the caller's registered role.

    Callers cannot claim a different role. Humans see all scopes. A Director
    may request all/disabled rules for management; every other AI receives
    only enabled ``everyone`` plus its actual registered role.
    """
    get_project(conn, project_id)
    role = "human" if actor_type == "human" else \
        (_registered_actor_role(conn, project_id, actor_id)
         if actor_type == "agent" and actor_id else "unassigned")
    manager = actor_type == "human" or role == "director"
    if include_all and not manager:
        raise AttaccaError(
            "include_all project rules requires a human or registered Director")
    if include_disabled and not manager:
        raise AttaccaError(
            "include_disabled project rules requires a human or registered Director")
    clauses = ["project_id=?"]
    params = [project_id]
    if not include_disabled:
        clauses.append("enabled=1")
    if not (actor_type == "human" or include_all):
        scopes = ["everyone"]
        if role in AGENT_ROLES:
            scopes.append(role)
        clauses.append("scope IN (%s)" % ",".join("?" for _ in scopes))
        params.extend(scopes)
    rows = conn.execute(
        "SELECT * FROM project_rules WHERE %s"
        " ORDER BY priority, CAST(SUBSTR(rule_id,3) AS INTEGER)"
        % " AND ".join(clauses), params).fetchall()
    return {"project": project_id, "actor_role": role,
            "applicable_scopes": RULE_SCOPES if actor_type == "human" or include_all
            else (["everyone", role] if role in AGENT_ROLES else ["everyone"]),
            "rules": [_rule_dict(row) for row in rows]}


def rule_create(conn, project_id, actor_id, actor_type, title, body,
                scope="everyone", priority=100):
    if not title or not str(title).strip():
        raise AttaccaError("rule_create: title is required")
    if not body or not str(body).strip():
        raise AttaccaError("rule_create: body is required")
    scope = _rule_scope(scope)
    priority = _rule_priority(priority)
    with write_tx(conn):
        get_project(conn, project_id)
        _require_rule_manager(conn, project_id, actor_id, actor_type)
        rule_id = _next_counter_id(
            conn, "project_rules", "rule_id", project_id, "R-")
        nowi = now_iso()
        owner = current_owner()
        conn.execute(
            "INSERT INTO project_rules (project_id, rule_id, title, body,"
            " scope, priority, enabled, version, created_by, created_owner,"
            " created_at, updated_by, updated_owner, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (project_id, rule_id, str(title).strip(), str(body).strip(), scope,
             priority, 1, 1, actor_id, owner, nowi, actor_id, owner, nowi))
        context_version = bump_context_version(conn, project_id)
        event = append_event(
            conn, project_id, actor_id, actor_type, "rule.created",
            {"rule_id": rule_id, "title": str(title).strip(),
             "body": str(body).strip(), "scope": scope,
             "priority": priority, "enabled": True, "version": 1},
            in_tx=True)
        rule = _rule_dict(_rule_row(conn, project_id, rule_id))
    return {"ok": True, "rule": rule, "context_version": context_version,
            "event": event}


def rule_update(conn, project_id, actor_id, actor_type, rule_id, updates,
                expected_version):
    allowed = {"title", "body", "scope", "priority", "enabled"}
    updates = {key: value for key, value in (updates or {}).items()
               if key in allowed and value is not None}
    if not updates:
        raise AttaccaError("rule_update needs at least one of: %s"
                           % ", ".join(sorted(allowed)))
    if expected_version is None:
        raise AttaccaError("rule_update requires expected_version")
    try:
        expected_version = int(expected_version)
    except (TypeError, ValueError):
        raise AttaccaError("expected_version must be an integer")
    if "title" in updates:
        if not str(updates["title"]).strip():
            raise AttaccaError("rule title cannot be empty")
        updates["title"] = str(updates["title"]).strip()
    if "body" in updates:
        if not str(updates["body"]).strip():
            raise AttaccaError("rule body cannot be empty")
        updates["body"] = str(updates["body"]).strip()
    if "scope" in updates:
        updates["scope"] = _rule_scope(updates["scope"])
    if "priority" in updates:
        updates["priority"] = _rule_priority(updates["priority"])
    if "enabled" in updates and not isinstance(updates["enabled"], bool):
        raise AttaccaError("rule enabled must be true or false")
    with write_tx(conn):
        get_project(conn, project_id)
        _require_rule_manager(conn, project_id, actor_id, actor_type)
        row = _rule_row(conn, project_id, rule_id)
        if row["version"] != expected_version:
            raise AttaccaError(
                "rule conflict: expected %s v%d but it is v%d; reload rules "
                "and reconcile before writing"
                % (rule_id, expected_version, row["version"]))
        changed = {}
        for key, value in updates.items():
            current = bool(row[key]) if key == "enabled" else row[key]
            if current != value:
                changed[key] = value
        if not changed:
            return {"ok": True, "already_current": True,
                    "rule": _rule_dict(row),
                    "context_version": get_project(
                        conn, project_id)["context_version"]}
        merged = {key: (bool(row[key]) if key == "enabled" else row[key])
                  for key in allowed}
        merged.update(changed)
        new_version = row["version"] + 1
        nowi = now_iso()
        owner = current_owner()
        conn.execute(
            "UPDATE project_rules SET title=?, body=?, scope=?, priority=?,"
            " enabled=?, version=?, updated_by=?, updated_owner=?, updated_at=?"
            " WHERE project_id=? AND rule_id=? AND version=?",
            (merged["title"], merged["body"], merged["scope"],
             merged["priority"], 1 if merged["enabled"] else 0,
             new_version, actor_id, owner, nowi, project_id, rule_id,
             expected_version))
        context_version = bump_context_version(conn, project_id)
        event = append_event(
            conn, project_id, actor_id, actor_type, "rule.updated",
            {"rule_id": rule_id, "title": merged["title"],
             "changed": changed, "scope": merged["scope"],
             "priority": merged["priority"], "enabled": merged["enabled"],
             "version": new_version}, in_tx=True)
        rule = _rule_dict(_rule_row(conn, project_id, rule_id))
    return {"ok": True, "rule": rule, "changed": sorted(changed),
            "context_version": context_version, "event": event}


def _require_cloud_context_manager(conn, project_id, actor_id, actor_type):
    """Cloud context, like Project Rules, may only be edited by a human or a
    registered Director. Advisors and workers are rejected."""
    if actor_type == "human":
        return "human"
    role = _registered_actor_role(conn, project_id, actor_id) \
        if actor_type == "agent" else "unassigned"
    if actor_type != "agent" or role != "director":
        raise AttaccaError(
            "cloud context may only be edited by a human or registered "
            "Director; '%s' is %s" % (actor_id, role))
    return role


def _cloud_context_row(conn, project_id):
    return conn.execute(
        "SELECT * FROM project_cloud_context WHERE project_id=?",
        (project_id,)).fetchone()


def _cloud_context_dict(row):
    if not row:
        return {"content": "", "version": 0, "sha256": sha256_hex(""),
                "updated_by": None, "updated_owner": None,
                "updated_at": None}
    return {"content": row["content"], "version": row["version"],
            "sha256": sha256_hex(row["content"] or ""),
            "updated_by": row["updated_by"],
            "updated_owner": row["updated_owner"],
            "updated_at": row["updated_at"]}


def cloud_context_get(conn, project_id, actor_id=None, actor_type="agent"):
    """Read the project cloud context: a single shared free-text document, like
    a hosted AGENTS.md / CLAUDE.md, that is injected into every session brief.
    Any worker may read it; only humans and Directors may edit it."""
    get_project(conn, project_id)
    return {"project": project_id,
            "cloud_context": _cloud_context_dict(_cloud_context_row(
                conn, project_id))}


def cloud_context_set(conn, project_id, actor_id, actor_type, content,
                      expected_version=None):
    """Replace the cloud context document (human/Director only) with optimistic
    version checking. Bumps project context so active clients re-read it."""
    if content is None:
        raise AttaccaError("cloud_context_set: content is required")
    content = str(content)
    if len(content) > 100000:
        raise AttaccaError("cloud context is limited to 100000 characters")
    if expected_version is not None:
        try:
            expected_version = int(expected_version)
        except (TypeError, ValueError):
            raise AttaccaError("expected_version must be an integer")
    with write_tx(conn):
        get_project(conn, project_id)
        _require_cloud_context_manager(conn, project_id, actor_id, actor_type)
        row = _cloud_context_row(conn, project_id)
        current_version = row["version"] if row else 0
        if expected_version is not None and expected_version != current_version:
            raise AttaccaError(
                "cloud context conflict: expected v%d but it is v%d; reload "
                "and reconcile before writing"
                % (expected_version, current_version))
        if row is not None and row["content"] == content:
            return {"ok": True, "already_current": True,
                    "cloud_context": _cloud_context_dict(row),
                    "context_version": get_project(
                        conn, project_id)["context_version"]}
        new_version = current_version + 1
        nowi = now_iso()
        owner = current_owner()
        if row is None:
            conn.execute(
                "INSERT INTO project_cloud_context (project_id, content,"
                " version, updated_by, updated_owner, updated_at)"
                " VALUES (?,?,?,?,?,?)",
                (project_id, content, new_version, actor_id, owner, nowi))
        else:
            conn.execute(
                "UPDATE project_cloud_context SET content=?, version=?,"
                " updated_by=?, updated_owner=?, updated_at=?"
                " WHERE project_id=? AND version=?",
                (content, new_version, actor_id, owner, nowi, project_id,
                 current_version))
        context_version = bump_context_version(conn, project_id)
        event = append_event(
            conn, project_id, actor_id, actor_type, "cloud_context.updated",
            {"version": new_version, "length": len(content)}, in_tx=True)
        result = _cloud_context_dict(_cloud_context_row(conn, project_id))
    return {"ok": True, "cloud_context": result,
            "context_version": context_version, "event": event}


# --- agents ----------------------------------------------------------------

def _migrate_actor_references_in_tx(conn, project_id, aliases, canonical_id,
                                    canonical_role):
    """Move mutable identity pointers; immutable ledger rows stay untouched."""
    aliases = sorted({a for a in aliases if a and a != canonical_id})
    if not aliases:
        return {"aliases": [], "lead_migrated": False,
                "claims_migrated": 0, "cursor_migrated": False,
                "agent_rows_migrated": 0,
                "bridge_access_migrated": 0,
                "state_changed": False}
    placeholders = ",".join("?" for _ in aliases)
    nowi = now_iso()
    agent_rows_migrated = conn.execute(
        "SELECT COUNT(*) AS n FROM agents WHERE project_id=?"
        " AND agent_id IN (%s)" % placeholders,
        [project_id] + aliases).fetchone()["n"]
    for legacy in aliases:
        conn.execute(
            "INSERT INTO actor_aliases (project_id, legacy_actor_id,"
            " canonical_actor_id, migrated_at) VALUES (?,?,?,?)"
            " ON CONFLICT(project_id, legacy_actor_id) DO UPDATE SET"
            " canonical_actor_id=excluded.canonical_actor_id,"
            " migrated_at=excluded.migrated_at",
            (project_id, legacy, canonical_id, nowi))
    # Flatten earlier alias chains when a runtime changes role.
    conn.execute(
        "UPDATE actor_aliases SET canonical_actor_id=?, migrated_at=?"
        " WHERE project_id=? AND canonical_actor_id IN (%s)" % placeholders,
        [canonical_id, nowi, project_id] + aliases)
    cursor_rows = conn.execute(
        "SELECT MAX(last_read_seq) AS last_read_seq FROM inbox_cursors"
        " WHERE project_id=? AND actor_id IN (%s)" % placeholders,
        [project_id] + aliases).fetchone()
    cursor = cursor_rows["last_read_seq"] if cursor_rows else None
    if cursor is not None:
        conn.execute(
            "INSERT INTO inbox_cursors (project_id, actor_id, last_read_seq,"
            " updated_at) VALUES (?,?,?,?)"
            " ON CONFLICT(project_id, actor_id) DO UPDATE SET"
            " last_read_seq=MAX(last_read_seq, excluded.last_read_seq),"
            " updated_at=excluded.updated_at",
            (project_id, canonical_id, cursor, nowi))
        conn.execute(
            "DELETE FROM inbox_cursors WHERE project_id=?"
            " AND actor_id IN (%s)" % placeholders,
            [project_id] + aliases)
    claims = conn.execute(
        "UPDATE tasks SET claimed_by=?, updated_at=? WHERE project_id=?"
        " AND claimed_by IN (%s) AND status NOT IN ('done','cancelled')" %
        placeholders,
        [canonical_id, nowi, project_id] + aliases).rowcount
    project = get_project(conn, project_id)
    lead_migrated = project.get("lead_director") in aliases
    if lead_migrated:
        conn.execute(
            "UPDATE projects SET lead_director=? WHERE project_id=?",
            (canonical_id if canonical_role == "director" else None,
             project_id))

    # Selected-agent bridge policies are mutable identity pointers too. A
    # confirmed role migration (worker -> director, legacy -> canonical, ...)
    # must not silently lock that same AI out of a named bridge conversation.
    # Update only this workspace's side and notify both connected workspaces;
    # the authority relationship and the peer-side policy are untouched.
    bridge_access_migrated = 0
    bridge_rows = conn.execute(
        "SELECT * FROM bridges WHERE project_a=? OR project_b=?",
        (project_id, project_id)).fetchall()
    for bridge_row in bridge_rows:
        column = "access_a" \
            if bridge_row["project_a"] == project_id else "access_b"
        access = _stored_bridge_participation(bridge_row[column])
        migrated_agents = sorted({
            canonical_id if item in aliases else item
            for item in access["agents"]})
        if migrated_agents == access["agents"]:
            continue
        access["agents"] = migrated_agents
        conn.execute(
            "UPDATE bridges SET %s=? WHERE project_a=? AND project_b=?" %
            column,
            (canonical_json(access), bridge_row["project_a"],
             bridge_row["project_b"]))
        bridge_access_migrated += 1
        peer = bridge_row["project_b"] \
            if bridge_row["project_a"] == project_id \
            else bridge_row["project_a"]
        updated_row = _bridge_row(conn, project_id, peer)
        for side, other in ((project_id, peer), (peer, project_id)):
            side_access = _bridge_side_participation(updated_row, side)
            far_access = _bridge_side_participation(updated_row, other)
            bump_context_version(conn, side)
            append_event(
                conn, side, canonical_id, "agent",
                "bridge.access_identity_migrated",
                {"with": other, "migrated_from": aliases,
                 "canonical_actor_id": canonical_id,
                 "participation": side_access,
                 "peer_participation": far_access}, in_tx=True)
    conn.execute(
        "DELETE FROM agents WHERE project_id=? AND agent_id IN (%s)" %
        placeholders, [project_id] + aliases)
    state_changed = bool(agent_rows_migrated or lead_migrated or claims
                         or cursor is not None or bridge_access_migrated)
    return {"aliases": aliases, "lead_migrated": lead_migrated,
            "claims_migrated": claims, "cursor_migrated": cursor is not None,
            "agent_rows_migrated": agent_rows_migrated,
            "bridge_access_migrated": bridge_access_migrated,
            "state_changed": state_changed}


def agent_register(conn, project_id, actor_id, actor_type, agent_id=None,
                   display_name=None, role=None, runtime=None,
                   canonical_identity=False, registration_username=None,
                   allow_foreign_owner=False,
                   authorized_owner_labels=None):
    requested_id = agent_id or actor_id
    registration_username = str(registration_username or "").strip() or None
    authorized_owner_keys = {
        _auth_owner_alias_key(value)
        for value in (authorized_owner_labels or []) if str(value or "").strip()
    }
    if registration_username:
        authorized_owner_keys.add(
            _auth_owner_alias_key(registration_username))

    def owner_is_authorized(row):
        return bool(row and row["owner"] and
                    _auth_owner_alias_key(row["owner"]) in
                    authorized_owner_keys)

    def owned_by_another(row):
        return bool(
            registration_username and row and row["owner"] and
            not owner_is_authorized(row) and not allow_foreign_owner)

    def protected_field_changes(row, requested_role, requested_runtime):
        """Return authority/ownership changes a member may not smuggle in.

        An authenticated non-admin may create its own absent actor and may
        repeat the exact same registration, but an existing actor is an
        authority record rather than an upsert-shaped profile.  In
        particular, setup/repair must not become a route for changing its
        owner, role, or runtime.  Admin browser sessions opt out explicitly at
        the HTTP boundary; terminal/service tokens never inherit that opt-out.
        """
        if not registration_username or allow_foreign_owner or not row:
            return []
        changes = []
        effective_owner = str(row["owner"] or "").strip()
        if not effective_owner or not owner_is_authorized(row):
            changes.append("owner")
        if requested_role is not None and row["role"] != requested_role:
            changes.append("role")
        if requested_runtime is not None \
                and row["runtime"] != requested_runtime:
            changes.append("runtime")
        return changes

    explicit_role = role is not None
    if role is not None and role not in ("director", "advisor", "worker"):
        raise AttaccaError("agent role must be director, advisor, or worker")
    with write_tx(conn):
        project = get_project(conn, project_id)
        migration = {"aliases": [], "lead_migrated": False,
                     "claims_migrated": 0, "cursor_migrated": False,
                     "agent_rows_migrated": 0,
                     "bridge_access_migrated": 0,
                     "state_changed": False}
        if canonical_identity:
            records = [dict(row) for row in conn.execute(
                "SELECT * FROM agents WHERE project_id=?", (project_id,))]
            identity = registered_agent_identity(
                records, project_id, requested_id, runtime=runtime)
            runtime = identity["runtime"]
            if role is None:
                if identity.get("conflict_roles"):
                    raise AttaccaError(
                        "AI runtime '%s' has conflicting existing roles in "
                        "workspace '%s': %s. Run complete Attacca setup and "
                        "explicitly choose this AI's role; no identity was "
                        "changed" % (runtime, project_id, ", ".join(
                            identity["conflict_roles"])))
                role = identity["role"]
            agent_id = canonical_agent_id(project_id, role, runtime)
            matching = [record["agent_id"] for record in records
                        if _matching_runtime(record, runtime)
                        and (record.get("role") in (None, role)
                             or not explicit_role)
                        and record["agent_id"] != agent_id]
            if explicit_role:
                # Some older sessions claimed tasks or wrote events without
                # ever creating an agents row.  A confirmed role choice must
                # still migrate those exact role-marked pointers/aliases, or
                # active work remains stranded under e.g.
                # ``jack.codex_director``.  Do not infer a role for generic
                # QA/session ids; they remain separate until explicitly set up.
                legacy_rows = conn.execute(
                    "SELECT actor_id AS legacy_id FROM events"
                    " WHERE project_id=?"
                    " UNION SELECT claimed_by FROM tasks"
                    " WHERE project_id=? AND claimed_by IS NOT NULL"
                    " UNION SELECT actor_id FROM inbox_cursors"
                    " WHERE project_id=?"
                    " UNION SELECT lead_director FROM projects"
                    " WHERE project_id=? AND lead_director IS NOT NULL",
                    (project_id, project_id, project_id,
                     project_id)).fetchall()
                matching.extend(
                    row["legacy_id"] for row in legacy_rows
                    if row["legacy_id"] != agent_id
                    and legacy_actor_role_hint(row["legacy_id"]) == role
                    and normalize_agent_runtime(
                        actor=row["legacy_id"]) == runtime)
            if requested_id != agent_id:
                matching.append(requested_id)
            # Resolve mentions/cursors written by the owner-prefixed scheme
            # used before canonical workspace identities.
            if current_owner() and requested_id != agent_id:
                matching.append("%s.%s" % (
                    slugify(current_owner()), requested_id))
            affected_ids = set(matching) | {agent_id}
            foreign = [record["agent_id"] for record in records
                       if record["agent_id"] in affected_ids
                       and owned_by_another(record)]
            if foreign:
                raise AuthorizationError(
                    "agent_owner_mismatch: authenticated user '%s' cannot"
                    " replace or migrate actor(s) owned by another user: %s" %
                    (registration_username, ", ".join(sorted(foreign))))
            authority_changes = {
                record["agent_id"]: protected_field_changes(
                    record, role, runtime)
                for record in records if record["agent_id"] in affected_ids
                and protected_field_changes(record, role, runtime)
            }
            if authority_changes:
                detail = ", ".join(
                    "%s (%s)" % (actor, "/".join(fields))
                    for actor, fields in sorted(authority_changes.items()))
                raise AuthorizationError(
                    "agent_registration_not_idempotent: authenticated user"
                    " '%s' cannot change an existing actor's owner, role, or"
                    " runtime: %s" % (registration_username, detail))
            migration = _migrate_actor_references_in_tx(
                conn, project_id, matching, agent_id, role)
            # A self-registration/setup action is attributed to the new
            # operational identity immediately. Owner stays a separate field.
            if actor_type == "agent" and normalize_agent_runtime(
                    actor=actor_id) == runtime:
                actor_id = agent_id
            project = get_project(conn, project_id)
            if display_name is None:
                display_name = "%s · %s · %s" % (
                    project["name"], role or "unassigned", runtime)
        else:
            agent_id = requested_id
        row = conn.execute(
            "SELECT * FROM agents WHERE project_id=? AND agent_id=?",
            (project_id, agent_id)).fetchone()
        if owned_by_another(row):
            raise AuthorizationError(
                "agent_owner_mismatch: actor '%s' is owned by Attacca user"
                " '%s', not '%s'" %
                (agent_id, row["owner"], registration_username))
        protected_changes = protected_field_changes(row, role, runtime)
        if protected_changes:
            raise AuthorizationError(
                "agent_registration_not_idempotent: authenticated user '%s'"
                " cannot change existing actor '%s' field(s): %s" %
                (registration_username, agent_id,
                 ", ".join(protected_changes)))
        if role is not None and agent_id == project.get("lead_director") \
                and role != "director":
            raise AttaccaError(
                "Lead Director '%s' must keep the director role; assign a "
                "different lead before changing this AI to %s"
                % (agent_id, role or "unassigned"))
        nowi = now_iso()
        owner = current_owner()
        if row:
            previous_role = row["role"]
            effective_owner = row["owner"] or owner
            conn.execute(
                "UPDATE agents SET display_name=COALESCE(?, display_name),"
                " role=COALESCE(?, role), runtime=COALESCE(?, runtime),"
                " owner=COALESCE(owner, ?), last_seen_at=?"
                " WHERE project_id=? AND agent_id=?",
                (display_name, role, runtime, owner, nowi,
                 project_id, agent_id))
            result = {"ok": True, "agent_id": agent_id,
                      "already_registered": True,
                      "role": role if role is not None else previous_role,
                      "identity": {"workspace": project_id,
                                   "role": role if role is not None else previous_role,
                                   "runtime": runtime,
                                   "owner": effective_owner},
                      "migration": migration}
            # MCP startup may have discovered this actor before guided setup
            # assigned its authority. Record the later explicit role choice as
            # a durable governance event, while keeping identical setup reruns
            # quiet and idempotent.
            if role is not None and role != previous_role:
                result["role_changed"] = True
                result["context_version"] = bump_context_version(
                    conn, project_id)
                role_payload = {"agent_id": agent_id,
                                "from": previous_role, "to": role}
                if migration["aliases"]:
                    role_payload["migrated_from"] = migration["aliases"]
                result["event"] = append_event(
                    conn, project_id, actor_id, actor_type,
                    "agent.role_changed", role_payload, in_tx=True)
            elif migration["state_changed"]:
                result["context_version"] = bump_context_version(
                    conn, project_id)
                result["event"] = append_event(
                    conn, project_id, actor_id, actor_type,
                    "agent.identity_migrated",
                    {"agent_id": agent_id,
                     "migrated_from": migration["aliases"],
                     "lead_migrated": migration["lead_migrated"],
                     "claims_migrated": migration["claims_migrated"],
                     "bridge_access_migrated": migration[
                         "bridge_access_migrated"]},
                    in_tx=True)
            return result
        conn.execute(
            "INSERT INTO agents (project_id, agent_id, display_name, role, runtime,"
            " owner, actor_type, registered_at, last_seen_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (project_id, agent_id, display_name or agent_id, role, runtime,
             owner, actor_type, nowi, nowi))
        context_version = bump_context_version(conn, project_id) \
            if role is not None else None
        event = append_event(conn, project_id, actor_id, actor_type,
                             "agent.registered",
                             {"agent_id": agent_id,
                              "display_name": display_name or agent_id,
                              "role": role, "runtime": runtime,
                              "owner": owner,
                              "migrated_from": migration["aliases"]},
                             in_tx=True)
    result = {"ok": True, "agent_id": agent_id,
              "already_registered": False, "role": role, "event": event,
              "identity": {"workspace": project_id, "role": role,
                           "runtime": runtime, "owner": owner},
              "migration": migration}
    if context_version is not None:
        result["context_version"] = context_version
    return result


def agent_list(conn, project_id):
    get_project(conn, project_id)
    rows = conn.execute(
        "SELECT * FROM agents WHERE project_id=? ORDER BY registered_at",
        (project_id,)).fetchall()
    agents = []
    for row in rows:
        agent = dict(row)
        runtime = normalize_agent_runtime(agent.get("runtime")) \
            if agent.get("runtime") else normalize_agent_runtime(
                actor=agent.get("agent_id"))
        agent["identity"] = {
            "workspace": project_id,
            "role": agent.get("role") or "unassigned",
            "runtime": runtime,
            "owner": agent.get("owner"),
        }
        agent["operational_actor_id"] = canonical_agent_id(
            project_id, agent.get("role"), runtime)
        agents.append(agent)
    return {"project": project_id, "agents": agents}


def project_actor_identity(conn, project_id, actor_id, actor_type="agent",
                           owner=None):
    """Project/role/runtime projection for UI and API reads.

    It never changes historical actor_id values in the ledger. Legacy ids are
    resolved through the alias table (or their registry row) and exposed as a
    canonical display identity; the original remains available to callers.
    """
    if actor_type != "agent":
        role = "human" if actor_type == "human" else actor_type
        raw = str(actor_id or "").strip()
        parts = raw.rsplit(".", 2)
        canonical_human = len(parts) == 3 and parts[1] == "human"
        human_user = None
        if actor_type == "human":
            human_user = str(owner or (
                parts[2] if canonical_human else raw.rsplit(".", 1)[-1]
            ) or "unknown").strip()
            runtime = slugify(human_user) or "unknown"
        else:
            runtime = normalize_agent_runtime(actor=actor_id)
        return {"workspace": project_id, "role": role,
                "runtime": runtime, "owner": owner,
                "human_user": human_user,
                "actor_id": "%s.%s.%s" % (
                    slugify(project_id), slugify(role), runtime),
                "ledger_actor_id": actor_id}
    alias = conn.execute(
        "SELECT canonical_actor_id FROM actor_aliases WHERE project_id=?"
        " AND legacy_actor_id=?", (project_id, actor_id)).fetchone()
    canonical_id = alias["canonical_actor_id"] if alias else None
    canonical_id = canonical_id or actor_id
    parsed = parse_canonical_agent_id(canonical_id, project_id)
    row = conn.execute(
        "SELECT role, runtime, owner FROM agents WHERE project_id=?"
        " AND agent_id=?", (project_id, canonical_id or actor_id)).fetchone()
    if parsed:
        role, runtime = parsed["role"], parsed["runtime"]
    elif row:
        role = row["role"] or "unassigned"
        runtime = normalize_agent_runtime(row["runtime"]) \
            if row["runtime"] else normalize_agent_runtime(actor=actor_id)
        canonical_id = canonical_agent_id(project_id, role, runtime)
    else:
        role = "unassigned"
        runtime = normalize_agent_runtime(actor=actor_id)
        canonical_id = canonical_agent_id(project_id, role, runtime)
    return {"workspace": project_id, "role": role, "runtime": runtime,
            "owner": owner or (row["owner"] if row else None),
            "actor_id": canonical_id, "ledger_actor_id": actor_id}


def immutable_event_attribution(conn, project_id, actor_id,
                                actor_type="agent", owner=None):
    """Read-time attribution derived only from immutable event fields.

    A human actor *is* the human user, so an ownerless historical human event
    must not render a second ``Run by user: not recorded`` label. AI actions
    keep the canonical operational actor and the literal event owner as the
    accountable human. Never use a mutable current agent owner to rewrite
    historical attribution.
    """
    identity = project_actor_identity(
        conn, project_id, actor_id, actor_type, owner=owner)
    identity["owner"] = owner
    human_user = identity.get("human_user") if actor_type == "human" else None
    return {
        "actor_id": identity["actor_id"],
        "ledger_actor_id": actor_id,
        "actor_type": actor_type,
        "human_user": human_user,
        "run_by_user": None if actor_type == "human" else owner,
        "identity": identity,
    }


# --- log / status / freshness / verify ------------------------------------

def render_log_line(row):
    """Human-readable one-liner for a ledger event, or None if it is noise."""
    payload = json.loads(row["payload"])
    etype = row["event_type"]
    at = row["created_at"][:19].replace("T", " ")
    actor = row["actor_id"]
    owner = row["owner"] if "owner" in row.keys() else None
    if owner:
        actor = "%s (OWNER: %s)" % (actor, owner)
    branch = row["git_branch"] if "git_branch" in row.keys() else None
    revision = row["base_revision"]
    if branch:
        actor += " [branch: %s%s]" % (
            branch, " @ %s" % revision[:10] if revision else "")
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
    if etype == "agent.role_changed":
        return "%s  %s changed agent '%s' role: %s -> %s" % (
            at, actor, payload.get("agent_id"),
            payload.get("from") or "unassigned", payload.get("to"))
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
    if etype in ("task.plan.created", "task.plan.revised"):
        verb = "created" if etype.endswith("created") else "revised"
        return "%s  %s %s%s plan v%s [%s]: %s" % (
            at, actor, verb, task, payload.get("plan_version"),
            payload.get("status"), payload.get("title"))
    if etype == "task.plan.submitted":
        return "%s  %s submitted%s plan v%s for review" % (
            at, actor, task, payload.get("plan_version"))
    if etype in ("task.plan.approved", "task.plan.suggested",
                 "task.plan.commented"):
        verb = {"task.plan.approved": "approved",
                "task.plan.suggested": "suggested an edit to",
                "task.plan.commented": "commented on"}[etype]
        section = (" section %s of" % payload["section_id"]) \
            if payload.get("section_id") else ""
        note = (": %s" % payload["note"]) if payload.get("note") else ""
        return "%s  %s %s%s%s plan v%s%s" % (
            at, actor, verb, section, task, payload.get("plan_version"), note)
    if etype == "decision.proposed":
        return "%s  %s proposed %s: %s" % (
            at, actor, payload.get("decision_id"), payload.get("title"))
    if etype == "decision.resolved":
        return "%s  %s marked %s %s: %s" % (
            at, actor, payload.get("decision_id"),
            payload.get("resolution"), payload.get("title"))
    if etype == "rule.created":
        return "%s  %s created project rule %s [%s]: %s" % (
            at, actor, payload.get("rule_id"), payload.get("scope"),
            payload.get("title"))
    if etype == "rule.updated":
        return "%s  %s updated project rule %s to v%s (%s)" % (
            at, actor, payload.get("rule_id"), payload.get("version"),
            ", ".join(sorted((payload.get("changed") or {}).keys())))
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


def project_log(conn, project_id, limit=40, actor_id=None,
                actor_type="agent"):
    get_project(conn, project_id)
    limit = max(1, min(int(limit or 40), 1000))
    return {"project": project_id, "log": _significant_events(
        conn, project_id, after_seq=0, limit=limit,
        actor_id=actor_id, actor_type=actor_type)}


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
        " (SELECT COUNT(*) FROM project_rules WHERE project_id=:p AND enabled=1) AS active_rules,"
        " (SELECT COUNT(*) FROM agents WHERE project_id=:p) AS agents",
        {"p": project_id}).fetchone()
    actor_row = conn.execute(
        "SELECT role, runtime, owner FROM agents WHERE project_id=?"
        " AND agent_id=?", (project_id, actor_id)).fetchone()
    identity = {
        "workspace": project_id,
        "role": (actor_row["role"] if actor_row else None) or "unassigned",
        "runtime": (normalize_agent_runtime(actor_row["runtime"])
                    if actor_row and actor_row["runtime"] else
                    normalize_agent_runtime(actor=actor_id)),
        "owner": (actor_row["owner"] if actor_row else None)
                 or current_owner(),
    }
    return {
        "project": project_id,
        "name": project["name"],
        "root_path": project["root_path"],
        "db": str(db_path),
        "you": {"actor_id": actor_id, "actor_type": actor_type,
                "identity": identity},
        "context_version": project["context_version"],
        "lead_director": project.get("lead_director"),
        "handoff_updated_at": handoff_row["updated_at"] if handoff_row else None,
        "counts": dict(counts),
        "git": {"head": git_head(project.get("root_path")),
                "branch": git_branch(project.get("root_path"))},
        "workflow_warnings": workflow_warnings(
            conn, project_id, actor_id, actor_type),
    }


def check_freshness(conn, project_id, context_version, actor_id=None,
                    actor_type="agent"):
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
            conn, project_id, after_seq=row["s"], limit=200,
            actor_id=actor_id, actor_type=actor_type)[-20:]
        result["action"] = ("Material project changes occurred after you were "
                            "briefed. Re-run get_handoff before writing (Drift "
                            "Guard, blueprint §11.3).")
    return result


def _search_query_terms(query):
    """Natural search terms with punctuation treated as separators.

    ``magic link claim`` must match ``magic-link claim``. Preserve term order
    for a stable response, but de-duplicate so repeated words do not generate
    redundant SQL predicates.
    """
    terms = re.findall(r"[^\W_]+", str(query or "").casefold(), re.UNICODE)
    return list(dict.fromkeys(term for term in terms if term))


def _search_predicate(columns, terms):
    haystack = "LOWER(" + " || ' ' || ".join(
        "COALESCE(%s,'')" % column for column in columns) + ")"
    return " AND ".join("%s LIKE ?" % haystack for _ in terms), [
        "%%%s%%" % term for term in terms]


def _search_room_line(row, payload):
    origin = payload.get("origin_project")
    origin_txt = " from %s" % origin if origin else ""
    authority = payload.get("authority")
    authority_txt = " [%s]" % authority.upper() if authority else ""
    return "%s  %s%s %s%s: %s" % (
        row["created_at"][:19].replace("T", " "), row["actor_id"],
        origin_txt, str(payload.get("msg_type") or "chat").upper(),
        authority_txt, payload.get("body") or "")


def search_project(conn, project_id, query, limit=20, actor_id=None,
                   actor_type="agent"):
    """Token-aware AND search across all durable project history.

    Search results are useful records rather than log-renderer side effects:
    every matching room event includes its full body even when that message
    type is intentionally omitted from the ordinary concise project log.
    """
    get_project(conn, project_id)
    if not query or not str(query).strip():
        raise AttaccaError("search: query is required")
    terms = _search_query_terms(query)
    if not terms:
        raise AttaccaError("search query needs at least one letter or number")
    limit = max(1, min(int(limit or 20), 100))

    event_where, event_params = _search_predicate(
        ["payload", "actor_id", "event_type", "task_id"], terms)
    event_rows = conn.execute(
        "SELECT * FROM events WHERE project_id=? AND " + event_where +
        " ORDER BY seq DESC", [project_id] + event_params).fetchall()
    raw_payloads = {
        row["event_id"]: json.loads(row["payload"] or "{}")
        for row in event_rows}
    room_rows = [row for row in event_rows
                 if row["event_type"] == "room.message"]
    room_payloads = _room_policy_payloads(
        conn, project_id, room_rows,
        payloads=[raw_payloads[row["event_id"]] for row in room_rows])
    policy_payloads = {
        row["event_id"]: payload
        for row, payload in zip(room_rows, room_payloads)}
    events = []
    for row in event_rows:
        payload = raw_payloads[row["event_id"]]
        if row["event_type"] == "room.message":
            payload = policy_payloads[row["event_id"]]
        if row["event_type"] == "room.message" and not \
                _bridge_message_visible(
                    conn, project_id, payload, actor_id, actor_type):
            continue
        identity_project = payload.get("origin_project") \
            if row["event_type"] == "room.message" else project_id
        attribution = immutable_event_attribution(
            conn, identity_project or project_id, row["actor_id"],
            row["actor_type"], row["owner"])
        result = {
            "event_id": row["event_id"], "seq": row["seq"],
            "event_type": row["event_type"], "at": row["created_at"],
            "actor": attribution["actor_id"],
            "actor_type": row["actor_type"], "owner": row["owner"],
            "task_id": row["task_id"], "attribution": attribution,
            "line": render_log_line(row) or "%s by %s" % (
                row["event_type"], attribution["actor_id"]),
        }
        if row["event_type"] == "room.message":
            # Never let LOG_EXCLUDED_MSG_TYPES turn a real search match into a
            # header-only result. Search is the history Ctrl+F, not a compact
            # activity feed.
            result.update({
                "line": _search_room_line(row, payload),
                "body": payload.get("body") or "",
                "msg_type": payload.get("msg_type") or "chat",
                "mentions": payload.get("mentions") or [],
                "reply_to": payload.get("reply_to"),
                "origin_project": payload.get("origin_project"),
                "authority": payload.get("authority"),
                "mirrored_to": _visible_bridge_peers(
                    conn, project_id, payload, actor_id, actor_type),
            })
        else:
            result["payload"] = payload
        events.append(result)
        if len(events) >= limit:
            break

    task_where, task_params = _search_predicate(
        ["title", "description", "last_report"], terms)
    tasks = []
    for row in conn.execute(
            "SELECT * FROM tasks WHERE project_id=? AND " + task_where +
            " ORDER BY updated_at DESC LIMIT ?",
            [project_id] + task_params + [limit]):
        report = json.loads(row["last_report"]) if row["last_report"] else None
        tasks.append({"task_id": row["task_id"], "title": row["title"],
                      "description": row["description"],
                      "status": row["status"], "last_report": report,
                      "updated_at": row["updated_at"]})

    decision_where, decision_params = _search_predicate(
        ["title", "detail", "rationale"], terms)
    decisions = [
        {"decision_id": row["decision_id"], "title": row["title"],
         "detail": row["detail"], "rationale": row["rationale"],
         "status": row["status"],
         "updated_at": row["resolved_at"] or row["created_at"]}
        for row in conn.execute(
            "SELECT * FROM decisions WHERE project_id=? AND " +
            decision_where +
            " ORDER BY COALESCE(resolved_at, created_at) DESC LIMIT ?",
            [project_id] + decision_params + [limit])]

    rule_where, rule_params = _search_predicate(["title", "body"], terms)
    rules = [
        {"rule_id": row["rule_id"], "title": row["title"],
         "body": row["body"], "scope": row["scope"],
         "enabled": bool(row["enabled"]), "version": row["version"]}
        for row in conn.execute(
            "SELECT * FROM project_rules WHERE project_id=? AND " +
            rule_where + " ORDER BY priority,"
            " CAST(SUBSTR(rule_id,3) AS INTEGER) LIMIT ?",
            [project_id] + rule_params + [limit])]

    handoff_where, handoff_params = _search_predicate(
        ["content", "updated_by"], terms)
    handoffs = [
        {"version": row["version"], "updated_by": row["updated_by"],
         "updated_at": row["updated_at"],
         "content": json.loads(row["content"])}
        for row in conn.execute(
            "SELECT * FROM handoffs WHERE project_id=? AND " +
            handoff_where + " ORDER BY version DESC LIMIT ?",
            [project_id] + handoff_params + [limit])]
    return {
        "project": project_id, "query": str(query), "query_terms": terms,
        "term_semantics": "AND", "events": events, "tasks": tasks,
        "decisions": decisions, "rules": rules,
        "handoff_versions": handoffs,
        "total_hits": (len(events) + len(tasks) + len(decisions) +
                       len(rules) + len(handoffs)),
        "hint": ("Punctuation and spacing are ignored between terms; every "
                 "returned record contains all query terms."),
    }


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
        raise AttaccaError("no event with seq %s in %s" % (seq, project_id))
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
        if row["hash_version"] >= 2:
            chain_material = "|".join([
                row["prev_hash"], row["payload_hash"], row["project_id"],
                str(row["seq"]), row["event_type"], row["actor_id"],
                row["created_at"], row["actor_type"], row["owner"] or "",
                str(row["context_version"] or ""), row["base_revision"] or "",
                row["git_branch"] or "", row["device_id"] or "",
                row["task_id"] or ""])
        else:
            chain_material = "|".join([
                row["prev_hash"], row["payload_hash"], row["project_id"],
                str(row["seq"]), row["event_type"], row["actor_id"],
                row["created_at"]])
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


def _b(desc):
    return {"type": "boolean", "description": desc}


def _arr(desc):
    return {"type": "array", "items": {"type": "string"}, "description": desc}


PROJECT_PROP = _s("Project id. Optional — defaults to the configured/detected project. "
                  "Set it to address another project (cross-project messaging).")

MCP_TOOLS = [
    {
        "name": "attacca_status",
        "description": "Who am I and where am I? Returns your actor identity, the resolved "
                       "project, context version, open task/decision counts and git state. "
                       "Cheap sanity check that the attacca layer is wired up.",
        "inputSchema": {"type": "object", "properties": {"project": PROJECT_PROP}},
    },
    {
        "name": "get_handoff",
        "description": "CALL THIS FIRST in every session. Returns the project's current "
                       "handoff (objective, what changed, active work, blockers, risks, "
                       "next actions), mandatory rules applicable to your registered role, "
                       "open tasks, standing decisions, recent activity and "
                       "the current context_version. This replaces re-discovering the "
                       "project or relying on stale chat memory.",
        "inputSchema": {"type": "object", "properties": {"project": PROJECT_PROP}},
    },
    {
        "name": "update_handoff",
        "description": "Update the current-state handoff for the next worker (any tool, any "
                       "model). Pass only the fields that changed; others are preserved. "
                       "On a role-governed workspace, only registered Directors may write "
                       "this shared document (humans retain override authority). The Lead "
                       "Director breaks ties but other Directors can write. Stale writes "
                       "are rejected by context version; other roles report through tasks "
                       "and room. Call at a meaningful transition or session end.",
        "inputSchema": {"type": "object", "properties": {
            "project": PROJECT_PROP,
            "objective": _s("Current objective of the project/phase."),
            "what_changed": _s("What changed recently (merged, refactored, fixed)."),
            "active_work": _s("Work in progress and by whom."),
            "blockers": _s("Known blockers."),
            "risks": _s("Current risks."),
            "next_actions": _s("Concrete next actions for the next worker."),
            "notes": _s("Anything else the next worker must know."),
            "expected_context_version": _i(
                "Version returned by get_handoff; stale values are rejected."),
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
        "description": "Post a message to one shared human+AI workspace room. Use msg_type: "
                       "chat (talk), directive (create instruction), claim (announce you "
                       "take work), handoff (state ready for others), challenge (dispute a "
                       "claim with evidence), decision, approval, status. For an explicit "
                       "destination, set target_project to one directly bridged workspace "
                       "for a retained copy in both rooms. Omit it for local-only delivery; "
                       "Attacca never fans routine work out implicitly.",
        "inputSchema": {"type": "object", "properties": {
            "body": _s("Message text."),
            "msg_type": _s("One of: %s (default chat)." % ", ".join(MSG_TYPES)),
            "mentions": _arr("Canonical actor ids you are addressing, e.g. "
                             "['analytics-engine.director.codex']."),
            "task_id": _s("Related task id, e.g. T-3."),
            "reply_to": _s("event_id of the message you reply to."),
            "target_project": _s(
                "Explicit cross-project destination. A directly bridged "
                "workspace means both rooms retain the conversation. Omit it "
                "to keep the message local."),
            "project": PROJECT_PROP,
        }, "required": ["body"]},
    },
    {
        "name": "room_read",
        "description": "Read the shared Project Room group conversation. Every "
                       "participant allowed by the room/bridge policy can read every "
                       "visible message; mentions and replies assign attention, not "
                       "visibility. First call: omit since_seq for the latest messages. "
                       "Then poll with since_seq=next_since_seq for only newer rows.",
        "inputSchema": {"type": "object", "properties": {
            "since_seq": _i("Only messages with ledger seq greater than this."),
            "limit": _i("Max messages (default 30)."),
            "project": PROJECT_PROP,
        }},
    },
    {
        "name": "check_inbox",
        "description": "YOUR unread projection of the shared group room: every "
                       "participation-visible non-self message since your persistent "
                       "actor cursor, with attention metadata. Mentions/replies identify "
                       "the expected responder; they never hide content from other "
                       "participants. Chat/directive with no mention or reply is sent to "
                       "everyone. Marks the scanned page read by default; "
                       "mark_read=false peeks. Drain again when may_have_more is true.",
        "inputSchema": {"type": "object", "properties": {
            "mark_read": {"type": "boolean",
                          "description": "Advance your read cursor (default true)."},
            "limit": _i("Max messages to scan (default 50)."),
            "project": PROJECT_PROP,
        }},
    },
    {
        "name": "message_dispose",
        "description": "Record the explicit outcome of an addressed message "
                       "or broadcast directive. Reading is not completion: "
                       "use acknowledged/not_actionable for closed messages, "
                       "or claimed/deferred/blocked/completed to keep the "
                       "assignment state durable. Claimed/completed require "
                       "a linked task in the matching board state.",
        "inputSchema": {"type": "object", "properties": {
            "event_id": _s("Room message event_id."),
            "disposition": _s("One of: %s." %
                              " | ".join(MESSAGE_DISPOSITIONS)),
            "note": _s("Reason/status; required for deferred, blocked, and "
                       "not_actionable."),
            "task_id": _s("Linked task id; required for claimed/completed."),
            "project": PROJECT_PROP,
        }, "required": ["event_id", "disposition"]},
    },
    {
        "name": "set_lead_director",
        "description": "Designate or change the project's Lead Director — the "
                       "actor whose directives assign work and break ties "
                       "(boss mode). Pass an empty agent_id to clear it. "
                       "Bumps the context version.",
        "inputSchema": {"type": "object", "properties": {
            "agent_id": _s("Canonical actor id to make lead, e.g. "
                           "analytics-engine.director.claude. "
                           "Empty string clears the lead."),
            "project": PROJECT_PROP,
        }, "required": ["agent_id"]},
    },
    {
        "name": "bridge_add",
        "description": "Bridge this project with another. Authority "
                       "(Peer/Master/Advisor) and participation are separate: "
                       "each side can allow all AIs, Directors+Advisors, "
                       "Directors only, or selected registered agents. Messages "
                       "stay local unless room_send explicitly names the connected "
                       "workspace as target_project.",
        "inputSchema": {"type": "object", "properties": {
            "other_project": _s("Project id to bridge with (see list_projects)."),
            "boss": _s("Optional: project id whose directors RULE the other "
                       "(master/subordinate relationship). Their messages "
                       "arrive tagged [MASTER]; the other side's arrive as "
                       "suggestions."),
            "advisor": _s("Optional: project id that ADVISES the other — its "
                          "messages arrive tagged as advice, no authority."),
            "participation": _s("Who in this workspace may enter the bridged "
                                 "conversation: all, directors_advisors, "
                                 "directors, or selected_agents."),
            "selected_agents": _arr("Registered actor ids allowed on this "
                                     "side when participation=selected_agents."),
            "peer_participation": _s("Who in the other workspace may enter: "
                                      "all, directors_advisors, directors, "
                                      "or selected_agents."),
            "peer_selected_agents": _arr("Registered actor ids allowed on the "
                                          "other side when peer_participation="
                                          "selected_agents."),
            "project": PROJECT_PROP,
        }, "required": ["other_project"]},
    },
    {
        "name": "bridge_update_access",
        "description": "Change who can read/send on each side of an existing "
                       "bridge without deleting it or changing its Peer/Master/"
                       "Advisor authority relationship. Human users and registered "
                       "Directors may manage this policy.",
        "inputSchema": {"type": "object", "properties": {
            "other_project": _s("Connected project id."),
            "participation": _s("This side: all, directors_advisors, directors, "
                                 "or selected_agents."),
            "selected_agents": _arr("This side's selected registered actor ids."),
            "peer_participation": _s("Other side: all, directors_advisors, "
                                      "directors, or selected_agents."),
            "peer_selected_agents": _arr("Other side's selected registered actor ids."),
            "project": PROJECT_PROP,
        }, "required": ["other_project"]},
    },
    {
        "name": "bridge_list",
        "description": "List connected projects, authority relationships, both "
                       "participation policies, and whether this AI may enter each room.",
        "inputSchema": {"type": "object", "properties": {"project": PROJECT_PROP}},
    },
    {
        "name": "bridge_remove",
        "description": "Remove an existing workspace relationship and disconnect "
                       "its inter-project room. Do not remove it merely to change "
                       "participation.",
        "inputSchema": {"type": "object", "properties": {
            "other_project": _s("Connected project id to remove."),
            "project": PROJECT_PROP,
        }, "required": ["other_project"]},
    },
    {
        "name": "search",
        "description": "Token-aware history Ctrl+F across everything stored "
                       "for this project — ledger "
                       "events, room messages, tasks, rules, decisions and handoff "
                       "history. Punctuation is ignored and every term must match "
                       "the same record; room matches always include the full body. "
                       "This is the Ctrl+F equivalent: "
                       "use relevant terms before filesystem/Git archaeology when "
                       "work depends on what, why, or who happened earlier.",
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
                       "workers get overlap warnings. Set plan_required for large work "
                       "that needs a detailed reviewable plan before implementation.",
        "inputSchema": {"type": "object", "properties": {
            "title": _s("Short task title."),
            "description": _s("Details, acceptance criteria."),
            "expected_scope": _arr("Paths/globs likely to change, e.g. ['src/auth/**']."),
            "dependencies": _arr("Task ids that must complete first, e.g. ['T-1']."),
            "risk_level": _s("low | medium | high (default medium)."),
            "plan_required": {
                "type": "boolean",
                "description": "Whether this task needs a detailed plan."},
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
        "name": "task_show",
        "description": "Show one task with its complete immutable action history, "
                       "including separate AI actor and human-user attribution. Use "
                       "this after search when investigating a known task.",
        "inputSchema": {"type": "object", "properties": {
            "task_id": _s("Task id, e.g. T-3."),
            "project": PROJECT_PROP,
        }, "required": ["task_id"]},
    },
    {
        "name": "task_plan_get",
        "description": "Open a task's complete detailed plan, its immutable revision "
                       "list, review actions, approvals, comments, and edit suggestions. "
                       "Omit version for the latest plan.",
        "inputSchema": {"type": "object", "properties": {
            "task_id": _s("Task id, e.g. T-3."),
            "version": _i("Optional historical plan version."),
            "project": PROJECT_PROP,
        }, "required": ["task_id"]},
    },
    {
        "name": "task_plan_set",
        "description": "Create or revise a long structured task plan. Every revision "
                       "is immutable; pass expected_version when revising so concurrent "
                       "edits cannot silently overwrite one another.",
        "inputSchema": {"type": "object", "properties": {
            "task_id": _s("Task id, e.g. T-3."),
            "title": _s("Plan title."),
            "overview": _s("Long-form plan overview."),
            "sections": {"type": "array", "description":
                "Ordered plan sections with stable section_id, title, and body.",
                "items": {"type": "object", "properties": {
                    "section_id": _s("Stable section identifier."),
                    "title": _s("Section heading."),
                    "body": _s("Detailed section content."),
                }, "required": ["section_id", "title", "body"]}},
            "expected_version": _i(
                "Current latest version when revising; omit only for version 1."),
            "submit_for_review": {"type": "boolean", "description":
                "Create this revision directly in review instead of draft."},
            "project": PROJECT_PROP,
        }, "required": ["task_id", "title", "sections"]},
    },
    {
        "name": "task_plan_submit",
        "description": "Submit the current draft task plan for approval or edit "
                       "suggestions using optimistic version checking.",
        "inputSchema": {"type": "object", "properties": {
            "task_id": _s("Task id, e.g. T-3."),
            "expected_version": _i("Current plan version."),
            "project": PROJECT_PROP,
        }, "required": ["task_id", "expected_version"]},
    },
    {
        "name": "task_plan_review",
        "description": "Approve a whole plan or one section, suggest a concrete edit, "
                       "or add a comment. Humans and Directors may approve; any "
                       "registered AI or human may leave attributed feedback.",
        "inputSchema": {"type": "object", "properties": {
            "task_id": _s("Task id, e.g. T-3."),
            "expected_version": _i("Current plan version."),
            "action": _s("approve | suggest_edit | comment."),
            "section_id": _s("Optional stable section id; omit to address the plan."),
            "note": _s("Required for suggest_edit and comment."),
            "project": PROJECT_PROP,
        }, "required": ["task_id", "expected_version", "action"]},
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
        "name": "rule_list",
        "description": "Read mandatory Project Rules. By default an AI receives enabled "
                       "rules for everyone plus its ACTUAL registered role; callers cannot "
                       "select a different role. Humans and Directors may request the full "
                       "management list.",
        "inputSchema": {"type": "object", "properties": {
            "include_disabled": _b(
                "Include disabled rules (human/Director management only)."),
            "include_all": _b(
                "Include all role scopes (human/Director management only)."),
            "project": PROJECT_PROP,
        }},
    },
    {
        "name": "rule_create",
        "description": "Create a durable role-scoped Project Rule. Only humans and "
                       "registered Directors may manage rules. The change bumps project "
                       "context so active clients receive it automatically.",
        "inputSchema": {"type": "object", "properties": {
            "title": _s("Short rule title."),
            "body": _s("Binding instruction the applicable AI must follow."),
            "scope": _s("everyone | director | advisor | worker (default everyone)."),
            "priority": _i("Ordering priority, 0 first through 1000 (default 100)."),
            "project": PROJECT_PROP,
        }, "required": ["title", "body"]},
    },
    {
        "name": "rule_update",
        "description": "Edit, enable, or disable a Project Rule with optimistic version "
                       "checking. Only humans and registered Directors may manage rules.",
        "inputSchema": {"type": "object", "properties": {
            "rule_id": _s("Rule id, e.g. R-2."),
            "expected_version": _i("Current rule version; stale updates are rejected."),
            "title": _s("Replacement title."),
            "body": _s("Replacement binding instruction."),
            "scope": _s("everyone | director | advisor | worker."),
            "priority": _i("Ordering priority, 0 first through 1000."),
            "enabled": _b("Whether this rule is active."),
            "project": PROJECT_PROP,
        }, "required": ["rule_id", "expected_version"]},
    },
    {
        "name": "cloud_context_get",
        "description": "Read the project cloud context: a shared free-text document "
                       "(like a hosted AGENTS.md/CLAUDE.md) injected into every session "
                       "brief. Any worker may read it.",
        "inputSchema": {"type": "object", "properties": {
            "project": PROJECT_PROP,
        }},
    },
    {
        "name": "cloud_context_set",
        "description": "Replace the project cloud context document. Only humans and "
                       "registered Directors may edit it. The change bumps project "
                       "context so active clients re-read it automatically.",
        "inputSchema": {"type": "object", "properties": {
            "content": _s("Full replacement text of the cloud context document."),
            "expected_version": _i("Current cloud context version; stale writes are "
                                   "rejected. Omit to overwrite unconditionally."),
            "project": PROJECT_PROP,
        }, "required": ["content"]},
    },
    {
        "name": "migration_directive",
        "description": "Fetch the Attacca project-migration directive: the server-side "
                       "steps to migrate an existing project’s history/logs into Attacca "
                       "(archive logs; populate Cloud Context and Rules; record decisions "
                       "and tasks) so Attacca becomes the source of truth. Read this when "
                       "setup offers migration. Includes any detected source docs.",
        "inputSchema": {"type": "object", "properties": {"project": PROJECT_PROP}},
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
        "description": "List all projects registered in this attacca database (for "
                       "cross-project coordination/messaging). Also returns your effective "
                       "MCP actor identity so guided setup assigns the role to this AI, "
                       "not to the shell user running its helper command.",
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

MCP_INSTRUCTIONS = """This server is the project's shared attacca layer (event ledger, task
board, mandatory role-scoped rules, decision records, handoff, and a human+AI project room) shared by ALL
workers across tools (Claude Code, Codex, GLM, humans).

Session protocol:
1. START: call get_handoff and rule_list, then check_inbox. Project rooms are
   group conversations: read every participation-visible unread message, including
   messages mentioning/replying to another participant. Mentions/replies assign
   attention, not visibility; an untargeted chat/directive is sent to everyone.
   Do not rely on prior chat memory or re-discover the repo from scratch.
2. PROJECT RULES: everyone + your ACTUAL registered role are mandatory. Only
   humans and registered Directors may manage them.
3. HISTORY-FIRST: when work depends on what/why/who happened earlier, call
   search with relevant terms (the project-memory Ctrl+F), then get_project_log
   and task_show around the hits before filesystem/Git archaeology.
4. Claim a task (task_claim) before substantive work; create one if needed.
5. Announce intent / coordinate via room_send; poll check_inbox / room_read
   and consider all relevant group context even when no action is assigned.
   The lifecycle watcher performs routine checks; never make the human prompt
   you to check messages. Reading does not dispose addressed work: call
   message_dispose before yielding (and link claimed/completed work to a task).
   Messages tagged [MASTER-DIRECTIVE] come from a project whose
   directors rule this one — treat them as binding; [SUGGESTION]/[ADVICE]
   are input, not orders.
6. Record durable choices with decision_propose / decision_resolve.
7. FINISH: task_report with evidence, then update_handoff so the next worker
   (possibly a different tool/model) resumes cold without a rebrief.
If any response contains a stale_context warning, re-run get_handoff before
writing."""


class McpSession:
    """One MCP stdio session: newline-delimited JSON-RPC over stdin/stdout."""

    def __init__(self, db_path, default_project=None, actor=None,
                 actor_type=None, stdin=None, stdout=None, detect_cwd=True,
                 owner=None, require_project=False,
                 setup_required_reason=None, git_branch_name=None,
                 git_revision=None, device_id=None, auth_user_id=None,
                 authorized_project=None, preserve_actor_identity=False,
                 auth_token_id=None, auth_token_kind=None,
                 release_version=None):
        self.db_path = db_path
        self.conn = None
        self.default_project = default_project
        self.actor = actor
        self.actor_type = actor_type or "agent"
        self.client_name = None
        self.detect_cwd = detect_cwd  # False for HTTP: server cwd is meaningless
        self.require_project = require_project
        self.setup_required_reason = setup_required_reason
        # detect_cwd doubles as "local session": stdio sessions read the
        # machine identity themselves; HTTP sessions get owner from a header.
        self.owner = owner if owner is not None else \
            (load_owner() if detect_cwd else None)
        self.git_branch_name = git_branch_name
        self.git_revision = git_revision
        self.device_id = device_id
        self.auth_user_id = auth_user_id
        self.auth_token_id = auth_token_id
        self.auth_token_kind = auth_token_kind
        self.release_version = str(release_version or VERSION)
        self.authorized_project = authorized_project
        self.preserve_actor_identity = bool(preserve_actor_identity)
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
            sys.stderr.write("attacca mcp: internal error: %r\n" % err)
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
                "serverInfo": {"name": "attacca",
                               "version": self.release_version},
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
            except AttaccaError as err:
                return self._res(msg_id, {
                    "content": [{"type": "text", "text": "error: %s" % err}],
                    "isError": True})
            except Exception as err:
                sys.stderr.write("attacca mcp: tool %s failed: %r\n" % (name, err))
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

    def _authenticated_principal_context(self):
        """Rehydrate only non-secret authorization metadata for this session."""
        if not self.auth_user_id:
            return None
        user = self._conn().execute(
            "SELECT user_id,username,is_admin FROM auth_users"
            " WHERE user_id=? AND disabled_at IS NULL",
            (self.auth_user_id,)).fetchone()
        if not user:
            raise AuthorizationError(
                "MCP authenticated user is no longer active")
        return {
            "user_id": user["user_id"],
            "username": user["username"],
            "is_admin": bool(user["is_admin"]),
            "token_id": self.auth_token_id,
            "token_kind": self.auth_token_kind,
            "actor_type": self.actor_type,
            "project_id": self.authorized_project,
        }

    def _authorize_bridge_peer(self, project, actor, other_project):
        return authorize_authenticated_bridge_peer(
            self._conn(), self._authenticated_principal_context(), project,
            actor, self.actor_type, other_project)

    def _actor(self, project=None):
        base = self.actor or (slugify(self.client_name)
                              if self.client_name else "unknown-agent")
        base = qualify_actor(base, owner=self.owner)
        if self.actor_type != "agent" or not project:
            return base
        if self.preserve_actor_identity and self._conn().execute(
                "SELECT 1 FROM agents WHERE project_id=? AND agent_id=?",
                (project, base)).fetchone():
            return base
        aliases = [base]
        if self.owner:
            aliases.insert(0, "%s.%s" % (slugify(self.owner), base))
        for candidate in aliases:
            row = self._conn().execute(
                "SELECT canonical_actor_id FROM actor_aliases"
                " WHERE project_id=? AND legacy_actor_id=?",
                (project, candidate)).fetchone()
            if row:
                return row["canonical_actor_id"]
        records = [dict(row) for row in self._conn().execute(
            "SELECT * FROM agents WHERE project_id=?", (project,))]
        return registered_agent_identity(
            records, project, base,
            runtime=normalize_agent_runtime(self.client_name, base))["actor_id"]

    def _auto_register(self, conn, project, actor):
        """First contact of this session with a project: record the agent's
        identity (runtime = the connecting client) so 'who did what, with
        which engine, owned by whom' is always answerable."""
        if (project, actor) in self._registered:
            return
        self._registered.add((project, actor))
        if self.preserve_actor_identity and conn.execute(
                "SELECT 1 FROM agents WHERE project_id=? AND agent_id=?",
                (project, actor)).fetchone():
            # Authentication is not an actor migration operation. In
            # particular, never let canonical auto-registration delete an
            # exact legacy/bespoke row selected by a terminal binding.
            return
        try:
            agent_register(conn, project, actor, self.actor_type,
                           runtime=normalize_agent_runtime(
                               self.client_name, actor),
                           canonical_identity=self.actor_type == "agent")
        except AttaccaError:
            pass

    def _project(self, args):
        if self.authorized_project and args.get("project") \
                and args.get("project") != self.authorized_project:
            raise AuthorizationError(
                "this API token is bound to workspace '%s'"
                % self.authorized_project)
        if self.require_project and not args.get("project") \
                and not self.default_project:
            reason = (self.setup_required_reason or
                      "this checkout is not attached to an Attacca workspace")
            raise AttaccaError(
                "Attacca setup required: %s; use "
                "plugin setup (Codex: `$attacca:setup`; Claude/Kimi: "
                "`/attacca:setup`)" % reason)
        project = resolve_project_id(self._conn(), explicit=args.get("project"),
                                     default=self.default_project,
                                     use_cwd=self.detect_cwd)
        # Register from the raw runtime hint so migration records aliases for
        # both it and the old owner-prefixed form; operations then use the
        # canonical workspace.role.runtime identity.
        self._auto_register(self._conn(), project, self._actor())
        return project

    def _project_actor(self, args):
        """Resolve workspace first, then derive its role-scoped actor."""
        project = self._project(args)
        return project, self._actor(project)

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
        if self.detect_cwd:
            set_current_git_context(git_branch(os.getcwd()), git_head(os.getcwd()),
                                    load_device_id())
        else:
            set_current_git_context(self.git_branch_name, self.git_revision,
                                    self.device_id)

        if name == "list_projects":
            result = list_projects(conn)
            allowed_projects = auth_visible_project_ids(
                conn, self._authenticated_principal_context())
            if allowed_projects is not None:
                result["projects"] = [
                    item for item in result["projects"]
                    if item["project_id"] in allowed_projects]
            # Setup must assign governance to the AI that is actually running,
            # not to the shell account (for example `vscode`) that happens to
            # execute its command. This unscoped call is available before a
            # checkout is attached, so native setup flows can carry the exact
            # MCP identity into the one-shot CLI without displaying raw IDs.
            result["you"] = {
                "actor_id": actor,
                "actor_type": atype,
                "runtime": normalize_agent_runtime(
                    self.client_name, actor) if atype == "agent" else None,
                "owner": self.owner,
                "identity_pending": atype == "agent",
                "hint": ("workspace and role are selected during setup; the "
                         "final actor is workspace.role.runtime"
                         if atype == "agent" else None),
            }
            return result

        if name == "attacca_status":
            project, actor = self._project_actor(args)
            return project_status(conn, project, actor, atype, self.db_path)

        if name == "get_handoff":
            project, actor = self._project_actor(args)
            result = get_handoff(conn, project, actor_id=actor,
                                 actor_type=atype)
            self.briefed_versions[project] = result["context_version"]
            return result

        if name == "check_inbox":
            project, actor = self._project_actor(args)
            mark = args.get("mark_read")
            return inbox_read(conn, project, actor,
                              mark_read=True if mark is None else bool(mark),
                              limit=args.get("limit") or 50,
                              actor_type=atype)

        if name == "message_dispose":
            project, actor = self._project_actor(args)
            return self._guarded_write(project, lambda: message_dispose(
                conn, project, actor, atype, args.get("event_id"),
                args.get("disposition"), note=args.get("note"),
                task_id=args.get("task_id")))

        if name == "set_lead_director":
            project, actor = self._project_actor(args)
            return self._guarded_write(project, lambda: set_lead_director(
                conn, project, actor, atype, args.get("agent_id")))

        if name == "bridge_add":
            project, actor = self._project_actor(args)
            self._authorize_bridge_peer(
                project, actor, args.get("other_project"))
            return self._guarded_write(project, lambda: bridge_add(
                conn, project, actor, atype, args.get("other_project"),
                boss=args.get("boss"), advisor=args.get("advisor"),
                participation=args.get("participation") or "all",
                peer_participation=args.get("peer_participation"),
                selected_agents=args.get("selected_agents"),
                peer_selected_agents=args.get("peer_selected_agents")))

        if name == "bridge_list":
            project, actor = self._project_actor(args)
            return bridge_list(conn, project, actor_id=actor,
                               actor_type=atype)

        if name == "bridge_update_access":
            project, actor = self._project_actor(args)
            self._authorize_bridge_peer(
                project, actor, args.get("other_project"))
            return self._guarded_write(project, lambda: bridge_update_access(
                conn, project, actor, atype, args.get("other_project"),
                participation=args.get("participation"),
                peer_participation=args.get("peer_participation"),
                selected_agents=args.get("selected_agents"),
                peer_selected_agents=args.get("peer_selected_agents")))

        if name == "bridge_remove":
            project, actor = self._project_actor(args)
            self._authorize_bridge_peer(
                project, actor, args.get("other_project"))
            return self._guarded_write(project, lambda: bridge_remove(
                conn, project, actor, atype, args.get("other_project")))

        if name == "search":
            project, actor = self._project_actor(args)
            return search_project(conn, project, args.get("query"),
                                  limit=args.get("limit") or 20,
                                  actor_id=actor, actor_type=atype)

        if name == "update_handoff":
            project, actor = self._project_actor(args)
            updates = {k: args.get(k) for k in HANDOFF_FIELDS}
            expected = args.get("expected_context_version")
            if expected is None:
                expected = self.briefed_versions.get(project)
            result = update_handoff(
                conn, project, actor, atype, updates,
                expected_context_version=expected)
            self.briefed_versions[project] = result["context_version"]
            return result

        if name == "get_project_log":
            project, actor = self._project_actor(args)
            return project_log(conn, project, limit=args.get("limit") or 40,
                               actor_id=actor, actor_type=atype)

        if name == "room_send":
            requested = self._project(args)
            source = requested
            explicit_target = args.get("target_project")
            if args.get("project") and not explicit_target:
                try:
                    default_source = resolve_project_id(
                        conn, default=self.default_project,
                        use_cwd=self.detect_cwd)
                except AttaccaError:
                    default_source = None
                if default_source and default_source != requested:
                    source = default_source
                    explicit_target = requested
            source, actor = self._project_actor({"project": source})
            return room_send(conn, source, actor, atype,
                             body=args.get("body"),
                             msg_type=args.get("msg_type") or "chat",
                             mentions=args.get("mentions"),
                             task_id=args.get("task_id"),
                             reply_to=args.get("reply_to"),
                             target_project=explicit_target)

        if name == "room_read":
            project, actor = self._project_actor(args)
            return room_read(conn, project, since_seq=args.get("since_seq"),
                             limit=args.get("limit") or 30, actor_id=actor,
                             actor_type=atype)

        if name == "task_create":
            project, actor = self._project_actor(args)
            return task_create(conn, project, actor, atype,
                               title=args.get("title"),
                               description=args.get("description"),
                               expected_scope=args.get("expected_scope"),
                               dependencies=args.get("dependencies"),
                               risk_level=args.get("risk_level") or "medium",
                               plan_required=args.get("plan_required", False))

        if name == "task_list":
            project, actor = self._project_actor(args)
            return task_list(conn, project, status=args.get("status"))

        if name == "task_show":
            project, actor = self._project_actor(args)
            return task_show(conn, project, task_id=args.get("task_id"))

        if name == "task_plan_get":
            project, actor = self._project_actor(args)
            return task_plan_get(conn, project, task_id=args.get("task_id"),
                                 version=args.get("version"))

        if name == "task_plan_set":
            project, actor = self._project_actor(args)
            return self._guarded_write(project, lambda: task_plan_set(
                conn, project, args.get("task_id"), actor, atype,
                title=args.get("title"), overview=args.get("overview"),
                sections=args.get("sections"),
                expected_version=args.get("expected_version"),
                submit_for_review=args.get("submit_for_review", False)))

        if name == "task_plan_submit":
            project, actor = self._project_actor(args)
            return self._guarded_write(project, lambda: task_plan_submit(
                conn, project, args.get("task_id"), actor, atype,
                expected_version=args.get("expected_version")))

        if name == "task_plan_review":
            project, actor = self._project_actor(args)
            return self._guarded_write(project, lambda: task_plan_review(
                conn, project, args.get("task_id"), actor, atype,
                expected_version=args.get("expected_version"),
                action=args.get("action"), section_id=args.get("section_id"),
                note=args.get("note")))

        if name == "task_claim":
            project, actor = self._project_actor(args)
            return self._guarded_write(project, lambda: task_claim(
                conn, project, actor, atype,
                task_id=args.get("task_id"),
                expected_scope=args.get("expected_scope"),
                lease_minutes=args.get("lease_minutes")))

        if name == "task_report":
            project, actor = self._project_actor(args)
            return self._guarded_write(project, lambda: task_report(
                conn, project, actor, atype,
                task_id=args.get("task_id"),
                summary=args.get("summary"),
                evidence=args.get("evidence"),
                requested_state=args.get("requested_state") or "review"))

        if name == "task_release":
            project, actor = self._project_actor(args)
            return task_release(conn, project, actor, atype,
                                task_id=args.get("task_id"),
                                reason=args.get("reason"))

        if name == "task_set_status":
            project, actor = self._project_actor(args)
            return self._guarded_write(project, lambda: task_set_status(
                conn, project, actor, atype,
                task_id=args.get("task_id"),
                status=args.get("status"),
                reason=args.get("reason")))

        if name == "decision_propose":
            project, actor = self._project_actor(args)
            return decision_propose(conn, project, actor, atype,
                                    title=args.get("title"),
                                    detail=args.get("detail"),
                                    rationale=args.get("rationale"))

        if name == "decision_resolve":
            project, actor = self._project_actor(args)
            return self._guarded_write(project, lambda: decision_resolve(
                conn, project, actor, atype,
                decision_id=args.get("decision_id"),
                resolution=args.get("resolution"),
                rationale=args.get("rationale")))

        if name == "decision_list":
            project, actor = self._project_actor(args)
            return decision_list(conn, project, status=args.get("status"))

        if name == "rule_list":
            project, actor = self._project_actor(args)
            return rule_list(
                conn, project, actor_id=actor, actor_type=atype,
                include_disabled=bool(args.get("include_disabled")),
                include_all=bool(args.get("include_all")))

        if name == "rule_create":
            project, actor = self._project_actor(args)
            return self._guarded_write(project, lambda: rule_create(
                conn, project, actor, atype, title=args.get("title"),
                body=args.get("body"), scope=args.get("scope") or "everyone",
                priority=args.get("priority") if args.get("priority") is not None
                else 100))

        if name == "rule_update":
            project, actor = self._project_actor(args)
            updates = {key: args[key] for key in
                       ("title", "body", "scope", "priority", "enabled")
                       if key in args}
            return self._guarded_write(project, lambda: rule_update(
                conn, project, actor, atype, rule_id=args.get("rule_id"),
                updates=updates,
                expected_version=args.get("expected_version")))

        if name == "cloud_context_get":
            project, actor = self._project_actor(args)
            return cloud_context_get(conn, project, actor_id=actor,
                                     actor_type=atype)

        if name == "cloud_context_set":
            project, actor = self._project_actor(args)
            return self._guarded_write(project, lambda: cloud_context_set(
                conn, project, actor, atype, content=args.get("content"),
                expected_version=args.get("expected_version")))

        if name == "migration_directive":
            root = None
            try:
                project = self._project(args)
                root = get_project(conn, project).get("root_path")
            except Exception:
                root = os.getcwd() if self.detect_cwd else None
            return migration_directive(root)

        if name == "agent_register":
            project, actor = self._project_actor(args)
            return agent_register(conn, project, actor, atype,
                                  agent_id=args.get("agent_id"),
                                  display_name=args.get("display_name"),
                                  role=args.get("role"),
                                  runtime=args.get("runtime"),
                                  canonical_identity=atype == "agent")

        if name == "agent_list":
            project, actor = self._project_actor(args)
            return agent_list(conn, project)

        if name == "append_event":
            project, actor = self._project_actor(args)
            event_type = args.get("event_type")
            if not event_type:
                raise AttaccaError("append_event: event_type is required")
            if str(event_type) == "room.message":
                raise AttaccaError(
                    "room.message may only be written through room_send so "
                    "bridge targeting and participation are enforced")
            payload = args.get("payload")
            if payload is not None and not isinstance(payload, dict):
                raise AttaccaError("append_event: payload must be a JSON object")
            return {"ok": True,
                    "event": append_event(conn, project, actor, atype,
                                          str(event_type), payload or {},
                                          task_id=args.get("task_id"))}

        if name == "check_freshness":
            project, actor = self._project_actor(args)
            version = args.get("context_version")
            if version is None:
                version = self.briefed_versions.get(project)
            result = check_freshness(
                conn, project, version, actor_id=actor, actor_type=atype)
            if not result.get("stale"):
                self.briefed_versions[project] = result["current_context_version"]
            return result

        raise AttaccaError("unknown tool: %s" % name)


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
                            name=body.get("name"), move=bool(body.get("move")),
                            repository_fingerprint=body.get(
                                "repository_fingerprint"))
    repository_fingerprint = _validated_repository_fingerprint(
        body.get("repository_fingerprint"))
    explicit_project_id = bool(body.get("project_id"))
    matched = _project_for_repository(conn, repository_fingerprint)
    # Git matching is discovery for a create request. An explicit project id
    # is an attach/verify request and must never be silently substituted with
    # whichever project currently owns the fingerprint.
    if matched and not explicit_project_id:
        project = get_project(conn, matched)
        return {"project_id": matched, "name": project["name"],
                "root_path": project["root_path"], "already_existed": True,
                "matched_by": "git"}
    raw_id = body.get("project_id") or body.get("name")
    if not raw_id:
        raise AttaccaError("provide project_id or name (root_path optional)")
    requested_id = slugify(str(raw_id))
    project_id = requested_id
    name = body.get("name") or project_id
    with write_tx(conn):
        existing = conn.execute(
            "SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
        if existing:
            # An explicit id means "attach/verify this project". Supplying
            # only a name means "create", so avoid accidentally joining an
            # unrelated same-named project by finding a free suffix.
            if not explicit_project_id:
                if existing["name"] != name:
                    raise AttaccaError(
                        "workspace id '%s' already belongs to '%s'; choose a "
                        "different name" % (project_id, existing["name"]))
                if existing["repository_fingerprint"] \
                        != repository_fingerprint:
                    raise AttaccaError(
                        "workspace '%s' already exists with a different or "
                        "unconfirmed Git identity; choose it explicitly with "
                        "--attach" % project_id)
                return {"project_id": project_id, "name": existing["name"],
                        "root_path": existing["root_path"],
                        "already_existed": True, "matched_by": "name"}
            else:
                if repository_fingerprint:
                    other = conn.execute(
                        "SELECT project_id FROM projects"
                        " WHERE repository_fingerprint=? AND project_id<>?",
                        (repository_fingerprint, project_id)).fetchone()
                    if other:
                        raise AttaccaError(
                            "this Git repository already belongs to project '%s',"
                            " not '%s'" % (other["project_id"], project_id))
                    current = existing["repository_fingerprint"]
                    if current and current != repository_fingerprint:
                        raise AttaccaError(
                            "project '%s' belongs to a different Git repository"
                            % project_id)
                    if not current:
                        conn.execute(
                            "UPDATE projects SET repository_fingerprint=?"
                            " WHERE project_id=?",
                            (repository_fingerprint, project_id))
                        append_event(
                            conn, project_id, actor_id, actor_type,
                            "project.repository_linked",
                            {"repository_fingerprint": repository_fingerprint},
                            in_tx=True)
                return {"project_id": project_id, "name": existing["name"],
                        "root_path": existing["root_path"],
                        "already_existed": True, "matched_by": "project_id"}
        if existing:
            return {"project_id": project_id, "name": existing["name"],
                    "root_path": existing["root_path"], "already_existed": True}
        conn.execute(
            "INSERT INTO projects (project_id, name, root_path,"
            " repository_fingerprint, created_by, created_at)"
            " VALUES (?,?,NULL,?,?,?)",
            (project_id, name, repository_fingerprint, actor_id, now_iso()))
        append_event(conn, project_id, actor_id, actor_type, "project.created",
                     {"name": name, "root_path": None,
                      "repository_fingerprint": repository_fingerprint},
                     in_tx=True)
        _grant_new_project_creator_membership_in_tx(
            conn, project_id, actor_id, actor_type)
    return {"project_id": project_id, "name": name, "root_path": None,
            "already_existed": False}


def _api_events_sync(conn, project_id, after, limit, actor_id=None,
                     actor_type="agent"):
    """GET /v1/projects/{id}/events?after=N — the raw sync feed."""
    get_project(conn, project_id)
    limit = max(1, min(int(limit), 1000))
    latest = conn.execute(
        "SELECT COALESCE(MAX(seq), 0) AS seq FROM events WHERE project_id=?",
        (project_id,)).fetchone()["seq"]
    rows = conn.execute(
        "SELECT * FROM events WHERE project_id=? AND seq>? ORDER BY seq LIMIT ?",
        (project_id, int(after), limit)).fetchall()
    events = []
    raw_payloads = [json.loads(row["payload"]) for row in rows]
    room_rows = [row for row in rows
                 if row["event_type"] == "room.message"]
    room_payloads = _room_policy_payloads(
        conn, project_id, room_rows,
        payloads=[payload for row, payload in zip(rows, raw_payloads)
                  if row["event_type"] == "room.message"])
    room_payload_iter = iter(room_payloads)
    for row, raw_payload in zip(rows, raw_payloads):
        # The sync cursor follows the immutable raw sequence, while the
        # payload is actor-private.  Advancing past a hidden row prevents a
        # denied bridge message from permanently wedging an offline watcher.
        payload = raw_payload
        if row["event_type"] == "room.message":
            payload = next(room_payload_iter)
            if actor_id is not None and not _bridge_message_visible(
                    conn, project_id, payload, actor_id, actor_type):
                continue
        event = dict(row)
        event["payload"] = payload
        if event["event_type"] == "room.message":
            event["payload"].update(_inbox_message_attention(
                conn, _actor_alias_ids(conn, project_id, actor_id),
                event["payload"]))
            if event["payload"].get("mirrored_to") and actor_id is not None:
                event["payload"]["mirrored_to"] = _visible_bridge_peers(
                    conn, project_id, event["payload"], actor_id, actor_type)
        identity_project = event["payload"].get("origin_project") \
            if event["event_type"] == "room.message" else None
        attribution = immutable_event_attribution(
            conn, identity_project or project_id, event["actor_id"],
            event["actor_type"], event.get("owner"))
        event["identity"] = attribution["identity"]
        event["attribution"] = attribution
        event["operational_actor_id"] = attribution["actor_id"]
        events.append(event)
    next_after = rows[-1]["seq"] if rows else int(after)
    return {"project": project_id, "events": events, "next_after": next_after,
            "latest_seq": latest, "may_have_more": next_after < latest}


# Complete project backups are intentionally separate from the lightweight
# offline agent mirror.  These helpers build one consistent export snapshot,
# then serialize exactly one requested human/admin download artifact.
PROJECT_EXPORT_FORMATS = {
    "zip": {
        "serializer": "project_export_zip_bytes",
        "content_type": "application/zip",
        "suffix": "export.zip",
    },
    "json": {
        "serializer": "project_export_json_bytes",
        "content_type": "application/json; charset=utf-8",
        "suffix": "export.json",
    },
    "ledger.ndjson": {
        "serializer": "project_export_ledger_ndjson_bytes",
        "content_type": "application/x-ndjson; charset=utf-8",
        "suffix": "ledger.ndjson",
    },
    "full-log.txt": {
        "serializer": "project_export_full_log_bytes",
        "content_type": "text/plain; charset=utf-8",
        "suffix": "full-log.txt",
    },
}
_PROJECT_EXPORT_MODULE = None
_PROJECT_EXPORT_MODULE_LOCK = threading.Lock()
_SYNC_RUNTIME = None
_SYNC_RUNTIME_LOCK = threading.Lock()
_OFFLINE_SYNC_RUNTIME = None
_OFFLINE_SYNC_RUNTIME_LOCK = threading.Lock()
_TERMINAL_FLOW_RUNTIME = None
_TERMINAL_FLOW_RUNTIME_LOCK = threading.Lock()


def _project_export_module():
    """Load the bundled sibling module in package and standalone modes."""
    global _PROJECT_EXPORT_MODULE
    if _PROJECT_EXPORT_MODULE is not None:
        return _PROJECT_EXPORT_MODULE
    with _PROJECT_EXPORT_MODULE_LOCK:
        if _PROJECT_EXPORT_MODULE is not None:
            return _PROJECT_EXPORT_MODULE
        path = Path(script_path()).resolve().parent / "project_export.py"
        if not path.is_file():
            raise AttaccaError(
                "project export support is missing from this Attacca install")
        spec = importlib.util.spec_from_file_location(
            "attacca_project_export_runtime", path)
        if spec is None or spec.loader is None:
            raise AttaccaError("cannot load Attacca project export support")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _PROJECT_EXPORT_MODULE = module
    return _PROJECT_EXPORT_MODULE


def _sync_runtime():
    """Load the bundled schema-v1 protocol/server in standalone installs.

    ``attacca.py`` is both an importable development module and a copied
    executable beside these files.  Loading by absolute sibling path keeps
    both layouts identical without adding the install directory to sys.path.
    """
    global _SYNC_RUNTIME
    if _SYNC_RUNTIME is not None:
        return _SYNC_RUNTIME
    with _SYNC_RUNTIME_LOCK:
        if _SYNC_RUNTIME is not None:
            return _SYNC_RUNTIME
        root = Path(script_path()).resolve().parent
        protocol_path = root / "sync_protocol.py"
        server_path = root / "sync_server.py"
        if not protocol_path.is_file() or not server_path.is_file():
            raise AttaccaError(
                "offline sync support is missing from this Attacca install")
        protocol_spec = importlib.util.spec_from_file_location(
            "attacca_sync_protocol_runtime", protocol_path)
        server_spec = importlib.util.spec_from_file_location(
            "attacca_sync_server_runtime", server_path)
        if protocol_spec is None or protocol_spec.loader is None \
                or server_spec is None or server_spec.loader is None:
            raise AttaccaError("cannot load Attacca offline sync support")
        protocol = importlib.util.module_from_spec(protocol_spec)
        protocol_spec.loader.exec_module(protocol)
        server = importlib.util.module_from_spec(server_spec)
        # sync_server's direct-file fallback imports ``sync_protocol`` and
        # dataclasses expects its defining module to be registered while the
        # class body executes.  Keep only our uniquely named server module;
        # restore any unrelated top-level protocol module afterward.
        prior_protocol = sys.modules.get("sync_protocol")
        sys.modules[server_spec.name] = server
        sys.modules["sync_protocol"] = protocol
        try:
            server_spec.loader.exec_module(server)
        finally:
            if prior_protocol is None:
                sys.modules.pop("sync_protocol", None)
            else:
                sys.modules["sync_protocol"] = prior_protocol
        _SYNC_RUNTIME = (protocol, server)
    return _SYNC_RUNTIME


def _offline_sync_runtime():
    """Load the verified-mirror client beside the standalone executable.

    The loader deliberately shares the already-loaded schema-v1 protocol
    module with :func:`_sync_runtime`; otherwise direct-file installs could
    validate the same envelope through two subtly different module instances.
    """
    global _OFFLINE_SYNC_RUNTIME
    if _OFFLINE_SYNC_RUNTIME is not None:
        return _OFFLINE_SYNC_RUNTIME
    with _OFFLINE_SYNC_RUNTIME_LOCK:
        if _OFFLINE_SYNC_RUNTIME is not None:
            return _OFFLINE_SYNC_RUNTIME
        protocol, _ = _sync_runtime()
        path = Path(script_path()).resolve().parent / "offline_sync.py"
        if not path.is_file():
            raise AttaccaError(
                "verified offline mirror support is missing from this "
                "Attacca install")
        spec = importlib.util.spec_from_file_location(
            "attacca_offline_sync_runtime", path)
        if spec is None or spec.loader is None:
            raise AttaccaError("cannot load Attacca verified offline mirror")
        module = importlib.util.module_from_spec(spec)
        prior_protocol = sys.modules.get("sync_protocol")
        sys.modules[spec.name] = module
        sys.modules["sync_protocol"] = protocol
        try:
            spec.loader.exec_module(module)
        finally:
            if prior_protocol is None:
                sys.modules.pop("sync_protocol", None)
            else:
                sys.modules["sync_protocol"] = prior_protocol
        _OFFLINE_SYNC_RUNTIME = (protocol, module)
    return _OFFLINE_SYNC_RUNTIME


def _terminal_flow_runtime():
    """Load the bundled per-install client-key authorization helper."""
    global _TERMINAL_FLOW_RUNTIME
    if _TERMINAL_FLOW_RUNTIME is not None:
        return _TERMINAL_FLOW_RUNTIME
    with _TERMINAL_FLOW_RUNTIME_LOCK:
        if _TERMINAL_FLOW_RUNTIME is not None:
            return _TERMINAL_FLOW_RUNTIME
        path = Path(script_path()).resolve().parent / "terminal_flow.py"
        if not path.is_file():
            raise AttaccaError(
                "terminal authorization support is missing from this install")
        spec = importlib.util.spec_from_file_location(
            "attacca_terminal_flow_runtime", path)
        if spec is None or spec.loader is None:
            raise AttaccaError("cannot load terminal authorization support")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _TERMINAL_FLOW_RUNTIME = module
    return _TERMINAL_FLOW_RUNTIME


def build_project_export_artifact(conn, project_id, export_format="zip"):
    """Return deterministic bytes + response metadata for one full backup."""
    export_format = str(export_format or "zip").strip().lower()
    spec = PROJECT_EXPORT_FORMATS.get(export_format)
    if not spec:
        raise AttaccaError(
            "export format must be one of: %s" %
            ", ".join(PROJECT_EXPORT_FORMATS))
    exporter = _project_export_module()
    try:
        snapshot = exporter.build_project_export(
            conn, project_id, log_renderer=render_log_line)
        data = getattr(exporter, spec["serializer"])(snapshot)
    except exporter.ProjectExportError as err:
        raise AttaccaError("cannot export project: %s" % err)
    return {
        "format": export_format,
        "data": data,
        "content_type": spec["content_type"],
        "filename": "attacca-%s-%s" % (project_id, spec["suffix"]),
        "sha256": hashlib.sha256(data).hexdigest(),
        "snapshot": dict(snapshot["manifest"]["snapshot"]),
    }


SYNC_OPERATION_TO_TOOL = {
    "room.send": "room_send", "room_send": "room_send",
    "message.dispose": "message_dispose",
    "message_dispose": "message_dispose",
    "task.create": "task_create", "task_create": "task_create",
    "task.claim": "task_claim", "task_claim": "task_claim",
    "task.report": "task_report", "task_report": "task_report",
    "task.release": "task_release", "task_release": "task_release",
    "task.set_status": "task_set_status",
    "task_set_status": "task_set_status",
    "task.plan.set": "task_plan_set",
    "task_plan_set": "task_plan_set",
    "task.plan.submit": "task_plan_submit",
    "task_plan_submit": "task_plan_submit",
    "task.plan.review": "task_plan_review",
    "task_plan_review": "task_plan_review",
    "decision.propose": "decision_propose",
    "decision_propose": "decision_propose",
    "decision.resolve": "decision_resolve",
    "decision_resolve": "decision_resolve",
    "rule.create": "rule_create", "rule_create": "rule_create",
    "rule.update": "rule_update", "rule_update": "rule_update",
    "handoff.update": "update_handoff",
    "update_handoff": "update_handoff",
    "event.append": "append_event", "append_event": "append_event",
}
SYNC_DIRECTOR_TOOLS = {"rule_create", "rule_update", "update_handoff"}
SYNC_RESERVED_ARGUMENTS = {
    "actor", "actor_id", "actor_type", "authenticated_scope", "device_id",
    "human_user", "owner", "principal_id", "project", "project_id", "role",
    "run_by_user", "server_id", "workspace",
}
SYNC_SECRET_KEYS = {
    "api_token", "auth_sessions", "auth_tokens", "credentials", "csrf_hash",
    "password_hash", "password_salt", "session_hash", "token_hash",
}


def _sync_server_id(conn):
    """Return one durable, non-secret identity for this hosted database."""
    key = "sync.server_id"
    row = conn.execute(
        "SELECT value FROM server_settings WHERE setting_key=?", (key,)).fetchone()
    if row:
        return row["value"]
    candidate = "srv_" + secrets.token_hex(16)
    with write_tx(conn):
        row = conn.execute(
            "SELECT value FROM server_settings WHERE setting_key=?", (key,)).fetchone()
        if row:
            return row["value"]
        conn.execute(
            "INSERT INTO server_settings (setting_key,value,updated_at)"
            " VALUES (?,?,?)", (key, candidate, now_iso()))
    return candidate


def _sync_human_has_project_access(conn, project, principal):
    if principal.get("is_admin"):
        return True
    username = principal.get("username")
    owners = _project_export_owner_usernames(conn, project)
    owners.update(
        row["owner"] for row in conn.execute(
            "SELECT DISTINCT owner FROM agents WHERE project_id=?"
            " AND owner IS NOT NULL", (project["project_id"],))
        if row["owner"])
    return username in owners


def _authenticated_agent_actor(conn, project_id, principal,
                               allow_admin_owner_migration=False):
    """Resolve only the exact token actor or its explicit migration alias."""
    raw_actor = principal.get("actor_id")
    row = conn.execute(
        "SELECT * FROM agents WHERE project_id=? AND agent_id=?",
        (project_id, raw_actor)).fetchone()
    if row is None:
        alias = conn.execute(
            "SELECT canonical_actor_id FROM actor_aliases"
            " WHERE project_id=? AND legacy_actor_id=?",
            (project_id, raw_actor)).fetchone()
        if alias:
            row = conn.execute(
                "SELECT * FROM agents WHERE project_id=? AND agent_id=?",
                (project_id, alias["canonical_actor_id"])).fetchone()
    if row is None:
        raise AuthorizationError(
            "the API token's AI is no longer registered in workspace '%s'"
            % project_id)
    if row["owner"] and row["owner"] != principal.get("username") \
            and not (allow_admin_owner_migration and principal.get("is_admin")):
        raise AuthorizationError(
            "the API token's AI belongs to Attacca user '%s'" % row["owner"])
    role = str(row["role"] or "unassigned").lower()
    runtime = normalize_agent_runtime(
        row["runtime"] or principal.get("runtime"), row["agent_id"])
    return row["agent_id"], role, row


def _compatibility_sync_scope(handler, project_id):
    """Narrow anonymous migration sync to one registered actor and device."""
    if not handler._compatibility_active():
        raise AuthenticationError(
            "client_authorization_required: authentication principal missing")
    device_id = str(handler._request_device_id() or "").strip()
    claimed = str(handler.headers.get("X-Attacca-Actor") or "").strip()
    if not device_id or not claimed:
        raise AuthenticationError(
            "legacy_sync_identity_required: exact actor and device are required")
    conn = handler._conn()
    project_id = get_project(conn, project_id)["project_id"]
    row = conn.execute(
        "SELECT * FROM agents WHERE project_id=? AND agent_id=?",
        (project_id, claimed)).fetchone()
    if row is None and "." not in claimed:
        runtime = normalize_agent_runtime(actor=claimed)
        candidates = [candidate for candidate in conn.execute(
            "SELECT * FROM agents WHERE project_id=? AND role IS NOT NULL",
            (project_id,)).fetchall()
            if normalize_agent_runtime(
                candidate["runtime"], candidate["agent_id"]) == runtime]
        if len(candidates) == 1:
            row = candidates[0]
    if row is None:
        raise AuthorizationError(
            "legacy_sync_actor_not_registered: actor/device scope rejected")
    role = str(row["role"] or "unassigned").lower()
    runtime = normalize_agent_runtime(row["runtime"], row["agent_id"])
    operational_actor = row["agent_id"]
    auth_migration_target_upsert(
        conn, project_id, row["agent_id"], device_id,
        selected_by="compatibility-sync", required=True)
    owner = str(row["owner"] or "").strip() or None
    principal_id = owner or (
        "legacy-device-%s" % sha256_hex(device_id)[:16])
    handler.sync_principal = {
        "auth_kind": "compatibility",
        "token_kind": "legacy_device",
        "user_id": None,
        "username": owner,
        "actor_id": operational_actor,
        "actor_type": "agent",
        "project_id": project_id,
        "runtime": runtime,
        "role": role,
        "device_id": device_id,
    }
    return {
        "server_id": _sync_server_id(conn),
        "project_id": project_id,
        "principal_id": principal_id,
        "actor_id": operational_actor,
        "actor_type": "agent",
        "role": role,
    }


def _sync_authenticated_scope(handler, project_id):
    """Build schema-v1 identity exclusively from the verified principal."""
    principal = getattr(handler, "principal", None)
    if not principal:
        return _compatibility_sync_scope(handler, project_id)
    conn = handler._conn()
    project = get_project(conn, project_id)
    if principal.get("token_kind") == "client":
        if principal.get("project_id") != project_id:
            raise AuthorizationError(
                "client key selected workspace '%s'" %
                principal.get("project_id"))
        actor = principal.get("actor_id")
        role = principal.get("role")
        if not actor or not role:
            raise AuthorizationError(
                "client key requires one exact registered actor")
        actor_type = "agent"
    elif principal.get("token_kind") == "terminal":
        if principal.get("project_id") != project_id:
            raise AuthorizationError(
                "terminal credential selected workspace '%s'" %
                principal.get("project_id"))
        actor = principal.get("actor_id")
        role = principal.get("role") or (
            parse_canonical_agent_id(actor, project_id) or {}).get("role")
        if not actor or not role:
            raise AuthorizationError(
                "terminal credential lacks an allowed actor binding")
        actor_type = "agent"
    elif principal.get("token_kind") == "service":
        if principal.get("project_id") != project_id:
            raise AuthorizationError(
                "service credential selected workspace '%s'" %
                principal.get("project_id"))
        actor = principal.get("actor_id")
        bound_actor = principal.get("actor_type") == "agent"
        role = (principal.get("role") or "unassigned") \
            if bound_actor else "unassigned"
        # Schema-v1 intentionally has no privileged "service" actor/role.
        # Represent an unbound read-only integration as a tool with no role;
        # _sync_authorize then permits projection reads but rejects every
        # mutation.  Exact service bindings continue as their registered
        # actor/role and obey the ordinary role checks.
        actor_type = "agent" if bound_actor else "tool"
        if not actor:
            raise AuthorizationError(
                "service credential lacks a selected workspace scope")
    elif principal.get("auth_kind") == "token" \
            and principal.get("actor_type") == "agent":
        if principal.get("project_id") != project_id:
            raise AuthorizationError(
                "this API token is bound to workspace '%s'" %
                principal.get("project_id"))
        actor, role, _ = _authenticated_agent_actor(
            conn, project_id, principal,
            allow_admin_owner_migration=(
                handler._compatibility_active()))
        actor_type = "agent"
    else:
        if not _sync_human_has_project_access(conn, project, principal):
            raise AuthorizationError(
                "Attacca user '%s' is not an owner or administrator of "
                "workspace '%s'" % (principal.get("username"), project_id))
        role = "human"
        actor_type = "human"
        actor = "%s.human.%s" % (
            slugify(project_id), slugify(principal.get("username")) or "user")
    return {
        "server_id": _sync_server_id(conn),
        "project_id": project_id,
        # The canonical event ledger records the authenticated username in
        # ``owner`` / "Run by user".  Bind the sync principal to that same
        # immutable account name so convergence can verify human attribution
        # directly against the visible hash-bound event without leaking an
        # internal database id or conflating it with the AI actor.
        "principal_id": principal["username"],
        "actor_id": actor,
        "actor_type": actor_type,
        "role": role,
    }


def _sync_event_record(row):
    value = dict(row)
    payload_json = value.get("payload")
    value["payload_json"] = payload_json
    try:
        value["payload"] = json.loads(payload_json)
    except (TypeError, ValueError):
        value["payload"] = payload_json
    value["context_version"] = int(value.get("context_version") or 0)
    value["hash_version"] = int(value.get("hash_version") or 1)
    return value


def _sync_head_cursor(conn, project_id):
    protocol, _ = _sync_runtime()
    project = get_project(conn, project_id)
    row = conn.execute(
        "SELECT seq,hash FROM events WHERE project_id=? ORDER BY seq DESC LIMIT 1",
        (project_id,)).fetchone()
    return protocol.make_cursor(
        row["seq"] if row else 0,
        row["hash"] if row else protocol.GENESIS_HASH,
        int(project.get("context_version") or 0))


def _sync_read_events(conn, project_id, after_seq, through_seq, limit):
    sql = ("SELECT * FROM events WHERE project_id=? AND seq>? AND seq<=? "
           "ORDER BY seq")
    params = [project_id, int(after_seq), int(through_seq)]
    if limit is not None:
        sql += " LIMIT ?"
        params.append(int(limit))
    return [_sync_event_record(row) for row in conn.execute(sql, params)]


def _sync_scrub_secrets(value):
    if isinstance(value, dict):
        return {key: _sync_scrub_secrets(child)
                for key, child in value.items()
                if str(key).lower() not in SYNC_SECRET_KEYS}
    if isinstance(value, list):
        return [_sync_scrub_secrets(child) for child in value]
    return value


def _sync_event_visible(conn, scope, event, room_payload=None):
    protocol, _ = _sync_runtime()
    policy_event = dict(event)
    if room_payload is not None:
        policy_event["payload"] = canonical_json(room_payload)
        if not _bridge_message_visible(
                conn, scope["project_id"], room_payload,
                scope["actor_id"], scope["actor_type"]):
            return False
    elif isinstance(policy_event.get("payload"), dict):
        policy_event["payload"] = policy_event.get("payload_json") \
            or canonical_json(policy_event["payload"])
    if room_payload is None and not _event_visible_to_actor(
            conn, scope["project_id"], policy_event, scope["actor_id"],
            scope["actor_type"]):
        return False
    try:
        # A historic custom event containing an explicitly secret-shaped key
        # is anchored but never copied into an offline mirror.
        protocol.make_visible_record(event)
    except protocol.SyncProtocolError:
        return False
    return True


def _sync_visibility_policy(conn, scope):
    rules = conn.execute(
        "SELECT rule_id,scope,enabled,version FROM project_rules"
        " WHERE project_id=? ORDER BY rule_id", (scope["project_id"],)).fetchall()
    bridges = _bridge_rows(conn, scope["project_id"])
    return {
        "actor_id": scope["actor_id"],
        "actor_type": scope["actor_type"],
        "role": scope["role"],
        "rules": [dict(row) for row in rules if row["enabled"] and (
            scope["actor_type"] == "human" or
            row["scope"] in ("everyone", scope["role"]))],
        "bridges": bridges,
    }


def _sync_projection(conn, scope):
    exporter = _project_export_module()
    snapshot = exporter.build_project_export(
        conn, scope["project_id"], log_renderer=render_log_line)
    events = snapshot["ledger"]["events"]
    room_events = [event for event in events
                   if event.get("event_type") == "room.message"]
    enriched_room_payloads = _room_policy_payloads(
        conn, scope["project_id"], room_events,
        payloads=[event.get("payload") or {} for event in room_events])
    room_payload_by_id = {
        event.get("event_id"): payload
        for event, payload in zip(room_events, enriched_room_payloads)}
    visible_events = [
        event for event in events
        if _sync_event_visible(
            conn, scope, event,
            room_payload=room_payload_by_id.get(event.get("event_id"))
            if event.get("event_type") == "room.message" else None)]
    visible_seqs = {event["seq"] for event in visible_events}

    room_messages = []
    for event in events:
        if event.get("event_type") != "room.message" \
                or event.get("seq") not in visible_seqs:
            continue
        payload = room_payload_by_id[event.get("event_id")]
        message = _room_message_dict(event, payload)
        message["project_id"] = scope["project_id"]
        if message.get("mirrored_to"):
            message["mirrored_to"] = _visible_bridge_peers(
                conn, scope["project_id"], message,
                scope["actor_id"], scope["actor_type"])
        identity_project = message.get("origin_project") or scope["project_id"]
        attribution = immutable_event_attribution(
            conn, identity_project, message["actor"], message["actor_type"],
            message.get("owner"))
        message["ledger_actor"] = message["actor"]
        message["actor"] = attribution["actor_id"]
        message["identity"] = attribution["identity"]
        message["attribution"] = attribution
        room_messages.append(message)

    listed_bridges = bridge_list(
        conn, scope["project_id"], actor_id=scope["actor_id"],
        actor_type=scope["actor_type"])["bridges"]
    accessible_bridges = []
    for bridge in listed_bridges:
        if bridge.get("can_participate") is False:
            continue
        item = dict(bridge)
        item["project_id"] = scope["project_id"]
        accessible_bridges.append(item)

    cursor = conn.execute(
        "SELECT * FROM inbox_cursors WHERE project_id=? AND actor_id=?",
        (scope["project_id"], scope["actor_id"])).fetchone()
    dispositions = [dict(row) for row in conn.execute(
        "SELECT * FROM message_dispositions"
        " WHERE project_id=? AND actor_id=?"
        " ORDER BY updated_at, message_event_id",
        (scope["project_id"], scope["actor_id"])).fetchall()]
    rules = rule_list(
        conn, scope["project_id"], actor_id=scope["actor_id"],
        actor_type=scope["actor_type"])["rules"]
    projection = {
        "project": snapshot["project"],
        "handoffs": snapshot["handoffs"],
        "rules": rules,
        "cloud_context": cloud_context_get(
            conn, scope["project_id"])["cloud_context"],
        "tasks": snapshot["tasks"],
        "decisions": snapshot["decisions"],
        "room_messages": room_messages,
        "agents": snapshot["agents"],
        "bridges": accessible_bridges,
        "inbox_cursor": dict(cursor) if cursor else None,
        "task_plans": [plan for task in snapshot["tasks"]
                       for plan in task.get("plan_revisions", [])],
        "full_log": [
            (render_log_line(dict(event, payload=event.get("payload_json")))
             or "%s %s" % (event.get("created_at"), event.get("event_type")))
            for event in visible_events
        ],
        "actor_aliases": snapshot["actor_aliases"],
        "message_dispositions": dispositions,
    }
    return _sync_scrub_secrets(projection)


def _sync_visibility_projector(conn, scope, mode, from_cursor,
                               through_cursor, events):
    result = {"visibility_policy": _sync_visibility_policy(conn, scope)}
    if mode == "policy":
        return result
    result["projection"] = _sync_projection(conn, scope)
    room_events = [event for event in events
                   if event.get("event_type") == "room.message"]
    room_payloads = _room_policy_payloads(
        conn, scope["project_id"], room_events,
        payloads=[event.get("payload") or {} for event in room_events])
    room_payload_by_id = {
        event.get("event_id"): payload
        for event, payload in zip(room_events, room_payloads)}
    result["visible_event_seqs"] = [
        event["seq"] for event in events
        if _sync_event_visible(
            conn, scope, event,
            room_payload=room_payload_by_id.get(event.get("event_id"))
            if event.get("event_type") == "room.message" else None)]
    return result


def _sync_authorize(conn, scope, action, operation=None):
    if action in ("sync.read", "sync.push", "sync.receipt.read"):
        return True
    if action != "sync.mutate":
        return False
    tool = SYNC_OPERATION_TO_TOOL.get(str(operation or ""))
    if not tool:
        return False
    if tool in SYNC_DIRECTOR_TOOLS and scope["actor_type"] == "agent" \
            and scope["role"] != "director":
        return False
    return scope["actor_type"] in ("agent", "human")


def _sync_check_precondition(conn, request):
    cursor = request.base_cursor
    head = _sync_head_cursor(
        conn, request.authenticated_scope["project_id"])
    if cursor["event_seq"] > head["event_seq"] \
            or cursor["context_version"] > head["context_version"]:
        return {
            "code": "base_cursor_ahead",
            "reason": "the mutation base cursor is ahead of this ledger",
            "current": {"server_cursor": head},
            "retryable": False,
        }
    if cursor["event_seq"] == 0:
        return None
    row = conn.execute(
        "SELECT hash FROM events WHERE project_id=? AND seq=?",
        (request.authenticated_scope["project_id"],
         cursor["event_seq"])).fetchone()
    if not row or row["hash"] != cursor["event_hash"]:
        return {
            "code": "base_cursor_diverged",
            "reason": "the mutation base cursor is not on this ledger",
            "current": {"server_cursor": _sync_head_cursor(
                conn, request.authenticated_scope["project_id"])},
            "retryable": False,
        }
    return None


def _sync_rejection(server, error):
    message = str(error)
    lowered = message.lower()
    if any(token in lowered for token in (
            "conflict", "stale", "claimed by", "lease until",
            "already resolved", "already has status")):
        return server.MutationConflict(
            "domain_conflict", message, retryable=False)
    return server.MutationRejected("invalid_operation", message)


def _sync_apply_mutation(conn, request, principal):
    _, server = _sync_runtime()
    tool = SYNC_OPERATION_TO_TOOL.get(request.operation)
    if not tool:
        raise server.MutationRejected(
            "unsupported_operation", "operation is not available offline")
    args = dict(request.payload)
    forbidden = sorted(SYNC_RESERVED_ARGUMENTS.intersection(args))
    if forbidden:
        raise server.MutationRejected(
            "reserved_identity_field",
            "mutation payload cannot set trusted field(s): %s" %
            ", ".join(forbidden))
    args["project"] = request.authenticated_scope["project_id"]
    branch = request.metadata.get("git_branch")
    revision = request.metadata.get("git_revision")
    for label, value in (("git_branch", branch), ("git_revision", revision)):
        if value is not None and (not isinstance(value, str)
                                  or len(value.encode("utf-8")) > 1000):
            raise server.MutationRejected(
                "invalid_git_context", "%s must be a bounded string" % label)
    scope = request.authenticated_scope
    session = McpSession(
        DEFAULT_DB, default_project=scope["project_id"],
        actor=scope["actor_id"], actor_type=scope["actor_type"],
        detect_cwd=False, owner=principal["username"],
        git_branch_name=branch, git_revision=revision,
        device_id=principal.get("audit_device_id") or request.device_id,
        auth_user_id=principal["user_id"],
        authorized_project=scope["project_id"], preserve_actor_identity=True)
    session.conn = conn
    session.client_name = scope["actor_id"].rsplit(".", 1)[-1]
    session._registered.add((scope["project_id"], scope["actor_id"]))
    try:
        result = session.dispatch_tool(tool, args)
    except AuthorizationError as error:
        raise server.MutationRejected("forbidden_operation", str(error)) from error
    except AttaccaError as error:
        raise _sync_rejection(server, error) from error
    event = result.get("event") if isinstance(result, dict) else None
    if not isinstance(event, dict) or not event.get("event_id") \
            or not event.get("seq"):
        # Even a guarded idempotent/no-op outcome needs one canonical ledger
        # mapping so clients can prove convergence rather than accepting a
        # receipt that never becomes observable in the hash chain.
        event = append_event(
            conn, scope["project_id"], scope["actor_id"],
            scope["actor_type"], "sync.mutation_recorded",
            {"client_mutation_id": request.client_mutation_id,
             "operation": request.operation}, in_tx=False)
        result = dict(result or {})
        result["event"] = event
    result = dict(result)
    result["canonical_event_id"] = event["event_id"]
    result["canonical_event_seq"] = event["seq"]
    return {"result": result,
            "server_cursor": _sync_head_cursor(conn, scope["project_id"])}


def _sync_engine(handler, scope):
    _, server = _sync_runtime()
    principal = dict(getattr(handler, "sync_principal", None)
                     or handler.principal)
    principal["audit_device_id"] = handler._request_audit_device_id()
    fault = getattr(handler.server, "sync_fault_injector", None)
    adapters = server.SyncServerAdapters(
        authorize=_sync_authorize,
        head_cursor=_sync_head_cursor,
        read_events=_sync_read_events,
        visibility_projector=_sync_visibility_projector,
        apply_mutation=lambda conn, request: _sync_apply_mutation(
            conn, request, principal),
        check_precondition=_sync_check_precondition,
        fault_injector=fault,
    )
    return server.SyncServerEngine(handler._conn(), adapters)


def save_project_export_artifact(path, data, force=False):
    """Atomically save a complete backup as a private local file."""
    target = Path(path).expanduser()
    if target.exists() and target.is_dir():
        raise AttaccaError("export output is a directory: %s" % target)
    if (target.exists() or target.is_symlink()) and not force:
        raise AttaccaError(
            "export output already exists: %s (pass --force to replace it)"
            % target)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".%s." % target.name, suffix=".tmp", dir=str(target.parent))
    try:
        os.chmod(temporary_name, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, str(target))
        os.chmod(str(target), 0o600)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return str(target)


# Files that make up the downloadable plugin (paths relative to this script).
# One zip, three native plugin manifests. Each client ignores the manifests it
# does not understand, so the same download also remains the universal shell
# install payload.
PLUGIN_FILES = [
    "attacca.py",
    "codex_hook_compat.py",
    "offline_sync.py",
    "project_export.py",
    "sync_client.py",
    "sync_protocol.py",
    "sync_server.py",
    "terminal_flow.py",
    "tools/repair_codex_config.py",
    "requirements.txt",
    "README.md",
    "plugin-mcp.json",
    "kimi.plugin.json",
    ".mcp.json",
    ".claude-plugin/plugin.json",
    ".claude-plugin/marketplace.json",
    ".codex-plugin/plugin.json",
    ".agents/plugins/marketplace.json",
    "skills/setup/SKILL.md",
    "skills/msg/SKILL.md",
    "skills/update/SKILL.md",
    "kimi-skills/session/SKILL.md",
    "hooks/hooks.json",
    "hooks/session_start.py",
    "web/admin.html",
    "commands/status.md",
    "commands/brief.md",
    "commands/inbox.md",
    "commands/room.md",
    "commands/tasks.md",
    "kimi-commands/setup.md",
    "kimi-commands/status.md",
    "kimi-commands/brief.md",
    "kimi-commands/inbox.md",
    "kimi-commands/room.md",
    "kimi-commands/tasks.md",
    "kimi-commands/msg.md",
    "kimi-commands/update.md",
]

# ZIP metadata is part of the artifact hash used to select the dumb-HTTP Git
# cache.  A wall-clock timestamp here would create a different repository for
# every request and could route one Git clone across inconsistent commits.
_PLUGIN_ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)
_PLUGIN_MCP_CONFIG_FILES = frozenset((
    "plugin-mcp.json", "kimi.plugin.json", ".mcp.json",
))


def _read_plugin_source_snapshot(src_root=None, plugin_files=None):
    """Read one complete, immutable plugin source payload.

    A hosted process must never combine its already-imported VERSION with
    files from a later checkout update.  The returned tuple contains only
    immutable path strings and bytes and is therefore safe to retain for the
    lifetime of one :class:`AttaccaServer`.
    """
    root = Path(src_root or Path(script_path()).parent)
    files = tuple(PLUGIN_FILES if plugin_files is None else plugin_files)

    def read_once():
        missing = [rel for rel in files if not (root / rel).is_file()]
        if missing:
            return None, missing
        try:
            return tuple((rel, (root / rel).read_bytes()) for rel in files), []
        except OSError:
            return None, []

    for _attempt in range(3):
        before = root.stat()
        generation = (before.st_dev, before.st_ino, before.st_mtime_ns,
                      before.st_ctime_ns)
        first, first_missing = read_once()
        second, second_missing = read_once()
        after = root.stat()
        after_generation = (after.st_dev, after.st_ino, after.st_mtime_ns,
                            after.st_ctime_ns)
        if generation != after_generation:
            continue
        missing = first_missing or second_missing
        if missing:
            raise FileNotFoundError(
                "plugin bundle is incomplete; missing: %s" %
                ", ".join(missing))
        if first is not None and first == second:
            return first
    raise AttaccaError(
        "plugin bundle changed repeatedly while its startup snapshot was read")


def _capture_distribution_snapshot():
    """Capture every mutable input used by hosted distribution routes."""
    plugin_files = tuple(PLUGIN_FILES)
    if len(plugin_files) != len(set(plugin_files)):
        raise AttaccaError("plugin bundle declares duplicate paths")
    plugin_sources = _read_plugin_source_snapshot(
        plugin_files=plugin_files)
    by_name = dict(plugin_sources)
    if "web/admin.html" not in by_name:
        raise FileNotFoundError(
            "plugin bundle is incomplete; missing: web/admin.html")
    # Parse the request-rewritten manifests now as well.  A malformed source
    # package must fail server startup instead of becoming a request-time 500.
    for rel in _PLUGIN_MCP_CONFIG_FILES:
        try:
            config = json.loads(by_name[rel])
        except (KeyError, TypeError, ValueError) as error:
            raise AttaccaError(
                "plugin bundle has invalid %s: %s" % (rel, error))
        if not isinstance(config.get("mcpServers"), dict):
            raise AttaccaError(
                "plugin bundle has invalid %s: mcpServers must be an object"
                % rel)
        if not isinstance(config["mcpServers"].get("attacca"), dict):
            raise AttaccaError(
                "plugin bundle has invalid %s: attacca MCP server is missing"
                % rel)
        for server_name, server in config["mcpServers"].items():
            if not isinstance(server, dict):
                raise AttaccaError(
                    "plugin bundle has invalid %s: MCP server %s must be an"
                    " object" % (rel, server_name))
            if "env" in server and not isinstance(server["env"], dict):
                raise AttaccaError(
                    "plugin bundle has invalid %s: MCP server %s env must be"
                    " an object" % (rel, server_name))
    version = str(VERSION)
    try:
        runtime_text = by_name["attacca.py"].decode("utf-8")
    except (KeyError, UnicodeDecodeError) as error:
        raise AttaccaError(
            "plugin bundle has invalid attacca.py: %s" % error) from None
    runtime_match = re.search(
        r'^VERSION\s*=\s*["\']([^"\']+)["\']', runtime_text,
        re.MULTILINE)
    runtime_version = runtime_match.group(1) if runtime_match else None
    if runtime_version != version:
        raise AttaccaError(
            "plugin bundle VERSION mismatch: running %s, attacca.py %s" %
            (version, runtime_version or "missing"))
    for rel, codex_build in (
            (".claude-plugin/plugin.json", False),
            ("kimi.plugin.json", False),
            (".codex-plugin/plugin.json", True)):
        try:
            manifest_version = str(
                json.loads(by_name[rel]).get("version") or "")
        except (KeyError, TypeError, ValueError) as error:
            raise AttaccaError(
                "plugin bundle has invalid %s: %s" % (rel, error)) from None
        valid = re.fullmatch(
            re.escape(version) + r"\+codex\.[a-z0-9]+(?:-[a-z0-9]+)*",
            manifest_version) if codex_build \
            else manifest_version == version
        if not valid:
            raise AttaccaError(
                "plugin bundle VERSION mismatch: %s reports %s, expected %s%s"
                % (rel, manifest_version or "missing", version,
                   "+codex.<cachebuster>" if codex_build else ""))
    laws = managed_instruction_metadata(_MANAGED_TEMPLATE_PROJECT)
    return MappingProxyType({
        "version": version,
        "plugin_files": plugin_files,
        "plugin_sources": plugin_sources,
        "plugin_mcp_config_files": tuple(sorted(_PLUGIN_MCP_CONFIG_FILES)),
        "plugin_zip_date_time": tuple(_PLUGIN_ZIP_DATE_TIME),
        "app_template": by_name["web/admin.html"],
        "landing_template": LANDING_TEMPLATE.encode("utf-8"),
        "install_template": str(INSTALL_SH_TEMPLATE),
        "managed_instructions_version": laws["version"],
        "managed_instructions_sha256": laws["law_sha256"],
    })


def build_plugin_zip(base_url, source_snapshot=None, plugin_files=None,
                     mcp_config_files=None, zip_date_time=None):
    """Zip the plugin, with the MCP configs in both plugin manifests
    pre-wired to the serving host so a downloaded copy talks to the server
    it came from.

    ``source_snapshot`` is supplied by hosted servers so later filesystem
    changes cannot alter their artifact.  Direct callers retain the historical
    behavior of taking a fresh source snapshot for each invocation.
    """
    files = tuple(PLUGIN_FILES if plugin_files is None else plugin_files)
    config_files = _PLUGIN_MCP_CONFIG_FILES if mcp_config_files is None \
        else frozenset(mcp_config_files)
    archive_date_time = _PLUGIN_ZIP_DATE_TIME if zip_date_time is None \
        else tuple(zip_date_time)
    sources = _read_plugin_source_snapshot(plugin_files=files) \
        if source_snapshot is None else tuple(source_snapshot)
    source_by_name = dict(sources)
    missing = [rel for rel in files if rel not in source_by_name]
    if missing:
        raise FileNotFoundError(
            "plugin bundle is incomplete; missing: %s" %
            ", ".join(missing))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in files:
            data = source_by_name[rel]
            if rel in config_files:
                cfg = json.loads(data)
                for server in cfg.get("mcpServers", {}).values():
                    server.setdefault("env", {})["ATTACCA_URL"] = base_url
                data = (json.dumps(cfg, indent=2) + "\n").encode()
            info = zipfile.ZipInfo(rel, date_time=archive_date_time)
            info.create_system = 3  # Unix mode bits in external_attr.
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    return buf.getvalue()


INSTALL_SH_TEMPLATE = """#!/bin/sh
# attacca installer — served by the attacca server itself.
# One line wires every AI coding tool it finds on this machine:
#   curl -fsSL {base}/install.sh | sh
set -e
BASE="{base}"
DEST="$HOME/.attacca/plugin/attacca"
EXPECTED_VERSION="{version}"
TMP="$(mktemp -d)"
echo "downloading attacca from $BASE/plugin.zip ..."
if command -v curl >/dev/null 2>&1; then
  curl -fsS "$BASE/plugin.zip" -o "$TMP/plugin.zip"
else
  wget -qO "$TMP/plugin.zip" "$BASE/plugin.zip"
fi
python3 - "$TMP/plugin.zip" "$DEST" "$EXPECTED_VERSION" <<'PYEOF'
import json, os, re, shutil, sys, tempfile, zipfile
from pathlib import PurePosixPath

zip_path, dest, expected_version = sys.argv[1:4]
required_files = {required_files}
dest = os.path.abspath(dest)
parent = os.path.dirname(dest)
os.makedirs(parent, exist_ok=True)
stage = tempfile.mkdtemp(prefix=".attacca-stage-", dir=parent)
backup = None
rollback = os.path.join(os.path.dirname(parent), "plugin-data", "rollback",
                        "attacca")

def remove_path(path):
    if not path or not os.path.lexists(path):
        return
    if os.path.islink(path) or os.path.isfile(path):
        os.unlink(path)
    else:
        shutil.rmtree(path)

try:
    with zipfile.ZipFile(zip_path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise RuntimeError("plugin ZIP contains duplicate paths")
        for info in infos:
            name = info.filename
            path = PurePosixPath(name)
            mode = (info.external_attr >> 16) & 0o170000
            if (not name or "\\\\" in name or path.is_absolute() or
                    ".." in path.parts or mode == 0o120000):
                raise RuntimeError("unsafe plugin ZIP path: %r" % name)
        missing = [name for name in required_files if name not in names]
        if missing:
            raise RuntimeError("plugin ZIP is incomplete; missing: %s" %
                               ", ".join(missing))
        archive.extractall(stage)

    for name in required_files:
        if not os.path.isfile(os.path.join(stage, name)):
            raise RuntimeError("plugin payload is not a regular file: %s" % name)
    with open(os.path.join(stage, "attacca.py"),
              encoding="utf-8") as handle:
        runtime_text = handle.read()
    match = re.search(r'^VERSION\\s*=\\s*["\\\']([^"\\\']+)["\\\']',
                      runtime_text, re.MULTILINE)
    if not match or match.group(1) != expected_version:
        raise RuntimeError("plugin VERSION mismatch: expected %s, got %s" %
                           (expected_version,
                            match.group(1) if match else "missing"))
    manifests = [
        (".claude-plugin/plugin.json", False),
        ("kimi.plugin.json", False),
        (".codex-plugin/plugin.json", True),
    ]
    for name, allow_build in manifests:
        with open(os.path.join(stage, name), encoding="utf-8") as handle:
            manifest_version = str(json.load(handle).get("version") or "")
        if allow_build:
            valid_version = re.fullmatch(
                re.escape(expected_version) +
                r"\\+codex\\.[a-z0-9]+(?:-[a-z0-9]+)*",
                manifest_version)
        else:
            valid_version = manifest_version == expected_version
        if not valid_version:
            suffix = (" with one +codex.<cachebuster> suffix"
                      if allow_build else "")
            raise RuntimeError(
                "%s VERSION mismatch: expected %s%s, got %s" %
                (name, expected_version, suffix, manifest_version))
    os.chmod(os.path.join(stage, "attacca.py"), 0o755)
    os.chmod(os.path.join(stage, "hooks/session_start.py"), 0o755)

    # Validate everything before touching the active plugin. The two renames
    # stay on one filesystem; any ordinary failure restores the prior bundle.
    if os.path.lexists(dest):
        backup = tempfile.mkdtemp(prefix=".attacca-backup-", dir=parent)
        os.rmdir(backup)
        os.replace(dest, backup)
    try:
        os.replace(stage, dest)
        stage = None
    except BaseException:
        if backup is not None and not os.path.lexists(dest):
            os.replace(backup, dest)
            backup = None
        raise
    if backup is not None:
        os.makedirs(os.path.dirname(rollback), exist_ok=True)
        remove_path(rollback)
        os.replace(backup, rollback)
    backup = None
finally:
    remove_path(stage)
    if backup is not None and not os.path.lexists(dest):
        os.replace(backup, dest)
        backup = None
    remove_path(backup)
PYEOF
rm -rf "$TMP"
chmod +x "$DEST/attacca.py" "$DEST/hooks/session_start.py"
mkdir -p "$HOME/.local/bin"
ln -sf "$DEST/attacca.py" "$HOME/.local/bin/attacca"
echo "attacca downloaded to $DEST (wired to $BASE)"
echo "command installed: $HOME/.local/bin/attacca"
echo ""

# The stable plugin directory was just atomically replaced. A detached Python
# watcher keeps its previously imported code in memory, so explicitly ensure
# the new launch fingerprint now. This does not depend on curl's cwd: the hook
# selects a valid saved linked subscription and preserves its cursor, auth
# latch, pending notices, and offline/outbox state. A first install with no
# linked checkout is a safe deferred start, not a fabricated identity.
if ATTACCA_WATCHER_UPGRADE="$(python3 "$DEST/attacca.py" watch upgrade)"; then
  python3 - "$ATTACCA_WATCHER_UPGRADE" <<'PYEOF'
import json, sys
result = json.loads(sys.argv[1])
if result.get("deferred"):
    print("attacca watcher: upgrade restart deferred — no valid saved linked checkout; it will start at the next project setup/session.")
elif result.get("disabled_for_process"):
    print("attacca watcher: restart disabled for this installer process.")
elif result.get("started"):
    print("attacca watcher: upgraded daemon started automatically (pid %s)." % result.get("pid"))
elif result.get("already_running") or result.get("already_starting"):
    print("attacca watcher: current daemon already active (pid %s)." % result.get("pid"))
else:
    print("attacca watcher: upgrade check completed.")
PYEOF
else
  echo "attacca watcher: automatic upgrade restart is pending; no unverified process was stopped." >&2
  echo "  The next Attacca session hook will retry it automatically." >&2
fi

# Claude Code: native plugin install.
ATTACCA_CLAUDE_NATIVE=0
if command -v claude >/dev/null 2>&1; then
  # Remove the dead pre-rename registration but preserve its plugin data.
  claude plugin uninstall continuity@agentg --scope user --keep-data \
    >/dev/null 2>&1 || true
  # Project/local plugin scopes are resolved from Claude's cwd. Enumerate the
  # projectPath recorded for every Attacca registration and uninstall from its
  # owning directory so registrations made in other checkouts cannot survive.
  if ! python3 - "$DEST" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[1])
import attacca
result = attacca.uninstall_claude_scoped_attacca_plugins()
for item in result["uninstalled"]:
    print("claude code: removed %s Attacca plugin from %s" %
          (item["scope"], item["project_path"]))
for item in result["missing"]:
    print("claude code: skipped stale %s registration; directory is missing: %s" %
          (item["scope"], item["project_path"]))
if result.get("error"):
    print("claude code: " + result["error"], file=sys.stderr)
for item in result["invalid"] + result["failed"]:
    print("claude code: could not remove %s registration at %r: %s" %
          (item.get("scope"), item.get("project_path"),
           item.get("error") or "invalid projectPath"), file=sys.stderr)
if not result["ok"]:
    raise SystemExit(1)
PYEOF
  then
    echo "claude code: warning — cross-directory plugin cleanup was incomplete." >&2
  fi
  # Re-point our marketplace every run. Updating a marketplace snapshot does
  # not repair an absolute path left behind by another HOME/container.
  # Keep this cwd-based loop as a fallback for state from older Claude builds.
  for ATTACCA_CLAUDE_SCOPE in user project local; do
    claude plugin uninstall attacca@agentg \
      --scope "$ATTACCA_CLAUDE_SCOPE" --keep-data -y \
      >/dev/null 2>&1 || true
  done
  claude plugin marketplace remove agentg >/dev/null 2>&1 || true
  claude plugin marketplace add "$DEST" --scope user >/dev/null 2>&1 || true
  if claude plugin install attacca@agentg --scope user >/dev/null 2>&1; then
    ATTACCA_CLAUDE_NATIVE=1
    echo "claude code: plugin installed/updated — restart it and open a project."
    echo "  Attacca checks automatically and asks once if setup is needed."
    echo "  manual setup is always available as /attacca:setup."
  else
    echo "claude code: marketplace added — finish inside Claude Code with:"
    echo "  /plugin install attacca@agentg"
  fi
  python3 "$DEST/codex_hook_compat.py" prune \
    --cache-root "$HOME/.claude/plugins/cache/agentg/attacca" \
    --active-version "$EXPECTED_VERSION" --rollback-count 1 >/dev/null || \
    echo "claude code: warning — Attacca cache cleanup was incomplete." >&2
else
  echo "claude code: CLI not found — skipping (install later from $DEST)."
fi

# Upgrade an already-setup checkout from the old project MCP route to the
# native Claude plugin route. Unlinked directories remain untouched; only the
# managed `attacca` key is removed and unrelated .mcp.json content survives.
if [ "$ATTACCA_CLAUDE_NATIVE" = "1" ]; then
  if ! python3 - "$DEST" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[1])
import attacca
result = attacca.reconcile_native_claude_checkout()
if result.get("changed"):
    print("claude code: removed duplicate project MCP entry from %s" % result["removed"])
PYEOF
  then
    echo "claude code: warning — could not reconcile this checkout's old MCP entry." >&2
    echo "  Re-run the complete Attacca setup here to remove the duplicate." >&2
  fi
fi

# Kimi Code: install the same bundle as one native managed plugin. Kimi exposes
# plugin installation only inside its interactive /plugins UI, so the universal
# installer mirrors Kimi's versioned installed-store contract after the user has
# already authorized this downloaded bundle. The helper also removes the old
# global Attacca MCP entry to prevent duplicate plugin/global servers.
ATTACCA_KIMI_NATIVE=0
if command -v kimi >/dev/null 2>&1 || [ -d "$HOME/.kimi-code" ]; then
  if ATTACCA_KIMI_REPORT="$(python3 - "$DEST" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[1])
import attacca
result = attacca.install_kimi_native_plugin(sys.argv[1])
print("kimi code: native plugin installed/updated at %s" % result["root"])
if not result["enabled"]:
    print("  note: it remains disabled by your existing Kimi preference; enable it in /plugins.")
print("__ATTACCA_KIMI_ENABLED=%d" % bool(result["enabled"]))
PYEOF
  )"; then
    ATTACCA_KIMI_NATIVE=1
    printf '%s\n' "$ATTACCA_KIMI_REPORT" | sed '$d'
    case "$ATTACCA_KIMI_REPORT" in
      *"__ATTACCA_KIMI_ENABLED=1")
        echo "  restart Kimi (or /reload); Attacca checks automatically."
        ;;
      *)
        echo "  Attacca will stay inactive until you enable it in Kimi's /plugins screen."
        ;;
    esac
    echo "  manual setup is always available as /attacca:setup."
  else
    echo "kimi code: native plugin install failed; falling back to global MCP." >&2
  fi
else
  echo "kimi code: not found — skipping (rerun this installer after adding it)."
fi

# Every remaining detected MCP client — Codex, Cline, Cursor, Windsurf, plus
# Kimi when native installation was unavailable — gets one global MCP config.
# Touches no project files.
echo ""
attacca_configure_tools() {{
  if [ "$ATTACCA_KIMI_NATIVE" = "1" ]; then
    python3 "$DEST/attacca.py" setup --tools-only --skip-tools kimi --url "$BASE"
  else
    python3 "$DEST/attacca.py" setup --tools-only --url "$BASE"
  fi
}}
if ! attacca_configure_tools; then
  echo "attacca: tool configuration failed; nothing is connected yet." >&2
  exit 1
fi

# Codex CLI: add the native setup skill and bundled MCP after tools-only has
# created/updated CODEX_HOME. The global MCP entry remains for Codex surfaces
# that do not load plugins; Codex resolves the same server name as one entry.
if command -v codex >/dev/null 2>&1; then
  # An open Codex process keeps the absolute cache path that existed when its
  # thread started. `codex plugin add` may replace that versioned directory;
  # remember every live-compatible path and restore missing ones as symlinks
  # to Attacca's stable installation immediately after the update.
  ATTACCA_CODEX_CACHE_ROOT="${{CODEX_HOME:-$HOME/.codex}}/plugins/cache/attacca-local/attacca"
  ATTACCA_CODEX_COMPAT_STATE="$HOME/.attacca/plugin-data/codex-attacca/cache-compat.json"
  ATTACCA_CODEX_OLD_CACHE_VERSIONS="$(python3 "$DEST/codex_hook_compat.py" \
    snapshot --cache-root "$ATTACCA_CODEX_CACHE_ROOT" \
    --state "$ATTACCA_CODEX_COMPAT_STATE")"
  attacca_restore_codex_cache() {{
    # The helper reports: "codex: preserved live hook compatibility ..."
    python3 "$DEST/codex_hook_compat.py" restore \
      --cache-root "$ATTACCA_CODEX_CACHE_ROOT" --stable-root "$DEST" \
      --versions-json "$ATTACCA_CODEX_OLD_CACHE_VERSIONS"
  }}
  # Preserve the paths on ordinary failure and interrupt as well as success.
  # The persisted snapshot also repairs a previous kill -9 on the next run.
  trap 'attacca_restore_codex_cache >/dev/null 2>&1 || true' 0
  trap 'attacca_restore_codex_cache >/dev/null 2>&1 || true; exit 1' 1 2 15
  codex plugin marketplace remove attacca-local >/dev/null 2>&1 || true
  codex plugin marketplace add "$DEST" >/dev/null 2>&1 || true
  ATTACCA_CODEX_NATIVE=0
  if codex plugin add attacca@attacca-local >/dev/null 2>&1; then
    ATTACCA_CODEX_NATIVE=1
  fi
  if ! attacca_restore_codex_cache; then
    echo "codex: failed to preserve an open session's old hook path." >&2
    exit 1
  fi
  ATTACCA_CODEX_ACTIVE_VERSION="$(python3 - "$DEST/.codex-plugin/plugin.json" <<'PYEOF'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["version"])
PYEOF
)"
  python3 "$DEST/codex_hook_compat.py" prune \
    --cache-root "$ATTACCA_CODEX_CACHE_ROOT" \
    --active-version "$ATTACCA_CODEX_ACTIVE_VERSION" --rollback-count 1 || \
    echo "codex: warning — Attacca cache cleanup was incomplete." >&2
  trap - 0 1 2 15
  if [ "$ATTACCA_CODEX_NATIVE" = "1" ]; then
    echo "codex: native plugin installed/updated."
    echo "  one-time: start Codex, open /hooks, and trust Attacca's SessionStart hook."
    echo "  then start a new session; Attacca will ask once whether to set up this folder."
    echo "  manual setup is always available as \\$attacca:setup."
  else
    echo "codex: MCP is configured; this Codex build did not install the optional native setup plugin."
  fi
fi

# Do not claim Codex works merely because files were written. Ask the same
# executable the user will launch to resolve the effective MCP server.
if command -v codex >/dev/null 2>&1; then
  if codex mcp get attacca >/dev/null 2>&1; then
    echo "codex: verified — MCP server 'attacca' is visible to Codex."
  else
    echo "codex: configuration was written but this Codex cannot see it." >&2
    echo "Run the installer inside the same host/container where Codex runs." >&2
    exit 1
  fi
fi

echo ""
echo "Open the project in your coding client. Its AI runs complete setup."
echo "If authentication is required, the AI opens a short-lived Attacca Settings"
echo "link. Sign in, review the client, then explicitly Authorize or Deny it."
echo "The client polls silently, stores the credential, and reconnects"
echo "automatically: no key copy/paste, auth command, or client restart."
echo "Kimi native manual install/refresh alternative:"
echo "  /plugins install $BASE/plugin.zip    then /reload (or start a new session)"
echo "attacca web panel:"
echo "  $BASE/app"
echo "any other MCP tool (grok, zed, ...):"
echo "  python3 $DEST/attacca.py setup --details"
"""


LANDING_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Attacca — One universal setup for every AI coding tool</title>
  <style>
    :root { --paper:#f4f0e7; --ink:#161b18; --muted:#667069; --lime:#caff55; --blue:#3659e3; --line:#babcb2; }
    * { box-sizing:border-box; }
    html { scroll-behavior:smooth; }
    body { margin:0; color:var(--ink); background:var(--paper); font:16px/1.5 Inter,ui-sans-serif,system-ui,sans-serif; }
    a { color:inherit; }
    .wrap { width:min(1120px,calc(100% - 36px)); margin:auto; }
    header { height:78px; display:flex; align-items:center; justify-content:space-between; border-bottom:1px solid var(--line); }
    .brand { display:flex; align-items:center; gap:10px; font:800 14px/1 ui-monospace,monospace; letter-spacing:.14em; text-decoration:none; }
    .mark { display:grid; place-items:center; width:34px; height:34px; border:2px solid var(--ink); border-radius:50% 50% 50% 8px; background:var(--lime); font:700 20px Georgia,serif; transform:rotate(-7deg); }
    .head-actions { display:flex; align-items:center; gap:10px; }
    .panel-link { padding:9px 12px; border:1px solid var(--ink); border-radius:99px; font:700 11px/1 ui-monospace,monospace; text-decoration:none; text-transform:uppercase; }
    .online { display:flex; align-items:center; gap:8px; padding:8px 11px; border:1px solid var(--ink); border-radius:99px; font:700 11px/1 ui-monospace,monospace; text-transform:uppercase; }
    .dot { width:8px; height:8px; border-radius:50%; background:#32a852; }
    .hero { min-height:610px; display:grid; grid-template-columns:1.2fr .8fr; gap:70px; align-items:center; padding:76px 0; }
    .eyebrow { margin:0 0 18px; font:800 12px/1 ui-monospace,monospace; letter-spacing:.12em; text-transform:uppercase; }
    .eyebrow::before { content:""; display:inline-block; width:32px; height:3px; margin:0 10px 3px 0; background:#ef5b35; }
    h1 { max-width:720px; margin:0 0 25px; font:500 clamp(58px,7.4vw,94px)/.9 Georgia,serif; letter-spacing:-.055em; }
    h1 em { color:var(--blue); font-weight:inherit; }
    .lede { max-width:650px; margin:0 0 32px; color:#3e4942; font-size:19px; }
    .actions { display:flex; gap:12px; flex-wrap:wrap; }
    .button { min-height:48px; display:inline-flex; align-items:center; padding:11px 17px; border:2px solid var(--ink); border-radius:8px; font:800 13px/1 ui-monospace,monospace; text-decoration:none; }
    .primary { background:var(--lime); box-shadow:4px 4px 0 var(--ink); }
    .memory { border:2px solid var(--ink); border-radius:16px; overflow:hidden; color:white; background:var(--ink); box-shadow:8px 8px 0 var(--blue); transform:rotate(1.5deg); }
    .memory-head { display:flex; justify-content:space-between; padding:14px 17px; border-bottom:1px solid #46504a; font:700 10px/1 ui-monospace,monospace; letter-spacing:.1em; text-transform:uppercase; }
    .memory-head span:last-child { color:var(--lime); }
    .memory-body { padding:26px 22px; }
    .memory-label { color:#9ba69f; font:700 10px/1 ui-monospace,monospace; text-transform:uppercase; }
    .memory h2 { margin:8px 0 22px; font:500 32px/1.05 Georgia,serif; }
    .event { display:grid; grid-template-columns:68px 1fr; gap:10px; padding:12px 0; border-top:1px solid #3c4540; font-size:13px; }
    .agent { color:var(--lime); font:700 10px/1.7 ui-monospace,monospace; }
    .install { padding:95px 0; color:white; background:var(--blue); }
    .install-grid { display:grid; grid-template-columns:.7fr 1.3fr; gap:60px; align-items:start; }
    .install h2 { margin:8px 0 18px; font:500 clamp(42px,6vw,72px)/.95 Georgia,serif; letter-spacing:-.04em; }
    .install-copy { color:#dfe4ff; }
    .terminal { border:2px solid var(--ink); border-radius:14px; overflow:hidden; background:var(--ink); box-shadow:7px 7px 0 var(--lime); }
    .terminal-top { padding:12px 16px; border-bottom:1px solid #46504a; color:#aeb8b2; font:700 10px/1 ui-monospace,monospace; text-transform:uppercase; }
    .command { padding:27px 22px; overflow-x:auto; }
    code { font:700 14px/1.5 ui-monospace,monospace; white-space:nowrap; }
    .prompt { color:var(--lime); }
    .copy { width:100%; min-height:50px; border:0; border-top:1px solid #46504a; color:var(--ink); background:var(--lime); font:800 12px/1 ui-monospace,monospace; cursor:pointer; }
    .fine { margin:18px 0 0; color:#dfe4ff; font-size:13px; }
    .tools { display:flex; flex-wrap:wrap; gap:8px; margin-top:24px; }
    .tool { padding:7px 10px; border:1px solid rgba(255,255,255,.5); border-radius:99px; font-size:12px; }
    .steps { padding:100px 0; }
    .steps h2 { max-width:680px; margin:0 0 46px; font:500 clamp(42px,5vw,68px)/.98 Georgia,serif; letter-spacing:-.04em; }
    .step-grid { display:grid; grid-template-columns:repeat(3,1fr); border-top:1px solid var(--ink); }
    .step { min-height:220px; padding:24px 24px 20px 0; border-right:1px solid var(--ink); }
    .step + .step { padding-left:24px; }
    .step:last-child { border-right:0; }
    .num { display:block; margin-bottom:42px; color:var(--blue); font:800 12px/1 ui-monospace,monospace; }
    .step h3 { margin:0 0 10px; font:600 27px/1 Georgia,serif; }
    .step p { margin:0; color:var(--muted); }
    .alt { padding:28px 0 70px; border-top:1px solid var(--line); }
    .alt-row { display:flex; gap:30px; justify-content:space-between; align-items:center; }
    .alt h2 { margin:0 0 5px; font:600 26px/1.1 Georgia,serif; }
    .alt p { margin:0; color:var(--muted); }
    .mini { max-width:100%; padding:14px 16px; border-radius:8px; color:white; background:var(--ink); overflow-x:auto; }
    footer { padding:30px 0; color:#bec7c1; background:var(--ink); font-size:12px; }
    .foot { display:flex; justify-content:space-between; gap:20px; }
    :focus-visible { outline:3px solid var(--lime); outline-offset:3px; }
    @media (max-width:780px) {
      .hero,.install-grid { grid-template-columns:1fr; gap:42px; }
      .hero { padding:58px 0 70px; }
      .memory { max-width:520px; }
      .step-grid { grid-template-columns:1fr; }
      .step,.step + .step { min-height:0; padding:25px 0; border-right:0; border-bottom:1px solid var(--ink); }
      .num { margin-bottom:18px; }
      .alt-row { display:block; }
      .mini { margin-top:22px; }
    }
    @media (max-width:600px) { .panel-link { display:none; } }
    @media (max-width:480px) { .online .version { display:none; } h1 { font-size:54px; } .foot { flex-direction:column; } }
  </style>
</head>
<body>
  <header class="wrap">
    <a class="brand" href="/"><span class="mark">A</span> ATTACCA</a>
    <div class="head-actions"><a class="panel-link" href="/app">Open control panel</a><div class="online"><span class="dot"></span> Server online <span class="version">v__VERSION__</span></div></div>
  </header>

  <main>
    <section class="wrap hero">
      <div>
        <p class="eyebrow">Universal setup for AI coding</p>
        <h1>One install.<br>Every tool <em>in sync.</em></h1>
        <p class="lede">Attacca finds your supported AI coding tools and connects all of them to the same handoff, task board, decisions and project room.</p>
        <div class="actions">
          <a class="button primary" href="#install">Show me the install ↓</a>
          <a class="button" href="/app">Open control panel</a>
          <a class="button" href="#steps">How it works</a>
        </div>
      </div>
      <aside class="memory">
        <div class="memory-head"><span>Project handoff</span><span>Current</span></div>
        <div class="memory-body">
          <span class="memory-label">Everyone sees the latest state</span>
          <h2>Ship the migration without losing the plot.</h2>
          <div class="event"><span class="agent">DIRECTOR</span><span>Updated the handoff</span></div>
          <div class="event"><span class="agent">WORKER</span><span>Claimed the API work</span></div>
          <div class="event"><span class="agent">REVIEWER</span><span>Ran tests and left evidence</span></div>
        </div>
      </aside>
    </section>

    <section class="install" id="install">
      <div class="wrap install-grid">
        <div>
          <p class="eyebrow">Install once</p>
          <h2>One command.<br>Every tool.</h2>
          <p class="install-copy">Run it once. Attacca detects and configures every supported AI coding tool already on your machine.</p>
        </div>
        <div>
          <div class="terminal">
            <div class="terminal-top">Terminal · universal setup</div>
            <div class="command"><code id="install-command"><span class="prompt">$ </span>curl -fsSL __BASE__/install.sh | sh</code></div>
            <button class="copy" id="copy" type="button">COPY INSTALL COMMAND</button>
          </div>
          <p class="fine" id="copy-note" aria-live="polite">Python 3.8+ · macOS, Linux or WSL · no pip packages</p>
          <div class="tools">
            <span class="tool">Auto-detects tools</span><span class="tool">Configures all at once</span>
            <span class="tool">One shared connection</span><span class="tool">Confirm workspace once</span>
          </div>
        </div>
      </div>
    </section>

    <section class="wrap steps" id="steps">
      <h2>From install to shared context in three moves.</h2>
      <div class="step-grid">
        <article class="step"><span class="num">01 — INSTALL</span><h3>Paste the line</h3><p>Attacca finds the coding tools already on your machine and connects them.</p></article>
        <article class="step"><span class="num">02 — RESTART</span><h3>Open your project</h3><p>Every detected tool loads the same shared Attacca connection.</p></article>
        <article class="step"><span class="num">03 — CONNECT</span><h3>Confirm the workspace</h3><p>Setup detects the Git remote, suggests a match, or lists existing workspaces plus Create new.</p></article>
      </div>
    </section>

    <section class="wrap alt">
      <div class="alt-row">
        <div><h2>No tool-by-tool installation.</h2><p>The universal installer handles every supported tool it detects in one pass.</p></div>
        <div class="mini"><code>ONE INSTALL → EVERY DETECTED TOOL</code></div>
      </div>
    </section>
  </main>

  <footer><div class="wrap foot"><span>Attacca · one install for every tool</span><span><a href="/app">Control panel</a> · <a href="/healthz">Health</a> · <a href="/install.sh">Installer script</a></span></div></footer>
  <script>
    document.getElementById('copy').addEventListener('click', async function () {
      var text = document.getElementById('install-command').textContent.replace(/^\\$\\s*/, '');
      try {
        await navigator.clipboard.writeText(text);
        this.textContent = 'COPIED ✓';
        document.getElementById('copy-note').textContent = 'Copied — paste it into your terminal.';
      } catch (_) {
        document.getElementById('copy-note').textContent = 'Select the command above and copy it.';
      }
    });
  </script>
</body>
</html>
"""


def server_settings_load(conn):
    rows = conn.execute(
        "SELECT setting_key, value FROM server_settings").fetchall()
    result = {}
    for row in rows:
        try:
            result[row["setting_key"]] = json.loads(row["value"])
        except (TypeError, ValueError):
            continue
    return result


def server_settings_store(conn, updates):
    nowi = now_iso()
    with write_tx(conn):
        for key, value in updates.items():
            conn.execute(
                "INSERT INTO server_settings (setting_key, value, updated_at)"
                " VALUES (?,?,?) ON CONFLICT(setting_key) DO UPDATE SET"
                " value=excluded.value, updated_at=excluded.updated_at",
                (key, json.dumps(value, separators=(",", ":")), nowi))


class AttaccaServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, db_path, default_project=None, verbose=False,
                 auth=False, auth_mode="auto"):
        auth_mode = str(auth_mode or "auto").strip().lower()
        if auth_mode not in AUTH_MODES:
            raise AttaccaError(
                "auth_mode must be one of: %s" % ", ".join(AUTH_MODES))
        settings_conn = connect(db_path)
        try:
            persisted = server_settings_load(settings_conn)
        finally:
            settings_conn.close()
        if default_project is None:
            default_project = persisted.get("default_project")
        if not verbose:
            verbose = bool(persisted.get("verbose", False))
        interval = persisted.get(
            "update_interval_seconds", DEFAULT_UPDATE_INTERVAL_SECONDS)
        try:
            interval = int(interval)
        except (TypeError, ValueError):
            interval = DEFAULT_UPDATE_INTERVAL_SECONDS
        if interval != 0 and not 60 <= interval <= 3600:
            interval = DEFAULT_UPDATE_INTERVAL_SECONDS
        distribution_snapshot = _capture_distribution_snapshot()
        # Freeze the executable/package identity used by this process. Disk
        # updates require a restart before their QA evidence can activate;
        # otherwise old imported code could attest newer on-disk bytes.
        auth_artifact_sha256_at_start = auth_source_sha256()
        super().__init__(addr, AttaccaHandler)
        try:
            self.db_path = db_path
            self.default_project = default_project
            self.verbose = verbose
            self.distribution_snapshot = distribution_snapshot
            self.auth_mode = auth_mode
            self.auth_artifact_sha256_at_start = \
                auth_artifact_sha256_at_start
            # --auth is now a readiness request only.  It cannot persist or
            # enable enforcement; only the version-checked, confirmed
            # activation endpoint may do that after migration readiness.
            self.auth_requested = bool(
                auth or persisted.get("authentication", False)
                or persisted.get("auth.activation_requested", False))
            self.auth_forced = False  # older integration introspection
            self.update_interval_seconds = interval
            self._local = threading.local()
            self._sessions_lock = threading.Lock()
            self._sessions = {}
            self._distribution_git_lock = threading.Lock()
            self._distribution_git_repos = {}
            self._distribution_cache_root = None
        except BaseException:
            super().server_close()
            raise

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

    def server_close(self):
        """Close the socket and discard this process's bounded Git cache."""
        try:
            super().server_close()
        finally:
            lock = getattr(self, "_distribution_git_lock", None)
            if lock is not None:
                with lock:
                    root = getattr(self, "_distribution_cache_root", None)
                    self._distribution_cache_root = None
                    self._distribution_git_repos.clear()
                    if root is not None:
                        shutil.rmtree(root, ignore_errors=True)


class _UnquotedMatch:
    """URL-decodes captured path segments after routing (decoding before the
    regex match would let %2F change which route matches)."""

    def __init__(self, match):
        self._groups = [urllib.parse.unquote(g) if g is not None else None
                        for g in match.groups()]

    def group(self, index):
        return self._groups[index - 1]


class AttaccaHandler(BaseHTTPRequestHandler):
    server_version = "attacca/" + VERSION
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
            values = value if isinstance(value, (list, tuple)) else [value]
            for item in values:
                self.send_header(key, str(item))
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
            raise AttaccaError("request body must be valid JSON: %s" % err)
        if not isinstance(body, dict):
            raise AttaccaError("request body must be a JSON object")
        return body

    def _cookie_value(self, name):
        raw = self.headers.get("Cookie") or ""
        try:
            cookie = http.cookies.SimpleCookie()
            cookie.load(raw)
            return cookie[name].value if name in cookie else None
        except Exception:
            return None

    def _auth_enabled(self):
        # Request hot path: activation enforcement is a single persisted bit.
        # Artifact hashing and migration scans belong only to status/admin
        # readiness endpoints, never every watcher/MCP poll.
        return bool(self.server.auth_mode != "compatibility" and
                    _auth_setting(self._conn(), "auth.activated", False))

    def _compatibility_active(self):
        return auth_compatibility_active(self._conn(), self.server)

    def _authenticate_request(self):
        authorization = self.headers.get("Authorization") or ""
        if authorization:
            if not authorization.lower().startswith("bearer "):
                raise AuthenticationError("use Authorization: Bearer <Attacca API token>")
            raw_bearer = authorization.split(None, 1)[1].strip()
            principal = auth_token_principal(self._conn(), raw_bearer)
            if not principal:
                historical = self._conn().execute(
                    "SELECT token_kind FROM auth_tokens WHERE token_hash=?",
                    (sha256_hex(raw_bearer),)).fetchone()
                kind = historical["token_kind"] if historical else None
                modern_credential = bool(
                    kind in ("client", "terminal", "service", "human") or
                    raw_bearer.startswith(
                        ("atkey_", "atd_", "atsvc_", "ats_")))
                if modern_credential:
                    # Compatibility is a bounded bridge for stale historical
                    # actor credentials, never a revocation bypass for modern
                    # human-owned terminal/service/session credentials.
                    raise AuthenticationError(
                        "invalid_credential: bearer is invalid, expired or revoked")
                if self._compatibility_active():
                    # Explicit migration mode is the sole place a stale
                    # pre-auth bearer may degrade to narrowly scoped legacy
                    # identity.  Auto/enforced servers always reject it.
                    return None
                raise AuthenticationError(
                    "invalid_credential: bearer is invalid, expired or revoked")
            token_kind = principal.get("token_kind") or (
                "actor" if principal.get("actor_type") == "agent" else "human")
            if token_kind == "client":
                expected_instance = str(
                    principal.get("client_instance") or "")
                supplied_instance = str(
                    self.headers.get(CLIENT_INSTANCE_HEADER) or "")
                if not supplied_instance or not hmac.compare_digest(
                        supplied_instance, expected_instance):
                    raise AuthorizationError(
                        "client_instance_mismatch: API key belongs to another"
                        " Attacca installation")
                expected_device = str(principal.get("device_id") or "")
                if expected_device:
                    supplied_device = str(self._request_device_id() or "")
                    if not supplied_device or not hmac.compare_digest(
                            supplied_device, expected_device):
                        raise AuthorizationError(
                            "client_device_mismatch: API key belongs to another"
                            " device")
                requested_project = self._request_project_id()
                if requested_project:
                    path = urllib.parse.urlparse(self.path).path
                    registration = bool(
                        self.command == "POST" and re.match(
                            r"^/v1/projects/[^/]+/agents$", path))
                    setup_discovery = bool(
                        self.command in ("GET", "HEAD") and re.match(
                            r"^/v1/projects/[^/]+/"
                            r"(?:status|agents|bridges|inbox)$", path))
                    try:
                        scope = auth_client_principal_scope(
                            self._conn(), principal, requested_project,
                            self.headers.get("X-Attacca-Actor"))
                        principal.update(scope)
                    except AuthorizationError as error:
                        if not (registration or setup_discovery) \
                                or not str(error).startswith(
                                    "client_actor_not_registered:"):
                            raise
                        principal.update({
                            "project_id": auth_client_project_access(
                                self._conn(), principal, requested_project),
                            "actor_id": None,
                            "actor_type": "client",
                            "runtime": "client",
                            "role": "client",
                            # A newly installed runtime must see the bounded
                            # read-only setup context before POST /agents can
                            # create its exact actor.  This flag never grants
                            # MCP, sync, task, room, export, or mutation access.
                            "client_setup_discovery": setup_discovery,
                        })
                return principal
            if token_kind == "actor" and self._auth_enabled():
                raise AuthorizationError(
                    "legacy_actor_token_disabled: create a client API key")
            if token_kind == "terminal" and self._auth_enabled():
                raise AuthorizationError(
                    "terminal_credential_retired: create a client API key")
            if token_kind == "terminal":
                supplied_device = self._request_device_id()
                expected_device = str(principal.get("device_id") or "")
                if not supplied_device or not hmac.compare_digest(
                        supplied_device, expected_device):
                    raise AuthorizationError(
                        "terminal_device_mismatch: credential is bound to another device")
                with write_tx(self._conn()):
                    self._conn().execute(
                        "UPDATE auth_device_enrollments SET status='consumed',"
                        " consumed_at=COALESCE(consumed_at,?)"
                        " WHERE issued_token_id=? AND consumed_at IS NULL",
                        (now_iso(), principal["token_id"]))
                all_bindings = auth_terminal_bindings(
                    self._conn(), principal["token_id"])
                raw_binding_count = self._conn().execute(
                    "SELECT COUNT(*) AS n FROM auth_token_actor_bindings"
                    " WHERE token_id=? AND revoked_at IS NULL",
                    (principal["token_id"],)).fetchone()["n"]
                historical_binding_count = self._conn().execute(
                    "SELECT COUNT(*) AS n FROM auth_token_actor_bindings"
                    " WHERE token_id=?",
                    (principal["token_id"],)).fetchone()["n"]
                if raw_binding_count != len(all_bindings):
                    raise AuthorizationError(
                        "terminal_binding_invalid: an exact registered actor"
                        " binding is missing; re-enrollment is required")
                if historical_binding_count and not raw_binding_count:
                    raise AuthorizationError(
                        "terminal_binding_revoked: a previously bound terminal"
                        " cannot become a provisional human credential")
                # A provisional human terminal is deliberately a zero-binding
                # credential. Once any exact actor has been attached, requests
                # outside those bindings must fail closed; an owner/admin token
                # must never silently regain broad human authority in another
                # workspace.
                provisional = historical_binding_count == 0
                if provisional:
                    principal.update({
                        "actor_id": "web.%s" % principal["username"],
                        "actor_type": "human", "runtime": "terminal-setup",
                        "role": "human", "provisional_human": True,
                    })
                requested_project = self._request_project_id()
                if requested_project:
                    project_id = get_project(
                        self._conn(), requested_project)["project_id"]
                    project_bindings = [item for item in all_bindings
                                        if item["project_id"] == project_id]
                    if project_bindings:
                        binding = auth_terminal_principal_binding(
                            self._conn(), principal, project_id,
                            self.headers.get("X-Attacca-Actor"))
                        principal.update({
                            "actor_id": binding["actor_id"],
                            "allowed_existing_actor_id": binding["actor_id"],
                            "actor_type": "agent",
                            "project_id": binding["project_id"],
                            "runtime": binding["runtime"],
                            "role": binding["role"],
                            "terminal_binding": binding,
                        })
                    elif provisional:
                        if "/sync/" in urllib.parse.urlparse(self.path).path \
                                or urllib.parse.urlparse(self.path).path == "/mcp":
                            raise AuthorizationError(
                                "terminal_actor_binding_required: AI/sync access"
                                " requires one exact actor binding")
                        if not principal.get("is_admin") \
                                and not auth_has_project_membership(
                                    self._conn(), principal, project_id):
                            raise AuthorizationError(
                                "terminal_project_membership_required")
                        principal.update({
                            "actor_id": "web.%s" % principal["username"],
                            "actor_type": "human", "project_id": project_id,
                            "runtime": "terminal-setup", "role": "human",
                            "provisional_human": True,
                        })
                    else:
                        raise AuthorizationError(
                            "terminal_scope_denied: credential has no exact actor"
                            " binding for workspace '%s'" % project_id)
                return principal
            if token_kind == "service":
                requested_project = self._request_project_id()
                if requested_project:
                    scope = auth_service_principal_scope(
                        self._conn(), principal, requested_project,
                        self.headers.get("X-Attacca-Actor"))
                    binding = scope.get("actor_binding")
                    principal.update({
                        "project_id": scope["project_id"],
                        "service_scope": scope,
                        "actor_id": (binding["actor_id"] if binding else
                                     scope["service_actor_id"]),
                        "actor_type": "agent" if binding else "service",
                        "runtime": binding["runtime"] if binding else "service",
                        "role": binding["role"] if binding else "service",
                    })
                return principal
            claimed_actor = self.headers.get("X-Attacca-Actor")
            if claimed_actor and principal.get("actor_type") == "agent":
                # A short runtime hint ("codex") remains compatible with the
                # global connect shim. A dotted/canonical claim must match the
                # exact token-bound actor; merely ending in the same runtime
                # never authorizes a cross-project/role actor override.
                allowed = {principal.get("actor_id"), principal.get("runtime")}
                dotted_override = "." in claimed_actor \
                    and claimed_actor != principal.get("actor_id")
                if dotted_override or (claimed_actor not in allowed and
                        normalize_agent_runtime(
                            actor=claimed_actor) != principal.get("runtime")):
                    raise AuthorizationError(
                        "this API token is bound to %s, not %s"
                        % (principal.get("actor_id"), claimed_actor))
            return principal
        raw_session = self._cookie_value("attacca_session")
        return auth_session_principal(self._conn(), raw_session)

    def _request_project_id(self):
        requested = str(self.headers.get("X-Attacca-Project") or "").strip()
        if requested:
            return requested
        path = urllib.parse.urlparse(self.path).path
        match = re.match(r"^/v1/projects/([^/]+)", path)
        return urllib.parse.unquote(match.group(1)) if match else None

    def _enforce_human_project_membership(self, project_id):
        """Keep a human account inside its explicitly granted workspaces.

        Bound terminal/service/legacy actor credentials have a stricter exact
        scope enforced by their own authentication paths. Browser sessions,
        human API credentials, and provisional setup terminals instead derive
        workspace access from ``auth_project_memberships``.  Server admins are
        the sole account-wide exception.
        """
        principal = getattr(self, "principal", None)
        if not principal or principal.get("is_admin"):
            return
        if principal.get("token_kind") == "service":
            return
        if principal.get("token_kind") == "terminal" \
                and not principal.get("provisional_human"):
            return
        human_principal = bool(
            principal.get("auth_kind") == "session" or
            principal.get("actor_type") == "human" or
            principal.get("provisional_human"))
        if not human_principal:
            return
        if not auth_has_project_membership(
                self._conn(), principal, project_id):
            raise AuthorizationError(
                "project_membership_required: Attacca user '%s' has no access"
                " to workspace '%s'" %
                (principal.get("username"), project_id))

    def _enforce_project_route_membership(self, path):
        match = re.match(r"^/v1/projects/([^/]+)(?:/|$)", path)
        if match:
            self._enforce_human_project_membership(
                urllib.parse.unquote(match.group(1)))

    def _actor(self):
        principal = getattr(self, "principal", None)
        if principal:
            if principal.get("token_kind") == "client":
                actor_id = principal.get("actor_id")
                if actor_id:
                    return actor_id, "agent"
                # Project creation is the only client-key route that has no
                # existing actor yet; attribute that bootstrap mutation to the
                # immutable signed-in human and register the AI afterward.
                return "web.%s" % principal["username"], "human"
            if principal.get("token_kind") == "terminal":
                actor_id = principal.get("actor_id")
                if not actor_id:
                    raise AuthorizationError(
                        "terminal credential requires a workspace actor binding")
                return actor_id, principal.get("actor_type") or "agent"
            if principal.get("token_kind") == "service":
                actor_id = principal.get("actor_id")
                if not actor_id:
                    raise AuthorizationError(
                        "service_scope_required: workspace scope is missing")
                return actor_id, principal.get("actor_type") or "service"
            if principal["auth_kind"] == "token" \
                    and principal.get("actor_type") == "agent":
                return principal["actor_id"], "agent"
            # Browser sessions and human tokens always act as humans. The
            # authenticated username is immutable; raw actor/owner headers
            # must not make an attributed human action look like another
            # account or AI runtime.
            return "web.%s" % principal["username"], "human"
        return (self.headers.get("X-Attacca-Actor") or "api-client",
                self.headers.get("X-Attacca-Actor-Type") or "agent")

    def _request_device_id(self):
        # Schema-v1 sync uses the explicit -ID spelling. Preserve the original
        # header for existing lifecycle/connect clients during migration.
        return (self.headers.get(SYNC_DEVICE_HEADER) or
                self.headers.get(DEVICE_HEADER))

    def _request_audit_device_id(self):
        device_id = str(self._request_device_id() or "").strip() or None
        instance = str(self.headers.get(CLIENT_INSTANCE_HEADER) or "").strip()
        if instance:
            if len(instance) > 120:
                raise AttaccaError("client instance id is too long")
            return "%s/%s" % (device_id or "unknown-device", instance)
        return device_id

    def _enforce_service_route_scope(self, http_method, path):
        """Keep service credentials out of human/account authority.

        An unbound service credential is a read-only workspace integration.
        A credential with an exact registered actor binding may use project or
        MCP routes as that actor, where the normal role checks still apply.
        Server settings, account administration, activation, project creation,
        and full backup export remain unavailable to all service bearers.
        """
        principal = getattr(self, "principal", None)
        if not principal or principal.get("token_kind") != "service":
            return
        method = "GET" if http_method == "HEAD" else http_method
        if method == "GET" and path in (
                "/healthz", "/v1/auth/status", "/v1/projects"):
            return
        if method == "GET" and path == "/v1/managed-law" \
                and principal.get("actor_type") == "agent":
            return
        project_route = re.match(r"^/v1/projects/[^/]+(?:/|$)", path)
        if project_route:
            if path.endswith("/export"):
                raise AuthorizationError(
                    "service_export_denied: full backup export requires a human session")
            if principal.get("actor_type") == "agent":
                return
            if method == "GET":
                return
            raise AuthorizationError(
                "service_actor_binding_required: unbound service credentials"
                " are read-only")
        if path == "/mcp" and principal.get("actor_type") == "agent":
            return
        raise AuthorizationError(
            "service_route_denied: service credentials cannot access account,"
            " server, activation, or project-creation routes")

    def _enforce_client_route_scope(self, http_method, path):
        """Keep client-install keys on AI/project surfaces only."""
        principal = getattr(self, "principal", None)
        if not principal or principal.get("token_kind") != "client":
            return
        method = "GET" if http_method == "HEAD" else http_method
        if method == "GET" and path in (
                "/healthz", "/v1/auth/status", "/v1/projects",
                "/v1/settings"):
            return
        if method == "GET" and path == "/v1/managed-law" \
                and principal.get("actor_type") == "agent":
            return
        if path == "/v1/projects" and method == "POST":
            return
        if re.match(r"^/v1/projects/[^/]+(?:/|$)", path):
            if path.endswith("/export"):
                raise AuthorizationError(
                    "client_export_denied: full export requires browser sign-in")
            if principal.get("actor_type") == "agent":
                return
            if principal.get("client_setup_discovery") and method == "GET" \
                    and re.match(
                        r"^/v1/projects/[^/]+/"
                        r"(?:status|agents|bridges|inbox)$", path):
                return
            if method == "POST" and path.endswith("/agents") \
                    and principal.get("project_id"):
                return
            raise AuthorizationError(
                "client_actor_required: project requests need one exact"
                " registered X-Attacca-Actor")
        if path == "/mcp" and principal.get("actor_type") == "agent":
            return
        raise AuthorizationError(
            "client_key_route_denied: client keys cannot manage accounts,"
            " API keys, invitations, authentication enforcement, or server"
            " settings")

    def _enforce_terminal_route_scope(self, http_method, path):
        """Separate provisional human setup from bound AI authority."""
        principal = getattr(self, "principal", None)
        if not principal or principal.get("token_kind") != "terminal":
            return
        method = "GET" if http_method == "HEAD" else http_method
        provisional = bool(principal.get("provisional_human"))
        if method == "GET" and path in (
                "/healthz", "/v1/auth/status", "/v1/auth/access",
                "/v1/settings", "/v1/projects"):
            return
        if method == "GET" and path == "/v1/managed-law" \
                and not provisional \
                and principal.get("actor_type") == "agent":
            return
        if method == "POST" and path in (
                "/v1/auth/device/start", "/v1/auth/device/poll"):
            return
        if re.match(r"^/v1/auth/terminals/[^/]+/bindings$", path) \
                and method == "POST":
            return
        if re.match(r"^/v1/auth/terminals/[^/]+$", path) \
                and method == "DELETE":
            return
        if path == "/v1/projects" and method == "POST" and provisional:
            return
        project_route = re.match(r"^/v1/projects/[^/]+(?:/(.*))?$", path)
        if project_route:
            if not provisional:
                # Authentication already resolved one exact actor binding for
                # this workspace. The normal role checks remain authoritative.
                return
            suffix = str(project_route.group(1) or "")
            if method == "GET" and (
                    suffix in ("status", "agents", "bridges", "inbox") or
                    suffix.startswith("inbox/")):
                return
            if method == "POST" and suffix == "agents":
                return
            if method == "PUT" and suffix == "lead":
                return
            if suffix == "bridges" and method == "POST":
                return
            if suffix.startswith("bridges/") \
                    and method in ("PUT", "DELETE"):
                return
            raise AuthorizationError(
                "provisional_terminal_setup_only: zero-binding terminals may"
                " only discover/create/register/configure setup identity")
        if path == "/mcp":
            if not provisional and principal.get("actor_type") == "agent":
                return
            raise AuthorizationError(
                "terminal_actor_binding_required: MCP requires an exact actor")
        raise AuthorizationError(
            "terminal_route_denied: terminal credentials cannot access account,"
            " activation, invitation, service-key, or server mutation routes")

    def _trusted_mcp_identity(self, requested_project):
        """Bind one HTTP-MCP request to its authenticated server principal."""
        principal = getattr(self, "principal", None)
        if not principal:
            return {
                "actor": self.headers.get("X-Attacca-Actor"),
                "actor_type": self.headers.get(
                    "X-Attacca-Actor-Type") or "agent",
                "owner": self.headers.get("X-Attacca-Owner"),
                "auth_user_id": None,
                "requested_project": requested_project,
                "authorized_project": None,
            }
        owner = principal["username"]
        if principal.get("token_kind") == "client":
            project = principal.get("project_id")
            actor = principal.get("actor_id")
            if not project or not actor:
                raise AuthorizationError(
                    "client_actor_required: MCP needs a workspace and exact"
                    " registered actor")
            if requested_project and requested_project != project:
                raise AuthorizationError(
                    "client key selected workspace '%s'" % project)
            return {
                "actor": actor,
                "actor_type": "agent",
                "owner": owner,
                "auth_user_id": principal["user_id"],
                "requested_project": project,
                "authorized_project": project,
            }
        if principal.get("token_kind") == "terminal":
            project = principal.get("project_id")
            actor = principal.get("actor_id")
            if not project or not actor:
                raise AuthorizationError(
                    "terminal credential requires one allowed workspace actor binding")
            if requested_project and requested_project != project:
                raise AuthorizationError(
                    "terminal credential selected workspace '%s'" % project)
            return {
                "actor": actor,
                "actor_type": "agent",
                "owner": owner,
                "auth_user_id": principal["user_id"],
                "requested_project": project,
                "authorized_project": project,
            }
        if principal.get("token_kind") == "service":
            project = principal.get("project_id")
            actor = principal.get("actor_id")
            if not project or not actor:
                raise AuthorizationError(
                    "service_scope_required: MCP workspace header is missing")
            return {
                "actor": actor,
                "actor_type": principal.get("actor_type") or "service",
                "owner": owner,
                "auth_user_id": principal["user_id"],
                "requested_project": project,
                "authorized_project": project,
            }
        if principal.get("auth_kind") == "token" \
                and principal.get("actor_type") == "agent":
            project = principal.get("project_id")
            if requested_project and requested_project != project:
                raise AuthorizationError(
                    "this API token is bound to workspace '%s'" % project)
            actor, _role, _row = _authenticated_agent_actor(
                self._conn(), project, principal)
            return {
                "actor": actor,
                "actor_type": "agent",
                "owner": owner,
                "auth_user_id": principal["user_id"],
                "requested_project": project,
                "authorized_project": project,
            }
        # Browser sessions and human API tokens use an immutable actor derived
        # from the authenticated username. Raw actor/owner headers are display
        # hints in legacy anonymous mode only; they cannot impersonate a user.
        return {
            "actor": "web.%s" % owner,
            "actor_type": "human",
            "owner": owner,
            "auth_user_id": principal["user_id"],
            "requested_project": requested_project,
            "authorized_project": None,
        }

    @staticmethod
    def _bind_mcp_session_identity(session, identity, authorized_project,
                                   device_id):
        """Reject a session id replayed under another principal/actor/device."""
        if session.auth_user_id != identity["auth_user_id"]:
            raise AuthorizationError(
                "MCP session belongs to a different authenticated user")
        if session.auth_token_id != identity.get("auth_token_id") \
                or session.auth_token_kind != identity.get("auth_token_kind"):
            raise AuthorizationError(
                "MCP session belongs to a different authenticated credential")
        if session.actor != identity["actor"] \
                or session.actor_type != identity["actor_type"]:
            raise AuthorizationError(
                "MCP session belongs to a different authenticated actor")
        if session.owner != identity["owner"]:
            raise AuthorizationError(
                "MCP session belongs to a different authenticated owner")
        if session.device_id and device_id \
                and session.device_id != device_id:
            raise AuthorizationError(
                "MCP session belongs to a different client device")
        if session.authorized_project and authorized_project \
                and session.authorized_project != authorized_project:
            raise AuthorizationError(
                "MCP session is bound to workspace '%s'" %
                session.authorized_project)
        if not session.device_id and device_id:
            session.device_id = device_id
        if not session.authorized_project and authorized_project:
            session.authorized_project = authorized_project

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
        self.principal = None
        set_current_request_auth_user(active=False)
        try:
            self.principal = self._authenticate_request()
            set_current_request_auth_user(
                self.principal.get("user_id") if self.principal else None,
                active=True)
            public = (path in ("/", "/app", "/app/", "/healthz",
                               "/install.sh", "/plugin.zip",
                               "/plugin/marketplace.json",
                               "/v1/auth/status", "/v1/auth/bootstrap",
                               "/v1/auth/login",
                               "/v1/auth/invitations/accept",
                               "/v1/auth/client-authorizations",
                               "/v1/auth/client-authorizations/poll")
                      or path.startswith("/plugin.git/"))
            if self._auth_enabled() and not public and not self.principal:
                raise AuthenticationError(
                    "client_authorization_required: authenticated credential missing")
            self._enforce_service_route_scope(http_method, path)
            self._enforce_client_route_scope(http_method, path)
            self._enforce_terminal_route_scope(http_method, path)
            self._enforce_project_route_membership(path)
            if self.principal and self.principal.get("project_id"):
                match = re.match(r"^/v1/projects/([^/]+)", path)
                if match and urllib.parse.unquote(match.group(1)) != \
                        self.principal["project_id"]:
                    raise AuthorizationError(
                        "this API token is bound to workspace '%s'"
                        % self.principal["project_id"])
            if self.principal and self.principal["auth_kind"] == "session" \
                    and http_method in ("POST", "PUT", "DELETE") \
                    and path != "/v1/auth/login":
                csrf = self.headers.get("X-Attacca-CSRF") or ""
                if not csrf or not hmac.compare_digest(
                        sha256_hex(csrf), self.principal["csrf_hash"]):
                    raise AuthorizationError(
                        "missing or invalid browser CSRF token; refresh and retry")
            owner = self.principal["username"] if self.principal \
                else self.headers.get("X-Attacca-Owner")
            set_current_owner(owner)
            set_current_git_context(
                self.headers.get(GIT_BRANCH_HEADER),
                self.headers.get(GIT_REVISION_HEADER),
                self._request_audit_device_id())
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
        except AuthenticationError as err:
            message = str(err)
            prefix = message.split(":", 1)[0]
            code = prefix if re.match(r"^[a-z][a-z0-9_]+$", prefix) \
                else "authentication_required"
            self._reply_json(401, {
                "error": message,
                "code": code,
                "login_required": True,
                "api_key_settings_uri": _base_url(self) + "/app#settings",
                "verification_uri": _base_url(self) + "/app#settings",
            },
                             {"WWW-Authenticate": "Bearer"})
        except AuthorizationError as err:
            self._reply_json(403, {"error": str(err)})
        except AttaccaError as err:
            self._reply_json(400, {"error": str(err)})
        except ValueError as err:
            self._reply_json(400, {"error": "bad parameter: %s" % err})
        except BrokenPipeError:
            pass
        except Exception as err:
            sys.stderr.write("attacca serve: internal error: %r\n" % err)
            sys.stderr.flush()
            try:
                self._reply_json(500, {"error": "internal error: %s" % err})
            except Exception:
                pass
        finally:
            set_current_request_auth_user(active=False)

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
        requested_project = self.headers.get("X-Attacca-Project")
        identity = self._trusted_mcp_identity(requested_project)
        principal = getattr(self, "principal", None)
        identity["auth_token_id"] = principal.get("token_id") \
            if principal else None
        identity["auth_token_kind"] = principal.get("token_kind") \
            if principal else None
        actor = identity["actor"]
        actor_type = identity["actor_type"]
        trusted_owner = identity["owner"]
        requested_project = identity["requested_project"]
        # Bearer validation above uses the physical device id. Ledger/session
        # attribution additionally distinguishes multiple client instances on
        # that device.
        device_id = self._request_audit_device_id()
        git_branch_header = self.headers.get(GIT_BRANCH_HEADER)
        git_revision_header = self.headers.get(GIT_REVISION_HEADER)
        is_init = isinstance(msg, dict) and msg.get("method") == "initialize"
        requested_sid = self.headers.get("Mcp-Session-Id")
        setup_required = False
        setup_required_reason = None
        default_project = requested_project or self.server.default_project
        if not default_project and self.headers.get("X-Attacca-Root"):
            try:
                default_project = resolve_or_register_root(
                    self._conn(), self.headers["X-Attacca-Root"],
                    actor or "system",
                    repository_fingerprint=self.headers.get(
                        REPOSITORY_FINGERPRINT_HEADER))
            except AttaccaError as err:
                # Let an unlinked client complete MCP startup and enumerate
                # tools without silently choosing a workspace. Project tools
                # still fail clearly until setup confirms/creates the link.
                recoverable = str(err).startswith((
                    "this checkout is not attached",
                    "this Git repository matches",
                    "checkout path maps to project"))
                if not recoverable or not (is_init or requested_sid):
                    raise
                default_project = None
                setup_required = True
                setup_required_reason = str(err)
        elif default_project:
            try:
                default_project = get_project(
                    self._conn(), default_project)["project_id"]
            except AttaccaError as err:
                # A well-formed checkout link can outlive a server database
                # (deleted workspace, wrong server, restored checkout). Let
                # MCP initialize so the lifecycle hook can offer repair, but
                # never fall back to the server's sole project or auto-create.
                # A broken server default remains an operator error.
                recoverable = requested_project and \
                    str(err).startswith("unknown project ")
                if not recoverable or not (is_init or requested_sid):
                    raise
                default_project = None
                setup_required = True
                setup_required_reason = (
                    "unknown project '%s' on the configured Attacca server "
                    "(saved checkout link)" % requested_project)
        if default_project:
            self._enforce_human_project_membership(default_project)
        preserve_exact_actor = bool(
            actor_type == "agent" and actor and default_project and
            self._conn().execute(
                "SELECT 1 FROM agents WHERE project_id=? AND agent_id=?",
                (default_project, actor)).fetchone())
        authorized_project = identity["authorized_project"]
        if getattr(self, "principal", None) and not authorized_project:
            # Human principals select a workspace through the trusted MCP
            # session/header and cannot switch it later through tool args.
            authorized_project = default_project
        extra_headers = {}
        if is_init:
            session = McpSession(self.server.db_path,
                                 default_project=default_project,
                                 actor=actor, actor_type=actor_type,
                                 detect_cwd=False, owner=trusted_owner,
                                 require_project=setup_required,
                                 setup_required_reason=setup_required_reason,
                                 git_branch_name=git_branch_header,
                                 git_revision=git_revision_header,
                                 device_id=device_id,
                                 auth_user_id=identity["auth_user_id"],
                                 authorized_project=authorized_project,
                                 preserve_actor_identity=preserve_exact_actor,
                                 auth_token_id=identity["auth_token_id"],
                                 auth_token_kind=identity["auth_token_kind"],
                                 release_version=self.server
                                 .distribution_snapshot["version"])
            sid = self.server.create_session(session)
            lock = self.server.get_session(sid)[1]
            extra_headers["Mcp-Session-Id"] = sid
            if default_project:
                extra_headers["X-Attacca-Project"] = default_project
        else:
            sid = requested_sid
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
                # Legacy unauthenticated HTTP-MCP clients commonly send the
                # actor/owner only on initialize.  The session id is their
                # continuity capability, so omitted display headers inherit
                # the already-bound session identity.  Explicitly changing a
                # non-empty value is still rejected below.  Authenticated
                # callers never take this branch: their immutable values came
                # from the verified principal on every request.
                if identity["auth_user_id"] is None:
                    if identity["actor"] is None:
                        identity["actor"] = session.actor
                    if identity["owner"] is None:
                        identity["owner"] = session.owner
                    actor = identity["actor"]
                    trusted_owner = identity["owner"]
            else:
                # Lenient: serve session-less requests with an ephemeral
                # session (loses Drift Guard state, still fully functional).
                session = McpSession(self.server.db_path,
                                     default_project=default_project,
                                     actor=actor, actor_type=actor_type,
                                     detect_cwd=False, owner=trusted_owner,
                                     require_project=setup_required,
                                     setup_required_reason=setup_required_reason,
                                     git_branch_name=git_branch_header,
                                     git_revision=git_revision_header,
                                     device_id=device_id,
                                     auth_user_id=identity["auth_user_id"],
                                     authorized_project=authorized_project,
                                     preserve_actor_identity=preserve_exact_actor,
                                     auth_token_id=identity["auth_token_id"],
                                     auth_token_kind=identity["auth_token_kind"],
                                     release_version=self.server
                                     .distribution_snapshot["version"])
                lock = threading.Lock()
        with lock:
            self._bind_mcp_session_identity(
                session, identity, authorized_project, device_id)
            session.owner = trusted_owner
            # Git headers are optional continuation metadata.  Omitting them
            # must not erase the checkout origin captured at initialize; an
            # explicit empty header may still intentionally clear it.
            if git_branch_header is not None:
                session.git_branch_name = git_branch_header or None
            if git_revision_header is not None:
                session.git_revision = git_revision_header or None
            session.device_id = device_id or session.device_id
            # Setup can write project.json while the client stays open. Adopt
            # that confirmed link on its very next request without requiring
            # another Codex/Claude restart.
            if setup_required:
                session.default_project = None
                session.require_project = True
                session.setup_required_reason = setup_required_reason
            elif default_project and session.default_project != default_project:
                session.default_project = default_project
                session.require_project = False
                session.setup_required_reason = None
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
    snapshot = h.server.distribution_snapshot
    h._reply_json(200, {
        "ok": True,
        "version": snapshot["version"],
        "db": str(h.server.db_path),
        "managed_instructions": {
            "version": snapshot["managed_instructions_version"],
            "sha256": snapshot["managed_instructions_sha256"],
        },
    }, _distribution_headers())


def _base_url(h):
    host = h.headers.get("Host") or "127.0.0.1:%d" % h.server.server_address[1]
    forwarded = (h.headers.get("X-Forwarded-Proto") or "").split(",", 1)[0]
    scheme = "https" if forwarded.strip().lower() == "https" else "http"
    return "%s://%s" % (scheme, host)


def _distribution_base_url(h):
    """Return a shell/JSON-safe canonical origin for download wiring.

    Distribution remains request-origin aware for reverse proxies and hosts
    with several reachable names.  Host is therefore not an authorization
    signal: it only selects deterministic URL substitutions over the server's
    immutable source snapshot.  Strict syntax validation prevents a crafted
    Host header from becoming shell syntax in ``install.sh``.
    """
    host_headers = h.headers.get_all("Host") or []
    if len(host_headers) > 1:
        raise AttaccaError(
            "invalid Host header for distribution URL: expected exactly one")
    raw_host = host_headers[0] if host_headers else None
    if raw_host is None and h.request_version.upper() == "HTTP/1.1":
        raise AttaccaError(
            "invalid Host header for distribution URL: HTTP/1.1 requires one")
    if raw_host is None:
        bound_host, bound_port = h.server.server_address[:2]
        if bound_host in ("0.0.0.0", "::", ""):
            bound_host = "127.0.0.1"
        raw_host = ("[%s]:%d" if ":" in bound_host else "%s:%d") % (
            bound_host, bound_port)
    raw_host = str(raw_host)
    if not raw_host or len(raw_host) > 512 \
            or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127
                   for ch in raw_host):
        raise AttaccaError("invalid Host header for distribution URL")
    parsed = urllib.parse.urlsplit("http://" + raw_host)
    if parsed.path or parsed.query or parsed.fragment \
            or parsed.username is not None or parsed.password is not None \
            or not parsed.hostname:
        raise AttaccaError("invalid Host header for distribution URL")
    try:
        port = parsed.port
    except ValueError:
        raise AttaccaError("invalid Host header port for distribution URL") \
            from None
    host = parsed.hostname
    if ":" in host:
        try:
            socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            raise AttaccaError(
                "invalid IPv6 Host header for distribution URL") from None
        canonical_host = "[%s]" % host.lower()
    else:
        try:
            canonical_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise AttaccaError(
                "invalid Host header for distribution URL") from None
        canonical_host = canonical_host.rstrip(".")
        labels = canonical_host.split(".")
        if len(canonical_host) > 253 or not canonical_host \
                or any(not re.match(
                    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", label)
                    for label in labels):
            raise AttaccaError("invalid Host header for distribution URL")
    forwarded_headers = h.headers.get_all("X-Forwarded-Proto") or []
    if len(forwarded_headers) > 1:
        raise AttaccaError(
            "invalid X-Forwarded-Proto header for distribution URL")
    forwarded = (forwarded_headers[0] if forwarded_headers else "").split(
        ",", 1)[0]
    scheme = "https" if forwarded.strip().lower() == "https" else "http"
    default_port = (scheme == "http" and port == 80) \
        or (scheme == "https" and port == 443)
    netloc = canonical_host if port is None or default_port \
        else "%s:%d" % (canonical_host, port)
    return "%s://%s" % (scheme, netloc)


def _reply_bytes(h, code, content_type, data, download_name=None,
                 headers=None):
    h._drain_body()
    h.send_response(code)
    h.send_header("Content-Type", content_type)
    h.send_header("Content-Length", str(len(data)))
    if download_name:
        h.send_header("Content-Disposition",
                      'attachment; filename="%s"' % download_name)
    for key, value in (headers or {}).items():
        h.send_header(key, value)
    h.end_headers()
    if h.command != "HEAD":
        h.wfile.write(data)


def _distribution_headers(headers=None):
    result = {
        # These fixed URLs intentionally change only when a new server starts.
        # Never let a proxy pair an old installer/HEAD with a new ZIP/repo.
        "Cache-Control": "no-store, max-age=0",
        "Pragma": "no-cache",
    }
    result.update(headers or {})
    # Host is already part of an HTTP cache key; forwarded scheme is not.
    result["Vary"] = "X-Forwarded-Proto"
    return result


def _r_landing(h, m, q):
    snapshot = h.server.distribution_snapshot
    page = (snapshot["landing_template"]
            .replace(b"__VERSION__", snapshot["version"].encode("utf-8"))
            .replace(b"__BASE__", _distribution_base_url(h).encode("utf-8")))
    _reply_bytes(h, 200, "text/html; charset=utf-8", page,
                 headers=_distribution_headers())


def _r_app(h, m, q):
    snapshot = h.server.distribution_snapshot
    page = (snapshot["app_template"]
            .replace(b"__VERSION__", snapshot["version"].encode("utf-8"))
            .replace(b"__BASE__", _distribution_base_url(h).encode("utf-8")))
    _reply_bytes(
        h, 200, "text/html; charset=utf-8", page,
        headers=_distribution_headers({
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache"}))


def _r_install_sh(h, m, q):
    snapshot = h.server.distribution_snapshot
    _reply_bytes(h, 200, "text/x-shellscript; charset=utf-8",
                 snapshot["install_template"].format(
                     base=_distribution_base_url(h),
                     version=snapshot["version"],
                     required_files=repr(
                         list(snapshot["plugin_files"]))).encode(),
                 headers=_distribution_headers())


def _r_plugin_zip(h, m, q):
    snapshot = h.server.distribution_snapshot
    _reply_bytes(h, 200, "application/zip", build_plugin_zip(
        _distribution_base_url(h),
        source_snapshot=snapshot["plugin_sources"],
        plugin_files=snapshot["plugin_files"],
        mcp_config_files=snapshot["plugin_mcp_config_files"],
        zip_date_time=snapshot["plugin_zip_date_time"]),
                 download_name="attacca-plugin.zip",
                 headers=_distribution_headers())


def _r_marketplace_json(h, m, q):
    """Marketplace manifest for URL installs: the plugin source is this
    server's own git-over-HTTP endpoint, so `/plugin marketplace add <url>`
    followed by `/plugin install attacca@agentg` works natively."""
    base = _distribution_base_url(h)
    manifest = {
        "name": "agentg",
        "owner": {"name": "agentg"},
        "plugins": [{
            "name": "attacca",
            # Valid but version-gated in Claude Code: newer versions install
            # straight from this URL marketplace; older ones use /install.sh.
            "source": {"source": "git", "url": base + "/plugin.git"},
            "description": "Shared project memory for AI coding tools: "
                           "ledger, task claims, decisions, room, and "
                           "cold-start handoffs.",
        }],
    }
    _reply_bytes(h, 200, "application/json",
                 (json.dumps(manifest, indent=2) + "\n").encode(),
                 headers=_distribution_headers())


_GIT_REPO_LOCK = threading.Lock()
_PLUGIN_GIT_COMMIT_DATE = "2000-01-01T00:00:00+00:00"
_MAX_DISTRIBUTION_GIT_REPOS = 8


def ensure_plugin_git_repo(base_url, cache_root, plugin_blob=None,
                           version=None):
    """Build and atomically publish a deterministic bare plugin repository.

    The process lock avoids duplicate work between request threads; the one
    cache-root lock file provides the same exclusion to multiple processes.
    Publication is a same-filesystem rename, so a crash never exposes a half
    cloned repository at its content-addressed path.
    """
    blob = build_plugin_zip(base_url) if plugin_blob is None else plugin_blob
    release_version = VERSION if version is None else str(version)
    bundle_hash = hashlib.sha256(blob).hexdigest()
    key = sha256_hex("%s\0%s\0%s" % (
        base_url, release_version, bundle_hash))[:20]
    plugin_root = Path(cache_root) / "plugin-git"
    repo = plugin_root / key / "plugin.git"
    with _GIT_REPO_LOCK:
        plugin_root.mkdir(parents=True, exist_ok=True)
        lock_handle = (plugin_root / ".build.lock").open("a+b")
        try:
            if fcntl is not None:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            if (repo / "info" / "refs").is_file():
                return repo
            # Only a pre-atomic/crashed older build can leave this path.  The
            # cross-process lock makes its exact removal safe.
            if repo.parent.exists():
                shutil.rmtree(repo.parent)
            work = Path(tempfile.mkdtemp(prefix="attacca-plugin-work-"))
            staging = Path(tempfile.mkdtemp(
                prefix=".%s-" % key, dir=str(plugin_root)))
            staging_repo = staging / "plugin.git"
            try:
                zipfile.ZipFile(io.BytesIO(blob)).extractall(work)
                git = ["git", "-c", "user.name=attacca",
                       "-c", "user.email=attacca@localhost",
                       "-c", "commit.gpgSign=false",
                       "-c", "core.autocrlf=false",
                       "-c", "core.hooksPath=" + os.devnull]
                # Git has many environment overrides (GIT_DIR, index/object
                # paths, GIT_CONFIG_COUNT, identity fields).  None are valid
                # inputs to a release artifact; retain ordinary process state
                # such as PATH while rebuilding the complete Git namespace.
                git_env = {
                    key: value for key, value in os.environ.items()
                    if not key.startswith("GIT_")
                }
                git_env.update({
                    "GIT_AUTHOR_NAME": "attacca",
                    "GIT_AUTHOR_EMAIL": "attacca@localhost",
                    "GIT_AUTHOR_DATE": _PLUGIN_GIT_COMMIT_DATE,
                    "GIT_COMMITTER_NAME": "attacca",
                    "GIT_COMMITTER_EMAIL": "attacca@localhost",
                    "GIT_COMMITTER_DATE": _PLUGIN_GIT_COMMIT_DATE,
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_ATTR_NOSYSTEM": "1",
                    "TZ": "UTC",
                })
                subprocess.run(
                    git + ["-C", str(work), "init", "-q"],
                    check=True, env=git_env)
                subprocess.run(
                    git + ["-C", str(work), "symbolic-ref", "HEAD",
                           "refs/heads/main"], check=True, env=git_env)
                subprocess.run(git + ["-C", str(work), "add", "-A"],
                               check=True, env=git_env)
                subprocess.run(
                    git + ["-C", str(work), "commit", "-q", "-m",
                           "attacca plugin (wired to %s)" % base_url],
                    check=True, env=git_env)
                subprocess.run(
                    ["git", "clone", "-q", "--bare", str(work),
                     str(staging_repo)], check=True, env=git_env)
                subprocess.run(
                    ["git", "-C", str(staging_repo),
                     "update-server-info"], check=True, env=git_env)
                try:
                    os.replace(str(staging), str(repo.parent))
                except OSError:
                    # On platforms without flock, another process may have
                    # atomically won the same publication race.
                    if not (repo / "info" / "refs").is_file():
                        raise
                return repo
            finally:
                shutil.rmtree(work, ignore_errors=True)
                shutil.rmtree(staging, ignore_errors=True)
        finally:
            if fcntl is not None:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            lock_handle.close()


def _server_plugin_git_repo(server, base_url, plugin_blob):
    """Return one repo from a bounded, process-lifetime Host-aware LRU."""
    repos = server._distribution_git_repos
    if server._distribution_cache_root is None:
        server._distribution_cache_root = Path(tempfile.mkdtemp(
            prefix="attacca-distribution-"))
    repo = repos.pop(base_url, None)
    if repo is None or not (repo / "info" / "refs").is_file():
        repo = ensure_plugin_git_repo(
            base_url, server._distribution_cache_root,
            plugin_blob=plugin_blob,
            version=server.distribution_snapshot["version"])
    repos[base_url] = repo
    while len(repos) > _MAX_DISTRIBUTION_GIT_REPOS:
        evicted_base = next(iter(repos))
        evicted_repo = repos.pop(evicted_base)
        if evicted_repo != repo:
            shutil.rmtree(evicted_repo.parent, ignore_errors=True)
    return repo


def _r_plugin_git(h, m, q):
    """Serve the bare plugin repo statically (git dumb-HTTP protocol)."""
    try:
        snapshot = h.server.distribution_snapshot
        base = _distribution_base_url(h)
        blob = build_plugin_zip(
            base, source_snapshot=snapshot["plugin_sources"],
            plugin_files=snapshot["plugin_files"],
            mcp_config_files=snapshot["plugin_mcp_config_files"],
            zip_date_time=snapshot["plugin_zip_date_time"])
        with h.server._distribution_git_lock:
            repo = _server_plugin_git_repo(h.server, base, blob)
            rel = m.group(1) or "HEAD"
            target = (repo / rel).resolve()
            if repo.resolve() not in target.parents and target != repo.resolve():
                h._reply_json(403, {"error": "forbidden"},
                              _distribution_headers())
                return
            if not target.is_file():
                h._reply_json(404, {"error": "not found: %s" % rel},
                              _distribution_headers())
                return
            data = target.read_bytes()
    except (subprocess.CalledProcessError, OSError) as err:
        h._reply_json(
            501, {"error": "git unavailable on the server: %s" % err},
            _distribution_headers())
        return
    _reply_bytes(h, 200, "application/octet-stream", data,
                 headers=_distribution_headers())


def _auth_cookie_headers(session=None, clear=False, secure=False):
    """Return the two same-site browser cookies used by the prototype UI."""
    secure_flag = "; Secure" if secure else ""
    if clear:
        expired = "Path=/; Max-Age=0; SameSite=Strict%s" % secure_flag
        return ["attacca_session=; HttpOnly; %s" % expired,
                "attacca_csrf=; %s" % expired]
    max_age = SESSION_HOURS * 60 * 60
    return [
        "attacca_session=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict%s"
        % (session["session"], max_age, secure_flag),
        "attacca_csrf=%s; Path=/; Max-Age=%d; SameSite=Strict%s"
        % (session["csrf"], max_age, secure_flag),
    ]


def _auth_status_payload(h):
    principal = getattr(h, "principal", None)
    enabled = h._auth_enabled()
    bootstrapped = auth_is_enabled(h._conn())
    readiness = auth_activation_readiness(
        h._conn(), server=h.server, include_details=False)
    result = {
        "authentication_required": enabled,
        "authentication_mode": h.server.auth_mode,
        "compatibility_active": h._compatibility_active(),
        "effective_authentication": readiness["effective_authentication"],
        "activation_requested": readiness["activation_requested"],
        "authentication_activated": readiness["activated"],
        "activation_ready": readiness["ready"],
        "readiness_version": readiness["readiness_version"],
        "readiness_blockers": readiness["blockers"],
        "bootstrapped": bootstrapped,
        # The API remains backward-compatible before the first account, but
        # /app deliberately stops here so the owner creates that account
        # before the panel reads any workspace data.
        "bootstrap_required": not bootstrapped,
        "bootstrap_available": not bootstrapped,
        "authenticated": bool(principal),
        "user": None,
        "principal": None,
        "csrf_token": None,
        "api_key_required": bool(enabled and not principal),
        "terminal_enrollment_required": False,
        "credential_policy": {
            "client_api_key": "supported",
            "browser_session": "supported",
            "terminal": "retired",
            "legacy_actor": ("disabled" if enabled else "migration_only"),
            "new_actor_tokens": False,
            "actor_bound_keys": False,
        },
    }
    if not principal:
        return result
    row = h._conn().execute(
        "SELECT * FROM auth_users WHERE user_id=?", (principal["user_id"],)
    ).fetchone()
    result["user"] = _public_auth_user(row) if row else {
        "user_id": principal["user_id"],
        "username": principal["username"],
        "is_admin": bool(principal["is_admin"]),
    }
    result["user"]["is_owner"] = bool(principal.get("is_owner"))
    result["principal"] = {key: principal.get(key) for key in (
        "auth_kind", "token_kind", "token_id", "actor_id", "actor_type",
        "project_id", "runtime", "device_id", "client_label",
        "client_instance", "expires_at", "is_admin", "is_owner")}
    if principal.get("token_kind") == "client":
        result["principal"]["project_memberships"] = \
            auth_token_project_bindings(h._conn(), principal["token_id"])
    elif principal.get("token_kind") == "terminal":
        result["principal"]["bindings"] = auth_terminal_bindings(
            h._conn(), principal["token_id"])
    elif principal.get("token_kind") == "service":
        result["principal"]["project_memberships"] = \
            auth_token_project_bindings(h._conn(), principal["token_id"])
        result["principal"]["bindings"] = auth_terminal_bindings(
            h._conn(), principal["token_id"])
    if principal.get("auth_kind") == "session":
        csrf = h._cookie_value("attacca_csrf")
        if csrf and hmac.compare_digest(
                sha256_hex(csrf), principal.get("csrf_hash") or ""):
            result["csrf_token"] = csrf
    return result


def _reply_auth_session(h, code, session):
    payload = _auth_status_payload(h)
    # _auth_status_payload sees the request's old principal.  Return the newly
    # authenticated account explicitly; the next request resolves the cookie.
    payload.update({"authenticated": True, "bootstrap_required": False,
                    "user": session["user"],
                    "principal": {"auth_kind": "session",
                                  "actor_id": None,
                                  "actor_type": "human",
                                  "project_id": None,
                                  "runtime": None},
                    "csrf_token": session["csrf"]})
    h._reply_json(code, payload,
                  {"Set-Cookie": _auth_cookie_headers(
                      session=session,
                      secure=_base_url(h).startswith("https://")),
                   "Cache-Control": "no-store"})


def _require_auth_session(h):
    principal = getattr(h, "principal", None)
    if not principal:
        raise AuthenticationError(
            "browser_session_required: authenticated browser session missing")
    if principal.get("auth_kind") != "session":
        raise AuthorizationError(
            "browser_session_required: bearer credentials cannot manage accounts")
    return principal


def _require_admin_session(h):
    principal = _require_auth_session(h)
    if not principal.get("is_admin"):
        raise AuthorizationError("administrator access required")
    return principal


def _require_owner_session(h):
    principal = _require_admin_session(h)
    if not principal.get("is_owner"):
        raise AuthorizationError("server_owner_required: owner access required")
    return principal


def _r_auth_status(h, m, q):
    h._reply_json(200, _auth_status_payload(h), {"Cache-Control": "no-store"})


def _r_auth_bootstrap(h, m, q):
    if auth_is_enabled(h._conn()):
        raise AttaccaError("authentication is already bootstrapped; sign in")
    body = h._body_json()
    created = auth_create_user(
        h._conn(), body.get("username"), body.get("password"),
        display_name=body.get("display_name"), is_admin=True, bootstrap=True)
    row = h._conn().execute(
        "SELECT * FROM auth_users WHERE user_id=?",
        (created["user"]["user_id"],)).fetchone()
    _reply_auth_session(h, 201, auth_create_session(h._conn(), row))


def _r_auth_login(h, m, q):
    body = h._body_json()
    row = auth_verify_user(
        h._conn(), body.get("username"), body.get("password"))
    if not row:
        raise AuthenticationError("invalid username or password")
    _reply_auth_session(h, 200, auth_create_session(h._conn(), row))


def _r_auth_logout(h, m, q):
    principal = _require_auth_session(h)
    auth_logout_session(h._conn(), principal.get("session_hash"))
    h._reply_json(200, {"ok": True, "authenticated": False},
                  {"Set-Cookie": _auth_cookie_headers(
                      clear=True, secure=_base_url(h).startswith("https://")),
                   "Cache-Control": "no-store"})


def _r_auth_tokens_list(h, m, q):
    principal = _require_auth_session(h)
    h._reply_json(200, auth_token_list(h._conn(), principal["username"]),
                  {"Cache-Control": "no-store"})


def _r_auth_tokens_create(h, m, q):
    principal = _require_auth_session(h)
    body = h._body_json()
    actor_type = body.get("actor_type") or "agent"
    if actor_type == "agent":
        if h._auth_enabled() or h.server.auth_mode != "compatibility" \
                or body.get("legacy_migration") is not True:
            raise AuthorizationError(
                "actor_token_creation_disabled: create a client API key in"
                " Attacca Settings")
    h._reply_json(201, auth_token_create(
        h._conn(), principal["username"], body.get("label"),
        actor_id=body.get("actor_id"),
        actor_type=actor_type,
        project_id=body.get("project_id"), runtime=body.get("runtime"),
        expires_at=body.get("expires_at")), {"Cache-Control": "no-store"})


def _r_auth_tokens_revoke(h, m, q):
    principal = _require_auth_session(h)
    h._reply_json(200, auth_token_revoke(
        h._conn(), principal["username"], m.group(1)),
        {"Cache-Control": "no-store"})


def _r_auth_device_start(h, m, q):
    body = h._body_json()
    h._reply_json(201, auth_device_start(
        h._conn(), _base_url(h), body.get("device_id"),
        body.get("client_label"), body.get("requested_bindings"),
        client_instance=(body.get("client_instance") or
                         h.headers.get(CLIENT_INSTANCE_HEADER)),
        supersede_token_id=body.get("supersede_token_id"),
        principal=getattr(h, "principal", None)),
        {"Cache-Control": "no-store"})


def _r_auth_device_poll(h, m, q):
    body = h._body_json()
    h._reply_json(200, auth_device_poll(
        h._conn(), body.get("device_code"), body.get("device_id"),
        client_instance=(body.get("client_instance") or
                         h.headers.get(CLIENT_INSTANCE_HEADER))),
        {"Cache-Control": "no-store"})


def _r_auth_access(h, m, q):
    principal = getattr(h, "principal", None)
    # Terminal tokens receive their own no-secret metadata from auth/status;
    # account-wide enrollment/migration data is browser-session only.
    if principal and principal.get("auth_kind") != "session":
        principal = None
    h._reply_json(200, auth_access_payload(
        h._conn(), principal=principal, server=h.server),
        {"Cache-Control": "no-store"})


def _r_auth_terminal_enrollments(h, m, q):
    principal = _require_admin_session(h)
    payload = auth_access_payload(
        h._conn(), principal=principal, server=h.server)
    h._reply_json(200, {
        "terminal_enrollments": payload["terminal_enrollments"],
        "terminals": payload["terminals"],
    }, {"Cache-Control": "no-store"})


def _r_auth_terminal_enrollment_get(h, m, q):
    # The verification URI carries one exact short-lived user code. Any
    # authenticated human may inspect that one request so a non-admin can
    # approve their own preassigned actors/memberships without gaining an
    # account-wide enrollment inventory.
    _require_auth_session(h)
    row = _auth_device_row(h._conn(), urllib.parse.unquote(m.group(1)))
    try:
        requested = json.loads(row["requested_bindings"] or "[]")
    except ValueError:
        requested = []
    h._reply_json(200, {
        "user_code": row["user_code"], "status": row["status"],
        "device_id": row["device_id"], "client_label": row["client_label"],
        "client_instance": row["client_instance"],
        "requested_bindings": requested,
        "created_at": row["created_at"], "expires_at": row["expires_at"],
    }, {"Cache-Control": "no-store"})


def _r_auth_terminal_enrollment_start(h, m, q):
    # Browser and AI helpers use the same public device-start contract.
    _r_auth_device_start(h, m, q)


def _r_auth_terminal_enrollment_approve(h, m, q):
    principal = _require_auth_session(h)
    body = h._body_json()
    h._reply_json(200, auth_device_approve(
        h._conn(), urllib.parse.unquote(m.group(1)), principal,
        body.get("project_memberships"), body.get("actor_bindings"),
        expires_at=body.get("expires_at")), {"Cache-Control": "no-store"})


def _r_auth_terminal_enrollment_deny(h, m, q):
    principal = _require_admin_session(h)
    h._reply_json(200, auth_device_deny(
        h._conn(), urllib.parse.unquote(m.group(1)), principal),
        {"Cache-Control": "no-store"})


def _r_auth_terminal_revoke(h, m, q):
    principal = _require_auth_session(h)
    token_id = urllib.parse.unquote(m.group(1))
    row = h._conn().execute(
        "SELECT * FROM auth_tokens WHERE token_id=? AND token_kind='terminal'",
        (token_id,)).fetchone()
    if not row or (row["user_id"] != principal["user_id"]
                   and not principal.get("is_admin")):
        raise AuthorizationError("terminal credential is not owned by this user")
    with write_tx(h._conn()):
        h._conn().execute(
            "UPDATE auth_tokens SET revoked_at=? WHERE token_id=?"
            " AND revoked_at IS NULL", (now_iso(), token_id))
        h._conn().execute(
            "UPDATE auth_token_actor_bindings SET revoked_at=?"
            " WHERE token_id=? AND revoked_at IS NULL", (now_iso(), token_id))
    h._reply_json(200, {"ok": True, "token_id": token_id, "revoked": True},
                  {"Cache-Control": "no-store"})


def _r_auth_terminal_add_binding(h, m, q):
    principal = getattr(h, "principal", None)
    if not principal or principal.get("auth_kind") not in ("session", "token"):
        raise AuthenticationError(
            "terminal_or_browser_session_required: binding principal missing")
    if principal.get("auth_kind") == "token" \
            and principal.get("token_kind") != "terminal":
        raise AuthorizationError(
            "terminal_or_browser_session_required: wrong credential kind")
    body = h._body_json()
    h._reply_json(200, auth_terminal_add_binding(
        h._conn(), principal, urllib.parse.unquote(m.group(1)),
        body.get("project_id"), body.get("actor_id")),
        {"Cache-Control": "no-store"})


def _r_auth_service_keys(h, m, q):
    principal = _require_auth_session(h)
    payload = auth_access_payload(
        h._conn(), principal=principal, server=h.server)
    h._reply_json(200, {"service_keys": payload["service_keys"]},
                  {"Cache-Control": "no-store"})


def _r_auth_service_key_create(h, m, q):
    principal = _require_auth_session(h)
    body = h._body_json()
    h._reply_json(201, auth_service_key_create(
        h._conn(), principal, body.get("label"),
        body.get("project_memberships") or [],
        bindings=body.get("actor_bindings") or [],
        expires_at=body.get("expires_at")), {"Cache-Control": "no-store"})


def _r_auth_service_key_revoke(h, m, q):
    principal = _require_auth_session(h)
    h._reply_json(200, auth_service_key_revoke(
        h._conn(), principal, urllib.parse.unquote(m.group(1))),
        {"Cache-Control": "no-store"})


def _r_auth_invitations(h, m, q):
    principal = _require_admin_session(h)
    payload = auth_access_payload(
        h._conn(), principal=principal, server=h.server)
    h._reply_json(200, {"invitations": payload["invitations"]},
                  {"Cache-Control": "no-store"})


def _r_auth_client_keys(h, m, q):
    principal = _require_auth_session(h)
    h._reply_json(200, {
        "client_keys": auth_client_key_list(h._conn(), principal)},
        {"Cache-Control": "no-store"})


def _r_auth_client_key_create(h, m, q):
    principal = _require_auth_session(h)
    body = h._body_json()
    h._reply_json(201, auth_client_key_create(
        h._conn(), principal, body.get("label"),
        body.get("client_instance"),
        memberships=body.get("project_memberships"),
        expires_at=body.get("expires_at"),
        device_id=body.get("device_id")), {"Cache-Control": "no-store"})


def _r_auth_client_key_revoke(h, m, q):
    principal = _require_auth_session(h)
    h._reply_json(200, auth_client_key_revoke(
        h._conn(), principal, urllib.parse.unquote(m.group(1))),
        {"Cache-Control": "no-store"})


def _r_auth_client_key_delete(h, m, q):
    principal = _require_auth_session(h)
    h._reply_json(200, auth_client_key_delete(
        h._conn(), principal, urllib.parse.unquote(m.group(1))),
        {"Cache-Control": "no-store"})


def _r_auth_client_pairing_start(h, m, q):
    body = h._body_json()
    h._reply_json(201, auth_client_pairing_start(
        h._conn(), _base_url(h), body.get("client_instance"),
        body.get("label"), device_id=body.get("device_id")),
        {"Cache-Control": "no-store"})


def _r_auth_client_pairing_poll(h, m, q):
    body = h._body_json()
    h._reply_json(200, auth_client_pairing_poll(
        h._conn(), body.get("poll_secret"), body.get("client_instance"),
        device_id=body.get("device_id")), {"Cache-Control": "no-store"})


def _auth_pairing_lookup_throttle_key(h, principal):
    address = h.client_address[0] if getattr(h, "client_address", None) else ""
    return "%s|%s" % (principal.get("user_id") or "", address)


def _auth_pairing_lookup_check(key):
    cutoff = time.monotonic() - _PAIRING_LOOKUP_WINDOW_SECONDS
    with _PAIRING_LOOKUP_FAILURES_LOCK:
        # Opportunistic bounded pruning prevents attacker-selected source keys
        # from growing process memory without limit.
        if len(_PAIRING_LOOKUP_FAILURES) > 4096:
            for existing in list(_PAIRING_LOOKUP_FAILURES):
                recent = [stamp for stamp in
                          _PAIRING_LOOKUP_FAILURES[existing]
                          if stamp >= cutoff]
                if recent:
                    _PAIRING_LOOKUP_FAILURES[existing] = recent
                else:
                    _PAIRING_LOOKUP_FAILURES.pop(existing, None)
        failures = [stamp for stamp in _PAIRING_LOOKUP_FAILURES.get(key, [])
                    if stamp >= cutoff]
        _PAIRING_LOOKUP_FAILURES[key] = failures
        if len(failures) >= _PAIRING_LOOKUP_MAX_FAILURES:
            raise AuthorizationError(
                "client_pairing_lookup_throttled: wait before retrying")


def _auth_pairing_lookup_failed(key):
    with _PAIRING_LOOKUP_FAILURES_LOCK:
        _PAIRING_LOOKUP_FAILURES.setdefault(key, []).append(time.monotonic())


def _auth_pairing_lookup_succeeded(key):
    with _PAIRING_LOOKUP_FAILURES_LOCK:
        _PAIRING_LOOKUP_FAILURES.pop(key, None)


def _r_auth_client_pairing_get(h, m, q):
    principal = _require_auth_session(h)
    body = h._body_json()
    key = _auth_pairing_lookup_throttle_key(h, principal)
    _auth_pairing_lookup_check(key)
    try:
        record = auth_client_pairing_record(
            h._conn(), body.get("authorization_request"))
    except AttaccaError:
        _auth_pairing_lookup_failed(key)
        # One response for malformed and unknown codes avoids a format/existence
        # oracle while the per-account+address limiter bounds guessing.
        raise AttaccaError("client pairing request unavailable")
    _auth_pairing_lookup_succeeded(key)
    h._reply_json(200, record, {"Cache-Control": "no-store"})


def _r_auth_client_pairing_authorize(h, m, q):
    principal = _require_auth_session(h)
    body = h._body_json()
    key = _auth_pairing_lookup_throttle_key(h, principal)
    _auth_pairing_lookup_check(key)
    try:
        result = auth_client_pairing_decide(
            h._conn(), body.get("authorization_request"), principal, True,
            memberships=body.get("project_memberships"))
    except AttaccaError:
        _auth_pairing_lookup_failed(key)
        raise AttaccaError("client pairing request unavailable")
    _auth_pairing_lookup_succeeded(key)
    h._reply_json(200, result, {"Cache-Control": "no-store"})


def _r_auth_client_pairing_deny(h, m, q):
    principal = _require_auth_session(h)
    body = h._body_json()
    key = _auth_pairing_lookup_throttle_key(h, principal)
    _auth_pairing_lookup_check(key)
    try:
        result = auth_client_pairing_decide(
            h._conn(), body.get("authorization_request"), principal, False)
    except AttaccaError:
        _auth_pairing_lookup_failed(key)
        raise AttaccaError("client pairing request unavailable")
    _auth_pairing_lookup_succeeded(key)
    h._reply_json(200, result, {"Cache-Control": "no-store"})


def _r_auth_invitation_create(h, m, q):
    principal = _require_admin_session(h)
    body = h._body_json()
    result = auth_invitation_create(
        h._conn(), principal, body.get("label"),
        body.get("project_memberships") or [],
        expires_at=body.get("expires_at"),
        is_admin=body.get("is_admin") is True)
    result["verification_uri"] = _base_url(h) + "/app#settings"
    h._reply_json(201, result, {"Cache-Control": "no-store"})


def _r_auth_invitation_revoke(h, m, q):
    principal = _require_admin_session(h)
    h._reply_json(200, auth_invitation_revoke(
        h._conn(), principal, urllib.parse.unquote(m.group(1))),
        {"Cache-Control": "no-store"})


def _r_auth_invitation_accept(h, m, q):
    body = h._body_json()
    result = auth_invitation_accept(
        h._conn(), body.get("invitation_token"), body.get("username"),
        body.get("password"), display_name=body.get("display_name"))
    # Acceptance creates the invitee's own account; it never issues an
    # inviter/admin bearer.  The invitee can now establish a normal browser
    # session without reusing or exposing the consumed invitation secret.
    result.update({"login_required": True,
                   "login_endpoint": "/v1/auth/login"})
    h._reply_json(201, result, {"Cache-Control": "no-store"})


def _r_auth_migration_scope(h, m, q):
    principal = _require_owner_session(h)
    body = h._body_json()
    result = auth_migration_scope_update(
        h._conn(), principal, body.get("required_clients") or [],
        body.get("exclusions") or [], body.get("expected_readiness_version"),
        server=h.server)
    result["compatibility"] = auth_activation_readiness(
        h._conn(), server=h.server)
    h._reply_json(200, result, {"Cache-Control": "no-store"})


def _r_auth_activation(h, m, q):
    principal = _require_owner_session(h)
    body = h._body_json()
    result = auth_activate(
        h._conn(), principal, body.get("confirmed"),
        body.get("expected_readiness_version"), server=h.server,
        enabled=body.get("enabled", True))
    h.server.auth_requested = bool(result["activated"])
    h._reply_json(200, result, {"Cache-Control": "no-store"})


def _r_projects_list(h, m, q):
    result = list_projects(h._conn())
    principal = getattr(h, "principal", None)
    allowed = auth_visible_project_ids(h._conn(), principal)
    if allowed is not None:
        result["projects"] = [project for project in result["projects"]
                              if project["project_id"] in allowed]
    h._reply_json(200, result)


def _r_projects_create(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    principal = getattr(h, "principal", None)
    account_creation = bool(principal and (
        principal.get("actor_type") == "human" or
        principal.get("token_kind") == "client"))
    if principal and principal.get("project_id") \
            and body.get("project_id") != principal["project_id"]:
        raise AuthorizationError(
            "this API token is bound to workspace '%s'" %
            principal["project_id"])
    known_projects = {row["project_id"] for row in h._conn().execute(
        "SELECT project_id FROM projects")}
    explicit = str(body.get("project_id") or "").strip()
    matched = _project_for_repository(
        h._conn(), _validated_repository_fingerprint(
            body.get("repository_fingerprint")))
    preexisting_target = explicit if explicit in known_projects else matched
    if account_creation \
            and preexisting_target \
            and not auth_has_project_membership(
                h._conn(), principal, preexisting_target):
        raise AuthorizationError(
            "project_membership_required: existing workspace access denied")
    result = _api_project_init(h._conn(), actor, atype, body)
    if account_creation:
        has_access = auth_has_project_membership(
            h._conn(), principal, result["project_id"])
        if result.get("already_existed") and not has_access:
            # Close the check-then-create race: another account may have won
            # the same project id after ``known_projects`` was read.  A losing
            # create request is an attach to the winner's workspace, not a
            # membership grant.
            raise AuthorizationError(
                "project_membership_required: concurrently created workspace"
                " access denied")
        if not result.get("already_existed") and not has_access:
            # Fallback for a future project backend that cannot use the
            # creation-transaction helper; current human creation paths grant
            # atomically before returning.
            auth_grant_project_membership(
                h._conn(), principal, result["project_id"])
    h._reply_json(200, result)


def _settings_payload(h):
    snapshot = h.server.distribution_snapshot
    base = _distribution_base_url(h)
    return {
        "version": snapshot["version"],
        "server_url": base,
        "database": str(h.server.db_path),
        "default_project": h.server.default_project,
        "verbose": bool(h.server.verbose),
        "update_interval_seconds": h.server.update_interval_seconds,
        "authentication": h._auth_enabled(),
        "auth_bootstrapped": auth_is_enabled(h._conn()),
        "installer": "curl -fsSL %s/install.sh | sh" % base,
        "client_authorization": {
            "api_keys_endpoint": "/v1/auth/client-keys",
            "sign_in_uri": base + "/app#settings",
            "credential_model": "browser-session-or-client-api-key",
        },
    }


def _r_settings_get(h, m, q):
    h._reply_json(200, _settings_payload(h), _distribution_headers())


def _r_settings_put(h, m, q):
    # Once the owner explicitly activates authentication, global runtime
    # settings are server governance rather than ordinary project work. Keep
    # compatibility mode behavior unchanged until that deliberate flip.
    if h._auth_enabled():
        _require_owner_session(h)
    body = h._body_json()
    allowed = {"default_project", "verbose", "update_interval_seconds"}
    unknown = set(body) - allowed
    if unknown:
        raise AttaccaError("unknown runtime setting(s): %s" %
                           ", ".join(sorted(unknown)))
    persisted = {}
    if "default_project" in body:
        value = str(body.get("default_project") or "").strip() or None
        if value:
            value = get_project(h._conn(), value)["project_id"]
        h.server.default_project = value
        persisted["default_project"] = value
    if "verbose" in body:
        if not isinstance(body["verbose"], bool):
            raise AttaccaError("verbose must be true or false")
        h.server.verbose = body["verbose"]
        persisted["verbose"] = body["verbose"]
    if "update_interval_seconds" in body:
        try:
            interval = int(body["update_interval_seconds"])
        except (TypeError, ValueError):
            raise AttaccaError("update_interval_seconds must be an integer")
        if interval != 0 and not 60 <= interval <= 3600:
            raise AttaccaError(
                "update_interval_seconds must be 0 (off) or 60..3600")
        h.server.update_interval_seconds = interval
        persisted["update_interval_seconds"] = interval
    if persisted:
        server_settings_store(h._conn(), persisted)
    h._reply_json(200, _settings_payload(h), _distribution_headers())


def _r_project_status(h, m, q):
    actor, atype = h._actor()
    h._reply_json(200, project_status(
        h._conn(), m.group(1), actor, atype, h.server.db_path))


def _project_export_owner_usernames(conn, project):
    """Return authenticated usernames proven to have created the project."""
    project_id = project["project_id"]
    owners = {
        row["owner"] for row in conn.execute(
            "SELECT DISTINCT owner FROM events WHERE project_id=?"
            " AND event_type='project.created' AND owner IS NOT NULL",
            (project_id,))
        if row["owner"]
    }
    created_by = str(project.get("created_by") or "").strip()
    if created_by:
        owners.add(created_by)
        if created_by.startswith("web."):
            owners.add(created_by[4:])
        human_prefix = "%s.human." % project_id
        if created_by.startswith(human_prefix):
            owners.add(created_by[len(human_prefix):])
    return owners


def _require_project_export_access(h, project):
    """Full backup data is restricted to a human owner or server admin."""
    principal = getattr(h, "principal", None)
    if not principal:
        raise AuthenticationError(
            "full project export: Attacca login required (or use a human API"
            " token)")
    if principal.get("auth_kind") == "token" \
            and principal.get("actor_type") != "human":
        raise AuthorizationError(
            "agent API tokens cannot download full project backups; use an "
            "authenticated human account")
    if principal.get("is_admin"):
        return principal
    username = principal.get("username")
    if username not in _project_export_owner_usernames(h._conn(), project):
        raise AuthorizationError(
            "Attacca user '%s' is not the owner of workspace '%s'; a project "
            "owner or server admin must download its full backup" %
            (username, project["project_id"]))
    return principal


def _r_project_export(h, m, q):
    # Authenticate before resolving the id so anonymous callers cannot probe
    # private workspace names through the backup endpoint.
    if not getattr(h, "principal", None):
        raise AuthenticationError(
            "full project export: Attacca login required (or use a human API"
            " token)")
    project_id = m.group(1)
    row = h._conn().execute(
        "SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
    if not row:
        h._reply_json(404, {
            "error": "workspace '%s' was not found" % project_id,
            "project": project_id,
        })
        return
    project = dict(row)
    _require_project_export_access(h, project)
    artifact = build_project_export_artifact(
        h._conn(), project_id, q.get("format") or "zip")
    snapshot = artifact["snapshot"]
    _reply_bytes(
        h, 200, artifact["content_type"], artifact["data"],
        download_name=artifact["filename"], headers={
            "Cache-Control": "private, no-store, max-age=0",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
            "X-Attacca-Export-SHA256": artifact["sha256"],
            "X-Attacca-Export-Cursor": str(snapshot["event_cursor"]),
            "X-Attacca-Export-Head": snapshot["head_hash"],
        })


def _sync_route_scope(h, project_id):
    if not getattr(h, "principal", None) \
            and not h._compatibility_active():
        raise AuthenticationError(
            "client_authorization_required: authenticated sync principal missing")
    if not h._conn().execute(
            "SELECT 1 FROM projects WHERE project_id=?", (project_id,)).fetchone():
        h._reply_json(404, {
            "error": "workspace '%s' was not found" % project_id,
            "project": project_id,
        })
        return None
    return _sync_authenticated_scope(h, project_id)


def _sync_protocol_error(h, error):
    h._reply_json(400, {"error": str(error),
                        "code": getattr(error, "code", "invalid_sync_request")})


def _r_sync_snapshot(h, m, q):
    scope = _sync_route_scope(h, m.group(1))
    if scope is None:
        return
    protocol, server = _sync_runtime()
    try:
        capabilities = protocol.projection_capabilities_from_query(
            q.get("projection_schema_version"),
            q.get("projection_resources"))
        result = _sync_engine(h, scope).snapshot(
            scope, projection_capabilities=capabilities)
        protocol.validate_snapshot(result, expected_scope=scope)
    except protocol.SyncProtocolError as error:
        _sync_protocol_error(h, error)
        return
    except server.SyncServerAuthorizationError as error:
        raise AuthorizationError(str(error))
    h._reply_json(200, result, {
        "Cache-Control": "private, no-store, max-age=0",
        "X-Content-Type-Options": "nosniff",
    })


def _r_sync_pull(h, m, q):
    scope = _sync_route_scope(h, m.group(1))
    if scope is None:
        return
    protocol, server = _sync_runtime()
    try:
        required = ("after_seq", "after_hash", "context_version",
                    "visibility_fingerprint")
        missing = [key for key in required if key not in q]
        if missing:
            raise protocol.SyncProtocolError(
                "missing_field", "pull query is missing %s" %
                ", ".join(missing))
        request = protocol.make_pull_request(
            scope,
            protocol.make_cursor(
                int(q["after_seq"]), q["after_hash"],
                int(q["context_version"])),
            q["visibility_fingerprint"],
            limit=int(q.get("limit") or 200))
        capabilities = protocol.projection_capabilities_from_query(
            q.get("projection_schema_version"),
            q.get("projection_resources"))
        result = _sync_engine(h, scope).pull(
            scope, request, projection_capabilities=capabilities)
        protocol.validate_pull_result(result)
    except protocol.SyncProtocolError as error:
        _sync_protocol_error(h, error)
        return
    except server.SyncServerAuthorizationError as error:
        raise AuthorizationError(str(error))
    h._reply_json(200, result, {
        "Cache-Control": "private, no-store, max-age=0",
        "X-Content-Type-Options": "nosniff",
    })


def _r_sync_push(h, m, q):
    scope = _sync_route_scope(h, m.group(1))
    if scope is None:
        return
    protocol, server = _sync_runtime()
    try:
        try:
            length = int(h.headers.get("Content-Length") or 0)
        except ValueError:
            raise protocol.SyncProtocolError(
                "invalid_length", "Content-Length must be an integer")
        if length < 0 or length > protocol.MAX_PUSH_BYTES:
            raise protocol.EnvelopeTooLarge(
                "envelope_too_large",
                "push request exceeds %d bytes" % protocol.MAX_PUSH_BYTES)
        envelope = h._body_json()
        device_id = h._request_device_id()
        if not device_id:
            raise protocol.SyncProtocolError(
                "missing_device", "X-Attacca-Device-ID is required for push")
        if envelope.get("device_id") != device_id:
            raise protocol.SyncProtocolError(
                "cross_device_push",
                "push device_id differs from the authenticated request device")
        capabilities = protocol.projection_capabilities_from_query(
            q.get("projection_schema_version"),
            q.get("projection_resources"))
        result = _sync_engine(h, scope).push(
            scope, envelope, projection_capabilities=capabilities)
        protocol.validate_push_result(result, expected_scope=scope)
    except protocol.SyncProtocolError as error:
        _sync_protocol_error(h, error)
        return
    except server.SyncServerAuthorizationError as error:
        raise AuthorizationError(str(error))
    h._reply_json(200, result, {
        "Cache-Control": "private, no-store, max-age=0",
        "X-Content-Type-Options": "nosniff",
    })


def _r_lead_set(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, set_lead_director(
        h._conn(), m.group(1), actor, atype, body.get("agent_id")))


def _r_bridges_list(h, m, q):
    actor, atype = h._actor()
    h._reply_json(200, bridge_list(
        h._conn(), m.group(1), actor_id=actor, actor_type=atype))


def _r_bridges_add(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    authorize_authenticated_bridge_peer(
        h._conn(), getattr(h, "principal", None), m.group(1), actor, atype,
        body.get("other_project"))
    h._reply_json(200, bridge_add(
        h._conn(), m.group(1), actor, atype,
        other_project=body.get("other_project"), boss=body.get("boss"),
        advisor=body.get("advisor"),
        participation=body.get("participation") or "all",
        peer_participation=body.get("peer_participation"),
        selected_agents=body.get("selected_agents"),
        peer_selected_agents=body.get("peer_selected_agents")))


def _r_bridges_update(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    authorize_authenticated_bridge_peer(
        h._conn(), getattr(h, "principal", None), m.group(1), actor, atype,
        m.group(2))
    relationship_keys = {"relationship", "relation", "principal", "boss",
                         "advisor"}
    access_keys = {"participation", "selected_agents",
                   "peer_participation", "peer_selected_agents"}
    changes_relationship = bool(relationship_keys.intersection(body))
    changes_access = bool(access_keys.intersection(body))
    if changes_relationship and changes_access:
        raise AttaccaError(
            "update relationship and participation in separate requests")
    if changes_relationship:
        if body.get("boss") and body.get("advisor"):
            raise AttaccaError("choose either boss or advisor, not both")
        relationship = body.get("relationship") or body.get("relation")
        principal = body.get("principal")
        if body.get("boss"):
            relationship, principal = "master", body.get("boss")
        elif body.get("advisor"):
            relationship, principal = "advisor", body.get("advisor")
        h._reply_json(200, bridge_update_relationship(
            h._conn(), m.group(1), actor, atype, m.group(2),
            relationship, principal=principal))
        return
    h._reply_json(200, bridge_update_access(
        h._conn(), m.group(1), actor, atype, m.group(2),
        participation=body.get("participation"),
        peer_participation=body.get("peer_participation"),
        selected_agents=body.get("selected_agents"),
        peer_selected_agents=body.get("peer_selected_agents")))


def _r_bridges_remove(h, m, q):
    actor, atype = h._actor()
    authorize_authenticated_bridge_peer(
        h._conn(), getattr(h, "principal", None), m.group(1), actor, atype,
        m.group(2))
    h._reply_json(200, bridge_remove(
        h._conn(), m.group(1), actor, atype, m.group(2)))


def _r_handoff_get(h, m, q):
    actor, atype = h._actor()
    h._reply_json(200, get_handoff(
        h._conn(), m.group(1), actor_id=actor, actor_type=atype))


def _r_handoff_history(h, m, q):
    limit = q.get("limit") or 20
    h._reply_json(200, handoff_history(h._conn(), m.group(1), limit=limit))


def _r_inbox_get(h, m, q):
    actor, atype = h._actor()
    mark_read = str(q.get("mark_read", "1")).lower() not in (
        "0", "false", "no")
    principal = getattr(h, "principal", None)
    if principal and principal.get("client_setup_discovery"):
        # Setup discovery is deliberately read-only even if a caller omits
        # mark_read=0.  The actor does not exist yet, so it cannot own a
        # durable inbox cursor or disposition.
        mark_read = False
    if principal and principal.get("token_kind") == "service" \
            and atype == "service":
        # An unbound service credential is a read-only integration.  Reading
        # an inbox must not smuggle a durable inbox-cursor write through the
        # otherwise GET-only route.  A service credential explicitly bound to
        # a registered actor resolves as actor_type=agent and retains that
        # actor's normal inbox semantics.
        mark_read = False
    h._reply_json(200, inbox_read(
        h._conn(), m.group(1), actor, mark_read=mark_read,
        limit=int(q.get("limit") or 50), actor_type=atype))


def _r_message_dispose(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, message_dispose(
        h._conn(), m.group(1), actor, atype, body.get("event_id"),
        body.get("disposition"), note=body.get("note"),
        task_id=body.get("task_id")))


def _r_handoff_set(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    updates = {k: body.get(k) for k in HANDOFF_FIELDS}
    h._reply_json(200, update_handoff(
        h._conn(), m.group(1), actor, atype, updates,
        expected_context_version=body.get("expected_context_version")))


def _r_log(h, m, q):
    actor, atype = h._actor()
    h._reply_json(200, project_log(
        h._conn(), m.group(1), limit=int(q.get("limit") or 40),
        actor_id=actor, actor_type=atype))


def _r_events_sync(h, m, q):
    actor, atype = h._actor()
    h._reply_json(200, _api_events_sync(
        h._conn(), m.group(1), after=int(q.get("after") or 0),
        limit=int(q.get("limit") or 200), actor_id=actor,
        actor_type=atype))


def _r_events_append(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    event_type = body.get("event_type")
    if not event_type:
        raise AttaccaError("event_type is required")
    if str(event_type) == "room.message":
        raise AttaccaError(
            "room.message may only be written through room_send so bridge "
            "targeting and participation are enforced")
    payload = body.get("payload") or {}
    if not isinstance(payload, dict):
        raise AttaccaError("payload must be a JSON object")
    h._reply_json(200, {"ok": True, "event": append_event(
        h._conn(), m.group(1), actor, atype, str(event_type), payload,
        task_id=body.get("task_id"))})


def _r_room_read(h, m, q):
    actor, atype = h._actor()
    since = q.get("since_seq")
    h._reply_json(200, room_read(h._conn(), m.group(1),
                                 since_seq=int(since) if since is not None else None,
                                 limit=int(q.get("limit") or 30),
                                 actor_id=actor, actor_type=atype))


def _r_room_send(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    origin = h.headers.get("X-Attacca-Project")
    route_project = get_project(h._conn(), m.group(1))["project_id"]
    canonical_origin = None
    if origin:
        try:
            canonical_origin = get_project(
                h._conn(), origin)["project_id"]
        except AttaccaError:
            if getattr(h, "principal", None):
                # Do not turn a rejected source override into a workspace-name
                # enumeration oracle (get_project's compatibility error lists
                # known ids for local CLI users).
                raise AuthorizationError(
                    "rest_project_header_mismatch: authenticated REST room"
                    " source must be the route workspace; use"
                    " body.target_project for bridge delivery")
            raise
    if getattr(h, "principal", None) and canonical_origin \
            and canonical_origin != route_project:
        raise AuthorizationError(
            "rest_project_header_mismatch: authenticated REST room source is"
            " workspace '%s' from the route, not header workspace '%s'; use"
            " body.target_project for an authorized bridge delivery" %
            (route_project, canonical_origin))
    h._reply_json(200, room_send(
        h._conn(), route_project, actor, atype, body=body.get("body"),
        msg_type=body.get("msg_type") or "chat", mentions=body.get("mentions"),
        task_id=body.get("task_id"), reply_to=body.get("reply_to"),
        origin_project=(canonical_origin if canonical_origin
                        and canonical_origin != route_project else None),
        target_project=body.get("target_project")))


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
        risk_level=body.get("risk_level") or "medium",
        plan_required=body.get("plan_required", False)))


def _r_task_show(h, m, q):
    h._reply_json(200, task_show(h._conn(), m.group(1), m.group(2)))


def _r_task_plan_get(h, m, q):
    version = q.get("version")
    h._reply_json(200, task_plan_get(
        h._conn(), m.group(1), m.group(2),
        version=int(version) if version is not None else None))


def _r_task_plan_set(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, task_plan_set(
        h._conn(), m.group(1), m.group(2), actor, atype,
        title=body.get("title"), overview=body.get("overview"),
        sections=body.get("sections"),
        expected_version=body.get("expected_version"),
        submit_for_review=body.get("submit_for_review", False)))


def _r_task_plan_submit(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, task_plan_submit(
        h._conn(), m.group(1), m.group(2), actor, atype,
        expected_version=body.get("expected_version")))


def _r_task_plan_review(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, task_plan_review(
        h._conn(), m.group(1), m.group(2), actor, atype,
        expected_version=body.get("expected_version"),
        action=body.get("action"), section_id=body.get("section_id"),
        note=body.get("note")))


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


def _r_rules_list(h, m, q):
    actor, atype = h._actor()
    include_disabled = str(q.get("include_disabled", "0")).lower() in (
        "1", "true", "yes")
    include_all = str(q.get("include_all", "0")).lower() in (
        "1", "true", "yes")
    h._reply_json(200, rule_list(
        h._conn(), m.group(1), actor_id=actor, actor_type=atype,
        include_disabled=include_disabled, include_all=include_all))


def _r_rule_create(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, rule_create(
        h._conn(), m.group(1), actor, atype, title=body.get("title"),
        body=body.get("body"), scope=body.get("scope") or "everyone",
        priority=body.get("priority") if body.get("priority") is not None
        else 100))


def _r_rule_update(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    updates = {key: body[key] for key in
               ("title", "body", "scope", "priority", "enabled")
               if key in body}
    h._reply_json(200, rule_update(
        h._conn(), m.group(1), actor, atype, m.group(2), updates,
        expected_version=body.get("expected_version")))


def _r_cloud_context_get(h, m, q):
    actor, atype = h._actor()
    h._reply_json(200, cloud_context_get(
        h._conn(), m.group(1), actor_id=actor, actor_type=atype))


def _r_cloud_context_set(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    h._reply_json(200, cloud_context_set(
        h._conn(), m.group(1), actor, atype, content=body.get("content"),
        expected_version=body.get("expected_version")))


def _r_migration_directive(h, m, q):
    root = None
    pid = q.get("project")
    if pid:
        row = h._conn().execute(
            "SELECT root_path FROM projects WHERE project_id=?", (pid,)
        ).fetchone()
        root = row["root_path"] if row else None
    h._reply_json(200, migration_directive(root))


def _r_managed_law(h, m, q):
    pid = str(q.get("project") or "").strip() or None
    principal = getattr(h, "principal", None) or {}
    bound_project = str(principal.get("project_id") or "").strip() or None
    if bound_project:
        if pid and pid != bound_project:
            raise AuthorizationError(
                "managed_law_scope_denied: credential is bound to workspace "
                "'%s'" % bound_project)
        pid = bound_project
    if pid:
        h._enforce_human_project_membership(pid)
    db = getattr(h.server, "db_path", None)
    h._reply_json(200, managed_law_payload(pid, db),
                  {"Cache-Control": "no-store"})


def _r_poll_status(h, m, q):
    actor, atype = h._actor()
    # Identity comes only from the request's validated principal/headers.
    # Query parameters may describe client versions, never impersonate a
    # different inbox or actor type after authentication.
    h._reply_json(200, poll_status(
        h._conn(), m.group(1), actor_id=actor,
        actor_type=atype,
        plugin_version=q.get("plugin_version"),
        law_version=q.get("law_version")), {"Cache-Control": "no-store"})


def _r_agents_list(h, m, q):
    h._reply_json(200, agent_list(h._conn(), m.group(1)))


def _r_agent_register(h, m, q):
    actor, atype = h._actor()
    body = h._body_json()
    principal = getattr(h, "principal", None)
    project_id = m.group(1)
    if principal and (principal.get("auth_kind") == "session" or
                      principal.get("token_kind") == "client") \
            and not auth_has_project_membership(
                h._conn(), principal, project_id):
        raise AuthorizationError(
            "project_membership_required: actor registration access denied")
    registration_username = principal.get("username") if principal else None
    authorized_owner_labels = auth_principal_owner_labels(
        h._conn(), principal) if principal and principal.get("user_id") else []
    result = agent_register(
        h._conn(), m.group(1), actor, atype, agent_id=body.get("agent_id"),
        display_name=body.get("display_name"), role=body.get("role"),
        runtime=body.get("runtime"),
        canonical_identity=(atype == "agent" or
                            bool(principal and
                                 principal.get("token_kind") == "client") or
                            (atype == "human" and
                             body.get("canonical_identity") is True)),
        registration_username=registration_username,
        allow_foreign_owner=bool(
            principal and principal.get("auth_kind") == "session"
            and principal.get("is_admin")),
        authorized_owner_labels=authorized_owner_labels)
    h._reply_json(200, result)


def _r_freshness(h, m, q):
    actor, atype = h._actor()
    version = q.get("context_version")
    h._reply_json(200, check_freshness(
        h._conn(), m.group(1),
        int(version) if version is not None else None,
        actor_id=actor, actor_type=atype))


def _r_search(h, m, q):
    actor, atype = h._actor()
    h._reply_json(200, search_project(
        h._conn(), m.group(1), q.get("q"),
        limit=int(q.get("limit") or 20), actor_id=actor,
        actor_type=atype))


def _r_verify(h, m, q):
    h._reply_json(200, verify_ledger(h._conn(), m.group(1)))


_PID = "([^/]+)"
ROUTES = [
    (*_route_def("GET", "/"), _r_landing),
    (*_route_def("GET", "/app/?"), _r_app),
    (*_route_def("GET", "/install.sh"), _r_install_sh),
    (*_route_def("GET", "/plugin.zip"), _r_plugin_zip),
    (*_route_def("GET", "/plugin/marketplace.json"), _r_marketplace_json),
    (*_route_def("GET", "/plugin\\.git/(.+)"), _r_plugin_git),
    (*_route_def("GET", "/healthz"), _r_healthz),
    (*_route_def("GET", "/v1/auth/status"), _r_auth_status),
    (*_route_def("GET", "/v1/managed-law"), _r_managed_law),
    (*_route_def("GET", "/v1/migration-directive"), _r_migration_directive),
    (*_route_def("POST", "/v1/auth/bootstrap"), _r_auth_bootstrap),
    (*_route_def("POST", "/v1/auth/login"), _r_auth_login),
    (*_route_def("POST", "/v1/auth/logout"), _r_auth_logout),
    (*_route_def("GET", "/v1/auth/access"), _r_auth_access),
    (*_route_def("GET", "/v1/auth/client-keys"), _r_auth_client_keys),
    (*_route_def("POST", "/v1/auth/client-keys"),
     _r_auth_client_key_create),
    (*_route_def("DELETE", "/v1/auth/client-keys/%s" % _PID),
     _r_auth_client_key_revoke),
    (*_route_def("DELETE", "/v1/auth/client-keys/%s/permanent" % _PID),
     _r_auth_client_key_delete),
    (*_route_def("POST", "/v1/auth/client-authorizations"),
     _r_auth_client_pairing_start),
    (*_route_def("POST", "/v1/auth/client-authorizations/poll"),
     _r_auth_client_pairing_poll),
    (*_route_def("POST", "/v1/auth/client-authorizations/lookup"),
     _r_auth_client_pairing_get),
    (*_route_def("POST", "/v1/auth/client-authorizations/authorize"),
     _r_auth_client_pairing_authorize),
    (*_route_def("POST", "/v1/auth/client-authorizations/deny"),
     _r_auth_client_pairing_deny),
    (*_route_def("GET", "/v1/auth/service-keys"), _r_auth_service_keys),
    (*_route_def("POST", "/v1/auth/service-keys"),
     _r_auth_service_key_create),
    (*_route_def("DELETE", "/v1/auth/service-keys/%s" % _PID),
     _r_auth_service_key_revoke),
    (*_route_def("GET", "/v1/auth/invitations"), _r_auth_invitations),
    (*_route_def("POST", "/v1/auth/invitations"),
     _r_auth_invitation_create),
    (*_route_def("DELETE", "/v1/auth/invitations/%s" % _PID),
     _r_auth_invitation_revoke),
    (*_route_def("POST", "/v1/auth/invitations/accept"),
     _r_auth_invitation_accept),
    (*_route_def("POST", "/v1/auth/activation"), _r_auth_activation),
    (*_route_def("GET", "/v1/auth/tokens"), _r_auth_tokens_list),
    (*_route_def("POST", "/v1/auth/tokens"), _r_auth_tokens_create),
    (*_route_def("DELETE", "/v1/auth/tokens/%s" % _PID),
     _r_auth_tokens_revoke),
    (*_route_def("GET", "/v1/settings"), _r_settings_get),
    (*_route_def("PUT", "/v1/settings"), _r_settings_put),
    (*_route_def("GET", "/v1/projects"), _r_projects_list),
    (*_route_def("POST", "/v1/projects"), _r_projects_create),
    (*_route_def("GET", "/v1/projects/%s/status" % _PID), _r_project_status),
    (*_route_def("GET", "/v1/projects/%s/export" % _PID), _r_project_export),
    (*_route_def("GET", "/v1/projects/%s/sync/snapshot" % _PID),
     _r_sync_snapshot),
    (*_route_def("GET", "/v1/projects/%s/sync/pull" % _PID), _r_sync_pull),
    (*_route_def("POST", "/v1/projects/%s/sync/push" % _PID), _r_sync_push),
    (*_route_def("GET", "/v1/projects/%s/inbox" % _PID), _r_inbox_get),
    (*_route_def("POST", "/v1/projects/%s/inbox/dispositions" % _PID),
     _r_message_dispose),
    (*_route_def("PUT", "/v1/projects/%s/lead" % _PID), _r_lead_set),
    (*_route_def("GET", "/v1/projects/%s/bridges" % _PID), _r_bridges_list),
    (*_route_def("POST", "/v1/projects/%s/bridges" % _PID), _r_bridges_add),
    (*_route_def("PUT", "/v1/projects/%s/bridges/%s" % (_PID, _PID)),
     _r_bridges_update),
    (*_route_def("DELETE", "/v1/projects/%s/bridges/%s" % (_PID, _PID)),
     _r_bridges_remove),
    (*_route_def("GET", "/v1/projects/%s/handoff" % _PID), _r_handoff_get),
    (*_route_def("GET", "/v1/projects/%s/handoff/history" % _PID), _r_handoff_history),
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
    (*_route_def("GET", "/v1/projects/%s/tasks/%s/plan" % (_PID, _PID)),
     _r_task_plan_get),
    (*_route_def("PUT", "/v1/projects/%s/tasks/%s/plan" % (_PID, _PID)),
     _r_task_plan_set),
    (*_route_def("POST", "/v1/projects/%s/tasks/%s/plan/submit" % (_PID, _PID)),
     _r_task_plan_submit),
    (*_route_def("POST", "/v1/projects/%s/tasks/%s/plan/review" % (_PID, _PID)),
     _r_task_plan_review),
    (*_route_def("POST", "/v1/projects/%s/tasks/%s/claim" % (_PID, _PID)), _r_task_claim),
    (*_route_def("POST", "/v1/projects/%s/tasks/%s/report" % (_PID, _PID)), _r_task_report),
    (*_route_def("POST", "/v1/projects/%s/tasks/%s/release" % (_PID, _PID)), _r_task_release),
    (*_route_def("POST", "/v1/projects/%s/tasks/%s/status" % (_PID, _PID)), _r_task_status),
    (*_route_def("GET", "/v1/projects/%s/decisions" % _PID), _r_decisions_list),
    (*_route_def("POST", "/v1/projects/%s/decisions" % _PID), _r_decision_propose),
    (*_route_def("POST", "/v1/projects/%s/decisions/%s/resolve" % (_PID, _PID)), _r_decision_resolve),
    (*_route_def("GET", "/v1/projects/%s/rules" % _PID), _r_rules_list),
    (*_route_def("POST", "/v1/projects/%s/rules" % _PID), _r_rule_create),
    (*_route_def("PUT", "/v1/projects/%s/rules/%s" % (_PID, _PID)),
     _r_rule_update),
    (*_route_def("GET", "/v1/projects/%s/cloud-context" % _PID),
     _r_cloud_context_get),
    (*_route_def("PUT", "/v1/projects/%s/cloud-context" % _PID),
     _r_cloud_context_set),
    (*_route_def("GET", "/v1/projects/%s/poll-status" % _PID), _r_poll_status),
    (*_route_def("GET", "/v1/projects/%s/agents" % _PID), _r_agents_list),
    (*_route_def("POST", "/v1/projects/%s/agents" % _PID), _r_agent_register),
    (*_route_def("GET", "/v1/projects/%s/search" % _PID), _r_search),
    (*_route_def("GET", "/v1/projects/%s/freshness" % _PID), _r_freshness),
    (*_route_def("GET", "/v1/projects/%s/verify" % _PID), _r_verify),
]


def run_server(db_path, host="127.0.0.1", port=DEFAULT_PORT,
               default_project=None, verbose=False, auth=False,
               auth_mode="auto"):
    server = AttaccaServer((host, port), db_path,
                           default_project=default_project, verbose=verbose,
                           auth=auth, auth_mode=auth_mode)
    real_port = server.server_address[1]
    base = "http://%s:%d" % (host, real_port)
    print("attacca server listening on %s" % base, flush=True)
    print("  db:   %s" % db_path, flush=True)
    print("  MCP:  %s/mcp    REST: %s/v1/projects" % (base, base), flush=True)
    print("  plugin install: curl -fsSL %s/install.sh | sh" % base, flush=True)
    auth_state = auth_activation_readiness(
        server.conn(), server=server, include_details=False)
    if host not in ("127.0.0.1", "localhost", "::1") \
            and auth_state["effective_authentication"] != "required":
        print("  WARNING: unauthenticated server bound to a non-localhost "
              "address (no encryption in this build)", flush=True)
    elif auth_state["effective_authentication"] == "required":
        print("  authentication: required", flush=True)
    else:
        print("  authentication: optional migration mode (%s)" %
              server.auth_mode, flush=True)
    previous_sigterm = None
    if threading.current_thread() is threading.main_thread() \
            and hasattr(signal, "SIGTERM"):
        previous_sigterm = signal.getsignal(signal.SIGTERM)

        def _graceful_sigterm(_signum, _frame):
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, _graceful_sigterm)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if previous_sigterm is not None:
            signal.signal(signal.SIGTERM, previous_sigterm)


OFFLINE_PROXY_READ_TOOLS = {
    "attacca_status", "get_handoff", "get_project_log", "room_read",
    "check_inbox", "bridge_list", "search", "task_list", "task_show",
    "task_plan_get", "decision_list", "rule_list", "agent_list",
    "list_projects", "check_freshness",
}
OFFLINE_PROXY_WRITE_OPERATIONS = {
    "room_send": "room.send",
    "message_dispose": "message.dispose",
    "task_create": "task.create",
    "task_claim": "task.claim",
    "task_report": "task.report",
    "task_release": "task.release",
    "task_set_status": "task.set_status",
    "task_plan_set": "task.plan.set",
    "task_plan_submit": "task.plan.submit",
    "task_plan_review": "task.plan.review",
    "decision_propose": "decision.propose",
    "decision_resolve": "decision.resolve",
    "rule_create": "rule.create",
    "rule_update": "rule.update",
    "update_handoff": "handoff.update",
    "append_event": "event.append",
}
OFFLINE_PROXY_EXPLICITLY_UNAVAILABLE = {
    "set_lead_director", "bridge_add", "bridge_update_access",
    "bridge_remove", "agent_register",
}


def _offline_proxy_state_path():
    """Return watcher state without resolving away symlink evidence."""
    override = os.environ.get("ATTACCA_WATCHER_DIR")
    directory = Path(override).expanduser().absolute() if override else \
        Path.home() / ".attacca" / "watcher"
    return directory / "watcher-state.json"


def _offline_proxy_state(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AttaccaError(
            "no verified identity-scoped offline mirror is registered for "
            "this client")
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise AttaccaError(
            "the offline watcher identity registry is invalid: %s" % error)
    if not isinstance(value, dict) or not isinstance(
            value.get("subscriptions"), dict):
        raise AttaccaError("the offline watcher identity registry is invalid")
    return value


def _offline_proxy_wake(state_path, subscription_key):
    """Wake exactly the subscription whose outbox was just fsynced."""
    state_path = Path(state_path)
    lock_path = state_path.with_name(".%s.lock" % state_path.name)
    with _MACHINE_CONFIG_THREAD_LOCK, _exclusive_config_lock(lock_path):
        state = _offline_proxy_state(state_path)
        entry = (state.get("subscriptions") or {}).get(subscription_key)
        if not isinstance(entry, dict):
            return
        entry.update({
            "next_poll_at_epoch": 0,
            "wake_reason": "local_write",
            "wake_requested_at_epoch": time.time(),
        })
        _atomic_switch_write(
            state_path, _json_switch_bytes(state),
            mode=state_path.stat().st_mode & 0o777)


def _offline_proxy_subscription(url, project_id, root, actor_hint, runtime,
                                device_id):
    """Locate exactly one watcher identity without opening cached authority."""
    _, offline = _offline_sync_runtime()
    try:
        normalized_url = offline.normalize_server_url(url)
    except offline.OfflineSyncError as error:
        raise AttaccaError(str(error)) from error
    if not project_id:
        raise AttaccaError(
            "offline mode requires a checkout attached to one workspace")
    if not actor_hint or not runtime or not device_id:
        raise AttaccaError(
            "offline mode requires this client's configured actor, runtime, "
            "and device identity")
    state_path = _offline_proxy_state_path()
    state = _offline_proxy_state(state_path)
    canonical_root = str(Path(root).expanduser().resolve())
    matches = []
    for stored_key, candidate in (state.get("subscriptions") or {}).items():
        if not isinstance(candidate, dict):
            continue
        try:
            candidate_url = offline.normalize_server_url(
                candidate.get("server_url"))
            candidate_root = str(Path(candidate.get("root") or "")
                                 .expanduser().resolve())
        except Exception:
            continue
        actor_matches = actor_hint in {
            candidate.get("actor"), candidate.get("canonical_actor_id")}
        if candidate_url == normalized_url \
                and candidate.get("project_id") == project_id \
                and candidate.get("runtime") == runtime \
                and candidate.get("device_id") == device_id \
                and candidate_root == canonical_root and actor_matches:
            matches.append((stored_key, candidate))
    if len(matches) != 1:
        raise AttaccaError(
            "offline mode found %d exact verified client subscriptions; "
            "expected exactly one for server/workspace/root/runtime/actor/device"
            % len(matches))
    stored_key, entry = matches[0]
    return offline, normalized_url, state_path, state, stored_key, entry


def _offline_proxy_latch_auth_required(url, project_id, root, actor_hint,
                                       runtime, device_id, http_status):
    """Persist a hosted revocation before any later transport fallback."""
    state_path = _offline_proxy_state_path()
    lock_path = state_path.with_name(".%s.lock" % state_path.name)
    with _MACHINE_CONFIG_THREAD_LOCK, _exclusive_config_lock(lock_path):
        try:
            _, _, _, state, stored_key, entry = _offline_proxy_subscription(
                url, project_id, root, actor_hint, runtime, device_id)
        except AttaccaError:
            # No exact mirror can be activated later, so there is nothing safe
            # or necessary to latch in a different identity partition.
            return False
        current = (state.get("subscriptions") or {}).get(stored_key)
        if not isinstance(current, dict) or current.get("key") != \
                entry.get("key"):
            return False
        message = (
            "hosted MCP rejected this workspace credential or AI scope "
            "(HTTP %s)" % int(http_status))
        fingerprint = hashlib.sha256(
            ("authentication_required|" + message).encode("utf-8")).hexdigest()
        current.update({
            "auth_required": True,
            "auth_required_at": now_iso(),
            "last_attempt_at": now_iso(),
            "last_error": message,
            "last_auth_error_fingerprint": fingerprint,
            "offline_mode": "auth_required",
            "offline_mirror_stale": True,
            "offline_retry_seconds": 60,
            "next_poll_at_epoch": time.time(),
        })
        pending = [
            row for row in current.get("pending") or []
            if row.get("kind") not in {
                "authentication_required", "offline_connection_error",
                "connection_error"}]
        pending.append({
            "fingerprint": fingerprint, "created_at": now_iso(),
            "kind": "authentication_required",
            "summary": (
                "client_authorization_required workspace=%s http_status=%s "
                "api_key_settings_uri=%s/app#settings "
                "offline_access=blocked_until_identity_is_verified" % (
                    project_id, int(http_status), str(url).rstrip("/"))),
        })
        current["pending"] = pending[-100:]
        _atomic_switch_write(
            state_path, _json_switch_bytes(state),
            mode=state_path.stat().st_mode & 0o777)
        return True


def _offline_proxy_adapter(url, project_id, root, actor_hint, runtime,
                           device_id):
    """Open one exact watcher-owned verified mirror/outbox partition.

    No owner, role, principal, or token is inferred here.  All authority comes
    from the authenticated schema-v1 scope already recorded by the watcher.
    Zero or multiple exact subscriptions fail closed.
    """
    protocol, _ = _offline_sync_runtime()
    offline, normalized_url, state_path, _, stored_key, entry = \
        _offline_proxy_subscription(
            url, project_id, root, actor_hint, runtime, device_id)
    if entry.get("auth_required"):
        raise AttaccaError(
            "client_authorization_required: cached mirror access is blocked; "
            "api_key_settings_uri=%s/app#settings" % normalized_url)
    required = {
        "key", "plugin_root", "canonical_actor_id", "actor_role",
        "sync_scope", "sync_visibility_fingerprint", "sync_schema_version",
    }
    missing = sorted(key for key in required if entry.get(key) in (None, ""))
    if missing:
        raise AttaccaError(
            "offline subscription is not authenticated/activated (missing %s)"
            % ", ".join(missing))
    if entry.get("key") != stored_key:
        raise AttaccaError("offline subscription key was modified")
    if entry.get("sync_schema_version") != protocol.SCHEMA_VERSION:
        raise AttaccaError("offline subscription uses an unsupported schema")
    try:
        scope = protocol.validate_scope(entry["sync_scope"])
        visibility = protocol.validate_visibility_fingerprint(
            entry["sync_visibility_fingerprint"])
    except protocol.SyncProtocolError as error:
        raise AttaccaError(
            "offline subscription identity failed validation: %s" % error) \
            from error
    if scope["project_id"] != project_id \
            or scope["actor_type"] != "agent" \
            or scope["actor_id"] != entry["canonical_actor_id"] \
            or scope["role"] != entry["actor_role"]:
        raise AttaccaError(
            "offline subscription identity/role differs from its verified scope")
    material = json.dumps([
        entry["key"], entry["runtime"], entry["actor"], entry["device_id"],
    ], separators=(",", ":"), ensure_ascii=False)
    client_id = "watcher_" + hashlib.sha256(
        material.encode("utf-8")).hexdigest()[:32]
    wake = lambda: _offline_proxy_wake(state_path, stored_key)
    try:
        adapter = offline.OfflineProjectSync(
            state_path.parent / "offline", normalized_url, scope, client_id,
            device_id, visibility_fingerprint=visibility,
            wake_callback=wake)
        snapshot = adapter.local_snapshot()
        proof = offline.validate_convergence_proof(
            adapter.convergence_proof(), expected_server_url=normalized_url,
            expected_project=project_id, expected_scope=scope,
            require_online=False)
        checked_snapshot = protocol.validate_snapshot(
            snapshot, expected_scope=scope, expected_visibility=visibility)
    except (offline.OfflineSyncError, protocol.SyncProtocolError) as error:
        raise AttaccaError(
            "verified offline mirror is unavailable or invalid: %s" % error) \
            from error
    if proof["visibility_fingerprint"] != visibility \
            or checked_snapshot["scope"] != scope:
        raise AttaccaError(
            "offline mirror no longer matches the verified client identity")
    return adapter, checked_snapshot, proof, dict(entry)


def _offline_proxy_visible_events(snapshot):
    return [record["event"] for record in snapshot.get("records", [])
            if record.get("kind") == "event"]


def _offline_proxy_attribution(event):
    actor = event.get("actor_id")
    owner = event.get("owner")
    parsed = parse_canonical_agent_id(
        actor, project_id=event.get("project_id")) \
        if event.get("actor_type") == "agent" else None
    identity = {
        "workspace": event.get("project_id"),
        "role": (parsed or {}).get("role") or (
            "human" if event.get("actor_type") == "human" else "unassigned"),
        "runtime": (parsed or {}).get("runtime"),
        "owner": owner,
        "actor_id": actor,
        "ledger_actor_id": actor,
    }
    return {
        "actor_id": actor, "ledger_actor_id": actor,
        "actor_type": event.get("actor_type"),
        "human_user": actor if event.get("actor_type") == "human" else None,
        "run_by_user": owner, "identity": identity,
    }


def _offline_proxy_action(event):
    return {
        "event_id": event.get("event_id"), "seq": event.get("seq"),
        "event_type": event.get("event_type"),
        "actor_id": event.get("actor_id"),
        "operational_actor_id": event.get("actor_id"),
        "actor_type": event.get("actor_type"), "owner": event.get("owner"),
        "at": event.get("created_at"), "git_branch": event.get("git_branch"),
        "git_revision": event.get("base_revision"),
        "device_id": event.get("device_id"),
        "context_version": event.get("context_version"),
        "payload": event.get("payload") or {},
        "attribution": _offline_proxy_attribution(event),
    }


def _offline_proxy_marker(adapter, proof):
    status = adapter.status()
    return {
        "offline": True,
        "read_source": "verified_local_mirror",
        "pending_sync": bool(status.get("pending_sync")),
        "sync": {
            "mode": status.get("mode"),
            "mirror_stale": bool(proof.get("mirror_stale")),
            "mirror_verified_at": proof.get("mirror_verified_at"),
            "mirror_cursor": proof.get("cursor"),
            "pending_count": status.get("pending_count", 0),
            "conflict_count": status.get("conflict_count", 0),
            "convergence_awaiting_count": status.get(
                "convergence_awaiting_count", 0),
        },
    }


def _offline_proxy_mark(result, adapter, proof):
    value = dict(result)
    value.update(_offline_proxy_marker(adapter, proof))
    value.setdefault("pending_mutations", [{
        "kind": "pending_mutation",
        "client_mutation_id": item["client_mutation_id"],
        "operation": item["operation"],
        "payload": item["payload"],
        "metadata": item["metadata"],
        "sync_state": item["sync_state"],
        "pending_sync": True,
        "local_only": True,
        "hint": "Queued locally; not yet accepted by the hosted ledger.",
    } for item in adapter.pending_overlays()])
    return value


def _offline_proxy_task(projection, task_id):
    task = next((item for item in projection.get("tasks", [])
                 if item.get("task_id") == task_id), None)
    if task is None:
        raise AttaccaError("unknown task %s in verified offline mirror" % task_id)
    return dict(task)


def _offline_proxy_plan(snapshot, task_id, version=None):
    projection = snapshot["projection"]
    _offline_proxy_task(projection, task_id)
    plans = [dict(item) for item in projection.get("task_plans", [])
             if item.get("task_id") == task_id]
    plans.sort(key=lambda item: int(item.get("version") or 0), reverse=True)
    if version is None:
        selected = plans[0] if plans else None
    else:
        try:
            wanted = int(version)
        except (TypeError, ValueError):
            raise AttaccaError("plan version must be an integer")
        selected = next((item for item in plans
                         if int(item.get("version") or 0) == wanted), None)
        if selected is None:
            raise AttaccaError(
                "task %s has no cached plan version %s" % (task_id, wanted))
    if selected is None:
        return {"project": snapshot["scope"]["project_id"],
                "task_id": task_id, "plan": None, "revisions": []}
    selected_version = int(selected.get("version") or 0)
    events = [event for event in _offline_proxy_visible_events(snapshot)
              if event.get("task_id") == task_id
              and str(event.get("event_type") or "").startswith("task.plan.")
              and int((event.get("payload") or {}).get("plan_version") or 0)
              == selected_version]
    actions = [_offline_proxy_action(event) for event in events]
    selected["actions"] = actions
    selected["approvals"] = [item for item in actions
                              if item["event_type"] == "task.plan.approved"]
    selected["suggestions"] = [item for item in actions
                                if item["event_type"] == "task.plan.suggested"]
    selected["comments"] = [item for item in actions
                             if item["event_type"] == "task.plan.commented"]
    revisions = [{
        "version": item.get("version"), "status": item.get("status"),
        "title": item.get("title"),
        "section_count": len(item.get("sections") or []),
        "content_sha256": item.get("content_sha256"),
        "authored_by": item.get("authored_by"),
        "authored_owner": item.get("authored_owner"),
        "authored_at": item.get("authored_at"),
        "updated_at": item.get("updated_at"),
    } for item in plans]
    return {"project": snapshot["scope"]["project_id"],
            "task_id": task_id, "plan": selected, "revisions": revisions}


def _offline_proxy_collect_refs(value, found=None):
    found = found if found is not None else []
    if isinstance(value, dict):
        if set(value) == {"$local_ref", "path"}:
            mutation_id = value.get("$local_ref")
            if mutation_id not in found:
                found.append(mutation_id)
        else:
            for child in value.values():
                _offline_proxy_collect_refs(child, found)
    elif isinstance(value, list):
        for child in value:
            _offline_proxy_collect_refs(child, found)
    return found


class OfflineProxySession:
    """MCP-compatible facade over one verified mirror and durable outbox."""

    def __init__(self, url, project_getter, root, actor_hint, runtime,
                 device_id):
        self.url = url
        self.project_getter = project_getter
        self.root = root
        self.actor_hint = actor_hint
        self.runtime = runtime
        self.device_id = device_id
        self.briefed_context = None
        # Hosted cursors are immutable while offline.  This process-local
        # cursor lets one active AI drain cached pages without either skipping
        # rows or pretending the read was synchronized to the host. A restart
        # safely replays the page until hosted reconciliation succeeds.
        self.offline_inbox_cursors = {}

    @staticmethod
    def _res(msg_id, result):
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _err(msg_id, code, message):
        return {"jsonrpc": "2.0", "id": msg_id,
                "error": {"code": code, "message": message}}

    def _open(self):
        return _offline_proxy_adapter(
            self.url, self.project_getter(), self.root, self.actor_hint,
            self.runtime, self.device_id)

    def latch_auth_required(self, http_status):
        return _offline_proxy_latch_auth_required(
            self.url, self.project_getter(), self.root, self.actor_hint,
            self.runtime, self.device_id, http_status)

    @staticmethod
    def _project_args(args, scope):
        if not isinstance(args, dict):
            raise AttaccaError("tool arguments must be an object")
        requested = args.get("project")
        if requested and requested != scope["project_id"]:
            raise AttaccaError(
                "offline mode cannot cross workspace boundaries; this "
                "verified mirror belongs to '%s'" % scope["project_id"])

    def _read(self, name, args, adapter, snapshot, proof):
        scope = snapshot["scope"]
        project_id = scope["project_id"]
        projection = snapshot["projection"]
        project = projection.get("project") or {}
        events = _offline_proxy_visible_events(snapshot)
        self._project_args(args, scope)

        # The verified projection is already participation-scoped.  Build the
        # same actor-specific attention view used by hosted reads without
        # turning mentions/replies into a second visibility filter.
        aliases = {scope["actor_id"]}
        aliases.update(
            item.get("legacy_actor_id")
            for item in projection.get("actor_aliases", [])
            if item.get("canonical_actor_id") == scope["actor_id"]
            and item.get("legacy_actor_id"))
        cached_room = sorted(
            list(projection.get("room_messages") or []),
            key=lambda item: int(item.get("seq") or 0))
        cached_room_by_id = {
            item.get("event_id"): item for item in cached_room}

        def classify_room(item):
            message = dict(item)
            mentions = set(message.get("mentions") or [])
            mentioned = bool(aliases.intersection(mentions))
            replied = bool(
                message.get("reply_to") and
                ((cached_room_by_id.get(message["reply_to"]) or {}).get(
                    "actor") or
                 (cached_room_by_id.get(message["reply_to"]) or {}).get(
                    "actor_id")) in aliases)
            broadcast = bool(
                message.get("msg_type") in ("chat", "directive") and
                not mentions and not message.get("reply_to"))
            direct = mentioned or replied
            addressed = direct or broadcast
            message.update({
                "mentioned_to_you": mentioned,
                "reply_to_you": replied,
                "directed_to_you": direct,
                "broadcast_to_everyone": broadcast,
                "addressed_to_you": addressed,
                "group_context": not addressed,
            })
            return message

        def cached_pending_dispositions(limit=100):
            """Project cursor-independent assignment state plus local writes."""
            limit = max(1, min(int(limit or 100), 500))
            dispositions = {
                item.get("message_event_id"): dict(item)
                for item in projection.get("message_dispositions") or []
                if item.get("message_event_id")
            }
            # A disposition queued during the outage is authoritative for this
            # exact local identity view, but remains visibly pending_sync until
            # the hosted ledger accepts it.
            for overlay in adapter.pending_overlays("message_dispositions"):
                if overlay.get("operation") != "message.dispose":
                    continue
                payload = overlay.get("payload") or {}
                event_id = payload.get("event_id")
                if not event_id:
                    continue
                dispositions[event_id] = {
                    "project_id": project_id,
                    "actor_id": scope["actor_id"],
                    "message_event_id": event_id,
                    "disposition": payload.get("disposition"),
                    "note": payload.get("note"),
                    "task_id": payload.get("task_id"),
                    "updated_by": scope["actor_id"],
                    "updated_owner": scope["principal_id"],
                    "pending_sync": True,
                    "local_only": True,
                    "client_mutation_id": overlay.get(
                        "client_mutation_id"),
                    "sync_state": overlay.get("sync_state"),
                }
            pending = []
            for item in cached_room:
                sender = item.get("actor") or item.get("actor_id")
                if sender in aliases:
                    continue
                message = classify_room(item)
                requires = bool(message.get("directed_to_you") or (
                    message.get("broadcast_to_everyone") and
                    message.get("msg_type") == "directive"))
                if not requires:
                    continue
                disposition = dispositions.get(message.get("event_id"))
                if disposition and disposition.get("disposition") not in \
                        UNRESOLVED_MESSAGE_DISPOSITIONS:
                    continue
                message["requires_disposition"] = True
                message["disposition"] = disposition
                pending.append(message)
            return {
                "pending": pending[:limit],
                "pending_total": len(pending),
                "may_have_more": len(pending) > limit,
            }

        def cached_inbox(mark_read=True, limit=50):
            limit = max(1, min(int(limit or 50), 500))
            cursor_row = projection.get("inbox_cursor") or {}
            hosted_cursor = int(cursor_row.get("last_read_seq") or 0)
            cursor_key = (project_id, scope["actor_id"])
            cursor = max(
                hosted_cursor,
                int(self.offline_inbox_cursors.get(cursor_key) or 0))
            visible = []
            remaining_rows = []
            for item in cached_room:
                seq = int(item.get("seq") or 0)
                if seq <= cursor:
                    continue
                remaining_rows.append(item)
                sender = item.get("actor") or item.get("actor_id")
                if sender in aliases:
                    continue
                visible.append(classify_room(item))
            page = visible[:limit]
            scanned_through = int(page[-1].get("seq") or cursor) \
                if page else max(
                    [int(item.get("seq") or 0) for item in remaining_rows]
                    or [cursor])
            if mark_read and scanned_through > cursor:
                self.offline_inbox_cursors[cursor_key] = scanned_through
            addressed_count = sum(
                bool(item.get("addressed_to_you")) for item in page)
            direct_count = sum(
                bool(item.get("directed_to_you")) for item in page)
            everyone_count = sum(
                bool(item.get("broadcast_to_everyone")) for item in page)
            group_count = sum(
                bool(item.get("group_context")) for item in page)
            disposition_state = cached_pending_dispositions(limit=limit)
            return {
                "project": project_id, "actor": scope["actor_id"],
                "messages": page, "messages_include_all_visible": True,
                "unread_total": len(page),
                "unread_addressed": addressed_count,
                "unread_direct": direct_count,
                "unread_everyone": everyone_count,
                "unread_group_context": group_count,
                "unread_broadcasts": group_count,
                "may_have_more": len(visible) > len(page),
                "read_cursor": scanned_through if mark_read else cursor,
                "scanned_through_seq": scanned_through,
                "hosted_read_cursor": hosted_cursor,
                "offline_mark_read_deferred": bool(mark_read),
                "pending_dispositions": disposition_state["pending"],
                "pending_disposition_total":
                    disposition_state["pending_total"],
                "pending_disposition_may_have_more":
                    disposition_state["may_have_more"],
                "hint": ("cached group inbox page; call check_inbox again "
                         "while may_have_more is true. This process remembers "
                         "the page locally, but the hosted cursor advances "
                         "only after reconnect."),
            }
        if name == "attacca_status":
            tasks = projection.get("tasks") or []
            decisions = projection.get("decisions") or []
            rules = adapter.rules_for_role(scope["role"])
            agents = projection.get("agents") or []
            actor_row = next((item for item in agents
                              if item.get("agent_id") == scope["actor_id"]), {})
            result = {
                "project": project_id, "name": project.get("name"),
                "root_path": self.root, "db": None,
                "you": {"actor_id": scope["actor_id"],
                        "actor_type": scope["actor_type"],
                        "identity": {"workspace": project_id,
                                     "role": scope["role"],
                                     "runtime": self.runtime,
                                     "owner": scope["principal_id"]}},
                "context_version": project.get("context_version") or
                snapshot["cursor"]["context_version"],
                "lead_director": project.get("lead_director"),
                "handoff_updated_at": ((projection.get("handoffs") or [{}])[-1]
                                       .get("updated_at")),
                "counts": {
                    "events": len(events),
                    "messages": len(projection.get("room_messages") or []),
                    "open_tasks": sum(item.get("status") not in
                                      ("done", "cancelled") for item in tasks),
                    "claimed_tasks": sum(item.get("status") == "claimed"
                                         for item in tasks),
                    "open_decisions": sum(item.get("status") == "proposed"
                                          for item in decisions),
                    "active_rules": len(rules), "agents": len(agents),
                },
                "git": {"head": git_head(self.root),
                        "branch": git_branch(self.root)},
            }
            if actor_row:
                result["you"]["registered_agent"] = actor_row
            return _offline_proxy_mark(result, adapter, proof)
        if name == "get_handoff":
            handoffs = projection.get("handoffs") or []
            latest = handoffs[-1] if handoffs else None
            content = dict((latest or {}).get("content") or {})
            handoff = {field: content.get(field) for field in HANDOFF_FIELDS}
            handoff_event = next((event for event in reversed(events)
                                  if event.get("event_type") ==
                                  "handoff.updated"), None)
            tasks = [item for item in projection.get("tasks", [])
                     if item.get("status") not in ("done", "cancelled")]
            decisions = [item for item in projection.get("decisions", [])
                         if item.get("status") in ("proposed", "accepted")]
            bridges = projection.get("bridges") or []
            rules_over = [item.get("with") for item in bridges
                          if item.get("relation") == "master" and
                          item.get("principal") == project_id]
            follows = [item.get("principal") for item in bridges
                       if item.get("relation") == "master" and
                       item.get("principal") != project_id]
            advised = [item.get("with") for item in bridges
                       if item.get("relation") == "advisor" and
                       item.get("principal") != project_id]
            context = project.get("context_version") or \
                snapshot["cursor"]["context_version"]
            self.briefed_context = context
            peek = cached_inbox(mark_read=False, limit=200)
            result = {
                "project": project_id, "context_version": context,
                "lead_director": project.get("lead_director"),
                "your_inbox": {
                    "unread_total": peek["unread_total"],
                    "unread_addressed_to_you": peek["unread_addressed"],
                    "unread_everyone": peek["unread_everyone"],
                    "unread_group_context": peek["unread_group_context"],
                    "may_have_more": peek["may_have_more"],
                    "messages_include_all_visible": True,
                    "pending_dispositions": peek[
                        "pending_dispositions"],
                    "pending_disposition_total": peek[
                        "pending_disposition_total"],
                    "pending_disposition_may_have_more": peek[
                        "pending_disposition_may_have_more"],
                    "hint": ("read every message with check_inbox; mentions/"
                             "replies assign attention, not visibility"),
                }, "bridges": bridges,
                "governance": ({"rules_over": rules_over,
                                "follows": follows, "advised_by": advised,
                                "hint": "cached verified bridge authority"}
                               if rules_over or follows or advised else None),
                "project_rules": adapter.rules_for_role(scope["role"]),
                "cloud_context": projection.get("cloud_context") or {
                    "content": "", "version": 0, "updated_by": None,
                    "updated_owner": None, "updated_at": None},
                "handoff": handoff,
                "handoff_updated_by": (latest or {}).get("updated_by"),
                "handoff_updated_owner": (handoff_event or {}).get("owner"),
                "handoff_attribution": (_offline_proxy_action(handoff_event)
                                        if handoff_event else None),
                "handoff_updated_at": (latest or {}).get("updated_at"),
                "open_tasks": tasks, "decisions": decisions,
                "recent_activity": (projection.get("full_log") or [])[-8:],
                "git": {"head": git_head(self.root),
                        "branch": git_branch(self.root)},
                "hint": (None if latest else "No cached handoff exists."),
            }
            return _offline_proxy_mark(result, adapter, proof)
        if name == "get_project_log":
            limit = max(1, min(int(args.get("limit") or 40), 1000))
            return _offline_proxy_mark({
                "project": project_id,
                "log": (projection.get("full_log") or [])[-limit:],
            }, adapter, proof)
        if name == "room_read":
            limit = max(1, min(int(args.get("limit") or 30), 500))
            since = args.get("since_seq")
            if since is not None:
                eligible = [classify_room(item) for item in cached_room
                            if int(item.get("seq") or 0) > int(since)]
                page = eligible[:limit]
                next_since = int(page[-1].get("seq") or since) \
                    if page else int(since)
                may_have_more = len(eligible) > len(page)
                older_messages_available = False
            else:
                older_messages_available = len(cached_room) > limit
                may_have_more = False
                page = [classify_room(item)
                        for item in cached_room[-limit:]]
                # Initial room reads return the latest visible page and then
                # follow the mirror's raw event head for future polling.
                next_since = int(snapshot["cursor"]["event_seq"] or 0)
            return _offline_proxy_mark({
                "project": project_id, "messages": page,
                "next_since_seq": next_since,
                "may_have_more": may_have_more,
                "older_messages_available": older_messages_available,
                "hint": (("latest cached page shown; call room_read with "
                          "since_seq=0 to page chronologically from the "
                          "beginning") if older_messages_available else
                         ("more cached room messages remain — call room_read "
                          "again with next_since_seq" if may_have_more else
                          "cached through mirror cursor; poll hosted MCP after "
                          "reconnect")),
            }, adapter, proof)
        if name == "check_inbox":
            mark_read = bool(args.get("mark_read", True))
            return _offline_proxy_mark(cached_inbox(
                mark_read=mark_read, limit=args.get("limit") or 50),
                adapter, proof)
        if name == "bridge_list":
            return _offline_proxy_mark({
                "project": project_id,
                "bridges": projection.get("bridges") or [],
            }, adapter, proof)
        if name == "task_list":
            status_filter = args.get("status")
            if status_filter and status_filter not in TASK_STATUSES:
                raise AttaccaError(
                    "status must be one of %s" % ", ".join(TASK_STATUSES))
            tasks = [dict(item) for item in projection.get("tasks", [])
                     if not status_filter or item.get("status") == status_filter]
            return _offline_proxy_mark(
                {"project": project_id, "tasks": tasks}, adapter, proof)
        if name == "task_show":
            task = _offline_proxy_task(projection, args.get("task_id"))
            task_events = [event for event in events
                           if event.get("task_id") == task.get("task_id")]
            task["actions"] = [_offline_proxy_action(event)
                               for event in task_events
                               if str(event.get("event_type") or "").startswith(
                                   "task.")]
            task["history"] = [
                "%s %s by %s" % (event.get("created_at"),
                                  event.get("event_type"),
                                  event.get("actor_id"))
                for event in task_events]
            return _offline_proxy_mark(task, adapter, proof)
        if name == "task_plan_get":
            return _offline_proxy_mark(_offline_proxy_plan(
                snapshot, args.get("task_id"), args.get("version")),
                adapter, proof)
        if name == "decision_list":
            wanted = args.get("status")
            decisions = [dict(item) for item in projection.get("decisions", [])
                         if not wanted or item.get("status") == wanted]
            return _offline_proxy_mark(
                {"project": project_id, "decisions": decisions},
                adapter, proof)
        if name == "rule_list":
            if args.get("include_disabled") or args.get("include_all"):
                raise AttaccaError(
                    "offline mirror contains applicable active rules only; "
                    "rule management views require hosted MCP")
            return _offline_proxy_mark({
                "project": project_id, "role": scope["role"],
                "rules": adapter.rules_for_role(scope["role"]),
            }, adapter, proof)
        if name == "agent_list":
            return _offline_proxy_mark({
                "project": project_id,
                "agents": projection.get("agents") or [],
            }, adapter, proof)
        if name == "list_projects":
            scoped_project = dict(project)
            scoped_project.setdefault("project_id", project_id)
            return _offline_proxy_mark({
                "projects": [scoped_project], "scope_limited": True,
                "you": {"actor_id": scope["actor_id"],
                        "actor_type": scope["actor_type"],
                        "runtime": self.runtime,
                        "owner": scope["principal_id"],
                        "identity_pending": False},
            }, adapter, proof)
        if name == "check_freshness":
            current = project.get("context_version") or \
                snapshot["cursor"]["context_version"]
            given = args.get("context_version")
            result = {"project": project_id,
                      "current_context_version": current}
            if given is None:
                result.update({"stale": None,
                               "hint": "pass a briefing context_version"})
            else:
                given = int(given)
                result.update({"your_context_version": given,
                               "stale": given < current})
                if given < current:
                    result["changes_since_your_briefing"] = (
                        projection.get("full_log") or [])[-20:]
                    result["action"] = (
                        "Cached context is newer; reload get_handoff before "
                        "queueing writes.")
            return _offline_proxy_mark(result, adapter, proof)
        if name == "search":
            query = args.get("query")
            terms = _search_query_terms(query)
            if not terms:
                raise AttaccaError(
                    "search query needs at least one letter or number")
            limit = max(1, min(int(args.get("limit") or 20), 100))

            def matches(value):
                text = " ".join(re.findall(
                    r"[^\W_]+", canonical_json(value).casefold(), re.UNICODE))
                return all(term in text for term in terms)

            event_hits = []
            for event in reversed(events):
                if not matches(event):
                    continue
                payload = event.get("payload") or {}
                item = {
                    "event_id": event.get("event_id"),
                    "seq": event.get("seq"),
                    "event_type": event.get("event_type"),
                    "at": event.get("created_at"),
                    "actor": event.get("actor_id"),
                    "actor_type": event.get("actor_type"),
                    "owner": event.get("owner"),
                    "task_id": event.get("task_id"),
                    "attribution": _offline_proxy_attribution(event),
                    "line": "%s by %s" % (
                        event.get("event_type"), event.get("actor_id")),
                    "payload": payload,
                }
                if event.get("event_type") == "room.message":
                    item.update({"body": payload.get("body") or "",
                                 "msg_type": payload.get("msg_type") or "chat",
                                 "mentions": payload.get("mentions") or [],
                                 "reply_to": payload.get("reply_to"),
                                 "origin_project": payload.get("origin_project"),
                                 "authority": payload.get("authority"),
                                 "mirrored_to": payload.get("mirrored_to") or []})
                event_hits.append(item)
                if len(event_hits) >= limit:
                    break
            task_hits = [dict(item) for item in projection.get("tasks", [])
                         if matches(item)][:limit]
            decision_hits = [dict(item) for item in
                             projection.get("decisions", [])
                             if matches(item)][:limit]
            rule_hits = [dict(item) for item in adapter.rules_for_role(
                scope["role"]) if matches(item)][:limit]
            handoff_hits = [dict(item) for item in
                            reversed(projection.get("handoffs", []))
                            if matches(item)][:limit]
            pending_hits = []
            for overlay in adapter.pending_overlays():
                if not matches(overlay):
                    continue
                pending_hits.append({
                    "kind": "pending_mutation",
                    "client_mutation_id": overlay["client_mutation_id"],
                    "operation": overlay["operation"],
                    "payload": overlay["payload"],
                    "metadata": overlay["metadata"],
                    "sync_state": overlay["sync_state"],
                    "pending_sync": True,
                    "local_only": True,
                    "hint": "Queued locally; not yet accepted by the hosted ledger.",
                })
                if len(pending_hits) >= limit:
                    break
            result = {
                "project": project_id, "query": str(query),
                "query_terms": terms, "term_semantics": "AND",
                "events": event_hits, "tasks": task_hits,
                "decisions": decision_hits, "rules": rule_hits,
                "handoff_versions": handoff_hits,
                "pending_mutations": pending_hits,
                "total_hits": sum(map(len, (event_hits, task_hits,
                                            decision_hits, rule_hits,
                                            handoff_hits, pending_hits))),
                "hint": "Results come from the last verified identity mirror.",
            }
            return _offline_proxy_mark(result, adapter, proof)
        raise AttaccaError("tool %s is not available from an offline mirror" % name)

    def _write(self, name, args, adapter, snapshot, proof, allow_queue):
        scope = snapshot["scope"]
        self._project_args(args, scope)
        if not allow_queue:
            raise AttaccaError(
                "hosted mutation outcome is ambiguous after the transport "
                "failed; it was not queued. Retry after the outage is confirmed")
        if name in OFFLINE_PROXY_EXPLICITLY_UNAVAILABLE:
            raise AttaccaError(
                "%s is unavailable offline because it changes identity, "
                "authority, or bridge policy; reconnect to hosted MCP" % name)
        operation = OFFLINE_PROXY_WRITE_OPERATIONS.get(name)
        if not operation or operation not in SYNC_OPERATION_TO_TOOL:
            raise AttaccaError(
                "%s is not an allowlisted offline mutation" % name)
        if name == "room_send" and args.get("target_project"):
            raise AttaccaError(
                "cross-project room delivery is unavailable offline")
        if name in ("rule_create", "rule_update", "update_handoff") \
                and scope["role"] != "director":
            raise AttaccaError(
                "%s requires verified Director authority" % name)
        if name in ("task_plan_set", "task_plan_submit") \
                and scope["role"] != "director":
            task = _offline_proxy_task(
                snapshot["projection"], args.get("task_id"))
            if task.get("status") != "claimed" \
                    or task.get("claimed_by") != scope["actor_id"] \
                    or (task.get("lease_until") and
                        task["lease_until"] < now_iso()):
                raise AttaccaError(
                    "offline plan edits require verified Director authority "
                    "or this AI's active cached task claim")
        if name == "task_plan_review" \
                and args.get("action") == "approve" \
                and scope["role"] != "director":
            raise AttaccaError(
                "offline plan approval requires verified Director authority")
        payload = dict(args)
        payload.pop("project", None)
        forbidden = sorted(SYNC_RESERVED_ARGUMENTS.intersection(payload))
        if forbidden:
            raise AttaccaError(
                "offline mutation cannot override trusted field(s): %s" %
                ", ".join(forbidden))
        if name == "update_handoff" and payload.get(
                "expected_context_version") is None:
            if self.briefed_context is None:
                raise AttaccaError(
                    "offline handoff update requires expected_context_version "
                    "from a cached get_handoff briefing")
            payload["expected_context_version"] = self.briefed_context
        supplied_id = payload.pop("_attacca_client_mutation_id", None)
        dependencies = _offline_proxy_collect_refs(payload)
        try:
            mutation = adapter.queue_mutation(
                operation, payload, depends_on=dependencies or None,
                client_mutation_id=supplied_id,
                git_branch=git_branch(self.root),
                git_revision=git_head(self.root),
                actor_id=scope["actor_id"], actor_type=scope["actor_type"],
                owner=scope["principal_id"])
        except Exception as error:
            raise AttaccaError("cannot queue offline mutation: %s" % error) \
                from error
        protocol, _ = _offline_sync_runtime()
        result = {
            "ok": True, "offline": True, "pending_sync": True,
            "operation": operation,
            "client_mutation_id": mutation["client_mutation_id"],
            "queued_at": mutation.get("created_at"),
            "attribution": {
                "project_id": scope["project_id"],
                "principal_id": scope["principal_id"],
                "actor_id": scope["actor_id"],
                "actor_type": scope["actor_type"], "role": scope["role"],
                "device_id": self.device_id,
                "git_branch": mutation.get("metadata", {}).get("git_branch"),
                "git_revision": mutation.get("metadata", {}).get("git_revision"),
            },
            "hint": "Durably queued; the watcher will replay it exactly once.",
        }
        if name == "task_create":
            result["local_refs"] = {
                "task_id": protocol.local_ref(
                    mutation["client_mutation_id"], ["task_id"])}
        result["sync"] = _offline_proxy_marker(adapter, proof)["sync"]
        result["sync"]["pending_count"] = adapter.status()["pending_count"]
        return result

    def _tool(self, name, args, allow_queue):
        adapter, snapshot, proof, _ = self._open()
        if name in OFFLINE_PROXY_READ_TOOLS:
            return self._read(name, args, adapter, snapshot, proof)
        if name in OFFLINE_PROXY_WRITE_OPERATIONS \
                or name in OFFLINE_PROXY_EXPLICITLY_UNAVAILABLE:
            return self._write(
                name, args, adapter, snapshot, proof, allow_queue)
        raise AttaccaError(
            "%s is explicitly unavailable offline; reconnect to hosted MCP"
            % name)

    def process(self, msg, transport_error, allow_queue=True):
        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}
        if method is None or msg_id is None:
            return None
        if method == "initialize":
            requested = params.get("protocolVersion")
            selected = requested if requested in MCP_SUPPORTED_PROTOCOLS \
                else MCP_DEFAULT_PROTOCOL
            return self._res(msg_id, {
                "protocolVersion": selected, "capabilities": {"tools": {}},
                "serverInfo": {"name": "attacca", "version": VERSION},
                "instructions": MCP_INSTRUCTIONS +
                "\nHosted transport is unavailable. Tool calls use only an "
                "exact verified identity-scoped mirror/outbox when present.",
            })
        if method == "tools/list":
            return self._res(msg_id, {"tools": MCP_TOOLS})
        if method == "ping":
            try:
                self._open()
                return self._res(msg_id, {})
            except AttaccaError as error:
                return self._err(
                    msg_id, -32000,
                    "attacca server unreachable at %s (%s); verified "
                    "offline continuity unavailable: %s" %
                    (self.url, transport_error, error))
        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            try:
                result = self._tool(name, args, allow_queue)
                return self._res(msg_id, {
                    "content": [{"type": "text", "text": json.dumps(
                        result, indent=2, ensure_ascii=False)}],
                    "isError": False})
            except AttaccaError as error:
                return self._res(msg_id, {
                    "content": [{"type": "text",
                                 "text": "error: %s" % error}],
                    "isError": True})
            except Exception as error:
                return self._res(msg_id, {
                    "content": [{"type": "text",
                                 "text": "unexpected offline error in %s: %s"
                                 % (name, error)}],
                    "isError": True})
        return self._err(msg_id, -32601, "method not found: %s" % method)

    def process_message(self, msg, transport_error, allow_queue=True):
        if isinstance(msg, list):
            if not msg:
                return self._err(None, -32600, "invalid request: empty batch")
            responses = []
            for item in msg:
                if not isinstance(item, dict):
                    responses.append(self._err(None, -32600, "invalid request"))
                    continue
                response = self.process(item, transport_error, allow_queue)
                if response is not None:
                    responses.append(response)
            return responses or None
        if not isinstance(msg, dict):
            return self._err(None, -32600, "invalid request")
        return self.process(msg, transport_error, allow_queue)


def _offline_proxy_write_request(msg):
    items = msg if isinstance(msg, list) else [msg]
    return any(isinstance(item, dict) and item.get("method") == "tools/call"
               and ((item.get("params") or {}).get("name") in
                    OFFLINE_PROXY_WRITE_OPERATIONS)
               for item in items)


def _offline_proxy_safe_unavailable(error):
    """True only when no hosted mutation request could have been received."""
    import urllib.error
    if isinstance(error, (ConnectionRefusedError, socket.gaierror)):
        return True
    if isinstance(error, urllib.error.URLError):
        reason = error.reason
        return isinstance(reason, (ConnectionRefusedError, socket.gaierror))
    return False


def run_connect_proxy(url=None, actor=None, actor_type=None, project=None,
                      stdin=None, stdout=None):
    """`connect`: hosted MCP client with verified identity-scoped continuity.

    This is what the Claude Code plugin (and any stdio-only tool) spawns:
    it normally forwards JSON-RPC lines to the server's /mcp endpoint. A
    confirmed checkout link pins the workspace; otherwise a Git fingerprint
    can find an existing match. On a real transport outage it may serve only
    the exact watcher-verified identity mirror and fsync allowlisted writes to
    that identity's outbox. If the server is local and down, it boots it in the
    background (disable: ATTACCA_AUTOSTART=0).
    """
    import urllib.error
    import urllib.request as urlreq
    # Explicit --url wins; otherwise use the machine source of truth before a
    # possibly stale inherited client-manifest environment value.
    url = configured_server_url(url)
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    start = Path(os.environ.get("CLAUDE_PROJECT_DIR")
                 or os.getcwd()).resolve()
    configured_project = project or os.environ.get(ENV_PROJECT)
    link = None if configured_project else find_project_link(start)
    linked_project = link["project_id"] if link else None
    root = str(Path(link["root_path"]).resolve()) if link \
        else str(git_worktree_root(start))
    repository_fingerprint = git_repository_fingerprint(root)
    autostart = os.environ.get("ATTACCA_AUTOSTART", "1") != "0"
    try:
        request_timeout = float(os.environ.get(
            "ATTACCA_CONNECT_TIMEOUT_SECONDS", "5"))
    except (TypeError, ValueError):
        request_timeout = 5.0
    request_timeout = max(0.1, min(request_timeout, 120.0))
    state = {"session": None, "ensured": False,
             "project": configured_project or linked_project}
    actor_hint = actor or os.environ.get(ENV_ACTOR)
    runtime_hint = normalize_agent_runtime(actor=actor_hint)
    device_id = load_device_id()
    offline_session = OfflineProxySession(
        url, lambda: state.get("project"), root, actor_hint, runtime_hint,
        device_id)

    def send_line(obj):
        stdout.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False))
        stdout.write("\n")
        stdout.flush()

    def post(body, retry=True):
        # Checkout links are intentionally replaceable by setup. Re-read the
        # nearest link before every request so a long-running client can move
        # from a missing/stale workspace to the user's confirmed selection
        # without another restart. An explicit --project / ATTACCA_PROJECT
        # remains authoritative and is never replaced here.
        if not configured_project:
            current_link = find_project_link(start)
            state["project"] = (current_link or {}).get("project_id")
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json"}
        if state["project"]:
            headers["X-Attacca-Project"] = state["project"]
        else:
            headers["X-Attacca-Root"] = root
            if repository_fingerprint:
                headers[REPOSITORY_FINGERPRINT_HEADER] = repository_fingerprint
        owner = load_owner()
        if owner:
            headers["X-Attacca-Owner"] = owner
        actor_id = qualify_actor(actor or os.environ.get(ENV_ACTOR),
                                 owner=owner)
        if actor_id:
            headers["X-Attacca-Actor"] = actor_id
        atype = actor_type or os.environ.get(ENV_ACTOR_TYPE)
        if atype:
            headers["X-Attacca-Actor-Type"] = atype
        runtime_hint = normalize_agent_runtime(actor=actor_id)
        require_usable_terminal_credential(
            url, runtime=runtime_hint, project_id=state["project"],
            actor_id=actor_id)
        token = load_api_token(
            url, runtime=runtime_hint, project_id=state["project"],
            actor_id=actor_id)
        if token:
            headers["Authorization"] = "Bearer " + token
        device_id = load_device_id()
        if device_id:
            headers[SYNC_DEVICE_HEADER] = device_id
        client_instance = load_client_instance_id(runtime_hint)
        if client_instance:
            headers[CLIENT_INSTANCE_HEADER] = client_instance
        branch_name = git_branch(root)
        revision = git_head(root)
        if branch_name:
            headers[GIT_BRANCH_HEADER] = branch_name
        if revision:
            headers[GIT_REVISION_HEADER] = revision
        if state["session"]:
            headers["Mcp-Session-Id"] = state["session"]
        req = urlreq.Request(url + "/mcp", data=body, headers=headers,
                             method="POST")
        try:
            with urlreq.urlopen(req, timeout=request_timeout) as resp:
                sid = resp.headers.get("Mcp-Session-Id")
                if sid:
                    state["session"] = sid
                resolved_project = resp.headers.get("X-Attacca-Project")
                if resolved_project:
                    state["project"] = resolved_project
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
                    sys.stderr.write("attacca connect: autostart failed: "
                                     "%s\n" % err)
        try:
            status, data = post(line.encode("utf-8"))
        except AuthenticationError as err:
            # Local proof that a modern credential is unusable is itself an
            # authorization latch. Never reinterpret it as a transport outage
            # and never open cached authority or queue a write.
            try:
                offline_session.latch_auth_required(401)
            except Exception:
                pass
            if expects_reply:
                send_line({"jsonrpc": "2.0", "id": msg_id, "error": {
                    "code": -32000,
                    "message": str(err),
                    "data": {"http_status": 401,
                             "category": "authentication_required"}}})
            continue
        except Exception as err:
            # A verified mirror is authoritative only for this exact cached
            # identity. Reads may always fall back after a transport failure;
            # writes queue only when the failure proves the request never
            # reached the host (for example connection refused / DNS failure).
            # Timeouts/resets remain ambiguous and are never double-applied.
            allow_queue = (not _offline_proxy_write_request(msg)
                           or _offline_proxy_safe_unavailable(err))
            fallback = offline_session.process_message(
                msg, err, allow_queue=allow_queue)
            if fallback is not None:
                send_line(fallback)
            continue
        if status in (401, 403):
            # Persist revocation before returning the hosted error. Otherwise a
            # later connection outage in this or a new proxy process could
            # reactivate a mirror whose authority the host already rejected.
            try:
                offline_session.latch_auth_required(status)
            except Exception:
                # The hosted auth failure still returns unchanged. Failure to
                # find/write an exact watcher entry cannot authorize fallback.
                pass
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
                    "message": str(payload.get("error") or payload),
                    "data": {
                        "http_status": status,
                        "category": ("authentication_required"
                                     if status in (401, 403)
                                     else "hosted_http_error"),
                    }}})
            continue
        if isinstance(payload, dict) and isinstance(
                payload.get("error"), dict) and status >= 400:
            error_data = payload["error"].setdefault("data", {})
            if isinstance(error_data, dict):
                error_data.setdefault("http_status", status)
                if status in (401, 403):
                    error_data.setdefault(
                        "category", "authentication_required")
        try:
            send_line(payload)
        except BrokenPipeError:
            return


# ---------------------------------------------------------------------------
# Setup emitters: per-tool MCP config + managed instruction blocks + git hook
# ---------------------------------------------------------------------------

def script_path():
    return str(Path(__file__).resolve())


WATCHER_CRON_MARKER = "# attacca-watcher"


def ensure_watcher_cron(root_path, url=None, actor=None, runtime=None,
                        python_exe=None, crontab_bin=None):
    """Install an idempotent per-minute crontab entry that keeps the Attacca
    background watcher alive even when no coding client is open.

    The lifecycle hooks already spawn a per-minute daemon while a client is
    running; this cron is the reliability layer the project requires so
    shared-state polling continues independently of any editor session. It
    is idempotent: it refreshes (never duplicates) the entry for this exact
    checkout root, and it fails soft where cron is unavailable so the
    lifecycle daemon simply remains the only polling path."""
    hook = Path(script_path()).resolve().parent / "hooks" / "session_start.py"
    if not hook.is_file():
        return {"ok": False, "status": "unavailable",
                "error": "background watcher hook is missing: %s" % hook}
    crontab_bin = crontab_bin or shutil.which("crontab")
    if not crontab_bin:
        return {"ok": False, "status": "unavailable",
                "error": "crontab is not available on this machine; the "
                         "lifecycle daemon remains the polling path"}
    python_exe = python_exe or sys.executable or "python3"
    root = str(Path(root_path).resolve())
    marker = "%s:%s" % (WATCHER_CRON_MARKER, root)
    parts = [shlex.quote(python_exe), shlex.quote(str(hook)),
             "--watcher-ensure", "--cwd", shlex.quote(root)]
    runtime = str(runtime or "").strip().lower()
    if runtime:
        parts.extend(["--runtime", shlex.quote(runtime)])
    env_prefix = ""
    if url:
        env_prefix += "ATTACCA_URL=%s " % shlex.quote(
            configured_server_url(url))
    if actor:
        env_prefix += "%s=%s " % (ENV_ACTOR, shlex.quote(str(actor)))
    line = "* * * * * %s%s >/dev/null 2>&1  %s" % (
        env_prefix, " ".join(parts), marker)
    try:
        listing = subprocess.run([crontab_bin, "-l"], capture_output=True,
                                 text=True)
    except Exception as err:
        return {"ok": False, "status": "error", "error": str(err)}
    current = listing.stdout if listing.returncode == 0 else ""
    lines = current.splitlines()
    marker_lines = [ln for ln in lines if marker in ln]
    if marker_lines == [line]:
        return {"ok": True, "status": "already", "line": line}
    kept = [ln for ln in lines if marker not in ln]
    kept.append(line)
    new_crontab = "\n".join(kept).rstrip("\n") + "\n"
    try:
        proc = subprocess.run([crontab_bin, "-"], input=new_crontab,
                              text=True, capture_output=True)
    except Exception as err:
        return {"ok": False, "status": "error", "error": str(err)}
    if proc.returncode != 0:
        return {"ok": False, "status": "error",
                "error": (proc.stderr or "").strip() or
                "crontab install failed"}
    return {"ok": True, "status": "refreshed" if marker_lines else "installed",
            "line": line}


def watcher_command(action, root_path=None, url=None, actor=None,
                    runtime=None, timeout=10):
    """Control the machine-global idle watcher through the bundled hook."""
    hook = Path(script_path()).resolve().parent / "hooks" / "session_start.py"
    if not hook.is_file():
        raise AttaccaError("background watcher hook is missing: %s" % hook)
    flag = {"start": "--watcher-ensure", "upgrade": "--watcher-upgrade",
            "status": "--watcher-status",
            "stop": "--watcher-stop"}.get(action)
    if not flag:
        raise AttaccaError(
            "watch action must be start, upgrade, status, or stop")
    command = [sys.executable, str(hook), flag]
    if root_path:
        command.extend(["--cwd", str(Path(root_path).resolve())])
    runtime = str(runtime or "").strip().lower()
    if runtime:
        command.extend(["--runtime", runtime])
    env = dict(os.environ)
    if url:
        env["ATTACCA_URL"] = configured_server_url(url)
    if actor:
        env[ENV_ACTOR] = str(actor)
    owner = load_owner()
    if owner:
        env[ENV_OWNER] = owner
    proc = subprocess.run(
        command, env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=timeout)
    try:
        result = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except ValueError:
        result = {"ok": False, "error": proc.stdout.strip() or
                  proc.stderr.strip() or "watcher returned invalid output"}
    if proc.returncode != 0 and not result.get("error"):
        result["ok"] = False
        result["error"] = proc.stderr.strip() or \
            "watcher command exited %d" % proc.returncode
    return result


def _normalize_hosted_server_url(value):
    """Validate and canonicalize one hosted Attacca base URL."""
    try:
        return _terminal_flow_runtime().canonical_server_url(value)
    except Exception as error:
        # Keep the core CLI/API exception contract while using exactly the
        # same full-URL/default-port/path-scope canonicalizer as terminal
        # enrollment, watcher state, credentials, and offline sync.
        raise AttaccaError(str(error)) from None


def _read_machine_config(home=None):
    path = machine_config_path(home)
    if not path.exists():
        return {}, path
    if path.is_symlink() or not path.is_file():
        raise AttaccaError(
            "machine Attacca config is not a safe regular file: %s" % path)
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise AttaccaError(
            "machine Attacca config is invalid: %s" % error)
    if not isinstance(data, dict):
        raise AttaccaError("machine Attacca config must be a JSON object")
    if data.get("server_url"):
        data["server_url"] = _normalize_hosted_server_url(
            data["server_url"])
    return data, path


def _packaged_server_url():
    root = Path(script_path()).parent
    for name in ("plugin-mcp.json", "kimi.plugin.json", ".mcp.json"):
        manifest = root / name
        if not manifest.is_file():
            continue
        try:
            data = json.loads(manifest.read_text())
            servers = data.get("mcpServers") or {}
            for server in servers.values():
                candidate = (server.get("env") or {}).get("ATTACCA_URL")
                if candidate:
                    return _normalize_hosted_server_url(candidate)
        except AttaccaError:
            raise
        except Exception:
            continue
    return None


def _effective_server_url(home=None):
    """Return the URL plus the exact configuration source used.

    Once ``attacca server set`` has created the machine file, it intentionally
    outranks inherited client-process environment and packaged defaults.  This
    prevents a stale plugin manifest from silently undoing a machine-wide
    switch on the next launch.  Explicit command flags still outrank it via
    ``configured_server_url(explicit=...)``.
    """
    machine, path = _read_machine_config(home)
    if machine.get("server_url"):
        return machine["server_url"], "machine", path
    environment = os.environ.get("ATTACCA_URL")
    if environment:
        return _normalize_hosted_server_url(environment), "environment", path
    packaged = _packaged_server_url()
    if packaged:
        return packaged, "packaged_plugin", path
    return DEFAULT_URL, "default", path


def configured_server_url(explicit=None, home=None):
    """Resolve the server packaged with the plugin/install bundle.

    Slash-command shells do not inherit an MCP subprocess's environment, so
    setup can read both the machine source of truth and the pre-wired plugin
    manifest beside this script. Explicit CLI values retain precedence.
    """
    if explicit is not None:
        return _normalize_hosted_server_url(explicit)
    return _effective_server_url(home)[0]


def _fsync_directory(directory):
    try:
        descriptor = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _atomic_switch_write(path, data, mode=None):
    """Atomically install bytes without following a destination symlink."""
    path = Path(path)
    if path.is_symlink():
        raise AttaccaError("refusing to replace symlinked config: %s" % path)
    if path.exists() and not path.is_file():
        raise AttaccaError("config target is not a regular file: %s" % path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if mode is None:
        mode = (path.stat().st_mode & 0o777) if path.exists() else 0o600
    descriptor, temporary = tempfile.mkstemp(
        prefix=".%s.attacca-switch." % path.name, dir=str(path.parent))
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(path))
        os.chmod(str(path), mode)
        _fsync_directory(path.parent)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


@contextlib.contextmanager
def _exclusive_config_lock(path):
    """Cross-process lock with a same-process thread guard."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.open("a+")
    try:
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def _codex_config_lock_path(config_path):
    """Return the one cooperative lock shared by every Codex TOML writer.

    The lock is deliberately adjacent to ``config.toml`` rather than under
    Attacca's machine state directory.  ``CODEX_HOME`` can point somewhere
    outside ``HOME`` and setup/install repair paths do not otherwise touch the
    machine server file, so using either of those locations would leave two
    independent lock domains for the same TOML target.
    """
    target = Path(config_path)
    return target.with_name(".%s.attacca.lock" % target.name)


@contextlib.contextmanager
def _exclusive_codex_config_lock(config_path):
    """Serialize all Attacca read-normalize-write cycles for Codex TOML."""
    lock_path = _codex_config_lock_path(config_path)
    with _MACHINE_CONFIG_THREAD_LOCK, _exclusive_config_lock(lock_path):
        # Lock files contain no data and must not become a source of machine
        # information disclosure when the caller has a permissive umask.
        try:
            os.chmod(str(lock_path), 0o600)
        except OSError as error:
            raise AttaccaError(
                "cannot make Codex config lock private: %s" % error)
        yield


def _snapshot_switch_paths(paths):
    snapshots = []
    for path in sorted({Path(value) for value in paths}, key=str):
        if path.is_symlink():
            raise AttaccaError("refusing symlinked config target: %s" % path)
        if path.exists() and not path.is_file():
            raise AttaccaError("config target is not a regular file: %s" % path)
        snapshots.append({
            "path": path,
            "existed": path.exists(),
            "data": path.read_bytes() if path.exists() else None,
            "mode": (path.stat().st_mode & 0o777) if path.exists() else None,
        })
    return snapshots


def _restore_switch_snapshots(snapshots):
    failures = []
    for snapshot in reversed(snapshots):
        path = snapshot["path"]
        try:
            if snapshot["existed"]:
                _atomic_switch_write(
                    path, snapshot["data"], mode=snapshot["mode"])
            elif path.exists() or path.is_symlink():
                path.unlink()
                _fsync_directory(path.parent)
        except Exception as error:
            failures.append("%s: %s" % (path, error))
    return failures


def _json_switch_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8")


def _read_switch_json(path, label):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AttaccaError("%s is not a safe regular JSON file: %s" %
                           (label, path))
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise AttaccaError("%s is invalid JSON (%s): %s" %
                           (label, path, error))
    if not isinstance(value, dict):
        raise AttaccaError("%s must be a JSON object: %s" % (label, path))
    return value


def _retarget_attacca_json(value, server_url):
    """Retarget one existing Attacca MCP entry, preserving every other key."""
    found = False
    changed = False
    for section_name in ("mcpServers", "servers", "mcp"):
        section = value.get(section_name)
        if not isinstance(section, dict) or "attacca" not in section:
            continue
        found = True
        entry = section["attacca"]
        if not isinstance(entry, dict):
            raise AttaccaError(
                "%s.attacca must be a JSON object" % section_name)
        args = entry.get("args")
        command = entry.get("command")
        command_values = []
        if isinstance(args, list):
            command_values.extend(str(item) for item in args)
        if isinstance(command, list):
            command_values.extend(str(item) for item in command)
        elif command is not None:
            command_values.append(str(command))
        connect_proxy = any(item == "connect" for item in command_values)
        environment_key = "environment" if "environment" in entry else "env"
        environment = entry.get(environment_key)
        if environment is not None and not isinstance(environment, dict):
            raise AttaccaError(
                "%s.attacca.%s must be an object" %
                (section_name, environment_key))
        if connect_proxy or (isinstance(environment, dict) and
                             "ATTACCA_URL" in environment):
            if environment is None:
                environment = {}
                entry[environment_key] = environment
            if environment.get("ATTACCA_URL") != server_url:
                environment["ATTACCA_URL"] = server_url
                changed = True
        remote_type = str(entry.get("type") or "").lower() in (
            "http", "remote")
        if "httpUrl" in entry:
            wanted = server_url + "/mcp"
            if entry.get("httpUrl") != wanted:
                entry["httpUrl"] = wanted
                changed = True
        if "url" in entry or remote_type:
            wanted = server_url + "/mcp"
            if entry.get("url") != wanted:
                entry["url"] = wanted
                changed = True
    return found, changed


def _watcher_state_path_for_home(home=None):
    override = os.environ.get("ATTACCA_WATCHER_DIR") if home is None else None
    directory = Path(override).expanduser().resolve() if override else \
        Path(home or Path.home()).expanduser().resolve() / ".attacca" / "watcher"
    return directory / "watcher-state.json"


def _watcher_subscription_key_for_url(entry, server_url):
    required = ("project_id", "runtime", "actor", "device_id", "root")
    if any(entry.get(key) in (None, "") for key in required):
        return None
    raw = json.dumps([
        server_url, entry["project_id"], entry["runtime"], entry["actor"],
        entry["device_id"], str(Path(entry["root"]).expanduser().resolve()),
    ], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


_WATCHER_REMOTE_STATE_FIELDS = (
    "event_cursor", "event_cursor_initialized", "snapshot", "last_poll_at",
    "last_poll_at_epoch", "last_error", "last_success_at",
    "last_success_at_epoch", "interval_seconds", "visibility_fingerprint",
    "context_version", "offline_mode", "offline_failure_count",
    "offline_pending_sync", "offline_mirror_stale", "wake_reason",
    "wake_requested_at_epoch",
)


def _merge_watcher_pending(left, right):
    output = []
    seen = set()
    for item in list(left or []) + list(right or []):
        marker = json.dumps(
            item, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if marker not in seen:
            seen.add(marker)
            output.append(item)
    return output[-50:]


def _retarget_watcher_state(state, server_url):
    subscriptions = state.get("subscriptions") or {}
    if not isinstance(subscriptions, dict):
        raise AttaccaError("watcher subscriptions must be a JSON object")
    rewritten = {}
    changed_count = 0
    switched_at = now_iso()
    for old_key, raw_entry in subscriptions.items():
        if not isinstance(raw_entry, dict):
            raise AttaccaError(
                "watcher subscription %s must be a JSON object" % old_key)
        entry = dict(raw_entry)
        previous = str(entry.get("server_url") or "").rstrip("/")
        new_key = _watcher_subscription_key_for_url(entry, server_url) or old_key
        changed = previous != server_url or new_key != old_key
        if changed:
            entry["server_url"] = server_url
            entry["key"] = new_key
            entry["previous_server_url"] = previous or None
            entry["server_switched_at"] = switched_at
            entry["next_poll_at_epoch"] = 0
            entry["cursor_registered_at_epoch"] = time.time()
            for field in _WATCHER_REMOTE_STATE_FIELDS:
                entry.pop(field, None)
            changed_count += 1
        existing = rewritten.get(new_key)
        if existing is not None:
            existing["pending"] = _merge_watcher_pending(
                existing.get("pending"), entry.get("pending"))
            existing["next_poll_at_epoch"] = 0
            changed_count += 1
        else:
            rewritten[new_key] = entry
    if changed_count:
        state["subscriptions"] = rewritten
    return changed_count


def _installed_plugin_roots(home, watcher_state, codex_root=None,
                            claude_root=None, kimi_root=None):
    """Discover only Attacca plugin roots already registered on this machine."""
    home = Path(home).expanduser().resolve()
    roots = set()
    stable = home / ".attacca" / "plugin" / "attacca"
    if (stable / "attacca.py").is_file():
        roots.add(stable)
    for entry in (watcher_state.get("subscriptions") or {}).values():
        if isinstance(entry, dict) and entry.get("plugin_root"):
            candidate = Path(entry["plugin_root"]).expanduser()
            if (candidate / "attacca.py").is_file():
                roots.add(candidate.resolve())

    kimi_root = Path(kimi_root or (home / ".kimi-code")).expanduser()
    kimi_state = kimi_root / "plugins" / "installed.json"
    if kimi_state.is_file():
        data = _read_switch_json(kimi_state, "Kimi plugin state")
        plugins = data.get("plugins") or []
        if not isinstance(plugins, list):
            raise AttaccaError("Kimi plugin state plugins must be an array")
        for item in plugins:
            if isinstance(item, dict) and item.get("id") == "attacca" \
                    and item.get("root"):
                candidate = Path(item["root"]).expanduser()
                if (candidate / "attacca.py").is_file():
                    roots.add(candidate.resolve())
    managed_kimi = kimi_root / "plugins" / "managed" / "attacca"
    if (managed_kimi / "attacca.py").is_file():
        roots.add(managed_kimi.resolve())

    claude_root = Path(claude_root or (home / ".claude")).expanduser()
    claude_state = claude_root / "plugins" / "installed_plugins.json"
    if claude_state.is_file():
        data = _read_switch_json(claude_state, "Claude plugin state")
        entries = ((data.get("plugins") or {}).get("attacca@agentg") or []) \
            if isinstance(data.get("plugins") or {}, dict) else []
        if not isinstance(entries, list):
            raise AttaccaError("Claude Attacca plugin state must be an array")
        for item in entries:
            if isinstance(item, dict) and item.get("installPath"):
                candidate = Path(item["installPath"]).expanduser()
                if (candidate / "attacca.py").is_file():
                    roots.add(candidate.resolve())

    codex_root = Path(codex_root or (home / ".codex")).expanduser()
    for cache in (codex_root / "plugins" / "cache",
                  claude_root / "plugins" / "cache"):
        if not cache.is_dir():
            continue
        for candidate in cache.rglob("attacca.py"):
            if candidate.is_file():
                roots.add(candidate.parent.resolve())
    return sorted(roots, key=str)


def _switch_json_candidates(home, watcher_state, codex_root=None,
                            claude_root=None, kimi_root=None):
    home = Path(home).expanduser().resolve()
    candidates = {}

    def add(tool, path):
        path = Path(path)
        if path.is_file() or path.is_symlink():
            candidates.setdefault(path.resolve() if not path.is_symlink()
                                  else path.absolute(), set()).add(tool)

    add("cursor", home / ".cursor" / "mcp.json")
    add("windsurf", home / ".codeium" / "windsurf" / "mcp_config.json")
    add("kimi", Path(kimi_root or (home / ".kimi-code")) / "mcp.json")
    for path in (
        home / ".config/Code/User/globalStorage/saoudrizwan.claude-dev"
               "/settings/cline_mcp_settings.json",
        home / ".config/Code - Insiders/User/globalStorage"
               "/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        home / "Library/Application Support/Code/User/globalStorage"
               "/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
    ):
        add("cline", path)
    for entry in (watcher_state.get("subscriptions") or {}).values():
        if not isinstance(entry, dict) or not entry.get("root"):
            continue
        root = Path(entry["root"]).expanduser()
        add("claude-project", root / ".mcp.json")
        add("gemini", root / ".gemini" / "settings.json")
        add("vscode", root / ".vscode" / "mcp.json")
        add("opencode", root / "opencode.json")
    for root in _installed_plugin_roots(
            home, watcher_state, codex_root=codex_root,
            claude_root=claude_root, kimi_root=kimi_root):
        add("plugin", root / "plugin-mcp.json")
        add("kimi-plugin", root / "kimi.plugin.json")
        add("codex-plugin", root / ".mcp.json")
    return [("+".join(sorted(tools)), path)
            for path, tools in sorted(candidates.items(), key=lambda item: str(item[0]))]


def _preserved_offline_outbox_summary(home, watcher_path, server_url):
    """Report, but never migrate, URL-scoped offline writes.

    A queued write is authorized against one authenticated server scope. Moving
    it to another hostname would silently change that trust boundary. The
    switch therefore leaves every mirror/outbox byte in its old URL partition
    and reports a conservative pending count to the user.
    """
    if not server_url:
        return {"server_url": None, "preserved": True,
                "pending_mutations": 0, "outboxes": 0,
                "unreadable_records": 0}
    offline_root = Path(watcher_path).parent / "offline"
    storage_directories = set()
    unreadable = 0
    if offline_root.is_dir():
        for mirror in offline_root.glob("*/mirrors/*/snapshot.json"):
            try:
                wrapper = json.loads(mirror.read_text())
                if isinstance(wrapper, dict) and \
                        str(wrapper.get("normalized_server_url") or "").rstrip(
                            "/") == server_url:
                    storage_directories.add(mirror.parents[2])
            except Exception:
                unreadable += 1
    pending = 0
    outboxes = 0
    for storage in storage_directories:
        for records in (storage / "outboxes").glob("*/records"):
            if not records.is_dir():
                continue
            outboxes += 1
            mutations = set()
            converged = set()
            for record_path in records.glob("*.json"):
                try:
                    record = json.loads(record_path.read_text())
                    if not isinstance(record, dict):
                        raise ValueError("offline journal record is not an object")
                    mutation_id = record.get("client_mutation_id")
                    if record.get("kind") == "mutation" and mutation_id:
                        mutations.add(mutation_id)
                    elif record.get("kind") == "converged" and mutation_id:
                        converged.add(mutation_id)
                except Exception:
                    unreadable += 1
            pending += len(mutations - converged)
    return {
        "server_url": server_url,
        "preserved": True,
        "storage_root": str(offline_root),
        "pending_mutations": pending,
        "outboxes": outboxes,
        "unreadable_records": unreadable,
        "note": ("Old-server writes remain in their authenticated URL "
                 "partition and are not replayed to the new server."),
    }


def _probe_server_for_switch(server_url, timeout=3):
    import urllib.error
    import urllib.request
    request = urllib.request.Request(
        server_url + "/healthz", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as error:
        raise AttaccaError(
            "cannot switch: %s/healthz is unreachable or invalid (%s)" %
            (server_url, error))
    if not isinstance(payload, dict) or not payload.get("ok") \
            or not isinstance(payload.get("version"), str) \
            or not payload["version"].strip():
        raise AttaccaError(
            "cannot switch: %s/healthz did not identify a healthy Attacca server"
            % server_url)
    return {"ok": True, "version": payload.get("version")}


def machine_server_show(home=None):
    effective, source, path = _effective_server_url(home)
    machine, _ = _read_machine_config(home)
    return {
        "ok": True,
        "server_url": effective,
        "source": source,
        "machine_server_url": machine.get("server_url"),
        "config_path": str(path),
        "configured": bool(machine.get("server_url")),
    }


def machine_server_set(server_url, home=None, validate=True, probe=None):
    """Atomically switch every installed Attacca client on one machine.

    The hosted server cannot perform this operation remotely: the command must
    run on each computer so it can update that computer's private client and
    watcher files. On any failure every touched byte is restored.
    """
    server_url = _normalize_hosted_server_url(server_url)
    if validate:
        health = (probe or _probe_server_for_switch)(server_url)
        if health is False or (isinstance(health, dict) and
                               not health.get("ok", True)):
            raise AttaccaError("target did not pass the Attacca health check")
    else:
        health = {"ok": None, "skipped": True}
    resolved_home = Path(home or Path.home()).expanduser().resolve()
    # A real CLI call (home=None) must honor each client's standard config-root
    # override. An explicit home is an isolation boundary used by setup/tests.
    effective_codex_root = codex_config_dir(home)
    effective_claude_root = _claude_config_root(home)
    effective_kimi_root = Path(
        os.environ.get("KIMI_CODE_HOME")
        if home is None and os.environ.get("KIMI_CODE_HOME")
        else (resolved_home / ".kimi-code")).expanduser().resolve()
    config_path = machine_config_path(resolved_home)
    machine_lock = config_path.with_name(".%s.lock" % config_path.name)
    watcher_path = _watcher_state_path_for_home(home)
    watcher_lock = watcher_path.with_name(".%s.lock" % watcher_path.name)
    codex_target = effective_codex_root / "config.toml"
    codex_lock = _codex_config_lock_path(codex_target)

    with _MACHINE_CONFIG_THREAD_LOCK, _exclusive_config_lock(machine_lock), \
            _exclusive_config_lock(watcher_lock), \
            _exclusive_config_lock(codex_lock):
        try:
            os.chmod(str(codex_lock), 0o600)
        except OSError as error:
            raise AttaccaError(
                "cannot make Codex config lock private: %s" % error)
        machine, _ = _read_machine_config(resolved_home)
        watcher_state = {}
        if watcher_path.exists() or watcher_path.is_symlink():
            watcher_state = _read_switch_json(
                watcher_path, "Attacca watcher state")
        watcher_server_urls = sorted({
            str(entry.get("server_url") or "").rstrip("/")
            for entry in (watcher_state.get("subscriptions") or {}).values()
            if isinstance(entry, dict) and entry.get("server_url")})
        previous = machine.get("server_url")
        if previous is None and len(watcher_server_urls) == 1:
            previous = watcher_server_urls[0]
        candidates = _switch_json_candidates(
            resolved_home, watcher_state,
            codex_root=effective_codex_root,
            claude_root=effective_claude_root,
            kimi_root=effective_kimi_root)
        prepared = []
        for tool, path in candidates:
            value = _read_switch_json(path, "%s MCP config" % tool)
            found, changed = _retarget_attacca_json(value, server_url)
            if found:
                prepared.append({"tool": tool, "path": path,
                                 "changed": changed,
                                 "data": _json_switch_bytes(value)})

        watcher_changed = _retarget_watcher_state(
            watcher_state, server_url) if watcher_state else 0
        watcher_bytes = _json_switch_bytes(watcher_state) \
            if watcher_changed else None

        codex_backup = codex_target.with_name(
            codex_target.name + ".attacca-backup")
        codex_present = False
        if codex_target.exists() or codex_target.is_symlink():
            repair = _codex_config_repair_module()
            try:
                original = codex_target.read_text()
                codex_present = any(
                    repair._is_attacca_table(repair._table_header_path(line))
                    for line in original.splitlines())
                if codex_present:
                    repaired = repair.replace_attacca_tables(
                        original, codex_connect_toml(
                            server_url, home=resolved_home))
                    repair.validate_repaired_toml(repaired)
            except repair.CodexConfigRepairError as error:
                raise AttaccaError(
                    "cannot safely prepare Codex config repair: %s" % error)
            except (OSError, UnicodeDecodeError) as error:
                raise AttaccaError("cannot read Codex config: %s" % error)

        machine_changed = previous != server_url or \
            machine.get("version") != MACHINE_CONFIG_SCHEMA_VERSION
        if machine_changed:
            machine["version"] = MACHINE_CONFIG_SCHEMA_VERSION
            machine["server_url"] = server_url
            machine["updated_at"] = now_iso()
        machine_bytes = _json_switch_bytes(machine)
        preserved_outbox_rows = [
            _preserved_offline_outbox_summary(
                resolved_home, watcher_path, candidate)
            for candidate in sorted(set(
                watcher_server_urls + ([previous] if previous else [])))
            if candidate != server_url]
        preserved_outbox = {
            "server_url": previous,
            "servers": preserved_outbox_rows,
            "preserved": True,
            "pending_mutations": sum(
                row["pending_mutations"] for row in preserved_outbox_rows),
            "outboxes": sum(row["outboxes"] for row in preserved_outbox_rows),
            "unreadable_records": sum(
                row["unreadable_records"] for row in preserved_outbox_rows),
            "note": ("Old-server writes remain in their authenticated URL "
                     "partitions and are not replayed to the new server."),
        }

        paths = [config_path]
        paths.extend(item["path"] for item in prepared if item["changed"])
        if watcher_bytes is not None:
            paths.append(watcher_path)
        if codex_present:
            paths.extend((codex_target, codex_backup))
        snapshots = _snapshot_switch_paths(paths)
        codex_changed = False
        try:
            if codex_present:
                before = codex_target.read_bytes()
                _configure_codex_locked(
                    None, server_url, DEFAULT_DB, stdio=False,
                    home=home, target=codex_target)
                codex_changed = codex_target.read_bytes() != before
            for item in prepared:
                if item["changed"]:
                    _atomic_switch_write(item["path"], item["data"])
            if watcher_bytes is not None:
                _atomic_switch_write(watcher_path, watcher_bytes)
            if machine_changed or not config_path.exists():
                _atomic_switch_write(config_path, machine_bytes, mode=0o600)
        except Exception as error:
            rollback_failures = _restore_switch_snapshots(snapshots)
            detail = "server switch rolled back after: %s" % error
            if rollback_failures:
                detail += "; rollback failure(s): %s" % "; ".join(
                    rollback_failures)
            raise AttaccaError(detail)

    rewired = [{"tool": item["tool"], "path": str(item["path"]),
                "changed": item["changed"]} for item in prepared]
    if codex_present:
        rewired.append({"tool": "codex", "path": str(codex_target),
                        "changed": codex_changed})
    changed = bool(machine_changed or codex_changed or watcher_changed or
                   any(item["changed"] for item in prepared))
    return {
        "ok": True,
        "server_url": server_url,
        "previous_server_url": previous,
        "config_path": str(config_path),
        "changed": changed,
        "health": health,
        "rewired": rewired,
        "watcher_state": str(watcher_path),
        "watcher_subscriptions_rewired": watcher_changed,
        "old_server_outbox": preserved_outbox,
        "url_scoped_credentials_preserved": True,
        "restart_required": sorted({item["tool"] for item in rewired
                                    if item["changed"]}),
        "note": ("Restart/reconnect listed coding clients. The watcher will "
                 "poll the new server on its next lightweight tick."),
    }


_remote_setup_auth = threading.local()


def _remote_setup_session(url):
    context = getattr(_remote_setup_auth, "context", None) or {}
    return context if context.get("server_url") == configured_server_url(url) \
        else None


def _remote_path_project(path):
    match = re.match(r"^/v1/projects/([^/]+)(?:/|$)", str(path or ""))
    if match:
        return urllib.parse.unquote(match.group(1))
    try:
        link = find_project_link(Path(os.getcwd()).resolve())
    except Exception:
        link = None
    return (link or {}).get("project_id")


def remote_json(url, method, path, body=None, actor=None, actor_type=None,
                use_auth=True, bearer_token=None, project_id=None):
    """Small stdlib REST client used by setup against the hosted server."""
    import urllib.error
    import urllib.request
    payload = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        configured_server_url(url) + path, data=payload, method=method)
    request.add_header("Accept", "application/json")
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    if actor:
        request.add_header("X-Attacca-Actor", actor)
    if actor_type:
        request.add_header("X-Attacca-Actor-Type", actor_type)
    if use_auth:
        session = _remote_setup_session(url)
        if bearer_token:
            # Explicit one-shot verification must not be shadowed by a
            # currently open setup session.
            request.add_header("Authorization", "Bearer " + bearer_token)
        elif session and session.get("kind") == "token":
            request.add_header(
                "Authorization", "Bearer " + session["bearer_token"])
        elif session:
            request.add_header("Cookie", session["cookie"])
            if method in ("POST", "PUT", "DELETE"):
                request.add_header("X-Attacca-CSRF", session["csrf"])
        else:
            runtime = normalize_agent_runtime(actor=actor)
            scoped_project = project_id or _remote_path_project(path)
            require_usable_terminal_credential(
                url, runtime=runtime, project_id=scoped_project,
                actor_id=actor)
            token = load_api_token(
                url, runtime=runtime, project_id=scoped_project,
                actor_id=actor)
            if token:
                request.add_header("Authorization", "Bearer " + token)
    owner = load_owner()
    if owner:
        request.add_header("X-Attacca-Owner", owner)
    device_id = load_device_id()
    if device_id:
        request.add_header(SYNC_DEVICE_HEADER, device_id)
    client_instance = load_client_instance_id(
        normalize_agent_runtime(actor=actor))
    if client_instance:
        request.add_header(CLIENT_INSTANCE_HEADER, client_instance)
    branch_name = git_branch(os.getcwd())
    revision = git_head(os.getcwd())
    if branch_name:
        request.add_header(GIT_BRANCH_HEADER, branch_name)
    if revision:
        request.add_header(GIT_REVISION_HEADER, revision)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read()
    except urllib.error.HTTPError as err:
        raw = err.read()
        try:
            detail = json.loads(raw).get("error")
        except Exception:
            detail = raw.decode("utf-8", "replace") or str(err)
        raise AttaccaError("server rejected setup: %s" % detail)
    except Exception as err:
        raise AttaccaError(
            "cannot reach Attacca server at %s: %s" % (url, err))
    try:
        return json.loads(raw) if raw else {}
    except Exception as err:
        raise AttaccaError("Attacca server returned invalid JSON: %s" % err)


def remote_setup_login(url, username, password):
    """Open one in-memory browser-style setup session; never persist a password."""
    import urllib.error
    import urllib.request
    server_url = configured_server_url(url)
    payload = json.dumps({"username": username, "password": password}).encode()
    request = urllib.request.Request(
        server_url + "/v1/auth/login", data=payload, method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read()
            cookie_lines = response.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            detail = json.loads(raw).get("error")
        except Exception:
            detail = "login failed"
        raise AuthenticationError(detail or "login failed")
    except Exception as error:
        raise AttaccaError(
            "cannot reach Attacca server at %s: %s" % (server_url, error))
    result = json.loads(raw) if raw else {}
    cookies = {}
    for line in cookie_lines:
        parsed = http.cookies.SimpleCookie()
        parsed.load(line)
        cookies.update({key: value.value for key, value in parsed.items()})
    csrf = result.get("csrf_token") or cookies.get("attacca_csrf")
    if not cookies.get("attacca_session") or not csrf:
        raise AttaccaError("Attacca login did not return a usable setup session")
    _remote_setup_auth.context = {
        "server_url": server_url,
        "kind": "session",
        "cookie": "attacca_session=%s; attacca_csrf=%s" %
                  (cookies["attacca_session"], csrf),
        "csrf": csrf,
        "username": (result.get("user") or {}).get("username"),
    }
    return result


def _resume_provisional_setup_terminal(url, terminal_flow, device_id,
                                       actor_id=None):
    """Load and verify one zero-binding terminal for setup across processes.

    The raw bearer remains private in the thread-local request context. Public
    results contain metadata only. A terminal with any AI binding is not a
    provisional human and can never regain broad setup authority through this
    path.
    """
    status = terminal_flow.terminal_credential_status(
        url, device_id=device_id, requested_bindings=[],
        credentials_path=CREDENTIALS_FILE)
    if status.get("status") != "ready" or not status.get("provisional_human"):
        return None
    token = terminal_flow.load_terminal_credential(
        url, device_id=device_id, requested_bindings=[],
        credentials_path=CREDENTIALS_FILE)
    if not token:
        return None
    try:
        verified = remote_json(
            url, "GET", "/v1/auth/status", actor=actor_id,
            actor_type="agent", bearer_token=token)
    except AttaccaError:
        return None
    principal = verified.get("principal") or {}
    if not verified.get("authenticated") \
            or principal.get("token_kind") != "terminal" \
            or principal.get("device_id") != device_id \
            or principal.get("bindings"):
        return None
    _remote_setup_auth.context = {
        "server_url": configured_server_url(url), "kind": "token",
        "bearer_token": token, "token_kind": "terminal",
        "token_id": principal.get("token_id"), "device_id": device_id,
        "provisional_human": True,
    }
    return {
        "required": True, "authenticated": True, "kind": "terminal",
        "token_kind": "terminal", "token_id": principal.get("token_id"),
        "device_id": device_id, "bindings": [], "binding_count": 0,
        "provisional_human": True,
        "credentials_file": str(CREDENTIALS_FILE),
    }


def _ensure_client_setup_auth(url, actor_id, interactive=False,
                              paste_token=False):
    """D-17 integrated setup authorization for one installed client."""
    server_url = configured_server_url(url)
    anonymous = remote_json(
        server_url, "GET", "/v1/auth/status", actor=actor_id,
        actor_type="agent", use_auth=False)
    if anonymous.get("bootstrap_required"):
        raise AuthenticationError(
            "account_bootstrap_required: open %s/app#settings" % server_url)
    try:
        link = find_project_link(Path(os.getcwd()).resolve())
    except Exception:
        link = None
    project_id = (link or {}).get("project_id")
    runtime = normalize_agent_runtime(actor=actor_id)
    client_instance = load_client_instance_id(runtime)
    flow = _terminal_flow_runtime()
    # Native MCP configs may inject the already-issued install key through
    # ATTACCA_API_TOKEN instead of the private registry.  Treat that exact
    # process-local secret as a first-class hot-load source; verify the signed
    # client instance with the server before setup uses it and never copy the
    # value into another file or response.
    environment_token = str(os.environ.get(ENV_API_TOKEN) or "").strip()
    if environment_token:
        try:
            checked = remote_json(
                server_url, "GET", "/v1/auth/status", actor=actor_id,
                actor_type="agent", bearer_token=environment_token,
                project_id=project_id)
        except AttaccaError:
            checked = {}
        principal = checked.get("principal") or {}
        if checked.get("authenticated") \
                and principal.get("token_kind") == "client" \
                and principal.get("client_instance") == client_instance:
            _remote_setup_auth.context = {
                "server_url": server_url,
                "kind": "token",
                "bearer_token": environment_token,
                "token_kind": "client",
                "token_id": principal.get("token_id"),
                "client_instance": client_instance,
            }
            return {
                "required": bool(anonymous.get("authentication_required")),
                "authenticated": True,
                "kind": "client_api_key",
                "token_kind": "client",
                "client_instance": client_instance,
                "username": (checked.get("user") or {}).get("username"),
                "hot_reload": True,
                "credential_source": "environment",
            }
    local = flow.client_api_key_status(
        server_url, client_instance=client_instance, runtime=runtime,
        project_id=project_id, credentials_path=CREDENTIALS_FILE)
    if local.get("authorized"):
        token = flow.load_client_api_key(
            server_url, client_instance=client_instance, runtime=runtime,
            project_id=project_id, credentials_path=CREDENTIALS_FILE)
        try:
            checked = remote_json(
                server_url, "GET", "/v1/auth/status", actor=actor_id,
                actor_type="agent", bearer_token=token,
                project_id=project_id)
        except AttaccaError:
            checked = {}
        principal = checked.get("principal") or {}
        if checked.get("authenticated") \
                and principal.get("token_kind") == "client" \
                and principal.get("client_instance") == client_instance:
            _remote_setup_auth.context = {
                "server_url": server_url,
                "kind": "token",
                "bearer_token": token,
                "token_kind": "client",
                "token_id": principal.get("token_id"),
                "client_instance": client_instance,
            }
            return {
                "required": bool(anonymous.get("authentication_required")),
                "authenticated": True,
                "kind": "client_api_key",
                "token_kind": "client",
                "client_instance": client_instance,
                "username": (checked.get("user") or {}).get("username"),
                "hot_reload": True,
                "credentials_file": str(CREDENTIALS_FILE),
            }
    if not anonymous.get("authentication_required") and not (
            interactive or paste_token):
        return {"required": False, "authenticated": False,
                "client_instance": client_instance, "hot_reload": True}
    try:
        result = flow.authorize_client(
            server_url, client_instance=client_instance, runtime=runtime,
            project_id=project_id,
            actor_id=actor_id if project_id else None,
            device_id=load_device_id(),
            credentials_path=CREDENTIALS_FILE,
            open_browser=True, prompt=True,
            wait=bool(interactive), max_wait_seconds=110)
    except flow.TerminalFlowError as error:
        raise AuthenticationError(
            "client_authorization_required: open %s" %
            flow.client_key_settings_url(server_url, client_instance)) \
            from error
    if not result.get("authorized"):
        raise AuthenticationError(
            "client_authorization_required: open %s; sign in, review the"
            " client, and explicitly Authorize or Deny it; this client polls"
            " silently and reconnects automatically" %
            result.get("authorization_url"))
    # The credential was server-verified before it was atomically persisted;
    # load it immediately so the same setup process continues without restart.
    token = flow.load_client_api_key(
        server_url, client_instance=client_instance, runtime=runtime,
        project_id=project_id, credentials_path=CREDENTIALS_FILE)
    _remote_setup_auth.context = {
        "server_url": server_url, "kind": "token",
        "bearer_token": token, "token_kind": "client",
        "token_id": result.get("token_id"),
        "client_instance": client_instance,
    }
    return dict(result, required=True, authenticated=True,
                kind="client_api_key", token_kind="client",
                credentials_file=str(CREDENTIALS_FILE))


def ensure_remote_setup_auth(url, actor_id, interactive=False, ask=None,
                             login_username=None, paste_token=False):
    """Authorize this installation through explicit browser pairing.

    The active AI opens a non-secret link, silently polls the human's explicit
    Authorize/Deny choice, stores the one-time credential, and reconnects.
    Exact project/actor selection remains separate on every request. Legacy
    paste flags remain parser-compatible but are not part of normal setup.
    """
    return _ensure_client_setup_auth(
        url, actor_id, interactive=interactive,
        paste_token=bool(paste_token or login_username))

    server_url = configured_server_url(url)
    anonymous = remote_json(
        server_url, "GET", "/v1/auth/status", actor=actor_id,
        actor_type="agent", use_auth=False)
    # Compatibility remains usable without forcing enrollment.  An explicit
    # hidden-TTY paste may still migrate a prepared terminal credential, but
    # browser enrollment is started after role selection with an exact actor.
    if not anonymous.get("authentication_required") \
            and not paste_token and not login_username:
        return {"required": False, "authenticated": False}
    if anonymous.get("bootstrap_required"):
        raise AuthenticationError(
            "admin_bootstrap_required: verification_uri=%s/app" % server_url)
    try:
        current = remote_json(
            server_url, "GET", "/v1/auth/status", actor=actor_id,
            actor_type="agent")
        principal = current.get("principal") or {}
        if current.get("authenticated") \
                and principal.get("token_kind") == "terminal":
            return {
                "required": bool(anonymous.get("authentication_required")),
                "authenticated": True, "kind": "terminal",
                "token_kind": "terminal",
                "device_id": principal.get("device_id"),
                "bindings": principal.get("bindings") or [],
            }
    except AttaccaError:
        pass

    try:
        link = find_project_link(Path(os.getcwd()).resolve())
    except Exception:
        link = None
    linked_project = (link or {}).get("project_id")
    # ``--login`` is retained as a compatibility spelling that explicitly
    # starts this device flow. Its legacy username argument is never sent and
    # no account password/session is carried across setup processes.

    terminal_flow = _terminal_flow_runtime()
    device_id = load_device_id()
    runtime = normalize_agent_runtime(actor=actor_id)
    state_path = CREDENTIALS_FILE.with_name("terminal-flow.json")
    instance_path = CREDENTIALS_FILE.with_name("client-instance.json")
    client_instance = terminal_flow.load_client_instance_id(
        storage_path=instance_path, runtime=runtime)
    local_status = terminal_flow.terminal_credential_status(
        server_url, device_id=device_id, requested_bindings=[],
        credentials_path=CREDENTIALS_FILE)
    stale_local_provisional = bool(
        local_status.get("status") == "ready" and
        local_status.get("provisional_human"))
    provisional = _resume_provisional_setup_terminal(
        server_url, terminal_flow, device_id, actor_id=actor_id)
    if provisional:
        return provisional
    requested_bindings = []
    if linked_project and str(actor_id or "").startswith(
            str(linked_project) + "."):
        requested_bindings.append({
            "project_id": linked_project, "actor_id": actor_id,
            "runtime": runtime,
        })
    try:
        if paste_token:
            saved = terminal_flow.paste_from_controlling_tty(
                server_url, device_id=device_id,
                requested_bindings=requested_bindings,
                credentials_path=CREDENTIALS_FILE,
                client_instance_id=client_instance)
            return {
                "required": bool(anonymous.get("authentication_required")),
                "authenticated": True, "kind": "terminal",
                "token_kind": "terminal", "device_id": device_id,
                "binding_count": saved.get("binding_count", 0),
                "credentials_file": str(CREDENTIALS_FILE),
            }
        flow_kwargs = {
            "device_id": device_id,
            "client_label": "Attacca terminal device",
            "requested_bindings": requested_bindings,
            "state_path": state_path,
            "open_browser": bool(interactive),
            "client_instance_id": client_instance,
        }
        if stale_local_provisional:
            # Local shape/expiry checks passed but server verification failed
            # (revoked, disabled owner, or another authoritative rejection).
            # Start a replacement flow instead of treating stale private bytes
            # as a usable setup principal.
            flow = terminal_flow.start_device_flow(server_url, **flow_kwargs)
        else:
            flow = terminal_flow.advance_device_flow(
                server_url, credentials_path=CREDENTIALS_FILE,
                force_poll=True, **flow_kwargs)
    except terminal_flow.TerminalFlowError as error:
        raise AuthenticationError(
            "terminal_enrollment_deferred: status=deferred; "
            "verification_uri=%s/app#settings" % server_url) from error
    if flow.get("status") in ("ready", "approved"):
        resumed = _resume_provisional_setup_terminal(
            server_url, terminal_flow, device_id, actor_id=actor_id)
        if resumed:
            return resumed
        return {
            "required": bool(anonymous.get("authentication_required")),
            "authenticated": True, "kind": "terminal",
            "token_kind": "terminal", "device_id": device_id,
            "credentials_file": str(CREDENTIALS_FILE),
        }
    details = ["status=%s" % str(flow.get("status") or "pending")]
    if flow.get("verification_uri_complete"):
        details.append("verification_uri_complete=%s" %
                       flow["verification_uri_complete"])
    elif flow.get("verification_uri"):
        details.append("verification_uri=%s" % flow["verification_uri"])
    if flow.get("user_code"):
        details.append("user_code=%s" % flow["user_code"])
    raise AuthenticationError(
        "terminal_enrollment_pending: " + "; ".join(details))


def close_remote_setup_session(url=None):
    """Revoke and forget the short-lived login used by guided setup."""
    context = getattr(_remote_setup_auth, "context", None)
    if not context:
        return {"ok": True, "closed": False}
    server_url = context.get("server_url")
    if url and server_url != configured_server_url(url):
        return {"ok": True, "closed": False}
    if context.get("kind") == "token":
        _remote_setup_auth.context = None
        return {"ok": True, "closed": True}
    try:
        remote_json(
            server_url, "POST", "/v1/auth/logout", {}, use_auth=True)
    finally:
        _remote_setup_auth.context = None
    return {"ok": True, "closed": True}


def provision_setup_agent_token(url, project_id, actor_id):
    """Ensure this exact registered actor is on the machine terminal token.

    The historical name remains for setup callers. No actor token is created;
    an existing terminal credential is extended atomically or a browser
    enrollment is started for the selected project/actor binding.
    """
    project_id = str(project_id or "").strip()
    actor_id = str(actor_id or "").strip()
    if not project_id or not actor_id:
        raise AttaccaError(
            "client_actor_required: project_id and actor_id are required")
    runtime = normalize_agent_runtime(actor=actor_id)
    flow = _terminal_flow_runtime()
    client_instance = load_client_instance_id(runtime)
    active = _remote_setup_session(url) or {}
    if active.get("kind") == "token" \
            and active.get("token_kind") == "client" \
            and active.get("client_instance") == client_instance:
        # Discovery/apply may already be authenticated from an injected
        # process-local key. Re-verify the now-registered exact actor and keep
        # using that same installation credential; do not force a second
        # browser prompt or silently duplicate an environment secret into the
        # private registry.
        encoded = urllib.parse.quote(project_id, safe="")
        checked = remote_json(
            configured_server_url(url), "GET",
            "/v1/projects/%s/agents" % encoded,
            actor=actor_id, actor_type="agent",
            bearer_token=active.get("bearer_token"),
            project_id=project_id)
        if any(item.get("agent_id") == actor_id
               for item in (checked.get("agents") or [])):
            return {
                "created": False,
                "credential_kind": "client",
                "status": "ready",
                "actor_id": actor_id,
                "project_id": project_id,
                "runtime": runtime,
                "client_instance": client_instance,
                "credential_saved": False,
                "credential_source": "active_process",
                "hot_reload": True,
            }
    status = flow.client_api_key_status(
        configured_server_url(url), client_instance=client_instance,
        runtime=runtime, project_id=project_id,
        credentials_path=CREDENTIALS_FILE)
    if not status.get("authorized"):
        try:
            status = flow.authorize_client(
                configured_server_url(url), client_instance=client_instance,
                runtime=runtime, project_id=project_id, actor_id=actor_id,
                device_id=load_device_id(),
                credentials_path=CREDENTIALS_FILE,
                open_browser=True, prompt=True)
        except flow.TerminalFlowError as error:
            raise AuthenticationError(
                "client_authorization_required: open %s" %
                flow.client_key_settings_url(
                    configured_server_url(url), client_instance)) from error
    if not status.get("authorized"):
        raise AuthenticationError(
            "client_authorization_required: open %s" %
            status.get("authorization_url"))
    return {
        "created": False,
        "credential_kind": "client",
        "status": "ready",
        "actor_id": actor_id,
        "project_id": project_id,
        "runtime": runtime,
        "client_instance": client_instance,
        "credential_saved": True,
        "hot_reload": True,
        "credentials_file": str(CREDENTIALS_FILE),
    }

    terminal_flow = _terminal_flow_runtime()
    device_id = load_device_id()
    state_path = CREDENTIALS_FILE.with_name("terminal-flow.json")
    instance_path = CREDENTIALS_FILE.with_name("client-instance.json")
    client_instance = terminal_flow.load_client_instance_id(
        storage_path=instance_path, runtime=runtime)
    requested = [{"project_id": project_id, "actor_id": actor_id,
                  "runtime": runtime}]
    try:
        local = terminal_flow.terminal_credential_status(
            configured_server_url(url), device_id=device_id,
            requested_bindings=[], credentials_path=CREDENTIALS_FILE)
        if local.get("status") == "ready" \
                and local.get("provisional_human"):
            bound = terminal_flow.add_terminal_binding(
                configured_server_url(url), device_id=device_id,
                project_id=project_id, actor_id=actor_id, runtime=runtime,
                credentials_path=CREDENTIALS_FILE,
                client_instance_id=client_instance)
            return {
                "created": bound.get("status") == "bound",
                "credential_kind": "terminal",
                "status": bound.get("status"),
                "actor_id": actor_id, "project_id": project_id,
                "runtime": runtime, "device_id": device_id,
                "binding_count": bound.get("binding_count"),
                "credential_saved": bool(bound.get("credential_saved")),
                "credentials_file": str(CREDENTIALS_FILE),
            }
        result = terminal_flow.advance_device_flow(
            configured_server_url(url), device_id=device_id,
            client_label="Attacca terminal device",
            requested_bindings=requested,
            state_path=state_path, credentials_path=CREDENTIALS_FILE,
            open_browser=False, force_poll=True,
            client_instance_id=client_instance)
        public = {
            "created": result.get("status") == "approved",
            "credential_kind": "terminal",
            "status": result.get("status"),
            "actor_id": actor_id, "project_id": project_id,
            "runtime": runtime, "device_id": device_id,
            "credentials_file": str(CREDENTIALS_FILE),
        }
        for key in ("verification_uri", "verification_uri_complete",
                    "user_code", "action_required", "credential_saved"):
            if result.get(key) is not None:
                public[key] = result[key]
        return public
    except terminal_flow.TerminalFlowError as error:
        raise AuthenticationError(
            "terminal_enrollment_deferred: project_id=%s; actor_id=%s; "
            "verification_uri=%s/app#settings" % (
                project_id, actor_id, configured_server_url(url))) from error
    finally:
        try:
            close_remote_setup_session(url)
        except Exception:
            # Terminal state is independently hash/device verified. Failure to
            # close an old short-lived setup session must not discard it.
            _remote_setup_auth.context = None


def _client_instance_for_runtime(runtime, home=None):
    flow = _terminal_flow_runtime()
    path = flow.default_client_instance_path(home=home, runtime=runtime)
    return flow.load_client_instance_id(storage_path=path, runtime=runtime)


def mcp_server_config(actor, project_id, db_path, home=None):
    """Stdio (direct-DB) MCP config: the tool spawns a local shim."""
    # Always pin the DB path: the config already pins the absolute script
    # path, and the server may be spawned from any cwd/env.
    env = {ENV_ACTOR: actor, ENV_DB: str(db_path),
           ENV_CLIENT_INSTANCE: _client_instance_for_runtime(actor, home)}
    if project_id:
        env[ENV_PROJECT] = project_id
    return {"command": "python3", "args": [script_path(), "mcp"], "env": env}


def mcp_http_config(actor, project_id, url, home=None):
    """HTTP MCP config: the tool is a thin client of the hosted server."""
    headers = {"X-Attacca-Actor": actor,
               CLIENT_INSTANCE_HEADER:
                   _client_instance_for_runtime(actor, home)}
    if project_id:
        headers["X-Attacca-Project"] = project_id
    return {"type": "http", "url": url.rstrip("/") + "/mcp", "headers": headers}


def mcp_connect_config(actor, url, home=None):
    """Stdio-shaped config that is still a pure server client: the tool
    spawns `attacca.py connect`, which forwards to the server and resolves a
    confirmed checkout link or matching Git remote."""
    return {"command": "python3", "args": [script_path(), "connect"],
            "env": {
                ENV_ACTOR: actor,
                ENV_CLIENT_INSTANCE: _client_instance_for_runtime(actor, home),
                "ATTACCA_URL": url.rstrip("/")}}


def codex_http_toml(project_id, url):
    pairs = ['"X-Attacca-Actor" = "codex"']
    if project_id:
        pairs.append('"X-Attacca-Project" = "%s"' % project_id)
    return "\n".join([
        "[mcp_servers.attacca]",
        'url = "%s/mcp"' % url.rstrip("/"),
        "http_headers = { %s }" % ", ".join(pairs),
    ])


def codex_connect_toml(url, home=None):
    """Global Codex config: connect proxy, project resolved per checkout.
    Works on every Codex version (plain stdio server from Codex's view)."""
    return "\n".join([
        "[mcp_servers.attacca]",
        'command = "python3"',
        'args = ["%s", "connect"]' % script_path(),
        'env = { "%s" = "codex", "%s" = "%s", "ATTACCA_URL" = "%s" }'
        % (ENV_ACTOR, ENV_CLIENT_INSTANCE,
           _client_instance_for_runtime("codex", home), url.rstrip("/")),
    ])


def codex_stdio_toml(project_id, db_path, home=None):
    path = script_path()
    env_pairs = ['"%s" = "codex"' % ENV_ACTOR,
                 '"%s" = "%s"' % (
                     ENV_CLIENT_INSTANCE,
                     _client_instance_for_runtime("codex", home)),
                 '"%s" = "%s"' % (ENV_DB, db_path)]
    if project_id:
        env_pairs.append('"%s" = "%s"' % (ENV_PROJECT, project_id))
    return "\n".join([
        "[mcp_servers.attacca]",
        'command = "python3"',
        'args = ["%s", "mcp"]' % path,
        "env = { %s }" % ", ".join(env_pairs),
    ])


def write_mcp_json_file(root_path, server_config):
    """Create or merge <root>/.mcp.json with the attacca server entry."""
    target = Path(root_path) / ".mcp.json"
    existing = {}
    if target.exists():
        try:
            existing = json.loads(target.read_text())
        except Exception:
            raise AttaccaError(
                "%s exists but is not valid JSON; fix it first" % target)
    if not isinstance(existing, dict) or \
            not isinstance(existing.get("mcpServers", {}), dict):
        raise AttaccaError(
            "%s exists but does not look like an MCP config (expected a "
            "JSON object with an optional mcpServers object)" % target)
    existing.setdefault("mcpServers", {})["attacca"] = server_config
    target.write_text(json.dumps(existing, indent=2) + "\n")
    return str(target)


def _claude_config_root(home=None):
    """Return Claude Code's config root, honoring its standard override."""
    if home is None and os.environ.get("CLAUDE_CONFIG_DIR"):
        return Path(os.environ["CLAUDE_CONFIG_DIR"]).expanduser()
    return Path(home or Path.home()).expanduser() / ".claude"


def claude_attacca_scoped_registrations(home=None):
    """Read Attacca's project/local registrations from Claude plugin state.

    Claude resolves ``plugin uninstall --scope project|local`` against the
    command's current directory.  Its version-2 installed state records the
    directory that owns each registration as ``projectPath``; callers need
    that path in order to remove registrations created from another checkout.
    """
    state_path = _claude_config_root(home) / "plugins" / \
        "installed_plugins.json"
    if not state_path.is_file():
        return []
    try:
        data = json.loads(state_path.read_text())
    except (OSError, ValueError) as err:
        raise AttaccaError("Claude plugin state is invalid: %s" % err)
    plugins = data.get("plugins") if isinstance(data, dict) else None
    if not isinstance(plugins, dict):
        raise AttaccaError(
            "Claude plugin state must contain a plugins object")
    entries = plugins.get("attacca@agentg") or []
    if not isinstance(entries, list):
        raise AttaccaError(
            "Claude Attacca plugin state must contain a registration array")
    registrations = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        scope = entry.get("scope")
        if scope not in ("project", "local"):
            continue
        registrations.append({"scope": scope,
                              "project_path": entry.get("projectPath")})
    return registrations


def uninstall_claude_scoped_attacca_plugins(home=None,
                                             claude_executable="claude"):
    """Remove cross-directory Claude project/local Attacca registrations.

    Missing checkout directories are stale, inactive registrations and are
    skipped safely.  Existing directories are de-duplicated by scope/path and
    passed as ``cwd`` directly to ``subprocess.run`` so spaces and shell
    metacharacters in project paths cannot change the command.
    """
    result = {"ok": True, "uninstalled": [], "missing": [],
              "invalid": [], "failed": []}
    try:
        registrations = claude_attacca_scoped_registrations(home)
    except AttaccaError as err:
        result["ok"] = False
        result["error"] = str(err)
        return result

    seen = set()
    for registration in registrations:
        scope = registration["scope"]
        raw_path = registration.get("project_path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            result["invalid"].append(registration)
            continue
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            result["invalid"].append(registration)
            continue
        try:
            project_path = candidate.resolve()
        except OSError:
            result["invalid"].append(registration)
            continue
        item = {"scope": scope, "project_path": str(project_path)}
        key = (scope, str(project_path))
        if key in seen:
            continue
        seen.add(key)
        if not project_path.is_dir():
            result["missing"].append(item)
            continue
        command = [str(claude_executable), "plugin", "uninstall",
                   "attacca@agentg", "--scope", scope, "--keep-data", "-y"]
        try:
            proc = subprocess.run(
                command, cwd=str(project_path), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                timeout=30)
        except (OSError, subprocess.SubprocessError) as err:
            failed = dict(item)
            failed["error"] = str(err)
            result["failed"].append(failed)
            continue
        if proc.returncode == 0:
            result["uninstalled"].append(item)
        else:
            failed = dict(item)
            failed["returncode"] = proc.returncode
            failed["error"] = (proc.stderr or proc.stdout or "").strip()[-500:]
            result["failed"].append(failed)
    if result["invalid"] or result["failed"]:
        result["ok"] = False
    return result


def claude_plugin_is_installed(home=None):
    """Whether this machine already has the native Attacca Claude plugin.

    Native Claude plugins contribute their own MCP server. Keeping a second
    checkout `.mcp.json` entry would expose the same Attacca server twice.
    """
    config_root = _claude_config_root(home)
    state_path = config_root / "plugins" / "installed_plugins.json"
    try:
        data = json.loads(state_path.read_text())
        entries = (data.get("plugins") or {}).get("attacca@agentg") or []
        return any(entry.get("scope") in ("user", "project", "local")
                   for entry in entries if isinstance(entry, dict))
    except Exception:
        return False


def remove_attacca_mcp_json_entry(root_path):
    """Remove only Attacca's checkout MCP entry, preserving all other config."""
    target = Path(root_path) / ".mcp.json"
    if not target.is_file():
        return None
    try:
        data = json.loads(target.read_text())
    except Exception:
        raise AttaccaError("%s exists but is not valid JSON; fix it first" % target)
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict) or "attacca" not in servers:
        return None
    del servers["attacca"]
    if not servers:
        data.pop("mcpServers", None)
    if data:
        temporary = target.with_name(".%s.%d.%s.tmp" %
                                     (target.name, os.getpid(),
                                      secrets.token_hex(4)))
        temporary.write_text(json.dumps(data, indent=2) + "\n")
        try:
            os.replace(str(temporary), str(target))
        except FileNotFoundError:
            temporary.unlink(missing_ok=True)
            return None
    else:
        try:
            target.unlink()
        except FileNotFoundError:
            return None
    return str(target)


def reconcile_native_claude_checkout(path=None, home=None):
    """Remove a legacy project MCP duplicate after native plugin install.

    The universal installer otherwise has no checkout side effects. This
    narrowly scoped upgrade only runs when the current directory is already an
    Attacca-linked checkout and Claude's native plugin is active; it removes
    the managed ``attacca`` key while preserving every unrelated MCP server and
    project setting.
    """
    start = Path(path or os.getcwd()).resolve()
    if not claude_plugin_is_installed(home):
        return {"changed": False, "reason": "native_plugin_not_installed"}
    link = find_project_link(start)
    if not link:
        return {"changed": False, "reason": "checkout_not_linked"}
    removed = remove_attacca_mcp_json_entry(link["root_path"])
    return {"changed": bool(removed), "removed": removed,
            "root_path": link["root_path"],
            "project_id": link["project_id"]}


def install_kimi_native_plugin(source_root, home=None):
    """Install/update Attacca in Kimi's managed plugin store.

    Kimi 0.37 exposes native plugin installation only through its interactive
    ``/plugins`` UI. The universal shell installer has already received the
    user's authorization to install this exact downloaded bundle, so it mirrors
    Kimi's version-1 installed-store contract: an atomic managed copy and one
    idempotent ``attacca`` record. Any unrelated plugins and capability choices
    are preserved. The old global Attacca MCP entry is removed because the
    native plugin contributes the same server plus commands, skills, and hooks.
    """
    source = Path(source_root).expanduser().resolve()
    manifest_path = source / "kimi.plugin.json"
    if not manifest_path.is_file():
        raise AttaccaError("Kimi plugin manifest is missing: %s" % manifest_path)
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError) as err:
        raise AttaccaError("Kimi plugin manifest is invalid: %s" % err)
    plugin_id = str(manifest.get("name") or "").strip()
    if plugin_id != "attacca":
        raise AttaccaError("expected Kimi plugin name 'attacca', got %r" % plugin_id)

    user_home = Path(home or Path.home()).expanduser().resolve()
    kimi_home = Path((user_home / ".kimi-code") if home is not None else
                     (os.environ.get("KIMI_CODE_HOME") or
                      (user_home / ".kimi-code"))).expanduser().resolve()
    plugins_dir = kimi_home / "plugins"
    managed_parent = plugins_dir / "managed"
    managed_root = managed_parent / plugin_id
    installed_path = plugins_dir / "installed.json"
    if installed_path.is_file():
        try:
            installed = json.loads(installed_path.read_text())
        except (OSError, ValueError) as err:
            raise AttaccaError("Kimi plugin state is invalid: %s" % err)
        if not isinstance(installed, dict) or not isinstance(
                installed.get("plugins"), list):
            raise AttaccaError("Kimi plugin state must contain a plugins array")
    else:
        installed = {"version": 1, "plugins": []}
    global_mcp = kimi_home / "mcp.json"
    global_data = None
    if global_mcp.is_file():
        try:
            global_data = json.loads(global_mcp.read_text())
        except (OSError, ValueError) as err:
            raise AttaccaError("Kimi MCP config is invalid: %s" % err)
        if not isinstance(global_data, dict):
            raise AttaccaError("Kimi MCP config must be a JSON object")

    managed_parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".%s-" % plugin_id,
                                    dir=str(managed_parent)))
    backup = None

    def remove_managed_path(path):
        if path is None or not os.path.lexists(str(path)):
            return
        if path.is_symlink() or path.is_file():
            path.unlink()
        else:
            shutil.rmtree(str(path))

    try:
        shutil.copytree(str(source), str(staging), dirs_exist_ok=True)
        if os.path.lexists(str(managed_root)):
            backup = Path(tempfile.mkdtemp(
                prefix=".%s-backup-" % plugin_id,
                dir=str(managed_parent)))
            backup.rmdir()
            os.replace(str(managed_root), str(backup))
        try:
            os.replace(str(staging), str(managed_root))
            staging = None
        except BaseException:
            if backup is not None and not os.path.lexists(str(managed_root)):
                os.replace(str(backup), str(managed_root))
                backup = None
            raise
        remove_managed_path(backup)
        backup = None
    finally:
        remove_managed_path(staging)
        if backup is not None and not os.path.lexists(str(managed_root)):
            os.replace(str(backup), str(managed_root))
            backup = None
        remove_managed_path(backup)

    now = now_iso()
    existing = next((item for item in installed["plugins"]
                     if isinstance(item, dict) and item.get("id") == plugin_id),
                    None)
    entry = {
        "id": plugin_id,
        "root": str(managed_root.resolve()),
        "source": "local-path",
        "enabled": existing.get("enabled", True) if existing else True,
        "installedAt": existing.get("installedAt", now) if existing else now,
        "updatedAt": now,
        "originalSource": str(source),
    }
    if existing and existing.get("capabilities") is not None:
        entry["capabilities"] = existing["capabilities"]
    installed["version"] = 1
    installed["plugins"] = [
        item for item in installed["plugins"]
        if not (isinstance(item, dict) and item.get("id") == plugin_id)
    ] + [entry]
    plugins_dir.mkdir(parents=True, exist_ok=True)
    temporary = installed_path.with_name(".%s.%d.tmp" %
                                         (installed_path.name, os.getpid()))
    temporary.write_text(json.dumps(installed, indent=2) + "\n")
    os.replace(str(temporary), str(installed_path))

    removed_global_mcp = None
    if global_data is not None:
        data = global_data
        servers = data.get("mcpServers")
        if isinstance(servers, dict) and "attacca" in servers:
            del servers["attacca"]
            if not servers:
                data.pop("mcpServers", None)
            if data:
                temporary = global_mcp.with_name(
                    ".%s.%d.tmp" % (global_mcp.name, os.getpid()))
                temporary.write_text(json.dumps(data, indent=2) + "\n")
                os.replace(str(temporary), str(global_mcp))
            else:
                global_mcp.unlink()
            removed_global_mcp = str(global_mcp)
    return {"ok": True, "plugin_id": plugin_id,
            "root": str(managed_root.resolve()),
            "state_file": str(installed_path),
            "enabled": bool(entry["enabled"]),
            "removed_global_mcp": removed_global_mcp}


def server_alive(url):
    try:
        import urllib.request as _rq
        with _rq.urlopen(url.rstrip("/") + "/healthz", timeout=2) as resp:
            return bool(json.loads(resp.read()).get("ok"))
    except Exception:
        return False


def ensure_server_running(url, db_path):
    """Start the attacca server in the background if it isn't up yet.
    Returns {"started": bool, "log": path|None, "pid": int|None}."""
    if server_alive(url):
        return {"started": False, "log": None, "pid": None}
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise AttaccaError(
            "server at %s is not reachable, and it is not local so setup "
            "cannot start it for you — start it on that machine with "
            "`attacca.py serve`" % url)
    port = parsed.port or DEFAULT_PORT
    log_path = Path(db_path).resolve().parent / "server.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "ab") as log:
        proc = subprocess.Popen(
            [sys.executable, script_path(), "--db", str(db_path), "serve",
             "--host", host, "--port", str(port)],
            stdout=log, stderr=log, stdin=subprocess.DEVNULL,
            start_new_session=True)
    # The server intentionally outlives setup. Keep a daemon reaper waiting on
    # the detached child so Python neither leaks a zombie nor emits a
    # ResourceWarning when the local Popen object leaves scope.
    threading.Thread(target=proc.wait, daemon=True,
                     name="attacca-server-%d" % proc.pid).start()
    for _ in range(50):
        if server_alive(url):
            return {"started": True, "log": str(log_path), "pid": proc.pid}
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    raise AttaccaError(
        "tried to start the server but %s/healthz did not come up — "
        "see the log at %s" % (url, log_path))


def codex_config_dir(home=None):
    if home is None and os.environ.get("CODEX_HOME"):
        return Path(os.environ["CODEX_HOME"]).expanduser()
    return Path(home or Path.home()) / ".codex"


_CODEX_CONFIG_REPAIR_MODULE = None
_CODEX_CONFIG_REPAIR_LOCK = threading.Lock()


def _codex_config_repair_module():
    """Load the bundled standalone repair helper without package assumptions."""
    global _CODEX_CONFIG_REPAIR_MODULE
    if _CODEX_CONFIG_REPAIR_MODULE is not None:
        return _CODEX_CONFIG_REPAIR_MODULE
    with _CODEX_CONFIG_REPAIR_LOCK:
        if _CODEX_CONFIG_REPAIR_MODULE is not None:
            return _CODEX_CONFIG_REPAIR_MODULE
        path = (Path(script_path()).resolve().parent / "tools" /
                "repair_codex_config.py")
        if not path.is_file():
            raise AttaccaError(
                "Codex config repair helper is missing from this Attacca install")
        spec = importlib.util.spec_from_file_location(
            "attacca_codex_config_repair_runtime", path)
        if spec is None or spec.loader is None:
            raise AttaccaError("cannot load the Codex config repair helper")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _CODEX_CONFIG_REPAIR_MODULE = module
    return _CODEX_CONFIG_REPAIR_MODULE


def _configure_codex_locked(project_id, url, db_path, stdio=False, home=None,
                            target=None):
    """Repair one Codex config while its adjacent lock is already held."""
    codex_dir = codex_config_dir(home)
    target = Path(target) if target is not None \
        else codex_dir / "config.toml"
    target.parent.mkdir(parents=True, exist_ok=True)
    block = codex_stdio_toml(project_id, db_path, home=home) if stdio \
        else codex_connect_toml(url, home=home)
    repair = _codex_config_repair_module()
    try:
        result = repair.repair_codex_config(
            target, canonical_block=block)
    except repair.CodexConfigRepairError as error:
        raise AttaccaError("cannot safely repair %s: %s" % (target, error))
    return result["config"]


def configure_codex(project_id, url, db_path, stdio=False, home=None):
    """Atomically replace every Attacca TOML table with one canonical entry.

    Older installers stopped at the first descendant table, which could leave
    ``[mcp_servers.attacca.env]`` beside the newer inline ``env`` key and make
    Codex reject its entire config.  The standalone repair helper removes all
    root/descendant copies, validates the result, and keeps a one-time backup.
    An adjacent lock covers the complete read-normalize-validate-write cycle so
    installers, setup repairs, and server switches cannot race one another
    even when ``CODEX_HOME`` is independent of the Attacca machine directory.
    """
    codex_dir = codex_config_dir(home)
    target = codex_dir / "config.toml"
    with _exclusive_codex_config_lock(target):
        return _configure_codex_locked(
            project_id, url, db_path, stdio=stdio, home=home,
            target=target)


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
            raise AttaccaError("%s exists but is not valid JSON; fix it first" % path)
        if not isinstance(data, dict):
            raise AttaccaError("%s is not a JSON object" % path)
        backup_path = path.with_name(path.name + ".attacca-backup")
        if backup and not backup_path.exists():
            backup_path.write_text(raw)
    section = data.setdefault(top_key, {})
    if not isinstance(section, dict):
        raise AttaccaError("%s: %r is not an object" % (path, top_key))
    section[entry_name] = value
    path.write_text(json.dumps(data, indent=2) + "\n")
    return str(path)


def _http_headers(actor, project_id, home=None):
    headers = {"X-Attacca-Actor": actor,
               CLIENT_INSTANCE_HEADER:
                   _client_instance_for_runtime(actor, home)}
    if project_id:
        headers["X-Attacca-Project"] = project_id
    return headers


def connect_tools(project_id, root, db_path, url=DEFAULT_URL, stdio=False,
                  skip=None, home=None):
    """Universal installer: detect which MCP-capable tools are installed and
    write each one's config. Detection = the tool's config dir exists, so
    nothing is written for tools the user does not have. Claude Code's
    .mcp.json is handled separately by one_shot_setup.

    Returns (configured, not_detected): configured is a list of
    {tool, path}; not_detected is a list of tool names."""
    supplied_home = home
    home = Path(home or Path.home())
    skip = set(skip or [])
    mcp_url = url.rstrip("/") + "/mcp"
    configured, missing = [], []

    def stdio_cfg(actor):
        return mcp_server_config(actor, project_id, db_path, home=home)

    def record(tool, path):
        configured.append({"tool": tool, "path": path})

    if "codex" not in skip:
        detected_codex_dir = codex_config_dir(supplied_home)
        if detected_codex_dir.is_dir() or \
                (supplied_home is None and shutil.which("codex")):
            record("codex", configure_codex(project_id, url, db_path,
                                            stdio=stdio, home=supplied_home))
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
            value = stdio_cfg("cline") if stdio \
                else mcp_connect_config("cline", url, home=home)
            record("cline", _merge_json_config(hit, "mcpServers", "attacca",
                                               value))
        else:
            missing.append("cline")

    if "cursor" not in skip:
        if (home / ".cursor").is_dir():
            # ~/.cursor/mcp.json is global: use the connect proxy so the
            # project is auto-detected per working directory.
            value = stdio_cfg("cursor") if stdio \
                else mcp_connect_config("cursor", url, home=home)
            record("cursor", _merge_json_config(home / ".cursor" / "mcp.json",
                                                "mcpServers", "attacca", value))
        else:
            missing.append("cursor")

    if "windsurf" not in skip:
        windsurf_dir = home / ".codeium" / "windsurf"
        if windsurf_dir.is_dir():
            value = stdio_cfg("windsurf") if stdio \
                else mcp_connect_config("windsurf", url, home=home)
            record("windsurf", _merge_json_config(
                windsurf_dir / "mcp_config.json", "mcpServers", "attacca",
                value))
        else:
            missing.append("windsurf")

    if "kimi" not in skip:
        if (home / ".kimi-code").is_dir():
            # ~/.kimi-code/mcp.json is user-level (every project): use the
            # connect proxy so the project is auto-detected per directory.
            value = stdio_cfg("kimi") if stdio \
                else mcp_connect_config("kimi", url, home=home)
            record("kimi", _merge_json_config(home / ".kimi-code" / "mcp.json",
                                              "mcpServers", "attacca", value))
        else:
            missing.append("kimi")

    if "gemini" not in skip:
        if (home / ".gemini").is_dir() and root:
            value = stdio_cfg("gemini") if stdio else \
                {"httpUrl": mcp_url,
                 "headers": _http_headers("gemini", project_id, home=home)}
            record("gemini", _merge_json_config(
                Path(root) / ".gemini" / "settings.json", "mcpServers",
                "attacca", value, backup=False))
        else:
            missing.append("gemini")

    if "vscode" not in skip:
        if root and ((home / ".vscode").is_dir()
                     or (Path(root) / ".vscode").is_dir()):
            value = {"type": "stdio", **stdio_cfg("vscode")} if stdio \
                else {"type": "http", "url": mcp_url,
                      "headers": _http_headers(
                          "vscode", project_id, home=home)}
            record("vscode", _merge_json_config(
                Path(root) / ".vscode" / "mcp.json", "servers", "attacca",
                value, backup=False))
        else:
            missing.append("vscode")

    if "opencode" not in skip:
        if root and ((home / ".config" / "opencode").is_dir()
                     or (Path(root) / "opencode.json").exists()):
            if stdio:
                cfg = stdio_cfg("opencode")
                value = {"type": "local",
                         "command": [cfg["command"]] + cfg["args"],
                         "environment": cfg["env"]}
            else:
                value = {"type": "remote", "url": mcp_url,
                         "headers": _http_headers(
                             "opencode", project_id, home=home)}
            record("opencode", _merge_json_config(
                Path(root) / "opencode.json", "mcp", "attacca", value,
                backup=False))
        else:
            missing.append("opencode")

    return configured, missing


def resolve_or_register_root(conn, root, actor_id,
                             repository_fingerprint=None):
    """Map a client checkout to an already-known project.

    A Git fingerprint identifies clones at unrelated absolute paths without
    sending the remote URL itself, but it never attaches one without user
    confirmation. Unknown checkouts are never silently named from their local
    directory: setup must let the user choose or explicitly create one.
    """
    root = str(Path(root).resolve())
    repository_fingerprint = _validated_repository_fingerprint(
        repository_fingerprint)
    root_project = _project_for_cwd(conn, root)
    repository_project = _project_for_repository(
        conn, repository_fingerprint)
    if root_project and repository_project \
            and root_project != repository_project:
        raise AttaccaError(
            "checkout path maps to project '%s' but its Git remote maps to '%s'; "
            "remove the stale project link or choose explicitly"
            % (root_project, repository_project))
    if root_project:
        if repository_fingerprint:
            remember_repository_fingerprint(
                conn, root_project, repository_fingerprint,
                actor_id=actor_id, actor_type="system")
        return root_project
    if repository_project:
        raise AttaccaError(
            "this Git repository matches Attacca workspace '%s'; confirm it "
            "with `setup --attach %s` or use plugin setup "
            "(Codex: `$attacca:setup`; Claude/Kimi: `/attacca:setup`)"
            % (repository_project, repository_project))
    raise AttaccaError(
        "this checkout is not attached to an Attacca workspace; use plugin "
        "setup (Codex: `$attacca:setup`; Claude/Kimi: `/attacca:setup`) to "
        "choose an existing workspace or create one")


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


def _configure_checkout(project_id, root, db_path, url, stdio,
                        write_instructions, manage_tools, skip_tools, home):
    """Write only checkout-local/global client configuration.

    `root` is always the current machine's checkout. It is intentionally not
    taken from the server's legacy projects.root_path field, which may name a
    path on another computer.
    """
    root = str(Path(root).resolve())
    project_link = write_project_link(root, project_id)
    if not stdio and claude_plugin_is_installed(home):
        # The plugin MCP resolves `.attacca/project.json` itself. Remove a
        # setup-created duplicate while keeping unrelated project MCP servers.
        remove_attacca_mcp_json_entry(root)
        mcp_json = None
        claude_connection = "native_plugin"
    else:
        config = mcp_server_config(
            "claude", project_id, db_path, home=home) if stdio else \
            mcp_http_config("claude", project_id, url, home=home)
        mcp_json = write_mcp_json_file(root, config)
        claude_connection = "project_mcp"
    configured, not_detected = ([], [])
    if manage_tools:
        configured, not_detected = connect_tools(
            project_id, root, db_path, url=url, stdio=stdio,
            skip=skip_tools, home=home)
    instruction_files = []
    if write_instructions:
        instruction_files = [f["file"] for f in
                             install_instructions(
                                 project_id, root, db_path)["files"]]
    return {"project_link": project_link, "mcp_json": mcp_json,
            "claude_connection": claude_connection,
            "configured_tools": configured, "not_detected": not_detected,
            "instruction_files": instruction_files}


def one_shot_setup(conn, actor_id, actor_type, db_path, url=DEFAULT_URL,
                   stdio=False, write_instructions=True, path=None, here=False,
                   manage_server=True, manage_tools=True, skip_tools=None,
                   home=None, tools_only=False, attach_project=None,
                   create_project=None):
    """`setup` with no arguments: make THIS directory a fully wired project.

    1. Registers the cwd as a project (if not already inside one; here=True
       forces the cwd to become its own project).
    2. Starts the attacca server in the background if it is not running
       (server mode only).
    3. Writes/merges .mcp.json — Claude Code and Claude-compatible CLIs
       (GLM etc.) pick it up automatically.
    4. Universal installer: writes the config of every DETECTED tool
       (codex, cline, cursor, windsurf, kimi, gemini, vscode, opencode),
       with one-time backups for global files.
    5. Writes the agent protocol block into CLAUDE.md / AGENTS.md.

    tools_only=True is the install.sh mode: only step 4, and only the
    GLOBAL tool configs (project-level tools need a root, so they are
    skipped) — no project registration, no server, no files in the cwd.
    """
    if tools_only:
        configured, not_detected = connect_tools(
            None, None, db_path, url=url, stdio=stdio, skip=skip_tools,
            home=home)
        return {"project_id": None, "root_path": None, "project_created": False,
                "mode": "stdio" if stdio else "server", "tools_only": True,
                "cwd_inside_root": False, "url": url,
                "server": {"started": False, "log": None, "pid": None,
                           "managed": False},
                "mcp_json": None, "configured_tools": configured,
                "not_detected": not_detected, "instruction_files": []}
    if attach_project and create_project:
        raise AttaccaError("choose either --attach or --create, not both")
    url = configured_server_url(url)
    cwd = Path(path or os.getcwd()).resolve()
    existing_link = None if here else find_project_link(cwd)
    if create_project and existing_link:
        raise AttaccaError(
            "%s already selects workspace '%s'; omit --create or use --here"
            % (existing_link["path"], existing_link["project_id"]))
    link = None if here or attach_project or create_project else existing_link
    project_id = attach_project or (link["project_id"] if link else None)
    local_root = Path(link["root_path"]) if link else cwd
    created = False
    if create_project:
        result = project_init(
            conn, actor_id, actor_type, path=str(cwd), name=create_project,
            repository_fingerprint=git_repository_fingerprint(cwd))
        project_id = result["project_id"]
        created = not result["already_existed"]
        local_root = cwd
    elif project_id:
        get_project(conn, project_id)
    elif not here:
        project_id = _project_for_cwd(conn, cwd)
    if not project_id:
        result = project_init(
            conn, actor_id, actor_type, path=str(cwd),
            repository_fingerprint=git_repository_fingerprint(cwd))
        project_id = result["project_id"]
        created = not result["already_existed"]
        local_root = cwd
    elif not create_project and not link and not attach_project:
        local_root = Path(get_project(conn, project_id).get("root_path") or cwd)
        fingerprint = git_repository_fingerprint(local_root)
        if fingerprint:
            remember_repository_fingerprint(
                conn, project_id, fingerprint, actor_id, actor_type)
    elif attach_project:
        local_root = cwd
    server = {"started": False, "log": None, "pid": None,
              "managed": manage_server and not stdio}
    if server["managed"]:
        server.update(ensure_server_running(url, db_path))
    files = _configure_checkout(
        project_id, local_root, db_path, url, stdio, write_instructions,
        manage_tools, skip_tools, home)
    return {"project_id": project_id, "root_path": str(local_root),
            "project_created": created, "mode": "stdio" if stdio else "server",
            "cwd_inside_root": str(cwd) != str(local_root),
            "url": url, "server": server, **files}


def _remote_setup_network(url, project_id, workspaces, actor_id, actor_type):
    """Read-only governance context used by native setup pickers.

    A relationship prompt must show what already exists before asking the
    user to change it. Every visible group-room message mirrored from another
    workspace is included because shared context—not only mentions or
    replies—is often the clearest evidence that this checkout is already part
    of an AI network.
    """
    by_id = {p["project_id"]: p for p in workspaces}
    candidate = by_id.get(project_id) if project_id else None
    bridges = []
    relationship_inbox = []
    agents = []
    if candidate:
        encoded = urllib.parse.quote(project_id, safe="")
        bridges = (remote_json(
            url, "GET", "/v1/projects/%s/bridges" % encoded,
            actor=actor_id, actor_type=actor_type).get("bridges") or [])
        inbox = remote_json(
            url, "GET", "/v1/projects/%s/inbox?mark_read=0&limit=100" % encoded,
            actor=actor_id, actor_type=actor_type)
        relationship_inbox = [m for m in (inbox.get("messages") or [])
                              if m.get("origin_project") or m.get("authority")]
        agents = (remote_json(
            url, "GET", "/v1/projects/%s/agents" % encoded,
            actor=actor_id, actor_type=actor_type).get("agents") or [])
    other = [p for p in workspaces if p["project_id"] != project_id]
    suggested_master = next(
        (m.get("origin_project") for m in relationship_inbox
         if m.get("origin_project") in by_id), None)
    named_bridges = []
    for bridge in bridges:
        item = dict(bridge)
        item["with_name"] = (by_id.get(item.get("with")) or {}).get(
            "name", item.get("with"))
        if item.get("principal"):
            item["principal_name"] = (
                by_id.get(item["principal"]) or {}).get(
                    "name", item["principal"])
        named_bridges.append(item)
    named_inbox = []
    for message in relationship_inbox:
        item = dict(message)
        if item.get("origin_project"):
            item["origin_project_name"] = (
                by_id.get(item["origin_project"]) or {}).get(
                    "name", item["origin_project"])
        named_inbox.append(item)
    identity = registered_agent_identity(
        agents, project_id, actor_id) if candidate and actor_type == "agent" \
        else {"actor_id": actor_id, "record": None, "role": None,
              "runtime": normalize_agent_runtime(actor=actor_id)}
    return {
        "workspace_id": project_id,
        "workspace_name": candidate.get("name") if candidate else None,
        "current_actor": identity["actor_id"],
        "current_runtime": identity["runtime"],
        "lead_director": candidate.get("lead_director") if candidate else None,
        "lead_director_record": next(
            (a for a in agents if candidate and
             a.get("agent_id") == candidate.get("lead_director")), None),
        "current_actor_record": identity["record"],
        "agents": agents,
        "existing_relationships": named_bridges,
        "relationship_inbox": named_inbox,
        "available_workspaces": [
            {"project_id": p["project_id"], "name": p["name"]}
            for p in other],
        "default_relationship": "master",
        "default_master_project": suggested_master,
        "note": ("A workspace has one room. Bridges connect workspace rooms; "
                 "they do not create duplicate rooms."),
    }


def discover_remote_setup(url=None, path=None, here=False,
                          actor_id=None, actor_type=None,
                          selected_project_id=None):
    """Read-only first-run discovery for conversational setup."""
    url = configured_server_url(url)
    cwd = Path(path or os.getcwd()).resolve()
    inherited_link = None if here else find_project_link(cwd)
    local_root = Path(inherited_link["root_path"]) if inherited_link \
        else (cwd if here else git_worktree_root(cwd))
    repository = git_repository_info(local_root)
    response = remote_json(url, "GET", "/v1/projects",
                           actor=actor_id, actor_type=actor_type)
    raw_projects = response.get("projects") or []
    folder_name = local_root.name
    folder_slug = slugify(folder_name)
    workspaces = [{"project_id": p["project_id"], "name": p["name"],
                   "git_match": bool(repository["fingerprint"] and
                                     p.get("repository_fingerprint") ==
                                     repository["fingerprint"]),
                   "folder_match": bool(
                       not repository["fingerprint"] and
                       (p["project_id"] == folder_slug or
                        slugify(p["name"]) == folder_slug))}
                  for p in raw_projects]
    git_matches = [p for p in workspaces if p["git_match"]]
    folder_matches = [p for p in workspaces if p["folder_match"]]
    linked = inherited_link["project_id"] if inherited_link else None
    stale_link = None
    if linked and linked not in {p["project_id"] for p in workspaces}:
        # A checkout can legitimately outlive or move between server
        # databases. Discovery must show repair choices instead of trapping
        # the user behind the stale ID. Nothing is overwritten until they
        # explicitly attach/create below.
        stale_link = {"project_id": linked, "path": inherited_link["path"]}
        linked = None
    suggested = linked
    match_reason = "project_link" if linked else None
    if not suggested and len(git_matches) == 1:
        suggested = git_matches[0]["project_id"]
        match_reason = "git"
    elif not suggested and len(folder_matches) == 1:
        suggested = folder_matches[0]["project_id"]
        match_reason = "folder"
    if linked:
        action = "already_linked"
    elif match_reason == "git":
        action = "confirm_git_match"
    elif match_reason == "folder":
        action = "confirm_folder_match"
    elif workspaces:
        action = "choose_or_create"
    else:
        action = "create_first_workspace"
    remote_name = repository["remote"].rsplit("/", 1)[-1] \
        if repository["remote"] else None
    network_project = selected_project_id or suggested
    if network_project and network_project not in {
            p["project_id"] for p in workspaces}:
        raise AttaccaError(
            "cannot inspect unknown workspace '%s'" % network_project)
    network = _remote_setup_network(
        url, network_project, raw_projects, actor_id, actor_type)
    return {"server_url": url,
            "git": {"detected": bool(repository["remote"]),
                    "remote": repository["remote"]},
            "folder": {"name": folder_name, "path": str(local_root)},
            "linked_project_id": linked,
            "stale_link": stale_link,
            "suggested_project_id": suggested,
            "suggested_new_name": remote_name or folder_name,
            "match_reason": match_reason,
            "action": action, "workspaces": workspaces,
            "migration_sources": detect_migration_sources(str(local_root)),
            "network": network}


def apply_remote_network_setup(url, project_id, actor_id, actor_type,
                               role="keep", lead="keep", bridge=None,
                               relationship=None, principal_side="other"):
    """Apply the explicitly confirmed governance part of guided setup.

    The function is deliberately idempotent. Re-running full setup registers
    the same actor and preserves a matching lead/bridge instead of duplicating
    or churning ledger events.
    """
    url = configured_server_url(url)
    encoded = urllib.parse.quote(project_id, safe="")
    projects = remote_json(url, "GET", "/v1/projects",
                           actor=actor_id, actor_type=actor_type).get(
                               "projects") or []
    known = {p["project_id"] for p in projects}
    if project_id not in known:
        raise AttaccaError("unknown setup workspace '%s'" % project_id)
    if role not in ("keep", "director", "advisor", "worker"):
        raise AttaccaError("role must be keep, director, advisor, or worker")
    if lead not in ("keep", "current", "clear"):
        raise AttaccaError("lead must be keep, current, or clear")
    if principal_side not in ("current", "other"):
        raise AttaccaError("principal side must be current or other")
    if relationship not in (None, "none", "master", "peer", "advisor"):
        raise AttaccaError(
            "relationship must be master, peer, advisor, or none")

    actions = []
    effective_actor = actor_id
    if role != "keep":
        runtime = normalize_agent_runtime(actor=actor_id)
        effective_actor = canonical_agent_id(project_id, role, runtime)
        workspace_name = next(
            p["name"] for p in projects if p["project_id"] == project_id)
        registered = remote_json(
            url, "POST", "/v1/projects/%s/agents" % encoded,
            {"agent_id": actor_id,
             "display_name": "%s · %s · %s" % (
                 workspace_name, role, runtime),
             "role": role, "runtime": runtime,
             "canonical_identity": True},
            actor=effective_actor, actor_type=actor_type)
        actions.append({"kind": "role", "role": role,
                        "actor_id": registered.get("agent_id"),
                        "already_registered": bool(
                            registered.get("already_registered"))})

    status = remote_json(
        url, "GET", "/v1/projects/%s/status" % encoded,
        actor=effective_actor, actor_type=actor_type)
    wanted_lead = (effective_actor if lead == "current" else
                   (None if lead == "clear" else status.get("lead_director")))
    if lead != "keep" and status.get("lead_director") != wanted_lead:
        changed = remote_json(
            url, "PUT", "/v1/projects/%s/lead" % encoded,
            {"agent_id": wanted_lead}, actor=effective_actor,
            actor_type=actor_type)
        actions.append({"kind": "lead", "lead_director":
                        changed.get("lead_director")})

    if relationship is not None:
        if not bridge or bridge not in known or bridge == project_id:
            raise AttaccaError(
                "a different known --bridge workspace is required")
        current = remote_json(
            url, "GET", "/v1/projects/%s/bridges" % encoded,
            actor=effective_actor, actor_type=actor_type).get("bridges") or []
        existing = next((b for b in current if b.get("with") == bridge), None)
        if relationship == "none":
            if existing:
                bridge_encoded = urllib.parse.quote(bridge, safe="")
                remote_json(
                    url, "DELETE", "/v1/projects/%s/bridges/%s" %
                    (encoded, bridge_encoded), actor=effective_actor,
                    actor_type=actor_type)
                actions.append({"kind": "bridge_removed", "with": bridge})
            else:
                actions.append({"kind": "bridge_removed", "with": bridge,
                                "unchanged": True})
            return {"ok": True, "project": project_id,
                    "actor": effective_actor,
                    "actions": actions}
        principal = None if relationship == "peer" else (
            project_id if principal_side == "current" else bridge)
        if existing and existing.get("relation") == relationship \
                and existing.get("principal") == principal:
            actions.append({"kind": "bridge", "with": bridge,
                            "relationship": relationship,
                            "principal": principal, "unchanged": True})
        else:
            bridge_encoded = urllib.parse.quote(bridge, safe="")
            if existing:
                # Relationship authority and room participation are
                # independent.  Reconfiguring setup must never tear down the
                # bridge (which used to reset both access policies to `all`).
                added = remote_json(
                    url, "PUT", "/v1/projects/%s/bridges/%s" %
                    (encoded, bridge_encoded),
                    {"relationship": relationship, "principal": principal},
                    actor=effective_actor, actor_type=actor_type)
            else:
                body = {"other_project": bridge}
                if relationship == "master":
                    body["boss"] = principal
                elif relationship == "advisor":
                    body["advisor"] = principal
                added = remote_json(
                    url, "POST", "/v1/projects/%s/bridges" % encoded, body,
                    actor=effective_actor, actor_type=actor_type)
            actions.append({"kind": "bridge", "with": bridge,
                            "relationship": added.get("relation"),
                            "principal": added.get("principal"),
                            "unchanged": False})
    return {"ok": True, "project": project_id, "actor": effective_actor,
            "actions": actions}


def one_shot_remote_setup(actor_id, actor_type, db_path, url=None,
                          write_instructions=True, path=None, here=False,
                          manage_server=True, manage_tools=True,
                          skip_tools=None, home=None, attach_project=None,
                          create_project=None):
    """Configure this checkout against the project database on *url*.

    This is the hosted/plugin path. It never registers the checkout in the
    client's private ~/.attacca/attacca.db and never repoints another
    computer's root_path.
    """
    url = configured_server_url(url)
    cwd = Path(path or os.getcwd()).resolve()
    if attach_project and create_project:
        raise AttaccaError("choose either --attach or --create, not both")
    inherited_link = None if here or attach_project or create_project \
        else find_project_link(cwd)
    local_root = Path(inherited_link["root_path"]) if inherited_link \
        else (cwd if here else git_worktree_root(cwd))
    repository_fingerprint = None if here \
        else git_repository_fingerprint(local_root)
    server = {"started": False, "log": None, "pid": None,
              "managed": bool(manage_server)}
    if manage_server:
        server.update(ensure_server_running(url, db_path))

    response = remote_json(url, "GET", "/v1/projects",
                           actor=actor_id, actor_type=actor_type)
    projects = response.get("projects") or []
    by_id = {p["project_id"]: p for p in projects}
    selected = attach_project or (
        inherited_link["project_id"] if inherited_link else None)
    matched_by = "explicit" if attach_project else (
        "project_link" if inherited_link else None)
    if selected and selected not in by_id:
        if attach_project:
            raise AttaccaError(
                "--attach selects unknown project '%s' on %s; known "
                "projects: %s"
                % (selected, url, ", ".join(sorted(by_id)) or "none"))
        # An inherited stale link is recoverable, but implicit setup must not
        # silently pick another workspace. Continue through the normal
        # confirmed Git/folder/choice flow.
        selected = None
        matched_by = None
    git_matches = []
    if repository_fingerprint:
        matches = [p for p in projects if
                   p.get("repository_fingerprint") == repository_fingerprint]
        if len(matches) > 1:
            raise AttaccaError(
                "multiple server projects match this Git repository: %s"
                % ", ".join(p["project_id"] for p in matches))
        git_matches = matches
    folder_matches = []
    if not repository_fingerprint:
        folder_slug = slugify(local_root.name)
        folder_matches = [p for p in projects if
                          p["project_id"] == folder_slug or
                          slugify(p["name"]) == folder_slug]

    if not selected and not create_project:
        if git_matches:
            raise AttaccaError(
                "Git remote matches Attacca workspace '%s'. Confirm it with "
                "`setup --attach %s`, or use the Attacca setup picker."
                % (git_matches[0]["project_id"],
                   git_matches[0]["project_id"]))
        if len(folder_matches) == 1:
            raise AttaccaError(
                "folder '%s' matches Attacca workspace '%s'. Confirm the "
                "default with `setup --attach %s`, or use the Attacca setup "
                "picker."
                % (local_root.name, folder_matches[0]["project_id"],
                   folder_matches[0]["project_id"]))
        known = ", ".join(sorted(by_id))
        if known:
            raise AttaccaError(
                "choose a workspace with `setup --attach ID` or explicitly "
                "create one with `setup --create NAME`. Available: %s" % known)
        raise AttaccaError(
            "no Attacca workspaces exist yet; create the first one with "
            "`setup --create NAME` or use the Attacca setup picker")
    if create_project and git_matches:
        raise AttaccaError(
            "this Git remote already belongs to workspace '%s'; attach it "
            "instead of creating a duplicate"
            % git_matches[0]["project_id"])

    if selected:
        # Also seeds old projects with their Git identity so the next clone
        # can auto-match even before project.json is committed.
        project = remote_json(
            url, "POST", "/v1/projects",
            {"project_id": selected,
             "repository_fingerprint": repository_fingerprint},
            actor=actor_id, actor_type=actor_type)
        if project.get("project_id") != selected:
            raise AttaccaError(
                "server resolved workspace '%s' while attaching '%s'; no "
                "checkout files were written"
                % (project.get("project_id"), selected))
        created = False
    else:
        project = remote_json(
            url, "POST", "/v1/projects",
            {"name": create_project,
             "repository_fingerprint": repository_fingerprint},
            actor=actor_id, actor_type=actor_type)
        selected = project["project_id"]
        created = not project.get("already_existed", False)
        matched_by = "created" if created else (
            project.get("matched_by") or "existing")

    files = _configure_checkout(
        selected, local_root, db_path, url, False, write_instructions,
        manage_tools, skip_tools, home)
    return {"project_id": selected, "root_path": str(local_root),
            "project_created": created, "matched_by": matched_by,
            "mode": "server", "tools_only": False,
            "cwd_inside_root": str(cwd) != str(local_root), "url": url,
            "server": server, **files}


def setup_details_text(project_id, db_path, url=DEFAULT_URL, tools=None):
    """`setup --details`: the full per-tool configuration reference."""
    path = script_path()
    out = []

    def stdio_config_json(actor):
        return json.dumps({"mcpServers": {
            "attacca": mcp_server_config(actor, project_id, db_path)}}, indent=2)

    out.append("Attacca configuration reference")
    out.append("=" * 60)
    out.append("Script:   %s" % path)
    out.append("Database: %s" % db_path)
    out.append("Server:   %s   (start with: python3 %s serve)" % (url, path))
    out.append("Project:  %s" % (project_id or "(none resolved)"))
    out.append("")
    out.append("Give each tool its own actor identity (X-Attacca-Actor header /")
    out.append("%s env) so the room shows who is who." % ENV_ACTOR)
    out.append("")

    selected = tools or ["claude", "kimi", "codex", "gemini", "opencode",
                         "glm", "cli"]

    if "claude" in selected:
        out.append("-- Claude Code (server mode, recommended) " + "-" * 18)
        out.append("  claude mcp add --transport http attacca %s/mcp \\" % url.rstrip("/"))
        out.append("    --header \"X-Attacca-Actor: claude\"%s"
                   % (" \\\n    --header \"X-Attacca-Project: %s\"" % project_id
                      if project_id else ""))
        out.append("or merge into <project>/.mcp.json (run `setup` to do this for you):")
        out.append(indent_block(json.dumps({"mcpServers": {"attacca":
                   mcp_http_config("claude", project_id, url)}}, indent=2)))
        out.append("-- Claude Code (stdio fallback, no server needed) " + "-" * 10)
        out.append(indent_block(stdio_config_json("claude")))
        out.append("")

    if "kimi" in selected:
        out.append("-- Kimi Code " + "-" * 47)
        out.append("Native plugin (easiest): inside Kimi run "
                   "/plugins install %s/plugin.zip" % url.rstrip("/"))
        out.append("or merge into ~/.kimi-code/mcp.json (user level — every")
        out.append("project; the checkout link selects the confirmed workspace):")
        out.append(indent_block(json.dumps({"mcpServers": {"attacca":
                   mcp_connect_config("kimi", url)}}, indent=2)))
        out.append("Stdio fallback (no server):")
        out.append(indent_block(stdio_config_json("kimi")))
        out.append("")

    if "codex" in selected:
        out.append("-- Codex CLI " + "-" * 47)
        out.append("Global config (~/.codex/config.toml), works on every Codex")
        out.append("version; the checkout link selects the confirmed workspace:")
        out.append(indent_block(codex_connect_toml(url)))
        out.append("Direct HTTP alternative (recent Codex; per-project header):")
        out.append(indent_block(codex_http_toml(project_id, url)))
        out.append("No-server stdio fallback:")
        out.append(indent_block(codex_stdio_toml(project_id, db_path)))
        out.append("")

    if "gemini" in selected:
        out.append("-- Gemini CLI " + "-" * 46)
        out.append("Merge into <project>/.gemini/settings.json (httpUrl = server mode):")
        gem = {"mcpServers": {"attacca": {
            "httpUrl": url.rstrip("/") + "/mcp",
            "headers": {"X-Attacca-Actor": "gemini",
                        **({"X-Attacca-Project": project_id} if project_id else {})}}}}
        out.append(indent_block(json.dumps(gem, indent=2)))
        out.append("Stdio fallback:")
        out.append(indent_block(stdio_config_json("gemini")))
        out.append("")

    if "opencode" in selected:
        out.append("-- opencode " + "-" * 48)
        oc = {"mcp": {"attacca": {
            "type": "remote", "url": url.rstrip("/") + "/mcp",
            "headers": {"X-Attacca-Actor": "opencode",
                        **({"X-Attacca-Project": project_id} if project_id else {})}}}}
        out.append("Merge into opencode.json (remote = server mode):")
        out.append(indent_block(json.dumps(oc, indent=2)))
        out.append("")

    if "glm" in selected:
        out.append("-- GLM (Zhipu) " + "-" * 45)
        out.append("GLM coding plans are typically used through Claude-Code-compatible or")
        out.append("Codex-compatible CLIs (e.g. ANTHROPIC_BASE_URL pointed at Zhipu).")
        out.append("Those clients read the SAME configs as above — use the Claude Code")
        out.append(".mcp.json / Codex config.toml with runtime hint glm.")
        out.append("")

    if "cli" in selected:
        out.append("-- Any other MCP client (Grok, Zed, Cline, ...) " + "-" * 12)
        out.append("HTTP (server mode):  url %s/mcp" % url.rstrip("/"))
        out.append("  headers: X-Attacca-Actor: <name>, X-Attacca-Project: %s"
                   % (project_id or "<project>"))
        out.append("Stdio (no server):   command python3, args [\"%s\", \"mcp\"]" % path)
        out.append("  env: %s=<name>, %s=%s, %s=%s"
                   % (ENV_ACTOR, ENV_DB, db_path, ENV_PROJECT,
                      project_id or "<project>"))
        out.append("REST API:  curl %s/v1/projects" % url.rstrip("/"))
        out.append("           curl %s/v1/projects/%s/handoff"
                   % (url.rstrip("/"), project_id or "<project>"))
        out.append("")

    out.append("Native Claude/Codex/Kimi lifecycle continuity is bundled in the plugin:")
    out.append("  Session start -> handoff + inbox + room + tasks + status via MCP")
    out.append("  Background watcher -> autonomous lightweight update check (default 1 min)")
    out.append("  No separate project hook or local database selection is required.")
    return "\n".join(out)


def indent_block(text, pad="    "):
    return "\n".join(pad + line for line in text.splitlines())


def managed_instruction_block(project_id, db_path):
    lines = []
    lines.append("%s v=%d project=%s do_not_edit=true -->" % (
        MANAGED_BEGIN, MANAGED_BLOCK_VERSION, project_id))
    lines.append("## Project Attacca Protocol (managed block)")
    lines.append("")
    lines.append("This project uses **Attacca**, a hosted project continuity layer")
    lines.append("shared by ALL workers — Claude Code, Kimi Code, Codex, GLM, Cline,")
    lines.append("other agents and humans. It is the source of truth for project")
    lines.append("state: append-only event ledger, shared task board with work claims,")
    lines.append("decision records, a human+AI project room, and the current handoff.")
    lines.append("The project owns the knowledge; your session is replaceable.")
    lines.append("")
    lines.append("MCP server `attacca` exposes the tools (get_handoff, room_send,")
    lines.append("task_claim, ...; installed via a tool plugin they appear under a")
    lines.append("prefix like mcp__plugin_attacca_attacca__). Follow this protocol:")
    lines.append("")
    lines.append("The installed plugin's **lifecycle hooks are the primary continuity path**.")
    lines.append("On startup/resume/clear/compact they resolve `.attacca/project.json` and")
    lines.append("load the handoff, mandatory Project Rules, inbox, room, tasks, agents, and")
    lines.append("status through MCP. A background watcher polls the hosted workspace every")
    lines.append("minute by default (configurable) even while the coding client is idle,")
    lines.append("queues concise changes, and surfaces them independently where the OS allows.")
    lines.append("Lifecycle hooks ensure the watcher is running, perform an immediate refresh,")
    lines.append("and inject queued changes into the next AI turn. Mutations are written to the")
    lines.append("hosted workspace immediately when it is reachable; otherwise the verified")
    lines.append("identity-scoped outbox fsyncs allowlisted writes for exact-once replay. The")
    lines.append("interval is only the pull cadence for changes made elsewhere.")
    lines.append("Setup is one-time; do not rerun it unless adding a client, switching, or")
    lines.append("repairing the workspace.")
    lines.append("The lifecycle hook also compares both the installed plugin version and this")
    lines.append("managed-law bundle with the server. It must ask before installing newer")
    lines.append("executable code. When compatible law content is available, it atomically")
    lines.append("refreshes only this managed block, preserves all content outside the")
    lines.append("markers, and reports the exact files changed.")
    lines.append("")
    lines.append("Agent identities use `workspace.role.runtime` (for example,")
    lines.append("`analytics-engine.director.codex`). The authenticated human operator is")
    lines.append("recorded separately on every mutation as `Run by user`; never combine or")
    lines.append("substitute the human and AI identities. Git branch and revision describe the")
    lines.append("originating client checkout, not the hosted server checkout.")
    lines.append("AI authority comes only from the registered workspace role: Claude and Codex")
    lines.append("Directors in the same workspace have identical permissions; runtime and Lead")
    lines.append("Director status never bypass the role check.")
    lines.append("")
    lines.append("1. **Session start and group-room reading**: use the injected")
    lines.append("   `ATTACCA ACTIVE SESSION BRIEF`. If that brief is absent, immediately")
    lines.append("   call `get_handoff`, then `check_inbox` and `room_read` before any other")
    lines.append("   work. A Project Room or permitted bridged conversation is a GROUP CHAT:")
    lines.append("   read every participation-visible unread message, including messages that")
    lines.append("   mention or reply to somebody else. Mentions/replies identify the expected")
    lines.append("   responder; they never restrict visibility. A chat or directive with no")
    lines.append("   mentions and no reply target is sent to everyone. Consider relevant design,")
    lines.append("   requirement, and project-context changes even when you are not assigned to")
    lines.append("   act on them. Continue draining `check_inbox` while `may_have_more` is true.")
    lines.append("   The lifecycle watcher, not the human, owns routine checking: never ask the")
    lines.append("   user to type 'check messages'. Addressed messages and broadcast directives")
    lines.append("   remain pending even after their read cursor advances; before yielding, call")
    lines.append("   `message_dispose` with acknowledged/claimed/deferred/blocked/completed/")
    lines.append("   not_actionable. A claimed/completed disposition must link the matching task.")
    lines.append("   Never choose, open, or ask about another Attacca database/store. Do not")
    lines.append("   rely on prior chat memory or re-discover the repo from scratch. Inbox items")
    lines.append("   tagged [MASTER-DIRECTIVE] come from a project that rules this one —")
    lines.append("   binding;")
    lines.append("   [SUGGESTION]/[ADVICE] are input, not orders.")
    lines.append("2. **Project Rules — binding dynamic instructions**: the mandatory")
    lines.append("   Project Rules for `everyone` plus your registered role are pinned as a")
    lines.append("   compact banner at the TOP of every turn’s brief and are BINDING on every")
    lines.append("   response — never bypass them. Do not rely on a truncated brief: if the")
    lines.append("   pinned rules banner is ever absent from your context, call `rule_list`")
    lines.append("   before acting. Reload them after a context/staleness warning and on")
    lines.append("   automatic refresh. Only humans and registered Directors may create, edit,")
    lines.append("   enable, or disable rules.")
    lines.append("   **Cloud Context — the shared project context file**: Attacca Cloud Context")
    lines.append("   is this project’s authoritative “cloud” AGENTS.md/CLAUDE.md — injected into")
    lines.append("   every brief and editable only by humans and registered Directors")
    lines.append("   (`cloud_context_get` / `cloud_context_set`). Read it every turn as the")
    lines.append("   current project context. When it is richer than the human’s local")
    lines.append("   AGENTS.md/CLAUDE.md (the content OUTSIDE these managed markers), offer to")
    lines.append("   sync it down into that local file so the checkout keeps the best context —")
    lines.append("   never modifying this managed block, which Attacca maintains and syncs")
    lines.append("   separately.")
    lines.append("   **On first setup, de-duplicate the local AGENTS.md/CLAUDE.md**: remove or")
    lines.append("   consolidate any project context now provided by this managed block or by")
    lines.append("   Cloud Context so the two do not overlap — keep only genuinely local")
    lines.append("   instructions, and migrate durable project context into Cloud Context")
    lines.append("   (see the project-migration directive) rather than leaving a duplicate copy")
    lines.append("   in the file.")
    lines.append("3. **History first**: when work depends on what happened, why, or who did it,")
    lines.append("   call `search` with relevant terms before filesystem or Git archaeology.")
    lines.append("   Follow with `get_project_log`, `task_show`, or the matching durable record.")
    lines.append("   This is the Activity-log Ctrl+F path; never claim history is absent until")
    lines.append("   you have searched Attacca's ledger and running project memory.")
    lines.append("4. **Tasks — owned, trackable work**: before editing or starting a concrete")
    lines.append("   implementation/research deliverable, check `task_list`; `task_claim` an")
    lines.append("   existing task or `task_create` then claim it. Declare `expected_scope` paths.")
    lines.append("   Heed scope-overlap warnings — coordinate in the room first.")
    lines.append("5. **Room — ephemeral group coordination**: announce intent, questions,")
    lines.append("   directives, challenges, and short updates with `room_send`; use `since_seq`")
    lines.append("   for replies. Every participant reads the whole visible group conversation;")
    lines.append("   addressing metadata assigns attention only. Room chat coordinates people")
    lines.append("   but does not replace a task or decision.")
    lines.append("   Messages are local by default. Never mirror routine claims, status, audits,")
    lines.append("   task updates, or handoffs into another workspace. Cross-project delivery")
    lines.append("   requires an explicit `target_project` and the content must match that bridge's")
    lines.append("   human-defined purpose. A feedback bridge carries feedback, acknowledgements,")
    lines.append("   and direct follow-ups only — not the source project's ordinary work log.")
    lines.append("6. **Decisions — durable choices**: use `decision_propose` /")
    lines.append("   `decision_resolve` for architecture, API, data-model, security, workflow,")
    lines.append("   or product choices that future workers must preserve. Do not create a")
    lines.append("   decision for routine code details or a transient question.")
    lines.append("7. **Record work where it belongs**: log tasks, reports, decisions, rules,")
    lines.append("   directives, and meaningful coordination through Attacca as the work happens;")
    lines.append("   do not leave project state only in chat or private files. Every write must")
    lines.append("   retain the authenticated human, canonical AI actor, and available Git context.")
    lines.append("8. **Handoff — canonical transition state, Director-only**: after reporting")
    lines.append("   task evidence, Directors update objective / what_changed / active_work /")
    lines.append("   blockers / risks / next_actions at a meaningful transition or session end.")
    lines.append("   Advisors and workers must use `task_report` and `room_send`; they cannot")
    lines.append("   write the shared handoff. A Director must pass the context version from")
    lines.append("   `get_handoff`; a stale version is rejected and must be reconciled.")
    lines.append("9. **Drift Guard**: if any response carries a `stale_context_warning`,")
    lines.append("   re-run `get_handoff` before further writes.")
    lines.append("")
    lines.append("If hosted MCP is unreachable, continue only through the installed plugin's")
    lines.append("verified identity-scoped offline mirror and durable outbox. Treat cached")
    lines.append("results as stale/offline and queued writes as pending until exact-once replay")
    lines.append("is proven after reconnect. If no verified mirror exists, authentication or")
    lines.append("authority is invalid, or a conflict/unsupported operation is reported, stop")
    lines.append("and tell the user. Never substitute a local Attacca database or admin export.")
    lines.append(MANAGED_END)
    return "\n".join(lines)


def _managed_block_span(text):
    """Return the one valid managed-block span, or ``None`` when absent.

    A half-written or duplicated block is never guessed at: replacing the
    wrong span could erase user-authored instructions outside Attacca's
    ownership boundary.
    """
    begins = list(_MANAGED_BEGIN_LINE.finditer(text))
    ends = list(_MANAGED_END_LINE.finditer(text))
    raw_begin_count = text.count("MANAGED_ATTACCA:BEGIN")
    raw_end_count = text.count("MANAGED_ATTACCA:END")
    if raw_begin_count != len(begins) or raw_end_count != len(ends):
        raise AttaccaError(
            "managed Attacca marker text is present but malformed")
    if not begins and not ends:
        return None
    if len(begins) != 1 or len(ends) != 1 \
            or ends[0].start() <= begins[0].start():
        raise AttaccaError(
            "managed Attacca block is malformed (expected one BEGIN followed "
            "by one END marker)")
    # The marker owns only its literal bytes. Keep the caller's trailing
    # spaces and CR/LF line ending in the outside-content slice unchanged.
    return begins[0].start(), ends[0].start() + len(MANAGED_END)


def _metadata_for_managed_block(block):
    """Describe exact block bytes without timestamps or machine-local data."""
    span = _managed_block_span(block)
    if span != (0, len(block)):
        raise AttaccaError("value is not exactly one managed Attacca block")
    header = block.splitlines()[0]
    version_match = re.search(r"\bv=(\d+)\b", header)
    project_match = re.search(r"\bproject=([^\s>]+)", header)
    ownership_match = re.search(r"\bdo_not_edit=([^\s>]+)", header)
    return {
        "version": int(version_match.group(1)) if version_match else None,
        "project_id": project_match.group(1) if project_match else None,
        "do_not_edit": bool(ownership_match and
                            ownership_match.group(1).lower() == "true"),
        "sha256": sha256_hex(block),
    }


def managed_instruction_metadata(project_id, db_path=None):
    """Return deterministic desired-block metadata for lifecycle hooks.

    ``sha256`` covers the exact project-specific block to be written.
    ``law_sha256`` covers the same bundled law template with a stable project
    placeholder, allowing clients to distinguish law changes from a checkout
    simply being attached to a different workspace.
    """
    block = managed_instruction_block(project_id, db_path)
    result = _metadata_for_managed_block(block)
    template = managed_instruction_block(_MANAGED_TEMPLATE_PROJECT, None)
    result["law_sha256"] = sha256_hex(template)
    return result


def inspect_managed_instruction_file(path, desired_project_id=None,
                                     db_path=None):
    """Inspect one real instruction file without changing it.

    Symlinks are reported rather than followed here. The refresh operation
    separately permits the one managed layout, ``CLAUDE.md -> AGENTS.md``,
    after proving that its target stays inside the checkout.
    """
    target = Path(path)
    result = {"file": str(target), "present": False, "malformed": False,
              "is_symlink": target.is_symlink()}
    if target.is_symlink():
        result["symlink_target"] = os.readlink(str(target))
        return result
    if not target.exists():
        return result
    if not target.is_file():
        result.update({"malformed": True,
                       "error": "instruction path is not a regular file"})
        return result
    try:
        text = target.read_bytes().decode("utf-8")
        span = _managed_block_span(text)
    except (OSError, UnicodeError, AttaccaError) as err:
        result.update({"malformed": True, "error": str(err)})
        return result
    if span is None:
        return result
    block = text[span[0]:span[1]]
    result.update({"present": True,
                   "metadata": _metadata_for_managed_block(block)})
    if desired_project_id is not None:
        desired = managed_instruction_block(desired_project_id, db_path)
        result["desired_metadata"] = managed_instruction_metadata(
            desired_project_id, db_path)
        result["matches_desired"] = block == desired
    return result


def _atomic_write_instruction(target, text, expected_text=None):
    """Atomically replace a regular instruction file in its own directory."""
    target = Path(target)
    if target.is_symlink():
        raise AttaccaError("refusing to replace symlink %s" % target)
    mode = (target.stat().st_mode & 0o7777) if target.exists() else 0o644
    fd, temporary_name = tempfile.mkstemp(
        prefix=".%s." % target.name, suffix=".tmp", dir=str(target.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(str(temporary), mode)
        if expected_text is not None:
            if target.is_symlink():
                raise AttaccaError(
                    "instruction file became a symlink during refresh")
            try:
                current_text = target.read_bytes().decode("utf-8")
            except (OSError, UnicodeError) as err:
                raise AttaccaError(
                    "could not recheck instruction file before refresh: %s"
                    % err)
            if current_text != expected_text:
                if current_text == text:
                    return False  # another lifecycle hook already converged
                raise AttaccaError(
                    "instruction file changed concurrently; left it untouched")
        os.replace(str(temporary), str(target))
        # Persist the rename where the platform supports directory fsync.
        try:
            directory_fd = os.open(str(target.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
        return True
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _instruction_target(root, filename):
    """Resolve a requested checkout-relative instruction path safely."""
    root = Path(root).resolve()
    requested = Path(filename)
    if requested.is_absolute():
        raise AttaccaError("instruction filename must be checkout-relative: %s"
                           % filename)
    target = root / requested
    try:
        parent = target.parent.resolve()
    except OSError as err:
        raise AttaccaError("cannot resolve instruction path %s: %s"
                           % (target, err))
    if parent != root and root not in parent.parents:
        raise AttaccaError("instruction path leaves checkout: %s" % filename)
    return target


def _standard_claude_link_target(target, root):
    """Resolve only ``CLAUDE.md -> <checkout>/AGENTS.md`` safely."""
    target = Path(target)
    root = Path(root).resolve()
    agents = root / "AGENTS.md"
    if agents.is_symlink():
        raise AttaccaError("AGENTS.md is itself a symlink")
    try:
        resolved = target.resolve(strict=True)
        expected = agents.resolve(strict=True)
    except (OSError, RuntimeError) as err:
        raise AttaccaError("cannot resolve CLAUDE.md symlink: %s" % err)
    if expected != root / "AGENTS.md" or resolved != expected:
        raise AttaccaError("target is not the checkout's regular AGENTS.md")
    if not expected.is_file():
        raise AttaccaError("AGENTS.md is not a regular file")
    return expected


def _managed_instruction_sync(project_id, root_path, db_path, files=None,
                              managed_only=False, desired_block=None):
    if not root_path or not Path(root_path).is_dir():
        raise AttaccaError(
            "project root %s does not exist; re-run init in the project dir"
            % (root_path or "(unset)"))
    if desired_block is None:
        block = managed_instruction_block(project_id, db_path)
        desired_metadata = managed_instruction_metadata(project_id, db_path)
    else:
        block = str(desired_block)
        desired_metadata = _metadata_for_managed_block(block)
        if desired_metadata.get("project_id") != project_id:
            raise AttaccaError(
                "managed-law block belongs to project '%s', not '%s'" % (
                    desired_metadata.get("project_id"), project_id))
        if not desired_metadata.get("do_not_edit"):
            raise AttaccaError(
                "managed-law block lacks do_not_edit=true ownership marker")
        if type(desired_metadata.get("version")) is not int or \
                desired_metadata["version"] < 1:
            raise AttaccaError("managed-law block version is invalid")
    results = []
    filenames = list(files or ["AGENTS.md", "CLAUDE.md"])
    root = Path(root_path).resolve()
    processed = {}
    for filename in filenames:
        target = _instruction_target(root, filename)
        # One source of truth: when writing the default pair, CLAUDE.md
        # becomes a symlink to AGENTS.md unless the user already has a real
        # CLAUDE.md (never clobber their content with a link).
        if filename == "CLAUDE.md" and "AGENTS.md" in filenames \
                and files is None:
            if target.is_symlink():
                try:
                    resolved = _standard_claude_link_target(target, root)
                except AttaccaError as err:
                    results.append({"file": str(target), "changed": False,
                                    "status": "unsafe_symlink",
                                    "action": "unsafe CLAUDE.md symlink",
                                    "error": str(err)})
                    continue
                prior = processed.get(str(resolved))
                results.append({
                    "file": str(target), "resolved_file": str(resolved),
                    "changed": False,
                    "status": "linked" if not prior else prior["status"],
                    "action": "already links to AGENTS.md",
                    "metadata": desired_metadata if prior and
                    prior["status"] in ("updated", "current") else None,
                })
                continue
            if not target.exists() and not managed_only:
                target.symlink_to("AGENTS.md")
                results.append({"file": str(target),
                                "changed": True, "status": "linked",
                                "action": "symlinked to AGENTS.md",
                                "metadata": desired_metadata})
                continue
        if target.is_symlink():
            # A custom CLAUDE-only refresh may follow the standard internal
            # link without replacing the link inode. All other symlinks are
            # left untouched so a checkout cannot write outside itself.
            if filename != "CLAUDE.md":
                results.append({"file": str(target), "changed": False,
                                "status": "unsafe_symlink",
                                "action": "unsafe instruction symlink"})
                continue
            try:
                resolved = _standard_claude_link_target(target, root)
            except AttaccaError as err:
                results.append({"file": str(target), "changed": False,
                                "status": "unsafe_symlink",
                                "action": "unsafe CLAUDE.md symlink",
                                "error": str(err)})
                continue
            target = resolved
        target_key = str(target.resolve()) if target.exists() else str(target)
        if target_key in processed:
            prior = processed[target_key]
            results.append({"file": str(root / filename),
                            "resolved_file": str(target), "changed": False,
                            "status": prior["status"],
                            "action": "managed target already processed",
                            "metadata": prior.get("metadata")})
            continue
        span = None
        old_metadata = None
        expected_text = None
        if target.exists():
            if not target.is_file():
                entry = {"file": str(root / filename), "changed": False,
                         "status": "malformed",
                         "action": "instruction path is not a regular file"}
                results.append(entry)
                processed[target_key] = entry
                continue
            try:
                text = target.read_bytes().decode("utf-8")
                expected_text = text
                span = _managed_block_span(text)
            except (OSError, UnicodeError, AttaccaError) as err:
                entry = {"file": str(root / filename), "changed": False,
                         "status": "malformed",
                         "action": "malformed managed block", "error": str(err)}
                results.append(entry)
                processed[target_key] = entry
                continue
            if span is not None:
                old_block = text[span[0]:span[1]]
                old_metadata = _metadata_for_managed_block(old_block)
                if managed_only and not old_metadata["do_not_edit"]:
                    entry = {"file": str(root / filename), "changed": False,
                             "status": "unmanaged",
                             "action": "managed block lacks do_not_edit=true",
                             "metadata": old_metadata}
                    results.append(entry)
                    processed[target_key] = entry
                    continue
                if managed_only and old_metadata["version"] is None:
                    entry = {"file": str(root / filename), "changed": False,
                             "status": "malformed",
                             "action": "managed block version is missing",
                             "metadata": old_metadata}
                    results.append(entry)
                    processed[target_key] = entry
                    continue
                if managed_only and old_metadata["version"] > \
                        desired_metadata["version"]:
                    entry = {"file": str(root / filename), "changed": False,
                             "status": "future",
                             "action": "newer managed block left unchanged",
                             "metadata": old_metadata,
                             "from_metadata": old_metadata,
                             "to_metadata": desired_metadata,
                             "version_change": "%s→%s refused" % (
                                 old_metadata["version"],
                                 desired_metadata["version"])}
                    results.append(entry)
                    processed[target_key] = entry
                    continue
                new_text = text[:span[0]] + block + text[span[1]:]
                if old_block == block:
                    entry = {"file": str(root / filename), "changed": False,
                             "status": "current",
                             "action": "managed block current",
                             "metadata": desired_metadata,
                             "from_metadata": old_metadata,
                             "to_metadata": desired_metadata,
                             "version_change": "%s→%s" % (
                                 old_metadata["version"],
                                 desired_metadata["version"])}
                    results.append(entry)
                    processed[target_key] = entry
                    continue
                action = "updated managed block"
            else:
                if managed_only:
                    entry = {"file": str(root / filename), "changed": False,
                             "status": "missing",
                             "action": "missing managed block"}
                    results.append(entry)
                    processed[target_key] = entry
                    continue
                sep = "" if text.endswith("\n\n") else ("\n" if text.endswith("\n") else "\n\n")
                new_text = text + sep + block + "\n"
                action = "appended managed block"
        else:
            if managed_only:
                entry = {"file": str(root / filename), "changed": False,
                         "status": "missing", "action": "instruction file missing"}
                results.append(entry)
                processed[target_key] = entry
                continue
            new_text = block + "\n"
            action = "created with managed block"
        try:
            wrote = _atomic_write_instruction(
                target, new_text, expected_text=expected_text)
        except (OSError, UnicodeError, AttaccaError) as err:
            entry = {"file": str(root / filename), "changed": False,
                     "status": "write_error", "action": "write failed",
                     "error": str(err)}
            results.append(entry)
            processed[target_key] = entry
            continue
        entry = {"file": str(root / filename), "changed": wrote,
                 "status": "updated" if wrote else "current",
                 "action": action if wrote else
                           "managed block current after concurrent refresh",
                 "metadata": desired_metadata}
        if span is not None:
            entry.update({
                "from_metadata": old_metadata,
                "to_metadata": desired_metadata,
                "version_change": "%s→%s" % (
                    old_metadata["version"], desired_metadata["version"]),
            })
        if target != root / filename:
            entry["resolved_file"] = str(target)
        results.append(entry)
        processed[target_key] = entry
    # Universal (R-2): keep the Cloud Context block in the same files in sync
    # with the managed block for EVERY project — create it on setup, refresh it
    # in place on later runs. Best-effort: never break the managed-block write.
    cloud_context_files = []
    if db_path:
        try:
            _cc_conn = connect(db_path)
            try:
                cloud_context_files = refresh_cloud_context_block(
                    _cc_conn, project_id, root_path, files=filenames,
                    create=not managed_only).get("files", [])
            finally:
                _cc_conn.close()
        except Exception:
            cloud_context_files = []
    return {
        "cloud_context_files": cloud_context_files,
        "ok": not any(item["status"] in (
            "malformed", "unsafe_symlink", "unmanaged", "future",
            "write_error")
                      for item in results),
        "changed": any(item["changed"] for item in results),
        "managed_only": managed_only,
        "metadata": desired_metadata,
        "files": results,
    }


def refresh_managed_instructions(project_id, root_path, db_path, files=None):
    """Refresh only existing valid managed blocks in a linked checkout.

    Unlike setup, this never creates a file, appends a missing block, replaces
    an arbitrary symlink, or guesses how to repair malformed markers. It is
    therefore safe for an automatic lifecycle hook after a plugin update.
    """
    return _managed_instruction_sync(
        project_id, root_path, db_path, files=files, managed_only=True)


def refresh_managed_instruction_block(project_id, root_path, block,
                                      expected_sha256=None, files=None):
    """Apply one server-supplied managed block without installing code.

    The caller must first establish which server/workspace it trusts. This
    adapter then validates exact bytes, project binding, ownership markers and
    monotonic file versions before atomically replacing only an existing valid
    managed region. It never creates a missing block or follows arbitrary
    symlinks.
    """
    if not isinstance(block, str):
        raise AttaccaError("server managed-law block must be text")
    if expected_sha256 is not None:
        expected = str(expected_sha256).strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise AttaccaError("server managed-law sha256 is invalid")
        if sha256_hex(block) != expected:
            raise AttaccaError("server managed-law block failed sha256 validation")
    return _managed_instruction_sync(
        project_id, root_path, None, files=files, managed_only=True,
        desired_block=block)


def install_instructions(project_id, root_path, db_path, files=None):
    """Setup-time install: create or append, then refresh on later runs."""
    return _managed_instruction_sync(
        project_id, root_path, db_path, files=files, managed_only=False)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

PROJECT_MIGRATION_DIRECTIVE_VERSION = 1
PROJECT_MIGRATION_DIRECTIVE = """# Attacca Project Migration Directive (v%d)

Run this when a project is first connected to Attacca and already has history or
docs, so Attacca becomes the authoritative source of truth. Put the migrated
knowledge in Attacca (Cloud Context, Rules, decisions, tasks) — NOT in the
AGENTS.md/CLAUDE.md managed block, so that block stays small.

1. Archive existing project logs/records.
   - Archive the project's existing log/decision docs (for example docs/LOG.md,
     CHANGELOG, ADRs): rename to *.archive.md and prepend a header —
     "ARCHIVE — historical only. Attacca is the authoritative source of truth."
   - Transfer all relevant historical records, decisions, directives, bugs,
     implementation history, and prior rulings into Attacca. Lose nothing.
   - Add completed work as done tasks and still-open work as open tasks
     (task_create); record durable choices as decisions (decision_propose /
     decision_resolve).
   - After migration the archived file is historical-only and is no longer an
     active authority.

2. Populate Attacca Cloud Context (cloud_context_set).
   - Capture the project's current architecture, systems, terminology,
     responsibilities, key implementation details, active decisions,
     dependencies, and essential historical context — enough for a new agent
     to understand the project without the old logs.

3. Consolidate Core Rules into Attacca Rules (rule_create).
   - Transfer core rules, owner directives, coding/safety/architecture/workflow
     rules, and non-negotiable requirements. Remove obsolete or superseded
     rules; where rules conflict, the latest explicit owner ruling wins.
     Attacca Rules are mandatory project law for every agent.

Authority order going forward:
  1. Latest explicit owner directive
  2. Attacca Rules
  3. Attacca Cloud Context / recorded decisions
  4. Current project / source documentation
  5. Archived logs (historical reference only)
Never treat archived material as active law when Attacca has a newer ruling.

Only humans and registered Directors may write Cloud Context and Rules.
""" % PROJECT_MIGRATION_DIRECTIVE_VERSION

MIGRATION_SOURCE_CANDIDATES = (
    "docs/LOG.md", "LOG.md", "docs/CHANGELOG.md", "CHANGELOG.md", "CHANGELOG",
    "HISTORY.md", "docs/DECISIONS.md", "docs/decisions", "docs/adr", "ADR.md",
)


def detect_migration_sources(root_path):
    """Best-effort discovery of existing history/decision docs worth migrating."""
    if not root_path:
        return []
    root = Path(root_path)
    found = []
    for rel in MIGRATION_SOURCE_CANDIDATES:
        try:
            candidate = root / rel
            if candidate.exists():
                upper = rel.upper()
                kind = "decisions" if ("DECISION" in upper or "ADR" in upper) \
                    else "log"
                found.append({"rel": rel, "path": str(candidate), "kind": kind,
                              "is_dir": candidate.is_dir()})
        except OSError:
            continue
    return found


def migration_directive(root_path=None):
    """The server-side project-migration directive plus any detected sources.

    The directive is bundled with the Attacca binary (versioned with the code)
    and served on demand; it is deliberately not part of the managed
    AGENTS.md/CLAUDE.md block."""
    return {
        "version": PROJECT_MIGRATION_DIRECTIVE_VERSION,
        "directive": PROJECT_MIGRATION_DIRECTIVE,
        "storage": ("bundled with the Attacca binary and served on demand; not "
                    "written into the AGENTS.md/CLAUDE.md managed block"),
        "authority_order": [
            "latest explicit owner directive",
            "Attacca Rules",
            "Attacca Cloud Context / recorded decisions",
            "current project/source documentation",
            "archived logs (historical reference only)",
        ],
        "migration_sources": detect_migration_sources(root_path),
    }


def _md_handoff_content(row):
    content = (row or {}).get("content")
    if isinstance(content, str):
        try:
            content = json.loads(content)
        except (ValueError, TypeError):
            content = {}
    return content if isinstance(content, dict) else {}


def render_state_markdown(projection):
    """Render an Attacca projection (the durable synced state: handoff, rules,
    cloud context, log, room, decisions, tasks) as a set of Markdown files.

    Returns {filename: markdown_text}. These are DERIVED, read-only views of the
    authoritative ledger/server — editing them does not sync back. Missing
    sections render as empty, never an error."""
    p = projection or {}
    proj = p.get("project") or {}
    name = proj.get("name") or proj.get("project_id") or "project"
    out = {}

    out["README.md"] = (
        "# Attacca mirror — %s\n\n"
        "Read-only Markdown views of this workspace's synced Attacca state, "
        "refreshed whenever the local sync runs. The authoritative source is the "
        "Attacca server / ledger and the local `snapshot.json`; editing these "
        "files does not change project state.\n\n"
        "- `HANDOFF.md` — current handoff\n- `CLOUD_CONTEXT.md` — project summary\n"
        "- `RULES.md` — mandatory Project Rules\n- `TASKS.md` — task board\n"
        "- `DECISIONS.md` — decision records\n- `ROOM.md` — recent room/inbox\n"
        "- `LOG.md` — project event log\n" % name)

    handoffs = p.get("handoffs") or []
    content = _md_handoff_content(handoffs[-1] if handoffs else None)
    lines = ["# Handoff — %s" % name, ""]
    fields = ("objective", "what_changed", "active_work", "blockers", "risks",
              "next_actions", "notes")
    if any(content.get(f) for f in fields):
        for f in fields:
            v = content.get(f)
            if v:
                lines += ["## %s" % f.replace("_", " ").title(), "", str(v), ""]
    else:
        lines += ["_No handoff written yet._", ""]
    out["HANDOFF.md"] = "\n".join(lines)

    cc = p.get("cloud_context") or {}
    cc_body = (cc.get("content") or "").strip()
    out["CLOUD_CONTEXT.md"] = (cc_body + "\n") if cc_body else \
        "# Cloud Context\n\n_No cloud context set._\n"

    rules = p.get("rules") or []
    rlines = ["# Project Rules — %s" % name, ""]
    if rules:
        for r in sorted(rules, key=lambda r: (r.get("priority", 100),
                                              str(r.get("rule_id") or ""))):
            state = "enabled" if r.get("enabled", True) else "disabled"
            rlines += ["## %s · %s (priority %s · %s · %s)" % (
                r.get("rule_id"), r.get("title"), r.get("priority"),
                r.get("scope"), state), "", str(r.get("body") or ""), ""]
    else:
        rlines += ["_No rules._", ""]
    out["RULES.md"] = "\n".join(rlines)

    tasks = p.get("tasks") or []
    tlines = ["# Tasks — %s" % name, "",
              "| Task | Status | Claimed by | Title |", "|---|---|---|---|"]
    for t in tasks:
        tlines.append("| %s | %s | %s | %s |" % (
            t.get("task_id"), t.get("status"), t.get("claimed_by") or "-",
            str(t.get("title") or "").replace("|", "\\|")))
    out["TASKS.md"] = "\n".join(tlines) + "\n"

    decisions = p.get("decisions") or []
    dlines = ["# Decisions — %s" % name, ""]
    if decisions:
        for d in decisions:
            dlines += ["## %s · %s [%s]" % (
                d.get("decision_id"), d.get("title"), d.get("status")), ""]
            if d.get("detail"):
                dlines += [str(d.get("detail")), ""]
            if d.get("rationale"):
                dlines += ["_Rationale:_ %s" % d.get("rationale"), ""]
    else:
        dlines += ["_No decisions._", ""]
    out["DECISIONS.md"] = "\n".join(dlines)

    room = p.get("room_messages") or []
    mlines = ["# Room / Inbox — %s" % name, ""]
    for m in room[-200:]:
        mlines.append("- **%s** · %s · _%s_: %s" % (
            m.get("actor"), m.get("msg_type") or "chat",
            m.get("at") or m.get("created_at") or "",
            str(m.get("body") or "").replace("\n", " ")))
    if not room:
        mlines.append("_No messages._")
    out["ROOM.md"] = "\n".join(mlines) + "\n"

    log = p.get("full_log") or []
    out["LOG.md"] = "# Project Log — %s\n\n```\n%s\n```\n" % (
        name, "\n".join(str(x) for x in log) if log else "(empty)")
    return out


def write_state_markdown(out_dir, projection):
    """Write render_state_markdown() output into ``out_dir`` (created if
    absent). Returns the list of written file paths. Atomic per file."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for filename, text in render_state_markdown(projection).items():
        target = directory / filename
        tmp = directory / (filename + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(str(tmp), str(target))
        written.append(str(target))
    return written


CLOUD_CONTEXT_BEGIN = "<!-- ATTACCA_CLOUD_CONTEXT:BEGIN"
CLOUD_CONTEXT_END = "<!-- ATTACCA_CLOUD_CONTEXT:END -->"
_CLOUD_CONTEXT_BLOCK_RE = re.compile(
    r"(?ms)^<!-- ATTACCA_CLOUD_CONTEXT:BEGIN\b[^\r\n]*-->.*?"
    r"^<!-- ATTACCA_CLOUD_CONTEXT:END -->[ \t]*$")


def cloud_context_block(cloud_context, project_id):
    """Build the versioned, sha-stamped Cloud Context block for AGENTS.md /
    CLAUDE.md. Like the managed block, it is a self-delimited region that
    Attacca owns; content outside the markers is never touched."""
    cc = cloud_context or {}
    content = (cc.get("content") or "").strip()
    version = cc.get("version") or 0
    sha = cc.get("sha256") or sha256_hex(content)
    header = "%s v=%s sha=%s project=%s do_not_edit=true -->" % (
        CLOUD_CONTEXT_BEGIN, version, sha[:16], project_id)
    body = content if content else "_No cloud context set yet._"
    note = ("<!-- Attacca Cloud Context: the shared project summary, synced "
            "from the server. Do not edit inside these markers; edit via the "
            "control panel or cloud_context_set. -->")
    return "%s\n%s\n%s\n%s" % (header, note, body, CLOUD_CONTEXT_END)


def cloud_context_block_present(text):
    """Return (present, version, sha) for a Cloud Context block in ``text``."""
    match = _CLOUD_CONTEXT_BLOCK_RE.search(text or "")
    if not match:
        return False, None, None
    head = match.group(0).splitlines()[0]
    ver = re.search(r"\bv=(\S+)", head)
    sha = re.search(r"\bsha=(\S+)", head)
    return True, (ver.group(1) if ver else None), (sha.group(1) if sha else None)


def refresh_cloud_context_block(conn, project_id, root_path, files=None,
                                create=False):
    """Sync the Cloud Context into AGENTS.md/CLAUDE.md as a managed block.

    If the block already exists it is refreshed in place (auto, like the
    managed law block). If it is absent it is only added when ``create`` is
    true (the AI offers this first). Everything outside the markers, including
    the managed protocol block and the human's own text, is preserved."""
    cc = cloud_context_get(conn, project_id)["cloud_context"]
    block = cloud_context_block(cc, project_id)
    root = Path(root_path).resolve()
    results = []
    for filename in (files or ["AGENTS.md", "CLAUDE.md"]):
        target = root / filename
        if target.is_symlink():
            # Follow the managed convention: a CLAUDE.md symlink to AGENTS.md
            # is refreshed through AGENTS.md, not written twice.
            results.append({"file": str(target), "changed": False,
                            "status": "linked"})
            continue
        text = target.read_text(encoding="utf-8") if target.exists() else ""
        match = _CLOUD_CONTEXT_BLOCK_RE.search(text)
        if match:
            if match.group(0).strip() == block.strip():
                results.append({"file": str(target), "changed": False,
                                "status": "current"})
                continue
            new_text = text[:match.start()] + block + text[match.end():]
            status = "updated"
        else:
            if not create:
                results.append({"file": str(target), "changed": False,
                                "status": "absent"})
                continue
            if not text:
                new_text = block + "\n"
            else:
                sep = "\n" if text.endswith("\n") else "\n\n"
                new_text = text + sep + block + "\n"
            status = "created"
        tmp = target.with_name(target.name + ".attacca-tmp")
        tmp.write_text(new_text, encoding="utf-8")
        os.replace(str(tmp), str(target))
        results.append({"file": str(target), "changed": True, "status": status})
    return {"ok": True, "project": project_id, "files": results,
            "version": cc.get("version"), "sha256": cc.get("sha256")}


def _version_tuple(value):
    parts = []
    for chunk in str(value or "").split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def poll_status(conn, project_id, actor_id=None, actor_type="agent",
                plugin_version=None, law_version=None):
    """One compact status for every hook/cron poll. Reports whether the plugin
    BINARY or the managed-law/MD block need updating (MONOTONIC — only being
    BEHIND the server counts, never a downgrade), and unread mail for the actor.
    Cheap and safe to call on every request."""
    project = get_project(conn, project_id)
    meta = managed_instruction_metadata(project_id, None)
    server_law_version = MANAGED_BLOCK_VERSION
    binary_update = bool(plugin_version) and \
        _version_tuple(plugin_version) < _version_tuple(VERSION)
    law_update = False
    if law_version is not None:
        try:
            law_update = int(law_version) < server_law_version
        except (TypeError, ValueError):
            law_update = False
    update = {
        "server_version": VERSION,
        "server_law_version": server_law_version,
        "server_law_sha256": meta.get("law_sha256"),
        "binary_update_available": binary_update,
        "managed_law_update_available": law_update,
        "up_to_date": not (binary_update or law_update),
    }
    mail = None
    if actor_id:
        peek = inbox_read(conn, project_id, actor_id, mark_read=False,
                          limit=200, actor_type=actor_type)
        mail = {
            "unread_total": peek.get("unread_total", 0),
            "unread_addressed": peek.get("unread_addressed", 0),
            "unread_direct": peek.get("unread_direct", 0),
            "unread_everyone": peek.get("unread_everyone", 0),
            "unread_group_context": peek.get("unread_group_context", 0),
            "unread_broadcasts": peek.get("unread_broadcasts", 0),
            "pending_disposition_total": peek.get(
                "pending_disposition_total", 0),
            "pending_dispositions": peek.get("pending_dispositions", []),
            "may_have_more": bool(peek.get("may_have_more")),
            "messages_include_all_visible": True,
            "has_new_mail": bool(peek.get("unread_total") or
                                 peek.get("may_have_more") or
                                 peek.get("pending_disposition_total")),
        }
    head = conn.execute(
        "SELECT MAX(seq) AS s FROM events WHERE project_id=?",
        (project_id,)).fetchone()
    return {"project": project_id,
            "context_version": project["context_version"],
            "update": update, "mail": mail,
            "workflow_warnings": workflow_warnings(
                conn, project_id, actor_id, actor_type),
            "cursor": {"event_seq": (head["s"] if head else 0) or 0}}


def managed_law_payload(project_id=None, db_path=None):
    """Serve the current managed-law block CONTENT so a client can apply it
    without a plugin/binary reinstall. Law is instruction text, not executable
    code; the server is authoritative for it. Version advances are monotonic on
    the client (never a downgrade)."""
    pid = project_id or _MANAGED_TEMPLATE_PROJECT
    block = managed_instruction_block(pid, db_path)
    meta = _metadata_for_managed_block(block)
    template = managed_instruction_block(_MANAGED_TEMPLATE_PROJECT, None)
    return {
        "version": MANAGED_BLOCK_VERSION,
        "sha256": meta.get("sha256"),
        "law_sha256": sha256_hex(template),
        "server_software_version": VERSION,
        "block": block,
    }


def build_parser():
    parser = argparse.ArgumentParser(
        prog="attacca.py",
        description="Local Project Attacca Layer: shared event ledger, task "
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

    sub.add_parser("projects", help="list projects in this attacca database")
    sub.add_parser("status", help="project + actor status")
    p = sub.add_parser("log", help="curated project log")
    p.add_argument("-n", "--limit", type=int, default=40)

    p = sub.add_parser(
        "export", help="write a complete deterministic workspace backup")
    p.add_argument(
        "--format", dest="export_format", default="zip",
        choices=tuple(PROJECT_EXPORT_FORMATS),
        help="backup artifact (default: zip)")
    p.add_argument(
        "-o", "--output", default=None,
        help="output file (default: attacca-PROJECT-FORMAT; '-' = stdout)")
    p.add_argument(
        "--force", action="store_true",
        help="replace an existing output file atomically")

    p = sub.add_parser("handoff", help="show or update the handoff")
    hsub = p.add_subparsers(dest="handoff_cmd")
    hsub.add_parser("show")
    ph = hsub.add_parser("history", help="all handoff versions")
    ph.add_argument("-n", "--limit", type=int, default=20)
    ps = hsub.add_parser("set", help="update handoff fields")
    for field in HANDOFF_FIELDS:
        ps.add_argument("--%s" % field.replace("_", "-"), dest=field, default=None)
    ps.add_argument("--expected-context-version", type=int, default=None,
                    help="reject the write if project context advanced")

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
                    help="one connected target workspace; both rooms retain it")
    pr = rsub.add_parser("read")
    pr.add_argument("--since", dest="since_seq", type=int, default=None)
    pr.add_argument("-n", "--limit", type=int, default=30)
    pr = rsub.add_parser("tail", help="follow the room (poll loop)")
    pr.add_argument("--interval", type=float, default=2.0)

    p = sub.add_parser(
        "inbox", help="your unread group-room messages; mentions/replies "
                      "assign attention only (persistent read cursor)")
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
    pt.add_argument("--plan-required", action="store_true",
                    help="mark this as large work requiring a detailed plan")
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
    pt = tsub.add_parser("plan", help="view, write, submit, or review a task plan")
    psub = pt.add_subparsers(dest="plan_cmd", required=True)
    pp = psub.add_parser("get", help="show the latest or a historical plan")
    pp.add_argument("task_id")
    pp.add_argument("--version", type=int, default=None)
    pp = psub.add_parser("set", help="create an immutable plan revision")
    pp.add_argument("task_id")
    pp.add_argument("--title", required=True)
    pp.add_argument("--overview", default="")
    sections_source = pp.add_mutually_exclusive_group(required=True)
    sections_source.add_argument(
        "--sections-json", default=None,
        help="JSON array of {section_id,title,body} objects")
    sections_source.add_argument(
        "--sections-file", default=None,
        help="path to a UTF-8 JSON array of plan sections")
    pp.add_argument("--expected-version", type=int, default=None)
    pp.add_argument("--submit", action="store_true",
                    help="submit this revision for review immediately")
    pp = psub.add_parser("submit", help="submit the current draft for review")
    pp.add_argument("task_id")
    pp.add_argument("--expected-version", type=int, required=True)
    pp = psub.add_parser("review", help="approve, suggest an edit, or comment")
    pp.add_argument("task_id")
    pp.add_argument("--expected-version", type=int, required=True)
    pp.add_argument("--action", required=True,
                    choices=["approve", "suggest_edit", "comment"])
    pp.add_argument("--section", dest="section_id", default=None)
    pp.add_argument("--note", default=None)

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

    p = sub.add_parser("serve", help="host the attacca server "
                                     "(REST API + MCP over HTTP) — the app "
                                     "owns the state; tools are clients")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--auth", action="store_true",
                   help="request authentication activation readiness; never "
                        "enforces until an admin explicitly activates")
    p.add_argument("--auth-mode", choices=AUTH_MODES, default="auto",
                   help="auto follows persisted activation; compatibility "
                        "keeps accounts optional for legacy-client migration")

    p = sub.add_parser(
        "connect", help="hosted stdio MCP client with verified identity-scoped "
                        "mirror/outbox continuity on transport outage (what "
                        "plugins and stdio-only tools spawn)")
    p.add_argument("--url", default=None,
                   help="server URL (default $ATTACCA_URL or %s)" % DEFAULT_URL)

    p = sub.add_parser(
        "mcp", help="run explicit direct-DB MCP development mode (never the "
                    "automatic hosted-connect fallback)")

    p = sub.add_parser(
        "watch", help="autonomous hosted-state watcher (runs while AI clients idle)")
    wsub = p.add_subparsers(dest="watch_cmd")
    pw = wsub.add_parser("start", help="subscribe this checkout and ensure one daemon")
    pw.add_argument("--url", default=None)
    pw.add_argument("--runtime", default=None)
    wsub.add_parser(
        "upgrade", help="restart stale watcher code from a saved linked checkout")
    wsub.add_parser("status", help="show daemon, subscriptions, cadence and queue")
    wsub.add_parser("stop", help="stop this machine's watcher daemon")

    p = sub.add_parser(
        "server", help="show or switch this machine's hosted Attacca URL")
    ssub = p.add_subparsers(dest="server_cmd")
    ssub.add_parser("show", help="show the effective machine server URL")
    ps = ssub.add_parser(
        "set", help="atomically rewire installed clients and watcher state")
    ps.add_argument("url", help="new http:// or https:// Attacca base URL")
    ps.add_argument(
        "--no-check", action="store_true",
        help="store an intentionally offline/future URL without /healthz validation")

    p = sub.add_parser("setup", help="one-shot project setup: register this "
                                     "directory, write .mcp.json, install the "
                                     "agent protocol block")
    p.add_argument("tools", nargs="*", default=None,
                   help="with --details: subset (claude kimi codex gemini "
                        "opencode glm cli)")
    p.add_argument("--url", default=None,
                   help="attacca server URL (default $ATTACCA_URL, packaged "
                        "plugin server, or %s)" % DEFAULT_URL)
    p.add_argument("--stdio", action="store_true",
                   help="wire tools as local stdio shims instead of clients "
                        "of the hosted server")
    p.add_argument("--no-instructions", action="store_true",
                   help="skip writing CLAUDE.md/AGENTS.md")
    p.add_argument("--here", action="store_true",
                   help="register THIS directory as its own project even if "
                        "it sits inside another registered project")
    p.add_argument("--attach", default=None, metavar="PROJECT_ID",
                   help="attach this checkout to an existing server project; "
                        "normally Git remote detection does this automatically")
    p.add_argument("--create", default=None, metavar="NAME",
                   help="explicitly create and attach a new server workspace")
    p.add_argument("--discover", action="store_true",
                   help="read-only: show Git detection and available server "
                        "workspaces for a conversational setup UI")
    p.add_argument("--role", choices=("keep", "director", "advisor", "worker"),
                   default="keep",
                   help="confirmed role for this AI in the selected workspace")
    p.add_argument("--lead", choices=("keep", "current", "clear"),
                   default="keep",
                   help="preserve the lead, make this actor lead, or clear it")
    p.add_argument("--bridge", default=None, metavar="PROJECT_ID",
                   help="confirmed workspace to connect in the AI Network")
    p.add_argument("--relationship",
                   choices=("master", "peer", "advisor", "none"),
                   default=None,
                   help="confirmed relationship for --bridge (default picker "
                        "choice is master)")
    p.add_argument("--principal", choices=("current", "other"),
                   default="other",
                   help="which side is master/advisor (default: other)")
    p.add_argument("--no-server", action="store_true",
                   help="do not auto-start the attacca server")
    p.add_argument("--skip-tools", default=None,
                   help="comma-separated tools NOT to configure "
                        "(codex,cline,cursor,windsurf,kimi,gemini,vscode,"
                        "opencode); 'all' configures none of them")
    p.add_argument("--tools-only", action="store_true",
                   help="only write GLOBAL tool configs (codex, cline, cursor, "
                        "windsurf, kimi) — no project registration, no server, "
                        "no files in this directory; used by install.sh")
    p.add_argument("-i", "--interactive", action="store_true",
                   help="show a numbered workspace picker and tool choices")
    p.add_argument("--login", metavar="USERNAME", default=None,
                   help=argparse.SUPPRESS)
    p.add_argument("--paste-token", action="store_true",
                   help=argparse.SUPPRESS)
    p.add_argument("--owner", default=None,
                   help="your name for attribution — every ledger event and "
                        "agent is tagged separately; it is never prefixed to "
                        "the workspace.role.runtime actor id")
    p.add_argument("--details", action="store_true",
                   help="print the full per-tool configuration reference "
                        "instead of running setup")

    p = sub.add_parser("install-instructions",
                       help="write managed attacca block into CLAUDE.md/AGENTS.md")
    p.add_argument("--files", default=None,
                   help="comma-separated filenames (default CLAUDE.md,AGENTS.md)")

    return parser


def human_print(result, command=None):
    """Render common result shapes in a terminal-friendly way."""
    if isinstance(result, dict) and "plan" in result:
        plan = result.get("plan")
        task_id = result.get("task_id") or (plan or {}).get("task_id") or "task"
        if not plan:
            print("%s has no detailed plan" % task_id)
            return
        print("%s plan v%s [%s] — %s" % (
            task_id, plan.get("version"), plan.get("status"),
            plan.get("title")))
        if plan.get("overview"):
            print("\n%s" % plan["overview"])
        for index, section in enumerate(plan.get("sections") or [], 1):
            print("\n%d. %s [%s]" % (
                index, section.get("title"), section.get("section_id")))
            print(section.get("body") or "")
        actions = plan.get("actions") or []
        if actions:
            print("\nReview history:")
            for action in actions:
                payload = action.get("payload") or {}
                owner = action.get("owner")
                origin = " by %s" % action.get("operational_actor_id")
                if owner:
                    origin += " (run by %s)" % owner
                note = (": %s" % payload.get("note")) \
                    if payload.get("note") else ""
                print("- %s%s%s" % (
                    action.get("event_type"), origin, note))
        return
    if isinstance(result, dict) and "log" in result:
        for line in result["log"]:
            print(line)
        return
    if isinstance(result, dict) and "messages" in result:
        if not result["messages"] and "unread_broadcasts" in result:
            print("group inbox empty")
        for msg in result["messages"]:
            origin = (" via %s" % msg["origin_project"]) if msg.get("origin_project") else ""
            task = (" [%s]" % msg["task_id"]) if msg.get("task_id") else ""
            auth = (" [%s]" % msg["authority"].upper()) if msg.get("authority") else ""
            owner = (" (OWNER: %s)" % msg["owner"]) if msg.get("owner") else ""
            mentions = (" @" + ",@".join(str(m) for m in msg["mentions"])) \
                if msg.get("mentions") else ""
            attention = (" [EVERYONE]" if msg.get("broadcast_to_everyone")
                         else " [YOUR ATTENTION]" if msg.get("addressed_to_you")
                         else " [GROUP CONTEXT]" if msg.get("group_context")
                         else "")
            print("#%-4d %s  %s%s%s (%s)%s%s%s%s: %s" % (
                msg["seq"], msg["at"][:19].replace("T", " "), msg["actor"], owner,
                origin, msg["msg_type"], auth, task, mentions, attention,
                msg["body"]))
        if "next_since_seq" in result:
            print("-- next_since_seq: %s" % result["next_since_seq"])
        if "unread_broadcasts" in result:
            total = result.get("unread_total", len(result["messages"]))
            print("-- unread visible group messages: %d%s" % (
                total, " (more pages remain)" if result.get("may_have_more")
                else ""))
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
    set_current_git_context(git_branch(os.getcwd()), git_head(os.getcwd()))
    actor = args.actor or os.environ.get(ENV_ACTOR) or os.environ.get("USER") or "human"
    actor = qualify_actor(actor, owner=owner)
    actor_type = args.actor_type or os.environ.get(ENV_ACTOR_TYPE) or "human"
    default_project = args.project or os.environ.get(ENV_PROJECT)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "serve":
        run_server(db_path, host=args.host, port=args.port,
                   default_project=default_project, verbose=args.verbose,
                   auth=args.auth, auth_mode=args.auth_mode)
        return 0

    if args.command == "connect":
        run_connect_proxy(url=args.url,
                          actor=args.actor or os.environ.get(ENV_ACTOR),
                          actor_type=args.actor_type
                          or os.environ.get(ENV_ACTOR_TYPE),
                          project=default_project)
        return 0

    if args.command == "mcp":
        session = McpSession(db_path, default_project=default_project,
                             actor=args.actor or os.environ.get(ENV_ACTOR),
                             actor_type=args.actor_type
                             or os.environ.get(ENV_ACTOR_TYPE) or "agent")
        session.serve()
        return 0

    if args.command == "watch":
        watch_cmd = args.watch_cmd or "status"
        runtime = getattr(args, "runtime", None) or \
            normalize_agent_runtime(actor=args.actor or os.environ.get(ENV_ACTOR))
        result = watcher_command(
            "start" if watch_cmd == "start" else watch_cmd,
            root_path=os.getcwd() if watch_cmd == "start" else None,
            url=getattr(args, "url", None),
            actor=args.actor or os.environ.get(ENV_ACTOR), runtime=runtime)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("ok", True) else 2

    if args.command == "server":
        server_cmd = args.server_cmd or "show"
        if server_cmd == "set":
            result = machine_server_set(
                args.url, validate=not args.no_check)
        else:
            result = machine_server_show()
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif server_cmd == "set":
            state = "switched" if result["changed"] else "already configured"
            print("Attacca server %s: %s" % (state, result["server_url"]))
            print("Machine config: %s" % result["config_path"])
            for item in result["rewired"]:
                marker = "updated" if item["changed"] else "already current"
                print("  %s: %s (%s)" %
                      (item["tool"], item["path"], marker))
            print("Watcher subscriptions rewired: %d" %
                  result["watcher_subscriptions_rewired"])
            old_outbox = result["old_server_outbox"]
            if old_outbox["pending_mutations"]:
                print("Old-server offline writes preserved (not moved): %d" %
                      old_outbox["pending_mutations"])
            if result["restart_required"]:
                print("Restart/reconnect: %s" %
                      ", ".join(result["restart_required"]))
        else:
            print("Attacca server: %s" % result["server_url"])
            print("Source: %s" % result["source"])
            print("Machine config: %s" % result["config_path"])
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
        result = project_log(conn, project(), limit=args.limit,
                             actor_id=actor, actor_type=actor_type)
    elif cmd == "export":
        artifact = build_project_export_artifact(
            conn, project(), args.export_format)
        if args.output == "-":
            sys.stdout.buffer.write(artifact["data"])
            sys.stdout.buffer.flush()
            return 0
        output_path = args.output or artifact["filename"]
        saved = save_project_export_artifact(
            output_path, artifact["data"], force=args.force)
        if args.json:
            print(json.dumps({
                "ok": True, "project": project(),
                "format": artifact["format"], "path": saved,
                "bytes": len(artifact["data"]),
                "sha256": artifact["sha256"],
                "snapshot": artifact["snapshot"],
            }, indent=2, ensure_ascii=False))
        else:
            print("wrote %s (%d bytes, sha256 %s)" % (
                saved, len(artifact["data"]), artifact["sha256"]))
        return 0
    elif cmd == "handoff":
        if args.handoff_cmd == "set":
            updates = {field: getattr(args, field) for field in HANDOFF_FIELDS}
            result = update_handoff(
                conn, project(), actor, actor_type, updates,
                expected_context_version=args.expected_context_version)
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
        human_print(project_log(conn, proj, limit=15, actor_id=actor,
                                actor_type=actor_type))
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
            source = project()
            result = room_send(conn, source, actor, actor_type, body=args.body,
                               msg_type=args.msg_type,
                               mentions=args.mentions.split(",") if args.mentions else None,
                               task_id=args.task_id,
                               target_project=args.to_project or source)
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
                               limit=getattr(args, "limit", 30),
                               actor_id=actor, actor_type=actor_type)
    elif cmd == "inbox":
        result = inbox_read(conn, project(), actor,
                            mark_read=not args.keep_unread, limit=args.limit,
                            actor_type=actor_type)
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
                                 risk_level=args.risk,
                                 plan_required=args.plan_required)
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
                raise AttaccaError(
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
        elif args.task_cmd == "plan":
            if args.plan_cmd == "get":
                result = task_plan_get(
                    conn, project(), args.task_id, version=args.version)
            elif args.plan_cmd == "set":
                raw_sections = args.sections_json
                if args.sections_file:
                    try:
                        raw_sections = Path(args.sections_file).read_text(
                            encoding="utf-8")
                    except OSError as err:
                        raise AttaccaError(
                            "could not read --sections-file: %s" % err)
                try:
                    sections = json.loads(raw_sections)
                except json.JSONDecodeError as err:
                    raise AttaccaError(
                        "plan sections must be valid JSON: %s" % err)
                result = task_plan_set(
                    conn, project(), args.task_id, actor, actor_type,
                    title=args.title, overview=args.overview,
                    sections=sections,
                    expected_version=args.expected_version,
                    submit_for_review=args.submit)
            elif args.plan_cmd == "submit":
                result = task_plan_submit(
                    conn, project(), args.task_id, actor, actor_type,
                    expected_version=args.expected_version)
            elif args.plan_cmd == "review":
                result = task_plan_review(
                    conn, project(), args.task_id, actor, actor_type,
                    expected_version=args.expected_version,
                    action=args.action, section_id=args.section_id,
                    note=args.note)
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
                raise AttaccaError("--payload must be valid JSON: %s" % err)
            if not isinstance(payload, dict):
                raise AttaccaError("--payload must be a JSON object")
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
        result = check_freshness(conn, project(), args.context_version,
                                 actor_id=actor, actor_type=actor_type)
    elif cmd == "setup":
        setup_url = configured_server_url(args.url)
        setup_auth = None
        if args.discover:
            setup_auth = ensure_remote_setup_auth(
                setup_url, actor, interactive=False,
                login_username=args.login, paste_token=args.paste_token)
            discovery = discover_remote_setup(
                setup_url, actor_id=actor, actor_type=actor_type,
                here=args.here, selected_project_id=args.attach)
            if args.json:
                print(json.dumps(discovery, indent=2, ensure_ascii=False))
            else:
                git = discovery["git"]
                print("Git repository: %s" % (
                    git["remote"] if git["detected"] else "not detected"))
                if discovery["suggested_project_id"]:
                    print("Suggested workspace: %s (confirmation required)"
                          % discovery["suggested_project_id"])
                elif discovery["workspaces"]:
                    print("Available workspaces: %s"
                          % ", ".join(p["project_id"]
                                      for p in discovery["workspaces"]))
                else:
                    print("No workspaces exist yet — create the first one.")
            return 0
        if args.details or args.tools:
            proj_id = None
            try:
                proj_id = project()
            except AttaccaError:
                pass
            print(setup_details_text(proj_id, db_path, url=setup_url,
                                     tools=args.tools or None))
            return 0
        if args.tools_only:
            # install.sh mode: global tool configs only — no identity
            # interview, no project registration, nothing written to cwd.
            skip = None
            if args.skip_tools:
                skip = ({"codex", "cline", "cursor", "windsurf", "kimi",
                         "gemini", "vscode", "opencode"}
                        if args.skip_tools.strip() == "all"
                        else {t.strip() for t in args.skip_tools.split(",")})
            info = one_shot_setup(conn, actor, actor_type, db_path,
                                  url=setup_url, stdio=args.stdio,
                                  manage_server=False, skip_tools=skip,
                                  tools_only=True)
            for entry in info["configured_tools"]:
                print("✔ %s: %s" % (entry["tool"], entry["path"]))
            if info["not_detected"]:
                print("· not detected (skipped): %s"
                      % ", ".join(info["not_detected"]))
            if not info["configured_tools"]:
                print("· no supported tools detected — `setup --details` "
                      "prints configs to paste by hand")
            return 0
        if not args.interactive and not args.stdio and not args.attach \
                and not args.create and sys.stdin.isatty():
            # `attacca setup` is the human-facing one-run entry point. Scripts
            # and native skills remain deterministic because their stdin is
            # non-interactive or they pass the confirmed flags explicitly.
            args.interactive = True
        if args.owner:
            save_owner(args.owner)
            owner = load_owner()
            set_current_owner(owner)
            actor = qualify_actor(args.actor or os.environ.get(ENV_ACTOR)
                                  or os.environ.get("USER") or "human",
                                  owner=owner)
            print("✔ identity: %s (stored in %s)" % (owner, IDENTITY_FILE))
        if args.interactive and args.stdio:
            def ask_stdio(prompt):
                try:
                    return input(prompt).strip()
                except EOFError:
                    return ""
            print("attacca interactive serverless setup — press Enter to "
                  "accept defaults")
            cwd = Path(os.getcwd()).resolve()
            linked = None if args.here else find_project_link(cwd)
            registered = None if args.here else _project_for_cwd(conn, cwd)
            if not args.attach and not args.create and not linked \
                    and not registered:
                suggestion = git_worktree_root(cwd).name
                args.create = ask_stdio(
                    "local workspace name [%s]: " % suggestion) or suggestion
            skip_in = ask_stdio(
                "tools to SKIP (codex,cline,cursor,windsurf,kimi,gemini,"
                "vscode,opencode; blank = wire all detected): ")
            if skip_in:
                args.skip_tools = skip_in
            # The hosted interactive branch below performs REST discovery;
            # serverless setup must never call it.
            args.interactive = False
        if args.interactive:
            def ask(prompt):
                try:
                    return input(prompt).strip()
                except EOFError:
                    return ""
            print("attacca interactive setup — press Enter to accept defaults")
            url_in = ask("server URL [%s]: " % setup_url)
            if url_in:
                setup_url = configured_server_url(url_in)
            setup_auth = ensure_remote_setup_auth(
                setup_url, actor, interactive=True, ask=ask,
                login_username=args.login, paste_token=args.paste_token)
            discovery = discover_remote_setup(
                setup_url, actor_id=actor, actor_type=actor_type,
                here=args.here)
            git = discovery["git"]
            workspace_names = {
                workspace["project_id"]: workspace["name"]
                for workspace in discovery["workspaces"]}
            print("  Git repository: %s" % (
                git["remote"] if git["detected"] else "not detected"))
            if discovery["linked_project_id"]:
                print("  already linked: %s" % workspace_names.get(
                    discovery["linked_project_id"],
                    discovery["linked_project_id"]))
            elif discovery["action"] in (
                    "confirm_git_match", "confirm_folder_match"):
                suggestion = discovery["suggested_project_id"]
                suggestion_name = workspace_names.get(suggestion, suggestion)
                subject = "repository" if discovery["action"] == \
                    "confirm_git_match" else "folder"
                confirmed = ask(
                    "this %s matches workspace '%s'. Use it? [Y/n]: "
                    % (subject, suggestion_name)).lower()
                if confirmed in ("", "y", "yes"):
                    args.attach = suggestion
            if not discovery["linked_project_id"] and not args.attach:
                workspaces = discovery["workspaces"]
                if workspaces:
                    print("  available workspaces:")
                    for index, workspace in enumerate(workspaces, 1):
                        print("    %d. %s" % (index, workspace["name"]))
                    print("    %d. Create new" % (len(workspaces) + 1))
                    choice = ask("choose a workspace number: ")
                    try:
                        choice_number = int(choice)
                    except ValueError:
                        raise AttaccaError("choose one of the listed numbers")
                    if 1 <= choice_number <= len(workspaces):
                        args.attach = workspaces[choice_number - 1]["project_id"]
                    elif choice_number == len(workspaces) + 1:
                        args.create = ask("new workspace name: ")
                    else:
                        raise AttaccaError("choose one of the listed numbers")
                else:
                    suggestion = discovery["suggested_new_name"] or ""
                    print("  no Attacca workspaces exist yet.")
                    args.create = ask(
                        "create the first workspace%s: "
                        % (" [%s]" % suggestion if suggestion else "")) \
                        or suggestion
            if args.create is not None and not args.create.strip():
                raise AttaccaError("new workspace name cannot be blank")
            skip_in = ask("tools to SKIP (codex,cline,cursor,windsurf,kimi,gemini,"
                          "vscode,opencode; blank = wire all detected): ")
            if skip_in:
                args.skip_tools = skip_in
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
            skip = ({"codex", "cline", "cursor", "windsurf", "kimi", "gemini",
                     "vscode", "opencode"} if args.skip_tools.strip() == "all"
                    else {t.strip() for t in args.skip_tools.split(",")})
        if args.stdio:
            info = one_shot_setup(
                conn, actor, actor_type, db_path, url=setup_url, stdio=True,
                here=args.here, manage_server=False, skip_tools=skip,
                write_instructions=not args.no_instructions,
                attach_project=args.attach, create_project=args.create)
        else:
            if setup_auth is None:
                setup_auth = ensure_remote_setup_auth(
                    setup_url, actor, interactive=False,
                    login_username=args.login,
                    paste_token=args.paste_token)
            info = one_shot_remote_setup(
                actor, actor_type, db_path, url=setup_url, here=args.here,
                manage_server=not args.no_server, skip_tools=skip,
                write_instructions=not args.no_instructions,
                attach_project=args.attach, create_project=args.create)
        network_result = None
        if info["mode"] == "server":
            if args.interactive:
                network_discovery = discover_remote_setup(
                    setup_url, actor_id=actor, actor_type=actor_type,
                    here=args.here,
                    selected_project_id=info["project_id"])
                network = network_discovery["network"]
                print("\nAI Network")
                print("  one workspace = one room; bridges connect rooms")
                if network["relationship_inbox"]:
                    print("  existing cross-workspace inbox activity:")
                    for message in network["relationship_inbox"][-5:]:
                        print("    from %s · %s: %s" % (
                            message.get("origin_project_name") or
                            message.get("origin_project") or
                            "connected workspace",
                            message.get("actor") or "unknown",
                            str(message.get("body") or "").replace("\n", " ")[:100]))
                if network["existing_relationships"]:
                    print("  existing relationships:")
                    for bridge in network["existing_relationships"]:
                        print("    %s · %s · principal %s" % (
                            bridge.get("with_name") or bridge["with"],
                            bridge["relation"],
                            bridge.get("principal_name") or
                            bridge.get("principal") or "neither"))

                if actor_type == "agent":
                    lead = network.get("lead_director")
                    current_ai = network.get("current_actor") or actor
                    if lead == current_ai:
                        print("  lead director remains %s" % current_ai)
                        args.role = "director"
                    elif lead:
                        lead_record = network.get("lead_director_record") or {}
                        lead_name = lead_record.get("display_name") or lead
                        print("  current lead director: %s" % lead_name)
                        print("    1. Keep that lead; join this AI as another director (default)")
                        print("    2. Replace the lead with this AI")
                        print("    3. Join this AI as an advisor (cannot write handoff)")
                        print("    4. Join this AI as a worker (cannot write handoff)")
                        choice = ask("  choose this AI's role [1]: ") or "1"
                        if choice == "1":
                            args.role = "director"
                        elif choice == "2":
                            args.role, args.lead = "director", "current"
                        elif choice == "3":
                            args.role = "advisor"
                        elif choice == "4":
                            args.role = "worker"
                        else:
                            raise AttaccaError("choose role 1, 2, 3, or 4")
                    else:
                        print("    1. Make this AI Lead Director (default)")
                        print("    2. Join as a director without a lead")
                        print("    3. Join as an advisor (cannot write handoff)")
                        print("    4. Join as a worker (cannot write handoff)")
                        choice = ask("  choose this AI's role [1]: ") or "1"
                        if choice == "1":
                            args.role, args.lead = "director", "current"
                        elif choice == "2":
                            args.role = "director"
                        elif choice == "3":
                            args.role = "advisor"
                        elif choice == "4":
                            args.role = "worker"
                        else:
                            raise AttaccaError("choose role 1, 2, 3, or 4")

                keep_relationships = bool(network["existing_relationships"])
                if keep_relationships:
                    keep = ask("  keep the existing workspace relationships? [Y/n]: ").lower()
                    keep_relationships = keep in ("", "y", "yes")
                candidates = network["available_workspaces"]
                if candidates and not keep_relationships:
                    connect_choice = ask(
                        "  connect this room to another workspace room? [Y/n]: ").lower()
                    if connect_choice in ("", "y", "yes"):
                        preferred = network.get("default_master_project")
                        if preferred:
                            candidates.sort(
                                key=lambda item: item["project_id"] != preferred)
                        for index, workspace in enumerate(candidates, 1):
                            marker = " (default)" if index == 1 else ""
                            print("    %d. %s%s" % (
                                index, workspace["name"], marker))
                        raw_choice = ask("  choose connected workspace [1]: ") or "1"
                        try:
                            selected_index = int(raw_choice) - 1
                            if not 0 <= selected_index < len(candidates):
                                raise IndexError
                            selected_bridge = candidates[selected_index]
                        except (ValueError, IndexError):
                            raise AttaccaError("choose a listed workspace number")
                        args.bridge = selected_bridge["project_id"]
                        print("    1. Master/subordinate (default)")
                        print("    2. Peer")
                        print("    3. Advisor")
                        print("    4. Do not connect")
                        relation_choice = ask("  relationship [1]: ") or "1"
                        relation_map = {"1": "master", "2": "peer",
                                        "3": "advisor", "4": "none"}
                        if relation_choice not in relation_map:
                            raise AttaccaError("choose relationship 1, 2, 3, or 4")
                        args.relationship = relation_map[relation_choice]
                        if args.relationship in ("master", "advisor"):
                            label = "master" if args.relationship == "master" \
                                else "advisor"
                            print("    1. %s is %s (default)" % (
                                selected_bridge["name"], label))
                            print("    2. %s is %s" % (
                                info["project_id"], label))
                            principal_choice = ask(
                                "  principal side [1]: ") or "1"
                            if principal_choice not in ("1", "2"):
                                raise AttaccaError(
                                    "choose principal side 1 or 2")
                            args.principal = "current" \
                                if principal_choice == "2" else "other"
            if args.bridge and args.relationship is None:
                raise AttaccaError(
                    "--bridge requires --relationship master, peer, advisor, "
                    "or none")
            if args.relationship not in (None, "none") and not args.bridge:
                raise AttaccaError(
                    "--relationship requires a different --bridge workspace")
            if args.role != "keep" or args.lead != "keep" \
                    or args.relationship is not None:
                network_result = apply_remote_network_setup(
                    setup_url, info["project_id"], actor, actor_type,
                    role=args.role, lead=args.lead, bridge=args.bridge,
                    relationship=args.relationship,
                    principal_side=args.principal)
        credential_result = None
        if info["mode"] == "server" and actor_type == "agent":
            token_actor = (network_result or {}).get("actor") or actor
            credential_result = provision_setup_agent_token(
                setup_url, info["project_id"], token_actor)
        elif _remote_setup_session(setup_url):
            close_remote_setup_session(setup_url)
        watcher_result = None
        watcher_error = None
        if info["mode"] == "server":
            watcher_actor = (network_result or {}).get("actor") or actor
            watcher_runtime = normalize_agent_runtime(actor=watcher_actor)
            try:
                watcher_result = watcher_command(
                    "start", root_path=info["root_path"], url=setup_url,
                    actor=watcher_actor, runtime=watcher_runtime)
                if not watcher_result.get("ok", True):
                    watcher_error = watcher_result.get("error") or \
                        "watcher did not start"
            except Exception as err:
                watcher_error = str(err)
        cron_result = None
        cron_error = None
        if info["mode"] == "server":
            cron_actor = (network_result or {}).get("actor") or actor
            cron_runtime = normalize_agent_runtime(actor=cron_actor)
            try:
                cron_result = ensure_watcher_cron(
                    info["root_path"], url=setup_url, actor=cron_actor,
                    runtime=cron_runtime)
                if not cron_result.get("ok"):
                    cron_error = cron_result.get("error")
            except Exception as err:
                cron_error = str(err)
        script = script_path()
        inside = "  (this folder is inside it — use --here to make ./ its own project)" \
            if info["cwd_inside_root"] else ""
        print("✔ project: %s  root: %s%s"
              % (info["project_id"], info["root_path"], inside))
        print("✔ portable workspace link (safe to commit): %s%s" % (
            info["project_link"],
            "  (matched by %s)" % info["matched_by"]
            if info.get("matched_by") else ""))
        if info["mode"] == "server":
            server = info["server"]
            if server["managed"]:
                print("✔ server: %s at %s%s"
                      % ("started" if server["started"] else "running",
                         info["url"],
                         ("  (log: %s)" % server["log"]) if server["log"] else ""))
            else:
                print("✔ server: connected at %s" % info["url"])
        if info["mcp_json"]:
            print("✔ machine-local MCP endpoint (regenerate per machine): %s"
                  % info["mcp_json"])
            print("  contains this machine/site's server connection; it does not "
                  "identify the workspace")
        else:
            print("✔ claude code: native Attacca plugin (no duplicate project MCP)")
        for entry in info["configured_tools"]:
            print("✔ %s: %s" % (entry["tool"], entry["path"]))
        if info["instruction_files"]:
            print("✔ modified agent instructions (review before commit): %s"
                  % ", ".join(Path(f).name for f in info["instruction_files"]))
        if info["not_detected"]:
            print("· not detected (skipped): %s" % ", ".join(info["not_detected"]))
        if network_result:
            print("✔ AI Network: %s" % (
                ", ".join(action["kind"] for action in
                          network_result["actions"]) or "already configured"))
        if credential_result and credential_result.get("status") in (
                "ready", "approved"):
            print("✔ client authorization: %s" %
                  credential_result.get("client_instance", "this install"))
            if credential_result.get("credentials_file"):
                print("  client API key stored privately in %s" %
                      credential_result["credentials_file"])
            else:
                print("  client API key hot-loaded from this active process")
            print("  AI actor and Run by user attribution remain separate")
        elif credential_result and credential_result.get("authorization_url"):
            print("· client authorization pending in Settings: %s" %
                  credential_result["authorization_url"])
        if watcher_result and not watcher_error:
            action = "already running" if watcher_result.get(
                "already_running") else "started"
            print("✔ autonomous watcher: %s (lightweight checks every minute while idle)"
                  % action)
            if watcher_result.get("log"):
                print("  log: %s" % watcher_result["log"])
        elif watcher_error:
            print("! autonomous watcher could not start: %s" % watcher_error,
                  file=sys.stderr)
        if cron_result and cron_result.get("ok"):
            _cron_word = {"installed": "installed", "refreshed": "refreshed",
                          "already": "already installed"}.get(
                cron_result.get("status"), cron_result.get("status"))
            print("✔ per-minute update cron: %s (pings Attacca for updates "
                  "every minute even while no client is open)" % _cron_word)
        elif cron_error:
            print("· per-minute update cron not installed: %s" % cron_error,
                  file=sys.stderr)
            print("  the lifecycle watcher daemon still polls every minute "
                  "while a client is open.", file=sys.stderr)
        lifecycle_hook = Path(script_path()).resolve().parent / "hooks" / "hooks.json"
        if lifecycle_hook.is_file():
            print("✔ lifecycle continuity hooks: %s" % lifecycle_hook)
            print("  startup hooks inject handoff, rules, inbox, room, tasks and status")
            print("  the background watcher keeps checking while clients are idle")
            print("  (Codex: trust Attacca once in /hooks)")
        else:
            print("! lifecycle startup hook missing from this install", file=sys.stderr)
        print()
        print("Done — setup is one-time. Credential changes are detected "
              "without a client restart.")
        print("Any other MCP client (Grok, Zed, ...): `setup --details` prints "
              "generic configs.")
        return 0
    elif cmd == "install-instructions":
        proj_id = project()
        root = get_project(conn, proj_id).get("root_path")
        files = args.files.split(",") if args.files else None
        result = install_instructions(proj_id, root, db_path, files=files)
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
    except AttaccaError as err:
        sys.stderr.write("error: %s\n" % err)
        sys.exit(2)
    except BrokenPipeError:
        sys.exit(0)
    finally:
        # Revoke any legacy short-lived browser session even when setup exits
        # early; terminal/device credentials are stored independently.
        try:
            close_remote_setup_session()
        except Exception:
            _remote_setup_auth.context = None


if __name__ == "__main__":
    main()
