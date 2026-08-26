#!/usr/bin/env python3
"""Codex, Claude, and Kimi lifecycle hook for Attacca.

An unlinked folder gets a one-time setup offer. A linked checkout is resolved
through ``.attacca/project.json`` and synchronized through the configured MCP
connection before the agent begins work. A detached machine-local watcher polls
the hosted workspace at the server-configured cadence even while coding clients
are idle. It durably queues concise changes; lifecycle hooks inject that queue
at the next supported turn boundary, so the user never has to type
"check messages".
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import signal
import shlex
import shutil
import subprocess
import sys
import threading
import time
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlparse
from urllib.request import Request, urlopen

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback remains atomic replace
    fcntl = None


STATE_NAME = "setup-prompts.json"
WATCHER_STATE_NAME = "watcher-state.json"
WATCHER_QUEUE_LIMIT = 50
WATCHER_WAKE_SECONDS = 5
WATCHER_EVENT_PAGE_SIZE = 200
WATCHER_EVENT_MAX_PAGES = 20
WATCHER_OUTAGE_BACKOFF_MAX_SECONDS = 15 * 60
DEFAULT_UPDATE_INTERVAL_SECONDS = 60
CONFIGURED_AI_ROLES = {"director", "advisor", "worker"}
UPDATE_CHOICES = {"install", "later", "skip"}
AUXILIARY_HTTP_TIMEOUT_SECONDS = 1
UPDATE_REMIND_AFTER_SECONDS = 24 * 60 * 60
UPDATE_CHECK_INTERVAL_SECONDS = 5 * 60

# A watcher process keeps executing the Python code which was imported when it
# started even if install.sh later atomically replaces the stable plugin tree.
# Capture that launch image once, before any daemon work begins.  Heartbeats
# must carry these immutable values; rereading VERSION or source from the
# replaced path would let an old process falsely relabel itself as current.
WATCHER_LAUNCH_FILES = (
    "hooks/session_start.py",
    "terminal_flow.py",
    "sync_protocol.py",
    "sync_client.py",
    "offline_sync.py",
)
WATCHER_LAUNCH_FINGERPRINT_ENV = "ATTACCA_WATCHER_LAUNCH_FINGERPRINT"
WATCHER_LAUNCH_HOOK_SHA_ENV = "ATTACCA_WATCHER_LAUNCH_HOOK_SHA256"
WATCHER_LAUNCH_VERSION_ENV = "ATTACCA_WATCHER_LAUNCH_VERSION"


def _watcher_launch_identity_for_root(plugin_root):
    """Hash every file executable by the detached watcher at launch time."""
    root = Path(plugin_root).expanduser().resolve()
    digest = hashlib.sha256()
    hook_sha = None
    for relative in WATCHER_LAUNCH_FILES:
        data = (root / relative).read_bytes()
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        if relative == "hooks/session_start.py":
            hook_sha = "sha256:" + hashlib.sha256(data).hexdigest()
    runtime = (root / "attacca.py").read_text()
    match = re.search(
        r'^VERSION\s*=\s*["\']([^"\']+)["\']\s*$', runtime,
        flags=re.MULTILINE)
    if not match:
        raise RuntimeError("installed Attacca plugin has no VERSION")
    return {
        "launch_version": match.group(1).strip(),
        "launch_hook_sha256": hook_sha,
        "launch_fingerprint": "sha256:" + digest.hexdigest(),
    }


try:
    _CAPTURED_WATCHER_LAUNCH_IDENTITY = _watcher_launch_identity_for_root(
        Path(__file__).resolve().parent.parent)
except Exception:
    # A partial/corrupt install must fail the daemon handshake later rather
    # than making every diagnostic invocation of this hook unimportable.
    _CAPTURED_WATCHER_LAUNCH_IDENTITY = None

_SYNC_MODULE_CACHE = {}
_TERMINAL_MODULE_CACHE = {}
_RUNTIME_SOURCE_CACHE = {}
_RUNTIME_SOURCE_CACHE_LIMIT = 32
_RUNTIME_MODULE_CACHE_LIMIT = 8


def _runtime_name():
    explicit = str(os.environ.get("ATTACCA_RUNTIME") or "").strip().lower()
    if explicit:
        return explicit
    if os.environ.get("PLUGIN_ROOT"):
        return "codex"
    if os.environ.get("KIMI_PLUGIN_ROOT"):
        return "kimi"
    # Codex deliberately also exports CLAUDE_PLUGIN_ROOT for hook
    # compatibility, so the Codex-specific PLUGIN_ROOT check must stay first.
    # A real Claude plugin has CLAUDE_PLUGIN_ROOT without PLUGIN_ROOT.
    return "claude"


def _stable_plugin_root():
    """Return the install root containing this stable lifecycle launcher."""
    return Path(__file__).resolve().parent.parent


def _plugin_root():
    """Run one coherent plugin image beside this stable hook launcher.

    Codex and Claude export versioned cache roots for plugin discovery, but
    this hook is deliberately invoked from the machine-stable Attacca install.
    Mixing that newer launcher with dependencies from an older cache produced
    a split runtime: direct MCP stayed online while the watcher loaded an old
    schema (or could not find a newly packaged module). Runtime identity still
    comes from the client markers in :func:`_runtime_name`; executable code and
    configuration come from the directory containing the hook that is actually
    running. Kimi's relative hook naturally resolves its own installed root.
    """
    return _stable_plugin_root()


def _git(args, cwd):
    try:
        proc = subprocess.run(
            ["git"] + list(args), cwd=str(cwd), capture_output=True,
            text=True, timeout=3)
        value = proc.stdout.strip()
        return value if proc.returncode == 0 and value else None
    except Exception:
        return None


def _canonical_remote(remote):
    raw = str(remote or "").strip()
    if not raw:
        return None
    host = path = None
    if "://" not in raw and ":" in raw:
        left, path = raw.split(":", 1)
        host = left.rsplit("@", 1)[-1]
    else:
        parsed = urlparse(raw)
        host, path = parsed.hostname, parsed.path
    if not host or not path:
        return None
    path = unquote(path).strip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    return "%s/%s" % (host.lower(), path) if path else None


def _project_identity(cwd):
    cwd = Path(cwd).resolve()
    git_root = _git(["rev-parse", "--show-toplevel"], cwd)
    root = Path(git_root).resolve() if git_root else cwd
    remote = _canonical_remote(_git(["config", "--get", "remote.origin.url"], root))
    raw = "git:%s" % remote if remote else "path:%s" % root
    key = "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return key, root, remote


def _find_link(cwd):
    start = Path(cwd).resolve()
    for directory in (start,) + tuple(start.parents):
        target = directory / ".attacca" / "project.json"
        if not target.is_file():
            continue
        try:
            data = json.loads(target.read_text())
            project_id = data.get("project_id") if isinstance(data, dict) else None
            if isinstance(project_id, str) and project_id.strip():
                return project_id.strip(), str(target)
        except Exception:
            return None
    return None


def _reconcile_claude_project_mcp(cwd):
    """Self-heal the pre-native-plugin Claude project MCP duplicate.

    Curl can be rerun from anywhere, so the installer cannot discover every
    checkout on a machine. The native Claude hook *does* know the checkout when
    it opens. Remove only the managed ``attacca`` key and preserve every other
    project MCP server/setting. The current process may already have loaded the
    old entry, so callers surface one restart notice after a change.
    """
    if not os.environ.get("CLAUDE_PLUGIN_ROOT") \
            or os.environ.get("PLUGIN_ROOT") \
            or os.environ.get("KIMI_PLUGIN_ROOT"):
        return None
    link = _find_link(cwd)
    if not link:
        return None
    root = Path(link[1]).parent.parent
    target = root / ".mcp.json"
    if not target.is_file():
        return None
    try:
        data = json.loads(target.read_text())
    except Exception as err:
        return {"changed": False, "path": str(target),
                "error": "is not valid JSON: %s" % err}
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict) or "attacca" not in servers:
        return None
    del servers["attacca"]
    if not servers:
        data.pop("mcpServers", None)
    try:
        if data:
            temporary = target.with_name(".%s.%d.tmp" %
                                         (target.name, os.getpid()))
            temporary.write_text(json.dumps(data, indent=2) + "\n")
            try:
                os.replace(str(temporary), str(target))
            except Exception:
                try:
                    temporary.unlink()
                except Exception:
                    pass
                raise
        else:
            target.unlink()
    except Exception as err:
        return {"changed": False, "path": str(target),
                "error": "could not be updated: %s" % err}
    return {"changed": True, "path": str(target)}


def _state_path(value=None):
    root = value or os.environ.get("PLUGIN_DATA") \
        or os.environ.get("CLAUDE_PLUGIN_DATA")
    if root:
        return Path(root).expanduser().resolve() / STATE_NAME
    return Path.home() / ".attacca" / "plugin-data" / "codex-attacca" / STATE_NAME


def _read_state(path):
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_state(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(".%s.%d.tmp" % (path.name, os.getpid()))
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    os.replace(str(temporary), str(path))


def _mutate_state(path, mutation):
    """Serialize read/modify/write across simultaneous lifecycle sessions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(".%s.lock" % path.name)
    with lock_path.open("a+") as lock:
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            state = _read_state(path)
            mutation(state)
            _write_state(path, state)
            return state
        finally:
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _watcher_state_path():
    root = os.environ.get("ATTACCA_WATCHER_DIR")
    # Do not resolve an override here: OfflineProjectSync must see and reject
    # every symlink component instead of receiving an already-dereferenced
    # storage root. ``absolute`` normalizes cwd without erasing that evidence.
    directory = Path(root).expanduser().absolute() if root else \
        Path.home() / ".attacca" / "watcher"
    return directory / WATCHER_STATE_NAME


def _watcher_offline_directory(subscription_key):
    """Machine-global root for identity-scoped mirrors and outboxes.

    ``OfflineProjectSync`` adds its own normalized server+project+principal
    partition and per-actor/per-device paths below this root. The subscription
    key therefore must not become a second checkout-path partition: two local
    checkouts for the same authenticated workspace need one verified mirror.
    ``subscription_key`` remains accepted for compatibility with older callers.
    """
    del subscription_key
    return _watcher_state_path().parent / "offline"


def _local_device_id():
    explicit = str(os.environ.get("ATTACCA_DEVICE_ID") or "").strip()
    if explicit:
        return explicit
    try:
        # New installs share the exact persisted machine id with terminal
        # enrollment and the hosted client. Never authorize a flow against a
        # transient hook-only identifier.
        return _terminal_flow_module().load_device_id()
    except Exception as error:
        # Known-invalid private identity can never be replaced with a
        # deterministic fallback: doing so would strand a valid device-bound
        # credential and could reactivate the wrong offline authority.
        raise HostedAuthenticationRequired(
            "local device identity requires repair: %s" %
            _trim(error, 160)) from None


def _client_instance_id():
    """Stable non-secret id for this installed coding-client integration."""
    explicit = str(os.environ.get("ATTACCA_CLIENT_INSTANCE") or "").strip()
    if explicit:
        return explicit
    try:
        return _terminal_flow_module().load_client_instance_id(
            runtime=_runtime_name())
    except Exception as error:
        raise HostedAuthenticationRequired(
            "local client-instance identity requires repair: %s" %
            _trim(error, 160)) from None


def _pid_alive(pid):
    try:
        pid = int(pid)
        if pid <= 1:
            return False
        os.kill(pid, 0)
        return True
    except (OSError, TypeError, ValueError):
        return False


def _watcher_process_matches(pid, nonce):
    """Verify a Linux watcher PID before signalling it.

    PID metadata is diagnostic only; the lifetime flock is authoritative.
    The nonce prevents a stale/reused PID from being killed by a later install.
    """
    if not _pid_alive(pid) or not nonce:
        return False
    environ = Path("/proc") / str(pid) / "environ"
    try:
        marker = ("ATTACCA_WATCHER_NONCE=%s" % nonce).encode("utf-8")
        return marker in environ.read_bytes().split(b"\0")
    except Exception:
        return False


def _watcher_process_launch_matches(pid, nonce, launch_fingerprint=None,
                                    hook_path=None):
    """Prove that a PID is the recorded watcher launch before signalling it.

    A nonce alone is sufficient to distinguish normal PID reuse, but upgrade
    replacement additionally verifies the immutable launch fingerprint stored
    in the process environment and the watcher daemon command line.  Legacy
    daemons have no fingerprint marker; they remain replaceable only when both
    their nonce and exact daemon command are proven.
    """
    if not _watcher_process_matches(pid, nonce):
        return False
    proc = Path("/proc") / str(pid)
    try:
        environment = proc.joinpath("environ").read_bytes().split(b"\0")
        if launch_fingerprint:
            marker = ("%s=%s" % (
                WATCHER_LAUNCH_FINGERPRINT_ENV,
                launch_fingerprint)).encode("utf-8")
            if marker not in environment:
                return False
        arguments = [part.decode("utf-8", "surrogateescape")
                     for part in proc.joinpath("cmdline").read_bytes().split(
                         b"\0") if part]
        if "--watcher-daemon" not in arguments:
            return False
        if hook_path is not None:
            expected = str(Path(hook_path).expanduser().resolve())
            candidates = []
            for value in arguments:
                if value.endswith("session_start.py"):
                    try:
                        candidates.append(str(Path(value).expanduser().resolve()))
                    except Exception:
                        continue
            if expected not in candidates:
                return False
        return True
    except Exception:
        return False


def _signal_watcher_process(pid, nonce, signum, launch_fingerprint=None,
                            hook_path=None):
    """Signal only a proven watcher; pin the process with pidfd on Linux."""
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send = getattr(signal, "pidfd_send_signal", None)
    if callable(pidfd_open) and callable(pidfd_send):
        descriptor = None
        try:
            descriptor = pidfd_open(int(pid), 0)
            if not _watcher_process_launch_matches(
                    pid, nonce, launch_fingerprint=launch_fingerprint,
                    hook_path=hook_path):
                return False
            pidfd_send(descriptor, signum)
            return True
        except (OSError, TypeError, ValueError):
            return False
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    if not _watcher_process_launch_matches(
            pid, nonce, launch_fingerprint=launch_fingerprint,
            hook_path=hook_path):
        return False
    if not _watcher_process_launch_matches(
            pid, nonce, launch_fingerprint=launch_fingerprint,
            hook_path=hook_path):
        return False
    try:
        os.kill(int(pid), signum)
        return True
    except (OSError, TypeError, ValueError):
        return False


def _normalized_server_url(value):
    # URL parsing is part of this hook's own code identity. Load the sibling
    # module beside the executing hook rather than trusting a stale/incomplete
    # PLUGIN_ROOT marker left by a removed native cache directory.
    return _terminal_flow_module().canonical_server_url(value)


def _local_version(plugin_root):
    """Read the packaged Attacca version without importing the application."""
    try:
        text = (Path(plugin_root) / "attacca.py").read_text()
        match = re.search(
            r'^VERSION\s*=\s*[\"\']([^\"\']+)[\"\']\s*$', text,
            flags=re.MULTILINE)
        return match.group(1).strip() if match else None
    except Exception:
        return None


def _semver_key(value):
    """Return a comparable SemVer key, ignoring build metadata."""
    text = str(value or "").strip()
    if text.startswith("v"):
        text = text[1:]
    match = re.fullmatch(
        r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
        r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
        r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?", text)
    if not match:
        return None
    core = tuple(int(match.group(index)) for index in (1, 2, 3))
    prerelease = match.group(4)
    if prerelease is None:
        return core + ((1,),)
    if any(item.isdigit() and len(item) > 1 and item.startswith("0")
           for item in prerelease.split(".")):
        return None
    identifiers = tuple(
        (0, int(item)) if item.isdigit() else (1, item)
        for item in prerelease.split("."))
    return core + ((0,) + identifiers,)


def _server_release(config):
    request = Request(
        _normalized_server_url(config["url"]) + "/healthz",
        headers={"Accept": "application/json"})
    with urlopen(request, timeout=AUXILIARY_HTTP_TIMEOUT_SECONDS) as response:
        health = json.loads(response.read().decode("utf-8"))
    value = health.get("version") if isinstance(health, dict) else None
    laws = health.get("managed_instructions") \
        if isinstance(health, dict) else None
    return {
        "version": str(value).strip() if value else None,
        "managed_instructions": laws if isinstance(laws, dict) else None,
    }


def _server_version(config):
    """Compatibility helper for diagnostics and focused tests."""
    return _server_release(config)["version"]


def set_update_choice(data_dir, server_url, server_version, choice,
                      setup_cwd=None):
    """Persist a user's explicit choice for one server release."""
    if choice not in UPDATE_CHOICES:
        raise ValueError("update choice must be install, later, or skip")
    server_url = _normalized_server_url(server_url)
    server_version = str(server_version or "").strip()
    if not server_url or not server_version:
        raise ValueError("server URL and version are required")
    path = _state_path(data_dir)

    def mutate(state):
        entry = state.setdefault("updates", {}).setdefault(
            server_url, {}).setdefault(server_version, {})
        decided = datetime.now(timezone.utc)
        entry.update({
            "decision": choice,
            "decided_at": decided.isoformat(),
            "decided_at_epoch": decided.timestamp(),
        })
        if choice == "later":
            remind_after = decided + timedelta(
                seconds=UPDATE_REMIND_AFTER_SECONDS)
            entry.update({
                "remind_after": remind_after.isoformat(),
                "remind_after_epoch": remind_after.timestamp(),
            })
        else:
            entry.pop("remind_after", None)
            entry.pop("remind_after_epoch", None)

    _mutate_state(path, mutate)
    if setup_cwd and choice in ("later", "skip"):
        # An update took priority over the unlinked-folder setup question.
        # Later/Skip lets the agent ask that setup question now, so record its
        # one-time offer. Install leaves it unconsumed for the restarted client.
        set_offered(setup_cwd, data_dir)
    return {
        "server_url": server_url,
        "server_version": server_version,
        "decision": choice,
        "setup_offer_recorded": bool(
            setup_cwd and choice in ("later", "skip")),
        "state_path": str(path),
    }


def _entry_epoch(entry, epoch_key, iso_key):
    value = entry.get(epoch_key)
    if isinstance(value, (int, float)):
        return float(value)
    value = entry.get(iso_key)
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError):
        return None


def _claim_update_offer(state_path, server_url, server_version,
                        local_version, release_fingerprint=None,
                        reason="software_update"):
    """Atomically suppress duplicate offers and claim one reminder window."""
    path = Path(state_path)
    claimed = {"value": False}

    def mutate(state):
        entry = state.setdefault("updates", {}).setdefault(
            server_url, {}).setdefault(server_version, {})
        previous_fingerprint = entry.get("release_fingerprint")
        if previous_fingerprint and release_fingerprint \
                and previous_fingerprint != release_fingerprint:
            # Same software version with changed managed laws is a distinct
            # release choice. Do not carry Skip/Later across that content.
            for key in ("decision", "decided_at", "decided_at_epoch",
                        "remind_after", "remind_after_epoch",
                        "first_offered_at", "last_offered_at",
                        "last_offered_epoch", "offer_count"):
                entry.pop(key, None)
        now = datetime.now(timezone.utc)
        now_epoch = now.timestamp()
        decision = entry.get("decision")
        if decision == "skip":
            return
        if decision == "later":
            remind_after = _entry_epoch(
                entry, "remind_after_epoch", "remind_after")
            if remind_after is not None and now_epoch < remind_after:
                return
        # An unanswered offer (or an expired Later reminder that was shown
        # again) is emitted at most once per window. An explicit Install choice
        # bypasses this guard: it is audit, not proof the installer succeeded.
        last_offered = _entry_epoch(
            entry, "last_offered_epoch", "last_offered_at")
        if decision != "install" and last_offered is not None \
                and now_epoch - last_offered < UPDATE_REMIND_AFTER_SECONDS:
            return
        now_iso = now.isoformat()
        entry.setdefault("first_offered_at", now_iso)
        entry.update({
            "last_offered_at": now_iso,
            "last_offered_epoch": now_epoch,
            "installed_version": local_version,
            "release_fingerprint": release_fingerprint,
            "reason": reason,
            "offer_count": int(entry.get("offer_count") or 0) + 1,
        })
        claimed["value"] = True

    try:
        _mutate_state(path, mutate)
    except OSError:
        # An unwritable prompt cache must not break the project-state brief.
        return True
    return claimed["value"]


def _cached_server_release(status, config, minimum_interval=0):
    """Throttle Kimi prompt-boundary health checks without delaying startup."""
    server_url = _normalized_server_url(config["url"])
    path = Path(status["state_path"])
    now = time.time()
    if minimum_interval:
        entry = ((_read_state(path).get("release_checks") or {})
                 .get(server_url) or {})
        checked = entry.get("checked_at_epoch")
        if isinstance(checked, (int, float)) \
                and 0 <= now - checked < minimum_interval:
            return {
                "version": entry.get("available_version"),
                "managed_instructions": entry.get("managed_instructions"),
            }
    try:
        release = _server_release(config)
    except Exception:
        release = {"version": None, "managed_instructions": None}
    if minimum_interval:
        def mutate(state):
            state.setdefault("release_checks", {})[server_url] = {
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "checked_at_epoch": now,
                "available_version": release.get("version"),
                "managed_instructions": release.get(
                    "managed_instructions"),
            }
        try:
            _mutate_state(path, mutate)
        except OSError:
            pass
    return release


def _local_managed_instructions(plugin_root):
    try:
        runtime = _load_attacca_runtime(plugin_root)
        metadata = runtime.managed_instruction_metadata(
            runtime._MANAGED_TEMPLATE_PROJECT)
        return {"version": metadata.get("version"),
                "sha256": metadata.get("law_sha256")}
    except Exception:
        return None


def _update_choice_command(hook_path, state_path, server_url,
                           server_version, choice, setup_cwd=None):
    values = [
        sys.executable, str(hook_path),
        "--data-dir", str(Path(state_path).parent),
        "--update-choice", choice,
        "--server-url", server_url,
        "--server-version", server_version,
    ]
    if setup_cwd:
        values.extend(["--setup-cwd", str(setup_cwd)])
    return " ".join(shlex.quote(value) for value in values)


def _update_offer(status, plugin_root, config, setup_cwd=None,
                  check_interval_seconds=0):
    """Build a user-controlled update offer, or stay quiet when up to date."""
    try:
        installed = _local_version(plugin_root)
        release = _cached_server_release(
            status, config, check_interval_seconds)
        available = release.get("version")
        installed_key = _semver_key(installed)
        available_key = _semver_key(available)
        if not installed_key or not available_key:
            return None
        software_update = available_key > installed_key
        server_laws = release.get("managed_instructions") or {}
        local_laws = _local_managed_instructions(plugin_root) or {}
        law_update = (
            available_key == installed_key and
            isinstance(server_laws.get("version"), int) and
            bool(server_laws.get("sha256")) and
            (server_laws.get("version") != local_laws.get("version") or
             server_laws.get("sha256") != local_laws.get("sha256")))
        if not software_update and not law_update:
            return None
    except Exception:
        # Version discovery is advisory. Never replace a successful MCP brief
        # with an update-check outage.
        return None

    server_url = _normalized_server_url(config["url"])
    # The atomic claim handles exact-version Skip, Later snoozing, unanswered
    # offers, and simultaneous lifecycle hooks without duplicate prompts.
    fingerprint = "%s|%s|%s" % (
        available, server_laws.get("version") or "",
        server_laws.get("sha256") or "")
    reason = "software_update" if software_update else "managed_law_update"
    if not _claim_update_offer(
            status["state_path"], server_url, available, installed,
            release_fingerprint=fingerprint, reason=reason):
        return None

    hook_path = Path(plugin_root) / "hooks" / "session_start.py"
    install_url = shlex.quote(server_url + "/install.sh")
    install_command = (
        "attacca_update_script=$(mktemp) && "
        "curl -fsSL %s -o \"$attacca_update_script\" && "
        "sh \"$attacca_update_script\"; "
        "attacca_update_status=$?; "
        "rm -f \"${attacca_update_script:-}\"; "
        "exit \"$attacca_update_status\"" % install_url)
    install_record = _update_choice_command(
        hook_path, status["state_path"], server_url, available, "install")
    later_record = _update_choice_command(
        hook_path, status["state_path"], server_url, available, "later",
        setup_cwd=setup_cwd)
    skip_record = _update_choice_command(
        hook_path, status["state_path"], server_url, available, "skip",
        setup_cwd=setup_cwd)
    runtime = _runtime_name()
    selection = (
        "Codex has no choice buttons here: ask the user to type 1, 2, or 3."
        if runtime == "codex" else
        "Use the client's choice UI for these three options; also accept 1/2/3.")
    restart = ("open `/hooks`, trust the updated Attacca hook, and start a new Codex thread"
               if runtime == "codex" else
               "restart Claude Code" if runtime == "claude" else
               "restart Kimi Code")
    availability = (
        "Attacca %s is available from %s; this client has %s." %
        (available, server_url, installed)
        if software_update else
        "Attacca %s managed laws changed on %s; this client has the same "
        "software version but a different managed-law bundle." %
        (available, server_url))
    context = """ATTACCA UPDATE CHOICE — ASK BEFORE INSTALLING
%s
Ask one concise question and show exactly these choices:
1. Install now
2. Later
3. Skip this version
%s

Do not install silently. After an explicit choice:
- Install now: run `%s` to record the request (it does not mark the release as
  installed), then run `%s`. On success, tell the user to %s. On failure, report
  it; the older installed VERSION will make Attacca offer the update again.
- Later: run `%s`. Snooze this exact release for 24 hours.
- Skip this version: run `%s`. Suppress %s only; a newer release may ask again.
Sequence the work: after Later or Skip, continue with the authoritative setup
or session brief below. After a successful install, stop this turn and resume
that brief in the newly restarted client; do not run old plugin code further.""" % (
        availability, selection, install_record,
        install_command, restart, later_record, skip_record, available)
    return {
        "system_message": "Attacca %s %s · choose Install now, Later, or Skip this version"
                          % (available, "available" if software_update else
                             "managed laws changed"),
        "context": context,
    }


def _load_attacca_runtime(plugin_root):
    """Load the installed helper module behind a small, mockable adapter."""
    path = Path(plugin_root) / "attacca.py"
    spec = importlib.util.spec_from_file_location(
        "_attacca_managed_instruction_refresh", path)
    if not spec or not spec.loader:
        raise RuntimeError("cannot load %s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _managed_law_adapter(plugin_root, project_id, root_path, db_path=None):
    runtime = _load_attacca_runtime(plugin_root)
    refresh = getattr(runtime, "refresh_managed_instructions", None)
    if not callable(refresh):
        return []
    return refresh(project_id, root_path, db_path, files=None)


def _refresh_managed_laws(status, plugin_root):
    """Refresh only valid existing Attacca-owned instruction blocks."""
    try:
        checkout_root = str(Path(status["link_path"]).parent.parent) \
            if status.get("link_path") else status["root"]
        result = _managed_law_adapter(
            plugin_root, status["project_id"], checkout_root,
            os.environ.get("ATTACCA_DB")) or []
    except Exception as err:
        return {
            "system_message": "Attacca managed-law refresh could not run",
            "context": ("Attacca could not refresh its managed AGENTS.md/CLAUDE.md "
                        "block: %s. Shared-state synchronization still succeeded."
                        % _trim(err, 240)),
        }
    results = (result.get("files") or []) \
        if isinstance(result, dict) else result
    changed = [item for item in results
               if item.get("changed") is True or
               str(item.get("action") or "").lower().startswith("updated")]
    problems = [item for item in results if item.get("status") in {
        "malformed", "unsafe_symlink", "unmanaged", "future", "write_error"}]
    if not changed and not problems:
        return None
    files = ", ".join(dict.fromkeys(
        Path(item["file"]).name for item in changed))
    problem_text = "; ".join(
        "%s: %s" % (Path(item.get("file") or "instructions").name,
                     item.get("action") or item.get("status"))
        for item in problems)
    if problems and not changed:
        return {
            "system_message": "Attacca managed laws need manual review",
            "context": ("ATTACCA MANAGED LAW REFRESH NEEDS REVIEW: %s. "
                        "No unsafe or malformed file was overwritten; shared-state "
                        "synchronization still succeeded." % problem_text),
        }
    suffix = " Review needed: %s." % problem_text if problem_text else ""
    return {
        "system_message": "Attacca managed laws refreshed · %s" % files,
        "context": ("ATTACCA MANAGED LAWS REFRESHED: %s. Only the valid "
                    "MANAGED_ATTACCA block was replaced; content outside it "
                    "was preserved.%s" % (files, suffix)),
    }


def _notice_output(event_name, notice):
    if not notice:
        return None
    return _event_context_output(
        event_name, notice["system_message"], notice["context"])


def _append_notices(output, event_name, notices):
    for notice in notices:
        if not notice:
            continue
        output = _append_notice(output, notice) if output \
            else _notice_output(event_name, notice)
    return output


def _append_notice(output, notice):
    if not output or not notice:
        return output
    if "message" in output and "hookSpecificOutput" not in output:
        output["message"] = notice["context"] + "\n\n" + output["message"]
        return output
    output["systemMessage"] = " ".join(filter(None, [
        output.get("systemMessage"), notice["system_message"]]))
    specific = output.get("hookSpecificOutput") or {}
    context = specific.get("additionalContext")
    if context:
        specific["additionalContext"] = notice["context"] + "\n\n" + context
        output["hookSpecificOutput"] = specific
    elif output.get("decision") == "block":
        output["reason"] = notice["context"] + "\n\n" + output.get("reason", "")
    return output


def prompt_status(cwd, data_dir=None):
    cwd = Path(cwd).resolve()
    link = _find_link(cwd)
    key, root, remote = _project_identity(cwd)
    state_path = _state_path(data_dir)
    state = _read_state(state_path)
    dismissed = bool((state.get("dismissed") or {}).get(key))
    offered_entry = (state.get("offered") or {}).get(key) or {}
    offered = bool(offered_entry)
    stale_offer = bool(link and offered_entry.get("stale_project_id") == link[0])
    home = Path.home().resolve()
    eligible = cwd.is_dir() and cwd not in (home, Path("/"))
    if stale_offer:
        status = "offered"
    elif link:
        status = "linked"
    elif dismissed:
        status = "dismissed"
    elif offered:
        status = "offered"
    else:
        status = "ask" if eligible else "ignored"
    return {
        "status": status,
        "key": key,
        "root": str(root),
        "folder": root.name,
        "git_remote": remote,
        "project_id": link[0] if link else None,
        "link_path": link[1] if link else None,
        "state_path": str(state_path),
    }


def set_dismissed(cwd, data_dir=None, dismissed=True):
    status = prompt_status(cwd, data_dir)
    path = Path(status["state_path"])

    def mutate(state):
        entries = state.setdefault("dismissed", {})
        if dismissed:
            entries[status["key"]] = {
                "folder": status["folder"],
                "dismissed_at": datetime.now(timezone.utc).isoformat(),
            }
        else:
            entries.pop(status["key"], None)
            (state.get("offered") or {}).pop(status["key"], None)

    _mutate_state(path, mutate)
    status["status"] = "dismissed" if dismissed else "ask"
    return status


def set_offered(cwd, data_dir=None, stale_project_id=None):
    """Record that this checkout received its one-time setup offer.

    SessionStart is already trusted by the client, so this machine-local write
    avoids asking the user to approve a second shell command merely to say No.
    """
    status = prompt_status(cwd, data_dir)
    path = Path(status["state_path"])
    entry = {
        "folder": status["folder"],
        "offered_at": datetime.now(timezone.utc).isoformat(),
    }
    if stale_project_id:
        entry["stale_project_id"] = stale_project_id
    _mutate_state(
        path, lambda state: state.setdefault("offered", {}).__setitem__(
            status["key"], entry))
    status["status"] = "offered"
    return status


def _hook_input():
    try:
        value = json.load(sys.stdin)
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _event_context_output(event_name, system_message, context):
    """Inject context at the event's supported continuation point.

    Stop hooks cannot attach ``additionalContext``. When a due poll finds a
    change, blocking Stop once is the supported way to hand that change to the
    model. Claude marks its recursive event with ``stop_hook_active``; Kimi
    0.37.2 accepts the structured deny below and caps that continuation once.
    """
    if _runtime_name() == "kimi":
        if event_name == "Stop":
            return {
                "message": context,
                "hookSpecificOutput": {
                    "permissionDecision": "deny",
                    "permissionDecisionReason": context,
                },
            }
        return {"message": context}
    if event_name == "Stop":
        return {"decision": "block", "reason": context,
                "systemMessage": system_message}
    return {
        "systemMessage": system_message,
        "hookSpecificOutput": {
            "hookEventName": event_name, "additionalContext": context}}


def _with_migration_notice(output, migration):
    if not output or not migration:
        return output
    if migration.get("changed"):
        notice = ("Attacca removed the legacy project-level MCP entry from %s. "
                  "Restart Claude once so this already-open session drops the "
                  "duplicate; unrelated MCP entries were preserved."
                  % migration["path"])
    else:
        notice = ("Attacca could not remove the legacy project MCP entry at %s: "
                  "%s. Repair that JSON file manually; setup cannot overwrite "
                  "an invalid MCP configuration."
                  % (migration["path"], migration.get("error") or "unknown error"))
    output["systemMessage"] = ((output.get("systemMessage") or "") +
                               " " + notice).strip()
    specific = output.get("hookSpecificOutput") or {}
    context = specific.get("additionalContext")
    if context:
        specific["additionalContext"] = notice + "\n\n" + context
        output["hookSpecificOutput"] = specific
    return output


def _hook_output(status, recovery_reason=None, event_name="SessionStart"):
    is_codex = _runtime_name() == "codex"
    setup_entry = "$attacca:setup" if is_codex else "/attacca:setup"
    choice_instruction = (
        "Codex has no choice buttons here, so ask the user to type 1 or 2 "
        "(also accept yes/no)." if is_codex else
        "Offer Yes and No as a short choice; also accept typed 1/2 or yes/no.")
    situation = ("Attacca is installed, but this folder is not linked to an "
                 "Attacca workspace.")
    question = "Set up Attacca for this project?"
    if recovery_reason:
        situation = ("Attacca is installed, but this folder's saved workspace "
                     "link needs repair. %s" % recovery_reason)
        question = "Repair Attacca setup for this project?"
    context = """ATTACCA FIRST-RUN CHOICE (do this before the user's request):
%s
Ask exactly one short question: “%s”
Show exactly two numbered choices:
1. Yes — begin the complete native setup (recommended)
2. No — never ask again for this folder
%s Do not ask for a raw workspace ID and do not ask for a human attribution
name in this question.

If Yes: invoke `%s`. It must show named/numbered workspace choices,
put the obvious folder/Git match first as the default, and require confirmation
before writing.

If No: confirm that Attacca will not ask again for this folder. The trusted
Attacca lifecycle hook already recorded this one-time offer, so do not run a shell
command and do not ask for another approval.
If the human later asks to connect this folder, the active AI invokes the same
native setup flow itself; do not hand the human a shell command.
Do not expose discovery/attach/create as separate setup commands. The setup
entry is one guided run: choose or create the workspace, write the checkout
link, configure detected tools, verify MCP, install the lifecycle checks, and
offer AI Network roles/bridges. At the end it reviews this AI conversation for
pending/deferred work and asks once before importing any task. Do not set up,
dismiss, or import anything until the user explicitly chooses.""" % (
        situation, question, choice_instruction, setup_entry)
    prefix = ("Attacca setup needs repair for %s. " % status["folder"]
              if recovery_reason else
              "Attacca is installed but this folder is not set up. ")
    return _event_context_output(
        event_name,
        prefix + "Your next turn will offer the complete setup; type 1 or 2.",
        context)


def _connection_config(plugin_root):
    runtime = _runtime_name()
    if runtime == "codex":
        candidates = [plugin_root / ".mcp.json",
                      plugin_root / "plugin-mcp.json"]
    elif runtime == "kimi":
        candidates = [plugin_root / "kimi.plugin.json",
                      plugin_root / "plugin-mcp.json",
                      plugin_root / ".mcp.json"]
    else:
        candidates = [plugin_root / "plugin-mcp.json",
                      plugin_root / ".mcp.json"]
    configured = {}
    for path in candidates:
        try:
            data = json.loads(path.read_text())
            configured = next(iter((data.get("mcpServers") or {}).values()))
            if configured:
                break
        except Exception:
            continue
    variables = configured.get("env") or {}
    machine_url = None
    machine_path = Path.home() / ".attacca" / "config.json"
    if machine_path.exists():
        if machine_path.is_symlink() or not machine_path.is_file():
            raise RuntimeError(
                "machine Attacca config is not a safe regular file: %s" %
                machine_path)
        try:
            machine = json.loads(machine_path.read_text())
        except (OSError, ValueError) as error:
            raise RuntimeError(
                "machine Attacca config is invalid: %s" % error) from None
        if not isinstance(machine, dict):
            raise RuntimeError(
                "machine Attacca config must be a JSON object")
        if machine.get("server_url"):
            machine_url = _normalized_server_url(machine["server_url"])
    return {
        # The machine-wide switch is hot-read on every hook/watcher cycle and
        # intentionally outranks a stale URL inherited by an already-running
        # coding client. Explicit command flags are handled by the core CLI.
        "url": (machine_url or os.environ.get("ATTACCA_URL") or
                variables.get("ATTACCA_URL") or "http://127.0.0.1:8722"),
        "actor": (os.environ.get("ATTACCA_ACTOR") or
                  variables.get("ATTACCA_ACTOR") or
                  {"codex": "codex", "claude": "claude",
                   "kimi": "kimi"}[runtime]),
        "owner": os.environ.get("ATTACCA_OWNER") or "",
    }


def _trim(value, length=500):
    text = str(value or "")
    return text if len(text) <= length else text[:length - 1] + "…"


class StaleProjectLink(RuntimeError):
    """The checkout's saved project is absent from the reachable server."""


class HostedAuthenticationRequired(RuntimeError):
    """The host is reachable but rejected this credential or AI scope."""

    def __init__(self, message, http_status=None):
        super().__init__(message)
        self.http_status = http_status


def _settings_interval(config, entry=None):
    """Read the live server cadence with this exact AI credential.

    Hosted settings become protected only after explicit owner activation;
    account bootstrap alone remains compatibility-safe. A watcher subscription
    already has the project + canonical actor needed by
    ``_watcher_api_token``; use that narrowly scoped token at request time and
    never persist it in watcher state.  Unlinked/pre-bootstrap callers retain
    the anonymous compatibility path and the documented one-minute fallback.
    """
    try:
        headers = {"Accept": "application/json"}
        if isinstance(entry, dict):
            device_id = str(
                entry.get("device_id") or _local_device_id()).strip()
            actor_id = str(entry.get("canonical_actor_id") or "").strip()
            project_id = str(entry.get("project_id") or "").strip()
            if device_id:
                headers["X-Attacca-Device-ID"] = device_id
            if actor_id:
                headers["X-Attacca-Actor"] = actor_id
                headers["X-Attacca-Actor-Type"] = "agent"
            if project_id:
                headers["X-Attacca-Project"] = project_id
            headers["X-Attacca-Client-Instance"] = _client_instance_id()
        token = _watcher_api_token(entry) if entry else None
        if isinstance(token, str) and token.strip() \
                and "\n" not in token and "\r" not in token:
            headers["Authorization"] = "Bearer " + token.strip()
        request = Request(config["url"].rstrip("/") + "/v1/settings",
                          headers=headers)
        with urlopen(
                request,
                timeout=AUXILIARY_HTTP_TIMEOUT_SECONDS) as response:
            settings = json.loads(response.read().decode("utf-8"))
        interval = int(settings.get("update_interval_seconds",
                                    DEFAULT_UPDATE_INTERVAL_SECONDS))
        if interval == 0 or 60 <= interval <= 3600:
            return interval
    except Exception:
        pass
    return DEFAULT_UPDATE_INTERVAL_SECONDS


def _runtime_actor(config, project_id, runtime=None):
    runtime = runtime or _runtime_name()
    actor = config.get("actor") or {
        "codex": "codex", "claude": "claude",
        "kimi": "kimi"}[runtime]
    # Owner is separate attribution (ATTACCA_OWNER), never part of the actor
    # key. The server resolves this runtime hint to workspace.role.runtime.
    raw = json.dumps([_normalized_server_url(config.get("url")),
                      project_id, runtime, actor],
                     separators=(",", ":"))
    return {
        "key": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "runtime": runtime,
        "actor": actor,
    }


def _watcher_subscription_key(status, config, runtime=None):
    identity = _runtime_actor(config, status["project_id"], runtime=runtime)
    raw = json.dumps([
        _normalized_server_url(config.get("url")), status["project_id"],
        identity["runtime"], identity["actor"], _local_device_id(),
        str(Path(status["root"]).resolve()),
    ], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _register_watcher_subscription(status, plugin_root, config, runtime=None,
                                   now=None):
    """Register one checkout without storing credentials or project data."""
    now = time.time() if now is None else float(now)
    runtime = runtime or _runtime_name()
    key = _watcher_subscription_key(status, config, runtime=runtime)
    path = _watcher_state_path()
    identity = _runtime_actor(config, status["project_id"], runtime=runtime)

    def mutate(state):
        subscriptions = state.setdefault("subscriptions", {})
        entry = subscriptions.setdefault(key, {})
        previous_plugin_root = entry.get("plugin_root")
        installed_plugin_root = str(Path(plugin_root).resolve())
        entry.update({
            "key": key,
            "server_url": _normalized_server_url(config.get("url")),
            "project_id": status["project_id"],
            "runtime": runtime,
            "actor": identity["actor"],
            "owner": config.get("owner") or None,
            "device_id": _local_device_id(),
            "root": str(Path(status["root"]).resolve()),
            "link_path": status.get("link_path"),
            "plugin_root": installed_plugin_root,
            "offline_directory": str(_watcher_offline_directory(key)),
            "last_registered_at": datetime.now(timezone.utc).isoformat(),
        })
        if previous_plugin_root \
                and previous_plugin_root != installed_plugin_root:
            entry["next_poll_at_epoch"] = 0
            entry["wake_reason"] = "executable_root_rebound"
            entry["wake_requested_at_epoch"] = now
        else:
            entry.setdefault("next_poll_at_epoch", now)
        entry.setdefault("pending", [])
        entry.setdefault("cursor_registered_at_epoch", now)
        entry.setdefault("offline_failure_count", 0)
        if "event_cursor" not in entry:
            # Seamlessly migrate a watcher that completed a full-snapshot poll
            # before delta cursors existed. Event count equals the latest seq
            # because the project ledger is append-only.
            legacy_count = (((entry.get("snapshot") or {}).get("counts") or {})
                            .get("events"))
            if isinstance(legacy_count, int) and legacy_count >= 0:
                entry["event_cursor"] = legacy_count
                entry["event_cursor_initialized"] = True

    _mutate_state(path, mutate)
    return key


def _watcher_wake_subscription(key, reason="local_write", now=None):
    """Make one subscription due now and wake the detached daemon.

    Offline queue integration calls the injected ``wake`` callback only after
    its immutable mutation file is fsynced.  The watcher still scans every five
    seconds as a fallback, but SIGUSR1 avoids waiting for that scan on systems
    that support it.
    """
    now = time.time() if now is None else float(now)
    found = {"value": False}

    def mutate(state):
        entry = (state.get("subscriptions") or {}).get(key)
        if not entry:
            return
        found["value"] = True
        entry.update({
            "next_poll_at_epoch": 0,
            "wake_reason": str(reason or "local_write"),
            "wake_requested_at_epoch": now,
        })

    _mutate_state(_watcher_state_path(), mutate)
    signalled = False
    state = _read_state(_watcher_state_path())
    daemon = state.get("daemon") or {}
    wake_signal = getattr(signal, "SIGUSR1", None)
    if found["value"] and wake_signal is not None \
            and _watcher_process_matches(daemon.get("pid"), daemon.get("nonce")):
        try:
            os.kill(int(daemon["pid"]), wake_signal)
            signalled = True
        except (OSError, TypeError, ValueError):
            pass
    return {"ok": found["value"], "key": key, "signalled": signalled}


def _runtime_file_signatures(root, relative_files):
    signatures = []
    for relative in relative_files:
        path = root / relative
        try:
            metadata = path.stat()
        except OSError as error:
            raise RuntimeError(
                "installed Attacca plugin lacks runtime module: %s" %
                relative) from error
        if not path.is_file():
            raise RuntimeError(
                "installed Attacca runtime module is not a regular file: %s" %
                relative)
        signatures.append((
            relative, metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns))
    return tuple(signatures)


def _runtime_module_snapshot(root, relative_files):
    """Read one exact module image, cheaply reusing unchanged source bytes.

    A watcher checks many subscriptions every five seconds. Rehashing every
    packaged module per subscription is needless steady-state IO, while using
    only a path or Python's timestamp-based bytecode cache can retain old code
    after a same-version in-place repair. Two matching stat snapshots provide
    the cheap cache key; cache misses retain and compile the exact bytes whose
    SHA-256 names the runtime module image.
    """
    root = Path(root).resolve()
    relative_files = tuple(relative_files)
    for _ in range(3):
        before = _runtime_file_signatures(root, relative_files)
        source_key = (str(root), before)
        cached = _RUNTIME_SOURCE_CACHE.get(source_key)
        if cached is not None:
            if before == _runtime_file_signatures(root, relative_files):
                # Refresh insertion order so bounded eviction is LRU-like.
                _RUNTIME_SOURCE_CACHE.pop(source_key, None)
                _RUNTIME_SOURCE_CACHE[source_key] = cached
                return cached
            continue
        sources = {
            relative: (root / relative).read_bytes()
            for relative in relative_files
        }
        if before != _runtime_file_signatures(root, relative_files):
            continue
        digest = hashlib.sha256()
        for relative in relative_files:
            data = sources[relative]
            encoded = relative.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)
        result = ((str(root), digest.hexdigest()), sources)
        _RUNTIME_SOURCE_CACHE[source_key] = result
        while len(_RUNTIME_SOURCE_CACHE) > _RUNTIME_SOURCE_CACHE_LIMIT:
            _RUNTIME_SOURCE_CACHE.pop(next(iter(_RUNTIME_SOURCE_CACHE)))
        return result
    raise RuntimeError(
        "installed Attacca runtime changed while it was being loaded")


def _exec_runtime_module(qualified, path, source, package):
    """Execute exact source bytes without consulting a stale ``__pycache__``."""
    module = types.ModuleType(qualified)
    module.__file__ = str(path)
    module.__package__ = package
    module.__loader__ = None
    module.__spec__ = None
    sys.modules[qualified] = module
    try:
        exec(compile(source, str(path), "exec", dont_inherit=True),
             module.__dict__)
    except Exception:
        sys.modules.pop(qualified, None)
        raise
    return module


def _runtime_namespace(prefix, key):
    digest = hashlib.sha256(
        json.dumps(key, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return "%s%s" % (prefix, digest)


def _evict_sync_runtime(key):
    package_name = _runtime_namespace("_attacca_hook_sync_", key)
    for suffix in ("", ".sync_protocol", ".terminal_flow",
                   ".offline_sync", ".sync_client"):
        sys.modules.pop(package_name + suffix, None)


def _evict_terminal_runtime(key):
    qualified = _runtime_namespace("_attacca_hook_terminal_", key)
    sys.modules.pop(qualified, None)


def _watcher_sync_modules():
    """Load schema-v1 clients only from this stable lifecycle image."""
    root = _plugin_root().resolve()
    load_order = ("sync_protocol", "terminal_flow", "offline_sync",
                  "sync_client")
    relative_files = tuple(name + ".py" for name in load_order)
    key, sources = _runtime_module_snapshot(root, relative_files)
    if key in _SYNC_MODULE_CACHE:
        cached = _SYNC_MODULE_CACHE.pop(key)
        _SYNC_MODULE_CACHE[key] = cached
        return cached
    package_name = _runtime_namespace("_attacca_hook_sync_", key)
    package = sys.modules.get(package_name)
    if package is None:
        package = types.ModuleType(package_name)
        package.__path__ = [str(root)]
        package.__package__ = package_name
        sys.modules[package_name] = package

    loaded = {}
    try:
        for name in load_order:
            qualified = "%s.%s" % (package_name, name)
            module = sys.modules.get(qualified)
            if module is None:
                relative = name + ".py"
                module = _exec_runtime_module(
                    qualified, root / relative, sources[relative],
                    package_name)
            loaded[name] = module
    except Exception:
        _evict_sync_runtime(key)
        raise
    result = (loaded["sync_protocol"], loaded["offline_sync"],
              loaded["sync_client"])
    _SYNC_MODULE_CACHE[key] = result
    while len(_SYNC_MODULE_CACHE) > _RUNTIME_MODULE_CACHE_LIMIT:
        oldest = next(iter(_SYNC_MODULE_CACHE))
        _SYNC_MODULE_CACHE.pop(oldest, None)
        _evict_sync_runtime(oldest)
    return result


def _terminal_flow_module():
    """Load terminal auth only from this stable lifecycle image."""
    root = _plugin_root().resolve()
    key, sources = _runtime_module_snapshot(root, ("terminal_flow.py",))
    if key in _TERMINAL_MODULE_CACHE:
        cached = _TERMINAL_MODULE_CACHE.pop(key)
        _TERMINAL_MODULE_CACHE[key] = cached
        return cached
    path = root / "terminal_flow.py"
    qualified = _runtime_namespace("_attacca_hook_terminal_", key)
    module = sys.modules.get(qualified)
    if module is None:
        module = _exec_runtime_module(
            qualified, path, sources["terminal_flow.py"], "")
    _TERMINAL_MODULE_CACHE[key] = module
    while len(_TERMINAL_MODULE_CACHE) > _RUNTIME_MODULE_CACHE_LIMIT:
        oldest = next(iter(_TERMINAL_MODULE_CACHE))
        _TERMINAL_MODULE_CACHE.pop(oldest, None)
        _evict_terminal_runtime(oldest)
    return module


def _terminal_requested_bindings(status, entry=None):
    entry = entry if isinstance(entry, dict) else {}
    actor = str(entry.get("canonical_actor_id") or "").strip()
    project = str(status.get("project_id") or entry.get("project_id") or "").strip()
    if not project or not actor:
        return []
    binding = {"project_id": project, "actor_id": actor}
    runtime = str(entry.get("runtime") or _runtime_name()).strip().lower()
    if runtime:
        binding["runtime"] = runtime
    return [binding]


def _terminal_flow_progress(status, config, entry=None, *, force_poll=False,
                            open_browser=False):
    """Advance one bounded browser/device step and return public fields only."""
    module = _terminal_flow_module()
    bindings = _terminal_requested_bindings(status, entry)
    device_id = _local_device_id()
    client_instance = _client_instance_id()
    result = module.safe_recovery_result(
        config["url"],
        lambda: module.advance_device_flow(
            config["url"], device_id=device_id,
            client_label="Attacca terminal · device %s" % device_id[-12:],
            requested_bindings=bindings,
            timeout=AUXILIARY_HTTP_TIMEOUT_SECONDS,
            open_browser=open_browser, force_poll=force_poll,
            client_instance_id=client_instance))
    if result.get("status") in {"approved", "ready"} \
            and isinstance(entry, dict) and entry.get("key"):
        _watcher_wake_subscription(
            entry["key"], "terminal_credential_ready")
    return result


def _terminal_flow_notice(status, config, event_name, entry=None,
                          result=None, migration=False, open_browser=False):
    """Build a secret-free lifecycle notice; never hand the user a command."""
    try:
        module = _terminal_flow_module()
        result = result or _terminal_flow_progress(
            status, config, entry, open_browser=open_browser)
        message = module.format_recovery_message(
            result, config["url"], status.get("project_id"))
    except Exception:
        result = {"status": "deferred"}
        message = (
            "Attacca needs secure browser sign-in for workspace %s. Open %s/app. "
            "The native lifecycle flow will retry automatically; never paste a "
            "password or token into chat, and no shell command is required." %
            (status.get("project_id"), config["url"].rstrip("/")))
    label = "credential migration" if migration else "authentication"
    notice_context = "ATTACCA SECURE TERMINAL AUTHORIZATION\n" + message
    return {
        "result": result,
        "notice": {
            "system_message":
                "Attacca %s · %s · secure browser enrollment %s" % (
                    label, status.get("project_id"), result.get("status")),
            "context": notice_context,
        },
        "message": message,
    }


def _terminal_migration_notice(status, config, event_name, entry=None):
    """Never initiate authorization from a healthy lifecycle boundary.

    Required-auth recovery calls :func:`_terminal_flow_notice` directly, and
    native setup has its own explicit enrollment path. Starting or polling a
    device flow here would mutate authentication state merely because a normal
    SessionStart/UserPromptSubmit/Stop hook ran while compatibility auth was
    healthy and optional.
    """
    return None


def _watcher_sync_client_id(entry):
    material = json.dumps([
        entry.get("key"), entry.get("runtime"), entry.get("actor"),
        entry.get("device_id"),
    ], separators=(",", ":"), ensure_ascii=False)
    return "watcher_" + hashlib.sha256(
        material.encode("utf-8")).hexdigest()[:32]


def _watcher_validated_sync_scope(entry, protocol):
    scope = entry.get("sync_scope")
    visibility = entry.get("sync_visibility_fingerprint")
    if not isinstance(scope, dict) or not visibility:
        return None
    checked = protocol.validate_scope(scope)
    protocol.validate_visibility_fingerprint(visibility)
    if checked["project_id"] != entry.get("project_id"):
        raise RuntimeError("cached sync scope belongs to another workspace")
    if checked["actor_id"] != entry.get("canonical_actor_id") \
            or checked["role"] != entry.get("actor_role"):
        raise RuntimeError(
            "cached sync scope differs from the live-verified AI identity")
    return checked, visibility


def _watcher_default_offline_factory(entry, wake):
    protocol, offline, _ = _watcher_sync_modules()
    identity = _watcher_validated_sync_scope(entry, protocol)
    if identity is None:
        return None
    scope, visibility = identity
    return offline.OfflineProjectSync(
        _watcher_state_path().parent / "offline", entry["server_url"], scope,
        _watcher_sync_client_id(entry),
        entry.get("device_id") or _local_device_id(),
        visibility_fingerprint=visibility, wake_callback=wake)


def _watcher_default_remote_factory(entry):
    protocol, _, client = _watcher_sync_modules()
    identity = _watcher_validated_sync_scope(entry, protocol)
    if identity is None:
        return None
    scope, visibility = identity
    return client.AuthenticatedSyncHttpClient(
        entry["server_url"], entry["project_id"], scope, visibility,
        _watcher_sync_client_id(entry),
        entry.get("device_id") or _local_device_id(),
        lambda: _watcher_api_token(entry),
        client_instance_id=_client_instance_id(),
        compatibility_optional_auth=True)


def _watcher_build_offline_adapter(entry, factory=None):
    """Construct the identity-scoped sync client, or stay safely inactive.

    There is deliberately no converter from the old admin/full-export cache:
    redacted visibility anchors make that conversion both lossy and unsafe.
    The default client activates only after a Bearer-authenticated schema-v1
    snapshot agrees with the AI identity already verified through MCP. Tests
    can inject ``factory``; it receives subscription metadata without tokens
    and a wake callback which is invoked only after an outbox fsync.
    """
    factory = factory or _watcher_default_offline_factory
    wake = lambda: _watcher_wake_subscription(entry["key"], "local_write")
    return factory(dict(entry), wake)


def _watcher_build_remote_adapter(entry, factory=None):
    factory = factory or _watcher_default_remote_factory
    return factory(dict(entry))


def _watcher_adapter_status(adapter):
    if adapter is None:
        return None
    method = getattr(adapter, "status", None)
    if not callable(method):
        raise RuntimeError("offline sync adapter has no status() method")
    value = method()
    if not isinstance(value, dict):
        raise RuntimeError("offline sync adapter status must be an object")
    return value


def _offline_write_marker(adapter_status):
    if not isinstance(adapter_status, dict) or not adapter_status.get(
            "pending_sync"):
        return None
    raw = [adapter_status.get("last_local_write_at"),
           adapter_status.get("journal_records"),
           adapter_status.get("pending_count"),
           adapter_status.get("conflict_count")]
    return hashlib.sha256(json.dumps(
        raw, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _watcher_status_payload():
    state = _read_state(_watcher_state_path())
    daemon = dict(state.get("daemon") or {})
    daemon["alive"] = _watcher_process_matches(
        daemon.get("pid"), daemon.get("nonce"))
    current = _CAPTURED_WATCHER_LAUNCH_IDENTITY
    daemon["current_launch"] = bool(
        daemon["alive"] and _watcher_launch_fields_match(daemon, current)
        and _watcher_process_launch_matches(
            daemon.get("pid"), daemon.get("nonce"),
            daemon.get("launch_fingerprint"),
            (Path(daemon["plugin_root"]) / "hooks" / "session_start.py")
            if daemon.get("plugin_root") else None))
    launch = dict(state.get("daemon_launch") or {})
    launch["alive"] = _watcher_process_matches(
        launch.get("pid"), launch.get("nonce"))
    launch["current_launch"] = bool(
        launch["alive"] and _watcher_launch_fields_match(launch, current)
        and _watcher_process_launch_matches(
            launch.get("pid"), launch.get("nonce"),
            launch.get("launch_fingerprint"),
            (Path(launch["plugin_root"]) / "hooks" / "session_start.py")
            if launch.get("plugin_root") else None))
    subscriptions = []
    for entry in (state.get("subscriptions") or {}).values():
        subscriptions.append({
            key: entry.get(key) for key in (
                "key", "server_url", "project_id", "runtime", "actor",
                "device_id", "root", "interval_seconds", "last_poll_at",
                "next_poll_at_epoch", "last_error", "event_cursor",
                "event_cursor_initialized", "offline_mode",
                "offline_failure_count", "offline_pending_sync",
                "offline_pending_count", "offline_conflict_count",
                "offline_convergence_awaiting_count",
                "offline_mirror_stale", "offline_mirror_cursor",
                "offline_mirror_verified_at", "offline_directory",
                "sync_schema_version", "sync_activated_at",
                "sync_bootstrap_error")
        } | {"pending_count": len(entry.get("pending") or []),
             "queued_notice_count": len(entry.get("pending") or [])})
    return {"daemon": daemon, "daemon_launch": launch,
            "current_launch": dict(current or {}),
            "subscriptions": subscriptions,
            "state_path": str(_watcher_state_path())}


def _desktop_notify(project_id, summary):
    """Best-effort user notification; the durable queue remains authoritative."""
    executable = shutil.which("notify-send")
    if not executable or not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        return False
    lines = [line for line in str(summary).splitlines()
             if line.startswith("- ")][:4]
    body = "\n".join(lines) or _trim(summary, 500)
    try:
        subprocess.run(
            [executable, "Attacca · %s" % project_id, body],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=3, check=False)
        return True
    except Exception:
        return False


def _watcher_api_token(entry):
    """Load a device-bound terminal credential or legacy exact actor token.

    The terminal credential is runtime-independent, but the lookup still
    requires this subscription's exact canonical actor binding and machine
    device. A runtime alone is never authorization. Legacy actor tokens remain
    readable during migration; neither credential is copied into watcher state.
    """
    if not isinstance(entry, dict):
        return None
    server_url = entry.get("server_url")
    runtime = str(entry.get("runtime") or "").strip().lower()
    project_id = str(entry.get("project_id") or "").strip()
    actor_id = str(entry.get("canonical_actor_id") or "").strip()
    if not server_url or not runtime or not project_id or not actor_id:
        return None
    try:
        terminal = _terminal_flow_module()
        device_id = entry.get("device_id") or _local_device_id()
        status = terminal.terminal_credential_status(
            server_url, device_id=device_id, project_id=project_id,
            actor_id=actor_id, runtime=runtime)
        state = str(status.get("status") or "invalid")
        if status.get("credential_present") and state != "ready":
            raise HostedAuthenticationRequired(
                "local terminal credential requires enrollment repair "
                "(%s)" % state)
        token = terminal.load_terminal_credential(
            server_url, device_id=device_id,
            project_id=project_id, actor_id=actor_id, runtime=runtime)
        if token:
            return token
        if state == "ready":
            raise HostedAuthenticationRequired(
                "local terminal credential could not be loaded safely")
    except HostedAuthenticationRequired:
        raise
    except Exception as error:
        raise HostedAuthenticationRequired(
            "local terminal credential state is invalid: %s" %
            _trim(error, 160)) from None
    explicit = os.environ.get("ATTACCA_API_TOKEN")
    explicit_project = str(os.environ.get("ATTACCA_PROJECT") or "").strip()
    explicit_actor = str(os.environ.get("ATTACCA_ACTOR") or "").strip()
    if explicit is not None and runtime == _runtime_name() \
            and explicit_project == project_id \
            and explicit_actor in {entry.get("actor"), actor_id}:
        return explicit.strip() or None
    try:
        data = terminal.read_credentials_store()
        server = terminal.server_record_for_url(data, server_url)
        record = (((server.get("agent_tokens") or {}).get(project_id) or {})
                  .get(actor_id))
        if not isinstance(record, dict):
            return None
        recorded_runtime = str(record.get("runtime") or "").strip().lower()
        token = record.get("token")
        if recorded_runtime != runtime or not isinstance(token, str):
            return None
        return token.strip() or None
    except Exception:
        return None


def _watcher_fetch_sync_snapshot(entry, transport=None):
    """Fetch a freshly authorized identity snapshot for cache bootstrap."""
    protocol, offline, client = _watcher_sync_modules()
    token = _watcher_api_token(entry)
    if token is not None and (
            not isinstance(token, str) or not token.strip() or
            "\n" in token or "\r" in token or
            len(token.encode("utf-8")) > client.MAX_TOKEN_BYTES):
        raise RuntimeError(
            "no valid Attacca terminal credential is available for sync")
    request_transport = transport or client.UrllibJsonTransport()
    headers = {
        "Accept": "application/json",
        "X-Attacca-Device-ID": (
            entry.get("device_id") or _local_device_id()),
        "X-Attacca-Actor": entry.get("canonical_actor_id"),
        "X-Attacca-Actor-Type": "agent",
        "X-Attacca-Project": entry["project_id"],
        "X-Attacca-Client-Instance": _client_instance_id(),
    }
    if token:
        headers["Authorization"] = "Bearer " + token.strip()
    else:
        # Anonymous compatibility is never inferred from absence of a token.
        # It requires a fresh public status response immediately before the
        # exact actor/project/device request.
        status_response = request_transport.request(
            "GET", offline.normalize_server_url(entry["server_url"]) +
            "/v1/auth/status", headers=headers, body=None,
            timeout=AUXILIARY_HTTP_TIMEOUT_SECONDS,
            max_response_bytes=client.MAX_ERROR_BODY_BYTES)
        if not isinstance(status_response, client.JsonHttpResponse) \
                or status_response.status != 200 \
                or not isinstance(status_response.headers, dict) \
                or not isinstance(status_response.body, bytes) \
                or len(status_response.body) > client.MAX_ERROR_BODY_BYTES \
                or "application/json" not in str(
                    status_response.headers.get("content-type") or "").lower():
            auth_status = None
        else:
            try:
                auth_status = json.loads(status_response.body.decode("utf-8"))
            except Exception:
                auth_status = None
        if not isinstance(auth_status, dict) \
                or auth_status.get("authentication_required") is not False \
                or auth_status.get("effective_authentication") != "optional" \
                or auth_status.get("compatibility_active") is not True:
            raise HostedAuthenticationRequired(
                "Attacca requires terminal enrollment for sync", http_status=401)
    url = "%s/v1/projects/%s/sync/snapshot" % (
        offline.normalize_server_url(entry["server_url"]),
        quote(str(entry["project_id"]), safe=""))
    response = request_transport.request(
        "GET", url, headers=headers,
        body=None, timeout=AUXILIARY_HTTP_TIMEOUT_SECONDS,
        max_response_bytes=protocol.MAX_SNAPSHOT_BYTES)
    if not isinstance(response, client.JsonHttpResponse) \
            or not isinstance(response.status, int) \
            or isinstance(response.status, bool) \
            or not isinstance(response.headers, dict) \
            or not isinstance(response.body, bytes):
        raise RuntimeError("sync snapshot transport returned malformed fields")
    if response.status in {401, 403}:
        raise HostedAuthenticationRequired(
            "Attacca rejected the current terminal credential or AI scope",
            http_status=response.status)
    if not 200 <= response.status < 300:
        raise RuntimeError(
            "sync snapshot endpoint returned HTTP %d" % response.status)
    if len(response.body) > protocol.MAX_SNAPSHOT_BYTES:
        raise RuntimeError("sync snapshot exceeded its bounded size")
    if "application/json" not in str(
            response.headers.get("content-type") or "").lower():
        raise RuntimeError("sync snapshot response is not JSON")
    try:
        value = json.loads(response.body.decode("utf-8"))
        snapshot = protocol.validate_snapshot(value)
    except Exception as error:
        raise RuntimeError(
            "sync snapshot failed schema-v1 validation: %s" % error) from error
    scope = snapshot["scope"]
    if scope["project_id"] != entry.get("project_id") \
            or scope["actor_id"] != entry.get("canonical_actor_id") \
            or scope["role"] != entry.get("actor_role") \
            or scope["actor_type"] != "agent":
        raise HostedAuthenticationRequired(
            "sync snapshot differs from the authenticated MCP workspace/AI",
            http_status=403)
    previous = entry.get("sync_scope")
    if isinstance(previous, dict):
        previous = protocol.validate_scope(previous)
        stable = ("server_id", "project_id", "principal_id")
        if any(previous[name] != scope[name] for name in stable):
            raise HostedAuthenticationRequired(
                "sync snapshot changed server, project, or human principal",
                http_status=403)
    return snapshot


def _watcher_install_sync_snapshot(key, entry, snapshot):
    """Atomically seed/rebind the real mirror, then persist its exact scope."""
    protocol, offline, _ = _watcher_sync_modules()
    checked = protocol.validate_snapshot(snapshot)
    scope = checked["scope"]
    visibility = checked["visibility_fingerprint"]
    if scope["project_id"] != entry.get("project_id") \
            or scope["actor_id"] != entry.get("canonical_actor_id") \
            or scope["role"] != entry.get("actor_role") \
            or scope["actor_type"] != "agent":
        raise RuntimeError(
            "refusing to install a snapshot outside the MCP-verified AI scope")
    previous_scope = entry.get("sync_scope")
    previous_visibility = entry.get("sync_visibility_fingerprint")
    if isinstance(previous_scope, dict):
        previous_scope = protocol.validate_scope(previous_scope)
    else:
        previous_scope = scope
    if previous_visibility is None:
        previous_visibility = visibility
    engine = offline.OfflineProjectSync(
        _watcher_state_path().parent / "offline", entry["server_url"],
        previous_scope, _watcher_sync_client_id(entry),
        entry.get("device_id") or _local_device_id(),
        visibility_fingerprint=previous_visibility,
        wake_callback=lambda: _watcher_wake_subscription(
            key, "local_write"))
    reset = previous_scope != scope or previous_visibility != visibility
    engine.install_snapshot(
        checked, reset=reset,
        reset_reason="authenticated sync bootstrap" if reset else None)
    proof = engine.convergence_proof()
    engine_status = engine.status()
    offline.validate_convergence_proof(
        proof, expected_server_url=entry["server_url"],
        expected_project=entry["project_id"], expected_scope=scope)

    def persist(state):
        current = (state.get("subscriptions") or {}).get(key)
        if not current:
            return
        if current.get("canonical_actor_id") != scope["actor_id"] \
                or current.get("actor_role") != scope["role"]:
            raise RuntimeError(
                "live-verified identity changed during sync bootstrap")
        current.update({
            "sync_schema_version": protocol.SCHEMA_VERSION,
            "sync_scope": scope,
            "sync_visibility_fingerprint": visibility,
            "sync_activated_at": datetime.now(timezone.utc).isoformat(),
            "offline_mirror_cursor": proof["cursor"],
            "offline_mirror_verified_at": proof["mirror_verified_at"],
            "offline_mirror_stale": proof["mirror_stale"],
            "offline_mode": engine_status.get("mode"),
            "offline_pending_sync": bool(engine_status.get("pending_sync")),
            "offline_pending_count": int(
                engine_status.get("pending_count") or 0),
            "offline_conflict_count": int(
                engine_status.get("conflict_count") or 0),
            "offline_convergence_awaiting_count": len(
                proof["convergence_awaiting_receipts"]),
        })
        current.pop("auth_required", None)
        current.pop("auth_required_at", None)
        current.pop("last_auth_error_fingerprint", None)
        current["pending"] = [
            row for row in current.get("pending") or []
            if row.get("kind") not in {
                "authentication_required", "offline_connection_error",
                "connection_error"}]

    _mutate_state(_watcher_state_path(), persist)
    return engine


def _watcher_seed_identity_mirror(status, config, transport=None,
                                  runtime=None):
    """Create the first mirror only after MCP and HTTP agree on identity."""
    key, entry = _watcher_subscription_entry(
        status, config, runtime=runtime)
    if not entry.get("canonical_actor_id") or not entry.get("actor_role"):
        raise RuntimeError("authenticated MCP identity has not been recorded")
    snapshot = _watcher_fetch_sync_snapshot(entry, transport=transport)
    return _watcher_install_sync_snapshot(key, entry, snapshot)


def _watcher_activate_identity_sync(status, config, transport=None,
                                    runtime=None):
    """Best-effort activation after MCP has verified this exact AI identity.

    A valid existing mirror is reused without a full download. The first
    activation (or a role rebind) fetches the authenticated schema-v1 snapshot.
    Failure is diagnostic only while live MCP is healthy: it never replaces or
    suppresses the authoritative live startup brief, and it never enables an
    unverified cache.
    """
    key, entry = _watcher_subscription_entry(
        status, config, runtime=runtime)
    error = None
    adapter = None
    try:
        if not entry.get("canonical_actor_id") or not entry.get("actor_role"):
            raise RuntimeError("authenticated MCP identity is not role-complete")
        try:
            adapter = _watcher_build_offline_adapter(entry)
            if adapter is not None:
                _watcher_validated_convergence(
                    entry, adapter, require_online=False)
        except Exception:
            # A missing/stale mirror is repaired only by another authenticated
            # full snapshot. No data is synthesized from legacy exports.
            adapter = None
        # A durable revocation/authority latch can be cleared only by a fresh
        # authenticated identity snapshot, never by merely reopening old bytes.
        if entry.get("auth_required"):
            adapter = None
        if adapter is None:
            adapter = _watcher_seed_identity_mirror(
                status, config, transport=transport, runtime=runtime)
        proof, _, _ = _watcher_validated_convergence(
            (_watcher_subscription_entry(
                status, config, runtime=runtime)[1]),
            adapter, require_online=False)
        _watcher_wake_subscription(key, "sync_activated")
    except Exception as caught:
        error = _trim(caught, 240)
        if _authentication_required_error(caught):
            _watcher_queue_auth_required(key, entry, caught, time.time())

    def persist(state):
        current = (state.get("subscriptions") or {}).get(key)
        if not current:
            return
        if error is None:
            current.pop("sync_bootstrap_error", None)
            current.pop("sync_bootstrap_failed_at", None)
            current["sync_bootstrap_verified_at"] = datetime.now(
                timezone.utc).isoformat()
        else:
            current["sync_bootstrap_error"] = error
            current["sync_bootstrap_failed_at"] = datetime.now(
                timezone.utc).isoformat()

    _mutate_state(_watcher_state_path(), persist)
    if error is not None:
        return {"ok": False, "active": False, "error": error, "key": key}
    return {"ok": True, "active": True, "key": key,
            "cursor": proof["cursor"]}


def _watcher_event_delta(entry, after, opener=None):
    """Fetch bounded raw-ledger pages after one durable event cursor.

    This is intentionally a direct, read-only HTTP feed rather than an MCP
    snapshot. An unchanged workspace costs one small request and zero project
    materialization calls.
    """
    cursor = max(0, int(after or 0))
    initial_cursor = cursor
    events = []
    may_have_more = False
    open_request = opener or urlopen
    token = _watcher_api_token(entry)
    headers = {
        "Accept": "application/json",
        "X-Attacca-Actor": entry.get("canonical_actor_id") or
                            entry.get("actor") or entry.get("runtime") or
                            "watcher",
        "X-Attacca-Actor-Type": "agent",
        "X-Attacca-Project": entry["project_id"],
        "X-Attacca-Device": entry.get("device_id") or _local_device_id(),
        "X-Attacca-Device-ID": (
            entry.get("device_id") or _local_device_id()),
        "X-Attacca-Client-Instance": _client_instance_id(),
    }
    if entry.get("owner"):
        headers["X-Attacca-Owner"] = entry["owner"]
    if token:
        headers["Authorization"] = "Bearer %s" % token
    for _ in range(WATCHER_EVENT_MAX_PAGES):
        url = "%s/v1/projects/%s/events?after=%d&limit=%d" % (
            entry["server_url"].rstrip("/"),
            quote(str(entry["project_id"]), safe=""), cursor,
            WATCHER_EVENT_PAGE_SIZE)
        request = Request(url, headers=headers)
        with open_request(
                request,
                timeout=AUXILIARY_HTTP_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("event feed returned a non-object response")
        page = payload.get("events")
        if not isinstance(page, list) or any(
                not isinstance(event, dict) for event in page):
            raise RuntimeError("event feed returned an invalid events array")
        try:
            next_cursor = int(payload.get("next_after", cursor))
        except (TypeError, ValueError):
            raise RuntimeError("event feed returned an invalid cursor")
        if page and next_cursor == cursor:
            try:
                next_cursor = max(int(event.get("seq")) for event in page)
            except (TypeError, ValueError):
                raise RuntimeError("event feed rows are missing numeric seq")
        if next_cursor < cursor or (page and next_cursor <= cursor):
            raise RuntimeError("event feed cursor did not advance")
        events.extend(page)
        cursor = next_cursor
        may_have_more = bool(payload.get("may_have_more"))
        if not may_have_more:
            break
    return {
        "events": events,
        "after": initial_cursor,
        "next_after": cursor,
        "may_have_more": may_have_more,
    }


def _watcher_relevant_event(event):
    event_type = str(event.get("event_type") or "")
    return (event_type == "room.message" or
            event_type.startswith("task.") or
            event_type.startswith("rule.") or
            event_type.startswith("decision.") or
            event_type.startswith("handoff.") or
            event_type.startswith("bridge."))


def _watcher_event_epoch(event):
    value = event.get("created_at") or event.get("at")
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError):
        return None


def _watcher_event_actor(event):
    return (event.get("operational_actor_id") or event.get("actor_id") or
            "unknown")


def _watcher_event_line(event):
    """Render one coordination-relevant ledger event without a full read."""
    event_type = str(event.get("event_type") or "event")
    payload = event.get("payload") \
        if isinstance(event.get("payload"), dict) else {}
    actor = _watcher_event_actor(event)
    task_id = event.get("task_id") or payload.get("task_id") or "task"
    verb = event_type.rsplit(".", 1)[-1].replace("_", " ")

    if event_type == "room.message":
        source = " from %s" % payload["origin_project"] \
            if payload.get("origin_project") else ""
        authority = " [%s]" % payload["authority"] \
            if payload.get("authority") else ""
        msg_type = payload.get("msg_type") or "chat"
        return "Room%s%s · %s · %s: %s" % (
            source, authority, msg_type, actor,
            _trim(payload.get("body"), 180))
    if event_type.startswith("task.plan."):
        version = " v%s" % payload["plan_version"] \
            if payload.get("plan_version") is not None else ""
        section = " · section %s" % payload["section_id"] \
            if payload.get("section_id") else ""
        state = " · %s" % payload["status"] \
            if payload.get("status") else ""
        detail = (payload.get("note") or payload.get("title") or "")
        suffix = ": %s" % _trim(detail, 150) if detail else ""
        return "Task plan %s%s %s%s%s · %s%s" % (
            task_id, version, verb, section, state, actor, suffix)
    if event_type.startswith("task."):
        state = (payload.get("to") or payload.get("status") or
                 payload.get("requested_state"))
        state_text = " → %s" % state if state else ""
        detail = (payload.get("title") or payload.get("summary") or
                  payload.get("reason") or "")
        suffix = " — %s" % _trim(detail, 150) if detail else ""
        return "Task %s %s%s · %s%s" % (
            task_id, verb, state_text, actor, suffix)
    if event_type.startswith("rule."):
        rule_id = payload.get("rule_id") or "rule"
        version = " v%s" % payload["version"] \
            if payload.get("version") is not None else ""
        title = " — %s" % _trim(payload.get("title"), 140) \
            if payload.get("title") else ""
        return "Project Rule %s%s %s · %s%s" % (
            rule_id, version, verb, actor, title)
    if event_type.startswith("decision."):
        decision_id = payload.get("decision_id") or "decision"
        outcome = payload.get("resolution") or payload.get("status")
        state = " → %s" % outcome if outcome else ""
        title = " — %s" % _trim(payload.get("title"), 140) \
            if payload.get("title") else ""
        return "Decision %s %s%s · %s%s" % (
            decision_id, verb, state, actor, title)
    if event_type.startswith("handoff."):
        fields = payload.get("fields") or []
        changed = " (%s)" % ", ".join(str(item) for item in fields) \
            if fields else ""
        version = " · context v%s" % event["context_version"] \
            if event.get("context_version") is not None else ""
        return "Handoff %s%s%s · %s" % (verb, changed, version, actor)
    if event_type.startswith("bridge."):
        peer = payload.get("with") or payload.get("other_project") or "peer"
        relation = " · %s" % payload["relation"] \
            if payload.get("relation") else ""
        return "Bridge %s %s%s · %s" % (peer, verb, relation, actor)
    return "%s · %s" % (event_type, actor)


def _watcher_delta_summary(status, events, interval):
    if not events:
        return None
    shown = events[-10:]
    lines = ["ATTACCA BACKGROUND DELTA · %s" % status["project_id"]]
    lines.extend("- " + _watcher_event_line(event) for event in shown)
    if len(events) > len(shown):
        lines.append("- %d earlier relevant event(s) were coalesced." %
                     (len(events) - len(shown)))
    lines.extend([
        "Manual full update: `$attacca:update` (Codex) or `/attacca:update` "
        "(Claude/Kimi).",
        "Autonomous watcher interval: %ss; change it in Attacca Settings "
        "(`/app`), where 0 pauses background polling." % interval,
        "These ledger deltas were queued while the client was idle and are "
        "now being injected into the AI turn.",
    ])
    return "\n".join(lines)


def _watcher_subscription_status(entry):
    return {
        "status": "linked",
        "root": entry["root"],
        "project_id": entry["project_id"],
        "link_path": entry.get("link_path"),
    }


def _watcher_subscription_config(entry):
    return {"url": entry["server_url"], "actor": entry.get("actor"),
            "owner": entry.get("owner") or ""}


def _watcher_queue_auth_required(key, entry, error, now):
    """Queue a fail-closed credential notice without claiming offline mode."""
    message = _trim(error, 300)
    recovery_message = None
    recovery_status = None
    try:
        status = _watcher_subscription_status(entry)
        config = _watcher_subscription_config(entry)
        recovery = _terminal_flow_notice(
            status, config, "SessionStart", entry)
        recovery_message = recovery["message"]
        recovery_status = recovery["result"].get("status")
    except Exception:
        recovery_message = (
            "Open %s/app to complete secure browser sign-in. The native "
            "lifecycle flow will retry automatically; never paste a password "
            "or token into chat." % entry["server_url"].rstrip("/"))
    fingerprint = hashlib.sha256(
        ("authentication_required|" + message).encode("utf-8")).hexdigest()
    queued = False

    def mutate(state):
        nonlocal queued
        current = (state.get("subscriptions") or {}).get(key)
        if not current:
            return
        current.update({
            "last_attempt_at": datetime.now(timezone.utc).isoformat(),
            "last_error": message,
            "next_poll_at_epoch": now if recovery_status in {
                "approved", "ready"} else
                now + DEFAULT_UPDATE_INTERVAL_SECONDS,
            "auth_required": True,
            "auth_required_at": datetime.now(timezone.utc).isoformat(),
            "offline_mode": "auth_required",
            "offline_mirror_stale": True,
            "offline_retry_seconds": DEFAULT_UPDATE_INTERVAL_SECONDS,
        })
        # A prior connection-refused notice may explicitly authorize continued
        # cached work. Confirmed revocation makes that guidance unsafe, so keep
        # durable project deltas but remove all connection/continuity notices.
        pending = current.setdefault("pending", [])
        pending[:] = [
            row for row in pending
            if row.get("kind") not in {
                "offline_connection_error", "connection_error"}
            and not (row.get("kind") == "authentication_required"
                     and row.get("fingerprint") != fingerprint)]
        if current.get("last_auth_error_fingerprint") == fingerprint:
            return
        current["last_auth_error_fingerprint"] = fingerprint
        summary = (
            "ATTACCA AUTHENTICATION REQUIRED · %s\n"
            "- The hosted server is reachable but rejected this workspace/AI "
            "credential: %s\n"
            "- Cached authority and offline queueing are blocked. %s\n"
            "- The watcher will hot-reload the private terminal credential "
            "and clear this latch only after authenticated sync succeeds."
            % (entry["project_id"], message, recovery_message))
        pending.append({
            "fingerprint": fingerprint,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "kind": "authentication_required",
        })
        del pending[:-WATCHER_QUEUE_LIMIT]
        queued = True

    _mutate_state(_watcher_state_path(), mutate)
    return queued


def _watcher_queue_error(key, entry, err, now, offline_status=None,
                         offline_adapter=None):
    message = _trim(err, 300)
    fingerprint = hashlib.sha256(
        ("error|" + message).encode("utf-8")).hexdigest()
    queued = False
    proof = None
    if offline_adapter is not None:
        try:
            proof, _, validated_status = _watcher_validated_convergence(
                entry, offline_adapter, require_online=False)
            offline_status = validated_status
        except Exception:
            # A malformed/mismatched adapter must never turn a connection
            # failure into an authoritative offline-session claim.
            proof = None
            offline_status = None

    def mutate(state):
        nonlocal queued
        current = (state.get("subscriptions") or {}).get(key)
        if not current:
            return
        if current.get("auth_required"):
            # Revocation is a durable trust boundary, not a transient network
            # mode. A later outage may retry authentication but can never
            # reactivate the old mirror or emit continuity guidance.
            current.update({
                "last_attempt_at": datetime.now(timezone.utc).isoformat(),
                "last_error": message,
                "next_poll_at_epoch": now + DEFAULT_UPDATE_INTERVAL_SECONDS,
                "offline_mode": "auth_required",
                "offline_mirror_stale": True,
                "offline_retry_seconds": DEFAULT_UPDATE_INTERVAL_SECONDS,
            })
            current["pending"] = [
                row for row in current.get("pending") or []
                if row.get("kind") not in {
                    "offline_connection_error", "connection_error"}]
            return
        failure_count = max(0, int(current.get("offline_failure_count") or 0)) + 1
        backoff = min(
            DEFAULT_UPDATE_INTERVAL_SECONDS * (2 ** min(failure_count - 1, 8)),
            WATCHER_OUTAGE_BACKOFF_MAX_SECONDS)
        valid_mirror = proof is not None
        current.update({
            "last_attempt_at": datetime.now(timezone.utc).isoformat(),
            "last_error": message,
            "next_poll_at_epoch": now + backoff,
            "offline_failure_count": failure_count,
            "offline_mode": (offline_status or {}).get("mode")
                            or ("offline" if valid_mirror
                                else "offline_uninitialized"),
            "offline_pending_sync": bool(
                (offline_status or {}).get("pending_sync")),
            "offline_pending_count": int(
                (offline_status or {}).get("pending_count") or 0),
            "offline_conflict_count": int(
                (offline_status or {}).get("conflict_count") or 0),
            "offline_convergence_awaiting_count": len(
                proof.get("convergence_awaiting_receipts") or [])
                if valid_mirror else 0,
            "offline_mirror_stale": bool(
                proof.get("mirror_stale") if proof else True),
            "offline_mirror_cursor": (
                proof.get("cursor")
                if valid_mirror else None),
            "offline_mirror_verified_at": (
                proof.get("mirror_verified_at")
                if valid_mirror else None),
            "convergence_awaiting_ids": list(
                proof.get("convergence_awaiting_receipts") or [])
                if valid_mirror else [],
            "offline_retry_seconds": backoff,
            "last_offline_write_marker": (
                _offline_write_marker(offline_status)
                or current.get("last_offline_write_marker")),
        })
        if current.get("last_error_fingerprint") == fingerprint:
            return
        current["last_error_fingerprint"] = fingerprint
        pending = current.setdefault("pending", [])
        if valid_mirror:
            summary = (
                "ATTACCA OFFLINE MODE ACTIVE · %s\n"
                "- Hosted sync failed: %s\n"
                "- The verified local mirror remains readable; continue work "
                "and queue every write in the durable outbox.\n"
                "- Automatic reconnect will retry in %ss; mirror cursor %s, "
                "%s pending write(s), %s conflict(s)." % (
                    entry["project_id"], message, backoff,
                    (proof.get("cursor") or {}).get(
                        "event_seq", 0),
                    offline_status.get("pending_count", 0),
                    offline_status.get("conflict_count", 0)))
            kind = "offline_connection_error"
        else:
            summary = (
                "ATTACCA BACKGROUND WATCHER CONNECTION ISSUE · %s\n"
                "- %s\n- It will retry automatically in %ss; no cursor or "
                "project state was advanced." %
                (entry["project_id"], message, backoff))
            kind = "connection_error"
        pending.append({
            "fingerprint": fingerprint,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "kind": kind,
        })
        del pending[:-WATCHER_QUEUE_LIMIT]
        queued = True

    _mutate_state(_watcher_state_path(), mutate)
    return queued


def _watcher_queue_sync_result(key, entry, result, adapter_status, now,
                               offline_adapter=None, notifier=None):
    """Queue only proof-observed acceptance, retaining delayed notices."""
    if not isinstance(result, dict):
        raise RuntimeError("offline synchronize() result must be an object")
    sync_status = str(result.get("status") or "").lower()
    if sync_status not in ("online", "pending", "offline", "conflict"):
        raise RuntimeError("offline synchronize() returned invalid status %r" %
                           sync_status)
    applied = list(result.get("applied") or [])
    duplicates = list(result.get("duplicates") or [])
    converged = list(result.get("converged") or [])
    conflicts = list(result.get("conflicts") or [])
    blocked = list(result.get("blocked") or [])
    for rows in (applied, duplicates, converged, conflicts, blocked):
        if any(not isinstance(item, str) or not item for item in rows):
            raise RuntimeError("offline sync mutation ids must be strings")
    proof, _, validated_status = _watcher_validated_convergence(
        entry, offline_adapter, require_online=False)
    if adapter_status != validated_status:
        raise RuntimeError("sync result status changed before proof validation")
    observed = list(proof["own_canonical_events_observed"])
    if any(item not in observed for item in converged):
        raise RuntimeError(
            "sync result claims convergence absent from the canonical proof")
    may_accept = bool(sync_status == "online" and proof["online"]
                      and not proof["mirror_stale"]
                      and not proof["convergence_awaiting_receipts"])
    queued = False
    queued_summary = {"value": None}

    def mutate(state):
        nonlocal queued
        current = (state.get("subscriptions") or {}).get(key)
        if not current:
            return
        current.update({
            "convergence_awaiting_ids": list(
                proof["convergence_awaiting_receipts"]),
            "last_convergence_cursor": proof["cursor"],
            "last_convergence_checked_at": datetime.now(
                timezone.utc).isoformat(),
        })
        notified = list(current.get("notified_convergence_ids") or [])
        accepted = [item for item in observed
                    if may_accept and item not in notified]
        if not accepted and not conflicts:
            return
        fingerprint = hashlib.sha256(json.dumps([
            "conflict" if conflicts else "accepted", accepted, conflicts,
            blocked, proof["cursor"],
        ], sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        if current.get("last_sync_fingerprint") == fingerprint:
            return
        if conflicts:
            summary = (
                "ATTACCA OFFLINE SYNC CONFLICT · %s\n"
                "- %d queued write(s) conflicted: %s\n"
                "- %d later write(s) remain durably blocked in local order. "
                "Review and explicitly resolve the conflict; nothing was "
                "discarded." % (
                    entry["project_id"], len(conflicts),
                    ", ".join(conflicts[:6]), len(blocked)))
            kind = "offline_sync_conflict"
        else:
            applied_count = len(set(accepted) & set(applied))
            duplicate_count = len(set(accepted) & set(duplicates))
            delayed_count = len(accepted) - applied_count - duplicate_count
            parts = []
            if applied_count:
                parts.append("%d applied" % applied_count)
            if duplicate_count:
                parts.append("%d safely deduplicated" % duplicate_count)
            if delayed_count:
                parts.append("%d confirmed after reconnect" % delayed_count)
            summary = (
                "ATTACCA OFFLINE SYNC ACCEPTED · %s\n"
                "- Hosted reconciliation confirmed %d queued write(s): %s.\n"
                "- Each mutation's exact canonical event, AI actor, human "
                "principal, device, and mirror cursor were observed before "
                "this notice was queued." % (
                    entry["project_id"], len(accepted), ", ".join(parts)))
            kind = "offline_sync_accepted"
            current["notified_convergence_ids"] = (
                notified + accepted)[-500:]
        current["last_sync_fingerprint"] = fingerprint
        pending = current.setdefault("pending", [])
        pending.append({
            "fingerprint": fingerprint,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "kind": kind,
            "accepted": accepted,
            "applied": applied,
            "duplicates": duplicates,
            "conflicts": conflicts,
            "blocked": blocked,
            "proof_cursor": proof["cursor"],
        })
        del pending[:-WATCHER_QUEUE_LIMIT]
        queued_summary["value"] = summary
        queued = True

    _mutate_state(_watcher_state_path(), mutate)
    if queued:
        try:
            (notifier or _desktop_notify)(
                entry["project_id"], queued_summary["value"])
        except Exception:
            pass
    return queued


def _watcher_tick(key, now=None, delta_loader=None, notifier=None,
                  force=False, offline_adapter=None, offline_factory=None,
                  remote_adapter=None, remote_factory=None):
    """Advance one subscription cursor and durably queue relevant deltas."""
    now = time.time() if now is None else float(now)
    state = _read_state(_watcher_state_path())
    entry = (state.get("subscriptions") or {}).get(key)
    if not entry:
        return {"ok": False, "missing": True, "key": key}
    adapter = None
    adapter_status = None
    try:
        adapter = offline_adapter or _watcher_build_offline_adapter(
            entry, factory=offline_factory)
        adapter_status = _watcher_adapter_status(adapter)
    except Exception as err:
        if _authentication_required_error(err) or entry.get("auth_required"):
            auth_error = err if _authentication_required_error(err) else \
                HostedAuthenticationRequired(
                    entry.get("last_error") or "credential repair required")
            _watcher_queue_auth_required(key, entry, auth_error, now)
            return {"ok": False, "due": True,
                    "authentication_required": True, "offline": False,
                    "error": str(auth_error), "key": key}
        _watcher_queue_error(key, entry, err, now, offline_adapter=adapter)
        return {"ok": False, "due": True,
                "offline_uninitialized": True,
                "error": str(err), "key": key}
    local_write_marker = _offline_write_marker(adapter_status)
    write_woke = bool(
        local_write_marker
        and local_write_marker != entry.get("last_offline_write_marker"))
    if not force and not write_woke \
            and now < float(entry.get("next_poll_at_epoch") or 0):
        if entry.get("auth_required"):
            return {"ok": False, "due": False,
                    "authentication_required": True, "offline": False,
                    "error": entry.get("last_error") or
                    "credential/AI scope repair is required", "key": key}
        return {"ok": True, "due": False, "key": key}
    config = _watcher_subscription_config(entry)
    interval = _settings_interval(config, entry=entry)
    if interval == 0:
        def disable(state_value):
            current = (state_value.get("subscriptions") or {}).get(key)
            if current:
                current.update({"interval_seconds": 0,
                                "next_poll_at_epoch": now + 60,
                                "last_error": None})
        _mutate_state(_watcher_state_path(), disable)
        if entry.get("auth_required"):
            return {"ok": False, "due": True, "disabled": True,
                    "authentication_required": True, "offline": False,
                    "error": entry.get("last_error") or
                    "credential/AI scope repair is required", "key": key}
        return {"ok": True, "due": True, "disabled": True, "key": key}
    sync_result = None
    sync_notice_queued = False
    if adapter is not None:
        # A bootstrap factory may have persisted the authenticated scope while
        # constructing the local adapter. Refresh before building the remote.
        entry = (((_read_state(_watcher_state_path()).get(
            "subscriptions") or {}).get(key)) or entry)
        try:
            remote = remote_adapter or _watcher_build_remote_adapter(
                entry, factory=remote_factory)
        except Exception as err:
            if _authentication_required_error(err):
                _watcher_queue_auth_required(key, entry, err, now)
                return {"ok": False, "due": True,
                        "authentication_required": True, "offline": False,
                        "error": str(err), "key": key}
            _watcher_queue_error(
                key, entry, err, now, offline_status=adapter_status,
                offline_adapter=adapter)
            if entry.get("auth_required"):
                return {"ok": False, "due": True,
                        "authentication_required": True, "offline": False,
                        "error": str(err), "key": key}
            return {"ok": False, "due": True, "error": str(err),
                    "key": key}
        synchronize = getattr(adapter, "synchronize", None)
        if not callable(synchronize):
            err = RuntimeError(
                "offline sync adapter has no synchronize() method")
            _watcher_queue_error(
                key, entry, err, now, offline_status=adapter_status,
                offline_adapter=adapter)
            return {"ok": False, "due": True, "error": str(err),
                    "key": key}
        try:
            sync_result = synchronize(remote)
            if not isinstance(sync_result, dict):
                raise RuntimeError(
                    "offline synchronize() result must be an object")
            adapter_status = _watcher_adapter_status(adapter)
        except Exception as err:
            if _authentication_required_error(err):
                _watcher_queue_auth_required(key, entry, err, now)
                return {"ok": False, "due": True,
                        "authentication_required": True, "offline": False,
                        "error": str(err), "key": key}
            _watcher_queue_error(
                key, entry, err, now, offline_status=adapter_status,
                offline_adapter=adapter)
            if entry.get("auth_required"):
                return {"ok": False, "due": True,
                        "authentication_required": True, "offline": False,
                        "error": str(err), "key": key}
            return {"ok": False, "due": True, "error": str(err),
                    "key": key, "offline": bool(adapter_status)}
        sync_state = str(sync_result.get("status") or "").lower()
        if sync_state not in ("online", "pending", "offline", "conflict"):
            err = RuntimeError(
                "offline synchronize() returned invalid status %r" %
                sync_state)
            _watcher_queue_error(
                key, entry, err, now, offline_status=adapter_status,
                offline_adapter=adapter)
            return {"ok": False, "due": True, "error": str(err),
                    "key": key}
        sync_error = str(sync_result.get("error") or "").lower()
        if sync_state == "conflict" and any(marker in sync_error for marker in (
                "actor or role", "server/project/principal",
                "identity changed", "visibility changed")):
            auth_error = HostedAuthenticationRequired(
                sync_result.get("error") or
                "authenticated AI identity/authority changed",
                http_status=403)
            _watcher_queue_auth_required(key, entry, auth_error, now)
            return {"ok": False, "due": True,
                    "authentication_required": True, "offline": False,
                    "error": str(auth_error), "key": key}
        if sync_state == "offline":
            error = sync_result.get("error") or adapter_status.get(
                "last_error") or "hosted sync is unavailable"
            _watcher_queue_error(
                key, entry, error, now, offline_status=adapter_status,
                offline_adapter=adapter)
            current = ((_read_state(_watcher_state_path()).get(
                "subscriptions") or {}).get(key) or {})
            if current.get("auth_required"):
                return {
                    "ok": False, "due": True,
                    "authentication_required": True, "offline": False,
                    "error": str(error), "key": key,
                    "retry_in_seconds": current.get(
                        "offline_retry_seconds"),
                }
            return {
                "ok": False, "due": True, "offline": True,
                "error": str(error), "key": key,
                "retry_in_seconds": current.get("offline_retry_seconds"),
                "pending_sync": bool(adapter_status.get("pending_sync")),
            }
        try:
            sync_notice_queued = _watcher_queue_sync_result(
                key, entry, sync_result, adapter_status, now,
                offline_adapter=adapter,
                notifier=notifier)
            sync_proof, _, adapter_status = \
                _watcher_validated_convergence(
                    entry, adapter, require_online=False)
        except Exception as err:
            _watcher_queue_error(
                key, entry, err, now, offline_status=adapter_status,
                offline_adapter=adapter)
            current = ((_read_state(_watcher_state_path()).get(
                "subscriptions") or {}).get(key) or {})
            if current.get("auth_required"):
                return {"ok": False, "due": True,
                        "authentication_required": True, "offline": False,
                        "error": str(err), "key": key}
            return {"ok": False, "due": True, "error": str(err),
                    "key": key}

        def persist_sync(state_value):
            live = (state_value.get("subscriptions") or {}).get(key)
            if not live:
                return
            live.update({
                "offline_mode": adapter_status.get("mode") or sync_state,
                "offline_pending_sync": bool(
                    adapter_status.get("pending_sync")),
                "offline_pending_count": int(
                    adapter_status.get("pending_count") or 0),
                "offline_conflict_count": int(
                    adapter_status.get("conflict_count") or 0),
                "offline_convergence_awaiting_count": len(
                    sync_proof["convergence_awaiting_receipts"]),
                "offline_mirror_stale": bool(
                    sync_proof["mirror_stale"]),
                "offline_mirror_cursor": sync_proof["cursor"],
                "offline_mirror_verified_at": sync_proof[
                    "mirror_verified_at"],
                "offline_failure_count": 0,
                "offline_retry_seconds": None,
                "last_offline_write_marker": _offline_write_marker(
                    adapter_status),
                "last_sync_at": datetime.now(timezone.utc).isoformat(),
                "last_sync_result": sync_state,
            })
            if sync_state in ("online", "pending", "conflict"):
                live.pop("auth_required", None)
                live.pop("auth_required_at", None)
                live.pop("last_auth_error_fingerprint", None)
                live["pending"] = [
                    row for row in live.get("pending") or []
                    if row.get("kind") not in {
                        "authentication_required", "offline_connection_error",
                        "connection_error"}]

        _mutate_state(_watcher_state_path(), persist_sync)
    cursor = max(0, int(entry.get("event_cursor") or 0))
    initialized = bool(entry.get("event_cursor_initialized"))
    loader = delta_loader or (
        lambda after: _watcher_event_delta(entry, after))
    try:
        delta = loader(cursor)
        events = delta.get("events")
        next_cursor = int(delta.get("next_after", cursor))
        may_have_more = bool(delta.get("may_have_more"))
        if not isinstance(events, list) or any(
                not isinstance(event, dict) for event in events):
            raise RuntimeError("event delta loader returned invalid events")
        if next_cursor < cursor:
            raise RuntimeError("event delta loader moved the cursor backwards")
    except Exception as err:
        if _authentication_required_error(err):
            _watcher_queue_auth_required(key, entry, err, now)
            return {"ok": False, "due": True,
                    "authentication_required": True, "offline": False,
                    "error": str(err), "key": key}
        _watcher_queue_error(
            key, entry, err, now, offline_status=adapter_status,
            offline_adapter=adapter)
        if entry.get("auth_required"):
            return {"ok": False, "due": True,
                    "authentication_required": True, "offline": False,
                    "error": str(err), "key": key}
        return {"ok": False, "due": True, "error": str(err), "key": key}
    if initialized:
        relevant = [event for event in events
                    if _watcher_relevant_event(event)]
    else:
        # A first cursor walk establishes the historical baseline. Preserve
        # events created after this subscription was registered so a message
        # racing the startup snapshot cannot disappear into that baseline.
        registered_at = entry.get("cursor_registered_at_epoch")
        relevant = [
            event for event in events
            if _watcher_relevant_event(event)
            and isinstance(_watcher_event_epoch(event), (int, float))
            and isinstance(registered_at, (int, float))
            and _watcher_event_epoch(event) >= registered_at]
    status = _watcher_subscription_status(entry)
    summary = _watcher_delta_summary(status, relevant, interval)
    fingerprint = hashlib.sha256(json.dumps([
        [event.get("seq"), event.get("event_id"), event.get("event_type")]
        for event in relevant
    ], sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()
    queued = False

    def persist(state_value):
        nonlocal queued
        live = (state_value.get("subscriptions") or {}).get(key)
        if not live:
            return
        live.update({
            "event_cursor": next_cursor,
            "event_cursor_initialized": initialized or not may_have_more,
            "interval_seconds": interval,
            "last_poll_at": datetime.now(timezone.utc).isoformat(),
            "last_poll_at_epoch": now,
            "next_poll_at_epoch": now + interval,
            "last_error": None,
            "last_error_fingerprint": None,
            "offline_failure_count": 0,
        })
        # Discard the legacy materialized view after the first successful
        # delta request. Only cursors and concise pending summaries persist.
        live.pop("snapshot", None)
        if not summary or live.get("last_queued_fingerprint") == fingerprint:
            return
        live["last_queued_fingerprint"] = fingerprint
        pending = live.setdefault("pending", [])
        pending.append({
            "fingerprint": fingerprint,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "kind": "project_delta",
            "after": cursor,
            "through": next_cursor,
            "event_count": len(relevant),
            "event_types": sorted({event.get("event_type")
                                   for event in relevant}),
        })
        del pending[:-WATCHER_QUEUE_LIMIT]
        queued = True

    # Persistence happens before any optional desktop notification. A notifier
    # failure therefore cannot lose the update.
    _mutate_state(_watcher_state_path(), persist)
    if queued:
        try:
            (notifier or _desktop_notify)(entry["project_id"], summary)
        except Exception:
            pass
    return {"ok": True, "due": True,
            "queued": bool(queued or sync_notice_queued),
            "sync_queued": sync_notice_queued,
            "sync_status": ((sync_result or {}).get("status")
                            if sync_result is not None else None),
            "write_woke": write_woke,
            "key": key, "interval_seconds": interval,
            "event_count": len(events), "relevant_count": len(relevant),
            "event_cursor": next_cursor,
            "cursor_initialized": initialized or not may_have_more}


def _watcher_pending_notice(status, config, runtime=None, consume=True):
    key = _watcher_subscription_key(status, config, runtime=runtime)
    captured = {"rows": []}

    def mutate(state):
        entry = (state.get("subscriptions") or {}).get(key)
        if not entry:
            return
        captured["rows"] = list(entry.get("pending") or [])
        if consume and captured["rows"]:
            entry["pending"] = []
            entry["last_delivered_at"] = datetime.now(timezone.utc).isoformat()

    if consume:
        _mutate_state(_watcher_state_path(), mutate)
    else:
        mutate(_read_state(_watcher_state_path()))
    rows = captured["rows"]
    if not rows:
        return None
    shown = rows[-5:]
    context = "\n\n".join(row["summary"] for row in shown)
    if len(rows) > len(shown):
        context += "\n\n- %d earlier queued update(s) were coalesced." % (
            len(rows) - len(shown))
    context += ("\n\nThe background watcher captured these ledger deltas while "
                "the coding client was idle. Refresh the affected handoff, "
                "room, task, plan, rule, decision, or bridge through Attacca "
                "before acting when full current detail is required.")
    return {"system_message": "Attacca background watcher · %d queued update(s)"
                              % len(rows),
            "context": context}


def _watcher_launch_fields_match(record, identity):
    return bool(record and identity) and all(
        record.get(key) == identity.get(key) for key in (
            "launch_version", "launch_hook_sha256", "launch_fingerprint"))


def _watcher_mark_daemon(nonce, plugin_root, launch_identity=None, **updates):
    identity = dict(launch_identity or
                    _watcher_launch_identity_for_root(plugin_root))

    def mutate(state):
        launch = state.get("daemon_launch") or {}
        if launch.get("nonce") == nonce:
            launch_pid = launch.get("pid")
            if launch_pid not in (None, os.getpid()):
                return
            if not _watcher_launch_fields_match(launch, identity):
                return
            daemon = {}
            state["daemon"] = daemon
            state.pop("daemon_launch", None)
        else:
            daemon = state.setdefault("daemon", {})
            if daemon.get("nonce") not in (None, nonce):
                return
            if daemon.get("nonce") == nonce \
                    and not _watcher_launch_fields_match(daemon, identity):
                return
        daemon.update({
            "nonce": nonce,
            "pid": os.getpid(),
            "plugin_root": str(Path(plugin_root).resolve()),
            # plugin_version remains for older status clients.  It is pinned
            # to the process launch version, never reread from replaced disk.
            "plugin_version": identity["launch_version"],
            **identity,
        })
        daemon.update(updates)
    _mutate_state(_watcher_state_path(), mutate)


def _watcher_lock_available():
    """Probe the lifetime flock without changing daemon metadata."""
    if fcntl is None:
        return True
    path = _watcher_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name("watcher.lock")
    lock = lock_path.open("a+")
    try:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return True
    finally:
        lock.close()


def _watcher_daemon_loop(plugin_root, nonce, wait=None, clock=None,
                         max_ticks=None, offline_factory=None,
                         remote_factory=None, launch_identity=None):
    """Poll every registered checkout independently while holding one flock."""
    launch_identity = dict(
        launch_identity or _watcher_launch_identity_for_root(plugin_root))
    wake_event = None
    previous_wake_handler = None
    wake_signal = getattr(signal, "SIGUSR1", None)
    if wait is None:
        wake_event = threading.Event()
        wait = wake_event.wait
        if wake_signal is not None:
            try:
                previous_wake_handler = signal.getsignal(wake_signal)
                signal.signal(wake_signal, lambda *_: wake_event.set())
            except (ValueError, OSError):  # Not the main thread / unsupported.
                previous_wake_handler = None
    clock = clock or time.time
    path = _watcher_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name("watcher.lock")
    lock = lock_path.open("a+")
    if fcntl is not None:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            lock.close()
            def clear_failed_launch(state):
                launch = state.get("daemon_launch") or {}
                if launch.get("nonce") == nonce:
                    state.pop("daemon_launch", None)
            _mutate_state(path, clear_failed_launch)
            if previous_wake_handler is not None and wake_signal is not None:
                try:
                    signal.signal(wake_signal, previous_wake_handler)
                except (ValueError, OSError):
                    pass
            return {"ok": True, "already_running": True}
    ticks = 0
    try:
        _watcher_mark_daemon(
            nonce, plugin_root, launch_identity=launch_identity, running=True,
            started_at=datetime.now(timezone.utc).isoformat(),
            heartbeat_at_epoch=clock())
        while True:
            state = _read_state(path)
            keys = list((state.get("subscriptions") or {}).keys())
            for key in keys:
                options = {}
                if offline_factory is not None:
                    options["offline_factory"] = offline_factory
                if remote_factory is not None:
                    options["remote_factory"] = remote_factory
                _watcher_tick(key, now=clock(), **options)
            ticks += 1
            _watcher_mark_daemon(
                nonce, plugin_root, launch_identity=launch_identity,
                running=True,
                heartbeat_at=datetime.now(timezone.utc).isoformat(),
                heartbeat_at_epoch=clock(), subscription_count=len(keys))
            if max_ticks is not None and ticks >= max_ticks:
                break
            wait(WATCHER_WAKE_SECONDS)
            if wake_event is not None:
                wake_event.clear()
        return {"ok": True, "ticks": ticks}
    finally:
        def stopped(state):
            daemon = state.get("daemon") or {}
            if daemon.get("nonce") == nonce:
                daemon.update({"running": False,
                               "stopped_at": datetime.now(
                                   timezone.utc).isoformat()})
        _mutate_state(path, stopped)
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()
        if previous_wake_handler is not None and wake_signal is not None:
            try:
                signal.signal(wake_signal, previous_wake_handler)
            except (ValueError, OSError):
                pass


def _watcher_record_hook_path(record):
    root = record.get("plugin_root") if isinstance(record, dict) else None
    return Path(root) / "hooks" / "session_start.py" if root else None


def _watcher_record_proven(record):
    if not isinstance(record, dict):
        return False
    return _watcher_process_launch_matches(
        record.get("pid"), record.get("nonce"),
        launch_fingerprint=record.get("launch_fingerprint"),
        hook_path=_watcher_record_hook_path(record))


def _watcher_record_current(record, identity):
    return _watcher_launch_fields_match(record, identity) \
        and _watcher_record_proven(record)


def _stop_background_watcher():
    state = _read_state(_watcher_state_path())
    for record_name in ("daemon", "daemon_launch"):
        record = state.get(record_name) or {}
        if not _watcher_process_matches(
                record.get("pid"), record.get("nonce")):
            continue
        if not _signal_watcher_process(
                record.get("pid"), record.get("nonce"), signal.SIGTERM,
                launch_fingerprint=record.get("launch_fingerprint"),
                hook_path=_watcher_record_hook_path(record)):
            return {
                "ok": False, "stopped": False, "unverifiable": True,
                "pid": record.get("pid"),
                "error": "watcher process identity could not be verified",
            }
        return {"ok": True, "stopped": True,
                "pid": int(record["pid"])}
    return {"ok": True, "stopped": False, "already_stopped": True}


def _ensure_registered_watcher(subscription_key, launch_root, plugin_root):
    """Ensure one daemon for an already-persisted subscription identity."""
    key = subscription_key
    if os.environ.get("ATTACCA_DISABLE_WATCHER") == "1":
        return {"ok": True, "disabled_for_process": True,
                "subscription_key": key}
    plugin_root = Path(plugin_root).expanduser().resolve()
    launch_root = Path(launch_root).expanduser().resolve()
    identity = _watcher_launch_identity_for_root(plugin_root)
    hook_path = plugin_root / "hooks" / "session_start.py"
    state = _read_state(_watcher_state_path())
    daemon = state.get("daemon") or {}
    launch = state.get("daemon_launch") or {}
    if _watcher_record_current(launch, identity):
        return {"ok": True, "already_starting": True,
                "pid": launch.get("pid"), "subscription_key": key}
    if _watcher_record_current(daemon, identity):
        return {"ok": True, "already_running": True,
                "pid": daemon.get("pid"), "subscription_key": key}

    # Replace a stale launch/daemon only when its nonce, immutable environment
    # marker (when present), and watcher command line all prove its identity.
    stale = next((record for record in (daemon, launch)
                  if _watcher_process_matches(
                      record.get("pid"), record.get("nonce"))), None)
    if stale:
        if not _signal_watcher_process(
                stale.get("pid"), stale.get("nonce"), signal.SIGTERM,
                launch_fingerprint=stale.get("launch_fingerprint"),
                hook_path=_watcher_record_hook_path(stale)):
            return {
                "ok": False, "restart_pending": True,
                "pid": stale.get("pid"), "subscription_key": key,
                "error": "existing watcher identity could not be verified; "
                         "refusing to signal it",
            }
        deadline = time.time() + 3.0
        while time.time() < deadline and _watcher_process_matches(
                stale.get("pid"), stale.get("nonce")):
            time.sleep(0.05)
        if _watcher_process_matches(
                stale.get("pid"), stale.get("nonce")):
            return {
                "ok": False, "restart_pending": True,
                "pid": stale.get("pid"), "subscription_key": key,
                "error": "existing watcher did not stop; retrying later",
            }
    # PID metadata can be stale while an unrecorded older daemon still owns the
    # lifetime flock. Never spawn and overwrite metadata in that state: the
    # child would immediately exit already_running and strand future wakeups.
    if not _watcher_lock_available():
        return {
            "ok": False, "restart_pending": True,
            "pid": daemon.get("pid"), "subscription_key": key,
            "error": "watcher lock is still held; retrying later",
        }
    nonce = hashlib.sha256(os.urandom(32)).hexdigest()[:24]
    log_path = _watcher_state_path().with_name("watcher.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update({
        "ATTACCA_WATCHER_NONCE": nonce,
        "ATTACCA_WATCHER_PROCESS": "1",
        WATCHER_LAUNCH_VERSION_ENV: identity["launch_version"],
        WATCHER_LAUNCH_HOOK_SHA_ENV: identity["launch_hook_sha256"],
        WATCHER_LAUNCH_FINGERPRINT_ENV: identity["launch_fingerprint"],
    })
    reserved = {"value": False, "already_running_pid": None}

    def reserve(state_value):
        live_daemon = state_value.get("daemon") or {}
        if _watcher_record_current(live_daemon, identity):
            # Another lifecycle process may have completed the launch after
            # our initial read/lock probe. Re-check under the state mutation
            # lock so two concurrent ensure calls never spawn a redundant
            # child or replace the winner's metadata.
            reserved["already_running_pid"] = live_daemon.get("pid")
            return
        current = state_value.get("daemon_launch") or {}
        started = current.get("started_at_epoch")
        if current and isinstance(started, (int, float)) \
                and time.time() - started < 10:
            return
        state_value["daemon_launch"] = {
            "nonce": nonce, "pid": None, "running": False,
            "plugin_root": str(plugin_root),
            "plugin_version": identity["launch_version"],
            **identity,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "started_at_epoch": time.time(),
        }
        reserved["value"] = True

    _mutate_state(_watcher_state_path(), reserve)
    if reserved["already_running_pid"] is not None:
        return {"ok": True, "already_running": True,
                "pid": reserved["already_running_pid"],
                "subscription_key": key}
    if not reserved["value"]:
        return {"ok": True, "already_starting": True,
                "subscription_key": key}
    try:
        with log_path.open("a", encoding="utf-8") as log:
            process = subprocess.Popen(
                [sys.executable, str(hook_path), "--watcher-daemon",
                 "--watcher-nonce", nonce,
                 "--watcher-launch-version", identity["launch_version"],
                 "--watcher-launch-hook-sha256",
                 identity["launch_hook_sha256"],
                 "--watcher-launch-fingerprint",
                 identity["launch_fingerprint"]],
                cwd=str(launch_root), env=env,
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                start_new_session=True, close_fds=True)
    except Exception:
        def clear_reservation(state_value):
            current = state_value.get("daemon_launch") or {}
            if current.get("nonce") == nonce:
                state_value.pop("daemon_launch", None)
        _mutate_state(_watcher_state_path(), clear_reservation)
        raise

    def record_launch_pid(state_value):
        current = state_value.get("daemon_launch") or {}
        if current.get("nonce") == nonce:
            current["pid"] = process.pid
    _mutate_state(_watcher_state_path(), record_launch_pid)
    return {"ok": True, "started": True, "pid": process.pid,
            "subscription_key": key, "log": str(log_path)}


def _ensure_background_watcher(status, plugin_root, config, runtime=None):
    key = _register_watcher_subscription(
        status, plugin_root, config, runtime=runtime)
    return _ensure_registered_watcher(key, status["root"], plugin_root)


def _valid_saved_watcher_subscriptions(state):
    """Return deterministic, locally linked subscriptions without network IO."""
    valid = []
    subscriptions = state.get("subscriptions") \
        if isinstance(state, dict) else None
    if not isinstance(subscriptions, dict):
        return valid
    for stored_key, raw in subscriptions.items():
        if not isinstance(raw, dict) or raw.get("key") != stored_key:
            continue
        try:
            root = Path(raw["root"]).expanduser().resolve()
            link = Path(raw["link_path"]).expanduser().resolve()
            if not root.is_dir() or not link.is_file() \
                    or link.name != "project.json" \
                    or link.parent.name != ".attacca":
                continue
            checkout_root = link.parent.parent.resolve()
            try:
                root.relative_to(checkout_root)
            except ValueError:
                continue
            linked = json.loads(link.read_text())
            if not isinstance(linked, dict) \
                    or linked.get("project_id") != raw.get("project_id"):
                continue
            server_url = _normalized_server_url(raw.get("server_url"))
            parsed = urlparse(server_url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc \
                    or parsed.username is not None \
                    or parsed.password is not None \
                    or parsed.query or parsed.fragment:
                continue
            runtime = str(raw.get("runtime") or "").strip().lower()
            actor = str(raw.get("actor") or "").strip()
            device_id = str(raw.get("device_id") or "").strip()
            project_id = str(raw.get("project_id") or "").strip()
            if not runtime or not actor or not device_id or not project_id:
                continue
            material = json.dumps([
                server_url, project_id, runtime, actor, device_id, str(root),
            ], separators=(",", ":"), ensure_ascii=False)
            expected_key = hashlib.sha256(
                material.encode("utf-8")).hexdigest()
            if expected_key != stored_key:
                continue
            valid.append((stored_key, root, dict(raw)))
        except Exception:
            continue
    return sorted(valid, key=lambda item: item[0])


def _restart_background_watcher_after_upgrade(plugin_root):
    """Rebind and ensure the daemon without relying on install.sh's cwd.

    The installer may be piped from an unrelated directory.  Existing linked
    subscriptions are the only safe launch authority; if none remain valid we
    defer without stopping a process or inventing a workspace identity.
    """
    plugin_root = Path(plugin_root).expanduser().resolve()
    path = _watcher_state_path()
    state = _read_state(path)
    candidates = _valid_saved_watcher_subscriptions(state)
    if not candidates:
        return {
            "ok": True,
            "deferred": True,
            "reason": "no_valid_linked_subscription",
            "message": ("watcher restart deferred: no valid linked Attacca "
                        "checkout is saved on this machine"),
        }
    valid_keys = {item[0] for item in candidates}
    rebound_at = time.time()

    def rebind(current):
        subscriptions = current.get("subscriptions") or {}
        for key in valid_keys:
            entry = subscriptions.get(key)
            if isinstance(entry, dict):
                # Rebind executable metadata and make every valid subscription
                # due immediately so a repaired daemon proves convergence now,
                # rather than preserving an earlier outage backoff for up to
                # fifteen minutes. Auth latches, cursors, pending notices,
                # exact sync scope, and offline/outbox paths remain intact.
                entry["plugin_root"] = str(plugin_root)
                entry["next_poll_at_epoch"] = 0
                entry["wake_reason"] = "executable_root_rebound"
                entry["wake_requested_at_epoch"] = rebound_at

    _mutate_state(path, rebind)
    chosen_key, chosen_root, _ = candidates[0]
    result = _ensure_registered_watcher(
        chosen_key, chosen_root, plugin_root)
    result["valid_subscription_count"] = len(candidates)
    result["rebound_subscription_count"] = len(candidates)
    result["upgrade_restart"] = True
    return result


def _message_key(message):
    event_id = message.get("event_id")
    if event_id:
        return "event:%s" % event_id
    return json.dumps([
        message.get("source_project"), message.get("seq"),
        message.get("actor"), message.get("body")],
        sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _task_view(task):
    return {key: task.get(key) for key in (
        "task_id", "title", "status", "claimed_by", "lease_until",
        "lease_expired", "risk_level", "updated_at")}


def _current_actor_record(snapshot):
    """Match the effective MCP identity to its post-registration agent row."""
    status = snapshot.get("status") or {}
    actor_id = (status.get("you") or {}).get("actor_id")
    agents = (snapshot.get("agents") or {}).get("agents") or []
    return next((agent for agent in agents
                 if agent.get("agent_id") == actor_id), None)


def _needs_role_setup(snapshot):
    status = snapshot.get("status") or {}
    you = status.get("you") or {}
    if you.get("actor_type") != "agent" or not you.get("actor_id"):
        return False
    record = _current_actor_record(snapshot) or {}
    role = str(record.get("role") or "").strip().lower()
    return role not in CONFIGURED_AI_ROLES


def _mandatory_rules_banner(rules):
    """Compact banner of the mandatory Project Rules, pinned near the very
    top of every injected turn so it survives host-side truncation of the
    larger state payload. Returns None when no rules apply."""
    applicable = [r for r in (rules or []) if r.get("enabled", True)]
    if not applicable:
        return None
    applicable = sorted(
        applicable,
        key=lambda r: (r.get("priority", 100), str(r.get("rule_id") or "")))
    lines = [
        "===================== ATTACCA MANDATORY PROJECT RULES ====================",
        "BINDING on EVERY response \u2014 do not bypass. Re-pinned every turn; if this",
        "section is ever missing from your context, call rule_list before acting.",
        "",
    ]
    for r in applicable:
        body = " ".join(str(r.get("body") or "").split())
        if len(body) > 600:
            body = body[:597] + "..."
        lines.append("\u2022 [%s \u00b7 priority %s \u00b7 %s] %s" % (
            r.get("rule_id"), r.get("priority"), r.get("scope"),
            " ".join(str(r.get("title") or "").split())))
        lines.append("    %s" % body)
    lines.append(
        "==========================================================================")
    return "\n".join(lines)


def _poll_view(snapshot):
    """Stable shared-state markers used to suppress no-change hook output."""
    handoff = snapshot.get("handoff") or {}
    room = snapshot.get("room") or {}
    tasks = snapshot.get("tasks") or {}
    status = snapshot.get("status") or {}
    rules = snapshot.get("rules") or {}
    return {
        # Exclude handoff.your_inbox and recent_activity: the startup poll marks
        # inbox rows read and registers its actor, so those transient values
        # would otherwise manufacture a change on the first periodic poll.
        "context_version": handoff.get("context_version"),
        "lead_director": handoff.get("lead_director"),
        "handoff": handoff.get("handoff"),
        "decisions": handoff.get("decisions") or [],
        "project_rules": rules.get("rules") or [],
        "cloud_context": handoff.get("cloud_context"),
        "tasks": [_task_view(task) for task in (tasks.get("tasks") or [])],
        "room_keys": [_message_key(message)
                      for message in (room.get("messages") or [])],
        "counts": status.get("counts") or {},
    }


def _poll_entry(status, config):
    identity = _runtime_actor(config, status["project_id"])
    state = _read_state(Path(status["state_path"]))
    entry = (state.get("polls") or {}).get(identity["key"]) or {}
    if entry.get("project_id") != status["project_id"]:
        entry = {}
    return identity, entry


def _record_poll(status, identity, interval, checked_at, snapshot):
    """Persist one actor/project baseline without disturbing setup choices."""
    path = Path(status["state_path"])

    def mutate(state):
        state.setdefault("polls", {})[identity["key"]] = {
            "project_id": status["project_id"],
            "runtime": identity["runtime"],
            "actor": identity["actor"],
            "last_poll_at": checked_at,
            "interval_seconds": interval,
            "snapshot": snapshot,
        }

    try:
        _mutate_state(path, mutate)
    except OSError:
        # Poll persistence is an optimization. A read-only plugin-data folder
        # must not turn a successful project sync into an outage report.
        pass


def _compact_snapshot(snapshot):
    handoff = snapshot.get("handoff") or {}
    inbox = snapshot.get("inbox") or {}
    room = snapshot.get("room") or {}
    tasks = snapshot.get("tasks") or {}
    rules = snapshot.get("rules") or {}

    def messages(rows, limit):
        return [{"seq": row.get("seq"), "actor": row.get("actor"),
                 "type": row.get("msg_type"), "body": _trim(row.get("body")),
                 "task_id": row.get("task_id"),
                 "mentions": row.get("mentions"),
                 "origin_project": row.get("origin_project"),
                 "authority": row.get("authority"),
                 "mirrored_to": row.get("mirrored_to")}
                for row in (rows or [])[-limit:]]

    status = snapshot.get("status") or {}
    actor_record = _current_actor_record(snapshot) or {}
    return {
        "project": snapshot.get("project"),
        "checked_at": snapshot.get("checked_at"),
        "context_version": handoff.get("context_version"),
        "lead_director": handoff.get("lead_director"),
        "handoff": handoff.get("handoff"),
        "open_tasks": handoff.get("open_tasks"),
        "decisions": handoff.get("decisions"),
        "project_rules": rules.get("rules") or [],
        "cloud_context": handoff.get("cloud_context"),
        "recent_activity": handoff.get("recent_activity"),
        "inbox": messages(inbox.get("messages"), 20),
        "unread_broadcasts": inbox.get("unread_broadcasts"),
        "recent_room": messages(room.get("messages"), 20),
        "tasks": [_task_view(task) for task in (tasks.get("tasks") or [])
                  if task.get("status") not in ("done", "cancelled")][:50],
        "actor": (status.get("you") or {}).get("actor_id"),
        "actor_role": actor_record.get("role"),
        "counts": status.get("counts"),
    }


def _mcp_snapshot(status, plugin_root, config, mark_inbox_read=True):
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "attacca-session-hook",
                                   "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "list_projects", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "get_handoff", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "check_inbox",
                    "arguments": {"mark_read": bool(mark_inbox_read),
                                  "limit": 50}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "room_read", "arguments": {"limit": 30}}},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
         "params": {"name": "task_list", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
         "params": {"name": "attacca_status", "arguments": {}}},
        # A project tool above auto-registers this MCP actor. List agents after
        # registration, then fetch rules after the actor's real role is known.
        {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
         "params": {"name": "agent_list", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
         "params": {"name": "rule_list", "arguments": {}}},
    ]
    env = dict(os.environ)
    env.update({"ATTACCA_URL": config["url"],
                "ATTACCA_ACTOR": config["actor"],
                "ATTACCA_AUTOSTART": "0",
                "CLAUDE_PROJECT_DIR": status["root"]})
    if config["owner"]:
        env["ATTACCA_OWNER"] = config["owner"]
    env.pop("ATTACCA_PROJECT", None)
    proc = subprocess.run(
        [sys.executable, str(plugin_root / "attacca.py"), "connect",
         "--url", config["url"]], cwd=status["root"], env=env,
        input="\n".join(json.dumps(item) for item in requests) + "\n",
        capture_output=True, text=True, timeout=4)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or
                           "MCP connect exited %d" % proc.returncode)
    responses = {}
    for line in proc.stdout.splitlines():
        value = json.loads(line)
        if isinstance(value, dict) and value.get("id") is not None:
            responses[value["id"]] = value

    def tool_result(request_id):
        response = responses.get(request_id) or {}
        if response.get("error"):
            error = response["error"]
            data = error.get("data") if isinstance(error, dict) else None
            status_code = (data or {}).get("http_status") \
                if isinstance(data, dict) else None
            message = error.get("message") if isinstance(error, dict) \
                else str(error)
            if status_code in (401, 403) or (
                    isinstance(data, dict) and
                    data.get("category") == "authentication_required"):
                raise HostedAuthenticationRequired(
                    message or "Attacca rejected this credential",
                    http_status=status_code)
            raise RuntimeError(message or str(error))
        result = response.get("result") or {}
        if result.get("isError"):
            message = result.get("content", [{}])[0].get(
                "text", "Attacca MCP tool failed")
            lowered = str(message).lower()
            if any(marker in lowered for marker in (
                    "authentication", "api token", "not authorized",
                    "authorization", "forbidden", "token's ai belongs",
                    "token is bound")):
                raise HostedAuthenticationRequired(message)
            raise RuntimeError(message)
        return json.loads(result["content"][0]["text"])

    projects = tool_result(2).get("projects") or []
    if status["project_id"] not in {p.get("project_id") for p in projects}:
        known = ", ".join(p.get("name") or p.get("project_id")
                          for p in projects) or "none yet"
        raise StaleProjectLink(
            "The saved workspace '%s' does not exist on the configured "
            "server. Available workspaces: %s."
            % (status["project_id"], known))
    return {
        "project": status["project_id"],
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "handoff": tool_result(3),
        "inbox": tool_result(4),
        "room": tool_result(5),
        "tasks": tool_result(6),
        "status": tool_result(7),
        "agents": tool_result(8),
        "rules": tool_result(9),
    }


def _watcher_subscription_entry(status, config, runtime=None):
    key = _watcher_subscription_key(status, config, runtime=runtime)
    entry = ((_read_state(_watcher_state_path()).get("subscriptions") or {})
             .get(key))
    return key, dict(entry or {})


def _watcher_record_verified_identity(status, config, snapshot, runtime=None):
    """Cache only identity proven by a successful authenticated MCP snapshot."""
    key = _watcher_subscription_key(status, config, runtime=runtime)
    project_status = snapshot.get("status") or {}
    actor_id = (project_status.get("you") or {}).get("actor_id")
    actor = _current_actor_record(snapshot) or {}
    role = str(actor.get("role") or "").strip().lower()
    if not actor_id or role not in CONFIGURED_AI_ROLES:
        return False

    def mutate(state):
        entry = (state.get("subscriptions") or {}).get(key)
        if entry:
            entry.update({
                "canonical_actor_id": actor_id,
                "actor_role": role,
                "identity_verified_at": datetime.now(
                    timezone.utc).isoformat(),
            })

    _mutate_state(_watcher_state_path(), mutate)
    return True


def _watcher_activate_after_mcp(status, config, snapshot, runtime=None):
    """Keep cache activation strictly additive to a healthy MCP snapshot."""
    try:
        recorded = _watcher_record_verified_identity(
            status, config, snapshot, runtime=runtime)
        if recorded and not _needs_role_setup(snapshot):
            return _watcher_activate_identity_sync(
                status, config, runtime=runtime)
        return {"ok": True, "active": False,
                "reason": "MCP identity is not role-complete"}
    except Exception as error:
        # Watcher/cache files may be read-only, full, or temporarily locked.
        # None of those auxiliary failures may replace a successful hosted MCP
        # brief with a false connection-failure/offline state.
        return {"ok": False, "active": False,
                "error": _trim(error, 240)}


def _watcher_validated_convergence(entry, adapter, require_online=False):
    """Bind a core proof to the exact subscription and on-disk snapshot."""
    if adapter is None or not isinstance(entry, dict):
        raise RuntimeError("offline sync adapter/subscription is unavailable")
    protocol, offline, _ = _watcher_sync_modules()
    identity = _watcher_validated_sync_scope(entry, protocol)
    if identity is None:
        raise RuntimeError("subscription has no authenticated sync identity")
    scope, visibility = identity
    proof_method = getattr(adapter, "convergence_proof", None)
    snapshot_method = getattr(adapter, "local_snapshot", None)
    if not callable(proof_method) or not callable(snapshot_method):
        raise RuntimeError(
            "offline adapter lacks proof or identity snapshot validation")
    proof = offline.validate_convergence_proof(
        proof_method(), expected_server_url=entry["server_url"],
        expected_project=entry["project_id"], expected_scope=scope,
        require_online=require_online)
    if proof["visibility_fingerprint"] != visibility:
        raise RuntimeError(
            "convergence proof visibility differs from the subscription")
    try:
        snapshot = protocol.validate_snapshot(
            snapshot_method(), expected_scope=scope,
            expected_visibility=visibility)
    except Exception as error:
        raise RuntimeError(
            "offline identity snapshot failed protocol validation: %s" %
            error) from error
    digest = hashlib.sha256(
        protocol.canonical_json_bytes(snapshot)).hexdigest()
    if proof["snapshot_sha256"] != digest \
            or proof["cursor"] != snapshot["cursor"]:
        raise RuntimeError(
            "convergence proof does not describe the validated local snapshot")
    adapter_status = _watcher_adapter_status(adapter)
    status_proof = adapter_status.get("convergence_proof")
    if status_proof is not None and status_proof != proof:
        raise RuntimeError("adapter status and convergence proof disagree")
    if adapter_status.get("scope") not in (None, scope) \
            or adapter_status.get("visibility_fingerprint") not in (
                None, visibility):
        raise RuntimeError("adapter status identity differs from its proof")
    return proof, snapshot, adapter_status


def _offline_snapshot_projection(snapshot, entry):
    protocol, _, _ = _watcher_sync_modules()
    identity = _watcher_validated_sync_scope(entry, protocol)
    if identity is None:
        raise RuntimeError("subscription has no authenticated sync identity")
    scope, visibility = identity
    try:
        checked = protocol.validate_snapshot(
            snapshot, expected_scope=scope, expected_visibility=visibility)
    except Exception as error:
        raise RuntimeError(
            "offline mirror must be a schema-v1 identity snapshot: %s" %
            error) from error
    return checked["projection"]


def _offline_mirror_age_seconds(verified_at, now=None):
    if not verified_at:
        return None
    try:
        parsed = datetime.fromisoformat(str(verified_at).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        return max(0, int((current - parsed).total_seconds()))
    except (TypeError, ValueError):
        return None


def _offline_session_payload(status, adapter, entry=None, failure=None,
                             now=None):
    """Build a bounded brief only from a verified local mirror."""
    entry = entry or {}
    proof, envelope, adapter_status = _watcher_validated_convergence(
        entry, adapter, require_online=False)
    snapshot = _offline_snapshot_projection(envelope, entry)
    project = snapshot.get("project") or {}
    project_id = project.get("project_id") if isinstance(project, dict) else None
    if project_id != status["project_id"]:
        raise RuntimeError("offline mirror belongs to another workspace")

    scope = proof["scope"]
    actor_id = scope["actor_id"]
    actor_role = scope["role"]
    identity_verified = True

    rules = []
    for rule in snapshot.get("rules") or []:
        if not isinstance(rule, dict) or not bool(rule.get("enabled", 1)):
            continue
        rule_scope = str(rule.get("scope") or "everyone").lower()
        if rule_scope == "everyone" or (actor_role and rule_scope == actor_role):
            rules.append(rule)
    rules.sort(key=lambda item: (
        int(item.get("priority") or 100), str(item.get("rule_id") or "")))

    handoffs = snapshot.get("handoffs") or []
    latest_handoff = handoffs[-1] if handoffs else None
    if isinstance(latest_handoff, dict) and "content" in latest_handoff:
        latest_handoff = latest_handoff.get("content")
    pending_method = getattr(adapter, "pending_mutations", None)
    conflict_method = getattr(adapter, "conflicts", None)
    pending = pending_method() if callable(pending_method) else []
    conflicts = conflict_method() if callable(conflict_method) else []
    if not isinstance(pending, list) or not isinstance(conflicts, list):
        raise RuntimeError("offline pending/conflict state is malformed")

    def compact_mutation(item):
        return {key: item.get(key) for key in (
            "client_mutation_id", "operation", "client_sequence",
            "created_at", "sync_state")}

    def compact_decision(item):
        return {key: item.get(key) for key in (
            "decision_id", "title", "status", "rationale", "resolved_at")}

    def compact_room(item):
        return {"seq": item.get("seq"), "actor": (
                    item.get("actor") or item.get("actor_id")),
                "type": item.get("msg_type"),
                "body": _trim(item.get("body"), 500),
                "task_id": item.get("task_id"),
                "origin_project": item.get("origin_project"),
                "authority": item.get("authority")}

    def compact_agent(item):
        return {key: item.get(key) for key in (
            "agent_id", "display_name", "role", "runtime", "owner",
            "last_seen_at")}

    def compact_bridge(item):
        return {key: item.get(key) for key in (
            "project_a", "project_b", "boss_project", "advisor_project",
            "relation", "access_a", "access_b")}

    cursor = proof["cursor"]
    verified_at = proof["mirror_verified_at"]
    return {
        "state": "offline_verified",
        "project": status["project_id"],
        "connection_error": _trim(failure, 300),
        "mirror": {
            "verified_at": verified_at,
            "age_seconds": _offline_mirror_age_seconds(verified_at, now=now),
            "cursor": cursor,
            "stale_until_reconnect": bool(
                proof["mirror_stale"]),
            "read_source": "verified_local_mirror",
            "visibility_fingerprint": proof["visibility_fingerprint"],
            "convergence_online": proof["online"],
        },
        "identity": {
            "actor_id": actor_id,
            "role": actor_role,
            "principal_id": scope["principal_id"],
            "authority_verified": identity_verified,
            "warning": None,
        },
        "project_rules": rules,
        "handoff": latest_handoff,
        "tasks": [_task_view(item) for item in
                  (snapshot.get("tasks") or [])[:100]
                  if isinstance(item, dict)],
        "decisions": [compact_decision(item) for item in
                      (snapshot.get("decisions") or [])[:100]
                      if isinstance(item, dict)],
        "recent_room": [compact_room(item) for item in
                        (snapshot.get("room_messages") or [])[-30:]
                        if isinstance(item, dict)],
        "agents": [compact_agent(item) for item in
                   (snapshot.get("agents") or [])[:100]
                   if isinstance(item, dict)],
        "bridges": [compact_bridge(item) for item in
                    (snapshot.get("bridges") or [])[:100]
                    if isinstance(item, dict)],
        "history": {
            "event_count": len([
                record for record in envelope.get("records") or []
                if record.get("kind") == "event"]),
            "redacted_anchor_count": len([
                record for record in envelope.get("records") or []
                if record.get("kind") == "redacted"]),
            "full_log_records": len(snapshot.get("full_log") or []),
        },
        "outbox": {
            "pending_count": adapter_status.get("pending_count", len(pending)),
            "conflict_count": adapter_status.get(
                "conflict_count", len(conflicts)),
            "pending": [compact_mutation(item) for item in pending[:50]
                        if isinstance(item, dict)],
            "conflicts": [{
                "client_mutation_id": item.get("client_mutation_id"),
                "remote": item.get("remote"),
            } for item in conflicts[:50] if isinstance(item, dict)],
            "convergence_awaiting_receipts": proof[
                "convergence_awaiting_receipts"],
        },
    }


def _offline_failure_output(status, config, event_name, err, adapter,
                            entry=None):
    """Continue from a verified mirror, or state offline_uninitialized."""
    if isinstance(entry, dict) and entry.get("auth_required"):
        latched = HostedAuthenticationRequired(
            entry.get("last_error") or
            "the last hosted request revoked this credential/AI scope")
        return _authentication_required_output(
            status, config, event_name, latched)
    try:
        brief = _offline_session_payload(
            status, adapter, entry=entry, failure=err)
    except Exception as mirror_error:
        context = (
            "ATTACCA OFFLINE STATE · offline_uninitialized\n"
            "Hosted sync failed for workspace %r at %s: %s. No valid "
            "identity-scoped local mirror could be verified (%s). Cached "
            "handoff, rules, tasks, messages, and AI role authority are NOT "
            "being supplied or inferred. Repair connectivity or initialize a "
            "verified mirror before relying on Attacca continuity."
            % (status["project_id"], config["url"], _trim(err, 240),
               _trim(mirror_error, 240)))
        return _event_context_output(
            event_name,
            "Attacca offline_uninitialized · %s · no verified local mirror" %
            status["project_id"], context)
    context = (
        "ATTACCA ACTIVE OFFLINE SESSION BRIEF — AUTHORITATIVE VERIFIED LOCAL "
        "MIRROR\n"
        "The hosted MCP/server is unavailable, but the identity-scoped local "
        "mirror passed integrity and workspace checks. CONTINUE WORK from "
        "this cached state. It is authoritative through the recorded mirror "
        "cursor, not beyond it. Read cached history/logs/rules/tasks/decisions/"
        "handoff locally. Record every mutation through the durable offline "
        "outbox; do not describe a pending write as hosted until automatic "
        "reconciliation confirms it. The machine-global watcher retries with "
        "backoff and injects accepted/conflict results.\n\n%s" %
        json.dumps(brief, indent=2, ensure_ascii=False))
    return _event_context_output(
        event_name,
        "Attacca offline · %s · verified local mirror active; work may continue"
        % status["project_id"], context)


def _authentication_required_error(error):
    """Classify known hosted credential/scope rejection, never outages."""
    if isinstance(error, HostedAuthenticationRequired):
        return True
    if error.__class__.__name__ in {
            "SyncAuthenticationError", "SyncIdentityChangedError",
            "OfflineIdentityChangedError"}:
        return True
    return getattr(error, "code", None) in (401, 403) \
        or getattr(error, "status", None) in (401, 403)


def _authentication_required_output(status, config, event_name, error):
    status_code = getattr(error, "http_status", None) \
        or getattr(error, "code", None) or getattr(error, "status", None)
    detail = "HTTP %s · %s" % (status_code, _trim(error, 240)) \
        if status_code else _trim(error, 260)
    _, entry = _watcher_subscription_entry(status, config)
    try:
        recovery = _terminal_flow_notice(
            status, config, event_name, entry,
            open_browser=event_name in {"SessionStart", "UserPromptSubmit"})
        recovery_message = recovery["message"]
    except Exception:
        recovery_message = (
            "Open %s/app to complete secure browser sign-in. Attacca will "
            "retry automatically; never paste a password or token into chat."
            % config["url"].rstrip("/"))
    context = (
        "ATTACCA AUTHENTICATION REQUIRED — HOST REACHABLE, CACHE BLOCKED\n"
        "The configured Attacca server at %s rejected this workspace's "
        "credential or AI scope (%s). This is not a network outage. Do NOT "
        "continue from an older local mirror and do NOT queue new writes "
        "until the account/project binding is repaired. %s The lifecycle "
        "watcher hot-reloads the private terminal credential and clears its "
        "authentication latch only after verified hosted identity sync."
        % (config["url"], detail, recovery_message))
    return _event_context_output(
        event_name,
        "Attacca authentication required · %s · cached authority blocked" %
        status["project_id"], context)


def _failure_output(status, config, event_name, err):
    label = "STARTUP" if event_name == "SessionStart" else "AUTOMATIC UPDATE"
    context = ("ATTACCA MCP %s CHECK FAILED for workspace '%s' at %s: %s. "
               "Do not assume there are no messages. Tell the user the "
               "Attacca server is unreachable before coordinated work."
               % (label, status["project_id"], config["url"],
                  _trim(err, 300)))
    message = ("Attacca hook is active, but %s sync failed for %s"
               % ("startup" if event_name == "SessionStart" else "automatic",
                  status["project_id"]))
    return _event_context_output(event_name, message, context)


def _plugin_and_config():
    plugin_root = _plugin_root()
    return plugin_root, _connection_config(plugin_root)


def _standalone_update_notice(status, setup_cwd=None):
    plugin_root, config = _plugin_and_config()
    return _update_offer(
        status, plugin_root, config, setup_cwd=setup_cwd,
        check_interval_seconds=(UPDATE_CHECK_INTERVAL_SECONDS
                                if _runtime_name() == "kimi" else 0))


def _pending_unanswered_update(status, plugin_root, config):
    """Keep first-run setup queued while its preceding update awaits a choice."""
    installed_key = _semver_key(_local_version(plugin_root))
    if not installed_key:
        return False
    server_url = _normalized_server_url(config["url"])
    entries = ((_read_state(Path(status["state_path"])).get("updates") or {})
               .get(server_url) or {})
    for version, entry in entries.items():
        available_key = _semver_key(version)
        needs_choice = (available_key and available_key > installed_key) or \
            entry.get("reason") == "managed_law_update"
        if needs_choice \
                and not entry.get("decision") \
                and entry.get("last_offered_at"):
            return True
    return False


def _role_setup_output(status, snapshot):
    """Guide a newly seen AI through the one complete, explicit setup flow."""
    is_codex = _runtime_name() == "codex"
    setup_entry = "$attacca:setup" if is_codex else "/attacca:setup"
    project_status = snapshot.get("status") or {}
    current = _current_actor_record(snapshot) or {}
    workspace_name = project_status.get("name") or status["project_id"]
    lead_id = project_status.get("lead_director")
    agents = (snapshot.get("agents") or {}).get("agents") or []
    lead_record = next((agent for agent in agents
                        if agent.get("agent_id") == lead_id), None) or {}
    lead_name = lead_record.get("display_name") or lead_id
    actor_role = current.get("role")
    if not lead_id:
        default = (
            "No Lead Director exists. Recommend **Director + Lead Director** "
            "as the default choice.")
    elif lead_id == current.get("agent_id"):
        default = (
            "This AI is already the Lead Director. Recommend explicitly keeping "
            "it as Director + Lead Director.")
    else:
        default = (
            "Another Lead Director already exists (%s). Recommend **Join as "
            "another Director and keep %s as Lead Director** as the default "
            "choice." % (lead_name, lead_name))
    prior = ("Its current role is %r, which is not one of Director, Advisor, "
             "or Worker." % actor_role if actor_role else
             "It has no configured project role yet.")
    brief = _compact_snapshot(snapshot)
    context = """ATTACCA FIRST-RUN ROLE SETUP — COMPLETE BEFORE THE USER'S REQUEST
This checkout is already linked to workspace %r.
Workspace selection is already done; do not ask the user to choose a workspace
again or paste raw workspace/actor IDs. The effective MCP actor was
auto-registered only so it can be recognized. %s

Invoke `%s` now. This is the runtime's single complete setup entry. The user
must explicitly choose this AI's role: Director, Advisor, or Worker. %s Do not
call agent_register/set_lead_director directly, do not silently assign a role or
lead, and do not ask for raw workspace IDs or actor IDs.

After that explicit role/lead choice, keep the same guided setup running through
workspace relationship choices, detected tool and MCP wiring, lifecycle hook
verification, and the conversation task-import review. Task import also requires
explicit confirmation; never create or claim conversation work silently.

The authoritative startup snapshot has already been loaded:

%s""" % (workspace_name, prior, setup_entry, default,
          json.dumps(brief, indent=2, ensure_ascii=False))
    return _event_context_output(
        "SessionStart",
        "Attacca linked · %s · first-run AI role setup required"
        % status["project_id"], context)


def _active_output(status, offline_adapter=None, offline_factory=None):
    plugin_root, config = _plugin_and_config()
    interval = DEFAULT_UPDATE_INTERVAL_SECONDS
    watcher_notice = None
    try:
        watcher_result = _ensure_background_watcher(
            status, plugin_root, config)
        _, settings_entry = _watcher_subscription_entry(status, config)
        interval = _settings_interval(config, entry=settings_entry)
        if watcher_result.get("started"):
            watcher_notice = {
                "system_message": "Attacca background watcher started",
                "context": ("ATTACCA BACKGROUND WATCHER ACTIVE: autonomous "
                            "hosted-state checks now continue every %ss by "
                            "default even while the coding client is idle. "
                            "Cadence is configurable in Attacca Settings."
                            % interval),
            }
        elif not watcher_result.get("ok", False):
            watcher_notice = {
                "system_message": "Attacca background watcher restart pending",
                "context": (
                    "ATTACCA BACKGROUND WATCHER RESTART PENDING: %s. "
                    "The existing lock/daemon metadata was preserved; the "
                    "hook will retry without spawning competing daemons." %
                    _trim(watcher_result.get("error"), 240)),
            }
    except Exception as err:
        watcher_notice = {
            "system_message": "Attacca background watcher needs attention",
            "context": ("ATTACCA BACKGROUND WATCHER COULD NOT START: %s. "
                        "The immediate SessionStart sync still runs; repair "
                        "the watcher so idle checks resume." % _trim(err, 240)),
        }
    pending_notice = _watcher_pending_notice(status, config)
    offline_key, offline_entry = _watcher_subscription_entry(status, config)
    terminal_notice = _terminal_migration_notice(
        status, config, "SessionStart", offline_entry)
    if offline_adapter is None:
        try:
            offline_adapter = _watcher_build_offline_adapter(
                offline_entry, factory=offline_factory)
        except Exception:
            offline_adapter = None
    # Release discovery is independent of MCP/project compatibility: an update
    # may be exactly what repairs a stale link or older protocol client.
    update_notice = _update_offer(status, plugin_root, config)
    try:
        snapshot = _mcp_snapshot(status, plugin_root, config)
        # Sync activation is additive. A missing token/route/mirror or an
        # unwritable watcher directory can never break this healthy MCP brief.
        _watcher_activate_after_mcp(status, config, snapshot)
        identity, _ = _poll_entry(status, config)
        _record_poll(status, identity, interval, time.time(),
                     _poll_view(snapshot))
        if _needs_role_setup(snapshot):
            output = _role_setup_output(status, snapshot)
        else:
            brief = _compact_snapshot(snapshot)
            context = """ATTACCA ACTIVE SESSION BRIEF — AUTHORITATIVE PROJECT STATE
The installed SessionStart hook has already called get_handoff, check_inbox,
rule_list, room_read, task_list, agent_list, and attacca_status
through the configured MCP connection
for this workspace. Use this state before working; do not rediscover the
repository from scratch. Before writes, honor existing task claims and
claim/create the relevant Attacca task. Treat addressed room messages as pending
coordination. If any later Attacca response reports stale_context_warning,
reload the handoff before further writes.

%s""" % json.dumps(brief, indent=2, ensure_ascii=False)
            _rules_banner = _mandatory_rules_banner(
                (snapshot.get("rules") or {}).get("rules"))
            if _rules_banner:
                context = _rules_banner + "\n\n" + context
            output = _event_context_output(
                "SessionStart",
                "Attacca active · %s · MCP startup rules, handoff, inbox, room and tasks checked"
                % status["project_id"], context)
        # These are additive: neither version discovery nor managed-block
        # maintenance may prevent delivery of the authoritative shared state.
        output = _append_notice(
            output, _refresh_managed_laws(status, plugin_root))
        output = _append_notice(
            output, update_notice)
        output = _append_notice(output, watcher_notice)
        output = _append_notice(output, terminal_notice)
        output = _append_notice(output, pending_notice)
        return output
    except StaleProjectLink as err:
        set_offered(status["root"], stale_project_id=status["project_id"])
        output = _hook_output(status, recovery_reason=str(err))
        return _append_notices(
            output, "SessionStart",
            (update_notice, watcher_notice, terminal_notice, pending_notice))
    except Exception as err:
        auth_blocked = _authentication_required_error(err) or bool(
            isinstance(offline_entry, dict) and
            offline_entry.get("auth_required"))
        if auth_blocked:
            auth_error = err if _authentication_required_error(err) else \
                HostedAuthenticationRequired(
                    offline_entry.get("last_error") or
                    "credential/AI scope repair is required")
            _watcher_queue_auth_required(
                offline_key, offline_entry, auth_error, time.time())
            output = _authentication_required_output(
                status, config, "SessionStart", auth_error)
            # A previously queued outage notice may say that verified cached
            # work can continue. Once the reachable host rejects this identity,
            # that stale notice is no longer safe to inject. The live snapshot
            # after re-authentication will recover any durable project deltas.
            trailing_notices = (update_notice, watcher_notice)
        else:
            output = _offline_failure_output(
                status, config, "SessionStart", err, offline_adapter,
                entry=offline_entry)
            if output is None:
                output = _failure_output(status, config, "SessionStart", err)
            trailing_notices = (
                update_notice, watcher_notice, terminal_notice, pending_notice)
        return _append_notices(
            output, "SessionStart",
            trailing_notices)


def _task_change_lines(previous_tasks, current_tasks):
    before = {task.get("task_id"): task for task in previous_tasks or []}
    after = {task.get("task_id"): task for task in current_tasks or []}
    lines = []
    for task_id in sorted(after):
        old, task = before.get(task_id), after[task_id]
        if old == task:
            continue
        detail = "%s %s" % (task_id, task.get("status") or "unknown")
        if task.get("claimed_by"):
            detail += " by %s" % task["claimed_by"]
        title = _trim(task.get("title"), 90)
        lines.append("%s — %s" % (detail, title) if title else detail)
    for task_id in sorted(set(before) - set(after)):
        lines.append("%s removed from the task board" % task_id)
    return lines


def _change_summary(status, previous, current, snapshot, interval):
    inbox_messages = (snapshot.get("inbox") or {}).get("messages") or []
    if previous is None:
        changed = bool(inbox_messages)
    else:
        changed = previous != current or bool(inbox_messages)
    if not changed:
        return None

    details = []
    previous = previous or {}
    old_version = previous.get("context_version")
    new_version = current.get("context_version")
    if old_version != new_version or previous.get("handoff") != current.get("handoff"):
        objective = (current.get("handoff") or {}).get("objective")
        version = "context v%s→v%s" % (old_version, new_version) \
            if old_version is not None else "context v%s" % new_version
        details.append("Handoff: %s%s" % (
            version, "; objective: %s" % _trim(objective, 120)
            if objective else ""))
    if previous.get("lead_director") != current.get("lead_director"):
        details.append("Lead director: %s" % (
            current.get("lead_director") or "not set"))
    if previous.get("decisions") != current.get("decisions"):
        decisions = current.get("decisions") or []
        details.append("Decisions: %s" % (
            ", ".join("%s %s" % (item.get("decision_id"), item.get("status"))
                      for item in decisions[-3:]) or "none open"))
    if previous.get("project_rules") != current.get("project_rules"):
        rules = current.get("project_rules") or []
        details.append("Project Rules: %s" % (
            ", ".join("%s v%s · %s" % (
                item.get("rule_id"), item.get("version"),
                _trim(item.get("title"), 70)) for item in rules[:5])
            or "none active"))

    inbox_keys = {_message_key(message) for message in inbox_messages}
    for message in inbox_messages[-3:]:
        source = " from %s" % message["origin_project"] \
            if message.get("origin_project") else ""
        authority = " [%s]" % message["authority"] \
            if message.get("authority") else ""
        details.append("Inbox%s%s · %s: %s" % (
            source, authority, message.get("actor") or "unknown",
            _trim(message.get("body"), 160)))
    old_room = set(previous.get("room_keys") or [])
    new_room = [message for message in
                ((snapshot.get("room") or {}).get("messages") or [])
                if _message_key(message) not in old_room
                and _message_key(message) not in inbox_keys]
    for message in new_room[-3:]:
        source = " from %s" % message["origin_project"] \
            if message.get("origin_project") else ""
        target = " to %s" % ", ".join(message.get("mirrored_to") or []) \
            if message.get("mirrored_to") else ""
        details.append("Room%s%s · %s: %s" % (
            source, target, message.get("actor") or "unknown",
            _trim(message.get("body"), 160)))

    task_lines = _task_change_lines(previous.get("tasks"), current.get("tasks"))
    if task_lines:
        details.append("Tasks: " + "; ".join(task_lines[:4]))
    if not details:
        old_events = (previous.get("counts") or {}).get("events") or 0
        new_events = (current.get("counts") or {}).get("events") or 0
        delta = max(0, new_events - old_events)
        details.append("Shared activity changed%s." % (
            " (%d new ledger event%s)" % (delta, "" if delta == 1 else "s")
            if delta else ""))

    details = details[:7]
    lines = ["ATTACCA AUTOMATIC UPDATE · %s" % status["project_id"]]
    lines.extend("- " + detail for detail in details)
    lines.extend([
        "Manual full update: `$attacca:update` (Codex) or `/attacca:update` "
        "(Claude/Kimi).",
        "Autonomous watcher interval: %ss; change it in Attacca Settings "
        "(`/app`), where 0 pauses background polling." % interval,
        "The watcher checked while the client was idle and queued this update; "
        "this hook is now injecting it into the AI turn.",
    ])
    return "\n".join(lines)


def _periodic_output(status, event_name, offline_adapter=None,
                     offline_factory=None):
    plugin_root, config = _plugin_and_config()
    watcher_notice = None
    watcher_healthy = False
    try:
        watcher_result = _ensure_background_watcher(
            status, plugin_root, config)
        watcher_healthy = bool(
            watcher_result.get("started") or
            watcher_result.get("already_running"))
        if not watcher_result.get("ok", False):
            watcher_notice = {
                "system_message": "Attacca background watcher restart pending",
                "context": (
                    "ATTACCA BACKGROUND WATCHER RESTART PENDING: %s. "
                    "Direct-poll fallback remains active; no competing daemon "
                    "was spawned." % _trim(
                        watcher_result.get("error"), 240)),
            }
    except Exception as err:
        watcher_notice = {
            "system_message": "Attacca background watcher needs attention",
            "context": ("ATTACCA BACKGROUND WATCHER COULD NOT START: %s. "
                        "This lifecycle boundary is using the direct-poll "
                        "fallback." % _trim(err, 240)),
        }
    pending_notice = _watcher_pending_notice(status, config)
    offline_key, offline_entry = _watcher_subscription_entry(status, config)
    terminal_notice = _terminal_migration_notice(
        status, config, event_name, offline_entry)
    if offline_adapter is None:
        try:
            offline_adapter = _watcher_build_offline_adapter(
                offline_entry, factory=offline_factory)
        except Exception:
            offline_adapter = None
    # Kimi's native startup contract is a skill rather than a SessionStart
    # command hook. Its first prompt boundary is therefore the reliable place
    # to perform an unthrottled release check. Claude and Codex already check
    # on SessionStart, so their background shared-state cadence stays quiet.
    is_kimi_prompt = (_runtime_name() == "kimi" and
                      event_name == "UserPromptSubmit")
    update_notice = _update_offer(
        status, plugin_root, config,
        check_interval_seconds=UPDATE_CHECK_INTERVAL_SECONDS) \
        if is_kimi_prompt else None
    # Claude/Codex already checked this release on SessionStart. Their
    # prompt/stop hooks stay focused on shared-state changes.
    if not is_kimi_prompt:
        update_notice = None
    notices = (pending_notice, watcher_notice, update_notice, terminal_notice)
    # A healthy daemon is the primary periodic path. Queued changes bypass the
    # old hook throttle and are delivered immediately; otherwise this boundary
    # stays quiet and leaves network polling to the autonomous watcher.
    if watcher_healthy and not is_kimi_prompt:
        # The healthy watcher owns network polling, but the mandatory
        # Project Rules must still be re-pinned at the start of every
        # response so they never fall out of a long conversation.
        banner_output = None
        if event_name == "UserPromptSubmit":
            _identity, _entry = _poll_entry(status, config)
            _snap = (_entry or {}).get("snapshot") or {}
            _rules_banner = _mandatory_rules_banner(
                _snap.get("project_rules"))
            if _rules_banner:
                banner_output = _event_context_output(
                    event_name,
                    "Attacca \u00b7 mandatory project rules pinned",
                    _rules_banner)
        return _append_notices(banner_output, event_name, notices)
    interval = _settings_interval(config, entry=offline_entry)
    identity, entry = _poll_entry(status, config)
    # Polling Off still allows Kimi's first native prompt to validate the link
    # and refresh managed laws once; subsequent prompts remain off.
    if interval == 0 and not (is_kimi_prompt and not entry):
        return _append_notices(None, event_name, notices)
    checked_at = time.time()
    last_poll_at = entry.get("last_poll_at")
    elapsed = checked_at - last_poll_at \
        if isinstance(last_poll_at, (int, float)) else None
    if elapsed is not None and 0 <= elapsed < interval:
        return _append_notices(None, event_name, notices)
    try:
        snapshot = _mcp_snapshot(status, plugin_root, config)
        _watcher_activate_after_mcp(status, config, snapshot)
        # Kimi has no command SessionStart hook. Refresh laws only after the
        # saved workspace has been validated by the successful MCP snapshot.
        law_notice = _refresh_managed_laws(status, plugin_root) \
            if is_kimi_prompt else None
        notices = (law_notice, update_notice, terminal_notice)
        current = _poll_view(snapshot)
        previous = entry.get("snapshot") if entry else None
        _record_poll(status, identity, interval, checked_at, current)
        summary = _change_summary(status, previous, current, snapshot, interval)
        if not summary:
            return _append_notices(None, event_name, notices)
        output = _event_context_output(
            event_name, "Attacca update · shared project state changed", summary)
        return _append_notices(output, event_name, notices)
    except StaleProjectLink as err:
        set_offered(status["root"], stale_project_id=status["project_id"])
        output = _hook_output(status, recovery_reason=str(err),
                              event_name=event_name)
        return _append_notices(output, event_name, notices)
    except Exception as err:
        _record_poll(status, identity, interval, checked_at,
                     entry.get("snapshot") if entry else {})
        auth_blocked = _authentication_required_error(err) or bool(
            isinstance(offline_entry, dict) and
            offline_entry.get("auth_required"))
        if auth_blocked:
            auth_error = err if _authentication_required_error(err) else \
                HostedAuthenticationRequired(
                    offline_entry.get("last_error") or
                    "credential/AI scope repair is required")
            _watcher_queue_auth_required(
                offline_key, offline_entry, auth_error, time.time())
            output = _authentication_required_output(
                status, config, event_name, auth_error)
            # Never mix a stale queued outage-continuity notice into an auth or
            # authority rejection. The reachable host has revoked cached use.
            notices = (watcher_notice, update_notice)
        else:
            output = _offline_failure_output(
                status, config, event_name, err, offline_adapter,
                entry=offline_entry)
            if output is None:
                output = _failure_output(status, config, event_name, err)
        return _append_notices(output, event_name, notices)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwd", default=None)
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--dismiss", action="store_true")
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--update-choice", choices=sorted(UPDATE_CHOICES))
    parser.add_argument("--server-url")
    parser.add_argument("--server-version")
    parser.add_argument("--setup-cwd")
    parser.add_argument("--runtime")
    parser.add_argument("--watcher-daemon", action="store_true")
    parser.add_argument("--watcher-nonce")
    parser.add_argument("--watcher-launch-version")
    parser.add_argument("--watcher-launch-hook-sha256")
    parser.add_argument("--watcher-launch-fingerprint")
    parser.add_argument("--watcher-ensure", action="store_true")
    parser.add_argument("--watcher-upgrade", action="store_true")
    parser.add_argument("--watcher-status", action="store_true")
    parser.add_argument("--watcher-stop", action="store_true")
    args = parser.parse_args(argv)
    if args.runtime:
        os.environ["ATTACCA_RUNTIME"] = args.runtime
    if args.watcher_daemon:
        nonce = args.watcher_nonce or os.environ.get("ATTACCA_WATCHER_NONCE")
        if not nonce or nonce != os.environ.get("ATTACCA_WATCHER_NONCE"):
            parser.error("watcher daemon requires its private nonce")
        expected = {
            "launch_version": args.watcher_launch_version,
            "launch_hook_sha256": args.watcher_launch_hook_sha256,
            "launch_fingerprint": args.watcher_launch_fingerprint,
        }
        environment = {
            "launch_version": os.environ.get(WATCHER_LAUNCH_VERSION_ENV),
            "launch_hook_sha256": os.environ.get(
                WATCHER_LAUNCH_HOOK_SHA_ENV),
            "launch_fingerprint": os.environ.get(
                WATCHER_LAUNCH_FINGERPRINT_ENV),
        }
        if not _CAPTURED_WATCHER_LAUNCH_IDENTITY \
                or expected != _CAPTURED_WATCHER_LAUNCH_IDENTITY \
                or environment != _CAPTURED_WATCHER_LAUNCH_IDENTITY:
            parser.error(
                "watcher launch fingerprint/version differs from loaded code")
        plugin_root = Path(__file__).resolve().parent.parent
        result = _watcher_daemon_loop(
            plugin_root, nonce,
            launch_identity=_CAPTURED_WATCHER_LAUNCH_IDENTITY)
        print(json.dumps(result))
        return 0
    if args.watcher_status:
        print(json.dumps(_watcher_status_payload(), indent=2))
        return 0
    if args.watcher_stop:
        print(json.dumps(_stop_background_watcher(), indent=2))
        return 0
    if args.watcher_upgrade:
        plugin_root = Path(__file__).resolve().parent.parent
        result = _restart_background_watcher_after_upgrade(plugin_root)
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 2
    if args.watcher_ensure:
        cwd = args.cwd or os.getcwd()
        status = prompt_status(cwd, args.data_dir)
        if status.get("status") != "linked":
            print(json.dumps({"ok": False, "error": "checkout is not linked",
                              "status": status.get("status")}, indent=2))
            return 2
        plugin_root, config = _plugin_and_config()
        result = _ensure_background_watcher(
            status, plugin_root, config, runtime=args.runtime)
        print(json.dumps(result, indent=2))
        return 0
    if args.update_choice:
        result = set_update_choice(
            args.data_dir, args.server_url, args.server_version,
            args.update_choice, setup_cwd=args.setup_cwd)
        print(json.dumps(result, indent=2))
        return 0
    payload = {} if (args.cwd or args.dismiss or args.reset or args.status) \
        else _hook_input()
    cwd = args.cwd or payload.get("cwd") or os.getcwd()
    event_name = payload.get("hook_event_name") or "SessionStart"
    # A changed Stop poll blocks once so the model can process the update.
    # Claude marks the resulting second Stop event active; skipping it is what
    # makes the continuation strictly one-shot instead of recursive.
    if event_name == "Stop" and payload.get("stop_hook_active"):
        return 0
    if args.dismiss or args.reset:
        result = set_dismissed(cwd, args.data_dir, dismissed=args.dismiss)
        print(json.dumps(result, indent=2))
        return 0
    result = prompt_status(cwd, args.data_dir)
    is_first_run_boundary = (
        event_name == "SessionStart" or
        (_runtime_name() == "kimi" and event_name == "UserPromptSubmit"))
    # Only an actual lifecycle payload may mutate the checkout. CLI --status
    # and --cwd are diagnostic/read-only even though their default event label
    # is SessionStart.
    migration = _reconcile_claude_project_mcp(cwd) \
        if payload.get("hook_event_name") == "SessionStart" else None
    if args.status:
        print(json.dumps(result, indent=2))
    elif result["status"] == "ask" and is_first_run_boundary:
        output = _hook_output(result)
        update_notice = _standalone_update_notice(
            result, setup_cwd=result["root"])
        if update_notice:
            # The update question is asked first. Install must leave setup
            # unconsumed for the restarted client; Later/Skip commands mark the
            # setup offer immediately before the agent asks it below.
            output = _append_notice(output, update_notice)
        else:
            plugin_root, config = _plugin_and_config()
            if _pending_unanswered_update(result, plugin_root, config):
                output = None
            else:
                set_offered(cwd, args.data_dir)
        if output:
            print(json.dumps(output))
    elif result["status"] in ("offered", "dismissed") \
            and is_first_run_boundary:
        output = _notice_output(
            event_name, _standalone_update_notice(result))
        if output:
            print(json.dumps(output))
    elif result["status"] == "linked" and event_name in (
            "SessionStart", "UserPromptSubmit", "Stop"):
        output = _active_output(result) if event_name == "SessionStart" \
            else _periodic_output(result, event_name)
        if output:
            output = _with_migration_notice(output, migration)
            print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
