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
import stat
import subprocess
import sys
import threading
import time
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlencode, urlparse
from urllib.request import Request, urlopen

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback remains atomic replace
    fcntl = None


STATE_NAME = "setup-prompts.json"
WATCHER_STATE_NAME = "watcher-state.json"
WATCHER_QUEUE_LIMIT = 200
WATCHER_DELTA_CHUNK_SIZE = 10
WATCHER_NOTICE_BATCH_SIZE = 2
WATCHER_ATTENTION_PAGE_SIZE = 25
WATCHER_INBOX_MAX_PAGES = 20
WATCHER_INBOX_MAX_BYTES = 1024 * 1024
WATCHER_WAKE_SECONDS = 5
WATCHER_EVENT_PAGE_SIZE = 200
WATCHER_EVENT_MAX_PAGES = 20
WATCHER_OUTAGE_BACKOFF_MAX_SECONDS = 15 * 60
# A missing checkout is not automatically abandoned. External/network volumes
# can disappear temporarily, and a server/auth failure says nothing about the
# local checkout lifecycle. The daemon therefore requires both sustained,
# filesystem-proven absence and several distinct observations before removing
# only the polling registration. Shared identity-scoped mirrors/outboxes remain
# available when the checkout returns or another checkout uses the identity.
WATCHER_MISSING_GRACE_SECONDS = 24 * 60 * 60
WATCHER_MISSING_MIN_OBSERVATIONS = 3
DEFAULT_UPDATE_INTERVAL_SECONDS = 60
WATCHER_FULL_SYNC_SAFETY_SECONDS = 10 * 60
CONFIGURED_AI_ROLES = {"director", "advisor", "worker"}
UPDATE_CHOICES = {"install", "later", "skip"}
AUXILIARY_HTTP_TIMEOUT_SECONDS = 1
UPDATE_REMIND_AFTER_SECONDS = 24 * 60 * 60
UPDATE_CHECK_INTERVAL_SECONDS = 5 * 60
MANAGED_LAW_MAX_BYTES = 1024 * 1024
HOOK_CONTEXT_MAX_BYTES = 262_144
# Compatibility name retained for callers/tests; the host measures UTF-8
# bytes (approximately four bytes per token), not Python code points.
HOOK_CONTEXT_MAX_CHARACTERS = HOOK_CONTEXT_MAX_BYTES
HOOK_NOTICE_RESERVE_BYTES = 24_000
MANDATORY_RULES_BANNER_MAX_CHARACTERS = 24_000
STARTUP_INBOX_PAGE_SIZE = 25
STARTUP_UNREAD_BODY_LIMIT = 2_000
STARTUP_RULE_PAGE_SIZE = 60
# Startup must never silently discard binding law behind a collection page.
# A finite ceiling also prevents a corrupt/malicious server from keeping the
# lifecycle hook in an unbounded fetch loop.  Crossing it fails the connected
# snapshot closed instead of presenting a partial rules banner as complete.
STARTUP_RULE_MAX_PAGES = 64
WATCHER_ROOM_BODY_LIMIT = 600

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


class WatcherStateSecurityError(RuntimeError):
    """The watcher cannot safely use its machine-local private state."""


def _is_watcher_state_path(path):
    return Path(path).name == WATCHER_STATE_NAME


def _reject_watcher_symlink_components(path):
    """Reject an existing symlink anywhere in a watcher storage path.

    ``Path.resolve`` is deliberately forbidden here: resolving first would
    erase the evidence that an attacker redirected the private watcher state.
    Only the watcher directory itself is chmodded; existing ancestors are
    inspected but never modified.
    """
    path = Path(path).expanduser().absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            mode = os.lstat(str(current)).st_mode
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as error:
            raise WatcherStateSecurityError(
                "cannot inspect watcher storage path %s: %s" %
                (current, error)) from None
        if stat.S_ISLNK(mode):
            raise WatcherStateSecurityError(
                "refusing symlink traversal in watcher storage: %s" %
                current)


def _ensure_private_watcher_directory(path):
    """Create/repair exactly the watcher directory as mode 0700."""
    path = Path(path).expanduser().absolute()
    _reject_watcher_symlink_components(path)
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as error:
        raise WatcherStateSecurityError(
            "cannot create watcher storage directory %s: %s" %
            (path, error)) from None
    _reject_watcher_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError as error:
        raise WatcherStateSecurityError(
            "watcher storage is not a safe directory %s: %s" %
            (path, error)) from None
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise WatcherStateSecurityError(
                "watcher storage is not a directory: %s" % path)
        os.fchmod(descriptor, 0o700)
    except OSError as error:
        raise WatcherStateSecurityError(
            "cannot make watcher storage private %s: %s" %
            (path, error)) from None
    finally:
        os.close(descriptor)
    return path


def _open_private_watcher_file(path, flags, create=False):
    """Open one private watcher file without following links.

    Existing safe regular files are repaired to 0600 through the opened file
    descriptor, avoiding a chmod-by-path race.  The post-open inode check also
    rejects a concurrent path substitution before callers consume the file.
    """
    path = Path(path).expanduser().absolute()
    _ensure_private_watcher_directory(path.parent)
    _reject_watcher_symlink_components(path)
    try:
        existing = os.lstat(str(path))
    except FileNotFoundError:
        existing = None
    except OSError as error:
        raise WatcherStateSecurityError(
            "cannot inspect watcher file %s: %s" % (path, error)) from None
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        raise WatcherStateSecurityError(
            "watcher path is not a regular file: %s" % path)
    if existing is None and not create:
        raise FileNotFoundError(str(path))
    open_flags = flags | getattr(os, "O_CLOEXEC", 0) \
        | getattr(os, "O_NOFOLLOW", 0)
    if create:
        open_flags |= os.O_CREAT
    try:
        descriptor = os.open(str(path), open_flags, 0o600)
    except OSError as error:
        raise WatcherStateSecurityError(
            "cannot safely open watcher file %s: %s" %
            (path, error)) from None
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise WatcherStateSecurityError(
                "opened watcher path is not a regular file: %s" % path)
        os.fchmod(descriptor, 0o600)
        current = os.lstat(str(path))
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) \
                or (current.st_dev, current.st_ino) != \
                (opened.st_dev, opened.st_ino):
            raise WatcherStateSecurityError(
                "watcher path changed while it was opened: %s" % path)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _fsync_watcher_directory(path):
    """Best-effort directory fsync after an atomic watcher-state replace."""
    path = _ensure_private_watcher_directory(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _read_state(path):
    path = Path(path)
    if _is_watcher_state_path(path):
        try:
            descriptor = _open_private_watcher_file(path, os.O_RDONLY)
        except FileNotFoundError:
            _ensure_private_watcher_directory(path.parent)
            return {}
        try:
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = None
                data = json.load(handle)
            return data if isinstance(data, dict) else {}
        except (OSError, UnicodeError, ValueError):
            return {}
        finally:
            if descriptor is not None:
                os.close(descriptor)
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_state(path, state):
    path = Path(path)
    if _is_watcher_state_path(path):
        directory = _ensure_private_watcher_directory(path.parent)
        # Refuse a pre-existing link/non-file even though os.replace would not
        # follow the final symlink. Failing closed makes corruption/tampering
        # visible instead of silently deleting evidence.
        _reject_watcher_symlink_components(path)
        try:
            target = os.lstat(str(path))
        except FileNotFoundError:
            target = None
        if target is not None and not stat.S_ISREG(target.st_mode):
            raise WatcherStateSecurityError(
                "watcher state is not a regular file: %s" % path)
        data = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode(
            "utf-8")
        temporary = path.with_name(
            ".%s.%d.%s.tmp" %
            (path.name, os.getpid(), os.urandom(8).hex()))
        descriptor = None
        try:
            descriptor = _open_private_watcher_file(
                temporary, os.O_WRONLY | os.O_EXCL, create=True)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            # Re-check the destination immediately before replacement. A race
            # after this point can at worst have its link entry replaced; the
            # referenced victim is never opened or modified.
            _reject_watcher_symlink_components(path)
            try:
                current = os.lstat(str(path))
            except FileNotFoundError:
                current = None
            if current is not None and not stat.S_ISREG(current.st_mode):
                raise WatcherStateSecurityError(
                    "watcher state changed to an unsafe target: %s" % path)
            os.replace(str(temporary), str(path))
            _fsync_watcher_directory(directory)
            return
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(str(temporary))
            except FileNotFoundError:
                pass
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(".%s.%d.tmp" % (path.name, os.getpid()))
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    os.replace(str(temporary), str(path))


def _mutate_state(path, mutation):
    """Serialize read/modify/write across simultaneous lifecycle sessions."""
    path = Path(path)
    if _is_watcher_state_path(path):
        _ensure_private_watcher_directory(path.parent)
        lock_path = path.with_name(".%s.lock" % path.name)
        descriptor = _open_private_watcher_file(
            lock_path, os.O_RDWR | os.O_APPEND, create=True)
        with os.fdopen(descriptor, "a+", encoding="utf-8") as lock:
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


def _client_instance_id(runtime=None):
    """Stable non-secret id for this installed coding-client integration."""
    explicit = str(os.environ.get("ATTACCA_CLIENT_INSTANCE") or "").strip()
    if explicit:
        return explicit
    try:
        return _terminal_flow_module().load_client_instance_id(
            runtime=runtime or _runtime_name())
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
        if not software_update:
            return None
    except Exception:
        # Version discovery is advisory. Never replace a successful MCP brief
        # with an update-check outage.
        return None

    server_url = _normalized_server_url(config["url"])
    # The atomic claim handles exact-version Skip, Later snoozing, unanswered
    # offers, and simultaneous lifecycle hooks without duplicate prompts.
    fingerprint = str(available)
    reason = "software_update"
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
        (available, server_url, installed))
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
        "system_message": "Attacca %s available · choose Install now, Later, or Skip this version"
                          % available,
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


def _server_managed_law(config, project_id, opener=None, entry=None):
    """Fetch and fully validate one project-bound, non-executable law block."""
    url = "%s/v1/managed-law?project=%s" % (
        _normalized_server_url(config["url"]),
        quote(str(project_id), safe=""))
    headers = {"Accept": "application/json"}
    if isinstance(entry, dict) and entry:
        actor_id = str(entry.get("canonical_actor_id") or "").strip()
        device_id = str(
            entry.get("device_id") or _local_device_id()).strip()
        if actor_id:
            headers["X-Attacca-Actor"] = actor_id
            headers["X-Attacca-Actor-Type"] = "agent"
        headers["X-Attacca-Project"] = str(project_id)
        if device_id:
            headers["X-Attacca-Device-ID"] = device_id
        headers["X-Attacca-Client-Instance"] = (
            entry.get("client_instance") or
            _client_instance_id(entry.get("runtime")))
        if entry.get("owner"):
            headers["X-Attacca-Owner"] = str(entry["owner"])
        token = _watcher_api_token(entry)
        if isinstance(token, str) and token.strip() \
                and "\n" not in token and "\r" not in token:
            headers["Authorization"] = "Bearer " + token.strip()
    request = Request(url, headers=headers)
    open_request = opener or urlopen
    with open_request(
            request, timeout=AUXILIARY_HTTP_TIMEOUT_SECONDS) as response:
        raw = response.read(MANAGED_LAW_MAX_BYTES + 1)
    if len(raw) > MANAGED_LAW_MAX_BYTES:
        raise RuntimeError("managed-law response exceeded its size limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("managed-law response is not valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise RuntimeError("managed-law response is not an object")
    version = payload.get("version")
    block = payload.get("block")
    digest = payload.get("sha256")
    law_digest = payload.get("law_sha256")
    if type(version) is not int or version < 1:
        raise RuntimeError("managed-law response has an invalid version")
    if not isinstance(block, str) or not block:
        raise RuntimeError("managed-law response has no block text")
    if not isinstance(digest, str) or \
            re.fullmatch(r"[0-9a-f]{64}", digest) is None or \
            hashlib.sha256(block.encode("utf-8")).hexdigest() != digest:
        raise RuntimeError("managed-law response failed exact sha256 validation")
    if not isinstance(law_digest, str) or \
            re.fullmatch(r"[0-9a-f]{64}", law_digest) is None:
        raise RuntimeError("managed-law response has an invalid law sha256")
    lines = block.splitlines()
    header = lines[0] if lines else ""
    match = re.fullmatch(
        r"<!-- MANAGED_ATTACCA:BEGIN v=(\d+) project=([^\s>]+) "
        r"do_not_edit=true -->", header)
    if not match or int(match.group(1)) != version \
            or match.group(2) != project_id \
            or block.count("MANAGED_ATTACCA:BEGIN") != 1 \
            or block.count("MANAGED_ATTACCA:END") != 1 \
            or not block.endswith("<!-- MANAGED_ATTACCA:END -->"):
        raise RuntimeError("managed-law block markers or project binding are invalid")
    template = block.replace(
        "project=%s" % project_id, "project=attacca-project", 1)
    if hashlib.sha256(template.encode("utf-8")).hexdigest() != law_digest:
        raise RuntimeError("managed-law template hash does not match the block")
    return payload


def _server_managed_law_adapter(plugin_root, project_id, root_path, law):
    runtime = _load_attacca_runtime(plugin_root)
    refresh = getattr(runtime, "refresh_managed_instruction_block", None)
    if not callable(refresh):
        raise RuntimeError(
            "installed Attacca client cannot apply server-managed laws")
    return refresh(
        project_id, root_path, law["block"],
        expected_sha256=law["sha256"], files=None)


def _snapshot_cloud_context(snapshot):
    """Return the exact Cloud Context record from an MCP/offline snapshot."""
    value = snapshot.get("cloud_context") if isinstance(snapshot, dict) else None
    if isinstance(value, dict) and isinstance(value.get("cloud_context"), dict):
        value = value["cloud_context"]
    return value if isinstance(value, dict) else None


def _cloud_context_block_adapter(plugin_root, project_id, root_path,
                                 cloud_context, create=True):
    runtime = _load_attacca_runtime(plugin_root)
    refresh = getattr(runtime, "refresh_cloud_context_block_payload", None)
    if not callable(refresh):
        raise RuntimeError(
            "installed Attacca client cannot synchronize Cloud Context")
    return refresh(
        cloud_context, project_id, root_path, files=None, create=create,
        require_managed_ownership=create)


def _refresh_cloud_context_from_snapshot(status, plugin_root, snapshot,
                                         create=True):
    """Converge the separate local block from one authenticated snapshot.

    The core adapter compares exact desired bytes and performs no write when
    version/hash/content already match.  Missing blocks are created only for
    setup/lifecycle migration; malformed ownership boundaries fail closed.
    """
    cloud_context = _snapshot_cloud_context(snapshot)
    if cloud_context is None:
        return None
    checkout_root = str(Path(status["link_path"]).parent.parent) \
        if status.get("link_path") else status["root"]
    try:
        result = _cloud_context_block_adapter(
            plugin_root, status["project_id"], checkout_root,
            cloud_context, create=create)
    except Exception as err:
        return {
            "system_message": "Attacca Cloud Context local sync needs attention",
            "context": (
                "ATTACCA CLOUD CONTEXT LOCAL SYNC FAILED: %s. The hosted "
                "Cloud Context in this session brief remains authoritative; "
                "no malformed or unsafe local marker was overwritten." %
                _trim(err, 240)),
        }
    rows = (result.get("files") or []) if isinstance(result, dict) else []
    problems = [row for row in rows if row.get("status") in {
        "malformed", "unsafe_symlink", "write_error",
        "rollback_refused", "version_conflict", "ownership_invalid"}]
    changed = [row for row in rows if row.get("changed") is True]
    if problems:
        detail = "; ".join(
            "%s: %s" % (Path(row.get("file") or "instructions").name,
                         row.get("error") or row.get("status"))
            for row in problems)
        return {
            "system_message": "Attacca Cloud Context local sync needs attention",
            "context": (
                "ATTACCA CLOUD CONTEXT LOCAL SYNC NEEDS REVIEW: %s. The "
                "hosted value remains authoritative and unsafe local files "
                "were left untouched." % detail),
        }
    if not changed:
        return None
    names = ", ".join(dict.fromkeys(
        Path(row["file"]).name for row in changed))
    return {
        "system_message": "Attacca Cloud Context refreshed · %s" % names,
        "context": (
            "ATTACCA CLOUD CONTEXT LOCAL COPY REFRESHED: %s. Only the "
            "ATTACCA_CLOUD_CONTEXT marker block changed; local content and "
            "the separate MANAGED_ATTACCA block were preserved." % names),
    }


def _refresh_managed_laws(status, plugin_root, config=None, fetcher=None):
    """Apply server-authoritative law text without reinstalling executable code."""
    try:
        if config is None:
            _ignored_root, config = _plugin_and_config()
        if fetcher is not None:
            # Keep the narrow two-argument test/integration adapter contract.
            law = fetcher(config, status["project_id"])
        else:
            # A successful MCP startup records the exact canonical actor into
            # this subscription immediately before law refresh. Reload it so a
            # first-run client does not reuse the pre-MCP anonymous entry.
            _key, entry = _watcher_subscription_entry(status, config)
            law = _server_managed_law(
                config, status["project_id"], entry=entry)
        checkout_root = str(Path(status["link_path"]).parent.parent) \
            if status.get("link_path") else status["root"]
        result = _server_managed_law_adapter(
            plugin_root, status["project_id"], checkout_root, law) or []
    except Exception as err:
        if getattr(err, "code", None) == 404:
            return None  # older compatible server; executable update stays separate
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
        "malformed", "unsafe_symlink", "unmanaged", "missing",
        "write_error"}]
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


def _insert_after_rules_banner(context, addition):
    """Keep the mandatory banner literal-first while adding hook notices."""
    context = str(context or "")
    addition = str(addition or "")
    if not context:
        return addition
    if not addition:
        return context
    banner_end = None
    if context.startswith(
            "===================== ATTACCA MANDATORY PROJECT RULES"):
        footer = (
            "==========================================================================")
        found = context.find(footer)
        if found >= 0:
            banner_end = found + len(footer)
    if banner_end is None:
        return addition + "\n\n" + context
    prefix = context[:banner_end]
    suffix = context[banner_end:].lstrip("\n")
    return prefix + "\n\n" + addition + (
        "\n\n" + suffix if suffix else "")


def _append_notice(output, notice):
    if not output or not notice:
        return output
    if "message" in output:
        hook_specific = output.get("hookSpecificOutput") or {}
        if "hookSpecificOutput" not in output:
            output["message"] = _bound_injected_context(
                _insert_after_rules_banner(
                    output["message"], notice["context"]),
                reserve_notices=False)
            return output
        if hook_specific.get("permissionDecision") == "deny":
            combined = _bound_injected_context(
                _insert_after_rules_banner(
                    output["message"], notice["context"]),
                reserve_notices=False)
            output["message"] = combined
            hook_specific["permissionDecisionReason"] = combined
            output["hookSpecificOutput"] = hook_specific
            output["systemMessage"] = " ".join(filter(None, [
                output.get("systemMessage"), notice["system_message"]]))
            return output
    output["systemMessage"] = " ".join(filter(None, [
        output.get("systemMessage"), notice["system_message"]]))
    specific = output.get("hookSpecificOutput") or {}
    context = specific.get("additionalContext")
    if context:
        notice_context = str(notice.get("context") or "")
        available = max(
            0, HOOK_CONTEXT_MAX_BYTES -
            len(context.encode("utf-8")) - 4)
        if len(notice_context.encode("utf-8")) > available:
            recovery = (
                "[ATTACCA NOTICE COMPACTED TO FIT THE CLIENT CONTEXT LIMIT; "
                "refresh Attacca for the complete queued/update detail]")
            recovery_bytes = recovery.encode("utf-8")
            if available <= len(recovery_bytes):
                notice_context = recovery_bytes[:available].decode(
                    "utf-8", errors="ignore")
            else:
                notice_context, _ = _head_tail_text(
                    notice_context, available,
                    "refresh Attacca for the complete queued/update detail")
        if not notice_context:
            return output
        specific["additionalContext"] = _insert_after_rules_banner(
            context, notice_context)
        output["hookSpecificOutput"] = specific
    elif output.get("decision") == "block":
        output["reason"] = _bound_injected_context(
            _insert_after_rules_banner(
                output.get("reason", ""), notice["context"]),
            reserve_notices=False)
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
    context = _bound_injected_context(context)
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
        specific["additionalContext"] = _insert_after_rules_banner(
            context, notice)
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
            headers["X-Attacca-Client-Instance"] = (
                entry.get("client_instance") or
                _client_instance_id(entry.get("runtime")))
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


_WATCHER_MISSING_FIELDS = (
    "local_path_missing_since_epoch",
    "local_path_missing_last_checked_epoch",
    "local_path_missing_observations",
    "local_path_missing_reason",
)


def _watcher_expected_path_state(value, expected_kind):
    """Return present/absent/unknown for one absolute subscription path.

    Only ``FileNotFoundError``/``NotADirectoryError`` or an existing object of
    the wrong kind are affirmative absence evidence. Permission, transient IO,
    malformed metadata, and relative paths are unknown and can never advance
    pruning. ``os.stat`` follows a project.json symlink, matching normal link
    resolution while treating a broken symlink as absent.
    """
    if not isinstance(value, str) or not value.strip():
        return "unknown"
    try:
        path = Path(value).expanduser()
    except (OSError, TypeError, ValueError):
        return "unknown"
    if not path.is_absolute():
        return "unknown"
    try:
        mode = os.stat(str(path)).st_mode
    except (FileNotFoundError, NotADirectoryError):
        return "absent"
    except OSError:
        return "unknown"
    if expected_kind == "directory":
        return "present" if stat.S_ISDIR(mode) else "absent"
    if expected_kind == "file":
        return "present" if stat.S_ISREG(mode) else "absent"
    return "unknown"


def _watcher_subscription_missing_reason(entry):
    """Return path-only absence evidence, or None when healthy/unknown."""
    if not isinstance(entry, dict):
        return None
    root_state = _watcher_expected_path_state(entry.get("root"), "directory")
    if root_state == "absent":
        return "checkout_root_absent"
    if root_state != "present":
        return None
    link_state = _watcher_expected_path_state(entry.get("link_path"), "file")
    if link_state == "absent":
        return "project_link_absent"
    return None


def _prune_missing_watcher_subscriptions(now=None):
    """Age out sustained, filesystem-proven dead checkout registrations.

    This mutation is serialized with registration and every watcher update.
    A re-registration clears the observation window. We intentionally retain
    the shared offline directory: it is partitioned by authenticated identity,
    not subscription, and can contain exact-once outbox writes or a mirror used
    by another checkout. Network/auth errors are never consulted here.
    """
    now = time.time() if now is None else float(now)
    result = {"observed": [], "recovered": [], "removed": [],
              "deduplicated": []}

    def mutate(state):
        subscriptions = state.get("subscriptions")
        if not isinstance(subscriptions, dict):
            return
        for key, entry in list(subscriptions.items()):
            if not isinstance(entry, dict):
                continue
            reason = _watcher_subscription_missing_reason(entry)
            if reason is None:
                if any(field in entry for field in _WATCHER_MISSING_FIELDS):
                    for field in _WATCHER_MISSING_FIELDS:
                        entry.pop(field, None)
                    result["recovered"].append(key)
                continue

            since = entry.get("local_path_missing_since_epoch")
            if not isinstance(since, (int, float)):
                since = now
                entry["local_path_missing_since_epoch"] = now
                observations = 0
            else:
                observations = entry.get("local_path_missing_observations", 0)
                if not isinstance(observations, int) or observations < 0:
                    observations = 0

            last_checked = entry.get("local_path_missing_last_checked_epoch")
            # A busy loop or repeated calls with the same clock instant count
            # as one observation, not as artificial proof of sustained loss.
            if not isinstance(last_checked, (int, float)) or now > last_checked:
                observations += 1
                entry["local_path_missing_observations"] = observations
                entry["local_path_missing_last_checked_epoch"] = now
            entry["local_path_missing_reason"] = reason
            result["observed"].append(key)

            elapsed = max(0.0, now - float(since))
            if observations >= WATCHER_MISSING_MIN_OBSERVATIONS \
                    and elapsed >= WATCHER_MISSING_GRACE_SECONDS:
                # Delete by identity only while holding the state lock. A
                # concurrent registration runs before or after this mutation:
                # before clears markers; after safely recreates the entry.
                if subscriptions.get(key) is entry:
                    subscriptions.pop(key, None)
                    result["removed"].append(key)

        # Rolling versions historically included actor/device details in the
        # subscription hash, so the same installed client could accumulate
        # multiple live registrations for one checkout. Collapse only entries
        # whose canonical real root, server, project, runtime, and stable client
        # installation all agree. The newest registration owns live identity
        # and sync authority; only durable notification queues are unioned.
        groups = {}
        for key, entry in subscriptions.items():
            if not isinstance(entry, dict) or \
                    _watcher_subscription_missing_reason(entry) is not None:
                continue
            try:
                root_path = Path(entry["root"]).expanduser()
                if not root_path.is_absolute() or not root_path.is_dir():
                    continue
                root = str(root_path.resolve())
                identity = (
                    _normalized_server_url(entry.get("server_url")),
                    str(entry.get("project_id") or ""),
                    str(entry.get("runtime") or "").strip().lower(),
                    str(entry.get("client_instance") or ""), root)
            except Exception:
                continue
            if all(identity):
                groups.setdefault(identity, []).append((key, entry))
        for rows in groups.values():
            if len(rows) < 2:
                continue
            rows.sort(key=lambda item: (
                str(item[1].get("last_registered_at") or ""), item[0]))
            survivor_key, survivor = rows[-1]
            for duplicate_key, duplicate in rows[:-1]:
                for field, identity_field in (
                        ("pending", "fingerprint"),
                        ("attention", "message_key"),
                        ("pending_dispositions", "message_key")):
                    target = survivor.setdefault(field, [])
                    known = {item.get(identity_field) for item in target
                             if isinstance(item, dict)}
                    for item in duplicate.get(field) or []:
                        marker = item.get(identity_field) \
                            if isinstance(item, dict) else None
                        if marker and marker not in known:
                            target.append(item)
                            known.add(marker)
                survivor["attention_ack_cursor"] = max(
                    int(survivor.get("attention_ack_cursor") or 0),
                    int(duplicate.get("attention_ack_cursor") or 0))
                survivor["pending_disposition_total"] = max(
                    int(survivor.get("pending_disposition_total") or 0),
                    int(duplicate.get("pending_disposition_total") or 0))
                subscriptions.pop(duplicate_key, None)
                result["deduplicated"].append({
                    "removed": duplicate_key, "survivor": survivor_key})

    _mutate_state(_watcher_state_path(), mutate)
    return result


def _register_watcher_subscription(status, plugin_root, config, runtime=None,
                                   now=None):
    """Register one checkout without storing credentials or project data."""
    now = time.time() if now is None else float(now)
    runtime = runtime or _runtime_name()
    client_instance = _client_instance_id(runtime)
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
            "client_instance": client_instance,
            "root": str(Path(status["root"]).resolve()),
            "link_path": status.get("link_path"),
            "plugin_root": installed_plugin_root,
            "offline_directory": str(_watcher_offline_directory(key)),
            "last_registered_at": datetime.now(timezone.utc).isoformat(),
        })
        # Registration is positive evidence that this checkout is active.
        # Clear a prior temporary-unmount observation atomically so a daemon
        # pruning pass cannot remove a newly renewed subscription.
        for field in _WATCHER_MISSING_FIELDS:
            entry.pop(field, None)
        if previous_plugin_root \
                and previous_plugin_root != installed_plugin_root:
            entry["next_poll_at_epoch"] = 0
            entry["wake_reason"] = "executable_root_rebound"
            entry["wake_requested_at_epoch"] = now
        else:
            entry.setdefault("next_poll_at_epoch", now)
        entry.setdefault("pending", [])
        # Room mail is kept separately from disposable operational summaries.
        # A message leaves this durable FIFO only after the hosted inbox cursor
        # has acknowledged it *and* a lifecycle hook has injected it into an AI
        # turn.  Rendering is not allowed to masquerade as a successful read.
        entry.setdefault("attention", [])
        entry.setdefault("attention_ack_cursor", 0)
        # Addressed work survives the unread cursor until an explicit
        # message_dispose outcome removes it from the hosted pending set.
        entry.setdefault("pending_dispositions", [])
        entry.setdefault("pending_disposition_total", 0)
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
    client_instance = (entry.get("client_instance") if isinstance(entry, dict)
                       else None) or _client_instance_id(
                           entry.get("runtime") if isinstance(entry, dict)
                           else None)
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
        entry.get("device_id"), entry.get("client_instance"),
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
        visibility_fingerprint=visibility, wake_callback=wake,
        projection_capabilities=entry.get("sync_projection_capabilities"))


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
        client_instance_id=(entry.get("client_instance") or
                            _client_instance_id(entry.get("runtime"))),
        compatibility_optional_auth=True,
        projection_capabilities=entry.get("sync_projection_capabilities"))


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
                "last_full_sync_at_epoch", "last_full_sync_reason",
                "offline_failure_count", "offline_pending_sync",
                "offline_pending_count", "offline_conflict_count",
                "offline_convergence_awaiting_count",
                "offline_mirror_stale", "offline_mirror_cursor",
                "offline_mirror_verified_at", "offline_directory",
                "sync_schema_version", "sync_activated_at",
                "sync_bootstrap_error", "local_path_missing_reason",
                "local_path_missing_since_epoch",
                "local_path_missing_observations")
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
    """Load this installed client's account key without actor-token fallback.

    A D-17 client key authenticates one installed integration and its human
    account.  The exact project and canonical AI actor remain independent
    request headers; neither role nor runtime is encoded in the key.  Missing
    keys return ``None`` so only a real hosted 401/403 can latch authority off.
    """
    if not isinstance(entry, dict):
        return None
    server_url = entry.get("server_url")
    runtime = str(entry.get("runtime") or "").strip().lower()
    project_id = str(entry.get("project_id") or "").strip()
    client_instance = str(
        entry.get("client_instance") or _client_instance_id(runtime)).strip()
    if not server_url or not runtime or not project_id or not client_instance:
        return None
    try:
        terminal = _terminal_flow_module()
        token = terminal.load_client_api_key(
            server_url, client_instance=client_instance, runtime=runtime,
            project_id=project_id)
        return token.strip() if isinstance(token, str) and token.strip() else None
    except Exception as error:
        raise RuntimeError(
            "local client API key state is invalid: %s" %
            _trim(error, 160)) from None


def _watcher_request_actor(entry):
    """Use canonical identity when known, otherwise the runtime bootstrap hint."""
    return (entry.get("canonical_actor_id") or entry.get("actor") or
            entry.get("runtime") or "watcher")


def _watcher_fetch_sync_snapshot(entry, transport=None):
    """Fetch a freshly authorized identity snapshot for cache bootstrap."""
    protocol, offline, client = _watcher_sync_modules()
    token = _watcher_api_token(entry)
    if token is not None and (
            not isinstance(token, str) or not token.strip() or
            "\n" in token or "\r" in token or
            len(token.encode("utf-8")) > client.MAX_TOKEN_BYTES):
        raise RuntimeError(
            "no valid Attacca client API key is available for sync")
    request_transport = transport or client.UrllibJsonTransport()
    headers = {
        "Accept": "application/json",
        "X-Attacca-Device-ID": (
            entry.get("device_id") or _local_device_id()),
        "X-Attacca-Actor": _watcher_request_actor(entry),
        "X-Attacca-Actor-Type": "agent",
        "X-Attacca-Project": entry["project_id"],
        "X-Attacca-Client-Instance": (
            entry.get("client_instance") or
            _client_instance_id(entry.get("runtime"))),
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
    capabilities = protocol.validate_projection_capabilities(
        entry.get("sync_projection_capabilities") or
        protocol.current_projection_capabilities())
    url = "%s/v1/projects/%s/sync/snapshot?%s" % (
        offline.normalize_server_url(entry["server_url"]),
        quote(str(entry["project_id"]), safe=""),
        urlencode(protocol.projection_capabilities_query(capabilities)))
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
        protocol.validate_projection_for_capabilities(
            snapshot["projection"], snapshot["scope"], capabilities)
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
    capabilities = protocol.validate_projection_capabilities(
        entry.get("sync_projection_capabilities") or
        protocol.current_projection_capabilities())
    if scope["project_id"] != entry.get("project_id") \
            or scope["actor_id"] != entry.get("canonical_actor_id") \
            or scope["role"] != entry.get("actor_role") \
            or scope["actor_type"] != "agent":
        raise RuntimeError(
            "refusing to install a snapshot outside the MCP-verified AI scope")
    protocol.validate_projection_for_capabilities(
        checked["projection"], scope, capabilities)
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
        projection_capabilities=capabilities,
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
            "sync_projection_capabilities": capabilities,
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


def _watcher_request_headers(entry):
    """Build one authenticated, actor-scoped watcher request header set."""
    token = _watcher_api_token(entry)
    headers = {
        "Accept": "application/json",
        "X-Attacca-Actor": _watcher_request_actor(entry),
        "X-Attacca-Actor-Type": "agent",
        "X-Attacca-Project": entry["project_id"],
        "X-Attacca-Device": entry.get("device_id") or _local_device_id(),
        "X-Attacca-Device-ID": (
            entry.get("device_id") or _local_device_id()),
        "X-Attacca-Client-Instance": (
            entry.get("client_instance") or
            _client_instance_id(entry.get("runtime"))),
    }
    if entry.get("owner"):
        headers["X-Attacca-Owner"] = entry["owner"]
    if token:
        headers["Authorization"] = "Bearer %s" % token
    return headers


def _watcher_inbox_page(entry, mark_read=False,
                        limit=WATCHER_ATTENTION_PAGE_SIZE, opener=None):
    """Fetch one actor-private group-inbox page.

    The hook first peeks with ``mark_read=False`` and durably stages the exact
    messages.  Only then does it make the acknowledging request.  This closes
    the old crash gap where a remote read cursor could advance before the AI
    ever received the message.
    """
    limit = max(1, min(int(limit or WATCHER_ATTENTION_PAGE_SIZE), 500))
    url = "%s/v1/projects/%s/inbox?mark_read=%d&limit=%d" % (
        entry["server_url"].rstrip("/"),
        quote(str(entry["project_id"]), safe=""),
        1 if mark_read else 0, limit)
    request = Request(url, headers=_watcher_request_headers(entry))
    with (opener or urlopen)(
            request,
            timeout=AUXILIARY_HTTP_TIMEOUT_SECONDS) as response:
        raw = response.read(WATCHER_INBOX_MAX_BYTES + 1)
    if len(raw) > WATCHER_INBOX_MAX_BYTES:
        raise RuntimeError("inbox response exceeded its size limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("inbox response is not valid UTF-8 JSON") from error
    messages = payload.get("messages") if isinstance(payload, dict) else None
    if not isinstance(messages, list) or any(
            not isinstance(message, dict) for message in messages):
        raise RuntimeError("inbox response returned an invalid messages array")
    return payload


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
    headers = _watcher_request_headers(entry)
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
            event_type.startswith("cloud_context.") or
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


def _watcher_event_is_self(event, entry):
    """Reject the subscription's own room writes from its unread FIFO."""
    identity = event.get("identity") \
        if isinstance(event.get("identity"), dict) else {}
    attribution = event.get("attribution") \
        if isinstance(event.get("attribution"), dict) else {}
    candidates = {
        str(value) for value in (
            event.get("operational_actor_id"), event.get("actor_id"),
            identity.get("actor_id"), attribution.get("actor_id"))
        if value
    }
    own = {
        str(value) for value in (
            entry.get("canonical_actor_id"), entry.get("actor")) if value
    }
    return bool(candidates.intersection(own))


def _watcher_attention_projection(value, entry):
    """Return one bounded, actor-private room row for durable delivery."""
    is_event = value.get("event_type") == "room.message"
    payload = value.get("payload") if is_event else value
    if not isinstance(payload, dict):
        return None
    if is_event and _watcher_event_is_self(value, entry):
        return None
    sender = (_watcher_event_actor(value) if is_event else
              payload.get("actor") or payload.get("actor_id") or "unknown")
    canonical = str(entry.get("canonical_actor_id") or "")
    if not is_event and canonical and str(sender) == canonical:
        return None
    seq = value.get("seq") if is_event else payload.get("seq")
    try:
        numeric_seq = int(seq or 0)
    except (TypeError, ValueError):
        return None
    # Persist the exact body. Rendering is bounded later; truncating the
    # durable FIFO itself would make a transient watcher cache the only place
    # where an unread room message was silently destroyed.
    body = str(payload.get("body") or "")
    directed = bool(payload.get("directed_to_you") or
                    payload.get("addressed_to_you") and
                    not payload.get("broadcast_to_everyone"))
    everyone = bool(payload.get("broadcast_to_everyone"))
    bridge = bool(payload.get("origin_project") or payload.get("authority"))
    event_id = value.get("event_id") if is_event else payload.get("event_id")
    return {
        "event_id": event_id,
        "message_key": ("event:%s" % event_id if event_id else
                        json.dumps([numeric_seq, sender, body],
                                   separators=(",", ":"),
                                   ensure_ascii=False)),
        "seq": numeric_seq,
        "actor": sender,
        "msg_type": payload.get("msg_type") or payload.get("type") or "chat",
        "body": body,
        "body_truncated": False,
        "mentions": payload.get("mentions") or [],
        "reply_to": payload.get("reply_to"),
        "task_id": value.get("task_id") or payload.get("task_id"),
        "origin_project": payload.get("origin_project"),
        "authority": payload.get("authority"),
        "directed_to_you": directed,
        "broadcast_to_everyone": everyone,
        "group_context": bool(payload.get("group_context")) or
                         not (directed or everyone),
        "priority_attention": bool(directed or everyone or bridge),
    }


def _watcher_merge_attention(entry, rows, acknowledged=False):
    """Merge room rows into an unbounded lossless FIFO by immutable id."""
    pending = entry.setdefault("attention", [])
    by_key = {row.get("message_key"): row for row in pending
              if isinstance(row, dict) and row.get("message_key")}
    ack_cursor = max(0, int(entry.get("attention_ack_cursor") or 0))
    added = 0
    for row in rows:
        projected = _watcher_attention_projection(row, entry)
        if not projected:
            continue
        key = projected["message_key"]
        existing = by_key.get(key)
        acked = bool(acknowledged or projected["seq"] <= ack_cursor)
        if existing:
            existing.update({key: value for key, value in projected.items()
                             if value is not None})
            existing["acknowledged"] = bool(
                existing.get("acknowledged") or acked)
            continue
        projected["acknowledged"] = acked
        projected["staged_at"] = datetime.now(timezone.utc).isoformat()
        pending.append(projected)
        by_key[key] = projected
        added += 1
    pending.sort(key=lambda row: (
        int(row.get("seq") or 0), str(row.get("message_key") or "")))
    return added


def _watcher_ack_attention_through(key, cursor):
    """Record a hosted inbox cursor and mark already-staged rows acknowledged."""
    try:
        cursor = max(0, int(cursor or 0))
    except (TypeError, ValueError):
        return

    def mutate(state):
        entry = (state.get("subscriptions") or {}).get(key)
        if not entry:
            return
        entry["attention_ack_cursor"] = max(
            int(entry.get("attention_ack_cursor") or 0), cursor)
        for row in entry.get("attention") or []:
            if int(row.get("seq") or 0) <= cursor:
                row["acknowledged"] = True

    _mutate_state(_watcher_state_path(), mutate)


def _watcher_stage_attention(key, rows, acknowledged=False):
    captured = {"added": 0}

    def mutate(state):
        entry = (state.get("subscriptions") or {}).get(key)
        if entry:
            captured["added"] = _watcher_merge_attention(
                entry, rows, acknowledged=acknowledged)

    _mutate_state(_watcher_state_path(), mutate)
    return captured["added"]


def _watcher_replace_pending_dispositions(key, payload):
    """Persist the server's actor-private unresolved assignment projection.

    Unlike unread room rows, these records are a current set, not a FIFO. They
    remain pinned after the read cursor advances and disappear only when the
    server reports an explicit terminal disposition.
    """
    if not isinstance(payload, dict) or "pending_dispositions" not in payload:
        return False
    rows = payload.get("pending_dispositions")
    if not isinstance(rows, list) or any(not isinstance(row, dict)
                                         for row in rows):
        raise RuntimeError(
            "inbox response returned invalid pending_dispositions")
    projected = []
    for row in rows:
        item = _watcher_attention_projection(row, {})
        if not item:
            continue
        disposition = row.get("disposition")
        item["disposition"] = disposition if isinstance(disposition, dict) \
            else None
        item["requires_disposition"] = True
        projected.append(item)
    try:
        total = int(payload.get("pending_disposition_total", len(projected)))
    except (TypeError, ValueError):
        raise RuntimeError(
            "inbox response returned invalid pending_disposition_total")
    if total < len(projected) or total < 0:
        raise RuntimeError(
            "inbox response returned inconsistent pending disposition count")

    def mutate(state):
        entry = (state.get("subscriptions") or {}).get(key)
        if not entry:
            return
        entry["pending_dispositions"] = projected
        entry["pending_disposition_total"] = total
        entry["pending_disposition_may_have_more"] = bool(
            payload.get("pending_disposition_may_have_more") or
            total > len(projected))
        entry["pending_dispositions_refreshed_at"] = datetime.now(
            timezone.utc).isoformat()

    _mutate_state(_watcher_state_path(), mutate)
    return True


def _watcher_refresh_inbox_attention(status, config, runtime=None,
                                      opener=None):
    """Automatically stage and acknowledge all bounded unread inbox pages.

    Each page is peeked, fsynced into watcher state, and only then acknowledged
    remotely. More than ``WATCHER_INBOX_MAX_PAGES`` remains unread on the host
    for the next lifecycle boundary instead of being silently skipped.
    """
    key, entry = _watcher_subscription_entry(status, config, runtime=runtime)
    if not entry or not entry.get("server_url") or not entry.get("project_id"):
        return {"ok": False, "missing": True, "key": key}
    return _watcher_refresh_inbox_entry(key, entry, opener=opener)


def _watcher_refresh_inbox_entry(key, entry, opener=None):
    """Refresh one already-resolved subscription (including idle daemon use)."""
    pages = staged = 0
    more = False
    for _ in range(WATCHER_INBOX_MAX_PAGES):
        peek = _watcher_inbox_page(
            entry, mark_read=False, limit=WATCHER_ATTENTION_PAGE_SIZE,
            opener=opener)
        messages = peek.get("messages") or []
        _watcher_replace_pending_dispositions(key, peek)
        staged += _watcher_stage_attention(key, messages)
        # The common idle case is deliberately one lightweight request. There
        # is no hosted read cursor to advance when no visible unread row was
        # returned; unresolved dispositions were still refreshed above.
        if not messages and not peek.get("may_have_more"):
            pages += 1
            more = False
            break
        ack = _watcher_inbox_page(
            entry, mark_read=True, limit=WATCHER_ATTENTION_PAGE_SIZE,
            opener=opener)
        _watcher_replace_pending_dispositions(key, ack)
        try:
            ack_cursor = int(ack.get("read_cursor") or 0)
        except (TypeError, ValueError):
            raise RuntimeError("inbox acknowledgement returned an invalid cursor")
        last_message_seq = max(
            [int(message.get("seq") or 0) for message in messages] or [0])
        if ack_cursor < last_message_seq:
            raise RuntimeError(
                "inbox acknowledgement did not reach the durably staged page")
        _watcher_ack_attention_through(key, ack_cursor)
        pages += 1
        more = bool(peek.get("may_have_more") or ack.get("may_have_more"))
        if not more:
            break
    return {"ok": True, "key": key, "pages": pages, "staged": staged,
            "may_have_more": more}


def _watcher_attention_notice(status, config, runtime=None, consume=True):
    """Pin unresolved assignments and staged unread mail at every boundary."""
    key = _watcher_subscription_key(status, config, runtime=runtime)
    captured = {"rows": [], "remaining": 0, "dispositions": [],
                "disposition_total": 0, "disposition_more": False}

    def mutate(state):
        entry = (state.get("subscriptions") or {}).get(key)
        if not entry:
            return
        # A row acknowledged by the hosted inbox and delivered on a previous
        # lifecycle boundary is complete. Failed acknowledgements deliberately
        # repeat, even if a prior hook rendered them.
        pending = [row for row in (entry.get("attention") or [])
                   if not (row.get("acknowledged") and
                           row.get("delivered_at"))]
        entry["attention"] = pending
        captured["dispositions"] = list(
            entry.get("pending_dispositions") or [])[
                :WATCHER_ATTENTION_PAGE_SIZE]
        captured["disposition_total"] = max(
            len(captured["dispositions"]),
            int(entry.get("pending_disposition_total") or 0))
        captured["disposition_more"] = bool(
            entry.get("pending_disposition_may_have_more") or
            captured["disposition_total"] >
            len(captured["dispositions"]))
        disposition_keys = {
            row.get("message_key") for row in captured["dispositions"]}
        selected = pending[:WATCHER_ATTENTION_PAGE_SIZE]
        captured["rows"] = [
            row for row in selected
            if row.get("message_key") not in disposition_keys]
        captured["remaining"] = max(
            0, len(pending) - len(selected))
        if consume:
            delivered_at = datetime.now(timezone.utc).isoformat()
            for row in selected:
                row["delivered_at"] = delivered_at

    if consume:
        _mutate_state(_watcher_state_path(), mutate)
    else:
        mutate(_read_state(_watcher_state_path()))
    rows = captured["rows"]
    dispositions = captured["dispositions"]
    if not rows and not dispositions:
        return None
    lines = [
        "ATTACCA PENDING ASSIGNMENTS + UNREAD GROUP MAIL · %s" %
        status["project_id"],
        "ATTACCA AUTOMATIC UPDATE · group-mail check completed",
        "Automatically checked by Attacca. Read and disposition messages "
        "marked YOUR ATTENTION, EVERYONE, or BRIDGE before yielding; no user "
        "needs to type ‘check messages’.",
    ]
    if dispositions:
        lines.append(
            "PENDING DISPOSITIONS (%d): these stay pinned even after the read "
            "cursor advances. Handle each assignment, then record its outcome "
            "with message_dispose; rendering alone does not clear it." %
            captured["disposition_total"])
    for row in dispositions:
        current = row.get("disposition") or {}
        state = current.get("disposition") if isinstance(current, dict) \
            else None
        body, _ = _head_tail_text(
            row.get("body") or "", WATCHER_ROOM_BODY_LIMIT,
            "call room_read with since_seq=%s for the complete message" %
            max(0, int(row.get("seq") or 0) - 1))
        lines.append(
            "- [DISPOSITION REQUIRED%s] Event %s · Room #%s · %s · %s: %s" % (
                " · current=%s" % state if state else "",
                row.get("event_id") or row.get("message_key") or "?",
                row.get("seq") or "?", row.get("msg_type") or "directive",
                row.get("actor") or "unknown", body))
    if captured["disposition_more"]:
        lines.append(
            "- %d additional pending disposition(s) exist on the host; call "
            "check_inbox for the complete current assignment set." % max(
                0, captured["disposition_total"] - len(dispositions)))
    for row in rows:
        labels = []
        if row.get("origin_project") or row.get("authority"):
            labels.append("BRIDGE")
        if row.get("directed_to_you"):
            labels.append("YOUR ATTENTION")
        elif row.get("broadcast_to_everyone"):
            labels.append("EVERYONE")
        else:
            labels.append("GROUP CONTEXT")
        source = " from %s" % row["origin_project"] \
            if row.get("origin_project") else ""
        authority = " [%s]" % row["authority"] \
            if row.get("authority") else ""
        body, _ = _head_tail_text(
            row.get("body") or "", WATCHER_ROOM_BODY_LIMIT,
            "call room_read with since_seq=%s for the complete message" %
            max(0, int(row.get("seq") or 0) - 1))
        lines.append("- [%s] Room #%s%s%s · %s · %s: %s" % (
            "][".join(labels), row.get("seq") or "?", source, authority,
            row.get("msg_type") or "chat", row.get("actor") or "unknown",
            body))
    if captured["remaining"]:
        lines.append(
            "- %d additional staged message(s) remain in lossless FIFO and "
            "will be pinned on subsequent turn boundaries." %
            captured["remaining"])
    lines.append(
        "These rows were durably staged before the hosted read cursor was "
        "acknowledged. A failed acknowledgement keeps them pinned and retries "
        "automatically.")
    return {
        "system_message": (
            "Attacca assignments/mail · %d pending dispositions, %d unread "
            "shown, %d queued" % (
                captured["disposition_total"], len(rows),
                captured["remaining"])),
        "context": "\n".join(lines),
    }


def _watcher_entity_key(event):
    """Stable coalescing key for supersedable operational ledger entities."""
    event_type = str(event.get("event_type") or "")
    payload = event.get("payload") \
        if isinstance(event.get("payload"), dict) else {}
    task_id = event.get("task_id") or payload.get("task_id")
    if event_type.startswith("task.plan."):
        return "task-plan:%s" % (task_id or "unknown")
    if event_type.startswith("task."):
        return "task:%s" % (task_id or "unknown")
    if event_type.startswith("rule."):
        return "rule:%s" % (payload.get("rule_id") or "unknown")
    if event_type.startswith("cloud_context."):
        return "cloud-context"
    if event_type.startswith("decision."):
        return "decision:%s" % (
            payload.get("decision_id") or "unknown")
    if event_type.startswith("handoff."):
        return "handoff"
    if event_type.startswith("bridge."):
        return "bridge:%s" % (
            payload.get("with") or payload.get("other_project") or "unknown")
    return None


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
        attention = (
            "everyone" if payload.get("broadcast_to_everyone") else
            "your-attention" if payload.get("addressed_to_you") else
            "group-context")
        body = str(payload.get("body") or "")
        excerpt, _ = _head_tail_text(
            body, WATCHER_ROOM_BODY_LIMIT,
            "call room_read with since_seq=%s for the complete message" %
            max(0, int(event.get("seq") or 1) - 1))
        return "Room #%s%s%s · %s · %s · %s: %s" % (
            event.get("seq") or "?", source, authority, msg_type, attention,
            actor, excerpt)
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
        if payload.get("enabled") is False or event_type.endswith(".disabled"):
            state = " · CURRENTLY DISABLED"
        elif payload.get("enabled") is True or event_type.endswith(".enabled"):
            state = " · currently enabled"
        else:
            state = ""
        title = " — %s" % _trim(payload.get("title"), 140) \
            if payload.get("title") else ""
        return "Project Rule %s%s %s%s · %s%s" % (
            rule_id, version, verb, state, actor, title)
    if event_type.startswith("cloud_context."):
        version = " v%s" % payload["version"] \
            if payload.get("version") is not None else ""
        return ("Cloud Context%s %s · %s — synchronized local context "
                "changed; read the refreshed authoritative context" %
                (version, verb, actor))
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
    lines = ["ATTACCA BACKGROUND DELTA · %s" % status["project_id"]]
    # The caller chunks events before this renderer. Never collapse a room
    # message into a count: each queued delta must retain the content the AI
    # is expected to read at the next lifecycle boundary.
    lines.extend("- " + _watcher_event_line(event) for event in events)
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
    try:
        credential_sent = bool(_watcher_api_token(entry))
    except Exception:
        credential_sent = False
    recovery_message = None
    recovery_status = None
    recovery_interval = DEFAULT_UPDATE_INTERVAL_SECONDS
    try:
        status = _watcher_subscription_status(entry)
        config = _watcher_subscription_config(entry)
        recovery = _terminal_flow_notice(
            status, config, "SessionStart", entry)
        recovery_message = recovery["message"]
        recovery_status = recovery["result"].get("status")
        try:
            recovery_interval = max(1, min(
                DEFAULT_UPDATE_INTERVAL_SECONDS,
                int(recovery["result"].get("interval") or
                    DEFAULT_UPDATE_INTERVAL_SECONDS)))
        except (TypeError, ValueError):
            recovery_interval = DEFAULT_UPDATE_INTERVAL_SECONDS
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
                now + recovery_interval,
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
        cause = (
            "No installation credential was sent to the hosted server"
            if not credential_sent else
            "The hosted server rejected the installation credential or AI scope")
        summary = (
            "ATTACCA AUTHENTICATION REQUIRED · %s\n"
            "- %s: %s\n"
            "- Cached authority and offline queueing are blocked. %s\n"
            "- The watcher will hot-reload the private terminal credential "
            "and clear this latch only after authenticated sync succeeds."
            % (entry["project_id"], cause, message, recovery_message))
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


def _watcher_write_markdown_mirror(entry, adapter):
    """Best-effort: render the synced durable state (handoff, cloud context,
    rules, tasks, decisions, room, log) to Markdown files under
    <checkout>/.attacca/mirror/ so the AI can read it directly. A convenience
    view only; it never raises and never blocks sync."""
    root = entry.get("root") if isinstance(entry, dict) else None
    getter = getattr(adapter, "local_projection", None)
    if not root or not callable(getter):
        return
    try:
        projection = getter()
        runtime = _load_attacca_runtime(entry.get("plugin_root"))
    except Exception:
        return
    if not isinstance(projection, dict):
        return
    try:
        writer = getattr(runtime, "write_state_markdown", None)
        if callable(writer):
            writer(str(Path(root) / ".attacca" / "mirror"), projection)
    except Exception:
        pass
    try:
        refresh_context = getattr(
            runtime, "refresh_cloud_context_block_payload", None)
        cloud_context = projection.get("cloud_context")
        if callable(refresh_context) and isinstance(cloud_context, dict):
            # This projection has passed the identity-scoped snapshot and
            # convergence validation immediately before this call.  Reuse it;
            # never issue another hosted content request from the watcher.
            refresh_context(
                cloud_context, entry["project_id"], root,
                files=None, create=True, require_managed_ownership=True)
    except Exception:
        pass


def _watcher_tick(key, now=None, delta_loader=None, notifier=None,
                  force=False, offline_adapter=None, offline_factory=None,
                  remote_adapter=None, remote_factory=None):
    """Poll lightweight signals and refresh the full mirror only when due."""
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

    # The minute cadence is a lightweight signal poll, not a minute-by-minute
    # download of the identity-scoped project projection.  Read the bounded
    # append-only event feed first and reuse this response below.  A relevant
    # change triggers an immediate verified mirror refresh; otherwise a full
    # refresh is only a ten-minute safety reconciliation.  Pending local
    # writes always bypass both timers so durable outbox replay remains prompt.
    cursor = max(0, int(entry.get("event_cursor") or 0))
    initialized = bool(entry.get("event_cursor_initialized"))
    # Explicit forced checks are diagnostic/recovery operations. Preserve
    # their historical guarantee that authentication/sync is attempted even
    # if the auxiliary event feed is unavailable; normal daemon ticks always
    # perform the lightweight signal request.
    priority_sync = bool(
        force or write_woke or int(entry.get("offline_failure_count") or 0))
    loader = (lambda after: {
        "events": [], "next_after": after, "may_have_more": False,
    }) if priority_sync and delta_loader is None else (delta_loader or (
        lambda after: _watcher_event_delta(entry, after)))
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
        return {"ok": False, "due": True, "error": str(err), "key": key}
    if initialized:
        relevant = [event for event in events
                    if _watcher_relevant_event(event)]
    else:
        registered_at = entry.get("cursor_registered_at_epoch")
        relevant = [
            event for event in events
            if _watcher_relevant_event(event)
            and isinstance(_watcher_event_epoch(event), (int, float))
            and isinstance(registered_at, (int, float))
            and _watcher_event_epoch(event) >= registered_at]
    last_full_sync = float(entry.get("last_full_sync_at_epoch") or 0)
    safety_sync_due = now - last_full_sync >= WATCHER_FULL_SYNC_SAFETY_SECONDS
    retry_sync_due = (int(entry.get("offline_failure_count") or 0) > 0 or
                      str((adapter_status or {}).get("mode") or "") ==
                      "offline")
    perform_full_sync = bool(force or write_woke or relevant or
                             safety_sync_due or retry_sync_due)
    sync_result = None
    sync_notice_queued = False
    if adapter is not None and perform_full_sync:
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
        _watcher_write_markdown_mirror(entry, adapter)
        try:
            # A successful capability negotiation can rebind visibility (and
            # therefore the mirror key) without changing authority. Validate
            # that exact pair before any result is queued or treated as a
            # convergence proof.
            entry, _rebind_proof, _rebind_snapshot, adapter_status = \
                _watcher_accept_synced_identity(entry, adapter)
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
                "last_full_sync_at_epoch": now,
                "last_full_sync_reason": (
                    "forced" if force else "local_write" if write_woke else
                    "relevant_change" if relevant else
                    "retry" if retry_sync_due else "safety_refresh"),
                "last_sync_result": sync_state,
                "sync_scope": entry["sync_scope"],
                "sync_visibility_fingerprint": entry[
                    "sync_visibility_fingerprint"],
                "sync_projection_capabilities": entry[
                    "sync_projection_capabilities"],
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
    inbox_result = None
    inbox_error = None
    if delta_loader is None:
        # The detached daemon, not only lifecycle hooks, performs the inbox
        # read every configured minute. This is what makes new assignments
        # visible while every coding client is otherwise idle.
        try:
            inbox_result = _watcher_refresh_inbox_entry(key, entry)

            def clear_inbox_error(state_value):
                live = (state_value.get("subscriptions") or {}).get(key)
                if live:
                    live.pop("last_inbox_error", None)
                    live.pop("last_inbox_error_at", None)

            _mutate_state(_watcher_state_path(), clear_inbox_error)
        except Exception as err:
            if _authentication_required_error(err):
                _watcher_queue_auth_required(key, entry, err, now)
                return {"ok": False, "due": True,
                        "authentication_required": True, "offline": False,
                        "error": str(err), "key": key}
            inbox_error = _trim(err, 300)

            def record_inbox_error(state_value):
                live = (state_value.get("subscriptions") or {}).get(key)
                if live:
                    live["last_inbox_error"] = inbox_error
                    live["last_inbox_error_at"] = datetime.now(
                        timezone.utc).isoformat()

            _mutate_state(_watcher_state_path(), record_inbox_error)
            # Do not let one failed auxiliary inbox request suppress the raw
            # event feed or verified offline synchronization. Hosted unread
            # state is not acknowledged on failure and retries next minute.
    status = _watcher_subscription_status(entry)
    room_events = [event for event in relevant
                   if event.get("event_type") == "room.message"
                   and not _watcher_event_is_self(event, entry)]
    entity_events = [event for event in relevant
                     if event.get("event_type") != "room.message"]
    notification_summary = _watcher_delta_summary(
        status, (room_events + entity_events)[-WATCHER_DELTA_CHUNK_SIZE:],
        interval)
    fingerprint = hashlib.sha256(json.dumps([
        [event.get("seq"), event.get("event_id"), event.get("event_type")]
        for event in relevant
    ], sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()
    queued = False
    attention_added = 0

    def persist(state_value):
        nonlocal queued, attention_added
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
        # Room traffic has its own durable FIFO and is never coalesced. This
        # merge is in the same fsynced state transaction as the event cursor,
        # so advancing the cursor cannot lose a message.
        attention_added = _watcher_merge_attention(live, room_events)
        inbox_cursor = delta.get("inbox_read_cursor")
        if inbox_cursor is not None:
            try:
                inbox_cursor = max(0, int(inbox_cursor))
            except (TypeError, ValueError):
                inbox_cursor = None
        if inbox_cursor is not None:
            live["attention_ack_cursor"] = max(
                int(live.get("attention_ack_cursor") or 0), inbox_cursor)
            for row in live.get("attention") or []:
                if int(row.get("seq") or 0) <= inbox_cursor:
                    row["acknowledged"] = True

        if live.get("last_queued_fingerprint") == fingerprint:
            queued = bool(attention_added)
            return
        live["last_queued_fingerprint"] = fingerprint
        pending = live.setdefault("pending", [])
        created_at = datetime.now(timezone.utc).isoformat()
        for event in entity_events:
            entity_key = _watcher_entity_key(event)
            if not entity_key:
                continue
            # An older revision of the same task/rule/decision/handoff/bridge
            # is unsafe to inject after a newer revision exists. Replace it in
            # place with the latest observed ledger state instead of replaying
            # historical instructions oldest-first.
            pending[:] = [row for row in pending if not (
                row.get("kind") == "project_entity_delta" and
                row.get("entity_key") == entity_key)]
            seq = int(event.get("seq") or 0)
            line = _watcher_event_line(event)
            pending.append({
                "fingerprint": "%s:%s:%s" % (
                    fingerprint, entity_key, seq),
                "created_at": created_at,
                "summary": (
                    "ATTACCA CURRENT ENTITY UPDATE · %s\n"
                    "- %s\n"
                    "This row supersedes older queued revisions for %s and "
                    "reflects the newest watcher event through #%s. Refresh "
                    "the entity before acting when complete current detail "
                    "is required." % (
                        entry["project_id"], line, entity_key, seq)),
                "kind": "project_entity_delta",
                "entity_key": entity_key,
                "after": max(cursor, seq - 1),
                "through": seq,
                "event_count": 1,
                "event_types": [event.get("event_type")],
            })
        if len(pending) > WATCHER_QUEUE_LIMIT:
            # Room bodies live in the separate lossless attention FIFO. This
            # queue contains only re-fetchable operational state and may be
            # compacted under an extreme number of distinct entities.
            removable = max(0, len(pending) - WATCHER_QUEUE_LIMIT)
            kept = []
            coalesced = []
            for item in pending:
                if removable and item.get("kind") in {
                        "project_entity_delta", "project_delta"}:
                    coalesced.append(item)
                    removable -= 1
                else:
                    kept.append(item)
            if coalesced:
                kept.insert(0, {
                    "fingerprint": "operational-overflow:%s" % fingerprint,
                    "created_at": created_at,
                    "summary": (
                        "ATTACCA OPERATIONAL BACKLOG · %s\n"
                        "- %d supersedable entity update(s) were compacted. "
                        "No group-room message was dropped; refresh tasks/"
                        "rules/Cloud Context/decisions/handoff for current "
                        "detail." % (
                            entry["project_id"], sum(int(
                                item.get("event_count") or 0)
                                for item in coalesced))),
                    "kind": "project_delta_backlog",
                    "after": coalesced[0].get("after"),
                    "through": coalesced[-1].get("through"),
                    "event_count": sum(int(item.get("event_count") or 0)
                                       for item in coalesced),
                    "event_types": sorted({event_type for item in coalesced
                                           for event_type in
                                           (item.get("event_types") or [])}),
                })
            pending[:] = kept
        queued = bool(attention_added or entity_events)

    # Persistence happens before any optional desktop notification. A notifier
    # failure therefore cannot lose the update.
    _mutate_state(_watcher_state_path(), persist)
    if queued and notification_summary:
        try:
            (notifier or _desktop_notify)(
                entry["project_id"], notification_summary)
        except Exception:
            pass
    return {"ok": True, "due": True,
            "queued": bool(queued or sync_notice_queued),
            "sync_queued": sync_notice_queued,
            "sync_status": ((sync_result or {}).get("status")
                            if sync_result is not None else None),
            "full_sync_performed": bool(sync_result is not None),
            "full_sync_reason": (
                "forced" if force else "local_write" if write_woke else
                "relevant_change" if relevant else
                "retry" if retry_sync_due else
                "safety_refresh" if safety_sync_due else None),
            "write_woke": write_woke,
            "key": key, "interval_seconds": interval,
            "event_count": len(events), "relevant_count": len(relevant),
            "attention_count": attention_added,
            "inbox_checked": bool(inbox_result and inbox_result.get("ok")),
            "inbox_staged": int((inbox_result or {}).get("staged") or 0),
            "inbox_error": inbox_error,
            "event_cursor": next_cursor,
            "cursor_initialized": initialized or not may_have_more}


def _watcher_pending_notice(status, config, runtime=None, consume=True):
    key = _watcher_subscription_key(status, config, runtime=runtime)
    captured = {"rows": [], "remaining": 0}

    def mutate(state):
        entry = (state.get("subscriptions") or {}).get(key)
        if not entry:
            return
        pending = list(entry.get("pending") or [])
        captured["rows"] = pending[:WATCHER_NOTICE_BATCH_SIZE]
        captured["remaining"] = max(
            0, len(pending) - len(captured["rows"]))
        if consume and captured["rows"]:
            # Deliver oldest-first and retain every undisplayed update for the
            # next lifecycle turn. Clearing the full queue after rendering a
            # five-row suffix used to lose group-room content silently.
            entry["pending"] = pending[len(captured["rows"]):]
            entry["last_delivered_at"] = datetime.now(timezone.utc).isoformat()

    if consume:
        _mutate_state(_watcher_state_path(), mutate)
    else:
        mutate(_read_state(_watcher_state_path()))
    rows = captured["rows"]
    if not rows:
        return None
    rendered = []
    for row in rows:
        summary = row["summary"]
        if row.get("kind") == "project_delta":
            # Pre-upgrade queues baked multiple historical entity revisions
            # into one opaque string. They cannot be proven current. Preserve
            # any legacy room excerpts for recovery, but explicitly prohibit
            # acting on its task/rule/decision/handoff lines.
            summary = (
                "ATTACCA LEGACY QUEUED DELTA — ENTITY STATE NOT "
                "REVALIDATED\n"
                "Do not act on any task/rule/decision/handoff/bridge state "
                "below until refreshing that entity. Room excerpts remain "
                "message-recovery evidence.\n" + summary)
        rendered.append(summary)
    context = "\n\n".join(rendered)
    if captured["remaining"]:
        context += ("\n\n- %d queued update(s) remain and will be injected "
                    "oldest-first at subsequent lifecycle boundaries; none "
                    "were cleared or coalesced." % captured["remaining"])
    context += ("\n\nThe background watcher captured these ledger deltas while "
                "the coding client was idle. Supersedable entity rows were "
                "collapsed to their newest observed revision; room mail uses "
                "a separate lossless FIFO. Refresh the affected handoff, "
                "task, plan, rule, decision, or bridge when full current "
                "detail is required.")
    return {"system_message": "Attacca background watcher · %d delivered, %d queued"
                              % (len(rows), captured["remaining"]),
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
    path = _watcher_state_path()
    lock_path = path.with_name("watcher.lock")
    descriptor = _open_private_watcher_file(
        lock_path, os.O_RDWR | os.O_APPEND, create=True)
    with os.fdopen(descriptor, "a+", encoding="utf-8") as lock:
        if fcntl is None:
            return True
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return True


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
    lock_path = path.with_name("watcher.lock")
    lock_descriptor = _open_private_watcher_file(
        lock_path, os.O_RDWR | os.O_APPEND, create=True)
    lock = os.fdopen(lock_descriptor, "a+", encoding="utf-8")
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
            prune = _prune_missing_watcher_subscriptions(now=clock())
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
            prior_pruned = ((state.get("daemon") or {}).get(
                "pruned_subscription_count"))
            if not isinstance(prior_pruned, int) or prior_pruned < 0:
                prior_pruned = 0
            _watcher_mark_daemon(
                nonce, plugin_root, launch_identity=launch_identity,
                running=True,
                heartbeat_at=datetime.now(timezone.utc).isoformat(),
                heartbeat_at_epoch=clock(), subscription_count=len(keys),
                missing_subscription_count=len(prune["observed"]),
                pruned_subscription_count=(prior_pruned
                                           + len(prune["removed"])))
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
        log_descriptor = _open_private_watcher_file(
            log_path, os.O_WRONLY | os.O_APPEND, create=True)
        with os.fdopen(log_descriptor, "a", encoding="utf-8") as log:
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


def _head_tail_text(value, limit, recovery):
    """Bound hostile/verbose hosted text without hiding that it was cut.

    Lifecycle context is finite.  Keeping both ends preserves headings and
    recent appendices, while the explicit recovery instruction prevents a
    compacted projection from masquerading as the complete durable record.
    """
    text = str(value or "")
    limit = max(1, int(limit))
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    marker = ("\n\n[ATTACCA COMPACTED TEXT OF %d UTF-8 BYTES TO FIT A %d "
              "BYTE BRIEF LIMIT; %s]\n\n" %
              (len(encoded), limit, recovery))
    marker_bytes = marker.encode("utf-8")
    if len(marker_bytes) >= limit:
        return marker_bytes[:limit].decode("utf-8", errors="ignore"), True
    payload = max(0, limit - len(marker_bytes))
    head = (payload * 3) // 5
    tail = payload - head
    head_text = encoded[:head].decode("utf-8", errors="ignore") \
        if head else ""
    tail_text = encoded[-tail:].decode("utf-8", errors="ignore") \
        if tail else ""
    result = head_text + marker + tail_text
    # UTF-8 boundary recovery can only reduce each slice, but keep this guard
    # explicit so future marker edits cannot violate the client spill limit.
    while len(result.encode("utf-8")) > limit and tail_text:
        tail_text = tail_text[1:]
        result = head_text + marker + tail_text
    return result, True


def _bound_injected_context(context, reserve_notices=True):
    """Enforce the host budget while preserving a literal-first rules banner."""
    context = str(context or "")
    limit = HOOK_CONTEXT_MAX_BYTES - (
        HOOK_NOTICE_RESERVE_BYTES if reserve_notices else 0)
    if len(context.encode("utf-8")) <= limit:
        return context
    footer = (
        "==========================================================================")
    banner_end = context.find(footer) if context.startswith(
        "===================== ATTACCA MANDATORY PROJECT RULES") else -1
    if banner_end >= 0:
        banner_end += len(footer)
        prefix = context[:banner_end]
        suffix = context[banner_end:].lstrip("\n")
        available = max(
            1, limit - len(prefix.encode("utf-8")) - 2)
        compact, _ = _head_tail_text(
            suffix, available,
            "call the relevant Attacca read tools before relying on omitted "
            "brief state")
        return prefix + "\n\n" + compact
    compact, _ = _head_tail_text(
        context, limit,
        "call the relevant Attacca read tools before relying on omitted "
        "brief state")
    return compact


def _compact_cloud_context(value):
    if not isinstance(value, dict):
        return value
    result = {key: value.get(key) for key in (
        "version", "sha256", "updated_by", "updated_owner", "updated_at")
              if key in value}
    content, truncated = _head_tail_text(
        value.get("content"), 100_000,
        "call cloud_context_get before relying on the omitted section")
    result["content"] = content
    if truncated:
        result["content_truncated"] = True
    return result


def _compact_role_scope(value):
    """Keep the applicable role instructions ahead of operational state."""
    if not isinstance(value, dict):
        return value
    result = {key: value.get(key) for key in (
        "actor", "role", "is_lead", "lead_director") if key in value}
    scopes = []
    for item in value.get("scopes") or []:
        if not isinstance(item, dict):
            continue
        scope = {key: item.get(key) for key in (
            "role", "version", "updated_by", "updated_owner", "updated_at")
                 if key in item}
        content, truncated = _head_tail_text(
            item.get("content"), 16_000,
            "call role_scope_get before relying on the omitted section")
        scope["content"] = content
        if truncated:
            scope["content_truncated"] = True
        scopes.append(scope)
    result["scopes"] = scopes
    effective, effective_truncated = _head_tail_text(
        value.get("effective_content"), 24_000,
        "call role_scope_get before relying on the omitted section")
    result["effective_content"] = effective
    if effective_truncated:
        result["effective_content_truncated"] = True
    return result


def _compact_handoff(value):
    if not isinstance(value, dict):
        return value
    result = {}
    for key, raw in value.items():
        compact, truncated = _head_tail_text(
            raw, 1_000,
            "call get_handoff before relying on the omitted text")
        result[key] = compact
        if truncated:
            result[key + "_truncated"] = True
    return result


def _compact_rule_view(rule):
    result = {key: rule.get(key) for key in (
        "project_id", "rule_id", "scope", "priority", "enabled", "version",
        "created_by", "created_owner", "created_at",
        "updated_by", "updated_owner", "updated_at") if key in rule}
    title, title_truncated = _head_tail_text(
        rule.get("title"), 180, "call rule_list for the complete title")
    body, body_truncated = _head_tail_text(
        rule.get("body"), 2_000,
        "call rule_list before acting on this truncated binding rule")
    result.update({"title": title, "body": body})
    if title_truncated:
        result["title_truncated"] = True
    if body_truncated:
        result["body_truncated"] = True
    return result


def _compact_rule_projection(rules, max_characters=16_000):
    """Keep a bounded rule projection plus the exact omitted rule ids."""
    source = [rule for rule in (rules or []) if isinstance(rule, dict)]
    result = []
    omitted_ids = []
    for index, rule in enumerate(source):
        candidate = _compact_rule_view(rule)
        projected = json.dumps(
            result + [candidate], separators=(",", ":"), ensure_ascii=False)
        if len(projected.encode("utf-8")) > max_characters:
            omitted_ids.extend(
                str(item.get("rule_id") or "<missing-rule-id>")
                for item in source[index:])
            break
        result.append(candidate)
    return result, omitted_ids


def _compact_rule_list(rules, max_characters=16_000):
    """Compatibility wrapper returning the historical omission count."""
    result, omitted_ids = _compact_rule_projection(
        rules, max_characters=max_characters)
    return result, len(omitted_ids)


def _compact_activity(rows):
    result = []
    for row in list(rows or [])[-8:]:
        if isinstance(row, dict):
            item = {}
            for key in ("event_id", "seq", "event_type", "actor", "at",
                        "task_id", "summary"):
                if key not in row:
                    continue
                value = row.get(key)
                if isinstance(value, str):
                    value, truncated = _head_tail_text(
                        value, 300,
                        "call search/get_project_log for the complete event")
                    if truncated:
                        item[key + "_truncated"] = True
                item[key] = value
            result.append(item)
        else:
            value, _ = _head_tail_text(
                row, 300, "call get_project_log for the complete event")
            result.append(value)
    return result


def _task_view(task):
    result = {key: task.get(key) for key in (
        "task_id", "title", "status", "claimed_by", "lease_until",
        "lease_expired", "risk_level", "updated_at")}
    title, truncated = _head_tail_text(
        result.get("title"), 180, "call task_show for the complete title")
    result["title"] = title
    if truncated:
        result["title_truncated"] = True
    return result


def _decision_view(decision):
    """Keep durable decision meaning without injecting its full event history."""
    result = {key: decision.get(key) for key in (
        "decision_id", "title", "status", "detail", "rationale",
        "proposed_by", "resolved_by", "created_at", "resolved_at")}
    for key, limit in (("title", 180), ("detail", 350),
                       ("rationale", 350)):
        compact, truncated = _head_tail_text(
            result.get(key), limit,
            "call decision_list/search for the complete decision")
        result[key] = compact
        if truncated:
            result[key + "_truncated"] = True
    return result


def _current_actor_record(snapshot):
    """Return the effective actor's authoritative role-bearing record.

    ``agent_list`` is deliberately paginated.  The current actor can therefore
    be absent from its first page in a large workspace even though the hosted
    ``attacca_status`` response resolved that exact actor successfully.  Use a
    matching list row when present, then fall back to the server-owned
    ``you.identity`` projection instead of treating page omission as an
    unconfigured identity.
    """
    status = snapshot.get("status") or {}
    you = status.get("you") or {}
    actor_id = you.get("actor_id")
    agents = (snapshot.get("agents") or {}).get("agents") or []
    record = next((agent for agent in agents
                   if agent.get("agent_id") == actor_id), None)
    if record is not None:
        return record
    identity = you.get("identity")
    if not actor_id or not isinstance(identity, dict):
        return None
    return {
        "agent_id": actor_id,
        "role": identity.get("role"),
        "runtime": identity.get("runtime"),
        "owner": identity.get("owner"),
        "status_identity_projection": True,
    }


def _needs_role_setup(snapshot):
    status = snapshot.get("status") or {}
    you = status.get("you") or {}
    if you.get("actor_type") != "agent" or not you.get("actor_id"):
        return False
    record = _current_actor_record(snapshot) or {}
    role = str(record.get("role") or "").strip().lower()
    return role not in CONFIGURED_AI_ROLES


def _mandatory_rules_banner(rules, pre_omitted=0, pre_omitted_ids=None):
    """Render only whole binding rules and name every omitted rule id."""
    applicable = [r for r in (rules or []) if r.get("enabled", True)]
    pre_ids = [str(value) for value in (pre_omitted_ids or []) if value]
    missing_pre_ids = max(0, int(pre_omitted or 0) - len(pre_ids))
    pre_ids.extend("<legacy-omitted-%d>" % (index + 1)
                   for index in range(missing_pre_ids))
    if not applicable and not pre_ids:
        return None
    applicable = sorted(
        applicable,
        key=lambda r: (r.get("priority", 100), str(r.get("rule_id") or "")))
    header = [
        "===================== ATTACCA MANDATORY PROJECT RULES ====================",
        "BINDING on EVERY response \u2014 do not bypass. Re-pinned every turn; if this",
        "section is ever missing from your context, call rule_list before acting.",
        "",
    ]
    footer = "=========================================================================="
    included = []
    omitted_ids = list(pre_ids)

    def omission_lines(ids):
        if not ids:
            return []
        return [
            "\u2022 Omitted binding rule_ids: %s" % ", ".join(ids),
            "    STOP before other work and call rule_list for those exact "
            "rule_ids; every omitted rule remains binding.",
        ]

    def render(blocks, ids):
        lines = list(header)
        for block in blocks:
            lines.extend(block)
        lines.extend(omission_lines(ids))
        lines.append(footer)
        return "\n".join(lines)

    for rule in applicable:
        rule_id = str(rule.get("rule_id") or "<missing-rule-id>")
        # Cached projections say explicitly when text was shortened. Never
        # present that partial text as if it were a complete binding rule.
        if rule.get("title_truncated") or rule.get("body_truncated"):
            omitted_ids.append(rule_id)
            continue
        body = " ".join(str(rule.get("body") or "").split())
        title = " ".join(str(rule.get("title") or "").split())
        rule_lines = ["\u2022 [%s \u00b7 priority %s \u00b7 %s] %s" % (
            rule_id, rule.get("priority"), rule.get("scope"), title),
            "    %s" % body]
        if len(render(included + [rule_lines], omitted_ids).encode(
                "utf-8")) <= MANDATORY_RULES_BANNER_MAX_CHARACTERS:
            included.append(rule_lines)
        else:
            omitted_ids.append(rule_id)

    # Exact omitted IDs consume budget too. Remove complete trailing rules,
    # never bytes from a rule, until the hard host cap is respected.
    banner = render(included, omitted_ids)
    while included and len(banner.encode("utf-8")) > \
            MANDATORY_RULES_BANNER_MAX_CHARACTERS:
        removed = included.pop()
        match = re.match(r"^\u2022 \[([^ \u00b7]+)", removed[0])
        omitted_ids.append(match.group(1) if match else "<missing-rule-id>")
        banner = render(included, omitted_ids)
    if len(banner.encode("utf-8")) > \
            MANDATORY_RULES_BANNER_MAX_CHARACTERS:
        raise RuntimeError(
            "mandatory rule_id list exceeds the hook context budget")
    return banner


def _poll_view(snapshot):
    """Stable shared-state markers used to suppress no-change hook output."""
    handoff = snapshot.get("handoff") or {}
    room = snapshot.get("room") or {}
    tasks = snapshot.get("tasks") or {}
    status = snapshot.get("status") or {}
    rules = snapshot.get("rules") or {}
    compact_rules, omitted_rule_ids = _compact_rule_projection(
        rules.get("rules") or [])
    return {
        # Exclude handoff.your_inbox and recent_activity: the startup poll marks
        # inbox rows read and registers its actor, so those transient values
        # would otherwise manufacture a change on the first periodic poll.
        "context_version": handoff.get("context_version"),
        "lead_director": handoff.get("lead_director"),
        "handoff": handoff.get("handoff"),
        "decisions": handoff.get("decisions") or [],
        "project_rules": compact_rules,
        "project_rules_omitted_count": len(omitted_rule_ids),
        "project_rules_omitted_ids": omitted_rule_ids,
        "cloud_context": _compact_cloud_context(
            (snapshot.get("cloud_context") or {}).get("cloud_context")
            if isinstance(snapshot.get("cloud_context"), dict)
            else handoff.get("cloud_context")),
        "role_scope": _compact_role_scope(snapshot.get("role_scope")),
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

    def messages(rows, limit, body_limit=180, newest=True):
        rows = list(rows or [])
        selected = rows[-limit:] if newest else rows[:limit]
        result = []
        for row in selected:
            body = str(row.get("body") or "")
            if body_limit is None:
                rendered_body, body_truncated = body, False
            else:
                rendered_body, body_truncated = _head_tail_text(
                    body, body_limit,
                    "call room_read with since_seq=%s before relying on the "
                    "omitted message text" % max(
                        0, int(row.get("seq") or 1) - 1))
            result.append({"event_id": row.get("event_id"),
                 "seq": row.get("seq"), "actor": row.get("actor"),
                 "type": row.get("msg_type"),
                 "body": rendered_body,
                 "body_truncated": body_truncated,
                 "task_id": row.get("task_id"),
                 "mentions": row.get("mentions"),
                 "reply_to": row.get("reply_to"),
                 "addressed_to_you": row.get("addressed_to_you"),
                 "broadcast_to_everyone": row.get(
                     "broadcast_to_everyone"),
                 "group_context": row.get("group_context"),
                 "origin_project": row.get("origin_project"),
                 "authority": row.get("authority"),
                 "mirrored_to": row.get("mirrored_to")}
            )
        return result

    status = snapshot.get("status") or {}
    actor_record = _current_actor_record(snapshot) or {}
    # check_inbox is oldest-first. Never take a suffix of a page whose cursor
    # has already advanced; doing so would silently discard earlier group chat.
    all_unread_rows = list(inbox.get("messages") or [])
    unread_rows = all_unread_rows[:STARTUP_INBOX_PAGE_SIZE]
    unread_keys = {_message_key(row) for row in unread_rows}
    recent_rows = [row for row in (room.get("messages") or [])
                   if _message_key(row) not in unread_keys]
    unread_messages = messages(
        unread_rows, max(1, len(unread_rows)),
        body_limit=STARTUP_UNREAD_BODY_LIMIT, newest=False)
    decision_rows = [item for item in (handoff.get("decisions") or [])
                     if isinstance(item, dict)]
    task_rows = [task for task in (tasks.get("tasks") or [])
                 if task.get("status") not in ("done", "cancelled")]
    compact_rules, omitted_rule_ids = _compact_rule_projection(
        rules.get("rules") or [])
    return {
        "project": snapshot.get("project"),
        "checked_at": snapshot.get("checked_at"),
        "context_version": handoff.get("context_version"),
        # Rules and Cloud Context stay ahead of verbose operational state so
        # host-side context limits cannot silently drop the project's law and
        # durable background after a long decision/task history.
        "project_rules": compact_rules,
        "project_rules_omitted_count": len(omitted_rule_ids),
        "project_rules_omitted_ids": omitted_rule_ids,
        "project_rules_next_action": (
            "STOP before other work and call rule_list; omitted rules remain "
            "binding." if omitted_rule_ids else None),
        "room_protocol": (
            "This is a group conversation. Read every unread_room message. "
            "Mentions/replies assign the expected responder, not visibility; "
            "chat/directive with neither is broadcast to everyone. Retain "
            "relevant context even when no action is assigned."),
        "cloud_context": _compact_cloud_context(
            (snapshot.get("cloud_context") or {}).get("cloud_context")
            if isinstance(snapshot.get("cloud_context"), dict)
            else handoff.get("cloud_context")),
        "role_scope": _compact_role_scope(snapshot.get("role_scope")),
        "lead_director": handoff.get("lead_director"),
        "handoff": _compact_handoff(handoff.get("handoff")),
        "unread_room": unread_messages,
        "unread_room_counts": {
            "total": inbox.get("unread_total", len(unread_messages)),
            "addressed": inbox.get("unread_addressed"),
            "direct": inbox.get("unread_direct"),
            "everyone": inbox.get("unread_everyone"),
            "group_context": inbox.get("unread_group_context"),
        },
        "unread_room_may_have_more": bool(
            inbox.get("may_have_more") or
            len(all_unread_rows) > len(unread_rows)),
        "unread_room_next_action": (
            "Call check_inbox again before other work; more unread group "
            "messages remain behind this page."
            if (inbox.get("may_have_more") or
                len(all_unread_rows) > len(unread_rows)) else None),
        "decisions": [_decision_view(item) for item in decision_rows[:10]],
        "decisions_total": len(decision_rows),
        "decisions_truncated": len(decision_rows) > 10,
        "decisions_next_action": (
            "Call decision_list for the omitted durable decisions."
            if len(decision_rows) > 10 else None),
        "recent_activity": _compact_activity(
            handoff.get("recent_activity")),
        "recent_room": messages(recent_rows, 20, body_limit=180),
        "tasks": [_task_view(task) for task in task_rows[:25]],
        "tasks_total": len(task_rows),
        "tasks_truncated": len(task_rows) > 25,
        "tasks_next_action": (
            "Call task_list for the omitted open tasks."
            if len(task_rows) > 25 else None),
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
        # Resolve/register the exact actor before fetching any role-scoped
        # governance.  Everything after this point follows the durable startup
        # order: rules, cloud context, role scope, identity handoff, history,
        # and finally volatile collaboration state.
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "agent_list", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "rule_list", "arguments": {
             "limit": STARTUP_RULE_PAGE_SIZE, "offset": 0}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "cloud_context_get", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
         "params": {"name": "role_scope_get", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
         "params": {"name": "get_handoff", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
         "params": {"name": "get_project_log", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
         "params": {"name": "check_inbox",
                    "arguments": {"mark_read": bool(mark_inbox_read),
                                  "limit": STARTUP_INBOX_PAGE_SIZE}}},
        {"jsonrpc": "2.0", "id": 10, "method": "tools/call",
         "params": {"name": "room_read", "arguments": {"limit": 50}}},
        {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
         "params": {"name": "task_list", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 12, "method": "tools/call",
         "params": {"name": "attacca_status", "arguments": {}}},
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

    def tool_result(request_id, response_map=None):
        selected_responses = responses if response_map is None else response_map
        response = selected_responses.get(request_id) or {}
        if response.get("error"):
            error = response["error"]
            data = error.get("data") if isinstance(error, dict) else None
            status_code = (data or {}).get("http_status") \
                if isinstance(data, dict) else None
            message = error.get("message") if isinstance(error, dict) \
                else str(error)
            if status_code in (401, 403):
                raise HostedAuthenticationRequired(
                    message or "Attacca rejected this credential",
                    http_status=status_code)
            raise RuntimeError(message or str(error))
        result = response.get("result") or {}
        if result.get("isError"):
            message = result.get("content", [{}])[0].get(
                "text", "Attacca MCP tool failed")
            raise RuntimeError(message)
        return json.loads(result["content"][0]["text"])

    def complete_rules(first_page):
        """Drain every binding-rule page or reject the connected snapshot.

        ``rule_list`` is capped at sixty rows like every long collection, but
        lifecycle law cannot use ordinary best-effort pagination: a rule on a
        later page is just as binding as one on page one.  Fetch the remaining
        known offsets in one additional MCP connection, verify a stable exact
        collection, and fail closed on malformed, moving, or over-bound data.
        """
        if not isinstance(first_page, dict):
            raise RuntimeError("rule_list returned an invalid first page")
        rows = first_page.get("rules")
        try:
            total = int(first_page["total"])
            limit = int(first_page["limit"])
            offset = int(first_page["offset"])
        except (KeyError, TypeError, ValueError):
            raise RuntimeError(
                "rule_list pagination metadata is missing or invalid")
        if not isinstance(rows, list) or offset != 0 \
                or limit != STARTUP_RULE_PAGE_SIZE \
                or total < len(rows) or len(rows) > limit:
            raise RuntimeError("rule_list returned an inconsistent first page")
        maximum = STARTUP_RULE_PAGE_SIZE * STARTUP_RULE_MAX_PAGES
        if total > maximum:
            raise RuntimeError(
                "rule_list contains %d applicable rules, above the startup "
                "safety bound of %d; refusing a partial binding-law snapshot"
                % (total, maximum))
        expected_more = len(rows) < total
        if bool(first_page.get("has_more")) != expected_more:
            raise RuntimeError("rule_list first-page has_more is inconsistent")
        if not expected_more:
            return first_page

        page_offsets = list(range(limit, total, limit))
        page_requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "attacca-session-hook",
                                       "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        ]
        request_ids = []
        for index, page_offset in enumerate(page_offsets):
            request_id = 100 + index
            request_ids.append(request_id)
            page_requests.append({
                "jsonrpc": "2.0", "id": request_id,
                "method": "tools/call",
                "params": {"name": "rule_list", "arguments": {
                    "limit": STARTUP_RULE_PAGE_SIZE,
                    "offset": page_offset}},
            })
        page_proc = subprocess.run(
            [sys.executable, str(plugin_root / "attacca.py"), "connect",
             "--url", config["url"]], cwd=status["root"], env=env,
            input="\n".join(json.dumps(item) for item in page_requests) + "\n",
            capture_output=True, text=True,
            timeout=max(4, min(20, 4 + len(page_offsets))))
        if page_proc.returncode != 0:
            raise RuntimeError(
                page_proc.stderr.strip() or
                "MCP rule paging exited %d" % page_proc.returncode)
        page_responses = {}
        for line in page_proc.stdout.splitlines():
            value = json.loads(line)
            if isinstance(value, dict) and value.get("id") is not None:
                page_responses[value["id"]] = value

        all_rows = list(rows)
        for index, (request_id, page_offset) in enumerate(
                zip(request_ids, page_offsets)):
            page = tool_result(request_id, page_responses)
            page_rows = page.get("rules") if isinstance(page, dict) else None
            try:
                page_total = int(page["total"])
                page_limit = int(page["limit"])
                returned_offset = int(page["offset"])
            except (KeyError, TypeError, ValueError):
                raise RuntimeError(
                    "rule_list continuation metadata is missing or invalid")
            expected_page_more = page_offset + len(page_rows or []) < total
            if not isinstance(page_rows, list) \
                    or page_total != total \
                    or page_limit != limit \
                    or returned_offset != page_offset \
                    or len(page_rows) > limit \
                    or bool(page.get("has_more")) != expected_page_more:
                raise RuntimeError(
                    "rule_list changed or returned an inconsistent page at "
                    "offset %d; refusing a partial binding-law snapshot"
                    % page_offset)
            all_rows.extend(page_rows)
        if len(all_rows) != total:
            raise RuntimeError(
                "rule_list returned %d of %d applicable rules; refusing a "
                "partial binding-law snapshot" % (len(all_rows), total))
        rule_ids = [str(row.get("rule_id") or "")
                    for row in all_rows if isinstance(row, dict)]
        if len(rule_ids) != total or any(not value for value in rule_ids) \
                or len(set(rule_ids)) != total:
            raise RuntimeError(
                "rule_list returned missing or duplicate rule ids; refusing "
                "a partial binding-law snapshot")
        complete = dict(first_page)
        complete.update({"rules": all_rows, "offset": 0,
                         "has_more": False})
        return complete

    project_page = tool_result(2)
    projects = project_page.get("projects") or []
    current_status = None
    if status["project_id"] not in {p.get("project_id") for p in projects}:
        # list_projects is deliberately capped at 60.  A linked workspace can
        # therefore be absent from that first authorized page even though all
        # exact project-scoped startup calls succeeded.  attacca_status is an
        # exact current-workspace read, so use it as the authoritative
        # existence proof before diagnosing a stale checkout link.
        try:
            candidate_status = tool_result(12)
        except HostedAuthenticationRequired:
            raise
        except RuntimeError:
            candidate_status = None
        if isinstance(candidate_status, dict) and \
                candidate_status.get("project") == status["project_id"]:
            current_status = candidate_status
        else:
            known = ", ".join(p.get("name") or p.get("project_id")
                              for p in projects) or "none yet"
            qualifier = " (first page)" if project_page.get("has_more") else ""
            raise StaleProjectLink(
                "The saved workspace '%s' does not exist on the configured "
                "server. Available workspaces%s: %s."
                % (status["project_id"], qualifier, known))
    complete_rule_page = complete_rules(tool_result(4))
    return {
        "project": status["project_id"],
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "agents": tool_result(3),
        "rules": complete_rule_page,
        "cloud_context": tool_result(5),
        "role_scope": tool_result(6),
        "handoff": tool_result(7),
        "log": tool_result(8),
        "inbox": tool_result(9),
        "room": tool_result(10),
        "tasks": tool_result(11),
        "status": current_status or tool_result(12),
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


def _watcher_accept_synced_identity(entry, adapter):
    """Validate and copy a capability/visibility rebind after hosted sync.

    Projection capability negotiation legitimately changes the visibility
    fingerprint and mirror path.  It must not look like principal drift.  The
    new pair is accepted only when the proof and local snapshot agree, the
    server/project/human principal are stable, and the exact MCP-verified
    actor, role, and actor type are unchanged.
    """
    if adapter is None or not isinstance(entry, dict):
        raise RuntimeError("offline sync adapter/subscription is unavailable")
    protocol, offline, _ = _watcher_sync_modules()
    previous = protocol.validate_scope(entry.get("sync_scope"))
    proof_method = getattr(adapter, "convergence_proof", None)
    snapshot_method = getattr(adapter, "local_snapshot", None)
    if not callable(proof_method) or not callable(snapshot_method):
        raise RuntimeError(
            "offline adapter lacks proof or identity snapshot validation")
    proof = offline.validate_convergence_proof(
        proof_method(), expected_server_url=entry["server_url"],
        expected_project=entry["project_id"], require_online=False)
    scope = protocol.validate_scope(proof["scope"])
    stable = ("server_id", "project_id", "principal_id")
    if any(previous[name] != scope[name] for name in stable):
        raise RuntimeError(
            "synced mirror changed server, project, or human principal")
    if scope["project_id"] != entry.get("project_id") \
            or scope["actor_id"] != entry.get("canonical_actor_id") \
            or scope["role"] != entry.get("actor_role") \
            or scope["actor_type"] != "agent":
        raise RuntimeError(
            "synced mirror differs from the MCP-verified actor/role/type")
    capabilities = protocol.validate_projection_capabilities(
        proof["projection_capabilities"])
    visibility = protocol.validate_visibility_fingerprint(
        proof["visibility_fingerprint"])
    snapshot = protocol.validate_snapshot(
        snapshot_method(), expected_scope=scope,
        expected_visibility=visibility)
    protocol.validate_projection_for_capabilities(
        snapshot["projection"], scope, capabilities)
    digest = hashlib.sha256(
        protocol.canonical_json_bytes(snapshot)).hexdigest()
    if proof["snapshot_sha256"] != digest \
            or proof["cursor"] != snapshot["cursor"]:
        raise RuntimeError(
            "synced capability proof does not describe the local snapshot")
    status = _watcher_adapter_status(adapter)
    if status.get("scope") not in (None, scope) \
            or status.get("visibility_fingerprint") not in (None, visibility) \
            or status.get("projection_capabilities") not in (
                None, capabilities):
        raise RuntimeError(
            "synced adapter status differs from its capability proof")
    status_proof = status.get("convergence_proof")
    if status_proof is not None and status_proof != proof:
        raise RuntimeError("adapter status and convergence proof disagree")
    rebound = dict(entry)
    rebound.update({
        "sync_scope": scope,
        "sync_visibility_fingerprint": visibility,
        "sync_projection_capabilities": capabilities,
    })
    return rebound, proof, snapshot, status


def _watcher_validated_convergence(entry, adapter, require_online=False):
    """Bind a core proof to the exact subscription and on-disk snapshot."""
    if adapter is None or not isinstance(entry, dict):
        raise RuntimeError("offline sync adapter/subscription is unavailable")
    protocol, offline, _ = _watcher_sync_modules()
    identity = _watcher_validated_sync_scope(entry, protocol)
    if identity is None:
        raise RuntimeError("subscription has no authenticated sync identity")
    scope, visibility = identity
    capabilities = protocol.validate_projection_capabilities(
        entry.get("sync_projection_capabilities") or
        protocol.current_projection_capabilities())
    proof_method = getattr(adapter, "convergence_proof", None)
    snapshot_method = getattr(adapter, "local_snapshot", None)
    if not callable(proof_method) or not callable(snapshot_method):
        raise RuntimeError(
            "offline adapter lacks proof or identity snapshot validation")
    proof = offline.validate_convergence_proof(
        proof_method(), expected_server_url=entry["server_url"],
        expected_project=entry["project_id"], expected_scope=scope,
        expected_projection_capabilities=capabilities,
        require_online=require_online)
    if proof["visibility_fingerprint"] != visibility:
        raise RuntimeError(
            "convergence proof visibility differs from the subscription")
    try:
        snapshot = protocol.validate_snapshot(
            snapshot_method(), expected_scope=scope,
            expected_visibility=visibility)
        protocol.validate_projection_for_capabilities(
            snapshot["projection"], scope, capabilities)
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
                None, visibility) \
            or adapter_status.get("projection_capabilities") not in (
                None, capabilities):
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

    def compact_room(item):
        body, truncated = _head_tail_text(
            item.get("body"), STARTUP_UNREAD_BODY_LIMIT,
            "call room_read with since_seq=%s before relying on the omitted "
            "message text" % max(0, int(item.get("seq") or 1) - 1))
        return {"event_id": item.get("event_id"),
                "seq": item.get("seq"), "actor": (
                    item.get("actor") or item.get("actor_id")),
                "type": item.get("msg_type"),
                "body": body,
                "body_truncated": truncated,
                "task_id": item.get("task_id"),
                "mentions": item.get("mentions"),
                "reply_to": item.get("reply_to"),
                "addressed_to_you": item.get("addressed_to_you"),
                "broadcast_to_everyone": item.get(
                    "broadcast_to_everyone"),
                "group_context": item.get("group_context"),
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

    room_rows = [dict(item) for item in
                 (snapshot.get("room_messages") or [])
                 if isinstance(item, dict)]
    aliases = {actor_id}
    aliases.update(
        item.get("legacy_actor_id") for item in
        (snapshot.get("actor_aliases") or [])
        if isinstance(item, dict) and
        item.get("canonical_actor_id") == actor_id and
        item.get("legacy_actor_id"))
    by_id = {item.get("event_id"): item for item in room_rows}
    inbox_cursor = int(
        (snapshot.get("inbox_cursor") or {}).get("last_read_seq") or 0)
    unread_rows = []
    for item in room_rows:
        sender = item.get("actor") or item.get("actor_id")
        if int(item.get("seq") or 0) <= inbox_cursor or sender in aliases:
            continue
        mentions = set(item.get("mentions") or [])
        mentioned = bool(aliases.intersection(mentions))
        reply = by_id.get(item.get("reply_to")) or {}
        replied = bool(item.get("reply_to") and
                       (reply.get("actor") or reply.get("actor_id")) in aliases)
        broadcast = bool(
            item.get("msg_type") in ("chat", "directive") and
            not mentions and not item.get("reply_to"))
        addressed = mentioned or replied or broadcast
        item.update({
            "addressed_to_you": addressed,
            "broadcast_to_everyone": broadcast,
            "group_context": not addressed,
        })
        unread_rows.append(item)
    unread_page = unread_rows[:STARTUP_INBOX_PAGE_SIZE]
    unread_keys = {_message_key(item) for item in unread_page}
    recent_rows = [item for item in room_rows
                   if _message_key(item) not in unread_keys][-20:]
    compact_rules, omitted_rule_ids = _compact_rule_projection(rules)

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
        "project_rules": compact_rules,
        "project_rules_omitted_count": len(omitted_rule_ids),
        "project_rules_omitted_ids": omitted_rule_ids,
        "project_rules_next_action": (
            "STOP before other work and read cached rule_list; omitted rules "
            "remain binding." if omitted_rule_ids else None),
        # Cloud Context is part of the verified identity projection. Keep it
        # ahead of operational lists so a host context cap cannot erase the
        # project's durable background during an outage.
        "cloud_context": _compact_cloud_context(
            snapshot.get("cloud_context")),
        "room_protocol": (
            "The room is a group conversation. Read every visible message; "
            "mentions/replies assign attention, not visibility, and an "
            "unaddressed chat/directive is broadcast to everyone."),
        "unread_room": [compact_room(item) for item in unread_page],
        "unread_room_counts": {
            "total": len(unread_page),
            "addressed": sum(bool(item.get("addressed_to_you"))
                             for item in unread_page),
            "everyone": sum(bool(item.get("broadcast_to_everyone"))
                            for item in unread_page),
            "group_context": sum(bool(item.get("group_context"))
                                 for item in unread_page),
        },
        "unread_room_may_have_more": len(unread_rows) > len(unread_page),
        "unread_room_next_action": (
            "Call cached check_inbox again before other work; more unread "
            "group messages remain behind this page."
            if len(unread_rows) > len(unread_page) else None),
        "offline_read_cursor_deferred": True,
        "handoff": _compact_handoff(latest_handoff),
        "tasks": [_task_view(item) for item in
                  (snapshot.get("tasks") or [])[:50]
                  if isinstance(item, dict)],
        "decisions": [_decision_view(item) for item in
                      (snapshot.get("decisions") or [])[:20]
                      if isinstance(item, dict)],
        "recent_room": [compact_room(item) for item in recent_rows],
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
    # SessionStart/UserPromptSubmit inject the banner SILENTLY (additionalContext);
    # only a Stop turn renders it as a visible blocking-reason wall (worse here —
    # it would drag the full offline brief JSON along). Suppress the banner on
    # Stop only; the offline brief itself still reaches the AI on every turn.
    if event_name != "Stop":
        rules_banner = _mandatory_rules_banner(
            brief.get("project_rules"),
            pre_omitted=brief.get("project_rules_omitted_count"),
            pre_omitted_ids=brief.get("project_rules_omitted_ids"))
        if rules_banner:
            context = rules_banner + "\n\n" + context
    return _event_context_output(
        event_name,
        "Attacca offline · %s · verified local mirror active; work may continue"
        % status["project_id"], context)


def _authentication_required_error(error):
    """Latch authority off only for a proven hosted 401/403 response.

    Local key-store/schema failures, visibility changes, and cached identity
    validation errors are repairable sync failures, not proof that the host
    revoked this account. Treating their class names or message text as auth
    would incorrectly disable a still-valid verified offline mirror.
    """
    status = getattr(error, "http_status", None) \
        or getattr(error, "code", None) or getattr(error, "status", None)
    try:
        return int(status) in (401, 403)
    except (TypeError, ValueError):
        return False


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
    rules_banner = _mandatory_rules_banner(
        (snapshot.get("rules") or {}).get("rules"))
    if rules_banner:
        context = rules_banner + "\n\n" + context
    return _event_context_output(
        "SessionStart",
        "Attacca linked · %s · first-run AI role setup required"
        % status["project_id"], context)


CLAUDE_INBOX_LOOP_MARKER_PREFIX = "ATTACCA_MANAGED_INBOX_LOOP_V1:"
CLAUDE_INBOX_LOOP_CRONS = {"* * * * *", "*/1 * * * *"}


def _claude_inbox_loop_marker(project_id):
    return "%s%s" % (CLAUDE_INBOX_LOOP_MARKER_PREFIX, project_id)


def _claude_inbox_loop_prompt(project_id):
    return "/attacca:inbox [%s]" % _claude_inbox_loop_marker(project_id)


def _claude_loop_status(payload, project_id):
    """Classify Claude-owned cron rows without touching unrelated jobs."""
    rows = (payload or {}).get("session_crons")
    if not isinstance(rows, list):
        return None
    marker = _claude_inbox_loop_marker(project_id)
    prompt = _claude_inbox_loop_prompt(project_id)
    managed = []
    exact = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        row_prompt = str(row.get("prompt") or "")
        if CLAUDE_INBOX_LOOP_MARKER_PREFIX not in row_prompt:
            continue
        managed.append(row)
        schedule = str(row.get("cron") or row.get("schedule") or "").strip()
        recurring = row.get("recurring") is not False
        if marker in row_prompt and row_prompt.strip() == prompt \
                and schedule in CLAUDE_INBOX_LOOP_CRONS and recurring:
            exact.append(row)
    return {"rows": rows, "managed": managed, "exact": exact,
            "healthy": len(managed) == 1 and len(exact) == 1}


def _claude_loop_disabled():
    return str(os.environ.get("CLAUDE_CODE_DISABLE_CRON") or "").strip() \
        .lower() in ("1", "true", "yes", "on")


def _claude_session_loop_notice(status, interval, payload=None):
    """Ask real Claude sessions to maintain one native one-minute inbox job.

    Claude's ``/loop`` jobs live inside the current coding session, unlike
    Attacca's machine-global watcher.  A lifecycle hook cannot call Claude's
    host-owned Cron tools itself, so every fresh/resumed SessionStart injects
    an idempotent agent instruction: inspect existing jobs, create the missing
    one, and remove only duplicate Attacca-managed jobs.  Codex deliberately
    also exports ``CLAUDE_PLUGIN_ROOT`` for hook compatibility; runtime
    detection keeps this contract out of Codex and Kimi sessions.
    """
    if _runtime_name() != "claude":
        return None
    project_id = status["project_id"]
    loop_status = _claude_loop_status(payload, project_id)
    disabled = _claude_loop_disabled() or interval == 0
    if disabled:
        reason = "CLAUDE_CODE_DISABLE_CRON is set" \
            if _claude_loop_disabled() else "Attacca background polling is Off"
        return {
            "system_message": "Attacca Claude one-minute loop disabled by host",
            "context": (
                "ATTACCA CLAUDE SESSION LOOP DISABLED: %s. Do not change that "
                "user choice. If CronList remains available, use CronDelete "
                "to remove only jobs whose prompt "
                "contains `%s`; leave every unrelated job untouched. The "
                "machine-global Attacca watcher remains the independent "
                "continuity "
                "path when polling is enabled; an inactive Claude session "
                "cannot be forced to generate a turn." %
                (reason, CLAUDE_INBOX_LOOP_MARKER_PREFIX)),
        }
    if loop_status and loop_status["healthy"]:
        return None
    prompt = _claude_inbox_loop_prompt(project_id)
    return {
        "system_message": "Attacca Claude one-minute inbox loop required",
        "context": (
            "ATTACCA CLAUDE SESSION LOOP — ESTABLISH NOW: Before continuing "
            "with the user's work, use Claude's CronList tool and ensure "
            "exactly one recurring session job exists with cron expression "
            "`* * * * *` whose exact prompt is `%s`. Delete only stale or "
            "duplicate jobs containing `%s` with CronDelete, never unrelated "
            "jobs. If the "
            "current job is absent, create it with CronCreate using "
            "recurring=true and durable=true when the host accepts durable "
            "jobs; otherwise create the session-only recurring job. Do not "
            "ask the user to run the command. This is the managed equivalent "
            "of `/loop 1m /attacca:inbox`. Claude "
            "jobs are session-scoped, so this check is intentionally repeated "
            "on every startup/resume/clear/compact. If those Cron tools are "
            "unavailable, state that once and rely on the already-running "
            "machine-global Attacca watcher; never claim the Claude loop was "
            "created without tool confirmation." %
            (prompt, CLAUDE_INBOX_LOOP_MARKER_PREFIX)),
    }


def _claude_stop_loop_notice(status, payload, interval):
    """Block one Stop per session when Claude reports a missing managed job."""
    if _runtime_name() != "claude" or _claude_loop_disabled() or interval == 0:
        return None
    loop_status = _claude_loop_status(payload, status["project_id"])
    session_id = str((payload or {}).get("session_id") or "").strip()
    if loop_status is None or not session_id:
        return None
    key = "%s:%s" % (status["project_id"], session_id)
    state_path = Path(status["state_path"])
    if loop_status["healthy"]:
        def clear_attempt(state):
            attempts = state.get("claude_loop_attempts") or {}
            attempts.pop(key, None)
            if attempts:
                state["claude_loop_attempts"] = attempts
            else:
                state.pop("claude_loop_attempts", None)
        _mutate_state(state_path, clear_attempt)
        return None
    already_attempted = bool(
        (_read_state(state_path).get("claude_loop_attempts") or {}).get(key))
    if already_attempted:
        return None

    def record_attempt(state):
        attempts = state.setdefault("claude_loop_attempts", {})
        attempts[key] = {
            "attempted_at": datetime.now(timezone.utc).isoformat(),
            "project_id": status["project_id"],
        }
        if len(attempts) > 64:
            for stale_key in sorted(
                    attempts,
                    key=lambda item: str(
                        (attempts.get(item) or {}).get("attempted_at") or ""))[
                            :-64]:
                attempts.pop(stale_key, None)
    _mutate_state(state_path, record_attempt)
    return _claude_session_loop_notice(status, interval, payload={})


def _active_output(status, offline_adapter=None, offline_factory=None,
                   hook_payload=None):
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
    claude_loop_notice = _claude_session_loop_notice(
        status, interval, payload=hook_payload)
    pending_notice = _watcher_pending_notice(status, config)
    offline_key, offline_entry = _watcher_subscription_entry(status, config)
    inbox_check_notice = None
    try:
        _watcher_refresh_inbox_attention(status, config)
    except Exception as err:
        inbox_check_notice = {
            "system_message": "Attacca automatic inbox check will retry",
            "context": (
                "ATTACCA AUTOMATIC INBOX CHECK FAILED: %s. Previously staged "
                "mail remains pinned and the per-minute watcher will retry; "
                "do not assume an empty inbox." % _trim(err, 240)),
        }
    attention_notice = _watcher_attention_notice(
        status, config, consume=False)
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
        cloud_context_notice = _refresh_cloud_context_from_snapshot(
            status, plugin_root, snapshot, create=True)
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
claim/create the relevant Attacca task. The project room is a group conversation:
read every message in unread_room and recent_room, including messages mentioning
or replying to another participant. Mentions/replies identify the expected
responder; they never limit visibility. A chat or directive with neither is sent
to everyone. Consider relevant design and context changes even when no action is
assigned. If any later Attacca response reports stale_context_warning, reload the
handoff before further writes.

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
        # Deliver the durable watcher FIFO first so lower-priority update and
        # migration notices cannot consume its reserved context budget.
        output = _append_notice(output, pending_notice)
        output = _append_notice(
            output, _refresh_managed_laws(status, plugin_root, config=config))
        output = _append_notice(output, cloud_context_notice)
        output = _append_notice(
            output, update_notice)
        output = _append_notice(output, watcher_notice)
        output = _append_notice(output, claude_loop_notice)
        output = _append_notice(output, terminal_notice)
        output = _append_notice(output, inbox_check_notice)
        # Append last: _insert_after_rules_banner places the newest notice
        # directly after the mandatory rules, making unread mail the first
        # operational content at every supported turn boundary.
        attention_notice = _watcher_attention_notice(status, config)
        output = _append_notice(output, attention_notice)
        return output
    except StaleProjectLink as err:
        set_offered(status["root"], stale_project_id=status["project_id"])
        output = _hook_output(status, recovery_reason=str(err))
        return _append_notices(
            output, "SessionStart",
            (update_notice, watcher_notice, claude_loop_notice,
             terminal_notice, pending_notice, inbox_check_notice))
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
            attention_notice = _watcher_attention_notice(status, config)
            output = _offline_failure_output(
                status, config, "SessionStart", err, offline_adapter,
                entry=offline_entry)
            if output is None:
                output = _failure_output(status, config, "SessionStart", err)
            trailing_notices = (
                pending_notice, update_notice, watcher_notice,
                claude_loop_notice, terminal_notice, inbox_check_notice,
                attention_notice)
        if auth_blocked:
            trailing_notices = trailing_notices + (claude_loop_notice,)
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
    if previous.get("cloud_context") != current.get("cloud_context"):
        cloud_context = current.get("cloud_context") or {}
        content = str(cloud_context.get("content") or "")
        updated = "Cloud Context changed to v%s" % (
            cloud_context.get("version") or "?")
        if content:
            updated += (
                "; this refreshed text is authoritative for the current "
                "session:\n\n%s\n\n[END ATTACCA CLOUD CONTEXT]" % content)
        else:
            updated += "; the authoritative context is now empty"
        details.append(updated)

    group_details = []
    inbox_keys = {_message_key(message) for message in inbox_messages}
    for message in inbox_messages[-100:]:
        source = " from %s" % message["origin_project"] \
            if message.get("origin_project") else ""
        authority = " [%s]" % message["authority"] \
            if message.get("authority") else ""
        if message.get("broadcast_to_everyone"):
            label = "Everyone room broadcast"
        elif message.get("directed_to_you"):
            label = "Direct room message"
        else:
            label = "Group room context"
        body = str(message.get("body") or "")
        excerpt, _ = _head_tail_text(
            body, WATCHER_ROOM_BODY_LIMIT,
            "call room_read with since_seq=%s for the complete message" %
            max(0, int(message.get("seq") or 1) - 1))
        group_details.append("%s #%s%s%s · %s: %s" % (
            label,
            message.get("seq") or "?", source, authority,
            message.get("actor") or "unknown", excerpt))
    old_room = set(previous.get("room_keys") or [])
    new_room = [message for message in
                ((snapshot.get("room") or {}).get("messages") or [])
                if _message_key(message) not in old_room
                and _message_key(message) not in inbox_keys]
    # Backward compatibility: older servers put non-addressed room messages
    # only in room_read. Surface every new visible one until the all-group
    # inbox contract is available, then inbox_keys deduplicates this path.
    for message in new_room[-100:]:
        source = " from %s" % message["origin_project"] \
            if message.get("origin_project") else ""
        target = " to %s" % ", ".join(message.get("mirrored_to") or []) \
            if message.get("mirrored_to") else ""
        body = str(message.get("body") or "")
        excerpt, _ = _head_tail_text(
            body, WATCHER_ROOM_BODY_LIMIT,
            "call room_read with since_seq=%s for the complete message" %
            max(0, int(message.get("seq") or 1) - 1))
        group_details.append("Group room context #%s%s%s · %s: %s" % (
            message.get("seq") or "?", source, target,
            message.get("actor") or "unknown", excerpt))

    task_lines = _task_change_lines(previous.get("tasks"), current.get("tasks"))
    if task_lines:
        details.append("Tasks: " + "; ".join(task_lines[:4]))
    if not details and not group_details:
        old_events = (previous.get("counts") or {}).get("events") or 0
        new_events = (current.get("counts") or {}).get("events") or 0
        delta = max(0, new_events - old_events)
        details.append("Shared activity changed%s." % (
            " (%d new ledger event%s)" % (delta, "" if delta == 1 else "s")
            if delta else ""))

    # Room content comes first and is never collapsed to a count. Operational
    # state remains compact behind it so an active hook cannot hide a group
    # design/directive message merely because the task board also changed.
    details = group_details + details[:7]
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
                     offline_factory=None, hook_payload=None):
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
    _early_identity, early_poll_entry = _poll_entry(status, config)
    polling_disabled = bool(
        (offline_entry or {}).get("interval_seconds") == 0 or
        (early_poll_entry or {}).get("interval_seconds") == 0)
    interval = _settings_interval(config, entry=offline_entry)
    claude_loop_notice = _claude_stop_loop_notice(
        status, hook_payload, interval) if event_name == "Stop" else None
    inbox_check_notice = None
    if not polling_disabled:
        try:
            _watcher_refresh_inbox_attention(status, config)
        except Exception as err:
            inbox_check_notice = {
                "system_message": "Attacca automatic inbox check will retry",
                "context": (
                    "ATTACCA AUTOMATIC INBOX CHECK FAILED: %s. Previously "
                    "staged mail remains pinned and the per-minute watcher "
                    "will retry; do not assume an empty inbox." %
                    _trim(err, 240)),
            }
    attention_notice = _watcher_attention_notice(
        status, config, consume=False)
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
    notices = (pending_notice, watcher_notice, update_notice, terminal_notice,
               inbox_check_notice, claude_loop_notice, attention_notice)
    # A healthy daemon is the primary periodic path. Queued changes bypass the
    # old hook throttle and are delivered immediately; otherwise this boundary
    # stays quiet and leaves network polling to the autonomous watcher.
    if watcher_healthy and not is_kimi_prompt:
        # The healthy watcher owns network polling, but the mandatory
        # Project Rules must still be re-pinned at the start of every
        # response so they never fall out of a long conversation.
        banner_output = None
        # Rules are pinned SILENTLY at every UserPromptSubmit (additionalContext,
        # never displayed). Re-pinning them on Stop would surface as a visible
        # blocking-reason wall in the client chat, so Stop never emits the banner.
        if event_name == "UserPromptSubmit":
            _identity, _entry = _poll_entry(status, config)
            _snap = (_entry or {}).get("snapshot") or {}
            _rules_banner = _mandatory_rules_banner(
                _snap.get("project_rules"),
                pre_omitted=_snap.get("project_rules_omitted_count"),
                pre_omitted_ids=_snap.get("project_rules_omitted_ids"))
            if _rules_banner:
                banner_output = _event_context_output(
                    event_name,
                    "Attacca \u00b7 mandatory project rules pinned",
                    _rules_banner)
        notices = notices[:-1] + (
            _watcher_attention_notice(status, config),)
        return _append_notices(banner_output, event_name, notices)
    identity, entry = _poll_entry(status, config)
    cached_rules_output = None
    # Same rule as above: the banner is a UserPromptSubmit-only silent injection,
    # never a Stop blocking-reason (which the client renders as a visible wall).
    if event_name == "UserPromptSubmit":
        cached_poll = (entry or {}).get("snapshot") or {}
        cached_banner = _mandatory_rules_banner(
            cached_poll.get("project_rules"),
            pre_omitted=cached_poll.get("project_rules_omitted_count"),
            pre_omitted_ids=cached_poll.get("project_rules_omitted_ids"))
        if cached_banner:
            cached_rules_output = _event_context_output(
                event_name, "Attacca · mandatory project rules pinned",
                cached_banner)
    # Polling Off still allows Kimi's first native prompt to validate the link
    # and refresh managed laws once; subsequent prompts remain off.
    if interval == 0 and not (is_kimi_prompt and not entry):
        notices = notices[:-1] + (
            _watcher_attention_notice(status, config),)
        return _append_notices(cached_rules_output, event_name, notices)
    checked_at = time.time()
    last_poll_at = entry.get("last_poll_at")
    elapsed = checked_at - last_poll_at \
        if isinstance(last_poll_at, (int, float)) else None
    if elapsed is not None and 0 <= elapsed < interval:
        notices = notices[:-1] + (
            _watcher_attention_notice(status, config),)
        return _append_notices(cached_rules_output, event_name, notices)
    try:
        snapshot = _mcp_snapshot(status, plugin_root, config)
        _watcher_activate_after_mcp(status, config, snapshot)
        cloud_context_notice = _refresh_cloud_context_from_snapshot(
            status, plugin_root, snapshot, create=True)
        # Kimi has no command SessionStart hook. Refresh laws only after the
        # saved workspace has been validated by the successful MCP snapshot.
        law_notice = _refresh_managed_laws(
            status, plugin_root, config=config) \
            if is_kimi_prompt else None
        notices = (law_notice, cloud_context_notice, update_notice,
                   terminal_notice,
                   inbox_check_notice,
                   _watcher_attention_notice(status, config))
        current = _poll_view(snapshot)
        previous = entry.get("snapshot") if entry else None
        _record_poll(status, identity, interval, checked_at, current)
        rules_output = None
        if event_name == "UserPromptSubmit":
            rules_banner = _mandatory_rules_banner(
                (snapshot.get("rules") or {}).get("rules"))
            if rules_banner:
                rules_output = _event_context_output(
                    event_name,
                    "Attacca · mandatory project rules pinned",
                    rules_banner)
        summary = _change_summary(status, previous, current, snapshot, interval)
        # On Stop we deliver only a genuine change summary (short), never the
        # rules banner — that stays a UserPromptSubmit-only silent injection so
        # the client chat is not flooded with a re-pinned wall every turn.
        if not summary:
            return _append_notices(rules_output, event_name, notices)
        if rules_output:
            output = _append_notice(rules_output, {
                "system_message": "Attacca update · shared project state changed",
                "context": summary,
            })
        else:
            output = _event_context_output(
                event_name,
                "Attacca update · shared project state changed", summary)
        return _append_notices(output, event_name, notices)
    except StaleProjectLink as err:
        set_offered(status["root"], stale_project_id=status["project_id"])
        output = _hook_output(status, recovery_reason=str(err),
                              event_name=event_name)
        return _append_notices(
            output, event_name,
            tuple(notice for notice in notices
                  if notice is not attention_notice))
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
            notices = notices[:-1] + (
                _watcher_attention_notice(status, config),)
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
        output = _active_output(
            result, hook_payload=payload) if event_name == "SessionStart" \
            else _periodic_output(result, event_name, hook_payload=payload)
        if output:
            output = _with_migration_notice(output, migration)
            print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
