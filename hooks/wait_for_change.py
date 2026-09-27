#!/usr/bin/env python3
"""Quiet, local-only receiver for Claude Monitor and targeted Codex queues.

The machine watcher owns network transport. This process only observes its
private staged projection; emitting a signal never reads or disposes mail.
``--jsonl`` exposes the same change-only stdout channel as schema-v1 NDJSON.
It is not ROOM.md tailing and never emits a periodic heartbeat into AI input.
Receipts prove emission/queue acceptance only, never that an AI processed work.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import session_start as hook

HEARTBEAT_TTL_SECONDS = 120
REPAIR_BACKOFF_SECONDS = (60, 120, 300)
RECEIVER_STOP_TIMEOUT_SECONDS = 1.5


def _session_id(value):
    value = str(value or "")
    return value.lower() if re.fullmatch(
        r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value) else None


def _process_identity(pid):
    try:
        raw = Path("/proc/%d/stat" % int(pid)).read_text()
        fields = raw[raw.rfind(")") + 2:].split()
        return (int(pid), fields[19]) if fields[0] != "Z" else None
    except (OSError, ValueError, IndexError, TypeError):
        return None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _source_generation():
    fingerprint = hashlib.sha256()
    for name in ("wait_for_change.py", "codex_wake.py", "session_start.py"):
        fingerprint.update(name.encode("utf-8"))
        try:
            fingerprint.update(Path(__file__).with_name(name).read_bytes())
        except OSError:
            fingerprint.update(b"missing")
    return fingerprint.hexdigest()


RECEIVER_GENERATION = _source_generation()


def host_process(runtime):
    """Find the owning CLI on Linux; never guess a different session."""
    pid = os.getppid()
    for _ in range(20):
        try:
            raw = Path("/proc/%d/stat" % pid).read_text()
            fields = raw[raw.rfind(")") + 2:].split()
            command = Path("/proc/%d/cmdline" % pid).read_bytes().split(b"\0")
            names = [Path(os.fsdecode(x)).name for x in command[:2]]
            if runtime in names or (runtime == "claude" and "claude-code" in names):
                return pid, fields[19]
            pid = int(fields[1])
            if pid <= 1:
                break
        except (OSError, ValueError, IndexError):
            break
    return None


def host_alive(identity):
    if identity is None:
        return True  # A native Monitor host owns/terminates its child process.
    try:
        raw = Path("/proc/%d/stat" % identity[0]).read_text()
        fields = raw[raw.rfind(")") + 2:].split()
        return fields[0] != "Z" and fields[19] == identity[1]
    except (OSError, IndexError):
        return False


def _registration_path(cwd, runtime, parent):
    return hook._watcher_state_path().parent / "wake-sessions" / \
        digest([runtime, str(Path(cwd).resolve()), parent]) / hook.WATCHER_STATE_NAME


def register_session(cwd, runtime, session_id, parent=None):
    """Bind the hook's exact session to its actual CLI owner, without IO to hosts."""
    selected = _session_id(session_id)
    parent = parent or host_process(runtime)
    if runtime not in ("claude", "codex") or not selected or not parent:
        return {"registered": False, "reason": "exact_session_owner_unavailable"}
    hook._write_state(_registration_path(cwd, runtime, parent), {
        "schema_version": 1, "session_id": selected, "runtime": runtime,
        "parent": list(parent), "cwd": str(Path(cwd).resolve())})
    return {"registered": True, "session_id": selected}


def _registered_session(cwd, runtime, parent):
    if not parent:
        return None
    value = _read_receipt(_registration_path(cwd, runtime, parent))
    if value.get("parent") != list(parent) or value.get("runtime") != runtime \
            or value.get("cwd") != str(Path(cwd).resolve()):
        return None
    return _session_id(value.get("session_id"))


def _read_receipt(path):
    if not Path(path).parent.exists():
        return {}
    try:
        fd = hook._open_private_watcher_file(path, os.O_RDONLY)
    except FileNotFoundError:
        return {}
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("receiver receipt exceeds its size bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid receiver receipt")
    return value


def event_keys(entry):
    """Select actionable, never-rendered events without changing the ledger."""
    keys = set()
    own = hook._watcher_own_actor_ids(entry)
    rows = list(entry.get("pending_dispositions") or [])
    rows += [row for row in entry.get("attention") or []
             if not (row.get("acknowledged") and row.get("delivered_at"))]
    for row, mode, state in hook._watcher_render_plan(
            hook._watcher_render_ledger(entry), rows, False, ""):
        if mode != "full" or row.get("actor") in own:
            continue
        if not any(row.get(field) for field in (
                "requires_disposition", "directed_to_you", "addressed_to_you",
                "broadcast_to_everyone")):
            continue  # Group context is read at the next real turn.
        key = hook._watcher_rendered_key(row)
        if key:
            keys.add("mail:" + digest([key, state,
                                      hook._watcher_body_sha256(row.get("body"))]))
    for row in entry.get("pending") or []:
        if row.get("actor") in own or row.get("kind") not in {
                "plugin_update", "managed_law_update", "authentication_required",
                "sync_error", "sync_conflict", "sync_recovered", "offline_recovered",
                "outage_recovered", "unjournaled_write", "update_available",
                "connection_error", "offline_connection_error",
                "offline_sync_conflict", "offline_sync_accepted"}:
            continue
        keys.add("change:" + digest([row.get("kind"), row.get("fingerprint")
                                     or row.get("summary")]))
    return keys


class ChangeObserver:
    """Per-session announcements, separate from the watcher's render ledger."""
    def __init__(self, saved=None):
        self.saved = saved or {}

    def prepare(self, scope, entry, problem=None):
        previous = self.saved.get(scope) or {}
        sequence = int(previous.get("sequence") or 0) + 1
        known = set(previous.get("announced") or [])
        problem = problem or ("authorization_required" if entry.get("auth_required")
                              else "identity_refresh_required" if entry.get(
                                  "identity_refresh_required") else None)
        if problem:
            if previous.get("problem") == problem:
                return None
            return {"event_id": "%s:%d" % (scope, sequence),
                    "sequence": sequence, "kind": "connection_problem",
                    "actionable_count": 0,
                    "message": "ATTACCA_EVENT: connection needs attention (%s). "
                               "Check Attacca status; do not use blocked cached authority."
                               % problem,
                    "scope": scope, "next": {"announced": sorted(known),
                                                "problem": problem,
                                                "sequence": sequence}}
        current = event_keys(entry)
        fresh = current - known
        recovered = bool(previous.get("problem"))
        if not fresh and not recovered:
            return None
        message = ("ATTACCA_EVENT: connection recovered. " if recovered else
                   "ATTACCA_EVENT: ")
        message += ("%d new actionable change(s). Read check_inbox and relevant "
                    "current records, then handle assigned work under existing "
                    "role and scope. No new authority is granted." % len(fresh))
        return {"event_id": "%s:%d" % (scope, sequence),
                "sequence": sequence, "kind": "connection_recovered" if recovered else "actionable_change",
                "actionable_count": len(fresh),
                "message": message, "scope": scope,
                "next": {"announced": sorted(known | current), "problem": None,
                         "sequence": sequence}}

    def accept(self, notice):
        self.saved[notice["scope"]] = notice["next"]


def _state_directory(runtime, cwd, identity, session_id):
    # A resumed conversation has a new process but retains its delivery ledger.
    # Unknown native hosts stay process-bound; never guess the latest session.
    selected = _session_id(session_id)
    name = digest([runtime, str(Path(cwd).resolve()),
                   "session" if selected else identity, selected or session_id])
    return hook._watcher_state_path().parent / "wake" / name


def receiver_status(cwd, runtime, session_id=None):
    """Local, read-only delivery health; configuration is not a running receiver."""
    parent = host_process(runtime)
    try:
        selected = _session_id(session_id) or _registered_session(cwd, runtime, parent)
        owner = parent or ("native-monitor", os.getppid())
        directory = _state_directory(runtime, cwd, owner, selected)
        saved = _read_receipt(directory / hook.WATCHER_STATE_NAME)
        health = dict(saved.get("_health") or {})
        age = time.time() - float(health.get("heartbeat_at_epoch") or 0)
        process = (health.get("pid"), health.get("pid_start"))
        alive = bool(health.get("running") and process[0] and process[1]
                     and host_alive(process))
        if any(key in health and health[key] != value for key, value in {
                "runtime": runtime, "cwd": str(Path(cwd).resolve()),
                "session_id": selected}.items()) \
                or (alive and parent and "parent" in health and health["parent"] != list(parent)):
            raise ValueError("receiver health scope mismatch")
        running = alive and 0 <= age <= HEARTBEAT_TTL_SECONDS
        current_generation = health.get("generation") == RECEIVER_GENERATION
        upgrade = _read_receipt(directory / "repair" / hook.WATCHER_STATE_NAME)
        return {"configured": bool(health), "running": running,
                "current_generation": current_generation,
                "runtime": runtime, "session_id": selected,
                "heartbeat_at_epoch": health.get("heartbeat_at_epoch"),
                "last_delivery_state": health.get("last_delivery_state", "not_attempted"),
                "last_event_id": health.get("last_event_id"),
                "ai_processing": "unverified",
                "diagnostic": ("receiver_generation_stale" if running and not current_generation else None) or health.get("problem") or (
                    None if running else "receiver_heartbeat_stale" if alive else "receiver_not_running"),
                "repair_attempts": int((saved.get("_repair") or {}).get("attempts") or 0),
                "upgrade_state": "ready" if running and current_generation else upgrade.get("status"),
                "upgrade_attempts": int(upgrade.get("attempts") or 0),
                "watcher_healthy": health.get("watcher_healthy"),
                "producer_running": health.get("producer_running"),
                "subscription_state": health.get("subscription_state"),
                "event_channel": "attacca.event/v1", "state_directory": str(directory)}
    except (OSError, ValueError, TypeError, hook.WatcherStateSecurityError):
        return {"configured": False, "running": False, "runtime": runtime,
                "diagnostic": "receiver_state_invalid", "ai_processing": "unverified"}


def _event_envelope(notice):
    return {"schema_version": 1, "type": "attacca.event",
            **{key: notice[key] for key in (
                "event_id", "scope", "sequence", "kind", "actionable_count", "message")}}


def _subscription_problem(entry):
    if entry.get("auth_required") or entry.get("offline_mode") == "auth_required":
        return "authorization_required"
    if entry.get("identity_refresh_required"):
        return "identity_refresh_required"
    if entry.get("sync_bootstrap_error"):
        return "identity_sync_failed"
    if entry.get("last_inbox_error"):
        return "inbox_sync_failed"
    if entry.get("last_error"):
        return "watcher_transport_failed"
    if entry.get("offline_conflict_count"):
        return "sync_conflict"
    return None


def _repair_watcher(saved, problem, status, plugin_root, config, runtime, key, entry, now,
                    persist=None):
    """Bounded local producer rearm, never a new AI turn or an auth override."""
    if problem not in ("watcher_subscription_missing", "watcher_not_running", "watcher_heartbeat_stale") \
            or entry.get("interval_seconds") == 0 \
            or os.environ.get("ATTACCA_DISABLE_WATCHER") == "1":
        return
    record = saved.setdefault("_repair", {"attempts": 0, "next_at_epoch": 0})
    attempts = int(record.get("attempts") or 0)
    if attempts >= len(REPAIR_BACKOFF_SECONDS) or now < float(record.get("next_at_epoch") or 0):
        return
    # Reserve the attempt before calling a potentially failing/spawning helper.
    record.update({"attempts": attempts + 1,
                   "next_at_epoch": now + REPAIR_BACKOFF_SECONDS[attempts],
                   "problem": problem})
    if persist:
        persist()
    try:
        if problem == "watcher_heartbeat_stale":
            # A slow but live producer is never killed. Its nonce-verified wake
            # signal is safe; continued staleness remains explicitly unhealthy.
            hook._watcher_wake_subscription(key, "receiver_health_probe")
            record["result"] = "wake_requested"
        else:
            result = hook._ensure_background_watcher(status, plugin_root, config, runtime=runtime)
            record["result"] = "launch_requested" if result.get("started") else "checked"
    except (OSError, RuntimeError, ValueError):
        record["result"] = "repair_failed"


def _monitor_lock(directory, name="receiver.lock"):
    if hook.fcntl is None:
        return None
    fd = hook._open_private_watcher_file(directory / name,
                                       os.O_RDWR, create=True)
    try:
        hook.fcntl.flock(fd, hook.fcntl.LOCK_EX | hook.fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def _pending_delivery(saved, scope):
    pending = saved.get("_pending_deliveries", {})
    if not isinstance(pending, dict):
        raise ValueError("invalid pending delivery mapping")
    notice = pending.get(scope)
    if notice is None:
        return None
    if not isinstance(notice, dict) or notice.get("scope") != scope:
        raise ValueError("pending delivery scope mismatch")
    sequence = notice.get("sequence")
    previous = saved.get(scope) or {}
    next_state = notice.get("next")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0 \
            or not isinstance(previous, dict) \
            or sequence != int(previous.get("sequence") or 0) + 1 \
            or notice.get("event_id") != "%s:%d" % (scope, sequence) \
            or notice.get("kind") not in {"connection_problem", "connection_recovered", "actionable_change"} \
            or not isinstance(notice.get("message"), str) \
            or len(notice["message"].encode()) > 4096 or "\0" in notice["message"] \
            or not isinstance(next_state, dict) or next_state.get("sequence") != sequence \
            or not isinstance(next_state.get("announced"), list) \
            or any(not isinstance(value, str) for value in next_state["announced"]):
        raise ValueError("invalid pending delivery envelope")
    return notice


def run(cwd, runtime, session_id=None, parent=None, interval=3, max_ticks=None,
        jsonl=False, repair=True):
    os.environ["ATTACCA_RUNTIME"] = runtime
    if runtime == "codex":
        from codex_wake import queue_event, queue_supported
        if not parent or not _session_id(session_id) or not queue_supported():
            return 2  # No detached receiver without an exact live owner.
    # Claude CLI owns one interactive conversation per process. Its native
    # monitor and tool fallback therefore share a lock across helper restarts.
    # Codex hosts can own several threads: keep the exact thread in the key.
    receipt_session = _session_id(session_id or os.environ.get("CLAUDE_SESSION_ID"))
    if not receipt_session:
        receipt_session = _registered_session(cwd, runtime, parent)
    receipt_owner = parent or ("native-monitor", os.getppid())
    directory = _state_directory(runtime, cwd, receipt_owner, receipt_session)
    lock_directory = _state_directory(runtime, cwd, receipt_owner, None) \
        if runtime == "claude" else directory
    lock = _monitor_lock(lock_directory)
    if hook.fcntl is not None and lock is None:
        return 0
    session_lock = None
    if runtime == "claude" and receipt_session and hook.fcntl is not None:
        session_lock = _monitor_lock(directory)
        if session_lock is None:
            if lock is not None:
                os.close(lock)
            return 0
    receipt = directory / hook.WATCHER_STATE_NAME
    try:
        saved = _read_receipt(receipt)
    except (OSError, ValueError, UnicodeError, hook.WatcherStateSecurityError):
        if runtime == "claude":
            print("ATTACCA_EVENT: receiver state is invalid; automatic wake "
                  "is stopped to avoid duplicate notifications. Repair setup.",
                  file=sys.stderr if jsonl else sys.stdout, flush=True)
        if lock is not None:
            os.close(lock)
        if session_lock is not None:
            os.close(session_lock)
        return 2
    observer = ChangeObserver(saved)
    failed_since = None
    ticks = 0
    identity = _process_identity(os.getpid())

    def persist_health(problem=None, watcher_healthy=None, **changes):
        health = observer.saved.setdefault("_health", {})
        health.update({"schema_version": 1, "running": True,
                       "generation": RECEIVER_GENERATION,
                       "pid": os.getpid(), "pid_start": identity[1] if identity else None,
                       "runtime": runtime, "session_id": receipt_session,
                       "cwd": str(Path(cwd).resolve()),
                       "parent": list(parent) if parent else None,
                       "heartbeat_at_epoch": time.time(), "problem": problem,
                       "watcher_healthy": watcher_healthy,
                       "ai_processing": "unverified", **changes})
        hook._write_state(receipt, observer.saved)

    try:
        while host_alive(parent) and (max_ticks is None or ticks < max_ticks):
            ticks += 1
            problem = None
            producer_running = None
            entry = {}
            scope = "connection"
            try:
                # A native Monitor may start before SessionStart records its
                # UUID, or survive /clear within one CLI process. Adopt only
                # that exact verified parent's registration, never the latest.
                selected = _registered_session(cwd, runtime, parent) if runtime == "claude" else None
                if selected and selected != receipt_session:
                    next_directory = _state_directory(runtime, cwd, receipt_owner, selected)
                    next_receipt = next_directory / hook.WATCHER_STATE_NAME
                    next_lock = _monitor_lock(next_directory)
                    if hook.fcntl is not None and next_lock is None:
                        return 0
                    try:
                        next_saved = _read_receipt(next_receipt)
                    except BaseException:
                        if next_lock is not None:
                            os.close(next_lock)
                        raise
                    persist_health(running=False)
                    if session_lock is not None:
                        os.close(session_lock)
                    session_lock = next_lock
                    receipt_session = selected
                    directory, receipt = next_directory, next_receipt
                    observer = ChangeObserver(next_saved)
                status = hook.prompt_status(cwd)
                if status.get("status") != "linked":
                    persist_health(problem="workspace_not_linked")
                    time.sleep(interval)
                    continue  # Installation can precede project setup.
                plugin_root, config = hook._plugin_and_config()
                key = hook._watcher_subscription_key(status, config, runtime)
                state = hook._read_state(hook._watcher_state_path())
                entry = (state.get("subscriptions") or {}).get(key) or {}
                scope = digest([key, entry.get("canonical_actor_id"),
                                entry.get("client_instance")])
                daemon = state.get("daemon") or {}
                producer_running = daemon_healthy(daemon)
                if not entry:
                    problem = "watcher_subscription_missing"
                elif not producer_running:
                    problem = "watcher_heartbeat_stale" if daemon_process_alive(daemon) else "watcher_not_running"
                if problem is None:
                    failed_since = None
                    observer.saved.pop("_repair", None)
                elif repair:
                    _repair_watcher(observer.saved, problem, status, plugin_root,
                                    config, runtime, key, entry, time.time(),
                                    persist=lambda: persist_health(problem=problem, watcher_healthy=False))
            except (OSError, ValueError, RuntimeError, hook.WatcherStateSecurityError):
                problem = "watcher_state_unavailable"
            reported_problem = problem or _subscription_problem(entry)
            paused = entry.get("interval_seconds") == 0
            subscription_state = "paused" if paused else reported_problem or "watching"
            persist_health(problem=reported_problem or ("watcher_paused" if paused else None),
                           watcher_healthy=reported_problem is None and not paused,
                           producer_running=producer_running, subscription_state=subscription_state)
            if problem:
                if failed_since is None:
                    failed_since = time.monotonic()
                if time.monotonic() - failed_since < HEARTBEAT_TTL_SECONDS:
                    time.sleep(interval)
                    continue
            if entry.get("interval_seconds") == 0 and not entry.get("auth_required"):
                time.sleep(interval)
                continue
            try:
                notice = _pending_delivery(observer.saved, scope) if runtime == "codex" else None
            except (ValueError, TypeError):
                persist_health(problem="receiver_state_invalid", watcher_healthy=False,
                               last_delivery_state="state_error")
                time.sleep(interval)
                continue
            pending = observer.saved.setdefault("_pending_deliveries", {}) if runtime == "codex" else {}
            if notice and notice["kind"] != "connection_problem" and reported_problem in {
                    "authorization_required", "identity_refresh_required", "identity_sync_failed"}:
                # Preserve the old exact envelope, but never let it override
                # a newly invalidated authority boundary after a restart.
                time.sleep(interval)
                continue
            notice = notice or observer.prepare(scope, entry, reported_problem)
            if notice:
                if runtime == "codex":
                    # Preserve the exact event envelope before an external
                    # queue command can be interrupted. A resumed receiver
                    # must resolve this batch first, not absorb later mail
                    # into the same uncertain event ID.
                    pending[scope] = notice
                    persist_health(problem=reported_problem,
                                   watcher_healthy=reported_problem is None,
                                   last_delivery_state="prepared",
                                   last_event_id=notice["event_id"])
                    result = queue_event(directory, session_id, notice["event_id"],
                                         True, notice["message"], cwd=cwd)
                    accepted = result.get("status") in (
                        "queued", "duplicate", "pending_unknown")
                    if result.get("status") == "pending_unknown":
                        # Record attempted keys, not a delivery acknowledgement.
                        # Future fresh batches must not retry these same events.
                        observer.saved["_delivery_error"] = "pending_unknown"
                    if result.get("status") == "unsupported":
                        observer.saved["_delivery_error"] = "unsupported"
                        hook._write_state(receipt, observer.saved)
                        return 2
                    delivery = result.get("status")
                else:
                    # stdout has no acknowledgment/idempotency protocol.
                    # Reserve before output so a crash cannot replay a wake;
                    # the original mail remains pinned in the watcher ledger.
                    observer.accept(notice)
                    persist_health(problem=reported_problem, watcher_healthy=reported_problem is None,
                                   last_delivery_state="pending_unknown", last_event_id=notice["event_id"])
                    print(json.dumps(_event_envelope(notice), sort_keys=True) if jsonl
                          else notice["message"], flush=True)
                    delivery = "stdout_emitted"
                    accepted = True
                if accepted:
                    observer.accept(notice)
                    pending.pop(scope, None)
                persist_health(problem=reported_problem, watcher_healthy=reported_problem is None,
                               last_delivery_state=delivery, last_event_id=notice["event_id"])
            time.sleep(interval)
    finally:
        health = observer.saved.get("_health") or {}
        try:
            persist_health(problem=health.get("problem"), watcher_healthy=health.get("watcher_healthy"),
                           running=False)
        finally:
            if session_lock is not None:
                os.close(session_lock)
            if lock is not None:
                os.close(lock)
    return 0


def daemon_healthy(daemon):
    try:
        age = time.time() - float(daemon.get("heartbeat_at_epoch") or 0)
    except (ValueError, TypeError):
        return False
    return daemon_process_alive(daemon) and 0 <= age <= HEARTBEAT_TTL_SECONDS


def daemon_process_alive(daemon):
    if sys.platform.startswith("linux"):
        return hook._watcher_process_matches(daemon.get("pid"), daemon.get("nonce"))
    return bool(daemon.get("pid"))


def _receiver_command(cwd, session_id, parent):
    return [sys.executable, str(Path(__file__).resolve()), "--runtime", "codex",
            "--cwd", str(Path(cwd).resolve()), "--session-id", session_id,
            "--parent-pid", str(parent[0]), "--parent-start", str(parent[1])]


def _owned_receiver_process(health, cwd, session_id, parent):
    """Prove one exact receiver, including legacy health without cwd/parent."""
    try:
        identity = (int(health["pid"]), str(health["pid_start"]))
        if identity[0] <= 1 or identity[0] in {os.getpid(), parent[0]} \
                or health.get("runtime") != "codex" \
                or _session_id(health.get("session_id")) != session_id \
                or ("cwd" in health and health["cwd"] != str(Path(cwd).resolve())) \
                or ("parent" in health and health["parent"] != list(parent)) \
                or not host_alive(parent) or _process_identity(identity[0]) != identity:
            return False
        process = Path("/proc/%d" % identity[0])
        if process.stat().st_uid != os.getuid():
            return False
        command = (process / "cmdline").read_bytes()
        if not command.endswith(b"\0") or len(command) > 16384:
            return False
        argv = [os.fsdecode(value) for value in command[:-1].split(b"\0")]
        expected = _receiver_command(cwd, session_id, parent)
        if len(argv) != len(expected) \
                or Path(argv[0]).resolve() != Path(sys.executable).resolve() \
                or (process / "exe").resolve() != Path(sys.executable).resolve() \
                or argv[1:] != expected[1:]:
            return False
        return _process_identity(identity[0]) == identity and host_alive(parent)
    except (OSError, ValueError, TypeError, KeyError):
        return False


def _stop_owned_stale_receiver(health, cwd, session_id, parent):
    """Pin and terminate only a proven receiver; never signal a bare PID."""
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        return "pidfd_unavailable"
    if not _owned_receiver_process(health, cwd, session_id, parent):
        return "ownership_unverified"
    descriptor = None
    try:
        descriptor = os.pidfd_open(int(health["pid"]), 0)
        # Pin first, then revalidate PID/start, argv and owner. PID reuse in
        # either window cannot redirect this signal to a different process.
        if not _owned_receiver_process(health, cwd, session_id, parent):
            return "ownership_changed"
        signal.pidfd_send_signal(descriptor, signal.SIGTERM, None, 0)
        poll = select.poll()
        poll.register(descriptor, select.POLLIN)
        if not poll.poll(int(RECEIVER_STOP_TIMEOUT_SECONDS * 1000)):
            return "stop_timeout"
        return "stopped"
    except (OSError, ValueError, TypeError):
        return "stop_failed"
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _queue_checkpoint_verified(directory, session_id):
    """Called with the queue lock held; never interrupt uncheckpointed intent."""
    from codex_wake import MAX_RECEIPTS_PER_SESSION, _read_receipt as read_queue_receipt
    saved = _read_receipt(directory / hook.WATCHER_STATE_NAME)
    known = set()
    budget = MAX_RECEIPTS_PER_SESSION
    for scope, value in saved.items():
        if scope.startswith("_"):
            continue
        if not isinstance(value, dict):
            return False
        sequence = value.get("sequence", 0)
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0 \
                or sequence > budget:
            return False
        budget -= sequence
        for index in range(1, sequence + 1):
            known.add(hashlib.sha256(("%s:%d" % (scope, index)).encode()).hexdigest())
    pending = saved.get("_pending_deliveries", {})
    if not isinstance(pending, dict):
        return False
    for scope in pending:
        notice = _pending_delivery(saved, scope)
        if notice is None:
            return False
        known.add(hashlib.sha256(notice["event_id"].encode()).hexdigest())
    paths = list((directory / session_id).iterdir())
    if len(paths) > MAX_RECEIPTS_PER_SESSION + 1:
        return False
    for path in paths:
        if path.name == ".lock":
            continue
        if not re.fullmatch(r"[0-9a-f]{64}\.json", path.name):
            return False
        receipt = read_queue_receipt(path)
        if not receipt or receipt.get("thread") != session_id \
                or receipt.get("event_sha256") != path.stem \
                or receipt.get("status") not in {"queued", "pending_unknown", "retryable"}:
            return False
        if receipt["status"] != "retryable" and path.stem not in known:
            return False
    return True


def start_codex_receiver(cwd, session_id):
    """Request a session receiver; True never proves heartbeat or AI delivery."""
    from codex_wake import queue_supported
    session_id = _session_id(session_id)
    if not session_id:
        return False
    native_thread = os.environ.get("CODEX_THREAD_ID")
    if native_thread and _session_id(native_thread) != session_id:
        return False
    parent = host_process("codex")
    if parent is None or not queue_supported() or hook.fcntl is None:
        return False
    directory = _state_directory("codex", cwd, parent, session_id)
    repair_path = directory / "repair" / hook.WATCHER_STATE_NAME
    launch_lock = None
    lifetime_lock = None
    queue_lock = None
    try:
        # This lock serializes old-process verification, stop, lifetime-lock
        # proof and replacement launch across simultaneous lifecycle hooks.
        launch_lock = _monitor_lock(directory, "receiver-launch.lock")
        if launch_lock is None:
            return False
        current = receiver_status(cwd, "codex", session_id)
        saved = _read_receipt(directory / hook.WATCHER_STATE_NAME)
        health = dict(saved.get("_health") or {})
        repair = _read_receipt(repair_path)
        scope = {"runtime": "codex", "cwd": str(Path(cwd).resolve()),
                 "session_id": session_id, "parent": list(parent)}
        if health and any(key in health and health[key] != scope[key]
                          for key in ("runtime", "cwd", "session_id")):
            return False  # Launch records never override contradictory scope.
        if "parent" in health and health["parent"] != list(parent) \
                and health.get("pid") and _process_identity(health["pid"]) is not None:
            return False  # A resumed host cannot stop a still-live other owner.
        if current.get("running") and current.get("current_generation"):
            return health.get("runtime") == "codex" and \
                _session_id(health.get("session_id")) == session_id
        if repair and any(repair.get(key) != value for key, value in scope.items()):
            # A resumed owner can reuse receipts, not another process's
            # pending launch or permission to stop its child.
            if repair.get("session_id") != session_id or repair.get("cwd") != scope["cwd"] \
                    or repair.get("runtime") != "codex":
                return False
            repair = {}
        launch = repair.get("launched_process") or {}
        if launch and _owned_receiver_process(launch, cwd, session_id, parent):
            if repair.get("target_generation") == RECEIVER_GENERATION:
                return True
            if health.get("pid") and health["pid"] != launch["pid"] \
                    and _process_identity(health["pid"]) is not None:
                return False  # Conflicting live ownership is never guessed.
            # A previous successful upgrade is still an old receiver after
            # the next installation. Its launch proof can bridge startup
            # before that child writes a health heartbeat of its own.
            health = {**launch, "generation": repair.get("target_generation")}
        if repair.get("target_generation") != RECEIVER_GENERATION:
            repair = {**scope, "schema_version": 1,
                      "target_generation": RECEIVER_GENERATION, "attempts": 0}
        attempts = int(repair.get("attempts") or 0)
        if attempts >= len(REPAIR_BACKOFF_SECONDS) \
                or time.time() < float(repair.get("next_at_epoch") or 0):
            return False
        repair.update({"attempts": attempts + 1,
                       "next_at_epoch": time.time() + REPAIR_BACKOFF_SECONDS[attempts],
                       "status": "rearm_reserved"})
        hook._write_state(repair_path, repair)
        # Guard both live replacement and a dead legacy receiver's restart.
        # Without its exact checkpoint an uncertain prior event cannot be
        # reconstructed safely, so later mail must not be folded into it.
        queue_lock = _monitor_lock(directory / session_id, ".lock")
        try:
            checkpoint_verified = queue_lock is not None and \
                _queue_checkpoint_verified(directory, session_id)
        except (OSError, ValueError, TypeError, hook.WatcherStateSecurityError):
            checkpoint_verified = False
        if not checkpoint_verified:
            repair["status"] = "queue_checkpoint_unverified"
            hook._write_state(repair_path, repair)
            return False
        if current.get("running") or (
                health.get("pid") and _process_identity(health["pid"]) is not None):
            if health.get("generation") == RECEIVER_GENERATION:
                repair["status"] = "current_receiver_not_ready"
                hook._write_state(repair_path, repair)
                return False
            result = _stop_owned_stale_receiver(health, cwd, session_id, parent)
            repair["status"] = result
            hook._write_state(repair_path, repair)
            if result != "stopped":
                return False
        # Exit alone is insufficient: a foreign/competing owner may hold the
        # exact session's lifetime lock. Never launch behind that owner.
        lifetime_lock = _monitor_lock(directory)
        if lifetime_lock is None or not host_alive(parent):
            repair["status"] = "lifetime_lock_unavailable"
            hook._write_state(repair_path, repair)
            return False
        register_session(cwd, "codex", session_id, parent=parent)
        os.close(lifetime_lock)
        lifetime_lock = None
        process = subprocess.Popen(
            _receiver_command(cwd, session_id, parent), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True)
        identity = _process_identity(process.pid)
        repair.update({"status": "launch_requested", "launched_process": {
            **scope, "pid": process.pid,
            "pid_start": identity[1] if identity else None}})
        hook._write_state(repair_path, repair)
        return True
    except (OSError, ValueError, TypeError, hook.WatcherStateSecurityError):
        return False
    finally:
        if queue_lock is not None:
            os.close(queue_lock)
        if lifetime_lock is not None:
            os.close(lifetime_lock)
        if launch_lock is not None:
            os.close(launch_lock)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", choices=("claude", "codex"), default="claude")
    parser.add_argument("--cwd", default=os.getcwd())
    parser.add_argument("--session-id")
    parser.add_argument("--parent-pid", type=int)
    parser.add_argument("--parent-start")
    parser.add_argument("--jsonl", action="store_true", help="emit change-only schema-v1 NDJSON on stdout")
    parser.add_argument("--status", action="store_true", help="print local receiver health without polling")
    parser.add_argument("--no-repair", action="store_true", help="observe only; do not rearm a failed producer")
    args = parser.parse_args(argv)
    if args.status:
        print(json.dumps(receiver_status(args.cwd, args.runtime, args.session_id), sort_keys=True))
        return 0
    parent = ((args.parent_pid, args.parent_start) if args.parent_pid and
              args.parent_start else host_process(args.runtime))
    return run(args.cwd, args.runtime, args.session_id, parent,
               jsonl=args.jsonl, repair=not args.no_repair)


if __name__ == "__main__":
    raise SystemExit(main())
