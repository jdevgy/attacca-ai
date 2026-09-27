"""Deliver one Attacca event to an explicitly bound existing Codex session.

This adapter never starts a new Codex session and never polls with AI prompts.
The caller decides which authenticated watcher changes require attention. A
successful queue command is an acceptance receipt, not proof of delivery to an
AI turn, execution, completion or a message disposition.

The queue CLI has no idempotency key. Persist an uncertainty receipt before
starting it, so a timeout or process crash cannot cause automatic duplicate
delivery. Normal lifecycle inbox delivery remains available in that case.
"""

import functools
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import uuid


MAX_MESSAGE_BYTES = 4096
MAX_EVENT_BYTES = 1024
MAX_RECEIPTS_PER_SESSION = 4096
MAX_RECEIPT_BYTES = 4096


def _thread_uuid(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    # Names, bare hex, whitespace, and aliases must never select a target.
    return str(parsed) if str(parsed) == value.lower() else None


def _result(status, **details):
    return dict(status=status, **details)


def _sync_directory(path):
    if os.name != "nt":
        descriptor = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _private_directory(path):
    path = Path(path).absolute()
    # Inspect existing ancestors before creating anything beneath them.
    for component in reversed((path,) + tuple(path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            try:
                component.mkdir(mode=0o700)
            except FileExistsError:
                pass
            _sync_directory(component.parent)
            info = component.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise OSError("wake state path contains a symlink")
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode)
            or (os.name != "nt" and info.st_mode & 0o077)
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())):
        raise OSError("wake state directory is not private")
    return path


def _open_private(path, flags):
    descriptor = os.open(str(path), flags | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(descriptor)
        linked = Path(path).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or stat.S_ISLNK(linked.st_mode)
                or (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)
                or (os.name != "nt" and info.st_mode & 0o077)
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())):
            raise OSError("wake state file is not private")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _acquire_lock(path):
    descriptor = _open_private(path, os.O_CREAT | os.O_RDWR)
    try:
        if os.name == "nt":
            import msvcrt
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _write_receipt(path, receipt):
    descriptor, temporary = tempfile.mkstemp(prefix=".wake-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(receipt, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, str(path))
        _sync_directory(path.parent)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _read_receipt(path):
    try:
        descriptor = _open_private(path, os.O_RDONLY)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as stream:
        raw = stream.read(MAX_RECEIPT_BYTES + 1)
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError("oversized wake receipt")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("malformed wake receipt")
    return value


@functools.lru_cache(maxsize=16)
def queue_supported(codex_command="codex"):
    """Probe the installed CLI, without starting a session or generating tokens."""
    try:
        result = subprocess.run(
            [os.fspath(codex_command), "queue", "--help"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=5, check=False,
            encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    output = result.stdout or ""
    return (result.returncode == 0 and "--thread" in output
            and "--message" in output and "queue" in output.lower())


def queue_event(state_dir, session_id, event_id, actionable, message,
                codex_command="codex", timeout=15, cwd=None, env=None):
    """Queue a coalesced actionable change at most once per exact session.

    ``event_id`` must include the caller's authenticated workspace/actor scope
    and stable change identifiers. Never use a wall-clock polling timestamp.
    ``message`` is a bounded, non-secret wake notice pointing to Attacca's
    staged inbox, not a copied credential or arbitrary shell command.

    ``queued`` means Codex accepted the command, not that the AI acted yet.
    ``pending_unknown`` is deliberately not retried: the host might already
    own the input. ``retryable`` proves no child command started. The caller
    retains its pending change on every result except queued or duplicate.
    """
    if actionable is not True:
        return _result("not_actionable")
    thread = _thread_uuid(session_id)
    if not thread:
        return _result("invalid_target")
    if (not isinstance(event_id, str) or not event_id
            or len(event_id.encode("utf-8")) > MAX_EVENT_BYTES):
        return _result("invalid_event")
    if (not isinstance(message, str) or not message.strip() or "\x00" in message
            or len(message.encode("utf-8")) > MAX_MESSAGE_BYTES):
        return _result("invalid_message")
    if not queue_supported(codex_command):
        return _result("unsupported")
    lock = None
    try:
        root = _private_directory(state_dir)
        directory = _private_directory(root / thread)
        try:
            lock = _acquire_lock(directory / ".lock")
        except BlockingIOError:
            return _result("busy")
        digest = hashlib.sha256(event_id.encode("utf-8")).hexdigest()
        receipt_path = directory / (digest + ".json")
        receipt = _read_receipt(receipt_path)
        if receipt:
            if receipt.get("thread") != thread or receipt.get("event_sha256") != digest:
                return _result("state_error", reason="wake receipt scope mismatch")
            if receipt.get("status") == "queued":
                return _result("duplicate")
            if receipt.get("status") != "retryable":
                return _result("pending_unknown")
        elif sum(1 for path in directory.iterdir() if path.suffix == ".json") >= MAX_RECEIPTS_PER_SESSION:
            # Never evict dedup receipts and accidentally replay old events.
            return _result("state_error", reason="session wake receipt limit reached")
        receipt = {"schema_version": 1, "thread": thread,
                   "event_sha256": digest, "status": "pending_unknown"}
        _write_receipt(receipt_path, receipt)
        try:
            result = subprocess.run(
                [os.fspath(codex_command), "queue", "--thread", thread,
                 "--message", message], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=max(1, min(float(timeout), 30)), check=False,
                cwd=cwd, env=env)
        except OSError:
            # Popen did not successfully start a process: a later retry is safe.
            receipt["status"] = "retryable"
            _write_receipt(receipt_path, receipt)
            return _result("retryable")
        except subprocess.SubprocessError:
            return _result("pending_unknown")
        if result.returncode != 0:
            # Nonzero does not prove non-delivery under the current CLI contract.
            return _result("pending_unknown", returncode=result.returncode)
        receipt["status"] = "queued"
        _write_receipt(receipt_path, receipt)
        return _result("queued")
    except (OSError, ValueError, TypeError):
        return _result("state_error", reason="wake receipt storage unavailable or invalid")
    finally:
        if lock is not None:
            os.close(lock)
