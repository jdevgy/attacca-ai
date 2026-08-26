"""Secure, runtime-independent terminal authentication for Attacca clients.

The lifecycle hooks and native setup/update skills use this module to start or
advance a browser/device-code authorization without asking an AI conversation
to carry a password or token.  The high-entropy device code and the resulting
terminal credential are private machine state; public results contain only the
verification URL, short user code, and non-secret status metadata.

One terminal credential is stored per canonical server URL.  It is bound to a
machine device and may select multiple pre-authorized, unchanged AI actors.
Runtime/instance identity is therefore request metadata, never credential
ownership.  Existing actor-bound records are preserved during migration.
"""

from __future__ import annotations

import argparse
import contextlib
import hmac
import json
import os
import re
import secrets
import socket
import stat
import tempfile
import threading
import time
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows uses the process lock below.
    fcntl = None


SCHEMA_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 5
MAX_JSON_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 16 * 1024
MAX_DEVICE_CODE_BYTES = 8 * 1024
MAX_URL_BYTES = 8 * 1024
MAX_CREDENTIALS_BYTES = 4 * 1024 * 1024
MAX_PRIVATE_STATE_BYTES = 1024 * 1024
POLL_SLOW_DOWN_SECONDS = 5

DEVICE_START_PATH = "/v1/auth/device/start"
DEVICE_POLL_PATH = "/v1/auth/device/poll"
AUTH_STATUS_PATH = "/v1/auth/status"
TERMINAL_BINDING_PATH = "/v1/auth/terminals/{token_id}/bindings"

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}$")
_SAFE_USER_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{2,63}$")
_PROCESS_LOCK = threading.RLock()


class TerminalFlowError(RuntimeError):
    """Base error whose message is always safe to show outside the terminal."""


class TerminalFlowProtocolError(TerminalFlowError):
    """The authorization server returned an unsafe or malformed response."""


class TerminalFlowTransportError(TerminalFlowError):
    """The authorization server could not be reached safely."""


class ControllingTerminalUnavailable(TerminalFlowError):
    """No verified foreground controlling terminal is available for paste."""


@dataclass(frozen=True)
class JsonResponse:
    status: int
    headers: dict
    value: dict


class _RejectRedirects(HTTPRedirectHandler):
    """Never forward a device code or terminal credential through redirects."""

    def redirect_request(self, request, fp, code, msg, headers, new_url):
        return None


class UrllibJsonTransport:
    """Small bounded JSON transport which never retains request credentials."""

    def __init__(self):
        self._opener = build_opener(_RejectRedirects())

    def request(self, method, url, *, headers, payload=None,
                timeout=DEFAULT_TIMEOUT_SECONDS):
        body = None
        request_headers = dict(headers)
        if payload is not None:
            try:
                body = json.dumps(
                    payload, separators=(",", ":"), ensure_ascii=False
                ).encode("utf-8")
            except (TypeError, ValueError) as error:
                raise TerminalFlowProtocolError(
                    "terminal authorization request is not valid JSON") from error
            if len(body) > MAX_JSON_BYTES:
                raise TerminalFlowProtocolError(
                    "terminal authorization request is too large")
            request_headers["Content-Type"] = "application/json"
        request = Request(
            url, data=body, headers=request_headers, method=str(method).upper())
        try:
            with self._opener.open(request, timeout=float(timeout)) as response:
                raw = response.read(MAX_JSON_BYTES + 1)
                if len(raw) > MAX_JSON_BYTES:
                    raise TerminalFlowProtocolError(
                        "terminal authorization response is too large")
                status = int(response.status)
                headers_out = {
                    key.lower(): value for key, value in response.headers.items()}
        except HTTPError as error:
            raw = error.read(MAX_JSON_BYTES + 1)
            if len(raw) > MAX_JSON_BYTES:
                raw = b""
            status = int(error.code)
            headers_out = {
                key.lower(): value for key, value in
                (error.headers.items() if error.headers is not None else [])}
        except (URLError, socket.timeout, TimeoutError, OSError) as error:
            raise TerminalFlowTransportError(
                "Attacca terminal authorization is temporarily unavailable"
            ) from None
        try:
            value = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TerminalFlowProtocolError(
                "terminal authorization returned malformed JSON") from None
        if not isinstance(value, dict):
            raise TerminalFlowProtocolError(
                "terminal authorization returned a non-object response")
        return JsonResponse(status=status, headers=headers_out, value=value)


def default_credentials_path(home=None):
    return Path(home or Path.home()).expanduser().resolve() / \
        ".attacca" / "credentials.json"


def default_state_path(home=None):
    return Path(home or Path.home()).expanduser().resolve() / \
        ".attacca" / "terminal-flow.json"


def default_identity_path(home=None):
    return Path(home or Path.home()).expanduser().resolve() / \
        ".attacca" / "identity.json"


def default_client_instance_path(home=None):
    return Path(home or Path.home()).expanduser().resolve() / \
        ".attacca" / "client-instance.json"


def _safe_comparison_path(value, label):
    """Return a decoded path only after rejecting browser/proxy traversal.

    ``urlsplit`` deliberately preserves dot segments, while browsers normalize
    them before navigation.  A raw prefix comparison would therefore accept
    ``/tenant/../other`` (including percent-encoded variants) as inside the
    configured tenant.  Decode a bounded number of layers, reject separators
    with ambiguous proxy behavior, and compare the resulting safe path.
    """
    raw = str(value or "")
    if re.search(r"%(?![0-9A-Fa-f]{2})", raw):
        raise TerminalFlowProtocolError(
            "%s contains malformed percent encoding" % label)
    decoded = raw
    for _ in range(8):
        try:
            expanded = unquote(decoded, errors="strict")
        except (UnicodeDecodeError, ValueError):
            raise TerminalFlowProtocolError(
                "%s contains invalid path encoding" % label) from None
        if expanded == decoded:
            break
        decoded = expanded
    else:
        raise TerminalFlowProtocolError(
            "%s path is excessively encoded" % label)
    if "\\" in decoded or "//" in decoded:
        raise TerminalFlowProtocolError(
            "%s contains an ambiguous path separator" % label)
    if any(ord(character) < 32 or ord(character) == 127
           for character in decoded):
        raise TerminalFlowProtocolError(
            "%s contains a control character" % label)
    if any(segment in (".", "..") for segment in decoded.split("/")):
        raise TerminalFlowProtocolError(
            "%s contains a path traversal segment" % label)
    return decoded.rstrip("/")


def canonical_server_url(value):
    """Canonicalize a complete hosted base URL without weakening path scope."""
    raw = str(value or "").strip()
    if not raw or len(raw.encode("utf-8")) > MAX_URL_BYTES:
        raise TerminalFlowProtocolError("Attacca server URL is missing or too long")
    if any(character.isspace() for character in raw):
        raise TerminalFlowProtocolError(
            "Attacca server URL cannot contain whitespace")
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise TerminalFlowProtocolError(
            "Attacca server URL must use http or https with a host")
    if parsed.username is not None or parsed.password is not None \
            or parsed.query or parsed.fragment:
        raise TerminalFlowProtocolError(
            "Attacca server URL cannot contain credentials, a query, or a fragment")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise TerminalFlowProtocolError(
            "Attacca server URL has an invalid host") from None
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    try:
        port = parsed.port
    except ValueError:
        raise TerminalFlowProtocolError("Attacca server URL has an invalid port") \
            from None
    default_port = (parsed.scheme.lower() == "http" and port == 80) or \
        (parsed.scheme.lower() == "https" and port == 443)
    netloc = host if port is None or default_port else "%s:%d" % (host, port)
    decoded_path = _safe_comparison_path(parsed.path, "Attacca server URL")
    path = quote(decoded_path, safe="/:@-._~")
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))


def _endpoint(server_url, path):
    return canonical_server_url(server_url).rstrip("/") + path


def _same_server_verification_url(server_url, value, label):
    raw = str(value or "").strip()
    if not raw or len(raw.encode("utf-8")) > MAX_URL_BYTES:
        raise TerminalFlowProtocolError("%s is missing or too long" % label)
    if any(ord(character) < 32 or ord(character) == 127
           for character in raw):
        raise TerminalFlowProtocolError(
            "%s contains a control character" % label)
    parsed = urlsplit(raw)
    base = urlsplit(canonical_server_url(server_url))
    def effective_port(item):
        try:
            port = item.port
        except ValueError:
            raise TerminalFlowProtocolError(
                "%s has an invalid port" % label) from None
        if port is not None:
            return port
        return 80 if item.scheme.lower() == "http" else 443

    if parsed.scheme.lower() != base.scheme.lower() \
            or (parsed.hostname or "").lower() != (base.hostname or "").lower() \
            or effective_port(parsed) != effective_port(base) \
            or parsed.username is not None or parsed.password is not None:
        raise TerminalFlowProtocolError(
            "%s must stay on the configured Attacca server" % label)
    base_path = _safe_comparison_path(
        base.path, "configured Attacca server URL")
    candidate_path = _safe_comparison_path(parsed.path, label)
    if base_path and candidate_path != base_path \
            and not candidate_path.startswith(base_path + "/"):
        raise TerminalFlowProtocolError(
            "%s escaped the configured Attacca base path" % label)
    return raw


def _bounded_safe_id(value, label):
    text = str(value or "").strip()
    if not _SAFE_ID.fullmatch(text):
        raise TerminalFlowProtocolError("%s is missing or invalid" % label)
    return text


def _normalize_binding(value):
    if not isinstance(value, dict):
        raise TerminalFlowProtocolError("terminal credential binding is invalid")
    project = _bounded_safe_id(value.get("project_id"), "project_id")
    actor = _bounded_safe_id(value.get("actor_id"), "actor_id")
    result = {"project_id": project, "actor_id": actor}
    runtime = str(value.get("runtime") or "").strip().lower()
    if runtime:
        result["runtime"] = _bounded_safe_id(runtime, "runtime")
    return result


def normalize_bindings(bindings):
    if bindings is None:
        return []
    if not isinstance(bindings, (list, tuple)) or len(bindings) > 500:
        raise TerminalFlowProtocolError("terminal credential bindings are invalid")
    result = []
    seen = set()
    for value in bindings:
        binding = _normalize_binding(value)
        key = (binding["project_id"], binding["actor_id"])
        if key not in seen:
            seen.add(key)
            result.append(binding)
    return result


def _binding_allowed(bindings, project_id=None, actor_id=None,
                     runtime=None):
    if project_id is None and actor_id is None:
        return True
    if not project_id or not actor_id:
        return False
    project_id = str(project_id).strip()
    actor_id = str(actor_id).strip()
    runtime = str(runtime or "").strip().lower()
    for binding in bindings:
        if binding["project_id"] != project_id \
                or binding["actor_id"] != actor_id:
            continue
        recorded_runtime = str(binding.get("runtime") or "").lower()
        if not runtime or not recorded_runtime or recorded_runtime == runtime:
            return True
    return False


def _parse_expiry(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def _read_json(path, default):
    try:
        value = json.loads(Path(path).read_text())
        return value if isinstance(value, dict) else dict(default)
    except (OSError, ValueError, TypeError):
        return dict(default)


def _read_private_json_unlocked(path, default, label, max_bytes,
                                missing_ok=True):
    """Read private JSON only when it is an owner-only regular file.

    Missing is a valid first-install state. Existing malformed, unreadable,
    symlinked, non-regular, wrong-owner, or non-0600 files are never treated as
    empty: doing so would both consume an exposed bearer and let a later save
    silently destroy legacy actor records or forensic recovery data.
    """
    path = Path(path)
    try:
        before = os.lstat(str(path))
    except FileNotFoundError:
        if missing_ok:
            return dict(default)
        raise TerminalFlowProtocolError(
            "%s is missing" % label) from None
    except OSError:
        raise TerminalFlowProtocolError(
            "%s cannot be inspected" % label) from None
    if not stat.S_ISREG(before.st_mode):
        raise TerminalFlowProtocolError(
            "%s must be a regular file" % label)
    if stat.S_IMODE(before.st_mode) != 0o600:
        raise TerminalFlowProtocolError(
            "%s must have mode 0600" % label)
    if hasattr(os, "geteuid") and before.st_uid != os.geteuid():
        raise TerminalFlowProtocolError(
            "%s must be owned by the current user" % label)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags)
    except OSError:
        raise TerminalFlowProtocolError(
            "%s cannot be opened safely" % label) from None
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) \
                or opened.st_dev != before.st_dev \
                or opened.st_ino != before.st_ino \
                or stat.S_IMODE(opened.st_mode) != 0o600 \
                or (hasattr(os, "geteuid") and opened.st_uid != os.geteuid()):
            raise TerminalFlowProtocolError(
                "%s changed during secure open" % label)
        chunks = []
        remaining = int(max_bytes) + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > int(max_bytes):
            raise TerminalFlowProtocolError(
                "%s is too large" % label)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, TypeError):
        raise TerminalFlowProtocolError(
            "%s is malformed; it was preserved" % label) from None
    if not isinstance(value, dict):
        raise TerminalFlowProtocolError(
            "%s has an invalid structure; it was preserved" % label)
    return value


def _read_private_credentials_unlocked(path, missing_ok=True):
    value = _read_private_json_unlocked(
        path, {"version": SCHEMA_VERSION, "servers": {}},
        "Attacca credential store", MAX_CREDENTIALS_BYTES,
        missing_ok=missing_ok)
    if not isinstance(value.get("servers", {}), dict):
        raise TerminalFlowProtocolError(
            "Attacca credential store has an invalid structure; it was preserved")
    return value


def read_credentials_store(credentials_path=None):
    """Return a private credential mapping without exposing any value publicly."""
    path = Path(credentials_path or default_credentials_path())
    with _private_file_lock(path):
        return _read_private_credentials_unlocked(path, missing_ok=True)


def update_credentials_store(credentials_path, updater):
    """Serialize one fail-closed, preservation-safe credential mutation."""
    if not callable(updater):
        raise TypeError("credential updater must be callable")
    path = Path(credentials_path or default_credentials_path())
    with _private_file_lock(path):
        data = _read_private_credentials_unlocked(path, missing_ok=True)
        updated = updater(data)
        if updated is not None:
            data = updated
        if not isinstance(data, dict) or not isinstance(
                data.get("servers", {}), dict):
            raise TerminalFlowProtocolError(
                "credential update returned an invalid structure")
        data.setdefault("version", SCHEMA_VERSION)
        data.setdefault("servers", {})
        _atomic_private_json(path, data)
    return str(path)


def read_identity_store(identity_path=None):
    """Read the shared device/owner identity with private-file guarantees."""
    path = Path(identity_path or default_identity_path())
    with _private_file_lock(path):
        return _read_private_json_unlocked(
            path, {}, "Attacca machine identity", MAX_PRIVATE_STATE_BYTES)


def update_identity_store(identity_path, updater):
    """Serialize one preservation-safe update to the shared identity file."""
    if not callable(updater):
        raise TypeError("identity updater must be callable")
    path = Path(identity_path or default_identity_path())
    with _private_file_lock(path):
        identity = _read_private_json_unlocked(
            path, {}, "Attacca machine identity", MAX_PRIVATE_STATE_BYTES)
        updated = updater(identity)
        if updated is not None:
            identity = updated
        if not isinstance(identity, dict):
            raise TerminalFlowProtocolError(
                "identity update returned an invalid structure")
        _atomic_private_json(path, identity)
    return str(path)


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


@contextlib.contextmanager
def _private_file_lock(path):
    lock_path = Path(str(path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _PROCESS_LOCK:
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(str(lock_path), flags, 0o600)
        except OSError:
            raise TerminalFlowProtocolError(
                "Attacca private-state lock cannot be opened safely") from None
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) \
                    or (hasattr(os, "geteuid") and
                        opened.st_uid != os.geteuid()):
                raise TerminalFlowProtocolError(
                    "Attacca private-state lock is not owner-controlled")
            os.fchmod(fd, 0o600)
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def load_device_id(identity_path=None):
    """Load/create the same private machine id used by the core client."""
    explicit = str(os.environ.get("ATTACCA_DEVICE_ID") or "").strip()
    if explicit:
        return _bounded_safe_id(explicit, "device_id")
    path = Path(identity_path or default_identity_path())
    result = {"device_id": None}

    def update(identity):
        current = str(identity.get("device_id") or "").strip()
        if current:
            result["device_id"] = _bounded_safe_id(current, "device_id")
            return identity
        current = "dev_" + secrets.token_hex(8)
        identity["device_id"] = current
        result["device_id"] = current
        return identity

    update_identity_store(path, update)
    return result["device_id"]


def load_client_instance_id(storage_path=None, runtime=None):
    """Return a stable non-secret id for one installed terminal client."""
    explicit = str(os.environ.get("ATTACCA_CLIENT_INSTANCE") or "").strip()
    if explicit:
        return _bounded_safe_id(explicit, "client_instance_id")
    runtime = _bounded_safe_id(
        str(runtime or "terminal").strip().lower(), "runtime")
    path = Path(storage_path or default_client_instance_path())
    with _private_file_lock(path):
        data = _read_private_json_unlocked(
            path, {"version": 1, "instances": {}},
            "Attacca client-instance state", MAX_PRIVATE_STATE_BYTES)
        instances = data.setdefault("instances", {})
        current = str(instances.get(runtime) or "").strip()
        if current:
            return _bounded_safe_id(current, "client_instance_id")
        current = "client_" + secrets.token_hex(8)
        instances[runtime] = current
        _atomic_private_json(path, data)
        return current


def _resolved_client_instance_id(value=None):
    return _bounded_safe_id(
        value or load_client_instance_id(), "client_instance_id")


def _merge_private_mapping(left, right):
    result = json.loads(json.dumps(left))
    for key, value in right.items():
        if key not in result:
            result[key] = json.loads(json.dumps(value))
        elif result[key] == value:
            continue
        elif isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_private_mapping(result[key], value)
        else:
            raise TerminalFlowProtocolError(
                "equivalent Attacca server credential records conflict")
    return result


def server_record_for_url(data, server_url):
    """Merge only exact canonically equivalent full-URL credential records."""
    target = canonical_server_url(server_url)
    matches = []
    for key, value in (data.get("servers") or {}).items():
        if not isinstance(value, dict):
            continue
        try:
            equivalent = canonical_server_url(key) == target
        except TerminalFlowError:
            equivalent = False
        if equivalent:
            matches.append(value)
    merged = {}
    for value in matches:
        merged = _merge_private_mapping(merged, value)
    return merged


def canonical_server_record_for_update(data, server_url):
    """Atomically re-key equivalent legacy spellings during a safe mutation."""
    target = canonical_server_url(server_url)
    servers = data.setdefault("servers", {})
    merged = server_record_for_url(data, target)
    for key in list(servers):
        try:
            equivalent = canonical_server_url(key) == target
        except TerminalFlowError:
            equivalent = False
        if equivalent:
            servers.pop(key, None)
    servers[target] = merged
    return merged


def _terminal_record(data, server_url):
    server = server_record_for_url(data, server_url)
    record = server.get("terminal_credential")
    return record if isinstance(record, dict) else None


def terminal_credential_status(server_url, *, device_id, project_id=None,
                               actor_id=None, runtime=None,
                               requested_bindings=None,
                               credentials_path=None, now=None):
    """Return non-secret readiness/migration metadata for one exact binding."""
    device_id = _bounded_safe_id(device_id, "device_id")
    path = Path(credentials_path or default_credentials_path())
    try:
        data = read_credentials_store(path)
    except TerminalFlowError:
        return {"status": "invalid", "credential_present": path.exists(),
                "legacy_actor_credentials": False,
                "credential_store_invalid": True}
    try:
        server = server_record_for_url(data, server_url)
    except TerminalFlowError:
        return {"status": "invalid", "credential_present": True,
                "legacy_actor_credentials": False,
                "credential_store_invalid": True}
    legacy = bool(server.get("agent_tokens") or server.get("tokens") or
                  server.get("api_token"))
    record = server.get("terminal_credential")
    if not isinstance(record, dict):
        return {"status": "migration_required" if legacy else "missing",
                "credential_present": False,
                "legacy_actor_credentials": legacy}
    recorded_device = str(record.get("device_id") or "")
    if recorded_device != device_id:
        return {"status": "wrong_device", "credential_present": True,
                "legacy_actor_credentials": legacy}
    try:
        checked = _validate_credential(record, device_id)
    except TerminalFlowError:
        return {"status": "invalid", "credential_present": True,
                "legacy_actor_credentials": legacy}
    bindings = checked["bindings"]
    expiry = _parse_expiry(checked.get("expires_at"))
    if expiry is not None and expiry <= float(time.time() if now is None else now):
        return {"status": "expired", "credential_present": True,
                "legacy_actor_credentials": legacy}
    if requested_bindings is not None:
        required = normalize_bindings(requested_bindings)
    elif project_id is None and actor_id is None:
        required = []
    elif not project_id or not actor_id:
        return {"status": "binding_missing", "credential_present": True,
                "legacy_actor_credentials": legacy}
    elif "." in str(actor_id):
        required = normalize_bindings([{
            "project_id": project_id, "actor_id": actor_id,
            **({"runtime": runtime} if runtime else {})}])
    else:
        runtime_hint = str(runtime or actor_id).strip().lower()
        candidates = [binding for binding in bindings
                      if binding["project_id"] == str(project_id)
                      and str(binding.get("runtime") or
                              binding["actor_id"].rsplit(".", 1)[-1]).lower()
                      == runtime_hint]
        if len(candidates) != 1:
            return {"status": "binding_missing", "credential_present": True,
                    "legacy_actor_credentials": legacy}
        required = candidates
    if any(not _binding_allowed(
            bindings, item["project_id"], item["actor_id"],
            item.get("runtime")) for item in required):
        return {"status": "binding_missing", "credential_present": True,
                "legacy_actor_credentials": legacy}
    return {"status": "ready", "credential_present": True,
            "legacy_actor_credentials": legacy,
            "binding_authorized": bool(required),
            "provisional_human": not bindings,
            "binding_count": len(bindings)}


def load_terminal_credential(server_url, *, device_id, project_id=None,
                             actor_id=None, runtime=None,
                             requested_bindings=None,
                             credentials_path=None, now=None):
    """Load the raw token only for an exact authorized call site.

    Callers must never serialize or log the return value.  Public status APIs
    above intentionally expose only booleans and state labels.
    """
    status = terminal_credential_status(
        server_url, device_id=device_id, project_id=project_id,
        actor_id=actor_id, runtime=runtime,
        requested_bindings=requested_bindings,
        credentials_path=credentials_path, now=now)
    if status["status"] != "ready":
        return None
    try:
        data = read_credentials_store(
            Path(credentials_path or default_credentials_path()))
    except TerminalFlowError:
        return None
    try:
        record = _terminal_record(data, server_url)
        checked = _validate_credential(record, device_id) if record else None
    except TerminalFlowError:
        return None
    return checked["token"] if checked else None


def _existing_valid_credential(server_url, *, device_id,
                               credentials_path=None, now=None):
    """Load one current private record for request-time supersession only."""
    try:
        data = read_credentials_store(
            Path(credentials_path or default_credentials_path()))
    except TerminalFlowError:
        return None
    try:
        record = _terminal_record(data, server_url)
        if not isinstance(record, dict):
            return None
        checked = _validate_credential(record, device_id)
    except TerminalFlowError:
        return None
    expiry = _parse_expiry(checked.get("expires_at"))
    if expiry is not None and expiry <= float(
            time.time() if now is None else now):
        return None
    return checked


def _existing_valid_bindings(server_url, *, device_id,
                             credentials_path=None, now=None):
    """Read only non-secret bindings from a currently usable local record."""
    record = _existing_valid_credential(
        server_url, device_id=device_id, credentials_path=credentials_path,
        now=now)
    return record["bindings"] if record else []


def _validate_credential(value, expected_device_id):
    if not isinstance(value, dict):
        raise TerminalFlowProtocolError(
            "approved terminal authorization omitted the credential")
    token = value.get("token")
    if not isinstance(token, str) or not token.strip() \
            or "\n" in token or "\r" in token \
            or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise TerminalFlowProtocolError(
            "approved terminal authorization returned an invalid credential")
    token_kind = str(value.get("token_kind") or "")
    if token_kind != "terminal":
        raise TerminalFlowProtocolError(
            "approved authorization did not return a terminal credential")
    device_id = _bounded_safe_id(value.get("device_id"), "credential device_id")
    if device_id != expected_device_id:
        raise TerminalFlowProtocolError(
            "approved terminal credential belongs to another device")
    token_id = _bounded_safe_id(value.get("token_id"), "credential token_id")
    bindings = normalize_bindings(value.get("bindings"))
    record = {
        "token": token.strip(),
        "token_kind": "terminal",
        "token_id": token_id,
        "device_id": device_id,
        "bindings": bindings,
    }
    for key in ("created_at", "expires_at"):
        if value.get(key) is not None:
            record[key] = str(value[key])
    for key in ("client_label", "client_instance"):
        if value.get(key) is None:
            continue
        metadata = str(value[key]).strip()
        if not metadata or len(metadata) > 120 \
                or any(ord(character) < 32 or ord(character) == 127
                       for character in metadata):
            raise TerminalFlowProtocolError(
                "terminal credential %s is invalid" % key)
        record[key] = metadata
    if "expires_at" in record and _parse_expiry(record["expires_at"]) is None:
        raise TerminalFlowProtocolError(
            "terminal credential expiry is invalid")
    return record


def save_terminal_credential(server_url, credential, *, device_id,
                             credentials_path=None):
    """Atomically persist exactly one runtime-independent server credential."""
    expected_device = _bounded_safe_id(device_id, "device_id")
    record = _validate_credential(credential, expected_device)
    path = Path(credentials_path or default_credentials_path())

    def update(data):
        data.setdefault("version", 1)
        server = canonical_server_record_for_update(data, server_url)
        # Preserve actor-bound records during migration/rollback.  The shared
        # terminal credential is one sibling record, never a runtime key. A
        # browser-approved zero-binding record is a provisional human setup
        # principal; exact AI lookups below remain fail-closed until a binding
        # is added or the credential is atomically replaced.
        server["terminal_credential"] = record
        return data

    update_credentials_store(path, update)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        raise TerminalFlowError(
            "terminal credential file permissions could not be secured")
    return {"status": "saved", "credential_saved": True,
            "credentials_file": str(path),
            "binding_count": len(record["bindings"])}


def add_terminal_binding(server_url, *, device_id, project_id, actor_id,
                         runtime=None, credentials_path=None, transport=None,
                         timeout=DEFAULT_TIMEOUT_SECONDS,
                         client_instance_id=None):
    """Add one exact actor and atomically refresh the same terminal bearer.

    This promotes a browser-approved provisional human setup credential without
    minting or exposing another secret. The current bearer authenticates the
    binding request, is verified again through auth/status, and is re-saved only
    after the server returns the exact requested actor binding.
    """
    server_url = canonical_server_url(server_url)
    device_id = _bounded_safe_id(device_id, "device_id")
    requested = _normalize_binding({
        "project_id": project_id,
        "actor_id": actor_id,
        **({"runtime": runtime} if runtime else {}),
    })
    client_instance_id = _resolved_client_instance_id(client_instance_id)
    credentials = Path(credentials_path or default_credentials_path())
    # Serialize binding refreshes across runtimes/processes. Without this
    # separate lock, a slower A response could overwrite a newer A+B metadata
    # record even though the server remained authoritative.
    update_lock = Path(str(credentials) + ".binding-update")
    with _private_file_lock(update_lock):
        current = _existing_valid_credential(
            server_url, device_id=device_id,
            credentials_path=credentials)
        if current is None:
            raise TerminalFlowProtocolError(
                "no valid Attacca terminal credential is available to bind")
        if _binding_allowed(
                current["bindings"], requested["project_id"],
                requested["actor_id"], requested.get("runtime")):
            return {
                "status": "ready", "credential_saved": True,
                "binding_count": len(current["bindings"]),
                "project_id": requested["project_id"],
                "actor_id": requested["actor_id"],
            }
        endpoint = TERMINAL_BINDING_PATH.format(
            token_id=quote(current["token_id"], safe=""))
        response = (transport or UrllibJsonTransport()).request(
            "POST", _endpoint(server_url, endpoint),
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer " + current["token"],
                "X-Attacca-Device-ID": device_id,
                "X-Attacca-Client-Instance": client_instance_id,
            },
            payload={
                "project_id": requested["project_id"],
                "actor_id": requested["actor_id"],
            }, timeout=timeout)
        if response.status != 200:
            raise TerminalFlowProtocolError(
                "Attacca rejected the terminal actor binding request")
        record = response.value.get("record")
        if not isinstance(record, dict):
            raise TerminalFlowProtocolError(
                "terminal actor binding returned invalid metadata")
        returned = _validate_credential(
            {**record, "token": current["token"]}, device_id)
        if not hmac.compare_digest(
                returned["token_id"], current["token_id"]):
            raise TerminalFlowProtocolError(
                "terminal actor binding returned another credential")
        if not _binding_allowed(
                returned["bindings"], requested["project_id"],
                requested["actor_id"], requested.get("runtime")):
            raise TerminalFlowProtocolError(
                "terminal actor binding did not authorize the requested AI")
        checked = _verify_pasted_terminal_credential(
            server_url, current["token"], device_id=device_id,
            requested_bindings=[requested], transport=transport,
            timeout=timeout, client_instance_id=client_instance_id)
        if not hmac.compare_digest(
                checked["token_id"], current["token_id"]):
            raise TerminalFlowProtocolError(
                "terminal actor binding verification changed credential")
        saved = save_terminal_credential(
            server_url, checked, device_id=device_id,
            credentials_path=credentials)
        return {
            "status": "bound", "credential_saved": True,
            "binding_count": saved["binding_count"],
            "project_id": requested["project_id"],
            "actor_id": requested["actor_id"],
        }


def _state_data(path):
    value = _read_private_json_unlocked(
        path, {"version": SCHEMA_VERSION, "flows": {}},
        "Attacca terminal-flow state", MAX_PRIVATE_STATE_BYTES)
    value.setdefault("version", SCHEMA_VERSION)
    value.setdefault("flows", {})
    return value


def _public_pending(flow, *, now, status="pending", browser_opened=False):
    remaining = max(0, int(float(flow["expires_at_epoch"]) - float(now)))
    next_poll = max(0, int(float(flow.get("next_poll_at_epoch") or now) -
                           float(now)))
    return {
        "status": status,
        "action_required": True,
        "verification_uri": flow["verification_uri"],
        "verification_uri_complete": flow.get("verification_uri_complete"),
        "user_code": flow["user_code"],
        "expires_in": remaining,
        "interval": int(flow["interval"]),
        "next_poll_in": next_poll,
        "browser_opened": bool(browser_opened),
    }


def _validate_start_response(server_url, value, *, device_id, client_label,
                             requested_bindings, client_instance_id, now):
    if not isinstance(value, dict):
        raise TerminalFlowProtocolError(
            "device authorization start returned an invalid response")
    device_code = value.get("device_code")
    if not isinstance(device_code, str) or not device_code.strip() \
            or "\n" in device_code or "\r" in device_code \
            or not 32 <= len(device_code.encode("utf-8")) \
            <= MAX_DEVICE_CODE_BYTES:
        raise TerminalFlowProtocolError(
            "device authorization start returned an invalid device code")
    device_code = device_code.strip()
    encoded_device_code = quote(device_code, safe="")
    pending_values = [item for key, item in value.items()
                      if key != "device_code"]
    inspected = 0
    while pending_values:
        item = pending_values.pop()
        inspected += 1
        if inspected > 10000:
            raise TerminalFlowProtocolError(
                "device authorization start returned excessive public metadata")
        if isinstance(item, dict):
            pending_values.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending_values.extend(item)
        elif isinstance(item, str) and (
                device_code in item or encoded_device_code in item):
            raise TerminalFlowProtocolError(
                "device authorization response reflected its private code")
    user_code = str(value.get("user_code") or "").strip()
    if not _SAFE_USER_CODE.fullmatch(user_code):
        raise TerminalFlowProtocolError(
            "device authorization start returned an invalid user code")
    verification_uri = _same_server_verification_url(
        server_url, value.get("verification_uri"), "verification_uri")
    complete = value.get("verification_uri_complete")
    verification_uri_complete = _same_server_verification_url(
        server_url, complete, "verification_uri_complete") if complete else None
    try:
        expires_in = int(value.get("expires_in"))
        interval = int(value.get("interval"))
    except (TypeError, ValueError):
        raise TerminalFlowProtocolError(
            "device authorization timing fields are invalid") from None
    if not 30 <= expires_in <= 24 * 60 * 60 or not 1 <= interval <= 60:
        raise TerminalFlowProtocolError(
            "device authorization timing fields are outside safe bounds")
    return {
        "server_url": canonical_server_url(server_url),
        "device_id": device_id,
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete,
        "client_label": client_label,
        # Private flow metadata. The backend binds polling to the client
        # instance that started enrollment, even though the resulting terminal
        # credential is shared by every runtime on this device.
        "client_instance_id": _bounded_safe_id(
            client_instance_id, "flow client_instance_id"),
        "requested_bindings": requested_bindings,
        "started_at_epoch": float(now),
        "expires_at_epoch": float(now) + expires_in,
        "interval": interval,
        "next_poll_at_epoch": float(now) + interval,
    }


def _open_verification_page(flow, browser_open=None):
    target = flow.get("verification_uri_complete") or flow["verification_uri"]
    try:
        return bool((browser_open or webbrowser.open)(target, new=2))
    except Exception:
        return False


def _stored_flow_client_instance(flow):
    """Return a safe creator instance or None for pre-upgrade/corrupt state."""
    if not isinstance(flow, dict):
        return None
    try:
        return _bounded_safe_id(
            flow.get("client_instance_id"), "flow client_instance_id")
    except TerminalFlowError:
        return None


def _claim_browser_attempt(path, server_url, device_id, now):
    """Claim one foreground browser attempt for a pending shared flow."""
    server_url = canonical_server_url(server_url)
    with _private_file_lock(path):
        data = _state_data(path)
        current = data["flows"].get(server_url)
        if not isinstance(current, dict) \
                or current.get("device_id") != device_id \
                or float(current.get("expires_at_epoch") or 0) <= float(now) \
                or current.get("browser_open_attempted_at_epoch") is not None:
            return current, False
        current["browser_open_attempted_at_epoch"] = float(now)
        data["flows"][server_url] = current
        _atomic_private_json(path, data)
        return current, True


def start_device_flow(server_url, *, device_id, client_label,
                      requested_bindings=None, state_path=None,
                      transport=None, timeout=DEFAULT_TIMEOUT_SECONDS,
                      now=None, open_browser=False, browser_open=None,
                      client_instance_id=None, supersede_credential=None):
    """Start once per server/device, returning only URL + short user code."""
    server_url = canonical_server_url(server_url)
    device_id = _bounded_safe_id(device_id, "device_id")
    client_label = str(client_label or "Attacca terminal").strip()
    if not client_label or len(client_label.encode("utf-8")) > 120 \
            or "\n" in client_label or "\r" in client_label:
        raise TerminalFlowProtocolError("client_label is invalid")
    bindings = normalize_bindings(requested_bindings)
    client_instance_id = _resolved_client_instance_id(client_instance_id)
    supersede = _validate_credential(supersede_credential, device_id) \
        if supersede_credential is not None else None
    path = Path(state_path or default_state_path())
    clock = float(time.time() if now is None else now)
    resumed = False
    with _private_file_lock(path):
        data = _state_data(path)
        existing = data["flows"].get(server_url)
        if isinstance(existing, dict) \
                and existing.get("device_id") == device_id \
                and _stored_flow_client_instance(existing) is not None \
                and float(existing.get("expires_at_epoch") or 0) > clock:
            flow = existing
            resumed = True
        else:
            payload = {"device_id": device_id, "client_label": client_label}
            if bindings:
                payload["requested_bindings"] = bindings
            headers = {"Accept": "application/json",
                       "X-Attacca-Device-ID": device_id,
                       "X-Attacca-Client-Instance": client_instance_id}
            if supersede:
                payload["supersede_token_id"] = supersede["token_id"]
                headers["Authorization"] = "Bearer " + supersede["token"]
            response = (transport or UrllibJsonTransport()).request(
                "POST", _endpoint(server_url, DEVICE_START_PATH),
                headers=headers, payload=payload, timeout=timeout)
            if response.status in {401, 403} and supersede:
                # A revoked/obsolete local terminal record must not deadlock
                # repair. Retry the public browser approval start once without
                # claiming supersession; the rejected old bearer is already
                # unusable and remains only in the preserved local record until
                # verified replacement storage succeeds.
                headers = dict(headers)
                headers.pop("Authorization", None)
                payload = dict(payload)
                payload.pop("supersede_token_id", None)
                response = (transport or UrllibJsonTransport()).request(
                    "POST", _endpoint(server_url, DEVICE_START_PATH),
                    headers=headers, payload=payload, timeout=timeout)
            if response.status not in {200, 201}:
                raise TerminalFlowProtocolError(
                    "Attacca rejected the device authorization start request")
            flow = _validate_start_response(
                server_url, response.value, device_id=device_id,
                client_label=client_label, requested_bindings=bindings,
                client_instance_id=client_instance_id, now=clock)
            data["flows"][server_url] = flow
            _atomic_private_json(path, data)
    opened = False
    if open_browser:
        claimed_flow, claimed = _claim_browser_attempt(
            path, server_url, device_id, clock)
        if claimed:
            opened = _open_verification_page(claimed_flow, browser_open)
    return _public_pending(
        flow, now=clock, status="pending" if resumed else "started",
        browser_opened=opened)


def _remove_flow(data, server_url):
    data.setdefault("flows", {}).pop(canonical_server_url(server_url), None)


def poll_device_flow(server_url, *, device_id, state_path=None,
                     credentials_path=None, transport=None,
                     timeout=DEFAULT_TIMEOUT_SECONDS, now=None, force=False,
                     client_instance_id=None):
    """Perform at most one bounded poll and consume an approved secret once."""
    server_url = canonical_server_url(server_url)
    device_id = _bounded_safe_id(device_id, "device_id")
    path = Path(state_path or default_state_path())
    # Validate caller metadata, but always poll with the creator recorded in
    # private flow state. Codex, Claude, and Kimi may all advance one shared
    # enrollment; switching runtimes must not invalidate backend polling.
    _resolved_client_instance_id(client_instance_id)
    clock = float(time.time() if now is None else now)
    with _private_file_lock(path):
        data = _state_data(path)
        flow = data["flows"].get(server_url)
        if not isinstance(flow, dict) or flow.get("device_id") != device_id:
            return {"status": "missing", "action_required": False}
        flow_client_instance = _stored_flow_client_instance(flow)
        if flow_client_instance is None:
            # A pre-upgrade flow did not retain the backend-bound instance and
            # cannot be polled safely. Discard only this ephemeral code so the
            # active caller can start a fresh browser flow on its next step.
            _remove_flow(data, server_url)
            _atomic_private_json(path, data)
            return {"status": "missing", "action_required": False}
        if float(flow.get("expires_at_epoch") or 0) <= clock:
            _remove_flow(data, server_url)
            _atomic_private_json(path, data)
            return {"status": "expired", "action_required": False}
        if not force and float(flow.get("next_poll_at_epoch") or 0) > clock:
            return _public_pending(flow, now=clock)
        response = (transport or UrllibJsonTransport()).request(
            "POST", _endpoint(server_url, DEVICE_POLL_PATH),
            headers={"Accept": "application/json",
                     "X-Attacca-Device-ID": device_id,
                     "X-Attacca-Client-Instance": flow_client_instance},
            payload={"device_code": flow["device_code"],
                     "device_id": device_id}, timeout=timeout)
        if response.status != 200:
            raise TerminalFlowProtocolError(
                "Attacca rejected the device authorization poll")
        state = str(response.value.get("status") or "").strip().lower()
        if state in {"pending", "authorization_pending"}:
            flow["next_poll_at_epoch"] = clock + int(flow["interval"])
            data["flows"][server_url] = flow
            _atomic_private_json(path, data)
            return _public_pending(flow, now=clock)
        if state == "slow_down":
            flow["interval"] = min(
                60, int(flow["interval"]) + POLL_SLOW_DOWN_SECONDS)
            flow["next_poll_at_epoch"] = clock + int(flow["interval"])
            data["flows"][server_url] = flow
            _atomic_private_json(path, data)
            return _public_pending(flow, now=clock, status="slow_down")
        if state in {"denied", "expired"}:
            _remove_flow(data, server_url)
            _atomic_private_json(path, data)
            return {"status": state, "action_required": False}
        if state not in {"approved", "consumed"}:
            raise TerminalFlowProtocolError(
                "device authorization poll returned an unknown status")
        # Approval promotes this flow's high-entropy device code to the
        # terminal Bearer. The server stores only its hash. A dropped approved
        # response can therefore be retried without minting another secret;
        # ``consumed`` means a prior verification arrived but a local atomic
        # write may still need to be repeated.
        credential = response.value.get("credential")
        promoted = credential.get("token") \
            if isinstance(credential, dict) else None
        if state == "approved" and (
                not isinstance(promoted, str) or
                not hmac.compare_digest(promoted, flow["device_code"])):
            raise TerminalFlowProtocolError(
                "approved authorization did not promote the device code")
        checked = _verify_pasted_terminal_credential(
            server_url, flow["device_code"], device_id=device_id,
            requested_bindings=flow.get("requested_bindings"),
            transport=transport, timeout=timeout,
            client_instance_id=flow_client_instance)
        saved = save_terminal_credential(
            server_url, checked, device_id=device_id,
            credentials_path=credentials_path)
        _remove_flow(data, server_url)
        _atomic_private_json(path, data)
        return {"status": "approved", "credential_saved": True,
                "action_required": False,
                "binding_count": saved["binding_count"]}


def advance_device_flow(server_url, *, device_id, client_label,
                        requested_bindings=None, state_path=None,
                        credentials_path=None, transport=None,
                        timeout=DEFAULT_TIMEOUT_SECONDS, now=None,
                        open_browser=False, browser_open=None,
                        force_poll=False, client_instance_id=None):
    """Nonblocking start/resume entry used by hooks and native skills."""
    bindings = normalize_bindings(requested_bindings)
    client_instance_id = _resolved_client_instance_id(client_instance_id)
    ready = terminal_credential_status(
        server_url, device_id=device_id,
        requested_bindings=bindings, credentials_path=credentials_path,
        now=now)
    if ready["status"] == "ready":
        return {"status": "ready", "credential_saved": True,
                "action_required": False,
                "provisional_human": bool(ready.get("provisional_human")),
                "binding_count": int(ready.get("binding_count") or 0)}
    path = Path(state_path or default_state_path())
    state = _state_data(path)
    flow = state.get("flows", {}).get(canonical_server_url(server_url))
    if isinstance(flow, dict) and flow.get("device_id") == device_id:
        opened = False
        if open_browser:
            claimed_flow, claimed = _claim_browser_attempt(
                path, server_url, device_id,
                float(time.time() if now is None else now))
            if claimed:
                opened = _open_verification_page(claimed_flow, browser_open)
        result = poll_device_flow(
            server_url, device_id=device_id, state_path=path,
            credentials_path=credentials_path, transport=transport,
            timeout=timeout, now=now, force=force_poll,
            client_instance_id=client_instance_id)
        if result.get("status") == "missing":
            # A pre-upgrade flow lacked its creator instance and was safely
            # removed. Continue this same foreground step by starting anew.
            flow = None
        else:
            if result.get("status") in {"pending", "slow_down"}:
                result["browser_opened"] = opened
            return result
    # Extending a machine credential must preserve every still-valid binding.
    # Requested bindings come first so their runtime metadata wins if an older
    # record omitted it.
    current = _existing_valid_credential(
        server_url, device_id=device_id,
        credentials_path=credentials_path, now=now)
    enrollment_bindings = normalize_bindings(
        bindings + (current["bindings"] if current else []))
    return start_device_flow(
        server_url, device_id=device_id, client_label=client_label,
        requested_bindings=enrollment_bindings, state_path=path,
        transport=transport,
        timeout=timeout, now=now, open_browser=open_browser,
        browser_open=browser_open,
        client_instance_id=client_instance_id,
        supersede_credential=current)


def fallback_login_url(server_url):
    return canonical_server_url(server_url).rstrip("/") + "/app"


def safe_recovery_result(server_url, operation):
    """Convert transport/protocol failure into a secret-free deferred result."""
    try:
        return operation()
    except TerminalFlowError:
        return {"status": "deferred", "action_required": True,
                "verification_uri": fallback_login_url(server_url),
                "verification_uri_complete": None, "user_code": None,
                "error": "secure browser sign-in is temporarily unavailable"}


@contextlib.contextmanager
def open_controlling_terminal():
    """Yield only a real foreground controlling TTY, never lifecycle stdin."""
    if os.name == "nt":  # pragma: no cover - CI exercises the POSIX contract.
        try:
            stream = open("CONIN$", "r+")
        except OSError:
            raise ControllingTerminalUnavailable(
                "no controlling terminal is available") from None
        try:
            if not stream.isatty():
                raise ControllingTerminalUnavailable(
                    "no controlling terminal is available")
            yield stream
        finally:
            stream.close()
        return
    flags = os.O_RDWR | getattr(os, "O_NOCTTY", 0)
    try:
        fd = os.open("/dev/tty", flags)
    except OSError:
        raise ControllingTerminalUnavailable(
            "no controlling terminal is available") from None
    try:
        if not os.isatty(fd):
            raise ControllingTerminalUnavailable(
                "no controlling terminal is available")
        if hasattr(os, "tcgetpgrp") and os.tcgetpgrp(fd) != os.getpgrp():
            raise ControllingTerminalUnavailable(
                "the controlling terminal is not in the foreground")
        with os.fdopen(fd, "r+", buffering=1, closefd=False) as stream:
            yield stream
    finally:
        os.close(fd)


def _read_hidden_line(stream, prompt):
    if not hasattr(stream, "fileno") or not stream.isatty():
        raise ControllingTerminalUnavailable(
            "hidden input requires a real controlling terminal")
    stream.write(prompt)
    stream.flush()
    if os.name == "nt":  # pragma: no cover
        import msvcrt
        chars = []
        while True:
            char = msvcrt.getwch()
            if char in {"\r", "\n"}:
                break
            if char == "\b":
                if chars:
                    chars.pop()
            elif char == "\x03":
                raise KeyboardInterrupt
            else:
                chars.append(char)
        stream.write("\n")
        return "".join(chars)
    import termios
    fd = stream.fileno()
    original = termios.tcgetattr(fd)
    hidden = list(original)
    hidden[3] &= ~termios.ECHO
    try:
        termios.tcsetattr(fd, termios.TCSAFLUSH, hidden)
        value = stream.readline()
    finally:
        termios.tcsetattr(fd, termios.TCSAFLUSH, original)
        stream.write("\n")
        stream.flush()
    return value.rstrip("\r\n")


def _verify_pasted_terminal_credential(server_url, token, *, device_id,
                                       requested_bindings=None,
                                       transport=None,
                                       timeout=DEFAULT_TIMEOUT_SECONDS,
                                       client_instance_id=None):
    if not isinstance(token, str) or not token.strip() or "\n" in token \
            or "\r" in token or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise TerminalFlowProtocolError("terminal credential is invalid")
    response = (transport or UrllibJsonTransport()).request(
        "GET", _endpoint(server_url, AUTH_STATUS_PATH),
        headers={"Accept": "application/json",
                 "Authorization": "Bearer " + token.strip(),
                 "X-Attacca-Device-ID": device_id,
                 "X-Attacca-Client-Instance":
                     _resolved_client_instance_id(client_instance_id)},
        timeout=timeout)
    if response.status != 200 or response.value.get("authenticated") is not True:
        raise TerminalFlowProtocolError(
            "Attacca rejected the terminal credential")
    principal = response.value.get("principal")
    if not isinstance(principal, dict):
        raise TerminalFlowProtocolError(
            "Attacca did not return terminal credential metadata")
    credential = {
        "token": token.strip(),
        "token_kind": principal.get("token_kind"),
        "token_id": principal.get("token_id"),
        "device_id": principal.get("device_id"),
        "bindings": principal.get("bindings"),
        "created_at": principal.get("created_at"),
        "expires_at": principal.get("expires_at"),
    }
    checked = _validate_credential(credential, device_id)
    for binding in normalize_bindings(requested_bindings):
        if not _binding_allowed(
                checked["bindings"], binding["project_id"],
                binding["actor_id"], binding.get("runtime")):
            raise TerminalFlowProtocolError(
                "terminal credential is not authorized for this workspace AI")
    return checked


def paste_from_controlling_tty(server_url, *, device_id,
                               requested_bindings=None,
                               credentials_path=None, transport=None,
                               timeout=DEFAULT_TIMEOUT_SECONDS,
                               tty_opener=open_controlling_terminal,
                               client_instance_id=None):
    """Hidden paste fallback; impossible through hook/chat stdin or argv."""
    device_id = _bounded_safe_id(device_id, "device_id")
    with tty_opener() as terminal:
        token = _read_hidden_line(
            terminal, "Paste Attacca terminal credential (input hidden): ")
    try:
        checked = _verify_pasted_terminal_credential(
            server_url, token, device_id=device_id,
            requested_bindings=requested_bindings,
            transport=transport, timeout=timeout,
            client_instance_id=client_instance_id)
        return save_terminal_credential(
            server_url, checked, device_id=device_id,
            credentials_path=credentials_path)
    finally:
        token = None


def format_recovery_message(result, server_url, project_id=None):
    """Format a model/user-visible message from a strict public field allowlist."""
    result = result if isinstance(result, dict) else {}
    state = str(result.get("status") or "deferred")
    workspace = " for workspace %s" % project_id if project_id else ""
    if state in {"started", "pending", "slow_down"}:
        target = result.get("verification_uri_complete") or \
            result.get("verification_uri") or fallback_login_url(server_url)
        code = result.get("user_code")
        code_text = " and enter code %s" % code if code else ""
        return (
            "Secure Attacca browser sign-in%s is ready. Open %s%s. "
            "Attacca started this flow and will poll, store the device-bound "
            "credential privately, and reconnect automatically. Do not paste "
            "a password or token into chat; no shell command or client restart "
            "is required." % (workspace, target, code_text))
    if state in {"approved", "ready"}:
        return (
            "Attacca browser sign-in%s is complete. The terminal credential "
            "was stored privately; hosted identity sync is being verified "
            "before the authentication latch is cleared." % workspace)
    if state in {"denied", "expired"}:
        return (
            "Attacca browser sign-in%s was %s. Attacca or the active AI will "
            "start a fresh native flow on its next retry; do not send "
            "credentials through chat." %
            (workspace, state))
    target = result.get("verification_uri") or fallback_login_url(server_url)
    return (
        "Attacca needs browser sign-in%s. Open %s. The lifecycle flow remains "
        "deferred and will retry without blocking this terminal; never paste "
        "a password or token into chat." % (workspace, target))


def _binding_argument(value):
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        raise argparse.ArgumentTypeError(
            "binding must be JSON with project_id and actor_id") from None
    try:
        return _normalize_binding(parsed)
    except TerminalFlowError as error:
        raise argparse.ArgumentTypeError(str(error)) from None


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Advance Attacca browser/device terminal authorization")
    parser.add_argument("action", choices=("advance", "poll", "status", "paste"))
    parser.add_argument("--server-url", required=True)
    parser.add_argument("--device-id")
    parser.add_argument("--client-instance-id")
    parser.add_argument("--client-label", default="Attacca terminal")
    parser.add_argument("--binding", action="append", type=_binding_argument,
                        default=[])
    parser.add_argument("--state-file")
    parser.add_argument("--credentials-file")
    parser.add_argument("--open-browser", action="store_true")
    parser.add_argument("--force-poll", action="store_true")
    args = parser.parse_args(argv)
    try:
        device_id = args.device_id or load_device_id()
        client_instance_id = args.client_instance_id or \
            load_client_instance_id()
        if args.action == "status":
            result = terminal_credential_status(
                args.server_url, device_id=device_id,
                requested_bindings=args.binding,
                credentials_path=args.credentials_file)
        elif args.action == "poll":
            result = poll_device_flow(
                args.server_url, device_id=device_id,
                state_path=args.state_file,
                credentials_path=args.credentials_file,
                force=args.force_poll,
                client_instance_id=client_instance_id)
        elif args.action == "paste":
            result = paste_from_controlling_tty(
                args.server_url, device_id=device_id,
                requested_bindings=args.binding,
                credentials_path=args.credentials_file,
                client_instance_id=client_instance_id)
        else:
            result = safe_recovery_result(
                args.server_url,
                lambda: advance_device_flow(
                    args.server_url, device_id=device_id,
                    client_label=args.client_label,
                    requested_bindings=args.binding,
                    state_path=args.state_file,
                    credentials_path=args.credentials_file,
                    open_browser=args.open_browser,
                    force_poll=args.force_poll,
                    client_instance_id=client_instance_id))
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("status") not in {"denied", "expired"} else 2
    except TerminalFlowError as error:
        print(json.dumps({"status": "error", "error": str(error)}, indent=2))
        return 2


__all__ = [
    "AUTH_STATUS_PATH", "DEVICE_POLL_PATH", "DEVICE_START_PATH",
    "ControllingTerminalUnavailable", "JsonResponse",
    "TerminalFlowError", "TerminalFlowProtocolError",
    "TerminalFlowTransportError", "TERMINAL_BINDING_PATH",
    "UrllibJsonTransport", "add_terminal_binding",
    "advance_device_flow", "canonical_server_url",
    "default_client_instance_path", "default_credentials_path",
    "default_identity_path", "default_state_path", "fallback_login_url",
    "format_recovery_message", "load_client_instance_id", "load_device_id",
    "load_terminal_credential", "normalize_bindings",
    "open_controlling_terminal", "paste_from_controlling_tty",
    "poll_device_flow", "safe_recovery_result", "save_terminal_credential",
    "start_device_flow", "terminal_credential_status",
]


if __name__ == "__main__":
    raise SystemExit(main())
