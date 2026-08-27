"""Private client-install authentication for Attacca coding clients.

Attacca supports exactly two interactive authentication mechanisms:

* a browser session for a human using the control panel; and
* a human-owned API key for one installed client instance.

The API key authenticates the installation, not an AI model, runtime, actor,
or role.  Every project request separately supplies the exact workspace and
canonical ``workspace.role.runtime`` actor.  The server then checks the
human's workspace membership and ownership of that already-registered actor.

The active AI starts a one-click browser pairing itself.  The signed-in human
approves the installation, while the client silently polls with a private
one-time pairing secret.  The delivered key is written atomically to the
private credential store and is available to the watcher immediately; it is
never pasted into argv, stdin, a URL, a log line, or the AI conversation, and
no coding-client restart is required.

Older releases imported several ``terminal_*`` and ``device_flow`` symbols.
Narrow compatibility wrappers remain at the bottom of this module and now map
onto the install-only pairing flow; no pairing binds an AI actor or role.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
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
except ImportError:  # pragma: no cover - Windows uses the process lock.
    fcntl = None


SCHEMA_VERSION = 2
DEFAULT_TIMEOUT_SECONDS = 5
MAX_JSON_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 16 * 1024
MAX_URL_BYTES = 8 * 1024
MAX_CREDENTIALS_BYTES = 4 * 1024 * 1024
MAX_PRIVATE_STATE_BYTES = 1024 * 1024

AUTH_STATUS_PATH = "/v1/auth/status"
CLIENT_KEYS_PATH = "/v1/auth/client-keys"
CLIENT_PAIRINGS_PATH = "/v1/auth/client-pairings"
CLIENT_INSTANCE_HEADER = "X-Attacca-Client-Instance"
DEVICE_ID_HEADER = "X-Attacca-Device-ID"
PROJECT_HEADER = "X-Attacca-Project"
ACTOR_HEADER = "X-Attacca-Actor"

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}$")
_SAFE_RUNTIME = re.compile(r"[^a-z0-9._-]+")
_PROCESS_LOCK = threading.RLock()


class TerminalFlowError(RuntimeError):
    """Base error whose text is safe to show outside the hidden prompt."""


class TerminalFlowProtocolError(TerminalFlowError):
    """The authorization server or local private state was malformed."""


class TerminalFlowTransportError(TerminalFlowError):
    """The authorization server could not be reached safely."""


class ControllingTerminalUnavailable(TerminalFlowError):
    """No verified foreground controlling terminal is available."""


@dataclass(frozen=True)
class JsonResponse:
    status: int
    headers: dict
    value: dict


class _RejectRedirects(HTTPRedirectHandler):
    """Never forward an API key to a redirect target."""

    def redirect_request(self, request, fp, code, msg, headers, new_url):
        return None


class UrllibJsonTransport:
    """Bounded JSON transport which never retains request credentials."""

    def __init__(self):
        self._opener = build_opener(_RejectRedirects())

    def request(self, method, url, *, headers, payload=None,
                timeout=DEFAULT_TIMEOUT_SECONDS):
        body = None
        request_headers = dict(headers or {})
        if payload is not None:
            try:
                body = json.dumps(
                    payload, separators=(",", ":"), ensure_ascii=False
                ).encode("utf-8")
            except (TypeError, ValueError) as error:
                raise TerminalFlowProtocolError(
                    "client authorization request is not valid JSON") from error
            if len(body) > MAX_JSON_BYTES:
                raise TerminalFlowProtocolError(
                    "client authorization request is too large")
            request_headers["Content-Type"] = "application/json"
        request = Request(
            url, data=body, headers=request_headers, method=str(method).upper())
        try:
            with self._opener.open(request, timeout=float(timeout)) as response:
                raw = response.read(MAX_JSON_BYTES + 1)
                if len(raw) > MAX_JSON_BYTES:
                    raise TerminalFlowProtocolError(
                        "client authorization response is too large")
                status_code = int(response.status)
                response_headers = {
                    key.lower(): value for key, value in response.headers.items()}
        except HTTPError as error:
            raw = error.read(MAX_JSON_BYTES + 1)
            if len(raw) > MAX_JSON_BYTES:
                raw = b""
            status_code = int(error.code)
            response_headers = {
                key.lower(): value for key, value in
                (error.headers.items() if error.headers is not None else [])}
        except (URLError, socket.timeout, TimeoutError, OSError):
            raise TerminalFlowTransportError(
                "Attacca client authorization is temporarily unavailable"
            ) from None
        try:
            value = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TerminalFlowProtocolError(
                "client authorization returned malformed JSON") from None
        if not isinstance(value, dict):
            raise TerminalFlowProtocolError(
                "client authorization returned a non-object response")
        return JsonResponse(
            status=status_code, headers=response_headers, value=value)


def default_credentials_path(home=None):
    return Path(home or Path.home()).expanduser().resolve() / \
        ".attacca" / "credentials.json"


def default_state_path(home=None):
    """Compatibility path only; client-key authorization has no poll state."""
    return Path(home or Path.home()).expanduser().resolve() / \
        ".attacca" / "authorization.json"


def default_identity_path(home=None):
    return Path(home or Path.home()).expanduser().resolve() / \
        ".attacca" / "identity.json"


def _normalized_runtime(runtime):
    value = str(runtime or os.environ.get("ATTACCA_RUNTIME") or "generic") \
        .strip().lower()
    value = _SAFE_RUNTIME.sub("-", value).strip("-._") or "generic"
    return value[:64]


def default_client_instance_path(home=None, runtime=None):
    """Return the private identity file for one concrete client install.

    Runtime-specific configuration roots distinguish two Codex/Claude/Kimi
    installations on the same machine.  Runtime is descriptive only; the
    generated ID itself carries no model or actor authorization.
    """
    explicit = os.environ.get("ATTACCA_CLIENT_INSTANCE_FILE")
    if explicit:
        return _absolute_private_path(explicit)
    base_home = Path(home or Path.home()).expanduser().resolve()
    runtime_name = _normalized_runtime(runtime)
    if runtime_name == "codex":
        root = Path(os.environ.get("CODEX_HOME") or base_home / ".codex")
    elif runtime_name in {"claude", "claude-code"}:
        root = Path(os.environ.get("CLAUDE_CONFIG_DIR") or base_home / ".claude")
    elif runtime_name in {"kimi", "kimi-code"}:
        root = Path(os.environ.get("KIMI_CODE_HOME") or
                    base_home / ".kimi-code")
    else:
        root = base_home / ".attacca" / "clients" / runtime_name
    return root.expanduser().resolve() / "attacca-client.json"


def _safe_comparison_path(value, label):
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
    """Canonicalize a hosted base URL without weakening tenant path scope."""
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
    if parsed.username is not None or parsed.password is not None:
        raise TerminalFlowProtocolError(
            "Attacca server URL cannot contain user information")
    if parsed.query or parsed.fragment:
        raise TerminalFlowProtocolError(
            "Attacca server URL cannot contain a query or fragment")
    try:
        port = parsed.port
    except ValueError:
        raise TerminalFlowProtocolError("Attacca server URL has an invalid port") \
            from None
    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    default_port = (parsed.scheme.lower() == "http" and port == 80) or \
        (parsed.scheme.lower() == "https" and port == 443)
    netloc = host if port is None or default_port else "%s:%s" % (host, port)
    path = _safe_comparison_path(parsed.path or "", "Attacca server URL")
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))


def _endpoint(server_url, path):
    return canonical_server_url(server_url) + "/" + str(path).lstrip("/")


def _bounded_safe_id(value, label, *, required=True):
    text = str(value or "").strip()
    if not text and not required:
        return None
    if not _SAFE_ID.fullmatch(text):
        raise TerminalFlowProtocolError("%s is missing or invalid" % label)
    return text


def _bounded_client_instance(value):
    text = _bounded_safe_id(value, "client_instance")
    if len(text) > 120:
        raise TerminalFlowProtocolError(
            "client_instance must be 120 characters or fewer")
    return text


def _parse_expiry(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        raise TerminalFlowProtocolError(
            "client API key has an invalid expiry") from None


def _now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _assert_private_regular(path, label, *, missing_ok=False,
                            max_bytes=MAX_PRIVATE_STATE_BYTES):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise TerminalFlowProtocolError("%s is missing" % label) from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise TerminalFlowProtocolError("%s must be a regular file" % label)
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise TerminalFlowProtocolError("%s is owned by another user" % label)
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise TerminalFlowProtocolError("%s must have mode 0600" % label)
    if info.st_size > max_bytes:
        raise TerminalFlowProtocolError("%s is too large" % label)
    return info


def _absolute_private_path(path):
    """Make a path absolute without resolving away a final symlink."""
    expanded = Path(path).expanduser()
    return Path(os.path.abspath(str(expanded)))


def _read_private_json_unlocked(path, default, label, max_bytes,
                                *, missing_ok=True):
    path = _absolute_private_path(path)
    info = _assert_private_regular(
        path, label, missing_ok=missing_ok, max_bytes=max_bytes)
    if info is None:
        return copy.deepcopy(default)
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise TerminalFlowProtocolError("%s is not valid private JSON" % label) \
            from None
    if not isinstance(value, dict):
        raise TerminalFlowProtocolError("%s must contain a JSON object" % label)
    return value


def _atomic_private_json(path, value):
    path = _absolute_private_path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    payload = (json.dumps(value, indent=2, sort_keys=True,
                          ensure_ascii=False) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(
        prefix=".%s." % path.name, dir=str(path.parent))
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        if hasattr(os, "O_DIRECTORY"):
            directory_fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


@contextlib.contextmanager
def _private_file_lock(path):
    path = _absolute_private_path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = path.with_name(".%s.lock" % path.name)
    with _PROCESS_LOCK:
        descriptor = os.open(
            str(lock_path), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
            0o600)
        try:
            os.fchmod(descriptor, 0o600)
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def read_credentials_store(credentials_path=None):
    path = _absolute_private_path(
        credentials_path or default_credentials_path())
    with _private_file_lock(path):
        value = _read_private_json_unlocked(
            path, {"schema": SCHEMA_VERSION, "servers": {}},
            "Attacca credentials", MAX_CREDENTIALS_BYTES)
    servers = value.get("servers")
    if servers is None:
        value["servers"] = {}
    elif not isinstance(servers, dict):
        raise TerminalFlowProtocolError(
            "Attacca credentials servers must be an object")
    return value


def update_credentials_store(credentials_path, updater):
    path = _absolute_private_path(
        credentials_path or default_credentials_path())
    with _private_file_lock(path):
        value = _read_private_json_unlocked(
            path, {"schema": SCHEMA_VERSION, "servers": {}},
            "Attacca credentials", MAX_CREDENTIALS_BYTES)
        if not isinstance(value.get("servers", {}), dict):
            raise TerminalFlowProtocolError(
                "Attacca credentials servers must be an object")
        value.setdefault("servers", {})
        updated = updater(value)
        if updated is not None:
            value = updated
        if not isinstance(value, dict):
            raise TerminalFlowProtocolError(
                "Attacca credentials update must return an object")
        value["schema"] = max(int(value.get("schema") or 1), SCHEMA_VERSION)
        _atomic_private_json(path, value)
        return copy.deepcopy(value)


def read_identity_store(identity_path=None):
    path = _absolute_private_path(identity_path or default_identity_path())
    with _private_file_lock(path):
        return _read_private_json_unlocked(
            path, {"schema": 1}, "Attacca identity", MAX_PRIVATE_STATE_BYTES)


def update_identity_store(identity_path, updater):
    path = _absolute_private_path(identity_path or default_identity_path())
    with _private_file_lock(path):
        value = _read_private_json_unlocked(
            path, {"schema": 1}, "Attacca identity", MAX_PRIVATE_STATE_BYTES)
        updated = updater(value)
        if updated is not None:
            value = updated
        if not isinstance(value, dict):
            raise TerminalFlowProtocolError(
                "Attacca identity update must return an object")
        value.setdefault("schema", 1)
        _atomic_private_json(path, value)
        return copy.deepcopy(value)


def load_device_id(identity_path=None):
    """Return a stable audit-only machine ID; it grants no authority."""
    found = read_identity_store(identity_path).get("device_id")
    if found:
        return _bounded_safe_id(found, "device_id")
    created = "device_%s" % secrets.token_urlsafe(18).rstrip("=")

    def install(value):
        existing = value.get("device_id")
        if existing:
            return value
        value["device_id"] = created
        value.setdefault("created_at", _now_iso())
        return value

    return _bounded_safe_id(
        update_identity_store(identity_path, install)["device_id"], "device_id")


def load_client_instance_id(storage_path=None, runtime=None):
    """Return the stable ID of this exact installed coding client."""
    # The bundled core historically passed the runtime as the first positional
    # argument. Preserve that call shape while keeping explicit file paths
    # unambiguous for isolated installs/tests.
    if runtime is None and isinstance(storage_path, str) \
            and "/" not in storage_path and "\\" not in storage_path \
            and storage_path.lower() in {
                "codex", "claude", "claude-code", "kimi", "kimi-code",
                "generic", "cline", "cursor", "windsurf", "gemini",
                "opencode", "mcp"}:
        runtime, storage_path = storage_path, None
    environment_id = os.environ.get("ATTACCA_CLIENT_INSTANCE")
    if environment_id:
        return _bounded_client_instance(environment_id)
    runtime_name = _normalized_runtime(runtime)
    path = _absolute_private_path(
        storage_path or default_client_instance_path(runtime=runtime_name))
    with _private_file_lock(path):
        value = _read_private_json_unlocked(
            path, {"schema": 1}, "Attacca client identity",
            MAX_PRIVATE_STATE_BYTES)
        found = value.get("client_instance")
        # Read the previous map format without changing the established ID.
        if not found and isinstance(value.get("runtimes"), dict):
            previous = value["runtimes"].get(runtime_name)
            if isinstance(previous, dict):
                found = previous.get("client_instance_id") or \
                    previous.get("client_instance")
            elif isinstance(previous, str):
                found = previous
        if found:
            return _bounded_client_instance(found)
        created = "client_%s" % secrets.token_urlsafe(24).rstrip("=")
        value.update({
            "schema": 1,
            "client_instance": created,
            "runtime": runtime_name,
            "created_at": _now_iso(),
        })
        _atomic_private_json(path, value)
        return created


def _resolved_client_instance_id(value=None, *, runtime=None,
                                 storage_path=None):
    return _bounded_client_instance(
        value or load_client_instance_id(storage_path, runtime=runtime))


def server_record_for_url(data, server_url):
    if not isinstance(data, dict) or not isinstance(data.get("servers"), dict):
        return None
    return data["servers"].get(canonical_server_url(server_url))


def canonical_server_record_for_update(data, server_url):
    if not isinstance(data, dict):
        raise TerminalFlowProtocolError("Attacca credentials must be an object")
    servers = data.setdefault("servers", {})
    if not isinstance(servers, dict):
        raise TerminalFlowProtocolError(
            "Attacca credentials servers must be an object")
    key = canonical_server_url(server_url)
    record = servers.setdefault(key, {})
    if not isinstance(record, dict):
        raise TerminalFlowProtocolError(
            "Attacca server credential record must be an object")
    return record


def _validate_token(token):
    if not isinstance(token, str):
        raise TerminalFlowProtocolError("client API key is invalid")
    token = token.strip()
    if not token.startswith("atkey_") or any(character.isspace()
                                               for character in token):
        raise TerminalFlowProtocolError(
            "Attacca rejected this value: expected a client API key")
    if len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise TerminalFlowProtocolError("client API key is too long")
    return token


def _validate_client_credential(value, expected_instance=None):
    if not isinstance(value, dict):
        raise TerminalFlowProtocolError(
            "stored client API key record is invalid")
    token = _validate_token(value.get("token"))
    client_instance = _bounded_client_instance(value.get("client_instance"))
    if expected_instance and client_instance != expected_instance:
        raise TerminalFlowProtocolError(
            "stored client API key belongs to another client installation")
    token_id = _bounded_safe_id(value.get("token_id"), "token_id", required=False)
    username = _bounded_safe_id(value.get("username"), "username", required=False)
    memberships = value.get("project_memberships") or []
    if not isinstance(memberships, list):
        raise TerminalFlowProtocolError(
            "stored client API key workspace scope is invalid")
    memberships = [_bounded_safe_id(item, "project_id") for item in memberships]
    expiry = value.get("expires_at")
    _parse_expiry(expiry)
    return {
        "token": token,
        "token_kind": "client",
        "token_id": token_id,
        "client_instance": client_instance,
        "username": username,
        "project_memberships": list(dict.fromkeys(memberships)),
        "scope_mode": value.get("scope_mode") or
            ("selected_workspaces" if memberships else "account_memberships"),
        "label": str(value.get("label") or "Attacca client")[:120],
        "device_id": value.get("device_id"),
        "created_at": value.get("created_at"),
        "expires_at": expiry,
        "last_verified_at": value.get("last_verified_at"),
    }


def _client_key_record(data, server_url, client_instance):
    server = server_record_for_url(data, server_url)
    if not isinstance(server, dict):
        return None
    keys = server.get("client_api_keys")
    if not isinstance(keys, dict):
        return None
    return keys.get(client_instance)


def client_api_key_status(server_url, *, client_instance=None, runtime=None,
                          storage_path=None, project_id=None,
                          credentials_path=None, now=None, **_ignored):
    instance = _resolved_client_instance_id(
        client_instance, runtime=runtime, storage_path=storage_path)
    data = read_credentials_store(credentials_path)
    raw = _client_key_record(data, server_url, instance)
    if raw is None:
        server = server_record_for_url(data, server_url) or {}
        legacy = bool(server.get("terminal_credential") or
                      server.get("agent_tokens"))
        return {
            "status": "authorization_required",
            "authorized": False,
            "client_instance": instance,
            "legacy_credential_present": legacy,
            "authorization_url": client_key_settings_url(
                server_url, instance),
            "hot_reload": True,
        }
    try:
        record = _validate_client_credential(raw, instance)
    except TerminalFlowProtocolError as error:
        return {"status": "invalid", "authorized": False,
                "client_instance": instance, "error": str(error),
                "authorization_url": client_key_settings_url(
                    server_url, instance), "hot_reload": True}
    instant = now or datetime.now(timezone.utc)
    expiry = _parse_expiry(record.get("expires_at"))
    if expiry and expiry <= instant:
        return {"status": "expired", "authorized": False,
                "client_instance": instance, "token_id": record.get("token_id"),
                "username": record.get("username"),
                "authorization_url": client_key_settings_url(
                    server_url, instance), "hot_reload": True}
    memberships = record["project_memberships"]
    if project_id and memberships and project_id not in memberships:
        return {"status": "wrong_workspace", "authorized": False,
                "client_instance": instance, "token_id": record.get("token_id"),
                "username": record.get("username"),
                "project_memberships": memberships,
                "authorization_url": client_key_settings_url(
                    server_url, instance), "hot_reload": True}
    return {
        "status": "ready",
        "authorized": True,
        "client_instance": instance,
        "token_id": record.get("token_id"),
        "username": record.get("username"),
        "project_memberships": memberships,
        "scope_mode": record.get("scope_mode"),
        "expires_at": record.get("expires_at"),
        "hot_reload": True,
    }


def load_client_api_key(server_url, *, client_instance=None, runtime=None,
                        storage_path=None, project_id=None,
                        credentials_path=None):
    instance = _resolved_client_instance_id(
        client_instance, runtime=runtime, storage_path=storage_path)
    status = client_api_key_status(
        server_url, client_instance=instance, project_id=project_id,
        credentials_path=credentials_path)
    if status["status"] != "ready":
        return None
    record = _client_key_record(
        read_credentials_store(credentials_path), server_url, instance)
    return _validate_client_credential(record, instance)["token"]


def save_client_api_key(server_url, credential, *, client_instance=None,
                        runtime=None, storage_path=None,
                        credentials_path=None):
    """Persist a server-verified key without ever returning its plaintext."""
    instance = _resolved_client_instance_id(
        client_instance, runtime=runtime, storage_path=storage_path)
    supplied = credential
    if isinstance(credential, dict) and isinstance(credential.get("record"), dict):
        supplied = dict(credential["record"])
        supplied["token"] = credential.get("token")
    if not isinstance(supplied, dict):
        supplied = {"token": supplied}
    supplied = dict(supplied)
    supplied.setdefault("client_instance", instance)
    supplied.setdefault("token_kind", "client")
    supplied.setdefault("created_at", _now_iso())
    checked = _validate_client_credential(supplied, instance)
    checked["last_verified_at"] = supplied.get("last_verified_at") or _now_iso()

    def install(data):
        server = canonical_server_record_for_update(data, server_url)
        keys = server.setdefault("client_api_keys", {})
        if not isinstance(keys, dict):
            raise TerminalFlowProtocolError(
                "Attacca client API key store is invalid")
        keys[instance] = checked
        return data

    update_credentials_store(credentials_path, install)
    return {
        "status": "ready", "authorized": True,
        "client_instance": instance, "token_id": checked.get("token_id"),
        "username": checked.get("username"),
        "project_memberships": checked.get("project_memberships", []),
        "scope_mode": checked.get("scope_mode"),
        "expires_at": checked.get("expires_at"), "hot_reload": True,
    }


def forget_client_api_key(server_url, *, client_instance=None, runtime=None,
                          storage_path=None, credentials_path=None):
    instance = _resolved_client_instance_id(
        client_instance, runtime=runtime, storage_path=storage_path)

    def remove(data):
        server = server_record_for_url(data, server_url)
        if isinstance(server, dict) and isinstance(
                server.get("client_api_keys"), dict):
            server["client_api_keys"].pop(instance, None)
        return data

    update_credentials_store(credentials_path, remove)
    return {"ok": True, "client_instance": instance, "forgotten": True}


def client_request_headers(server_url, *, token=None, client_instance=None,
                           runtime=None, storage_path=None, project_id=None,
                           actor_id=None, device_id=None,
                           credentials_path=None):
    """Build exact, attribution-preserving headers for one client request."""
    instance = _resolved_client_instance_id(
        client_instance, runtime=runtime, storage_path=storage_path)
    secret = token or load_client_api_key(
        server_url, client_instance=instance, project_id=project_id,
        credentials_path=credentials_path)
    if not secret:
        raise TerminalFlowProtocolError(
            "this Attacca client installation is not authorized")
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer " + _validate_token(secret),
        CLIENT_INSTANCE_HEADER: instance,
    }
    if device_id:
        headers[DEVICE_ID_HEADER] = _bounded_safe_id(device_id, "device_id")
    if bool(project_id) != bool(actor_id):
        raise TerminalFlowProtocolError(
            "project_id and canonical actor_id must be supplied together")
    if project_id:
        headers[PROJECT_HEADER] = _bounded_safe_id(project_id, "project_id")
        headers[ACTOR_HEADER] = _bounded_safe_id(actor_id, "actor_id")
    return headers


def verify_client_api_key(server_url, token, *, client_instance=None,
                          runtime=None, storage_path=None, project_id=None,
                          actor_id=None, device_id=None, transport=None,
                          timeout=DEFAULT_TIMEOUT_SECONDS,
                          verify_registered_actor=True):
    """Verify a pasted key and return only safe metadata."""
    instance = _resolved_client_instance_id(
        client_instance, runtime=runtime, storage_path=storage_path)
    headers = client_request_headers(
        server_url, token=token, client_instance=instance,
        project_id=project_id if verify_registered_actor else None,
        actor_id=actor_id if verify_registered_actor else None,
        device_id=device_id)
    response = (transport or UrllibJsonTransport()).request(
        "GET", _endpoint(server_url, AUTH_STATUS_PATH), headers=headers,
        timeout=timeout)
    if response.status not in {200, 401, 403}:
        raise TerminalFlowProtocolError(
            "Attacca returned an unexpected authorization response")
    if response.status != 200 or response.value.get("authenticated") is not True:
        raise TerminalFlowProtocolError(
            "Attacca rejected this client API key")
    principal = response.value.get("principal")
    if not isinstance(principal, dict) or principal.get("token_kind") != "client":
        raise TerminalFlowProtocolError(
            "Attacca rejected this value: it is not a client API key")
    returned_instance = _bounded_client_instance(
        principal.get("client_instance"))
    if returned_instance != instance:
        raise TerminalFlowProtocolError(
            "client API key belongs to another client installation")
    user = response.value.get("user")
    username = principal.get("username")
    if not username and isinstance(user, dict):
        username = user.get("username")
    username = _bounded_safe_id(username, "username")
    memberships = principal.get("project_memberships") or []
    if not isinstance(memberships, list):
        raise TerminalFlowProtocolError(
            "Attacca returned an invalid client workspace scope")
    memberships = [_bounded_safe_id(item, "project_id") for item in memberships]
    if project_id and memberships and project_id not in memberships:
        raise TerminalFlowProtocolError(
            "client API key is outside this workspace scope")
    record = {
        "token": _validate_token(token),
        "token_kind": "client",
        "token_id": _bounded_safe_id(
            principal.get("token_id"), "token_id", required=False),
        "client_instance": instance,
        "username": username,
        "project_memberships": list(dict.fromkeys(memberships)),
        "scope_mode": principal.get("scope_mode") or
            ("selected_workspaces" if memberships else "account_memberships"),
        "label": principal.get("client_label") or "Attacca client",
        "device_id": principal.get("device_id"),
        "created_at": principal.get("created_at"),
        "expires_at": principal.get("expires_at"),
        "last_verified_at": _now_iso(),
    }
    return _validate_client_credential(record, instance)


def client_key_settings_url(server_url, client_instance=None,
                            client_label="Attacca client"):
    """Return a same-server browser URL containing only non-secret hints."""
    instance = _resolved_client_instance_id(client_instance)
    fragment = "settings&client_instance=%s&client_label=%s" % (
        quote(instance, safe=""), quote(str(client_label or "Attacca client")[:120],
                                        safe=""))
    return _endpoint(server_url, "/app") + "#" + fragment


def _pairing_record(data, server_url, client_instance):
    server = server_record_for_url(data, server_url)
    rows = server.get("client_pairings") if isinstance(server, dict) else None
    return rows.get(client_instance) if isinstance(rows, dict) else None


def _validate_pairing_secret(value):
    if not isinstance(value, str) or not 16 <= len(value) <= MAX_TOKEN_BYTES \
            or any(character.isspace() for character in value):
        raise TerminalFlowProtocolError(
            "Attacca returned an invalid pairing secret")
    return value


def _store_pairing(server_url, instance, pairing, credentials_path=None):
    def install(data):
        server = canonical_server_record_for_update(data, server_url)
        server.setdefault("client_pairings", {})[instance] = pairing
        return data
    update_credentials_store(credentials_path, install)


def _forget_pairing(server_url, instance, credentials_path=None):
    def remove(data):
        server = server_record_for_url(data, server_url)
        if isinstance(server, dict) and isinstance(
                server.get("client_pairings"), dict):
            server["client_pairings"].pop(instance, None)
        return data
    update_credentials_store(credentials_path, remove)


def start_client_pairing(server_url, *, client_instance=None, runtime=None,
                         storage_path=None, client_label="Attacca client",
                         device_id=None, credentials_path=None, transport=None,
                         timeout=DEFAULT_TIMEOUT_SECONDS, open_browser=True,
                         browser_open=None):
    """Start one install-only browser pairing and persist its secret privately."""
    instance = _resolved_client_instance_id(
        client_instance, runtime=runtime, storage_path=storage_path)
    response = (transport or UrllibJsonTransport()).request(
        "POST", _endpoint(server_url, CLIENT_PAIRINGS_PATH),
        headers={"Accept": "application/json"}, payload={
            "client_instance": instance,
            "label": str(client_label or "Attacca client")[:120],
            "device_id": device_id,
        }, timeout=timeout)
    if response.status not in {200, 201}:
        raise TerminalFlowProtocolError(
            "Attacca could not start client authorization")
    value = response.value
    secret = _validate_pairing_secret(value.get("pairing_secret"))
    code = _bounded_safe_id(value.get("pairing_code"), "pairing_code")
    url = value.get("verification_uri_complete")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise TerminalFlowProtocolError(
            "Attacca returned an invalid authorization link")
    pairing = {
        "pairing_secret": secret, "pairing_code": code,
        "authorization_url": url,
        "expires_at": value.get("expires_at"),
        "expires_in": value.get("expires_in"),
        "interval": max(1, int(value.get("interval") or 5)),
        "device_id": device_id,
        "created_at": _now_iso(), "browser_prompted": True,
    }
    _store_pairing(server_url, instance, pairing, credentials_path)
    opened = False
    if open_browser:
        try:
            opened = bool((browser_open or webbrowser.open)(url))
        except Exception:
            opened = False
    return {"status": "pending", "authorized": False,
            "client_instance": instance, "pairing_code": code,
            "authorization_url": url, "browser_opened": opened,
            "interval": pairing["interval"], "hot_reload": True}


def poll_client_pairing(server_url, *, client_instance=None, runtime=None,
                        storage_path=None, credentials_path=None,
                        transport=None, timeout=DEFAULT_TIMEOUT_SECONDS):
    """Poll silently; consume and persist an approved one-time credential."""
    instance = _resolved_client_instance_id(
        client_instance, runtime=runtime, storage_path=storage_path)
    pairing = _pairing_record(
        read_credentials_store(credentials_path), server_url, instance)
    if not isinstance(pairing, dict):
        return {"status": "authorization_required", "authorized": False,
                "client_instance": instance, "hot_reload": True}
    response = (transport or UrllibJsonTransport()).request(
        "POST", _endpoint(server_url, CLIENT_PAIRINGS_PATH + "/poll"),
        headers={"Accept": "application/json"}, payload={
            "pairing_secret": pairing.get("pairing_secret"),
            "client_instance": instance,
            "device_id": pairing.get("device_id"),
        }, timeout=timeout)
    value = response.value
    state = str(value.get("status") or "").lower()
    if response.status in {202, 428} or state in {"pending", "slow_down"}:
        return {"status": "pending", "authorized": False,
                "client_instance": instance,
                "authorization_url": pairing.get("authorization_url"),
                "pairing_code": pairing.get("pairing_code"),
                "interval": pairing.get("interval", 5), "hot_reload": True}
    if response.status != 200 or state not in {"approved", "ready"}:
        if state in {"denied", "expired"} or response.status in {404, 410}:
            _forget_pairing(server_url, instance, credentials_path)
        return {"status": state or "authorization_required",
                "authorized": False, "client_instance": instance,
                "hot_reload": True}
    credential = value.get("credential") or value.get("client_api_key")
    if isinstance(credential, str):
        credential = {"token": credential}
    if not isinstance(credential, dict):
        credential = dict(value)
        credential["token"] = value.get("token")
    credential.setdefault("client_instance", instance)
    credential.setdefault("token_kind", "client")
    result = save_client_api_key(
        server_url, credential, client_instance=instance,
        credentials_path=credentials_path)
    _forget_pairing(server_url, instance, credentials_path)
    return result


@contextlib.contextmanager
def open_controlling_terminal():
    """Yield only a real foreground controlling TTY, never hook/chat stdin."""
    if os.name == "nt":  # pragma: no cover
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
        descriptor = os.open("/dev/tty", flags)
    except OSError:
        raise ControllingTerminalUnavailable(
            "no controlling terminal is available") from None
    try:
        if not os.isatty(descriptor):
            raise ControllingTerminalUnavailable(
                "no controlling terminal is available")
        if hasattr(os, "tcgetpgrp") and os.tcgetpgrp(descriptor) != os.getpgrp():
            raise ControllingTerminalUnavailable(
                "the controlling terminal is not in the foreground")
        with os.fdopen(descriptor, "r+", buffering=1, closefd=False) as stream:
            yield stream
    finally:
        os.close(descriptor)


def _read_hidden_line(stream, prompt):
    if not hasattr(stream, "fileno") or not stream.isatty():
        raise ControllingTerminalUnavailable(
            "hidden input requires a real controlling terminal")
    stream.write(prompt)
    stream.flush()
    if os.name == "nt":  # pragma: no cover
        import msvcrt
        characters = []
        while True:
            character = msvcrt.getwch()
            if character in {"\r", "\n"}:
                break
            if character == "\b":
                if characters:
                    characters.pop()
            elif character == "\x03":
                raise KeyboardInterrupt
            else:
                characters.append(character)
        stream.write("\n")
        return "".join(characters)
    import termios
    descriptor = stream.fileno()
    original = termios.tcgetattr(descriptor)
    hidden = list(original)
    hidden[3] &= ~termios.ECHO
    try:
        termios.tcsetattr(descriptor, termios.TCSAFLUSH, hidden)
        value = stream.readline()
    finally:
        termios.tcsetattr(descriptor, termios.TCSAFLUSH, original)
        stream.write("\n")
        stream.flush()
    return value.rstrip("\r\n")


def paste_client_api_key(server_url, *, client_instance=None, runtime=None,
                         storage_path=None, project_id=None, actor_id=None,
                         device_id=None, credentials_path=None, transport=None,
                         timeout=DEFAULT_TIMEOUT_SECONDS,
                         tty_opener=open_controlling_terminal):
    """Accept, verify, and persist one key through hidden terminal input."""
    instance = _resolved_client_instance_id(
        client_instance, runtime=runtime, storage_path=storage_path)
    token = None
    try:
        with tty_opener() as terminal:
            token = _read_hidden_line(
                terminal,
                "Paste the Attacca client API key (hidden; never paste it in chat): ")
        checked = verify_client_api_key(
            server_url, token, client_instance=instance,
            project_id=project_id, actor_id=actor_id, device_id=device_id,
            transport=transport, timeout=timeout,
            # A fresh runtime in an already-linked checkout does not have an
            # actor row yet. First verify the human-owned install key itself;
            # the immediately following POST /agents proves membership and
            # creates only that exact requested actor. Normal calls then use
            # exact project+actor headers.
            verify_registered_actor=False)
        return save_client_api_key(
            server_url, checked, client_instance=instance,
            credentials_path=credentials_path)
    finally:
        token = None


def authorize_client(server_url, *, client_instance=None, runtime=None,
                     storage_path=None, client_label="Attacca client",
                     project_id=None, actor_id=None, device_id=None,
                     credentials_path=None, transport=None,
                     timeout=DEFAULT_TIMEOUT_SECONDS, open_browser=True,
                     browser_open=None, prompt=True,
                     tty_opener=open_controlling_terminal):
    """AI-initiated one-click browser pairing with silent hot reload."""
    instance = _resolved_client_instance_id(
        client_instance, runtime=runtime, storage_path=storage_path)
    status = client_api_key_status(
        server_url, client_instance=instance, project_id=project_id,
        credentials_path=credentials_path)
    if status.get("authorized"):
        return status
    existing = _pairing_record(
        read_credentials_store(credentials_path), server_url, instance)
    if isinstance(existing, dict):
        polled = poll_client_pairing(
            server_url, client_instance=instance,
            credentials_path=credentials_path, transport=transport,
            timeout=timeout)
        if polled.get("status") not in {"expired", "denied",
                                         "authorization_required"}:
            return polled
    return start_client_pairing(
        server_url, client_instance=instance, client_label=client_label,
        device_id=device_id, credentials_path=credentials_path,
        transport=transport, timeout=timeout, open_browser=open_browser,
        browser_open=browser_open)


def fallback_login_url(server_url):
    return _endpoint(server_url, "/app") + "#settings"


def safe_recovery_result(server_url, operation):
    try:
        return operation()
    except TerminalFlowError:
        return {
            "status": "authorization_required", "authorized": False,
            "authorization_url": fallback_login_url(server_url),
            "hot_reload": True,
            "error": "secure client authorization is temporarily unavailable",
        }


def format_authorization_message(result, server_url, project_id=None):
    """Format a public message from an explicit no-secret allowlist."""
    result = result if isinstance(result, dict) else {}
    workspace = " for workspace %s" % project_id if project_id else ""
    if result.get("status") == "ready" or result.get("authorized") is True:
        return (
            "Attacca authorization%s is ready for this client installation. "
            "The human account, AI actor, role, and runtime remain separate "
            "audit fields; no client restart is required." % workspace)
    url = result.get("authorization_url") or fallback_login_url(server_url)
    return (
        "Attacca needs browser sign-in and client authorization%s. The active "
        "AI opened %s so the signed-in human can approve this client "
        "installation. Attacca polls silently, stores the delivered credential "
        "privately, and reconnects immediately. Never paste an API key into "
        "chat or an ordinary shell command; no "
        "coding-client restart is required." % (workspace, url))


# -- rolling-update compatibility -----------------------------------------

def _binding(value):
    if not isinstance(value, dict):
        raise TerminalFlowProtocolError("binding must be an object")
    project = _bounded_safe_id(value.get("project_id"), "project_id")
    actor = _bounded_safe_id(value.get("actor_id"), "actor_id")
    return {"project_id": project, "actor_id": actor,
            "runtime": value.get("runtime")}


def normalize_bindings(bindings):
    result = []
    for value in bindings or []:
        item = _binding(value)
        if item not in result:
            result.append(item)
    return result


def _first_binding(requested_bindings=None, project_id=None, actor_id=None):
    values = normalize_bindings(requested_bindings)
    if values:
        return values[0]["project_id"], values[0]["actor_id"]
    return project_id, actor_id


def terminal_credential_status(server_url, *, device_id=None, project_id=None,
                               actor_id=None, requested_bindings=None,
                               credentials_path=None, client_instance_id=None,
                               runtime=None, **kwargs):
    project, _actor = _first_binding(
        requested_bindings, project_id, actor_id)
    return client_api_key_status(
        server_url, client_instance=client_instance_id, runtime=runtime,
        project_id=project, credentials_path=credentials_path)


def load_terminal_credential(server_url, *, device_id=None, project_id=None,
                             actor_id=None, requested_bindings=None,
                             credentials_path=None, client_instance_id=None,
                             runtime=None, **kwargs):
    project, _actor = _first_binding(
        requested_bindings, project_id, actor_id)
    return load_client_api_key(
        server_url, client_instance=client_instance_id, runtime=runtime,
        project_id=project, credentials_path=credentials_path)


def save_terminal_credential(server_url, credential, *, device_id=None,
                             credentials_path=None, client_instance_id=None,
                             runtime=None, **kwargs):
    return save_client_api_key(
        server_url, credential, client_instance=client_instance_id,
        runtime=runtime, credentials_path=credentials_path)


def paste_from_controlling_tty(server_url, *, device_id=None,
                               requested_bindings=None, credentials_path=None,
                               transport=None, timeout=DEFAULT_TIMEOUT_SECONDS,
                               tty_opener=open_controlling_terminal,
                               client_instance_id=None, runtime=None, **kwargs):
    project_id, actor_id = _first_binding(requested_bindings)
    return paste_client_api_key(
        server_url, client_instance=client_instance_id, runtime=runtime,
        project_id=project_id, actor_id=actor_id, device_id=device_id,
        credentials_path=credentials_path, transport=transport,
        timeout=timeout, tty_opener=tty_opener)


def add_terminal_binding(server_url, *, device_id=None, project_id,
                         actor_id, credentials_path=None,
                         client_instance_id=None, transport=None,
                         timeout=DEFAULT_TIMEOUT_SECONDS, **kwargs):
    token = load_client_api_key(
        server_url, client_instance=client_instance_id,
        project_id=project_id, credentials_path=credentials_path)
    if not token:
        return {"status": "authorization_required", "authorized": False,
                "client_instance": _resolved_client_instance_id(
                    client_instance_id), "hot_reload": True}
    checked = verify_client_api_key(
        server_url, token, client_instance=client_instance_id,
        project_id=project_id, actor_id=actor_id, device_id=device_id,
        transport=transport, timeout=timeout)
    return save_client_api_key(
        server_url, checked, client_instance=client_instance_id,
        credentials_path=credentials_path)


def start_device_flow(server_url, *, device_id=None,
                      client_label="Attacca client", requested_bindings=None,
                      credentials_path=None, client_instance_id=None,
                      open_browser=True, browser_open=None, transport=None,
                      timeout=DEFAULT_TIMEOUT_SECONDS, **kwargs):
    project_id, actor_id = _first_binding(requested_bindings)
    return authorize_client(
        server_url, client_instance=client_instance_id,
        client_label=client_label, project_id=project_id, actor_id=actor_id,
        device_id=device_id, credentials_path=credentials_path,
        transport=transport, timeout=timeout, open_browser=open_browser,
        browser_open=browser_open, prompt=False)


def poll_device_flow(server_url, *, device_id=None, credentials_path=None,
                     client_instance_id=None, requested_bindings=None,
                     **kwargs):
    return poll_client_pairing(
        server_url, client_instance=client_instance_id,
        credentials_path=credentials_path,
        transport=kwargs.get("transport"),
        timeout=kwargs.get("timeout", DEFAULT_TIMEOUT_SECONDS))


def advance_device_flow(server_url, *, device_id=None,
                        client_label="Attacca client", requested_bindings=None,
                        credentials_path=None, client_instance_id=None,
                        open_browser=True, browser_open=None, transport=None,
                        timeout=DEFAULT_TIMEOUT_SECONDS, **kwargs):
    project_id, actor_id = _first_binding(requested_bindings)
    return authorize_client(
        server_url, client_instance=client_instance_id,
        client_label=client_label, project_id=project_id, actor_id=actor_id,
        device_id=device_id, credentials_path=credentials_path,
        transport=transport, timeout=timeout, open_browser=open_browser,
        browser_open=browser_open, prompt=False)


def format_recovery_message(result, server_url, project_id=None):
    return format_authorization_message(result, server_url, project_id)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Authorize this installed Attacca client")
    parser.add_argument("action", choices=("authorize", "open", "paste", "status"))
    parser.add_argument("--server-url", required=True)
    parser.add_argument("--runtime", default="generic")
    parser.add_argument("--client-instance")
    parser.add_argument("--client-label", default="Attacca client")
    parser.add_argument("--project-id")
    parser.add_argument("--actor-id")
    parser.add_argument("--credentials-file")
    args = parser.parse_args(argv)
    try:
        instance = _resolved_client_instance_id(
            args.client_instance, runtime=args.runtime)
        if args.action == "status":
            result = client_api_key_status(
                args.server_url, client_instance=instance,
                project_id=args.project_id,
                credentials_path=args.credentials_file)
        elif args.action == "open":
            result = authorize_client(
                args.server_url, client_instance=instance,
                client_label=args.client_label, project_id=args.project_id,
                actor_id=args.actor_id,
                credentials_path=args.credentials_file, prompt=False)
        elif args.action == "paste":
            result = paste_client_api_key(
                args.server_url, client_instance=instance,
                project_id=args.project_id, actor_id=args.actor_id,
                credentials_path=args.credentials_file)
        else:
            result = authorize_client(
                args.server_url, client_instance=instance,
                client_label=args.client_label, project_id=args.project_id,
                actor_id=args.actor_id,
                credentials_path=args.credentials_file)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("status") not in {"invalid", "expired"} else 2
    except TerminalFlowError as error:
        print(json.dumps({"status": "error", "error": str(error)}, indent=2))
        return 2


__all__ = [
    "ACTOR_HEADER", "AUTH_STATUS_PATH", "CLIENT_INSTANCE_HEADER",
    "CLIENT_KEYS_PATH", "ControllingTerminalUnavailable", "DEVICE_ID_HEADER",
    "JsonResponse", "PROJECT_HEADER", "TerminalFlowError",
    "TerminalFlowProtocolError", "TerminalFlowTransportError",
    "UrllibJsonTransport", "add_terminal_binding", "advance_device_flow",
    "authorize_client", "canonical_server_record_for_update",
    "canonical_server_url", "client_api_key_status", "client_key_settings_url",
    "client_request_headers", "default_client_instance_path",
    "default_credentials_path", "default_identity_path", "default_state_path",
    "fallback_login_url", "forget_client_api_key", "format_authorization_message",
    "format_recovery_message", "load_client_api_key", "load_client_instance_id",
    "load_device_id", "load_terminal_credential", "normalize_bindings",
    "open_controlling_terminal", "paste_client_api_key",
    "paste_from_controlling_tty", "poll_device_flow", "read_credentials_store",
    "read_identity_store", "safe_recovery_result", "save_client_api_key",
    "save_terminal_credential", "server_record_for_url", "start_device_flow",
    "terminal_credential_status", "update_credentials_store",
    "update_identity_store", "verify_client_api_key",
]


if __name__ == "__main__":
    raise SystemExit(main())
