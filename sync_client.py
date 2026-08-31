"""Authenticated schema-v1 HTTP client for Attacca offline synchronization.

Tokens are supplied by a callable and loaded immediately before every request;
they are never copied into the adapter, mirror metadata, URL, exception text,
or durable watcher state.  The transport is injectable for deterministic tests
and defaults to a bounded ``urllib`` implementation.
"""

from __future__ import annotations

import json
import re
import socket
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:  # Namespace package when imported as ``attacca.sync_client``.
    from . import sync_protocol as protocol
    from .offline_sync import normalize_server_url
except (ImportError, ValueError):  # Direct module loading in isolated tests.
    import sync_protocol as protocol
    from offline_sync import normalize_server_url


DEFAULT_TIMEOUT_SECONDS = 10
MAX_ERROR_BODY_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 16 * 1024

_SAFE_HEADER_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$")


class SyncClientError(RuntimeError):
    """Base client configuration, authentication, or response error."""


class SyncAuthenticationError(SyncClientError):
    """The current request has no usable token or was rejected by auth."""

    def __init__(self, message, *, http_status=None):
        super().__init__(message)
        self.http_status = http_status


class SyncTransportError(ConnectionError):
    """The hosted endpoint could not be reached or completed."""


class SyncResponseError(SyncClientError):
    """The server returned malformed, unsafe, or unexpected data."""

    def __init__(self, message, *, http_status=None, protocol_code=None):
        super().__init__(message)
        self.http_status = http_status
        self.protocol_code = protocol_code


class SyncSchemaCompatibilityError(SyncResponseError):
    """The endpoint is reachable/authenticated but wire schemas differ."""


class SyncIdentityChangedError(SyncResponseError):
    """A response is valid but belongs to another authenticated scope."""

    def __init__(self, message, scope=None, visibility_fingerprint=None):
        super().__init__(message)
        self.scope = scope
        self.visibility_fingerprint = visibility_fingerprint


class SyncVisibilityChangedError(SyncResponseError):
    """The same identity has a newer visibility/projection generation."""

    def __init__(self, message, scope=None, visibility_fingerprint=None):
        super().__init__(message)
        self.scope = scope
        self.visibility_fingerprint = visibility_fingerprint


@dataclass(frozen=True)
class JsonHttpResponse:
    status: int
    headers: dict
    body: bytes


class _RejectRedirects(HTTPRedirectHandler):
    """Never forward an Attacca Bearer token through an HTTP redirect."""

    def redirect_request(self, request, file_pointer, code, message, headers,
                         new_url):
        return None


class UrllibJsonTransport:
    """Small bounded transport; it does not retain requests or credentials."""

    def __init__(self):
        self._opener = build_opener(_RejectRedirects())

    def request(self, method, url, *, headers, body, timeout,
                max_response_bytes):
        request = Request(url, data=body, headers=dict(headers), method=method)
        try:
            with self._opener.open(request, timeout=timeout) as response:
                raw = response.read(int(max_response_bytes) + 1)
                if len(raw) > int(max_response_bytes):
                    raise SyncResponseError(
                        "sync response exceeded its bounded size")
                return JsonHttpResponse(
                    status=int(response.status),
                    headers={key.lower(): value
                             for key, value in response.headers.items()},
                    body=raw,
                )
        except HTTPError as error:
            raw = error.read(MAX_ERROR_BODY_BYTES + 1)
            if len(raw) > MAX_ERROR_BODY_BYTES:
                raw = b""
            return JsonHttpResponse(
                status=int(error.code),
                headers={key.lower(): value
                         for key, value in (error.headers.items()
                                           if error.headers is not None
                                           else [])},
                body=raw,
            )
        except (URLError, socket.timeout, TimeoutError, OSError) as error:
            raise SyncTransportError(
                "Attacca sync endpoint is unavailable") from error


class AuthenticatedSyncHttpClient:
    """Strict client for snapshot, pull, and push schema-v1 routes."""

    def __init__(self, server_url, project_id, scope, visibility_fingerprint,
                 client_id, device_id, token_loader, *, transport=None,
                 timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
                 client_instance_id=None,
                 compatibility_optional_auth=False,
                 projection_capabilities=None):
        self.server_url = normalize_server_url(server_url)
        self.project_id = str(project_id or "").strip()
        if not self.project_id:
            raise SyncClientError("project_id is required")
        self.scope = protocol.validate_scope(scope)
        if self.scope["project_id"] != self.project_id:
            raise SyncClientError("project_id differs from authenticated scope")
        self.visibility_fingerprint = (
            protocol.validate_visibility_fingerprint(visibility_fingerprint)
            if visibility_fingerprint is not None else None)
        self.client_id = str(client_id or "").strip()
        self.device_id = str(device_id or "").strip()
        self.client_instance_id = str(
            client_instance_id or self.client_id).strip()
        if not _SAFE_HEADER_ID_RE.fullmatch(self.client_id) \
                or not _SAFE_HEADER_ID_RE.fullmatch(self.device_id) \
                or not _SAFE_HEADER_ID_RE.fullmatch(self.client_instance_id):
            raise SyncClientError(
                "client_id, device_id, and client_instance_id must be bounded "
                "safe identifiers")
        if not callable(token_loader):
            raise SyncClientError("token_loader must be callable")
        self._token_loader = token_loader
        self._transport = transport or UrllibJsonTransport()
        self.timeout_seconds = float(timeout_seconds)
        if not 0 < self.timeout_seconds <= 120:
            raise SyncClientError("timeout_seconds must be in (0, 120]")
        self._compatibility_optional_auth = False
        self._compatibility_probe_allowed = bool(
            compatibility_optional_auth)
        self.projection_capabilities = \
            protocol.validate_projection_capabilities(
                projection_capabilities or
                protocol.current_projection_capabilities())

    @property
    def route_base(self):
        return "%s/v1/projects/%s/sync" % (
            self.server_url, quote(self.project_id, safe=""))

    @staticmethod
    def _stable_scope(scope):
        return {key: scope[key] for key in (
            "server_id", "project_id", "principal_id")}

    def _check_scope(self, scope, allow_scope_change=False):
        checked = protocol.validate_scope(scope)
        if self._stable_scope(checked) != self._stable_scope(self.scope):
            raise SyncIdentityChangedError(
                "sync response belongs to another server/project/principal",
                scope=checked)
        if not allow_scope_change and checked != self.scope:
            raise SyncIdentityChangedError(
                "authenticated actor or role changed; snapshot reset required",
                scope=checked)
        return checked

    def _load_token(self):
        try:
            token = self._token_loader()
        except Exception:
            # Loader exceptions may contain environment values or command
            # output. Do not retain them as __cause__ on a public error.
            raise SyncAuthenticationError(
                "could not load the current Attacca terminal credential") from None
        if token is None and self._compatibility_probe_allowed:
            if not self._compatibility_optional_auth:
                self._enable_fresh_compatibility_optional_auth()
            return None
        if not isinstance(token, str) or not token.strip() \
                or "\n" in token or "\r" in token \
                or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
            raise SyncAuthenticationError(
                "a valid Attacca terminal credential is required")
        return token.strip()

    def _identity_headers(self):
        return {
            "Accept": "application/json",
            "X-Attacca-Device-ID": self.device_id,
            "X-Attacca-Project": self.project_id,
            "X-Attacca-Actor": self.scope["actor_id"],
            "X-Attacca-Actor-Type": self.scope["actor_type"],
            "X-Attacca-Client-Instance": self.client_instance_id,
        }

    def _enable_fresh_compatibility_optional_auth(self):
        """Enable anonymous compatibility only from a live public status."""
        response = self._transport.request(
            "GET", self.server_url + "/v1/auth/status",
            headers=self._identity_headers(), body=None,
            timeout=self.timeout_seconds,
            max_response_bytes=MAX_ERROR_BODY_BYTES)
        if isinstance(response, JsonHttpResponse) \
                and response.status in {401, 403}:
            raise SyncAuthenticationError(
                "Attacca rejected the current terminal credential",
                http_status=response.status)
        if not isinstance(response, JsonHttpResponse) \
                or response.status != 200 \
                or not isinstance(response.headers, dict) \
                or not isinstance(response.body, bytes) \
                or len(response.body) > MAX_ERROR_BODY_BYTES \
                or "application/json" not in str(
                    response.headers.get("content-type") or "").lower():
            raise SyncAuthenticationError(
                "could not verify Attacca compatibility authentication mode")
        try:
            status = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SyncAuthenticationError(
                "could not verify Attacca compatibility authentication mode") \
                from None
        if not isinstance(status, dict) \
                or status.get("authentication_required") is not False \
                or status.get("effective_authentication") != "optional" \
                or status.get("compatibility_active") is not True:
            raise SyncAuthenticationError(
                "a valid Attacca terminal credential is required")
        self._compatibility_optional_auth = True

    def _request(self, method, path, *, query=None, envelope=None,
                 max_response_bytes):
        url = self.route_base + path
        if query:
            url += "?" + urlencode(query)
        token = self._load_token()
        headers = self._identity_headers()
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        body = None
        if envelope is not None:
            body = protocol.canonical_json_bytes(
                envelope, max_bytes=protocol.MAX_PUSH_BYTES)
            headers["Content-Type"] = "application/json"
        response = self._transport.request(
            method, url, headers=headers, body=body,
            timeout=self.timeout_seconds,
            max_response_bytes=max_response_bytes)
        if not isinstance(response, JsonHttpResponse):
            raise SyncResponseError(
                "sync transport returned an invalid response object")
        if not isinstance(response.status, int) \
                or isinstance(response.status, bool) \
                or not isinstance(response.headers, dict) \
                or not isinstance(response.body, bytes):
            raise SyncResponseError(
                "sync transport returned malformed response fields")
        if len(response.body) > int(max_response_bytes):
            raise SyncResponseError(
                "sync response exceeded its bounded size")
        if response.status in {401, 403}:
            # Compatibility is a live server state, never a sticky downgrade.
            self._compatibility_optional_auth = False
            self._compatibility_probe_allowed = False
            raise SyncAuthenticationError(
                "Attacca rejected the current terminal credential or AI scope",
                http_status=response.status)
        if not 200 <= response.status < 300:
            protocol_code = None
            try:
                error_value = json.loads(response.body.decode("utf-8"))
                if isinstance(error_value, dict) and isinstance(
                        error_value.get("code"), str):
                    protocol_code = error_value["code"][:128]
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            error_class = SyncSchemaCompatibilityError \
                if protocol_code in {
                    "unknown_field", "unsupported_snapshot",
                    "unsupported_pull_request", "unsupported_pull_result",
                    "unsupported_push_request", "unsupported_push_result",
                    "unsupported_mutation",
                    "unsupported_projection_capabilities",
                    "unsupported_projection_schema",
                    "unsupported_projection_resource",
                    "unnegotiated_projection_resource",
                } else SyncResponseError
            suffix = " (%s)" % protocol_code if protocol_code else ""
            raise error_class(
                "Attacca sync endpoint returned HTTP %d%s" %
                (response.status, suffix),
                http_status=response.status, protocol_code=protocol_code)
        content_type = str(response.headers.get("content-type") or "")
        if "application/json" not in content_type.lower():
            raise SyncResponseError("Attacca sync response is not JSON")
        try:
            value = json.loads(response.body.decode("utf-8"))
            protocol.canonical_json_bytes(value, max_bytes=max_response_bytes)
            return value
        except (UnicodeDecodeError, json.JSONDecodeError,
                protocol.SyncProtocolError) as error:
            raise SyncResponseError(
                "Attacca sync endpoint returned malformed JSON") from error

    def bind_verified_identity(self, scope, visibility_fingerprint):
        """Rebind actor/role only after a validated full snapshot reset."""
        checked = self._check_scope(scope, allow_scope_change=True)
        visibility = protocol.validate_visibility_fingerprint(
            visibility_fingerprint)
        self.scope = checked
        self.visibility_fingerprint = visibility

    def fetch_snapshot(self, allow_scope_change=False):
        value = self._request(
            "GET", "/snapshot",
            query=protocol.projection_capabilities_query(
                self.projection_capabilities),
            max_response_bytes=protocol.MAX_SNAPSHOT_BYTES)
        try:
            checked = protocol.validate_snapshot(value)
            protocol.validate_projection_for_capabilities(
                checked["projection"], checked["scope"],
                self.projection_capabilities)
        except protocol.SyncProtocolError as error:
            error_class = SyncSchemaCompatibilityError \
                if protocol.is_schema_compatibility_error(error) \
                else SyncResponseError
            raise error_class(
                "snapshot failed schema-v1/projection-v%d validation: %s" %
                (self.projection_capabilities["schema_version"], error),
                protocol_code=error.code) from error
        self._check_scope(
            checked["scope"], allow_scope_change=allow_scope_change)
        if self.visibility_fingerprint is not None \
                and not allow_scope_change \
                and checked["visibility_fingerprint"] != \
                self.visibility_fingerprint:
            raise SyncVisibilityChangedError(
                "snapshot visibility changed; reset required",
                scope=checked["scope"],
                visibility_fingerprint=checked["visibility_fingerprint"])
        return checked

    def pull(self, *, cursor, visibility_fingerprint, limit=200):
        visibility = protocol.validate_visibility_fingerprint(
            visibility_fingerprint)
        request = protocol.make_pull_request(
            self.scope, cursor, visibility, limit=limit)
        value = self._request(
            "GET", "/pull",
            query={
                "after_seq": request["cursor"]["event_seq"],
                "after_hash": request["cursor"]["event_hash"],
                "context_version": request["cursor"]["context_version"],
                "visibility_fingerprint": request[
                    "visibility_fingerprint"],
                "limit": request["limit"],
            } | protocol.projection_capabilities_query(
                self.projection_capabilities),
            max_response_bytes=protocol.MAX_PULL_BYTES)
        try:
            checked = protocol.validate_pull_result(value)
            if checked["status"] == "ok":
                protocol.validate_projection_for_capabilities(
                    checked["changes"], checked["scope"],
                    self.projection_capabilities, partial=True)
        except protocol.SyncProtocolError as error:
            error_class = SyncSchemaCompatibilityError \
                if protocol.is_schema_compatibility_error(error) \
                else SyncResponseError
            raise error_class(
                "pull failed schema-v1/projection-v%d validation: %s" %
                (self.projection_capabilities["schema_version"], error),
                protocol_code=error.code) from error
        self._check_scope(
            checked["scope"],
            allow_scope_change=checked["status"] == "reset_required")
        if checked["status"] == "ok" \
                and checked["visibility_fingerprint"] != visibility:
            raise SyncVisibilityChangedError(
                "successful pull changed visibility without reset",
                scope=checked["scope"],
                visibility_fingerprint=checked["visibility_fingerprint"])
        return checked

    def push(self, *, mutations, known_receipts=None):
        if self.visibility_fingerprint is None:
            raise SyncIdentityChangedError(
                "a verified snapshot must pin visibility before push")
        try:
            request = protocol.make_push_request(
                self.scope, self.visibility_fingerprint, self.client_id,
                self.device_id, mutations,
                known_receipts=known_receipts or [])
        except protocol.SyncProtocolError as error:
            raise SyncClientError(
                "queued mutation batch is invalid: %s" % error) from error
        value = self._request(
            "POST", "/push",
            query=protocol.projection_capabilities_query(
                self.projection_capabilities),
            envelope=request,
            max_response_bytes=protocol.MAX_PUSH_BYTES * 2)
        try:
            return protocol.validate_push_result(
                value, expected_scope=self.scope,
                expected_visibility=self.visibility_fingerprint,
                expected_mutation_ids=[
                    item["client_mutation_id"] for item in mutations])
        except protocol.SyncProtocolError as error:
            raise SyncResponseError(
                "push failed schema-v1 validation: %s" % error) from error


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS", "MAX_TOKEN_BYTES", "SyncClientError",
    "SyncAuthenticationError", "SyncTransportError", "SyncResponseError",
    "SyncSchemaCompatibilityError", "SyncIdentityChangedError",
    "SyncVisibilityChangedError", "JsonHttpResponse", "UrllibJsonTransport",
    "AuthenticatedSyncHttpClient",
]
