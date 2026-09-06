"""Authenticated schema-v1 HTTP client for Attacca offline synchronization.

Tokens are supplied by a callable and loaded immediately before every request;
they are never copied into the adapter, mirror metadata, URL, exception text,
or durable watcher state.  The transport is injectable for deterministic tests
and defaults to a bounded ``urllib`` implementation.
"""

from __future__ import annotations

import errno
import http.client
import json
import re
import socket
import threading
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import (
    HTTPHandler, HTTPRedirectHandler, HTTPSHandler, Request, build_opener,
)

try:  # Namespace package when imported as ``attacca.sync_client``.
    from . import sync_protocol as protocol
    from .offline_sync import normalize_server_url
except (ImportError, ValueError):  # Direct module loading in isolated tests.
    import sync_protocol as protocol
    from offline_sync import normalize_server_url


DEFAULT_TIMEOUT_SECONDS = 10
MAX_ERROR_BODY_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 16 * 1024
MAX_RECEIPT_LOOKUP_IDS = 100

# How far one HTTP attempt got before it failed.  ``connect`` covers DNS,
# TCP connect, and the TLS handshake; ``send`` covers writing request headers
# and body; ``response`` covers waiting for and reading the reply.
TRANSPORT_PHASES = ("connect", "send", "response")
UNDELIVERED = "undelivered"
AMBIGUOUS = "ambiguous"
PHASE_ATTRIBUTE = "attacca_transport_phase"
CLASSIFICATION_ATTRIBUTE = "attacca_transport_classification"

# Errors that prove no byte of a request could have been accepted, even when
# the phase was not recorded (an older caller, or a re-raised cause).
_UNDELIVERED_ERRNOS = frozenset(
    value for value in (
        getattr(errno, name, None) for name in (
            "ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH", "ENETDOWN",
            "EHOSTDOWN", "EADDRNOTAVAIL", "EAFNOSUPPORT", "ENOTCONN",
        )
    ) if value is not None)

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
    """The hosted endpoint could not be reached or completed.

    ``phase`` records how far the attempt got and ``classification`` states
    whether a request could have been delivered.  ``undelivered`` is proof
    that queueing the write is safe; ``ambiguous`` never is.
    """

    def __init__(self, message, *, phase=None, classification=None):
        super().__init__(message)
        self.phase = phase
        self.classification = classification or AMBIGUOUS


class SyncResponseError(SyncClientError):
    """The server returned malformed, unsafe, or unexpected data."""

    def __init__(self, message, *, http_status=None, protocol_code=None):
        super().__init__(message)
        self.http_status = http_status
        self.protocol_code = protocol_code


class SyncSchemaCompatibilityError(SyncResponseError):
    """The endpoint is reachable/authenticated but wire schemas differ."""


class SyncReceiptsUnsupportedError(SyncResponseError):
    """This hosted server has no live/outbox receipt lookup route."""


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


def _iter_causes(error):
    """Walk an exception and its declared transport causes, never contexts."""
    seen = set()
    current = error
    while isinstance(current, BaseException) and id(current) not in seen:
        seen.add(id(current))
        yield current
        reason = getattr(current, "reason", None)
        current = reason if isinstance(reason, BaseException) \
            else current.__cause__


def proves_request_undelivered(error):
    """True only when the error proves no request byte reached the server."""
    for item in _iter_causes(error):
        if isinstance(item, (ConnectionRefusedError, socket.gaierror)):
            return True
        code = getattr(item, "errno", None)
        if isinstance(code, int) and code in _UNDELIVERED_ERRNOS:
            return True
    return False


def classify_transport_failure(error, phase=None):
    """Return ``'undelivered'`` or ``'ambiguous'`` for one transport failure.

    The phase is authoritative: nothing that failed while connecting or while
    the request body was still being written can have been applied, because a
    truncated body is not a parsable hosted request.  Once the complete
    request has been sent, every failure is ambiguous -- the server may have
    committed the write and lost only its reply.  Without a recorded phase the
    classification falls back to proof-by-exception and otherwise stays
    ambiguous, which is the fail-safe answer.
    """
    if isinstance(phase, str):
        normalized = phase.strip().lower()
        if normalized in ("connect", "send"):
            return UNDELIVERED
        if normalized == "response":
            return AMBIGUOUS
    recorded = getattr(error, PHASE_ATTRIBUTE, None)
    if isinstance(recorded, str) and recorded.strip().lower() in TRANSPORT_PHASES:
        return classify_transport_failure(error, recorded)
    return UNDELIVERED if proves_request_undelivered(error) else AMBIGUOUS


def annotate_transport_failure(error, phase):
    """Attach the observed phase/classification to a live exception object."""
    classification = classify_transport_failure(error, phase)
    try:
        setattr(error, PHASE_ATTRIBUTE, phase)
        setattr(error, CLASSIFICATION_ATTRIBUTE, classification)
    except (AttributeError, TypeError):  # pragma: no cover - exotic exception
        pass
    return classification


class TransportPhaseTracker:
    """Mutable record of the phase one HTTP attempt has reached."""

    __slots__ = ("phase",)

    def __init__(self):
        self.phase = "connect"


def _tracking_connection_class(base, tracker):
    class _TrackedConnection(base):
        def connect(self):
            tracker.phase = "connect"
            base.connect(self)
            # The socket is established; anything that fails from here until
            # the reply is requested happened while writing the request.
            tracker.phase = "send"

        def getresponse(self):
            tracker.phase = "response"
            return base.getresponse(self)

    return _TrackedConnection


class _TrackingHTTPHandler(HTTPHandler):
    def __init__(self, tracker_getter):
        HTTPHandler.__init__(self)
        self._tracker_getter = tracker_getter

    def http_open(self, req):
        return self.do_open(
            _tracking_connection_class(
                http.client.HTTPConnection, self._tracker_getter()), req)


class _TrackingHTTPSHandler(HTTPSHandler):
    def __init__(self, tracker_getter):
        HTTPSHandler.__init__(self)
        self._tracker_getter = tracker_getter

    def https_open(self, req):
        arguments = {"context": getattr(self, "_context", None)}
        # ``check_hostname`` exists on 3.8-3.11 handlers and was dropped in
        # newer ones; forward it only when this interpreter still has it.
        check_hostname = getattr(self, "_check_hostname", None)
        if check_hostname is not None:
            arguments["check_hostname"] = check_hostname
        return self.do_open(
            _tracking_connection_class(
                http.client.HTTPSConnection, self._tracker_getter()), req,
            **arguments)


class PhaseTrackingOpener:
    """One urllib opener that records the phase of every failed attempt.

    Redirects are refused so an Attacca Bearer credential is never replayed
    to another host, and each thread keeps its own phase record.
    """

    def __init__(self):
        self._local = threading.local()
        self._opener = build_opener(
            _TrackingHTTPHandler(self._tracker),
            _TrackingHTTPSHandler(self._tracker),
            _RejectRedirects())

    def _tracker(self):
        tracker = getattr(self._local, "tracker", None)
        if tracker is None:
            tracker = TransportPhaseTracker()
            self._local.tracker = tracker
        return tracker

    @property
    def opener(self):
        """The urllib OpenerDirector, for callers that install it globally."""
        return self._opener

    @property
    def phase(self):
        return self._tracker().phase

    def reset(self):
        """Start a new attempt; the phase is 'connect' until a socket opens."""
        self._tracker().phase = "connect"
        return self

    def open(self, request, timeout=None):
        tracker = self._tracker()
        tracker.phase = "connect"
        try:
            return self._opener.open(request, timeout=timeout)
        except HTTPError:
            # A complete hosted reply arrived; this is not a transport outage.
            raise
        except Exception as error:
            annotate_transport_failure(error, tracker.phase)
            raise


class UrllibJsonTransport:
    """Small bounded transport; it does not retain requests or credentials."""

    def __init__(self):
        self._opener = PhaseTrackingOpener()

    @property
    def phase(self):
        return self._opener.phase

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
            phase = getattr(error, PHASE_ATTRIBUTE, None) or self._opener.phase
            raise SyncTransportError(
                "Attacca sync endpoint is unavailable", phase=phase,
                classification=classify_transport_failure(
                    error, phase)) from error


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
            # The host answered; the answer does not fit the bounded
            # envelope.  Carry the protocol code so a caller can narrow the
            # request instead of treating it as an outage.
            raise SyncResponseError(
                "sync response exceeded its bounded size",
                http_status=response.status,
                protocol_code="envelope_too_large")
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

    def pull(self, *, cursor, visibility_fingerprint, limit=200,
             resources=None):
        """Fetch one delta, optionally narrowed to ``resources``.

        ``resources`` restricts only what THIS response delivers.  The
        capability offer - and therefore the negotiated shape and the
        visibility fingerprint - is unchanged, so a narrowed pull returns a
        smaller partial ``changes`` instead of ``reset_required``.
        """
        visibility = protocol.validate_visibility_fingerprint(
            visibility_fingerprint)
        request = protocol.make_pull_request(
            self.scope, cursor, visibility, limit=limit)
        try:
            subset = protocol.validate_projection_subset(
                resources, capabilities=self.projection_capabilities)
        except protocol.SyncProtocolError as error:
            raise SyncClientError(
                "pull resource subset is invalid: %s" % error) from error
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
                self.projection_capabilities)
            | protocol.projection_subset_query(subset),
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

    def fetch_receipts(self, ids):
        """Look up idempotency receipts for this device's mutation ids.

        The answer for each id is a receipt object, or ``None`` when the
        server holds no record.  ``None`` means "never applied"; a receipt in
        ``reserved`` state deliberately means "unknown", not "absent".
        """
        wanted = []
        for item in ids or []:
            item = str(item)
            if not protocol.is_client_mutation_id(item):
                raise SyncClientError("receipt lookup id is unsafe")
            if item not in wanted:
                wanted.append(item)
        if not wanted:
            return {}
        if len(wanted) > MAX_RECEIPT_LOOKUP_IDS:
            raise SyncClientError(
                "receipt lookup accepts at most %d ids" %
                MAX_RECEIPT_LOOKUP_IDS)
        try:
            value = self._request(
                "GET", "/receipts", query={"ids": ",".join(wanted)},
                max_response_bytes=protocol.MAX_PUSH_BYTES)
        except SyncResponseError as error:
            if getattr(error, "http_status", None) in (404, 405, 501):
                raise SyncReceiptsUnsupportedError(
                    "this Attacca server has no receipt lookup route",
                    http_status=error.http_status) from error
            raise
        if not isinstance(value, dict) \
                or value.get("format") != "attacca.sync.receipts-result" \
                or not isinstance(value.get("receipts"), dict):
            raise SyncResponseError("receipt lookup returned an invalid body")
        self._check_scope(value.get("scope"))
        receipts = {}
        for key, item in value["receipts"].items():
            if key not in wanted:
                raise SyncResponseError(
                    "receipt lookup returned an unrequested mutation id")
            if item is None:
                receipts[key] = None
                continue
            try:
                checked = protocol.validate_live_receipt(
                    item, expected_scope=self.scope)
            except protocol.SyncProtocolError as error:
                raise SyncResponseError(
                    "receipt lookup returned an invalid receipt: %s"
                    % error) from error
            if checked["client_mutation_id"] != key:
                raise SyncResponseError(
                    "receipt lookup returned a mismatched mutation id")
            receipts[key] = checked
        return {key: receipts.get(key) for key in wanted}

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
    "DEFAULT_TIMEOUT_SECONDS", "MAX_TOKEN_BYTES", "MAX_RECEIPT_LOOKUP_IDS",
    "TRANSPORT_PHASES", "UNDELIVERED", "AMBIGUOUS", "PHASE_ATTRIBUTE",
    "CLASSIFICATION_ATTRIBUTE", "SyncClientError",
    "SyncAuthenticationError", "SyncTransportError", "SyncResponseError",
    "SyncSchemaCompatibilityError", "SyncReceiptsUnsupportedError",
    "SyncIdentityChangedError",
    "SyncVisibilityChangedError", "JsonHttpResponse", "UrllibJsonTransport",
    "TransportPhaseTracker", "PhaseTrackingOpener",
    "classify_transport_failure", "annotate_transport_failure",
    "proves_request_undelivered", "AuthenticatedSyncHttpClient",
]
