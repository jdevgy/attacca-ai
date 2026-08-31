"""Pure schema-v1 wire contract for Attacca offline synchronization.

The module deliberately contains no database, HTTP, MCP, or filesystem code.
It validates the boundary between an authenticated hosted workspace and one
identity-scoped local mirror.  Callers may therefore use the same contract in
the server, the ``attacca.py connect`` gateway, hooks, and deterministic tests
without importing either side's runtime.

Important trust boundary: ``scope`` is derived from the authenticated server
principal.  A client may present a scope, actor, or owner hint, but the server
must compare it with that authenticated scope before reading a snapshot,
accepting a mutation, or returning an idempotency receipt.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone


SCHEMA_VERSION = 1

# The outer snapshot/pull/push envelopes remain schema-v1.  Projection
# resources evolve independently and are negotiated before the server emits a
# snapshot or delta.  This separation is deliberate: adding an optional
# projection key must never make an otherwise compatible, still-running
# schema-v1 client reject the entire offline mirror.
PROJECTION_SCHEMA_VERSION = 2
LEGACY_PROJECTION_SCHEMA_VERSION = 1
PROJECTION_CAPABILITIES_FORMAT = "attacca.sync.projection-capabilities"

SNAPSHOT_FORMAT = "attacca.sync.snapshot"
PULL_REQUEST_FORMAT = "attacca.sync.pull-request"
PULL_RESULT_FORMAT = "attacca.sync.pull-result"
PUSH_REQUEST_FORMAT = "attacca.sync.push-request"
PUSH_RESULT_FORMAT = "attacca.sync.push-result"
MUTATION_FORMAT = "attacca.sync.client-mutation"
MUTATION_RESULT_FORMAT = "attacca.sync.mutation-result"
STORED_RECEIPT_FORMAT = "attacca.sync.stored-receipt"

GENESIS_HASH = "0" * 64

MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_PULL_BYTES = 16 * 1024 * 1024
MAX_PUSH_BYTES = 4 * 1024 * 1024
MAX_MUTATION_BYTES = 256 * 1024
MAX_MUTATIONS = 100
MAX_PULL_RECORDS = 1000
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 250000
MAX_IDENTIFIER_LENGTH = 200
MAX_OPERATION_LENGTH = 128
MAX_STRING_BYTES = 8 * 1024 * 1024
MAX_REF_PATH_SEGMENTS = 16

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$")
_MUTATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{7,199}$")
_OPERATION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:\-]{0,127}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")

_ROLES = {"director", "advisor", "worker", "unassigned", "human"}
_ACTOR_TYPES = {"agent", "human", "tool"}
_SCOPE_KEYS = {
    "server_id", "project_id", "principal_id", "actor_id", "actor_type",
    "role",
}
_CURSOR_KEYS = {"event_seq", "event_hash", "context_version"}
_MUTATION_KEYS = {
    "format", "schema_version", "client_mutation_id", "client_id",
    "device_id", "client_sequence", "created_at", "operation", "payload",
    "metadata", "base_cursor", "depends_on", "scope_fingerprint",
    "request_sha256",
}
_IDENTITY_PROJECTION_REQUIRED = {
    "project", "handoffs", "rules", "tasks", "decisions", "room_messages",
    "agents", "bridges", "inbox_cursor",
}
_IDENTITY_PROJECTION_OPTIONAL = {
    "task_plans", "full_log", "actor_aliases", "cloud_context",
    "message_dispositions",
}
_PROJECTION_V2_RESOURCES = {"cloud_context", "message_dispositions"}
_PROJECTION_RESOURCE_INTRODUCED = {
    key: LEGACY_PROJECTION_SCHEMA_VERSION
    for key in (_IDENTITY_PROJECTION_REQUIRED |
                (_IDENTITY_PROJECTION_OPTIONAL - _PROJECTION_V2_RESOURCES))
}
for _resource in _PROJECTION_V2_RESOURCES:
    _PROJECTION_RESOURCE_INTRODUCED[_resource] = 2
_PROJECTION_RESOURCES = set(_PROJECTION_RESOURCE_INTRODUCED)
_LEGACY_PROJECTION_RESOURCES = {
    key for key, version in _PROJECTION_RESOURCE_INTRODUCED.items()
    if version <= LEGACY_PROJECTION_SCHEMA_VERSION
}
_PROJECTION_CAPABILITY_KEYS = {"format", "schema_version", "resources"}
_PROJECTION_RESOURCE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_PROJECTION_RESOURCES = 64
_SECRET_KEYS = {
    "api_token", "auth_sessions", "auth_tokens", "credentials",
    "csrf_hash", "password_hash", "password_salt", "session_hash",
    "token_hash",
}


class SyncProtocolError(ValueError):
    """A protocol object is malformed, unsafe, or belongs to another scope."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = str(code)


class EnvelopeTooLarge(SyncProtocolError):
    """A syntactically valid JSON object exceeds a protocol size limit."""


_SCHEMA_COMPATIBILITY_ERROR_CODES = {
    "unknown_field", "unsupported_snapshot", "unsupported_pull_request",
    "unsupported_pull_result", "unsupported_push_request",
    "unsupported_push_result", "unsupported_mutation",
    "unsupported_projection_capabilities", "unsupported_projection_schema",
    "unsupported_projection_resource", "unnegotiated_projection_resource",
}


def is_schema_compatibility_error(error):
    """Return true only for version/resource incompatibility, never auth."""
    return getattr(error, "code", None) in _SCHEMA_COMPATIBILITY_ERROR_CODES


def _error(code, message):
    raise SyncProtocolError(code, message)


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _canonical_json_bytes(value):
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        _error("invalid_json", "value is not canonical JSON: %s" % error)


def canonical_json_bytes(value, max_bytes=None):
    """Return deterministic JSON bytes after bounded structural validation."""
    _validate_json_tree(value)
    data = _canonical_json_bytes(value)
    if max_bytes is not None and len(data) > int(max_bytes):
        raise EnvelopeTooLarge(
            "envelope_too_large",
            "canonical JSON is %d bytes; limit is %d" % (len(data), max_bytes),
        )
    return data


def _json_copy(value, max_bytes=None):
    return json.loads(canonical_json_bytes(value, max_bytes=max_bytes))


def _validate_json_tree(value):
    seen = set()
    item_count = 0

    def walk(item, depth, path):
        nonlocal item_count
        if depth > MAX_JSON_DEPTH:
            _error("json_too_deep", "%s exceeds JSON depth %d" % (
                path, MAX_JSON_DEPTH))
        item_count += 1
        if item_count > MAX_JSON_ITEMS:
            _error("json_too_many_items", "JSON contains too many values")
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                _error("invalid_number", "%s contains a non-finite number" % path)
            return
        if isinstance(item, str):
            if len(item.encode("utf-8")) > MAX_STRING_BYTES:
                raise EnvelopeTooLarge(
                    "string_too_large", "%s contains an oversized string" % path)
            return
        if isinstance(item, (list, dict)):
            marker = id(item)
            if marker in seen:
                _error("cyclic_json", "%s contains a cyclic value" % path)
            seen.add(marker)
            try:
                if isinstance(item, list):
                    for index, child in enumerate(item):
                        walk(child, depth + 1, "%s[%d]" % (path, index))
                else:
                    for key, child in item.items():
                        if not isinstance(key, str):
                            _error("non_string_key", "%s has a non-string key" % path)
                        walk(child, depth + 1, "%s.%s" % (path, key))
            finally:
                seen.remove(marker)
            return
        _error("invalid_json_type", "%s contains %s" % (
            path, type(item).__name__))

    walk(value, 0, "$")


def _exact_keys(value, required, optional=(), label="object"):
    if not isinstance(value, dict):
        _error("invalid_%s" % label.replace(" ", "_"), "%s must be an object" % label)
    required = set(required)
    allowed = required | set(optional)
    missing = required - set(value)
    unknown = set(value) - allowed
    if missing:
        _error("missing_field", "%s is missing %s" % (
            label, ", ".join(sorted(missing))))
    if unknown:
        _error("unknown_field", "%s contains unknown field(s): %s" % (
            label, ", ".join(sorted(unknown))))


def _identifier(label, value, mutation=False):
    if not isinstance(value, str) or not value:
        _error("invalid_identifier", "%s must be a non-empty string" % label)
    pattern = _MUTATION_ID_RE if mutation else _ID_RE
    if len(value) > MAX_IDENTIFIER_LENGTH or not pattern.fullmatch(value):
        _error("invalid_identifier", "%s has unsafe syntax" % label)
    return value


def _timestamp(value, label="timestamp"):
    if not isinstance(value, str) or not value:
        _error("invalid_timestamp", "%s must be an ISO-8601 string" % label)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _error("invalid_timestamp", "%s is not valid ISO-8601" % label)
    if parsed.tzinfo is None:
        _error("invalid_timestamp", "%s must include a timezone" % label)
    return value


def utc_now():
    return datetime.now(timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def _raw_hash(value, label="hash"):
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        _error("invalid_hash", "%s must be 64 lowercase hex characters" % label)
    return value


def _digest(value, label="digest"):
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        _error("invalid_digest", "%s must be sha256:<64 lowercase hex>" % label)
    return value


def _sha256(value):
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def validate_projection_capabilities(capabilities, *, allow_unknown=False):
    """Validate one explicit projection-resource offer or selection.

    A newer client may offer resource names an older server does not know.
    Servers validate their bounded syntax and negotiate the known intersection;
    they never echo or persist an unknown resource.  A selected capability set
    used to validate a local mirror is stricter and rejects unknown names.
    """
    _exact_keys(
        capabilities, _PROJECTION_CAPABILITY_KEYS,
        label="projection capabilities")
    value = _json_copy(capabilities, max_bytes=16 * 1024)
    if value["format"] != PROJECTION_CAPABILITIES_FORMAT:
        _error(
            "unsupported_projection_capabilities",
            "unsupported projection-capabilities format")
    version = value["schema_version"]
    if not _is_int(version) or not 1 <= version <= 2 ** 31 - 1:
        _error(
            "unsupported_projection_schema",
            "projection schema_version must be a positive integer")
    resources = value["resources"]
    if not isinstance(resources, list) \
            or not len(_IDENTITY_PROJECTION_REQUIRED) <= len(resources) \
            <= _MAX_PROJECTION_RESOURCES:
        _error(
            "invalid_projection_capabilities",
            "projection resources must be a bounded array")
    seen = set()
    for resource in resources:
        if not isinstance(resource, str) \
                or not _PROJECTION_RESOURCE_RE.fullmatch(resource):
            _error(
                "invalid_projection_capabilities",
                "projection resource has unsafe syntax")
        if resource in seen:
            _error(
                "invalid_projection_capabilities",
                "projection resources contain a duplicate")
        seen.add(resource)
        introduced = _PROJECTION_RESOURCE_INTRODUCED.get(resource)
        if introduced is None:
            if not allow_unknown:
                _error(
                    "unsupported_projection_resource",
                    "projection resource %s is unsupported" % resource)
            continue
        if introduced > version:
            _error(
                "unsupported_projection_resource",
                "projection resource %s requires schema %d" %
                (resource, introduced))
    if not _IDENTITY_PROJECTION_REQUIRED <= set(resources):
        _error(
            "invalid_projection_capabilities",
            "projection capabilities omit a required schema-v1 resource")
    value["resources"] = sorted(resources)
    return value


def make_projection_capabilities(schema_version=PROJECTION_SCHEMA_VERSION,
                                 resources=None):
    """Build a known local projection capability set."""
    if resources is None:
        if not _is_int(schema_version) or schema_version < 1:
            _error(
                "unsupported_projection_schema",
                "projection schema_version must be a positive integer")
        resources = [
            key for key, introduced in _PROJECTION_RESOURCE_INTRODUCED.items()
            if introduced <= schema_version
        ]
    return validate_projection_capabilities({
        "format": PROJECTION_CAPABILITIES_FORMAT,
        "schema_version": schema_version,
        "resources": sorted(resources),
    })


def legacy_projection_capabilities():
    """Capabilities of clients shipped before explicit negotiation."""
    return make_projection_capabilities(
        LEGACY_PROJECTION_SCHEMA_VERSION,
        _LEGACY_PROJECTION_RESOURCES)


def current_projection_capabilities():
    return make_projection_capabilities(PROJECTION_SCHEMA_VERSION)


def negotiate_projection_capabilities(offered=None):
    """Return the safe known intersection of a client offer and this build.

    Absence means a legacy schema-v1 client.  This default is the compatibility
    guarantee that was missing when newer optional resources were first
    introduced.
    """
    if offered is None:
        return legacy_projection_capabilities()
    checked = validate_projection_capabilities(offered, allow_unknown=True)
    selected_version = min(
        checked["schema_version"], PROJECTION_SCHEMA_VERSION)
    selected = {
        resource for resource in checked["resources"]
        if resource in _PROJECTION_RESOURCES
        and _PROJECTION_RESOURCE_INTRODUCED[resource] <= selected_version
    }
    # Required v1 resources cannot be negotiated away.  The offer validator
    # already proves they were explicitly present.
    selected |= _IDENTITY_PROJECTION_REQUIRED
    return make_projection_capabilities(selected_version, selected)


def projection_capabilities_query(capabilities=None):
    """Encode a bounded capability offer for snapshot/pull query strings."""
    checked = validate_projection_capabilities(
        capabilities or current_projection_capabilities())
    return {
        "projection_schema_version": str(checked["schema_version"]),
        "projection_resources": ",".join(checked["resources"]),
    }


def projection_capabilities_from_query(schema_version=None, resources=None):
    """Parse a query offer; an entirely absent offer is legacy schema-v1."""
    if schema_version is None and resources is None:
        return legacy_projection_capabilities()
    if schema_version is None or resources is None:
        _error(
            "invalid_projection_capabilities",
            "projection schema version and resources must be sent together")
    if isinstance(schema_version, bool) or not re.fullmatch(
            r"[1-9][0-9]{0,9}", str(schema_version)):
        _error(
            "unsupported_projection_schema",
            "projection schema version has unsafe syntax")
    if not isinstance(resources, str) or len(resources.encode("utf-8")) > 4096:
        _error(
            "invalid_projection_capabilities",
            "projection resource query is invalid")
    rows = resources.split(",") if resources else []
    offered = {
        "format": PROJECTION_CAPABILITIES_FORMAT,
        "schema_version": int(schema_version),
        "resources": rows,
    }
    return negotiate_projection_capabilities(offered)


def projection_visibility_policy(visibility_policy, capabilities=None):
    """Bind non-legacy projection shape to the visibility fingerprint.

    The exact legacy policy material is preserved for clients which do not
    negotiate.  Negotiated mirrors receive a distinct fingerprint, forcing a
    safe full reset instead of silently relabelling an older projection.
    """
    policy = _json_copy(visibility_policy, max_bytes=512 * 1024)
    selected = negotiate_projection_capabilities(capabilities)
    if selected == legacy_projection_capabilities():
        return policy
    return {
        "visibility_policy": policy,
        "projection_capabilities": selected,
    }


def validate_scope(scope, expected_scope=None):
    """Validate and optionally bind a scope to the authenticated principal."""
    _exact_keys(scope, _SCOPE_KEYS, label="scope")
    value = _json_copy(scope, max_bytes=8192)
    for key in ("server_id", "project_id", "principal_id", "actor_id"):
        _identifier("scope.%s" % key, value[key])
    if not isinstance(value["actor_type"], str) \
            or value["actor_type"] not in _ACTOR_TYPES:
        _error("invalid_actor_type", "scope.actor_type is invalid")
    if not isinstance(value["role"], str) or value["role"] not in _ROLES:
        _error("invalid_role", "scope.role is invalid")
    if value["actor_type"] == "agent":
        prefix = "%s.%s." % (value["project_id"], value["role"])
        if not value["actor_id"].startswith(prefix) \
                or not value["actor_id"][len(prefix):]:
            _error(
                "noncanonical_actor",
                "agent actor_id must be <project>.<role>.<runtime>",
            )
    if expected_scope is not None:
        expected = validate_scope(expected_scope)
        if value != expected:
            _error(
                "cross_principal_scope",
                "sync envelope does not belong to the authenticated scope",
            )
    return value


def scope_fingerprint(scope):
    return _sha256({"scope": validate_scope(scope)})


def visibility_fingerprint(scope, visibility_policy):
    """Bind cached visibility to identity, role, and server policy material."""
    validated_scope = validate_scope(scope)
    policy = _json_copy(visibility_policy, max_bytes=512 * 1024)
    return _sha256({"scope": validated_scope, "policy": policy})


def validate_visibility_fingerprint(value, expected=None):
    value = _digest(value, "visibility_fingerprint")
    if expected is not None and value != _digest(expected, "expected visibility"):
        _error(
            "visibility_changed",
            "visibility fingerprint does not match the verified local scope",
        )
    return value


def make_cursor(event_seq, event_hash, context_version):
    value = {
        "event_seq": event_seq,
        "event_hash": event_hash,
        "context_version": context_version,
    }
    return validate_cursor(value)


def validate_cursor(cursor):
    _exact_keys(cursor, _CURSOR_KEYS, label="cursor")
    value = _json_copy(cursor, max_bytes=2048)
    if not _is_int(value["event_seq"]) or value["event_seq"] < 0:
        _error("invalid_cursor", "cursor.event_seq must be a non-negative integer")
    _raw_hash(value["event_hash"], "cursor.event_hash")
    if not _is_int(value["context_version"]) or value["context_version"] < 0:
        _error(
            "invalid_cursor",
            "cursor.context_version must be a non-negative integer",
        )
    if value["event_seq"] == 0 and value["event_hash"] != GENESIS_HASH:
        _error("invalid_cursor", "event sequence zero must use the genesis hash")
    return value


def make_visible_record(event):
    if not isinstance(event, dict):
        _error("invalid_event", "visible chain record needs an event object")
    try:
        seq = event["seq"]
        previous = event["prev_hash"]
        event_hash = event["hash"]
    except KeyError as error:
        _error("invalid_event", "event is missing %s" % error.args[0])
    return validate_chain_record({
        "kind": "event", "seq": seq, "prev_hash": previous,
        "hash": event_hash, "event": event,
    })


def make_redacted_anchor(seq, prev_hash, event_hash):
    return validate_chain_record({
        "kind": "redacted", "seq": seq, "prev_hash": prev_hash,
        "hash": event_hash,
    })


def _verify_visible_event_hash(event):
    required = {
        "project_id", "seq", "event_type", "actor_id", "actor_type",
        "owner", "created_at", "payload", "payload_hash", "prev_hash",
        "hash", "hash_version", "context_version", "base_revision",
        "git_branch", "device_id", "task_id",
    }
    missing = required - set(event)
    if missing:
        _error(
            "incomplete_visible_event",
            "visible event lacks integrity field(s): %s" %
            ", ".join(sorted(missing)),
        )
    payload_json = event.get("payload_json")
    if payload_json is None:
        payload_json = _canonical_json_bytes(event["payload"]).decode("utf-8")
    elif not isinstance(payload_json, str):
        _error("invalid_event", "event.payload_json must be a string")
    else:
        try:
            decoded_payload = json.loads(payload_json)
        except (TypeError, ValueError):
            decoded_payload = payload_json
        if decoded_payload != event["payload"]:
            _error(
                "event_payload_mismatch",
                "event payload differs from the hash-bound payload_json",
            )
    payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    if event["payload_hash"] != payload_hash:
        _error("event_payload_hash_mismatch", "visible event payload was modified")
    hash_version = event["hash_version"]
    if not _is_int(hash_version) or hash_version not in {1, 2}:
        _error("unsupported_event_hash", "unsupported event hash version")
    material = [
        event["prev_hash"] or "", payload_hash, event["project_id"] or "",
        str(event["seq"]), event["event_type"] or "",
        event["actor_id"] or "", event["created_at"] or "",
    ]
    if hash_version >= 2:
        material.extend([
            event["actor_type"] or "", event["owner"] or "",
            str(event["context_version"] or ""),
            event["base_revision"] or "", event["git_branch"] or "",
            event["device_id"] or "", event["task_id"] or "",
        ])
    computed = hashlib.sha256("|".join(material).encode("utf-8")).hexdigest()
    if event["hash"] != computed:
        _error("event_hash_mismatch", "visible event hash was modified")


def validate_chain_record(record, project_id=None):
    if not isinstance(record, dict):
        _error("invalid_chain_record", "chain record must be an object")
    kind = record.get("kind")
    if kind == "event":
        _exact_keys(
            record, {"kind", "seq", "prev_hash", "hash", "event"},
            label="visible chain record")
    elif kind == "redacted":
        _exact_keys(
            record, {"kind", "seq", "prev_hash", "hash"},
            label="redacted chain record")
    else:
        _error("invalid_chain_record", "chain record kind must be event or redacted")
    value = _json_copy(record, max_bytes=MAX_MUTATION_BYTES * 2)
    if not _is_int(value["seq"]) or value["seq"] <= 0:
        _error("invalid_chain_record", "chain record seq must be positive")
    _raw_hash(value["prev_hash"], "chain prev_hash")
    _raw_hash(value["hash"], "chain hash")
    if kind == "event":
        event = value["event"]
        if not isinstance(event, dict):
            _error("invalid_event", "visible record event must be an object")
        if event.get("seq") != value["seq"] \
                or event.get("prev_hash") != value["prev_hash"] \
                or event.get("hash") != value["hash"]:
            _error("event_anchor_mismatch", "event does not match its chain anchor")
        if project_id is not None and event.get("project_id") != project_id:
            _error("cross_project_event", "event belongs to another project")
        _reject_secret_keys(event)
        _verify_visible_event_hash(event)
    return value


def validate_chain(records, from_cursor, to_cursor, project_id=None,
                   max_records=None):
    """Validate contiguous visible events/redacted anchors between cursors."""
    start = validate_cursor(from_cursor)
    end = validate_cursor(to_cursor)
    if not isinstance(records, list):
        _error("invalid_chain", "records must be an array")
    if max_records is not None and len(records) > max_records:
        _error("too_many_records", "chain contains more than %d records" % max_records)
    previous_hash = start["event_hash"]
    expected_seq = start["event_seq"] + 1
    validated = []
    for raw in records:
        record = validate_chain_record(raw, project_id=project_id)
        if record["seq"] != expected_seq:
            _error(
                "chain_sequence_gap",
                "expected chain seq %d, found %d" % (expected_seq, record["seq"]),
            )
        if record["prev_hash"] != previous_hash:
            _error("chain_hash_break", "chain prev_hash mismatch at seq %d" % expected_seq)
        previous_hash = record["hash"]
        expected_seq += 1
        validated.append(record)
    expected_end_seq = start["event_seq"] + len(validated)
    if end["event_seq"] != expected_end_seq or end["event_hash"] != previous_hash:
        _error("cursor_chain_mismatch", "to_cursor does not match the supplied chain")
    if end["context_version"] < start["context_version"]:
        _error("context_regression", "context version cannot move backwards")
    return validated


def _reject_secret_keys(value, path="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in _SECRET_KEYS:
                _error("secret_in_projection", "%s.%s is not mirror-safe" % (path, key))
            _reject_secret_keys(child, "%s.%s" % (path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_keys(child, "%s[%d]" % (path, index))


def validate_identity_projection(projection, scope, partial=False):
    scope = validate_scope(scope)
    required = set() if partial else _IDENTITY_PROJECTION_REQUIRED
    allowed = _IDENTITY_PROJECTION_REQUIRED | _IDENTITY_PROJECTION_OPTIONAL
    _exact_keys(projection, required, allowed - required, label="identity projection")
    value = _json_copy(projection, max_bytes=MAX_SNAPSHOT_BYTES)
    _reject_secret_keys(value)
    if "project" in value:
        project = value["project"]
        if not isinstance(project, dict) \
                or project.get("project_id") != scope["project_id"]:
            _error("cross_project_projection", "projection project does not match scope")
    for key in ("handoffs", "rules", "tasks", "decisions", "room_messages",
                "agents", "bridges", "task_plans", "full_log",
                "actor_aliases", "message_dispositions"):
        if key in value and not isinstance(value[key], list):
            _error("invalid_projection", "projection.%s must be an array" % key)
        if key in value and key != "full_log":
            for record in value[key]:
                if isinstance(record, dict) \
                        and record.get("project_id") is not None \
                        and record.get("project_id") != scope["project_id"]:
                    _error(
                        "cross_project_projection",
                        "projection.%s contains another project's record" % key,
                    )
    if "rules" in value:
        allowed_scopes = {"everyone", scope["role"]}
        if scope["actor_type"] == "human":
            allowed_scopes |= {"director", "advisor", "worker"}
        for rule in value["rules"]:
            if not isinstance(rule, dict) or str(rule.get("scope") or "everyone") \
                    not in allowed_scopes:
                _error("cross_role_rule", "projection contains a rule outside this role")
    if "inbox_cursor" in value:
        cursor = value["inbox_cursor"]
        if cursor is not None:
            if not isinstance(cursor, dict):
                _error("invalid_projection", "inbox_cursor must be an object or null")
            actor_id = cursor.get("actor_id")
            if actor_id is not None and actor_id != scope["actor_id"]:
                _error("cross_actor_inbox", "inbox cursor belongs to another actor")
    return value


def validate_projection_for_capabilities(projection, scope, capabilities,
                                         partial=False):
    """Validate both projection content and its negotiated resource shape."""
    value = validate_identity_projection(projection, scope, partial=partial)
    selected = validate_projection_capabilities(capabilities)
    unexpected = set(value) - set(selected["resources"])
    if unexpected:
        _error(
            "unnegotiated_projection_resource",
            "projection contains unnegotiated resource(s): %s" %
            ", ".join(sorted(unexpected)))
    return value


def filter_projection_for_capabilities(projection, scope, capabilities,
                                       partial=False):
    """Validate a server projection, then emit only negotiated resources.

    Validation occurs *before* filtering so a server adapter cannot hide a
    secret, cross-project row, or malformed known resource merely because the
    requesting client did not negotiate that resource.
    """
    value = validate_identity_projection(projection, scope, partial=partial)
    selected = negotiate_projection_capabilities(capabilities)
    filtered = {
        key: item for key, item in value.items()
        if key in set(selected["resources"])
    }
    return validate_projection_for_capabilities(
        filtered, scope, selected, partial=partial)


def make_snapshot(scope, visibility, cursor, projection, records, generated_at=None):
    scope = validate_scope(scope)
    cursor = validate_cursor(cursor)
    genesis = make_cursor(0, GENESIS_HASH, 0)
    records = validate_chain(records, genesis, cursor, project_id=scope["project_id"])
    projection = validate_identity_projection(projection, scope)
    envelope = {
        "format": SNAPSHOT_FORMAT,
        "schema_version": SCHEMA_VERSION,
        "scope": scope,
        "visibility_fingerprint": validate_visibility_fingerprint(visibility),
        "generated_at": generated_at or utc_now(),
        "cursor": cursor,
        "records": records,
        "projection": projection,
        "projection_sha256": _sha256(projection),
    }
    return validate_snapshot(envelope)


def validate_snapshot(envelope, expected_scope=None, expected_visibility=None):
    _exact_keys(envelope, {
        "format", "schema_version", "scope", "visibility_fingerprint",
        "generated_at", "cursor", "records", "projection",
        "projection_sha256",
    }, label="snapshot")
    value = _json_copy(envelope, max_bytes=MAX_SNAPSHOT_BYTES)
    if value["format"] != SNAPSHOT_FORMAT or value["schema_version"] != SCHEMA_VERSION:
        _error("unsupported_snapshot", "unsupported snapshot format or schema")
    scope = validate_scope(value["scope"], expected_scope=expected_scope)
    validate_visibility_fingerprint(
        value["visibility_fingerprint"], expected=expected_visibility)
    _timestamp(value["generated_at"], "snapshot.generated_at")
    cursor = validate_cursor(value["cursor"])
    validate_chain(
        value["records"], make_cursor(0, GENESIS_HASH, 0), cursor,
        project_id=scope["project_id"])
    projection = validate_identity_projection(value["projection"], scope)
    if value["projection_sha256"] != _sha256(projection):
        _error("projection_hash_mismatch", "snapshot projection digest is stale")
    return value


def make_pull_request(scope, cursor, visibility, limit=200, created_at=None):
    envelope = {
        "format": PULL_REQUEST_FORMAT,
        "schema_version": SCHEMA_VERSION,
        "scope": validate_scope(scope),
        "cursor": validate_cursor(cursor),
        "visibility_fingerprint": validate_visibility_fingerprint(visibility),
        "limit": limit,
        "created_at": created_at or utc_now(),
    }
    return validate_pull_request(envelope)


def validate_pull_request(envelope, expected_scope=None,
                          expected_visibility=None):
    _exact_keys(envelope, {
        "format", "schema_version", "scope", "cursor",
        "visibility_fingerprint", "limit", "created_at",
    }, label="pull request")
    value = _json_copy(envelope, max_bytes=64 * 1024)
    if value["format"] != PULL_REQUEST_FORMAT or value["schema_version"] != SCHEMA_VERSION:
        _error("unsupported_pull_request", "unsupported pull request format or schema")
    validate_scope(value["scope"], expected_scope=expected_scope)
    validate_cursor(value["cursor"])
    validate_visibility_fingerprint(
        value["visibility_fingerprint"], expected=expected_visibility)
    if not _is_int(value["limit"]) or not 1 <= value["limit"] <= MAX_PULL_RECORDS:
        _error("invalid_limit", "pull limit must be 1..%d" % MAX_PULL_RECORDS)
    _timestamp(value["created_at"], "pull request created_at")
    return value


def make_pull_result(scope, visibility, from_cursor, next_cursor, head_cursor,
                     records, changes, has_more=None, generated_at=None):
    scope = validate_scope(scope)
    start = validate_cursor(from_cursor)
    end = validate_cursor(next_cursor)
    head = validate_cursor(head_cursor)
    records = validate_chain(
        records, start, end, project_id=scope["project_id"],
        max_records=MAX_PULL_RECORDS)
    changes = validate_identity_projection(changes, scope, partial=True)
    expected_more = end["event_seq"] < head["event_seq"]
    if has_more is None:
        has_more = expected_more
    envelope = {
        "format": PULL_RESULT_FORMAT,
        "schema_version": SCHEMA_VERSION,
        "status": "ok",
        "scope": scope,
        "visibility_fingerprint": validate_visibility_fingerprint(visibility),
        "generated_at": generated_at or utc_now(),
        "from_cursor": start,
        "next_cursor": end,
        "head_cursor": head,
        "records": records,
        "changes": changes,
        "changes_sha256": _sha256(changes),
        "has_more": has_more,
    }
    return validate_pull_result(envelope)


def make_reset_required(scope, visibility, reason_code, reason,
                        current_cursor, generated_at=None):
    envelope = {
        "format": PULL_RESULT_FORMAT,
        "schema_version": SCHEMA_VERSION,
        "status": "reset_required",
        "scope": validate_scope(scope),
        "visibility_fingerprint": validate_visibility_fingerprint(visibility),
        "generated_at": generated_at or utc_now(),
        "reason_code": _identifier("reason_code", reason_code),
        "reason": str(reason or "").strip(),
        "current_cursor": validate_cursor(current_cursor),
    }
    if not envelope["reason"]:
        _error("invalid_reason", "reset_required needs a reason")
    return validate_pull_result(envelope)


def validate_pull_result(envelope, expected_scope=None, expected_visibility=None):
    if not isinstance(envelope, dict):
        _error("invalid_pull_result", "pull result must be an object")
    status = envelope.get("status")
    common = {
        "format", "schema_version", "status", "scope",
        "visibility_fingerprint", "generated_at",
    }
    if status == "ok":
        required = common | {
            "from_cursor", "next_cursor", "head_cursor", "records", "changes",
            "changes_sha256", "has_more",
        }
    elif status == "reset_required":
        required = common | {"reason_code", "reason", "current_cursor"}
    else:
        _error("invalid_pull_status", "pull status must be ok or reset_required")
    _exact_keys(envelope, required, label="pull result")
    value = _json_copy(envelope, max_bytes=MAX_PULL_BYTES)
    if value["format"] != PULL_RESULT_FORMAT or value["schema_version"] != SCHEMA_VERSION:
        _error("unsupported_pull_result", "unsupported pull result format or schema")
    scope = validate_scope(value["scope"], expected_scope=expected_scope)
    validate_visibility_fingerprint(
        value["visibility_fingerprint"], expected=expected_visibility)
    _timestamp(value["generated_at"], "pull result generated_at")
    if status == "reset_required":
        _identifier("reason_code", value["reason_code"])
        if not isinstance(value["reason"], str) or not value["reason"].strip():
            _error("invalid_reason", "reset_required needs a reason")
        validate_cursor(value["current_cursor"])
        return value
    start = validate_cursor(value["from_cursor"])
    end = validate_cursor(value["next_cursor"])
    head = validate_cursor(value["head_cursor"])
    validate_chain(
        value["records"], start, end, project_id=scope["project_id"],
        max_records=MAX_PULL_RECORDS)
    if head["event_seq"] < end["event_seq"] \
            or (head["event_seq"] == end["event_seq"]
                and head["event_hash"] != end["event_hash"]):
        _error("invalid_head_cursor", "head cursor is behind next cursor")
    if head["context_version"] < end["context_version"]:
        _error("invalid_head_cursor", "head context version is behind next cursor")
    if not isinstance(value["has_more"], bool) \
            or value["has_more"] != (end["event_seq"] < head["event_seq"]):
        _error("invalid_has_more", "has_more does not match next/head cursors")
    changes = validate_identity_projection(value["changes"], scope, partial=True)
    if value["changes_sha256"] != _sha256(changes):
        _error("changes_hash_mismatch", "pull changes digest is stale")
    return value


def _validate_ref_path(path):
    if not isinstance(path, list) or not 1 <= len(path) <= MAX_REF_PATH_SEGMENTS:
        _error("invalid_local_ref", "local reference path must be a non-empty array")
    for segment in path:
        if not isinstance(segment, str) or not _PATH_SEGMENT_RE.fullmatch(segment):
            _error("invalid_local_ref", "local reference path has an unsafe segment")


def local_ref(client_mutation_id, path):
    value = {"$local_ref": _identifier(
        "local reference", client_mutation_id, mutation=True), "path": list(path)}
    _validate_ref_path(value["path"])
    return value


def _collect_local_refs(value, found=None):
    found = found if found is not None else []
    if isinstance(value, dict):
        if "$local_ref" in value:
            if set(value) != {"$local_ref", "path"}:
                _error("ambiguous_local_ref", "local reference marker has extra fields")
            mutation_id = _identifier(
                "local reference", value["$local_ref"], mutation=True)
            _validate_ref_path(value["path"])
            found.append(mutation_id)
            return found
        for child in value.values():
            _collect_local_refs(child, found)
    elif isinstance(value, list):
        for child in value:
            _collect_local_refs(child, found)
    return found


def _mutation_unsigned(mutation):
    return {key: mutation[key] for key in sorted(_MUTATION_KEYS - {"request_sha256"})}


def mutation_sha256(mutation):
    if not isinstance(mutation, dict):
        _error("invalid_mutation", "mutation must be an object")
    missing = (_MUTATION_KEYS - {"request_sha256"}) - set(mutation)
    if missing:
        _error("missing_field", "mutation is missing %s" % ", ".join(sorted(missing)))
    return _sha256(_mutation_unsigned(mutation))


def make_client_mutation(scope, client_mutation_id, client_id, device_id,
                         client_sequence, operation, payload, base_cursor,
                         depends_on=None, metadata=None, created_at=None):
    scope = validate_scope(scope)
    mutation = {
        "format": MUTATION_FORMAT,
        "schema_version": SCHEMA_VERSION,
        "client_mutation_id": client_mutation_id,
        "client_id": client_id,
        "device_id": device_id,
        "client_sequence": client_sequence,
        "created_at": created_at or utc_now(),
        "operation": operation,
        "payload": payload,
        "metadata": metadata or {},
        "base_cursor": validate_cursor(base_cursor),
        "depends_on": list(depends_on or []),
        "scope_fingerprint": scope_fingerprint(scope),
    }
    mutation["request_sha256"] = mutation_sha256(mutation)
    return validate_client_mutation(mutation, expected_scope=scope)


def validate_client_mutation(mutation, expected_scope=None):
    _exact_keys(mutation, _MUTATION_KEYS, label="client mutation")
    value = _json_copy(mutation, max_bytes=MAX_MUTATION_BYTES)
    if value["format"] != MUTATION_FORMAT or value["schema_version"] != SCHEMA_VERSION:
        _error("unsupported_mutation", "unsupported mutation format or schema")
    _identifier("client_mutation_id", value["client_mutation_id"], mutation=True)
    _identifier("client_id", value["client_id"])
    _identifier("device_id", value["device_id"])
    if not _is_int(value["client_sequence"]) or value["client_sequence"] <= 0:
        _error("invalid_client_sequence", "client_sequence must be positive")
    _timestamp(value["created_at"], "mutation.created_at")
    if not isinstance(value["operation"], str) \
            or len(value["operation"]) > MAX_OPERATION_LENGTH \
            or not _OPERATION_RE.fullmatch(value["operation"]):
        _error("invalid_operation", "mutation operation has unsafe syntax")
    if not isinstance(value["payload"], dict) or not isinstance(value["metadata"], dict):
        _error("invalid_mutation_body", "payload and metadata must be objects")
    _reject_secret_keys(value["payload"])
    _reject_secret_keys(value["metadata"])
    validate_cursor(value["base_cursor"])
    if not isinstance(value["depends_on"], list):
        _error("invalid_dependencies", "depends_on must be an array")
    dependencies = []
    for dependency in value["depends_on"]:
        dependency = _identifier("dependency", dependency, mutation=True)
        if dependency in dependencies:
            _error("duplicate_dependency", "depends_on contains a duplicate")
        if dependency == value["client_mutation_id"]:
            _error("self_dependency", "mutation cannot depend on itself")
        dependencies.append(dependency)
    _digest(value["scope_fingerprint"], "scope_fingerprint")
    if expected_scope is not None \
            and value["scope_fingerprint"] != scope_fingerprint(expected_scope):
        _error("cross_principal_mutation", "mutation belongs to another scope")
    expected_hash = mutation_sha256(value)
    if value["request_sha256"] != expected_hash:
        _error("mutation_hash_mismatch", "immutable mutation digest does not match body")
    _collect_local_refs(value["payload"])
    return value


def make_push_request(scope, visibility, client_id, device_id, mutations,
                      created_at=None, known_receipts=None):
    envelope = {
        "format": PUSH_REQUEST_FORMAT,
        "schema_version": SCHEMA_VERSION,
        "scope": validate_scope(scope),
        "visibility_fingerprint": validate_visibility_fingerprint(visibility),
        "client_id": client_id,
        "device_id": device_id,
        "mutations": list(mutations),
        "created_at": created_at or utc_now(),
    }
    return validate_push_request(
        envelope,
        expected_scope=scope,
        known_receipts=known_receipts,
    )


def validate_push_request(envelope, expected_scope=None,
                          expected_visibility=None, known_receipts=None):
    _exact_keys(envelope, {
        "format", "schema_version", "scope", "visibility_fingerprint",
        "client_id", "device_id", "mutations", "created_at",
    }, label="push request")
    value = _json_copy(envelope, max_bytes=MAX_PUSH_BYTES)
    if value["format"] != PUSH_REQUEST_FORMAT or value["schema_version"] != SCHEMA_VERSION:
        _error("unsupported_push_request", "unsupported push request format or schema")
    scope = validate_scope(value["scope"], expected_scope=expected_scope)
    validate_visibility_fingerprint(
        value["visibility_fingerprint"], expected=expected_visibility)
    _identifier("client_id", value["client_id"])
    _identifier("device_id", value["device_id"])
    _timestamp(value["created_at"], "push request created_at")
    if not isinstance(value["mutations"], list) or not value["mutations"]:
        _error("empty_push", "push request needs at least one mutation")
    if len(value["mutations"]) > MAX_MUTATIONS:
        _error("too_many_mutations", "push request exceeds mutation limit")
    available = set(known_receipts or [])
    for item in list(available):
        _identifier("known receipt", item, mutation=True)
    seen = set()
    previous_sequence = None
    validated = []
    for raw in value["mutations"]:
        mutation = validate_client_mutation(raw, expected_scope=scope)
        mutation_id = mutation["client_mutation_id"]
        # A retry may legitimately name an operation already present in the
        # server receipt store; that is how duplicate-vs-body-conflict is
        # resolved. Only duplicates inside this envelope are malformed.
        if mutation_id in seen:
            _error("duplicate_mutation", "push contains a duplicate mutation id")
        if mutation["client_id"] != value["client_id"] \
                or mutation["device_id"] != value["device_id"]:
            _error("cross_client_mutation", "mutation client/device differs from push")
        if previous_sequence is not None \
                and mutation["client_sequence"] <= previous_sequence:
            _error("mutation_order", "client_sequence must be strictly increasing")
        allowed_dependencies = available | seen
        for dependency in mutation["depends_on"]:
            if dependency not in allowed_dependencies:
                _error(
                    "forward_dependency",
                    "dependency %s has no earlier receipt/mutation" % dependency,
                )
        refs = set(_collect_local_refs(mutation["payload"]))
        missing_dependencies = refs - set(mutation["depends_on"])
        if missing_dependencies:
            _error(
                "undeclared_local_ref",
                "local reference must also appear in depends_on: %s" %
                ", ".join(sorted(missing_dependencies)),
            )
        if refs - allowed_dependencies:
            _error("forward_local_ref", "local reference points forward or is unknown")
        previous_sequence = mutation["client_sequence"]
        seen.add(mutation_id)
        validated.append(mutation)
    value["mutations"] = validated
    return value


def _make_mutation_result(scope, mutation, status, code, reason,
                          result=None, current=None, retryable=False,
                          server_cursor=None, recorded_at=None):
    scope = validate_scope(scope)
    mutation = validate_client_mutation(mutation, expected_scope=scope)
    value = {
        "format": MUTATION_RESULT_FORMAT,
        "schema_version": SCHEMA_VERSION,
        "scope_fingerprint": scope_fingerprint(scope),
        "client_mutation_id": mutation["client_mutation_id"],
        "request_sha256": mutation["request_sha256"],
        "status": status,
        "code": str(code or "").strip(),
        "reason": str(reason or "").strip(),
        "result": result,
        "current": current,
        "retryable": bool(retryable),
        "server_cursor": server_cursor,
        "recorded_at": recorded_at or utc_now(),
    }
    return validate_mutation_result(value, expected_scope=scope)


def applied_result(scope, mutation, result, server_cursor, recorded_at=None):
    return _make_mutation_result(
        scope, mutation, "applied", "applied", "mutation applied",
        result=result, server_cursor=server_cursor, recorded_at=recorded_at)


def conflict_result(scope, mutation, code, reason, current=None,
                    retryable=False, server_cursor=None, recorded_at=None):
    return _make_mutation_result(
        scope, mutation, "conflict", code, reason, current=current,
        retryable=retryable, server_cursor=server_cursor,
        recorded_at=recorded_at)


def rejected_result(scope, mutation, code, reason, current=None,
                    server_cursor=None, recorded_at=None):
    return _make_mutation_result(
        scope, mutation, "rejected", code, reason, current=current,
        retryable=False, server_cursor=server_cursor, recorded_at=recorded_at)


def validate_mutation_result(value, expected_scope=None):
    _exact_keys(value, {
        "format", "schema_version", "scope_fingerprint",
        "client_mutation_id", "request_sha256", "status", "code", "reason",
        "result", "current", "retryable", "server_cursor", "recorded_at",
    }, label="mutation result")
    value = _json_copy(value, max_bytes=MAX_MUTATION_BYTES * 2)
    if value["format"] != MUTATION_RESULT_FORMAT \
            or value["schema_version"] != SCHEMA_VERSION:
        _error("unsupported_mutation_result", "unsupported mutation result")
    _digest(value["scope_fingerprint"], "result scope fingerprint")
    if expected_scope is not None \
            and value["scope_fingerprint"] != scope_fingerprint(expected_scope):
        _error("cross_principal_result", "mutation result belongs to another scope")
    _identifier("result client_mutation_id", value["client_mutation_id"], mutation=True)
    _digest(value["request_sha256"], "request_sha256")
    if not isinstance(value["status"], str) \
            or value["status"] not in {"applied", "duplicate", "conflict", "rejected"}:
        _error("invalid_mutation_status", "invalid mutation result status")
    if not isinstance(value["code"], str) or not value["code"] \
            or not isinstance(value["reason"], str) or not value["reason"]:
        _error("invalid_mutation_result", "mutation result needs code and reason")
    if not isinstance(value["retryable"], bool):
        _error("invalid_mutation_result", "retryable must be boolean")
    _timestamp(value["recorded_at"], "mutation result recorded_at")
    if value["server_cursor"] is not None:
        validate_cursor(value["server_cursor"])
    _reject_secret_keys(value["result"])
    _reject_secret_keys(value["current"])
    if value["status"] in {"applied", "duplicate"}:
        if not isinstance(value["result"], dict) or value["server_cursor"] is None:
            _error("invalid_success_result", "successful mutation needs result and cursor")
    elif value["result"] is not None:
        _error("invalid_failure_result", "conflict/rejection cannot contain success result")
    return value


def make_stored_receipt(scope, mutation, applied, stored_at=None):
    scope = validate_scope(scope)
    mutation = validate_client_mutation(mutation, expected_scope=scope)
    applied = validate_mutation_result(applied, expected_scope=scope)
    if applied["status"] != "applied" \
            or applied["client_mutation_id"] != mutation["client_mutation_id"] \
            or applied["request_sha256"] != mutation["request_sha256"]:
        _error("invalid_receipt", "stored receipt must wrap its applied mutation")
    receipt = {
        "format": STORED_RECEIPT_FORMAT,
        "schema_version": SCHEMA_VERSION,
        "scope_fingerprint": scope_fingerprint(scope),
        "client_mutation_id": mutation["client_mutation_id"],
        "request_sha256": mutation["request_sha256"],
        "applied": applied,
        "stored_at": stored_at or utc_now(),
    }
    return validate_stored_receipt(receipt, expected_scope=scope)


def validate_stored_receipt(receipt, expected_scope=None):
    _exact_keys(receipt, {
        "format", "schema_version", "scope_fingerprint",
        "client_mutation_id", "request_sha256", "applied", "stored_at",
    }, label="stored receipt")
    value = _json_copy(receipt, max_bytes=MAX_MUTATION_BYTES * 2)
    if value["format"] != STORED_RECEIPT_FORMAT \
            or value["schema_version"] != SCHEMA_VERSION:
        _error("unsupported_receipt", "unsupported stored receipt")
    _digest(value["scope_fingerprint"], "receipt scope fingerprint")
    if expected_scope is not None \
            and value["scope_fingerprint"] != scope_fingerprint(expected_scope):
        _error("cross_principal_receipt", "stored receipt belongs to another scope")
    _identifier("receipt client_mutation_id", value["client_mutation_id"], mutation=True)
    _digest(value["request_sha256"], "receipt request_sha256")
    applied = validate_mutation_result(value["applied"])
    if applied["status"] != "applied" \
            or applied["scope_fingerprint"] != value["scope_fingerprint"] \
            or applied["client_mutation_id"] != value["client_mutation_id"] \
            or applied["request_sha256"] != value["request_sha256"]:
        _error("invalid_receipt", "stored receipt and applied result disagree")
    _timestamp(value["stored_at"], "receipt stored_at")
    return value


def stored_receipt_outcome(receipt, mutation, request_scope, recorded_at=None):
    """Return duplicate/body-conflict/cross-principal result without writes."""
    scope = validate_scope(request_scope)
    mutation = validate_client_mutation(mutation, expected_scope=scope)
    receipt = validate_stored_receipt(receipt)
    if receipt["client_mutation_id"] != mutation["client_mutation_id"]:
        return rejected_result(
            scope, mutation, "receipt_key_mismatch",
            "stored receipt is for a different mutation id",
            recorded_at=recorded_at)
    if receipt["scope_fingerprint"] != scope_fingerprint(scope):
        return rejected_result(
            scope, mutation, "cross_principal_idempotency_key",
            "idempotency receipt belongs to another authenticated scope",
            recorded_at=recorded_at)
    if receipt["request_sha256"] != mutation["request_sha256"]:
        return conflict_result(
            scope, mutation, "idempotency_key_reused",
            "client_mutation_id was already stored for a different body",
            retryable=False, recorded_at=recorded_at)
    applied = receipt["applied"]
    duplicate = dict(applied)
    duplicate.update({
        "status": "duplicate",
        "code": "duplicate",
        "reason": "identical mutation was already applied",
        "recorded_at": recorded_at or utc_now(),
    })
    return validate_mutation_result(duplicate, expected_scope=scope)


def make_push_result(scope, visibility, results, server_cursor,
                     generated_at=None):
    scope = validate_scope(scope)
    results = [validate_mutation_result(item, expected_scope=scope)
               for item in results]
    statuses = {item["status"] for item in results}
    status = "ok" if statuses <= {"applied", "duplicate"} else "partial"
    envelope = {
        "format": PUSH_RESULT_FORMAT,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "scope": scope,
        "visibility_fingerprint": validate_visibility_fingerprint(visibility),
        "results": results,
        "server_cursor": validate_cursor(server_cursor),
        "generated_at": generated_at or utc_now(),
    }
    return validate_push_result(envelope, expected_scope=scope)


def validate_push_result(envelope, expected_scope=None,
                         expected_visibility=None,
                         expected_mutation_ids=None):
    _exact_keys(envelope, {
        "format", "schema_version", "status", "scope",
        "visibility_fingerprint", "results", "server_cursor", "generated_at",
    }, label="push result")
    value = _json_copy(envelope, max_bytes=MAX_PUSH_BYTES * 2)
    if value["format"] != PUSH_RESULT_FORMAT or value["schema_version"] != SCHEMA_VERSION:
        _error("unsupported_push_result", "unsupported push result format or schema")
    scope = validate_scope(value["scope"], expected_scope=expected_scope)
    validate_visibility_fingerprint(
        value["visibility_fingerprint"], expected=expected_visibility)
    validate_cursor(value["server_cursor"])
    _timestamp(value["generated_at"], "push result generated_at")
    if not isinstance(value["results"], list) or len(value["results"]) > MAX_MUTATIONS:
        _error("invalid_push_results", "push results must be a bounded array")
    ids = []
    for item in value["results"]:
        result = validate_mutation_result(item, expected_scope=scope)
        if result["client_mutation_id"] in ids:
            _error("duplicate_push_result", "push result repeats a mutation id")
        ids.append(result["client_mutation_id"])
    if expected_mutation_ids is not None and ids != list(expected_mutation_ids):
        _error("push_result_order", "push results do not match request order")
    expected_status = "ok" if all(
        item["status"] in {"applied", "duplicate"}
        for item in value["results"]) else "partial"
    if value["status"] != expected_status:
        _error("invalid_push_status", "push aggregate status is incorrect")
    return value


__all__ = [
    "SCHEMA_VERSION", "SNAPSHOT_FORMAT", "PULL_REQUEST_FORMAT",
    "PULL_RESULT_FORMAT", "PUSH_REQUEST_FORMAT", "PUSH_RESULT_FORMAT",
    "MUTATION_FORMAT", "MUTATION_RESULT_FORMAT", "STORED_RECEIPT_FORMAT",
    "PROJECTION_SCHEMA_VERSION", "LEGACY_PROJECTION_SCHEMA_VERSION",
    "PROJECTION_CAPABILITIES_FORMAT", "GENESIS_HASH",
    "MAX_SNAPSHOT_BYTES", "MAX_PULL_BYTES",
    "MAX_PUSH_BYTES", "MAX_MUTATION_BYTES", "MAX_MUTATIONS",
    "MAX_PULL_RECORDS", "SyncProtocolError", "EnvelopeTooLarge",
    "is_schema_compatibility_error",
    "canonical_json_bytes", "utc_now", "validate_scope",
    "scope_fingerprint", "visibility_fingerprint",
    "validate_visibility_fingerprint", "make_cursor", "validate_cursor",
    "make_visible_record", "make_redacted_anchor", "validate_chain_record",
    "validate_chain", "validate_projection_capabilities",
    "make_projection_capabilities", "legacy_projection_capabilities",
    "current_projection_capabilities", "negotiate_projection_capabilities",
    "projection_capabilities_query", "projection_capabilities_from_query",
    "projection_visibility_policy", "validate_identity_projection",
    "validate_projection_for_capabilities",
    "filter_projection_for_capabilities", "make_snapshot",
    "validate_snapshot", "make_pull_request", "validate_pull_request",
    "make_pull_result", "make_reset_required", "validate_pull_result",
    "local_ref", "mutation_sha256", "make_client_mutation",
    "validate_client_mutation", "make_push_request", "validate_push_request",
    "applied_result", "conflict_result", "rejected_result",
    "validate_mutation_result", "make_stored_receipt",
    "validate_stored_receipt", "stored_receipt_outcome",
    "make_push_result", "validate_push_result",
]
