"""Deterministic, portable Attacca project exports and offline snapshots.

This module deliberately has no dependency on :mod:`attacca.py`, which lets
the HTTP, CLI, and test surfaces integrate it without creating an import
cycle.  It operates on an already-open SQLite connection and never mutates
that database.

The JSON export keeps both a decoded event ``payload`` and the exact stored
``payload_json`` used by Attacca's immutable hash chain.  Server-global
settings and authentication secrets are intentionally outside a project
export.  The deterministic ZIP contains the JSON export plus two convenient
artifacts: ``ledger.ndjson`` and ``full-log.txt``.
"""

import hashlib
import io
import json
import os
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path


EXPORT_FORMAT = "attacca.project-export"
EXPORT_SCHEMA_VERSION = 1
OFFLINE_CACHE_FORMAT = "attacca.offline-project-cache"
OFFLINE_CACHE_SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64


class ProjectExportError(ValueError):
    """The requested project or supplied export/cache is invalid."""


class OfflineCacheError(ProjectExportError):
    """An offline baseline is malformed, stale, or from a forked ledger."""


def _canonical_json(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _json_bytes(value, pretty=False):
    if pretty:
        body = json.dumps(
            value, ensure_ascii=False, sort_keys=True, indent=2)
    else:
        body = _canonical_json(value)
    return (body + "\n").encode("utf-8")


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _decoded_json(value):
    """Decode valid JSON while retaining malformed legacy text losslessly."""
    if value is None:
        return None
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def _query_rows(conn, sql, params=()):
    cursor = conn.execute(sql, params)
    columns = [item[0] for item in cursor.description or ()]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _table_names(conn):
    return {
        row["name"] for row in _query_rows(
            conn,
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
        )
    }


def _optional_rows(conn, tables, table, sql, params=()):
    if table not in tables:
        return []
    return _query_rows(conn, sql, params)


@contextmanager
def _consistent_snapshot(conn):
    """Keep every section on one SQLite read snapshot.

    SAVEPOINT works both in autocommit mode and inside a caller-owned
    transaction.  It does not acquire a write lock.
    """
    name = "attacca_project_export_snapshot"
    conn.execute("SAVEPOINT %s" % name)
    try:
        yield
    except Exception:
        conn.execute("ROLLBACK TO %s" % name)
        conn.execute("RELEASE %s" % name)
        raise
    else:
        conn.execute("RELEASE %s" % name)


def _event_record(row):
    event = dict(row)
    payload_json = event.get("payload")
    event["payload_json"] = payload_json
    event["payload"] = _decoded_json(payload_json)
    return event


def _decode_columns(rows, columns):
    decoded = []
    for source in rows:
        row = dict(source)
        for column in columns:
            if column in row:
                row[column] = _decoded_json(row[column])
        decoded.append(row)
    return decoded


def _room_record(event):
    message = {
        key: event.get(key) for key in (
            "event_id", "project_id", "seq", "actor_id", "actor_type",
            "owner", "task_id", "context_version", "base_revision",
            "git_branch", "device_id", "created_at", "payload_hash",
            "prev_hash", "hash", "hash_version",
        )
    }
    payload = event.get("payload")
    payload = payload if isinstance(payload, dict) else {}
    message.update({
        "msg_type": payload.get("msg_type"),
        "body": payload.get("body"),
        "mentions": payload.get("mentions"),
        "reply_to": payload.get("reply_to"),
        "origin_project": payload.get("origin_project"),
        "authority": payload.get("authority"),
        "mirrored_to": payload.get("mirrored_to") or [],
        "payload": event.get("payload"),
        "payload_json": event.get("payload_json"),
    })
    return message


def _generic_log_line(event):
    """Render one complete event when the application renderer omits it."""
    at = str(event.get("created_at") or "").replace("T", " ")[:19]
    actor = str(event.get("actor_id") or "unknown")
    if event.get("owner"):
        actor += " (OWNER: %s)" % event["owner"]
    task = " [%s]" % event["task_id"] if event.get("task_id") else ""
    payload = event.get("payload")
    if not isinstance(payload, dict):
        payload = _decoded_json(
            event.get("payload_json")
            if event.get("payload_json") is not None else payload)
    if event.get("event_type") == "room.message" and isinstance(payload, dict):
        origin = " (from %s)" % payload["origin_project"] \
            if payload.get("origin_project") else ""
        authority = " [%s]" % str(payload["authority"]).upper() \
            if payload.get("authority") else ""
        return "%s  %s%s %s%s%s: %s" % (
            at, actor, origin,
            str(payload.get("msg_type") or "chat").upper(), authority, task,
            payload.get("body") or "",
        )
    body = _canonical_json(payload)
    return "%s  %s %s%s %s" % (
        at, actor, event.get("event_type") or "unknown", task, body)


def _full_log(events, log_renderer=None):
    lines = []
    for event in events:
        line = None
        if log_renderer is not None:
            # attacca.render_log_line accepts a sqlite.Row-like mapping.
            try:
                line = log_renderer(event)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                line = None
        # The normal concise renderer intentionally drops room chat/status.
        # A portable full log must still have one entry for every event.
        lines.append(str(line) if line is not None else _generic_log_line(event))
    return lines


def _stored_payload(event):
    if "payload_json" in event and isinstance(event["payload_json"], str):
        return event["payload_json"]
    payload = event.get("payload")
    return payload if isinstance(payload, str) else _canonical_json(payload)


def verify_exported_ledger(events, project_id=None):
    """Verify an exported Attacca hash chain without importing attacca.py."""
    problems = []
    previous_hash = GENESIS_HASH
    expected_seq = 1
    for event in events:
        seq = event.get("seq")
        if seq != expected_seq:
            problems.append(
                "seq gap: expected %d, found %s (event %s)" % (
                    expected_seq, seq, event.get("event_id")))
            if isinstance(seq, int):
                expected_seq = seq
        if project_id is not None and event.get("project_id") != project_id:
            problems.append(
                "event %s belongs to project %s, expected %s" % (
                    event.get("event_id"), event.get("project_id"), project_id))
        if event.get("prev_hash") != previous_hash:
            problems.append("chain break at seq %s: prev_hash mismatch" % seq)
        payload_json = _stored_payload(event)
        payload_hash = _sha256(payload_json.encode("utf-8"))
        if payload_hash != event.get("payload_hash"):
            problems.append("payload tampered at seq %s" % seq)
        hash_version = int(event.get("hash_version") or 1)
        if hash_version >= 2:
            material = "|".join([
                event.get("prev_hash") or "", payload_hash,
                event.get("project_id") or "", str(seq),
                event.get("event_type") or "", event.get("actor_id") or "",
                event.get("created_at") or "", event.get("actor_type") or "",
                event.get("owner") or "",
                str(event.get("context_version") or ""),
                event.get("base_revision") or "",
                event.get("git_branch") or "", event.get("device_id") or "",
                event.get("task_id") or "",
            ])
        else:
            material = "|".join([
                event.get("prev_hash") or "", payload_hash,
                event.get("project_id") or "", str(seq),
                event.get("event_type") or "", event.get("actor_id") or "",
                event.get("created_at") or "",
            ])
        if _sha256(material.encode("utf-8")) != event.get("hash"):
            problems.append("event hash mismatch at seq %s" % seq)
        previous_hash = event.get("hash") or ""
        expected_seq += 1
    return {
        "ok": not problems,
        "events": len(events),
        "head_hash": previous_hash if events else GENESIS_HASH,
        "problems": problems,
    }


def _ledger_ndjson_bytes(events):
    if not events:
        return b""
    return ("\n".join(_canonical_json(event) for event in events) + "\n").encode(
        "utf-8")


def _full_log_bytes(lines):
    if not lines:
        return b""
    return ("\n".join(lines) + "\n").encode("utf-8")


def _snapshot_at(sections):
    timestamps = []
    for rows in sections:
        for row in rows:
            if not isinstance(row, dict):
                continue
            for key, value in row.items():
                if (key.endswith("_at") or key == "created_at") \
                        and isinstance(value, str) and value:
                    timestamps.append(value)
    return max(timestamps) if timestamps else None


def build_project_export(conn, project_id, log_renderer=None):
    """Build a deterministic, JSON-serializable project snapshot.

    ``log_renderer`` may be ``attacca.render_log_line``.  Any events that the
    concise application renderer excludes are rendered by this module so the
    exported full log always has exactly one entry per ledger event.
    """
    project_id = str(project_id or "").strip()
    if not project_id:
        raise ProjectExportError("project_id is required")

    with _consistent_snapshot(conn):
        tables = _table_names(conn)
        if "projects" not in tables or "events" not in tables:
            raise ProjectExportError(
                "database does not contain the Attacca project ledger schema")
        projects = _query_rows(
            conn, "SELECT * FROM projects WHERE project_id=?", (project_id,))
        if not projects:
            raise ProjectExportError("unknown project %r" % project_id)
        project = projects[0]

        raw_events = _query_rows(
            conn,
            "SELECT * FROM events WHERE project_id=? ORDER BY seq, event_id",
            (project_id,),
        )
        events = [_event_record(row) for row in raw_events]
        raw_tasks = _optional_rows(
            conn, tables, "tasks",
            "SELECT * FROM tasks WHERE project_id=? "
            "ORDER BY CAST(SUBSTR(task_id,3) AS INTEGER), task_id",
            (project_id,),
        )
        tasks = _decode_columns(
            raw_tasks, ("expected_scope", "dependencies", "last_report"))
        raw_plans = _optional_rows(
            conn, tables, "task_plan_revisions",
            "SELECT * FROM task_plan_revisions WHERE project_id=? "
            "ORDER BY CAST(SUBSTR(task_id,3) AS INTEGER), task_id, version",
            (project_id,),
        )
        plans = _decode_columns(raw_plans, ("sections",))
        plans_by_task = {}
        for plan in plans:
            plans_by_task.setdefault(plan.get("task_id"), []).append(plan)
        for task in tasks:
            task["plan_revisions"] = plans_by_task.get(task.get("task_id"), [])

        raw_handoffs = _optional_rows(
            conn, tables, "handoffs",
            "SELECT * FROM handoffs WHERE project_id=? ORDER BY version",
            (project_id,),
        )
        handoffs = _decode_columns(raw_handoffs, ("content",))
        decisions = _optional_rows(
            conn, tables, "decisions",
            "SELECT * FROM decisions WHERE project_id=? "
            "ORDER BY CAST(SUBSTR(decision_id,3) AS INTEGER), decision_id",
            (project_id,),
        )
        rules = _optional_rows(
            conn, tables, "project_rules",
            "SELECT * FROM project_rules WHERE project_id=? "
            "ORDER BY priority, CAST(SUBSTR(rule_id,3) AS INTEGER), rule_id",
            (project_id,),
        )
        agents = _optional_rows(
            conn, tables, "agents",
            "SELECT * FROM agents WHERE project_id=? "
            "ORDER BY registered_at, agent_id",
            (project_id,),
        )
        aliases = _optional_rows(
            conn, tables, "actor_aliases",
            "SELECT * FROM actor_aliases WHERE project_id=? "
            "ORDER BY legacy_actor_id, canonical_actor_id",
            (project_id,),
        )
        raw_bridges = _optional_rows(
            conn, tables, "bridges",
            "SELECT * FROM bridges WHERE project_a=? OR project_b=? "
            "ORDER BY project_a, project_b",
            (project_id, project_id),
        )
        bridges = _decode_columns(raw_bridges, ("access_a", "access_b"))
        cursors = _optional_rows(
            conn, tables, "inbox_cursors",
            "SELECT * FROM inbox_cursors WHERE project_id=? ORDER BY actor_id",
            (project_id,),
        )
        clients = _optional_rows(
            conn, tables, "agent_clients",
            "SELECT * FROM agent_clients WHERE project_id=? "
            "ORDER BY agent_id, device_id",
            (project_id,),
        )

    full_log = _full_log(raw_events, log_renderer=log_renderer)
    room_messages = [
        _room_record(event) for event in events
        if event.get("event_type") == "room.message"
    ]
    verification = verify_exported_ledger(events, project_id=project_id)
    ledger_bytes = _ledger_ndjson_bytes(events)
    log_bytes = _full_log_bytes(full_log)
    latest_event = events[-1] if events else None
    counts = {
        "events": len(events),
        "room_messages": len(room_messages),
        "tasks": len(tasks),
        "task_plan_revisions": len(plans),
        "handoffs": len(handoffs),
        "decisions": len(decisions),
        "rules": len(rules),
        "agents": len(agents),
        "actor_aliases": len(aliases),
        "bridges": len(bridges),
        "inbox_cursors": len(cursors),
        "agent_clients": len(clients),
    }
    snapshot_at = _snapshot_at([
        [project], raw_events, raw_tasks, raw_plans, raw_handoffs, decisions,
        rules, agents, aliases, raw_bridges, cursors, clients,
    ])
    export_body = {
        "project": project,
        "ledger": {"events": events, "verification": verification},
        "full_log": full_log,
        "room_messages": room_messages,
        "tasks": tasks,
        "handoffs": handoffs,
        "decisions": decisions,
        "rules": rules,
        "agents": agents,
        "actor_aliases": aliases,
        "bridges": bridges,
        "inbox_cursors": cursors,
        "agent_clients": clients,
    }
    manifest = {
        "format": EXPORT_FORMAT,
        "schema_version": EXPORT_SCHEMA_VERSION,
        "project_id": project_id,
        "snapshot": {
            "at": snapshot_at,
            "context_version": project.get("context_version"),
            "event_cursor": latest_event.get("seq") if latest_event else 0,
            "head_hash": latest_event.get("hash") if latest_event else GENESIS_HASH,
        },
        "counts": counts,
        "integrity": {"ledger": verification},
        "content_sha256": _sha256(_json_bytes(export_body, pretty=False)),
        "artifacts": {
            "ledger.ndjson": {
                "bytes": len(ledger_bytes),
                "records": len(events),
                "sha256": _sha256(ledger_bytes),
            },
            "full-log.txt": {
                "bytes": len(log_bytes),
                "records": len(full_log),
                "sha256": _sha256(log_bytes),
            },
        },
        "excluded_server_tables": [
            "auth_sessions", "auth_tokens", "auth_users", "server_settings",
        ],
    }
    return {"manifest": manifest, **export_body}


def project_export_json_bytes(project_export, pretty=True):
    """Serialize a project export with stable key order and a final newline."""
    validate_project_export(project_export, require_valid_ledger=False)
    return _json_bytes(project_export, pretty=pretty)


def project_export_ledger_ndjson_bytes(project_export):
    validate_project_export(project_export, require_valid_ledger=False)
    return _ledger_ndjson_bytes(project_export["ledger"]["events"])


def project_export_full_log_bytes(project_export):
    validate_project_export(project_export, require_valid_ledger=False)
    return _full_log_bytes(project_export["full_log"])


def validate_project_export(project_export, require_valid_ledger=True):
    """Validate format, artifact digests, cursor, and the immutable ledger."""
    if not isinstance(project_export, dict):
        raise ProjectExportError("project export must be a JSON object")
    manifest = project_export.get("manifest")
    if not isinstance(manifest, dict) or manifest.get("format") != EXPORT_FORMAT:
        raise ProjectExportError("not an Attacca project export")
    if manifest.get("schema_version") != EXPORT_SCHEMA_VERSION:
        raise ProjectExportError(
            "unsupported project export schema version %r" %
            manifest.get("schema_version"))
    project_id = manifest.get("project_id")
    if not project_id or (project_export.get("project") or {}).get(
            "project_id") != project_id:
        raise ProjectExportError("project metadata does not match manifest")
    ledger = project_export.get("ledger")
    events = ledger.get("events") if isinstance(ledger, dict) else None
    if not isinstance(events, list):
        raise ProjectExportError("project export ledger.events must be an array")
    lines = project_export.get("full_log")
    if not isinstance(lines, list) or not all(isinstance(line, str) for line in lines):
        raise ProjectExportError("project export full_log must be an array of strings")
    if len(lines) != len(events):
        raise ProjectExportError("full_log must contain one record per event")

    verification = verify_exported_ledger(events, project_id=project_id)
    if ledger.get("verification") != verification \
            or (manifest.get("integrity") or {}).get("ledger") != verification:
        raise ProjectExportError("recorded ledger verification is stale")
    if require_valid_ledger and not verification["ok"]:
        raise ProjectExportError(
            "exported ledger failed verification: %s" %
            "; ".join(verification["problems"]))
    snapshot = manifest.get("snapshot") or {}
    last = events[-1] if events else None
    if snapshot.get("event_cursor") != (last.get("seq") if last else 0) \
            or snapshot.get("head_hash") != (
                last.get("hash") if last else GENESIS_HASH):
        raise ProjectExportError("manifest snapshot cursor does not match ledger")
    artifacts = manifest.get("artifacts") or {}
    expected = {
        "ledger.ndjson": _ledger_ndjson_bytes(events),
        "full-log.txt": _full_log_bytes(lines),
    }
    for name, data in expected.items():
        metadata = artifacts.get(name) or {}
        if metadata.get("sha256") != _sha256(data) \
                or metadata.get("bytes") != len(data):
            raise ProjectExportError("manifest digest does not match %s" % name)
    export_body = {
        key: value for key, value in project_export.items() if key != "manifest"
    }
    if manifest.get("content_sha256") != _sha256(
            _json_bytes(export_body, pretty=False)):
        raise ProjectExportError("manifest content digest does not match export")
    return verification


def _zip_entry(name, data):
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info, data


def project_export_zip_bytes(project_export):
    """Return a deterministic portable ZIP for an already-built export."""
    validate_project_export(project_export, require_valid_ledger=False)
    files = [
        ("manifest.json", _json_bytes(project_export["manifest"], pretty=True)),
        ("project-export.json", _json_bytes(project_export, pretty=True)),
        ("ledger.ndjson", _ledger_ndjson_bytes(
            project_export["ledger"]["events"])),
        ("full-log.txt", _full_log_bytes(project_export["full_log"])),
    ]
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.comment = b"Attacca deterministic project export v1"
        for name, data in files:
            info, body = _zip_entry(name, data)
            archive.writestr(info, body)
    return output.getvalue()


def build_project_export_zip(conn, project_id, log_renderer=None):
    """Build a project snapshot and return its deterministic ZIP bytes."""
    return project_export_zip_bytes(build_project_export(
        conn, project_id, log_renderer=log_renderer))


def _copy_json(value):
    return json.loads(_canonical_json(value))


def build_offline_cache(project_export):
    """Wrap a complete export as a deterministic local baseline + cursor."""
    validate_project_export(project_export)
    baseline = _copy_json(project_export)
    baseline_bytes = _json_bytes(baseline, pretty=False)
    snapshot = baseline["manifest"]["snapshot"]
    return {
        "format": OFFLINE_CACHE_FORMAT,
        "schema_version": OFFLINE_CACHE_SCHEMA_VERSION,
        "project_id": baseline["manifest"]["project_id"],
        "cursor": {
            "event_seq": snapshot["event_cursor"],
            "event_hash": snapshot["head_hash"],
            "context_version": snapshot.get("context_version"),
        },
        "baseline_sha256": _sha256(baseline_bytes),
        "baseline": baseline,
    }


def validate_offline_cache(cache, expected_project_id=None):
    """Validate an offline record and return a copy of its sync cursor."""
    if not isinstance(cache, dict) or cache.get("format") != OFFLINE_CACHE_FORMAT:
        raise OfflineCacheError("not an Attacca offline project cache")
    if cache.get("schema_version") != OFFLINE_CACHE_SCHEMA_VERSION:
        raise OfflineCacheError(
            "unsupported offline cache schema version %r" %
            cache.get("schema_version"))
    project_id = cache.get("project_id")
    if expected_project_id is not None and project_id != expected_project_id:
        raise OfflineCacheError(
            "offline cache is for %s, not %s" %
            (project_id, expected_project_id))
    baseline = cache.get("baseline")
    try:
        validate_project_export(baseline)
    except ProjectExportError as error:
        raise OfflineCacheError(str(error))
    if baseline["manifest"]["project_id"] != project_id:
        raise OfflineCacheError("offline baseline project does not match cache")
    digest = _sha256(_json_bytes(baseline, pretty=False))
    if digest != cache.get("baseline_sha256"):
        raise OfflineCacheError("offline baseline digest mismatch")
    snapshot = baseline["manifest"]["snapshot"]
    expected_cursor = {
        "event_seq": snapshot["event_cursor"],
        "event_hash": snapshot["head_hash"],
        "context_version": snapshot.get("context_version"),
    }
    if cache.get("cursor") != expected_cursor:
        raise OfflineCacheError("offline cursor does not match its baseline")
    return dict(expected_cursor)


def offline_cache_cursor(cache, expected_project_id=None):
    """Return a validated cursor suitable for a later delta/snapshot request."""
    return validate_offline_cache(
        cache, expected_project_id=expected_project_id)


def advance_offline_cache(cache, project_export):
    """Replace a baseline only when the new export extends the same ledger.

    Cursor regression and a different hash at the cached sequence are rejected
    before the new snapshot becomes durable.  Non-ledger state (for example an
    inbox cursor) may still refresh while the event cursor remains unchanged.
    """
    old_cursor = validate_offline_cache(cache)
    validate_project_export(project_export)
    project_id = cache["project_id"]
    if project_export["manifest"]["project_id"] != project_id:
        raise OfflineCacheError("cannot advance cache with a different project")
    new_events = project_export["ledger"]["events"]
    new_cursor = project_export["manifest"]["snapshot"]["event_cursor"]
    if new_cursor < old_cursor["event_seq"]:
        raise OfflineCacheError("offline event cursor cannot move backwards")
    if old_cursor["event_seq"]:
        matching = next((
            event for event in new_events
            if event.get("seq") == old_cursor["event_seq"]
        ), None)
        if matching is None or matching.get("hash") != old_cursor["event_hash"]:
            raise OfflineCacheError(
                "new export does not extend the cached ledger (fork detected)")
    return build_offline_cache(project_export)


def save_offline_cache(path, cache):
    """Atomically persist a validated cache as a user-private JSON file."""
    validate_offline_cache(cache)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise OfflineCacheError("refusing to replace symlinked offline cache")
    data = _json_bytes(cache, pretty=True)
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


def load_offline_cache(path, expected_project_id=None):
    """Load and fully validate a previously saved offline baseline."""
    target = Path(path)
    try:
        with target.open("r", encoding="utf-8") as handle:
            cache = json.load(handle)
    except (OSError, ValueError) as error:
        raise OfflineCacheError("cannot load offline cache %s: %s" %
                                (target, error))
    validate_offline_cache(cache, expected_project_id=expected_project_id)
    return cache


__all__ = [
    "EXPORT_FORMAT", "EXPORT_SCHEMA_VERSION", "OFFLINE_CACHE_FORMAT",
    "OFFLINE_CACHE_SCHEMA_VERSION", "ProjectExportError", "OfflineCacheError",
    "build_project_export", "build_project_export_zip",
    "project_export_json_bytes", "project_export_zip_bytes",
    "project_export_ledger_ndjson_bytes", "project_export_full_log_bytes",
    "verify_exported_ledger", "validate_project_export",
    "build_offline_cache", "validate_offline_cache", "offline_cache_cursor",
    "advance_offline_cache", "save_offline_cache", "load_offline_cache",
]
