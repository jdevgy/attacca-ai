#!/usr/bin/env python3
"""Safely repair duplicate Attacca tables in a Codex ``config.toml``.

Older Attacca installers replaced only the first
``[mcp_servers.attacca]`` table.  A descendant table such as
``[mcp_servers.attacca.env]`` could survive beside the newer inline ``env``
key, making Codex reject the entire file as a duplicate key.  This standalone
utility removes every Attacca root/descendant table, preserves unrelated TOML
verbatim, validates the repaired document, and atomically installs one
canonical block.
"""

from __future__ import print_function

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path

try:  # Python 3.11+ standard library.
    import tomllib
except ImportError:  # pragma: no cover - retained for Attacca's Python 3.8+ floor.
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:  # pragma: no cover
        tomllib = None


ATTACCA_TABLE_PREFIX = ("mcp_servers", "attacca")


class CodexConfigRepairError(RuntimeError):
    """The repair could not be proven safe; the input was left untouched."""


def _toml_string(value):
    """Return a TOML-compatible basic string with deterministic escaping."""
    return json.dumps(str(value), ensure_ascii=False)


def canonical_connect_block(server_url, script_path):
    server_url = str(server_url or "").strip().rstrip("/")
    if not re.match(r"^https?://[^\s]+$", server_url):
        raise CodexConfigRepairError(
            "--server-url must be an http:// or https:// URL")
    script_path = str(Path(script_path).expanduser().resolve())
    return "\n".join([
        "[mcp_servers.attacca]",
        'command = "python3"',
        "args = [%s, \"connect\"]" % _toml_string(script_path),
        "env = { \"ATTACCA_ACTOR\" = \"codex\", "
        "\"ATTACCA_URL\" = %s }" % _toml_string(server_url),
    ])


def _split_table_key(value):
    """Parse enough TOML dotted-key syntax to identify exact table paths."""
    parts = []
    token = []
    quote = None
    escaped = False

    def finish():
        raw = "".join(token).strip()
        del token[:]
        if not raw:
            raise CodexConfigRepairError("empty key in TOML table header")
        if raw[0:1] in ('"', "'"):
            if len(raw) < 2 or raw[-1] != raw[0]:
                raise CodexConfigRepairError("unterminated quoted TOML table key")
            if raw[0] == '"':
                try:
                    raw = json.loads(raw)
                except (TypeError, ValueError) as error:
                    raise CodexConfigRepairError(
                        "invalid quoted TOML table key: %s" % error)
            else:
                raw = raw[1:-1]
        parts.append(raw)

    for character in value:
        if quote:
            token.append(character)
            if quote == '"' and escaped:
                escaped = False
            elif quote == '"' and character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in ('"', "'"):
            quote = character
            token.append(character)
        elif character == ".":
            finish()
        else:
            token.append(character)
    if quote:
        raise CodexConfigRepairError("unterminated quote in TOML table header")
    finish()
    return tuple(parts)


def _table_header_path(line):
    """Return one TOML table path, or ``None`` for a non-header line."""
    candidate = line.strip()
    if not candidate.startswith("["):
        return None
    array = candidate.startswith("[[")
    opening = 2 if array else 1
    closing = "]]" if array else "]"
    quote = None
    escaped = False
    end = None
    index = opening
    while index < len(candidate):
        character = candidate[index]
        if quote:
            if quote == '"' and escaped:
                escaped = False
            elif quote == '"' and character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character in ('"', "'"):
            quote = character
            index += 1
            continue
        if candidate.startswith(closing, index):
            end = index
            break
        index += 1
    if end is None:
        return None
    remainder = candidate[end + len(closing):].strip()
    if remainder and not remainder.startswith("#"):
        return None
    return _split_table_key(candidate[opening:end])


def _is_attacca_table(path):
    return path is not None and tuple(path[:2]) == ATTACCA_TABLE_PREFIX


def replace_attacca_tables(text, canonical_block):
    """Replace every Attacca TOML table/descendant with one canonical block.

    Text outside the removed table sections is preserved byte-for-byte.  The
    result is stable: applying this function again with the same block returns
    exactly the same text.
    """
    if not isinstance(text, str) or not isinstance(canonical_block, str):
        raise CodexConfigRepairError("config text and canonical block are required")
    block = canonical_block.strip("\r\n")
    if _table_header_path(block.splitlines()[0]) != ATTACCA_TABLE_PREFIX:
        raise CodexConfigRepairError(
            "canonical block must begin with [mcp_servers.attacca]")

    lines = text.splitlines(True)
    offsets = []
    cursor = 0
    headers = []
    for line in lines:
        path = _table_header_path(line)
        if path is not None:
            headers.append((cursor, path))
        cursor += len(line)
    # ``splitlines(True)`` is empty for an empty document and still accounts
    # for a final non-newline-terminated line when content exists.
    if text and cursor != len(text):
        raise CodexConfigRepairError("could not scan the complete TOML document")
    for index, (start, path) in enumerate(headers):
        end = headers[index + 1][0] if index + 1 < len(headers) else len(text)
        if _is_attacca_table(path):
            offsets.append((start, end))

    if not offsets:
        if not text:
            return block + "\n"
        separator = "" if text.endswith("\n\n") else (
            "\n" if text.endswith("\n") else "\n\n")
        return text + separator + block + "\n"

    first_start = offsets[0][0]
    output = []
    position = 0
    inserted = False
    for start, end in offsets:
        output.append(text[position:start])
        if not inserted:
            has_suffix = end < len(text) or len(offsets) > 1
            output.append(block + ("\n\n" if has_suffix else "\n"))
            inserted = True
        position = end
    output.append(text[position:])
    return "".join(output)


def validate_repaired_toml(text):
    if tomllib is None:  # Keep the main installer usable on Python 3.8-3.10.
        # The scanner can still prove that exactly one root and no descendant
        # Attacca tables remain. Full TOML validation is performed whenever
        # stdlib tomllib (or optional tomli) is available.
        paths = [
            path for path in (_table_header_path(line)
                              for line in text.splitlines())
            if _is_attacca_table(path)
        ]
        if paths != [ATTACCA_TABLE_PREFIX]:
            raise CodexConfigRepairError(
                "repaired config does not contain one canonical Attacca table")
        return {"validator": "structural-fallback"}
    try:
        parsed = tomllib.loads(text)
    except Exception as error:
        raise CodexConfigRepairError(
            "repaired config is still invalid TOML; original left untouched: %s"
            % error)
    attacca = (parsed.get("mcp_servers") or {}).get("attacca") \
        if isinstance(parsed, dict) else None
    if not isinstance(attacca, dict) \
            or attacca.get("command") != "python3" \
            or not isinstance(attacca.get("args"), list) \
            or not isinstance(attacca.get("env"), dict):
        raise CodexConfigRepairError(
            "repaired config did not produce one canonical Attacca MCP entry")
    return {"validator": "tomllib", "parsed": parsed}


def _stage_bytes(directory, prefix, data, mode):
    descriptor, name = tempfile.mkstemp(prefix=prefix, dir=str(directory))
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return Path(name)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(name)
        except OSError:
            pass
        raise


def _fsync_directory(directory):
    try:
        descriptor = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _create_backup_once(target, data, mode):
    backup = target.with_name(target.name + ".attacca-backup")
    if backup.is_symlink():
        raise CodexConfigRepairError(
            "refusing unsafe symlinked Codex backup: %s" % backup)
    if backup.exists() and not backup.is_file():
        raise CodexConfigRepairError(
            "Codex backup path is not a regular file: %s" % backup)
    if backup.exists():
        return backup
    staged = _stage_bytes(
        target.parent, ".%s.attacca-backup." % target.name, data, mode)
    try:
        try:
            os.link(str(staged), str(backup))
        except FileExistsError:
            pass
        _fsync_directory(target.parent)
    finally:
        try:
            staged.unlink()
        except OSError:
            pass
    return backup


def repair_codex_config(config_path, server_url=None, script_path=None,
                        canonical_block=None):
    """Repair one config and return paths/change/validation metadata."""
    target = Path(config_path).expanduser()
    if target.is_symlink():
        raise CodexConfigRepairError(
            "refusing to replace symlinked Codex config: %s" % target)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        original_bytes = target.read_bytes() if target.exists() else b""
        original = original_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise CodexConfigRepairError("cannot read %s: %s" % (target, error))
    if canonical_block is None:
        if script_path is None:
            script_path = (Path.home() / ".attacca" / "plugin" /
                           "attacca" / "attacca.py")
        canonical_block = canonical_connect_block(server_url, script_path)
    repaired = replace_attacca_tables(original, canonical_block)
    validation = validate_repaired_toml(repaired)
    repaired_bytes = repaired.encode("utf-8")
    changed = repaired_bytes != original_bytes
    backup = target.with_name(target.name + ".attacca-backup")
    if changed:
        mode = (target.stat().st_mode & 0o777) if target.exists() else 0o600
        if target.exists():
            backup = _create_backup_once(target, original_bytes, mode)
        staged = _stage_bytes(
            target.parent, ".%s.attacca-repair." % target.name,
            repaired_bytes, mode)
        try:
            os.replace(str(staged), str(target))
            os.chmod(str(target), mode)
            _fsync_directory(target.parent)
        finally:
            try:
                staged.unlink()
            except OSError:
                pass
    return {
        "ok": True,
        "config": str(target),
        "backup": str(backup) if backup.exists() else None,
        "changed": changed,
        "validator": validation["validator"],
    }


def build_parser():
    parser = argparse.ArgumentParser(
        description="Repair duplicate Attacca MCP tables in Codex config.toml")
    parser.add_argument("--config", required=True,
                        help="exact Codex config.toml path to repair")
    parser.add_argument("--server-url", required=True,
                        help="Attacca server base URL used by the connect shim")
    parser.add_argument(
        "--script-path", default=None,
        help="installed attacca.py path (default ~/.attacca/plugin/attacca/attacca.py)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        result = repair_codex_config(
            args.config, server_url=args.server_url,
            script_path=args.script_path)
    except CodexConfigRepairError as error:
        print("repair failed: %s" % error, file=sys.stderr)
        return 2
    state = "repaired" if result["changed"] else "already canonical"
    print("Codex Attacca config %s: %s" % (state, result["config"]))
    if result["backup"]:
        print("Original backup: %s" % result["backup"])
    print("Validated with: %s" % result["validator"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
