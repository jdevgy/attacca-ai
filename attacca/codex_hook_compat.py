#!/usr/bin/env python3
"""Preserve hook paths held by already-running Codex sessions.

Codex expands a plugin hook to a versioned cache path when a thread starts.
Updating the plugin may remove that cache directory while the old process is
still alive.  The universal installer snapshots those paths before invoking
Codex and restores any removed path as a symlink to Attacca's stable install.

The snapshot is also persisted outside the Codex cache.  That makes a later
installer run able to repair paths after a prior install was interrupted
between cache removal and restoration.
"""

import argparse
import json
import os
import re
import secrets
import shutil
import tempfile
from pathlib import Path


STATE_VERSION = 1
_CACHE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,159}$")


def _version(value):
    value = str(value or "")
    if not _CACHE_VERSION.fullmatch(value):
        raise ValueError("unsafe Codex plugin cache version %r" % value)
    return value


def _load_state(path):
    path = Path(path)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as err:
        raise RuntimeError("invalid Codex hook compatibility state: %s" % err)
    if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
        raise RuntimeError("unsupported Codex hook compatibility state")
    versions = data.get("cache_versions")
    if not isinstance(versions, list):
        raise RuntimeError("Codex hook compatibility state has no version list")
    return [_version(item) for item in versions]


def _save_state(path, versions):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": STATE_VERSION,
               "cache_versions": sorted(set(versions))}
    fd, temporary = tempfile.mkstemp(
        prefix=".%s." % path.name, dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def snapshot_codex_cache(cache_root, state_path):
    """Persist the newest pre-upgrade cache generation as one rollback."""
    cache_root = Path(cache_root)
    candidates = []
    if cache_root.is_dir():
        for child in cache_root.iterdir():
            try:
                version = _version(child.name)
            except ValueError:
                continue
            # Directories and directory symlinks are both valid retained
            # plugin paths. Files and broken symlinks are never recorded.
            if child.is_dir():
                candidates.append((child.stat().st_mtime_ns, version))
    if candidates:
        ordered = [max(candidates)[1]]
    else:
        prior = _load_state(state_path)
        ordered = prior[-1:]  # interrupted update: retain one known rollback
    _save_state(state_path, ordered)
    return ordered


def prune_attacca_cache(cache_root, active_version=None, rollback_count=1):
    """Prune only verified Attacca generations, retaining active + rollback.

    Unknown files and cache entries without Attacca's runtime and manifest are
    never removed.  Claude's ``.in_use`` generations are active, not rollback
    copies, and therefore remain until Claude releases them.
    """
    cache_root = Path(cache_root)
    if not cache_root.is_dir():
        return {"removed": [], "kept": [], "skipped": []}
    owned, skipped = [], []
    for child in cache_root.iterdir():
        try:
            version = _version(child.name)
        except ValueError:
            skipped.append(child.name)
            continue
        resolved = child.resolve() if child.is_symlink() else child
        manifests = (resolved / ".codex-plugin" / "plugin.json",
                     resolved / ".claude-plugin" / "plugin.json")
        if not (resolved.is_dir() and (resolved / "attacca.py").is_file()
                and any(item.is_file() for item in manifests)):
            skipped.append(version)
            continue
        owned.append((child.stat().st_mtime_ns, version, child))
    protected = {str(active_version)} if active_version else set()
    protected.update(version for _, version, child in owned
                     if (child / ".in_use").exists())
    rollback = sorted(
        (item for item in owned if item[1] not in protected), reverse=True)
    protected.update(item[1] for item in rollback[:max(0, rollback_count)])
    removed, kept = [], []
    for _, version, child in owned:
        if version in protected:
            kept.append(version)
            continue
        if child.is_symlink():
            child.unlink()
        else:
            shutil.rmtree(child)
        removed.append(version)
    return {"removed": sorted(removed), "kept": sorted(kept),
            "skipped": sorted(skipped)}


def restore_codex_cache(cache_root, stable_root, versions):
    """Restore missing cache paths atomically, without replacing real data."""
    cache_root = Path(cache_root)
    stable_root = Path(stable_root).resolve()
    hook = stable_root / "hooks" / "session_start.py"
    if not hook.is_file():
        raise RuntimeError("stable Attacca hook is missing: %s" % hook)
    cache_root.mkdir(parents=True, exist_ok=True)
    repaired, present = [], []
    for raw_version in versions:
        version = _version(raw_version)
        target = cache_root / version
        if os.path.lexists(target):
            if target.is_dir() and (target / "hooks" / "session_start.py").is_file():
                present.append(version)
                continue
            raise RuntimeError(
                "refusing to replace invalid existing cache path: %s" % target)
        temporary = cache_root / (
            ".%s.attacca-link-%d-%s" %
            (version, os.getpid(), secrets.token_hex(4)))
        try:
            os.symlink(str(stable_root), str(temporary),
                       target_is_directory=True)
            os.replace(str(temporary), str(target))
        finally:
            if os.path.lexists(temporary):
                os.unlink(temporary)
        repaired.append(version)
    return {"repaired": repaired, "present": present}


def _parser():
    parser = argparse.ArgumentParser(
        description="Preserve hook paths across Codex plugin upgrades")
    sub = parser.add_subparsers(dest="command", required=True)
    snapshot = sub.add_parser("snapshot")
    snapshot.add_argument("--cache-root", required=True)
    snapshot.add_argument("--state", required=True)
    restore = sub.add_parser("restore")
    restore.add_argument("--cache-root", required=True)
    restore.add_argument("--stable-root", required=True)
    restore.add_argument("--versions-json", required=True)
    prune = sub.add_parser("prune")
    prune.add_argument("--cache-root", required=True)
    prune.add_argument("--active-version")
    prune.add_argument("--rollback-count", type=int, default=1)
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    if args.command == "snapshot":
        print(json.dumps(snapshot_codex_cache(
            args.cache_root, args.state), separators=(",", ":")))
        return 0
    if args.command == "prune":
        print(json.dumps(prune_attacca_cache(
            args.cache_root, args.active_version, args.rollback_count),
            separators=(",", ":")))
        return 0
    try:
        versions = json.loads(args.versions_json)
    except Exception as err:
        raise SystemExit("invalid --versions-json: %s" % err)
    if not isinstance(versions, list):
        raise SystemExit("--versions-json must be an array")
    result = restore_codex_cache(
        args.cache_root, args.stable_root, versions)
    for version in result["repaired"]:
        print("codex: preserved live hook compatibility for %s" % version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
