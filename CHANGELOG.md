# Changelog

All notable changes to Attacca are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Attacca is a pre-production prototype: the `0.x` series makes no semantic
versioning promise, and only the latest `0.5.x` receives fixes.

Entries below are reconstructed from the Git history. Releases are marked in
history by a `Release x.y.z` commit that also bumps `VERSION` in `attacca.py`;
where a release has no such commit that is noted on the entry. There are no
Git tags in this repository, so versions are dated by their bump commit.

## [Unreleased]

### Added

- `CONTRIBUTING.md`: local server workflow, the test command, the
  standard-library-only constraint, the frozen-snapshot restart rule, the
  installer working-directory rule, and documentation orientation.
- `CHANGELOG.md` (this file).
- `SECURITY.md`: reporting process, supported versions, and the prototype
  known-limits list.
- `.github/workflows/ci.yml`: GitHub Actions running the unit suite on
  Python 3.8, 3.10, and 3.12.

### Fixed

- `tests/test_codex_config_repair.py`, `tests/test_server_switch.py`, and
  `tests/test_codex_toml_concurrency_regression.py` imported `tomllib`
  (Python 3.11+) at top level, so they failed to import on 3.8/3.10. The
  import is now guarded, so the modules import on 3.8/3.10 and the tests that
  need `tomllib` are skipped there.

### Pending

- No `LICENSE` file yet. One must be chosen before publication.

## [0.5.8] - 2026-09-06

### Removed

- Retired the per-minute managed inbox cron (D-29). `SessionStart` no longer
  offers to create it, and a surviving legacy job is retired once.

## [0.5.7] - 2026-09-03

### Changed

- The lifecycle hook renders the reconnect outage summary, the unjournaled-write
  count, and the stale-mirror refusal **once per state** rather than repeating
  them every turn (T-84 A9 / T-85 E).

## [0.5.6] - 2026-09-03

### Changed

- Live-receipt retention: receipts are tombstoned, never deleted (T-88, D-28).
- Apply and receipt are written atomically, with recovery for stranded
  reservations.

### Added

- A last-resort ambiguous trace for writes whose outcome cannot be proven.

### Fixed

- Sync test module-order dependency.

## [0.5.5] - 2026-09-03

### Added

- Proven-failure queueing and ambiguous-write reconciliation (T-85, D-27): a
  proven connection refusal may queue; an ambiguous timeout must not create a
  duplicate side effect.
- Export carries `message_disposition_baselines`, and the `cloud_context`
  record is validated on export (T-87).

### Changed

- Compact default read projections (T-86, T-84 B2/B3).

## [0.5.4] - 2026-09-03

### Added

- The session brief renders both the shared project handoff and the caller's
  own identity handoff (T-75).
- Historical disposition reconciliation (T-80, D-26): implicit resolution
  rules, a per-identity upgrade baseline, and bounded bulk disposition.

## [0.5.3] - 2026-09-03

### Added

- Split handoffs: one shared project handoff plus a per-identity handoff owned
  by each registered actor, with independent optimistic versions
  (T-81/T-83/T-75).
- Persona repair and guided setup for duplicate or legacy identities.
- Hook injection contract (T-82/T-84, D-23/D-24): auth gate, show-once render
  ledger, silent `Stop`, show-once count lines, no self-echo, coalesced entity
  updates, outage reported once, pulse-as-ping with back-off, compact rules
  banner, and compaction parity.

### Changed

- Managed law bumped to v15.

### Fixed

- `SessionStart` hook matcher includes `fork`, so forked Claude sessions get
  the brief.
- Identity allocation and selection defaults.
- Legacy rule startup compatibility preserved.

## [0.5.2] - 2026-08-31

Version bumped inside the "Ship named identities and complete continuity
paging" commit; there is no separate `Release 0.5.2` commit in history.

### Added

- Named AI identities bound per client installation, with a persona handoff
  model (`workspace.role.runtime.persona`).
- Paged panel feeds, with Control Panel pagination wired to hosted collection
  queries.
- Sortable project log panel.
- Hot-reload of hosted MCP credentials and endpoint.
- A warning on cross-project sends with no addressee.

### Changed

- Repository re-rooted at the `attacca` package.
- README rewritten; SVG architecture diagram added.

### Fixed

- Client authorization bootstrap.
- Pairing acknowledgement retries, with the failure surfaced in the panel.
- Hardened client credential delivery acknowledgement.

## [0.5.1] - 2026-08-27

### Added

- `--version` flag.
- Browser-authorized client key pairing, replacing manual key onboarding:
  one-click authorization with an explicit browser review step.
- Permanent deletion for revoked client keys.

### Changed

- Human login and account identity unified into one account name in the
  Control Panel.
- Client pairing codes hardened to 256 bits, with all pairing decisions
  throttled and the expiring legacy code alphabet matched for compatibility.
- Obsolete plugin cache generations pruned; stale watcher subscriptions
  deduplicated; watcher mirror refresh made signal-driven.

### Fixed

- Auth-link surfacing, and an offline Stop-banner leak.
- Pairing link mismatch: the client now accepts the server's
  `#settings&authorization_request=` URL.
- Browser pairing authorization route, and pairing approval now auto-polls to
  completion instead of reporting "no authorizations".
- The `Stop` hook no longer dumps the rules banner as a blocking reason.
- Installer manifest closed after cache cleanup.

## [0.5.0] - 2026-08-26

First release under the Attacca name (renamed from `continuity`), covering the
hosted continuity layer end to end.

### Added

- Hosted server (`attacca.py serve`): streamable HTTP MCP at `/mcp`, REST
  under `/v1`, the Control Panel at `/app`, and self-hosted installer and
  plugin distribution.
- Per-project append-only hash-chained event ledger, human-readable project
  log, versioned handoff, room and inbox, task board with claims and evidence,
  decision records, role-scoped Project Rules, and Cloud Context.
- Cloud Context synced into `AGENTS.md`/`CLAUDE.md` as a managed block, and
  synced state rendered as local Markdown files.
- Managed-law content served from the server rather than baked into the
  binary, with downgrade offers rejected, law ordering fail-closed, and
  release metadata validated.
- Offline sync projections with forward-compatible negotiation, plus sync
  initialization and push capability binding.
- D-17 client install keys replacing terminal enrollment, with security
  regression coverage and client auth/workflow integrity enforcement.
- Rooms as true group conversations, and autonomous inbox delivery.
- `/v1/projects/{id}/poll-status` returning per-request update and new-mail
  flags.
- Handoff-history REST endpoint and Control Panel section.
- Project-migration option in setup, and an AI-role dropdown in the panel.

### Changed

- Renamed from `continuity` to Attacca, with a universal one-line install.
- Mandatory rules pinned every turn.
- Hooks detached from stale plugin caches and kept out of auth flows.
- Codex TOML rewrites serialized across clients; watcher state kept private and
  abandoned subscriptions pruned safely.
- `docs/LOG.md` archived to `docs/LOG.archive.md` — Attacca itself is now the
  project's source of truth.
