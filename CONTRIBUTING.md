# Contributing to Attacca

Attacca is a hosted project-continuity layer for humans and AI coding tools.
This file covers what you need to build, run, and test it locally.

Attacca is a **pre-production dogfood/prototype**. Please read
[`SECURITY.md`](SECURITY.md) before running a server anywhere other people can
reach, and do not describe prototype behaviour as production-ready.

## Ground rules

### Standard library only

Attacca targets **Python 3.8+ and uses the standard library exclusively**.
There are no third-party runtime dependencies and there is no build step:
`attacca.py` is run directly.

`requirements.txt` exists as conventional scaffolding and deliberately lists
nothing — `pip install -r requirements.txt` is a successful no-op. **Do not add
a runtime dependency.** If you find yourself wanting one, that is a design
discussion (an Attacca decision record), not a patch.

The floor is real: 3.8 is the oldest interpreter CI runs, so avoid syntax and
stdlib APIs newer than 3.8 (no `match`, no `X | Y` type unions at runtime, no
`str.removeprefix`, no `functools.cache`, no `zoneinfo` without a fallback).
You can check a file's syntax against the floor without installing 3.8:

```bash
python3 -c "import ast; ast.parse(open('attacca.py').read(), feature_version=(3,8))"
```

That catches post-3.8 *syntax* only. Post-3.8 *stdlib APIs* are caught by the
3.8 leg of CI.

### Repository layout

The Git repository root **is** the `attacca` package directory — `attacca.py`,
`tests/`, and `.github/` all sit at the top level of the checkout. There is no
extra `attacca/` subdirectory inside the repo.

## Running the server locally

The server is the app: it owns all state and exposes MCP, REST, and the
Control Panel from one process.

```bash
python3 attacca.py serve                       # http://127.0.0.1:8722
```

Useful flags (`python3 attacca.py serve --help` for the full list):

| Flag | Meaning |
| --- | --- |
| `--host` | Bind address, default `127.0.0.1`. |
| `--port` | Port, default `8722`. |
| `--verbose` | Request logging. |
| `--auth` | Request authentication *readiness*; never enforces on its own. |

Surfaces on a running server:

- `/mcp` — streamable HTTP MCP endpoint
- `/v1/...` — REST resources
- `/app` — the Control Panel (workspaces, activity, rooms, tasks, decisions,
  agents, rules, Cloud Context, settings, export)
- `/install.sh`, `/plugin.zip` — the self-hosted installer and plugin bundle

### Keep your dev server off shared state

- Point the development server at a **scratch database**:
  `ATTACCA_DB=/tmp/attacca-dev.db python3 attacca.py serve --port 8799`.
- Use a **port other than the default** if a shared or dogfood instance is
  already running on this machine, and never point development work, tests, or
  a migration at a shared instance.
- Stay on loopback. `--host 0.0.0.0` publishes an unencrypted, unthrottled
  admin surface — see `SECURITY.md`.
- Never commit a database. `.gitignore` already excludes `*.db`, `*.db-wal`,
  `*.db-shm`, `server.log`, and `.attacca/` (except the non-secret
  `project.json`).

### A running server serves a frozen snapshot

This trips people up constantly, so it is worth stating plainly:

> **When the server starts, it captures an immutable distribution snapshot** —
> its landing page, Control Panel assets, installer, plugin archive, version
> string, and managed-law bundle. Editing the source files on disk does **not**
> mutate what a running server hands out.

Consequences:

1. After changing anything a client downloads (installer, plugin, panel assets,
   managed law, version), you must **restart the server** before it serves the
   new bytes.
2. `git log` showing a change is not evidence that a running server, a packaged
   plugin, or an *installed* plugin has it. Those are four distinct artifacts.
   Release evidence must say which one was tested.
3. A running coding client may additionally need a fresh session to load newly
   installed plugin code. That is a client lifecycle fact, not a bug.
4. Never interrupt a live shared server just to run tests — the test suite
   never needs one (see below).

## Running the tests

```bash
python3 -m unittest $(cd tests && ls test_*.py | sed 's/\.py$//; s/^/tests./')
```

Run it from the repository root. It expands to the explicit module list
`tests.test_auth_http tests.test_auth_onboarding ...` and is the form CI uses.

### Why not plain discovery

`tests/` has no `__init__.py`, and Python 3.11+ no longer discovers namespace
packages. So:

```bash
python3 -m unittest discover          # Ran 0 tests — exits 5, NO TESTS RAN
python3 -m unittest discover -s tests -t .   # ImportError: Start directory is not importable
```

The first form is the dangerous one: it **silently runs nothing and does not
fail loudly**, so it can look like a green run. Do not use it.

`python3 -m unittest discover -s tests` does execute tests, but it imports each
module top-level (as `test_http`) while a handful of modules import their
siblings as package members (`from tests.test_http import ServerFixture`).
That loads the same module twice under two names. Use the explicit form.

### Keep the suite importable on 3.8

The runtime floor applies to `tests/` too: every test module must **import**
cleanly on Python 3.8. `unittest` substitutes a placeholder failing test for a
module it cannot import, so the rest of the run still completes -- but that
module reports an error and the run exits non-zero.

If a test needs a newer stdlib module, guard the import and skip the affected
tests rather than importing it at top level. `tomllib` (3.11+) is the existing
example -- `tests/test_codex_config_repair.py`,
`tests/test_server_switch.py`, and
`tests/test_codex_toml_concurrency_regression.py` all do:

```python
try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None

...

@unittest.skipUnless(tomllib is not None, "tomllib requires Python 3.11+")
def test_something_that_parses_toml(self):
```

Skip the tests that need the feature *indirectly* too. `validate_repaired_toml`
in `tools/repair_codex_config.py` falls back to a structural check when
`tomllib` is absent and raises a different error message, so a test asserting
the `tomllib`-branch message needs the same guard even though it never names
`tomllib`.

### Running a subset

Individual modules take the same package path:

```bash
python3 -m unittest tests.test_store tests.test_http -v
python3 -m unittest tests.test_mcp.McpTestCase.test_some_case
```

### What the tests may and may not touch

Tests must use **temporary databases, temporary homes and configurations, and
ephemeral loopback ports**. They must never restart, reconfigure, authenticate,
migrate, or write to a configured shared server, and they must not write to a
real `~/.attacca`. If you add a test that needs a server, use the existing
`ServerFixture` in `tests/test_http.py` rather than starting one by hand.

Beyond the baseline suite, risk-specific coverage lives in dedicated modules:
concurrent writers and claimants, MCP and HTTP contracts, Control Panel
behaviour, native client configuration, hook lifecycle and cache replacement,
managed-law monotonicity, bridge participation and routing, search and
pagination, task-plan optimistic revisions, export integrity, watcher cadence,
offline corruption/revocation/ambiguity, exact-once replay, and authentication
red-team cases. `demo/` contains the cold-handoff and two-agent MCP acceptance
demonstrations.

## Installing the plugin (the cwd rule)

The installer is served by a running server and wires every AI coding tool it
finds on the machine:

```bash
curl -fsSL http://127.0.0.1:8722/install.sh | sh
```

> **Run the installer from a directory outside this checkout.**

The installer inspects its working directory to decide what to configure. Run
it from inside the Attacca source checkout and it will treat the development
tree as a user project — rewriting local MCP configuration and plugin
registrations against your working copy. `cd ~` (or any unrelated directory)
first.

Two more installer facts:

- Run it **inside the same host or container where the coding tool actually
  runs**. Server URL, client installation, and credentials are machine-local; a
  machine-specific MCP configuration cannot be generated remotely.
- It is deliberately **rerunnable and idempotent**. It refreshes one managed
  registration rather than stacking a second active Attacca server, and
  preserves unrelated configuration. Rerun it only to add a client, switch
  servers, or repair an installation.

## The Attacca protocol (this project uses itself)

Attacca is developed *through* Attacca. `AGENTS.md` and `CLAUDE.md` in this
repository each carry two marker-bounded managed blocks:

- **`MANAGED_ATTACCA`** — the versioned protocol/"managed law" block.
- **`ATTACCA_CLOUD_CONTEXT`** — a synchronized read-only copy of the hosted
  Cloud Context record.

**Never hand-edit inside either marker pair.** Both are machine-owned:
lifecycle sync rewrites them atomically when the hosted version or hash
changes, so local edits are lost and can trip the monotonicity checks. To
change Cloud Context, edit the hosted record (`cloud_context_get` /
`cloud_context_set`) — humans and registered Directors only. Content **outside**
both marker regions is human-authored and is preserved.

If you are an AI worker on this repository, follow the protocol in the managed
block: load the session brief, rules, and Cloud Context; search Attacca history
before filesystem archaeology; claim a task with declared path scope before
substantive edits; coordinate scope overlap in the room; record durable choices
as decisions; and report task evidence at the end. The hosted project — not a
chat transcript — is the source of truth.

Human contributors do not need an Attacca account to send a patch.

## Commits and pull requests

- **Small, focused commits on `main`.** This is a fast-moving prototype with a
  short history; keep each commit to one coherent change with a subject line
  that says what changed. The existing log is the style guide — release commits
  read `Release 0.5.8: <summary>`, work commits often reference the task or
  decision they close (`T-88: ...`, `D-29: ...`).
- **Tests green before you commit.** Run the full suite above. If a change is
  risk-specific (concurrency, auth, hooks, sync, export), run and mention the
  matching module.
- **Don't rewrite published history**, and don't force-push `main`.
- **Preserve other people's work.** Do not revert, stash, or commit unrelated
  dirty files you find in the tree — another agent or human may have them
  claimed.
- **Update `README.md` when shipped behaviour changes**, and add a
  `CHANGELOG.md` entry under `## [Unreleased]`.
- **Never commit a secret.** Ledger events, room messages, tasks, decisions,
  rules, Cloud Context, `AGENTS.md`/`CLAUDE.md`, `.attacca/project.json`,
  command arguments, logs, plugin archives, and exports are all copied, synced,
  and exported verbatim.

## Where the documentation lives

| File | What it is |
| --- | --- |
| [`README.md`](README.md) | **The maintained user and developer guide.** Current architecture and usage. Start here, and keep it true when shipped behaviour changes. |
| [`SECURITY.md`](SECURITY.md) | Reporting process, prototype status, and the known-limits list. |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history, Keep a Changelog format. |
| `AGENTS.md` / `CLAUDE.md` | Managed protocol block plus the synced Cloud Context copy. Machine-owned inside the markers. |
| `docs/LOG.archive.md` | **Historical only.** The archived build narrative from before Attacca became its own source of truth. Evidence of what happened, not a description of current behaviour. |
| `docs/blueprint.txt` | **Vision, not implemented.** The broader SaaS direction — end-to-end encryption, Project Brain, capability marketplaces, billing, production identity. Nothing here is implemented merely because the blueprint describes it. Do not cite it as shipped behaviour. |

When these disagree, current source and tests are the implementation truth.

## Licence

This repository does not yet carry a `LICENSE` file. One still has to be chosen
before publication; until then, no open-source licence grant is in effect.
