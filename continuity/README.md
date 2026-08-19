# Continuity — Local Project Continuity Layer

A local, zero-dependency implementation of the **Project Continuity Layer** from the
Multi-Agent Developer SaaS blueprint (Phase 0 "dogfood protocol", §31 steps 1–8):
the layer that makes AI sessions replaceable and projects resumable.

Point Claude Code, Codex, GLM-backed CLIs, any MCP client, and humans at the same
project, and they all share:

- **Append-only event ledger** — hash-chained, per-project sequence numbers (blueprint §9.1)
- **Project log** — curated, human-readable projection of meaningful events (§9.2)
- **Handoff** — current-state snapshot so a fresh worker resumes cold, no rebrief (§9.3)
- **Project Room** — structured human+AI messaging: chat, directive, claim, handoff,
  challenge, decision, approval (§7)
- **Tasks + work claims** — expiring leases, exactly-one-winner claiming, scope-overlap
  warnings, evidence-based reports (§8). Claims are enforced: only the claimant can
  report or release a task while its lease is active, finished tasks must be reopened
  explicitly before re-reporting, and giving a task back clears the claimant.
- **Decision records** — durable, out of chat history (§6.5, §9)
- **Drift Guard lite** — context versions; stale workers get warned before writing (§11.3)
- **Agent identities** — stable actor ids per tool/model, model-swappable (§5), tagged
  with their **owner**: setup asks who you are, every ledger event carries an `owner`
  key, and actor ids become `you.agent` (`jack.claude_director`) so two people's
  agents can never collide; agents auto-register with their runtime on first contact
- **Per-agent inboxes** — `check_inbox`: messages that mention or reply to you, with
  persistent read cursors that survive across sessions and tools
- **Lead Director** — per-project boss mode (§6.4) via `set_lead_director` / `lead`
- **Bridges** — link two projects' AI teams with a chosen relationship: **peers**,
  **master/subordinate** (the boss project's messages arrive `[MASTER-DIRECTIVE]`,
  the other side's arrive as `[SUGGESTION]`), or **advisor** (`[ADVICE]`); addressed
  and structured messages mirror across rooms and inboxes, chat stays local
- **Explore everything** — `search` across events/messages/tasks/decisions/handoffs,
  `overview` one-screen tour, `handoff history`, `event show`, plus per-thing
  list/show commands

**Deliberately not in this build:** encryption/key hierarchy (blueprint §17–19), the
Project Brain/context packs (§10–11), capability packs (§14). The protocol is designed so
those layer on later — the server-side of this file is what would become the encrypted
sync target.

## Architecture

**The app hosts the server; tools are API clients.** `continuity.py serve` runs the
continuity server — it owns the state and exposes two client surfaces:

- **MCP over HTTP** at `/mcp` (streamable HTTP transport) — what Claude Code, Codex,
  GLM-backed CLIs and other MCP clients connect to. Client identity comes from the
  `X-Continuity-Actor` header, project from `X-Continuity-Project`.
- **REST API** under `/v1/…` (blueprint §22.1 shape) — for curl, scripts, dashboards
  and anything that isn't an MCP client.

There is also a **stdio fallback** (`continuity.py mcp`) for tools that can't speak
HTTP MCP: the tool spawns a local shim against the same SQLite store. Honest note:
in this build the server is the *primary* writer, not the *sole* one — the CLI and
stdio shims write to the same WAL-mode SQLite database directly, which is what makes
the fallback and `room tail` work with no server running.

- **Language:** Python 3.8+ standard library only. Nothing to install
  (`requirements.txt` exists and is intentionally empty of dependencies).
- **One database, many projects.** Default `~/.continuity/continuity.db`
  (override: `CONTINUITY_DB`). Claims use single conditional UPDATEs, appends use
  `BEGIN IMMEDIATE` — safe under many concurrent clients (`tests/test_concurrency.py`).
- **Identity per tool.** Give each tool its own actor (`claude_director`,
  `codex_director`, `glm_worker`, …) via the header (server mode) or
  `CONTINUITY_ACTOR` env (stdio mode) so the room shows who is who.

## Quickstart

**The server is the app.** It runs standalone — its own directory, its own
lifecycle — and owns all state. Tools are pure clients; users never run
anything inside their projects.

**1. Host the server** (whoever runs the platform; once):

```bash
cd continuity && python3 continuity.py serve     # http://127.0.0.1:8722
# production-ish: nohup/systemd; --host/--port to taste
```

**2. Users install the Claude Code plugin from the server — one URL:**

```bash
curl -s http://127.0.0.1:8722/install.sh | sh
```

The server serves its own plugin (`/install.sh`, `/plugin.zip`): the download
comes **pre-wired to the server it came from**, and the script installs it
into Claude Code. Manual alternative:

```bash
claude plugin marketplace add /path/to/continuity
claude plugin install continuity@agentg --scope user
```

Open Claude Code in **any** project: the plugin connects to the server
(`CONTINUITY_URL`, default `http://127.0.0.1:8722`) and the server
**auto-registers the project on first contact** — zero per-project commands.
Convenience for local dev: if the URL is localhost and no server is up, the
plugin boots one in the background (`CONTINUITY_AUTOSTART=0` disables).
Plugin extras: `/continuity:status`, `/continuity:brief`, `/continuity:setup`;
tools appear as `mcp__plugin_continuity_continuity__<name>`.

**3. Other tools** — one command, run once, from anywhere:

```bash
python3 continuity.py setup
```

It auto-detects installed tools and points each at the server: Codex, Cursor,
Cline, Windsurf get **global** configs via the `connect` client (project
auto-detected per working directory — no per-project entries); Gemini CLI,
VS Code (Copilot agent), opencode and Claude-without-plugin get project-level
files; CLAUDE.md/AGENTS.md get the agent protocol block. One-time backups are
kept for every global config touched. GLM coding plans ride whichever
Claude/Codex-compatible CLI they run through. Works with **any MCP-speaking
tool** — for ones not auto-detected (Grok, Zed, …), `setup --details` prints
generic configs; anything else can use the REST API or CLI.

Setup variants: `-i/--interactive` (asks your identity, extra projects, tools,
and bridges + relationships), `--owner NAME` (who you are — tagged on every
log entry), `--here` (force this subfolder to be its own project; id comes
from the folder name — collisions need `init --project-id`), `--stdio`
(serverless mode: tools open the database directly), `--url http://host:port`,
`--skip-tools codex,cline` / `--skip-tools all`, `--no-server`,
`install-hooks` (git commits → ledger).

## How a tool connects (three shapes, one server)

| Shape | Who uses it | Project identity |
|---|---|---|
| `connect` stdio client | Claude plugin, Codex, Cursor, Cline, Windsurf | auto: working directory sent as `X-Continuity-Root`; server registers on first contact |
| HTTP MCP (`/mcp`) | Gemini, VS Code, opencode, anything with native HTTP MCP | `X-Continuity-Project` header |
| stdio direct (`mcp`) | serverless fallback (`setup --stdio`) | cwd walk-up against the local DB |

Keep the server running across reboots with anything you like, e.g.
`nohup python3 /abs/continuity.py serve >/tmp/continuity.log 2>&1 &` or a
systemd user unit. It binds `127.0.0.1` by default; `--host 0.0.0.0` exposes an
**unauthenticated** server (no encryption in this build) — only do that on a
trusted network.

## REST API (server mode)

```
GET  /healthz
GET  /v1/projects                          POST /v1/projects
GET  /v1/projects/{id}/handoff             POST /v1/projects/{id}/handoff
GET  /v1/projects/{id}/log?limit=          GET  /v1/projects/{id}/events?after=&limit=
POST /v1/projects/{id}/events              GET  /v1/projects/{id}/room?since_seq=&limit=
POST /v1/projects/{id}/room                GET  /v1/projects/{id}/tasks?status=
POST /v1/projects/{id}/tasks               GET  /v1/projects/{id}/tasks/{tid}
POST /v1/projects/{id}/tasks/{tid}/claim   POST /v1/projects/{id}/tasks/{tid}/report
POST /v1/projects/{id}/tasks/{tid}/release POST /v1/projects/{id}/tasks/{tid}/status
GET  /v1/projects/{id}/decisions           POST /v1/projects/{id}/decisions
POST /v1/projects/{id}/decisions/{did}/resolve
GET  /v1/projects/{id}/agents              POST /v1/projects/{id}/agents
GET  /v1/projects/{id}/freshness?context_version=
GET  /v1/projects/{id}/verify
```

Actor identity via `X-Continuity-Actor` / `X-Continuity-Actor-Type` headers.
Writes return the same payloads (and warnings) as the MCP tools.

## The protocol agents follow

Injected via the managed block and the MCP server's `instructions`:

1. **Session start** — `get_handoff` (returns handoff + open tasks + standing decisions +
   recent activity + `context_version`), then `room_read`. Register once with `agent_register`.
2. **Before working** — `task_claim` (or `task_create` then claim). Declare
   `expected_scope`; heed overlap warnings.
3. **While working** — coordinate via `room_send` / poll `room_read since_seq=…`
   (the cursor is lossless: a truncated batch sets `may_have_more` and the next poll
   picks up exactly where the last one ended); record durable choices with
   `decision_propose` / `decision_resolve`.
4. **Session end** — `task_report` with evidence, then `update_handoff` so the next
   worker (any tool, any model) resumes cold.
5. **Drift Guard** — responses carry `stale_context_warning` when the project moved
   after your briefing; re-run `get_handoff` before writing.

## MCP tools (25)

`continuity_status`, `get_handoff`, `update_handoff`, `get_project_log`,
`check_inbox`, `room_send`, `room_read`, `task_create`, `task_list`, `task_claim`,
`task_report`, `task_release`, `task_set_status`, `decision_propose`,
`decision_resolve`, `decision_list`, `set_lead_director`, `bridge_add`,
`bridge_list`, `search`, `agent_register`, `agent_list`, `list_projects`,
`append_event`, `check_freshness`.

In Claude Code they appear as `mcp__continuity__<name>`. Every tool takes an optional
`project` argument for cross-project work.

## CLI reference (same data, for humans and non-MCP tools)

```
continuity.py [--db PATH] [--project ID] [--actor ID] [--actor-type human|agent|system] [--json] COMMAND

init [PATH] [--project-id ID] [--name NAME] [--move]   register a project
                                               (--move re-points an existing id to a new root)
projects | status | log [-n N] | freshness [--context-version N]
handoff show | handoff set --objective ... --what-changed ... --next-actions ...
room send --type chat|directive|claim|handoff|challenge|decision|approval|status
          --body TEXT [--mentions a,b] [--task T-1] [--to OTHER_PROJECT]
room read [--since SEQ] [-n N] | room tail [--interval SECS]
task create TITLE [--scope a,b] [--depends-on T-1] [--risk low|medium|high]
task list [--status S] | task show T-1 | task claim T-1 [--scope a,b] [--lease MIN]
task report T-1 --summary TEXT [--evidence JSON] [--state review|done|blocked|queued]
task release T-1 [--reason TEXT] | task set-status T-1 STATUS [--reason TEXT]
decision propose TITLE [--detail TEXT] [--rationale TEXT]
decision resolve D-1 accepted|rejected|superseded | decision list
inbox [-n N] [--keep-unread]                    your mentions/replies, cursor persists
lead [ACTOR_ID] [--clear]                       show or set the Lead Director
bridge add OTHER [--boss P | --advisor P] | bridge remove OTHER | bridge list
search QUERY [-n N] | overview                  explore everything stored
handoff history [-n N] | event show SEQ         version and event detail
agent register [--id X] [--role R] [--runtime RT] | agent list
event append --type note.x --payload '{"k":"v"}' | event tail | event verify
serve [--host H] [--port P] [--verbose]        host the continuity server (REST + MCP/HTTP)
mcp                                            stdio MCP fallback (direct DB, no server)
setup [--url U] [--stdio] [--no-instructions]  one-shot project setup
setup --details [claude codex gemini opencode glm cli]   full config reference
install-instructions [--files CLAUDE.md,AGENTS.md] | install-hooks
```

## Demos and tests

```bash
./demo/demo_cold_handoff.sh        # blueprint north-star: fresh worker resumes cold
python3 demo/demo_two_agents_mcp.py  # two real MCP sessions coordinating via the ledger
python3 -m unittest discover -s tests -v   # 76 tests: storage, MCP (stdio+HTTP), REST, concurrency
python3 continuity.py event verify  # hash-chain + sequence integrity of a real ledger
```

## Notes and limits (honest edges)

- **No enforcement.** Prompt-level protocol only; hooks/permissions enforcement is a
  later layer (blueprint §12.3, §28 "policy bypass").
- **No encryption.** Everything is plaintext on your machine. The E2E key hierarchy
  (§17) is the next milestone and slots in at the sync boundary.
- **Leases are soft locks** for coordination, not Git locking. Use branches/worktrees
  as usual; `base_revision` is recorded at claim/report for later comparison.
- **Hash chain is tamper-*evident*, not tamper-*proof*** (no signatures yet — §23.3).
- **One actor id = one worker.** Two live sessions sharing a `CONTINUITY_ACTOR` also
  share task leases (a renewal warning is emitted). Give each concurrent session its
  own actor id.
- The room is a projection of `room.message` events in the ledger — chat is not the
  database (blueprint principle, §2.3).
