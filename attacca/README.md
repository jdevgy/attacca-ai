# Attacca — Local Project Continuity Layer

A local, zero-dependency implementation of the **Project Continuity Layer** from the
Multi-Agent Developer SaaS blueprint (Phase 0 "dogfood protocol", §31 steps 1–8):
the layer that makes AI sessions replaceable and projects resumable.

Point Claude Code, Kimi Code, Codex, Cline, GLM-backed CLIs, any MCP client, and
humans at the same project, and they all share:

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
- **Agent identities** — operational actor ids are
  `workspace.role.runtime` (for example `analytics-engine.director.codex`).
  The human **owner** is a separate event/agent field, never an actor prefix.
  Runtime remains visible for audit, but authorization depends only on the
  registered workspace role: Claude and Codex Directors are permission peers.
  Legacy owner-prefixed ids are aliased without rewriting hashed ledger history.
- **Per-agent inbox cursors** — `check_inbox` delivers every visible non-self
  room message, with a persistent cursor per canonical actor. Mentions and
  replies assign attention/expected response without hiding shared context;
  untargeted chat and directives are everyone-broadcasts. Bridge participation
  and access policy are the cross-workspace visibility boundary.
- **AI roles + Lead Director** — setup assigns Director, Advisor, or Worker;
  only Directors can update a governed workspace's shared handoff or issue a
  binding directive from a master workspace. Multiple Directors are allowed,
  the Lead Director breaks ties, and optimistic context-version checks reject
  stale handoff overwrites instead of silently replacing another Director.
- **Bridges** — link two projects' AI teams with a chosen relationship: **peers**,
  **master/subordinate** (the boss project's messages arrive `[MASTER-DIRECTIVE]`,
  the other side's arrive as `[SUGGESTION]`), or **advisor** (`[ADVICE]`). Messages
  remain local unless `target_project` names one connected workspace, retaining
  a labeled copy in both rooms. Routine local work never fans out implicitly;
  cross-project content must match the bridge's human-defined purpose.
- **Explore everything** — `search` across events/messages/tasks/decisions/handoffs,
  `overview` one-screen tour, `handoff history`, `event show`, plus per-thing
  list/show commands

**Deliberately not in this build:** encryption/key hierarchy (blueprint §17–19), the
Project Brain/context packs (§10–11), capability packs (§14). The protocol is designed so
those layer on later — the server-side of this file is what would become the encrypted
sync target.

## Architecture

**The app hosts the server; tools are API clients.** `attacca.py serve` runs the
attacca server — it owns the state and exposes two client surfaces:

- **MCP over HTTP** at `/mcp` (streamable HTTP transport) — what Claude Code, Kimi
  Code, Codex, GLM-backed CLIs and other MCP clients connect to. Client identity
  comes from the `X-Attacca-Actor` header, project from `X-Attacca-Project`.
- **REST API** under `/v1/…` (blueprint §22.1 shape) — for curl, scripts, dashboards
  and anything that isn't an MCP client.

The installed **`connect` stdio client** normally forwards MCP to the configured
host. If that transport is unavailable, it can continue only from the exact
schema-v1 mirror previously authenticated for this server, workspace, human
principal, canonical AI role, checkout, and device. Cached reads are marked
offline/stale; allowlisted writes are fsynced to a device outbox and replayed
idempotently after reconnect. Missing, ambiguous, forged, or role-changed mirrors
fail closed.

`attacca.py mcp` is a separate, explicitly selected serverless/direct-database
mode for local development (`setup --stdio`). It is not the installed plugins'
automatic hosted fallback, and neither a local database nor the administrative
full export can substitute for the verified identity-scoped mirror.

- **Language:** Python 3.8+ standard library only. Nothing to install
  (`requirements.txt` exists and is intentionally empty of dependencies).
- **One database, many projects.** Default `~/.attacca/attacca.db`
  (override: `ATTACCA_DB`). Claims use single conditional UPDATEs, appends use
  `BEGIN IMMEDIATE` — safe under many concurrent clients (`tests/test_concurrency.py`).
- **Identity per workspace role + AI.** Clients send a runtime hint (`claude`,
  `codex`, `kimi`, …); after setup the server resolves it to
  `workspace.role.runtime`. Owner is transmitted and stored separately.

## Quickstart

**The server is the app.** It runs standalone — its own directory, its own
lifecycle — and owns all state. Tools are pure clients; no Attacca server or
database is installed inside a user's project.

**1. Host the server** (whoever runs the platform; once):

```bash
cd attacca && python3 attacca.py serve     # http://127.0.0.1:8722
# bootstrap the owner, create per-install client keys, and enable auth in /app Settings
# remote prototype: --host 0.0.0.0 (put TLS in front of it)
```

**2. Users install the plugin from the server — one line, every tool:**

```bash
curl -fsSL http://127.0.0.1:8722/install.sh | sh
```

The server serves its own plugin (`/install.sh`, `/plugin.zip`): the download
comes **pre-wired to the server it came from**, and the script wires **every AI
coding tool it finds on the machine** — Claude Code, Codex CLI, and Kimi Code
get their native plugins, while Codex / Cline / Cursor / Windsurf get global
MCP configuration. Codex keeps the global entry too because Codex surfaces
without plugin support still read it; Kimi's old global Attacca entry is removed
when its native plugin is installed so only one server is active. An unlinked
directory is untouched. In
an already-linked checkout, a reinstall may remove only Attacca's obsolete
project-level `.mcp.json` entry so Claude does not load it alongside the native
plugin; unrelated MCP entries are preserved. Run the installer inside the same
host/container where the coding tool runs; after configuring Codex it verifies
the effective server with
`codex mcp get attacca` instead of merely claiming success.

The installer is deliberately rerunnable. It refreshes the native plugin and
one managed MCP entry instead of stacking active copies, and it configures a
newly installed client that was absent on the previous run. Claude user/project/
local registrations in the current checkout are normalized to one user plugin;
old `.orphaned_at` cache directories are inactive retention, not registrations.

Prefer a native in-tool install? The same zip carries Claude, Kimi, and Codex
plugin manifests:

- **Claude Code:** after the one-liner adds the local marketplace, run
  `/plugin install attacca@agentg` if needed
- **Kimi Code:** `/plugins install http://127.0.0.1:8722/plugin.zip`
- **Codex CLI:** the one-liner installs `attacca@attacca-local`; open
  `/plugins` in a new session, or run
  `codex plugin add attacca@attacca-local` again to refresh it.

`plugin.zip` contains the zero-dependency `attacca.py` runtime, the Claude /
Codex / Kimi manifests and MCP launch configs, setup/message/update commands
and skills, lifecycle-hook code, this README, and the web-panel asset. It does
not contain the server database, a checkout's `.attacca/project.json`, user
identity, credentials, or project history.

Start a new Codex, Claude, or native-plugin Kimi session in a project. Codex and
Claude use their trusted SessionStart hooks; Kimi injects the equivalent startup
bootstrap from its plugin manifest. Each checks whether the checkout is linked
and offers setup once when it is not. Accepting invokes `$attacca:setup` in
Codex or `/attacca:setup` in Claude/Kimi. All three use the same flow. It connects
to the packaged server (`ATTACCA_URL`, default
`http://127.0.0.1:8722`), detects the canonical Git remote, and checks it
against existing Attacca workspaces. A match is shown for confirmation;
otherwise setup lists every workspace plus **Create new**. It never silently
creates or attaches a workspace from local path/Git identity. The confirmed
non-secret id is stored in `.attacca/project.json`.
That is the portable workspace link and is safe to commit so another clone
selects the same workspace. A checkout `.mcp.json`, when needed by a client
without the native plugin, contains a machine/site-specific server endpoint;
regenerate it on each machine rather than using it as workspace identity.
The same guided run then configures every detected tool, verifies MCP and the
lifecycle hooks, asks this AI's workspace role (first-run default: Director +
Lead Director), shows existing relationship/inbox evidence, asks how to connect
another workspace (default: MASTER, with the direction stated explicitly), and
finally inspects the current AI conversation for pending/deferred work. It
compares candidates with the task board and asks once before creating anything;
setup never silently imports or claims a task.
Convenience for local dev: if the URL is localhost and no server is up, the
plugin boots one in the background (`ATTACCA_AUTOSTART=0` disables).
Claude and Kimi expose `/attacca:brief`, `/attacca:inbox`, `/attacca:room`,
`/attacca:tasks`, `/attacca:status`, `/attacca:setup`, `/attacca:msg`, and
`/attacca:update`. Codex exposes the three packaged skills `$attacca:setup`,
`$attacca:msg`, and `$attacca:update`; status, handoff, inbox, room, and tasks
remain available through natural requests and the Attacca MCP tools. MCP tools
appear as `mcp__plugin_attacca_attacca__<name>`.

**3. Per-project setup / anything else** — one complete command, run once, from
the project:

```bash
attacca setup
```

It auto-detects installed tools and points each at the server: Codex, Cursor,
Cline, Windsurf and Kimi Code get **global** configs via the `connect` client
(project auto-detected per working directory — no per-project entries); Gemini
CLI, VS Code (Copilot agent), opencode and Claude-without-plugin get
project-level files; CLAUDE.md/AGENTS.md get the agent protocol block. One-time
backups are kept for every global config touched. GLM coding plans ride
whichever Claude/Codex-compatible CLI they run through. Works with **any
MCP-speaking tool** — for ones not auto-detected (Grok, Zed, …),
`setup --details` prints generic configs; anything else can use the REST API
or CLI.

When Claude's native Attacca plugin is installed, setup removes only Attacca's
checkout `.mcp.json` entry (preserving unrelated MCP servers/settings), because
the native plugin already contributes that MCP connection. This prevents the
same Attacca tools appearing twice.

Setup variants: `-i/--interactive` (detects Git, asks for confirmation, and
lists existing/create-new choices), `--owner NAME` (who you are — shown as
`(OWNER: name)` on every log line), `--here` (force this subfolder to be its
own project), `--attach ID`, `--create NAME`, `--discover`, `--stdio`
(serverless mode: tools open the database
directly), `--url http://host:port`, `--tools-only` (global tool configs only,
no project side effects — what install.sh uses),
`--skip-tools codex,cline` / `--skip-tools all`, and `--no-server`.

## Hosted authentication (prototype)

The Control Panel at `/app` is the first-run entry point. Before it loads
workspace data, it checks public authentication status and asks for the first
owner account when needed. Bootstrap establishes that human account but does
**not** enable enforcement. The owner enables or disables enforcement with the
single explicit toggle in Settings; the toggle sends `{enabled, confirmed:true}`.
There is no separate readiness workflow or automatic activation side effect.

Attacca supports exactly two advertised authentication forms:

- A browser uses an expiring `HttpOnly`, `SameSite=Strict` session cookie and a
  separate CSRF token for every state-changing request. Signing out in Settings
  revokes the session.
- Each installed Attacca client keeps its own human-owned API key with prefix
  `atkey_`. The key identifies that concrete installation through its required
  stable `client_instance`; it does not identify or bind an AI model, runtime,
  actor, role, or Git checkout.

Settings creates, lists, and revokes client-install keys through
`/v1/auth/client-keys`. Creation may restrict the key to selected workspace
memberships; leaving the selection empty follows the authenticated human's
current memberships. The plaintext key appears once, is kept only in page
memory, and is never returned by list responses. Stored records contain only a
hash, prefix, human owner, client installation, scope, timestamps, and status.
Revoking one installation does not revoke another installation or rewrite any
AI identity or audit history.

Every authenticated AI request still supplies the exact
`X-Attacca-Project: <workspace>` and
`X-Attacca-Actor: <workspace>.<role>.<runtime>` headers. The server validates
the key's workspace scope, the human's workspace membership, and that the
registered actor belongs to that authenticated human; authorization then comes
from the actor's registered role. Ledger writes therefore record the canonical
AI actor and `Run by user` separately. A Codex client key is not a Codex actor
key: the same installed client can select any valid actor owned by that human.

When a protected server needs authorization, the native setup/update skill or
lifecycle hook starts the packaged helper inside the active AI terminal. The
helper generates or loads that installation's stable non-secret client ID and
opens the browser directly on Settings with only the client ID and label in the
URL fragment. The signed-in human creates the key there; if a manual transfer is
needed, the helper accepts it only through a hidden foreground controlling-TTY
prompt. The AI runs this flow itself: the product never tells the human to run a
recovery shell command, and secrets are never accepted in chat, argv, stdin,
URLs, logs, or browser storage.

After verification, the helper atomically stores the key in the private
`~/.attacca/credentials.json` registry with mode `0600`, scoped by the full
server base URL and the stable client installation ID. Claude, Codex, Kimi, and
generic MCP clients use the same client-key contract while retaining distinct
client configuration roots and canonical AI actors. MCP, lifecycle hooks, and
the watcher hot-reload a repaired key in the current host; authorization repair
does not require an executable plugin reinstall or a client restart.

The landing page, `/install.sh`, plugin zip/marketplace, health check, auth
status, bootstrap, and login remain public so a new machine can install and
connect. This is prototype account security, not a claim of production
hardening: Attacca does not terminate TLS, provide SSO/MFA, rate-limit login,
or encrypt the database. Put TLS and appropriate network controls in front of
any remotely reachable instance.

The native plugins bundle lifecycle continuity. Claude/Codex use `SessionStart`,
`UserPromptSubmit`, and `Stop`; Kimi uses its manifest startup skill plus native
`UserPromptSubmit` and `Stop` hooks. Once setup writes `.attacca/project.json`,
each new session loads handoff, Project Rules, inbox, room, tasks, agents, and
status. Setup also starts one machine-global background watcher. It polls the
hosted workspace at the server-configured interval (one minute by default,
configurable or disableable in `/app` Settings) even while coding clients are
idle, deduplicates changes, and queues a concise local notification. The next
supported lifecycle boundary injects that queue into the AI's context. The user
never has to type “check messages,” and there is no second project database.

Lifecycle startup compares the installed Attacca executable `VERSION` and the
checkout's managed-law version/hash with the configured server. Only a newer
**executable bundle** asks once per reminder window with **Install now / Later /
Skip this version**; downloaded code is never installed without the user's
explicit choice. An unanswered executable offer is deduplicated, Later snoozes
that release for 24 hours, and Skip suppresses only that release. Simultaneous
clients atomically claim the offer so they cannot all ask at once. A successful
executable install may require a fresh client session to load the new code.

Managed law is a separate, non-executable update path. The client fetches the
server-authoritative project-bound block from `/v1/managed-law`, verifies its
exact SHA-256, template hash, ownership markers, project ID, and monotonic
version, then atomically refreshes existing valid `MANAGED_ATTACCA` blocks in
`AGENTS.md` and `CLAUDE.md` without a binary reinstall or restart. It never
downgrades a newer local law. A missing, malformed, project-mismatched, or
hash-mismatched **server payload** is rejected. A valid Attacca-owned local
block may be rebound after this checkout is verifiably relinked to another
workspace; an unmanaged, malformed, or unsafe local target is left untouched
and reported. Bytes outside the markers are preserved exactly.

The universal installer downloads into same-filesystem staging, rejects
missing/unsafe files or mismatched runtime/manifests, and only then swaps the
validated bundle into place. If validation or the swap fails, the previously
working plugin is retained or restored. The native Git marketplace cache is
content-addressed by the served bundle, so a server upgrade cannot keep
returning an older cached plugin.

The managed-law refresh runs independently of executable update state. The
server publishes the current version/hash through `/healthz` and the exact
project-bound content through `/v1/managed-law`.

Lifecycle briefs include the complete Cloud Context whenever it fits the
client's configured hook-context budget. That budget is measured in UTF-8
bytes, so unusually large Unicode-heavy context may be rendered as an explicit
head/tail compacted view with `cloud_context_get` recovery instructions; the
authoritative hosted content itself is never shortened or rewritten.

## How a tool connects (three shapes, one server)

| Shape | Who uses it | Project identity |
|---|---|---|
| `connect` stdio client | Claude plugin, Kimi Code, Codex, Cursor, Cline, Windsurf | explicit env → nearest `.attacca/project.json` → same-machine registered root; on transport outage only, the exact verified watcher identity activates its scoped mirror/outbox |
| HTTP MCP (`/mcp`) | Gemini, VS Code, opencode, anything with native HTTP MCP | `X-Attacca-Project` header |
| stdio direct (`mcp`) | explicit local/serverless development mode (`setup --stdio`) | cwd walk-up against the selected local DB; never an automatic hosted fallback |

### Two computers, one workspace

Both computers must use the **same Attacca server URL/database**. Absolute
checkout paths are irrelevant. Computer A confirms or creates the workspace,
then commits `.attacca/project.json`; computer B can clone anywhere and the
client sends the same stable project id. Even before that file is committed,
the normalized Git remote fingerprint lets setup suggest the same workspace
for confirmation. The link contains no token, user identity, database path, or
absolute directory.

Each computer keeps a separate installation-scoped outbox and a verified mirror
scoped to its human-owned client key plus exact project and actor headers. During
an outage, each can queue its own allowlisted mutations;
the background watcher reconnects, pulls, replays immutable mutation IDs in
order, and pulls again. Duplicate retries return the stored receipt, while real
conflicts remain visible and block dependent work instead of being overwritten.

Keep the server running across reboots with anything you like, e.g.
`nohup python3 /abs/attacca.py serve >/tmp/attacca.log 2>&1 &` or a
systemd user unit. It binds `127.0.0.1` by default; `--host 0.0.0.0` exposes an
unencrypted HTTP listener. Bootstrap an account, create a separate key for every
active client installation, explicitly enable enforcement in Settings, and put
TLS in front of it before using it outside a trusted development network.

## REST API (server mode)

```
GET  /                         GET /app[/]                 GET /healthz
GET  /v1/auth/status
POST /v1/auth/bootstrap       POST /v1/auth/login         POST /v1/auth/logout
GET/POST /v1/auth/client-keys
DELETE /v1/auth/client-keys/{token_id}
POST /v1/auth/activation
GET/PUT /v1/settings
GET  /v1/projects                          POST /v1/projects
GET  /v1/projects/{id}/status              GET  /v1/projects/{id}/inbox
PUT  /v1/projects/{id}/lead
GET/POST /v1/projects/{id}/bridges         DELETE /v1/projects/{id}/bridges/{other}
GET  /v1/projects/{id}/handoff             POST /v1/projects/{id}/handoff
GET  /v1/projects/{id}/log?limit=          GET  /v1/projects/{id}/events?after=&limit=
POST /v1/projects/{id}/events              GET  /v1/projects/{id}/room?since_seq=&limit=
POST /v1/projects/{id}/room                GET  /v1/projects/{id}/tasks?status=
POST /v1/projects/{id}/tasks               GET  /v1/projects/{id}/tasks/{tid}
GET/PUT /v1/projects/{id}/tasks/{tid}/plan
POST /v1/projects/{id}/tasks/{tid}/plan/submit
POST /v1/projects/{id}/tasks/{tid}/plan/review
POST /v1/projects/{id}/tasks/{tid}/claim   POST /v1/projects/{id}/tasks/{tid}/report
POST /v1/projects/{id}/tasks/{tid}/release POST /v1/projects/{id}/tasks/{tid}/status
GET  /v1/projects/{id}/decisions           POST /v1/projects/{id}/decisions
POST /v1/projects/{id}/decisions/{did}/resolve
GET  /v1/projects/{id}/agents              POST /v1/projects/{id}/agents
GET  /v1/projects/{id}/search?q=
GET  /v1/projects/{id}/freshness?context_version=
GET  /v1/projects/{id}/verify
```

In legacy anonymous mode, actor identity uses `X-Attacca-Actor` /
`X-Attacca-Actor-Type`. Once authenticated, browser/human writes derive an
immutable `web.<username>` actor and owner from the account, while agent writes
derive their exact project/actor/runtime from the token; spoofable identity
headers are ignored or rejected. Writes return the same payloads (and warnings)
as the MCP tools.

## The protocol agents follow

Injected via the managed block and the MCP server's `instructions`:

1. **Session start** — use the hook-injected brief, or call `get_handoff`,
   `check_inbox`, `room_read`, `task_list`, and `attacca_status` if absent.
   Drain every `check_inbox` page while `may_have_more` is true before calling
   the inbox current.
2. **Tasks for owned, trackable work** — before editing, `task_claim` (or
   `task_create` then claim). Declare `expected_scope`; heed overlap warnings.
3. **Room for ephemeral coordination** — questions, directives, challenges,
   and short updates use `room_send` / `room_read since_seq=…`. Every permitted
   participant reads every visible non-self message. Mentions/replies route
   attention only; an untargeted chat/directive addresses everyone. Explicit
   bridge participation/access, not mentions, sets the privacy boundary. The
   cursor is lossless: a truncated batch sets `may_have_more` and the next poll
   picks up exactly where the last one ended.
4. **Decisions for durable choices** — architecture, API, data, security,
   workflow, or product choices use `decision_propose` / `decision_resolve`,
   not chat; routine implementation details do not need a decision record.
5. **Handoff at transitions/session end** — report task evidence first, then a
   Director calls `update_handoff` with the version from `get_handoff`.
   Advisors/workers report via tasks/room, and stale handoff writes fail.
6. **Drift Guard** — responses carry `stale_context_warning` when the project moved
   after your briefing; re-run `get_handoff` before writing.

## MCP tools (35)

`attacca_status`, `get_handoff`, `update_handoff`, `get_project_log`,
`check_inbox`, `room_send`, `room_read`, `task_create`, `task_list`, `task_show`,
`task_plan_get`, `task_plan_set`, `task_plan_submit`, `task_plan_review`,
`task_claim`, `task_report`, `task_release`, `task_set_status`, `decision_propose`,
`decision_resolve`, `decision_list`, `set_lead_director`, `bridge_add`,
`bridge_update_access`, `bridge_remove`, `bridge_list`, `search`, `rule_list`,
`rule_create`, `rule_update`, `agent_register`, `agent_list`, `list_projects`,
`append_event`, `check_freshness`.

In Claude Code they appear as `mcp__attacca__<name>`. Every tool takes an optional
`project` argument for cross-project work.

## CLI reference (same data, for humans and non-MCP tools)

```
attacca.py [--db PATH] [--project ID] [--actor ID] [--actor-type human|agent|system] [--json] COMMAND

init [PATH] [--project-id ID] [--name NAME] [--move]   register a project
                                               (--move re-points an existing id to a new root)
projects | status | log [-n N] | freshness [--context-version N]
handoff show | handoff set --objective ... --what-changed ... --next-actions ...
            [--expected-context-version N]
room send --type chat|directive|claim|handoff|challenge|decision|approval|status
          --body TEXT [--mentions a,b] [--task T-1] [--to OTHER_PROJECT]
room read [--since SEQ] [-n N] | room tail [--interval SECS]
task create TITLE [--scope a,b] [--depends-on T-1] [--risk low|medium|high]
                  [--plan-required]
task list [--status S] | task show T-1 | task claim T-1 [--scope a,b] [--lease MIN]
task plan get T-1 [--version N]
task plan set T-1 --title TEXT (--sections-json JSON | --sections-file PATH)
              [--overview TEXT] [--expected-version N] [--submit]
task plan submit T-1 --expected-version N
task plan review T-1 --expected-version N --action approve|suggest_edit|comment
                 [--section ID] [--note TEXT]
task report T-1 --summary TEXT [--evidence JSON] [--state review|done|blocked|queued]
task release T-1 [--reason TEXT] | task set-status T-1 STATUS [--reason TEXT]
decision propose TITLE [--detail TEXT] [--rationale TEXT]
decision resolve D-1 accepted|rejected|superseded | decision list
inbox [-n N] [--keep-unread]                    visible non-self room messages, cursor persists
lead [ACTOR_ID] [--clear]                       show or set the Lead Director
bridge add OTHER [--boss P | --advisor P] | bridge remove OTHER | bridge list
search QUERY [-n N] | overview                  explore everything stored
handoff history [-n N] | event show SEQ         version and event detail
agent register [--id X] [--role R] [--runtime RT] | agent list
event append --type note.x --payload '{"k":"v"}' | event tail | event verify
serve [--host H] [--port P] [--verbose]        host REST + MCP/HTTP
mcp                                            explicit stdio direct-DB mode (not hosted fallback)
setup --discover | --attach ID | --create NAME  advanced/scripted workspace flags
setup [--url U] [--stdio] [--no-instructions]  one-shot checkout setup
      [-i|--interactive]
      [--role director|advisor|worker] [--lead keep|current|clear]
      [--bridge ID --relationship master|peer|advisor|none --principal current|other]
setup --details [claude kimi codex gemini opencode glm cli]   full config reference
install-instructions [--files CLAUDE.md,AGENTS.md]
```

## Demos and tests

```bash
./demo/demo_cold_handoff.sh        # blueprint north-star: fresh worker resumes cold
python3 demo/demo_two_agents_mcp.py  # two real MCP sessions coordinating via the ledger
python3 -m unittest discover -s tests -v   # storage, hooks, MCP, REST, UI, concurrency
python3 attacca.py event verify  # hash-chain + sequence integrity of a real ledger
```

## Notes and limits (honest edges)

- **Prototype authentication, not production identity infrastructure.** Account
  sessions, CSRF, hash-only per-install client keys, exact project/actor request
  selection, human attribution, Director-only handoff/directive rules, and stale
  versions are enforced. SSO/MFA, login rate
  limits, centralized key rotation, TLS termination, and hostile-host isolation
  remain later layers (blueprint §12.3, §28 "policy bypass").
- **No encryption.** Everything is plaintext on your machine. The E2E key hierarchy
  (§17) is the next milestone and slots in at the sync boundary.
- **Offline mode is identity-scoped, not a second database.** It activates only
  after an authenticated snapshot has bound server, project, human principal,
  canonical AI actor/role, visibility policy and client installation. Bridge/agent/lead-policy
  changes and cross-project sends remain unavailable offline. A timeout after a
  mutation may be ambiguous, so `connect` refuses to queue that request; a proven
  connection refusal can be queued safely.
- **Leases are soft locks** for coordination, not Git locking. Use branches/worktrees
  as usual; `base_revision` is recorded at claim/report for later comparison.
- **Hash chain is tamper-*evident*, not tamper-*proof*** (no signatures yet — §23.3).
- **One canonical actor = one workspace/role/runtime persona.** Two simultaneous
  sessions of the same AI in the same role intentionally share its inbox cursor and
  task leases; owner remains separately visible on every new event.
- The room is a projection of `room.message` events in the ledger — chat is not the
  database (blueprint principle, §2.3).
