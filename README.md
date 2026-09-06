# Attacca

Attacca is a durable project-continuity layer for humans and AI coding tools.
It keeps the parts of a project that outlive a chat window — an append-only
event ledger, a shared task board, decisions, handoffs, binding rules, and one
human+AI room — on a small server you run yourself. Claude Code, Codex CLI,
Kimi Code, Cline, Cursor, Windsurf, other MCP clients, and the browser Control
Panel all read and write the same workspace, so any one session can end, crash,
or be replaced without taking the project state with it. Sessions are
disposable; the project is not.

> [!IMPORTANT]
> Attacca is a pre-production dogfood prototype, not a finished public SaaS. It
> runs the complete continuity workflow with strong correctness boundaries, but
> it does not terminate TLS or provide SSO, MFA, login rate limiting, encrypted
> database storage, or hardened hostile-host isolation. Keep it on localhost, or
> put your own TLS and network controls in front of it.

## Quick start (local server)

You need Python 3.8+ and Git. There is nothing else to install: Attacca is
Python standard library only.

**1. Clone the repository and start the server**

```bash
git clone https://github.com/jdevgy/attacca-ai.git && cd attacca-ai
python3 attacca.py serve --host 127.0.0.1 --port 4173
```

All state lives in one SQLite file (`~/.attacca/attacca.db`; override with
`ATTACCA_DB`), and `http://127.0.0.1:4173/healthz` reports the running version.
Any free port works — `8722` is the built-in default the examples further down
use.

**2. Open the Control Panel and create the first admin account**

```
http://127.0.0.1:4173/app
```

While no account exists the panel opens on a **Create the first administrator**
form; submitting it creates that account and signs you in.

**3. Give other people their own accounts** *(optional)*

An admin opens self-service sign-up — start the server with
`--allow-self-registration`, or set `self_registration` to `open` in server
settings (`PUT /v1/settings`) — and everyone else joins through the **Create
account** form on the sign-in page (0.5.9 and later). The alternative: a
signed-in admin creates one invitation per person with
`POST /v1/auth/invitations`, and the invited person accepts it in the panel.

**4. Install the Attacca plugin into your coding tools**

```bash
cd ~ && curl -fsSL http://127.0.0.1:4173/install.sh | sh
```

Run this from your home directory, not from this checkout. The server serves
its own plugin pre-wired to the URL it came from, installs it under
`~/.attacca/plugin/attacca`, and configures every AI coding tool it finds.

**5. Link a project and register the AI**

Open your own project in Claude Code and run `/attacca:setup` (Codex:
`$attacca:setup`; Kimi: `/attacca:setup`). The guided flow picks or creates a
workspace, registers this AI's role and identity, and writes the non-secret
workspace link into `.attacca/project.json`.

**6. Verify**

Run `/attacca:status` in Claude Code or Kimi (Codex: `$attacca:update`). It
reports the linked workspace, this AI's identity, and the current handoff.

## What you get

- **One shared memory** — a hash-chained, append-only event ledger plus a
  readable activity log of what changed, why, and who ran it.
- **Cold resume** — a Director-owned project handoff, per-AI identity handoffs,
  shared Cloud Context, and binding role-scoped rules, injected at session start.
- **Coordinated work** — a task board with expiring claims, declared file scope,
  immutable plan revisions, decisions, and evidence-based completion.
- **A room humans and AIs share** — group messages, persistent per-identity
  inbox cursors, and explicit dispositions so addressed work is never dropped.
- **Separate identity and authority** — the AI actor, the authenticated human
  operator, the runtime, the role, and the Git checkout stay distinct on every write.
- **The tools you already run** — native plugins for Claude Code, Codex CLI, and
  Kimi Code; MCP config for Cline, Cursor, Windsurf, and any other MCP client;
  REST and a CLI for everything else.
- **No cloud dependency** — one Python process, one SQLite file, zero third-party
  packages.

## Documentation

- [What Attacca gives a project](#what-attacca-gives-a-project) — the full feature list
- [Architecture](#architecture) — server, clients, and installation-bound AI identity
- [Setup and installation in detail](#setup-and-installation-in-detail) — every install path, flag, and side effect
- [Hosted authentication](#hosted-authentication-prototype) — accounts, client API keys, enforcement
- [How a tool connects](#how-a-tool-connects-three-shapes-one-server) — the three client shapes; two computers, one workspace
- [REST API](#rest-api-server-mode) — every `/v1` endpoint and the shared paging contract
- [The protocol agents follow](#the-protocol-agents-follow) — what every AI session is required to do
- [Message dispositions](#message-dispositions) — why reading a message is not handling it
- [MCP tools](#mcp-tools) — the tool surface and compact read projections
- [CLI reference](#cli-reference-same-data-for-humans-and-non-mcp-tools) — the same data without MCP
- [Demos and tests](#demos-and-tests) — cold-handoff demo, unittest suite, ledger verification
- [Notes and limits](#notes-and-limits-honest-edges) — the honest edges

## What Attacca gives a project

Claude Code, Codex CLI, Kimi Code, Cline, Cursor, Windsurf, GLM-backed clients,
other MCP tools, and the browser Control Panel can coordinate through the same
workspace:

- **History that survives sessions** — a per-project, hash-chained event ledger
  and a readable activity log preserve what changed, why, and who ran it.
- **Cold-resume context** — one Director-governed shared project handoff,
  shared Cloud Context, binding role-scoped Rules, shared Role Scope,
  exact-AI-identity handoffs, and startup briefs restore the state a returning
  worker needs without merging parallel AI identities.
- **Coordinated work** — rooms, persistent inbox cursors, tasks, expiring claims,
  declared path scopes, immutable plan revisions, decisions, and evidence-based
  completion keep parallel workers aligned.
- **Separate identity and authority** — new canonical AI actors use
  `workspace.role.runtime.persona` (for example,
  `engine.director.codex.gibbs`, displayed as **Gibbs** / **@Gibbs**);
  the authenticated human operator, client installation, Git revision,
  runtime, role, and persona remain distinct audit fields. Existing three-part
  actors remain compatibility identities and are never rewritten implicitly.
- **Purpose-limited collaboration** — peer, master/subordinate, and advisor
  bridges move only explicit cross-workspace messages under participation and
  routing policy.
- **Continuity through outages** — the installed client can use only an exact,
  integrity-verified, identity-scoped offline mirror. Cached reads are visibly
  stale, eligible writes are fsynced to an idempotent outbox, and ambiguous or
  unauthorized fallback fails closed.

The runtime is Python 3.8+ standard library only. One hosted Attacca process
serves many isolated workspaces from SQLite; projects do not receive their own
hidden server or database.

The broader design in [`docs/blueprint.txt`](docs/blueprint.txt) also describes
future encryption, Project Brain/context packs, capability marketplaces, and
commercial layers. Those features are not implemented merely because the
blueprint discusses them.

## Architecture

![Attacca architecture: native Claude, Codex, and Kimi sessions use lifecycle plugins before a stable stdio proxy; other supported MCP clients use that proxy directly, while a machine watcher maintains a verified local mirror and outbox for one hosted service.](docs/assets/attacca-architecture.svg)

**The app hosts the server; tools are API clients.** `attacca.py serve` runs the
attacca server — it owns the state and exposes two client surfaces:

- **MCP over HTTP** at `/mcp` (streamable HTTP transport) — what Claude Code, Kimi
  Code, Codex, GLM-backed CLIs and other MCP clients connect to. Requests select
  the canonical actor and workspace with `X-Attacca-Actor` and
  `X-Attacca-Project`; authentication separately identifies the human-owned
  client installation.
- **REST API** under `/v1/…` (blueprint §22.1 shape) — for curl, scripts, dashboards
  and anything that isn't an MCP client.

The installed **`connect` stdio client** normally forwards MCP to the configured
host. If that transport is unavailable, it can continue only from the exact
schema-v1 mirror previously authenticated for this server, workspace, human
principal, exact canonical AI actor and role, checkout, and device. Cached reads
are marked offline/stale; allowlisted writes are fsynced to a device outbox and
replayed idempotently after reconnect. Missing, ambiguous, forged, or role-
changed mirrors fail closed.

`attacca.py mcp` is a separate, explicitly selected serverless/direct-database
mode for local development (`setup --stdio`). It is not the installed plugins'
automatic hosted fallback, and neither a local database nor the administrative
full export can substitute for the verified identity-scoped mirror.

- **Language:** Python 3.8+ standard library only. Nothing to install
  (`requirements.txt` exists and is intentionally empty of dependencies).
- **One database, many projects.** Default `~/.attacca/attacca.db`
  (override: `ATTACCA_DB`). Claims use single conditional UPDATEs, appends use
  `BEGIN IMMEDIATE` — safe under many concurrent clients (`tests/test_concurrency.py`).
- **Installation-bound, named AI identity.** Clients send a runtime hint
  (`claude`, `codex`, `kimi`, …); setup binds that runtime on this client
  installation to one exact `workspace.role.runtime.persona` actor. New actors
  receive short human-friendly names beginning with Gibbs. New names are
  reserved transactionally and case-insensitively across every workspace on
  the server, including historical identities, and are never issued twice.
  An upgrade preserves grandfathered duplicates; rerunning setup detects the
  later duplicate, aliases its old actor for audit, assigns the next unique
  name, and repairs that installation's binding. Normal start/resume silently
  reuses the binding. Selecting an existing identity in explicit native setup
  changes only that MCP process unless **Make default** is also chosen. Owner is transmitted and
  stored separately, and no conversation or host-session ID participates in
  identity. Existing Red/Blue and three-part actors remain compatibility
  records; only an explicit duplicate-name repair migrates one safely.

## Setup and installation in detail

The [Quick start](#quick-start-local-server) above is the short path. This
section explains what each step actually does, every supported client, and
the flags for non-default installations.

**The server is the app.** It runs standalone — its own directory, its own
lifecycle — and owns all state. Tools are pure clients; no Attacca server or
database is installed inside a user's project.

**1. Host the server** (whoever runs the platform; once):

```bash
python3 attacca.py serve                   # http://127.0.0.1:8722
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
Lead Director), and confirms its installation identity. A new installation
creates the next permanent generated name by default (the first is **Gibbs**).
An explicit setup on an existing installation can instead continue its bound
name, take over another existing named identity, create the next permanent
name, or use a freshly generated name only in the current MCP process. The
temporary path is deliberately performed by `agent_register` through that
already-running, already-bound proxy; it is not offered to a first/unbound
client because D-17 authentication requires an exact actor first. A setup shell
subprocess cannot claim to change its parent MCP process. Reuse is
selection-only: it shares that exact actor's identity handoff, inbox cursor,
and task leases without merging, deleting, or renaming the currently active
identity.
User-facing choices show **Gibbs** / **@Gibbs** with role and runtime; raw
project and actor IDs remain internal arguments.

Normal session start/resume never asks this question: the non-secret binding in
`~/.attacca/config.json` is keyed by normalized server URL, workspace, runtime,
and stable client installation. Sessions using the same Attacca configuration
home and client installation therefore reuse the same actor. A container or
machine with a separate home receives a separate client installation and makes
the one-time choice during setup; mounting the same home deliberately shares the
binding. Codex/Claude/Kimi conversation and session IDs are never used as the
durable key. Existing `workspace.role.runtime` actors remain selectable
compatibility identities, but setup never silently converts or clones them.

Setup also shows existing relationship/inbox evidence, asks how to connect
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
`--identity-mode auto|reuse|new|repair` (normally selected by guided setup; an exact
reuse/repair target stays an internal argument), plus `--make-default` when an
existing identity should replace the installation default. Reuse without that
choice is current-process only. Native guided setup also offers a
temporary current-proxy identity to an already-bound client and activates it
only through that current MCP connection. Direct CLI `temporary` is rejected
because a child process cannot alter its parent,
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

Settings authorizes, lists, and revokes client-install keys. A new installation
opens a short-lived non-secret pairing link; the signed-in human reviews the
client and optional workspace scope, then explicitly selects Authorize or Deny.
The displayed pairing code retains 256 random bits as canonical unpadded
Base32, grouped for readability; failed or unknown browser lookups are
rate-limited without revealing whether a code exists.
The client polls silently and receives the one-time credential directly after
approval—there is no copy/paste step and the browser never displays the key.
Leaving workspace selection empty follows the authenticated human's current
memberships. Stored records contain only a
hash, prefix, human owner, client installation, scope, timestamps, and status.
Revoking one installation does not revoke another installation or rewrite any
AI identity or audit history.

Every authenticated AI request still supplies the exact
`X-Attacca-Project: <workspace>` and
`X-Attacca-Actor: <workspace>.<role>.<runtime>.<persona>` headers (or an
existing three-part compatibility actor). The server validates the key's
workspace scope, the human's workspace membership, and that the registered
actor belongs to that authenticated human; authorization then comes from the
actor's registered role. Ledger writes therefore record the canonical AI actor
and `Run by user` separately. A Codex client key is not a Codex actor key: the
same installed client can select any valid actor owned by that human, while its
machine-local actor binding decides which one normal sessions select.

When a protected server needs authorization, the native setup/update skill or
lifecycle hook starts the packaged helper inside the active AI terminal. The
helper generates or loads that installation's stable non-secret client ID and
opens the browser directly on Settings with only a short-lived pairing code in
the URL. The signed-in human explicitly Authorizes or Denies the reviewed
installation. The helper polls silently, stores the delivered credential, and
automatically reconnects MCP and watcher sync in the same running client. The
AI runs this flow itself: the product never tells the human to run a recovery
shell command or asks anyone to create, copy, reveal, or paste a key.

After verification, the helper atomically stores the key in the private
`~/.attacca/credentials.json` registry with mode `0600`, scoped by the full
server base URL and the stable client installation ID. Claude, Codex, Kimi, and
generic MCP clients use the same client-key contract while retaining distinct
client configuration roots and canonical AI actors. MCP, lifecycle hooks, and
the watcher hot-reload a repaired key in the current host; authorization repair
does not require an executable plugin reinstall or a client restart.

The credential registry and actor binding solve different problems. The API
key proves which human-owned client installation may connect. The non-secret
actor binding in `~/.attacca/config.json` selects one exact AI actor for the
normalized server URL, workspace, runtime, and that installation. Neither file
uses a coding host's conversation/session ID, and repairing authorization never
changes the actor binding.

The landing page, `/install.sh`, plugin zip/marketplace, health check, auth
status, bootstrap, and login remain public so a new machine can install and
connect. This is prototype account security, not a claim of production
hardening: Attacca does not terminate TLS, provide SSO/MFA, rate-limit login,
or encrypt the database. Put TLS and appropriate network controls in front of
any remotely reachable instance.

The native plugins bundle lifecycle continuity. Claude/Codex use `SessionStart`,
`UserPromptSubmit`, and `Stop`; Kimi uses its manifest startup skill plus native
`UserPromptSubmit` and `Stop` hooks. Once setup writes `.attacca/project.json`,
each new session loads Project Rules, Cloud Context, the shared project handoff,
its applicable Role Scope, its exact AI identity handoff, inbox, room, tasks,
agents, and status. Setup also
starts one machine-global background watcher. At the
server-configured interval (one minute by default, configurable or disableable
in `/app` Settings), it makes lightweight inbox and append-only event-feed
checks even while coding clients are idle. A relevant change or pending local
write immediately triggers a verified mirror refresh; otherwise the full mirror
receives a ten-minute safety refresh. The watcher deduplicates changes and
queues a concise local notification. The next
supported lifecycle boundary injects that queue into the AI's context. The user
never has to type “check messages,” and there is no second project database.

Claude additionally maintains one native session job equivalent to
`/loop 1m /attacca:inbox`. Every Claude SessionStart asks the host's Cron tools
to list existing jobs, create the job when absent, and remove only duplicate
Attacca inbox jobs. This check repeats on startup, resume, clear, and compact
because Claude loop jobs are session-scoped and recurring jobs expire after
seven days; it never replaces the
machine-global watcher, which continues transport and staging while no Claude
generation is active. The native pulse runs only while Claude is open and idle,
and each firing is a model turn that can consume credits even when prompt
caching reduces its cost. Codex and Kimi do not receive the Claude-only Cron
instruction. If the user has disabled Claude cron jobs, Attacca preserves that
choice and continues with the watcher alone.

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

Session-start lifecycle briefs include the complete Cloud Context whenever it
fits the client's configured hook-context budget. Subsequent unchanged turn
briefs rely on that cached/current version; the watcher refetches and injects
the full text only after its version/hash changes. The session-start budget is
measured in UTF-8 bytes, so unusually large Unicode-heavy context may be
rendered as an explicit head/tail compacted view with `cloud_context_get`
recovery instructions; the authoritative hosted content itself is never
shortened or rewritten.

## How a tool connects (three shapes, one server)

| Shape | Who uses it | Project identity |
|---|---|---|
| `connect` stdio client | Claude plugin, Kimi Code, Codex, Cursor, Cline, Windsurf, Gemini, VS Code, opencode | explicit env → nearest `.attacca/project.json` → same-machine registered root; on transport outage only, the exact verified watcher identity activates its scoped mirror/outbox |
| HTTP MCP (`/mcp`) | Manually configured clients and integrations that deliberately use native HTTP transport | exact `X-Attacca-Project` + `X-Attacca-Actor` headers; authentication remains the separate browser/client-key access channel |
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
scoped to its human-owned client key plus exact project and actor headers. Its
actor choice is also installation-local: a fresh home/container has no actor
binding and setup asks whether to take over an existing named identity, create
the next permanent generated name, or select another same-owner compatibility
identity. A temporary current-process name is offered only after an exact
machine binding already authorizes the running MCP proxy.
The project reserves each generated name forever, case-insensitively, so a
retired Gibbs can never collide with a later `gibbs` in another role/runtime.
Two sessions sharing the same `~/.attacca` home and runtime silently reuse one
binding; two
isolated homes make independent choices even in the same checkout. During an
outage, each can queue its own allowlisted mutations;
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
POST /v1/projects/{id}/inbox/dispositions  POST /v1/projects/{id}/messages/dispose-bulk
PUT  /v1/projects/{id}/lead
GET/POST /v1/projects/{id}/bridges         DELETE /v1/projects/{id}/bridges/{other}
GET  /v1/projects/{id}/handoff             PUT  /v1/projects/{id}/handoff
GET  /v1/projects/{id}/handoff/history
GET  /v1/projects/{id}/identity-handoff?actor=AI
PUT  /v1/projects/{id}/identity-handoff?actor=AI
GET  /v1/projects/{id}/identity-handoff/history?actor=AI
GET  /v1/projects/{id}/role-scopes
PUT  /v1/projects/{id}/role-scopes/{role}
GET  /v1/projects/{id}/role-scopes/{role}/history
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
immutable `web.<username>` actor and owner from the account; spoofable browser
identity headers are ignored or rejected. Agent requests instead authenticate
the human-owned client installation with its API key and independently select
the exact project and already-registered actor with `X-Attacca-Project` and
`X-Attacca-Actor`. The server validates account membership, key scope, actor
ownership, and the actor's registered role. The client key never carries the
AI actor, runtime, or role. Writes return the same payloads (and warnings) as
the MCP tools.

Long collection reads use one product-wide paging contract across REST, MCP,
the Control Panel, and the verified offline mirror. A page is capped at 60
rows and reports exact `total`, `unfiltered_total`, `limit`, `offset`, and
`has_more`; search, status/filter, and `newest|oldest` sort are applied to the
complete authorized collection before the slice is taken. `search` likewise
returns one unified page across result kinds rather than a separate 60-row
slice per category. `task_show` pages task actions and readable task history
independently, while `task_plan_get` independently pages immutable plan
revisions and review actions. Guided setup is the deliberate exception: its
authenticated `options=1` directories remain complete so a workspace,
existing same-owner identity, or permanently reserved friendly name is never
hidden by an arbitrary page boundary.

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
   sender may address a named identity as `@Gibbs` (case-insensitive); Attacca
   resolves that server-unique short name in the destination workspace and
   stores the exact canonical actor.
   cursor is lossless: a truncated batch sets `may_have_more` and the next poll
   picks up exactly where the last one ended.
4. **Decisions for durable choices** — architecture, API, data, security,
   workflow, or product choices use `decision_propose` / `decision_resolve`,
   not chat; routine implementation details do not need a decision record.
5. **Shared handoff + identity handoff + Role Scope** — the shared project
   handoff is the workspace-wide objective and current status; only registered
   AI Directors update it, using an optimistic project-handoff version. Every
   registered AI may separately update only its own exact identity handoff
   after reporting task evidence; Gibbs can never overwrite Turing's history.
   Web and console humans remain separately attributed operators and never own
   an identity handoff. Role Scope is durable background shared by every AI in
   one role, with an additional Lead Director overlay for the lead; humans and
   registered Directors govern Role Scope through its own optimistic version.
6. **Drift Guard** — responses carry `stale_context_warning` when the project moved
   after your briefing; re-run `get_handoff` before writing.

**Product-default rule R-0:** every new workspace receives an ordinary,
audited Project Rule for the local coordination hierarchy. In a direct local
exchange, a Worker or Advisor periodically acknowledges the addressed Director
as the project's **MASTER**; a non-Lead Director addressing the Lead Director
periodically acknowledges the Lead as **MASTER coordinator**. Only an explicit
local mention, reply, or selected recipient triggers this conversational
reminder—ordinary group visibility does not. It grants no permission and never
bypasses role, Lead, runtime, or bridge authority. It never applies across
projects, where bridge policy remains the sole authority. Existing workspaces
receive R-0 once when opened by the upgraded product; because it is a normal
Project Rule, authorized governance may edit or disable it and Attacca will not
overwrite that choice.

## Message dispositions

Reading a room message is not the same as handling it. Every message directed
at you (a mention, a reply to your own message) and every broadcast directive
requires an explicit outcome recorded with `message_dispose`
(`acknowledged`, `claimed`, `deferred`, `blocked`, `completed`, or
`not_actionable`; `claimed`/`completed` must name a task in the matching board
state). `deferred`, `blocked`, and `claimed` deliberately stay pending.

Some outcomes are already proven by the project's own history, so Attacca
resolves them **implicitly** instead of demanding a second manual record:

| Rule | Implied disposition |
| --- | --- |
| You already replied to the message in the room | `acknowledged` |
| The message was retracted — a `room.message_retracted` ledger event names it, appended by its own sender or by a human | `not_actionable` |
| Its linked task — its own `task_id`, or the one carried by the message it replies to — is `done` or `cancelled` | `completed` |
| Its `seq` is at or below your reconciliation baseline | `acknowledged` |

Nothing is hidden: `check_inbox` and `room_read` still return the message with
`requires_disposition: true` and
`disposition: {disposition, implicit: true, reason}`, and the Control Panel
room feed shows an `auto · …` badge. An explicit disposition row always wins
over an implicit rule, so a message you deliberately deferred stays pending
even below a baseline.

**Reconciliation baseline.** An identity that has never recorded a single
disposition is reconciled exactly once, from its own persisted inbox read
cursor: history it had already read before implicit resolution existed is not
resurrected as mandatory work by an upgrade. The baseline is stored per actor
(`message_disposition_baselines`), appended to the ledger as
`room.disposition_baseline` with the number of rows it reconciled, and may only
move forward. Identities that were already disposing messages by hand are never
auto-baselined. Read-only surfaces (`get_handoff`, `check_freshness`, a
`mark_read=0` inbox) apply the baseline but never persist it; only a
write-capable call (`check_inbox` marking read, or a dispose) records it. A
verified offline mirror applies only the baseline the server has already
persisted — it never derives one from a read cursor, so an outage can never
close addressed work on its own.

**Bulk resolution.** `message_dispose_bulk` (REST:
`POST /v1/projects/{id}/messages/dispose-bulk`) closes up to 100 of your own
pending messages in one audited write. It takes either `event_ids` (max 100;
more is an error) or a bounded `filter`
(`{before_seq, older_than_hours?, task_state?}`, which truncates at 100 and
reports `remaining_pending`), plus `disposition` limited to
`acknowledged | not_actionable | deferred` and a mandatory `note`. It writes
one `message_dispositions` row per message and a single
`room.message_dispositions_bulk` ledger event naming every message closed, and
returns `{disposed, skipped, remaining_pending, baseline_seq}`. A
`before_seq`-only filter also moves your reconciliation baseline to
`before_seq`; adding `older_than_hours` or `task_state` narrows the selection
and deliberately leaves the baseline alone, so a narrowing call can never
silently close the rows it excluded. Another identity's rows are never
touched. The Control Panel exposes this as **Resolve all before
#N…** in the Room / Inbox view, with a live count preview and a confirm step.

## MCP tools

`attacca_status`, `get_handoff`, `update_handoff`, `get_identity_handoff`,
`update_identity_handoff`, `identity_handoff_history`, `get_project_log`,
`role_scope_get`, `role_scope_set`, `role_scope_history`,
`room_send`, `room_read`, `check_inbox`, `message_dispose`,
`message_dispose_bulk`,
`set_lead_director`, `bridge_add`, `bridge_update_access`, `bridge_list`,
`bridge_remove`, `search`, `task_create`, `task_list`, `task_show`,
`task_plan_get`, `task_plan_set`, `task_plan_submit`, `task_plan_review`,
`task_claim`, `task_report`, `task_release`, `task_set_status`,
`decision_propose`, `decision_resolve`, `decision_list`, `rule_list`,
`rule_create`, `rule_update`, `cloud_context_get`, `cloud_context_set`,
`migration_directive`, `agent_register`, `agent_list`, `list_projects`,
`append_event`, `check_freshness`.

In Claude Code they appear as `mcp__plugin_attacca_attacca__<name>` (the native plugin prefix). Every tool takes an optional
`project` argument for cross-project work.

### Compact read projections (`detail`)

`get_handoff`, `task_list`, `task_show`, `check_inbox` and `room_read` answer
with a **compact** projection by default over MCP and REST. The default is what
an agent needs to act — ids, titles, states, owners, versions, one-line
summaries and cursors — and nothing a follow-up call can fetch:

| Read | Compact default | Reach the rest with |
| --- | --- | --- |
| `get_handoff` | both handoffs, rules, role scope, governance, warnings, `recent_activity`; `open_tasks`/`decisions` capped at 30 id rows with `open_tasks_total`/`decisions_total`; `your_inbox` counters plus `first_page` (10 pending rows); `cloud_context` as `version`+`sha256` | `task_list`, `decision_list`, `check_inbox`, `cloud_context_get` |
| `task_list` | board row: ids, state, risk, claimant, lease, plan version, dependencies, first 8 declared scope paths (`expected_scope_total`), `last_report` head (200 chars), `verification_status`, and ONE compact attribution record for the latest action | `task_show` |
| `task_show` | that row plus the task description, newest 10 actions and 10 history lines | `action_limit`/`history_limit`/`action_sort` paging |
| `check_inbox`, `room_read` | routing, attention flags, disposition state and the **complete** message body — the nested identity/attribution duplication is dropped | `detail=full` |

Every compact attribution is `{actor_id, actor_type, run_by_user, role,
runtime, persona, at}` (plus `human_user` for a human actor). The accountable
human is never dropped.

Pass `detail=full` to restore the complete nested identity, `ledger_actor` and
per-lifecycle attribution records — the exact pre-compaction response. The
Control Panel does this wherever it renders an identity chip. `task_list` and
`task_show` also accept `fields` (a comma-separated row allow-list), and
`get_handoff` accepts `cloud_context_sha` (send the sha256 your checkout's
`ATTACCA_CLOUD_CONTEXT` block already holds and the body is returned only when
it changed) or `cloud_context=full` to force the document.

The same flags are query parameters on the matching REST reads:
`GET /v1/projects/{id}/tasks?detail=full&fields=status,claimed_by`,
`GET /v1/projects/{id}/tasks/{tid}?detail=full`,
`GET /v1/projects/{id}/inbox?detail=full`,
`GET /v1/projects/{id}/room?detail=full`,
`GET /v1/projects/{id}/room/history?detail=full`, and
`GET /v1/projects/{id}/handoff?detail=full&cloud_context=full`.
Sync, export and the verified offline mirror are separate projections and are
unchanged by these flags.

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
      [--identity-mode auto|reuse|new|temporary|repair] [--make-default|--session-only]
                                                            temporary/session-only require current MCP
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
  selection, human attribution, Director-governed shared project handoff,
  exact-AI-identity handoff ownership, Director-managed Role Scope/directive
  rules, and stale versions are enforced.
  SSO/MFA, login rate
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
- **One exact actor = one workspace/role/runtime/persona continuity owner.**
  Two simultaneous sessions that reuse the same named actor intentionally
  share its identity handoff, inbox cursor, and task leases. Separate permanent
  names have independent identity handoffs/cursors/leases while receiving the
  same shared project handoff and applicable Role Scope. Existing three-part
  actors remain explicit compatibility choices;
  existing Red/Blue persona records are preserved unless an explicit setup
  repair resolves a grandfathered duplicate. New setup-created identities
  always receive a server-unique friendly name and `@ShortName`. Owner remains
  separately visible on every new event.
- The room is a projection of `room.message` events in the ledger — chat is not the
  database (blueprint principle, §2.3).
