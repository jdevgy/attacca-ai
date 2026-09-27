---
description: Run the complete guided Attacca setup flow in Kimi Code (/attacca:setup)
---

# Attacca guided setup

Run one complete setup for this checkout against the server packaged with the
plugin. This is the `/attacca:setup` flow for Claude Code and Kimi Code. Never
start another local server, use `init --move`, or offer a second setup variant.

Use native choice UI for each decision when it is available. Otherwise show a
short numbered list and accept the number or displayed name. Always label
choices with workspace names. Keep exact project and actor ids from discovery
only as internal tool arguments; never display, invent, or ask the user for a
raw id. Identity choices use the generated server-unique name and short
address, such as **Gibbs · @Gibbs · Director · Kimi**, never the raw canonical
actor string. Treat $ARGUMENTS as preferences, not permission to skip
confirmation. Ordinary Kimi startup/resume silently reuses the installation
binding and must never ask an identity question; this choice belongs only in an
explicit setup flow.

## 0. Resolve the runtime and authenticate before MCP

Do not call unscoped `list_projects` first: an authenticated server correctly
rejects it when this machine has no credential. Resolve the bundled runtime
before any Attacca MCP call and verify `attacca.py` exists. If that fails, stop
and report the missing plugin runtime instead of searching for or starting a
second Attacca copy. Set the private runtime hint to `claude` in Claude Code or
`kimi` in Kimi Code, with actor type `agent`.

After verifying the bundled runtime, run the setup CLI discovery once as the
first remote preflight. It calls
the public authentication status before any protected workspace request; never
delegate a recovery command to the human:

```bash
ATTACCA_PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-${KIMI_PLUGIN_ROOT:-${KIMI_CODE_HOME:-$HOME/.kimi-code}/plugins/managed/attacca}}"
test -f "$ATTACCA_PLUGIN_ROOT/attacca.py" || exit 1
python3 "$ATTACCA_PLUGIN_ROOT/attacca.py" \
  --actor "RUNTIME_HINT" --actor-type agent --json setup --discover
```

Use the returned workspace and network data for the choices in Steps 1-4;
do not call MCP `list_projects` before first/unbound setup has registered the
exact AI identity. Keep `CURRENT_AI_ACTOR=RUNTIME_HINT` and
`CURRENT_AI_TYPE=agent` until the CLI applies the confirmed identity choice.
When discovery reports a valid `network.machine_actor_binding` with its
matching `network.current_actor_record`, you may instead use that exact bound
actor internally for the same workspace. Never substitute the shell user or
invent an actor id. After apply, use the returned exact registered identity
for MCP verification.

Handle the server's access choice before account authorization:

- `server_setup_required` or `setup_required=true`: open the displayed console
  URL and ask the human to choose **Local use without login** or **Protect with
  login**. First-run setup must be completed from the server's localhost browser
  or an SSH tunnel. Strongly recommend protection when the server is exposed
  beyond localhost; the human must explicitly acknowledge the risk of choosing
  no login there. Do not choose, activate, disable, or otherwise change the
  server's access policy for them. Pause workspace setup until they finish,
  then retry discovery.
- A fresh verified `access_mode=local`, `anonymous_access=true`, and
  `authentication_required=false` (CLI `kind=local`) means the human has already
  completed no-login setup. Skip account creation and browser authorization;
  continue workspace, role, and exact AI identity setup. Keep `authenticated=false`:
  this mode does not establish an authenticated human. Do not rename an existing
  actor or change its role because login is optional.
- A rejected credential or 401/403 is not evidence of local access. Never
  purge credentials, bypass rejection by retrying anonymously, or disable login
  protection to recover. Use the authorization flow below only when an
  account-based installation explicitly requests client authorization. Otherwise
  report that the credential or scope needs repair and stop; do not create an
  account or change a no-login server's policy to work around the rejection.
  Verify repaired access against the live server before proceeding.

For a protected or legacy account-based installation that still needs its first
owner, open the displayed `/app` URL and ask the human to create or sign in to
that account in the browser. This account step does not apply to completed local
no-login mode. If that account-based installation returns
`client_authorization_required` or a 401/403 explicitly requiring client
authorization, Kimi itself starts the packaged
`terminal_flow.py authorize` helper in the
active terminal; never give the human a recovery command. The helper opens a
short-lived, non-secret Attacca Settings link for the exact client-install ID.
The human signs in, reviews the installation and optional workspace scope, and
explicitly selects **Authorize** or **Deny**. Kimi polls silently; after
approval it receives and atomically stores the one-time credential in the
private 0600 credentials file, then reconnects MCP/watcher automatically.
Never ask anyone to create, copy, reveal, or paste an API key. If the browser
cannot open, show the safe link and keep lifecycle polling nonblockingly.

The credential belongs to the authenticated human and one client
installation—not to Kimi, Claude, Codex, any actor, or any role. Every project
request separately sends the exact workspace and canonical actor; the server
checks membership, actor ownership, and the actor's registered role. The key
persists across discovery and apply so Kimi can finish the explicitly confirmed
workspace, actor, and role setup. Browser cookies never cross into the CLI.

The non-secret AI actor binding is separate from that credential. It is scoped
by normalized server URL, workspace, runtime, and stable client installation in
the machine-local Attacca configuration. Kimi sessions using the same
`~/.attacca` home and client installation silently reuse the same actor. A
separate home/container gets a separate installation and makes a one-time setup
choice; mounting the same home deliberately shares it. Never use a Kimi, Claude,
or Codex conversation/session ID as any part of durable identity.

After authorization, hot-reload the credential and retry discovery. An
already-bound client can verify hosted status/sync immediately; a first/unbound
client must finish the confirmed CLI apply before MCP verification.
Clear the latch only after verified hosted sync; do not force a restart, alter
the established actor identity, or repeat completed Steps 1-5. Cached offline
data never authorizes recovery.

## 1. Select the workspace

Use the successful read-only discovery result from §0; this is not another
discovery call. Retry only after the human completes pending server setup or
authorization, or for the different-workspace governance lookup below.

Report the detected Git remote or local folder and whether a stale project link
needs repair; keep its raw ID internal. Then resolve `action` conversationally:

- `already_linked`: name the linked workspace and continue without asking the
  user to select it again.
- `confirm_git_match` or `confirm_folder_match`: recommend the named match,
  then offer **Use this workspace** or **Choose another**. Do not attach until
  the user confirms, even for a unique Git match.
- `choose_or_create`: offer every named workspace followed by **Create a new
  workspace**.
- `create_first_workspace`: explain that this server has no workspace yet and
  recommend `suggested_new_name`; let the user accept or edit that display
  name.

Do not attach or create anything yet. For a selected existing workspace whose
network data was not returned in the first result, re-run read-only discovery
with its exact internal id as `--attach`. This loads governance context without
changing the checkout:

```bash
ATTACCA_PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-${KIMI_PLUGIN_ROOT:-${KIMI_CODE_HOME:-$HOME/.kimi-code}/plugins/managed/attacca}}"
test -f "$ATTACCA_PLUGIN_ROOT/attacca.py" || {
  printf '%s\n' "Attacca plugin runtime not found: $ATTACCA_PLUGIN_ROOT/attacca.py" >&2
  exit 1
}
python3 "$ATTACCA_PLUGIN_ROOT/attacca.py" \
  --actor "CURRENT_AI_ACTOR" --actor-type "CURRENT_AI_TYPE" \
  --json setup --discover --attach "INTERNAL_PROJECT_ID"
```

## 2. Choose this AI's role

Use the current AI record from `network` internally, but show only its friendly
persona name, `@ShortName`, role, and runtime plus the current Lead Director.
Never render its raw actor ID. Then ask which role this AI should have:

- With no Lead Director on a first setup, recommend **Director + Lead Director**
  (`--role director --lead current`). Also offer **Director without
  assigning a lead**, **Advisor**, and **Worker**.
- When another Lead Director exists, recommend **Join as Director and keep
  <lead name> as Lead Director** (`--role director --lead keep`). Also offer
  **Advisor**, **Worker**, and **Replace <lead name> with this AI as Lead
  Director** (`--role director --lead current`).
- If this AI is already Lead Director, recommend keeping it as Director and
  Lead Director. Do not silently change an existing role or lead.

State the consequence beside the choices. One project-wide handoff gives every
AI the shared objective and current status; only a registered AI Director may
update it. Every registered AI also owns and may update only its own exact-
identity handoff after reporting work; it can never overwrite another named
identity's handoff. Web and console humans remain attributed operators and do
not own identity handoffs. Advisors and Workers still cannot manage Project
Rules, Cloud Context, Role Scope, or the shared project handoff. Humans and
registered Directors manage the versioned Role Scope shared by each role; the
selected Lead Director also receives the `lead_director` overlay. Shared
handoff, identity handoff, and Role Scope writes use independent optimistic
versions and stale writes must reload and reconcile.

## 3. Choose this installation's AI identity

Use `network.machine_actor_binding` and the selected role's entry in
`network.identity_options_by_role`. Internally, new durable actors have the
shape `workspace.role.runtime.persona`; do not show that string. New setup-
created actors receive human-friendly names such as **Gibbs** with short address
**@Gibbs**. The server transactionally reserves each name case-insensitively
across the entire Attacca server—every workspace, role, runtime, current
identity, and historical identity—so a new name can never be issued twice.
Setup flags grandfathered cross-workspace duplicates and offers a safe repair
that retains the old actor as an audit alias. A discovered three-part actor or an
existing Red/Blue persona is an **Existing compatibility identity**: it may be
explicitly reused, but setup never silently migrates, clones, or renames it.

Offer friendly choices:

1. When the chosen role/runtime has a valid binding, **Continue as <Role> ·
   Kimi · <Name> (@<Name>) (recommended)**.
2. For each other same-owner identity, **Take over/reuse <Role> · Kimi ·
   <Name> (@<Name>)**. State briefly that simultaneous clients reusing it share its
   identity handoff, inbox cursor, and task leases.
3. **Create permanent <next generated name> identity**. The server allocates and
   forever reserves the name atomically; `persona_name` / `short_name` from
   discovery are previews only (the first available server name is Gibbs).
4. When a valid machine binding already authorizes this running proxy, **Use
   temporary <next generated name> identity in this MCP process**. It remains
   auditable but does not replace the machine binding, so a fresh process does
   not select it automatically.

When `repair_required` is true for the bound identity, recommend repair and
apply `identity_mode=repair`. The server preserves immutable history and the
old reservation, records an alias, migrates mutable identity pointers, and
saves the unique replacement as the installation default. A healthy rerun is
a no-op.

With no binding, recommend the permanent next generated name and do not offer a
temporary identity: authenticated MCP requires an exact registered actor first.
Never infer takeover just because another Kimi actor already exists. A
first/unbound permanent setup carries the choice into the CLI as
`--identity-mode new|reuse`; reuse alone passes the discovered exact actor
through hidden `--identity-actor`, never in UI text. New saves the default.
Reuse changes only the current MCP process unless the human explicitly chooses
**Make default**; then pass `make_default=true`. A first/unbound reuse must make
that explicit choice because it has no restart-safe default. Reuse never merges,
deletes, or renames either identity.

For an explicit switch in an already-linked running Kimi client with a valid
binding, call `agent_register` through the **current Attacca MCP proxy** with
the selected `role`, current `runtime`, and `identity_mode`
(`identity_mode=temporary` for the process-only choice). For reuse, pass the
selected discovered `persona` for a named identity. A persona-less three-part
compatibility choice instead passes its exact discovered `agent_id` as a hidden
tool argument, never visible or requested as UI text. A successful permanent
`new` updates the binding; `reuse` hot-switches only this proxy unless
`make_default=true`; `temporary` hot-switches only this proxy in memory. Never
call this path during ordinary
startup/resume. If tool wiring also needs repair, run that idempotent repair
before switching so a temporary choice is not overwritten by another process.

## 4. Choose the workspace relationship

Explain that one workspace has one room and bridges connect rooms. Before
asking, show:

- relevant `network.relationship_inbox` evidence, including the named origin
  workspace, sender, authority label, and a short message summary; and
- every `network.existing_relationships` entry, with both workspace names,
  relationship, and which side is master or advisor.

Never imply that an empty inbox means no relationship. If existing
relationships are correct, let the user explicitly keep them. Otherwise, when
another workspace is available, ask which named workspace to connect. Put
`default_master_project` first when it is present, but display its name only.

For a new or changed connection, make **MASTER** the recommended/default
relationship, followed by **Peer**, **Advisor**, and **Do not add a
relationship**. For MASTER or Advisor, ask which named workspace has that
authority. Before confirmation, say the direction in full, for example:
"Workspace Design System will be MASTER; workspace Web App will follow it."
Map that decision to `--bridge`, `--relationship`, and `--principal` internally.
If there is no other workspace, say that no relationship can be configured;
do not fabricate a target.

## 5. Apply and verify once

After all choices are confirmed, build and run one shell-quoted setup command.
It contains exactly one workspace action (attach, create, or the already-linked
default), the confirmed role/identity/lead, and relationship flags only when
the user confirmed a connection. This is the first/unbound path; an explicit
in-process switch follows §3 instead:

```bash
ATTACCA_PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-${KIMI_PLUGIN_ROOT:-${KIMI_CODE_HOME:-$HOME/.kimi-code}/plugins/managed/attacca}}"
test -f "$ATTACCA_PLUGIN_ROOT/attacca.py" || {
  printf '%s\n' "Attacca plugin runtime not found: $ATTACCA_PLUGIN_ROOT/attacca.py" >&2
  exit 1
}
python3 "$ATTACCA_PLUGIN_ROOT/attacca.py" \
  --actor "CURRENT_AI_ACTOR" --actor-type "CURRENT_AI_TYPE" \
  setup WORKSPACE_ACTION \
  --role CONFIRMED_ROLE IDENTITY_FLAGS \
  --lead CONFIRMED_LEAD RELATIONSHIP_FLAGS
```

Substitute exact discovered values internally; the uppercase tokens above are
not literal values. For a permanent choice, `IDENTITY_FLAGS` is
`--identity-mode new|reuse`, plus hidden `--identity-actor` only for reuse.
`temporary` appears only in a current-proxy `agent_register` call for an
already-bound client. Never show the hidden actor value. Do not
use `-i`, because the native guided choices already collected every decision.
Setup must configure all detected tools, MCP, the
managed project instructions, and the lifecycle startup hook. Check its output
for the server URL, `.attacca/project.json`, configured tools, MCP wiring, and
the lifecycle hook. State that `.attacca/project.json` is the portable,
safe-to-commit workspace selection, while any checkout `.mcp.json` is a
machine/site-local endpoint that must be regenerated per machine. Then call
`get_handoff`, `get_identity_handoff`, `role_scope_get`, `attacca_status`,
`agent_list`, and `bridge_list` through MCP to verify the selected workspace,
shared project handoff, friendly name / `@ShortName` / role / runtime identity,
applicable Role Scope, exact AI identity handoff, role/lead, and relationship.
If the host cannot hot-reload immediately, say
exactly what remains unverified and let its native reconnect path retry; never
claim success from files alone or make restart the default recovery.

## 6. Offer conversation work as tasks

This is the final setup step, not a repository scan. Inspect the **CURRENT AI CONVERSATION**
for concrete unresolved, pending, deferred, or shelved work.
Call `task_list`, then compare candidates by intended outcome, scope, and
acceptance criteria rather than exact wording. Remove completed/resolved items,
duplicates within the conversation, and anything already represented on the
task board.

Show the remaining deduplicated candidates with short titles and one-line
scope. Ask the user exactly once which candidates to add (native multi-select
when available, or one numbered answer); include **None**. Only after that one
confirmation, call `task_create` for the selected candidates. Never silently
import, create, or claim a task, and never claim a newly created task as part
of setup. If there are no candidates, say so and make no write.

Finish with one concise report: server, Git remote/folder, workspace,
`.attacca/project.json`, friendly name / `@ShortName` / role / runtime identity, whether it is
permanently bound or current-process temporary, Lead Director, relationship
direction, tool and hook verification, MCP result, and tasks created or
skipped. Explain that another checkout connects to the same project by
confirming the same Git workspace or selecting the same named workspace on the
same server; its separate client installation then makes its own identity
choice.

$ARGUMENTS
