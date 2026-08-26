---
name: setup
description: Run the complete guided Attacca setup flow for the current checkout. Use when the user invokes the native Attacca setup command or asks to set up, connect, choose, create, switch, or repair an Attacca workspace.
---

# Attacca guided setup

Run one complete native setup flow: `$attacca:setup` in Codex or
`/attacca:setup` in Claude Code. Use the server bundled with the installed
native plugin. Never assume the universal shell installer has also created
`~/.attacca/plugin/attacca`, start a second local server, use `init --move`,
or offer multiple setup variants.

In Claude Code, use its native choice UI for each decision. Codex has no popup
choice picker for this flow, so present a short numbered list and ask the user
to type a number or displayed name. Keep exact project and actor ids from
discovery only as internal arguments; never display, invent, or ask for a raw
id.

## 0. Resolve the runtime and authenticate before MCP

Resolve the exact installed runtime **before any Attacca MCP call**. In Claude Code,
evaluate `$CLAUDE_PLUGIN_ROOT/attacca.py` and require that file to exist. In
Codex, run `codex mcp get attacca --json` and inspect `transport`: prefer the
existing absolute `attacca.py` argument in `transport.args`; otherwise use
`transport.cwd/attacca.py` when it exists. Codex may fall back to
`~/.attacca/plugin/attacca/attacca.py` only when that file actually exists.
Store the verified absolute path internally as `ATTACCA_RUNTIME`. If no
runtime-specific candidate is a file, stop with the native plugin/MCP
diagnostics instead of guessing a path. Use this same resolved runtime for
**every** CLI call below.

Use the host runtime as the initial private actor hint (`codex`, `claude`, or
`kimi`) with actor type `agent`. The AI runs the first authentication preflight
itself, never an unscoped `list_projects` MCP call and never a command delegated
to the human:

```bash
python3 "ATTACCA_RUNTIME" \
  --actor "RUNTIME_HINT" --actor-type agent \
  --json setup --discover
```

The CLI checks the public `/v1/auth/status` before workspace discovery. If it
succeeds, call MCP `list_projects` and keep `you.actor_id` / `you.actor_type`
internally as `CURRENT_AI_ACTOR` / `CURRENT_AI_TYPE`; pass them to every later
CLI call so actions belong to this AI, not the shell user.

If the server needs its first admin, the AI opens the displayed `/app` URL and
asks the human only to create or authenticate the account there. On an enforced
server with a brand-new/unlinked checkout, the AI starts the packaged
`terminal_flow.py` browser/device flow with an explicit zero-binding request.
The owner/admin approves it in the browser with empty memberships and actor
bindings. The helper polls and stores that device credential as a provisional
human setup principal; it cannot authorize AI/sync writes or select an actor.

The 0600 credential—not a browser cookie—persists across the separate discovery
and apply processes. Those processes may use it only as the authenticated human
to list/create a workspace, establish membership, and register the explicitly
confirmed actor and role. After that exact actor exists, the AI authenticates
`POST /v1/auth/terminals/{token_id}/bindings` with the same device credential,
adds `{project_id, actor_id}`, refreshes its saved no-secret metadata, and only
then retries as that AI. A non-admin approval must select an existing membership.
If provisional setup is abandoned, the owner can revoke it in Settings. A
hidden existing-terminal-credential fallback is allowed only through a verified
controlling TTY. Compatibility mode may do the initial setup anonymously, then
initiate exact-binding enrollment at the end.

This is an internal tool action: never show the human a recovery shell command
and never ask them to run setup again. Display only the server-verified login
URL and short device code. Poll in bounded steps while lifecycle hooks and the
watcher keep retrying; a headless browser failure remains deferred and
nonblocking. On a 401/403, the AI itself initiates or resumes this browser/device
recovery and retries only after verified hosted identity sync.

Passwords, API tokens, and the high-entropy device code never enter chat, tool
arguments, process arguments, or logs. Browser approval is the universal path
for Codex, Claude, and Kimi. Claude's native choice UI may select non-secret
options, but authentication still stays in the browser. A hidden paste fallback
is allowed only when the helper proves it owns a real foreground controlling
TTY; otherwise keep the browser flow. The helper atomically stores one 0600,
device-bound terminal credential per full server URL. That credential belongs
to the human/device and may select multiple server-approved existing AI actors;
it never changes their ledger identity.

After approval, retry MCP and watcher sync in the current host. Hot-reload the
credential and clear the authentication latch only after a verified hosted
identity sync; do not force a client restart. The native discovery and apply
processes remain separate; only the privately stored provisional terminal
credential crosses that boundary, so never claim a temporary login session
carries between them. Do not repeat Steps 1-4 after an already completed setup; continue
at verification and Step 5. Cached offline data is never authenticated recovery.

## 1. Select the workspace

Start with read-only discovery:

```bash
python3 "ATTACCA_RUNTIME" \
  --actor "CURRENT_AI_ACTOR" --actor-type "CURRENT_AI_TYPE" \
  --json setup --discover
```

Report the detected Git remote or local folder and any stale link. Then:

- `already_linked`: name the workspace and continue without selecting it
  again.
- `confirm_git_match` or `confirm_folder_match`: list **Use this workspace
  (recommended)** first and **Choose another** second. Require confirmation.
- `choose_or_create`: list every workspace by name, then **Create a new
  workspace**.
- `create_first_workspace`: explain that none exists and recommend
  `suggested_new_name`, which the user may accept or edit.

Do not write yet. If the user selected an existing workspace other than the
one represented by `network.workspace_id`, load its governance context with a
second read-only discovery call, using its exact internal id:

```bash
python3 "ATTACCA_RUNTIME" \
  --actor "CURRENT_AI_ACTOR" --actor-type "CURRENT_AI_TYPE" \
  --json setup --discover --attach "INTERNAL_PROJECT_ID"
```

## 2. Choose this AI's role

Show `network.current_actor_record` and the current Lead Director before the
role question.

- On a first setup with no lead, default to **Director + Lead Director**
  (`--role director --lead current`). Also list Director without assigning a
  lead, Advisor, and Worker.
- If another lead exists, default to **Join as Director and keep <lead name> as
  Lead Director** (`--role director --lead keep`). Also list Advisor, Worker,
  and Replace the lead with this AI (`--role director --lead current`).
- If this AI is already the lead, recommend keeping it Director and Lead
  Director. Never silently change an existing role or lead.

Label Advisor and Worker clearly: those roles cannot update the shared
handoff, so they report with `task_report` and `room_send`. Directors can write
the handoff, but writes are version-checked against the context version from
`get_handoff`; a stale director must reload and reconcile before retrying.

## 3. Choose the workspace relationship

Explain that one workspace has one room and bridges connect rooms. Before the
relationship question, show named evidence from
`network.relationship_inbox`—origin workspace, sender, authority, summary—and
show every `network.existing_relationships` entry with both workspace names,
relationship, and master/advisor side. An empty inbox is not proof that no
relationship exists.

Let the user explicitly keep correct existing relationships. Otherwise list
available workspace names, placing `default_master_project` first when set.
For a new or changed connection, list:

1. MASTER (recommended/default)
2. Peer
3. Advisor
4. Do not add a relationship

For MASTER or Advisor, ask which workspace has authority. Before applying it,
state the direction with names, for example: "Workspace Design System will be
MASTER; workspace Web App will follow it." Map the selected names internally
to `--bridge`, `--relationship`, and `--principal`. If no other workspace
exists, explain that a relationship cannot be configured rather than
inventing a target.

## 4. Apply and verify once

After confirmation, build one shell-quoted command containing exactly one
workspace action (attach, create, or already-linked default), the selected
role and lead flags, and only confirmed relationship flags:

```bash
python3 "ATTACCA_RUNTIME" \
  --actor "CURRENT_AI_ACTOR" --actor-type "CURRENT_AI_TYPE" \
  setup WORKSPACE_ACTION \
  --role CONFIRMED_ROLE --lead CONFIRMED_LEAD RELATIONSHIP_FLAGS
```

Replace all uppercase tokens, including `ATTACCA_RUNTIME`, with their exact
internally resolved values; they are not literal arguments. Do not use `-i`,
because this guided flow already obtained typed choices.

Setup must configure all detected coding tools, MCP, managed instructions, and
the lifecycle startup hook. Inspect its result for server URL,
`.attacca/project.json`, tool/MCP wiring, and the hook. State that
`.attacca/project.json` is the portable, safe-to-commit workspace selection;
any checkout `.mcp.json` is a machine/site-local endpoint that must be
regenerated per machine. Then re-brief and verify
through MCP with `get_handoff`, `attacca_status`, `agent_list`, and
`bridge_list`. `get_handoff` is required here because role, lead, and
relationship choices may have advanced the context version; it makes later
Director writes use the new version instead of an obsolete pre-setup briefing.
If the current MCP host cannot hot-reload the new connection, report the exact
unverified checks and let its native reconnect mechanism run; never infer
success from configuration files and never make restart the default recovery.

## 5. Offer conversation work as tasks

Finally inspect the **CURRENT AI CONVERSATION**—not the repository—for
concrete unresolved, pending, deferred, or shelved work. Call `task_list` and
compare by outcome, scope, and acceptance criteria. Exclude completed work,
deduplicate overlapping conversation items, and remove candidates already
represented on the board.

Show each remaining candidate as a numbered title plus one-line scope. Ask
once: type `all`, `none`, or comma-separated numbers to choose what to add.
Only after that one answer, call `task_create` for selected candidates. Never
silently import, create, or claim work, and never claim newly created tasks as
part of setup. With no candidates, report that and make no write.

Finish with a concise summary of the server, Git remote/folder, workspace,
project link, role/lead, relationship direction, tool/MCP/hook verification,
and tasks created or skipped. Another checkout joins the same project by
confirming the same Git workspace or selecting the same named workspace on the
same server.
