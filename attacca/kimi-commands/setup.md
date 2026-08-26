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
raw id. Treat $ARGUMENTS as preferences, not permission to skip confirmation.

## 0. Resolve the runtime and authenticate before MCP

Do not call unscoped `list_projects` first: an authenticated server correctly
rejects it when this machine has no credential. Resolve the bundled runtime
before any Attacca MCP call and verify `attacca.py` exists. If that fails, stop
and report the missing plugin runtime instead of searching for or starting a
second Attacca copy. Set the private runtime hint to `claude` in Claude Code or
`kimi` in Kimi Code, with actor type `agent`.

Run the setup CLI discovery yourself as the first remote preflight. It calls
the public authentication status before any protected workspace request; never
delegate a recovery command to the human:

```bash
ATTACCA_PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-${KIMI_PLUGIN_ROOT:-${KIMI_CODE_HOME:-$HOME/.kimi-code}/plugins/managed/attacca}}"
test -f "$ATTACCA_PLUGIN_ROOT/attacca.py" || exit 1
python3 "$ATTACCA_PLUGIN_ROOT/attacca.py" \
  --actor "RUNTIME_HINT" --actor-type agent --json setup --discover
```

When that succeeds, call MCP `list_projects`; keep `you.actor_id` and
`you.actor_type` internally as `CURRENT_AI_ACTOR` and `CURRENT_AI_TYPE` and
pass both to later setup CLI calls. They identify the actual Claude/Kimi AI,
not the shell account such as `vscode`.

If the server needs its first owner, open the displayed `/app` URL and ask the
human only to create or sign in to that account in the browser. On a 401/403,
Kimi itself starts the packaged `terminal_flow.py authorize` helper in the
active terminal; never give the human a recovery command. The helper opens
Attacca Settings with the exact non-secret client-install ID filled in. The
signed-in human creates one `atkey_` API key for that installation, optionally
limits its workspace memberships, and pastes it only into the helper's hidden
foreground-terminal prompt. Never accept the key in chat, `$ARGUMENTS`, argv,
a URL, logs, or ordinary stdin. With no controlling TTY, leave authorization
deferred and nonblocking while the lifecycle hook retries.

The helper verifies the key and atomically stores it in the private 0600
credentials file. It belongs to the authenticated human and one client
installation—not to Kimi, Claude, Codex, any actor, or any role. Every project
request separately sends the exact workspace and canonical actor; the server
checks membership, actor ownership, and the actor's registered role. The key
persists across discovery and apply so Kimi can finish the explicitly confirmed
workspace, actor, and role setup. Browser cookies never cross into the CLI.

After authorization, hot-reload and retry MCP/watcher sync in this same client.
Clear the latch only after verified hosted sync; do not force a restart, alter
the established actor identity, or repeat completed Steps 1-4. Cached offline
data never authorizes recovery.

## 1. Select the workspace

Run read-only discovery first:

```bash
ATTACCA_PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-${KIMI_PLUGIN_ROOT:-${KIMI_CODE_HOME:-$HOME/.kimi-code}/plugins/managed/attacca}}"
test -f "$ATTACCA_PLUGIN_ROOT/attacca.py" || {
  printf '%s\n' "Attacca plugin runtime not found: $ATTACCA_PLUGIN_ROOT/attacca.py" >&2
  exit 1
}
python3 "$ATTACCA_PLUGIN_ROOT/attacca.py" \
  --actor "CURRENT_AI_ACTOR" --actor-type "CURRENT_AI_TYPE" \
  --json setup --discover
```

Report the detected Git remote or local folder and any stale project link.
Then resolve `action` conversationally:

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

Show the current AI record and current Lead Director from `network` before
asking. Ask which role this AI should have:

- With no Lead Director on a first setup, recommend **Director + Lead Director**
  (`--role director --lead current`). Also offer **Director without
  assigning a lead**, **Advisor**, and **Worker**.
- When another Lead Director exists, recommend **Join as Director and keep
  <lead name> as Lead Director** (`--role director --lead keep`). Also offer
  **Advisor**, **Worker**, and **Replace <lead name> with this AI as Lead
  Director** (`--role director --lead current`).
- If this AI is already Lead Director, recommend keeping it as Director and
  Lead Director. Do not silently change an existing role or lead.

State the consequence beside the choices: workers and advisors cannot update
the shared handoff; they report through `task_report` and `room_send` instead.
Directors may update it, but director handoff writes are version-checked
against the context version from `get_handoff`; stale writes must reload and
reconcile first.

## 3. Choose the workspace relationship

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

## 4. Apply and verify once

After all choices are confirmed, build and run one shell-quoted setup command.
It contains exactly one workspace action (attach, create, or the already-linked
default), the confirmed `--role` and `--lead`, and relationship flags only when
the user confirmed a connection:

```bash
ATTACCA_PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-${KIMI_PLUGIN_ROOT:-${KIMI_CODE_HOME:-$HOME/.kimi-code}/plugins/managed/attacca}}"
test -f "$ATTACCA_PLUGIN_ROOT/attacca.py" || {
  printf '%s\n' "Attacca plugin runtime not found: $ATTACCA_PLUGIN_ROOT/attacca.py" >&2
  exit 1
}
python3 "$ATTACCA_PLUGIN_ROOT/attacca.py" \
  --actor "CURRENT_AI_ACTOR" --actor-type "CURRENT_AI_TYPE" \
  setup WORKSPACE_ACTION \
  --role CONFIRMED_ROLE --lead CONFIRMED_LEAD RELATIONSHIP_FLAGS
```

Substitute exact discovered values internally; the uppercase tokens above are
not literal values. Do not use `-i`, because the native guided choices already
collected every decision. Setup must configure all detected tools, MCP, the
managed project instructions, and the lifecycle startup hook. Check its output
for the server URL, `.attacca/project.json`, configured tools, MCP wiring, and
the lifecycle hook. State that `.attacca/project.json` is the portable,
safe-to-commit workspace selection, while any checkout `.mcp.json` is a
machine/site-local endpoint that must be regenerated per machine. Then call
`get_handoff`, `attacca_status`, `agent_list`,
and `bridge_list` through MCP to verify the selected workspace, current AI
role/lead, and relationship. `get_handoff` refreshes the context version after
the governance changes so a later Director handoff does not write from the
obsolete pre-setup briefing. If the host cannot hot-reload immediately, say
exactly what remains unverified and let its native reconnect path retry; never
claim success from files alone or make restart the default recovery.

## 5. Offer conversation work as tasks

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
`.attacca/project.json`, role and Lead Director, relationship direction, tool
and hook verification, MCP result, and tasks created or skipped. Explain that
another checkout connects to the same project by confirming the same Git
workspace or selecting the same named workspace on the same server.

$ARGUMENTS
