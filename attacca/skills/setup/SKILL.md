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

## FAST PATH — this is a DECISION flow, NOT a thinking job

Setup is: pick a workspace, pick a role, apply. Do it fast. Do NOT investigate,
audit, narrate reasoning, weigh trade-offs, or run extra commands. The single
`setup --discover` call already returns everything you need.

On invocation, do exactly this:
1. Run `setup --discover` **once** (one command). Nothing before it.
2. **Immediately** present the decisions in a **single** native choice-UI call
   (Claude Code AskUserQuestion): put the workspace choice and the role choice
   in the **same** call (add the relationship question only if a bridge
   decision is actually pending). Do not write prose between discovery and the
   popup — go straight to the popup.
3. Apply the confirmed choices in **one** `setup …` command, then one short
   confirmation line.

Budget: ~2 commands + 1 popup. If discovery shows a valid credential and an
already-linked/obvious workspace, skip straight to the role choice (or straight
to apply if the role is already set). If auth is needed, surface the one link
from the CLI and stop — do not loop or advise. Never spend a turn "thinking"
about setup; if you catch yourself investigating, stop and show the popup.

The sections below are REFERENCE for the exact CLI arguments and edge cases —
consult them only as needed to fill in a choice; they are not a script to
narrate step by step.

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

If the server needs its first owner, the AI opens the displayed `/app` URL and
asks the human only to create or sign in to that account in the browser. If a
401/403 says this installation needs a credential, the AI itself starts the
packaged `terminal_flow.py authorize` flow in its active terminal. Never tell
the human to run a command. The helper opens a short-lived, non-secret Attacca
Settings link for this exact `client_instance`. The human signs in, reviews the
client and optional workspace scope, and explicitly selects **Authorize** or
**Deny**. The helper polls silently; after approval the server delivers the
one-time credential directly to that installation, stores it atomically in the
private 0600 credentials file, and reconnects MCP/watcher automatically. Never
ask anyone to create, copy, reveal, or paste an API key. If the browser cannot
open, show the safe link and leave lifecycle hooks polling nonblockingly.
The credential is human-owned and may be used by Claude, Codex, Kimi, or a
generic MCP client only from that one installation. It is **not** bound to an
AI model, runtime, actor, or role. Every project request still sends the exact
`X-Attacca-Project` and canonical `X-Attacca-Actor`; the server independently
checks the human's workspace access, that the registered actor belongs to that
human, and the actor's registered role. Reuse the key only for sessions that
resolve to the same `client_instance`; a distinct client installation or
configuration root gets its own key even when it opens the same checkout or
runs the same AI runtime. Never rewrite actor identity during auth repair.

The private key persists across the separate discovery and apply processes, so
the AI can list or create an allowed workspace, register the explicitly chosen
actor and role, and then retry as that actor. Browser cookies remain browser
only. On success, hot-reload the credential in the current client, run a fresh
hosted status/sync check, and clear the authentication latch; do not force a
restart or ask the human to rerun setup. Cached offline data is never proof of
authentication. Do not repeat Steps 1-4 after setup is already complete;
continue at verification and Step 5.

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

## 5. Offer project migration into Attacca

Read `migration_sources` from discovery (Step 1). If it is non-empty—or the
checkout otherwise has substantial prior history (a `docs/LOG.md`, CHANGELOG,
ADRs, or a long-lived README of decisions)—offer to migrate it so Attacca
becomes the authoritative source of truth. Ask once, using the client's choice
UI: "This project has existing history (for example `docs/LOG.md`). Migrate it
into Attacca now—archive it, and populate Cloud Context, Core Rules, decisions,
and tasks?" with **Yes (recommended)** and **No, not now**.

Only on an explicit Yes: call `migration_directive` to fetch the server-side
directive (it is bundled with the binary, not the managed block) and follow it
exactly—archive each detected source to `*.archive.md` with a historical-only
header, transfer its records, then `cloud_context_set` the project context,
`rule_create` the consolidated Core Rules, and record decisions/tasks. Writing
Cloud Context and Rules requires a human or registered Director, so confirm this
AI's role first (from Step 2); if it is not a Director, have the human run it or
promote the AI. Never write the migrated project context into the managed
AGENTS.md/CLAUDE.md block. On No, make no write and continue.

## 6. Offer conversation work as tasks

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
