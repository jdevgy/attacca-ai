---
name: update
description: Load a fresh, complete Attacca project update. Use when the user invokes the native Attacca update command or asks to refresh the handoff, inbox, room, tasks, and current project status together.
---

# Attacca project update

Before the seven reads, treat a hosted 401/403 as an AI-owned authorization
transition. The AI itself starts the packaged client-key authorization helper
in its active terminal; never give the human a shell command. The helper opens
a short-lived, non-secret Attacca Settings link for this exact installation.
The human signs in, reviews the optional workspace scope, and explicitly
selects **Authorize** or **Deny**. The helper polls silently, receives and
atomically stores the one-time human-owned credential, then the watcher
hot-reloads it and retries hosted sync without a client restart. Never ask the
human to create, copy, reveal, or paste an API key. The key authenticates the installation only; every request must still
send the saved workspace and exact canonical actor so role and human
attribution remain server-validated. A headless/no-TTY host stays deferred and
nonblocking while lifecycle hooks retry.

Refresh the current project's shared state through the `attacca` MCP tools.
Call all seven, even if the SessionStart brief already ran:

1. `get_handoff`
2. `check_inbox` with `mark_read: true`; process every returned page and keep
   calling while `may_have_more` is true
3. `room_read`
4. `task_list`
5. `attacca_status`
6. `agent_list`
7. `rule_list`

Return one concise update rather than raw tool output. Include the objective
and context version; material changes; blockers, risks, and next actions;
claimed work and its owners; queued, blocked, review, or expired tasks;
every visible non-self room message; which messages expect this actor's
response; important shared group context; and anything requiring the user's
decision. Mentions and replies route attention only; an untargeted `chat` or
`directive` is an everyone-broadcast. Do not omit a visible message merely
because it routes attention to another participant. Preserve authority labels
on bridged messages such as master directives, suggestions, and advice;
bridge participation and access policy remain the visibility boundary.
Include any changed mandatory Project Rules and agent/role changes.

If the user names a topic, still load the full update and emphasize that topic
in the summary. Do not call the inbox fully refreshed until `may_have_more` is
false. This workflow reads state and marks the inbox read; it does not claim
work, send messages, or change the handoff.

If the checkout is not attached, invoke the native Attacca setup skill as the
AI and continue its guided named choices; do not hand the human a command and
do not fall back to another Attacca database or workspace.
