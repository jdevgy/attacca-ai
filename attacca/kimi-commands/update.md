---
description: Load a fresh full-project update from Attacca in Kimi Code (/attacca:update)
---

Before the seven reads, treat authentication, terminal-credential migration,
or a hosted 401/403 for a linked checkout as an AI-owned recovery transition.
Immediately advance the packaged browser/device enrollment flow for the exact
saved project/actor binding with browser opening enabled,
show only the verified login URL and short code, and poll in bounded steps.
Never give the human a shell command or request a password/token in chat or
`$ARGUMENTS`. Headless/no-TTY recovery stays deferred and nonblocking; the
watcher hot-reloads the private 0600 device credential and clears its latch
only after verified hosted sync. Do not force a restart.

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

Give the user one concise update, not a raw tool dump. Cover the current
objective and context version; material changes; blockers, risks, and next
actions; claimed work and its owners; queued, blocked, review, or expired
tasks; every visible non-self room message; which messages expect this actor's
response; important shared group context; and anything requiring the user's
decision. Mentions and replies route attention only; an untargeted `chat` or
`directive` is an everyone-broadcast. Do not omit a visible message merely
because it routes attention to another participant. Preserve authority labels
on bridged messages such as master directives, suggestions, and advice;
bridge participation and access policy remain the visibility boundary.
Include changed mandatory Project Rules and agent/role changes.

If $ARGUMENTS names a topic, still load the complete update but emphasize that
topic in the summary. Do not call the inbox fully refreshed until
`may_have_more` is false. This command reads state and marks the inbox read; it
does not claim work, send messages, or change the handoff.

If Attacca reports that this checkout is not attached, invoke the native setup
flow as the AI and continue its guided named choices; do not hand the human a
command or fall back to another Attacca database or workspace.

$ARGUMENTS
