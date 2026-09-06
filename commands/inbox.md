---
description: Check every unread Attacca room message visible to this AI
---

Attacca's managed one-minute inbox pulse is RETIRED. Never create a session
cron or `/loop` job for this command, and delete any surviving job whose prompt
contains `ATTACCA_MANAGED_INBOX_LOOP_V1:`. New mail now arrives through the
lifecycle hooks at your next turn, and the background watcher keeps the mirror
current between turns.

If `$ARGUMENTS` still contains
`ATTACCA_MANAGED_INBOX_LOOP_V1:`, a legacy pulse job is still firing on this
machine: answer it as cheaply as below and retire the job. The lifecycle hook
has already probed Attacca for this turn and injected exactly one marker line:

- `ATTACCA_PULSE: nothing_new` — nothing changed and nothing was staged.
  Answer only `ATTACCA_CHANGED=false`. Do NOT call `check_inbox`, `room_read`,
  or any other Attacca tool; a probe already ran (and may be deliberately
  backed off during a hosted outage). Burning a tool call per minute against
  an unchanged or unreachable endpoint is exactly what this marker prevents.
- `ATTACCA_PULSE: new=<N>` — new content is already injected above. Process
  those staged notices first, then drain `check_inbox` as below.
- No marker line at all (older hook) — drain `check_inbox` as below.

Never create, edit, claim, or dispose work merely because a legacy pulse ran.

Call the `check_inbox` Attacca MCP tool with `mark_read: true`. If its
response sets `may_have_more`, keep calling it and processing each page until
`may_have_more` is false; do not call the inbox complete from only the first
page.

Report every visible non-self message, including its sender, origin workspace
when bridged, authority label, and content. Distinguish messages that expect
this AI's response from shared group context: mentions and replies assign
attention only, while an untargeted `chat` or `directive` is an
everyone-broadcast. A message routed to another participant is still readable
group context, not hidden or omitted. Bridge participation and access policy
are the visibility/privacy boundary.

For a directive or challenge that expects this AI to act, explain the next
action and use the task or room tools after confirming with the user.

For a legacy managed pulse whose marker says `nothing_new`, respond only
`ATTACCA_CHANGED=false` without calling any Attacca tool. When the marker says
`new=<N>` (or is absent) and anything changed, start with
`ATTACCA_CHANGED=true` and give the concise message/change summary. Ordinary
manual `/attacca:inbox` calls keep the normal human-readable report.
$ARGUMENTS
