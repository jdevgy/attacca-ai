---
description: Check every unread Attacca room message visible to this AI
---

Attacca's managed one-minute inbox pulse is RETIRED. Never create a session
cron or `/loop` job for this command, and delete any surviving job whose prompt
contains `ATTACCA_MANAGED_INBOX_LOOP_V1:`. New mail arrives through the
lifecycle hooks at your next turn and the background watcher keeps the mirror
current between turns.

If `$ARGUMENTS` still contains `ATTACCA_MANAGED_INBOX_LOOP_V1:`, a legacy pulse
job is still firing and the lifecycle hook has already probed Attacca for this
turn:

- `ATTACCA_PULSE: nothing_new` in this turn's injected context means nothing
  changed. Answer only `ATTACCA_CHANGED=false` and call no Attacca tool; the
  probe already ran and may be backed off during a hosted outage.
- `ATTACCA_PULSE: new=<N>`, or no marker line at all, means you must drain
  `check_inbox` below and report with `ATTACCA_CHANGED=true` when anything
  changed. Never create, edit, claim, or dispose work merely because a legacy
  pulse ran.

Call the `check_inbox` Attacca MCP tool with `mark_read: true`. If the response
sets `may_have_more`, keep calling it and processing every page until
`may_have_more` is false; do not call the inbox complete from only the first
page.

Report every visible non-self message with its sender, origin workspace when
bridged, authority label, and content. Distinguish messages that expect this
AI's response from shared group context: mentions and replies assign attention
only, while an untargeted `chat` or `directive` is an everyone-broadcast. A
message routed to another participant remains readable group context. Bridge
participation and access policy are the visibility/privacy boundary.

For a directive or challenge that expects this AI to act, explain the next
action and use Attacca's task and room tools after user confirmation.
$ARGUMENTS
