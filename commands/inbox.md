---
description: Check every unread Attacca room message visible to this AI
---

If `$ARGUMENTS` contains
`ATTACCA_MANAGED_INBOX_LOOP_V1:`, this invocation is Attacca's managed
one-minute Claude pulse. Process any watcher-staged Attacca notices already
injected into this turn first, then perform the same read-only inbox drain
below without asking for confirmation. Never create, edit, claim, or dispose
work merely because the pulse ran.

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

For a managed pulse with no staged or hosted change, respond only
`ATTACCA_CHANGED=false`. When anything changed, start with
`ATTACCA_CHANGED=true` and give the concise message/change summary. Ordinary
manual `/attacca:inbox` calls keep the normal human-readable report.
$ARGUMENTS
