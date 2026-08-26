---
description: Check every unread Attacca room message visible to this AI
---

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
$ARGUMENTS
