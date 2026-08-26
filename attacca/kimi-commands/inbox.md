---
description: Check every unread Attacca room message visible to this AI
---

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
