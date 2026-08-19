---
description: Read the project room, or post to it (/continuity:room <message to send>)
---

If arguments were given, post them to the project room with the `room_send`
continuity MCP tool (msg_type `chat`, or `directive` if the user is clearly
instructing the workers; mention specific actors with `mentions` when the
message is addressed to someone). Then confirm what was sent and to whom —
including any bridged projects it mirrored to.

If no arguments were given, call `room_read` and summarize the recent
conversation for the user: who is talking (Claude, Codex, GLM, humans —
across every tool), what they are coordinating on, and anything that needs
the user's decision.

$ARGUMENTS
