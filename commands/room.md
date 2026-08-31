---
description: Read the project room, or post to it (/attacca:room <message to send>)
---

If arguments were given, post them to the project room with the `room_send`
attacca MCP tool (msg_type `chat`, or `directive` if the user is clearly
instructing the workers). Use `mentions` to assign a specific participant's
attention or expected response, never to make a room message private. An
untargeted `chat` or `directive` is broadcast to everyone in that room. Choose
an explicit `target_project` for cross-project delivery; bridge participation
and access policy, not mentions, define who may read the mirrored copy. Then
confirm the room, attention recipients, and any bridged project it mirrored
to.

If no arguments were given, call `room_read` and summarize the recent
conversation for the user: who is talking (Claude, Codex, GLM, humans —
across every tool), what they are coordinating on, and anything that needs
the user's decision. Include visible messages routed to another participant
as shared group context rather than filtering them out.

$ARGUMENTS
