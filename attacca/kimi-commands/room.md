---
description: Read the workspace room, or post to it (/attacca:room <message>)
---

If $ARGUMENTS contains a message, send it once with the `room_send` Attacca
MCP tool. Use `chat` unless the user is clearly directing workers, resolve
named attention recipients through `agent_list`, and pass an explicit
destination so a local message does not fan out across every relationship.
Mentions assign attention or an expected responder; they never make a shared
room message private. An untargeted `chat` or `directive` is broadcast to
everyone in the selected room. Bridge participation and access policy define
who may read a connected-workspace copy. Confirm its room, attention
recipients, and any connected workspace copy.

With no message, call `room_read` and summarize the selected workspace room:
who is talking, what they are coordinating, authority on bridged messages,
and anything needing the user's decision. Include visible messages routed to
another participant as shared group context rather than filtering them out.
