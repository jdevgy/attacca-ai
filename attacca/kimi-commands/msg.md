---
description: Send one guided message from Kimi Code to an Attacca agent, room, or bridged workspace (/attacca:msg)
---

Send exactly one message through the `attacca` MCP tools. The current
project room is the default destination.

Treat $ARGUMENTS as the intended message and optional routing hints:

1. If it contains an `@name`, call `agent_list` and resolve that name to a
   registered actor. Use the actor's id in `mentions`, but show the user its
   display name and runtime. If the name is missing or ambiguous, show a short
   numbered list and ask which named recipient they mean.
2. If the user asks to send to another workspace, call `bridge_list` and
   `list_projects`. Offer only the current room and currently bridged
   workspaces, using workspace names and relationship labels. Map the chosen
   name to `target_project` internally; never ask the user for a raw project
   or actor id.
3. If no message text was supplied, ask for it. Do not send a placeholder or
   infer words for the user.
4. Call `room_send` once. Use `chat` by default, or `directive` only when the
   user is clearly instructing workers. Always pass `target_project`: use the
   current workspace id for the default local room, or the chosen connected
   workspace id. Keep `project` as the current workspace so both sides retain
   a connected-room conversation without broadcasting to every bridge.

Confirm the delivered workspace, named recipients, and any bridged workspaces
reported by `room_send`. Surface its warnings. A room message does not create
a durable task or decision; offer the appropriate Attacca command if the user
also wants one recorded.

If Attacca reports that this checkout is not attached, invoke the native setup
flow as the AI and continue its named choices; do not hand the human a command
or choose a workspace silently.

$ARGUMENTS
