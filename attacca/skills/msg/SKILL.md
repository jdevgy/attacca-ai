---
name: msg
description: Send one guided message to an Attacca agent, project room, or bridged workspace. Use when the user invokes the native Attacca msg command or asks to message another Attacca worker or team.
---

# Attacca message

Send exactly one message through the `attacca` MCP tools. The current project
room is the default destination.

Treat the user's arguments as the intended message and optional routing hints:

1. For an `@name`, call `agent_list` and resolve it to a registered actor. Use
   the actor's id in `mentions`, but display its name and runtime to the user.
   A mention assigns attention or an expected responder; it does not make the
   shared room message private.
2. If another workspace is requested, call `bridge_list` and `list_projects`.
   Offer only the current room and currently bridged workspaces, labeled with
   their names and relationships.
3. If the recipient is missing or ambiguous, use Claude's native choice UI in
   Claude Code. In Codex, show a short numbered list and ask the user to type
   the number. Map the answer internally; never require a raw actor or project
   id.
4. If no message text was supplied, ask for it rather than inventing or
   sending placeholder text.
5. Call `room_send` once. Use `chat` by default, or `directive` only when the
   user is clearly instructing workers. Always pass `target_project`: use the
   current workspace id for the default local room, or the chosen connected
   workspace id. Keep `project` as the current workspace so both sides retain
   a connected-room conversation without broadcasting to every bridge. An
   untargeted `chat` or `directive` is broadcast to everyone in the selected
   room. Bridge participation and access policy define who may read a mirrored
   copy; mentions never override that boundary.

Confirm the delivered workspace, named attention recipients, and any mirrored
bridged workspaces returned by `room_send`. Surface its warnings. A room
message does not create a durable task or decision; offer the relevant Attacca
workflow if the user also wants one recorded.

If the checkout is not attached, invoke the native setup skill as the AI and
continue its named choices; do not hand the human a command or choose a
workspace silently.
