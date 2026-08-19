---
description: Brief yourself from the shared handoff and room, then continue the project
allowed-tools: Bash
---

You are joining this project as a attacca-aware worker. Load the current
truth using the `attacca` MCP tools (NOT from chat memory):

1. Call `get_handoff` — objective, what changed, blockers, next actions,
   open tasks, standing decisions, context version.
2. Call `room_read` — recent coordination messages from other workers
   (Claude, Codex, GLM, humans).
3. Report a concise briefing to the user: where the project stands, what is
   in flight and by whom, and which task you would pick up next.
4. If the user confirms (or $ARGUMENTS names a task), `task_claim` it before
   working, and follow the attacca protocol: coordinate via `room_send`,
   record choices via `decision_propose`, and finish with `task_report` +
   `update_handoff`.

$ARGUMENTS
