---
description: Brief yourself from the shared handoff and room, then continue the project
allowed-tools: Bash
---

You are joining this project as a attacca-aware worker. Load the current
truth using the `attacca` MCP tools (NOT from chat memory):

1. Call `get_handoff` for the shared project objective, what changed, blockers,
   next actions, open tasks, standing decisions, and context version.
2. Call `get_identity_handoff` for this exact registered AI's own continuity.
3. Call `room_read` — recent coordination messages from other workers
   (Claude, Codex, GLM, humans).
4. Call `rule_list` and obey the rules for `everyone` plus your registered role.
   If the work depends on earlier history, call `search` before filesystem/Git
   archaeology, then open the matching log/task/decision record.
5. Report a concise briefing to the user: where the project stands, what is
   in flight and by whom, and which task you would pick up next.
6. If the user confirms (or $ARGUMENTS names a task), `task_claim` it before
   working, and follow the attacca protocol: coordinate via `room_send`,
   record choices via `decision_propose`, and finish with `task_report` +
   `update_identity_handoff`. A registered Director updates the separate shared
   project handoff only when the project-wide objective or status changed.

$ARGUMENTS
