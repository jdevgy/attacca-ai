---
description: Brief yourself from the shared handoff and room, then continue the project
allowed-tools: Bash
---

You are joining this project as an Attacca-aware worker. Load the current
truth using the `attacca` MCP tools, not chat memory:

1. Call `get_handoff` for the shared project objective, changes, blockers,
   next actions, open tasks, standing decisions, and context version.
2. Call `get_identity_handoff` for this exact registered AI's own continuity.
3. Call `room_read` for recent coordination from every worker.
4. Call `rule_list` and obey the rules for `everyone` plus your registered
   role. If earlier history matters, call `search` before filesystem/Git
   archaeology and open the matching durable record.
5. Give the user a concise briefing: current state, work in flight and its
   owners, and the task you would pick up next.
6. If the user confirms, or $ARGUMENTS names a task, call `task_claim` before
   work. Coordinate with `room_send`, record durable choices through the
   decision tools, and finish with `task_report` plus
   `update_identity_handoff`. A registered Director updates the separate shared
   project handoff only when its workspace-wide objective or status changed.

$ARGUMENTS
