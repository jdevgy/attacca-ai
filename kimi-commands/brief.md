---
description: Brief yourself from the shared handoff and room, then continue the project
allowed-tools: Bash
---

You are joining this project as an Attacca-aware worker. Load the current
truth using the `attacca` MCP tools, not chat memory:

1. Call `get_handoff` for the objective, changes, blockers, next actions,
   open tasks, standing decisions, and context version.
2. Call `room_read` for recent coordination from every worker.
3. Call `rule_list` and obey the rules for `everyone` plus your registered
   role. If earlier history matters, call `search` before filesystem/Git
   archaeology and open the matching durable record.
4. Give the user a concise briefing: current state, work in flight and its
   owners, and the task you would pick up next.
5. If the user confirms, or $ARGUMENTS names a task, call `task_claim` before
   work. Coordinate with `room_send`, record durable choices through the
   decision tools, and finish with `task_report` plus a Director handoff when
   the role permits it.

$ARGUMENTS
