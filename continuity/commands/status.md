---
description: Show continuity status for this project (handoff, tasks, room, context version)
allowed-tools: Bash
---

Current continuity state:

!`python3 ${CLAUDE_PLUGIN_ROOT}/continuity.py --json status 2>&1`

Recent project log:

!`python3 ${CLAUDE_PLUGIN_ROOT}/continuity.py log -n 15 2>&1`

Summarize the project state for the user in a few sentences: context version, open/claimed tasks, pending decisions, recent activity, and anything that needs their attention. If the output says the project is unknown, call any continuity MCP tool (e.g. continuity_status) once — the server auto-registers the project on first contact — then re-run this command.
