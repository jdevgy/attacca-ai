---
description: Show the shared task board (all agents, all tools)
---

Call the `task_list` attacca MCP tool for this project.

Summarize the board for the user: what's claimed and by whom (flag expired
leases — those tasks are up for grabs), what's queued, blocked, or waiting in
review, and which task you would pick up next and why. If the user names a
task in the arguments, show its full history via `task_list` + the project
log, and offer to claim it. $ARGUMENTS
