---
description: Interactive continuity setup — identity, other AI tools, projects and inter-project relationships
allowed-tools: Bash
---

Walk the user through continuity setup conversationally. Claude Code itself
needs no wiring (this plugin already connects it, and the server auto-registers
projects on first contact). Ask them, one at a time:

1. **Identity** — "What should the logs call you?" Every ledger entry and
   agent gets tagged with this owner name, and agent ids become
   `<you>.<agent>` so two people's `claude_director`s can never collide.
2. **Other AI tools** — wire Codex / Cline / Cursor / Windsurf / Gemini /
   VS Code / opencode into this project's continuity? (auto-detected; global
   configs get a one-time backup). Any to skip?
3. **More projects** — other folders to register as projects?
4. **Bridges** — link this project's AI team with another project's? For
   each: what relationship — **equal peers**, one side the **boss**
   (its directors' messages arrive tagged [MASTER]; the other side can only
   suggest), or one side an **advisor** (its messages arrive as advice)?

Then execute with Bash (never run bare `setup -i`; pass their answers as flags):

- Identity: `python3 ${CLAUDE_PLUGIN_ROOT}/continuity.py setup --no-server --skip-tools all --owner "NAME"`
- Tools: append `--skip-tools x,y` (or drop the flag to wire all detected)
- Extra project: `python3 ${CLAUDE_PLUGIN_ROOT}/continuity.py init PATH`
- Bridge: `python3 ${CLAUDE_PLUGIN_ROOT}/continuity.py bridge add OTHER [--boss PROJECT_ID | --advisor PROJECT_ID]`

Finally summarize: identity set, project + root, tools configured/skipped,
bridges + relationships created, and that they can watch it all live with
`python3 ${CLAUDE_PLUGIN_ROOT}/continuity.py room tail`.

$ARGUMENTS
