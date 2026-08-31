---
name: attacca-session
description: Load authoritative Attacca project state and enforce its coordination protocol at Kimi session startup or resume.
---

# Attacca session startup

Complete this startup before handling the user's request. The plugin skill is
the Kimi-native SessionStart path; do not run a raw `SessionStart` or
`SessionHeartbeat` hook.

## Load the authoritative snapshot

Call Attacca's unscoped `list_projects` tool first. For a linked checkout, call
all of these MCP tools before other work:

1. `get_handoff`
2. `check_inbox` with `mark_read: true`; process every returned page and keep
   calling while `may_have_more` is true
3. `room_read`
4. `task_list`
5. `attacca_status`
6. `agent_list`
7. `rule_list`

Call `agent_list` after the earlier project calls auto-register the effective
MCP actor, then call `rule_list` so rules are filtered by its real role. Treat
this snapshot as authoritative instead of rediscovering the repository from
prior chat memory.

If project-scoped calls report no selected workspace, a missing saved
workspace, or a stale checkout link, offer the single complete setup entry
`/attacca:setup`. Use named choices and explicit confirmation; never ask for a
raw workspace or actor id. If the server or MCP connection is unavailable,
stop and report that failure instead of using another Attacca database or
pretending the inbox is empty.

## Finish first-run AI role setup

Compare `attacca_status.you.actor_id` with its exact `agent_list` record. When
`you.actor_type` is `agent` and the record has no role other than `director`,
`advisor`, or `worker`, invoke `/attacca:setup` before the user's request.

The checkout is already linked in this case: workspace selection is finished.
The user must explicitly choose this AI's role; do not silently register or
assign it and do not ask for raw ids.

- With no Lead Director, recommend **Director + Lead Director**.
- With another Lead Director, recommend **Join as another Director and keep
  the existing Lead Director**.

Keep the same setup flow running through relationship choices, detected tool
and MCP wiring, lifecycle verification, and the explicit conversation
task-import review. An already configured Director, Advisor, or Worker needs no
role prompt.

## Follow the managed project protocol

- Project Rules scoped to `everyone` plus this AI's registered role are
  binding. Reload them after context drift and every automatic refresh.
- When work depends on what happened, why, or who did it, call `search` with
  relevant terms before filesystem/Git archaeology; follow with
  `get_project_log`, `task_show`, or the matching durable record.
- Before writes, honor current claims. Claim an existing task or create then
  claim one, declaring the expected file scope; coordinate any overlap in the
  room first.
- Announce intent and questions with `room_send`, and use `room_read` for
  replies. Read every visible non-self inbox message. Mentions and replies
  assign attention or an expected responder only; they do not hide the message
  from other room participants. An untargeted `chat` or `directive` is an
  everyone-broadcast. Keep messages routed to another participant as shared
  group context. Bridge participation and access policy are the privacy
  boundary. Honor `[MASTER-DIRECTIVE]` for its expected responder, or for
  everyone when broadcast; `[SUGGESTION]` and `[ADVICE]` are input, not orders.
- Record durable choices with `decision_propose` and `decision_resolve`, not
  only in chat.
- On `stale_context_warning`, reload `get_handoff` before another write.
- At session end, call `task_report` with evidence. Directors then update the
  canonical handoff with objective, changes, active work, blockers, risks, and
  next actions; Advisors and Workers report through the task and room instead
  of attempting a director-only handoff update.

The machine-global background watcher polls shared changes every minute
by default even while Kimi is idle and queues them durably. Inline
`UserPromptSubmit` and `Stop` hooks inject that queue at the next supported turn
boundary; setup and SessionStart also ensure the watcher is still running.
