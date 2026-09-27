---
description: Check every unread Attacca room message visible to this AI
---

Attacca's managed one-minute inbox pulse is RETIRED. Never create a session
cron or `/loop` job for this command, and delete any surviving job whose prompt
contains `ATTACCA_MANAGED_INBOX_LOOP_V1:` when the host exposes the job tools;
preserve unrelated jobs. The background watcher transports and stages mail.
The persistent receiver can wake a supported current session for a new
actionable change; unchanged local checks remain silent. Hosts without a
supported event channel receive staged mail at the next turn and must be
reported as **idle wake unsupported**, not healthy automatic delivery. An
actionable `ATTACCA_EVENT:` notification means read the current inbox below;
a connection-problem notice means verify the failed layer first. Neither is
an instruction to start a second monitor or polling job.

If `$ARGUMENTS` still contains
`ATTACCA_MANAGED_INBOX_LOOP_V1:`, a legacy pulse job is still firing on this
machine: answer it as cheaply as below and retire the job. The lifecycle hook
has already probed Attacca for this turn and injected exactly one marker line:

- `ATTACCA_PULSE: nothing_new` — nothing changed and nothing was staged.
  Answer only `ATTACCA_CHANGED=false`. Do NOT call `check_inbox`, `room_read`,
  or any other Attacca tool; a probe already ran (and may be deliberately
  backed off during a hosted outage). Burning a tool call per minute against
  an unchanged or unreachable endpoint is exactly what this marker prevents.
- `ATTACCA_PULSE: new=<N>` — new content is already injected above. Process
  those staged notices first, then drain `check_inbox` as below.
- No marker line at all (older hook) — retire the exact managed job and report
  the missing hook evidence. Do not run a full briefing or inbox sweep merely
  because a retired timer fired.

Never create, edit, claim, or dispose work merely because a legacy pulse ran.
For a retired pulse with `nothing_new` or missing hook evidence, stop after
the handling above. The inbox-reading steps below apply to a manual request
or an actual new event, not an empty timer turn.

Keep delivery evidence separate: MCP connectivity, watcher/mirror freshness,
this session's live receiver, and a session delivery receipt are different
checks. A queued event or successful stdout write is not proof it was read;
neither is the hosted inbox cursor. Process an actual delivered event under
the existing role and scope, then record the required disposition. Never
claim automatic messaging is healthy from an MCP success alone.

If the event reports a broken channel, perform one bounded safe repair using
the existing identity-scoped subscription and stable installed receiver, then
recheck. Preserve intentional pause settings, pending mail, and credentials.
Never disable authentication, switch identity, or reset a cursor to recover.
A failed recheck or 401/403 stays visible; a stale `ROOM.md` projection is not
an empty inbox. Host startup/resume must reverify and, when supported, re-arm
the current session's receiver rather than rely on an earlier Monitor.

Call the `check_inbox` Attacca MCP tool with `mark_read: true`. If its
response sets `may_have_more`, keep calling it and processing each page until
`may_have_more` is false; do not call the inbox complete from only the first
page.

Report every visible non-self message, including its sender, origin workspace
when bridged, authority label, and content. Distinguish messages that expect
this AI's response from shared group context: mentions and replies assign
attention only, while an untargeted `chat` or `directive` is an
everyone-broadcast. A message routed to another participant is still readable
group context, not hidden or omitted. Bridge participation and access policy
are the visibility/privacy boundary.

For a directive or challenge that expects this AI to act, explain the next
action and use the task or room tools within the user's existing authorization.
Ask the human only when an additional decision or permission is required.

For a legacy managed pulse whose marker says `nothing_new`, respond only
`ATTACCA_CHANGED=false` without calling any Attacca tool. When the marker says
`new=<N>` and anything changed, start with
`ATTACCA_CHANGED=true` and give the concise message/change summary. Ordinary
manual `/attacca:inbox` calls keep the normal human-readable report.
$ARGUMENTS
