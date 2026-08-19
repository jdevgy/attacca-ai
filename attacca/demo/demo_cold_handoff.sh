#!/usr/bin/env bash
# North-star demo (blueprint §31, minus crypto):
#   Session A — "Claude Director" changes an API, records the decision, reports
#   the task and updates the handoff.
#   Session B — a completely fresh worker ("Codex Director") on another tool
#   resumes the exact project cold: no manual rebrief, no shared chat history.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ATTACCA="$HERE/../attacca.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export ATTACCA_DB="$WORK/attacca.db"
# Isolate the demo from any machine identity (~/.attacca/identity.json):
# actor ids must stay exactly claude_director / codex_director.
export ATTACCA_OWNER=""
mkdir -p "$WORK/acme-app"

step() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
A() { python3 "$ATTACCA" --actor claude_director --actor-type agent "$@"; }
B() { python3 "$ATTACCA" --actor codex_director --actor-type agent "$@"; }

cd "$WORK/acme-app"

step "Setup: register the project once"
python3 "$ATTACCA" init --project-id acme --name "Acme App" >/dev/null
echo "project registered: acme"

step "SESSION A (Claude Director, e.g. inside Claude Code on Computer A)"
A agent register --role director --runtime claude-code >/dev/null
A task create "Migrate auth API to PKCE" \
  --description "Replace implicit flow; add /token and /refresh endpoints." \
  --scope "src/auth/**,api/token.ts" --risk high >/dev/null
A task claim T-1 >/dev/null
echo "claimed T-1"
A room send --type directive --task T-1 \
  --body "Renaming API field session_token -> access_token. Frontend must follow." >/dev/null
A decision propose "Use OAuth PKCE for desktop auth" \
  --detail "No implicit flow. Token lifetime 10 minutes." \
  --rationale "Implicit flow is deprecated; PKCE survives public clients." >/dev/null
A decision resolve D-1 accepted >/dev/null
A task report T-1 --state done \
  --summary "Backend token endpoint merged; API field renamed to access_token." \
  --evidence '[{"kind":"test","name":"auth:e2e","result":"pass"},{"kind":"commit","sha":"b81af94"}]' >/dev/null
A task create "Update frontend to renamed access_token field" \
  --scope "src/frontend/auth/**" --depends-on T-1 >/dev/null
A handoff set \
  --objective "Complete PKCE auth migration and remove legacy cookie path" \
  --what-changed "Backend token endpoint merged; session_token renamed to access_token" \
  --active-work "Frontend field rename is queued as T-2" \
  --blockers "None known" \
  --risks "Legacy clients may depend on the old cookie endpoint" \
  --next-actions "Claim T-2, update frontend callback, run auth:e2e regression" >/dev/null
echo "Session A finished: task done + decision recorded + handoff written."

step "SESSION B (Codex Director — FRESH context, different tool, cold start)"
B agent register --role director --runtime codex-cli >/dev/null
echo '--- what the fresh worker sees (get_handoff): ---'
HANDOFF="$(B --json handoff show)"
echo "$HANDOFF" | python3 -c '
import json,sys
h = json.load(sys.stdin)
print("objective:     ", h["handoff"]["objective"])
print("what changed:  ", h["handoff"]["what_changed"])
print("next actions:  ", h["handoff"]["next_actions"])
print("context version:", h["context_version"])
print("open tasks:    ", [(t["task_id"], t["title"], t["status"]) for t in h["open_tasks"]])
print("decisions:     ", [(d["decision_id"], d["title"], d["status"]) for d in h["decisions"]])
'
echo '--- the room (directives from session A): ---'
B room read
step "Session B continues the work without any rebrief"
B task claim T-2 >/dev/null
echo "claimed T-2 (scope warning checks ran)"
B room send --type claim --task T-2 \
  --body "Taking T-2: updating frontend to access_token per D-1." >/dev/null
B task report T-2 --state review \
  --summary "Frontend callback updated to access_token; awaiting review." \
  --evidence '[{"kind":"test","name":"frontend:auth","result":"pass"}]' >/dev/null
echo "reported T-2 -> review"

step "The shared project log both sessions produced (one ledger)"
python3 "$ATTACCA" log

step "Ledger integrity"
python3 "$ATTACCA" event verify

step "ASSERTIONS"
fail() { echo "DEMO FAILED: $1" >&2; exit 1; }
echo "$HANDOFF" | grep -q "PKCE auth migration" || fail "handoff objective missing"
echo "$HANDOFF" | grep -q "access_token"        || fail "handoff what_changed missing"
python3 "$ATTACCA" --json task list | grep -q '"claimed_by": "codex_director"' \
  || fail "codex_director claim not recorded"
python3 "$ATTACCA" --json event verify | grep -q '"ok": true' \
  || fail "ledger verification failed"
python3 "$ATTACCA" --json decision list | grep -q '"status": "accepted"' \
  || fail "decision not recorded"
echo "OK: fresh worker resumed the project cold from shared state alone."
