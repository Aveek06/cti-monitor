#!/usr/bin/env bash
set -e

# --- Guard: skip if GitHub Actions ran successfully within the last 10 hours ---
HOURS_AGO=$(curl -sf \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/Aveek06/cti-monitor/actions/workflows/cti-monitor.yml/runs?status=success&per_page=1" \
  | python3 -c "
import json, sys
from datetime import datetime, timezone
runs = json.load(sys.stdin).get('workflow_runs', [])
if runs:
    ts = datetime.fromisoformat(runs[0]['created_at'].replace('Z', '+00:00'))
    print(f'{(datetime.now(timezone.utc) - ts).total_seconds() / 3600:.1f}')
" 2>/dev/null || echo "")

if [ -n "$HOURS_AGO" ] && python3 -c "import sys; sys.exit(0 if float('${HOURS_AGO}') < 10 else 1)" 2>/dev/null; then
  echo "GitHub Actions ran ${HOURS_AGO}h ago — skipping Render backup run."
  exit 0
fi
echo "No recent GitHub Actions run (last: ${HOURS_AGO:-unknown}h ago) — proceeding."
# --- End guard ---

REPO_URL="https://x-access-token:${GITHUB_TOKEN}@github.com/Aveek06/cti-monitor.git"
STATE_BRANCH="state"
STATE_DIR="_state"

echo "=== Restoring state from branch: ${STATE_BRANCH} ==="
if git clone --branch "${STATE_BRANCH}" --depth 1 "${REPO_URL}" "${STATE_DIR}" 2>/dev/null; then
    for f in state.json last_active.json prev_run_links.json; do
        if [ -f "${STATE_DIR}/${f}" ]; then
            cp "${STATE_DIR}/${f}" .
            echo "  Restored: ${f}"
        fi
    done
else
    echo "  State branch not found — starting fresh."
    mkdir -p "${STATE_DIR}"
    cd "${STATE_DIR}"
    git init
    git remote add origin "${REPO_URL}"
    cd ..
fi

echo "=== Applying seed data ==="
python -c '
import json, os
if not os.path.exists("state_seeds.json"):
    exit()
seed_data = json.load(open("state_seeds.json"))
state = json.load(open("state.json")) if os.path.exists("state.json") else {}
force = seed_data.pop("_force_replace", [])
changed = 0
for name, links in seed_data.items():
    if (not state.get(name) or name in force) and links:
        state[name] = links
        changed += 1
        print(f"Seeded {name}: {len(links)} links")
if changed:
    json.dump(state, open("state.json", "w"), indent=2)
    print(f"Patched {changed} sites into state.json")
'

echo "=== Running CTI monitor ==="
python run_check.py config.json state.json last_active.json prev_run_links.json

echo "=== Saving state to branch: ${STATE_BRANCH} ==="
git -C "${STATE_DIR}" config user.email "cti-monitor@render"
git -C "${STATE_DIR}" config user.name  "CTI Monitor (Render)"

for f in state.json last_active.json prev_run_links.json ioc_export.json ttp_export.json; do
    [ -f "${f}" ] && cp "${f}" "${STATE_DIR}/" && echo "  Saved: ${f}"
done

git -C "${STATE_DIR}" add -A
if git -C "${STATE_DIR}" diff --cached --quiet; then
    echo "  No state changes — skipping commit."
else
    git -C "${STATE_DIR}" commit -m "state: render run $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    git -C "${STATE_DIR}" push origin "${STATE_BRANCH}"
    echo "  State pushed."
fi
