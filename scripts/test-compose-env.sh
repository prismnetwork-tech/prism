#!/usr/bin/env bash
set -euo pipefail

# A binary that calls required_env() aborts on startup when the variable is
# missing, and Compose only passes what its service block names. `compose
# config` cannot catch the gap because the value exists in the env file; it is
# simply never handed to the container. So compare the two lists directly.

compose=deploy/ec2/compose.yml
status=0

# Variables the deployed path never reaches. Both belong to the file handoff
# the settlement worker only takes without a database, which production has.
exempt="PRISM_SETTLEMENT_EVIDENCE_FILE PRISM_SETTLEMENT_OUTBOX_FILE"

check() {
  local service=$1 source=$2 block
  block=$(awk -v svc="  $service:" '
    $0 == svc { inside = 1; next }
    inside && /^  [a-z]/ { inside = 0 }
    inside { print }
  ' "$compose")

  while read -r name; do
    [[ -n $name ]] || continue
    [[ " $exempt " == *" $name "* ]] && continue
    if ! grep -q "^      $name:" <<<"$block"; then
      echo "$compose: service $service never receives $name, required by $source" >&2
      status=1
    fi
  done < <(grep -oE 'required_env\("[A-Z0-9_]+"' "$source" | cut -d'"' -f2 | sort -u)
}

check control-plane services/control-plane/src/main.rs
check access-gateway services/access-gateway/src/main.rs
check lifecycle-worker workers/lifecycle-worker/src/main.rs
check repro-worker workers/repro-worker/src/main.rs
check settlement-worker workers/settlement-worker/src/main.rs
check reconciliation-monitor services/reconciliation-monitor/src/main.rs

[[ $status -eq 0 ]] || exit 1
echo "Compose passes every required environment variable"
