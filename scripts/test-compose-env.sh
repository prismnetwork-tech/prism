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
exempt="PRISM_SETTLEMENT_EVIDENCE_FILE PRISM_SETTLEMENT_OUTBOX_FILE PRISM_PROOF_RECEIPTS_FILE PRISM_PROOF_OUTBOX_FILE"

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
check proof-worker workers/proof-worker/src/main.rs
check reconciliation-monitor services/reconciliation-monitor/src/main.rs

[[ $status -eq 0 ]] || exit 1

edge_block=$(awk '
  $0 == "  edge:" { inside = 1; next }
  inside && /^  [a-z]/ { inside = 0 }
  inside { print }
' "$compose")
proof_block=$(awk '
  $0 == "  proof-worker:" { inside = 1; next }
  inside && /^  [a-z]/ { inside = 0 }
  inside { print }
' "$compose")

grep -Fq -- '- ./proof-artifacts:/srv/proof:ro' <<<"$edge_block"
grep -Fq -- '- ./proof-artifacts:/var/lib/prism-proof' <<<"$proof_block"
grep -Fq 'PRISM_PROOF_ARTIFACT_DIR: /var/lib/prism-proof' <<<"$proof_block"
grep -Fq 'PRISM_ENABLE_X_DIGEST_POSTING: ${PRISM_ENABLE_X_DIGEST_POSTING:-0}' <<<"$proof_block"
grep -Fq '      postgres:' <<<"$proof_block"
if grep -Fq '      control-plane:' <<<"$proof_block"; then
  echo "$compose: proof-worker must not start the control plane during proof cutover" >&2
  exit 1
fi
if grep -Fq 'PRISM_X_USER_ACCESS_TOKEN: ${PRISM_X_USER_ACCESS_TOKEN:?' <<<"$proof_block"; then
  echo "$compose: proof-worker must not require an X credential" >&2
  exit 1
fi
grep -Fq '@proof_index path /proof/index.json' deploy/ec2/Caddyfile
grep -A7 '@proof_receipts path' deploy/ec2/Caddyfile | grep -Fq 'max-age=30'
grep -A7 '@proof_sets path' deploy/ec2/Caddyfile | grep -Fq 'max-age=31536000, immutable'

node <<'NODE'
const { readFileSync } = require("node:fs");

const deploy = readFileSync("deploy/ec2/README.md", "utf8");
const rolloutSteps = [
  "control-plane lifecycle-worker repro-worker settlement-worker proof-worker",
  "PRISM_RUN_MIGRATIONS_ONLY=1 control-plane",
  "install `operator_maintenance` under advisory lock `4663`",
  "drain the historical generation and then the current generation",
  "settlement-worker repro-worker proof-worker",
  "up -d --no-deps --pull never control-plane",
];
let cursor = -1;
for (const step of rolloutSteps) {
  const next = deploy.indexOf(step, cursor + 1);
  if (next < 0) throw new Error(`EC2 rollout procedure is missing: ${step}`);
  if (next <= cursor) throw new Error(`EC2 rollout procedure is out of order: ${step}`);
  cursor = next;
}

const runbook = readFileSync("docs/vast-launch.md", "utf8");
const drainSteps = [
  "**Stop admissions.**",
  "**Pause both escrows.**",
  "**Stop every normal worker and the static proof publisher.**",
  "**Latch maintenance under lock `4663`.**",
  "**Drain the historical generation first.**",
  "**Drain the current generation second.**",
  "**Perform proof cutover.**",
  "**Clear only maintenance under lock `4663`.**",
  "**Let one current owner rebuild health.**",
  "**Reopen current service and start control last.**",
];
cursor = -1;
for (const step of drainSteps) {
  const next = runbook.indexOf(step, cursor + 1);
  if (next < 0) throw new Error(`maintenance drain is missing: ${step}`);
  if (next <= cursor) throw new Error(`maintenance drain is out of order: ${step}`);
  cursor = next;
}
NODE

echo "Compose passes every required environment variable"
