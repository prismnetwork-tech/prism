#!/usr/bin/env bash
set -Eeuo pipefail

for command in cast curl docker; do
  command -v "$command" >/dev/null
done

root=$(mktemp -d)
container="prism-postgres-test-$$"
control_pid=
command_pid=
port=
gateway_token=0123456789abcdef0123456789abcdef
supplier_key=0x0000000000000000000000000000000000000000000000000000000000000004
supplier_wallet=$(cast wallet address --private-key "$supplier_key" | tr '[:upper:]' '[:lower:]')

cleanup() {
  if [[ -n $control_pid ]]; then
    kill "$control_pid" 2>/dev/null || true
    wait "$control_pid" 2>/dev/null || true
  fi
  if [[ -n $command_pid ]]; then
    kill "$command_pid" 2>/dev/null || true
    wait "$command_pid" 2>/dev/null || true
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$root"
}

report_failure() {
  local exit_code=$?
  local line=$1

  printf 'control-plane PostgreSQL integration failed at line %s\n' "$line" >&2
  if [[ -f "$root/control-plane.log" ]]; then
    tail -200 "$root/control-plane.log" >&2
  fi
  docker logs --tail 200 "$container" >&2 2>/dev/null || true
  exit "$exit_code"
}

trap 'report_failure "$LINENO"' ERR
trap cleanup EXIT

./scripts/generate-lightsail-tls.sh tunnel.integration.invalid "$root/tls" >/dev/null 2>&1
ca_certificate=$(<"$root/tls/ca.crt")
ca_key=$(<"$root/tls/ca.key")

docker run -d --name "$container" \
  -e POSTGRES_DB=prism \
  -e POSTGRES_USER=prism \
  -e POSTGRES_PASSWORD=integration-secret \
  -p 127.0.0.1::5432 \
  postgres:17-bookworm@sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394 \
  >/dev/null

for _ in $(seq 1 30); do
  if docker exec "$container" pg_isready -U prism -d prism >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$container" pg_isready -U prism -d prism >/dev/null

database_port=$(docker port "$container" 5432/tcp | awk -F: 'NR == 1 { print $NF }')
database_url="postgres://prism:integration-secret@127.0.0.1:$database_port/prism"

start_control_plane() {
  port=$(node -e '
    const server = require("net").createServer();
    server.listen(0, "127.0.0.1", () => {
      process.stdout.write(String(server.address().port));
      server.close();
    });
  ')
  env \
    DATABASE_URL="$database_url" \
    PRISM_ALLOW_DEVELOPMENT_AUTH=1 \
    PRISM_ALLOW_DEVELOPMENT_CHAIN=1 \
    PRISM_ALLOW_DEVELOPMENT_REGISTRY=1 \
    PRISM_LEASE_ESCROW_ADDRESS=0x2222222222222222222222222222222222222222 \
    PRISM_GATEWAY_OBSERVER_TOKEN="$gateway_token" \
    PRISM_OPERATOR_SUBJECTS=did:privy:operator \
    PRISM_REQUIRE_NODE_CERTIFICATES=1 \
    PRISM_NODE_CA_CERTIFICATE_PEM="$ca_certificate" \
    PRISM_NODE_CA_KEY_PEM="$ca_key" \
    PRISM_CONTROL_PLANE_ADDR="127.0.0.1:$port" \
    target/debug/prism-control-plane >"$root/control-plane.log" 2>&1 &
  control_pid=$!
  for _ in $(seq 1 30); do
    if curl --fail --silent "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
      return
    fi
    if ! kill -0 "$control_pid" 2>/dev/null; then
      cat "$root/control-plane.log" >&2
      return 1
    fi
    sleep 1
  done
  cat "$root/control-plane.log" >&2
  return 1
}

start_control_plane

node_id=$(target/debug/prismd create-identity --path "$root/device.json")
target/debug/prismd enroll \
  --identity "$root/device.json" \
  --control-plane "http://127.0.0.1:$port" \
  --operator-wallet "$supplier_wallet" \
  --payout-wallet "$supplier_wallet" \
  --gpu-model "NVIDIA integration GPU" \
  --vram-mib 24576 \
  --cuda-major 12 \
  --rate-per-second 100 \
  --benchmark-score 10000
target/debug/prismd heartbeat \
  --identity "$root/device.json" \
  --control-plane "http://127.0.0.1:$port"

certificate_output=$(target/debug/prismd certificate \
  --identity "$root/device.json" \
  --control-plane "http://127.0.0.1:$port" \
  --certificate "$root/node.crt" \
  --private-key "$root/node.key" \
  --ca-certificate "$root/ca.crt")
certificate_fingerprint=${certificate_output%% *}
[[ $certificate_fingerprint =~ ^[0-9a-f]{64}$ ]]

observed_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
curl --fail --silent \
  -H "Authorization: Bearer $gateway_token" \
  -H "Content-Type: application/json" \
  -d "{\"connection_id\":\"integration-tunnel\",\"certificate_fingerprint\":\"$certificate_fingerprint\",\"observed_at\":\"$observed_at\"}" \
  "http://127.0.0.1:$port/v1/gateway/tunnels/$node_id" >/dev/null

offers=$(curl --fail --silent "http://127.0.0.1:$port/v1/offers")
node -e '
  const offers = JSON.parse(process.argv[1]);
  if (offers.length !== 1 || offers[0].node_id !== process.argv[2]) process.exit(1);
' "$offers" "$node_id"

challenge=$(curl --fail --silent \
  -H "x-prism-development-subject: did:privy:integration" \
  -H "x-prism-development-session: session-integration" \
  -H "x-request-id: wallet-challenge-integration" \
  "http://127.0.0.1:$port/v1/account/wallets/challenge?address=$supplier_wallet")
challenge_id=$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).challenge_id)' "$challenge")
challenge_message=$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).message)' "$challenge")
wallet_signature=$(cast wallet sign --private-key "$supplier_key" "$challenge_message")
curl --fail --silent \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:integration" \
  -H "x-prism-development-session: session-integration" \
  -H "x-request-id: wallet-link-integration" \
  -d "{\"challenge_id\":\"$challenge_id\",\"wallet_address\":\"$supplier_wallet\",\"signature\":\"$wallet_signature\"}" \
  "http://127.0.0.1:$port/v1/account/wallets/link" >/dev/null
supplier_summary=$(curl --fail --silent \
  -H "x-prism-development-subject: did:privy:integration" \
  -H "x-prism-development-session: session-integration" \
  -H "x-request-id: supplier-summary-integration" \
  "http://127.0.0.1:$port/v1/supplier/summary")
node -e '
  const summary = JSON.parse(process.argv[1]);
  if (summary.linked_wallets.length !== 1 || summary.nodes.length !== 1) process.exit(1);
  if (summary.nodes[0].certificate_status !== "active") process.exit(1);
' "$supplier_summary"

node_suspend_id=018f0000-0000-7000-8000-000000000201
node_suspend="{\"action_id\":\"$node_suspend_id\",\"action\":\"node_suspend\",\"target_id\":\"$node_id\",\"reason\":\"integration node suspension\",\"evidence_hash\":null}"
curl --fail --silent \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:operator" \
  -H "x-prism-development-session: session-operator" \
  -H "x-request-id: node-suspend-integration" \
  -d "$node_suspend" \
  "http://127.0.0.1:$port/v1/operator/controls" >/dev/null
[[ $(curl --fail --silent "http://127.0.0.1:$port/v1/offers") == "[]" ]]
curl --fail --silent \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:operator" \
  -H "x-prism-development-session: session-operator" \
  -H "x-request-id: node-suspend-replay-integration" \
  -d "$node_suspend" \
  "http://127.0.0.1:$port/v1/operator/controls" >/dev/null
node_resume="{\"action_id\":\"018f0000-0000-7000-8000-000000000202\",\"action\":\"node_resume\",\"target_id\":\"$node_id\",\"reason\":\"integration node resume\",\"evidence_hash\":null}"
curl --fail --silent \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:operator" \
  -H "x-prism-development-session: session-operator" \
  -H "x-request-id: node-resume-integration" \
  -d "$node_resume" \
  "http://127.0.0.1:$port/v1/operator/controls" >/dev/null
observed_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
curl --fail --silent \
  -H "Authorization: Bearer $gateway_token" \
  -H "Content-Type: application/json" \
  -d "{\"connection_id\":\"integration-tunnel\",\"certificate_fingerprint\":\"$certificate_fingerprint\",\"observed_at\":\"$observed_at\"}" \
  "http://127.0.0.1:$port/v1/gateway/tunnels/$node_id" >/dev/null

request='{"request":{"image":"registry.example/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","duration_seconds":60,"min_vram_mib":16000,"preferred_node_id":null}}'
auth_headers=(
  -H "Content-Type: application/json"
  -H "x-prism-development-subject: did:privy:integration"
  -H "x-prism-development-session: session-integration"
  -H "x-request-id: match-integration"
)
risk_hold='{"action_id":"018f0000-0000-7000-8000-000000000203","action":"account_risk_hold","target_id":"did:privy:integration","reason":"integration account risk hold","evidence_hash":null}'
curl --fail --silent \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:operator" \
  -H "x-prism-development-session: session-operator" \
  -H "x-request-id: risk-hold-integration" \
  -d "$risk_hold" \
  "http://127.0.0.1:$port/v1/operator/controls" >/dev/null
risk_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:integration" \
  -H "x-prism-development-session: session-integration" \
  -H "x-request-id: held-match-integration" \
  -d "$request" "http://127.0.0.1:$port/v1/leases/match")
[[ $risk_status == 403 ]]
risk_release='{"action_id":"018f0000-0000-7000-8000-000000000204","action":"account_risk_release","target_id":"did:privy:integration","reason":"integration account risk release","evidence_hash":null}'
curl --fail --silent \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:operator" \
  -H "x-prism-development-session: session-operator" \
  -H "x-request-id: risk-release-integration" \
  -d "$risk_release" \
  "http://127.0.0.1:$port/v1/operator/controls" >/dev/null

quote=$(curl --fail --silent "${auth_headers[@]}" -d "$request" \
  "http://127.0.0.1:$port/v1/leases/match")
node -e '
  const quote = JSON.parse(process.argv[1]);
  if (quote.node_id !== process.argv[2] || quote.maximum_escrow !== 6000) process.exit(1);
' "$quote" "$node_id"

quote_id=$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).quote_id)' "$quote")
funding_hash=0x0000000000000001000000001111111111111111111111111111111111111111
ssh-keygen -q -t ed25519 -N "" -f "$root/renter"
ssh_key=$(cat "$root/renter.pub")
confirmation=$(curl --fail --silent \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:integration" \
  -H "x-prism-development-session: session-integration" \
  -H "x-request-id: confirm-integration" \
  -d "{\"quote_id\":\"$quote_id\",\"transaction_hash\":\"$funding_hash\",\"ssh_authorized_key\":\"$ssh_key\"}" \
  "http://127.0.0.1:$port/v1/leases/confirm")
node -e '
  const lease = JSON.parse(process.argv[1]);
  if (lease.lease_id !== 1 || lease.quote_id !== process.argv[2] || lease.state !== "funded") process.exit(1);
' "$confirmation" "$quote_id"

leases=$(curl --fail --silent \
  -H "x-prism-development-subject: did:privy:integration" \
  -H "x-prism-development-session: session-integration" \
  -H "x-request-id: list-leases-integration" \
  "http://127.0.0.1:$port/v1/leases")
node -e '
  const leases = JSON.parse(process.argv[1]);
  if (leases.length !== 1 || leases[0].funding_transaction_hash !== process.argv[2]) process.exit(1);
' "$leases" "$funding_hash"

target/debug/prismd commands \
  --identity "$root/device.json" \
  --control-plane "http://127.0.0.1:$port" \
  --workspace-root "$root/workspaces" \
  --state-root "$root/leases" \
  --poll-seconds 1 >"$root/commands.log" 2>&1 &
command_pid=$!
for _ in $(seq 1 20); do
  command_status=$(docker exec -e PGPASSWORD=integration-secret "$container" \
    psql -U prism -d prism -Atc "SELECT status FROM node_commands LIMIT 1;")
  if [[ $command_status == failed ]]; then
    break
  fi
  if ! kill -0 "$command_pid" 2>/dev/null; then
    cat "$root/commands.log" >&2
    exit 1
  fi
  sleep 1
done
[[ $command_status == failed ]]
lease_state=$(docker exec -e PGPASSWORD=integration-secret "$container" \
  psql -U prism -d prism -Atc "SELECT state FROM leases LIMIT 1;")
[[ $lease_state == closing ]]
lifecycle_action=$(docker exec -e PGPASSWORD=integration-secret "$container" \
  psql -U prism -d prism -Atc "SELECT kind FROM lifecycle_outbox LIMIT 1;")
[[ $lifecycle_action == expire_provision ]]
kill "$command_pid"
wait "$command_pid" 2>/dev/null || true
command_pid=

docker exec -e PGPASSWORD=integration-secret "$container" \
  psql -v ON_ERROR_STOP=1 -U prism -d prism -c \
  "UPDATE leases SET state = 'disputed', document = jsonb_set(document, '{state}', '\"disputed\"'), updated_at = NOW() WHERE lease_id = 1;
   INSERT INTO settlement_jobs (lease_id, evidence, status)
   SELECT 1,
          jsonb_build_object(
            'lease_id', 1,
            'lease_nonce', 1,
            'node_id', '$node_id',
            'device_public_key', 'integration-device',
            'gpu_model', 'NVIDIA integration GPU',
            'image_digest', 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'rate_per_second', 100,
            'deposit_base_units', 6000,
            'duration_seconds', 60,
            'access_started_at', 1700000000,
            'access_ended_at', 1700000060,
            'cuda_ready_at', 1700000001,
            'interactive_access_ready_at', 1700000002,
            'gateway_closed_at', 1700000060,
            'node_telemetry', jsonb_build_array((SELECT document FROM node_telemetry LIMIT 1))
          ),
          'disputed';" >/dev/null
forbidden_dispute_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "x-prism-development-subject: did:privy:integration" \
  -H "x-prism-development-session: session-integration" \
  -H "x-request-id: dispute-forbidden-integration" \
  "http://127.0.0.1:$port/v1/operator/disputes")
[[ $forbidden_dispute_status == 403 ]]
disputes=$(curl --fail --silent \
  -H "x-prism-development-subject: did:privy:operator" \
  -H "x-prism-development-session: session-operator" \
  -H "x-request-id: dispute-first-integration" \
  "http://127.0.0.1:$port/v1/operator/disputes")
evidence_hash=$(node -e '
  const disputes = JSON.parse(process.argv[1]);
  if (disputes.length !== 1 || disputes[0].proposal !== null) process.exit(1);
  process.stdout.write(disputes[0].evidence.evidence_hash);
' "$disputes")
receipt_hash="0x$(printf '12%.0s' {1..32})"
settlement_hash="0x$(printf '34%.0s' {1..32})"
docker exec -e PGPASSWORD=integration-secret "$container" \
  psql -v ON_ERROR_STOP=1 -U prism -d prism -c \
  "UPDATE settlement_jobs
   SET proposal = jsonb_build_object(
         'proposal', jsonb_build_object(
           'lease_id', 1,
           'usage_seconds', 58,
           'receipt_hash', '$receipt_hash',
           'evidence_hash', '$evidence_hash'
         ),
         'transaction_hash', '$settlement_hash'
       ),
       transaction_hash = '$settlement_hash',
       updated_at = NOW()
   WHERE lease_id = 1;" >/dev/null
disputes=$(curl --fail --silent \
  -H "x-prism-development-subject: did:privy:operator" \
  -H "x-prism-development-session: session-operator" \
  -H "x-request-id: dispute-resolved-view-integration" \
  "http://127.0.0.1:$port/v1/operator/disputes")
node -e '
  const [dispute] = JSON.parse(process.argv[1]);
  if (!dispute || dispute.lease_id !== 1 || dispute.evidence.telemetry_records !== 1) process.exit(1);
  if (dispute.evidence.proposal_integrity_valid !== true || dispute.proposal.usage_seconds !== 58) process.exit(1);
  const transaction = dispute.accept_proposal_transaction;
  if (!transaction || transaction.to !== "0x2222222222222222222222222222222222222222") process.exit(1);
  if (!transaction.data.startsWith("0x001bb9c1") || transaction.data.length !== 202) process.exit(1);
' "$disputes"
docker exec -e PGPASSWORD=integration-secret "$container" \
  psql -v ON_ERROR_STOP=1 -U prism -d prism -c \
  "UPDATE settlement_jobs SET proposal = jsonb_set(proposal, '{proposal,usage_seconds}', '61') WHERE lease_id = 1;" >/dev/null
disputes=$(curl --fail --silent \
  -H "x-prism-development-subject: did:privy:operator" \
  -H "x-prism-development-session: session-operator" \
  -H "x-request-id: dispute-invalid-proposal-integration" \
  "http://127.0.0.1:$port/v1/operator/disputes")
node -e '
  const [dispute] = JSON.parse(process.argv[1]);
  if (dispute.evidence.proposal_integrity_valid !== false) process.exit(1);
  if (dispute.accept_proposal_transaction !== null) process.exit(1);
' "$disputes"

replay_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "${auth_headers[@]}" -d "$request" "http://127.0.0.1:$port/v1/leases/match")
[[ $replay_status == 409 ]]

curl --fail --silent \
  -H "x-prism-development-subject: did:privy:integration" \
  -H "x-prism-development-session: session-integration" \
  -H "x-request-id: revoke-integration" \
  -X POST "http://127.0.0.1:$port/v1/account/session/revoke" >/dev/null

revoked_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:integration" \
  -H "x-prism-development-session: session-integration" \
  -H "x-request-id: after-revoke" \
  -d "$request" "http://127.0.0.1:$port/v1/leases/match")
[[ $revoked_status == 401 ]]

audit=$(curl --fail --silent \
  -H "x-prism-development-subject: did:privy:operator" \
  -H "x-prism-development-session: session-operator" \
  -H "x-request-id: audit-list-integration" \
  "http://127.0.0.1:$port/v1/operator/audit")
node -e '
  const audit = JSON.parse(process.argv[1]);
  if (audit.length !== 4 || audit.filter((event) => event.action === "node_suspend").length !== 1) process.exit(1);
' "$audit"
if docker exec -e PGPASSWORD=integration-secret "$container" \
  psql -v ON_ERROR_STOP=1 -U prism -d prism -c \
  "UPDATE operator_audit_events SET reason = 'mutation must fail';" >/dev/null 2>&1; then
  echo "operator audit accepted a mutation" >&2
  exit 1
fi

certificate_revoke="{\"action_id\":\"018f0000-0000-7000-8000-000000000205\",\"action\":\"node_certificate_revoke\",\"target_id\":\"$node_id\",\"reason\":\"integration certificate rotation\",\"evidence_hash\":null}"
curl --fail --silent \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:operator" \
  -H "x-prism-development-session: session-operator" \
  -H "x-request-id: certificate-revoke-integration" \
  -d "$certificate_revoke" \
  "http://127.0.0.1:$port/v1/operator/controls" >/dev/null
rejected_certificate=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "Authorization: Bearer $gateway_token" \
  -H "Content-Type: application/json" \
  -d "{\"connection_id\":\"integration-tunnel\",\"certificate_fingerprint\":\"$certificate_fingerprint\",\"observed_at\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"}" \
  "http://127.0.0.1:$port/v1/gateway/tunnels/$node_id")
[[ $rejected_certificate == 403 ]]
certificate_output=$(target/debug/prismd certificate \
  --identity "$root/device.json" \
  --control-plane "http://127.0.0.1:$port" \
  --certificate "$root/node.crt" \
  --private-key "$root/node.key" \
  --ca-certificate "$root/ca.crt")
certificate_fingerprint=${certificate_output%% *}
curl --fail --silent \
  -H "Authorization: Bearer $gateway_token" \
  -H "Content-Type: application/json" \
  -d "{\"connection_id\":\"integration-tunnel\",\"certificate_fingerprint\":\"$certificate_fingerprint\",\"observed_at\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"}" \
  "http://127.0.0.1:$port/v1/gateway/tunnels/$node_id" >/dev/null

counts=$(docker exec -e PGPASSWORD=integration-secret "$container" \
  psql -U prism -d prism -Atc \
  "SELECT (SELECT count(*) FROM node_offers), (SELECT count(*) FROM node_telemetry), (SELECT count(*) FROM node_tunnels), (SELECT count(*) FROM lease_quotes), (SELECT count(*) FROM leases), (SELECT count(*) FROM node_commands), (SELECT count(*) FROM lease_secrets), (SELECT count(*) FROM lifecycle_outbox), (SELECT count(*) FROM account_wallets WHERE verified_at IS NOT NULL), (SELECT count(*) FROM account_sessions WHERE revoked_at IS NOT NULL), (SELECT count(*) FROM node_certificates), (SELECT count(*) FROM operator_audit_events);")
expected_counts="1|1|1|1|1|1|1|1|2|1|2|5"
if [[ $counts != "$expected_counts" ]]; then
  echo "unexpected integration row counts: got $counts; expected $expected_counts" >&2
  exit 1
fi

kill "$control_pid"
wait "$control_pid" 2>/dev/null || true
control_pid=
start_control_plane
offers=$(curl --fail --silent "http://127.0.0.1:$port/v1/offers")
node -e '
  const offers = JSON.parse(process.argv[1]);
  if (offers.length !== 1 || offers[0].node_id !== process.argv[2]) process.exit(1);
' "$offers" "$node_id"

echo "control-plane PostgreSQL integration passed"
