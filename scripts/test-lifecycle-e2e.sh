#!/usr/bin/env bash
set -euo pipefail

for command in anvil cast curl docker forge node ssh-keygen; do
  command -v "$command" >/dev/null
done

cargo build --quiet \
  -p prism-control-plane \
  -p prism-lifecycle-worker \
  -p prism-proof-worker \
  -p prism-settlement-worker \
  -p prismd

root=$(mktemp -d)
postgres_container="prism-lifecycle-postgres-$$"
anvil_pid=
control_pid=
mock_pid=

cleanup() {
  for pid in "$control_pid" "$mock_pid" "$anvil_pid"; do
    if [[ -n $pid ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  docker rm -f "$postgres_container" >/dev/null 2>&1 || true
  rm -rf "$root" broadcast/DeployLocal.s.sol contracts/cache/DeployLocal.s.sol
}
trap cleanup EXIT

free_port() {
  node -e '
    const server = require("net").createServer();
    server.listen(0, "127.0.0.1", () => {
      process.stdout.write(String(server.address().port));
      server.close();
    });
  '
}

anvil_port=$(free_port)
control_port=$(free_port)
mock_port=$(free_port)
rpc_url="http://127.0.0.1:$anvil_port"
control_url="http://127.0.0.1:$control_port"
mock_url="http://127.0.0.1:$mock_port"

deployer_key=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
gateway_key=0000000000000000000000000000000000000000000000000000000000000002
attestor_key=0000000000000000000000000000000000000000000000000000000000000003
provider_key=0000000000000000000000000000000000000000000000000000000000000004
credential_key=1111111111111111111111111111111111111111111111111111111111111111
gateway_token=0123456789abcdef0123456789abcdef
image_digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

anvil --chain-id 4663 --host 127.0.0.1 --port "$anvil_port" --silent \
  >"$root/anvil.log" 2>&1 &
anvil_pid=$!
for _ in $(seq 1 30); do
  if cast chain-id --rpc-url "$rpc_url" >/dev/null 2>&1; then break; fi
  sleep 1
done
test "$(cast chain-id --rpc-url "$rpc_url")" = 4663

for key in "$gateway_key" "$attestor_key" "$provider_key"; do
  account=$(cast wallet address --private-key "$key")
  cast rpc --rpc-url "$rpc_url" anvil_setBalance "$account" 0x3635C9ADC5DEA00000 >/dev/null
done

node_id=$(target/debug/prismd create-identity --path "$root/device.json")
env \
  PRISM_LOCAL_DEPLOYER_KEY="0x$deployer_key" \
  PRISM_LOCAL_GATEWAY_KEY="0x$gateway_key" \
  PRISM_LOCAL_ATTESTOR_KEY="0x$attestor_key" \
  PRISM_LOCAL_PROVIDER_KEY="0x$provider_key" \
  PRISM_LOCAL_NODE_ID="$node_id" \
  forge script contracts/script/DeployLocal.s.sol:DeployLocal \
    --rpc-url "$rpc_url" --broadcast --slow >/dev/null

manifest=$(node -e '
  const run = require(process.argv[1]);
  const deployment = run.transactions.findLast((entry) => entry.contractName === "LocalManifest");
  if (!deployment?.contractAddress) process.exit(1);
  process.stdout.write(deployment.contractAddress);
' "$PWD/broadcast/DeployLocal.s.sol/4663/run-latest.json")
escrow=$(cast call "$manifest" "escrow()(address)" --rpc-url "$rpc_url")
test "$(cast call "$manifest" "leaseId()(uint256)" --rpc-url "$rpc_url")" = 1

docker run -d --name "$postgres_container" \
  -e POSTGRES_DB=prism \
  -e POSTGRES_USER=prism \
  -e POSTGRES_PASSWORD=integration-secret \
  -p 127.0.0.1::5432 \
  postgres:17-bookworm@sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394 \
  >/dev/null
for _ in $(seq 1 30); do
  if docker exec "$postgres_container" pg_isready -U prism -d prism >/dev/null 2>&1; then break; fi
  sleep 1
done
database_port=$(docker port "$postgres_container" 5432/tcp | awk -F: 'NR == 1 { print $NF }')
database_url="postgres://prism:integration-secret@127.0.0.1:$database_port/prism"

env \
  DATABASE_URL="$database_url" \
  PRISM_ACCESS_CREDENTIAL_KEY="$credential_key" \
  PRISM_ALLOW_DEVELOPMENT_AUTH=1 \
  PRISM_ALLOW_DEVELOPMENT_CHAIN=1 \
  PRISM_ALLOW_DEVELOPMENT_REGISTRY=1 \
  PRISM_CONTROL_PLANE_ADDR="127.0.0.1:$control_port" \
  PRISM_GATEWAY_OBSERVER_TOKEN="$gateway_token" \
  PRISM_PUBLIC_GATEWAY_HOST=127.0.0.1 \
  target/debug/prism-control-plane >"$root/control.log" 2>&1 &
control_pid=$!
for _ in $(seq 1 30); do
  if curl --fail --silent "$control_url/healthz" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$control_pid" 2>/dev/null; then
    cat "$root/control.log" >&2
    exit 1
  fi
  sleep 1
done
curl --fail --silent "$control_url/healthz" >/dev/null

provider=$(cast wallet address --private-key "$provider_key")
target/debug/prismd enroll \
  --identity "$root/device.json" \
  --control-plane "$control_url" \
  --operator-wallet "$provider" \
  --payout-wallet "$provider" \
  --gpu-model "NVIDIA lifecycle GPU" \
  --vram-mib 24576 \
  --cuda-major 12 \
  --rate-per-second 100 \
  --benchmark-score 10000
target/debug/prismd heartbeat \
  --identity "$root/device.json" \
  --control-plane "$control_url" \
  --tunnel-connected
observed_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
curl --fail --silent \
  -H "Authorization: Bearer $gateway_token" \
  -H "Content-Type: application/json" \
  -d "{\"connection_id\":\"lifecycle-tunnel\",\"observed_at\":\"$observed_at\"}" \
  "$control_url/v1/gateway/tunnels/$node_id" >/dev/null

request="{\"request\":{\"image\":\"registry.example/runtime@$image_digest\",\"duration_seconds\":60,\"min_vram_mib\":16000,\"preferred_node_id\":null}}"
quote=$(curl --fail --silent \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:lifecycle" \
  -H "x-prism-development-session: session-lifecycle" \
  -H "x-request-id: lifecycle-match" \
  -d "$request" "$control_url/v1/leases/match")
quote_id=$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).quote_id)' "$quote")
ssh-keygen -q -t ed25519 -N "" -C prism-test -f "$root/renter"
ssh_key=$(<"$root/renter.pub")
funding_hash=0x0000000000000001000000001111111111111111111111111111111111111111
curl --fail --silent \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:lifecycle" \
  -H "x-prism-development-session: session-lifecycle" \
  -H "x-request-id: lifecycle-confirm" \
  -d "{\"quote_id\":\"$quote_id\",\"transaction_hash\":\"$funding_hash\",\"ssh_authorized_key\":\"$ssh_key\"}" \
  "$control_url/v1/leases/confirm" >/dev/null

psql_exec() {
  docker exec -e PGPASSWORD=integration-secret "$postgres_container" \
    psql -v ON_ERROR_STOP=1 -U prism -d prism "$@"
}

psql_exec -c \
  "UPDATE leases SET state = 'ready', document = jsonb_set(document, '{state}', '\"ready\"'), updated_at = NOW() WHERE lease_id = 1;
   INSERT INTO lease_lifecycle (lease_id, connection_id, node_ready_at)
   VALUES (1, 'lifecycle-tunnel', NOW())
   ON CONFLICT (lease_id) DO UPDATE
   SET connection_id = EXCLUDED.connection_id, node_ready_at = EXCLUDED.node_ready_at;
   INSERT INTO lifecycle_outbox (action_id, lease_id, kind)
   VALUES ('018f0000-0000-7000-8000-000000000101', 1, 'start_access');" >/dev/null

PORT="$mock_port" node scripts/mock-external-services.mjs >"$root/mock.log" 2>&1 &
mock_pid=$!
for _ in $(seq 1 30); do
  if curl --fail --silent "$mock_url/healthz" >/dev/null 2>&1; then break; fi
  sleep 1
done

run_lifecycle() {
  env \
    DATABASE_URL="$database_url" \
    PRISM_ACCESS_CREDENTIAL_KEY="$credential_key" \
    PRISM_ALLOW_DEVELOPMENT_SIGNER=1 \
    PRISM_DEVELOPMENT_PRIVATE_KEY="$gateway_key" \
    PRISM_GATEWAY_CONTROL_TOKEN="$gateway_token" \
    PRISM_GATEWAY_CONTROL_URL="$mock_url" \
    PRISM_LEASE_ESCROW_ADDRESS="$escrow" \
    PRISM_LIFECYCLE_CONFIRMATIONS=1 \
    PRISM_RPC_URL="$rpc_url" \
    PRISM_RUN_ONCE=1 \
    target/debug/prism-lifecycle-worker
}

snapshot=$(cast rpc --rpc-url "$rpc_url" evm_snapshot | tr -d '"')
run_lifecycle
cast rpc --rpc-url "$rpc_url" evm_revert "$snapshot" >/dev/null
sleep 6
run_lifecycle
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
sleep 6
run_lifecycle
test "$(psql_exec -Atc "SELECT state FROM leases WHERE lease_id = 1")" = active

access=$(curl --fail --silent \
  -H "x-prism-development-subject: did:privy:lifecycle" \
  -H "x-prism-development-session: session-lifecycle" \
  -H "x-request-id: lifecycle-access" \
  "$control_url/v1/leases/1/access")
node -e '
  const access = JSON.parse(process.argv[1]);
  if (access.lease_id !== 1 || !access.token || !access.jupyter_token) process.exit(1);
' "$access"

target/debug/prismd heartbeat \
  --identity "$root/device.json" \
  --control-plane "$control_url" \
  --tunnel-connected \
  --active-lease 1 \
  --image-digest "$image_digest"
sleep 2
target/debug/prismd heartbeat \
  --identity "$root/device.json" \
  --control-plane "$control_url" \
  --tunnel-connected \
  --active-lease 1 \
  --image-digest "$image_digest"

cast rpc --rpc-url "$rpc_url" evm_increaseTime 5 >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
psql_exec -c \
  "UPDATE node_telemetry SET observed_at = NOW() - INTERVAL '2 minutes' WHERE node_id = '$node_id';
   UPDATE node_tunnels SET observed_at = NOW() - INTERVAL '2 minutes' WHERE node_id = '$node_id';" \
  >/dev/null
run_lifecycle
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
sleep 6
run_lifecycle
test "$(psql_exec -Atc "SELECT status FROM settlement_jobs WHERE lease_id = 1")" = queued

run_settlement() {
  env \
    DATABASE_URL="$database_url" \
    PRISM_ALLOW_DEVELOPMENT_SIGNER=1 \
    PRISM_DEVELOPMENT_PRIVATE_KEY="$attestor_key" \
    PRISM_LEASE_ESCROW_ADDRESS="$escrow" \
    PRISM_RPC_URL="$rpc_url" \
    PRISM_RUN_ONCE=1 \
    PRISM_SETTLEMENT_CONFIRMATIONS=1 \
    target/debug/prism-settlement-worker
}

run_settlement
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
sleep 6
run_settlement
test "$(psql_exec -Atc "SELECT status FROM settlement_jobs WHERE lease_id = 1")" = proposed

cast rpc --rpc-url "$rpc_url" evm_increaseTime 86401 >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
psql_exec -c \
  "UPDATE lifecycle_outbox SET available_at = NOW() WHERE lease_id = 1 AND kind = 'finalize';" \
  >/dev/null
run_lifecycle
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
sleep 6
run_lifecycle
test "$(psql_exec -Atc "SELECT state FROM leases WHERE lease_id = 1")" = finalized

timeout_reference=$(cast keccak timeout-quote)
cast send "$escrow" "createLease(bytes32,uint32,bytes32)" \
  "$node_id" 60 "$timeout_reference" \
  --private-key "$deployer_key" --rpc-url "$rpc_url" >/dev/null
test "$(cast call "$escrow" "leaseCount()(uint256)" --rpc-url "$rpc_url")" = 2
target/debug/prismd heartbeat \
  --identity "$root/device.json" \
  --control-plane "$control_url" \
  --tunnel-connected
observed_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
curl --fail --silent \
  -H "Authorization: Bearer $gateway_token" \
  -H "Content-Type: application/json" \
  -d "{\"connection_id\":\"lifecycle-tunnel\",\"observed_at\":\"$observed_at\"}" \
  "$control_url/v1/gateway/tunnels/$node_id" >/dev/null
quote=$(curl --fail --silent \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:lifecycle" \
  -H "x-prism-development-session: session-lifecycle" \
  -H "x-request-id: timeout-match" \
  -d "$request" "$control_url/v1/leases/match")
quote_id=$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).quote_id)' "$quote")
funding_hash=0x0000000000000002000000001111111111111111111111111111111111111111
curl --fail --silent \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:lifecycle" \
  -H "x-prism-development-session: session-lifecycle" \
  -H "x-request-id: timeout-confirm" \
  -d "{\"quote_id\":\"$quote_id\",\"transaction_hash\":\"$funding_hash\",\"ssh_authorized_key\":\"$ssh_key\"}" \
  "$control_url/v1/leases/confirm" >/dev/null
psql_exec -c \
  "UPDATE leases SET created_at = NOW() - INTERVAL '11 minutes' WHERE lease_id = 2;" \
  >/dev/null
cast rpc --rpc-url "$rpc_url" evm_increaseTime 601 >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
run_lifecycle
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
sleep 6
run_lifecycle
test "$(psql_exec -Atc "SELECT state FROM leases WHERE lease_id = 2")" = refunded

env \
  DATABASE_URL="$database_url" \
  PRISM_ALLOW_LOCAL_PROOF_ARTIFACTS=1 \
  PRISM_ALLOW_DEVELOPMENT_X_ENDPOINT=1 \
  PRISM_EXPLORER_URL=https://example.invalid/explorer \
  PRISM_LEASE_ESCROW_ADDRESS="$escrow" \
  PRISM_PROOF_ARTIFACT_DIR="$root/proof" \
  PRISM_PROOF_CONFIRMATIONS=1 \
  PRISM_PUBLIC_PROOF_URL=https://example.invalid/proof \
  PRISM_RPC_URL="$rpc_url" \
  PRISM_RUN_ONCE=1 \
  PRISM_X_POST_ENDPOINT="$mock_url/2/tweets" \
  PRISM_X_USER_ACCESS_TOKEN=test-token \
  target/debug/prism-proof-worker

node -e '
  const index = require(process.argv[1]);
  const outcomes = index.receipts.map((receipt) => receipt.outcome).sort();
  if (outcomes.join(",") !== "finalized,refunded") process.exit(1);
' "$root/proof/index.json"
test "$(psql_exec -Atc "SELECT count(*) FROM proof_receipts WHERE published_at IS NOT NULL")" = 2

echo "durable lease lifecycle end-to-end passed"
