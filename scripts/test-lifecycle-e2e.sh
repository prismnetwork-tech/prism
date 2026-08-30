#!/usr/bin/env bash
set -euo pipefail

# Use PRISM_TEST_POSTGRES_MODE=local for an isolated local cluster.
for command in anvil cargo cast curl forge node ssh-keygen; do
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
postgres_mode=${PRISM_TEST_POSTGRES_MODE:-docker}
postgres_root=
anvil_pid=
control_pid=
mock_pid=
lifecycle_pid=
ambiguous_rpc_pid=

cleanup() {
  for pid in "$lifecycle_pid" "$ambiguous_rpc_pid" "$control_pid" "$mock_pid" "$anvil_pid"; do
    if [[ -n $pid ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [[ $postgres_mode == local && -n $postgres_root ]]; then
    if [[ ! -f $postgres_root/data/postmaster.pid ]] || \
      pg_ctl -D "$postgres_root/data" -m immediate stop >/dev/null 2>&1; then
      rm -rf -- "$postgres_root"
    else
      echo "local PostgreSQL did not stop; retained $postgres_root" >&2
    fi
  elif [[ $postgres_mode == docker ]]; then
    docker rm -f "$postgres_container" >/dev/null 2>&1 || true
  fi
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
ambiguous_rpc_port=$(free_port)
rpc_url="http://127.0.0.1:$anvil_port"
control_url="http://127.0.0.1:$control_port"
mock_url="http://127.0.0.1:$mock_port"
ambiguous_rpc_url="http://127.0.0.1:$ambiguous_rpc_port"

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
registry=$(cast call "$manifest" "registry()(address)" --rpc-url "$rpc_url")
usd=$(cast call "$manifest" "usd()(address)" --rpc-url "$rpc_url")
escrow_db=$(tr '[:upper:]' '[:lower:]' <<<"$escrow")
test "$(cast call "$manifest" "leaseId()(uint256)" --rpc-url "$rpc_url")" = 1

if [[ $postgres_mode == local ]]; then
  for command in createdb initdb pg_ctl psql; do
    command -v "$command" >/dev/null
  done
  database_port=$(free_port)
  postgres_root=$(mktemp -d "${TMPDIR:-/tmp}/prism-lifecycle-postgres.XXXXXX")
  initdb -D "$postgres_root/data" --auth=trust --username=prism >/dev/null
  pg_ctl -D "$postgres_root/data" -l "$postgres_root/postgres.log" \
    -o "-h 127.0.0.1 -p $database_port" start >/dev/null
  createdb -h 127.0.0.1 -p "$database_port" -U prism prism
  database_url="postgres://prism@127.0.0.1:$database_port/prism?sslmode=disable"
else
  [[ $postgres_mode == docker ]]
  command -v docker >/dev/null
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
fi

psql_exec() {
  if [[ $postgres_mode == local ]]; then
    psql "$database_url" -v ON_ERROR_STOP=1 "$@"
  else
    docker exec -e PGPASSWORD=integration-secret "$postgres_container" \
      psql -v ON_ERROR_STOP=1 -U prism -d prism "$@"
  fi
}

env \
  DATABASE_URL="$database_url" \
  PRISM_ACCESS_CREDENTIAL_KEY="$credential_key" \
  PRISM_ALLOW_DEVELOPMENT_AUTH=1 \
  PRISM_ALLOW_DEVELOPMENT_CHAIN=1 \
  PRISM_ALLOW_DEVELOPMENT_REGISTRY=1 \
  PRISM_CONTROL_PLANE_ADDR="127.0.0.1:$control_port" \
  PRISM_GATEWAY_OBSERVER_TOKEN="$gateway_token" \
  PRISM_LEASE_ESCROW_ADDRESS="$escrow" \
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

request="{\"request\":{\"image\":\"docker.io/library/runtime@$image_digest\",\"duration_seconds\":60,\"min_vram_mib\":16000,\"preferred_node_id\":null}}"
quote_file="$root/quote.json"
quote_status=$(curl --show-error --silent --output "$quote_file" --write-out '%{http_code}' \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:lifecycle" \
  -H "x-prism-development-session: session-lifecycle" \
  -H "x-request-id: lifecycle-match" \
  -d "$request" "$control_url/v1/leases/match")
if [[ $quote_status != 200 ]]; then
  cat "$quote_file" >&2
  exit 1
fi
quote=$(<"$quote_file")
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
lease_id=$(psql_exec -Atc "SELECT lease_id FROM leases WHERE quote_id = '$quote_id'")
[[ $lease_id =~ ^[0-9]+$ ]]

psql_exec -c \
  "UPDATE leases SET state = 'ready', document = jsonb_set(document, '{state}', '\"ready\"'), updated_at = NOW() WHERE lease_id = $lease_id;
   INSERT INTO lease_lifecycle (lease_id, connection_id, node_ready_at)
   VALUES ($lease_id, 'lifecycle-tunnel', NOW())
   ON CONFLICT (lease_id) DO UPDATE
   SET connection_id = EXCLUDED.connection_id, node_ready_at = EXCLUDED.node_ready_at;
   INSERT INTO lifecycle_outbox (action_id, lease_id, kind)
   VALUES ('018f0000-0000-7000-8000-000000000101', $lease_id, 'start_access');" >/dev/null

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
    PRISM_NODE_REGISTRY_ADDRESS="$registry" \
    PRISM_RPC_URL="$rpc_url" \
    PRISM_RUN_ONCE=1 \
    target/debug/prism-lifecycle-worker
}

cast rpc --rpc-url "$rpc_url" evm_setAutomine false >/dev/null
run_lifecycle
original_start=$(psql_exec -AtF '|' -c \
  "SELECT raw_transaction, transaction_hash, transaction_nonce
   FROM lifecycle_outbox
   WHERE lease_id = $lease_id AND kind = 'start_access'")
IFS='|' read -r original_start_raw original_start_hash original_start_nonce <<<"$original_start"
[[ $original_start_raw == 0x* ]]
[[ $original_start_hash =~ ^0x[0-9a-f]{64}$ ]]
[[ $original_start_nonce =~ ^[0-9]+$ ]]
test "$(psql_exec -Atc \
  "SELECT status = 'submitted'
       AND submission_count = 1
       AND submitted_at IS NOT NULL
       AND superseded_at IS NULL
   FROM lifecycle_transaction_attempts
   WHERE transaction_hash = '$original_start_hash'")" = t

for _ in $(seq 1 101); do
  psql_exec -c \
    "UPDATE lifecycle_outbox SET available_at = NOW()
     WHERE lease_id = $lease_id AND kind = 'start_access';" >/dev/null
  run_lifecycle
done
test "$(psql_exec -Atc \
  "SELECT attempt.status = 'submitted'
       AND attempt.submission_count = 1
       AND action.status = 'submitted'
   FROM lifecycle_transaction_attempts AS attempt
   JOIN lifecycle_outbox AS action ON action.action_id = attempt.action_id
   WHERE attempt.transaction_hash = '$original_start_hash'")" = t

cast rpc --rpc-url "$rpc_url" anvil_dropTransaction "$original_start_hash" >/dev/null
psql_exec -c \
  "UPDATE lifecycle_transaction_attempts
   SET status = 'superseded', superseded_at = NOW()
   WHERE transaction_hash = '$original_start_hash';
   UPDATE lifecycle_outbox
   SET raw_transaction = NULL, transaction_hash = NULL, transaction_nonce = NULL,
       status = 'queued', attempts = GREATEST(0, attempts - 1),
       available_at = NOW(), lease_until = NULL
   WHERE lease_id = $lease_id AND kind = 'start_access';" >/dev/null

cast rpc --rpc-url "$rpc_url" anvil_setNextBlockBaseFeePerGas 0xb2d05e00 >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
run_lifecycle
replacement_start=$(psql_exec -AtF '|' -c \
  "SELECT raw_transaction, transaction_hash, transaction_nonce
   FROM lifecycle_outbox
   WHERE lease_id = $lease_id AND kind = 'start_access'")
IFS='|' read -r replacement_start_raw replacement_start_hash replacement_start_nonce \
  <<<"$replacement_start"
[[ $replacement_start_hash =~ ^0x[0-9a-f]{64}$ ]]
test "$replacement_start_hash" != "$original_start_hash"
test "$replacement_start_raw" != "$original_start_raw"
test "$replacement_start_nonce" = "$original_start_nonce"
test "$(psql_exec -Atc \
  "SELECT COUNT(*) = 2 AND bool_and(raw_transaction IS NOT NULL)
   FROM lifecycle_transaction_attempts
   WHERE action_id = '018f0000-0000-7000-8000-000000000101'")" = t

cast rpc --rpc-url "$rpc_url" anvil_dropTransaction "$replacement_start_hash" >/dev/null
psql_exec -c \
  "DO \$\$
   DECLARE ignored INTEGER;
   BEGIN
     FOR ignored IN 2..100 LOOP
       UPDATE lifecycle_transaction_attempts
       SET submission_count = submission_count + 1
       WHERE transaction_hash = '$replacement_start_hash';
     END LOOP;
   END
   \$\$;
   UPDATE lifecycle_outbox SET available_at = NOW()
   WHERE lease_id = $lease_id AND kind = 'start_access';" >/dev/null
run_lifecycle
test "$(psql_exec -Atc \
  "SELECT status = 'submitted' AND submission_count = 100
   FROM lifecycle_transaction_attempts
   WHERE transaction_hash = '$replacement_start_hash'")" = t
test "$(psql_exec -Atc \
  "SELECT status = 'submitted'
       AND available_at > NOW() + INTERVAL '4 minutes'
       AND last_error LIKE '%broadcast-attempt limit%'
   FROM lifecycle_outbox
   WHERE lease_id = $lease_id AND kind = 'start_access'")" = t
cast rpc --rpc-url "$rpc_url" anvil_setNextBlockBaseFeePerGas 0x3b9aca00 >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
accepted_start=$(cast rpc --rpc-url "$rpc_url" eth_sendRawTransaction "$original_start_raw" \
  | tr -d '"')
test "$accepted_start" = "$original_start_hash"
psql_exec -c \
  "UPDATE lifecycle_outbox
   SET raw_transaction = '$original_start_raw',
       transaction_hash = '$original_start_hash',
       transaction_nonce = $original_start_nonce,
       status = 'submitted', available_at = NOW(), lease_until = NULL
   WHERE lease_id = $lease_id AND kind = 'start_access';" >/dev/null
run_lifecycle
test "$(psql_exec -Atc \
  "SELECT status = 'submitted'
       AND transaction_hash = '$original_start_hash'
   FROM lifecycle_outbox
   WHERE lease_id = $lease_id AND kind = 'start_access'")" = t
test "$(psql_exec -Atc \
  "SELECT status = 'superseded' AND submission_count = 1
   FROM lifecycle_transaction_attempts
   WHERE transaction_hash = '$original_start_hash'")" = t
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
cast rpc --rpc-url "$rpc_url" evm_setAutomine true >/dev/null
psql_exec -c \
  "UPDATE lifecycle_outbox SET available_at = NOW()
   WHERE lease_id = $lease_id AND kind = 'start_access';" >/dev/null
run_lifecycle
test "$(psql_exec -Atc "SELECT state FROM leases WHERE lease_id = $lease_id")" = active
test "$(psql_exec -Atc \
  "SELECT access_started_at IS NOT NULL
       AND start_transaction_hash = '$original_start_hash'
       AND grant_token_id IS NOT NULL
       AND grant_token IS NOT NULL
   FROM lease_lifecycle WHERE lease_id = $lease_id")" = t
test "$(psql_exec -Atc \
  "SELECT status = 'completed'
       AND transaction_hash = '$original_start_hash'
       AND raw_transaction = '$original_start_raw'
       AND transaction_nonce = $original_start_nonce
       AND confirmed_block IS NOT NULL
       AND confirmed_block_hash IS NOT NULL
   FROM lifecycle_outbox
   WHERE lease_id = $lease_id AND kind = 'start_access'")" = t
test "$(psql_exec -Atc \
  "SELECT COUNT(*) = 2
       AND count(*) FILTER (
           WHERE transaction_hash = '$original_start_hash'
             AND status = 'confirmed'
             AND superseded_at IS NOT NULL
             AND confirmed_at IS NOT NULL
             AND raw_transaction = '$original_start_raw') = 1
       AND count(*) FILTER (
           WHERE transaction_hash = '$replacement_start_hash'
             AND status = 'superseded'
             AND superseded_at IS NOT NULL
             AND raw_transaction = '$replacement_start_raw') = 1
   FROM lifecycle_transaction_attempts
   WHERE action_id = '018f0000-0000-7000-8000-000000000101'")" = t

access=$(curl --fail --silent \
  -H "x-prism-development-subject: did:privy:lifecycle" \
  -H "x-prism-development-session: session-lifecycle" \
  -H "x-request-id: lifecycle-access" \
  "$control_url/v1/leases/$lease_id/access")
node -e '
  const access = JSON.parse(process.argv[1]);
  if (access.lease_id !== Number(process.argv[2]) || !access.token || !access.jupyter_token) process.exit(1);
' "$access" "$lease_id"

target/debug/prismd heartbeat \
  --identity "$root/device.json" \
  --control-plane "$control_url" \
  --tunnel-connected \
  --active-lease "$lease_id" \
  --image-digest "$image_digest"
sleep 2
target/debug/prismd heartbeat \
  --identity "$root/device.json" \
  --control-plane "$control_url" \
  --tunnel-connected \
  --active-lease "$lease_id" \
  --image-digest "$image_digest"

cast rpc --rpc-url "$rpc_url" evm_increaseTime 5 >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
psql_exec -c \
  "UPDATE node_telemetry SET observed_at = NOW() - INTERVAL '2 minutes' WHERE node_id = '$node_id';
   UPDATE node_tunnels SET observed_at = NOW() - INTERVAL '2 minutes' WHERE node_id = '$node_id';" \
  >/dev/null
cast rpc --rpc-url "$rpc_url" evm_setAutomine false >/dev/null
run_lifecycle
original_close=$(psql_exec -AtF '|' -c \
  "SELECT action_id, raw_transaction, transaction_hash, transaction_nonce
   FROM lifecycle_outbox
   WHERE lease_id = $lease_id AND kind = 'close_access'")
IFS='|' read -r close_action_id original_close_raw original_close_hash original_close_nonce \
  <<<"$original_close"
[[ $original_close_raw == 0x* ]]
[[ $original_close_hash =~ ^0x[0-9a-f]{64}$ ]]
[[ $original_close_nonce =~ ^[0-9]+$ ]]

cast rpc --rpc-url "$rpc_url" anvil_dropTransaction "$original_close_hash" >/dev/null
psql_exec -c \
  "UPDATE lifecycle_transaction_attempts
   SET status = 'superseded', superseded_at = NOW()
   WHERE transaction_hash = '$original_close_hash';
   UPDATE lifecycle_outbox
   SET raw_transaction = NULL, transaction_hash = NULL, transaction_nonce = NULL,
       status = 'queued', attempts = GREATEST(0, attempts - 1),
       available_at = NOW(), lease_until = NULL
   WHERE action_id = '$close_action_id';" >/dev/null

cast rpc --rpc-url "$rpc_url" anvil_setNextBlockBaseFeePerGas 0xb2d05e00 >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
run_lifecycle
replacement_close=$(psql_exec -AtF '|' -c \
  "SELECT raw_transaction, transaction_hash, transaction_nonce
   FROM lifecycle_outbox WHERE action_id = '$close_action_id'")
IFS='|' read -r replacement_close_raw replacement_close_hash replacement_close_nonce \
  <<<"$replacement_close"
[[ $replacement_close_hash =~ ^0x[0-9a-f]{64}$ ]]
test "$replacement_close_hash" != "$original_close_hash"
test "$replacement_close_raw" != "$original_close_raw"
test "$replacement_close_nonce" = "$original_close_nonce"

cast rpc --rpc-url "$rpc_url" anvil_dropTransaction "$replacement_close_hash" >/dev/null
psql_exec -c \
  "DO \$\$
   DECLARE ignored INTEGER;
   BEGIN
     FOR ignored IN 2..100 LOOP
       UPDATE lifecycle_transaction_attempts
       SET submission_count = submission_count + 1
       WHERE transaction_hash = '$replacement_close_hash';
     END LOOP;
   END
   \$\$;" >/dev/null
cast rpc --rpc-url "$rpc_url" anvil_setNextBlockBaseFeePerGas 0x3b9aca00 >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
accepted_close=$(cast rpc --rpc-url "$rpc_url" eth_sendRawTransaction "$original_close_raw" \
  | tr -d '"')
test "$accepted_close" = "$original_close_hash"
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
psql_exec -c \
  "UPDATE lifecycle_outbox SET available_at = NOW()
   WHERE action_id = '$close_action_id';" >/dev/null
run_lifecycle
test "$(psql_exec -Atc \
  "SELECT status = 'submitted'
       AND transaction_hash = '$original_close_hash'
   FROM lifecycle_outbox WHERE action_id = '$close_action_id'")" = t
test "$(psql_exec -Atc \
  "SELECT status = 'confirmed' AND superseded_at IS NOT NULL
   FROM lifecycle_transaction_attempts
   WHERE transaction_hash = '$original_close_hash'")" = t

cast rpc --rpc-url "$rpc_url" evm_setAutomine true >/dev/null
psql_exec -c \
  "UPDATE lifecycle_outbox SET available_at = NOW()
   WHERE action_id = '$close_action_id';" >/dev/null
run_lifecycle
test "$(psql_exec -Atc \
  "SELECT status = 'completed'
       AND transaction_hash = '$original_close_hash'
       AND raw_transaction = '$original_close_raw'
       AND transaction_nonce = $original_close_nonce
       AND confirmed_block IS NOT NULL
   FROM lifecycle_outbox WHERE action_id = '$close_action_id'")" = t
test "$(psql_exec -Atc \
  "SELECT COUNT(*) = 2
       AND count(*) FILTER (
           WHERE transaction_hash = '$original_close_hash'
             AND status = 'confirmed'
             AND superseded_at IS NOT NULL) = 1
       AND count(*) FILTER (
           WHERE transaction_hash = '$replacement_close_hash'
             AND status = 'superseded'
             AND submission_count = 100) = 1
   FROM lifecycle_transaction_attempts
   WHERE action_id = '$close_action_id'")" = t
test "$(psql_exec -Atc "SELECT status FROM settlement_jobs WHERE lease_id = $lease_id")" = queued

run_settlement() {
  env \
    DATABASE_URL="$database_url" \
    PRISM_ALLOW_DEVELOPMENT_SIGNER=1 \
    PRISM_DEVELOPMENT_PRIVATE_KEY="$attestor_key" \
    PRISM_LEASE_ESCROW_ADDRESS="$escrow" \
    PRISM_RPC_URL="$settlement_rpc_url" \
    PRISM_RUN_ONCE=1 \
    PRISM_SETTLEMENT_CONFIRMATIONS="$settlement_confirmations" \
    target/debug/prism-settlement-worker
}

settlement_confirmations=3
settlement_rpc_url="$rpc_url"
settlement_pre_submission_snapshot=$(cast rpc --rpc-url "$rpc_url" evm_snapshot | tr -d '"')
run_settlement
settlement_submission=$(psql_exec -AtF '|' -c \
  "SELECT raw_transaction, transaction_hash, transaction_nonce
   FROM settlement_jobs WHERE lease_id = $lease_id")
IFS='|' read -r settlement_raw settlement_hash settlement_nonce <<<"$settlement_submission"
settlement_chain_lease_id=$(psql_exec -Atc \
  "SELECT chain_lease_id FROM leases WHERE lease_id = $lease_id")
[[ $settlement_raw == 0x* ]]
[[ $settlement_hash =~ ^0x[0-9a-f]{64}$ ]]
[[ $settlement_nonce =~ ^[0-9]+$ ]]
test "$(psql_exec -Atc \
  "SELECT status = 'submitted' AND attempts = 0
   FROM settlement_jobs WHERE lease_id = $lease_id")" = t

# Recreate the exact post-migration shape of a signed in-flight proposal from
# before receipt generation identity was stored. Startup must prove the raw
# bytes first, add only the non-hashed identity fields, and retain the exact
# transaction so it can still be adopted after a late confirmation.
legacy_receipt_hash=$(psql_exec -Atc \
  "SELECT proposal->'proposal'->'receipt'->>'receipt_hash'
   FROM settlement_jobs WHERE lease_id = $lease_id")
psql_exec -c \
  "SET session_replication_role = replica;
   UPDATE settlement_transaction_attempts
   SET proposal = proposal #- '{proposal,receipt,escrow_address}'
                           #- '{proposal,receipt,chain_lease_id}',
       signer_address = NULL,
       nonce_reservation_state = 'pending',
       nonce_reservation_reason = NULL,
       generation_binding_state = 'pending',
       generation_binding_reason = NULL
   WHERE transaction_hash = '$settlement_hash';
   UPDATE settlement_jobs
   SET proposal = proposal #- '{proposal,receipt,escrow_address}'
                           #- '{proposal,receipt,chain_lease_id}'
   WHERE lease_id = $lease_id;
   SET session_replication_role = origin;" >/dev/null
run_settlement
test "$(psql_exec -Atc \
  "SELECT attempt.generation_binding_state = 'normalized'
       AND attempt.generation_binding_reason = 'legacy_receipt_identity_normalized'
       AND attempt.proposal = job.proposal
       AND attempt.proposal->'proposal'->'receipt'->>'escrow_address' = '$escrow_db'
       AND attempt.proposal->'proposal'->'receipt'->>'chain_lease_id' = '$settlement_chain_lease_id'
       AND attempt.proposal->'proposal'->'receipt'->>'receipt_hash' = '$legacy_receipt_hash'
       AND attempt.raw_transaction = '$settlement_raw'
       AND attempt.transaction_hash = '$settlement_hash'
   FROM settlement_transaction_attempts AS attempt
   JOIN settlement_jobs AS job ON job.lease_id = attempt.lease_id
   WHERE attempt.transaction_hash = '$settlement_hash'")" = t

# A transaction already visible in the mempool must not bypass the deadline
# margin. Preserve the near-expiry bytes, replace them at the same signer nonce,
# and keep both attempts immutable.
test "$(cast rpc --rpc-url "$rpc_url" evm_revert "$settlement_pre_submission_snapshot")" = true
deadline_replacement_snapshot=$(cast rpc --rpc-url "$rpc_url" evm_snapshot | tr -d '"')
original_settlement_hash=$settlement_hash
settlement_proposal=$(psql_exec -Atc \
  "SELECT proposal::text FROM settlement_jobs WHERE lease_id = $lease_id")
near_deadline=$(($(date +%s) + 60))
near_fields=$(node - "$settlement_proposal" <<'NODE'
const submission = JSON.parse(process.argv[2]);
const proposal = submission.proposal;
process.stdout.write([
  proposal.chain_lease_id,
  proposal.usage_seconds,
  proposal.receipt_hash,
  proposal.nonce,
].join("|"));
NODE
)
IFS='|' read -r near_chain_lease near_usage near_receipt_hash near_proposal_nonce \
  <<<"$near_fields"
near_typed_data=$(node - "$escrow" "$near_chain_lease" "$near_usage" \
  "$near_receipt_hash" "$near_proposal_nonce" "$near_deadline" <<'NODE'
const [escrow, leaseId, usageSeconds, receiptHash, nonce, deadline] = process.argv.slice(2);
process.stdout.write(JSON.stringify({
  types: {
    EIP712Domain: [
      {name: "name", type: "string"},
      {name: "version", type: "string"},
      {name: "chainId", type: "uint256"},
      {name: "verifyingContract", type: "address"},
    ],
    Settlement: [
      {name: "leaseId", type: "uint256"},
      {name: "usageSeconds", type: "uint64"},
      {name: "receiptHash", type: "bytes32"},
      {name: "nonce", type: "uint256"},
      {name: "deadline", type: "uint256"},
    ],
  },
  primaryType: "Settlement",
  domain: {name: "Prism Network", version: "1", chainId: 4663, verifyingContract: escrow},
  message: {
    leaseId,
    usageSeconds,
    receiptHash: receiptHash.startsWith("0x") ? receiptHash : `0x${receiptHash}`,
    nonce,
    deadline,
  },
}));
NODE
)
near_signature=$(cast wallet sign "$near_typed_data" --data --private-key "$attestor_key")
near_gas_price=$(cast gas-price --rpc-url "$rpc_url")
near_raw=$(cast mktx "$escrow" \
  'proposeSettlement(uint256,uint64,bytes32,uint256,bytes)' \
  "$near_chain_lease" "$near_usage" "0x${near_receipt_hash#0x}" \
  "$near_deadline" "$near_signature" \
  --private-key "$attestor_key" --chain 4663 --legacy --nonce "$settlement_nonce" \
  --gas-limit 500000 --gas-price "$near_gas_price")
near_hash=$(cast keccak "$near_raw")
near_proposal=$(node - "$settlement_proposal" "$near_deadline" "$near_signature" \
  "$near_raw" "$near_hash" <<'NODE'
const [stored, deadline, signature, raw, hash] = process.argv.slice(2);
const submission = JSON.parse(stored);
submission.proposal.deadline = Number(deadline);
submission.attestation_signature = signature;
submission.raw_transaction = raw;
submission.transaction_hash = hash;
submission.submitted = false;
process.stdout.write(JSON.stringify(submission));
NODE
)
settlement_signer=$(cast wallet address --private-key "$attestor_key" | tr '[:upper:]' '[:lower:]')
psql_exec -c \
  "INSERT INTO settlement_transaction_attempts
       (transaction_hash, lease_id, claim_generation, escrow_address,
        chain_lease_id, transaction_nonce, signer_address, raw_transaction,
        proposal, status, nonce_reservation_state, generation_binding_state)
   SELECT '$near_hash', job.lease_id, job.claim_generation, lease.escrow_address,
          lease.chain_lease_id, $settlement_nonce, '$settlement_signer', '$near_raw',
          '$near_proposal'::jsonb, 'prepared', 'reserved', 'verified'
   FROM settlement_jobs AS job
   JOIN leases AS lease ON lease.lease_id = job.lease_id
   WHERE job.lease_id = $lease_id;
   UPDATE settlement_transaction_attempts
   SET status = 'superseded', superseded_at = NOW()
   WHERE transaction_hash = '$original_settlement_hash';
   UPDATE settlement_jobs
   SET proposal = '$near_proposal'::jsonb, raw_transaction = '$near_raw',
       transaction_hash = '$near_hash', transaction_nonce = $settlement_nonce,
       status = 'submitted', available_at = NOW()
   WHERE lease_id = $lease_id;" >/dev/null
cast rpc --rpc-url "$rpc_url" evm_setAutomine false >/dev/null
accepted_near_hash=$(cast rpc --rpc-url "$rpc_url" eth_sendRawTransaction "$near_raw" | tr -d '"')
test "$accepted_near_hash" = "$near_hash"
run_settlement
fresh_submission=$(psql_exec -AtF '|' -c \
  "SELECT raw_transaction, transaction_hash, transaction_nonce,
          proposal->'proposal'->>'deadline'
   FROM settlement_jobs WHERE lease_id = $lease_id")
IFS='|' read -r settlement_raw settlement_hash replacement_nonce replacement_deadline \
  <<<"$fresh_submission"
test "$settlement_hash" != "$near_hash"
test "$replacement_nonce" = "$settlement_nonce"
test "$replacement_deadline" -gt "$(($(date +%s) + 600))"
test "$(psql_exec -Atc \
  "SELECT COUNT(*) = 3
       AND count(*) FILTER (
           WHERE transaction_hash = '$near_hash'
             AND raw_transaction = '$near_raw'
             AND status = 'superseded') = 1
       AND count(*) FILTER (
           WHERE transaction_hash = '$settlement_hash'
             AND transaction_nonce = $settlement_nonce
             AND status = 'submitted') = 1
   FROM settlement_transaction_attempts WHERE lease_id = $lease_id")" = t
test "$(cast rpc --rpc-url "$rpc_url" eth_getTransactionByHash "$near_hash")" = null
test "$(cast rpc --rpc-url "$rpc_url" evm_revert "$deadline_replacement_snapshot")" = true
cast rpc --rpc-url "$rpc_url" anvil_dropTransaction "$settlement_hash" >/dev/null
test "$(cast rpc --rpc-url "$rpc_url" eth_getTransactionByHash "$settlement_hash")" = null
cast rpc --rpc-url "$rpc_url" evm_setAutomine true >/dev/null

# A receipt that reverted inside the reorg window remains recheckable. Roll the
# chain back, make the exact signed proposal expire, and observe its shallow
# revert without retiring the hash.
settlement_success_snapshot=$(cast rpc --rpc-url "$rpc_url" evm_snapshot | tr -d '"')
cast rpc --rpc-url "$rpc_url" evm_increaseTime 3601 >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
shallow_revert_hash=$(cast rpc --rpc-url "$rpc_url" eth_sendRawTransaction "$settlement_raw" \
  | tr -d '"')
test "$shallow_revert_hash" = "$settlement_hash"
test "$(cast receipt "$settlement_hash" --rpc-url "$rpc_url" --json \
  | node -e 'let data=""; process.stdin.on("data", c => data += c).on("end", () => process.stdout.write(JSON.parse(data).status))')" = 0x0
psql_exec -c \
  "UPDATE settlement_jobs SET available_at = NOW() WHERE lease_id = $lease_id;" >/dev/null
run_settlement
test "$(psql_exec -Atc \
  "SELECT job.status = 'submitted'
       AND job.attempts = 0
       AND attempt.status = 'submitted'
       AND attempt.reverted_at IS NULL
   FROM settlement_jobs AS job
   JOIN settlement_transaction_attempts AS attempt
     ON attempt.transaction_hash = job.transaction_hash
   WHERE job.lease_id = $lease_id
     AND job.transaction_hash = '$settlement_hash'")" = t

# Restore the pre-expiry state and publish the exact same bytes. Once that same
# hash reaches the configured depth, the worker adopts it as canonical.
test "$(cast rpc --rpc-url "$rpc_url" evm_revert "$settlement_success_snapshot")" = true
reorged_success_hash=$(cast rpc --rpc-url "$rpc_url" eth_sendRawTransaction "$settlement_raw" \
  | tr -d '"')
test "$reorged_success_hash" = "$settlement_hash"
for _ in $(seq 1 "$settlement_confirmations"); do
  cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
done
psql_exec -c \
  "UPDATE settlement_jobs SET available_at = NOW() WHERE lease_id = $lease_id;" >/dev/null
run_settlement
test "$(psql_exec -Atc "SELECT status FROM settlement_jobs WHERE lease_id = $lease_id")" = proposed
test "$(psql_exec -Atc \
  "SELECT COUNT(*) = 3
       AND count(*) FILTER (
           WHERE transaction_hash = '$settlement_hash'
             AND raw_transaction = '$settlement_raw'
             AND status = 'confirmed') = 1
       AND count(*) FILTER (
           WHERE transaction_hash IN ('$original_settlement_hash', '$near_hash')
             AND status = 'superseded') = 2
   FROM settlement_transaction_attempts WHERE lease_id = $lease_id")" = t

register_settlement_node() {
  local test_node=$1
  local metadata nonce deadline digest signature
  metadata=$(cast keccak "settlement-concurrency-$test_node")
  nonce=$(cast call "$registry" "enrollmentNonces(address)(uint256)" "$settlement_node_operator" \
    --rpc-url "$rpc_url")
  deadline=$(($(cast block latest --field timestamp --rpc-url "$rpc_url") + 7200))
  digest=$(cast call "$registry" \
    "enrollmentDigest(bytes32,bytes32,address,address,uint128,bytes32,uint256,uint256)(bytes32)" \
    "$test_node" "$test_node" "$settlement_node_operator" "$provider" 100 \
    "$metadata" "$nonce" "$deadline" \
    --rpc-url "$rpc_url")
  signature=$(cast wallet sign "$digest" --no-hash --private-key "$deployer_key")
  cast send "$registry" \
    "register(bytes32,bytes32,address,uint128,bytes32,uint256,bytes)" \
    "$test_node" "$test_node" "$provider" 100 \
    "$metadata" "$deadline" "$signature" \
    --private-key "$deployer_key" --rpc-url "$rpc_url" >/dev/null
}

create_closed_settlement_lease() {
  local test_node=$1
  local reference=$2
  cast send "$escrow" "createLease(bytes32,uint32,bytes32)" \
    "$test_node" 60 "$reference" \
    --private-key "$deployer_key" --rpc-url "$rpc_url" >/dev/null
  cast call "$escrow" "leaseCount()(uint256)" --rpc-url "$rpc_url"
}

settlement_node_a=$(cast keccak settlement-concurrency-node-a)
settlement_node_b=$(cast keccak settlement-concurrency-node-b)
settlement_node_operator=$(cast wallet address --private-key "$deployer_key")
cast send "$usd" "approve(address,uint256)" "$registry" \
  0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  --private-key "$deployer_key" --rpc-url "$rpc_url" >/dev/null
register_settlement_node "$settlement_node_a"
register_settlement_node "$settlement_node_b"
concurrent_chain_a=$(create_closed_settlement_lease \
  "$settlement_node_a" "$(cast keccak settlement-concurrency-lease-a)")
concurrent_chain_b=$(create_closed_settlement_lease \
  "$settlement_node_b" "$(cast keccak settlement-concurrency-lease-b)")
for chain_lease in "$concurrent_chain_a" "$concurrent_chain_b"; do
  cast send "$escrow" "startAccess(uint256)" "$chain_lease" \
    --private-key "$gateway_key" --rpc-url "$rpc_url" >/dev/null
done
cast rpc --rpc-url "$rpc_url" evm_increaseTime 10 >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
for chain_lease in "$concurrent_chain_a" "$concurrent_chain_b"; do
  cast send "$escrow" "closeAccess(uint256)" "$chain_lease" \
    --private-key "$gateway_key" --rpc-url "$rpc_url" >/dev/null
done

lease_window() {
  cast call "$escrow" \
    "getLease(uint256)((address,bytes32,bytes32,uint128,uint128,uint32,uint64,uint64,uint64,uint64,uint64,uint128,bytes32,uint8))" \
    "$1" --rpc-url "$rpc_url" --json \
    | node -e '
        let data = "";
        process.stdin.on("data", chunk => data += chunk).on("end", () => {
          const decoded = JSON.parse(data);
          const lease = Array.isArray(decoded[0]) ? decoded[0] : decoded;
          const number = value => Number(typeof value === "string" ? BigInt(value) : value);
          process.stdout.write(`${number(lease[7])}|${number(lease[8])}`);
        });
      '
}

queue_settlement_fixture() {
  local test_node=$1
  local chain_lease=$2
  local quote_id=$3
  local funding_hash=$4
  local instance_id=$5
  local window access_started access_ended internal_id
  window=$(lease_window "$chain_lease")
  IFS='|' read -r access_started access_ended <<<"$window"
  psql_exec -c \
    "INSERT INTO node_offers (node_id, document, updated_at)
     SELECT '$test_node',
            document || jsonb_build_object(
              'node_id', '$test_node',
              'operator_wallet', lower('$settlement_node_operator'),
              'payout_wallet', lower('$provider'),
              'online', false,
              'command_channel', false,
              'managed_batch', false),
            NOW()
     FROM node_offers WHERE node_id = '$node_id';
     INSERT INTO lease_quotes (quote_id, node_id, document, expires_at, subject)
     VALUES ('$quote_id', '$test_node', '{}'::jsonb,
             NOW() + INTERVAL '1 hour', 'did:privy:lifecycle');
     INSERT INTO leases
         (quote_id, subject, renter_wallet, funding_transaction_hash, document,
          state, escrow_address, chain_lease_id)
     VALUES
         ('$quote_id', 'did:privy:lifecycle',
          '0x1111111111111111111111111111111111111111', '$funding_hash',
          jsonb_build_object('node_id', '$test_node'),
          'settlement_pending', '$escrow_db', $chain_lease);" >/dev/null
  internal_id=$(psql_exec -Atc "SELECT lease_id FROM leases WHERE quote_id = '$quote_id'")
  psql_exec -c \
    "INSERT INTO settlement_jobs (lease_id, evidence)
     SELECT $internal_id,
            jsonb_build_object(
              'lease_id', $internal_id,
              'chain_lease_id', $chain_lease,
              'lease_nonce', 1,
              'node_id', base.evidence->'node_id',
              'device_public_key', base.evidence->'device_public_key',
              'gpu_model', base.evidence->'gpu_model',
              'image_digest', base.evidence->'image_digest',
              'rate_per_second', 100,
              'deposit_base_units', 6000,
              'duration_seconds', 60,
              'access_started_at', $access_started,
              'access_ended_at', $access_ended,
              'cuda_ready_at', $access_started,
              'interactive_access_ready_at', $access_started,
              'gateway_closed_at', $access_ended,
              'execution', jsonb_build_object(
                  'mode', 'vast', 'instance_id', $instance_id,
                  'hourly_cost_micros', 100000),
              'node_telemetry', '[]'::jsonb)
     FROM settlement_jobs AS base WHERE base.lease_id = $lease_id;" >/dev/null
  printf '%s' "$internal_id"
}

concurrent_lease_a=$(queue_settlement_fixture \
  "$settlement_node_a" "$concurrent_chain_a" \
  018f0000-0000-7000-8000-000000000301 \
  0x0000000000000301000000000000000000000000000000000000000000000001 301)
concurrent_lease_b=$(queue_settlement_fixture \
  "$settlement_node_b" "$concurrent_chain_b" \
  018f0000-0000-7000-8000-000000000302 \
  0x0000000000000302000000000000000000000000000000000000000000000002 302)

# The proxy accepts the first raw transaction, drops its response, and then
# deliberately serves that stale pending nonce to the worker holding the lock
# for the second job. Durable reservations must still force distinct nonces.
PORT="$ambiguous_rpc_port" RPC_URL="$rpc_url" \
  node scripts/mock-ambiguous-rpc.mjs >"$root/ambiguous-rpc.log" 2>&1 &
ambiguous_rpc_pid=$!
for _ in $(seq 1 30); do
  if cast chain-id --rpc-url "$ambiguous_rpc_url" >/dev/null 2>&1; then break; fi
  sleep 1
done
settlement_rpc_url="$ambiguous_rpc_url"
run_settlement >"$root/settlement-concurrent-a.log" 2>&1 &
settlement_a_pid=$!
run_settlement >"$root/settlement-concurrent-b.log" 2>&1 &
settlement_b_pid=$!
if ! wait "$settlement_a_pid"; then
  cat "$root/settlement-concurrent-a.log" >&2
  exit 1
fi
if ! wait "$settlement_b_pid"; then
  cat "$root/settlement-concurrent-b.log" >&2
  exit 1
fi
test "$(psql_exec -Atc \
  "SELECT COUNT(*) = 2
       AND COUNT(DISTINCT transaction_nonce) = 2
       AND COUNT(DISTINCT raw_transaction) = 2
       AND MAX(transaction_nonce) - MIN(transaction_nonce) = 1
   FROM settlement_transaction_attempts
   WHERE lease_id IN ($concurrent_lease_a, $concurrent_lease_b)")" = t
test "$(psql_exec -Atc \
  "SELECT COUNT(*) = 2
   FROM settlement_signer_nonce_reservations
   WHERE lease_id IN ($concurrent_lease_a, $concurrent_lease_b)")" = t
test "$(psql_exec -Atc \
  "SELECT count(*) FILTER (WHERE status = 'queued' AND attempts = 1) = 1
       AND count(*) FILTER (WHERE status = 'submitted' AND attempts = 0) = 1
   FROM settlement_jobs
   WHERE lease_id IN ($concurrent_lease_a, $concurrent_lease_b)")" = t

ambiguous_lease_id=$(psql_exec -Atc \
  "SELECT lease_id FROM settlement_jobs
   WHERE lease_id IN ($concurrent_lease_a, $concurrent_lease_b)
     AND status = 'queued' AND attempts = 1")
ambiguous_submission=$(psql_exec -AtF '|' -c \
  "SELECT raw_transaction, transaction_hash, transaction_nonce
   FROM settlement_jobs WHERE lease_id = $ambiguous_lease_id")
IFS='|' read -r ambiguous_raw ambiguous_hash ambiguous_nonce <<<"$ambiguous_submission"
kill "$ambiguous_rpc_pid"
wait "$ambiguous_rpc_pid" 2>/dev/null || true
ambiguous_rpc_pid=
settlement_rpc_url="$rpc_url"
psql_exec -c \
  "UPDATE settlement_jobs SET available_at = NOW()
   WHERE lease_id = $ambiguous_lease_id;" >/dev/null
run_settlement
test "$(psql_exec -Atc \
  "SELECT job.status = 'submitted'
       AND job.attempts = 1
       AND job.raw_transaction = '$ambiguous_raw'
       AND job.transaction_hash = '$ambiguous_hash'
       AND job.transaction_nonce = $ambiguous_nonce
       AND COUNT(attempt.*) = 1
       AND bool_and(attempt.status = 'submitted')
       AND bool_and(attempt.submission_count = 1)
   FROM settlement_jobs AS job
   JOIN settlement_transaction_attempts AS attempt ON attempt.lease_id = job.lease_id
   WHERE job.lease_id = $ambiguous_lease_id
   GROUP BY job.lease_id")" = t

cast rpc --rpc-url "$rpc_url" evm_increaseTime 86401 >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
psql_exec -c \
  "UPDATE lifecycle_outbox SET available_at = NOW() WHERE lease_id = $lease_id AND kind = 'finalize';" \
  >/dev/null
run_lifecycle
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
sleep 6
run_lifecycle
test "$(psql_exec -Atc "SELECT state FROM leases WHERE lease_id = $lease_id")" = finalized

# A managed runner can finish exactly at the lease deadline while the lifecycle
# worker is down. On restart, its signed failure must close the already-ended
# access window and enter settlement without dropping or rewriting the report.
managed_node=$(cast keccak managed-restart-node)
register_settlement_node "$managed_node"
managed_reference=$(cast keccak managed-restart-after-deadline)
cast send "$escrow" "createLease(bytes32,uint32,bytes32)" \
  "$managed_node" 60 "$managed_reference" \
  --private-key "$deployer_key" --rpc-url "$rpc_url" >/dev/null
managed_chain_lease_id=$(cast call "$escrow" "leaseCount()(uint256)" --rpc-url "$rpc_url")
cast send "$escrow" "startAccess(uint256)" "$managed_chain_lease_id" \
  --private-key "$gateway_key" --rpc-url "$rpc_url" >/dev/null
managed_window=$(lease_window "$managed_chain_lease_id")
IFS='|' read -r managed_access_started ignored_access_end <<<"$managed_window"
test "$ignored_access_end" = 0
managed_deadline=$((managed_access_started + 60))
cast rpc --rpc-url "$rpc_url" evm_increaseTime 61 >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
managed_gateway=$(cast wallet address --private-key "$gateway_key")
managed_close_nonce=$(cast nonce "$managed_gateway" --block pending --rpc-url "$rpc_url")
managed_close_raw=$(cast mktx "$escrow" "closeAccess(uint256)" \
  "$managed_chain_lease_id" --private-key "$gateway_key" --rpc-url "$rpc_url" \
  --chain 4663 --legacy --nonce "$managed_close_nonce" --gas-limit 200000)
managed_close_hash=$(cast keccak "$managed_close_raw")
test "$(cast rpc --rpc-url "$rpc_url" eth_sendRawTransaction "$managed_close_raw" \
  | tr -d '"')" = "$managed_close_hash"
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
managed_window=$(lease_window "$managed_chain_lease_id")
IFS='|' read -r observed_managed_start managed_access_ended <<<"$managed_window"
test "$observed_managed_start" = "$managed_access_started"
test "$managed_access_ended" -gt "$managed_deadline"

managed_image="docker.io/library/runtime@$image_digest"
managed_command='nvidia-smi --query-gpu=name --format=csv,noheader'
managed_spec_hash=$(node - "$managed_image" "$managed_command" <<'NODE'
const crypto = require("crypto");
const [image, command] = process.argv.slice(2);
const spec = {image, command, duration_seconds: 60, min_vram_mib: 16000,
  expected_exit_code: 0};
const payload = Buffer.concat([
  Buffer.from("prism-gpu-repro-spec-v1\0"),
  Buffer.from(JSON.stringify(spec)),
]);
process.stdout.write(crypto.createHash("sha256").update(payload).digest("hex"));
NODE
)
managed_quote_id=018f0000-0000-7000-8000-000000000401
managed_command_id=018f0000-0000-7000-8000-000000000402
managed_report_id=018f0000-0000-7000-8000-000000000403
managed_lease_id=$(psql_exec -Atc "SELECT nextval('leases_internal_id_seq')")
managed_funding_hash=$(node -e \
  'process.stdout.write(`0x${BigInt(process.argv[1]).toString(16).padStart(64, "0")}`)' \
  "$managed_lease_id")
managed_started_at=$(node -e \
  'process.stdout.write(new Date(Number(process.argv[1]) * 1000).toISOString().replace(".000Z", "Z"))' \
  "$managed_access_started")
managed_finished_at=$(node -e \
  'process.stdout.write(new Date(Number(process.argv[1]) * 1000).toISOString().replace(".000Z", "Z"))' \
  "$managed_deadline")
managed_report_signer=$(cast wallet address --private-key "$gateway_key" \
  | tr '[:upper:]' '[:lower:]')
managed_host_key_hash=$(printf 'cd%.0s' {1..32})
managed_report_payload=$(node - \
  "$managed_report_id" "$managed_report_signer" "$managed_command_id" \
  "$managed_lease_id" "$managed_started_at" "$managed_finished_at" \
  "$managed_host_key_hash" <<'NODE'
const [reportId, signer, commandId, leaseId, startedAt, finishedAt, hostKeyHash] =
  process.argv.slice(2);
process.stdout.write(JSON.stringify({
  report_id: reportId,
  signer,
  command_id: commandId,
  lease_id: Number(leaseId),
  provider: "vast",
  provider_instance_id: 9401,
  gpu_model: "NVIDIA lifecycle GPU",
  gpu_vram_mib: 24576,
  transport_host_key_sha256: hostKeyHash,
  started_at: startedAt,
  finished_at: finishedAt,
  outcome: "failed",
  error: "managed runner restarted after lease deadline",
}));
NODE
)
managed_report_preimage=$(node - "$managed_report_payload" <<'NODE'
const payload = process.argv[2];
const encoded = Buffer.concat([
  Buffer.from("prism-managed-command-report-v1\0"),
  Buffer.from(payload),
]);
process.stdout.write(`0x${encoded.toString("hex")}`);
NODE
)
managed_report_digest=$(cast keccak "$managed_report_preimage")
managed_report_signature=$(cast wallet sign "$managed_report_digest" --no-hash \
  --private-key "$gateway_key")
managed_report=$(node - "$managed_report_payload" "$managed_report_signature" <<'NODE'
const report = JSON.parse(process.argv[2]);
report.signature = process.argv[3].toLowerCase();
process.stdout.write(JSON.stringify(report));
NODE
)
managed_command_document=$(node - \
  "$managed_command_id" "$managed_node" "$managed_lease_id" \
  "$managed_started_at" "$managed_finished_at" "$managed_image" "$managed_command" <<'NODE'
const [commandId, nodeId, leaseId, issuedAt, expiresAt, image, command] =
  process.argv.slice(2);
process.stdout.write(JSON.stringify({
  command_id: commandId,
  node_id: nodeId,
  lease_id: Number(leaseId),
  issued_at: issuedAt,
  expires_at: expiresAt,
  kind: {type: "batch", image, command, duration_seconds: 60},
}));
NODE
)

psql_exec -c \
  "INSERT INTO node_offers (node_id, document, updated_at)
   SELECT '$managed_node',
          document || jsonb_build_object(
            'node_id', '$managed_node',
            'operator_wallet', lower('$settlement_node_operator'),
            'payout_wallet', lower('$provider'),
            'online', false, 'command_channel', false, 'managed_batch', true),
          NOW()
   FROM node_offers WHERE node_id = '$node_id';
   INSERT INTO lease_quotes
       (quote_id, node_id, document, expires_at, subject, consumed_at)
   SELECT '$managed_quote_id', '$managed_node',
          document || jsonb_build_object(
            'quote_id', '$managed_quote_id', 'node_id', '$managed_node',
            'image', '$managed_image', 'duration_seconds', 60,
            'min_vram_mib', 16000, 'command', '$managed_command',
            'repro', jsonb_build_object(
              'token_hash', repeat('ab', 32), 'spec_hash', '$managed_spec_hash',
              'expected_exit_code', 0, 'executor', 'managed')),
          NOW() + INTERVAL '1 hour', subject, NOW()
   FROM lease_quotes WHERE quote_id = '$quote_id';
   INSERT INTO leases
       (lease_id, quote_id, subject, renter_wallet, funding_transaction_hash,
        document, state, escrow_address, chain_lease_id)
   SELECT $managed_lease_id, '$managed_quote_id', subject, renter_wallet,
          '$managed_funding_hash',
          document || jsonb_build_object(
            'lease_id', $managed_lease_id,
            'chain_lease_id', $managed_chain_lease_id,
            'escrow_address', '$escrow_db',
            'quote_id', '$managed_quote_id', 'node_id', '$managed_node',
            'image', '$managed_image', 'duration_seconds', 60,
            'rate_per_second', 100, 'maximum_escrow', 6000,
            'funding_transaction_hash', '$managed_funding_hash',
            'state', 'active', 'command', '$managed_command',
            'repro', jsonb_build_object(
              'token_hash', repeat('ab', 32), 'spec_hash', '$managed_spec_hash',
              'expected_exit_code', 0, 'executor', 'managed')),
          'active', '$escrow_db', $managed_chain_lease_id
   FROM leases WHERE lease_id = $lease_id;
   INSERT INTO lease_lifecycle
       (lease_id, connection_id, node_ready_at, cuda_ready_at, gateway_ready_at,
        access_started_at, gateway_closed_at)
   VALUES
       ($managed_lease_id, 'vast:9401', to_timestamp($managed_access_started),
        to_timestamp($managed_access_started), to_timestamp($managed_access_started),
        to_timestamp($managed_access_started), to_timestamp($managed_access_ended));
   INSERT INTO cloud_instances
       (lease_id, provider, provider_instance_id, provider_offer_id,
        hourly_cost_micros, status, started_at, destroyed_at, observed_at,
        gpu_model, gpu_vram_mib)
   VALUES
       ($managed_lease_id, 'vast', 9401, 9402, 100000, 'destroyed',
        to_timestamp($managed_access_started), to_timestamp($managed_access_ended),
        to_timestamp($managed_deadline), 'NVIDIA lifecycle GPU', 24576);
   INSERT INTO managed_repro_jobs
       (command_id, lease_id, command, status, transport_host_key,
        transport_host_key_sha256, gpu_model, gpu_vram_mib,
        prepared_provider_instance_id, prepared_hourly_cost_micros,
        report, started_at, finished_at, last_error)
   VALUES
       ('$managed_command_id', $managed_lease_id, '$managed_command_document'::jsonb,
        'failed', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILifecycleManagedHostKey',
        '$managed_host_key_hash', 'NVIDIA lifecycle GPU', 24576,
        9401, 100000, '$managed_report'::jsonb,
        to_timestamp($managed_access_started), to_timestamp($managed_deadline),
        'managed runner restarted after lease deadline');
   INSERT INTO lifecycle_outbox (action_id, lease_id, kind)
   VALUES ('018f0000-0000-7000-8000-000000000404', $managed_lease_id,
           'close_access');
   INSERT INTO lifecycle_transaction_attempts
       (transaction_hash, action_id, claim_generation, transaction_nonce,
        signer_address, raw_transaction, status)
   VALUES
       ('$managed_close_hash', '018f0000-0000-7000-8000-000000000404', 0,
        $managed_close_nonce, '$managed_report_signer', '$managed_close_raw', 'prepared');
   UPDATE lifecycle_outbox
   SET status = 'submitted', raw_transaction = '$managed_close_raw',
       transaction_hash = '$managed_close_hash', transaction_nonce = $managed_close_nonce
   WHERE action_id = '018f0000-0000-7000-8000-000000000404';" >/dev/null

run_lifecycle
test "$(psql_exec -Atc \
  "SELECT lease.state = 'settlement_pending'
       AND action.status = 'completed'
       AND action.raw_transaction = '$managed_close_raw'
       AND action.transaction_hash = '$managed_close_hash'
       AND action.transaction_nonce = $managed_close_nonce
       AND action.confirmed_block IS NOT NULL
       AND lifecycle.access_ended_at = to_timestamp($managed_access_ended)
   FROM leases AS lease
   JOIN lease_lifecycle AS lifecycle ON lifecycle.lease_id = lease.lease_id
   JOIN lifecycle_outbox AS action ON action.lease_id = lease.lease_id
   WHERE lease.lease_id = $managed_lease_id AND action.kind = 'close_access'")" = t
test "$(psql_exec -Atc \
  "SELECT job.status = 'queued'
       AND job.evidence #>> '{repro,report,executor}' = 'managed'
       AND job.evidence #> '{repro,report,report}' = managed.report
       AND managed.report = '$managed_report'::jsonb
       AND job.evidence #>> '{repro,report,report,outcome}' = 'failed'
       AND (job.evidence #>> '{repro,report,report,finished_at}')::timestamptz
             = to_timestamp($managed_deadline)
       AND (job.evidence->>'last_observed_at')::bigint = $managed_deadline
   FROM settlement_jobs AS job
   JOIN managed_repro_jobs AS managed ON managed.lease_id = job.lease_id
   WHERE job.lease_id = $managed_lease_id")" = t

timeout_reference=$(cast keccak timeout-quote)
cast send "$escrow" "createLease(bytes32,uint32,bytes32)" \
  "$node_id" 60 "$timeout_reference" \
  --private-key "$deployer_key" --rpc-url "$rpc_url" >/dev/null
test "$(cast call "$escrow" "leaseCount()(uint256)" --rpc-url "$rpc_url")" = \
  "$((managed_chain_lease_id + 1))"
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
timeout_quote_file="$root/timeout-quote.json"
timeout_quote_status=$(curl --show-error --silent --output "$timeout_quote_file" \
  --write-out '%{http_code}' \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:lifecycle" \
  -H "x-prism-development-session: session-lifecycle" \
  -H "x-request-id: timeout-match" \
  -d "$request" "$control_url/v1/leases/match")
if [[ $timeout_quote_status != 200 ]]; then
  cat "$timeout_quote_file" >&2
  exit 1
fi
quote=$(<"$timeout_quote_file")
quote_id=$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).quote_id)' "$quote")
printf -v funding_hash '0x%016x000000001111111111111111111111111111111111111111' \
  "$((managed_chain_lease_id + 1))"
curl --fail --silent \
  -H "Content-Type: application/json" \
  -H "x-prism-development-subject: did:privy:lifecycle" \
  -H "x-prism-development-session: session-lifecycle" \
  -H "x-request-id: timeout-confirm" \
  -d "{\"quote_id\":\"$quote_id\",\"transaction_hash\":\"$funding_hash\",\"ssh_authorized_key\":\"$ssh_key\"}" \
  "$control_url/v1/leases/confirm" >/dev/null
timeout_lease_id=$(psql_exec -Atc "SELECT lease_id FROM leases WHERE quote_id = '$quote_id'")
[[ $timeout_lease_id =~ ^[0-9]+$ ]]
psql_exec -c \
  "UPDATE leases SET created_at = NOW() - INTERVAL '11 minutes' WHERE lease_id = $timeout_lease_id;" \
  >/dev/null
cast rpc --rpc-url "$rpc_url" evm_increaseTime 601 >/dev/null
cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null

timeout_chain_lease_id=$(psql_exec -Atc \
  "SELECT chain_lease_id FROM leases WHERE lease_id = $timeout_lease_id")
gateway=$(cast wallet address --private-key "$gateway_key")
current_nonce=$(cast nonce "$gateway" --block pending --rpc-url "$rpc_url")
test "$current_nonce" -gt 0
stale_raw=$(cast mktx "$escrow" "expireProvision(uint256,bytes32)" \
  "$timeout_chain_lease_id" \
  0x0000000000000000000000000000000000000000000000000000000000000000 \
  --private-key "$gateway_key" --rpc-url "$rpc_url" --legacy --nonce 0 \
  --gas-limit 200000)
stale_hash=$(cast keccak "$stale_raw")
psql_exec -c \
  "SET session_replication_role = replica;
   INSERT INTO lifecycle_outbox
       (action_id, lease_id, kind, status, raw_transaction, transaction_hash,
        transaction_nonce)
   VALUES
       ('018f0000-0000-7000-8000-000000000202', $timeout_lease_id,
        'expire_provision', 'queued', '$stale_raw', '$stale_hash', 0);
   INSERT INTO lifecycle_transaction_attempts
       (transaction_hash, action_id, claim_generation, transaction_nonce,
        raw_transaction, generation_binding_state, status)
   VALUES
       ('$stale_hash', '018f0000-0000-7000-8000-000000000202', 0, 0,
        '$stale_raw', 'pending', 'prepared');
   SET session_replication_role = origin;" \
  >/dev/null

run_lifecycle
test "$(psql_exec -Atc \
  "SELECT raw_transaction <> '$stale_raw'
       AND transaction_hash <> '$stale_hash'
       AND transaction_nonce = $current_nonce
       AND status = 'submitted'
   FROM lifecycle_outbox
   WHERE lease_id = $timeout_lease_id AND kind = 'expire_provision'")" = t
test "$(psql_exec -Atc \
  "SELECT generation_binding_state = 'quarantined'
       AND generation_binding_reason = 'calldata_mismatch'
       AND signer_address IS NULL
   FROM lifecycle_transaction_attempts
   WHERE transaction_hash = '$stale_hash'")" = t
test "$(cast rpc --rpc-url "$rpc_url" eth_getTransactionByHash "$stale_hash")" = null

cast rpc --rpc-url "$rpc_url" evm_mine >/dev/null
sleep 6
run_lifecycle
test "$(psql_exec -Atc "SELECT state FROM leases WHERE lease_id = $timeout_lease_id")" = refunded

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

env \
  DATABASE_URL="$database_url" \
  PRISM_ACCESS_CREDENTIAL_KEY="$credential_key" \
  PRISM_ALLOW_DEVELOPMENT_SIGNER=1 \
  PRISM_DEVELOPMENT_PRIVATE_KEY="$gateway_key" \
  PRISM_GATEWAY_CONTROL_TOKEN="$gateway_token" \
  PRISM_GATEWAY_CONTROL_URL="$mock_url" \
  PRISM_LEASE_ESCROW_ADDRESS="$escrow" \
  PRISM_LIFECYCLE_CONFIRMATIONS=1 \
  PRISM_NODE_REGISTRY_ADDRESS="$registry" \
  PRISM_RPC_URL="$rpc_url" \
  target/debug/prism-lifecycle-worker >"$root/lifecycle-shutdown.log" 2>&1 &
lifecycle_pid=$!
sleep 1
kill -0 "$lifecycle_pid"
kill -TERM "$lifecycle_pid"
for _ in $(seq 1 100); do
  if ! kill -0 "$lifecycle_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if kill -0 "$lifecycle_pid" 2>/dev/null; then
  cat "$root/lifecycle-shutdown.log" >&2
  echo "lifecycle worker did not exit after SIGTERM" >&2
  exit 1
fi
wait "$lifecycle_pid"
lifecycle_pid=

echo "durable lease lifecycle end-to-end passed"
