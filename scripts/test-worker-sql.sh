#!/usr/bin/env bash
# Run the statements the workers issue against a real Postgres.
#
# A bound parameter that does not match a Postgres function signature is
# invisible to rustc, clippy and the unit tests: it fails only when the server
# parses it. One such statement bound a float to make_interval's hours argument,
# which is an int, and every lease refunded without an instance being created
# until it was caught by hand.
#
# These are copies rather than the statements themselves, so they can drift.
# That is still worth having: the drift is visible in review, and the class of
# error this catches otherwise reaches production intact.
# Set PRISM_TEST_POSTGRES_MODE=local to use an isolated local cluster when the
# pinned Docker image is unavailable.
set -Eeuo pipefail

for command in anvil cargo cast node; do
  command -v "$command" >/dev/null
done

container="prism-worker-sql-$$"
postgres_mode=${PRISM_TEST_POSTGRES_MODE:-docker}
postgres_root=
anvil_pid=
settlement_pid=
cleanup() {
  if [[ -n $settlement_pid ]]; then
    kill "$settlement_pid" 2>/dev/null || true
    wait "$settlement_pid" 2>/dev/null || true
  fi
  if [[ -n $anvil_pid ]]; then
    kill "$anvil_pid" 2>/dev/null || true
    wait "$anvil_pid" 2>/dev/null || true
  fi
  if [[ $postgres_mode == local && -n $postgres_root ]]; then
    if [[ ! -f $postgres_root/data/postmaster.pid ]] || \
      pg_ctl -D "$postgres_root/data" -m immediate stop >/dev/null 2>&1; then
      rm -rf -- "$postgres_root"
    else
      echo "local PostgreSQL did not stop; retained $postgres_root" >&2
    fi
  elif [[ $postgres_mode == docker ]]; then
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
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

postgres_port=$(free_port)
anvil_port=$(free_port)
rpc_url="http://127.0.0.1:$anvil_port"
historical_signer_key=0000000000000000000000000000000000000000000000000000000000000004
historical_signer=$(cast wallet address --private-key "$historical_signer_key" \
  | tr '[:upper:]' '[:lower:]')

make_historical_submission() {
  local prefix=$1
  local lease_id=$2
  local chain_lease_id=$3
  local escrow=$4
  local nonce=$5
  local gas_price=$6
  local receipt_data receipt_hash receipt_json typed_data signature raw transaction_hash proposal
  receipt_data=$(node - "$chain_lease_id" <<'NODE'
const crypto = require("crypto");
const chainLeaseId = process.argv[2];
const payload = {
  receipt_id: "018f0000-0000-7000-8000-000000000026",
  lease_id: chainLeaseId,
  node_id_hash: `0x${"11".repeat(32)}`,
  gpu_model: "migration-fixture",
  runtime_seconds: 1,
  charged_base_units: 1,
  refunded_base_units: 0,
  provider_paid_base_units: 1,
  failure_class: null,
  outcome: "finalized",
};
const receiptHash = crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex");
const receipt = {...payload, receipt_hash: receiptHash, transaction_hash: ""};
process.stdout.write(`${receiptHash}\n${JSON.stringify(receipt)}`);
NODE
  )
  receipt_hash=${receipt_data%%$'\n'*}
  receipt_json=${receipt_data#*$'\n'}
  typed_data=$(node - "$escrow" "$chain_lease_id" "$receipt_hash" <<'NODE'
const [escrow, chainLeaseId, receiptHash] = process.argv.slice(2);
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
    leaseId: chainLeaseId,
    usageSeconds: 1,
    receiptHash: `0x${receiptHash}`,
    nonce: 1,
    deadline: 4102444800,
  },
}));
NODE
  )
  signature=$(cast wallet sign "$typed_data" --data --private-key "$historical_signer_key")
  raw=$(cast mktx "$escrow" \
    'proposeSettlement(uint256,uint64,bytes32,uint256,bytes)' \
    "$chain_lease_id" 1 "0x$receipt_hash" 4102444800 "$signature" \
    --private-key "$historical_signer_key" --chain 4663 --legacy --nonce "$nonce" \
    --gas-limit 500000 --gas-price "$gas_price")
  transaction_hash=$(cast keccak "$raw")
  proposal=$(node - "$lease_id" "$chain_lease_id" "$receipt_hash" "$receipt_json" \
    "$signature" "$raw" "$transaction_hash" <<'NODE'
const [leaseId, chainLeaseId, receiptHash, receipt, signature, raw, transactionHash] =
  process.argv.slice(2);
process.stdout.write(JSON.stringify({
  proposal: {
    lease_id: Number(leaseId),
    chain_lease_id: Number(chainLeaseId),
    usage_seconds: 1,
    receipt_hash: receiptHash,
    nonce: 1,
    deadline: 4102444800,
    evidence_hash: `0x${"22".repeat(32)}`,
    receipt: JSON.parse(receipt),
  },
  attestation_signature: signature,
  raw_transaction: raw,
  transaction_hash: transactionHash,
  submitted: true,
}));
NODE
  )
  printf -v "${prefix}_raw" '%s' "$raw"
  printf -v "${prefix}_hash" '%s' "$transaction_hash"
  printf -v "${prefix}_proposal" '%s' "$proposal"
}

if [[ $postgres_mode == local ]]; then
  for command in initdb pg_ctl createdb psql; do
    command -v "$command" >/dev/null
  done
  postgres_root=$(mktemp -d "${TMPDIR:-/tmp}/prism-worker-sql.XXXXXX")
  initdb -D "$postgres_root/data" --auth=trust --username=prism >/dev/null
  pg_ctl -D "$postgres_root/data" -l "$postgres_root/postgres.log" \
    -o "-h 127.0.0.1 -p $postgres_port" start >/dev/null
  createdb -h 127.0.0.1 -p "$postgres_port" -U prism prism
  database_url="postgres://prism@127.0.0.1:$postgres_port/prism?sslmode=disable"
else
  [[ $postgres_mode == docker ]]
  command -v docker >/dev/null
  docker run -d --name "$container" \
    -p "127.0.0.1:$postgres_port:5432" \
    -e POSTGRES_DB=prism -e POSTGRES_USER=prism -e POSTGRES_PASSWORD=prism \
    postgres:17-bookworm@sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394 \
    >/dev/null

  for _ in $(seq 1 60); do
    if [[ $(docker exec -e PGPASSWORD=prism "$container" \
      psql -U prism -d prism -Atc 'SELECT 1' 2>/dev/null || true) == 1 ]]; then
      break
    fi
    sleep 1
  done
  docker exec -e PGPASSWORD=prism "$container" \
    psql -U prism -d prism -Atc 'SELECT 1' >/dev/null
  database_url="postgres://prism:prism@127.0.0.1:$postgres_port/prism"
fi

anvil --chain-id 4663 --host 127.0.0.1 --port "$anvil_port" --silent >/dev/null 2>&1 &
anvil_pid=$!
for _ in $(seq 1 30); do
  if cast chain-id --rpc-url "$rpc_url" >/dev/null 2>&1; then break; fi
  sleep 1
done
[[ $(cast chain-id --rpc-url "$rpc_url") == 4663 ]]

run() {
  if [[ $postgres_mode == local ]]; then
    psql "$database_url" -v ON_ERROR_STOP=1 -q "$@"
  else
    docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U prism -d prism -q "$@"
  fi
}

for migration in services/control-plane/migrations/*.sql; do
  if [[ $(basename "$migration") == 0024_provider_admission.sql ]]; then
    run -c "INSERT INTO accounts (subject) VALUES ('provider-migration-test');
            INSERT INTO node_offers (node_id, document, updated_at)
            VALUES ('provider-migration-node', '{}'::jsonb, NOW());
            INSERT INTO lease_quotes
                (quote_id, node_id, document, expires_at, subject)
            VALUES
                ('018f0000-0000-7000-8000-000000000024', 'provider-migration-node',
                 '{}'::jsonb, NOW() + INTERVAL '1 hour', 'provider-migration-test'),
                ('018f0000-0000-7000-8000-000000000026', 'provider-migration-node',
                 '{}'::jsonb, NOW() + INTERVAL '1 hour', 'provider-migration-test'),
                ('018f0000-0000-7000-8000-000000000028', 'provider-migration-node',
                 '{}'::jsonb, NOW() + INTERVAL '1 hour', 'provider-migration-test'),
                ('018f0000-0000-7000-8000-000000000030', 'provider-migration-node',
                 '{}'::jsonb, NOW() + INTERVAL '1 hour', 'provider-migration-test');
            INSERT INTO leases
                (quote_id, subject, renter_wallet, funding_transaction_hash, document, state,
                 escrow_address, chain_lease_id)
            VALUES
                ('018f0000-0000-7000-8000-000000000024', 'provider-migration-test',
                 '0x1111111111111111111111111111111111111111',
                 '0x2222222222222222222222222222222222222222222222222222222222222222',
                 '{\"node_id\":\"provider-migration-node\"}'::jsonb, 'funded',
                 '0x3333333333333333333333333333333333333333', 24),
                ('018f0000-0000-7000-8000-000000000026', 'provider-migration-test',
                 '0x1111111111111111111111111111111111111111',
                 '0x4444444444444444444444444444444444444444444444444444444444444444',
                 '{\"node_id\":\"provider-migration-node\"}'::jsonb, 'refunded',
                 '0x3333333333333333333333333333333333333333', 26),
                ('018f0000-0000-7000-8000-000000000028', 'provider-migration-test',
                 '0x1111111111111111111111111111111111111111',
                 '0x5555555555555555555555555555555555555555555555555555555555555555',
                 '{\"node_id\":\"provider-migration-node\"}'::jsonb, 'finalized',
                 '0x3333333333333333333333333333333333333333', 28),
                ('018f0000-0000-7000-8000-000000000030', 'provider-migration-test',
                 '0x1111111111111111111111111111111111111111',
                 '0x6666666666666666666666666666666666666666666666666666666666666666',
                 '{\"node_id\":\"provider-migration-node\"}'::jsonb, 'refunded',
                 '0x3333333333333333333333333333333333333333', 30);
            INSERT INTO cloud_instances (lease_id, provider_instance_id, status, destroyed_at)
            SELECT lease_id, 24001, 'running', NULL::timestamptz FROM leases
            WHERE quote_id = '018f0000-0000-7000-8000-000000000024'
            UNION ALL
            SELECT lease_id, 24002, 'running', NULL::timestamptz FROM leases
            WHERE quote_id = '018f0000-0000-7000-8000-000000000026'
            UNION ALL
            SELECT lease_id, 24003, 'failed', NULL::timestamptz FROM leases
            WHERE quote_id = '018f0000-0000-7000-8000-000000000028'
            UNION ALL
            SELECT lease_id, 24004, 'destroyed', NOW() FROM leases
            WHERE quote_id = '018f0000-0000-7000-8000-000000000030';
            INSERT INTO lifecycle_outbox
                (action_id, lease_id, kind, status, attempts, raw_transaction,
                 transaction_hash, transaction_nonce, confirmed_block,
                 confirmed_block_hash, last_error)
            SELECT '018f0000-0000-7000-8000-000000000025'::uuid, lease_id,
                   'expire_provision', 'failed', 100, '0x01',
                   '0x7777777777777777777777777777777777777777777777777777777777777777',
                   512, 240, '0x8888888888888888888888888888888888888888888888888888888888888888',
                   'stale transaction'
            FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000024'
            UNION ALL
            SELECT '018f0000-0000-7000-8000-000000000027'::uuid, lease_id,
                   'expire_provision', 'failed', 100, '0x02',
                   '0x9999999999999999999999999999999999999999999999999999999999999999',
                   513, 241, '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                   'archived refund'
            FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000026'
            UNION ALL
            SELECT '018f0000-0000-7000-8000-000000000029'::uuid, lease_id,
                   'finalize', 'failed', 100, '0x03',
                   '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                   514, 242, '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                   'archived finalization'
            FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000028';
            INSERT INTO settlement_jobs
                (lease_id, evidence, proposal, status, attempts, lease_until)
            SELECT lease_id, '{}'::jsonb, '{\"legacy\":\"proposal-only\"}'::jsonb,
                   'processing', 2, NOW() + INTERVAL '2 minutes'
            FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000026';" >/dev/null
  elif [[ $(basename "$migration") == 0025_lifecycle_transaction_attempts.sql ]]; then
    unsafe_lifecycle_id=$(run -Atc "SELECT lease_id FROM leases
                                   WHERE quote_id = '018f0000-0000-7000-8000-000000000030';")
    run -c "INSERT INTO lifecycle_outbox
                (action_id, lease_id, kind, status)
            VALUES
                ('018f0000-0000-7000-8000-000000000031', $unsafe_lifecycle_id,
                 'finalize', 'submitted');" >/dev/null
    if run -f - < "$migration" >/dev/null 2>&1; then
      echo "empty submitted lifecycle cursor did not block migration 0025" >&2
      exit 1
    fi
    [[ $(run -Atc "SELECT to_regclass('lifecycle_transaction_attempts') IS NULL;") == t ]]
    [[ $(run -Atc "SELECT status || ':' || (raw_transaction IS NULL) || ':' ||
                         (transaction_hash IS NULL) || ':' || (transaction_nonce IS NULL)
                  FROM lifecycle_outbox
                  WHERE action_id = '018f0000-0000-7000-8000-000000000031';") == \
      submitted:t:t:t ]]
    run -c "DELETE FROM lifecycle_outbox
            WHERE action_id = '018f0000-0000-7000-8000-000000000031';
            INSERT INTO lifecycle_outbox
                (action_id, lease_id, kind, status, raw_transaction)
            VALUES
                ('018f0000-0000-7000-8000-000000000031', $unsafe_lifecycle_id,
                 'finalize', 'queued', '0x01');" >/dev/null
    if run -f - < "$migration" >/dev/null 2>&1; then
      echo "partial lifecycle cursor did not block migration 0025" >&2
      exit 1
    fi
    [[ $(run -Atc "SELECT to_regclass('lifecycle_transaction_attempts') IS NULL;") == t ]]
    [[ $(run -Atc "SELECT status || ':' || raw_transaction || ':' ||
                         (transaction_hash IS NULL) || ':' || (transaction_nonce IS NULL)
                  FROM lifecycle_outbox
                  WHERE action_id = '018f0000-0000-7000-8000-000000000031';") == \
      queued:0x01:t:t ]]
    run -c "DELETE FROM lifecycle_outbox
            WHERE action_id = '018f0000-0000-7000-8000-000000000031';" >/dev/null
  elif [[ $(basename "$migration") == 0026_settlement_attempts.sql ]]; then
    unsafe_partial_id=$(run -Atc "SELECT lease_id FROM leases
                                  WHERE quote_id = '018f0000-0000-7000-8000-000000000030';")
    for unsafe_empty_status in submitted proposed disputed finalized; do
      run -c "INSERT INTO settlement_jobs (lease_id, evidence, status)
              VALUES ($unsafe_partial_id, '{}'::jsonb, '$unsafe_empty_status');" >/dev/null
      if run -f - < "$migration" >/dev/null 2>&1; then
        echo "empty $unsafe_empty_status settlement marker did not block migration 0026" >&2
        exit 1
      fi
      [[ $(run -Atc "SELECT COUNT(*) FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'settlement_jobs'
                      AND column_name = 'claim_generation';") == 0 ]]
      [[ $(run -Atc "SELECT status FROM settlement_jobs
                    WHERE lease_id = $unsafe_partial_id;") == "$unsafe_empty_status" ]]
      run -c "DELETE FROM settlement_jobs WHERE lease_id = $unsafe_partial_id;" >/dev/null
    done
    run -c "INSERT INTO settlement_jobs
                (lease_id, evidence, status, confirmed_block, confirmed_block_hash)
            VALUES
                ($unsafe_partial_id, '{}'::jsonb, 'proposed', 30,
                 '0x3030303030303030303030303030303030303030303030303030303030303030');" \
      >/dev/null
    if run -f - < "$migration" >/dev/null 2>&1; then
      echo "confirmation-only settlement cursor did not block migration 0026" >&2
      exit 1
    fi
    [[ $(run -Atc "SELECT COUNT(*) FROM information_schema.columns
                  WHERE table_schema = 'public' AND table_name = 'settlement_jobs'
                    AND column_name = 'claim_generation';") == 0 ]]
    [[ $(run -Atc "SELECT proposal IS NULL AND raw_transaction IS NULL AND
                         transaction_hash IS NULL AND transaction_nonce IS NULL AND
                         confirmed_block = 30 AND confirmed_block_hash IS NOT NULL
                  FROM settlement_jobs WHERE lease_id = $unsafe_partial_id;") == t ]]
    run -c "DELETE FROM settlement_jobs WHERE lease_id = $unsafe_partial_id;" >/dev/null
    run -c "INSERT INTO settlement_jobs
                (lease_id, evidence, proposal, transaction_hash, status)
            VALUES
                ($unsafe_partial_id, '{}'::jsonb, '{\"legacy\":true}'::jsonb,
                 '0x3030303030303030303030303030303030303030303030303030303030303030',
                 'submitted');" >/dev/null
    if run -f - < "$migration" >/dev/null 2>&1; then
      echo "unsafe partial settlement cursor did not block migration 0026" >&2
      exit 1
    fi
    [[ $(run -Atc "SELECT COUNT(*) FROM information_schema.columns
                  WHERE table_schema = 'public' AND table_name = 'settlement_jobs'
                    AND column_name = 'claim_generation';") == 0 ]]
    [[ $(run -Atc "SELECT proposal IS NOT NULL AND raw_transaction IS NULL AND
                         transaction_hash IS NOT NULL AND transaction_nonce IS NULL
                  FROM settlement_jobs WHERE lease_id = $unsafe_partial_id;") == t ]]
    run -c "DELETE FROM settlement_jobs WHERE lease_id = $unsafe_partial_id;" >/dev/null
    for unsafe_later_status in proposed disputed finalized; do
      run -c "INSERT INTO settlement_jobs
                  (lease_id, evidence, proposal, raw_transaction, transaction_hash,
                   transaction_nonce, status)
              VALUES
                  ($unsafe_partial_id, '{}'::jsonb, '{\"legacy\":true}'::jsonb,
                   '0x01',
                   '0x3131313131313131313131313131313131313131313131313131313131313131',
                   31, '$unsafe_later_status');" >/dev/null
      if run -f - < "$migration" >/dev/null 2>&1; then
        echo "unconfirmed $unsafe_later_status settlement cursor did not block migration 0026" >&2
        exit 1
      fi
      [[ $(run -Atc "SELECT COUNT(*) FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'settlement_jobs'
                      AND column_name = 'claim_generation';") == 0 ]]
      [[ $(run -Atc "SELECT status || ':' ||
                           (proposal IS NOT NULL AND raw_transaction IS NOT NULL AND
                            transaction_hash IS NOT NULL AND transaction_nonce = 31) || ':' ||
                           (confirmed_block IS NULL AND confirmed_block_hash IS NULL)
                    FROM settlement_jobs WHERE lease_id = $unsafe_partial_id;") == \
        "$unsafe_later_status:t:t" ]]
      run -c "DELETE FROM settlement_jobs WHERE lease_id = $unsafe_partial_id;" >/dev/null
    done
    historical_loser_id=$(run -Atc "SELECT lease_id FROM leases
                                    WHERE quote_id = '018f0000-0000-7000-8000-000000000024';")
    historical_owner_id=$(run -Atc "SELECT lease_id FROM leases
                                    WHERE quote_id = '018f0000-0000-7000-8000-000000000028';")
    make_historical_submission historical_loser "$historical_loser_id" 24 \
      0x3333333333333333333333333333333333333333 3 1000000000
    make_historical_submission historical_owner "$historical_owner_id" 28 \
      0x3333333333333333333333333333333333333333 3 2000000000
    run -c "INSERT INTO settlement_jobs
                (lease_id, evidence, proposal, status, raw_transaction,
                 transaction_hash, transaction_nonce, confirmed_block,
                 confirmed_block_hash)
            SELECT lease_id, '{}'::jsonb, '$historical_loser_proposal'::jsonb,
                   'failed', '$historical_loser_raw', '$historical_loser_hash',
                   3, NULL::bigint, NULL::text
            FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000024'
            UNION ALL
            SELECT lease_id, '{}'::jsonb, '$historical_owner_proposal'::jsonb,
                   'proposed', '$historical_owner_raw', '$historical_owner_hash',
                   3, 260,
                   '0xd3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3'
            FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000028';" >/dev/null
  fi
  run -f - < "$migration"
done
printf 'migrations applied\n'

# Migration 26 captures and clears the only provably-unsent legacy partial
# cursor shape before installing its strict job trigger. The immutable archive
# keeps the proposal while the job becomes safely writable and retryable.
historical_partial_id=$(run -Atc "SELECT lease_id FROM leases
                                  WHERE quote_id = '018f0000-0000-7000-8000-000000000026';")
[[ $(run -Atc "SELECT job_status || ':' || job_attempts || ':' ||
                     (proposal = '{\"legacy\":\"proposal-only\"}'::jsonb) || ':' ||
                     quarantine_reason
              FROM settlement_legacy_partial_cursors
              WHERE lease_id = $historical_partial_id;") == \
  processing:2:t:provably_unsent_partial_cursor ]]
[[ $(run -Atc "SELECT status || ':' || attempts || ':' ||
                     (proposal IS NULL AND raw_transaction IS NULL AND
                      transaction_hash IS NULL AND transaction_nonce IS NULL) || ':' ||
                     (lease_until IS NULL)
              FROM settlement_jobs WHERE lease_id = $historical_partial_id;") == queued:0:t:t ]]
if run -c "UPDATE settlement_legacy_partial_cursors SET proposal = '{}'::jsonb
           WHERE lease_id = $historical_partial_id;" >/dev/null 2>&1; then
  echo "legacy partial settlement evidence was mutable" >&2
  exit 1
fi
run -c "UPDATE settlement_jobs
        SET status = 'failed', last_error = 'migration regression complete'
        WHERE lease_id = $historical_partial_id;" >/dev/null

[[ $(run -Atc "SELECT status || ':' || submission_count || ':' ||
                     (submitted_at IS NULL) || ':' || (confirmed_at IS NULL)
              FROM settlement_transaction_attempts
              WHERE transaction_hash = '$historical_loser_hash';") == \
  prepared:0:t:t ]]
[[ $(run -Atc "SELECT status || ':' || submission_count || ':' ||
                     (submitted_at IS NOT NULL) || ':' || (confirmed_at IS NOT NULL) || ':' ||
                     confirmed_block
              FROM settlement_transaction_attempts
              WHERE transaction_hash = '$historical_owner_hash';") == \
  confirmed:1:t:t:260 ]]

# Historical workers could sign two different leases with one nonce. Resolve
# the entire signer+nonce group before reserving it: the uniquely confirmed
# lease owns it, its same-lease replacements remain valid, and the failed
# cross-lease attempt stays immutable but cannot reclaim the consumed nonce.
historical_loser_id=$(run -Atc "SELECT lease_id FROM leases
                                WHERE quote_id = '018f0000-0000-7000-8000-000000000024';")
historical_owner_id=$(run -Atc "SELECT lease_id FROM leases
                                WHERE quote_id = '018f0000-0000-7000-8000-000000000028';")
make_historical_submission historical_replacement "$historical_owner_id" 28 \
  0x3333333333333333333333333333333333333333 3 3000000000
run -c "SET session_replication_role = replica;
        INSERT INTO settlement_transaction_attempts
            (transaction_hash, lease_id, claim_generation, escrow_address,
             chain_lease_id, transaction_nonce, signer_address, raw_transaction,
             proposal, status, generation_binding_state)
        VALUES
            ('$historical_replacement_hash', $historical_owner_id, 0,
             '0x3333333333333333333333333333333333333333', 28, 3,
             '$historical_signer', '$historical_replacement_raw',
             '$historical_replacement_proposal'::jsonb, 'prepared', 'pending');
        SET session_replication_role = origin;
        INSERT INTO settlement_signer_nonce_reservations
            (signer_address, transaction_nonce, lease_id)
        VALUES ('$historical_signer', 3, $historical_loser_id);" >/dev/null

cargo build --quiet -p prism-settlement-worker
for _ in 1 2; do
  env \
    DATABASE_URL="$database_url" \
    PRISM_ALLOW_DEVELOPMENT_SIGNER=1 \
    PRISM_DEVELOPMENT_PRIVATE_KEY="$historical_signer_key" \
    PRISM_LEASE_ESCROW_ADDRESS=0xffffffffffffffffffffffffffffffffffffffff \
    PRISM_RPC_URL="$rpc_url" \
    PRISM_RUN_ONCE=1 \
    PRISM_SETTLEMENT_CONFIRMATIONS=1 \
    target/debug/prism-settlement-worker >/dev/null
done

# PID 1 must honor the platform's normal stop signal. An idle worker closes its
# claim gate immediately and exits cleanly instead of waiting for SIGKILL.
env \
  DATABASE_URL="$database_url" \
  PRISM_ALLOW_DEVELOPMENT_SIGNER=1 \
  PRISM_DEVELOPMENT_PRIVATE_KEY="$historical_signer_key" \
  PRISM_LEASE_ESCROW_ADDRESS=0xffffffffffffffffffffffffffffffffffffffff \
  PRISM_RPC_URL="$rpc_url" \
  PRISM_SETTLEMENT_CONFIRMATIONS=1 \
  target/debug/prism-settlement-worker >/dev/null 2>&1 &
settlement_pid=$!
sleep 1
kill -0 "$settlement_pid"
kill -TERM "$settlement_pid"
for _ in $(seq 1 100); do
  if ! kill -0 "$settlement_pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if kill -0 "$settlement_pid" 2>/dev/null; then
  echo "settlement worker ignored SIGTERM" >&2
  exit 1
fi
wait "$settlement_pid"
settlement_pid=

[[ $(run -Atc "SELECT nonce_reservation_state || ':' || nonce_reservation_reason || ':' ||
                     signer_address || ':' || transaction_nonce
              FROM settlement_transaction_attempts
              WHERE transaction_hash = '$historical_loser_hash';") == \
  "noncanonical:confirmed_historical_nonce_owner:$historical_signer:3" ]]
[[ $(run -Atc "SELECT COUNT(*) || ':' ||
                     bool_and(nonce_reservation_state = 'reserved') || ':' ||
                     bool_and(nonce_reservation_reason IS NULL)
              FROM settlement_transaction_attempts
              WHERE lease_id = $historical_owner_id AND transaction_nonce = 3;") == 2:t:t ]]
[[ $(run -Atc "SELECT lease_id || ':' || corrected_from_lease_id || ':' || correction_reason
              FROM settlement_signer_nonce_reservations
              WHERE signer_address = '$historical_signer' AND transaction_nonce = 3;") == \
  "$historical_owner_id:$historical_loser_id:confirmed_historical_nonce_owner" ]]
[[ $(run -Atc "SELECT COUNT(*) FROM settlement_jobs AS job
              JOIN settlement_transaction_attempts AS attempt
                ON attempt.transaction_hash = job.transaction_hash
              WHERE job.lease_id = $historical_loser_id
                AND attempt.nonce_reservation_state = 'reserved'
                AND EXISTS (
                    SELECT 1 FROM settlement_signer_nonce_reservations AS reservation
                    WHERE reservation.signer_address = attempt.signer_address
                      AND reservation.transaction_nonce = attempt.transaction_nonce
                      AND reservation.lease_id = attempt.lease_id);" ) == 0 ]]
[[ $(run -Atc "SELECT COALESCE(MAX(transaction_nonce) + 1, 0)
              FROM settlement_signer_nonce_reservations
              WHERE signer_address = '$historical_signer';") == 4 ]]

# A prior escrow generation can reuse the same chain lease id as the current
# generation. Signed bytes aimed at the current escrow must never become valid
# for the old lease merely because that numeric id collides.
run -c "INSERT INTO lease_quotes
            (quote_id, node_id, document, expires_at, subject)
        VALUES
            ('018f0000-0000-7000-8000-000000000032', 'provider-migration-node',
             '{}'::jsonb, NOW() + INTERVAL '1 hour', 'provider-migration-test');
        INSERT INTO leases
            (quote_id, subject, renter_wallet, funding_transaction_hash, document,
             state, escrow_address, chain_lease_id)
        VALUES
            ('018f0000-0000-7000-8000-000000000032', 'provider-migration-test',
             '0x1111111111111111111111111111111111111111',
             '0x3232323232323232323232323232323232323232323232323232323232323232',
             '{\"node_id\":\"provider-migration-node\"}'::jsonb, 'funded',
             '0xffffffffffffffffffffffffffffffffffffffff', 24);" >/dev/null
make_historical_submission historical_misbound "$historical_loser_id" 24 \
  0xffffffffffffffffffffffffffffffffffffffff 12 4000000000
run -c "SET session_replication_role = replica;
        INSERT INTO settlement_transaction_attempts
            (transaction_hash, lease_id, claim_generation, escrow_address,
             chain_lease_id, transaction_nonce, signer_address,
             nonce_reservation_state, generation_binding_state,
             raw_transaction, proposal, status, submission_count, submitted_at)
        VALUES
            ('$historical_misbound_hash', $historical_loser_id, 0,
             '0x3333333333333333333333333333333333333333', 24, 12, NULL,
             'pending', 'pending', '$historical_misbound_raw',
             '$historical_misbound_proposal'::jsonb, 'submitted', 1, NOW());
        UPDATE settlement_jobs
        SET proposal = '$historical_misbound_proposal'::jsonb,
            raw_transaction = '$historical_misbound_raw',
            transaction_hash = '$historical_misbound_hash',
            transaction_nonce = 12, status = 'submitted', attempts = 7,
            lease_until = NULL, available_at = NOW() - INTERVAL '1 hour'
        WHERE lease_id = $historical_loser_id;
        SET session_replication_role = origin;" >/dev/null
for _ in 1 2; do
  env \
    DATABASE_URL="$database_url" \
    PRISM_ALLOW_DEVELOPMENT_SIGNER=1 \
    PRISM_DEVELOPMENT_PRIVATE_KEY="$historical_signer_key" \
    PRISM_LEASE_ESCROW_ADDRESS=0xffffffffffffffffffffffffffffffffffffffff \
    PRISM_RPC_URL="$rpc_url" \
    PRISM_RUN_ONCE=1 \
    PRISM_SETTLEMENT_CONFIRMATIONS=1 \
    target/debug/prism-settlement-worker >/dev/null
done
[[ $(run -Atc "SELECT generation_binding_state || ':' || generation_binding_reason
              FROM settlement_transaction_attempts
              WHERE transaction_hash = '$historical_misbound_hash';") == \
  quarantined:signed_escrow_mismatch ]]
[[ $(run -Atc "SELECT COUNT(*) FROM settlement_transaction_attempts
              WHERE transaction_hash = '$historical_misbound_hash'
                AND nonce_reservation_state = 'reserved'
                AND generation_binding_state IN ('verified', 'normalized');") == 0 ]]
[[ $(run -Atc "SELECT status || ':' || attempts || ':' ||
                     (proposal IS NULL AND raw_transaction IS NULL AND
                      transaction_hash IS NULL AND transaction_nonce IS NULL) || ':' ||
                     (last_error LIKE 'historical settlement cursor quarantined%')
              FROM settlement_jobs WHERE lease_id = $historical_loser_id;") == queued:0:t:t ]]
# The strict cursor trigger no longer poisons ordinary job updates after the
# quarantined evidence is detached. Keep the fixture out of later claim tests.
run -c "UPDATE settlement_jobs
        SET attempts = attempts + 1, status = 'failed'
        WHERE lease_id = $historical_loser_id;" >/dev/null
[[ $(cast rpc --rpc-url "$rpc_url" eth_getTransactionByHash \
  "$historical_misbound_hash") == null ]]

# Structurally invalid legacy bytes have no recoverable signer or nonce. Keep
# that fact durable without manufacturing ownership: the attempt remains
# nonce-pending but is quarantined, and repeat startup can never select or send
# it.
historical_invalid_raw=0x01
historical_invalid_hash=$(cast keccak "$historical_invalid_raw")
run -c "SET session_replication_role = replica;
        INSERT INTO settlement_transaction_attempts
            (transaction_hash, lease_id, claim_generation, escrow_address,
             chain_lease_id, transaction_nonce, signer_address,
             nonce_reservation_state, generation_binding_state,
             raw_transaction, proposal, status)
        VALUES
            ('$historical_invalid_hash', $historical_loser_id, 0,
             '0x3333333333333333333333333333333333333333', 24, 15, NULL,
             'pending', 'pending', '$historical_invalid_raw',
             '{}'::jsonb, 'prepared');
        UPDATE settlement_jobs
        SET proposal = '{}'::jsonb, raw_transaction = '$historical_invalid_raw',
            transaction_hash = '$historical_invalid_hash', transaction_nonce = 15,
            status = 'submitted', attempts = 8, lease_until = NULL,
            available_at = NOW() - INTERVAL '1 hour'
        WHERE lease_id = $historical_loser_id;
        SET session_replication_role = origin;" >/dev/null
for _ in 1 2; do
  env \
    DATABASE_URL="$database_url" \
    PRISM_ALLOW_DEVELOPMENT_SIGNER=1 \
    PRISM_DEVELOPMENT_PRIVATE_KEY="$historical_signer_key" \
    PRISM_LEASE_ESCROW_ADDRESS=0xffffffffffffffffffffffffffffffffffffffff \
    PRISM_RPC_URL="$rpc_url" \
    PRISM_RUN_ONCE=1 \
    PRISM_SETTLEMENT_CONFIRMATIONS=1 \
    target/debug/prism-settlement-worker >/dev/null 2>&1
done
[[ $(run -Atc "SELECT generation_binding_state || ':' || generation_binding_reason || ':' ||
                     (signer_address IS NULL) || ':' || nonce_reservation_state
              FROM settlement_transaction_attempts
              WHERE transaction_hash = '$historical_invalid_hash';") == \
  quarantined:invalid_signed_transaction:t:pending ]]
[[ $(run -Atc "SELECT COUNT(*) FROM settlement_transaction_attempts
              WHERE transaction_hash = '$historical_invalid_hash'
                AND generation_binding_state IN ('verified', 'normalized');") == 0 ]]
[[ $(run -Atc "SELECT status || ':' || attempts || ':' ||
                     (proposal IS NULL AND raw_transaction IS NULL AND
                      transaction_hash IS NULL AND transaction_nonce IS NULL) || ':' ||
                     (last_error LIKE 'historical settlement cursor quarantined%')
              FROM settlement_jobs WHERE lease_id = $historical_loser_id;") == queued:0:t:t ]]
run -c "UPDATE settlement_jobs SET status = 'failed'
        WHERE lease_id = $historical_loser_id;" >/dev/null

# A quarantined cursor carrying a later local state is not silently left looking
# proposed. Its untrusted confirmation cursor is cleared and the job is made
# explicitly failed while the immutable attempt remains available for review.
run -c "SET session_replication_role = replica;
        UPDATE settlement_jobs
        SET proposal = '{}'::jsonb, raw_transaction = '$historical_invalid_raw',
            transaction_hash = '$historical_invalid_hash', transaction_nonce = 15,
            status = 'proposed', confirmed_block = 515,
            confirmed_block_hash =
              '0x5151515151515151515151515151515151515151515151515151515151515151'
        WHERE lease_id = $historical_loser_id;
        SET session_replication_role = origin;" >/dev/null
env \
  DATABASE_URL="$database_url" \
  PRISM_ALLOW_DEVELOPMENT_SIGNER=1 \
  PRISM_DEVELOPMENT_PRIVATE_KEY="$historical_signer_key" \
  PRISM_LEASE_ESCROW_ADDRESS=0xffffffffffffffffffffffffffffffffffffffff \
  PRISM_RPC_URL="$rpc_url" \
  PRISM_RUN_ONCE=1 \
  PRISM_SETTLEMENT_CONFIRMATIONS=1 \
  target/debug/prism-settlement-worker >/dev/null 2>&1
[[ $(run -Atc "SELECT status || ':' ||
                     (proposal IS NULL AND raw_transaction IS NULL AND
                      transaction_hash IS NULL AND transaction_nonce IS NULL) || ':' ||
                     (confirmed_block IS NULL AND confirmed_block_hash IS NULL) || ':' ||
                     (last_error LIKE 'historical settlement cursor quarantined%')
              FROM settlement_jobs WHERE lease_id = $historical_loser_id;") == failed:t:t:t ]]
[[ $(cast rpc --rpc-url "$rpc_url" eth_getTransactionByHash \
  "$historical_invalid_hash") == null ]]

# Recreate an interrupted old startup: one legacy attempt was normalized while
# its job cursor still held the pre-normalization proposal, then nonce recovery
# found an unresolved cross-lease collision. Every retry must report only the
# nonce conflict, preserve both attempts, and detach both poisoned job cursors.
make_historical_submission historical_conflict_a "$historical_loser_id" 24 \
  0x3333333333333333333333333333333333333333 9 1000000000
make_historical_submission historical_conflict_b "$historical_owner_id" 28 \
  0x3333333333333333333333333333333333333333 9 2000000000
run -c "SET session_replication_role = replica;
        INSERT INTO settlement_transaction_attempts
            (transaction_hash, lease_id, claim_generation, escrow_address,
             chain_lease_id, transaction_nonce, signer_address,
             nonce_reservation_state, generation_binding_state,
             generation_binding_reason,
             raw_transaction, proposal, status)
        VALUES
             ('$historical_conflict_a_hash', $historical_loser_id, 0,
             '0x3333333333333333333333333333333333333333', 24, 9,
             '$historical_signer', 'pending', 'normalized',
             'legacy_receipt_identity_normalized', '$historical_conflict_a_raw',
             jsonb_set(
               jsonb_set('$historical_conflict_a_proposal'::jsonb,
                         '{proposal,receipt,escrow_address}',
                         to_jsonb('0x3333333333333333333333333333333333333333'::text), TRUE),
               '{proposal,receipt,chain_lease_id}', to_jsonb('24'::text), TRUE),
             'prepared'),
             ('$historical_conflict_b_hash', $historical_owner_id, 0,
             '0x3333333333333333333333333333333333333333', 28, 9, NULL,
             'pending', 'pending', NULL, '$historical_conflict_b_raw',
             '$historical_conflict_b_proposal'::jsonb, 'prepared');
        UPDATE settlement_jobs
        SET proposal = '$historical_conflict_a_proposal'::jsonb,
            raw_transaction = '$historical_conflict_a_raw',
            transaction_hash = '$historical_conflict_a_hash',
            transaction_nonce = 9, status = 'submitted', attempts = 4,
            lease_until = NULL, available_at = NOW() - INTERVAL '2 hours'
        WHERE lease_id = $historical_loser_id;
        UPDATE settlement_jobs
        SET proposal = '$historical_conflict_b_proposal'::jsonb,
            raw_transaction = '$historical_conflict_b_raw',
            transaction_hash = '$historical_conflict_b_hash',
            transaction_nonce = 9, status = 'submitted', attempts = 5,
            lease_until = NULL, available_at = NOW() - INTERVAL '1 hour'
        WHERE lease_id = $historical_owner_id;
        SET session_replication_role = origin;" >/dev/null
for _ in 1 2; do
  if conflict_error=$(env \
      DATABASE_URL="$database_url" \
      PRISM_ALLOW_DEVELOPMENT_SIGNER=1 \
      PRISM_DEVELOPMENT_PRIVATE_KEY="$historical_signer_key" \
      PRISM_LEASE_ESCROW_ADDRESS=0xffffffffffffffffffffffffffffffffffffffff \
      PRISM_RPC_URL="$rpc_url" \
      PRISM_RUN_ONCE=1 \
      PRISM_SETTLEMENT_CONFIRMATIONS=1 \
      target/debug/prism-settlement-worker 2>&1); then
    echo "unresolved historical nonce collision did not block startup" >&2
    exit 1
  fi
  [[ $conflict_error == *"historical settlement signer nonce conflicts require operator resolution"* ]]
done
[[ $(run -Atc "SELECT COUNT(*) || ':' ||
                     bool_and(nonce_reservation_state = 'conflict') || ':' ||
                     bool_and(nonce_reservation_reason =
                         'historical_nonce_collision_without_confirmed_owner') || ':' ||
                     bool_and(signer_address = '$historical_signer')
              FROM settlement_transaction_attempts
              WHERE transaction_nonce = 9;") == 2:t:t:t ]]
[[ $(run -Atc "SELECT COUNT(*) FROM settlement_signer_nonce_reservations
              WHERE signer_address = '$historical_signer' AND transaction_nonce = 9;") == 0 ]]
[[ $(run -Atc "SELECT COUNT(DISTINCT lease_id)
              FROM settlement_transaction_attempts
              WHERE signer_address = '$historical_signer' AND transaction_nonce = 9
                AND status = 'confirmed';") == 0 ]]
[[ $(run -Atc "SELECT generation_binding_state || ':' || generation_binding_reason
              FROM settlement_transaction_attempts
              WHERE transaction_hash = '$historical_conflict_a_hash';") == \
  normalized:legacy_receipt_identity_normalized ]]
[[ $(run -Atc "SELECT generation_binding_state || ':' ||
                     (generation_binding_reason IS NULL)
              FROM settlement_transaction_attempts
              WHERE transaction_hash = '$historical_conflict_b_hash';") == pending:t ]]
[[ $(run -Atc "SELECT COUNT(*) || ':' ||
                     bool_and(status = 'queued') || ':' ||
                     bool_and(attempts = 0) || ':' ||
                     bool_and(proposal IS NULL AND raw_transaction IS NULL AND
                              transaction_hash IS NULL AND transaction_nonce IS NULL)
              FROM settlement_jobs
              WHERE lease_id IN ($historical_loser_id, $historical_owner_id);") == 2:t:t:t ]]
[[ $(cast rpc --rpc-url "$rpc_url" eth_getTransactionByHash \
  "$historical_conflict_a_hash") == null ]]
[[ $(cast rpc --rpc-url "$rpc_url" eth_getTransactionByHash \
  "$historical_conflict_b_hash") == null ]]

# Conflict state cannot be assigned away. Once an operator has attached
# immutable confirmation evidence to one exact attempt, startup can derive the
# unique lease owner, create the reservation, and classify every loser.
if run -c "UPDATE settlement_transaction_attempts
           SET nonce_reservation_state = 'reserved', nonce_reservation_reason = NULL
           WHERE transaction_hash = '$historical_conflict_a_hash';" >/dev/null 2>&1; then
  echo "unconfirmed settlement nonce conflict was manually reassigned" >&2
  exit 1
fi
run -c "UPDATE settlement_transaction_attempts
        SET status = 'confirmed', confirmed_at = NOW(), confirmed_block = 919,
            confirmed_block_hash =
              '0x9191919191919191919191919191919191919191919191919191919191919191'
        WHERE transaction_hash = '$historical_conflict_a_hash';" >/dev/null
env \
  DATABASE_URL="$database_url" \
  PRISM_ALLOW_DEVELOPMENT_SIGNER=1 \
  PRISM_DEVELOPMENT_PRIVATE_KEY="$historical_signer_key" \
  PRISM_LEASE_ESCROW_ADDRESS=0xffffffffffffffffffffffffffffffffffffffff \
  PRISM_RPC_URL="$rpc_url" \
  PRISM_RUN_ONCE=1 \
  PRISM_SETTLEMENT_CONFIRMATIONS=1 \
  target/debug/prism-settlement-worker >/dev/null
[[ $(run -Atc "SELECT nonce_reservation_state || ':' ||
                     (nonce_reservation_reason IS NULL)
              FROM settlement_transaction_attempts
              WHERE transaction_hash = '$historical_conflict_a_hash';") == reserved:t ]]
[[ $(run -Atc "SELECT nonce_reservation_state || ':' || nonce_reservation_reason || ':' ||
                     generation_binding_state
              FROM settlement_transaction_attempts
              WHERE transaction_hash = '$historical_conflict_b_hash';") == \
  noncanonical:confirmed_historical_nonce_owner:normalized ]]
[[ $(run -Atc "SELECT lease_id FROM settlement_signer_nonce_reservations
              WHERE signer_address = '$historical_signer' AND transaction_nonce = 9;") == \
  "$historical_loser_id" ]]

[[ $(run -Atc "SELECT status || ':' || attempts FROM lifecycle_outbox
              WHERE action_id = '018f0000-0000-7000-8000-000000000025';") == queued:100 ]]
[[ $(run -Atc "SELECT status || ':' || attempts FROM lifecycle_outbox
              WHERE action_id = '018f0000-0000-7000-8000-000000000027';") == failed:100 ]]
[[ $(run -Atc "SELECT status || ':' || attempts FROM lifecycle_outbox
              WHERE action_id = '018f0000-0000-7000-8000-000000000029';") == failed:100 ]]
[[ $(run -Atc "SELECT raw_transaction IS NULL
                  AND transaction_hash IS NULL
                  AND transaction_nonce IS NULL
                  AND confirmed_block IS NULL
                  AND confirmed_block_hash IS NULL
                  AND last_error IS NULL
              FROM lifecycle_outbox
              WHERE action_id = '018f0000-0000-7000-8000-000000000025';") == t ]]
[[ $(run -Atc "SELECT COUNT(*) FROM lifecycle_outbox
              WHERE action_id IN (
                  '018f0000-0000-7000-8000-000000000027',
                  '018f0000-0000-7000-8000-000000000029')
                AND raw_transaction IS NOT NULL
                AND transaction_hash IS NOT NULL
                AND transaction_nonce IS NOT NULL
                AND confirmed_block IS NOT NULL
                AND confirmed_block_hash IS NOT NULL
                AND last_error IS NOT NULL;") == 2 ]]
[[ $(run -Atc "SELECT COUNT(*) FROM lifecycle_transaction_attempts
              WHERE action_id IN (
                  '018f0000-0000-7000-8000-000000000027',
                  '018f0000-0000-7000-8000-000000000029')
                AND status = 'confirmed'
                AND submission_count = 0
                AND submitted_at IS NULL
                AND confirmed_at IS NOT NULL
                AND confirmed_block IS NOT NULL
                AND confirmed_block_hash IS NOT NULL;") == 2 ]]

reconcile_cloud_cleanup() {
  run -c "INSERT INTO lifecycle_outbox (action_id, lease_id, kind)
          SELECT md5(l.lease_id::text || ':cleanup_cloud')::uuid,
                 l.lease_id, 'cleanup_cloud'
          FROM leases l JOIN cloud_instances ci ON ci.lease_id = l.lease_id
          WHERE l.state IN ('finalized', 'refunded') AND ci.status <> 'destroyed'
          ON CONFLICT (lease_id, kind) DO UPDATE
            SET status = 'queued', attempts = 0, available_at = NOW(),
                lease_until = NULL, last_error = NULL, updated_at = NOW()
          WHERE lifecycle_outbox.status = 'failed';" >/dev/null
}

reconcile_cloud_cleanup
reconcile_cloud_cleanup
[[ $(run -Atc "SELECT COUNT(*) FROM lifecycle_outbox WHERE kind = 'cleanup_cloud';") == 2 ]]
[[ $(run -Atc "SELECT bool_and(o.action_id =
                  md5(o.lease_id::text || ':cleanup_cloud')::uuid)
              FROM lifecycle_outbox o WHERE o.kind = 'cleanup_cloud';") == t ]]
[[ $(run -Atc "SELECT COUNT(*) FROM lifecycle_outbox o
              JOIN leases l ON l.lease_id = o.lease_id
              JOIN cloud_instances ci ON ci.lease_id = l.lease_id
              WHERE o.kind = 'cleanup_cloud'
                AND l.state IN ('finalized', 'refunded')
                AND ci.status <> 'destroyed';") == 2 ]]

run -c "UPDATE lifecycle_outbox SET status = 'failed', attempts = 100,
            last_error = 'test failure' WHERE kind = 'cleanup_cloud';" >/dev/null
reconcile_cloud_cleanup
[[ $(run -Atc "SELECT COUNT(*) FROM lifecycle_outbox
              WHERE kind = 'cleanup_cloud' AND status = 'queued'
                AND attempts = 0 AND last_error IS NULL;") == 2 ]]

# workers/lifecycle-worker: a chain lease id can be reused after an escrow
# deployment. Only the current escrow may schedule or claim logical actions;
# provider cleanup remains global and historical transactions remain auditable.
run -c "INSERT INTO accounts (subject) VALUES ('escrow-fence-test');
        INSERT INTO node_offers (node_id, document, updated_at)
        VALUES ('escrow-fence-node', '{}'::jsonb, NOW());
        INSERT INTO lease_quotes
            (quote_id, node_id, document, expires_at, subject, consumed_at)
        VALUES
            ('018f0000-0000-7000-8000-000000000201', 'escrow-fence-node',
             '{}'::jsonb, NOW() + INTERVAL '1 hour', 'escrow-fence-test', NOW()),
            ('018f0000-0000-7000-8000-000000000202', 'escrow-fence-node',
             '{}'::jsonb, NOW() + INTERVAL '1 hour', 'escrow-fence-test', NOW());
        INSERT INTO leases
            (quote_id, subject, renter_wallet, funding_transaction_hash, document, state,
             escrow_address, chain_lease_id, created_at)
        VALUES
            ('018f0000-0000-7000-8000-000000000201', 'escrow-fence-test',
             '0x1111111111111111111111111111111111111111',
             '0x1111111111111111111111111111111111111111111111111111111111111201',
             '{\"node_id\":\"escrow-fence-node\",\"duration_seconds\":3600}'::jsonb,
             'funded', '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 42,
             NOW() - INTERVAL '2 hours'),
            ('018f0000-0000-7000-8000-000000000202', 'escrow-fence-test',
             '0x1111111111111111111111111111111111111111',
             '0x1111111111111111111111111111111111111111111111111111111111111202',
             '{\"node_id\":\"escrow-fence-node\",\"duration_seconds\":3600}'::jsonb,
             'funded', '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 42,
             NOW() - INTERVAL '2 hours');
        INSERT INTO lease_lifecycle
            (lease_id, access_started_at, grant_expires_at)
        SELECT lease_id, NOW() - INTERVAL '2 hours', NOW() + INTERVAL '5 minutes'
        FROM leases WHERE subject = 'escrow-fence-test';" >/dev/null

run -c "INSERT INTO lifecycle_outbox (action_id, lease_id, kind, available_at)
        SELECT md5(lease_id::text || ':expire_provision')::uuid,
               lease_id, 'expire_provision', GREATEST(NOW(), created_at + INTERVAL '10 minutes')
        FROM leases
        WHERE state IN ('funded', 'provisioning', 'ready')
          AND escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
          AND created_at <= NOW() - INTERVAL '10 minutes'
        ON CONFLICT (lease_id, kind) DO NOTHING;" >/dev/null
[[ $(run -Atc "SELECT COUNT(*) FROM lifecycle_outbox o JOIN leases l USING (lease_id)
              WHERE l.subject = 'escrow-fence-test' AND o.kind = 'expire_provision'
                AND l.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';") == 1 ]]
[[ $(run -Atc "SELECT COUNT(*) FROM lifecycle_outbox o JOIN leases l USING (lease_id)
              WHERE l.subject = 'escrow-fence-test' AND o.kind = 'expire_provision'
                AND l.escrow_address = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';") == 0 ]]
run -c "DELETE FROM lifecycle_outbox o USING leases l
        WHERE o.lease_id = l.lease_id AND l.subject = 'escrow-fence-test';
        UPDATE leases SET state = 'active' WHERE subject = 'escrow-fence-test';" >/dev/null

run -c "INSERT INTO lifecycle_outbox (action_id, lease_id, kind)
        SELECT md5(l.lease_id::text || ':close_access')::uuid, l.lease_id, 'close_access'
        FROM leases l
        JOIN lease_lifecycle lc ON lc.lease_id = l.lease_id
        LEFT JOIN node_telemetry nt ON nt.node_id = l.document->>'node_id'
        LEFT JOIN node_tunnels t ON t.node_id = l.document->>'node_id'
        LEFT JOIN cloud_instances ci ON ci.lease_id = l.lease_id
        WHERE l.state = 'active'
          AND l.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
          AND (lc.access_started_at +
               make_interval(secs => (l.document->>'duration_seconds')::int) <= NOW()
               OR (ci.lease_id IS NULL AND (
                   nt.observed_at IS NULL OR nt.observed_at < NOW() - INTERVAL '90 seconds'
                   OR t.observed_at IS NULL OR t.observed_at < NOW() - INTERVAL '90 seconds'))
               OR (ci.lease_id IS NOT NULL AND (
                   ci.status NOT IN ('running', 'destroying')
                   OR ci.observed_at IS NULL
                   OR ci.observed_at < NOW() - INTERVAL '150 seconds')))
        ON CONFLICT (lease_id, kind) DO NOTHING;" >/dev/null
[[ $(run -Atc "SELECT string_agg(l.escrow_address, ',' ORDER BY l.escrow_address)
              FROM lifecycle_outbox o JOIN leases l USING (lease_id)
              WHERE l.subject = 'escrow-fence-test' AND o.kind = 'close_access';") == 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]]
run -c "DELETE FROM lifecycle_outbox o USING leases l
        WHERE o.lease_id = l.lease_id AND l.subject = 'escrow-fence-test';
        UPDATE lease_lifecycle SET access_started_at = NOW()
        WHERE lease_id IN (SELECT lease_id FROM leases WHERE subject = 'escrow-fence-test');" >/dev/null

run -c "INSERT INTO lifecycle_outbox (action_id, lease_id, kind)
        SELECT md5(l.lease_id::text || ':refresh_grant')::uuid, l.lease_id, 'refresh_grant'
        FROM leases l JOIN lease_lifecycle lc ON lc.lease_id = l.lease_id
        WHERE l.state = 'active'
          AND l.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
          AND lc.grant_expires_at <= NOW() + INTERVAL '10 minutes'
          AND lc.access_started_at +
              make_interval(secs => (l.document->>'duration_seconds')::int)
              > NOW() + INTERVAL '10 minutes'
        ON CONFLICT (lease_id, kind) DO UPDATE
          SET status = 'queued', available_at = NOW(), lease_until = NULL,
              last_error = NULL, document = '{}'::jsonb, updated_at = NOW()
        WHERE lifecycle_outbox.status = 'completed';" >/dev/null
[[ $(run -Atc "SELECT string_agg(l.escrow_address, ',' ORDER BY l.escrow_address)
              FROM lifecycle_outbox o JOIN leases l USING (lease_id)
              WHERE l.subject = 'escrow-fence-test' AND o.kind = 'refresh_grant';") == 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]]
run -c "DELETE FROM lifecycle_outbox o USING leases l
        WHERE o.lease_id = l.lease_id AND l.subject = 'escrow-fence-test';
        INSERT INTO lifecycle_outbox
            (action_id, lease_id, kind, status, claim_generation, lease_until,
             raw_transaction, transaction_hash, transaction_nonce)
        SELECT '018f0000-0000-7000-8000-000000000203'::uuid, lease_id,
               'start_access', 'queued', 1, NULL::timestamptz,
               NULL::text, NULL::text, NULL::bigint
        FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000201'
        UNION ALL
        SELECT '018f0000-0000-7000-8000-000000000204'::uuid, lease_id,
               'close_access', 'processing', 2, NOW() + INTERVAL '2 minutes',
               NULL::text, NULL::text, NULL::bigint
        FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000201'
        UNION ALL
        SELECT '018f0000-0000-7000-8000-000000000205'::uuid, lease_id,
               'finalize', 'queued', 3, NULL,
               NULL::text, NULL::text, NULL::bigint
        FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000201'
        UNION ALL
        SELECT '018f0000-0000-7000-8000-000000000206'::uuid, lease_id,
               'cleanup_cloud', 'queued', 4, NULL::timestamptz,
               NULL::text, NULL::text, NULL::bigint
        FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000201'
        UNION ALL
        SELECT '018f0000-0000-7000-8000-000000000207'::uuid, lease_id,
               'start_access', 'queued', 5, NULL::timestamptz,
               NULL::text, NULL::text, NULL::bigint
        FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000202';" >/dev/null

[[ $(run -Atc "SELECT string_agg(kind || ':' || status || ':' || claim_generation, ',' ORDER BY kind)
              FROM lifecycle_outbox o JOIN leases l USING (lease_id)
              WHERE l.subject = 'escrow-fence-test'
                AND l.escrow_address = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                AND o.kind <> 'cleanup_cloud';") == \
  close_access:processing:2,finalize:queued:3,start_access:queued:1 ]]
[[ $(run -Atc "SELECT status || ':' || claim_generation FROM lifecycle_outbox
              WHERE action_id = '018f0000-0000-7000-8000-000000000206';") == queued:4 ]]
[[ $(run -Atc "SELECT status || ':' || claim_generation FROM lifecycle_outbox
              WHERE action_id = '018f0000-0000-7000-8000-000000000207';") == queued:5 ]]
[[ $(run -Atc "SELECT COUNT(*)
              FROM lifecycle_outbox o JOIN leases l ON l.lease_id = o.lease_id
              WHERE (o.attempts < 100 OR o.status = 'submitted'
                     OR o.kind IN ('close_access', 'expire_provision', 'finalize'))
                AND (o.kind = 'cleanup_cloud'
                     OR l.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
                AND o.available_at <= NOW()
                AND (o.status IN ('queued', 'submitted')
                     OR (o.status = 'processing' AND o.lease_until <= NOW()))
                AND o.action_id IN (
                    '018f0000-0000-7000-8000-000000000203',
                    '018f0000-0000-7000-8000-000000000204',
                    '018f0000-0000-7000-8000-000000000205',
                    '018f0000-0000-7000-8000-000000000206',
                    '018f0000-0000-7000-8000-000000000207');") == 2 ]]
[[ $(run -Atc "SELECT COUNT(*)
              FROM lifecycle_outbox o JOIN leases l ON l.lease_id = o.lease_id
              WHERE (o.attempts < 100 OR o.status = 'submitted'
                     OR o.kind IN ('close_access', 'expire_provision', 'finalize'))
                AND (o.kind = 'cleanup_cloud'
                     OR l.escrow_address = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')
                AND o.available_at <= NOW()
                AND (o.status IN ('queued', 'submitted')
                     OR (o.status = 'processing' AND o.lease_until <= NOW()))
                AND o.action_id IN (
                    '018f0000-0000-7000-8000-000000000203',
                    '018f0000-0000-7000-8000-000000000204',
                    '018f0000-0000-7000-8000-000000000205',
                    '018f0000-0000-7000-8000-000000000206',
                    '018f0000-0000-7000-8000-000000000207');") == 3 ]]

run -c "INSERT INTO lifecycle_transaction_attempts
            (transaction_hash, action_id, claim_generation, transaction_nonce,
             signer_address, raw_transaction, status)
        VALUES
            ('0x1212121212121212121212121212121212121212121212121212121212121212',
             '018f0000-0000-7000-8000-000000000205', 3, 42,
             '$historical_signer', '0x04', 'prepared');
        UPDATE lifecycle_outbox
        SET status = 'submitted', raw_transaction = '0x04',
            transaction_hash =
              '0x1212121212121212121212121212121212121212121212121212121212121212',
            transaction_nonce = 42
        WHERE action_id = '018f0000-0000-7000-8000-000000000205';
        UPDATE lifecycle_transaction_attempts
        SET status = 'submitted', submission_count = submission_count + 1,
            submitted_at = NOW()
        WHERE transaction_hash =
            '0x1212121212121212121212121212121212121212121212121212121212121212';
        UPDATE lifecycle_transaction_attempts
        SET status = 'superseded', superseded_at = NOW()
        WHERE transaction_hash =
            '0x1212121212121212121212121212121212121212121212121212121212121212';
        UPDATE lifecycle_transaction_attempts
        SET status = 'confirmed', confirmed_at = NOW(), confirmed_block = 425,
            confirmed_block_hash =
                '0x3434343434343434343434343434343434343434343434343434343434343434'
        WHERE transaction_hash =
            '0x1212121212121212121212121212121212121212121212121212121212121212';" >/dev/null
[[ $(run -Atc "SELECT status || ':' || submission_count || ':' ||
                     (submitted_at IS NOT NULL) || ':' ||
                     (superseded_at IS NOT NULL) || ':' || confirmed_block
              FROM lifecycle_transaction_attempts
              WHERE transaction_hash =
                  '0x1212121212121212121212121212121212121212121212121212121212121212';") == \
  confirmed:1:true:true:425 ]]
if run -c "UPDATE lifecycle_transaction_attempts SET raw_transaction = '0x05'
           WHERE transaction_hash =
               '0x1212121212121212121212121212121212121212121212121212121212121212';" \
    >/dev/null 2>&1; then
  echo "immutable lifecycle transaction bytes were rewritten" >&2
  exit 1
fi
if run -c "UPDATE lifecycle_transaction_attempts
           SET status = 'submitted', confirmed_at = NULL,
               confirmed_block = NULL, confirmed_block_hash = NULL
           WHERE transaction_hash =
               '0x1212121212121212121212121212121212121212121212121212121212121212';" \
    >/dev/null 2>&1; then
  echo "confirmed lifecycle transaction moved backward" >&2
  exit 1
fi
if run -c "DELETE FROM lifecycle_transaction_attempts
           WHERE transaction_hash =
               '0x1212121212121212121212121212121212121212121212121212121212121212';" \
    >/dev/null 2>&1; then
  echo "lifecycle transaction evidence was deleted" >&2
  exit 1
fi
if run -c "DELETE FROM lifecycle_outbox
           WHERE action_id = '018f0000-0000-7000-8000-000000000205';" \
    >/dev/null 2>&1; then
  echo "outbox action with transaction evidence was deleted" >&2
  exit 1
fi

# Migration-era signed bytes are trusted only after the lifecycle worker binds
# them to its exact escrow generation, signer, action and chain lease. Another
# generation's worker must leave the same pending evidence untouched.
binding_escrow=0xcccccccccccccccccccccccccccccccccccccccc
foreign_binding_escrow=0xdddddddddddddddddddddddddddddddddddddddd
valid_lifecycle_raw=$(cast mktx "$binding_escrow" 'finalize(uint256)' 701 \
  --private-key "$historical_signer_key" --chain 4663 --legacy --nonce 31 \
  --gas-limit 200000 --gas-price 1000000000)
valid_lifecycle_hash=$(cast keccak "$valid_lifecycle_raw")
misbound_lifecycle_raw=$(cast mktx "$binding_escrow" 'finalize(uint256)' 999 \
  --private-key "$historical_signer_key" --chain 4663 --legacy --nonce 32 \
  --gas-limit 200000 --gas-price 1000000000)
misbound_lifecycle_hash=$(cast keccak "$misbound_lifecycle_raw")
foreign_lifecycle_raw=$(cast mktx "$foreign_binding_escrow" 'finalize(uint256)' 703 \
  --private-key "$historical_signer_key" --chain 4663 --legacy --nonce 33 \
  --gas-limit 200000 --gas-price 1000000000)
foreign_lifecycle_hash=$(cast keccak "$foreign_lifecycle_raw")
binding_escrow_runtime=$(node - "$historical_signer" <<'NODE'
const gateway = process.argv[2].replace(/^0x/, "").toLowerCase();
process.stdout.write(`0x7f${gateway.padStart(64, "0")}5f5260205ff3`);
NODE
)
cast rpc --rpc-url "$rpc_url" anvil_setCode "$binding_escrow" \
  "$binding_escrow_runtime" >/dev/null
run -c "INSERT INTO lease_quotes
            (quote_id, node_id, document, expires_at, subject, consumed_at)
        VALUES
            ('018f0000-0000-7000-8000-000000000701', 'provider-migration-node',
             '{}'::jsonb, NOW() + INTERVAL '1 hour', 'provider-migration-test', NOW()),
            ('018f0000-0000-7000-8000-000000000702', 'provider-migration-node',
             '{}'::jsonb, NOW() + INTERVAL '1 hour', 'provider-migration-test', NOW()),
            ('018f0000-0000-7000-8000-000000000703', 'provider-migration-node',
             '{}'::jsonb, NOW() + INTERVAL '1 hour', 'provider-migration-test', NOW());
        INSERT INTO leases
            (quote_id, subject, renter_wallet, funding_transaction_hash, document,
             state, escrow_address, chain_lease_id)
        VALUES
            ('018f0000-0000-7000-8000-000000000701', 'provider-migration-test',
             '0x1111111111111111111111111111111111111111',
             '0x7070707070707070707070707070707070707070707070707070707070707001',
             '{}'::jsonb, 'finalized', '$binding_escrow', 701),
            ('018f0000-0000-7000-8000-000000000702', 'provider-migration-test',
             '0x1111111111111111111111111111111111111111',
             '0x7070707070707070707070707070707070707070707070707070707070707002',
             '{}'::jsonb, 'finalized', '$binding_escrow', 702),
            ('018f0000-0000-7000-8000-000000000703', 'provider-migration-test',
             '0x1111111111111111111111111111111111111111',
             '0x7070707070707070707070707070707070707070707070707070707070707003',
             '{}'::jsonb, 'finalized', '$foreign_binding_escrow', 703);
        SET session_replication_role = replica;
        INSERT INTO lifecycle_outbox
            (action_id, lease_id, kind, status, raw_transaction,
             transaction_hash, transaction_nonce)
        SELECT '018f0000-0000-7000-8000-000000000711'::uuid, lease_id,
               'finalize', 'failed', '$valid_lifecycle_raw',
               '$valid_lifecycle_hash', 31
        FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000701'
        UNION ALL
        SELECT '018f0000-0000-7000-8000-000000000712'::uuid, lease_id,
               'finalize', 'failed', '$misbound_lifecycle_raw',
               '$misbound_lifecycle_hash', 32
        FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000702'
        UNION ALL
        SELECT '018f0000-0000-7000-8000-000000000713'::uuid, lease_id,
               'finalize', 'failed', '$foreign_lifecycle_raw',
               '$foreign_lifecycle_hash', 33
        FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000703';
        INSERT INTO lifecycle_transaction_attempts
            (transaction_hash, action_id, claim_generation, transaction_nonce,
             raw_transaction, generation_binding_state, status)
        VALUES
            ('$valid_lifecycle_hash',
             '018f0000-0000-7000-8000-000000000711', 0, 31,
             '$valid_lifecycle_raw', 'pending', 'prepared'),
            ('$misbound_lifecycle_hash',
             '018f0000-0000-7000-8000-000000000712', 0, 32,
             '$misbound_lifecycle_raw', 'pending', 'prepared'),
            ('$foreign_lifecycle_hash',
             '018f0000-0000-7000-8000-000000000713', 0, 33,
             '$foreign_lifecycle_raw', 'pending', 'prepared');
        SET session_replication_role = origin;" >/dev/null

cargo build --quiet -p prism-lifecycle-worker
wrong_historical_signer_key=0000000000000000000000000000000000000000000000000000000000000005
wrong_signer_log=$(mktemp "${TMPDIR:-/tmp}/prism-lifecycle-wrong-signer.XXXXXX")
wrong_signer_rows_before=$(run -Atc \
  "SELECT md5(jsonb_agg(jsonb_build_object(
                 'attempt', to_jsonb(attempt), 'action', to_jsonb(action))
                 ORDER BY attempt.transaction_hash)::text)
   FROM lifecycle_transaction_attempts AS attempt
   JOIN lifecycle_outbox AS action ON action.action_id = attempt.action_id
   JOIN leases AS lease ON lease.lease_id = action.lease_id
   WHERE lease.escrow_address = '$binding_escrow';")
if env \
  DATABASE_URL="$database_url" \
  PRISM_ACCESS_CREDENTIAL_KEY=1111111111111111111111111111111111111111111111111111111111111111 \
  PRISM_ALLOW_DEVELOPMENT_SIGNER=1 \
  PRISM_DEVELOPMENT_PRIVATE_KEY="$wrong_historical_signer_key" \
  PRISM_GATEWAY_CONTROL_TOKEN=test-token \
  PRISM_GATEWAY_CONTROL_URL=http://127.0.0.1:1 \
  PRISM_LEASE_ESCROW_ADDRESS="$binding_escrow" \
  PRISM_LIFECYCLE_CONFIRMATIONS=1 \
  PRISM_NODE_REGISTRY_ADDRESS=0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
  PRISM_RPC_URL="$rpc_url" \
  PRISM_RUN_ONCE=1 \
  target/debug/prism-lifecycle-worker >"$wrong_signer_log" 2>&1; then
  echo "lifecycle worker accepted a signer that is not the escrow gateway" >&2
  exit 1
fi
grep -Fq "configured lifecycle signer does not match the on-chain escrow gateway" \
  "$wrong_signer_log"
rm -f "$wrong_signer_log"
wrong_signer_rows_after=$(run -Atc \
  "SELECT md5(jsonb_agg(jsonb_build_object(
                 'attempt', to_jsonb(attempt), 'action', to_jsonb(action))
                 ORDER BY attempt.transaction_hash)::text)
   FROM lifecycle_transaction_attempts AS attempt
   JOIN lifecycle_outbox AS action ON action.action_id = attempt.action_id
   JOIN leases AS lease ON lease.lease_id = action.lease_id
   WHERE lease.escrow_address = '$binding_escrow';")
test "$wrong_signer_rows_after" = "$wrong_signer_rows_before"
[[ $(run -Atc "SELECT COUNT(*) FROM lifecycle_transaction_attempts AS attempt
              JOIN lifecycle_outbox AS action ON action.action_id = attempt.action_id
              JOIN leases AS lease ON lease.lease_id = action.lease_id
              WHERE lease.escrow_address = '$binding_escrow'
                AND attempt.generation_binding_state = 'pending'
                AND attempt.signer_address IS NULL
                AND action.transaction_hash = attempt.transaction_hash;") == 2 ]]
for _ in 1 2; do
  env \
    DATABASE_URL="$database_url" \
    PRISM_ACCESS_CREDENTIAL_KEY=1111111111111111111111111111111111111111111111111111111111111111 \
    PRISM_ALLOW_DEVELOPMENT_SIGNER=1 \
    PRISM_DEVELOPMENT_PRIVATE_KEY="$historical_signer_key" \
    PRISM_GATEWAY_CONTROL_TOKEN=test-token \
    PRISM_GATEWAY_CONTROL_URL=http://127.0.0.1:1 \
    PRISM_LEASE_ESCROW_ADDRESS="$binding_escrow" \
    PRISM_LIFECYCLE_CONFIRMATIONS=1 \
    PRISM_NODE_REGISTRY_ADDRESS=0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
    PRISM_RPC_URL="$rpc_url" \
    PRISM_RUN_ONCE=1 \
    target/debug/prism-lifecycle-worker >/dev/null 2>&1
done
[[ $(run -Atc "SELECT generation_binding_state || ':' || signer_address
              FROM lifecycle_transaction_attempts
              WHERE transaction_hash = '$valid_lifecycle_hash';") == \
  "verified:$historical_signer" ]]
[[ $(run -Atc "SELECT generation_binding_state || ':' || generation_binding_reason
              FROM lifecycle_transaction_attempts
              WHERE transaction_hash = '$misbound_lifecycle_hash';") == \
  quarantined:calldata_mismatch ]]
[[ $(run -Atc "SELECT status || ':' ||
                     (raw_transaction IS NULL AND transaction_hash IS NULL AND
                      transaction_nonce IS NULL) || ':' ||
                     (last_error = 'historical lifecycle cursor quarantined: calldata_mismatch')
              FROM lifecycle_outbox
              WHERE action_id = '018f0000-0000-7000-8000-000000000712';") == failed:t:t ]]
[[ $(run -Atc "SELECT attempt.generation_binding_state || ':' ||
                     (attempt.signer_address IS NULL) || ':' ||
                     (action.transaction_hash = '$foreign_lifecycle_hash')
              FROM lifecycle_transaction_attempts AS attempt
              JOIN lifecycle_outbox AS action ON action.action_id = attempt.action_id
              WHERE attempt.transaction_hash = '$foreign_lifecycle_hash';") == pending:t:t ]]
[[ $(cast rpc --rpc-url "$rpc_url" eth_getTransactionByHash \
  "$misbound_lifecycle_hash") == null ]]

# workers/settlement-worker: each configured worker drains exactly one escrow
# generation even when another generation reused the same chain lease id.
run -c "INSERT INTO settlement_jobs (lease_id, evidence)
        SELECT lease_id,
               jsonb_build_object('lease_id', lease_id, 'chain_lease_id', chain_lease_id)
        FROM leases WHERE subject = 'escrow-fence-test';" >/dev/null
current_settlement_id=$(run -Atc "SELECT lease_id FROM leases
                                  WHERE subject = 'escrow-fence-test'
                                    AND escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';")
historical_settlement_id=$(run -Atc "SELECT lease_id FROM leases
                                     WHERE subject = 'escrow-fence-test'
                                       AND escrow_address = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';")
[[ $current_settlement_id != "$historical_settlement_id" ]]
[[ $(run -Atc "SELECT job.lease_id || ':' || lease.chain_lease_id
              FROM settlement_jobs AS job
              JOIN leases AS lease ON lease.lease_id = job.lease_id
              WHERE lease.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                AND job.attempts < 100 AND job.available_at <= NOW()
                AND (job.status IN ('queued', 'submitted')
                     OR (job.status = 'processing' AND job.lease_until <= NOW()))
              ORDER BY job.available_at, job.created_at LIMIT 1
              FOR UPDATE OF job, lease SKIP LOCKED;") == "$current_settlement_id:42" ]]

run -c "UPDATE settlement_jobs AS job
        SET status = 'processing', attempts = attempts + 1,
            claim_generation = claim_generation + 1,
            lease_until = NOW() + INTERVAL '2 minutes', updated_at = NOW()
        FROM leases AS lease
        WHERE job.lease_id = $current_settlement_id AND lease.lease_id = job.lease_id
          AND lease.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
          AND lease.chain_lease_id = 42;
        INSERT INTO settlement_transaction_attempts
            (transaction_hash, lease_id, claim_generation, escrow_address,
             chain_lease_id, transaction_nonce, signer_address, raw_transaction,
             proposal, status)
        VALUES
            ('0xabababababababababababababababababababababababababababababababab',
             $current_settlement_id, 1,
             '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 42, 42,
             '0xcccccccccccccccccccccccccccccccccccccccc', '0x01',
             '{\"generation\":\"current\"}'::jsonb, 'prepared');
        INSERT INTO settlement_signer_nonce_reservations
            (signer_address, transaction_nonce, lease_id)
        VALUES
            ('0xcccccccccccccccccccccccccccccccccccccccc', 42,
             $current_settlement_id);
        UPDATE settlement_jobs AS job
        SET proposal = '{\"generation\":\"current\"}'::jsonb,
            raw_transaction = '0x01',
            transaction_hash = '0xabababababababababababababababababababababababababababababababab',
            transaction_nonce = 42, status = 'submitted', lease_until = NULL,
            updated_at = NOW()
        FROM leases AS lease
        WHERE job.lease_id = $current_settlement_id AND lease.lease_id = job.lease_id
          AND lease.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
          AND lease.chain_lease_id = 42 AND job.claim_generation = 1;" >/dev/null
[[ $(run -Atc "SELECT status || ':' || attempts || ':' || claim_generation || ':' ||
                     (proposal->>'generation')
              FROM settlement_jobs WHERE lease_id = $current_settlement_id;") == submitted:1:1:current ]]
for unsafe_later_status in proposed disputed finalized; do
  if run -c "UPDATE settlement_jobs
             SET status = '$unsafe_later_status',
                 confirmed_block = NULL, confirmed_block_hash = NULL
             WHERE lease_id = $current_settlement_id;" >/dev/null 2>&1; then
    echo "captured settlement cursor entered $unsafe_later_status without confirmation evidence" >&2
    exit 1
  fi
  [[ $(run -Atc "SELECT status || ':' ||
                       (confirmed_block IS NULL AND confirmed_block_hash IS NULL)
                FROM settlement_jobs WHERE lease_id = $current_settlement_id;") == submitted:t ]]
done
[[ $(run -Atc "SELECT status || ':' || attempts || ':' || (proposal IS NULL)
              FROM settlement_jobs WHERE lease_id = $historical_settlement_id;") == queued:0:t ]]

run -c "UPDATE settlement_transaction_attempts
        SET status = 'submitted', submission_count = 1, submitted_at = NOW()
        WHERE transaction_hash =
              '0xabababababababababababababababababababababababababababababababab';
        INSERT INTO settlement_transaction_attempts
            (transaction_hash, lease_id, claim_generation, escrow_address,
             chain_lease_id, transaction_nonce, signer_address, raw_transaction,
             proposal, status)
        VALUES
            ('0xacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac',
             $current_settlement_id, 1,
             '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 42, 43,
             '0xcccccccccccccccccccccccccccccccccccccccc', '0x02',
             '{\"generation\":\"prepared\"}'::jsonb, 'prepared');
        INSERT INTO settlement_signer_nonce_reservations
            (signer_address, transaction_nonce, lease_id)
        VALUES
            ('0xcccccccccccccccccccccccccccccccccccccccc', 43,
             $current_settlement_id);
        DO \$\$
        BEGIN
          BEGIN
            UPDATE settlement_transaction_attempts SET raw_transaction = '0x02'
            WHERE transaction_hash =
                  '0xabababababababababababababababababababababababababababababababab';
            RAISE EXCEPTION 'immutable attempt update was accepted';
          EXCEPTION WHEN OTHERS THEN
            IF SQLERRM <> 'settlement transaction attempt evidence is immutable' THEN RAISE; END IF;
          END;
          BEGIN
            UPDATE settlement_transaction_attempts SET status = 'prepared'
            WHERE transaction_hash =
                  '0xabababababababababababababababababababababababababababababababab';
            RAISE EXCEPTION 'status rollback was accepted';
          EXCEPTION WHEN OTHERS THEN
            IF SQLERRM <> 'settlement transaction status cannot move backward' THEN RAISE; END IF;
          END;
          BEGIN
            UPDATE settlement_transaction_attempts SET submission_count = 0
            WHERE transaction_hash =
                  '0xabababababababababababababababababababababababababababababababab';
            RAISE EXCEPTION 'submission count rollback was accepted';
          EXCEPTION WHEN OTHERS THEN
            IF SQLERRM <> 'settlement transaction submission count is not monotonic' THEN RAISE; END IF;
          END;
          BEGIN
            UPDATE settlement_transaction_attempts SET submission_count = 3
            WHERE transaction_hash =
                  '0xabababababababababababababababababababababababababababababababab';
            RAISE EXCEPTION 'submission count jump was accepted';
          EXCEPTION WHEN OTHERS THEN
            IF SQLERRM <> 'settlement transaction submission count is not monotonic' THEN RAISE; END IF;
          END;
          BEGIN
            UPDATE settlement_transaction_attempts
            SET submitted_at = submitted_at + INTERVAL '1 second'
            WHERE transaction_hash =
                  '0xabababababababababababababababababababababababababababababababab';
            RAISE EXCEPTION 'submission timestamp mutation was accepted';
          EXCEPTION WHEN OTHERS THEN
            IF SQLERRM <> 'settlement submission timestamp is immutable' THEN RAISE; END IF;
          END;
          BEGIN
            UPDATE settlement_transaction_attempts SET submitted_at = NOW()
            WHERE transaction_hash =
                  '0xacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac';
            RAISE EXCEPTION 'unpaired submission timestamp was accepted';
          EXCEPTION WHEN OTHERS THEN
            IF SQLERRM <> 'settlement transaction submission timestamp has no submission' THEN RAISE; END IF;
          END;
          BEGIN
            UPDATE settlement_transaction_attempts SET confirmed_at = NOW()
            WHERE transaction_hash =
                  '0xacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac';
            RAISE EXCEPTION 'invalid confirmation annotation was accepted';
          EXCEPTION WHEN OTHERS THEN
            IF SQLERRM <> 'settlement transaction confirmation annotation is invalid' THEN RAISE; END IF;
          END;
          BEGIN
            DELETE FROM settlement_transaction_attempts
            WHERE transaction_hash =
                  '0xabababababababababababababababababababababababababababababababab';
            RAISE EXCEPTION 'attempt deletion was accepted';
          EXCEPTION WHEN OTHERS THEN
            IF SQLERRM <> 'settlement transaction attempts are append-only' THEN RAISE; END IF;
          END;
          BEGIN
            DELETE FROM settlement_jobs WHERE lease_id = $current_settlement_id;
            RAISE EXCEPTION 'attempt parent deletion was accepted';
          EXCEPTION WHEN foreign_key_violation THEN NULL;
          END;
        END \$\$;" >/dev/null

# An expired claim may be reclaimed, but the old generation cannot overwrite
# the job or submit through the generation-fenced worker path.
run -c "UPDATE settlement_jobs AS job
        SET status = 'processing', attempts = attempts + 1,
            claim_generation = claim_generation + 1,
            lease_until = NOW() + INTERVAL '2 minutes', updated_at = NOW()
        FROM leases AS lease
        WHERE job.lease_id = $current_settlement_id AND lease.lease_id = job.lease_id
          AND lease.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
          AND lease.chain_lease_id = 42 AND job.claim_generation = 1;" >/dev/null
[[ $(run -Atc "WITH stale AS (
                  UPDATE settlement_jobs AS job
                  SET proposal = '{\"generation\":\"stale\"}'::jsonb
                  FROM leases AS lease
                  WHERE job.lease_id = $current_settlement_id
                    AND lease.lease_id = job.lease_id
                    AND lease.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    AND lease.chain_lease_id = 42 AND job.claim_generation = 1
                  RETURNING 1
              ) SELECT COUNT(*) FROM stale;") == 0 ]]
[[ $(run -Atc "SELECT claim_generation || ':' || (proposal->>'generation')
              FROM settlement_jobs WHERE lease_id = $current_settlement_id;") == 2:current ]]
[[ $(run -Atc "WITH stale AS (
                  UPDATE settlement_jobs AS job
                  SET lease_until = NOW() + INTERVAL '2 minutes'
                  FROM leases AS lease
                  WHERE job.lease_id = $current_settlement_id
                    AND lease.lease_id = job.lease_id
                    AND lease.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    AND lease.chain_lease_id = 42 AND job.claim_generation = 1
                    AND job.status = 'processing'
                  RETURNING 1
              ) SELECT COUNT(*) FROM stale;") == 0 ]]
[[ $(run -Atc "WITH active AS (
                  UPDATE settlement_jobs AS job
                  SET lease_until = NOW() + INTERVAL '2 minutes'
                  FROM leases AS lease
                  WHERE job.lease_id = $current_settlement_id
                    AND lease.lease_id = job.lease_id
                    AND lease.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    AND lease.chain_lease_id = 42 AND job.claim_generation = 2
                    AND job.status = 'processing'
                  RETURNING 1
              ) SELECT COUNT(*) FROM active;") == 1 ]]

# Confirmation polling refunds the claim, but a finalized revert consumes it
# and reaches the retry cap with the bounded maximum backoff.
run -c "UPDATE settlement_jobs
        SET status = 'submitted', lease_until = NULL
        WHERE lease_id = $current_settlement_id AND claim_generation = 2;
        UPDATE settlement_jobs AS job
        SET attempts = GREATEST(0, attempts - 1), updated_at = NOW()
        FROM leases AS lease
        WHERE job.lease_id = $current_settlement_id
          AND lease.lease_id = job.lease_id
          AND lease.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
          AND lease.chain_lease_id = 42 AND job.claim_generation = 2
          AND job.status = 'submitted'
          AND job.transaction_hash =
              '0xabababababababababababababababababababababababababababababababab'
          AND EXISTS (
              SELECT 1 FROM settlement_transaction_attempts AS attempt
              WHERE attempt.transaction_hash = job.transaction_hash
                AND attempt.lease_id = job.lease_id
                AND attempt.escrow_address = lease.escrow_address
                AND attempt.chain_lease_id = lease.chain_lease_id
                AND attempt.status = 'submitted'
          );" >/dev/null
[[ $(run -Atc "SELECT attempts FROM settlement_jobs
              WHERE lease_id = $current_settlement_id;") == 1 ]]
run -c "UPDATE settlement_transaction_attempts
        SET status = 'reverted', reverted_at = NOW()
        WHERE transaction_hash =
              '0xabababababababababababababababababababababababababababababababab';
        UPDATE settlement_jobs
        SET status = 'queued', attempts = 99, available_at = NOW(), lease_until = NULL
        WHERE lease_id = $current_settlement_id;
        UPDATE settlement_jobs AS job
        SET status = 'processing', attempts = attempts + 1,
            claim_generation = claim_generation + 1,
            lease_until = NOW() + INTERVAL '2 minutes', updated_at = NOW()
        FROM leases AS lease
        WHERE job.lease_id = $current_settlement_id
          AND lease.lease_id = job.lease_id
          AND lease.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
          AND lease.chain_lease_id = 42;
        UPDATE settlement_jobs AS job
        SET status = CASE WHEN attempts >= 100 THEN 'failed' ELSE 'queued' END,
            lease_until = NULL,
            available_at = NOW() + make_interval(secs => LEAST(300, attempts * attempts)),
            last_error = 'finalized revert', updated_at = NOW()
        FROM leases AS lease
        WHERE job.lease_id = $current_settlement_id
          AND lease.lease_id = job.lease_id
          AND lease.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
          AND lease.chain_lease_id = 42 AND job.claim_generation = 3;" >/dev/null
[[ $(run -Atc "SELECT status || ':' || attempts || ':' ||
                     (available_at - NOW() BETWEEN INTERVAL '295 seconds' AND INTERVAL '301 seconds')
              FROM settlement_jobs WHERE lease_id = $current_settlement_id;") == failed:100:t ]]

[[ $(run -Atc "SELECT job.lease_id || ':' || lease.chain_lease_id
              FROM settlement_jobs AS job
              JOIN leases AS lease ON lease.lease_id = job.lease_id
              WHERE lease.escrow_address = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                AND job.attempts < 100 AND job.available_at <= NOW()
                AND (job.status IN ('queued', 'submitted')
                     OR (job.status = 'processing' AND job.lease_until <= NOW()))
              ORDER BY job.available_at, job.created_at LIMIT 1
              FOR UPDATE OF job, lease SKIP LOCKED;") == "$historical_settlement_id:42" ]]
run -c "UPDATE settlement_jobs AS job
        SET status = 'processing', attempts = attempts + 1,
            claim_generation = claim_generation + 1,
            lease_until = NOW() + INTERVAL '2 minutes', updated_at = NOW()
        FROM leases AS lease
        WHERE job.lease_id = $historical_settlement_id AND lease.lease_id = job.lease_id
          AND lease.escrow_address = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
          AND lease.chain_lease_id = 42;" >/dev/null
[[ $(run -Atc "SELECT status || ':' || attempts || ':' || claim_generation
              FROM settlement_jobs WHERE lease_id = $historical_settlement_id;") == processing:1:1 ]]

# workers/lifecycle-worker: current escrow leases reserve logical capacity,
# while every provider instance still alive reserves physical capacity.
run -c "INSERT INTO accounts (subject) VALUES ('capacity-scope-test');
        INSERT INTO node_offers (node_id, document, updated_at) VALUES
            ('scope-prior-failed', '{}'::jsonb, NOW()),
            ('scope-current-failed', '{}'::jsonb, NOW()),
            ('scope-prior-live', '{}'::jsonb, NOW());
        INSERT INTO cloud_capacity (node_id, provider, available, observed_at) VALUES
            ('scope-prior-failed', 'vast', FALSE, NOW()),
            ('scope-current-failed', 'vast', FALSE, NOW()),
            ('scope-prior-live', 'vast', FALSE, NOW());
        INSERT INTO lease_quotes
            (quote_id, node_id, document, expires_at, subject)
        VALUES
            ('018f0000-0000-7000-8000-000000000101', 'scope-prior-failed',
             '{}'::jsonb, NOW() + INTERVAL '1 hour', 'capacity-scope-test'),
            ('018f0000-0000-7000-8000-000000000102', 'scope-current-failed',
             '{}'::jsonb, NOW() + INTERVAL '1 hour', 'capacity-scope-test'),
            ('018f0000-0000-7000-8000-000000000103', 'scope-prior-live',
             '{}'::jsonb, NOW() + INTERVAL '1 hour', 'capacity-scope-test');
        INSERT INTO leases
            (quote_id, subject, renter_wallet, funding_transaction_hash, document, state,
             escrow_address, chain_lease_id)
        VALUES
            ('018f0000-0000-7000-8000-000000000101', 'capacity-scope-test',
             '0x1111111111111111111111111111111111111111',
             '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
             '{\"node_id\":\"scope-prior-failed\"}'::jsonb, 'failed',
             '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 1),
            ('018f0000-0000-7000-8000-000000000102', 'capacity-scope-test',
             '0x1111111111111111111111111111111111111111',
             '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
             '{\"node_id\":\"scope-current-failed\"}'::jsonb, 'failed',
             '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1),
            ('018f0000-0000-7000-8000-000000000103', 'capacity-scope-test',
             '0x1111111111111111111111111111111111111111',
             '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
             '{\"node_id\":\"scope-prior-live\"}'::jsonb, 'failed',
             '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 2);
        INSERT INTO cloud_instances
            (lease_id, provider_instance_id, status)
        SELECT lease_id, 99001, 'running' FROM leases
        WHERE quote_id = '018f0000-0000-7000-8000-000000000103';
        UPDATE lease_quotes SET consumed_at = NOW()
        WHERE subject = 'capacity-scope-test';" >/dev/null

[[ $(run -Atc "WITH commitments AS (
                  SELECT l.lease_id FROM leases l
                  WHERE l.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    AND l.state NOT IN ('finalized', 'refunded')
                    AND EXISTS (
                        SELECT 1 FROM cloud_capacity cc
                        WHERE cc.node_id = l.document->>'node_id' AND cc.provider = 'vast'
                    )
                  UNION
                  SELECT ci.lease_id FROM cloud_instances ci
                  WHERE ci.provider = 'vast' AND ci.status <> 'destroyed'
              )
              SELECT COUNT(*) FROM commitments c JOIN leases l USING (lease_id)
              WHERE l.subject = 'capacity-scope-test';") == 2 ]]

[[ $(run -Atc "WITH busy AS (
                  SELECT l.document->>'node_id' AS node_id FROM leases l
                  WHERE l.escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    AND l.state NOT IN ('finalized', 'refunded')
                  UNION
                  SELECT l.document->>'node_id' FROM leases l
                  JOIN cloud_instances ci ON ci.lease_id = l.lease_id
                  WHERE ci.status <> 'destroyed'
              )
              SELECT string_agg(node_id, ',' ORDER BY node_id) FROM busy
              WHERE node_id LIKE 'scope-%';") == scope-current-failed,scope-prior-live ]]

[[ $(run -Atc "SELECT COUNT(*) FROM leases
              WHERE subject = 'capacity-scope-test'
                AND escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                AND state NOT IN ('finalized', 'refunded');") == 1 ]]

[[ $(run -Atc "WITH reserved AS (
                  SELECT node_id FROM lease_quotes
                  WHERE consumed_at IS NULL AND expires_at > NOW()
                    AND created_at > NOW() - make_interval(secs => 90::float8)
                  UNION SELECT document->>'node_id' FROM leases
                  WHERE escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    AND state NOT IN ('finalized', 'refunded')
                  UNION SELECT l.document->>'node_id' FROM leases l
                  JOIN cloud_instances ci ON ci.lease_id = l.lease_id
                  WHERE ci.status <> 'destroyed'
              )
              SELECT string_agg(node_id, ',' ORDER BY node_id) FROM reserved
              WHERE node_id LIKE 'scope-%';") == scope-current-failed,scope-prior-live ]]

[[ $(run -Atc "WITH candidates(node_id) AS (VALUES
                  ('scope-prior-failed'),
                  ('scope-current-failed'),
                  ('scope-prior-live')
              )
              SELECT string_agg(node_id, ',' ORDER BY node_id) FROM candidates c
              WHERE EXISTS (
                  SELECT 1 FROM leases
                  WHERE document->>'node_id' = c.node_id
                    AND escrow_address = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    AND state NOT IN ('finalized', 'refunded')
                  UNION
                  SELECT 1 FROM leases l
                  JOIN cloud_instances ci ON ci.lease_id = l.lease_id
                  WHERE l.document->>'node_id' = c.node_id
                    AND ci.status <> 'destroyed'
              );") == scope-current-failed,scope-prior-live ]]

run -c "INSERT INTO cloud_provider_state
            (provider, balance_micros, state, failure_class, blocked_at)
        VALUES ('vast', 5000000, 'auth_blocked', 'provider_auth', NOW());
        INSERT INTO cloud_provider_state
            (provider, balance_micros, state, failure_class, blocked_at,
             observed_at, consecutive_failures)
        VALUES ('vast', 5000000, 'transient_blocked', 'provider_transient', NOW(), NOW(), 1)
        ON CONFLICT (provider) DO UPDATE SET
            state = CASE
                WHEN cloud_provider_state.state = 'operator_maintenance'
                THEN cloud_provider_state.state
                WHEN cloud_provider_state.state IN ('auth_blocked', 'permanent_blocked')
                 AND EXCLUDED.state NOT IN ('auth_blocked', 'permanent_blocked')
                THEN cloud_provider_state.state ELSE EXCLUDED.state END,
            failure_class = CASE
                WHEN cloud_provider_state.state = 'operator_maintenance'
                THEN cloud_provider_state.failure_class
                WHEN cloud_provider_state.state IN ('auth_blocked', 'permanent_blocked')
                 AND EXCLUDED.state NOT IN ('auth_blocked', 'permanent_blocked')
                THEN cloud_provider_state.failure_class ELSE EXCLUDED.failure_class END;" >/dev/null
[[ $(run -Atc "SELECT state || ':' || failure_class FROM cloud_provider_state
              WHERE provider = 'vast';") == auth_blocked:provider_auth ]]

# Migration 28's operator latch survives both success and every provider
# failure class. The create path reads the same latched state, and capacity
# remains unavailable until an operator removes exactly this row under lock.
run -c "DELETE FROM cloud_provider_state WHERE provider = 'vast';
        UPDATE cloud_capacity SET available = TRUE WHERE provider = 'vast';
        BEGIN;
        SELECT pg_advisory_xact_lock(4663);
        INSERT INTO cloud_provider_state
            (provider, balance_micros, state, failure_class, blocked_at,
             observed_at, consecutive_failures, updated_at)
        VALUES
            ('vast', 5000000, 'operator_maintenance', 'operator_maintenance',
             NOW(), NOW(), 0, NOW())
        ON CONFLICT (provider) DO UPDATE SET
            state = 'operator_maintenance',
            failure_class = 'operator_maintenance',
            blocked_at = CASE
                WHEN cloud_provider_state.state = 'operator_maintenance'
                THEN cloud_provider_state.blocked_at ELSE NOW() END,
            observed_at = NOW(), consecutive_failures = 0, updated_at = NOW()
        WHERE cloud_provider_state.state NOT IN ('auth_blocked', 'permanent_blocked');
        UPDATE cloud_capacity
        SET available = FALSE, updated_at = NOW()
        WHERE provider = 'vast';
        COMMIT;" >/dev/null
[[ $(run -Atc "SELECT state || ':' || failure_class || ':' ||
                     (blocked_at IS NOT NULL)
              FROM cloud_provider_state WHERE provider = 'vast';") == \
  operator_maintenance:operator_maintenance:t ]]
[[ $(run -Atc "SELECT COUNT(*) FILTER (WHERE available) FROM cloud_capacity
              WHERE provider = 'vast';") == 0 ]]

# A fresh funded observation cannot clear maintenance.
run -c "INSERT INTO cloud_provider_state
            (provider, balance_micros, state, observed_at)
        VALUES ('vast', 9000000, 'healthy', NOW())
        ON CONFLICT (provider) DO UPDATE SET
            balance_micros = EXCLUDED.balance_micros, state = 'healthy',
            failure_class = NULL, blocked_at = NULL,
            observed_at = NOW(), consecutive_failures = 0, updated_at = NOW()
        WHERE cloud_provider_state.state NOT IN
            ('auth_blocked', 'permanent_blocked', 'operator_maintenance');" >/dev/null
[[ $(run -Atc "SELECT state || ':' || failure_class || ':' || balance_micros
              FROM cloud_provider_state WHERE provider = 'vast';") == \
  operator_maintenance:operator_maintenance:5000000 ]]

# Even a normally latched provider failure is subordinate to operator
# maintenance and cannot replace its state, reason or latch timestamp.
maintenance_blocked_at=$(run -Atc "SELECT blocked_at FROM cloud_provider_state
                                   WHERE provider = 'vast';")
run -c "INSERT INTO cloud_provider_state
            (provider, balance_micros, state, failure_class, blocked_at,
             observed_at, consecutive_failures)
        VALUES ('vast', NULL, 'permanent_blocked', 'provider_response',
                NOW(), NOW(), 1)
        ON CONFLICT (provider) DO UPDATE SET
            balance_micros = COALESCE(EXCLUDED.balance_micros,
                                      cloud_provider_state.balance_micros),
            state = CASE
                WHEN cloud_provider_state.state = 'operator_maintenance'
                THEN cloud_provider_state.state
                WHEN cloud_provider_state.state IN ('auth_blocked', 'permanent_blocked')
                 AND EXCLUDED.state NOT IN ('auth_blocked', 'permanent_blocked')
                THEN cloud_provider_state.state ELSE EXCLUDED.state END,
            failure_class = CASE
                WHEN cloud_provider_state.state = 'operator_maintenance'
                THEN cloud_provider_state.failure_class
                WHEN cloud_provider_state.state IN ('auth_blocked', 'permanent_blocked')
                 AND EXCLUDED.state NOT IN ('auth_blocked', 'permanent_blocked')
                THEN cloud_provider_state.failure_class ELSE EXCLUDED.failure_class END,
            blocked_at = CASE
                WHEN cloud_provider_state.state = 'operator_maintenance'
                THEN cloud_provider_state.blocked_at
                WHEN cloud_provider_state.state IN ('auth_blocked', 'permanent_blocked')
                 AND EXCLUDED.state NOT IN ('auth_blocked', 'permanent_blocked')
                THEN cloud_provider_state.blocked_at
                WHEN cloud_provider_state.state = EXCLUDED.state
                THEN cloud_provider_state.blocked_at ELSE NOW() END,
            observed_at = NOW(),
            consecutive_failures = cloud_provider_state.consecutive_failures + 1,
            updated_at = NOW();
        UPDATE cloud_capacity
        SET available = FALSE, updated_at = NOW()
        WHERE provider = 'vast';" >/dev/null
[[ $(run -Atc "SELECT state || ':' || failure_class || ':' || blocked_at || ':' ||
                     consecutive_failures
              FROM cloud_provider_state WHERE provider = 'vast';") == \
  "operator_maintenance:operator_maintenance:$maintenance_blocked_at:1" ]]
[[ $(run -Atc "SELECT state IN
                     ('auth_blocked', 'permanent_blocked', 'operator_maintenance')
              FROM cloud_provider_state WHERE provider = 'vast';") == t ]]
[[ $(run -Atc "SELECT COUNT(*) FILTER (WHERE available) FROM cloud_capacity
              WHERE provider = 'vast';") == 0 ]]

# Clearing is exact-state-only and leaves capacity closed for the sole current
# owner to rebuild from a fresh provider observation.
run -c "BEGIN;
        SELECT pg_advisory_xact_lock(4663);
        UPDATE cloud_capacity
        SET available = FALSE, updated_at = NOW()
        WHERE provider = 'vast';
        DO \$maintenance_clear\$
        DECLARE
            current_state TEXT;
            removed INTEGER;
        BEGIN
            SELECT state INTO current_state
            FROM cloud_provider_state
            WHERE provider = 'vast'
            FOR UPDATE;
            IF current_state IS DISTINCT FROM 'operator_maintenance' THEN
                RAISE EXCEPTION 'unexpected provider state: %', current_state;
            END IF;
            DELETE FROM cloud_provider_state
            WHERE provider = 'vast' AND state = 'operator_maintenance';
            GET DIAGNOSTICS removed = ROW_COUNT;
            IF removed <> 1 THEN
                RAISE EXCEPTION 'expected one maintenance row, removed %', removed;
            END IF;
        END
        \$maintenance_clear\$;
        COMMIT;" >/dev/null
[[ $(run -Atc "SELECT COUNT(*) FROM cloud_provider_state
              WHERE provider = 'vast';") == 0 ]]
[[ $(run -Atc "SELECT COUNT(*) FILTER (WHERE available) FROM cloud_capacity
              WHERE provider = 'vast';") == 0 ]]

# The provider-spend path and operator maintenance use the same advisory lock.
# If spend wins, maintenance cannot commit in its final-check/create window. If
# maintenance wins, the locked recheck observes the latch and no spend occurs.
run -c "CREATE TABLE provider_spend_race_events (
            event_id BIGSERIAL PRIMARY KEY,
            event TEXT NOT NULL
        );
        INSERT INTO cloud_provider_state
            (provider, balance_micros, state, observed_at)
        VALUES ('vast', 9000000, 'healthy', NOW())
        ON CONFLICT (provider) DO UPDATE SET
            state = 'healthy', failure_class = NULL, blocked_at = NULL,
            observed_at = NOW(), updated_at = NOW();" >/dev/null
run -c "BEGIN;
        SELECT pg_advisory_xact_lock(4663);
        SELECT pg_sleep(1);
        INSERT INTO provider_spend_race_events (event) VALUES ('spend');
        COMMIT;" >/dev/null &
spend_first_pid=$!
for _ in $(seq 1 100); do
  if [[ $(run -Atc "SELECT COUNT(*) FROM pg_locks
                    WHERE locktype = 'advisory' AND classid = 0
                      AND objid = 4663 AND granted;") -ge 1 ]]; then
    break
  fi
  sleep 0.02
done
[[ $(run -Atc "SELECT COUNT(*) FROM pg_locks
              WHERE locktype = 'advisory' AND classid = 0
                AND objid = 4663 AND granted;") -ge 1 ]]
run -c "BEGIN;
        SELECT pg_advisory_xact_lock(4663);
        UPDATE cloud_provider_state
        SET state = 'operator_maintenance', failure_class = 'operator_maintenance',
            blocked_at = NOW(), updated_at = NOW()
        WHERE provider = 'vast';
        INSERT INTO provider_spend_race_events (event) VALUES ('maintenance');
        COMMIT;" >/dev/null &
maintenance_second_pid=$!
wait "$spend_first_pid"
wait "$maintenance_second_pid"
[[ $(run -Atc "SELECT string_agg(event, ':' ORDER BY event_id)
              FROM provider_spend_race_events;") == spend:maintenance ]]

run -c "TRUNCATE provider_spend_race_events;
        UPDATE cloud_provider_state
        SET state = 'healthy', failure_class = NULL, blocked_at = NULL,
            observed_at = NOW(), updated_at = NOW()
        WHERE provider = 'vast';" >/dev/null
run -c "BEGIN;
        SELECT pg_advisory_xact_lock(4663);
        UPDATE cloud_provider_state
        SET state = 'operator_maintenance', failure_class = 'operator_maintenance',
            blocked_at = NOW(), updated_at = NOW()
        WHERE provider = 'vast';
        INSERT INTO provider_spend_race_events (event) VALUES ('maintenance');
        SELECT pg_sleep(1);
        COMMIT;" >/dev/null &
maintenance_first_pid=$!
for _ in $(seq 1 100); do
  if [[ $(run -Atc "SELECT COUNT(*) FROM pg_locks
                    WHERE locktype = 'advisory' AND classid = 0
                      AND objid = 4663 AND granted;") -ge 1 ]]; then
    break
  fi
  sleep 0.02
done
[[ $(run -Atc "SELECT COUNT(*) FROM pg_locks
              WHERE locktype = 'advisory' AND classid = 0
                AND objid = 4663 AND granted;") -ge 1 ]]
run -c "BEGIN;
        SELECT pg_advisory_xact_lock(4663);
        INSERT INTO provider_spend_race_events (event)
        SELECT 'spend'
        WHERE NOT EXISTS (
            SELECT 1 FROM cloud_provider_state
            WHERE provider = 'vast'
              AND state IN ('auth_blocked', 'permanent_blocked',
                            'operator_maintenance')
        );
        COMMIT;" >/dev/null &
spend_second_pid=$!
wait "$maintenance_first_pid"
wait "$spend_second_pid"
[[ $(run -Atc "SELECT string_agg(event, ':' ORDER BY event_id)
              FROM provider_spend_race_events;") == maintenance ]]
run -c "DROP TABLE provider_spend_race_events;" >/dev/null

# workers/lifecycle-worker: the shared machine rejection list
run -c "SELECT machine_id FROM cloud_machine_rejections \
        WHERE last_rejected_at > NOW() - make_interval(secs => 21600::float8) \
        ORDER BY last_rejected_at DESC;" >/dev/null
run -c "INSERT INTO cloud_machine_rejections (machine_id, reason) VALUES (1, 'test') \
        ON CONFLICT (machine_id) DO UPDATE \
        SET reason = EXCLUDED.reason, \
            rejections = cloud_machine_rejections.rejections + 1, \
            last_rejected_at = NOW();" >/dev/null

# services/*: build version recorded on startup
run -c "INSERT INTO service_versions (service, version, started_at) \
        VALUES ('test', 'abc', NOW()) \
        ON CONFLICT (service) DO UPDATE \
        SET version = EXCLUDED.version, started_at = EXCLUDED.started_at;" >/dev/null

# services/reconciliation-monitor: deployed version drift
run -c "SELECT COUNT(DISTINCT version)::bigint FROM service_versions;" >/dev/null

printf 'worker SQL statements execute\n'
