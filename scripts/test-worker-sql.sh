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
set -Eeuo pipefail

command -v docker >/dev/null

container="prism-worker-sql-$$"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$container" \
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

run() {
  docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U prism -d prism -q "$@"
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
            FROM leases WHERE quote_id = '018f0000-0000-7000-8000-000000000028';" >/dev/null
  fi
  run -f - < "$migration"
done
printf 'migrations applied\n'

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

run -c "INSERT INTO cloud_provider_state
            (provider, balance_micros, state, failure_class, blocked_at)
        VALUES ('vast', 5000000, 'auth_blocked', 'provider_auth', NOW());
        INSERT INTO cloud_provider_state
            (provider, balance_micros, state, failure_class, blocked_at,
             observed_at, consecutive_failures)
        VALUES ('vast', 5000000, 'transient_blocked', 'provider_transient', NOW(), NOW(), 1)
        ON CONFLICT (provider) DO UPDATE SET
            state = CASE
                WHEN cloud_provider_state.state IN ('auth_blocked', 'permanent_blocked')
                 AND EXCLUDED.state NOT IN ('auth_blocked', 'permanent_blocked')
                THEN cloud_provider_state.state ELSE EXCLUDED.state END,
            failure_class = CASE
                WHEN cloud_provider_state.state IN ('auth_blocked', 'permanent_blocked')
                 AND EXCLUDED.state NOT IN ('auth_blocked', 'permanent_blocked')
                THEN cloud_provider_state.failure_class ELSE EXCLUDED.failure_class END;" >/dev/null
[[ $(run -Atc "SELECT state || ':' || failure_class FROM cloud_provider_state
              WHERE provider = 'vast';") == auth_blocked:provider_auth ]]

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

# services/control-plane: nodes a lease still occupies
run -c "SELECT node_id FROM lease_quotes \
        WHERE consumed_at IS NULL AND expires_at > NOW() \
          AND created_at > NOW() - make_interval(secs => 300::float8) \
        UNION SELECT document->>'node_id' FROM leases \
        WHERE state NOT IN ('finalized', 'refunded', 'failed');" >/dev/null

printf 'worker SQL statements execute\n'
