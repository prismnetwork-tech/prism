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
  if docker exec "$container" pg_isready -U prism -d prism >/dev/null 2>&1; then break; fi
  sleep 1
done

run() {
  docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U prism -d prism -q "$@"
}

for migration in services/control-plane/migrations/*.sql; do
  run -f - < "$migration"
done
printf 'migrations applied\n'

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
