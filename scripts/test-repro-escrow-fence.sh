#!/usr/bin/env bash
set -Eeuo pipefail

command -v docker >/dev/null

container="prism-repro-escrow-$$"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$container" -p 127.0.0.1::5432 \
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

port=$(docker port "$container" 5432/tcp | awk -F: 'NR == 1 { print $NF }')
PRISM_TEST_DATABASE_URL="postgres://prism:prism@127.0.0.1:${port}/prism" \
  cargo test -p prism-repro-worker tests::postgres_escrow_generations_claim_independently \
  -- --ignored --exact
PRISM_TEST_DATABASE_URL="postgres://prism:prism@127.0.0.1:${port}/prism" \
  cargo test -p prism-repro-worker tests::postgres_restart_after_deadline_persists_terminal_report \
  -- --ignored --exact
