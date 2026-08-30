#!/usr/bin/env bash
set -Eeuo pipefail

command -v docker >/dev/null

container="prism-proof-identity-$$"
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

docker exec -i -e PGPASSWORD=prism "$container" psql -v ON_ERROR_STOP=1 \
  -U prism -d prism >/dev/null <<'SQL'
CREATE TABLE leases (
    lease_id BIGINT PRIMARY KEY,
    escrow_address TEXT NOT NULL CHECK (escrow_address ~ '^0x[0-9a-f]{40}$'),
    chain_lease_id BIGINT NOT NULL CHECK (chain_lease_id > 0),
    UNIQUE (escrow_address, chain_lease_id)
);

CREATE TABLE proof_receipts (
    receipt_id UUID PRIMARY KEY,
    lease_id BIGINT NOT NULL UNIQUE REFERENCES leases(lease_id),
    document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    transaction_hash TEXT NOT NULL UNIQUE,
    block_number BIGINT NOT NULL,
    block_hash TEXT NOT NULL,
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO leases (lease_id, escrow_address, chain_lease_id) VALUES
    (1, '0x1111111111111111111111111111111111111111', 7),
    (1001, '0x2222222222222222222222222222222222222222', 7),
    (1002, '0x2222222222222222222222222222222222222222', 8),
    (1003, '0x2222222222222222222222222222222222222222', 9),
    (1004, '0x2222222222222222222222222222222222222222', 10);

INSERT INTO proof_receipts
    (receipt_id, lease_id, document, transaction_hash, block_number, block_hash, published_at)
VALUES
    ('00000000-0000-7000-8000-000000000001', 1,
     '{"receipt_id":"00000000-0000-7000-8000-000000000001","lease_id":"7","outcome":"finalized","receipt_hash":"hash-one"}',
     'tx-one', 10, 'block-one', NOW()),
    ('00000000-0000-7000-8000-000000000002', 1001,
     '{"receipt_id":"00000000-0000-7000-8000-000000000002","lease_id":"7","outcome":"finalized","receipt_hash":"hash-two"}',
     'tx-two', 11, 'block-two', NULL),
    ('00000000-0000-7000-8000-000000000003', 1002,
     '{"receipt_id":"00000000-0000-7000-8000-000000000003","lease_id":"999","outcome":"finalized","receipt_hash":"preserved-hash","marker":"preserved-document"}',
     'tx-three', 12, 'block-three', NOW());
SQL

docker exec -i -e PGPASSWORD=prism "$container" psql -v ON_ERROR_STOP=1 \
  -U prism -d prism >/dev/null \
  < services/control-plane/migrations/0027_proof_receipt_identity.sql

docker exec -i -e PGPASSWORD=prism "$container" psql -v ON_ERROR_STOP=1 \
  -U prism -d prism >/dev/null <<'SQL'
INSERT INTO proof_receipts
    (receipt_id, lease_id, escrow_address, chain_lease_id, document,
     transaction_hash, block_number, block_hash)
VALUES
    ('00000000-0000-7000-8000-000000000004', 1003,
     '0x2222222222222222222222222222222222222222', 9,
     '{"receipt_id":"00000000-0000-7000-8000-000000000004","lease_id":"9","escrow_address":"0x2222222222222222222222222222222222222222","chain_lease_id":"9","outcome":"finalized","receipt_hash":"hash-four"}',
     'tx-four', 13, 'block-four');
SQL

query() {
  docker exec -e PGPASSWORD=prism "$container" \
    psql -U prism -d prism -Atc "$1"
}

run_sql() {
  docker exec -e PGPASSWORD=prism "$container" \
    psql -v ON_ERROR_STOP=1 -U prism -d prism -c "$1" >/dev/null
}

expect_failure() {
  local description=$1 statement=$2
  if run_sql "$statement" 2>/dev/null; then
    echo "$description unexpectedly succeeded" >&2
    exit 1
  fi
}

test "$(query "SELECT count(*) FROM proof_receipts WHERE chain_lease_id = 7")" = 2
test "$(query "SELECT publication_state FROM proof_receipts WHERE lease_id = 1")" = published
test "$(query "SELECT publication_state FROM proof_receipts WHERE lease_id = 1001")" = pending
test "$(query "SELECT publication_state FROM proof_receipts WHERE lease_id = 1003")" = pending
test "$(query "SELECT document->>'chain_lease_id' FROM proof_receipts WHERE lease_id = 1001")" = 7
test "$(query "SELECT document->>'escrow_address' FROM proof_receipts WHERE lease_id = 1001")" = 0x2222222222222222222222222222222222222222
test "$(query "SELECT publication_state || ':' || quarantine_reason FROM proof_receipts WHERE lease_id = 1002")" = quarantined:legacy_chain_identity_mismatch
test "$(query "SELECT (document->>'receipt_hash') || ':' || (document->>'marker') || ':' || (document->>'lease_id') FROM proof_receipts WHERE lease_id = 1002")" = preserved-hash:preserved-document:999
test "$(query "SELECT NOT (document ? 'escrow_address') AND NOT (document ? 'chain_lease_id') AND published_at IS NULL FROM proof_receipts WHERE lease_id = 1002")" = t
test "$(query "SELECT count(*) FROM proof_receipts r JOIN leases l ON l.lease_id = r.lease_id AND l.escrow_address = r.escrow_address AND l.chain_lease_id = r.chain_lease_id WHERE r.publication_state <> 'quarantined' AND r.document->>'outcome' = 'finalized'")" = 3

run_sql "INSERT INTO proof_receipts
    (receipt_id, lease_id, escrow_address, chain_lease_id, document,
     transaction_hash, block_number, block_hash)
  VALUES
    ('00000000-0000-7000-8000-000000000004', 1003,
     '0x2222222222222222222222222222222222222222', 9,
     '{\"receipt_id\":\"00000000-0000-7000-8000-000000000004\",\"lease_id\":\"9\",\"escrow_address\":\"0x2222222222222222222222222222222222222222\",\"chain_lease_id\":\"9\",\"outcome\":\"finalized\",\"receipt_hash\":\"hash-four\"}',
     'tx-four', 13, 'block-four')
  ON CONFLICT (lease_id) DO UPDATE SET receipt_id = proof_receipts.receipt_id
  WHERE proof_receipts.receipt_id = EXCLUDED.receipt_id
    AND proof_receipts.escrow_address = EXCLUDED.escrow_address
    AND proof_receipts.chain_lease_id = EXCLUDED.chain_lease_id
    AND proof_receipts.document = EXCLUDED.document
    AND proof_receipts.transaction_hash = EXCLUDED.transaction_hash
    AND proof_receipts.block_number = EXCLUDED.block_number
    AND proof_receipts.block_hash = EXCLUDED.block_hash"

expect_failure "mixed escrow identity update" \
  "UPDATE proof_receipts SET escrow_address = '0x1111111111111111111111111111111111111111' WHERE lease_id = 1001"
expect_failure "chain lease identity update" \
  "UPDATE proof_receipts SET chain_lease_id = 10 WHERE lease_id = 1001"
expect_failure "receipt document mutation" \
  "UPDATE proof_receipts SET document = document || '{\"marker\":\"mutated\"}'::jsonb WHERE lease_id = 1"
expect_failure "transaction hash mutation" \
  "UPDATE proof_receipts SET transaction_hash = 'tx-mutated' WHERE lease_id = 1"
expect_failure "block hash mutation" \
  "UPDATE proof_receipts SET block_hash = 'block-mutated' WHERE lease_id = 1"
expect_failure "block number mutation" \
  "UPDATE proof_receipts SET block_number = block_number + 1 WHERE lease_id = 1"
expect_failure "receipt identity mutation" \
  "UPDATE proof_receipts SET receipt_id = '00000000-0000-7000-8000-000000000099' WHERE lease_id = 1"
expect_failure "internal lease identity mutation" \
  "UPDATE proof_receipts SET lease_id = 1004 WHERE lease_id = 1"
expect_failure "creation timestamp mutation" \
  "UPDATE proof_receipts SET created_at = created_at + INTERVAL '1 second' WHERE lease_id = 1"
expect_failure "published timestamp rewrite" \
  "UPDATE proof_receipts SET published_at = published_at + INTERVAL '1 second' WHERE lease_id = 1"
expect_failure "proof evidence deletion" \
  "DELETE FROM proof_receipts WHERE lease_id = 1"
expect_failure "published state rollback" \
  "UPDATE proof_receipts SET publication_state = 'pending', published_at = NULL WHERE lease_id = 1"
expect_failure "direct published insert" \
  "INSERT INTO proof_receipts
      (receipt_id, lease_id, escrow_address, chain_lease_id, document,
       transaction_hash, block_number, block_hash, publication_state, published_at)
    VALUES
      ('00000000-0000-7000-8000-000000000005', 1004,
       '0x2222222222222222222222222222222222222222', 10,
       '{\"receipt_id\":\"00000000-0000-7000-8000-000000000005\",\"lease_id\":\"10\",\"escrow_address\":\"0x2222222222222222222222222222222222222222\",\"chain_lease_id\":\"10\",\"outcome\":\"finalized\",\"receipt_hash\":\"hash-five\"}',
       'tx-five', 14, 'block-five', 'published', NOW())"

run_sql "UPDATE proof_receipts
  SET publication_state = 'published', published_at = NOW(), quarantine_reason = NULL
  WHERE lease_id = 1003"
published_token_before_revocation=$(query \
  "SELECT count(*)::text || ':' || COALESCE(max(published_at)::text, '')
   FROM proof_receipts WHERE publication_state = 'published'")
run_sql "UPDATE proof_receipts
  SET publication_state = 'quarantined', published_at = NULL, quarantine_reason = 'structural_revocation'
  WHERE lease_id = 1003"
published_token_after_revocation=$(query \
  "SELECT count(*)::text || ':' || COALESCE(max(published_at)::text, '')
   FROM proof_receipts WHERE publication_state = 'published'")
test "$published_token_before_revocation" != "$published_token_after_revocation"
test "$(query "SELECT publication_state || ':' || quarantine_reason FROM proof_receipts WHERE lease_id = 1003")" = quarantined:structural_revocation
expect_failure "quarantined state rollback to pending" \
  "UPDATE proof_receipts SET publication_state = 'pending', quarantine_reason = NULL WHERE lease_id = 1003"
expect_failure "quarantined state rollback to published" \
  "UPDATE proof_receipts SET publication_state = 'published', published_at = NOW(), quarantine_reason = NULL WHERE lease_id = 1003"

echo "proof receipt identity migration passed"
