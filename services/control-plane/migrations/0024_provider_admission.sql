CREATE TABLE cloud_provider_state (
    provider TEXT PRIMARY KEY CHECK (provider = 'vast'),
    balance_micros BIGINT,
    state TEXT NOT NULL CHECK (
        state IN (
            'healthy',
            'credit_blocked',
            'auth_blocked',
            'transient_blocked',
            'permanent_blocked'
        )
    ),
    failure_class TEXT CHECK (
        failure_class IS NULL OR char_length(failure_class) BETWEEN 1 AND 64
    ),
    blocked_at TIMESTAMPTZ,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE lifecycle_outbox
    DROP CONSTRAINT lifecycle_outbox_kind_check;

ALTER TABLE lifecycle_outbox
    ADD CONSTRAINT lifecycle_outbox_kind_check CHECK (
        kind IN (
            'start_access',
            'refresh_grant',
            'close_access',
            'expire_provision',
            'finalize',
            'cleanup_cloud'
        )
    );

-- A failed action can retain signed bytes for a nonce the signer has long since
-- passed. Only reopen unsettled local leases, and force the worker to preflight
-- the chain and prepare a fresh transaction.
UPDATE lifecycle_outbox AS action
SET status = 'queued',
    raw_transaction = NULL,
    transaction_hash = NULL,
    transaction_nonce = NULL,
    confirmed_block = NULL,
    confirmed_block_hash = NULL,
    lease_until = NULL,
    available_at = NOW(),
    last_error = NULL,
    updated_at = NOW()
FROM leases AS lease
WHERE action.lease_id = lease.lease_id
  AND action.status = 'failed'
  AND action.kind IN ('close_access', 'expire_provision', 'finalize')
  AND lease.state NOT IN ('finalized', 'refunded');
