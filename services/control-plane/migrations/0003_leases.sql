ALTER TABLE lease_quotes
    ADD COLUMN subject TEXT NOT NULL,
    ADD COLUMN consumed_at TIMESTAMPTZ;

CREATE INDEX lease_quotes_subject_idx ON lease_quotes(subject, created_at DESC);

CREATE TABLE leases (
    lease_id BIGINT PRIMARY KEY CHECK (lease_id > 0),
    quote_id UUID NOT NULL UNIQUE REFERENCES lease_quotes(quote_id),
    subject TEXT NOT NULL REFERENCES accounts(subject),
    renter_wallet TEXT NOT NULL CHECK (renter_wallet ~ '^0x[0-9a-f]{40}$'),
    funding_transaction_hash TEXT NOT NULL UNIQUE
        CHECK (funding_transaction_hash ~ '^0x[0-9a-f]{64}$'),
    document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    state TEXT NOT NULL CHECK (
        state IN (
            'funded',
            'provisioning',
            'ready',
            'active',
            'closing',
            'settlement_pending',
            'disputed',
            'finalized',
            'refunded',
            'failed'
        )
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX leases_subject_idx ON leases(subject, created_at DESC);
CREATE INDEX leases_state_idx ON leases(state, updated_at);
