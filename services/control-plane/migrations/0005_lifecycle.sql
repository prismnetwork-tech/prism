CREATE TABLE lease_secrets (
    lease_id BIGINT PRIMARY KEY REFERENCES leases(lease_id) ON DELETE CASCADE,
    jupyter_token JSONB NOT NULL CHECK (jsonb_typeof(jupyter_token) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE lease_lifecycle (
    lease_id BIGINT PRIMARY KEY REFERENCES leases(lease_id) ON DELETE CASCADE,
    connection_id TEXT CHECK (
        connection_id IS NULL OR char_length(connection_id) BETWEEN 1 AND 128
    ),
    node_ready_at TIMESTAMPTZ,
    cuda_ready_at TIMESTAMPTZ,
    gateway_ready_at TIMESTAMPTZ,
    access_started_at TIMESTAMPTZ,
    access_ended_at TIMESTAMPTZ,
    gateway_closed_at TIMESTAMPTZ,
    grant_token_id UUID,
    grant_token JSONB CHECK (
        grant_token IS NULL OR jsonb_typeof(grant_token) = 'object'
    ),
    grant_expires_at TIMESTAMPTZ,
    start_transaction_hash TEXT UNIQUE CHECK (
        start_transaction_hash IS NULL
        OR start_transaction_hash ~ '^0x[0-9a-f]{64}$'
    ),
    close_transaction_hash TEXT UNIQUE CHECK (
        close_transaction_hash IS NULL
        OR close_transaction_hash ~ '^0x[0-9a-f]{64}$'
    ),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE lifecycle_outbox (
    action_id UUID PRIMARY KEY,
    lease_id BIGINT NOT NULL REFERENCES leases(lease_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (
        kind IN ('start_access', 'refresh_grant', 'close_access', 'expire_provision', 'finalize')
    ),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (
        status IN ('queued', 'processing', 'submitted', 'completed', 'failed')
    ),
    document JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(document) = 'object'),
    raw_transaction TEXT CHECK (
        raw_transaction IS NULL OR raw_transaction ~ '^0x[0-9a-f]+$'
    ),
    transaction_hash TEXT UNIQUE CHECK (
        transaction_hash IS NULL OR transaction_hash ~ '^0x[0-9a-f]{64}$'
    ),
    transaction_nonce BIGINT CHECK (transaction_nonce IS NULL OR transaction_nonce >= 0),
    confirmed_block BIGINT CHECK (confirmed_block IS NULL OR confirmed_block >= 0),
    confirmed_block_hash TEXT CHECK (
        confirmed_block_hash IS NULL OR confirmed_block_hash ~ '^0x[0-9a-f]{64}$'
    ),
    attempts SMALLINT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_until TIMESTAMPTZ,
    last_error TEXT CHECK (last_error IS NULL OR char_length(last_error) <= 1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (lease_id, kind)
);

CREATE INDEX lifecycle_outbox_claim_idx
    ON lifecycle_outbox(status, available_at, created_at);

CREATE TABLE settlement_jobs (
    lease_id BIGINT PRIMARY KEY REFERENCES leases(lease_id) ON DELETE CASCADE,
    evidence JSONB NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
    proposal JSONB CHECK (proposal IS NULL OR jsonb_typeof(proposal) = 'object'),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (
        status IN ('queued', 'processing', 'submitted', 'proposed', 'disputed', 'finalized', 'failed')
    ),
    raw_transaction TEXT CHECK (
        raw_transaction IS NULL OR raw_transaction ~ '^0x[0-9a-f]+$'
    ),
    transaction_hash TEXT UNIQUE CHECK (
        transaction_hash IS NULL OR transaction_hash ~ '^0x[0-9a-f]{64}$'
    ),
    transaction_nonce BIGINT CHECK (transaction_nonce IS NULL OR transaction_nonce >= 0),
    confirmed_block BIGINT CHECK (confirmed_block IS NULL OR confirmed_block >= 0),
    confirmed_block_hash TEXT CHECK (
        confirmed_block_hash IS NULL OR confirmed_block_hash ~ '^0x[0-9a-f]{64}$'
    ),
    attempts SMALLINT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_until TIMESTAMPTZ,
    last_error TEXT CHECK (last_error IS NULL OR char_length(last_error) <= 1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX settlement_jobs_claim_idx
    ON settlement_jobs(status, available_at, created_at);

CREATE TABLE lease_telemetry (
    lease_id BIGINT NOT NULL REFERENCES leases(lease_id) ON DELETE CASCADE,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (lease_id, sequence)
);

CREATE INDEX lease_telemetry_window_idx
    ON lease_telemetry(lease_id, observed_at);

CREATE TABLE proof_receipts (
    receipt_id UUID PRIMARY KEY,
    lease_id BIGINT NOT NULL UNIQUE REFERENCES leases(lease_id),
    document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    transaction_hash TEXT NOT NULL UNIQUE CHECK (
        transaction_hash ~ '^0x[0-9a-f]{64}$'
    ),
    block_number BIGINT NOT NULL CHECK (block_number >= 0),
    block_hash TEXT NOT NULL CHECK (block_hash ~ '^0x[0-9a-f]{64}$'),
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE proof_digest_outbox (
    window_date DATE PRIMARY KEY,
    document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (
        status IN ('queued', 'processing', 'sent', 'failed')
    ),
    attempts SMALLINT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_until TIMESTAMPTZ,
    provider_post_id TEXT,
    last_error TEXT CHECK (last_error IS NULL OR char_length(last_error) <= 1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE chain_cursors (
    name TEXT PRIMARY KEY CHECK (char_length(name) BETWEEN 1 AND 64),
    next_block BIGINT NOT NULL CHECK (next_block >= 0),
    parent_block_hash TEXT NOT NULL CHECK (parent_block_hash ~ '^0x[0-9a-f]{64}$'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
