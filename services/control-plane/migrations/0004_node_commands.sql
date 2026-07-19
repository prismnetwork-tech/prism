CREATE TABLE node_commands (
    command_id UUID PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES node_offers(node_id),
    lease_id BIGINT NOT NULL REFERENCES leases(lease_id),
    document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    status TEXT NOT NULL CHECK (status IN ('queued', 'leased', 'ready', 'completed', 'failed')),
    attempts SMALLINT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 10),
    lease_until TIMESTAMPTZ,
    last_error TEXT CHECK (last_error IS NULL OR char_length(last_error) <= 512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (lease_id)
);

CREATE INDEX node_commands_claim_idx
    ON node_commands(node_id, status, created_at);

CREATE TABLE node_command_requests (
    request_id UUID PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES node_offers(node_id),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX node_command_requests_expiry_idx
    ON node_command_requests(expires_at);
