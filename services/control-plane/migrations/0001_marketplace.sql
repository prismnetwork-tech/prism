CREATE TABLE node_offers (
    node_id TEXT PRIMARY KEY,
    document JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE node_telemetry (
    node_id TEXT PRIMARY KEY REFERENCES node_offers(node_id) ON DELETE CASCADE,
    document JSONB NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE lease_quotes (
    quote_id UUID PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES node_offers(node_id),
    document JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX lease_quotes_expires_at_idx ON lease_quotes(expires_at);
CREATE INDEX lease_quotes_node_id_idx ON lease_quotes(node_id);
