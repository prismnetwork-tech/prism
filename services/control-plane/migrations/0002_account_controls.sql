CREATE TABLE accounts (
    subject TEXT PRIMARY KEY CHECK (char_length(subject) BETWEEN 1 AND 255),
    risk_hold BOOLEAN NOT NULL DEFAULT FALSE,
    suspended BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE account_sessions (
    session_id TEXT PRIMARY KEY CHECK (char_length(session_id) BETWEEN 1 AND 128),
    subject TEXT NOT NULL REFERENCES accounts(subject) ON DELETE CASCADE,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX account_sessions_subject_idx ON account_sessions(subject);

CREATE TABLE account_wallets (
    subject TEXT NOT NULL REFERENCES accounts(subject) ON DELETE CASCADE,
    wallet_address TEXT NOT NULL CHECK (wallet_address ~ '^0x[0-9a-f]{40}$'),
    verified_at TIMESTAMPTZ,
    PRIMARY KEY (subject, wallet_address)
);

CREATE TABLE identity_requests (
    request_id TEXT PRIMARY KEY CHECK (char_length(request_id) BETWEEN 1 AND 128),
    subject TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX identity_requests_expires_at_idx ON identity_requests(expires_at);

CREATE TABLE node_tunnels (
    node_id TEXT PRIMARY KEY REFERENCES node_offers(node_id) ON DELETE CASCADE,
    connection_id TEXT NOT NULL CHECK (char_length(connection_id) BETWEEN 1 AND 128),
    observed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX node_tunnels_observed_at_idx ON node_tunnels(observed_at);

ALTER TABLE node_offers
    ADD CONSTRAINT node_offers_document_object CHECK (jsonb_typeof(document) = 'object');

ALTER TABLE node_telemetry
    ADD CONSTRAINT node_telemetry_document_object CHECK (jsonb_typeof(document) = 'object');

ALTER TABLE lease_quotes
    ADD CONSTRAINT lease_quotes_document_object CHECK (jsonb_typeof(document) = 'object');
