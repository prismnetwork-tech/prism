CREATE TABLE node_certificates (
    certificate_id UUID PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES node_offers(node_id) ON DELETE CASCADE,
    fingerprint_sha256 TEXT NOT NULL UNIQUE
        CHECK (fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
    csr_sha256 TEXT NOT NULL CHECK (csr_sha256 ~ '^[0-9a-f]{64}$'),
    status TEXT NOT NULL CHECK (status IN ('active', 'superseded', 'revoked')),
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    CHECK (not_after > not_before)
);

CREATE UNIQUE INDEX node_certificates_active_idx
    ON node_certificates(node_id) WHERE status = 'active';

CREATE TABLE node_certificate_requests (
    request_id UUID PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES node_offers(node_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE wallet_link_challenges (
    challenge_id UUID PRIMARY KEY,
    subject TEXT NOT NULL REFERENCES accounts(subject) ON DELETE CASCADE,
    wallet_address TEXT NOT NULL CHECK (wallet_address ~ '^0x[0-9a-f]{40}$'),
    message TEXT NOT NULL CHECK (char_length(message) BETWEEN 1 AND 1024),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX wallet_link_challenges_expiry_idx
    ON wallet_link_challenges(expires_at);

CREATE TABLE operator_accounts (
    subject TEXT PRIMARY KEY CHECK (char_length(subject) BETWEEN 1 AND 255),
    role TEXT NOT NULL CHECK (role IN ('operator', 'administrator')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE node_controls (
    node_id TEXT PRIMARY KEY REFERENCES node_offers(node_id) ON DELETE CASCADE,
    suspended BOOLEAN NOT NULL DEFAULT FALSE,
    reason TEXT CHECK (reason IS NULL OR char_length(reason) <= 512),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE operator_audit_events (
    event_id UUID PRIMARY KEY,
    action_id UUID NOT NULL UNIQUE,
    actor_subject TEXT NOT NULL REFERENCES operator_accounts(subject),
    action TEXT NOT NULL CHECK (
        action IN (
            'account_risk_hold',
            'account_risk_release',
            'account_suspend',
            'account_resume',
            'node_suspend',
            'node_resume',
            'node_certificate_revoke',
            'slash_evidence_record'
        )
    ),
    target_type TEXT NOT NULL CHECK (target_type IN ('account', 'node')),
    target_id TEXT NOT NULL CHECK (char_length(target_id) BETWEEN 1 AND 255),
    reason TEXT NOT NULL CHECK (char_length(reason) BETWEEN 8 AND 512),
    evidence_hash TEXT CHECK (
        evidence_hash IS NULL OR evidence_hash ~ '^0x[0-9a-f]{64}$'
    ),
    before_state JSONB NOT NULL CHECK (jsonb_typeof(before_state) = 'object'),
    after_state JSONB NOT NULL CHECK (jsonb_typeof(after_state) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX operator_audit_events_created_idx
    ON operator_audit_events(created_at DESC);

CREATE FUNCTION reject_operator_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'operator audit events are append-only';
END;
$$;

CREATE TRIGGER operator_audit_events_append_only
BEFORE UPDATE OR DELETE ON operator_audit_events
FOR EACH ROW EXECUTE FUNCTION reject_operator_audit_mutation();
