-- Device attestation. `Isolated` used to be whatever a node said about itself
-- in its heartbeat. These two tables turn it into a grant this service issues
-- after checking a vendor-signed report against a nonce it chose.

-- One live challenge per node. The nonce is ours, so a report collected before
-- we asked for it cannot be replayed, and consumed_at makes a second use of the
-- same challenge fail rather than re-verify.
CREATE TABLE node_attestation_challenges (
    challenge_id UUID PRIMARY KEY,
    node_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX node_attestation_challenges_node_idx
    ON node_attestation_challenges(node_id, expires_at);

-- No foreign key to node_offers on purpose. node_telemetry cascades on delete
-- and takes its history with it; a verdict is what we would produce in a
-- dispute, so it has to outlive the node that earned it.
CREATE TABLE node_attestation_verdicts (
    node_id TEXT PRIMARY KEY,
    document JSONB NOT NULL,
    -- The attested device, as the vendor named it. Unique across the table
    -- because one physical GPU must not stand behind two node identities: an
    -- operator who moves a card gets a conflict, not a second earned class.
    device_identity TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX node_attestation_verdicts_device_idx
    ON node_attestation_verdicts(device_identity);

CREATE INDEX node_attestation_verdicts_expires_idx
    ON node_attestation_verdicts(expires_at);
