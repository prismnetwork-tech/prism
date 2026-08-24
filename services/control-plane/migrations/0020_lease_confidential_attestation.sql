-- Confidential lease attestation. 0018 records the SEV-SNP guest half of a
-- lease. Confidential silicon comes in two more pieces: a TDX quote is the
-- guest half on Intel, and an NVIDIA CC report is the GPU half on either. Each
-- is kept in its own table rather than folded into the SEV-SNP one, because a
-- TD's evidence is an image measurement and a runtime-register binding, and a
-- GPU's is a device identity and a measurement digest, neither of which fits
-- the chip and VMSA columns 0018 carries.

-- The TDX guest half, per lease. The mirror of lease_attestation_verdicts: a
-- quote the guest took of itself, bound to one lease through the quote's report
-- data, earning the guest rung on Intel silicon. No foreign key to leases, for
-- the reason 0017 gives: a verdict is what we would produce in a dispute, so it
-- has to outlive the row that earned it.
CREATE TABLE lease_tdx_guest_verdicts (
    lease_id BIGINT PRIMARY KEY,
    node_id TEXT NOT NULL,
    document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    -- The instance identity the TD extended into RTMR3, unique per deployment.
    device_identity TEXT NOT NULL,
    -- The compose file the event log bound the TD to.
    compose_hash TEXT NOT NULL,
    measurement_digest TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX lease_tdx_guest_verdicts_node_idx
    ON lease_tdx_guest_verdicts(node_id, verified_at DESC);

CREATE INDEX lease_tdx_guest_verdicts_expires_idx
    ON lease_tdx_guest_verdicts(expires_at);

-- The GPU confidential-computing half, per lease. Encrypted VRAM behind an
-- unmeasured guest is worth nothing on its own, so this rides its own axis and
-- the class only reaches Confidential when a guest verdict stands beside it.
CREATE TABLE lease_gpu_cc_verdicts (
    lease_id BIGINT PRIMARY KEY,
    node_id TEXT NOT NULL,
    document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    -- The device as the verifier read it off the leaf certificate: its common
    -- name and the firmware identity the report is bound to.
    device_identity TEXT NOT NULL,
    measurement_digest TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX lease_gpu_cc_verdicts_node_idx
    ON lease_gpu_cc_verdicts(node_id, verified_at DESC);

CREATE INDEX lease_gpu_cc_verdicts_expires_idx
    ON lease_gpu_cc_verdicts(expires_at);

-- The GPU-CC challenge, keyed by lease. Separate from the guest challenge in
-- 0018 because the card signs a report of its own: one live nonce at a time,
-- and consumed_at is what makes a second use of the same nonce fail rather than
-- re-verify.
CREATE TABLE lease_gpu_cc_challenges (
    lease_id BIGINT PRIMARY KEY,
    challenge_id UUID NOT NULL UNIQUE,
    node_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX lease_gpu_cc_challenges_expires_idx
    ON lease_gpu_cc_challenges(expires_at);
