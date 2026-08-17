-- Guest attestation, per lease. 0017 records which physical GPU answered for a
-- node; it says nothing about what software booted. A node-level SEV-SNP report
-- would say nothing either, because under SNP a report is taken by a guest of
-- itself: an operator could boot the measured image once a day, keep the
-- verdict, and serve renters from a bare container beside it, and nothing in
-- that report would contradict it. What is recorded here is a report the guest
-- serving one lease took of itself, bound to that lease.

-- One live challenge per lease, keyed by the lease so a second guest on the
-- same node cannot answer with a nonce issued for the first. consumed_at is
-- what makes a second use of the same nonce fail rather than re-verify.
CREATE TABLE lease_attestation_challenges (
    lease_id BIGINT PRIMARY KEY,
    challenge_id UUID NOT NULL UNIQUE,
    node_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX lease_attestation_challenges_expires_idx
    ON lease_attestation_challenges(expires_at);

-- No foreign key to leases, for the reason 0017 already gives: a verdict is
-- what we would produce in a dispute, so it has to outlive the row that earned
-- it.
CREATE TABLE lease_attestation_verdicts (
    lease_id BIGINT PRIMARY KEY,
    node_id TEXT NOT NULL,
    document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    -- The launch measurement over the initial guest image, its page layout and
    -- its per-vCPU VMSA. It means something only against a reference value
    -- computed from published inputs, never against one read off the machine
    -- being attested.
    measurement TEXT NOT NULL,
    chip_id_digest TEXT NOT NULL,
    -- The SSH host key the guest generated for this lease, so the renter can
    -- pin the box their session actually terminates on.
    channel_key_fingerprint TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX lease_attestation_verdicts_node_idx
    ON lease_attestation_verdicts(node_id, verified_at DESC);

CREATE INDEX lease_attestation_verdicts_expires_idx
    ON lease_attestation_verdicts(expires_at);

-- One physical processor stands behind one node identity, which is the bound
-- the unique device index in 0017 puts on the GPU. It does not stop a host
-- relaying a report from a machine it controls elsewhere; it stops the same
-- chip earning a class under two identities at once.
--
-- The node index is unique for the other direction: once a node has attested on
-- a processor, every later report has to come from that same one. An operator
-- who moves the board gets a conflict rather than a second earned class.
CREATE TABLE node_snp_chips (
    chip_id_digest TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    first_attested_at TIMESTAMPTZ NOT NULL,
    last_attested_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX node_snp_chips_node_idx ON node_snp_chips(node_id);
