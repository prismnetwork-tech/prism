-- The SSH host key a self-hosted workspace answers on, as its node reported it
-- on the signed report that opened access. Attested leases get the same
-- fingerprint out of a verified guest report instead; this column is what the
-- classes that produce no report have, and it is served marked as the node's
-- word so the two are never read as the same claim.
ALTER TABLE lease_lifecycle
    ADD COLUMN channel_key_fingerprint TEXT CHECK (
        channel_key_fingerprint IS NULL
        OR channel_key_fingerprint ~ '^SHA256:[A-Za-z0-9+/]{43}$'
    );
