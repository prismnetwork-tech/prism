-- A lease id is a counter inside one escrow deployment, so it identifies a lease
-- only together with the escrow that issued it. The escrow was replaced and the
-- new one restarted its counter at 1, which collided with the rows already here.
-- Every confirm against a colliding id failed after the renter had already paid,
-- because the funding sits on chain before the control plane ever sees it.
--
-- The fix separates the two identities. `lease_id` stays the internal key, so
-- every dependent table and foreign key is untouched, and it is now allocated
-- from a sequence that starts past the historical rows. `chain_lease_id` plus
-- `escrow_address` carry what the chain actually issued, unique per deployment.
-- Existing rows keep both equal, so nothing about their history changes.

ALTER TABLE leases
    ADD COLUMN escrow_address TEXT,
    ADD COLUMN chain_lease_id BIGINT;

UPDATE leases
SET escrow_address = '0x71df0ef3bc81022cb3bec0b1a05f52f12bafcded',
    chain_lease_id = lease_id
WHERE escrow_address IS NULL;

ALTER TABLE leases
    ALTER COLUMN escrow_address SET NOT NULL,
    ALTER COLUMN chain_lease_id SET NOT NULL,
    ADD CONSTRAINT leases_escrow_address_check
        CHECK (escrow_address ~ '^0x[0-9a-f]{40}$'),
    ADD CONSTRAINT leases_chain_lease_id_check CHECK (chain_lease_id > 0),
    ADD CONSTRAINT leases_chain_identity_key UNIQUE (escrow_address, chain_lease_id);

-- Start past every id the previous escrow ever handed out, so an internal id is
-- never confused with a chain id from a superseded deployment.
CREATE SEQUENCE leases_internal_id_seq AS BIGINT OWNED BY leases.lease_id;
SELECT setval('leases_internal_id_seq', GREATEST((SELECT COALESCE(MAX(lease_id), 0) FROM leases), 1000));
ALTER TABLE leases ALTER COLUMN lease_id SET DEFAULT nextval('leases_internal_id_seq');
