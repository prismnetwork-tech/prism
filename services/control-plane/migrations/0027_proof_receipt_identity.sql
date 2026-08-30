ALTER TABLE leases
    ADD CONSTRAINT leases_proof_identity_key
        UNIQUE (lease_id, escrow_address, chain_lease_id);

ALTER TABLE proof_receipts
    ADD COLUMN escrow_address TEXT,
    ADD COLUMN chain_lease_id BIGINT,
    ADD COLUMN publication_state TEXT NOT NULL DEFAULT 'pending',
    ADD COLUMN quarantine_reason TEXT;

UPDATE proof_receipts AS receipt
SET escrow_address = lease.escrow_address,
    chain_lease_id = lease.chain_lease_id,
    publication_state = CASE
        WHEN receipt.document->>'lease_id' IS DISTINCT FROM lease.chain_lease_id::text
            THEN 'quarantined'
        WHEN receipt.document ? 'escrow_address'
         AND lower(receipt.document->>'escrow_address') IS DISTINCT FROM lease.escrow_address
            THEN 'quarantined'
        WHEN receipt.document ? 'chain_lease_id'
         AND receipt.document->>'chain_lease_id' IS DISTINCT FROM lease.chain_lease_id::text
            THEN 'quarantined'
        WHEN receipt.published_at IS NOT NULL THEN 'published'
        ELSE 'pending'
    END,
    quarantine_reason = CASE
        WHEN receipt.document->>'lease_id' IS DISTINCT FROM lease.chain_lease_id::text
            THEN 'legacy_chain_identity_mismatch'
        WHEN receipt.document ? 'escrow_address'
         AND lower(receipt.document->>'escrow_address') IS DISTINCT FROM lease.escrow_address
            THEN 'receipt_escrow_identity_mismatch'
        WHEN receipt.document ? 'chain_lease_id'
         AND receipt.document->>'chain_lease_id' IS DISTINCT FROM lease.chain_lease_id::text
            THEN 'receipt_chain_identity_mismatch'
        ELSE NULL
    END
FROM leases AS lease
WHERE lease.lease_id = receipt.lease_id;

UPDATE proof_receipts
SET document = document || jsonb_build_object(
        'escrow_address', escrow_address,
        'chain_lease_id', chain_lease_id::text
    )
WHERE publication_state <> 'quarantined';

UPDATE proof_receipts
SET published_at = NULL
WHERE publication_state = 'quarantined';

ALTER TABLE proof_receipts
    ALTER COLUMN escrow_address SET NOT NULL,
    ALTER COLUMN chain_lease_id SET NOT NULL,
    ADD CONSTRAINT proof_receipts_escrow_address_check
        CHECK (escrow_address ~ '^0x[0-9a-f]{40}$'),
    ADD CONSTRAINT proof_receipts_chain_lease_id_check
        CHECK (chain_lease_id > 0),
    ADD CONSTRAINT proof_receipts_publication_state_check
        CHECK (publication_state IN ('pending', 'published', 'quarantined')),
    ADD CONSTRAINT proof_receipts_quarantine_reason_check
        CHECK (
            (publication_state = 'quarantined') = (quarantine_reason IS NOT NULL)
            AND (quarantine_reason IS NULL OR char_length(quarantine_reason) BETWEEN 1 AND 128)
        ),
    ADD CONSTRAINT proof_receipts_published_at_check
        CHECK ((publication_state = 'published') = (published_at IS NOT NULL)),
    ADD CONSTRAINT proof_receipts_document_identity_check
        CHECK (
            publication_state = 'quarantined'
            OR (
                document->>'escrow_address' IS NOT DISTINCT FROM escrow_address
                AND document->>'chain_lease_id' IS NOT DISTINCT FROM chain_lease_id::text
                AND document->>'lease_id' IS NOT DISTINCT FROM chain_lease_id::text
            )
        ),
    ADD CONSTRAINT proof_receipts_lease_identity_fkey
        FOREIGN KEY (lease_id, escrow_address, chain_lease_id)
        REFERENCES leases (lease_id, escrow_address, chain_lease_id);

CREATE INDEX proof_receipts_publication_claim_idx
    ON proof_receipts (publication_state, block_number, receipt_id);

CREATE FUNCTION enforce_proof_receipt_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'proof receipt evidence cannot be deleted; quarantine it instead'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.publication_state <> 'pending'
           OR NEW.published_at IS NOT NULL
           OR NEW.quarantine_reason IS NOT NULL THEN
            RAISE EXCEPTION 'new proof receipts must begin pending'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.receipt_id IS DISTINCT FROM OLD.receipt_id
       OR NEW.lease_id IS DISTINCT FROM OLD.lease_id
       OR NEW.escrow_address IS DISTINCT FROM OLD.escrow_address
       OR NEW.chain_lease_id IS DISTINCT FROM OLD.chain_lease_id
       OR NEW.document IS DISTINCT FROM OLD.document
       OR NEW.transaction_hash IS DISTINCT FROM OLD.transaction_hash
       OR NEW.block_number IS DISTINCT FROM OLD.block_number
       OR NEW.block_hash IS DISTINCT FROM OLD.block_hash
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'proof receipt identity and evidence are immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.publication_state = OLD.publication_state
       AND NEW.published_at IS NOT DISTINCT FROM OLD.published_at
       AND NEW.quarantine_reason IS NOT DISTINCT FROM OLD.quarantine_reason THEN
        RETURN NEW;
    END IF;

    IF OLD.publication_state = 'pending'
       AND NEW.publication_state = 'published'
       AND OLD.published_at IS NULL
       AND NEW.published_at IS NOT NULL
       AND NEW.quarantine_reason IS NULL THEN
        RETURN NEW;
    END IF;

    IF OLD.publication_state IN ('pending', 'published')
       AND NEW.publication_state = 'quarantined'
       AND NEW.published_at IS NULL
       AND NEW.quarantine_reason IS NOT NULL THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid proof receipt publication transition: % to %',
        OLD.publication_state, NEW.publication_state
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER proof_receipts_lifecycle_guard
    BEFORE INSERT OR UPDATE OR DELETE ON proof_receipts
    FOR EACH ROW
    EXECUTE FUNCTION enforce_proof_receipt_lifecycle();
