DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM settlement_jobs AS job
        WHERE (
            num_nonnulls(
                job.proposal,
                job.raw_transaction,
                job.transaction_hash,
                job.transaction_nonce
            ) BETWEEN 1 AND 3
            AND NOT (
                job.proposal IS NOT NULL
                AND job.raw_transaction IS NULL
                AND job.transaction_hash IS NULL
                AND job.transaction_nonce IS NULL
                AND job.confirmed_block IS NULL
                AND job.confirmed_block_hash IS NULL
                AND job.status IN ('queued', 'processing', 'failed')
                AND NOT job.proposal ?| ARRAY[
                    'raw_transaction', 'transaction_hash', 'submitted'
                ]
            )
        ) OR (
            num_nonnulls(job.confirmed_block, job.confirmed_block_hash) > 0
            AND (
                num_nonnulls(
                    job.proposal,
                    job.raw_transaction,
                    job.transaction_hash,
                    job.transaction_nonce
                ) <> 4
                OR num_nonnulls(job.confirmed_block, job.confirmed_block_hash) <> 2
            )
        ) OR (
            job.status IN ('submitted', 'proposed', 'disputed', 'finalized')
            AND (
                num_nonnulls(
                    job.proposal,
                    job.raw_transaction,
                    job.transaction_hash,
                    job.transaction_nonce
                ) <> 4
                OR (
                    job.status IN ('proposed', 'disputed', 'finalized')
                    AND num_nonnulls(
                        job.confirmed_block,
                        job.confirmed_block_hash
                    ) <> 2
                )
            )
        )
    ) THEN
        RAISE EXCEPTION USING
            MESSAGE = 'migration 0026 found incomplete settlement state, transaction, or confirmation evidence',
            HINT = 'Preserve and resolve the cursor before retrying; no hardened triggers were installed.';
    END IF;
END;
$$;

ALTER TABLE settlement_jobs
    ADD COLUMN claim_generation BIGINT NOT NULL DEFAULT 0 CHECK (claim_generation >= 0);

CREATE TABLE settlement_legacy_partial_cursors (
    lease_id BIGINT PRIMARY KEY,
    proposal JSONB,
    raw_transaction TEXT,
    transaction_hash TEXT,
    transaction_nonce BIGINT,
    confirmed_block BIGINT,
    confirmed_block_hash TEXT,
    job_status TEXT NOT NULL,
    job_attempts SMALLINT NOT NULL,
    job_created_at TIMESTAMPTZ NOT NULL,
    job_updated_at TIMESTAMPTZ NOT NULL,
    quarantine_reason TEXT NOT NULL CHECK (
        quarantine_reason = 'provably_unsent_partial_cursor'
    ),
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (num_nonnulls(proposal, raw_transaction, transaction_hash, transaction_nonce)
           BETWEEN 1 AND 3)
);

COMMENT ON TABLE settlement_legacy_partial_cursors IS
    'Immutable evidence from provably unsent, proposal-only settlement cursors repaired by migration 0026';

CREATE FUNCTION protect_settlement_legacy_partial_cursor() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'legacy partial settlement cursor evidence is append-only';
END;
$$;

CREATE TRIGGER settlement_legacy_partial_cursors_append_only
BEFORE UPDATE OR DELETE ON settlement_legacy_partial_cursors
FOR EACH ROW EXECUTE FUNCTION protect_settlement_legacy_partial_cursor();

INSERT INTO settlement_legacy_partial_cursors (
    lease_id,
    proposal,
    raw_transaction,
    transaction_hash,
    transaction_nonce,
    confirmed_block,
    confirmed_block_hash,
    job_status,
    job_attempts,
    job_created_at,
    job_updated_at,
    quarantine_reason
)
SELECT
    job.lease_id,
    job.proposal,
    job.raw_transaction,
    job.transaction_hash,
    job.transaction_nonce,
    job.confirmed_block,
    job.confirmed_block_hash,
    job.status,
    job.attempts,
    job.created_at,
    job.updated_at,
    'provably_unsent_partial_cursor'
FROM settlement_jobs AS job
WHERE job.proposal IS NOT NULL
  AND job.raw_transaction IS NULL
  AND job.transaction_hash IS NULL
  AND job.transaction_nonce IS NULL
  AND job.confirmed_block IS NULL
  AND job.confirmed_block_hash IS NULL
  AND job.status IN ('queued', 'processing', 'failed')
  AND NOT job.proposal ?| ARRAY[
      'raw_transaction', 'transaction_hash', 'submitted'
  ];

UPDATE settlement_jobs AS job
SET proposal = NULL,
    raw_transaction = NULL,
    transaction_hash = NULL,
    transaction_nonce = NULL,
    status = CASE WHEN job.status IN ('queued', 'processing') THEN 'queued' ELSE job.status END,
    attempts = CASE WHEN job.status IN ('queued', 'processing') THEN 0 ELSE job.attempts END,
    available_at = CASE
        WHEN job.status IN ('queued', 'processing') THEN NOW()
        ELSE job.available_at
    END,
    lease_until = CASE
        WHEN job.status IN ('queued', 'processing') THEN NULL
        ELSE job.lease_until
    END,
    last_error = CASE
        WHEN job.status IN ('queued', 'processing')
            THEN 'legacy proposal-only settlement cursor quarantined during migration 0026'
        ELSE job.last_error
    END,
    updated_at = NOW()
FROM settlement_legacy_partial_cursors AS legacy
WHERE legacy.lease_id = job.lease_id;

CREATE TABLE settlement_transaction_attempts (
    transaction_hash TEXT PRIMARY KEY CHECK (
        transaction_hash ~ '^0x[0-9a-f]{64}$'
    ),
    lease_id BIGINT NOT NULL REFERENCES settlement_jobs(lease_id),
    claim_generation BIGINT NOT NULL CHECK (claim_generation >= 0),
    escrow_address TEXT NOT NULL CHECK (
        escrow_address ~ '^0x[0-9a-f]{40}$'
    ),
    chain_lease_id BIGINT NOT NULL CHECK (chain_lease_id > 0),
    transaction_nonce BIGINT NOT NULL CHECK (transaction_nonce >= 0),
    signer_address TEXT CHECK (
        signer_address IS NULL OR signer_address ~ '^0x[0-9a-f]{40}$'
    ),
    nonce_reservation_state TEXT NOT NULL DEFAULT 'reserved' CHECK (
        nonce_reservation_state IN ('pending', 'reserved', 'noncanonical', 'conflict')
    ),
    nonce_reservation_reason TEXT CHECK (
        nonce_reservation_reason IS NULL
        OR nonce_reservation_reason IN (
            'confirmed_historical_nonce_owner',
            'historical_nonce_collision_without_confirmed_owner',
            'historical_nonce_collision_with_multiple_confirmed_owners'
        )
    ),
    generation_binding_state TEXT NOT NULL DEFAULT 'verified' CHECK (
        generation_binding_state IN ('pending', 'verified', 'normalized', 'quarantined')
    ),
    generation_binding_reason TEXT CHECK (
        generation_binding_reason IS NULL
        OR generation_binding_reason IN (
            'legacy_receipt_identity_normalized',
            'invalid_signed_transaction',
            'invalid_stored_submission',
            'job_attempt_proposal_mismatch',
            'transaction_hash_mismatch',
            'submission_transaction_mismatch',
            'signed_chain_mismatch',
            'signed_escrow_mismatch',
            'signed_nonce_mismatch',
            'proposal_lease_mismatch',
            'receipt_identity_mismatch',
            'receipt_hash_mismatch',
            'calldata_mismatch',
            'attestation_signature_mismatch'
        )
    ),
    raw_transaction TEXT NOT NULL CHECK (
        raw_transaction ~ '^0x[0-9a-f]+$'
    ),
    proposal JSONB NOT NULL CHECK (jsonb_typeof(proposal) = 'object'),
    status TEXT NOT NULL CHECK (
        status IN ('prepared', 'submitted', 'superseded', 'confirmed', 'reverted')
    ),
    submission_count SMALLINT NOT NULL DEFAULT 0 CHECK (
        submission_count BETWEEN 0 AND 100
    ),
    prepared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    submitted_at TIMESTAMPTZ,
    superseded_at TIMESTAMPTZ,
    confirmed_at TIMESTAMPTZ,
    reverted_at TIMESTAMPTZ,
    confirmed_block BIGINT CHECK (confirmed_block IS NULL OR confirmed_block >= 0),
    confirmed_block_hash TEXT CHECK (
        confirmed_block_hash IS NULL
        OR confirmed_block_hash ~ '^0x[0-9a-f]{64}$'
    ),
    CHECK ((confirmed_block IS NULL) = (confirmed_block_hash IS NULL)),
    CHECK (
        (nonce_reservation_state IN ('pending', 'reserved')
         AND nonce_reservation_reason IS NULL)
        OR (nonce_reservation_state = 'noncanonical'
            AND nonce_reservation_reason = 'confirmed_historical_nonce_owner')
        OR (nonce_reservation_state = 'conflict'
            AND nonce_reservation_reason IN (
                'historical_nonce_collision_without_confirmed_owner',
                'historical_nonce_collision_with_multiple_confirmed_owners'
            ))
    ),
    CHECK (
        (generation_binding_state IN ('pending', 'verified')
         AND generation_binding_reason IS NULL)
        OR (generation_binding_state = 'normalized'
            AND generation_binding_reason = 'legacy_receipt_identity_normalized')
        OR (generation_binding_state = 'quarantined'
            AND generation_binding_reason IS NOT NULL
            AND generation_binding_reason <> 'legacy_receipt_identity_normalized')
    ),
    CHECK (
        status <> 'submitted'
        OR (submitted_at IS NOT NULL AND submission_count > 0)
    ),
    CHECK (status <> 'superseded' OR superseded_at IS NOT NULL),
    CHECK (
        status <> 'confirmed'
        OR (
            confirmed_at IS NOT NULL
            AND confirmed_block IS NOT NULL
            AND confirmed_block_hash IS NOT NULL
        )
    ),
    CHECK (status <> 'reverted' OR reverted_at IS NOT NULL)
);

COMMENT ON COLUMN settlement_transaction_attempts.status IS
    'reverted is terminal only after the configured confirmation threshold; shallow reverted receipts remain submitted and can resolve to confirmed after a reorg';

COMMENT ON COLUMN settlement_transaction_attempts.nonce_reservation_state IS
    'pending is migration-only; reserved attempts may reuse their lease reservation, noncanonical attempts lost a cross-lease collision to the uniquely confirmed lease, and conflict resolves only after immutable confirmation evidence identifies one lease owner';

COMMENT ON COLUMN settlement_transaction_attempts.generation_binding_state IS
    'pending is migration-only; verified and normalized bytes passed exact chain, signer, destination, nonce, calldata, proposal and receipt checks; quarantined bytes are retained but can never be adopted or broadcast';

CREATE INDEX settlement_transaction_attempts_lease_idx
    ON settlement_transaction_attempts(lease_id, prepared_at DESC);

CREATE INDEX settlement_transaction_attempts_status_idx
    ON settlement_transaction_attempts(status, prepared_at);

CREATE INDEX settlement_transaction_attempts_signer_nonce_idx
    ON settlement_transaction_attempts(signer_address, transaction_nonce)
    WHERE signer_address IS NOT NULL;

CREATE TABLE settlement_signer_nonce_reservations (
    signer_address TEXT NOT NULL CHECK (
        signer_address ~ '^0x[0-9a-f]{40}$'
    ),
    transaction_nonce BIGINT NOT NULL CHECK (transaction_nonce >= 0),
    lease_id BIGINT NOT NULL REFERENCES settlement_jobs(lease_id),
    reserved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    corrected_from_lease_id BIGINT REFERENCES settlement_jobs(lease_id),
    corrected_at TIMESTAMPTZ,
    correction_reason TEXT CHECK (
        correction_reason IS NULL
        OR correction_reason = 'confirmed_historical_nonce_owner'
    ),
    CHECK (
        (corrected_from_lease_id IS NULL
         AND corrected_at IS NULL
         AND correction_reason IS NULL)
        OR (corrected_from_lease_id IS NOT NULL
            AND corrected_from_lease_id <> lease_id
            AND corrected_at IS NOT NULL
            AND correction_reason = 'confirmed_historical_nonce_owner')
    ),
    PRIMARY KEY (signer_address, transaction_nonce)
);

CREATE INDEX settlement_signer_nonce_reservations_lease_idx
    ON settlement_signer_nonce_reservations(lease_id, reserved_at);

CREATE FUNCTION protect_settlement_signer_nonce_reservation() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'settlement signer nonce reservations are append-only';
    END IF;
    IF NEW.signer_address IS DISTINCT FROM OLD.signer_address
       OR NEW.transaction_nonce IS DISTINCT FROM OLD.transaction_nonce
       OR NEW.reserved_at IS DISTINCT FROM OLD.reserved_at THEN
        RAISE EXCEPTION 'settlement signer nonce reservation is immutable';
    END IF;
    IF NEW.lease_id IS DISTINCT FROM OLD.lease_id THEN
        IF OLD.corrected_from_lease_id IS NOT NULL
           OR NEW.corrected_from_lease_id IS DISTINCT FROM OLD.lease_id
           OR NEW.corrected_at IS NULL
           OR NEW.correction_reason <> 'confirmed_historical_nonce_owner' THEN
            RAISE EXCEPTION 'settlement signer nonce reservation correction is invalid';
        END IF;
    ELSIF NEW.corrected_from_lease_id IS DISTINCT FROM OLD.corrected_from_lease_id
          OR NEW.corrected_at IS DISTINCT FROM OLD.corrected_at
          OR NEW.correction_reason IS DISTINCT FROM OLD.correction_reason THEN
        RAISE EXCEPTION 'settlement signer nonce reservation correction is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER settlement_signer_nonce_reservations_append_only
BEFORE UPDATE OR DELETE ON settlement_signer_nonce_reservations
FOR EACH ROW EXECUTE FUNCTION protect_settlement_signer_nonce_reservation();

INSERT INTO settlement_transaction_attempts (
    transaction_hash,
    lease_id,
    claim_generation,
    escrow_address,
    chain_lease_id,
    transaction_nonce,
    nonce_reservation_state,
    generation_binding_state,
    raw_transaction,
    proposal,
    status,
    submission_count,
    prepared_at,
    submitted_at,
    confirmed_at,
    confirmed_block,
    confirmed_block_hash
)
SELECT
    job.transaction_hash,
    job.lease_id,
    job.claim_generation,
    lease.escrow_address,
    lease.chain_lease_id,
    job.transaction_nonce,
    'pending',
    'pending',
    job.raw_transaction,
    job.proposal,
    CASE WHEN job.confirmed_block IS NULL THEN 'prepared' ELSE 'confirmed' END,
    CASE WHEN job.confirmed_block IS NULL THEN 0 ELSE 1 END,
    job.created_at,
    CASE WHEN job.confirmed_block IS NULL THEN NULL ELSE job.updated_at END,
    CASE WHEN job.confirmed_block IS NULL THEN NULL ELSE job.updated_at END,
    job.confirmed_block,
    job.confirmed_block_hash
FROM settlement_jobs AS job
JOIN leases AS lease ON lease.lease_id = job.lease_id
WHERE job.raw_transaction IS NOT NULL
  AND job.transaction_hash IS NOT NULL
  AND job.transaction_nonce IS NOT NULL
  AND job.proposal IS NOT NULL;

CREATE FUNCTION protect_settlement_transaction_attempt() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    normalized_proposal JSONB;
    confirmed_owner BIGINT;
    confirmed_owner_count BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.signer_address IS NULL
           OR NEW.nonce_reservation_state <> 'reserved'
           OR NEW.generation_binding_state <> 'verified' THEN
            RAISE EXCEPTION 'verified settlement transaction reservation is required';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'settlement transaction attempts are append-only';
    END IF;
    IF NEW.transaction_hash IS DISTINCT FROM OLD.transaction_hash
       OR NEW.lease_id IS DISTINCT FROM OLD.lease_id
       OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation
       OR NEW.escrow_address IS DISTINCT FROM OLD.escrow_address
       OR NEW.chain_lease_id IS DISTINCT FROM OLD.chain_lease_id
       OR NEW.transaction_nonce IS DISTINCT FROM OLD.transaction_nonce
       OR NEW.raw_transaction IS DISTINCT FROM OLD.raw_transaction
       OR NEW.prepared_at IS DISTINCT FROM OLD.prepared_at THEN
        RAISE EXCEPTION 'settlement transaction attempt evidence is immutable';
    END IF;
    IF NEW.proposal IS DISTINCT FROM OLD.proposal THEN
        normalized_proposal := jsonb_set(
            jsonb_set(
                OLD.proposal,
                '{proposal,receipt,escrow_address}',
                to_jsonb(OLD.escrow_address),
                TRUE
            ),
            '{proposal,receipt,chain_lease_id}',
            to_jsonb(OLD.chain_lease_id::TEXT),
            TRUE
        );
        IF OLD.generation_binding_state <> 'pending'
           OR NEW.generation_binding_state <> 'normalized'
           OR NEW.proposal IS DISTINCT FROM normalized_proposal THEN
            RAISE EXCEPTION 'settlement transaction attempt evidence is immutable';
        END IF;
    END IF;
    IF OLD.signer_address IS NOT NULL
       AND NEW.signer_address IS DISTINCT FROM OLD.signer_address THEN
        RAISE EXCEPTION 'settlement transaction signer is immutable';
    END IF;
    IF OLD.signer_address IS NULL AND NEW.signer_address IS NULL
       AND NOT (
           NEW.generation_binding_state = 'quarantined'
           AND NEW.generation_binding_reason = 'invalid_signed_transaction'
       ) THEN
        RAISE EXCEPTION 'settlement transaction signer was not backfilled';
    END IF;
    IF OLD.nonce_reservation_state = 'conflict'
       AND (
           NEW.nonce_reservation_state IS DISTINCT FROM OLD.nonce_reservation_state
           OR NEW.nonce_reservation_reason IS DISTINCT FROM OLD.nonce_reservation_reason
       ) THEN
        IF NEW.nonce_reservation_state NOT IN ('reserved', 'noncanonical') THEN
            RAISE EXCEPTION 'settlement transaction nonce reservation state is immutable';
        END IF;
        SELECT COUNT(DISTINCT attempt.lease_id), MIN(attempt.lease_id)
        INTO confirmed_owner_count, confirmed_owner
        FROM settlement_transaction_attempts AS attempt
        WHERE attempt.signer_address = NEW.signer_address
          AND attempt.transaction_nonce = NEW.transaction_nonce
          AND attempt.status = 'confirmed';
        IF confirmed_owner_count <> 1
           OR (NEW.nonce_reservation_state = 'reserved'
               AND (OLD.status <> 'confirmed'
                    OR NEW.lease_id <> confirmed_owner
                    OR NEW.nonce_reservation_reason IS NOT NULL))
           OR (NEW.nonce_reservation_state = 'noncanonical'
               AND (NEW.lease_id = confirmed_owner
                    OR NEW.nonce_reservation_reason IS DISTINCT FROM
                       'confirmed_historical_nonce_owner')) THEN
            RAISE EXCEPTION 'settlement nonce conflict has no unique confirmed owner';
        END IF;
    ELSIF NEW.nonce_reservation_state IS DISTINCT FROM OLD.nonce_reservation_state
          OR NEW.nonce_reservation_reason IS DISTINCT FROM OLD.nonce_reservation_reason THEN
        IF OLD.nonce_reservation_state <> 'pending'
           OR NEW.nonce_reservation_state = 'pending' THEN
            RAISE EXCEPTION 'settlement transaction nonce reservation state is immutable';
        END IF;
    END IF;
    IF NEW.generation_binding_state IS DISTINCT FROM OLD.generation_binding_state
       OR NEW.generation_binding_reason IS DISTINCT FROM OLD.generation_binding_reason THEN
        IF OLD.generation_binding_state <> 'pending'
           OR NEW.generation_binding_state = 'pending' THEN
            RAISE EXCEPTION 'settlement transaction generation binding is immutable';
        END IF;
    END IF;
    IF NEW.submission_count < OLD.submission_count
       OR NEW.submission_count > OLD.submission_count + 1 THEN
        RAISE EXCEPTION 'settlement transaction submission count is not monotonic';
    END IF;
    IF OLD.submitted_at IS NOT NULL
       AND NEW.submitted_at IS DISTINCT FROM OLD.submitted_at THEN
        RAISE EXCEPTION 'settlement submission timestamp is immutable';
    END IF;
    IF OLD.superseded_at IS NOT NULL
       AND NEW.superseded_at IS DISTINCT FROM OLD.superseded_at THEN
        RAISE EXCEPTION 'settlement supersession timestamp is immutable';
    END IF;
    IF OLD.confirmed_at IS NOT NULL
       AND NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at THEN
        RAISE EXCEPTION 'settlement confirmation timestamp is immutable';
    END IF;
    IF OLD.reverted_at IS NOT NULL
       AND NEW.reverted_at IS DISTINCT FROM OLD.reverted_at THEN
        RAISE EXCEPTION 'settlement reversion timestamp is immutable';
    END IF;
    IF OLD.confirmed_block IS NOT NULL
       AND (
           NEW.confirmed_block IS DISTINCT FROM OLD.confirmed_block
           OR NEW.confirmed_block_hash IS DISTINCT FROM OLD.confirmed_block_hash
       ) THEN
        RAISE EXCEPTION 'settlement transaction block evidence is immutable';
    END IF;
    IF NEW.submission_count > OLD.submission_count
       AND (
           NEW.status <> 'submitted'
           OR NEW.submitted_at IS NULL
       ) THEN
        RAISE EXCEPTION 'settlement transaction submission annotation is invalid';
    END IF;
    IF OLD.submitted_at IS NULL
       AND NEW.submitted_at IS NOT NULL
       AND NEW.submission_count = OLD.submission_count THEN
        RAISE EXCEPTION 'settlement transaction submission timestamp has no submission';
    END IF;
    IF NEW.status = 'submitted'
       AND (NEW.submitted_at IS NULL OR NEW.submission_count = 0) THEN
        RAISE EXCEPTION 'submitted settlement transaction has no submission evidence';
    END IF;
    IF NEW.superseded_at IS NOT NULL
       AND NEW.status NOT IN ('superseded', 'confirmed', 'reverted') THEN
        RAISE EXCEPTION 'settlement transaction supersession annotation is invalid';
    END IF;
    IF (
           NEW.confirmed_at IS NOT NULL
           OR NEW.confirmed_block IS NOT NULL
           OR NEW.confirmed_block_hash IS NOT NULL
       ) AND NEW.status <> 'confirmed' THEN
        RAISE EXCEPTION 'settlement transaction confirmation annotation is invalid';
    END IF;
    IF NEW.reverted_at IS NOT NULL AND NEW.status <> 'reverted' THEN
        RAISE EXCEPTION 'settlement transaction revert annotation is invalid';
    END IF;
    IF NOT (CASE OLD.status
        WHEN 'prepared' THEN NEW.status IN (
            'prepared', 'submitted', 'superseded', 'confirmed', 'reverted'
        )
        WHEN 'submitted' THEN NEW.status IN (
            'submitted', 'superseded', 'confirmed', 'reverted'
        )
        WHEN 'superseded' THEN NEW.status IN ('superseded', 'confirmed', 'reverted')
        WHEN 'confirmed' THEN NEW.status = 'confirmed'
        WHEN 'reverted' THEN NEW.status = 'reverted'
        ELSE FALSE
    END) THEN
        RAISE EXCEPTION 'settlement transaction status cannot move backward';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER settlement_transaction_attempts_append_only
BEFORE INSERT OR UPDATE OR DELETE ON settlement_transaction_attempts
FOR EACH ROW EXECUTE FUNCTION protect_settlement_transaction_attempt();

CREATE FUNCTION require_captured_settlement_job_transaction() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IN ('proposed', 'disputed', 'finalized')
       AND (
           num_nonnulls(
               NEW.proposal,
               NEW.raw_transaction,
               NEW.transaction_hash,
               NEW.transaction_nonce
           ) <> 4
           OR num_nonnulls(NEW.confirmed_block, NEW.confirmed_block_hash) <> 2
       ) THEN
        RAISE EXCEPTION 'settlement job later state has incomplete confirmation evidence';
    END IF;
    IF NEW.proposal IS NULL
       AND NEW.raw_transaction IS NULL
       AND NEW.transaction_hash IS NULL
       AND NEW.transaction_nonce IS NULL THEN
        RETURN NEW;
    END IF;
    IF NEW.proposal IS NULL
       OR NEW.raw_transaction IS NULL
       OR NEW.transaction_hash IS NULL
       OR NEW.transaction_nonce IS NULL THEN
        RAISE EXCEPTION 'settlement job transaction cursor is incomplete';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM settlement_transaction_attempts AS attempt
        WHERE attempt.transaction_hash = NEW.transaction_hash
          AND attempt.lease_id = NEW.lease_id
          AND attempt.raw_transaction = NEW.raw_transaction
          AND attempt.transaction_nonce = NEW.transaction_nonce
          AND attempt.proposal = NEW.proposal
          AND attempt.signer_address IS NOT NULL
          AND attempt.nonce_reservation_state = 'reserved'
          AND attempt.generation_binding_state IN ('verified', 'normalized')
          AND EXISTS (
              SELECT 1
              FROM settlement_signer_nonce_reservations AS reservation
              WHERE reservation.signer_address = attempt.signer_address
                AND reservation.transaction_nonce = attempt.transaction_nonce
                AND reservation.lease_id = attempt.lease_id
          )
    ) THEN
        RAISE EXCEPTION 'settlement job transaction was not captured by the hardened worker';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER settlement_jobs_require_captured_transaction
BEFORE INSERT OR UPDATE ON settlement_jobs
FOR EACH ROW EXECUTE FUNCTION require_captured_settlement_job_transaction();
