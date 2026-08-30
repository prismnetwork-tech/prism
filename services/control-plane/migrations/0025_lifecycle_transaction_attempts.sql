-- Refuse legacy states that cannot be preserved as a complete immutable
-- attempt. The migration is transactional, so an operator can inspect and
-- repair the exact row without a half-installed evidence schema.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM lifecycle_outbox
        WHERE num_nonnulls(raw_transaction, transaction_hash, transaction_nonce)
                  NOT IN (0, 3)
           OR num_nonnulls(confirmed_block, confirmed_block_hash) NOT IN (0, 2)
           OR (confirmed_block IS NOT NULL AND raw_transaction IS NULL)
           OR (status = 'submitted' AND raw_transaction IS NULL)
           OR (kind IN ('refresh_grant', 'cleanup_cloud')
               AND raw_transaction IS NOT NULL)
    ) THEN
        RAISE EXCEPTION 'unsafe legacy lifecycle transaction cursor blocks migration';
    END IF;
END;
$$;

CREATE TABLE lifecycle_transaction_attempts (
    transaction_hash TEXT PRIMARY KEY CHECK (
        transaction_hash ~ '^0x[0-9a-f]{64}$'
    ),
    -- The default RESTRICT behavior is deliberate: signed transaction evidence
    -- must be retained before an outbox action or its lease can be deleted.
    action_id UUID NOT NULL REFERENCES lifecycle_outbox(action_id),
    claim_generation BIGINT NOT NULL CHECK (claim_generation >= 0),
    transaction_nonce BIGINT NOT NULL CHECK (transaction_nonce >= 0),
    signer_address TEXT CHECK (
        signer_address IS NULL OR signer_address ~ '^0x[0-9a-f]{40}$'
    ),
    generation_binding_state TEXT NOT NULL DEFAULT 'verified' CHECK (
        generation_binding_state IN ('pending', 'verified', 'quarantined')
    ),
    generation_binding_reason TEXT CHECK (
        generation_binding_reason IS NULL
        OR generation_binding_reason IN (
            'invalid_signed_transaction',
            'transaction_hash_mismatch',
            'signed_chain_mismatch',
            'signed_escrow_mismatch',
            'signed_signer_mismatch',
            'signed_nonce_mismatch',
            'calldata_mismatch'
        )
    ),
    raw_transaction TEXT NOT NULL CHECK (
        raw_transaction ~ '^0x[0-9a-f]+$'
    ),
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
    CHECK (
        (confirmed_block IS NULL) = (confirmed_block_hash IS NULL)
    ),
    CHECK ((submitted_at IS NULL) = (submission_count = 0)),
    CHECK (
        (generation_binding_state IN ('pending', 'verified')
         AND generation_binding_reason IS NULL)
        OR (generation_binding_state = 'quarantined'
            AND generation_binding_reason IS NOT NULL)
    ),
    CHECK (
        generation_binding_state <> 'verified' OR signer_address IS NOT NULL
    ),
    CHECK (
        status <> 'submitted'
        OR (submitted_at IS NOT NULL AND submission_count > 0)
    ),
    CHECK (
        status <> 'confirmed'
        OR (
            confirmed_at IS NOT NULL
            AND confirmed_block IS NOT NULL
            AND confirmed_block_hash IS NOT NULL
        )
    ),
    CHECK (status <> 'reverted' OR reverted_at IS NOT NULL),
    CHECK (status <> 'superseded' OR superseded_at IS NOT NULL)
);

CREATE INDEX lifecycle_transaction_attempts_action_idx
    ON lifecycle_transaction_attempts(action_id, prepared_at);

CREATE INDEX lifecycle_transaction_attempts_status_idx
    ON lifecycle_transaction_attempts(status, prepared_at);

CREATE INDEX lifecycle_transaction_attempts_signer_nonce_idx
    ON lifecycle_transaction_attempts(signer_address, transaction_nonce)
    WHERE signer_address IS NOT NULL;

COMMENT ON COLUMN lifecycle_transaction_attempts.generation_binding_state IS
    'pending is migration-only; verified bytes passed exact hash, nonce, chain, signer, escrow, action and chain-lease checks; quarantined bytes are retained but can never be adopted or broadcast';

-- Preserve every signed transaction already held by an action. A stored
-- transaction is only known to have been submitted when a receipt exists;
-- anything else remains prepared until the worker broadcasts or reconciles it.
INSERT INTO lifecycle_transaction_attempts (
    transaction_hash,
    action_id,
    claim_generation,
    transaction_nonce,
    generation_binding_state,
    raw_transaction,
    status,
    prepared_at,
    confirmed_at,
    confirmed_block,
    confirmed_block_hash
)
SELECT
    transaction_hash,
    action_id,
    claim_generation,
    transaction_nonce,
    'pending',
    raw_transaction,
    CASE WHEN confirmed_block IS NULL THEN 'prepared' ELSE 'confirmed' END,
    created_at,
    CASE WHEN confirmed_block IS NULL THEN NULL ELSE updated_at END,
    confirmed_block,
    confirmed_block_hash
FROM lifecycle_outbox
WHERE raw_transaction IS NOT NULL
  AND transaction_hash IS NOT NULL
  AND transaction_nonce IS NOT NULL;

-- Attempt identity and signed bytes are immutable. Outcome annotations may
-- only move forward, and once recorded their timestamps and block evidence are
-- immutable too.
CREATE FUNCTION protect_lifecycle_transaction_attempt() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.signer_address IS NULL
           OR NEW.generation_binding_state <> 'verified'
           OR NEW.generation_binding_reason IS NOT NULL THEN
            RAISE EXCEPTION 'verified lifecycle transaction binding is required';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'lifecycle transaction attempts are append-only';
    END IF;
    IF NEW.transaction_hash IS DISTINCT FROM OLD.transaction_hash
       OR NEW.action_id IS DISTINCT FROM OLD.action_id
       OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation
       OR NEW.transaction_nonce IS DISTINCT FROM OLD.transaction_nonce
       OR NEW.raw_transaction IS DISTINCT FROM OLD.raw_transaction
       OR NEW.prepared_at IS DISTINCT FROM OLD.prepared_at THEN
        RAISE EXCEPTION 'lifecycle transaction attempt evidence is immutable';
    END IF;
    IF OLD.signer_address IS NOT NULL
       AND NEW.signer_address IS DISTINCT FROM OLD.signer_address THEN
        RAISE EXCEPTION 'lifecycle transaction signer is immutable';
    END IF;
    IF NEW.generation_binding_state IS DISTINCT FROM OLD.generation_binding_state
       OR NEW.generation_binding_reason IS DISTINCT FROM OLD.generation_binding_reason THEN
        IF OLD.generation_binding_state <> 'pending'
           OR NEW.generation_binding_state = 'pending' THEN
            RAISE EXCEPTION 'lifecycle transaction generation binding is immutable';
        END IF;
    END IF;
    IF OLD.signer_address IS NULL
       AND NEW.signer_address IS NULL
       AND NEW.generation_binding_state <> 'quarantined' THEN
        RAISE EXCEPTION 'lifecycle transaction signer was not backfilled';
    END IF;
    IF NEW.submission_count < OLD.submission_count
       OR NEW.submission_count > OLD.submission_count + 1 THEN
        RAISE EXCEPTION 'lifecycle transaction submission count is not monotonic';
    END IF;
    IF OLD.submitted_at IS NOT NULL
       AND NEW.submitted_at IS DISTINCT FROM OLD.submitted_at THEN
        RAISE EXCEPTION 'lifecycle transaction submission timestamp is immutable';
    END IF;
    IF OLD.superseded_at IS NOT NULL
       AND NEW.superseded_at IS DISTINCT FROM OLD.superseded_at THEN
        RAISE EXCEPTION 'lifecycle transaction supersession timestamp is immutable';
    END IF;
    IF OLD.confirmed_at IS NOT NULL
       AND NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at THEN
        RAISE EXCEPTION 'lifecycle transaction confirmation timestamp is immutable';
    END IF;
    IF OLD.reverted_at IS NOT NULL
       AND NEW.reverted_at IS DISTINCT FROM OLD.reverted_at THEN
        RAISE EXCEPTION 'lifecycle transaction revert timestamp is immutable';
    END IF;
    IF OLD.confirmed_block IS NOT NULL
       AND (
           NEW.confirmed_block IS DISTINCT FROM OLD.confirmed_block
           OR NEW.confirmed_block_hash IS DISTINCT FROM OLD.confirmed_block_hash
       ) THEN
        RAISE EXCEPTION 'lifecycle transaction block evidence is immutable';
    END IF;
    IF NEW.submission_count > OLD.submission_count
       AND (
           NEW.status <> 'submitted'
           OR NEW.submitted_at IS NULL
       ) THEN
        RAISE EXCEPTION 'lifecycle transaction submission annotation is invalid';
    END IF;
    IF OLD.submitted_at IS NULL
       AND NEW.submitted_at IS NOT NULL
       AND NEW.submission_count = OLD.submission_count THEN
        RAISE EXCEPTION 'lifecycle transaction submission timestamp has no submission';
    END IF;
    IF NEW.status = 'submitted'
       AND (NEW.submitted_at IS NULL OR NEW.submission_count = 0) THEN
        RAISE EXCEPTION 'submitted lifecycle transaction has no submission evidence';
    END IF;
    IF NEW.superseded_at IS NOT NULL
       AND NEW.status NOT IN ('superseded', 'confirmed', 'reverted') THEN
        RAISE EXCEPTION 'lifecycle transaction supersession annotation is invalid';
    END IF;
    IF (
           NEW.confirmed_at IS NOT NULL
           OR NEW.confirmed_block IS NOT NULL
           OR NEW.confirmed_block_hash IS NOT NULL
       ) AND NEW.status <> 'confirmed' THEN
        RAISE EXCEPTION 'lifecycle transaction confirmation annotation is invalid';
    END IF;
    IF NEW.reverted_at IS NOT NULL AND NEW.status <> 'reverted' THEN
        RAISE EXCEPTION 'lifecycle transaction revert annotation is invalid';
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
        RAISE EXCEPTION 'lifecycle transaction status cannot move backward';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER lifecycle_transaction_attempts_append_only
BEFORE INSERT OR UPDATE OR DELETE ON lifecycle_transaction_attempts
FOR EACH ROW EXECUTE FUNCTION protect_lifecycle_transaction_attempt();

CREATE FUNCTION require_captured_lifecycle_transaction() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.raw_transaction IS NULL
       AND NEW.transaction_hash IS NULL
       AND NEW.transaction_nonce IS NULL THEN
        IF NEW.confirmed_block IS NOT NULL OR NEW.confirmed_block_hash IS NOT NULL THEN
            RAISE EXCEPTION 'lifecycle confirmation has no captured transaction';
        END IF;
        IF NEW.status = 'submitted' THEN
            RAISE EXCEPTION 'submitted lifecycle action has no captured transaction';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.raw_transaction IS NULL
       OR NEW.transaction_hash IS NULL
       OR NEW.transaction_nonce IS NULL THEN
        RAISE EXCEPTION 'lifecycle transaction cursor is incomplete';
    END IF;
    IF NEW.kind IN ('refresh_grant', 'cleanup_cloud') THEN
        RAISE EXCEPTION 'non-chain lifecycle action carries a transaction';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM lifecycle_transaction_attempts AS attempt
        WHERE attempt.transaction_hash = NEW.transaction_hash
          AND attempt.action_id = NEW.action_id
          AND attempt.raw_transaction = NEW.raw_transaction
          AND attempt.transaction_nonce = NEW.transaction_nonce
          AND attempt.signer_address IS NOT NULL
          AND attempt.generation_binding_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'lifecycle transaction was not captured by the hardened worker';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER lifecycle_outbox_requires_captured_transaction
BEFORE INSERT OR UPDATE ON lifecycle_outbox
FOR EACH ROW EXECUTE FUNCTION require_captured_lifecycle_transaction();
