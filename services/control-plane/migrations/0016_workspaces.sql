-- Durable workspaces. A lease destroys its machine, so anything a renter wants
-- to keep has to live somewhere the machine does not.
--
-- Like vault_items, every column is either ciphertext metadata or a policy the
-- renter authenticated into that ciphertext. There is no key column and no
-- plaintext: the bytes live in object storage, sealed before they leave the
-- renter's side, and the control plane only ever learns how large they are and
-- when they changed.
CREATE TABLE workspaces (
    workspace_id UUID PRIMARY KEY,
    subject TEXT NOT NULL REFERENCES accounts(subject) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    -- Bumped on every successful upload, so a restore can name the snapshot it
    -- wants and two machines writing the same workspace cannot silently
    -- interleave.
    version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    wrapped_key TEXT NOT NULL DEFAULT '' CHECK (char_length(wrapped_key) <= 1024),
    nonce TEXT NOT NULL DEFAULT '' CHECK (char_length(nonce) <= 64),
    -- SHA-256 of the ciphertext, recorded by the renter. A restore that hashes
    -- to something else has been altered in storage, and the renter finds out
    -- before decrypting rather than after.
    ciphertext_digest TEXT NOT NULL DEFAULT ''
        CHECK (ciphertext_digest = '' OR ciphertext_digest ~ '^[0-9a-f]{64}$'),
    size_bytes BIGINT NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    min_trust_class TEXT NOT NULL DEFAULT 'open'
        CHECK (min_trust_class IN ('open', 'isolated', 'attested', 'confidential')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (subject, name)
);

CREATE INDEX workspaces_subject_idx ON workspaces(subject, updated_at DESC);
