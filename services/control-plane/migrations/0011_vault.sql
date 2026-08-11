-- Renter-encrypted storage. Every column here is either ciphertext or a policy
-- field the renter also authenticated into that ciphertext. There is
-- deliberately no key column: the control plane cannot read these rows, and
-- adding a way for it to would take a migration and a code change, not a config
-- flag.
CREATE TABLE vault_items (
    item_id UUID PRIMARY KEY,
    subject TEXT NOT NULL REFERENCES accounts(subject) ON DELETE CASCADE,
    version INTEGER NOT NULL CHECK (version >= 1),
    wrapped_key TEXT NOT NULL CHECK (char_length(wrapped_key) BETWEEN 1 AND 1024),
    nonce TEXT NOT NULL CHECK (char_length(nonce) BETWEEN 1 AND 64),
    ciphertext TEXT NOT NULL CHECK (char_length(ciphertext) BETWEEN 1 AND 262144),
    min_trust_class TEXT NOT NULL
        CHECK (min_trust_class IN ('open', 'isolated', 'attested', 'confidential')),
    label TEXT NOT NULL DEFAULT '' CHECK (char_length(label) <= 64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX vault_items_subject_idx ON vault_items(subject, updated_at DESC);

-- Append-only. A renter reads this to see what an agent handed to which lease,
-- and the row survives the item being deleted.
CREATE TABLE vault_releases (
    release_id BIGSERIAL PRIMARY KEY,
    subject TEXT NOT NULL REFERENCES accounts(subject) ON DELETE CASCADE,
    item_id UUID NOT NULL,
    lease_id BIGINT NOT NULL,
    item_version INTEGER NOT NULL,
    lease_trust_class TEXT NOT NULL,
    released_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX vault_releases_subject_idx ON vault_releases(subject, released_at DESC);
CREATE INDEX vault_releases_item_idx ON vault_releases(item_id, released_at DESC);
