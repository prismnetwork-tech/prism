CREATE TABLE repro_token_claims (
    token_hash TEXT PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Older releases indexed these commitments but did not require them to be
-- unique. Preserve every historical row, reserve each distinct commitment,
-- and let the status path reject any ambiguity already present.
INSERT INTO repro_token_claims (token_hash)
SELECT DISTINCT token_hash
FROM (
    SELECT document #>> '{repro,token_hash}' AS token_hash FROM lease_quotes
    UNION ALL
    SELECT document #>> '{repro,token_hash}' AS token_hash FROM leases
) AS historical
WHERE token_hash ~ '^[0-9a-f]{64}$'
ON CONFLICT (token_hash) DO NOTHING;
