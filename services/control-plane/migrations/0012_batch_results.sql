-- What a batch command printed, kept beside the command that produced it.
-- One command per lease already, so the renter's result is reachable from the
-- lease without another key.
ALTER TABLE node_commands
    ADD COLUMN result JSONB CHECK (result IS NULL OR jsonb_typeof(result) = 'object');
