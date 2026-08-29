-- Keep the signed envelope that justified each command transition, and give a
-- ready batch an explicit one-time execution claim before the node starts it.
ALTER TABLE node_commands
    ADD COLUMN verified_report JSONB CHECK (
        verified_report IS NULL OR jsonb_typeof(verified_report) = 'object'
    ),
    ADD COLUMN authorization_request_id UUID;

ALTER TABLE node_commands
    DROP CONSTRAINT node_commands_status_check,
    ADD CONSTRAINT node_commands_status_check CHECK (
        status IN ('queued', 'leased', 'ready', 'running', 'completed', 'failed')
    );
