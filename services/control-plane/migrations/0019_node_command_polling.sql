-- node_command_requests started as the replay guard for signed node requests
-- and is now read a second way: a live row for a node is the evidence that the
-- node is still polling the command channel, which is what makes it eligible
-- for batch work. The scheduler asks that question per node on every quote, so
-- the table needs an index on node_id as well as on the expiry sweep.
CREATE INDEX node_command_requests_node_idx
    ON node_command_requests(node_id, expires_at);
