ALTER TABLE cloud_instances
    ADD COLUMN rejected_machines BIGINT[] NOT NULL DEFAULT '{}';
