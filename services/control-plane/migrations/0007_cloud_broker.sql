CREATE TABLE cloud_capacity (
    node_id TEXT PRIMARY KEY REFERENCES node_offers(node_id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider = 'vast'),
    available BOOLEAN NOT NULL DEFAULT FALSE,
    provider_offer_id BIGINT CHECK (provider_offer_id IS NULL OR provider_offer_id > 0),
    hourly_cost_micros BIGINT CHECK (
        hourly_cost_micros IS NULL OR hourly_cost_micros > 0
    ),
    observed_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE cloud_instances (
    lease_id BIGINT PRIMARY KEY REFERENCES leases(lease_id) ON DELETE CASCADE,
    provider TEXT NOT NULL DEFAULT 'vast' CHECK (provider = 'vast'),
    provider_instance_id BIGINT UNIQUE CHECK (
        provider_instance_id IS NULL OR provider_instance_id > 0
    ),
    provider_offer_id BIGINT CHECK (
        provider_offer_id IS NULL OR provider_offer_id > 0
    ),
    hourly_cost_micros BIGINT CHECK (
        hourly_cost_micros IS NULL OR hourly_cost_micros > 0
    ),
    ssh_authorized_key TEXT NOT NULL CHECK (
        char_length(ssh_authorized_key) BETWEEN 80 AND 16384
    ),
    ssh_key_attached_at TIMESTAMPTZ,
    ssh_host TEXT CHECK (
        ssh_host IS NULL OR char_length(ssh_host) BETWEEN 1 AND 253
    ),
    ssh_port INTEGER CHECK (ssh_port IS NULL OR ssh_port BETWEEN 1 AND 65535),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (
        status IN ('queued', 'provisioning', 'running', 'destroying', 'destroyed', 'failed')
    ),
    started_at TIMESTAMPTZ,
    destroyed_at TIMESTAMPTZ,
    last_error TEXT CHECK (
        last_error IS NULL OR char_length(last_error) <= 1024
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX cloud_instances_status_idx
    ON cloud_instances(status, updated_at);
