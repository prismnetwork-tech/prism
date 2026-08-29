ALTER TABLE cloud_instances
    ALTER COLUMN ssh_authorized_key DROP NOT NULL,
    ADD COLUMN gpu_model TEXT CHECK (
        gpu_model IS NULL OR char_length(gpu_model) BETWEEN 1 AND 128
    ),
    ADD COLUMN gpu_vram_mib INTEGER CHECK (
        gpu_vram_mib IS NULL OR gpu_vram_mib BETWEEN 1 AND 196608
    );

ALTER TABLE lifecycle_outbox
    ADD COLUMN claim_generation BIGINT NOT NULL DEFAULT 0 CHECK (claim_generation >= 0);

CREATE TABLE managed_repro_jobs (
    command_id UUID PRIMARY KEY,
    lease_id BIGINT NOT NULL UNIQUE REFERENCES leases(lease_id) ON DELETE CASCADE,
    command JSONB NOT NULL CHECK (jsonb_typeof(command) = 'object'),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (
        status IN ('queued', 'preparing', 'ready', 'launching', 'running', 'completed', 'failed')
    ),
    runner_private_key JSONB CHECK (
        runner_private_key IS NULL OR jsonb_typeof(runner_private_key) = 'object'
    ),
    runner_public_key TEXT CHECK (
        runner_public_key IS NULL
        OR char_length(runner_public_key) BETWEEN 80 AND 16384
    ),
    transport_host_key TEXT CHECK (
        transport_host_key IS NULL OR char_length(transport_host_key) BETWEEN 32 AND 16384
    ),
    transport_host_key_sha256 TEXT CHECK (
        transport_host_key_sha256 IS NULL
        OR transport_host_key_sha256 ~ '^[0-9a-f]{64}$'
    ),
    gpu_model TEXT CHECK (
        gpu_model IS NULL OR char_length(gpu_model) BETWEEN 1 AND 128
    ),
    gpu_vram_mib INTEGER CHECK (
        gpu_vram_mib IS NULL OR gpu_vram_mib BETWEEN 1 AND 196608
    ),
    prepared_provider_instance_id BIGINT CHECK (
        prepared_provider_instance_id IS NULL OR prepared_provider_instance_id > 0
    ),
    prepared_hourly_cost_micros BIGINT CHECK (
        prepared_hourly_cost_micros IS NULL OR prepared_hourly_cost_micros > 0
    ),
    report JSONB CHECK (report IS NULL OR jsonb_typeof(report) = 'object'),
    attempts SMALLINT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 255),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claim_token UUID,
    claim_generation BIGINT NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
    lease_until TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    last_error TEXT CHECK (
        last_error IS NULL OR char_length(last_error) <= 1024
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((claim_token IS NULL) = (lease_until IS NULL)),
    CHECK (finished_at IS NULL OR (started_at IS NOT NULL AND finished_at >= started_at)),
    CHECK (report IS NULL OR status IN ('completed', 'failed')),
    CHECK (
        status <> 'completed'
        OR (report IS NOT NULL AND started_at IS NOT NULL AND finished_at IS NOT NULL)
    ),
    CHECK (status <> 'running' OR started_at IS NOT NULL),
    CHECK (
        status <> 'failed'
        OR started_at IS NULL
        OR (report IS NOT NULL AND finished_at IS NOT NULL)
    ),
    CHECK (
        (
            status NOT IN ('ready', 'launching', 'running', 'completed')
            AND NOT (status = 'failed' AND report IS NOT NULL)
        )
        OR (
            prepared_provider_instance_id IS NOT NULL
            AND prepared_hourly_cost_micros IS NOT NULL
            AND transport_host_key IS NOT NULL
            AND transport_host_key_sha256 IS NOT NULL
            AND gpu_model IS NOT NULL
            AND gpu_vram_mib IS NOT NULL
        )
    ),
    CHECK (
        status NOT IN ('preparing', 'ready', 'launching', 'running')
        OR (runner_private_key IS NOT NULL AND runner_public_key IS NOT NULL)
    )
);

CREATE FUNCTION bind_managed_repro_execution()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    capture_cost BOOLEAN := FALSE;
BEGIN
    IF TG_OP = 'UPDATE'
       AND (
           OLD.status IN ('launching', 'running', 'completed')
           OR NEW.status IN ('launching', 'running', 'completed')
           OR OLD.report IS NOT NULL
           OR NEW.report IS NOT NULL
       )
       AND ROW(
           NEW.prepared_provider_instance_id,
           NEW.prepared_hourly_cost_micros,
           NEW.transport_host_key,
           NEW.transport_host_key_sha256,
           NEW.gpu_model,
           NEW.gpu_vram_mib
       ) IS DISTINCT FROM ROW(
           OLD.prepared_provider_instance_id,
           OLD.prepared_hourly_cost_micros,
           OLD.transport_host_key,
           OLD.transport_host_key_sha256,
           OLD.gpu_model,
           OLD.gpu_vram_mib
       ) THEN
        RAISE EXCEPTION 'managed repro execution binding is immutable after launch';
    END IF;

    IF NEW.status = 'ready' THEN
        IF TG_OP = 'INSERT' THEN
            capture_cost := TRUE;
        ELSIF OLD.status <> 'ready'
              OR NEW.prepared_provider_instance_id IS DISTINCT FROM OLD.prepared_provider_instance_id THEN
            capture_cost := TRUE;
        END IF;
    END IF;

    IF capture_cost THEN
        SELECT hourly_cost_micros
        INTO NEW.prepared_hourly_cost_micros
        FROM cloud_instances
        WHERE lease_id = NEW.lease_id
          AND provider_instance_id = NEW.prepared_provider_instance_id
          AND status = 'running';

        IF NEW.prepared_hourly_cost_micros IS NULL THEN
            RAISE EXCEPTION 'managed repro preflight has no matching running provider cost';
        END IF;
    ELSIF TG_OP = 'UPDATE' THEN
        IF NEW.prepared_provider_instance_id IS DISTINCT FROM OLD.prepared_provider_instance_id THEN
            NEW.prepared_hourly_cost_micros := NULL;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER managed_repro_execution_binding
BEFORE INSERT OR UPDATE ON managed_repro_jobs
FOR EACH ROW EXECUTE FUNCTION bind_managed_repro_execution();

CREATE INDEX managed_repro_jobs_claim_idx
    ON managed_repro_jobs(status, available_at, lease_until, created_at);

CREATE INDEX lease_quotes_repro_token_idx
    ON lease_quotes ((document #>> '{repro,token_hash}'))
    WHERE document #>> '{repro,token_hash}' IS NOT NULL;

CREATE INDEX leases_repro_token_idx
    ON leases ((document #>> '{repro,token_hash}'))
    WHERE document #>> '{repro,token_hash}' IS NOT NULL;
