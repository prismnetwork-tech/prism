-- A machine that refuses one lease refuses the next one the same way, but the
-- rejection list lived on cloud_instances, so every lease started empty and
-- rediscovered the same bad hosts. Three machines were re-tested by nearly
-- every lease in a ten lease batch, spending attempts the ten minute
-- provisioning window cannot spare.
CREATE TABLE cloud_machine_rejections (
    machine_id BIGINT PRIMARY KEY,
    reason TEXT NOT NULL,
    rejections INTEGER NOT NULL DEFAULT 1,
    first_rejected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_rejected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX cloud_machine_rejections_recent_idx
    ON cloud_machine_rejections(last_rejected_at DESC);
