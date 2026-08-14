-- A self-hosted node proves it is alive every few seconds, and a lease whose
-- telemetry goes quiet for ninety seconds is closed and billed to that point. A
-- brokered cloud machine proved nothing after it started: `status` was written
-- once when the instance came up and never read from the provider again, so a
-- host that rebooted, was preempted, or whose container exited stayed 'running'
-- in this table until the lease expired on its own. Settlement meters the whole
-- window, so the renter paid for a machine that had stopped existing.
--
-- `observed_at` records when the provider last confirmed the instance, which is
-- what makes staleness visible.
ALTER TABLE cloud_instances ADD COLUMN observed_at TIMESTAMPTZ;

-- Instances already running predate the poll. Treat them as observed now rather
-- than as stale, so deploying this does not close every live lease at once.
UPDATE cloud_instances SET observed_at = NOW() WHERE status = 'running';
