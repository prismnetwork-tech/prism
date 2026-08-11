-- Which commit each service is actually running. Deployments here are manual
-- image pulls, so the repository and the host drift silently: a settlement
-- worker once served six-day-old code while the services either side of it were
-- current, and nothing anywhere reported it.
CREATE TABLE service_versions (
    service TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
