-- What GPU time actually cost, kept rather than overwritten.
--
-- cloud_capacity holds one row per node and is upserted on every refresh, so
-- the price a host cleared at survives about thirty seconds. That series is the
-- only public record of what compute really trades for across a fragmented spot
-- market, and it was being discarded. This table appends instead.
--
-- A row is written when the observed price or host changes, not on every poll,
-- so the series records movement rather than the polling interval.
CREATE TABLE capacity_prices (
    id BIGSERIAL PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES node_offers(node_id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider = 'vast'),
    gpu_model TEXT NOT NULL CHECK (char_length(gpu_model) BETWEEN 1 AND 64),
    vram_mib INTEGER NOT NULL CHECK (vram_mib > 0),
    provider_offer_id BIGINT CHECK (provider_offer_id IS NULL OR provider_offer_id > 0),
    hourly_cost_micros BIGINT NOT NULL CHECK (hourly_cost_micros > 0),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX capacity_prices_model_observed_idx ON capacity_prices (gpu_model, observed_at DESC);
CREATE INDEX capacity_prices_observed_idx ON capacity_prices (observed_at DESC);
