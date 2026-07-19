#!/usr/bin/env bash
set -euo pipefail

image=prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996

docker run --rm \
  --entrypoint promtool \
  -v "$PWD/deploy/observability:/etc/prometheus:ro" \
  "$image" \
  check config /etc/prometheus/prometheus.yml

docker run --rm \
  --entrypoint promtool \
  -v "$PWD/deploy/observability:/etc/prometheus:ro" \
  "$image" \
  check rules /etc/prometheus/prism-alerts.yml

echo "Observability configuration passed"
