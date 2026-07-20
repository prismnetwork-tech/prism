#!/usr/bin/env bash
set -euo pipefail

pnpm typecheck
pnpm lint
pnpm test
pnpm build
./scripts/test-web-runtime.sh
pnpm audit --audit-level moderate
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
cargo build --workspace
./scripts/lint-automation.sh
./scripts/security-scan.sh
./scripts/test-control-plane-postgres.sh
./scripts/test-control-plane-load.sh
./scripts/test-monitor-chaos.sh
./scripts/test-lifecycle-e2e.sh
./scripts/test-gateway-redis.sh
./scripts/test-tunnel-e2e.sh
./scripts/test-workspace-bootstrap.sh
./scripts/test-node-systemd.sh
./scripts/test-lightsail-tls.sh
./scripts/test-lightsail-compose.sh
docker compose --env-file deploy/lightsail/.env.example -f deploy/ec2/compose.yml config --quiet
./scripts/test-observability.sh
forge fmt --check
forge build
forge test
./scripts/check-secrets.sh
./scripts/verify-isolation.sh
