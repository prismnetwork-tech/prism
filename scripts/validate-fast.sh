#!/usr/bin/env bash
set -euo pipefail

pnpm typecheck
pnpm lint
pnpm test
pnpm build
./scripts/check-secrets.sh
./scripts/verify-isolation.sh
./scripts/check-ui-patterns.sh
