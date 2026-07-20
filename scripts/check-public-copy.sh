#!/usr/bin/env bash
set -euo pipefail

patterns=(
  'in this environment'
  'release-gated'
  'launch gate'
  'mainnet canary'
  'cost ceiling'
  'control plane could'
  'server-side operator allowlist'
  'configured authority'
  'durable account'
  'one clear product'
  'one measurable'
  'what this proves'
  'what we are building'
  'built in public'
  'use the channel built'
  'connection is not verification'
  'every mutation is attributable'
  'privileged mutation'
  'honest boundary'
)

expression=$(IFS='|'; echo "${patterns[*]}")
if rg -n -i "$expression" apps/web --glob '*.tsx'; then
  echo "Public copy contains banned internal or formulaic language." >&2
  exit 1
fi

echo "Public copy check passed."
