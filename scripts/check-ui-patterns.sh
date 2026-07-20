#!/usr/bin/env bash
set -euo pipefail

if rg -n --pcre2 'border-(?:left|inline-start)\s*:\s*(?:[2-9]|[1-9][0-9]+)px\s+solid' \
  apps/web --glob '*.css'; then
  echo "Decorative side-accent borders are not allowed." >&2
  exit 1
fi

echo "UI pattern check passed."
