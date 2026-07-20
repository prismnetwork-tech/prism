#!/usr/bin/env bash
set -euo pipefail

denylist="${PRISM_FORBIDDEN_TERMS_FILE:-}"

if [[ -n "${PRISM_EXPECTED_REMOTE:-}" ]]; then
  actual_remote="$(git remote get-url origin 2>/dev/null || true)"
  if [[ "$actual_remote" != "$PRISM_EXPECTED_REMOTE" ]]; then
    printf '%s\n' "The configured remote does not match PRISM_EXPECTED_REMOTE."
    exit 1
  fi
fi

if [[ -n "$denylist" ]]; then
  if [[ ! -f "$denylist" ]]; then
    printf '%s\n' "PRISM_FORBIDDEN_TERMS_FILE does not exist."
    exit 1
  fi
  if rg --fixed-strings --line-number --file "$denylist" \
    --glob '!pnpm-lock.yaml' \
    --glob '!Cargo.lock' \
    --glob '!contracts/out/**' \
    --glob '!contracts/cache/**' \
    .; then
    printf '%s\n' "Isolation scan found a forbidden term."
    exit 1
  fi
fi

check_commit_identities() {
  local label="$1"
  local format="$2"
  local allowed="$3"

  [[ -z "$allowed" ]] && return

  while IFS= read -r identity; do
    if ! grep -Fqx -- "$identity" <<<"$allowed"; then
      printf '%s\n' "Commit history contains an unapproved $label."
      exit 1
    fi
  done < <(git log --format="$format")
}

if git rev-parse --verify HEAD >/dev/null 2>&1; then
  check_commit_identities \
    "author email" \
    '%ae%n%ce' \
    "${PRISM_ALLOWED_GIT_EMAILS:-${PRISM_ALLOWED_GIT_EMAIL:-}}"
  check_commit_identities \
    "author name" \
    '%an%n%cn' \
    "${PRISM_ALLOWED_GIT_NAMES:-${PRISM_ALLOWED_GIT_NAME:-}}"
fi
