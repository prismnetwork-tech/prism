#!/usr/bin/env bash
set -euo pipefail

search_args=(
  --hidden
  --glob '!.git/**'
  --glob '!pnpm-lock.yaml'
  --glob '!Cargo.lock'
  --glob '!scripts/check-secrets.sh'
)

if rg --quiet "${search_args[@]}" \
  '(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|xox[baprs]-[0-9A-Za-z-]{10,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,}|rnd_[A-Za-z0-9]{20,}|cfut_[A-Za-z0-9_-]{20,})' .; then
  printf '%s\n' "Potential credential detected."
  exit 1
fi

if rg --quiet "${search_args[@]}" \
  '(/Users/[^/$]+/|/home/[^/$]+/|file:///|vscode://|Co-Authored-By:|Generated with (Claude|Codex)|AI[- ]generated)' .; then
  printf '%s\n' "Personal path or prohibited attribution detected."
  exit 1
fi

while IFS= read -r -d '' path; do
  name="${path##*/}"
  case "$name" in
    .env|.env.*)
      if [[ "$name" != ".env.example" ]]; then
        printf '%s\n' "Environment file must not be committed: $path"
        exit 1
      fi
      ;;
  esac
done < <(git ls-files --cached --others --exclude-standard -z)
