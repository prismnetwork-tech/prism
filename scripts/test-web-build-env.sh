#!/usr/bin/env bash
set -euo pipefail

# Next inlines NEXT_PUBLIC_* into the client bundle when it builds, so a value
# that is not present at build time is not merely empty at runtime, it is
# absent from the bundle entirely. Render passes its environment into a Docker
# build only for names the Dockerfile declares, which makes an undeclared ARG a
# silent no-op: the variable is set in the dashboard, the build ignores it, and
# the feature never turns on with nothing anywhere reporting a problem.

dockerfile=deploy/Dockerfile.web
status=0

while read -r name; do
  [[ -n $name ]] || continue
  if ! grep -qE "^ARG ${name}(=|$)" "$dockerfile"; then
    echo "$dockerfile: does not declare ARG $name, so the build cannot see it" >&2
    status=1
  fi
  if ! grep -qE "^ENV ${name}=" "$dockerfile"; then
    echo "$dockerfile: does not export ENV $name into the build" >&2
    status=1
  fi
done < <(grep -rhoE 'process\.env\.NEXT_PUBLIC_[A-Z0-9_]+' apps/web \
           --include='*.ts' --include='*.tsx' \
           --exclude='*.test.ts' --exclude='*.test.tsx' \
         | sed 's/^process\.env\.//' | sort -u)

[[ $status -eq 0 ]] || exit 1
echo "Every NEXT_PUBLIC_ the web app reads reaches its build"
