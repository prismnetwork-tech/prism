#!/usr/bin/env bash
set -uo pipefail

# Rents a GPU the way a customer does and records whether it worked, so the
# health check can alarm on the answer instead of inferring it from parts.
#
# Every fault worth finding this year was found by leasing rather than by
# watching: a lease id that collided with a superseded escrow, a host judged on
# a port it had not been given yet, a machine handed over before it was
# reachable. All of them left every other gauge reading normal.
#
# It spends real USDG. The canary's own caps bound that, and the result file is
# written whatever happens, because a run that dies without a verdict has to
# read as a failure rather than as silence.

result=${PRISM_CANARY_RESULT:-/var/lib/prism/canary.json}
log=${PRISM_CANARY_LOG:-/var/lib/prism/canary.log}
started=$(date +%s)

mkdir -p "$(dirname "$result")" "$(dirname "$log")"

write_result() {
  local ok=$1 stage=$2 error=$3
  # A partial file read by the health check mid-write looks like corruption, so
  # the real one is only ever moved into place complete.
  local tmp="$result.$$"
  printf '{"ok":%s,"stage":"%s","error":%s,"started_at":%s,"finished_at":%s}\n' \
    "$ok" "$stage" "$(printf '%s' "$error" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()[:400]))')" \
    "$started" "$(date +%s)" > "$tmp"
  mv "$tmp" "$result"
}

# The host runs no Node of its own, and adding one would be a second runtime to
# patch, so the canary runs in a container. Not the slim image: the SDK shells
# out to ssh-keygen and ssh, and slim carries neither, which fails the run at
# the point a renter would be handed their machine.
image=${PRISM_CANARY_IMAGE:-node:24-bookworm}
output=$(timeout -k 15s 1200s docker run --rm \
  --env-file /opt/prism/canary.env \
  -v /opt/prism/canary:/canary:ro \
  -v /var/lib/prism/canary-modules:/canary/node_modules:ro \
  -w /canary "$image" node canary.mjs 2>&1)
status=$?
printf '%s === exit %s ===\n%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$status" "$output" >> "$log"
tail -c 200000 "$log" > "$log.trim" && mv "$log.trim" "$log"

# The canary exits 0 after a preflight when CANARY_CONFIRM is unset, so a
# misconfigured unit would report healthy forever having rented nothing. That is
# the exact failure this check exists to remove, so it is treated as a fault.
if [[ $status -eq 0 && $output == *"preflight OK"* ]]; then
  write_result false preflight "canary ran preflight only; CANARY_CONFIRM is not set, so nothing was rented"
  exit 1
fi

if [[ $status -eq 0 ]]; then
  write_result false settlement_pending "execution succeeded; settlement, proof publication, and provider destruction are not verified yet"
  exit 1
fi

# Name the step that failed, so the alarm says what broke rather than that
# something did. These strings are the canary's own.
stage=unknown
case "$output" in
  *"Permission denied"*|*"ssh:"*) stage=ssh ;;
  *"access_timeout"*|*"provision"*) stage=provision ;;
  *"funding_mismatch"*|*"approve_reverted"*|*"lease_funding_reverted"*) stage=fund ;;
  *"no_match"*|*"no GPU offers"*|*"quote has"*|*"quote exceeds"*) stage=quote ;;
esac
[[ $status -eq 124 ]] && stage=timeout

write_result false "$stage" "$(printf '%s' "$output" | tail -c 400)"
exit 1
