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

output=$(timeout 900 node /opt/prism/canary/canary.mjs 2>&1)
status=$?
printf '%s === exit %s ===\n%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$status" "$output" >> "$log"
tail -c 200000 "$log" > "$log.trim" && mv "$log.trim" "$log"

if [[ $status -eq 0 ]]; then
  write_result true complete ""
  exit 0
fi

# Name the step that failed, so the alarm says what broke rather than that
# something did. These strings are the canary's own.
stage=unknown
case "$output" in
  *"no_match"*|*"quote"*)        stage=quote ;;
  *"funding_mismatch"*|*"fund"*) stage=fund ;;
  *"access_timeout"*|*provision*) stage=provision ;;
  *"Permission denied"*|*ssh*)   stage=ssh ;;
esac
[[ $status -eq 124 ]] && stage=timeout

write_result false "$stage" "$(printf '%s' "$output" | tail -c 400)"
exit 1
