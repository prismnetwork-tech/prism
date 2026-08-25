#!/usr/bin/env bash
# Runs the confidential demo the same way every time, which is what a terminal
# recording needs. Everything that can fail is checked before the screen is
# cleared, so a bad run never ends up in the take.
#
#   PRISM_AGENT_KEY=0x... ./demo-session.sh
set -euo pipefail
cd "$(dirname "$0")"

: "${PRISM_AGENT_KEY:?set PRISM_AGENT_KEY to a funded agent wallet key}"
export PRISM_INFERENCE_URL="${PRISM_INFERENCE_URL:-https://api.prismnetwork.tech/inference}"
export PRISM_MAX_USDG="${PRISM_MAX_USDG:-0.05}"
export PRISM_DEMO_PACE="${PRISM_DEMO_PACE:-1200}"

for tool in node curl; do
  command -v "$tool" >/dev/null || { echo "$tool is not on PATH" >&2; exit 1; }
done

catalog=$(curl -fsS --max-time 20 "$PRISM_INFERENCE_URL/v1/models" 2>/dev/null) ||
  { echo "$PRISM_INFERENCE_URL is not answering" >&2; exit 1; }
case "$catalog" in
  *'"confidential":true'*) ;;
  *) echo "$PRISM_INFERENCE_URL advertises no confidential models" >&2; exit 1 ;;
esac

type_cmd() {
  printf '\033[38;2;204;255;0m\xe2\x9d\xaf\033[0m '
  local s="$1"
  for ((i = 0; i < ${#s}; i++)); do
    printf '%s' "${s:$i:1}"
    sleep 0.03
  done
  printf '\n'
  sleep 0.5
}

clear
sleep 0.8

type_cmd 'node agent-demo.mjs'
node agent-demo.mjs
sleep 3
