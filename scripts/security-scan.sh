#!/usr/bin/env bash
set -euo pipefail

trivy=aquasec/trivy:0.65.0@sha256:a22415a38938a56c379387a8163fcb0ce38b10ace73e593475d3658d578b2436
syft=anchore/syft:v1.30.0@sha256:bd5357d2cd087f03af748dac24df48bfbc1723080d78f75f69aca1f2d429060e
slither_image=prism-slither:0.11.3
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v prism-trivy-cache:/cache \
  "$trivy" fs /workspace \
  --cache-dir /cache \
  --scanners vuln,secret,misconfig \
  --severity HIGH,CRITICAL \
  --exit-code 1 \
  --skip-dirs /workspace/apps/web/node_modules \
  --skip-dirs /workspace/apps/web/.next \
  --skip-dirs /workspace/.git \
  --skip-dirs /workspace/target \
  --skip-dirs /workspace/contracts/out \
  --skip-dirs /workspace/contracts/cache

docker run --rm \
  -v "$PWD:/workspace:ro" \
  "$syft" dir:/workspace \
  --exclude './apps/web/node_modules/**' \
  --exclude './apps/web/.next/**' \
  --exclude './.git/**' \
  --exclude './target/**' \
  --exclude './contracts/out/**' \
  --exclude './contracts/cache/**' \
  -o cyclonedx-json >"$temporary/sbom.json"
node -e '
  const fs = require("fs");
  const document = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (document.bomFormat !== "CycloneDX" || !Array.isArray(document.components)) process.exit(1);
' "$temporary/sbom.json"

forge build --build-info --force >/dev/null
docker build --quiet -f deploy/Dockerfile.security -t "$slither_image" . >/dev/null
docker run --rm \
  -v "$PWD:/workspace:ro" \
  -w /workspace \
  "$slither_image" . \
  --foundry-ignore-compile \
  --foundry-out-directory contracts/out \
  --exclude-dependencies \
  --filter-paths 'contracts/test|contracts/script' \
  --exclude arbitrary-send-eth,reentrancy-events,timestamp,assembly,low-level-calls

echo "Security scans and ephemeral SBOM generation passed"
