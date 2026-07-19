#!/usr/bin/env bash
set -euo pipefail

actionlint=rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
shellcheck=koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d
scripts=()

while IFS= read -r script; do
  scripts+=("$script")
done < <(find scripts -type f -name '*.sh' -print | sort)

docker run --rm -v "$PWD:/repo:ro" -w /repo "$actionlint"
docker run --rm -v "$PWD:/repo:ro" -w /repo "$shellcheck" -S warning "${scripts[@]}"
