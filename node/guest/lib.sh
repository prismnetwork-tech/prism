# Shared helpers for the guest build steps. Sourced, not executed.

set -eu

: "${GUEST_ROOT:=$(pwd)}"
LOCK="$GUEST_ROOT/inputs.lock.json"
MANIFEST_DIR="${MANIFEST_DIR:-$GUEST_ROOT/out}"

# Reads a dotted path out of the input lock. Every version, digest and salt the
# build depends on comes from there, so a step cannot quietly use whatever is
# newest.
lock() {
    python3 - "$LOCK" "$1" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    value = value[key]
if value is None:
    raise SystemExit(f"{sys.argv[2]} is not pinned in the input lock")
print(value)
PY
}

# Records what this build produced. The lock says what to build from; the
# manifest says what came out, and `make verify` is the difference between the
# two. A rebuild by someone else either lands on the same digests or it does
# not, and that answer is the whole point of a reproducible appliance.
record_file() {
    python3 - "$MANIFEST_DIR/manifest.json" "$1" "$2" <<'PY'
import hashlib
import json
import os
import sys

path, name, artifact = sys.argv[1:4]
manifest = json.load(open(path)) if os.path.exists(path) else {}
manifest[name] = "sha256:" + hashlib.sha256(open(artifact, "rb").read()).hexdigest()
json.dump(manifest, open(path, "w"), indent=2, sort_keys=True)
PY
}

record_value() {
    python3 - "$MANIFEST_DIR/manifest.json" "$1" "$2" <<'PY'
import json
import os
import sys

path, name, value = sys.argv[1:4]
manifest = json.load(open(path)) if os.path.exists(path) else {}
manifest[name] = value
json.dump(manifest, open(path, "w"), indent=2, sort_keys=True)
PY
}

verify_sha256() {
    printf '%s  %s\n' "$2" "$1" | sha256sum -c - >/dev/null
}

SOURCE_DATE_EPOCH=$(lock source_date_epoch)
export SOURCE_DATE_EPOCH
