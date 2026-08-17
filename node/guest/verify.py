#!/usr/bin/env python3
"""Compares what a build produced against the digests recorded for this image.

Reproducibility is only a claim until someone who did not build the image builds
it again and lands on the same bytes. That is what this compares. A recorded
output that nothing reproduces is worth less than no record at all, so an
unrecorded output is a failure rather than a silent pass.
"""

import json
import pathlib
import sys

GUEST = pathlib.Path(__file__).resolve().parent


def main() -> int:
    lock = json.loads((GUEST / "inputs.lock.json").read_text())
    manifest_path = GUEST / "out" / "manifest.json"
    if not manifest_path.exists():
        print(f"{manifest_path} does not exist; build the image first", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text())

    failures = []
    for name, recorded in sorted(lock["outputs"].items()):
        built = manifest.get(name)
        if built is None:
            failures.append(f"{name}: this build produced nothing")
        elif recorded is None:
            failures.append(f"{name}: nothing is recorded for it yet, this build produced {built}")
        elif recorded != built:
            failures.append(f"{name}: recorded {recorded}, built {built}")
        else:
            print(f"{name}: {built}")

    for failure in failures:
        print(failure, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
