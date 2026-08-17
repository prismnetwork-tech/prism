#!/bin/sh
# Builds the OVMF firmware the guest launches from.
#
# The AmdSevX64 platform is the one that carries an SNP kernel hashes section.
# Without it the firmware boots whatever the host hands it and the kernel and
# command line sit outside the launch measurement entirely.

. "$(dirname "$0")/../lib.sh"

out=${1:?output directory}
work="$GUEST_ROOT/build/edk2"
source=$(lock inputs.firmware.source)
commit=$(lock inputs.firmware.commit)
platform=$(lock inputs.firmware.platform)

mkdir -p "$out" "$GUEST_ROOT/build"
if [ ! -d "$work/.git" ]; then
    git clone --quiet "$source" "$work"
fi
git -C "$work" fetch --quiet --tags origin
git -C "$work" checkout --quiet --detach "$commit"
git -C "$work" submodule update --init --recursive --quiet

# edk2 stamps its own build time into the firmware volume unless told when the
# build happened.
export PYTHON_COMMAND=python3

(
    cd "$work"
    make -C BaseTools --silent
    . ./edksetup.sh BaseTools
    build -a X64 -b RELEASE -t GCC5 -p "$platform" -q
)

install -m 0644 "$work/Build/AmdSev/RELEASE_GCC5/FV/OVMF.fd" "$out/OVMF.fd"
record_file firmware "$out/OVMF.fd"
