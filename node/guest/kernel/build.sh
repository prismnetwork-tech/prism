#!/bin/sh
# Builds the guest kernel.
#
# The kernel is measured directly, so it is built from an upstream tarball whose
# digest is pinned rather than taken from a distribution that reissues the same
# version with different bytes.

. "$(dirname "$0")/../lib.sh"

out=${1:?output directory}
version=$(lock inputs.kernel.version)
source=$(lock inputs.kernel.source)
sha256=$(lock inputs.kernel.sha256)
tarball="$GUEST_ROOT/build/linux-$version.tar.xz"
work="$GUEST_ROOT/build/linux-$version"

mkdir -p "$out" "$GUEST_ROOT/build"
[ -f "$tarball" ] || curl --fail --silent --show-error --location --output "$tarball" "$source"
verify_sha256 "$tarball" "$sha256"

if [ ! -d "$work" ]; then
    tar --extract --file "$tarball" --directory "$GUEST_ROOT/build"
fi

# Anything that records who built the kernel, or when, changes its bytes and so
# changes the measurement.
export KBUILD_BUILD_TIMESTAMP="@$SOURCE_DATE_EPOCH"
export KBUILD_BUILD_USER=prism
export KBUILD_BUILD_HOST=guest
export KBUILD_BUILD_VERSION=1

make -C "$work" --silent x86_64_defconfig
"$work/scripts/kconfig/merge_config.sh" -m -O "$work" "$work/.config" "$GUEST_ROOT/kernel/config" >/dev/null
make -C "$work" --silent olddefconfig
make -C "$work" --silent "-j$(nproc)" bzImage

install -m 0644 "$work/arch/x86/boot/bzImage" "$out/vmlinuz"
record_file kernel "$out/vmlinuz"
