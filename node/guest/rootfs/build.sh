#!/bin/sh
# Builds the guest root filesystem, its verity hash tree, and the command line
# that anchors one to the other.
#
# The filesystem itself is not measured. The root hash of its verity tree is, by
# way of the command line, and the kernel refuses a block whose hash does not
# match. That is what lets a 400 MiB image sit under a 48 byte digest.

. "$(dirname "$0")/../lib.sh"

out=${1:?output directory}
work="$GUEST_ROOT/build/rootfs"
base=$(lock inputs.rootfs_base.source)
base_sha256=$(lock inputs.rootfs_base.sha256)
repository=$(lock inputs.rootfs_base.repository)
salt=$(lock verity.salt)
data_block=$(lock verity.data_block_size)
hash_block=$(lock verity.hash_block_size)
agent="$out/prism-guest-agent"
tarball="$GUEST_ROOT/build/$(basename "$base")"

if [ ! -x "$agent" ]; then
    echo "build the guest agent into $agent first; it is measured with the rest of the image" >&2
    exit 1
fi

mkdir -p "$out" "$GUEST_ROOT/build"
[ -f "$tarball" ] || curl --fail --silent --show-error --location --output "$tarball" "$base"
verify_sha256 "$tarball" "$base_sha256"

rm -rf "$work"
mkdir -p "$work"
tar --extract --file "$tarball" --directory "$work"

printf '%s\n' "$repository" > "$work/etc/apk/repositories"
packages=$(grep -v '^#' "$GUEST_ROOT/rootfs/packages" | tr '\n' ' ')
chroot "$work" /sbin/apk add --no-cache --no-progress $packages

# Alpine's branch repositories move under their own version numbers, so the
# resolved set is recorded and compared. A rebuild that resolves anything else
# is a different image and has to be treated as one.
chroot "$work" /sbin/apk list --installed | sort > "$out/packages.lock"
if [ -f "$GUEST_ROOT/rootfs/packages.lock" ]; then
    diff -u "$GUEST_ROOT/rootfs/packages.lock" "$out/packages.lock"
else
    echo "no rootfs/packages.lock yet; review $out/packages.lock and commit it" >&2
    exit 1
fi

# adduser stamps the day it ran into /etc/shadow, which would give two builds of
# the same image two different root hashes. The account is written out instead.
printf 'workspace:x:1000:1000::/workspace:/bin/sh\n' >> "$work/etc/passwd"
printf 'workspace:x:1000:\n' >> "$work/etc/group"
printf 'workspace:!::::::\n' >> "$work/etc/shadow"
install -d -m 0755 "$work/workspace"

install -D -m 0755 "$GUEST_ROOT/rootfs/init" "$work/sbin/init"
install -D -m 0644 "$GUEST_ROOT/rootfs/sshd_config" "$work/etc/ssh/sshd_config"
install -D -m 0755 "$agent" "$work/usr/libexec/prism-guest-agent"
# A host key baked into a public image is the same key on every machine that
# boots it. The agent generates one per boot and the report commits to it, so
# there is nothing to ship here.
rm -f "$work"/etc/ssh/ssh_host_*
rm -rf "$work/var/cache/apk" "$work/etc/apk/cache"

mksquashfs "$work" "$out/rootfs.squashfs" \
    -noappend -no-progress -all-root -no-xattrs \
    -mkfs-time "$SOURCE_DATE_EPOCH" -all-time "$SOURCE_DATE_EPOCH" \
    -comp zstd -Xcompression-level 19 >/dev/null

cp "$out/rootfs.squashfs" "$out/rootfs.img"
data_bytes=$(stat --format=%s "$out/rootfs.img")
data_blocks=$((data_bytes / data_block))
data_sectors=$((data_bytes / 512))

# A random salt would give every build a different root hash, a different
# command line and a different measurement. The salt is not a secret; the hash
# tree it seeds is checked against a value that is public by design.
root_hash=$(veritysetup format "$out/rootfs.img" "$out/rootfs.img" \
    --hash-offset "$data_bytes" \
    --hash sha256 \
    --salt "$salt" \
    --data-block-size "$data_block" \
    --hash-block-size "$hash_block" \
    | awk '/^Root hash:/ { print $3 }')

printf '%s' "console=ttyS0 panic=-1 ro rootfstype=squashfs root=/dev/dm-0 dm-mod.create=\"prism-root,,,ro,0 $data_sectors verity 1 /dev/vda /dev/vda $data_block $hash_block $data_blocks $data_blocks sha256 $root_hash $salt\"" > "$out/cmdline"

record_file rootfs "$out/rootfs.img"
record_value verity_root_hash "$root_hash"
record_file cmdline "$out/cmdline"
