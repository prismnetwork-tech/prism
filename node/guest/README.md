# Workspace guest

The measured virtual machine a lease runs in, and the recipe that builds it:
a pinned firmware, a pinned kernel, and a read-only root filesystem anchored by
a dm-verity root hash carried in the measured command line.

    make all       build the firmware, kernel and root filesystem
    make verify    compare this build against the digests in inputs.lock.json
    make measure   print reference entries for each machine shape
    make check     recompute the reference file from its recorded inputs

`inputs.lock.json` pins what goes in. `out/manifest.json` records what came out.
The expected launch measurement is computed from those inputs by
`tools/snp-measure` and never read off a report from the machine being attested.

[docs/GUEST_IMAGE.md](../../docs/GUEST_IMAGE.md) explains why, and what the
measurement does and does not cover.
