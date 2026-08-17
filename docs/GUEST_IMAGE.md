# The workspace guest image

A lease served above `isolated` runs inside a virtual machine whose initial
state is measured by the processor at launch. The measurement is a 48 byte
digest over the firmware image, its guest physical layout, the type of every
page, and the register state of every vCPU. The guest asks the platform for a
report carrying that digest, and the control plane compares it against a
reference value.

Everything below is about where that reference value comes from, because it is
the difference between a check and a formality.

## The rule

The reference measurement is computed from inputs. It is never read off a report
produced by the machine being attested.

A measurement copied from an observed report certifies whatever happened to
boot. It makes the verifier agree with the host by construction: the host boots
something, the report says what it booted, and the reference says the report is
correct because the reference came from the report. Nothing in that loop can
fail, which is another way of saying nothing in it is checked.

When the computed value and a captured value disagree, the computed value wins
and the disagreement is the finding. The image that booted was not the image
that was published, and that is exactly what the class exists to detect.

`tools/snp-measure` computes the value from the firmware, the kernel, the
command line and the machine shape. Its tests pin the digests it produces so a
refactor cannot move them quietly, which is worth having and is not the same as
agreeing with a PSP. Nothing here has been compared against a measurement taken
from a guest launched on SNP hardware yet, so the tool currently agrees with
itself. Checking in a vector from a real launch is what closes that.

## What the measurement covers

The firmware reaches the digest as bytes, one page at a time, each folded in
with its guest physical address and page type.

The kernel, the initrd and the kernel command line reach it through the hashes
table the firmware refuses to boot without. The table holds one SHA-256 per
input, so changing a single character of the command line changes the launch
measurement.

The root filesystem does not reach the digest directly. It is a read-only
squashfs behind dm-verity, and the root hash of its verity tree is carried in the
command line, which is measured. The kernel refuses any block whose hash does
not match. That is how a filesystem of a few hundred megabytes sits under a
48 byte digest with nothing left unanchored.

The guest agent is part of that filesystem, so the code that takes the
attestation report, generates the SSH host key and enforces the workload policy
is itself covered by the measurement.

The per-vCPU VMSA is in the digest as well, which is why the reference is keyed
by machine shape. Eight vCPUs and sixteen vCPUs on the same image are two
different measurements, and so are the same image and vCPU count on two
different processor steppings, because the CPUID signature reaches the guest in
RDX at reset.

## What it does not cover

The renter's container image is not baked in. It is pulled inside the guest and
its digest is bound through `HOST_DATA`, which the host fixes at launch and
cannot change afterwards. `HOST_DATA` is still a host input. It means something
only because the measured agent refuses to run anything else, and that is a
property of the image in this directory rather than of SNP.

The host is not covered at all. SNP has no host measurement and assumes the host
is hostile, so nothing here says which hypervisor or host kernel the guest ran
under.

The GPU is not covered. Passthrough traffic leaves the encrypted region through
shared bounce buffers, and VRAM is plaintext. An attested lease gives integrity
of what booted, not confidentiality of what is computed.

A measurement carries no notion of time or identity on its own. Freshness and
binding come from `REPORT_DATA`, which the guest fills with a digest over the
control plane's challenge, the lease id and the SSH host key the guest just
generated.

## The inputs

`node/guest/inputs.lock.json` pins every input by digest or commit:

- the builder container, by image digest, with its Debian packages resolved
  against a frozen snapshot archive rather than a rolling mirror;
- the firmware, by edk2 commit, built as `OvmfPkg/AmdSev/AmdSevX64.dsc`, which
  is the platform that carries an SNP kernel hashes section;
- the kernel, by the SHA-256 of an upstream tarball, configured by
  `node/guest/kernel/config`;
- the root filesystem base, by the SHA-256 of an Alpine minirootfs, with the
  resolved package set recorded in `node/guest/rootfs/packages.lock`;
- the verity salt, which is fixed rather than random so that two builds of the
  same tree produce the same root hash, the same command line and the same
  measurement.

The machine shape is not an input to the build. It is an input to the
measurement, and it is recorded per entry in the reference file.

## Rebuilding it bit for bit

    cd node/guest
    make all
    make verify

`make all` builds the firmware, the kernel and the root filesystem inside the
pinned builder and writes the digests it produced to `out/manifest.json`.
`make verify` compares them against the outputs recorded in
`inputs.lock.json`, and exits non-zero on any disagreement or on any output
nobody has recorded yet.

Determinism comes from a few specific decisions, each of which matters because
its absence would move the measurement:

- `SOURCE_DATE_EPOCH` is fixed in the lock and exported into every step;
- the kernel build sets `KBUILD_BUILD_TIMESTAMP`, `KBUILD_BUILD_USER` and
  `KBUILD_BUILD_HOST`, none of which are allowed to describe the machine that
  ran the build;
- the squashfs is built with fixed timestamps, no extended attributes and a
  single owner;
- the workspace account is written into `/etc/passwd` and `/etc/shadow`
  directly, because `adduser` stamps the day it ran into the shadow file;
- no SSH host key is shipped in the image. A key baked into a public image is
  the same key on every machine that boots it. The agent generates one per boot,
  and the report commits to it.

An independent rebuild is the point of all of this. Someone who did not build
the image runs the same commands, and either lands on the digests in the lock or
does not. Agreement is what makes a published measurement worth anything to a
renter, since the alternative is trusting the person who published it.

## Producing reference entries

    make measure CPU_FAMILY=25 CPU_MODEL=17 CPU_STEPPING=1

This prints one reference file entry per machine shape in `SHAPES`. The family,
model and stepping are the signature the VMM presents to the guest, which is not
always the signature of the processor underneath it. There is no default,
because measuring against whatever processor happened to run the build would
produce a reference that no node matches.

Entries go into `crates/attestation/reference/snp-launch-measurements.json`, and
the file's `provenance` becomes `computed` only when every entry in it was
produced this way.

    make check

recomputes every entry from its recorded inputs and exits non-zero on any
disagreement. The same check runs as a test in `tools/snp-measure`, so it is
part of every build: the moment the file says its measurements were computed,
the build stays red until the inputs that produced them are where it can hash
them. A measurement nobody can recompute is a measurement nobody checked.

## Where this stands

Nothing has been built from this recipe yet. The reference file carries
placeholders, no entry in it was computed from an input, and no node can be
granted `attested` from it. `MAX_VERIFIABLE_TRUST_CLASS` stays at `isolated`
until a measurement here is computed from pinned inputs, reproduced by someone
who did not build the image, and a genuine report from real hardware verifies
against it as a checked-in vector.

See [ATTESTATION.md](ATTESTATION.md) for what each class requires and
[SECURITY_MODEL.md](SECURITY_MODEL.md) for what a verified report does and does
not promise.
