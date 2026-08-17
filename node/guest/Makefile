GUEST_IMAGE := prism-guest-2026.08
OUT := out
CONTAINER ?= podman
BUILDER := prism-guest-builder
REFERENCE := ../../crates/attestation/reference/snp-launch-measurements.json
CARGO := cargo run --quiet --manifest-path ../../Cargo.toml -p prism-snp-measure --

# The shapes the network serves. Each is its own reference entry, because the
# launch digest covers the VMSA of every vCPU.
SHAPES := 8 16 32

# What the VMM presents to the guest, which reaches it in RDX and lands in the
# measurement. There is deliberately no default: measuring against whatever
# processor happened to run make would produce a reference no node matches.
CPU_FAMILY ?=
CPU_MODEL ?=
CPU_STEPPING ?=

# Every step runs in the pinned builder, so an output never depends on what is
# installed on the machine doing the building.
RUN := $(CONTAINER) run --rm --volume $(CURDIR):/build --workdir /build $(BUILDER)

.PHONY: all builder firmware kernel rootfs measure check verify clean

all: firmware kernel rootfs

builder:
	$(CONTAINER) build --tag $(BUILDER) builder

firmware: builder
	$(RUN) firmware/build.sh $(OUT)

kernel: builder
	$(RUN) kernel/build.sh $(OUT)

# The agent is installed into the root filesystem, so its bytes sit under the
# verity root hash and inside the measurement with everything else.
rootfs: builder
	$(RUN) rootfs/build.sh $(OUT)

measure:
	@test -n "$(CPU_FAMILY)$(CPU_MODEL)$(CPU_STEPPING)" || \
		{ echo "set CPU_FAMILY, CPU_MODEL and CPU_STEPPING to the signature the VMM presents to the guest" >&2; exit 1; }
	@for vcpus in $(SHAPES); do \
		$(CARGO) measure \
			--firmware $(OUT)/OVMF.fd \
			--kernel $(OUT)/vmlinuz \
			--cmdline "$$(cat $(OUT)/cmdline)" \
			--vcpus $$vcpus \
			--cpu-family $(CPU_FAMILY) \
			--cpu-model $(CPU_MODEL) \
			--cpu-stepping $(CPU_STEPPING) \
			--image-version $(GUEST_IMAGE) || exit 1; \
	done

check:
	$(CARGO) check --reference $(REFERENCE) --artifacts $(OUT)

# Compares what this build produced against the digests recorded in the input
# lock. This is the step an independent rebuild runs, and disagreement here is
# the finding.
verify:
	@python3 verify.py

clean:
	rm -rf $(OUT) build
