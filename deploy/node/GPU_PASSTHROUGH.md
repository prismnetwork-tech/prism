# Handing a GPU to a Kata guest

What `isolated` rests on: the host gives the card up entirely, and the renter's
workload runs in a virtual machine that holds it exclusively. This is how that
was made to work on the reference node, and the parts that are not obvious.

Proven on an AMD EPYC 9124 with an H100 PCIe 80GB, Ubuntu 24.04, Kata 4.0.0.
The result looks like this, and the two kernels are the point:

    host   7.0.0-29-generic        GPU driver in use: vfio-pci
    guest  6.18.35-nvidia-gpu      NVIDIA H100 PCIe, 81559 MiB, driver 595.58.03

## Give the card to vfio-pci

Bind by device id rather than by slot, and blacklist `nouveau`, which claims the
card during boot before anything else gets a chance:

    /etc/modprobe.d/prism-vfio.conf
      options vfio-pci ids=10de:2331
      softdep nvidia pre: vfio-pci
      softdep nouveau pre: vfio-pci

    /etc/modules-load.d/prism-vfio.conf
      vfio
      vfio_iommu_type1
      vfio-pci

Kernel command line needs `amd_iommu=on iommu=pt`. Confirm with
`lspci -k -s <bdf>` reporting `vfio-pci`, and a numbered group under `/dev/vfio`.

## Use the GPU guest image, and make it the default

This is the step that costs a day if you miss it. A plain Kata guest has no
NVIDIA driver, so the agent inside it waits for a device spec that nothing will
ever write, and every launch dies with:

    failed to inject devices after CDI timeout of 100 seconds

The error names CDI, which sends you looking at CDI specs on the host. Writing
one changes nothing. The injection happens inside the guest, and the fix is a
guest that has the driver: `kata-containers-nvidia-gpu.img`, shipped in the same
release, along with `configuration-qemu-nvidia-gpu.toml`.

Selecting it is its own trap. Kata resolves its configuration from the shim
name, and a second containerd runtime pointing at the GPU config is ignored:
`ConfigPath` in the runtime options does not reach it, a renamed shim symlink
does not either, and `KATA_CONF_FILE` is refused outright with "only shipped
Kata configuration files are accepted". What works is the standard override
path, which on a node whose whole job is GPU leases is also the honest default:

    cp /opt/kata/share/defaults/kata-containers/configuration-qemu-nvidia-gpu.toml \
       /etc/kata-containers/configuration.toml

Check which one actually loaded before believing anything, because Kata falls
back silently:

    journalctl -t kata | grep -oE 'configuration[a-z-]*\.toml|kata-ubuntu[a-z0-9.-]*\.image'

## The same error, a different cause

A card left in confidential mode fails identically. The guest image is right,
the driver is present, and the launch still dies on the CDI timeout, because a
CC-mode card refuses to attach outside a confidential guest and the driver
gives up before anything writes a device spec. Read the guest's own console
rather than the host log, which says nothing about it:

    NVRM: GPU0 confComputeConstructEngine_IMPL: CPU does not support confidential compute.
    NVRM: osInitNvMapping: *** Cannot attach gpu
    NVRC panic: /bin/nvidia-ctk failed with status: exit status: 1

Nothing on the host reports the mode either once the card is on `vfio-pci`, so
ask the card:

    python3 ./nvidia_gpu_tools.py --gpu-bdf=<bdf> --query-cc-mode
    python3 ./nvidia_gpu_tools.py --gpu-bdf=<bdf> --set-cc-mode=off \
      --reset-after-cc-mode-switch

The mode is persistent across reboots, so a node that once served confidential
guests keeps refusing ordinary ones until it is switched back. `isolated` and
`confidential` are exclusive settings of the same card, not layers.

Getting the console at all takes connecting to the socket while the VM is up;
it lives at `/run/vc/vm/<sandbox>/console.sock` and the shim does not copy it
into the journal.

## Settings the card forces

`cold_plug_vfio = "root-port"`, so the workload never observes a machine without
its device. `pcie_root_port = 1`, or root-port cold plug has no port to use.
`create_container_timeout` well above the default 60 seconds: the H100 has a
128 GB prefetchable BAR and the guest is still enumerating it when the default
gives up.

## containerd 2.x

The config is `version = 4` and the runtime table is single-quoted:

    [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata]
      runtime_type = 'io.containerd.kata.v2'
      privileged_without_host_devices = true

## Kernel

SEV-SNP host support arrived in Linux 6.11, so 24.04's stock 6.8 cannot do it;
`linux-generic-hwe-24.04` brings 7.0.0 and `kvm_amd: SEV-SNP enabled` with it.

The vendor `bnxt_en` DKMS module fails to build against 7.0.0. Removing it is
safe because the in-tree driver covers the BCM57416, and leaving it broken
blocks the whole package configuration.

Boot a new kernel as a one-shot with the old one still `GRUB_DEFAULT`:

    grub-reboot "<advanced-menu-id>>gnulinux-<version>-advanced-<uuid>"

On remote bare metal a NIC driver that fails takes the machine with it, and an
unattended reboot is the only way back that does not involve a support ticket.

## What this does not give you

The renter's isolation, not their secrecy. The host cannot use the card while
the guest holds it, but the operator still runs the hypervisor and can inspect
guest memory. Closing that needs a launch measurement, which is `attested`.

GPU attestation reports need confidential computing mode on the card, which
reports `CC status: OFF` by default and is not enabled by any of the above.
Until it is on, there is no NVIDIA-signed report to verify and the trust roots
in `crates/attestation` stay placeholders.

## Confidential guests

The same node runs the workload inside an SEV-SNP guest with the GPU attached,
which is what `confidential` describes. From inside such a guest:

    Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP
    nvidia-smi conf-compute -f  ->  CC status: ON

Three things have to line up, and each fails differently.

**Confidential mode on the card.** `nvidia-smi conf-compute -srs` is the ready
state, not the mode. The mode lives on the card and is set with NVIDIA's
`gpu-admin-tools`:

    python3 ./nvidia_gpu_tools.py --gpu-bdf=<bdf> --set-cc-mode=on \
      --reset-after-cc-mode-switch

Once it is on, the host's own `nvidia-smi` reports no devices. That is the mode
working, not a fault: a CC-mode card refuses to serve anything outside a
confidential guest, which also means the plain Kata path above stops getting a
GPU.

**IOMMUFD, not the legacy VFIO group.** A confidential guest refuses
`/dev/vfio/<group>` with "ConfidentialGuest needs IOMMUFD". Load `iommufd` and
pass the cdev instead:

    modprobe iommufd            # creates /dev/iommu
    --device /dev/vfio/devices/vfio0

**Guest pull, and the annotation it needs.** A confidential guest will not mount
a rootfs the host prepared, because trusting the host is the thing it exists to
avoid. It pulls its own image, which needs
`experimental_force_guest_pull = true`. Outside Kubernetes that then fails with
"Failed to get image name from annotation", because the image name normally
arrives from CRI. Supply it directly:

    nerdctl run --annotation io.kubernetes.cri.image-name=<full image ref> ...

Confirm it is genuinely confidential rather than a plain VM that happened to
boot. The guest's own dmesg is the authority, and the QEMU line should carry
`-object sev-snp-guest`:

    journalctl -t kata | grep -oE '\-object [a-z-]*'

## What is still missing for `attested`

The guest cannot take an SNP attestation report yet. Kata's guest kernel has no
`sev-guest` driver and no `/sys/kernel/config/tsm`, so there is no interface to
ask the PSP for one. Encrypted memory is running; the evidence that proves it to
someone else is not available. That needs a guest kernel built with
`CONFIG_SEV_GUEST`, or the CoCo attestation agent inside the guest image.
