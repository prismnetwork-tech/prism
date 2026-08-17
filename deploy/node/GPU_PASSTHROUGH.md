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
