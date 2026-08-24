import type { Metadata } from "next";
import Link from "next/link";
import { InformationPage, InformationSection } from "@/components/information-page";

export const metadata: Metadata = {
  title: "Serving leases from a machine you already own",
  description:
    "Run a Prism node on a stock Ubuntu machine with a consumer GPU, serve open-class leases, and let the card work between them.",
  alternates: { canonical: "/docs/open-mode" },
};

export default function OpenModePage() {
  return (
    <InformationPage
      eyebrow="Docs / Node operators"
      title="Serving leases from a machine you already own"
      description="Open mode leaves the GPU with the host driver and runs the renter's workload in a container with the card attached. No IOMMU work, no separate guest, so a gaming rig or a single-card workstation can serve leases on the same day it is set up."
    >
      <InformationSection index="01" title="What the renter is told">
        <p>
          The operator of an open node can read everything the workload touches. That is what the{" "}
          <code>open</code> <Link href="/learn/trust-classes">trust class</Link> states, and it is
          why a renter who needs more sets a minimum class and never reaches this node.
        </p>
        <p>
          A rig that only earns while leased sits idle most of the day, so the node daemon can run
          one workload of the operator&apos;s choosing between leases and take the card back before
          a lease starts. The idle workload section below covers it.
        </p>
      </InformationSection>

      <InformationSection index="02" title="What the host needs">
        <ul>
          <li>Ubuntu 24.04 x86-64 with root access.</li>
          <li>An NVIDIA GPU with the vendor driver installed and <code>nvidia-smi</code> working.</li>
          <li>
            <code>127.0.0.1:2222</code> and <code>127.0.0.1:8888</code> free. A lease binds both,
            and one lease runs per host.
          </li>
          <li>A wallet holding PRISM for the refundable bond and gas on Robinhood Chain.</li>
        </ul>
        <p>
          The install script shipped with the node source, <code>deploy/node/install.sh</code>,
          installs containerd, nerdctl, the CNI plugins and the NVIDIA Container Toolkit, creates
          the service accounts and their directories, and writes the node&apos;s environment file
          with <code>PRISM_ISOLATION=shared</code>. Values already in the file are left alone, so
          re-running it after an edit is safe. It reads no key material and posts no bond. nerdctl
          and the CNI plugins come from pinned releases checked against a recorded SHA-256; the
          toolkit comes from NVIDIA&apos;s apt repository, whose signing key is matched against a
          fingerprint before anything trusts it.
        </p>
        <p>Build and install the daemon, then run preflight:</p>
        <pre>{`cargo build --release --package prismd
install -o root -g root -m 0755 target/release/prismd /usr/local/sbin/prismd
prismd preflight --isolation shared`}</pre>
        <p>
          The shared baseline is Linux on x86-64, containerd, nerdctl, nftables,{" "}
          <code>nvidia-smi</code>, <code>nvidia-container-cli</code>, at least one host-visible
          NVIDIA GPU, both loopback ports bindable, and a forwarding policy that lets container
          traffic out. Kata, IOMMU, VFIO and disabled swap are not required. Docker on the same
          host sets the iptables forwarding policy to drop; preflight fails on this and prints the
          rule to add.
        </p>
      </InformationSection>

      <InformationSection index="03" title="Choosing the card">
        <pre>{`nvidia-smi --query-gpu=index,uuid,name,memory.total --format=csv`}</pre>
        <p>
          With one card visible, leave <code>PRISM_GPU_UUID</code> unset. With several, set it. The
          daemon refuses to start rather than guess which card it is selling. A card bound to{" "}
          <code>vfio-pci</code> for a gaming VM is invisible here; preflight warns about it and
          carries on as long as one card is left for the host.
        </p>
      </InformationSection>

      <InformationSection index="04" title="Identity, bond and enrollment">
        <p>
          These are the same steps every node takes: create a device identity, register the bond
          onchain, enroll with the network. Two things differ here. Enroll with the model and VRAM
          of the card you are actually serving, read from <code>nvidia-smi</code>; enrolling an
          H100&apos;s numbers against a 4090 is a signed statement the dispute process can act on.
          And the class published is <code>open</code>, so price against that: a renter paying for
          open capacity is paying for a bonded identity and metered billing, and a rate borrowed
          from an isolated node will lose every quote it enters.
        </p>
        <p>
          The node daemon builds from the Prism source tree. While repository access is limited,
          operators joining the pilot get the source and direct setup support.{" "}
          <Link href="/contact">Contact us</Link> to take part.
        </p>
      </InformationSection>

      <InformationSection index="05" title="The idle workload">
        <p>
          Point <code>PRISM_IDLE_CONFIG</code> at a JSON file, conventionally{" "}
          <code>/etc/prismd/idle.json</code>. No config means the feature is off, which is the
          default. The file is refused if it is group- or other-writable. The daemon can run the
          process itself:
        </p>
        <pre>{`{
  "argv": ["/usr/local/bin/miner", "--pool", "stratum+tcp://pool.example.com:3333"],
  "user": "prismd-idle",
  "working_directory": "/var/lib/prismd/idle",
  "environment": { "MINER_PASSWORD": "x" },
  "stop_grace_seconds": 30,
  "gpu_release_seconds": 20
}`}</pre>
        <p>Or systemd runs it and the daemon starts and stops the unit:</p>
        <pre>{`{ "systemd_unit": "miner.service", "stop_grace_seconds": 30, "gpu_release_seconds": 20 }`}</pre>
        <p>
          <code>argv</code> is an argument list. A shell line is refused, so quoting mistakes
          cannot turn into a command. <code>argv[0]</code> has to be an absolute path to a regular
          file that is not group- or other-writable. <code>user</code> is required and cannot be
          root. Pool credentials belong in <code>environment</code>, where they stay out of{" "}
          <code>ps</code> output and out of unit files. The miner binary cannot live under{" "}
          <code>/home</code>: the service hides it from anything the daemon spawns, so install the
          binary in <code>/usr/local/bin</code> or <code>/var/lib/prismd/idle/bin</code>, or
          describe it as a systemd unit and let systemd supervise it.
        </p>
        <p>
          Output goes to <code>/var/lib/prismd/idle-state/idle.log</code>, capped at 8 MiB per
          file with one older copy kept, so at most 16 MiB. A workload that exits keeps restarting
          on a backoff that starts at five seconds and doubles to five minutes.
        </p>
      </InformationSection>

      <InformationSection index="06" title="Prove the handover before you bond">
        <pre>{`prismd idle-check --idle-config /etc/prismd/idle.json`}</pre>
        <p>
          This starts the configured workload, waits until the card reports a compute process,
          then runs the exact stop sequence a lease runs. It prints the measured time to exit and
          time to a free GPU against the grace values you configured. A miner that ignores the
          stop signal, or that holds GPU memory for a while after it exits, shows up here instead
          of on a lease somebody paid for. It passes only when the workload stopped inside both
          allowances; raise them until it passes with room to spare.
        </p>
      </InformationSection>

      <InformationSection index="07" title="What a lease does to the workload">
        <p>
          The workload&apos;s process group gets the stop signal, then up to the configured grace
          to exit, then a kill. The card is polled until no compute process holds it. A missing{" "}
          <code>nvidia-smi</code>, a non-zero exit or output that will not parse all count as
          busy: the check fails closed, because handing a renter a card another process still
          holds is worse than failing the lease.
        </p>
        <p>
          If the card is still busy when the deadline runs out, the lease fails and says so. The
          daemon then stops restarting the workload and stops publishing telemetry, so the
          node&apos;s offer ages out of matching within about ninety seconds. A wedged driver
          costs one lease and then goes quiet. Both resume after two consecutive readings show the
          card free. After teardown and settlement the workload starts again on its own, and
          before every start the daemon checks for a live lease container, so a daemon that
          restarted mid-lease waits rather than mining on top of a renter.
        </p>
      </InformationSection>

      <InformationSection index="08" title="What has not been proven on this hardware yet">
        <p>
          The workspace image ships NVIDIA userspace matched to the isolated path&apos;s guest
          kernel. On an open node the toolkit bind-mounts the host&apos;s driver libraries into
          the container instead, and if the CUDA library resolves to a mismatched pair on your
          driver, the container starts and CUDA inside it fails. There is no driver-free workspace
          image published today, so match the host driver to the one the image was built against,
          and run a short lease against your own node to confirm CUDA works inside the workspace
          before you advertise it.
        </p>
        <p>
          A batch command served from an open node carries the operator&apos;s word for what ran.
          Nothing in the class proves the output came from the command as written.
        </p>
      </InformationSection>
    </InformationPage>
  );
}
