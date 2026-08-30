# Hardware attestation

A renter choosing capacity above `open` is asking one question: is this a real
machine with the isolation it advertises, or a string in a database? Prism
answers it with a report signed by the GPU itself. The control plane checks that
report against NVIDIA's signing keys before it will list the machine above
`open`, and a supplier that fails the check keeps the weakest class no matter
what it claims.

Attestation changes who is being trusted. Before, `isolated` rested on a node
describing its own configuration. Now it rests on a specific physical H100
signing a statement the control plane verifies for itself.

## What is live today

Every offer on the network is `open`, and the verifier's material is now half
real.

The trust roots are genuine. `roots/nvidia-device-identity-root.der` is the
`NVIDIA Device Identity CA`, self-signed and verified as such, taken from
NVIDIA's own verifier. `roots/amd-ark-genoa.der` is `ARK-Genoa` fetched from
AMD's key distribution service, self-signed, with the Genoa ASK chaining to it.
Both are pinned by the SHA-256 of their DER encoding.

The GPU measurements are real too. `reference/h100-measurements.json` holds the
21 active slots NVIDIA publishes for driver 580.173.02 in its reference
integrity manifest, keyed by slot index the way a report identifies them. Five
of those slots list more than one legitimate digest, and all of them are
accepted, because collapsing alternatives to a single value rejects cards that
are behaving correctly.

Two honest limits on that. They are what NVIDIA says an H100 on this driver
should report, not values read off our own card, so they check conformance
rather than identity. And the manifest is an XML-signed document whose signature
this verifier does not check yet, so their integrity rests on the transport they
arrived over rather than on NVIDIA's signature.

What is still a placeholder is the SNP side: the launch measurements and the TCB
floor are guesses, so `attested` cannot be earned. `reference/provenance.json` records the state of every
pinned artifact, and a test fails the build if the trust ceiling ever sits above
a rung whose artifacts are still placeholders. The GPU checks below run against those files today. The SEV-SNP rung
above them is specified and gated, and the conditions that would let a lease be
granted `attested` are listed at the end. Read all of it as what a class
requires. None of it describes capacity you can rent today.

## What each class requires

`open` requires a bonded onchain identity. The registry entry must be active,
the bond must meet the minimum, the device key hash must equal the node id, and
the operator wallet, payout wallet and rate must match the offer exactly. A live
tunnel record posted by the access gateway is also required. Brokered capacity
runs without the Prism daemon and without a tunnel, so it stays at `open`
unconditionally.

`isolated` requires everything `open` requires, plus a current attestation
verdict from the control plane. The verdict is issued only when an NVIDIA H100
report satisfies all of the following: its certificate chain validates to the
pinned NVIDIA root, its nonce equals the digest the control plane expects for
that node, its measurements appear in the checked-in reference set, and its
device identity is bound to no other node.

Be precise about what that verdict does and does not establish, because the two
halves of `isolated` are earned differently.

The verdict is hardware evidence. It proves which physical GPU answered and what
firmware it is running, signed by NVIDIA and checked against a pinned root by the
control plane. Nothing the node says about the card is taken on trust.

The Kata VM and the VFIO passthrough are not attested. The node reports its own
isolation posture on a signed heartbeat, and that report is a supplier claim
backed by the bond, not a measurement. A host that passes the GPU to a bare
container while reporting `kata_vfio` would be caught by nothing in this
document. Closing that gap needs a launch measurement of the machine the renter
is actually served from, which is what `attested` is for.

`attested` requires everything `isolated` requires, plus a verified AMD SEV-SNP
report taken by the guest that ran the lease. It is not served. The rung is
specified below, along with the three things that have to be true before it can
be granted.

`confidential` requires everything `attested` requires, plus an NVIDIA CC-mode
report showing VRAM encryption active and the GPU locked into a confidential
state, bound to the same lease. It is not served, and no verifier for it exists.

## The challenge

The control plane generates a random challenge for a node, records it against
that node id, and accepts it once. The node asks the GPU for a report whose
nonce is `SHA-256(challenge_nonce || node_id || device_public_key)`, then posts
the report on a signed submission to a dedicated endpoint. The control plane
recomputes that digest from the challenge it issued and the identity of the node
presenting it, and compares.

Two attacks close on that binding, and one does not.

A captured report cannot stand in for a fresh one against a different identity.
The digest commits to the node id and device key of the node presenting the
report, so evidence issued for one node produces a nonce mismatch at another.

A captured report cannot be replayed. A challenge is single use and short lived,
so a second presentation of the same report finds its challenge already
consumed.

What the binding does not close is a node forwarding its own nonce to a genuine
H100 somewhere else and presenting the answer. The report would be valid and the
nonce would be correct, because a GPU signs whatever nonce it is handed. This is
the ordinary limit of device attestation: it proves a real card answered, not
that the card is in the machine that answered. Two things bound it rather than
close it. A verified device identity is recorded under a unique index, so one
physical GPU backs one node id and an operator must hold a real H100 per node
they want to present. And the node stays bonded, so the claim carries a stake.
A launch measurement taken by the guest does not close it either, for the reason
given under [what `attested` does not cover](#what-attested-does-not-cover).

Attestation travels on its own submission rather than on the 30-second
heartbeat. The bytes a node signs for telemetry are unchanged, so every node
already in the field keeps signing exactly what it signed before, and a
multi-kilobyte certificate chain never rides a loop with a 15-second timeout.

## What the verifier checks

Verification is a full certificate chain walk in ECDSA P-384 over SHA-384, from
the report signature up through the device certificate to an NVIDIA root
certificate pinned in this repository by the SHA-256 digest of its DER encoding.
The root is not fetched at verification time, so substituting a root is not a
path into the network.

Any of these ends verification with no verdict, and no verdict means no class
above `open`:

- the chain does not terminate at the pinned root, or any signature in it fails;
- a certificate is outside its validity window at the time of the check;
- the report signature does not verify under the key in the leaf certificate;
- the nonce in the report is not equal to the expected digest;
- the challenge is unknown, expired, or already consumed;
- a reported measurement is absent from the reference set;
- the attested device identity is already bound to a different node id.

There is no partial credit. A node whose evidence fails simply holds the class
its remaining evidence supports, which is `open`.

## A verdict expires

A verdict is good for 24 hours. After that the node falls back to `open` until
it answers a fresh challenge. The class is applied when a quote is issued and
checked again when funding is confirmed, so a verdict that lapses between the
two does not leave a renter paying for a class the machine no longer holds.

## One GPU backs one node

The attested device identity is recorded under a unique index. A second node id
presenting the same physical GPU is refused, which stops one card from earning
`isolated` for several bonded identities at once.

## What an H100 report does not prove

It proves which GPU is present, that it is genuine NVIDIA silicon, and what
firmware that GPU is running. It says nothing about the host around it: which
kernel booted, what the hypervisor is doing, or whether the operator attached a
debugger to the workload. That is a different measurement rooted in a different
vendor's keys, and it is what `attested` is about.

## `attested` measures the guest, not the host

Earlier versions of this document called `attested` a host launch measurement.
That was wrong, and the error matters because it names the wrong party as the
one being trusted. SEV-SNP has no host measurement at all. Its threat model
assumes the hypervisor is hostile, and everything it signs describes a guest:
the image that guest launched from, the policy it launched under, and the 64
bytes that guest chose when it asked for the report. A guest report is therefore
worth more to a renter than a host report would have been, because it survives a
host that is lying, and it is also narrower, because it says nothing about the
machine around the guest.

## What a verified SNP report binds

A report that passes verification proves the following, and stops there.

- **Measurement.** A genuine AMD processor ran `SNP_LAUNCH` over an initial
  guest image, and `MEASUREMENT` is the digest of that image's page contents,
  guest physical layout, page types and per-vCPU VMSA.
- **Policy.** The guest ran under the policy in the report. Debug disabled means
  the host cannot use the PSP debug interface to read or write guest memory.
- **TCB.** The processor was at the TCB version encoded in the VCEK that signed
  the report, and `REPORTED_TCB` must sit at or above a pinned floor for the
  product line.
- **Chip identity.** `CHIP_ID` names the physical processor, and the VCEK's
  HWID extension has to equal it.
- **Report data.** `REPORT_DATA` is 64 bytes the guest chose at request time.
  It is the only freshness and binding channel the structure has.
- **Host data.** `HOST_DATA` is 32 bytes the host fixed at launch and cannot
  change afterwards.
- **The chain.** VCEK to ASK to ARK, with the ARK pinned in this repository per
  product line, the VCEK's HWID extension equal to `CHIP_ID`, and its four SVN
  extensions equal to `REPORTED_TCB`. Without all of that the chain proves
  nothing about this report.

## Why the report comes from the lease's own guest

A node-level SNP report, taken on a schedule the way the GPU report is, would be
a farmable badge. An operator boots the blessed VM once a day, harvests the
verdict, and then serves the renter from a bare container with the GPU on the
host. Every byte of that report is genuine and nothing in it contradicts the
substitution, because SNP reports describe the guest that asked, and that guest
is not the one the renter is in.

The construction that survives a hostile host is the other one. The guest that
runs the renter's workload takes its own report after boot, and `REPORT_DATA`
is the digest of the control plane's challenge, the lease id, and the public
half of the SSH host key that guest generated during boot. The control plane
refuses to release the access grant for a lease quoted above `isolated` until
that verdict exists. Because the fingerprint the renter connects to is inside
the report, the report is about the session they are in, not about a machine
that booted correctly earlier that day.

Node-level SNP evidence still has a use, and it is a smaller one. A signed
report of what the host's CPU supports establishes that a machine can serve the
class. It never grants it.

## What ends an SNP verification

Any of these ends verification with no verdict, and no verdict means the lease
holds the class its remaining evidence supports:

- the chain does not terminate at the pinned ARK for the product line, or any
  signature in it fails;
- the VCEK's HWID extension is not equal to `CHIP_ID`, or its SVN extensions are
  not equal to `REPORTED_TCB`;
- the report signature does not verify under the VCEK;
- `REPORT_DATA` is not the digest expected for this challenge, this lease id and
  the SSH host key presented with it;
- the challenge is unknown, expired, or already consumed;
- `MEASUREMENT` is absent from the reference set for the machine shape the lease
  was scheduled at;
- the guest policy allows debug, or falls below the pinned policy floor;
- `REPORTED_TCB` is below the pinned floor;
- `HOST_DATA` does not commit to the image digest the lease was quoted for.

There is no partial credit here either.

## What `attested` does not cover

The honest sentence for the rung: the workload ran in a virtual machine launched
from an image whose measurement we published and anyone can recompute, on a
genuine AMD processor at or above a pinned patch level, with host debug
disabled, running the container digest the renter asked for, and the SSH host
key they connected to was generated inside that machine. What ran is checkable.
Who was watching is not.

**Secrecy.** CPU memory is encrypted and GPU memory is not. Every tensor bound
for a passthrough device leaves the encrypted region through shared bounce
buffers, so weights and activations sit in host-readable memory and VRAM is
plaintext. An attested lease gives integrity of what booted. It gives no
confidentiality of what is computed, which is what `confidential` is for.

**The channel.** The attested channel is SSH end to end, because the host key it
terminates on is the one inside the report. Jupyter reaches the guest through
the access relay, which terminates TLS outside the guest, so a Jupyter session
is not covered by the report and must not be described as if it were.

**The GPU relay.** A hostile host can still emulate the H100 to the guest and
proxy SPDM to a real card elsewhere. SNP does not pull PCIe devices into the
guest's trust boundary without TDISP and IDE, which this hardware generation
does not offer. One chip backs one node and one card backs one node, both by
unique index, which bounds the substitution rather than closing it.

**Availability.** The host still controls scheduling, power, the network path,
and whether the VM launches at all. A refusal is a refund rather than a security
failure, but it does mean availability is never attested.

**Host data is a host input.** `HOST_DATA` is meaningful only because the
measured guest agent refuses to run anything but the image it names. If the
guest-side image pull and that agent policy are not both live, the report is
genuine and the workload image is unverified, and the class must not be claimed.

**Client enforcement.** The access grant carries the SSH host key fingerprint
from the report, and the renter's client has to pin it. A client that
auto-accepts the host key makes the binding decorative. Exposing the fingerprint
is Prism's job; enforcing it is the client's, and the clients Prism ships do it:
`@prismnetwork/agent-sdk`, `prismnetwork`, `@prismnetwork/mcp` and the inference
gateway read the key off the wire, compare it to the fingerprint on the grant,
and refuse the session if it differs. Anything else you connect with has to make
the same comparison, or the report covers a machine you are not talking to.

**Our verifier.** The chain walk runs in the control plane, so `attested` means
we checked it, not that the renter did. [SECURITY_MODEL.md](SECURITY_MODEL.md)
covers the zkVM route for removing us from that set.

**One CPU generation.** TCB semantics are pinned to Genoa. Turin changed the
`TCB_VERSION` encoding, so a second CPU generation needs its own ARK, its own
floor and its own measurement set rather than a widened one. The reference set
is also per vCPU count and per CPU family, model and stepping, because the VMSA
feeds the launch digest: changing the machine shape changes the expected
measurement, and an operator who cannot match a published shape cannot serve the
class.

## What has to be true before `attested` is served

The hardware is in place. The bare metal runs SEV-SNP host support with the RMP
table initialised, IOMMU SNP support enabled, and the H100 bound to `vfio-pci`
in its own IOMMU group. The missing kernel support that used to block this class
is no longer the obstacle. Three things still gate it, and all three are
observable rather than argued.

1. The expected launch measurement is computed from inputs recorded with their
   digests, and reproduced by someone who did not build the image. It is never
   read off a report from the machine being attested, because observing a
   measurement certifies whatever happened to boot.
2. A genuine Genoa report from real hardware verifies as a checked-in test
   vector.
3. The access gate refuses to hand a renter credentials for a lease quoted above
   `isolated` when no lease-bound verdict exists, proven by a test that funds
   such a lease and gets nothing.

`MAX_VERIFIABLE_TRUST_CLASS` in `prism-protocol` clamps every served class to
`isolated` until then. A passing SNP report earns `Attested`, because that is
what the evidence is worth, and `class_for_lease` clamps the lease back to
`isolated`, because that is what the network can substantiate. The ceiling moves
when the evidence exists and not when the hardware capable of producing it
arrives, which is the same rule as before and now cuts the other way: the
hardware is here and the ceiling has not moved.

## Asking for a class

Filter offers:

```bash
curl "https://api.prismnetwork.tech/v1/offers?min_trust=isolated"
```

Require it on a lease, so the decision is made before money moves:

```js
await agent.quote({ image, durationSeconds: 3600, minTrustClass: "isolated" });
```

If no online bonded offer holds that class, the quote is refused with `no_match`
and no escrow is touched. If capacity exists at that class but every machine is
busy, the answer is `capacity_reserved` instead, which is a different situation:
one clears on its own, the other needs supply. A request for `attested` or
`confidential` is refused today for the first reason.

Vault items carry the weakest class of workspace they may be released into, and
new items default to `confidential`, above anything the network serves. Handing
one to today's capacity is refused rather than quietly allowed. See
[VAULT.md](VAULT.md).

## What ends up in the receipt

The receipt for a lease records the trust class it settled under and, when a
verdict backed that class, a digest of the verdict. Raw reports are never
published, because a report carries a device serial that would identify the
host. See [PROOF_SPEC.md](PROOF_SPEC.md) for the receipt format and
[SECURITY_MODEL.md](SECURITY_MODEL.md) for what each class does and does not
promise.
