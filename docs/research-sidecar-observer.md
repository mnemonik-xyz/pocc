# Research: availability evidence that the tenant cannot stop

Status: closed, 6 Nov 2026, by decision 49. The owner adopted the first row of candidate
A: the agent runs in a privileged, attested component inside the confidential machine
(SEV-SNP VMPL0 or an SVSM), the **enclave agent** of architecture §2a, and it is the only
evidence authority of the dispute path. The other candidates (a sidecar outside the
machine, a host agent, every observer variant, a third-party meter) are not pursued. The
open points of §2 and the questions of §4 that concern candidate A's first row move to the
Stage 1 prototype; the rest are closed. Recorded 3 Nov 2026 with decision 47. Nothing
below is a design for implementation.

## 1. Problem

The PoCC agent runs inside the tenant's machine (architecture §2a). The tenant can stop
it, block it, or read its key. Decision 47 does not try to prevent this. It makes a
stopped agent end the lease: the seller watches the agent every slot and stops the
machine after `liveness_miss_slots` missed slots. That bounds the seller's loss, but the
lease depends on the tenant leaving the agent alone.

The research goal is evidence of availability with two properties:

| Property | Meaning | In-guest agent today |
|---|---|---|
| T: tenant-proof | The tenant cannot stop, block or change it | No |
| S: seller-proof | The seller cannot forge it (decision 02: the provider proves delivery to the tenant) | Yes, under the Stage 0 assumption |

A candidate is useful only if it has both. T without S gives back the overbilling
problem that PoCC exists to remove.

## 2. Candidate A: a sidecar that cannot be stopped

A sidecar is a measurement component attached to the tenant's machine and outside the
tenant's control.

| Placement | T | S | What it can see | Prerequisites |
|---|---|---|---|---|
| A privileged layer inside a confidential VM: an SEV-SNP VMPL0 service (for example an SVSM), or Intel TDX partitioning | Yes: the tenant's system runs at a lower privilege and cannot stop it | Yes, when the launch measurement covers it and the attestation is checked | That the VM is scheduled and its memory is live; not that the tenant's processes make progress | Stage 1 hardware and cloud support. The pilot cloud has neither (decision 01) |
| A separate sidecar VM or container in the seller's cloud account, next to the tenant's VM | Yes | No, unless it is attested or its output can be checked (candidate B methods) | External signals only: instance state from the cloud API; network reachability, which the tenant can block | An attested image, or checkable output |
| A host agent at the cloud operator, beside the hypervisor | Yes | As far as the cloud is honest | vCPU time and instance state from the hypervisor | The cloud's participation. The pilot cloud takes no part in Warrant |

Open points for candidate A:

- In the VMPL model, the privileged layer runs only when it is invoked. Find out whether
  the tenant's system can starve it without stopping the VM.
- A tenant can still shut down or pause its own VM from inside. That must show as a stop
  of service, not as delivered time.

## 3. Candidate B: an observer

An observer watches the machine from outside and signs or proves what it saw.

| Variant | T | S | Notes |
|---|---|---|---|
| An observer that the seller runs | Yes | No | The seller could report a stopped machine as running. Usable only with an attested key and image, or with output that a third party can check |
| A cloud-state observer with notarised TLS (TLSNotary, zkTLS) | Yes | Yes, as far as the cloud API is honest and the notary protocol is sound | Proves that the cloud's API reported the instance as active at a time, under the cloud's TLS certificate. Proves availability of the instance, not a running guest |
| A third-party observer, for example the agreed meter of the dispute mechanism with its own probes | Yes | As far as that party is honest | Moves trust to the third party; adds no cryptographic check |

## 4. Questions to answer

1. Which property does the buyer pay for: an available instance, or a running guest?
   The answer decides whether observer evidence alone can credit time.
2. The rule that combines sources: credit when the agent's heartbeat is anchored, or also
   when only the sidecar or observer confirms? At which `min_assurance` level?
3. The tenant's own stop: a shut-down or paused instance must end credit in every
   source.
4. Time bounds: sidecar and observer statements need the same bracket as heartbeats. Each
   statement must contain a drand round's random value (not before) and be anchored (not
   after), so that it cannot be produced early or backdated.
5. The witness format: how the meter, and later the guest (X-1), checks the attestation
   or the TLS proof.
6. The cost per slot of an attestation or a TLS proof, measured, not estimated.
7. The effect on SS-12: with a source that has T and S, agent silence alone no longer
   ends the lease. The seller stops when every accepted source is silent.

## 5. Relation to existing decisions

- Decision 47 stays in force until a candidate is adopted.
- Decision 01: Stage 1 hardware is a prerequisite for the privileged sidecar.
- Decision 02: property S is the reason the seller cannot simply run its own meter.
- X-1: a guest that verifies evidence would also verify the evidence of the adopted
  candidate.

## 6. What ends the research

- A written witness design for one candidate, with its time bounds.
- A measured cost per slot.
- A prototype on hardware or a cloud that supports it.
- An owner decision that names the property the buyer pays for.
