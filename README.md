# PoCC — Proof of Cloud Compute

A proof of concept for proving that ordered cloud compute was delivered for the
time it is billed, without trusting the provider's meter, and for paying only
for proven hours through [Warrant](https://github.com/mnemonik-xyz/warrant).

- **Stage 0** (this build) runs on any OpenStack cloud, including amnezia.cloud,
  without hardware attestation.
- **Stage 1** adds an AMD SEV-SNP boot report when such hosts are available.

Read [docs/architecture.md](docs/architecture.md) for roles, diagrams and the
proving cycle, [docs/run-stage0.md](docs/run-stage0.md) to run a cycle on OpenStack, and
[docs/live-test-plan.md](docs/live-test-plan.md) for the live test on amnezia.cloud
(reproducible with `scripts/live-test.sh`).

[docs/warrant-integration.md](docs/warrant-integration.md) is the proposal for
making PoCC the meter of Warrant's rent case; [docs/decisions.md](docs/decisions.md)
logs every design decision with its alternatives and reversal cost.

## How it works, in one paragraph

The tenant signs a request that carries a Warrant rent policy. The provider signs
an order bound to that request. An agent inside the VM binds itself to the order
at boot, then signs a chained heartbeat on every shared 60-second drand slot. A
notary anchors one Merkle root per slot for all VMs on a chain, which fixes when
each heartbeat existed. The verifier checks the chain, the beacon values and the
anchors, credits only unbroken time, and signs hourly usage records that Warrant's
escrow accepts as delivery evidence.

## Components

| Binary | Role |
|---|---|
| `pocc-agent` | Runs in the VM: boot proof, heartbeats, final heartbeat |
| `pocc-notary` | Batches entries per slot, anchors roots, serves proofs |
| `pocc-verify` | Checks a receipt, prints the verdict, signs usage records |
| `pocc-broker` | Signs requests and orders, provisions on OpenStack, assembles receipts |

## Build and test

```sh
go build ./...
go test ./...
```

Go 1.24 or later. The core has no third-party dependencies.

## Status

Work in progress. See the status table in
[docs/architecture.md](docs/architecture.md#7-repository-layout-and-status).
