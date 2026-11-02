# Rent guest benchmark

Measures the zkVM work of the rent case per hour of service: one usage record
signature and one note signature (64-byte secp256k1 over sha256 of the tagged
bincode encoding), the note's binding to the record hash, and gates D4, D5, D8 and
D9 (PE-0 sections 3 and 4). With `BATCH_SIG=1` the meter signs the batch's records
once instead of each record (decision 44). The batch-level checks of the real guest
(policy, credential, request, journal) are O(1) per batch and are not modelled.

Requires the RISC Zero 3.0.5 toolchain (`rzup install`), the same pinned
`k256`/`sha2` accelerator patches as `policy-execution/methods/guest`, and its
`Cargo.lock` for compatible guest dependencies.

```sh
cargo build --release
./target/release/rent-bench execute 1 6 24 168   # cycles per batch size
BATCH_SIG=1 ./target/release/rent-bench execute 1 6 24 168
./target/release/rent-bench prove 24             # succinct proof + Groth16 wrap, both verified against the image; needs a prover host
./target/release/rent-bench load 4 24            # four 24-hour batches proved at once: throughput and per-batch latency (DL-13)
```

`prove` and `load` measure what settles: a succinct receipt, its Groth16 wrap and
verification against the pinned image; never a composite receipt. Results of 2 Nov
2026 are in `../../docs/measurements.md`.
