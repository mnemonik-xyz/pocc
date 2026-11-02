# Handoff PC-8: measure the rent guest with no record or note signatures

Status: ready to execute. Blocked by nothing.
Repository: `mnemonik-xyz/pocc`. Base branch: `docs/decision-46-signatures-in-solidity`.
Work branch: `bench/pc-8-attested`. Open a draft pull request into the base branch.

## 1. Goal

Decision 46 (proposed) moves the verification of the hourly record and note signatures
out of the zkVM guest and into the settle transaction. The owner decides on 46 from
measured numbers only. This package produces those numbers for the guest side:

- zkVM cycles of the guest without the record and note signature checks, for batches of
  1, 6, 24 and 168 hours;
- the same, measured the same way, for the two current forms, so all three compare
  like for like;
- if a prover host is available: proving time, wrap time and peak memory for a 24-hour
  batch in all three forms.

The second half of 46 (gas on chain) is PE-9a, a separate handoff. Do not do it here.

## 2. Read first

| File | Why |
|---|---|
| `docs/decisions.md`, entries 43, 44, 45, 46 | What is being decided and why; 46 has the byte formats |
| `docs/measurements.md` | How the 2 Nov numbers were taken; you append a new section in the same style |
| `bench/rent-guest/README.md` | Toolchain and commands |
| `bench/rent-guest/bench-core/src/lib.rs` | The guest's work; you change this |
| `bench/rent-guest/host/src/main.rs` | The input generator and runner; you change this |

## 3. Toolchain

RISC Zero 3.0.5 through `rzup` (r0vm 3.0.5; guest toolchain Rust 1.88.0,
`riscv32im-risc0-zkvm-elf`). The guest's `Cargo.toml` pins patched `k256`, `sha2` and
`crypto-bigint`; keep those patches. `cargo build --release` in `bench/rent-guest`.

Machines:

- Cycle counts (`execute`): any x86-64 or arm64 box with 2 vCPU and 8 GB. Required.
- Proving (`prove`): at least 32 GB RAM; the Groth16 wrap needs x86-64 with Docker. An
  8 GB box is killed by the memory cgroup on `prove 1`. Optional; if you have no such
  host, say so in the results and stop after the cycle counts.

## 4. Changes

### 4.1 Three modes, chosen by environment variable

| Variable | Mode | Record signatures | Note signatures | Batch signature |
|---|---|---|---|---|
| none | `per-record` (today's default) | checked | checked | none |
| `BATCH_SIG=1` | `batch` (decision 44) | empty, not checked | checked | checked |
| `ATTESTED=1` | `attested` (decision 46) | empty, not checked | empty, not checked | none |

`BATCH_SIG` and `ATTESTED` together is an error. Replace `Input::batch_signature:
Option<Vec<u8>>` with an explicit `mode` enum plus the optional batch signature, so the
guest cannot infer the mode from empty vectors.

### 4.2 The credential signature, in all three modes

The real guest checks one seller credential signature per batch, and keeps it under 46.
The bench leaves it out today, so the 46 numbers would be about 330,000 cycles too
optimistic. Add it to all three modes:

- `Input` gains `registry_key: Vec<u8>` (compressed SEC1) and `credential: (Vec<u8>,
  Vec<u8>)`: an opaque 160-byte body and its 64-byte low-s signature over
  `tagged_bytes(b"warrant/credential/v1", &body)`.
- `check` verifies it once, before the loop, with the existing `verify`. Error
  `"credential signature"`.

Because this changes the `per-record` and `batch` numbers, re-measure them. Do not
compare against the 2 Nov table.

### 4.3 What `attested` computes and commits

In `attested` mode, `check` does everything it does today except the two signature
checks in the loop. It additionally computes:

1. `meter_addr` and `acceptance_addr`: for each compressed key,
   `VerifyingKey::from_sec1_bytes(key)` (error if it fails), then
   `to_encoded_point(false)`, drop the leading `0x04`, `keccak256` over the 64 bytes
   `X_be32 ‖ Y_be32`, take the last 20 bytes. Use the `sha3` crate (`Keccak256`), added
   to the workspace and the guest manifest, `default-features = false`.
2. `facts_hash`, exactly:

   ```text
   blob_r(k) = tagged_bytes(b"warrant/usage/v1", &record_k)        // the bytes the meter signs
   blob_n(k) = tagged_bytes(b"warrant/acceptance/v1", &note_k)     // the bytes the buyer signs
   body      = u32_le(n) ‖ for k: u32_le(len(blob_r(k))) ‖ blob_r(k)
             ‖ u32_le(m) ‖ for k: u32_le(len(blob_n(k))) ‖ blob_n(k)
   facts_hash = sha256( u64_le(22) ‖ "warrant/facts-batch/v1" ‖ u64_le(len(body)) ‖ body )
   ```

   `n` is the number of records, `m` the number of notes, both in input order. The outer
   framing is the same as `tagged_bytes` but over raw bytes, not bincode: write it by hand,
   do not call `tagged_bytes(tag, &body)`, which would bincode-encode `body` (a `Vec<u8>`)
   and add a length prefix.

The guest commits, in all modes, `(total: u64, records_commit: Hash, facts_hash: Hash,
meter_addr: [u8; 20], acceptance_addr: [u8; 20])`. In the two signed modes, also compute
them, so the only difference between the modes is the signature work. Update the host's
journal decode and its assertion against the native `check`.

### 4.4 Host input

`input(hours, mode)` generates as today. In `attested` mode, record and note signatures
are empty vectors. Add the credential with a third key (`key(11)`). Keep the
deterministic keys and constants so runs are reproducible.

## 5. Tests (native, `cargo test -p bench-core`)

1. Address vector: the key with private scalar 1 has address
   `0x7e5f4552091a69125d5dfcb7b8c2659029395bdf`. The wrong derivation with the `0x04`
   prefix gives `0x7d6e99bb8abf8cc013bb0e912d0b176596fe7b88`; assert you do not get it.
2. `facts_hash` vector: a 2-hour input from `input(2, attested)`. Print the hex and pin
   it in the test. PE-9a's Solidity must reproduce this value, so put the input bytes
   and the hash in `test/vectors/rent-facts-v1.json`: for each record and note the blob
   hex, its 65-byte recoverable signature hex (sign with
   `sign_prehash_recoverable(&sha256(blob))`, `v = 27 + recovery_id`, low-s; check it
   with `VerifyingKey::recover_from_prehash`), the two addresses and `facts_hash`.
3. The three modes return the same `total`, `records_commit`, `facts_hash` and
   addresses for the same records and notes.
4. `attested` with a wrong `credential` signature fails. `per-record` with a flipped
   byte in one record signature fails.

## 6. Runs

```sh
./target/release/rent-bench execute 1 6 24 168
BATCH_SIG=1 ./target/release/rent-bench execute 1 6 24 168
ATTESTED=1  ./target/release/rent-bench execute 1 6 24 168
# prover host only:
./target/release/rent-bench prove 24
BATCH_SIG=1 ./target/release/rent-bench prove 24
ATTESTED=1  ./target/release/rent-bench prove 24
```

For `prove`, record peak memory (`/usr/bin/time -v`, "Maximum resident set size").

## 7. Results

Append a new section to `docs/measurements.md`, dated, in the style of the 2 Nov section.
Do not edit the earlier sections. It contains:

- machine (CPU model, vCPU, RAM, GPU if any), OS, RISC Zero and Rust versions, commit;
- table 1: cycles and segments per mode and batch size;
- derived: cycles per hour of service and fixed cycles per batch, per mode (fit
  `cycles = a × hours + b` from the 1 and 168 rows; show the 6 and 24 residuals);
- table 2 (if proved): succinct seconds, wrap seconds, total, peak memory, for 24 hours,
  per mode;
- one paragraph: what the numbers say about decision 46's estimate (about 1.1 M cycles
  for a daily batch); state any difference without softening it.

## 8. Done when

- The draft pull request has the code, the tests passing, the vector file, and the new
  measurements section.
- The pull request description has table 1 (and table 2 if run) and the machine.
- Nothing else in `docs/` changes. Decision 46 stays "Proposed"; the owner decides.

## 9. Out of scope

Solidity, gas, the real rent guest in `policy-execution`, PE-0 text, any change to
decision rows. If you find that 46's byte format cannot be implemented as written, stop
and report it in the pull request; do not change the format yourself.
