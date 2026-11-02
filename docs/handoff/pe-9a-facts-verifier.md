# Handoff PE-9a: the settle-side signature verifier, standalone

Status: ready to execute. Blocked by nothing technical. Needs push access to
`mnemonik-xyz/policy-execution`, an Arc testnet RPC endpoint and a deployer key funded
with testnet USDC (Arc pays gas in USDC).
Repository: `mnemonik-xyz/policy-execution`. Work branch: `pe-9a/rent-facts-verifier`.
Open a draft pull request; the owner merges.

## 1. Goal

Decision 46 (proposed, `mnemonik-xyz/pocc` `docs/decisions.md`) moves the verification of
the rent case's hourly record and note signatures from the zkVM guest into
`WarrantEscrow.settle`. The guest keeps every other check and commits three journal
words: `factsHash`, `meterAddr`, `acceptanceAddr`. At settle time a stateless verifier
recovers each signer from the calldata `facts` against those two addresses and
recomputes `factsHash`.

This package builds that verifier and its byte formats as a standalone, tested contract,
and measures its gas on Arc testnet. It does not touch `WarrantEscrow`, the guest or
PE-0's text; that is PE-9b, which waits for PE-0's review and framework steps 2 and 3.

## 2. Read first

| File | Why |
|---|---|
| pocc `docs/decisions.md`, entry 46 (design, "who checks what", formats, per chain) | The decision; normative for formats until PE-0 is amended |
| pocc `docs/handoff/pc-8-attested-bench.md`, §4.3 and §5 | The same formats from the guest side, and the shared vector file |
| pocc `bench/rent-guest/bench-core/src/lib.rs` | `tagged_bytes`, `UsageRecord`, `Note`, the signing tags |
| this repo `docs/handoff/04-rent-interface-v1.md` (PE-0) | Signed objects, journal v2, `WarrantEscrow` terms |
| this repo's handoff rules (`docs/handoff/`) | No renames; Simplified Technical English; golden vectors changed only on purpose; no widening of the Verus claim |
| this repo's existing escrow contracts and their tests | Follow their layout, Solidity version, test framework and error style |

## 3. The security model, in one paragraph

The verifier treats every record and note as an opaque byte string. It never parses
bincode. Field checks (scope, `lease_id`, `meter_spec`, indices D1, windows D4, amounts
and the note-to-record binding D5, floors D6 and D7, bounds D8 and D9) stay in the
guest. The guest computes `factsHash` from the typed structs it checked, and the proof
commits it. The verifier proves that the bytes in `facts` hash to that same value and
that each byte string was signed by the address the guest derived from the pinned
policy. If any check fails, the transaction reverts; nothing is stored. Therefore: do
not add field checks, index checks or binding checks in Solidity. They would duplicate
the guest, and the index check in particular is wrong here: indices are lease-wide
(batch 1 of a daily batch carries 24 to 47).

## 4. Byte formats (exact)

```text
tagged_bytes(tag, payload) = u64_le(len(tag)) ‖ tag ‖ u64_le(len(payload)) ‖ payload

record blob : tagged_bytes("warrant/usage/v1",      bincode(UsageRecord))   tag length 16
note blob   : tagged_bytes("warrant/acceptance/v1", bincode(Note))          tag length 21
signature   : r (32) ‖ s (32) ‖ v (1), v ∈ {27, 28}, s ≤ n/2
digest      : sha256(blob)          (the precompile at 0x02; not keccak)
signer      : ecrecover(digest, v, r, s)

facts       = u32_le(n) ‖ for k in 0..n: u32_le(len(rblob_k)) ‖ rblob_k ‖ sig_k
            ‖ u32_le(m) ‖ for k in 0..m: u32_le(len(nblob_k)) ‖ nblob_k ‖ sig_k
              (len counts the blob only, not the 65 signature bytes; no trailing bytes)

body        = u32_le(n) ‖ for k: u32_le(len(rblob_k)) ‖ rblob_k
            ‖ u32_le(m) ‖ for k: u32_le(len(nblob_k)) ‖ nblob_k
factsHash   = sha256( u64_le(22) ‖ "warrant/facts-batch/v1" ‖ u64_le(len(body)) ‖ body )

address(key) = last20(keccak256(X_be32 ‖ Y_be32)), from the compressed SEC1 key,
               without the 0x04 prefix (Geth PubkeyToAddress)

n/2 = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
```

Solidity reads `u32_le` and `u64_le` little-endian; byte-swap explicitly.

## 5. Deliverables

### 5.1 Rust, in `core`

- `facts::encode(records: &[(Vec<u8>, [u8; 65])], notes: &[(Vec<u8>, [u8; 65])]) -> Vec<u8>`
- `facts::hash(records: &[Vec<u8>], notes: &[Vec<u8>]) -> [u8; 32]`
- `facts::eth_address(compressed_key: &[u8]) -> Result<[u8; 20], _>`
- Unit tests: the address of private scalar 1 is
  `0x7e5f4552091a69125d5dfcb7b8c2659029395bdf` (and not `0x7d6e99bb…7b88`, the value
  with the `0x04` prefix); `hash` and `encode` reproduce `test/vectors/rent-facts-v1.json`
  from PC-8 if it exists, otherwise generate that file here with the same content (§5.4)
  and say so in the pull request.

### 5.2 `warrant-evidence`: recoverable signatures behind an option

- `sign-usage --recoverable` and `sign-acceptance --recoverable` write 65 bytes:
  `sign_prehash_recoverable(&sha256(message))`, low-s, `v = 27 + recovery_id`; check it
  with `recover_from_prehash` before writing.
- The default output stays 64 bytes, byte for byte. Add a golden test that proves it.
  `core::verify` does not change.

### 5.3 `RentFactsVerifier.sol`

```solidity
function verify(
    bytes calldata facts,
    bytes32 factsHash,
    address meterAddr,
    address acceptanceAddr
) external view;   // reverts on any failure; returns nothing
```

Algorithm, in order; one custom error per failure:

1. Read `n`; require `n > 0`.
2. For each of `n` records: read `len`, the blob, the 65-byte signature. Require the
   blob starts with `u64_le(16) ‖ "warrant/usage/v1"` and that the following `u64_le`
   equals `len − 32`. Recover the signer of `sha256(blob)`; require `v ∈ {27, 28}`,
   `s ≤ n/2`, signer `≠ 0` and signer `== meterAddr`. Append `u32_le(len) ‖ blob` to the
   body buffer.
3. Read `m`; require `m > 0`. For each note, the same with the prefix
   `u64_le(21) ‖ "warrant/acceptance/v1"`, inner length `len − 37`, and
   `acceptanceAddr`.
4. Require the read offset equals `facts.length` (no trailing bytes) and every read stays
   in bounds.
5. Require `sha256(u64_le(22) ‖ "warrant/facts-batch/v1" ‖ u64_le(len(body)) ‖ body)
   == factsHash`.

`meterAddr == acceptanceAddr` is valid: in v1 one guardrail key fills both roles
(decision 25). The tag prefix check costs little and stops a note blob from standing
in for a record when the two keys are the same.

### 5.4 Vectors: `test/vectors/rent-facts-v1.json`

Generated by a Rust test from deterministic keys. Positive cases:

| Case | Content |
|---|---|
| `one-hour` | 1 record, 1 note |
| `day-batch-0` | 24 records and notes, indices 0 to 23 |
| `day-batch-1` | 24 records and notes, indices 24 to 47 |
| `partial-batch-2` | 3 records and notes, indices 48 to 50 |
| `one-key` | `meterAddr == acceptanceAddr` |

Each case: blob hex and signature hex per record and note, the full `facts` hex, the two
addresses, `factsHash`. The Solidity tests read the file (`vm.readFile`, `vm.parseJson`
or the repository's equivalent).

### 5.5 Solidity tests

Every positive vector passes. Each of these reverts with its specific error:

wrong `meterAddr`; wrong `acceptanceAddr`; high-s (replace `s` with `n − s` and flip
`v`); `v` of 0, 1 or 29; a signature that recovers to address zero; `n = 0`; `m = 0`;
`facts` truncated inside a length, a blob and a signature; one trailing byte; two
records swapped (signatures valid, `factsHash` differs); a note blob in the record
section with `meterAddr == acceptanceAddr` (tag check); an inner `u64_le` length that
disagrees with `len`; `factsHash` off by one bit.

Do not test a wrong note binding, a gap in indices or a wrong amount here. Those are
guest gates (D1, D5) and are tested there.

### 5.6 Gas

Measure `verify` alone for 1, 6, 24 and 168 hours, locally (Foundry gas report) and on
Arc testnet (deploy with a script; one call per size; report `gasUsed` from the receipt
and the fee in USDC).

Also measure separately on Arc testnet one call to RISC Zero's Groth16 verifier contract
(`risc0-ethereum`, the version this repository already uses) with any valid RISC Zero
Groth16 receipt. The invoice receipt from the repository's validation runs is
acceptable. Report the sum as the estimate of `settle`'s added cost. A combined
measurement waits for a real receipt of the 46 guest (PC-8, PE-9b).

For comparison with decision 44 (one meter signature over the batch): add a test-only
harness, not shipped, that recovers 1 batch signature plus `m` note signatures over the
same blobs, and report its gas for 24 hours beside the per-hour form.

Secrets: read the RPC URL and the deployer key from environment variables
(`ARC_TESTNET_RPC_URL`, `DEPLOYER_PRIVATE_KEY`). Never commit them, never print the key,
never put them in the pull request.

## 6. Done when

- The draft pull request has 5.1 to 5.5 with all tests passing in CI.
- The pull request description has the gas table: per size, local gas, Arc testnet gas,
  Arc testnet fee; the Groth16 call; the decision-44 harness for 24 hours; the contract
  addresses and transaction hashes on Arc testnet.
- Nothing in `WarrantEscrow`, the guest, the journal or PE-0 changes.

## 7. Out of scope (PE-9b)

`settle(seal, journal, facts)`, pinning the verifier per `schemaId`, the three journal
words in journal v2, the `facts-in-settle` guest image, the PE-0 amendment, mainnet. If
you find that a format in §4 cannot be implemented as written, stop and report it in the
pull request; do not change the format yourself.
