# Measurements

Numbers measured by us, with the machine and the commit, so that no estimate is
mistaken for a measurement. The cost analysis that uses them is the Claude doc
"PoCC × Warrant — cost of proving delivered compute".

## 2 Nov 2026: zkVM cycles of the rent work (DL-13, partial)

Machine: a 2-vCPU, 8 GB cloud sandbox; RISC Zero 3.0.5, r0vm 3.0.5, guest toolchain
Rust 1.88.0 (riscv32im-risc0-zkvm-elf), executor only. Code: `bench/rent-guest` in
this repository at the commit that adds this file; `policy-execution` at `5817e34`.

| Guest | Cycles | Segments (2^20) | Executor wall |
|---|---:|---:|---:|
| Invoice guest (`warrant-host invoice-execute`, the measured 445 s proof's program) | 1,571,975 | 2 | 0.29 s |
| Rent work, 1 hour | 689,041 | 1 | 0.19 s |
| Rent work, 6 hours | 4,063,591 | 5 | 0.42 s |
| Rent work, 24 hours | 16,196,163 | 17 | 1.36 s |
| Rent work, 168 hours | 113,305,823 | 116 | 8.07 s |

Derived: 674,352 cycles per hour of service (two secp256k1 verifications and two
sha256 of about 200 bytes each), 14,689 cycles of fixed work. The rent work is linear
in the hours; a 24-hour batch is 10.3 times the invoice guest.

Not measured here: proving time and memory. A real proof was attempted
(`rent-bench prove 1`, segment 2^19) and the sandbox's memory cgroup killed the
prover. The 445.65 s succinct proof plus 79.73 s Groth16 wrap of the invoice guest
(policy-execution `validation-results.md`, one Mac run) is the only proving
measurement; extrapolating by cycles gives, for that machine:

| Batch | Cycles / invoice | Proof (extrapolated) | + wrap | Per hour of service |
|---|---:|---:|---:|---:|
| 1 hour | 0.44 | 195 s | 275 s | 275 s |
| 6 hours | 2.59 | 1,152 s | 1,232 s | 205 s |
| 24 hours | 10.30 | 4,592 s | 4,672 s | 195 s |
| 168 hours | 72.08 | 32,120 s | 32,200 s | 192 s |

The extrapolation assumes proving time proportional to cycles at 283 µs per cycle,
which the recursion tree makes roughly true above one segment; it is an estimate
until DL-13 runs on a prover host.

Still to measure (PE-8, DL-13): a real proof of the rent guest on a CPU prover host
and on a GPU prover (RISC Zero CUDA), with proof time, wrap time, peak memory and the
host's price per hour, for batches of 1, 6, 24 and 168 hours; the settlement margin
follows from them. The GPU result decides whether VMs below about $10 a day can be
sold under PoCC at all.
