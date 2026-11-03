# PoCC decision log

Every design decision taken for PoCC and its Warrant integration, with the alternatives
that were on the table and what it costs to undo each one. The working copy is the
Claude doc "PoCC decision log"; the two must say the same.

## How to use this log

One row per decision, numbered in the order taken. A decision has a status: **Taken**
(in force), **Deferred** (agreed, not scheduled), **Reversed** (with the number of the
decision that replaced it). A decision is never edited after it is taken; to change it,
add a new row that names the old one, so the history of why stays readable.

Each entry ends with "Reversal": the concrete work to undo it and what else moves.
Where a decision changed a hash or an artifact format, the reversal also says whether
old artifacts (receipts, policies, images) stay valid.

Sources for the arguments: the PoC spec v0.2 and the Warrant integration spec v0.1
(Claude doc tabs; repository copy `docs/warrant-integration.md`),
`docs/architecture.md`, `test/live/2026-10-28/README.md`, and the policy-execution
handoff (`docs/handoff/`).

## Decisions

| ID | Date | Decision | Status | Applies to | Reversal cost |
|---|---|---|---|---|---|
| 01 | 2026-10-28 | Proof of concept first; Stage 0 without hardware attestation on amnezia.cloud, Stage 1 adds SEV-SNP | Taken | PoC spec §1 | None: Stage 1 is additive |
| 02 | 2026-10-28 | Direction: provider proves delivery to the tenant (anti-overbilling); node-to-protocol deferred | Taken | PoC spec §1 | Adds job commitments and sampling; artifacts gain fields |
| 03 | 2026-10-28 | Time from drand quicknet; heartbeats on shared 60 s slots (rounds divisible by 20); bracket 30 s | Taken | Agent, notary, verifier | Changes `meter_spec`, hence policy hashes; receipts stay verifiable under their own parameters |
| 04 | 2026-10-28 | Notary batches all VMs per slot and anchors one Merkle root; "cheap to write, reproducible to check" | Taken | Notary | Per-VM anchoring multiplies chain cost by the number of VMs |
| 05 | 2026-10-28 | Usage counters committed per field with HMAC salts; disclosed on demand (simplest selective disclosure) | Taken | Agent, receipt | Pedersen commitments later; chain hash changes, old receipts stay valid |
| 06 | 2026-10-28 | Credit = liveness only: an interval between two on-time heartbeats earns 60 s; gaps earn nothing | Taken | Verifier | Progress weighting changes credited values, not formats |
| 07 | 2026-10-28 | Allowlist of launch measurements owned by the relying party (buyer in direction a); builds via mkosi + SLSA provenance first | Taken | Stage 1 | None until Stage 1 |
| 08 | 2026-10-28 | GPU double-counting handled agent-side (GPU presence per heartbeat); registry only with a shared reward pool | Deferred | Stage 1 | — |
| 09 | 2026-10-28 | RATS role names adopted in text; receipt stays JSON, no EAT/CWT in the PoC | Taken | Specs | A format change if an EAR-shaped verdict is wanted |
| 10 | 2026-10-28 | tau_max for throughput checks = 1.25 × p99 of a reference run, published and pinned | Deferred | Stage 1 | — |
| 11 | 2026-10-28 | NVSwitch attestation out of scope | Deferred | Stage 1 | — |
| 12 | 2026-10-28 | Agent boots on a slot, so e0 shares the heartbeat bracket (found in the first local run) | Taken | Agent, verifier | Reintroduces a 44 s boot-anchoring gap |
| 13 | 2026-10-28 | Agent uses drand's latest round as its clock and skips slots reached late (live-test finding F1) | Taken | Agent | A paused VM sends stale heartbeats again |
| 14 | 2026-10-28 | A late anchor earns no credit but does not invalidate the receipt; an anchor before its round is fatal (finding F2) | Taken | Verifier, test T4 | Honest delivery around a pause becomes unpayable |
| 15 | 2026-10-29 | PoCC is the meter of Warrant's rent case; the buyer's verifier key is `meter_key` (Warrant Decision 6) | Taken (D-A) | Integration §1 | Choose another signer: provider, independent service, guest |
| 16 | 2026-10-29 | Uptime and assurance floors live in the delivery section, not as rule atoms | Taken (D-B) | Integration §4 | Two atoms, two `Facts` fields, Verus cases, new image; policy hashes change |
| 17 | 2026-10-29 | `meter_spec` is an opaque hash in Warrant's typed policy | Taken (D-C) | Integration §4 | Warrant structs would learn PoCC fields; `deny_unknown_fields` churn |
| 18 | 2026-10-29 | Usage record is Warrant-native; `pocc-verify` writes JSON, `warrant-evidence sign-usage` signs | Taken (D-D) | Integration §7 | PoCC would need secp256k1 and bincode in Go |
| 19 | 2026-10-29 | One piece = one clock hour; batch default 24; period aligned to the hour | Taken (D-E) | Integration §5 | Note and record indexing changes |
| 20 | 2026-10-29 | Dispute mechanic is future work; v1 ends disagreements with Warrant's `Ask` | Deferred (D-F) | Integration §8 | Adds `referee_key`, `dispute_window_s`, `disputed`; policy hash changes |
| 21 | 2026-10-29 | `PoccAnchor` on Arc; the provider pays anchoring as a cost of selling | Taken (D-G) | Integration §9 | Tenant-funded or Mnemonik-run notary: no format change |
| 22 | 2026-10-29 | `pocc` becomes a submodule of `warrant` | Taken (D-H) | warrant repo | Remove the submodule |
| 23 | 2026-10-29 | One order: the escrow order replaces the PoCC Order; `h0` derived from `policy_hash`, `lease_id`, chain, escrow, `orderId` | Taken | Integration §5, PC-1 | Reinstate the provider-signed PoCC Order; `h0` formula changes |
| 24 | 2026-10-29 | PoCC core stays consumer-agnostic (Ed25519, JCS); Warrant code isolated in `pkg/adapter/warrant` | Taken | pocc | None: an adapter can always be added |
| 25 | 2026-10-29 | One buyer guardrail key fills registry, acceptance and meter roles in v1; policy fields stay separate | Taken | Integration §3, template | Issue separate keys; no format change |
| 26 | 2026-10-29 | Phase A opened as draft PRs: policy-execution #76 (PE-1) and warrant #16 (W-1); the owner merges | Taken | Both repos | Close the PRs |
| 27 | 2026-10-29 | `lease_id = H(lease, tenant_pubkey, request_id, period)`; not `H(lease, request_hash)` | Taken, not yet reviewed by the owner | Integration §5, `pkg/pocc` | Formula change; leases of existing requests change |
| 28 | 2026-10-29 | A credited interval belongs to the hour it ends in; one ending exactly on the hour belongs to the hour before | Taken, not yet reviewed by the owner | Verifier | Changes which hour edge intervals credit, not the total |
| 29 | 2026-10-29 | In escrow mode the receipt's billed fields and signature are optional; billing is through the consumer's notes | Taken, not yet reviewed by the owner | Verifier | Make them mandatory again |
| 30 | 2026-11-02 | One mode, escrow only: the proof of delivery is whatever the executed policy says; PoCC is one delivery kind (`signed_usage`); `meter_spec` mandatory in the Request; the PoCC `Order` type and the offline path removed. Amends the last clause of 23 | Taken | Verifier, agent, broker, sim, `docs/architecture.md` | Reinstate the `Order` type and the offline branch; old fixtures verify again |
| 31 | 2026-11-02 | Challenge after the hour (SS-9); an hour below the floors gets a usage record and a zero note, so batches stay contiguous (D6, D7 bound the amount instead of denying) | Taken | Lease evidence §5a, §6; integration §6 | Allow gaps in batches: `authorize_meter` and the proved evaluator change |
| 32 | 2026-11-02 | One versioned interface document (PE-0) precedes PE-2, PE-3 and PE-6; the three journal and escrow variants in the docs are not approved for implementation on their own | Approved by the owner: the necessity of PE-0, not any interface; PE-0's content awaits review | Lease evidence §5, integration §10 | Pick one variant by fiat and start |
| 33 | 2026-11-02 | Pilot with a clearly identified reseller under an explicit spending limit with the cloud, responsible for terminating resources; the cloud is never described as accepting Warrant payments unless it participates | Approved by the owner, with those conditions | Architecture §1, lease evidence §5a | A participating cloud is the same protocol with two roles in one party |
| 34 | 2026-11-02 | The floor is creditable interval coverage (`min_coverage_bp`, `coverage_bp`), not uptime: the denominator (`creditable`) is fixed before the piece runs from the schedule alone; payment is for credited seconds only | Approved by the owner, renamed from uptime | Verifier, adapter, lease evidence 5a.2, D6, D8 | Measure against the clock hour instead (a perfect boundary hour then fails a 100 % floor) |
| 35 | 2026-11-02 | v1 trusts the guardrail's attestation of delivery as an explicitly limited pilot; a compromised signer can pay without evidence until X-1; a key split is not a substitute | Approved by the owner as a pilot limit | Lease evidence §5a.4, §8; integration §6 | X-1: guest-verified evidence; still inherits Stage 0's physical-machine assumption |
| 36 | 2026-11-02 | Continuation gate: hour k+1 is served against note k; the provider waits at most `challenge_timeout_s` (policy field) after hour k; exposure `E` = one hour + grace + shutdown + provisioning, stated everywhere | Taken | Lease evidence 5a.5, SS-9, SS-10; integration §1 | Serve blindly through hour k+1 (two hours of exposure) |
| 37 | 2026-11-02 | The index origin is `delivery.service_start`; the delivery section carries `service_start`, `service_end`, `piece_s`, `challenge_timeout_s`; the adapter refuses a policy whose period differs from the Request's | Taken | Lease evidence 5a.1, 5a.2; `pkg/adapter/warrant` | Derive the origin from `validity.after` (breaks when authorization precedes provisioning) |
| 38 | 2026-11-02 | Batches close once; a late note is refused; the guardrail sets note windows so none expires inside an unfinished batch (BG-6); the seller keeps a settled/held/open reservation ledger (SS-10) | Taken | Lease evidence 5a.5, SS-10, SS-11, BG-6 | Per-hour obligations on chain (contract change) |
| 39 | 2026-11-02 | Gates D4 to D9 have a Go reference (`warrant.Decide`) and shared decision vectors (`test/vectors/usage-gates.json`) that Warrant's `authorize_meter` must match | Taken | `pkg/adapter/warrant`, DL-12 | None |
| 40 | 2026-11-02 | The rent case settles through the framework interface (C): journal v2 with `schemaId` on `WarrantEscrow`, proof only; PE-0 (`policy-execution/docs/handoff/04-rent-interface-v1.md`) is its specification. Interface A (invoice journal as-is) is superseded; B (invoice journal plus delivery words on `ProofInvoiceEscrow`) is not for production and is not implemented | Chosen by the owner; PE-0's text awaits review | Lease evidence §5, integration §7, §10 | Implement B as a pilot bridge, thrown away at C |
| 41 | 2026-11-02 | The state machine of lease evidence 5a.5 is modelled in `pkg/lease` and the DL-11 scenarios run as tests; the model found that a full batch must settle before its own `deadline(b)`, not at the lease's end, so the worker settles each batch as it closes | Taken | `pkg/lease`, SS-4 | None |
| 42 | 2026-11-02 | The seller's challenge carries the amount its own verifier expects; a note below it is underpayment for delivered service and stops the lease after that piece, while a zero note for an outage the seller saw itself continues. Amounts are bounded (2^62) and every sum is checked | Taken | `pkg/lease`, lease evidence 5a.5 | Leave the gate to PC-3 and let the model continue on any note |
| 43 | 2026-11-02 | The pilot's prover is a GPU host with RISC Zero's CUDA prover; the CPU prover is for development and the Groth16 wrap; batches are daily; `settlement_margin_s = 1800` assumes the GPU until PE-8 and DL-13 measure it | Taken, with the owner | Lease evidence §4, §4c, ME-8; PE-0 §2.1; compute-rent §8; integration §10, §11 | A CPU prover: a 2.5 h margin, batches of at most about 6 h, about $1.30 per VM-day, no VM below about $10 a day |
| 44 | 2026-11-02 | One meter signature over the batch's records (`warrant/usage-batch-signed/v1`) replaces the per-record signatures in the proof; the per-hour records and the notes' binding are unchanged; the guest accepts either form (D2); the guardrail re-signs at batch close (BG-7) | Taken, with the owner | PE-0 §3, §4; lease evidence 5a.2, 5a.3, 5a.5, BG-7, DL-14; `pkg/adapter/warrant`, `pocc-verify` | Per-record signatures only: 16.2 M cycles per daily batch instead of 9.0 M |
| 45 | 2026-11-02 | The batch is signed from the hourly records persisted at each hour's signing, never from records regenerated from the receipt; the grace is `G = 2 × challenge_timeout_s + M` with `M` budgeted for the per-record fallback proof; DL-13 and PE-8 measure verified succinct and Groth16 receipts, in both signature forms, under concurrent load | Taken | Lease evidence 5a.2, 5a.5, BG-7, DL-13; `pkg/adapter/warrant`, `pkg/lease`, `bench/rent-guest` | Sign regenerated records (a receipt re-run could change what was signed); budget `G` for the fast path only (the fallback then misses the deadline) |
| 46 | 2026-11-02 | Buyer-note mode only. Signature verification of the rent case moves from the guest to Solidity, in the settle transaction: `WarrantEscrow.settle(seal, journal, facts)` hands `facts` (the batch's records and notes with their 65-byte signatures, index order) to a stateless `RentFactsVerifier` pinned per `schemaId` beside the image ID; it recomputes each digest, recovers the signer (low-s, no zero address), compares it with the `meterAddr` and `acceptanceAddr` words of the journal, and recomputes `factsHash` over the signature-free bytes, which must equal the journal's. The guest derives the two addresses from the policy's keys, keeps the nine pre-gate checks except the two signature checks, D1 and D3–D9, the credential signature and the rule tree, and commits `factsHash`, `meterAddr`, `acceptanceAddr`. No registry, no attestation state. Amends 40 (the escrow gains `facts` and one verifier call); the mode is a per-chain choice by `schemaId`, two images from one guest source. Supersedes 44 and, of 45, the re-signing wait and the fallback proof if taken; persisted records and 43's margin stay, `G = challenge_timeout_s + settlement_margin_s` | Proposed. PE-9a and PE-9b on hold pending mode priority; PC-8 is comparative only. Updated 3 Nov after review | Integration §6.2 steps 10–11, §6.3, §7, PE-9a, PE-9b, PC-8; handoffs `docs/handoff/`; PE-0 §3, §5, §6; `pkg/adapter/warrant`; `bench/rent-guest`; `WarrantEscrow` | Additive to the contract: drop `facts` and the verifier call, the guest verifies signatures again, 44 and 45 return; batches settled under 46 stay valid under 46's image |

## Pending request: dispute mechanism

On 3 Nov 2026 the owner requested payment on the buyer's delivery acknowledgement,
or provider-submitted proof after a response period. The owner named it the dispute mechanism. See the
[change specification](handoff/dispute-mechanism.md).
Existing contracts provide reusable signature/proof payment mechanics, but the current rent witness still depends on buyer signatures.
The draft preserves service batches and proposes independently available delivery evidence.
Those two business assumptions remain for review. No existing decision is silently marked superseded.
Acknowledgement settlement now requires the funded provider as caller, in addition to the buyer signature.
Buyer-only underpayment or cutoff submissions must leave the obligation unchanged. Proof settlement remains permissionless after timeout.
Decision 46's PE-9a/PE-9b are on hold until the owner selects mode priority; their buyer-note format is not the dispute witness.

## Decisions in full

Entries 01–14 are the PoC's own; 15–25 are the integration's.

**01 Proof of concept in two stages.** *Alternatives:* wait for SEV-SNP hosts; build
Stage 1 on a public cloud first. *Reason:* the probe on 28 Oct showed amnezia.cloud runs
Intel Broadwell and Cascade Lake on Nova Epoxy, so no TEE is available; the whole cycle
can still be exercised without one. *Consequence:* Stage 0 cannot detect a provider that
reads the agent key from VM memory; the spec states this. *Reversal:* none needed;
Stage 1 replaces one field of the boot proof.

**02 Provider-to-tenant direction.** *Alternatives:* node-to-protocol first (the
Mnemonic staked-operator case). *Reason:* one relying party, and the artifacts are
reused by the other direction later. *Reversal:* add job commitments, sampling and
slashing; the heartbeat gains a jobs root.

**03 drand slots and a 30 s bracket.** *Alternatives:* local clocks with signed
timestamps; a chain as the only clock. *Reason:* drand gives an unpredictable value
every 3 s for free and the same slots for every VM, which makes one notary root per
minute cover all VMs. *Consequence:* the live test found that a paused VM's clock lags
(decision 13). *Reversal:* a different beacon or period changes `meter_spec` and thus
policy hashes.

**04 Notary with per-slot batches.** *Alternatives:* each VM anchors itself; a
permissioned log; hourly anchoring. *Reason:* the owner's own criterion, cheap to write
and reproducible to check; the notary needs no trust because the root, not the sender,
carries it; hourly anchoring would widen the bracket to an hour. *Reversal:* per-VM
anchoring is a notary-less agent change, at N× chain cost.

**05 Salted per-field usage commitments.** *Alternatives:* hash the whole usage object
(reveals everything on verification); Pedersen commitments with range proofs. *Reason:*
the owner asked for the simplest scheme first; cumulative counters mean opening the
final heartbeat discloses the period total only. *Reversal:* a chain-hash change; old
receipts verify under the old rule.

**06 Liveness-only credit.** *Alternatives:* progress-weighted credit; GPU busy
counters as credit. *Reason:* no calibration needed for the PoC. *Consequence:* duty
cycling between heartbeats is not caught in Stage 0. *Reversal:* changes credited
values, not artifacts.

**07 Allowlist and reproducible builds.** *Alternatives:* provider-owned allowlist; Nix
bit-for-bit builds first. *Reason:* the relying party owns what it relies on; mkosi
plus SLSA provenance is enough until third parties must rebuild images. Deferred with
Stage 1.

**08, 10, 11 Stage 1 items** (GPU double counting, tau_max calibration, NVSwitch):
deferred by the owner on 28 Oct as not PoC-stage questions. The answers are recorded in
the PoC spec §11.

**09 RATS names, JSON receipt.** *Alternatives:* EAT/CWT tokens throughout. *Reason:*
vocabulary helps auditors; a token format adds work with no PoC value. *Reversal:* a
verdict format change only.

**12 Boot on a slot.** *Found by:* the first local run against real drand, where the
boot proof was anchored 44 s after its round and failed the bracket. *Alternatives:* a
longer bracket for the boot proof. *Reason:* one rule for every entry; every credited
interval becomes exactly 60 s. *Reversal:* reintroduces the gap.

**13 Beacon as the agent's clock.** *Found by:* live-test finding F1: after a 10 min
Nova pause, the guest clock lagged 10 min and the agent sent six stale heartbeats.
*Alternatives:* NTP in the guest (the host can still freeze it); host-proof TSC
(Stage 1 hardware). *Reason:* drand's latest round is real time the host cannot
freeze. Checked locally with SIGSTOP for 100 s. *Reversal:* stale heartbeats return.

**14 Late anchors earn nothing but do not invalidate.** *Found by:* finding F2: one
late heartbeat made the whole live receipt INVALID, so honest delivery around a pause
could never be paid. *Alternatives:* keep late anchors fatal (safe but unpayable).
*Reason:* backdated heartbeats earn nothing anyway, and billing them is caught as
overbilling; an anchor before its round stays fatal. *Reversal:* revert `timely` in the
verifier and test T4.

**15 PoCC as Warrant's meter, buyer-run (D-A).** *Alternatives:* provider signs (the
party being paid); independent service (new entity); co-signing (both online); guest
re-execution (end state X-1). *Reason:* the verifier is public code over public inputs,
so the buyer's run can be checked by anyone; a malicious buyer can only under-credit,
which costs the provider at most one hour and the buyer its service and reputation.
*Reversal:* change `meter_key` in the policy to another party's key; nothing in the
artifacts changes.

**16 Floors in the delivery section (D-B).** *Alternatives:* rule atoms
`uptime_at_least_bp`, `assurance_at_least`. *Reason:* no change to the Verus-proved
evaluator or the `Rule` enum; the delivery check is case code, tested like the invoice
and solver checkers. *Reversal:* two atoms, two facts, two proof cases, a new image;
policies keep their meaning, their hashes change.

**17 Opaque `meter_spec` (D-C).** *Alternatives:* PoCC fields typed into Warrant's
delivery struct. *Reason:* Warrant stays meter-agnostic; a new beacon or slot length
never touches a Warrant struct or image. *Reversal:* a struct change under
`deny_unknown_fields`.

**18 Warrant-native usage record (D-D).** *Alternatives:* Warrant verifies an
Ed25519/JCS record; PoCC reimplements bincode and secp256k1. *Reason:* each side
verifies only its own formats; signing goes through the existing `warrant-evidence`
tool. *Reversal:* either of the alternatives, both heavier.

**19 One piece = one hour (D-E).** *Alternatives:* a piece per slot (1,440 notes a
day); a piece per day. *Reason:* hourly matches the provider's billing granularity and
bounds the provider's exposure to one hour. *Reversal:* index arithmetic in notes and
records.

**20 Dispute deferred (D-F).** *Owner's words:* "We want to start without a dispute
mechanic. Future work." *Consequence:* v1 ends disagreements with Warrant's `Ask` and
the hour unpaid; the design in integration §8 is kept. *Reversal:* add the three
policy and record fields and PC-5.

**21 Provider pays anchoring (D-G).** *Owner's question:* who sponsors the notary.
*Alternatives:* tenant-funded; Mnemonik-run shared notary charging per root; anchoring
every 5 min. *Reason:* anchoring is what turns the provider's heartbeats into billable
delivery, so it is a cost of selling; estimated under 1 % of the hour price across
100 VMs, to be measured in phase D. *Reversal:* a funding change only.

**22 `pocc` as a submodule of `warrant` (D-H).** Follows the pattern of
`policy-execution` and `warrant-swap`.

**23 One order.** *Owner's challenge:* "can it be compiled to one? Or is there a reason
to have two? Defend it." *Outcome:* no reason survived; the escrow order already holds
everything, and `accept(orderId)` is the provider's signature. *Consequence:* `h0` is
derived from the escrow order; the provider-signed PoCC Order survives only as the
offline mode (that clause is amended by 30). *Reversal:* reinstate the Order type as the source of `h0`.

**24 Consumer-agnostic core, adapter per consumer.** *Owner's question:* fit
policy-execution or stay universal. *Outcome:* both: the core stays universal, the
usage record is the single interception point, and Warrant code lives in
`pkg/adapter/warrant`. *Reversal:* none needed.

**27 Lease id from request fields.** *Found by:* implementing PC-1: `lease_id = H(request_hash)` is circular, because the Warrant policy inside the request carries `lease_id`. *Outcome:* derive it from the tenant key, the request id and the period, which the policy does not contain. *Reversal:* formula change only.

**28 Hour attribution.** *Found by:* the escrow-mode simulation: drand slots fall at :24 past the minute, so intervals straddle hour edges. *Outcome:* an interval belongs to the hour it ends in; one ending exactly on the hour belongs to the hour before. The first hour of a period credits at most 3,540 s. *Reversal:* a verifier change; totals do not move.

**29 Optional billing fields in escrow mode.** *Reason:* with one order (decision 23) the provider bills through Warrant notes, not through the receipt. The receipt is evidence that anyone can assemble; when billed fields or a signature are present they are still checked. *Reversal:* make them mandatory.

**25 One guardrail key for three roles.** *Owner's ask:* fewer entities and keys.
*Outcome:* registry, acceptance and meter roles share one secp256k1 key in v1
(Warrant's own rent spec already uses the buyer's key as registry); the policy keeps
three fields so they can diverge. *Reversal:* issue separate keys; no format change.

**30 One mode, escrow only.** *Owner's question:* why two modes, when the proof of
delivery is signed into the initial policy. *Found:* the "offline mode" was the Stage 0
scaffolding that gave the agent an `h0` before the escrow existed; the provider's Order
chose the beacon, slot and notary after the buyer signed, which breaks the requirement
that the proof is fixed in the policy. The "buyer trusts a signature" case is not a PoCC
mode either: it is Warrant's `signed_acceptance` delivery kind. *Outcome:* the executed
policy decides the proof; PoCC runs only when a policy names it through
`delivery.kind = signed_usage` and a `meter_spec`; `meter_spec` is mandatory in the
Request; the `Order` type, the `-order` path and the verifier's offline branch are
removed; decision 29 stops being a special case (the bill is always Warrant notes). The
`test/live/2026-10-28` fixtures stay as history and no longer verify. *Reversal:*
reinstate the `Order` type and the branch.

**31 Challenge after, zero notes below the floors.** *Found by:* a review of the lease
spec on 2 Nov: SS-1 and SS-3 serve only against a note, but a usage record exists only
after the hour ran; and D1's no-gap rule meant a denied hour blocked the rest of its
batch. *Alternatives:* allow gaps in batches (changes `authorize_meter` and the proved
evaluator); assign note indices only to paid hours (gives up one piece = one clock
hour). *Outcome:* SS-9 fixes the order for `signed_usage` (challenge after piece k,
serve piece k+1 against note k, stop when note k is missing); D6 and D7 require
`amount_k = 0` below the floors instead of denying, and the guardrail signs the zero
note. A zero-amount accepted note is already a legal note, so nothing proved changes.
*Reversal:* either alternative.

**32 to 35 Answers to the audit of 2 Nov.** *Status:* the owner reviewed these on 2 Nov
and approved 32 (the necessity of PE-0, not an interface), 33 (with a spending limit
and the duty to terminate), 34 (renamed to coverage) and 35 (as a pilot limit). The
first version of this entry said the findings were "answered"; that was too strong. The
documents were changed, and the second audit round (36 to 39) found exposure,
accounting and batch-finalization problems in those changes. They are specified now,
not implemented or simulated (DL-11, DL-12); they remain engineering blockers until
then. *Found by:* an independent documentation
audit of pocc `8ea3f27`, policy-execution #76 at `a8978b8` and warrant #16 at
`332e300`, ten findings. 31 had already answered finding 3 (zero notes) and part of 4
(SS-9); the state machine of lease evidence 5a.5 answers the rest of 4; the example
policy and the simulator's policy numbers were wrong (finding 5: 24 × 3.96 USDC
exceeds a 50 USDC ceiling, and a 4 USDC rule on the batch total denies every batch
over one hour) and now follow lease evidence 5a.6 with SS-10 for outstanding notes;
findings 7 (record arithmetic: one record per index, exact windows, bounds, checked
arithmetic, note bound to the record) and 9 (evidence custody BG-5; roots cannot
rebuild withheld entries; X-1 witness design) are in the lease evidence and here; 1
(sampled liveness, the five-property table) is in the architecture and the lease
evidence; 10 (boundary hours) is decision 34. *Alternatives considered:* for 32, pick
a journal by fiat (the owner's framework track decides, so no); for 33, a cloud that
accepts Warrant directly (none does today); for 34, a cap on `min_uptime_bp` (hides
the accounting instead of stating it); for 35, split the keys now (no format change
either way; left to the owner). *Reversal:* per row.

**36 to 39 Second audit round, 2 Nov.** *Found by:* the auditor's review of #76 at
`8290bc0` and pocc `f330c0f`: the state machine let two hours run without a note
while claiming one; SS-10 ignored delivered hours whose note had not arrived; a
settled prefix consumed the batch and late notes had nowhere to go; the pocc copy of
the record and gates lagged #76; the two documents used different index origins;
`creditable` lacked both endpoint constraints; §6.3 and §4b still claimed no single
party could supply the path. *Outcome:* the gate, the ledger, batch closing with
BG-6, `service_start` as the one origin, the formula for `creditable` with its
commercial meaning, the claims replaced, and the Go reference with shared vectors so
the two implementations cannot drift again. *Reversal:* per row.

**40 Interface C only.** *Owner's words:* "we can't use B for production." *Alternatives:*
B as a pilot bridge on the existing `ProofInvoiceEscrow` (fast if the framework slips,
but a throwaway image and contract patch); A (cannot carry `deliverySpecHash`, so the
escrow cannot check the delivery spec the buyer approved). *Outcome:* PE-0 written
against the framework design; the pocc side needs no artifact change; phase D waits for
framework steps 2 and 3. *Reversal:* implement B.

**41 The state machine as code.** *Why:* the auditor's point that the DL-11 simulation
is the evidence for approving the state machine, not something to approve first. The
model is the seller's side only: a ledger with `settled`, `held`, `open` and `lost`,
pieces that are provisional until the gate for them passes, one open challenge at a
time, batches that close once, `deadline(b)` from the policy. *Found by the model:*
the exposure test first settled every batch at the lease's end and the model refused
it, because deadline(b) of an early batch passes long before; SS-4's "when full" is
not optional. *Reversal:* none; the model follows the specification.

**42 The underpayment gate in the model.** *Found by:* the fourth audit round: the
model accepted zero notes for three delivered pieces and ran on, so it did not show
the "stops after one piece" behaviour that decision 15 and lease evidence 5a.4 rely
on. *Outcome:* the seller runs the verifier on the evidence it sends with the challenge
and expects `units × price`; a note below that is kept (it is money) and the lease
stops; a zero expectation is an outage and a zero note is correct. Also from that
round: amounts bounded at 2^62, checked additions, `Exposure` exact and rounded up, a
grace longer than a piece refused. *Reversal:* per row.

**43 GPU prover.** *Found by:* the cycle measurement of 2 Nov (`docs/measurements.md`,
`bench/rent-guest`): the rent work is 674,352 cycles per hour of service, linear in
the hours, ten times the invoice guest for a daily batch; on the one CPU prover
measured that is about 77 minutes and $1.30 per VM-day, which makes proving 98 % of
the protocol cost and prices cheap VMs out. *Owner's words:* "please adopt all docs
following GPU prover usage." *Alternatives:* a CPU prover with a 2.5-hour margin and
small batches; fewer signatures per hour (a meter signature over a batch of records,
PE-0's range extension), which halves the work and is still open; a rented proving
service. *Outcome:* the GPU is the planned prover in every document; the figures for
it are published rates (100 kHz to 1 MHz), not measurements, until PE-8. *Reversal:*
per row.

**44 One meter signature per batch.** *Owner's words:* "adopt one meter signature over
a batch too." *Measured:* a daily batch is 9,034,772 cycles with the batch signature
and 16,196,163 without (44 % less); 363,155 cycles per hour of service, the note
signature and hashing, plus 337,000 fixed. *Design:* the hourly flow is unchanged (the
guardrail still signs record k with note k, so the seller has evidence hour by hour);
at batch close the guardrail signs the same records once as a list; the guest verifies
that one signature and recomputes each `hash(record_k)` for the notes' binding; a
guardrail that will not re-sign is non-cooperation and the seller falls back to the
per-record signatures it holds. *Alternatives:* one note per batch (breaks per-hour
billing and the challenge); aggregate signatures (not in the zkVM accelerator set).
*Reversal:* drop `batch_signature`; nothing else changes.

**45 Persisted records, the fallback inside the deadline, the proof that settles.**
*Found by:* the review of 2 Nov after decision 44, four items: batches built from
regenerated receipts could sign records that differ from what the guardrail signed hour
by hour; the batch-signature wait and the slower fallback proof were outside the
deadline budget; the benchmark's `prove` made composite receipts, which never settle;
and GPU cost had no throughput measurement. *Outcome:* `SignBatchExternal` loads the
persisted `usage-<k>.json` files and refuses a differing regenerated record;
`G = 2 × challenge_timeout_s + M` and `M` is sized for the per-record proof; the
benchmark proves succinct, wraps to Groth16 and verifies both, with a `load N` mode;
PE-8 and DL-13 say so. *Reversal:* per row.

**46 Signature verification in Solidity, a simpler guest.** *Found by:* the question of
2 Nov, why secp256k1 signatures are verified inside the zkVM when `ecrecover` is cheap.
Revised the same day after the review of PR #1 (six findings: binding of the attested
facts to the order's keys, a registry open to blocking and overwrite, the settlement
margin wrongly removed, checks without an owner, gas counted for 25 recoveries instead
of 48, formats unspecified); the review's own suggestion, verification in the settle
transaction, removes the first two.

*Scope, updated 3 Nov:* this decision concerns the existing buyer-note rent mode.
It does not implement the [dispute mechanism](https://github.com/mnemonik-xyz/policy-execution/pull/77).
That mechanism needs delivery evidence without a fresh buyer note; [pocc #2](https://github.com/mnemonik-xyz/pocc/pull/2) defines its integration.
PE-9a and PE-9b are on hold until the owner chooses the implementation priority for these modes.
PC-8 can remain a comparative experiment for the existing mode. Its results do not measure the new dispute guest.
Do not enable the dispute path by accepting `m = 0` in this schema.
The dispute authorization, billing eligibility and witness require a separate versioned interface.

*Measured and estimated:* per hour of service 363,155 cycles with the batch signature
and 674,352 without, of which each k256 verification is about 330,000; a daily batch
9,034,772 cycles, which the extrapolation of `docs/measurements.md` puts at about
2,641 s with the wrap on the measured Mac (the 4,672 s there is the 16.2 M-cycle path).
Guest after 46, estimated: about 30,000 cycles per hour of hashing, one credential
signature and the O(1) batch checks, about 1.1 M cycles for a daily batch, below the
invoice guest; PC-8 measures it before the owner decides.

The earlier 335k/210k gas estimates omitted signing-tag bytes and understated the batch-signature alternative.
The following accounting corrects those omissions for 24 records and 24 notes:

| Component | Bytes or gas |
|---|---:|
| Bincode record / note | 185 / 157 bytes |
| Record signing frame / note signing frame | 32 / 37 bytes |
| Tagged record / tagged note | 217 / 194 bytes |
| All tagged blobs | `24 * (217 + 194) = 9,864` bytes |
| Two counts and 48 lengths | `8 + 48 * 4 = 200` bytes |
| 48 signatures | `48 * 65 = 3,120` bytes |
| Encoded `facts` | **13,184 bytes** |
| Calldata component at 16 gas per byte | 210,944 gas |
| 48 recoveries at 3,000 gas | 144,000 gas |
| Previous provisional hashing allowance | 7,000 gas |
| Sum of these components | **361,944 gas, approximately 362k** |

This is not measured gas or a transaction upper bound. The hashing allowance needs measurement.
The model excludes the outer function ABI, memory, parsing, calls, other execution costs and chain-specific pricing.
Zero bytes reduce the ordinary calldata component; transaction floors can change the total.
Where applicable, account for [EIP-7623](https://eips.ethereum.org/EIPS/eip-7623).
PE-9a measures components; PE-9b measures the integrated settlement difference against its baseline.

For a comparison with decision 44, retain every record in calldata and replace 24 record signatures with one batch signature.
Assuming otherwise unchanged framing, the payload is `13,184 - 23 * 65 = 11,689` bytes.
Then `11,689 * 16 + 25 * 3,000 + 7,000 = 269,024` gas, approximately 269k for those components.
The aggregate signature encoding and hash workload still need specification and measurement in the test harness.
This estimate does not change the normative per-record format of decision 46.
*Design:* steps 1 to 9 of integration §6.2 are unchanged: the guardrail still signs
record k and note k hour by hour, the seller still challenges and still serves hour k+1
against note k, the batch still closes once in the seller's ledger (SS-10). Step 10:
the worker proves with the guest, which receives the records and notes without
signatures, derives `meterAddr` and `acceptanceAddr` from `delivery.meter_key` and
`acceptance_key` of the policy it checks against `policyHash` (format below), and commits in the journal three new words: `factsHash`,
`meterAddr`, `acceptanceAddr`. Step 11: `settle(seal, journal, facts)`; after the
existing checks (image ID, `schemaId`, both hashes, obligation consumed once, ceiling,
recipient) the escrow calls `RentFactsVerifier.verify(facts, journal)`, a view function
pinned per `schemaId` the way the image ID is, which for every record and note:
checks the blob's tag prefix (`warrant/usage/v1` for a record, `warrant/acceptance/v1`
for a note) and its inner length, recomputes the digest as `sha256(blob)` over the bytes
as carried, and recovers the
signer with `v ∈ {27, 28}`, `s ≤ n/2` (EIP-2) and a zero address refused, compares it
with the journal word for its kind; then recomputes `factsHash` over the signature-free
bytes (format below) and requires equality with the journal. The verifier checks no
index: the signed `first_index` is lease-wide (`batch × batch_size + position`, so
batch 1 of a daily batch carries 24 to 47 and a partial batch 2 carries 48 to 50) and
its validation is D1's, in the guest, unchanged; `factsHash` equality fixes the order
and the count of the records and notes the guest saw, so a position-level check in
Solidity would only repeat D1 and, written as "0 to n−1", would refuse every batch
after the first. Nothing is stored; a transaction that fails any check reverts and the obligation stays open. The
fact invariant holds: the evaluator trusts a record or a note only because the same
transaction that pays has recovered its signer against the addresses the evaluator
derived from the pinned policy; the provenance check moved into the settle transaction,
it did not disappear.

*Standalone-proof guarantee:* a `facts-in-settle` receipt proves evaluation over records and notes whose signatures the guest did not check.
It binds their bytes through `factsHash` and binds their expected signing addresses through the pinned policy.
The credential signature remains checked in the guest. Record and note authentication requires the additional facts verification.
Receipt validity alone is neither authenticated delivery evidence nor permission to pay.

Consumers must identify the mode from the pinned `(imageId, schemaId)` pair. Unknown or mismatched pairs must fail closed.
For `facts-in-settle`, an off-chain consumer must verify the receipt and the exact matching facts under the specified recovery and hash rules.
Alternatively, it can verify finalized successful settlement through an approved escrow with the correct pinned verifier and matching claim.
An unverified event, a submitted transaction or a receipt without facts is insufficient.
The host and indexers must distinguish receipt validity, authenticated facts and finalized payment.
A second contract cannot treat this receipt as standalone signed-evidence authorization.
For `signed-facts-in-guest`, record and note authentication is part of the proved computation; live payment checks still remain external.

*Who checks what, after 46:*

| Check | Today | After 46 |
|---|---|---|
| Record signatures (D2), note signatures | Guest | Verifier, in `settle` |
| Credential signature (seller's registry credential, one per batch) | Guest | Guest, unchanged |
| Policy scope, request, note recipient, `accepted`, per-note cap, deterministic note ids, request totals, validity-window intersection (the pre-gate checks of PE-0 §4 other than the two signature checks) | Guest | Guest, unchanged |
| D1, D3 (scope, `lease_id`, `meter_spec` equal the policy's), D4–D9, the rule tree, `deliveryHash` | Guest | Guest, unchanged |
| `meterAddr`, `acceptanceAddr` from the policy's keys; `factsHash` | — | Guest derives and commits |
| Image ID, `schemaId`, `policyHash`, `deliverySpecHash`, obligation once, ceiling, recipient | Escrow | Escrow, unchanged |
| Signer recovery, low-s, `factsHash` equality (no index check: D1 keeps it) | — | Verifier, in `settle` |
| Batch closure, late notes | Seller's ledger (SS-10), guardrail windows (BG-6) | Unchanged |

*Formats* (normative copy and vectors in PE-9a's fixtures, `test/vectors/rent-facts-v1.json`, which Rust and Solidity
must both pass, as `test/vectors/usage-gates.json` does for the gates): an address is
`last20(keccak256(X_be32 ‖ Y_be32))` of the point the compressed policy key decodes to,
without the SEC1 `0x04` prefix (Geth's `PubkeyToAddress`), and a key that does not
decode to a curve point fails the policy check; a recoverable signature is 65 bytes
`r ‖ s ‖ v` with `v ∈ {27, 28}` and `s ≤ n/2`, produced by `sign-usage --recoverable`
and `sign-acceptance --recoverable`, new options, while the 64-byte default and
`core::verify` stay as they are, so no built image or consumer changes; the signing
bytes are the existing `tagged_bytes(warrant/usage/v1, record)` and the note's tag, so
no signed object changes; only `settle` consumes the 65-byte form, the guest of 46
receives no record or note signature. Native full-facts verification must enforce the same
`v`, low-s, recovery and hash checks as Solidity; it cannot ignore `v` in this mode.
The existing 64-byte verification path remains separate. `facts` is `u32_le n ‖ (u32_le len ‖ record_k
‖ sig_k) × n ‖ u32_le m ‖ (u32_le len ‖ note_k ‖ sig_k) × m`, records then notes in
position order, where each `record_k` and `note_k` is its tagged bincode bytes as
signed, `len` counts those bytes without the 65 of the signature, and trailing bytes
are refused; with `body = u32_le n ‖ (u32_le len ‖ record_k) × n ‖ u32_le m ‖
(u32_le len ‖ note_k) × m`, `factsHash = sha256(u64_le 22 ‖ "warrant/facts-batch/v1" ‖
u64_le len(body) ‖ body)`, the framing of `tagged_bytes` over raw bytes, so the guest, which never sees the signatures, computes the
same value and a re-randomised signature cannot change it. Records and notes become
public calldata, where today only `deliveryHash` is; integration §6.3 states this.
*Per chain:* where the signatures are verified is a deployment choice, not a protocol
constant. Each escrow deployment pins an image ID and a `schemaId`, so two images coexist across deployments
from one guest source with the record and note signature check behind a feature:
`signed-facts-in-guest` (today's path, D2 in the guest, 64-byte signatures, no
`facts`) for chains where gas is dear, and `facts-in-settle` (46) where it is cheap.
Which image a chain gets is decided by measurement, not assumed: the additional chain
fees of 46 per batch (PE-9a components, PE-9b's integrated difference) against the
proving cost it removes (PC-8 on CPU, PE-8 on GPU, which shrinks the saving). An
illustration only: assume ETH costs $2,000 and use the incomplete 361,944-gas component model above.
Those components cost about $0.029 at 0.04 gwei, or $3.62 at 5 gwei.
Assuming $0.10 to $0.30 of CPU proving savings gives a component-only break-even range of roughly 0.14 to 0.41 gwei.
Neither the ETH price nor the proving savings is a current measured price claim.
Do not quote a single 0.3-gwei deployment threshold from this illustration.
GPU savings and the full settlement difference can change the comparison.
On Arc and L2s, cheaper verification remains a hypothesis until measured.
L2 fees can include execution, L1 data and operator fees; blobs do not remove data costs.
See the [OP Stack fee documentation](https://docs.optimism.io/op-stack/transactions/fees).
Records, notes, gates and the rule tree are the same in
both images; only `schemaId` and the journal's three words differ.
*Alternatives:* (a) keep the checks in the guest: the prover stays the cost driver,
with the GPU host and the margin of 43; (b) an attestation registry written in a
separate transaction (the first draft of 46): rejected on the review, since it needs an
authorisation and closure story of its own and can be blocked by a valid prefix or
overwritten during proving; (c) no guest for the rent case, gates and rule tree in
Solidity, no proving at all: rejected for v1 because the rent gates would leave the
proved evaluator and the proof-only symmetry of 40, kept as the fallback if Groth16
verification on Arc proves too costly. *Consequences:* if 46 is taken, 44 (the batch
signature and the re-signing wait, BG-7) is superseded, because the proof verifies no
record or note signature; of 45, only the batch re-signing wait and the two-proof-form
fallback (`M`) are superseded: the persisted hourly records stay required (a
regenerated record can change its `deliverable_hash` and break the note's binding,
whoever verifies the signature), `SignBatchExternal`'s refusal of a differing
regenerated record becomes the batch builder's (PC-6), and the full-pipeline
measurements of PE-8 and DL-13 stay; 43 is not superseded: `settlement_margin_s` still
covers proving, the wrap, inclusion and finality and is set from PC-8 and PE-8, and
whether a CPU prover suffices is what PC-8 measures. One formula:
`G = challenge_timeout_s + settlement_margin_s`. New
items, each with a handoff brief in `docs/handoff/`: PC-8 (the bench: `ATTESTED=1`, the
credential signature in all three modes, cycles and, on a prover host, proving time);
PE-9a (standalone, on hold for the mode-priority decision: the formats and vectors in `core`, `--recoverable`
signing, the `RentFactsVerifier` contract with tests for a wrong key, a high-s
signature, a zero recovery, a note blob in the record section, a truncated batch, a
reordered batch, trailing bytes, a `facts` whose hash differs, and acceptance of batch 1
(indices 24 to 47) and of a partial later batch; gas on the Arc testnet); PE-9b (after
PE-0's review, PE-3 and PE-6: the PE-0 amendment, `settle(seal, journal, facts)`, both
images from one guest source, one batch settled end to end). *Reversal:* drop
`facts` and the verifier call; the guest verifies signatures again and 44 and 45
return; batches settled under 46 settle under 46's image and stay valid.
