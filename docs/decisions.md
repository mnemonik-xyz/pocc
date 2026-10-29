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
| 27 | 2026-10-29 | `lease_id = H(lease, tenant_pubkey, request_id, period)`; not `H(lease, request_hash)` | Taken | Integration §5, `pkg/pocc` | Formula change; leases of existing requests change |
| 28 | 2026-10-29 | A credited interval belongs to the hour it ends in; one ending exactly on the hour belongs to the hour before | Taken | Verifier | Changes which hour edge intervals credit, not the total |
| 29 | 2026-10-29 | In escrow mode the receipt's billed fields and signature are optional; billing is through the consumer's notes | Taken | Verifier | Make them mandatory again |

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
offline mode. *Reversal:* reinstate the Order type as the source of `h0`.

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
