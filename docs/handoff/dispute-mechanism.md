# PoCC integration: dispute mechanism

Status: proposed specification, 3 Nov 2026. No implementation changes in this document.
Base: pocc PR #1 at `110d813`; policy-execution main at `e4b8ac8`.

The owner requested immediate payment on buyer acknowledgement, or proof settlement after a response period.
The existing service workflow remains the starting point.
The settlement unit and independent evidence authority are assumptions pending review.

The owner named this flow the **dispute mechanism**.
The normal path settles on buyer acknowledgement. The dispute path settles through a delivery proof after the response period.
"Fallback" below means the proof-based dispute path. Silence enables it but does not prove delivery.
This version resolves payment through the funded policy; it does not introduce a human arbitrator or appeals.
It is not the referee dispute of integration §8 (decision 20), which stays deferred.

The contract and evidence specification is
`policy-execution/docs/handoff/05-rent-dispute-mechanism.md`.
It lives in the companion `docs/dispute-mechanism` branch.
This file defines the PoCC work. It does not change decisions 40 or 46 silently.

## 1. Correctness finding

The existing buyer controls both the meter key and the per-piece acceptance key.
`pkg/lease` marks a timed-out note as loss and stops service.
`pkg/adapter/warrant.Decide` checks a subset of delivery gates. It is not a zkVM proof of delivery.
The existing rent proof specification still requires the absent buyer signature.

A final batch release signature can save proving when all hourly evidence already exists.
That optimization alone cannot recover a delivered hour whose buyer withheld its note or meter signature.
The requested full-silence fallback needs evidence available independently of that buyer.

## 2. Proposed scope

Preserve metered service batches. Acknowledgement pays the completed batch amount, not the remaining lease ceiling.
Provisioning and receipt of access credentials do not establish delivery of future compute hours.
If the intended product pays the full escrow at VM handover, define a separate handover predicate before implementation.

Proposed pilot evidence authority: a meter agreed by both parties and independent of both signing services.
The buyer records the proposed key before funding. Before accepting the order, the provider must approve that meter and its evidence-access commitments.
The provider must refuse terms whose meter, delivery predicate or retention promises it cannot accept.
It runs the verifier and signs records and billing eligibility under a key fixed before funding.
It must deliver the evidence to the provider without a new buyer signature.
This profile trusts the meter's signature at settlement. It is not a trust-free proof of physical compute.
The meter's output can be checked, however. Each usage record binds the hash of the receipt that it was computed from.
`pocc-verify` is deterministic, and the provider runs it for each piece, so the provider detects a false or conflicting record at once.
Anyone can refute such a record from the kept receipt. Detection is not enforcement: there is no referee or clawback in this version.
While the development anchor is in use, a refutation also rests on the notary's anchor key.

The agent runs inside the buyer's machine. The buyer can stop it, block it, or read its key (architecture §2a, decision 47).
The buyer cannot change anchored evidence: the notary keeps the first entry for each agent and sequence number.
A hostile buyer can therefore stop future evidence only. The provider watches the agent every slot and stops the machine after `liveness_miss_slots` slots (lease evidence SS-12).
The fallback pays only for time with anchored heartbeats. The listing states this.
A sidecar that the buyer cannot stop, and an observer, are research for a later improvement (`docs/research-sidecar-observer.md`).
The existing Stage 0 property table remains applicable.

X-1 remains the alternative for guest verification of authenticated raw evidence.
The current beacon client does not verify BLS signatures; hashing a signature into randomness is not that verification.
Roots alone also do not provide the witness bytes required by a prover.
Do not describe X-1 as already available.

## 3. Messages and persistent records

Use distinct names and storage for these objects:

| Object | Authority | Purpose |
|---|---|---|
| Funded policy and terms | Customer funding transaction | Advance authorization of the evidence model, schedule and payment bounds |
| Hourly continuation message | Existing buyer guardrail | Retains the current service continuation gate |
| Usage record | Agreed meter | Attests measured delivery; persist exact signed bytes |
| Billing eligibility / stop statement | Agreed meter | Binds billable prefix and observed continuation/stop events; excludes provisional work |
| Batch settlement acknowledgement | Funding customer | Direct authorization to release the displayed amount for the closed batch |
| Fallback receipt | Pinned rent guest | Verifies independent evidence and computes the payable amount |

Do not reuse an hourly `Acceptance` as a batch settlement acknowledgement.
Do not require a final buyer message to issue the fallback witness.
The meter must observe continuation and stopping as they happen; provider assertions alone cannot establish billing eligibility.
Freeze that witness type with Warrant before building the meter service.

Finality is part of the signed evidence, not a worker flag. Interim records and eligibility snapshots use separate types and tags and cannot authorize settlement.
Within the accepted policy scope, persist one final record content per `(lease_id, index)`, one final batch content per `(lease_id, batch)`, and one terminal stop content per lease.
Persist each commitment atomically before signing. Retries and crash recovery return the same content; they must not revise units, record hashes or cutoffs.
Replacing a signing key or service instance cannot reset the accepted lease's finalization history.

Finalize each record after its piece ends and the policy's evidence-completion/finality rule holds.
A final batch covers every scheduled piece, including zero-unit outages, unless a unique terminal statement establishes its exact final eligible prefix.
Bind that terminal statement's hash into the final batch when closing early. Do not select an arbitrary shorter prefix.
The guest rejects interim evidence, short non-final batches, incomplete final prefixes and supplied contradictory statements.
The worker must compare final evidence with its persisted expected claim before submitting either settlement.
On observed conflicting final statements, retain them and stop automatic settlement and service. Do not select whichever version pays most or arrives first.
Run `pocc-verify` on the receipt that each statement binds. A statement that does not follow from its receipt is the meter's fault; record that result with both statements.
This identifies the fault. It does not authorize a payment.
When the liveness watch stops the lease, the terminal stop statement records that stop, with the last piece that has anchored heartbeats as its cutoff.
Keep pending reservations Held until an authorized outcome or existing expiry/loss classification.

These are trusted-meter operating rules. A guest cannot detect an undisclosed conflicting signature elsewhere.
They complement the contract caller restriction; they do not justify permissionless proof settlement.
Different proof encodings for the same final entitlement are valid; the signed content must remain consistent.

Persist policy bytes, order identity, meter identity, hourly records, signatures, receipt inputs, closure and eligible prefix.
Store the exact acknowledgement request, received signature, local verification outcome, proof job and transaction hashes.
Never regenerate a signed record from a later receipt snapshot.
Copies and retention must survive buyer disconnection and outlive settlement finality.
No wallet private key or cloud credential belongs in a public receipt or evidence store.

## 4. Worker sequence

1. Read the funded mode, terms, image/schema and meter identity from trusted configuration and the accepted order.
2. Refuse an order whose evidence cannot be obtained independently or whose deadlines cannot be met.
3. Run the existing provisioning, metering, continuation and shutdown workflow, plus the per-slot liveness watch (PC-9, lease evidence SS-12).
4. Collect independent delivery and eligibility evidence continuously. Store every anchored entry and its inclusion proof within one slot (SS-13).
5. Close each full batch, or the final partial batch when the lease stops.
6. Build one canonical claim and compute the expected amount from the policy and evidence.
7. Send the buyer a typed settlement acknowledgement request. Retry the same request idempotently.
8. Check any returned signature and claim against the expected amount and fixed terms.
9. Submit acknowledgement settlement from the funded recipient account only after accepting its exact amount and closure terms.
10. If no valid acknowledgement has settled by `proof_after(batch)`, check on-chain consumption and start the prover.
11. Verify the resulting receipt locally against the pinned image and journal before submission.
12. Compare the proved claim with final evidence, check consumption again, and submit proof settlement from the funded recipient account before the deadline.
13. Reconcile both paths against finalized chain state before closing the payment reservation.

An acknowledgement received during proving can still settle. Cancel queued work when safe; running work can be wasted.
The contract's shared replay check resolves any submission race.
Both settlement paths require `msg.sender == order.recipient` in the contract, even for zero or reduced amounts and final-prefix cutoffs.
The buyer and third parties cannot consume the obligation using a signature or a valid proof without provider submission.
Proof settlement also requires a verified receipt after timeout and pays only the fixed recipient.
A provider contract wallet must call through its authorized execution path. An unrelated operator EOA cannot submit directly.
Direct third-party settlement on either path requires a future, separately reviewed provider countersignature; this version does not support it.
Provider account availability is therefore required for both paths. Provers can produce receipts without receiving the provider account's signing authority.
Do not add a permissionless timeout bypass. It would allow competing valid claims to consume the batch again.

A buyer signature is an offer until the provider submits it. Neither a signature nor a proof alone reserves or settles the claim.
Rejected or invalid offers cannot reset the response period, set a terminal cutoff, change spend or consume the batch.
Check the full journal, including evidence hash, amount, prefix and cutoff, before signing the provider transaction.
Do not use the worker's amount check as a substitute for the contract's caller check.
Never redirect the recipient or automatically deduct proof costs from the buyer's funded ceiling.
The provider bears those costs unless a separately agreed policy explicitly prices them.

## 5. Time and early stopping

Keep hourly `challenge_timeout_s` for service continuation.
Add separate `ack_timeout_s` for batch settlement response.
Reject zero piece sizes, non-positive periods and periods not exactly divisible by `piece_s` before calculating the number of pieces.
Require aligned service start, a supported positive batch size, and checked index/deadline arithmetic without truncation.
The proof gate uses the funded schedule, not a provider-supplied message timestamp:

```text
proof_after(b) = scheduled_batch_end(b) + ack_timeout_s
deadline(b) = proof_after(b) + settlement_margin_s
```

The final partial batch can settle by acknowledgement after its last completed eligible piece.
Its proof waits for the scheduled batch deadline basis, even if the VM stopped early.
Choose small batches if that delay is commercially unacceptable.
Do not invent an early delivery timestamp or shorten the buyer's funded response period.

A non-responsive buyer still triggers service shutdown under the existing continuation gate.
Completed eligible service remains claimable; provisional work remains unbillable.
Future service cannot be paid merely because escrow remains funded.
Final-prefix closure records a terminal lease cutoff shared by both paths and deployments.
The acknowledgement path requires both the buyer signature and provider submission for that final prefix.
It records their agreement; it does not independently prove physical shutdown. The provider must stop before accepting the cutoff.
The proof path instead authenticates the stop and eligible prefix through the guest's evidence checks.
Reject a cutoff below the shared registry's highest settled index.

## 6. Lease model changes

Reuse `pkg/lease` checked arithmetic, reservation bounds, stopping and exact-once batch closure.
Do not change an existing mode's semantics in place.

The current `TimedOut -> Lost` transition is wrong for completed independently provable service in this new mode.
Such service must enter Held with a pending-acknowledgement or pending-proof substate.
Keep provisional losses distinct. Do not count a signature and proof as separate obligations or separate Held balances.
A signature, queued proof, valid local receipt and submitted transaction are not final settlement states.

Keep the ceiling reservation until finalized payment or final loss classification.
Add the liveness stop as a Stopping cause. Time after the last anchored heartbeat is provider loss, bounded by `E` because `liveness_miss_slots × 60 s ≤ challenge_timeout_s`.
Preserve Lost overflow handling through Unresolved; do not drop reservations.
Repeated timeouts, retries, restarts and reorg reconciliation must be idempotent.
The old `Exposure()` remains a conservative service-exposure model, not a bound on proof fees or dispute-related capital lockup.
Recompute economic exposure with failed proofs, meter outages and the fallback settlement delay included.

## 7. Compatibility and implementation packages

| Package | Change |
|---|---|
| Policy adapter | New mode/version, response timeout, customer acknowledgement identity, independent meter and terms-hash fields |
| Meter service | Independent custody, durable final-content commitments, evidence delivery, authenticated eligibility and unique terminal cutoff |
| Buyer integration | Display and sign the versioned batch acknowledgement; distinguish it from hourly continuation |
| Batch builder | Build the same closed claim for both paths from persisted evidence |
| Lease model | Held fallback reservations, expiry and exact-once reconciliation |
| Settlement worker | Provider submission on both paths, final-evidence selection, proof settlement after timeout, pinned-image verification, race/reorg handling |
| Benchmark | New fallback witness and guest; CPU/GPU latency, concurrent queueing and both transaction paths |

Policy-execution owns the authoritative encodings and shared fixtures.
Do not use pocc JSON serialization as a replacement for Warrant's signing encoding.
New fixtures cover every field of the acknowledgement, journal, terms and meter statement.

Decisions affected if this mode is adopted:

- 25/35: buyer-controlled metering cannot guarantee settlement against that buyer's silence; independent evidence adds a different trust boundary.
- 36/42: retain service stopping on absent or insufficient continuation, but allow proof recovery for eligible delivered service.
- 38/41/45: retain closed batches, persistence and bounded accounting; distinguish response time from proof margin.
- 40: add a buyer-authorized, provider-accepted fast path for the new rent mode. Existing proof-only orders remain unchanged.
- 43: benchmark the new fallback guest before selecting prover capacity.
- 47: applies unchanged. The liveness watch and evidence custody bound what a buyer gains by stopping the agent.
- 44/46: do not require buyer notes or batch re-signing on a path intended to work without them.
  Optional Solidity verification of independent meter signatures requires a separate interface review.

Do not mark these decisions Taken merely because this draft exists.

Implementation priority: PE-9a and PE-9b of decision 46 are on hold for the owner's mode-priority decision.
They target the existing buyer-note mode, not this dispute mode. PC-8 can remain a comparative experiment for that earlier mode.
If disputes are selected first, keep PE-9a/PE-9b deferred and benchmark the new independent-evidence guest.
Do not treat `m = 0` as a compatible extension of decision 46; the authorization and eligibility witness also change.
Stacking this PR on #1 is a documentation dependency, not an approval to implement both modes together.

## 8. Acceptance evidence

Existing checks run on 3 Nov 2026:

- `go test ./pkg/lease ./pkg/adapter/warrant`: passed.
- Companion `InvoiceEscrowTest`: 30 tests passed with its test verifier.

Required new scenarios:

1. Buyer signs and provider submits the exact accepted claim; no proof is generated; one payment finalizes.
2. Buyer is entirely offline after funding; first eligible completed piece settles through independent evidence.
3. Buyer refuses only the final release signature; existing evidence is still usable.
4. Missing or forged independent evidence never pays on timeout alone.
5. Acknowledgement and proof race in both orders; one obligation and one payment.
6. Buyer submits zero or one unit for a fully delivered batch: contract rejects; a later full proof can still settle.
7. A stopped lease settles a final prefix; provisional service and later suffix never pay.
8. Crash during challenge, closure, signing, proof and submission; restart preserves commitments and balances.
9. Proof failure, retries, deadline boundary, refund and reorg; Held is retained until the outcome is known.
10. No buyer secret or signing endpoint is available during the full fallback test.
11. Buyer submits a one-piece final prefix while later delivered batches are unpaid: contract rejects; no cutoff or payment state changes.
12. A relayer copies a valid buyer signature: acknowledgement submission fails without a provider caller.
13. Provider deliberately accepts a reduced or zero amount: it closes once, with no later top-up.
14. Provider contract-wallet execution succeeds; an unrelated operator's direct submission fails.
15. Repeated rejected offers cannot restart the clock or change reservations; the provider's proof remains usable after timeout.
16. Non-divisible schedules and overflowing counts are refused before service starts.
17. Buyer or relayer submits a valid lower-value proof, earlier cutoff or copied provider proof: Unauthorized, with no payment-state changes.
18. Provider submits the full claim after those rejected attempts: it remains payable under all common bounds.
19. Interim eligibility or usage evidence is supplied to the guest: reject even when the signature is valid.
20. A short non-final prefix lacks a terminal statement, or ends before its declared cutoff: reject.
21. Meter restart attempts to re-sign changed units or a different final batch prefix: durable commitment check refuses it.
22. Worker observes conflicting final batch or terminal statements: retain evidence, stop automatic settlement and service, and retain Held accounting.
23. Provider submits an invalid proof: reject despite the authorized caller.
24. Buyer stops the agent or blocks its network mid-batch: the provider stops within `liveness_miss_slots` slots plus shutdown latency; anchored earlier pieces stay payable by proof; later time is unpaid.
25. Buyer signs a different entry for an anchored sequence number with the extracted key: the notary refuses it; the claim does not change.
26. Buyer signs an early final heartbeat: credit ends there, the provider stops, and the terminal stop statement records the cutoff.
27. Meter signs a record that does not follow from its bound receipt: the provider's verifier run detects it; automatic settlement stops and both results are kept.

The worker must refuse automatic acceptance of underpayment. An explicit provider concession remains possible.
The contract caller check prevents hostile submission through either path; worker and guest checks prevent acceptance of interim or inconsistent evidence.

Local model tests do not replace a real proved and funded testnet settlement.
The final acceptance report must identify the trusted meter and exactly what delivery property it attested.
