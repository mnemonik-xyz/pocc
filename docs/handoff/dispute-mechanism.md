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
This profile trusts the meter. It is not a trust-free proof of physical compute.
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

Persist policy bytes, order identity, meter identity, hourly records, signatures, receipt inputs, closure and eligible prefix.
Store the exact acknowledgement request, received signature, local verification outcome, proof job and transaction hashes.
Never regenerate a signed record from a later receipt snapshot.
Copies and retention must survive buyer disconnection and outlive settlement finality.
No wallet private key or cloud credential belongs in a public receipt or evidence store.

## 4. Worker sequence

1. Read the funded mode, terms, image/schema and meter identity from trusted configuration and the accepted order.
2. Refuse an order whose evidence cannot be obtained independently or whose deadlines cannot be met.
3. Run the existing provisioning, metering, continuation and shutdown workflow.
4. Collect independent delivery and eligibility evidence continuously.
5. Close each full batch, or the final partial batch when the lease stops.
6. Build one canonical claim and compute the expected amount from the policy and evidence.
7. Send the buyer a typed settlement acknowledgement request. Retry the same request idempotently.
8. Check any returned signature and claim against the expected amount and fixed terms.
9. Submit acknowledgement settlement from the funded recipient account only after accepting its exact amount and closure terms.
10. If no valid acknowledgement has settled by `proof_after(batch)`, check on-chain consumption and start the prover.
11. Verify the resulting receipt locally against the pinned image and journal before submission.
12. Check consumption again and submit proof settlement before the deadline.
13. Reconcile both paths against finalized chain state before closing the payment reservation.

An acknowledgement received during proving can still settle. Cancel queued work when safe; running work can be wasted.
The contract's shared replay check resolves any submission race.
Acknowledgement settlement requires `msg.sender == order.recipient` in the contract, even for zero or reduced amounts.
The buyer and third-party relayers cannot consume the obligation using only a buyer signature.
Proof settlement remains permissionless after timeout and pays only the fixed recipient.
A provider contract wallet must call through its authorized execution path. An unrelated operator EOA cannot submit directly.
Relayed acknowledgements require a future, separately reviewed provider countersignature; this version does not support them.

A buyer signature is an offer until the provider submits it. The signature alone is not a reservation or a confirmed payment.
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
Preserve Lost overflow handling through Unresolved; do not drop reservations.
Repeated timeouts, retries, restarts and reorg reconciliation must be idempotent.
The old `Exposure()` remains a conservative service-exposure model, not a bound on proof fees or dispute-related capital lockup.
Recompute economic exposure with failed proofs, meter outages and the fallback settlement delay included.

## 7. Compatibility and implementation packages

| Package | Change |
|---|---|
| Policy adapter | New mode/version, response timeout, customer acknowledgement identity, independent meter and terms-hash fields |
| Meter service | Independent custody, durable evidence delivery, authenticated billing eligibility and terminal cutoff |
| Buyer integration | Display and sign the versioned batch acknowledgement; distinguish it from hourly continuation |
| Batch builder | Build the same closed claim for both paths from persisted evidence |
| Lease model | Held fallback reservations, expiry and exact-once reconciliation |
| Settlement worker | Provider-authorized acknowledgement submission, permissionless proof settlement after timeout, pinned-image verification, race/reorg handling |
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
15. Repeated rejected offers cannot restart the clock or change reservations; proof remains permissionless after timeout.
16. Non-divisible schedules and overflowing counts are refused before service starts.

The worker must refuse automatic acceptance of underpayment. An explicit provider concession remains possible.
The contract caller check prevents hostile submission; the worker check only prevents the provider from accepting by mistake.

Local model tests do not replace a real proved and funded testnet settlement.
The final acceptance report must identify the trusted meter and exactly what delivery property it attested.
