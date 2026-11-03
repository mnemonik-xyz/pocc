package lease

import (
	"strings"
	"testing"
)

// The DL-11 scenarios of lease evidence 5a.5 and 5a.6, each with the expected
// outcome the specification names.

const (
	start   = int64(1794819600) // 2026-11-16T09:00:00Z
	hour    = int64(3600)
	timeout = int64(300)
	margin  = int64(1800)
	price   = uint64(1100)
	cap     = uint64(3600 * 1100) // max_note: a full hour
)

func params(hours int64, batch uint32, ceiling uint64) Params {
	p := Params{ServiceStart: start, ServiceEnd: start + hours*hour, PieceS: hour,
		ChallengeTimeoutS: timeout, SettlementMarginS: margin, ShutdownLatencyS: 60,
		MaxNote: cap, Ceiling: ceiling, BatchSize: batch}
	p.SettleBy = p.Deadline(p.Batch(p.Pieces()-1)) + 7*24*hour
	return p
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func check(t *testing.T, l *Lease) {
	t.Helper()
	if err := l.Invariant(); err != nil {
		t.Fatalf("%v\n%s", err, dump(l))
	}
}

func dump(l *Lease) string {
	var b strings.Builder
	for _, e := range l.Log {
		b.WriteString(strings.TrimSpace(strings.Repeat(" ", 0)+e.What) + "\n")
	}
	return b.String()
}

// answer is a cooperative buyer: it signs the full note for piece k right after
// the challenge, with the BG-6 window.
func answer(t *testing.T, l *Lease, k uint32, amount uint64, now int64) {
	t.Helper()
	must(t, l.Note(k, amount, l.P.Deadline(l.P.Batch(k)), now))
	check(t, l)
}

// Run a lease where every piece is answered: n hours, settled in batches.
func TestCooperativeLease(t *testing.T) {
	p := params(3, 3, 3*cap)
	l, err := New(p)
	must(t, err)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	for k := uint32(0); k < 3; k++ {
		must(t, l.PieceEnd(k, cap, p.End(k)))
		check(t, l)
		answer(t, l, k, cap, p.End(k)+30)
	}
	if l.State != Stopped || !l.Batches[0].Closed {
		t.Fatalf("state %s\n%s", l.State, dump(l))
	}
	got, err := l.Settle(0, p.End(2)+600, true)
	must(t, err)
	if got != 3*cap || l.Ledger.Settled != 3*cap || l.Ledger.Held != 0 || l.Ledger.Open != 0 || l.Ledger.Lost != 0 {
		t.Fatalf("settled %d, ledger %+v", got, l.Ledger)
	}
	if _, err := l.Settle(0, p.End(2)+700, true); err == nil {
		t.Fatal("a consumed batch settled twice")
	}
}

// DL-11: no response to the first challenge. The machine stops
// challenge_timeout_s after piece 0 ends; no note exists; the loss is E.
func TestNoResponseToFirstChallenge(t *testing.T) {
	p := params(3, 3, 3*cap)
	l, _ := New(p)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	must(t, l.PieceEnd(0, cap, p.End(0)))
	check(t, l)
	if l.Ledger.Open != 2*cap { // piece 0 challenged, piece 1 provisional
		t.Fatalf("open %d, want two pieces", l.Ledger.Open)
	}
	l.Tick(p.End(0) + timeout - 1)
	if l.State != Running {
		t.Fatal("stopped before the timeout")
	}
	l.Tick(p.End(0) + timeout)
	check(t, l)
	if l.State != Stopped || l.Ledger.Held != 0 || l.Ledger.Settled != 0 || l.Ledger.Open != 0 {
		t.Fatalf("state %s ledger %+v\n%s", l.State, l.Ledger, dump(l))
	}
	// The seller's loss in reservations is piece 0 and the provisional piece 1;
	// the money lost is bounded by E (one piece plus grace and shutdown).
	if l.Ledger.Lost != 2*cap {
		t.Fatalf("lost %d", l.Ledger.Lost)
	}
	if e, err := p.Exposure(0); err != nil || e != cap+price*uint64(timeout+60) {
		t.Fatalf("E = %d, %v", e, err)
	}
	if err := l.Note(0, cap, p.Deadline(0), p.End(0)+timeout+1); err == nil {
		t.Fatal("a note after the deadline was accepted")
	}
}

// DL-11: a lease whose ceiling covers one piece. Piece 1 never starts: SS-10
// refuses its reservation while piece 0 is open.
func TestOneHourFundedLease(t *testing.T) {
	p := params(3, 3, cap)
	l, _ := New(p)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	must(t, l.PieceEnd(0, cap, p.End(0)))
	check(t, l)
	if l.State != Stopping || !strings.HasPrefix(l.Stopped, "SS-10: ceiling") || l.Pieces[1] != Unserved {
		t.Fatalf("state %s (%s), piece 1 %d\n%s", l.State, l.Stopped, l.Pieces[1], dump(l))
	}
	answer(t, l, 0, cap, p.End(0)+30)
	if l.State != Stopped || !l.Batches[0].Closed {
		t.Fatalf("state %s\n%s", l.State, dump(l))
	}
	got, err := l.Settle(0, p.End(0)+600, true)
	must(t, err)
	if got != cap || l.Ledger.Settled != cap {
		t.Fatalf("settled %d", got)
	}
}

// DL-11: a late response after the batch closed is refused "batch closed";
// the batch settles the notes it holds.
func TestLateResponseAfterBatchClosed(t *testing.T) {
	p := params(2, 2, 2*cap)
	l, _ := New(p)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	must(t, l.PieceEnd(0, cap, p.End(0)))
	answer(t, l, 0, cap, p.End(0)+30)
	must(t, l.PieceEnd(1, cap, p.End(1))) // service end: stopping, final challenge 1
	l.Tick(p.End(1) + timeout)            // buyer silent: batch 0 closes with note 0
	check(t, l)
	if l.State != Stopped || !l.Batches[0].Closed || len(l.Batches[0].Notes) != 1 {
		t.Fatalf("state %s batch %+v\n%s", l.State, l.Batches[0], dump(l))
	}
	err := l.Note(1, cap, p.Deadline(0), p.End(1)+timeout+10)
	if err == nil || !strings.Contains(err.Error(), "SS-11") {
		t.Fatalf("late note: %v", err)
	}
	got, err := l.Settle(0, p.End(1)+timeout+600, true)
	must(t, err)
	if got != cap || l.Ledger.Lost != cap {
		t.Fatalf("settled %d lost %d", got, l.Ledger.Lost)
	}
}

// DL-11: a note that would expire inside an unfinished batch is never valid:
// BG-6 fixes valid_until to deadline(b), and SS-11 refuses anything else.
func TestExpiringNoteRefused(t *testing.T) {
	p := params(3, 3, 3*cap)
	l, _ := New(p)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	must(t, l.PieceEnd(0, cap, p.End(0)))
	err := l.Note(0, cap, p.End(0)+timeout, p.End(0)+30)
	if err == nil || !strings.Contains(err.Error(), "BG-6") {
		t.Fatalf("short window: %v", err)
	}
	answer(t, l, 0, cap, p.End(0)+40) // the right window is accepted
}

// DL-11 with SS-14 (decision 48): a middle piece below the floors gets a zero
// note, which stays in its batch. The lease stops at once: piece 2 is never
// served, and the batch settles the earlier piece.
func TestZeroNoteMiddlePiece(t *testing.T) {
	p := params(3, 3, 3*cap)
	l, _ := New(p)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	must(t, l.PieceEnd(0, cap, p.End(0)))
	answer(t, l, 0, cap, p.End(0)+30)
	must(t, l.PieceEnd(1, 0, p.End(1))) // the seller's own verifier saw the outage
	check(t, l)
	if l.State != Stopping || l.Pieces[2] != Unserved || l.Ledger.Open != cap {
		t.Fatalf("a zero-payable piece did not stop the lease: %s, piece 2 %d\n%s", l.State, l.Pieces[2], dump(l))
	}
	answer(t, l, 1, 0, p.End(1)+30) // the record shows it too: a correct zero note
	if l.State != Stopped || !l.Batches[0].Closed || len(l.Batches[0].Notes) != 2 || len(l.Underpaid) != 0 {
		t.Fatalf("state %s batch %+v\n%s", l.State, l.Batches[0], dump(l))
	}
	if err := l.PieceEnd(2, cap, p.End(2)); err == nil {
		t.Fatal("piece 2 served after a zero-payable piece")
	}
	got, err := l.Settle(0, p.End(1)+600, true)
	must(t, err)
	if got != cap || l.Ledger.Settled != cap || l.Ledger.Lost != 0 || l.Ledger.Open != 0 || l.Ledger.Held != 0 {
		t.Fatalf("settled %d ledger %+v", got, l.Ledger)
	}
}

// DL-11: the buyer disappears after the last piece. The final timeout passes,
// the held notes settle, the last piece is unpaid.
func TestBuyerDisappearsAfterLastPiece(t *testing.T) {
	p := params(3, 3, 3*cap)
	l, _ := New(p)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	for k := uint32(0); k < 2; k++ {
		must(t, l.PieceEnd(k, cap, p.End(k)))
		answer(t, l, k, cap, p.End(k)+30)
	}
	must(t, l.PieceEnd(2, cap, p.End(2)))
	l.Tick(p.End(2) + timeout)
	check(t, l)
	got, err := l.Settle(0, p.End(2)+timeout+600, true)
	must(t, err)
	if got != 2*cap || l.Ledger.Lost != cap || l.Pieces[2] != TimedOut {
		t.Fatalf("settled %d lost %d piece 2 %d\n%s", got, l.Ledger.Lost, l.Pieces[2], dump(l))
	}
}

// DL-11: a duplicate challenge answer returns the same note; a different one
// is refused (BG-2).
func TestDuplicateChallenge(t *testing.T) {
	p := params(2, 2, 2*cap)
	l, _ := New(p)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	must(t, l.PieceEnd(0, cap, p.End(0)))
	answer(t, l, 0, cap, p.End(0)+30)
	must(t, l.Note(0, cap, p.Deadline(0), p.End(0)+60)) // same answer again
	if err := l.Note(0, cap-1, p.Deadline(0), p.End(0)+70); err == nil {
		t.Fatal("a second, different note for index 0 was accepted")
	}
	if l.Ledger.Held != cap {
		t.Fatalf("held %d after a repeated note", l.Ledger.Held)
	}
}

// DL-11: a proof failure near the deadline is retried inside the margin; past
// the deadline the batch is lost and recorded.
func TestProofFailureNearDeadline(t *testing.T) {
	p := params(1, 1, cap)
	l, _ := New(p)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	must(t, l.PieceEnd(0, cap, p.End(0)))
	answer(t, l, 0, cap, p.End(0)+30)
	if _, err := l.Settle(0, p.Deadline(0)-60, false); err == nil || l.Batches[0].Lost {
		t.Fatalf("prover failure: %v, lost %v", err, l.Batches[0].Lost)
	}
	got, err := l.Settle(0, p.Deadline(0)-10, true)
	must(t, err)
	if got != cap {
		t.Fatalf("settled %d on retry", got)
	}

	l2, _ := New(p)
	must(t, l2.Accept(start-600))
	must(t, l2.Boot(start-120))
	must(t, l2.PieceEnd(0, cap, p.End(0)))
	answer(t, l2, 0, cap, p.End(0)+30)
	if _, err := l2.Settle(0, p.Deadline(0)+1, true); err == nil || !l2.Batches[0].Lost || l2.Ledger.Lost != cap {
		t.Fatalf("past the deadline: %v, ledger %+v", err, l2.Ledger)
	}
}

// DL-11: unavailable evidence. The seller cannot challenge without the
// evidence for the piece; the piece is then unpaid and the lease stops. In the
// model this is the seller stopping with the piece served and unchallenged:
// the final challenge is still sent, so a buyer with its own copy (BG-5) can
// answer; without an answer the piece is lost.
func TestUnavailableEvidence(t *testing.T) {
	p := params(2, 2, 2*cap)
	l, _ := New(p)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	l.Stop(p.End(0)-600, "notary unreachable: no evidence for piece 0")
	check(t, l)
	if l.State != Stopping || l.Pieces[0] != Challenged {
		t.Fatalf("state %s piece 0 %d\n%s", l.State, l.Pieces[0], dump(l))
	}
	l.Tick(p.End(0) - 600 + timeout)
	if l.State != Stopped || l.Ledger.Lost != cap || l.Ledger.Open != 0 {
		t.Fatalf("state %s ledger %+v", l.State, l.Ledger)
	}
}

// The exposure bound holds at every step: at most two pieces are in flight
// (one challenged, one provisional) and the ledger never exceeds the ceiling.
func TestExposureBound(t *testing.T) {
	p := params(5, 2, 5*cap)
	l, _ := New(p)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	for k := uint32(0); k < 5; k++ {
		must(t, l.PieceEnd(k, cap, p.End(k)))
		check(t, l)
		if l.Ledger.Open > 2*cap {
			t.Fatalf("piece %d: %d open", k, l.Ledger.Open)
		}
		answer(t, l, k, cap, p.End(k)+30)
		// A full batch settles inside its own deadline, not at the lease's end.
		if b := p.Batch(k); l.Batches[b].Closed && !l.Batches[b].Settled {
			if _, err := l.Settle(b, p.End(k)+600, true); err != nil {
				t.Fatalf("batch %d: %v", b, err)
			}
		}
	}
	if l.Ledger.Settled != 5*cap || l.Ledger.Held+l.Ledger.Open+l.Ledger.Lost != 0 {
		t.Fatalf("ledger %+v", l.Ledger)
	}
}

// SS-5: the seller refuses an order whose settleBy precedes deadline(last batch).
func TestSettleByTooEarly(t *testing.T) {
	p := params(2, 2, 2*cap)
	p.SettleBy = p.Deadline(0) - 1
	if _, err := New(p); err == nil {
		t.Fatal("accepted an order that cannot settle")
	}
}

// Finding 6 of the 2 Nov audit: a zero note for a delivered piece is an
// underpayment, not an outage. The seller keeps the note and stops after that
// piece. Regression for decision 48: three zero notes for outages the seller
// saw itself used to leave the lease running; now the first one stops it.
func TestUnderpaymentStops(t *testing.T) {
	p := params(4, 4, 4*cap)
	l, _ := New(p)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	must(t, l.PieceEnd(0, cap, p.End(0)))
	answer(t, l, 0, cap, p.End(0)+30)
	must(t, l.PieceEnd(1, cap, p.End(1))) // the seller's verifier credited the full hour
	answer(t, l, 1, 0, p.End(1)+30)       // the buyer signs zero: underpayment
	// Piece 1 already has its note, so nothing is open: the lease stops at once.
	if len(l.Underpaid) != 1 || l.Underpaid[0] != 1 || l.Pieces[2] != Unserved {
		t.Fatalf("underpaid %v piece 2 %d\n%s", l.Underpaid, l.Pieces[2], dump(l))
	}
	check(t, l)
	if l.State != Stopped || l.Ledger.Held != cap || l.Ledger.Lost != cap || !l.Batches[0].Closed {
		t.Fatalf("state %s ledger %+v\n%s", l.State, l.Ledger, dump(l))
	}

	l2, _ := New(p)
	must(t, l2.Accept(start-600))
	must(t, l2.Boot(start-120))
	must(t, l2.PieceEnd(0, 0, p.End(0))) // an outage the seller saw: piece 1 is never reserved
	answer(t, l2, 0, 0, p.End(0)+30)
	if l2.State != Stopped || len(l2.Underpaid) != 0 || l2.Pieces[1] != Unserved || l2.Ledger.Lost != 0 || l2.Ledger.Open != 0 {
		t.Fatalf("an outage zero note left the lease running: %s, piece 1 %d, ledger %+v\n%s",
			l2.State, l2.Pieces[1], l2.Ledger, dump(l2))
	}
	if err := l2.PieceEnd(1, 0, p.End(1)); err == nil {
		t.Fatal("a second unpaid hour was served")
	}
	check(t, l2)
}

// Finding 5: extreme parameters are refused, and the arithmetic is checked.
func TestBoundedParameters(t *testing.T) {
	p := params(2, 2, 2*cap)
	p.MaxNote, p.Ceiling = uint64(1)<<63, ^uint64(0)
	if _, err := New(p); err == nil {
		t.Fatal("accepted amounts that overflow")
	}
	p = params(2, 2, 2*cap)
	p.MaxNote = 3600*1100 + 1 // not divisible by the piece: E rounds up
	e, err := p.Exposure(0)
	must(t, err)
	if e <= p.MaxNote+1100*uint64(timeout+60) {
		t.Fatalf("E = %d did not round up", e)
	}
	p.ChallengeTimeoutS = hour
	if _, err := New(p); err == nil {
		t.Fatal("accepted a grace longer than a piece")
	}
}

// Fifth audit round: the loss ledger is checked and bounded; a negative
// shutdown latency is refused and Exposure returns an error, never panics.
func TestLossLedgerAndNegativeLatency(t *testing.T) {
	p := params(8, 1, uint64(1)<<62)
	p.MaxNote = uint64(1) << 61 // eight one-piece batches: 8 x 2^61 = 2^64 would wrap
	l, _ := New(p)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	var lastErr error
	var served uint32
	for k := uint32(0); k < 8 && l.State == Running; k++ {
		// Each piece is answered, each batch closes and is then left to expire.
		must(t, l.PieceEnd(k, p.MaxNote, p.End(k)))
		answer(t, l, k, p.MaxNote, p.End(k)+30)
		_, lastErr = l.Settle(k, p.Deadline(k)+1, true)
		if lastErr == nil {
			t.Fatalf("batch %d settled past its deadline", k)
		}
		if err := l.Invariant(); err != nil {
			t.Fatalf("after batch %d: %v", k, err)
		}
		served = k + 1
	}
	// Four 2^61 batches reach MaxLedger (2^63); the fifth and sixth refuse,
	// stay Held and unsettled, and the ledger keeps its last good value
	// instead of wrapping to zero. The unsettled notes then exhaust the
	// ceiling (SS-10) and the lease stops before piece 6.
	if l.Ledger.Lost != 4*p.MaxNote || !strings.Contains(lastErr.Error(), "overflow") || l.Ledger.Held != 2*p.MaxNote || served != 6 {
		t.Fatalf("lost %d held %d served %d, last error %v\n%s", l.Ledger.Lost, l.Ledger.Held, served, lastErr, dump(l))
	}

	q := params(2, 2, 2*cap)
	q.ShutdownLatencyS = -q.ChallengeTimeoutS - 1
	if _, err := New(q); err == nil {
		t.Fatal("negative shutdown latency accepted")
	}
	if _, err := q.Exposure(0); err == nil {
		t.Fatal("Exposure accepted a negative shutdown latency")
	}
}

// Sixth audit round: when the loss ledger is at its bound, a timed-out piece
// and a provisional piece are kept as unresolved accounting, never dropped;
// the service still stops.
func TestUnresolvedWhenLossLedgerFull(t *testing.T) {
	p := params(8, 1, uint64(1)<<62)
	p.MaxNote = uint64(1) << 61
	l, _ := New(p)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	for k := uint32(0); k < 4; k++ { // four expired batches fill Lost to 2^63
		must(t, l.PieceEnd(k, p.MaxNote, p.End(k)))
		answer(t, l, k, p.MaxNote, p.End(k)+30)
		if _, err := l.Settle(k, p.Deadline(k)+1, true); err == nil {
			t.Fatal("settled past the deadline")
		}
	}
	must(t, l.PieceEnd(4, p.MaxNote, p.End(4))) // challenge 4 open, piece 5 provisional
	if l.Ledger.Open != 2*p.MaxNote || l.Ledger.Lost != MaxLedger {
		t.Fatalf("before timeout: %+v", l.Ledger)
	}
	l.Tick(p.End(4) + timeout)
	check(t, l)
	if l.State != Stopped || l.Ledger.Open != 0 || l.Ledger.Lost != MaxLedger || l.Ledger.Unresolved != 2*p.MaxNote {
		t.Fatalf("after timeout: state %s %+v\n%s", l.State, l.Ledger, dump(l))
	}
}
