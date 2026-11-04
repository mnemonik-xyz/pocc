// Package lease is the seller's side of a rent lease as lease evidence 5a.5
// and 5a.6 specify it: the state machine, the reservation ledger (SS-10), batch
// closing (SS-11), note windows (BG-6) and the deadline formula. It moves no
// money and signs nothing; it decides what the seller's service does next and
// records every reservation exactly once. The simulation in lease_test.go runs
// the DL-11 scenarios against it. Decisions 47 and 48 add the coverage stop and
// the zero-payable stop (SS-12, SS-14) here, and the slot-by-slot decision
// logic of the liveness and coverage watch in watch.go; watch_test.go runs the
// DL-15 regression cases.
package lease

import (
	"errors"
	"fmt"
	"math/bits"
)

// MaxAmount bounds every token amount a policy may name (2^62) and MaxLedger
// bounds every ledger category (2^63), so that no sum the model forms can
// wrap a uint64 (finding 5 of the 2 Nov audit). A policy above MaxAmount is
// refused by Check; a ledger transition above MaxLedger is refused and
// logged, and the ledger keeps its last good value.
const (
	MaxAmount = uint64(1) << 62
	MaxLedger = uint64(1) << 63
)

// add is checked addition on amounts.
func add(a, b uint64) (uint64, error) {
	s, c := bits.Add64(a, b, 0)
	if c != 0 || s > MaxLedger {
		return 0, fmt.Errorf("amount overflow: %d + %d", a, b)
	}
	return s, nil
}

// Params are the policy and listing values the state machine depends on.
type Params struct {
	ServiceStart      int64  // unix seconds, on a piece boundary
	ServiceEnd        int64  // unix seconds
	PieceS            int64  // piece length
	ChallengeTimeoutS int64  // grace after a piece before the seller stops
	SettlementMarginS int64  // M: the seller's proving and settlement margin
	ShutdownLatencyS  int64  // how long it takes to terminate the machine
	MaxNote           uint64 // token base units, one piece
	Ceiling           uint64 // token base units, the lease
	BatchSize         uint32
	SettleBy          int64 // the order's settleBy

	// Decision 47 and 48 (lease evidence SS-12): the liveness and coverage
	// watch. Zero values disable the watch's stops; Check bounds them.
	MinCoverageBP     uint16 // the policy's min_coverage_bp (D6); 0 disables the coverage stop
	LivenessMissSlots uint32 // consecutive slots without a valid anchored heartbeat that stop the lease; 0 disables
	SlotS             int64  // the PoCC slot length (60 s)
}

// Pieces is the number of scheduled pieces.
func (p Params) Pieces() uint32 { return uint32((p.ServiceEnd - p.ServiceStart) / p.PieceS) }

// Start and End of piece k.
func (p Params) Start(k uint32) int64 { return p.ServiceStart + int64(k)*p.PieceS }
func (p Params) End(k uint32) int64   { return p.Start(k) + p.PieceS }

// Batch of piece k.
func (p Params) Batch(k uint32) uint32 { return k / p.BatchSize }

// Last is the last scheduled piece inside batch b.
func (p Params) Last(b uint32) uint32 {
	last := (b+1)*p.BatchSize - 1
	if n := p.Pieces(); last > n-1 {
		last = n - 1
	}
	return last
}

// Grace is G = 2 * challenge_timeout_s + M: one timeout for the batch's last
// note, one for the batch signature (BG-7), and the margin M budgeted for the
// slower fallback proof with per-record signatures (lease evidence 5a.5).
func (p Params) Grace() int64 { return 2*p.ChallengeTimeoutS + p.SettlementMarginS }

// Deadline is deadline(b) = service_start + (last(b) + 1) * piece_s + G: the one
// deadline formula of 5a.5. BG-6 sets note windows to it; SS-10 and the
// settlement worker use it.
func (p Params) Deadline(b uint32) int64 { return p.End(p.Last(b)) + p.Grace() }

// Check refuses a policy or order the seller cannot settle against (SS-5).
func (p Params) Check() error {
	switch {
	case p.PieceS <= 0 || p.ServiceEnd <= p.ServiceStart || (p.ServiceEnd-p.ServiceStart)%p.PieceS != 0:
		return errors.New("service period is not a whole number of pieces")
	case p.BatchSize == 0 || p.MaxNote == 0 || p.Ceiling < p.MaxNote:
		return errors.New("batch size, max_note or ceiling")
	case p.MaxNote > MaxAmount || p.Ceiling > MaxAmount:
		return fmt.Errorf("max_note or ceiling above %d", MaxAmount)
	case p.ChallengeTimeoutS+p.ShutdownLatencyS > p.PieceS:
		return errors.New("grace plus shutdown longer than a piece")
	case p.ChallengeTimeoutS <= 0 || p.SettlementMarginS <= 0 || p.ShutdownLatencyS < 0:
		return errors.New("challenge timeout or settlement margin missing, or negative shutdown latency")
	case p.ChallengeTimeoutS > p.PieceS || p.ShutdownLatencyS > p.PieceS || p.SettlementMarginS > 1<<40:
		return errors.New("timeout, shutdown latency or margin out of range")
	case p.MinCoverageBP > 10000:
		return errors.New("min_coverage_bp above 10000")
	case p.LivenessMissSlots > 0 && (p.SlotS <= 0 || p.SlotS > p.PieceS):
		return errors.New("liveness watch needs a slot length inside a piece")
	case p.LivenessMissSlots > 0 && int64(p.LivenessMissSlots) > p.ChallengeTimeoutS/p.SlotS:
		return errors.New("SS-12: liveness_miss_slots x slot_s above challenge_timeout_s")
	case p.SettleBy < p.Deadline(p.Batch(p.Pieces()-1)):
		return fmt.Errorf("settleBy %d before deadline(last batch) %d", p.SettleBy, p.Deadline(p.Batch(p.Pieces()-1)))
	}
	return nil
}

// Exposure is E: one piece at the cap, the grace and the shutdown at the piece
// price, and provisioning. The price of the grace is max_note x seconds /
// piece_s rounded up, so E is a bound, never an underestimate; the arithmetic
// is exact (128-bit intermediate) and the result is checked.
func (p Params) Exposure(provisioning uint64) (uint64, error) {
	if err := p.Check(); err != nil {
		return 0, err
	}
	grace := p.ChallengeTimeoutS + p.ShutdownLatencyS // both non-negative and at most piece_s each
	hi, lo := bits.Mul64(p.MaxNote, uint64(grace))
	if hi >= uint64(p.PieceS) {
		return 0, errors.New("exposure overflow")
	}
	q, r := bits.Div64(hi, lo, uint64(p.PieceS))
	if r != 0 {
		q++
	}
	e, err := add(p.MaxNote, q)
	if err != nil {
		return 0, err
	}
	return add(e, provisioning)
}

// State of the lease.
type State int

const (
	Offered State = iota
	Provisioning
	Running  // some piece is being served; a challenge may be open
	Stopping // the machine is being terminated; a final challenge may be open
	Stopped  // nothing runs; batches close and settle
)

func (s State) String() string {
	return [...]string{"Offered", "Provisioning", "Running", "Stopping", "Stopped"}[s]
}

// PieceStatus of one piece.
type PieceStatus int

const (
	Unserved     PieceStatus = iota
	Provisional              // running, funding reserved, not yet billable
	Served                   // billable: the gate for it passed
	Challenged               // ended, challenge sent, note awaited
	Acknowledged             // note durable: reservation moved to held
	TimedOut                 // no note in time: the reservation left open as a loss
)

// Ledger is the reservation ledger of SS-10. Each reservation moves exactly
// once: open -> held (note acknowledged) or open -> lost (timed out), and
// held -> settled (batch consumed) or held -> lost (batch lost). Every
// transition is a checked addition; Lost is bounded like the rest, and a
// transition that would exceed the bound is refused and logged, never wrapped.
type Ledger struct {
	Settled, Held, Open, Lost uint64
	// Unresolved holds reservations that left Open or Held but could not be
	// recorded in Lost because Lost is at its bound. Nothing is ever dropped:
	// a reservation is in exactly one of the five categories at all times.
	Unresolved uint64
}

// lose moves amount into Lost with checked arithmetic.
func (l *Lease) lose(amount uint64, now int64, why string) error {
	lost, err := add(l.Ledger.Lost, amount)
	if err != nil {
		l.log(now, "loss ledger overflow on %s: %v", why, err)
		return err
	}
	l.Ledger.Lost = lost
	return nil
}

// release takes a reservation out of Open and records it as lost, or as
// unresolved when the loss ledger is at its bound. Unresolved never exceeds
// the ceiling, because Open never does, so this addition cannot fail.
func (l *Lease) release(amount uint64, now int64, why string) {
	l.Ledger.Open -= amount
	if err := l.lose(amount, now, why); err != nil {
		l.Ledger.Unresolved += amount
		l.log(now, "%s: %d kept as unresolved accounting", why, amount)
	}
}

// Batch is one obligation's worth of pieces.
type Batch struct {
	Notes   map[uint32]uint64 // index -> amount, acknowledged
	Closed  bool
	Settled bool
	Lost    bool
}

// Event is one line of the lease's history.
type Event struct {
	At   int64
	What string
}

// Lease is the seller's state for one lease.
type Lease struct {
	P       Params
	State   State
	Pieces  []PieceStatus
	Batches map[uint32]*Batch
	Ledger  Ledger
	Stopped string // why
	Log     []Event
	// Expected is the seller's own view of what each challenged piece earns;
	// a note below it is an underpayment for delivered service and stops the
	// lease after that piece (lease evidence 5a.4). A zero expectation is an
	// outage the seller's own verifier saw: a zero note is then correct, but
	// the lease stops after that piece all the same (SS-14, decision 48).
	Expected  []uint64
	Underpaid []uint32 // pieces whose note was below the seller's expectation

	open      uint32 // index of the open challenge, valid if hasOpen
	hasOpen   bool
	deadline  int64 // when the open challenge times out
	lastServe uint32
}

// New prepares a lease in state Offered.
func New(p Params) (*Lease, error) {
	if err := p.Check(); err != nil {
		return nil, err
	}
	return &Lease{P: p, Pieces: make([]PieceStatus, p.Pieces()), Expected: make([]uint64, p.Pieces()),
		Batches: map[uint32]*Batch{}}, nil
}

func (l *Lease) log(at int64, f string, a ...any) {
	l.Log = append(l.Log, Event{at, fmt.Sprintf(f, a...)})
}

func (l *Lease) batch(b uint32) *Batch {
	if l.Batches[b] == nil {
		l.Batches[b] = &Batch{Notes: map[uint32]uint64{}}
	}
	return l.Batches[b]
}

// reserve makes the SS-10 check for piece k and moves max_note into open.
func (l *Lease) reserve(k uint32, now int64) error {
	b := l.P.Batch(k)
	committed, err := l.committed()
	if err != nil {
		return err
	}
	next, err := add(committed, l.P.MaxNote)
	if err != nil {
		return err
	}
	switch {
	case next > l.P.Ceiling:
		return fmt.Errorf("SS-10: ceiling: settled %d + held %d + open %d + %d > %d",
			l.Ledger.Settled, l.Ledger.Held, l.Ledger.Open, l.P.MaxNote, l.P.Ceiling)
	case l.P.End(k)+l.P.Grace() > l.P.Deadline(b) || l.P.End(k)+l.P.Grace() > l.P.SettleBy:
		return fmt.Errorf("SS-10: piece %d cannot settle before its deadline", k)
	case l.batch(b).Closed:
		return fmt.Errorf("SS-11: batch %d is closed", b)
	}
	l.Ledger.Open += l.P.MaxNote
	l.Pieces[k] = Provisional
	l.log(now, "piece %d provisional: %d reserved", k, l.P.MaxNote)
	return nil
}

// committed is settled + held + open with checked arithmetic.
func (l *Lease) committed() (uint64, error) {
	s, err := add(l.Ledger.Settled, l.Ledger.Held)
	if err != nil {
		return 0, err
	}
	return add(s, l.Ledger.Open)
}

// Accept moves Offered -> Provisioning and reserves piece 0.
func (l *Lease) Accept(now int64) error {
	if l.State != Offered {
		return fmt.Errorf("accept in state %s", l.State)
	}
	if err := l.reserve(0, now); err != nil {
		return err
	}
	l.State = Provisioning
	l.log(now, "accepted; provisioning")
	return nil
}

// Boot is the agent's anchored boot proof, before service_start: piece 0 is served.
func (l *Lease) Boot(now int64) error {
	if l.State != Provisioning {
		return fmt.Errorf("boot in state %s", l.State)
	}
	if now > l.P.ServiceStart {
		l.stop(now, "boot after service_start")
		return errors.New("boot after service_start")
	}
	l.State = Running
	l.Pieces[0] = Served
	l.lastServe = 0
	l.log(now, "booted; serving piece 0 from %d", l.P.ServiceStart)
	return nil
}

// PieceEnd is called when piece k ends (at End(k)). It sends the challenge for
// note k, carrying the amount the seller's own run of the verifier expects
// for the piece (units x price of the record it sends with the challenge), and
// makes piece k+1 provisional, or stops at the end of the service.
func (l *Lease) PieceEnd(k uint32, expected uint64, now int64) error {
	if l.State != Running || l.Pieces[k] != Served || k != l.lastServe {
		return fmt.Errorf("piece %d end in state %s, status %d", k, l.State, l.Pieces[k])
	}
	if l.hasOpen {
		return fmt.Errorf("challenge %d still open at the end of piece %d", l.open, k)
	}
	if expected > l.P.MaxNote {
		return fmt.Errorf("expected %d above max_note", expected)
	}
	l.Pieces[k] = Challenged
	l.Expected[k] = expected
	l.open, l.hasOpen, l.deadline = k, true, l.P.End(k)+l.P.ChallengeTimeoutS
	l.log(now, "challenge %d sent, expecting %d; deadline %d", k, expected, l.deadline)
	if expected == 0 {
		// SS-14: never continue after a zero-payable piece, also when the
		// buyer will sign zero correctly. Piece k+1 is not served; the zero
		// note still keeps the indices consecutive and settles with its batch.
		l.State = Stopping
		l.Stopped = fmt.Sprintf("SS-14: piece %d is zero-payable", k)
		l.log(now, "stopping: piece %d zero-payable; final challenge %d open", k, k)
		return nil
	}
	if k+1 >= l.P.Pieces() {
		l.State = Stopping
		l.Stopped = "service_end"
		l.log(now, "service end: stopping; final challenge %d open", k)
		return nil
	}
	if err := l.reserve(k+1, now); err != nil {
		l.State = Stopping
		l.Stopped = err.Error()
		l.log(now, "stopping: %v; final challenge %d open", err, k)
		return nil
	}
	return nil
}

// Note is the buyer's answer to challenge k: a signed record and a note for
// amount, valid until validUntil. It is idempotent for a repeated identical
// answer. A note for a closed batch, an unchallenged piece, a wrong window or
// an amount above the cap is refused.
func (l *Lease) Note(k uint32, amount uint64, validUntil, now int64) error {
	b := l.P.Batch(k)
	switch {
	case k >= l.P.Pieces():
		return fmt.Errorf("index %d outside the service", k)
	case l.Pieces[k] == Acknowledged:
		if l.batch(b).Notes[k] != amount {
			return fmt.Errorf("BG-2: a different note for index %d exists", k)
		}
		l.log(now, "note %d repeated: same answer", k)
		return nil
	case l.batch(b).Closed:
		return fmt.Errorf("SS-11: batch %d closed; note %d refused", b, k)
	case l.Pieces[k] != Challenged:
		return fmt.Errorf("SS-9: piece %d was not challenged (status %d)", k, l.Pieces[k])
	case amount > l.P.MaxNote:
		return fmt.Errorf("BG-1: amount %d above max_note %d", amount, l.P.MaxNote)
	case validUntil != l.P.Deadline(b):
		return fmt.Errorf("SS-11/BG-6: valid_until %d is not deadline(%d) = %d", validUntil, b, l.P.Deadline(b))
	case now > l.deadline:
		return fmt.Errorf("SS-9: note %d after the challenge deadline %d", k, l.deadline)
	}
	l.Pieces[k] = Acknowledged
	l.batch(b).Notes[k] = amount
	l.Ledger.Open -= l.P.MaxNote
	held, err := add(l.Ledger.Held, amount)
	if err != nil {
		return err
	}
	l.Ledger.Held = held
	l.hasOpen = false
	l.log(now, "note %d acknowledged: %d held", k, amount)
	if amount < l.Expected[k] {
		// The buyer paid less than the evidence shows: the note is still
		// money and is kept, but the service stops after this piece.
		l.Underpaid = append(l.Underpaid, k)
		l.log(now, "note %d below the expected %d: underpayment", k, l.Expected[k])
		l.closeFull(b, now)
		if l.State == Running {
			l.stop(now, fmt.Sprintf("underpayment on piece %d", k))
		} else {
			l.nextFinal(now)
		}
		return nil
	}
	if amount == 0 && l.State == Running {
		// SS-14: a zero note for any reason ends the lease after this piece.
		l.closeFull(b, now)
		l.stop(now, fmt.Sprintf("SS-14: zero note for piece %d", k))
		return nil
	}
	if l.State == Running && l.Pieces[k+1] == Provisional {
		// The gate for piece k+1 passed: provisional becomes served.
		l.Pieces[k+1] = Served
		l.lastServe = k + 1
		l.log(now, "piece %d billable from %d", k+1, l.P.Start(k+1))
	}
	l.closeFull(b, now)
	if l.State == Stopping {
		l.nextFinal(now)
	}
	return nil
}

// nextFinal, while stopping: challenge the last served piece if it has not
// been challenged, else close everything.
func (l *Lease) nextFinal(now int64) {
	if l.hasOpen {
		return
	}
	if k := l.lastServe; l.Pieces[k] == Served {
		l.Pieces[k] = Challenged
		l.open, l.hasOpen, l.deadline = k, true, now+l.P.ChallengeTimeoutS
		l.log(now, "final challenge %d sent; deadline %d", k, l.deadline)
		return
	}
	l.finish(now)
}

// Tick advances the clock: an open challenge past its deadline stops the lease.
func (l *Lease) Tick(now int64) {
	if !l.hasOpen || now < l.deadline {
		return
	}
	k := l.open
	l.hasOpen = false
	l.Pieces[k] = TimedOut
	l.release(l.P.MaxNote, now, "timeout")
	l.log(now, "challenge %d timed out: piece %d unpaid", k, k)
	if l.State == Running {
		l.stop(now, fmt.Sprintf("note %d missing", k))
		return
	}
	l.nextFinal(now)
}

// CoverageReachable is the integer form of D6 applied to what is still
// possible: with lost seconds of creditable already irrecoverable, can the
// piece still reach min_coverage_bp? (creditable - lost) * 10000 >=
// min_coverage_bp * creditable, in 128-bit arithmetic.
func CoverageReachable(creditable, lost uint64, minCoverageBP uint16) bool {
	if lost > creditable {
		lost = creditable
	}
	lh, ll := bits.Mul64(creditable-lost, 10000)
	rh, rl := bits.Mul64(uint64(minCoverageBP), creditable)
	return lh > rh || (lh == rh && ll >= rl)
}

// running reports whether piece k is running now: the served piece, or the
// provisional piece after it.
func (l *Lease) running(k uint32) bool {
	if l.State != Running || k >= l.P.Pieces() {
		return false
	}
	return (l.Pieces[k] == Served && k == l.lastServe) || l.Pieces[k] == Provisional
}

// Coverage is the coverage condition of SS-12 (decision 48): lost seconds of
// piece k's creditable seconds can no longer be credited, because their
// anchoring deadline passed. When the floor is out of reach, the lease stops
// now instead of serving the rest of a piece that D6 makes zero. It returns an
// error for a piece that is not running, and does nothing without a floor.
func (l *Lease) Coverage(k uint32, creditable, lost uint64, now int64) error {
	switch {
	case !l.running(k):
		return fmt.Errorf("coverage for piece %d, which is not running", k)
	case creditable == 0 || creditable > uint64(l.P.PieceS):
		return fmt.Errorf("creditable %d outside (0, piece_s]", creditable)
	case l.P.MinCoverageBP == 0:
		return nil
	}
	if !CoverageReachable(creditable, lost, l.P.MinCoverageBP) {
		l.stop(now, fmt.Sprintf("SS-12: piece %d cannot reach min_coverage_bp %d (%d of %d creditable seconds lost)",
			k, l.P.MinCoverageBP, lost, creditable))
	}
	return nil
}

// Stop ends the lease on the seller's or the buyer's initiative.
func (l *Lease) Stop(now int64, why string) {
	if l.State == Running {
		l.stop(now, why)
	}
}

// stop terminates the machine: a provisional piece is lost, the last served
// piece gets its final challenge.
func (l *Lease) stop(now int64, why string) {
	l.State, l.Stopped = Stopping, why
	l.log(now, "stopping: %s; machine terminated by %d", why, now+l.P.ShutdownLatencyS)
	for k := range l.Pieces {
		if l.Pieces[k] == Provisional {
			l.Pieces[k] = Unserved
			l.release(l.P.MaxNote, now, "provisional piece")
			l.log(now, "provisional piece %d: unpaid, reservation lost", k)
		}
	}
	l.nextFinal(now)
}

// finish closes every batch once nothing is open.
func (l *Lease) finish(now int64) {
	if l.hasOpen {
		return
	}
	l.State = Stopped
	for b := range l.Batches {
		l.close(b, now)
	}
	l.log(now, "stopped")
}

func (l *Lease) closeFull(b uint32, now int64) {
	bt := l.batch(b)
	if uint32(len(bt.Notes)) == l.P.Last(b)-b*l.P.BatchSize+1 {
		l.close(b, now)
	}
}

func (l *Lease) close(b uint32, now int64) {
	bt := l.batch(b)
	if !bt.Closed {
		bt.Closed = true
		l.log(now, "batch %d closed with %d note(s)", b, len(bt.Notes))
	}
}

// Settle proves and settles a closed batch. proverOK is the prover's result;
// a failure keeps the batch for a retry (SS-4). Past deadline(b) the batch is
// lost. It returns the amount consumed.
func (l *Lease) Settle(b uint32, now int64, proverOK bool) (uint64, error) {
	bt := l.batch(b)
	switch {
	case !bt.Closed:
		return 0, fmt.Errorf("batch %d is not closed", b)
	case bt.Settled:
		return 0, fmt.Errorf("batch %d already consumed", b)
	case bt.Lost:
		return 0, fmt.Errorf("batch %d lost", b)
	}
	var sum uint64
	for _, a := range bt.Notes {
		var err error
		if sum, err = add(sum, a); err != nil {
			return 0, err
		}
	}
	if now > l.P.Deadline(b) || now > l.P.SettleBy {
		if err := l.lose(sum, now, "lost batch"); err != nil {
			return 0, err // the batch stays Held and unsettled: the state is not corrupted
		}
		bt.Lost = true
		l.Ledger.Held -= sum
		l.log(now, "batch %d lost: past deadline %d", b, l.P.Deadline(b))
		return 0, fmt.Errorf("batch %d past its deadline", b)
	}
	if !proverOK {
		l.log(now, "batch %d: prover failed; kept for retry", b)
		return 0, errors.New("prover failed; retry")
	}
	bt.Settled = true
	l.Ledger.Held -= sum
	l.Ledger.Settled += sum
	l.log(now, "batch %d settled: %d", b, sum)
	return sum, nil
}

// Invariant checks the ledger against the ceiling and the piece statuses.
func (l *Lease) Invariant() error {
	committed, err := l.committed()
	if err != nil {
		return err
	}
	if committed > l.P.Ceiling {
		return fmt.Errorf("ledger above the ceiling: %+v", l.Ledger)
	}
	if l.Ledger.Lost > MaxLedger || l.Ledger.Unresolved > l.P.Ceiling {
		return fmt.Errorf("loss or unresolved ledger above its bound: %+v", l.Ledger)
	}
	var open uint64
	for _, s := range l.Pieces {
		if s == Provisional || s == Served || s == Challenged {
			open += l.P.MaxNote
		}
	}
	if open != l.Ledger.Open {
		return fmt.Errorf("open %d does not match the pieces in flight %d", l.Ledger.Open, open)
	}
	return nil
}
