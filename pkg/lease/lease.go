// Package lease is the seller's side of a rent lease as lease evidence 5a.5
// and 5a.6 specify it: the state machine, the reservation ledger (SS-10), batch
// closing (SS-11), note windows (BG-6) and the deadline formula. It moves no
// money and signs nothing; it decides what the seller's service does next and
// records every reservation exactly once. The simulation in lease_test.go runs
// the DL-11 scenarios against it.
package lease

import (
	"errors"
	"fmt"
)

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

// Grace is G = challenge_timeout_s + M.
func (p Params) Grace() int64 { return p.ChallengeTimeoutS + p.SettlementMarginS }

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
	case p.ChallengeTimeoutS <= 0 || p.SettlementMarginS <= 0:
		return errors.New("challenge timeout or settlement margin missing")
	case p.SettleBy < p.Deadline(p.Batch(p.Pieces()-1)):
		return fmt.Errorf("settleBy %d before deadline(last batch) %d", p.SettleBy, p.Deadline(p.Batch(p.Pieces()-1)))
	}
	return nil
}

// Exposure is E: one piece at the cap, the grace and the shutdown at the piece
// price, and provisioning. priceS is the price of one second at the cap.
func (p Params) Exposure(provisioning uint64) uint64 {
	perSecond := p.MaxNote / uint64(p.PieceS)
	return p.MaxNote + perSecond*uint64(p.ChallengeTimeoutS+p.ShutdownLatencyS) + provisioning
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
// held -> settled (batch consumed) or held -> lost (batch lost).
type Ledger struct {
	Settled, Held, Open, Lost uint64
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
	return &Lease{P: p, Pieces: make([]PieceStatus, p.Pieces()), Batches: map[uint32]*Batch{}}, nil
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
	switch {
	case l.Ledger.Settled+l.Ledger.Held+l.Ledger.Open+l.P.MaxNote > l.P.Ceiling:
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
// note k and makes piece k+1 provisional, or stops at the end of the service.
func (l *Lease) PieceEnd(k uint32, now int64) error {
	if l.State != Running || l.Pieces[k] != Served || k != l.lastServe {
		return fmt.Errorf("piece %d end in state %s, status %d", k, l.State, l.Pieces[k])
	}
	if l.hasOpen {
		return fmt.Errorf("challenge %d still open at the end of piece %d", l.open, k)
	}
	l.Pieces[k] = Challenged
	l.open, l.hasOpen, l.deadline = k, true, l.P.End(k)+l.P.ChallengeTimeoutS
	l.log(now, "challenge %d sent; deadline %d", k, l.deadline)
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
	l.Ledger.Held += amount
	l.hasOpen = false
	l.log(now, "note %d acknowledged: %d held", k, amount)
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
	l.Ledger.Open -= l.P.MaxNote
	l.Ledger.Lost += l.P.MaxNote
	l.log(now, "challenge %d timed out: piece %d unpaid", k, k)
	if l.State == Running {
		l.stop(now, fmt.Sprintf("note %d missing", k))
		return
	}
	l.nextFinal(now)
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
			l.Ledger.Open -= l.P.MaxNote
			l.Ledger.Lost += l.P.MaxNote
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
		sum += a
	}
	if now > l.P.Deadline(b) || now > l.P.SettleBy {
		bt.Lost = true
		l.Ledger.Held -= sum
		l.Ledger.Lost += sum
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
	if l.Ledger.Settled+l.Ledger.Held+l.Ledger.Open > l.P.Ceiling {
		return fmt.Errorf("ledger above the ceiling: %+v", l.Ledger)
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
