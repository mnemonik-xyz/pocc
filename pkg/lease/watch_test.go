package lease

import (
	"strings"
	"testing"
)

// The DL-15 scenarios of lease evidence SS-12 and SS-14 (pocc decisions 47 and
// 48): the per-slot liveness watch, the coverage stop and the zero-piece stop.

// wparams is a watched lease of n hours in one batch, 60 s slots from
// start+offset, a 30 s bracket, liveness_miss_slots = 5 (5 x 60 = 300 s, the
// challenge timeout) and the given coverage floor.
func wparams(hours, offset int64, minBP uint16) Params {
	p := params(hours, uint32(hours), uint64(hours)*cap)
	p.SlotS, p.FirstSlotAt, p.BracketS, p.LivenessMissSlots, p.MinCoverageBP = 60, start+offset, 30, 5, minBP
	return p
}

// sim drives a watched lease slot by slot, each at its anchoring deadline.
// A dropped slot has no live heartbeat. An interval is credited when both of
// its slots are live, as pocc-verify credits it, unless uncredited names it.
// At each piece end the seller challenges with the amount its own record
// gives, and the buyer signs exactly that amount.
type sim struct {
	t          *testing.T
	l          *Lease
	dropped    map[uint32]bool
	uncredited map[uint32]bool
	final      map[uint32]bool
	failed     map[uint32]bool
	piece      uint32
	until      uint32 // stop driving after this slot (0: run to the end)
}

func newSim(t *testing.T, p Params) *sim {
	t.Helper()
	l, err := New(p)
	must(t, err)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	return &sim{t: t, l: l, dropped: map[uint32]bool{}, uncredited: map[uint32]bool{},
		final: map[uint32]bool{}, failed: map[uint32]bool{}}
}

func (s *sim) obs(j uint32) Observation {
	live := !s.dropped[j]
	return Observation{Live: live, Final: s.final[j], Failed: s.failed[j],
		Credited: j >= 1 && live && !s.dropped[j-1] && !s.uncredited[j]}
}

// expected is the seller's own amount for piece k: units x price, or 0 below
// the coverage floor (D6).
func (s *sim) expected(k uint32) uint64 {
	cr, got := s.l.P.Creditable(k), s.l.Credited[k]
	if got*10000 < int64(s.l.P.MinCoverageBP)*cr {
		return 0
	}
	return uint64(got) * price
}

// step observes slot j.
func (s *sim) step(j uint32) {
	s.t.Helper()
	p := s.l.P
	now := p.AnchorDeadline(j)
	must(s.t, s.l.Watch(j, s.obs(j), now))
	check(s.t, s.l)
	if k := s.piece; s.l.State == Running && p.SlotTime(j+1) > p.End(k) {
		e := s.expected(k)
		must(s.t, s.l.PieceEnd(k, e, now))
		check(s.t, s.l)
		answer(s.t, s.l, k, e, now+1)
		s.piece++
	}
}

// run observes slots until the lease leaves Running, then answers the final
// challenge, if one is open, with the seller's expectation.
func (s *sim) run() {
	s.t.Helper()
	p := s.l.P
	for j := s.l.nextSlot; s.l.State == Running && p.SlotTime(j) <= p.ServiceEnd; j++ {
		s.step(j)
		if s.until != 0 && j == s.until {
			return
		}
	}
	s.answerFinal()
}

func (s *sim) answerFinal() {
	s.t.Helper()
	if s.l.hasOpen {
		k := s.l.open
		answer(s.t, s.l, k, s.l.Expected[k], s.l.deadline-1)
	}
}

// slot is the index of the slot at time t (t on the slot grid).
func slot(p Params, t int64) uint32 { return uint32((t - p.FirstSlotAt) / p.SlotS) }

// stoppedAt returns the time of the log line that put the lease in Stopping.
func stoppedAt(l *Lease) int64 {
	for _, e := range l.Log {
		if strings.HasPrefix(e.What, "stopping:") {
			return e.At
		}
	}
	return -1
}

func loss(t *testing.T, l *Lease) {
	t.Helper()
	e, err := l.P.Exposure(0)
	must(t, err)
	if l.Ledger.Lost > e {
		t.Fatalf("loss %d above E %d", l.Ledger.Lost, e)
	}
}

func TestCreditablePerPiece(t *testing.T) {
	aligned := wparams(3, 0, 9500)
	boundary := wparams(3, 13, 9500)
	for k, want := range []int64{3600, 3600, 3600} {
		if got := aligned.Creditable(uint32(k)); got != want {
			t.Fatalf("aligned piece %d: %d, want %d", k, got, want)
		}
	}
	// A first slot 13 s after service_start: the first hour loses one interval
	// (3,540 s, DL-10); the middle and last hours keep 3,600 (DL-12).
	for k, want := range []int64{3540, 3600, 3600} {
		if got := boundary.Creditable(uint32(k)); got != want {
			t.Fatalf("boundary piece %d: %d, want %d", k, got, want)
		}
	}
	// The integer form of D6 at 9500: four lost intervals in a middle hour,
	// three in a 3,540-second boundary hour.
	cases := []struct {
		cr, lost int64
		out      bool
	}{{3600, 180, false}, {3600, 240, true}, {3540, 120, false}, {3540, 180, true}}
	for _, c := range cases {
		if FloorOutOfReach(c.cr, c.lost, 9500) != c.out {
			t.Fatalf("creditable %d lost %d: want %v", c.cr, c.lost, c.out)
		}
	}
}

// DL-15: four consecutive lost intervals in a middle hour stop the lease at
// the anchoring deadline of the fourth. Three dropped slots lose four
// intervals, below the five-slot liveness rule.
func TestCoverageStopConsecutive(t *testing.T) {
	p := wparams(3, 0, 9500)
	s := newSim(t, p)
	first := slot(p, p.Start(1)+600)
	for j := first; j < first+3; j++ {
		s.dropped[j] = true
	}
	s.until = first + 2 // three lost intervals: still running
	s.run()
	if s.l.State != Running || s.l.LostS[1] != 180 {
		t.Fatalf("stopped early: %s lost %d\n%s", s.l.State, s.l.LostS[1], dump(s.l))
	}
	s.until = 0
	s.run()
	fourth := first + 3
	if s.l.State != Stopped || !strings.Contains(s.l.Stopped, "piece 1 cannot reach") ||
		stoppedAt(s.l) != p.AnchorDeadline(fourth) || s.l.LostS[1] != 240 {
		t.Fatalf("state %s why %q at %d\n%s", s.l.State, s.l.Stopped, stoppedAt(s.l), dump(s.l))
	}
	if s.l.Pieces[2] != Unserved || s.l.Batches[0].Notes[1] != 0 || len(s.l.Underpaid) != 0 {
		t.Fatalf("pieces %v notes %v\n%s", s.l.Pieces, s.l.Batches[0].Notes, dump(s.l))
	}
	got, err := s.l.Settle(0, p.End(1)+600, true)
	must(t, err)
	if got != cap { // piece 0 is paid in full; piece 1 is a zero note
		t.Fatalf("settled %d", got)
	}
	loss(t, s.l)
}

// DL-15: scattered lost intervals add up the same way, whether they come from
// two single dropped slots (two intervals each) or from four single intervals
// the verifier did not credit.
func TestCoverageStopScattered(t *testing.T) {
	p := wparams(3, 0, 9500)

	s := newSim(t, p)
	a, b := slot(p, p.Start(1)+300), slot(p, p.Start(1)+2400)
	s.dropped[a], s.dropped[b] = true, true
	s.run()
	if s.l.State != Stopped || stoppedAt(s.l) != p.AnchorDeadline(b+1) || s.l.LostS[1] != 240 {
		t.Fatalf("dropped slots: state %s at %d\n%s", s.l.State, stoppedAt(s.l), dump(s.l))
	}

	s = newSim(t, p)
	var last uint32
	for _, off := range []int64{120, 900, 1800, 3000} {
		last = slot(p, p.Start(1)+off)
		s.uncredited[last] = true
	}
	s.run()
	if s.l.State != Stopped || stoppedAt(s.l) != p.AnchorDeadline(last) || s.l.LostS[1] != 240 {
		t.Fatalf("single intervals: state %s at %d\n%s", s.l.State, stoppedAt(s.l), dump(s.l))
	}
	loss(t, s.l)
}

// DL-15: three lost intervals in a middle hour (3,420 of 3,600) do not stop
// the lease; the hour is paid for what it credited and the lease runs on.
func TestCoverageThreeLostDoNotStop(t *testing.T) {
	p := wparams(3, 0, 9500)
	s := newSim(t, p)
	first := slot(p, p.Start(1)+600)
	s.dropped[first], s.dropped[first+1] = true, true // three lost intervals
	s.run()
	if s.l.State != Stopped || s.l.Stopped != "service_end" || s.l.Credited[1] != 3420 {
		t.Fatalf("state %s why %q credited %d\n%s", s.l.State, s.l.Stopped, s.l.Credited[1], dump(s.l))
	}
	got, err := s.l.Settle(0, p.End(2)+600, true)
	must(t, err)
	if want := 2*cap + 3420*price; got != want {
		t.Fatalf("settled %d, want %d", got, want)
	}
}

// DL-15: in a boundary hour of 3,540 creditable seconds, three lost intervals
// stop the lease; two do not.
func TestCoverageBoundaryHour(t *testing.T) {
	p := wparams(3, 13, 9500)

	s := newSim(t, p)
	j := slot(p, p.FirstSlotAt+900)
	s.dropped[j], s.dropped[j+1] = true, true // intervals j, j+1, j+2
	s.run()
	if s.l.State != Stopped || !strings.Contains(s.l.Stopped, "piece 0 cannot reach") ||
		stoppedAt(s.l) != p.AnchorDeadline(j+2) || s.l.Pieces[1] != Unserved {
		t.Fatalf("state %s why %q\n%s", s.l.State, s.l.Stopped, dump(s.l))
	}
	if n, ok := s.l.Batches[0].Notes[0]; !ok || n != 0 {
		t.Fatalf("the boundary hour has no zero note: %v", s.l.Batches[0].Notes)
	}

	s = newSim(t, p)
	s.dropped[j] = true // two lost intervals: 3,420 of 3,540 passes 9500
	s.run()
	if s.l.State != Stopped || s.l.Stopped != "service_end" || s.l.Batches[0].Notes[0] != 3420*price {
		t.Fatalf("state %s why %q notes %v\n%s", s.l.State, s.l.Stopped, s.l.Batches[0].Notes, dump(s.l))
	}
}

// DL-15: an interval whose anchoring deadline has not passed is not counted.
// The watch refuses an observation before the deadline and changes nothing.
func TestCoverageDeadlineRule(t *testing.T) {
	p := wparams(3, 0, 9500)
	s := newSim(t, p)
	first := slot(p, p.Start(1)+600)
	for j := first; j < first+3; j++ {
		s.dropped[j] = true
	}
	s.until = first + 2
	s.run()
	fourth := first + 3
	before := s.l.LostS[1]
	if err := s.l.Watch(fourth, s.obs(fourth), p.AnchorDeadline(fourth)-1); err == nil {
		t.Fatal("an observation before the anchoring deadline was accepted")
	}
	if s.l.State != Running || s.l.LostS[1] != before || s.l.nextSlot != fourth {
		t.Fatalf("an early observation changed the lease: %s lost %d", s.l.State, s.l.LostS[1])
	}
	if err := s.l.Watch(fourth+1, s.obs(fourth+1), p.AnchorDeadline(fourth+1)); err == nil {
		t.Fatal("a slot out of order was accepted")
	}
	must(t, s.l.Watch(fourth, s.obs(fourth), p.AnchorDeadline(fourth)))
	if s.l.State != Stopping || s.l.LostS[1] != 240 {
		t.Fatalf("state %s lost %d", s.l.State, s.l.LostS[1])
	}
}

// Regression for the review of 3 Nov: the buyer drops two slots at a time,
// twice an hour, so each hour ends at 3,360 credited seconds against the 3,420
// it needs and the five-slot rule never fires. Before decision 48 every hour
// got a zero note and the lease ran to its end unpaid. Now the lease stops in
// the first hour at the fourth lost interval, serves at most one zero-payable
// piece, and the loss stays within E.
func TestBelowFloorEveryHourStopsInFirstHour(t *testing.T) {
	p := wparams(4, 0, 9500)
	s := newSim(t, p)
	for k := uint32(0); k < 4; k++ {
		for _, off := range []int64{600, 2400} {
			j := slot(p, p.Start(k)+off)
			s.dropped[j], s.dropped[j+1] = true, true // three lost intervals each
		}
	}
	s.run()
	zero := 0
	for _, a := range s.l.Batches[0].Notes {
		if a == 0 {
			zero++
		}
	}
	if s.l.State != Stopped || !strings.Contains(s.l.Stopped, "piece 0 cannot reach") || zero != 1 ||
		s.l.Pieces[1] != Unserved || s.l.Pieces[2] != Unserved || s.l.Pieces[3] != Unserved {
		t.Fatalf("state %s why %q zero notes %d pieces %v\n%s", s.l.State, s.l.Stopped, zero, s.l.Pieces, dump(s.l))
	}
	j := slot(p, p.Start(0)+2400)
	if stoppedAt(s.l) != p.AnchorDeadline(j) { // 3 lost from the first pair, the fourth here
		t.Fatalf("stopped at %d, want %d", stoppedAt(s.l), p.AnchorDeadline(j))
	}
	loss(t, s.l)
}

// DL-15, zero acknowledgements: a correct zero note for an honest outage, and
// a zero note for an hour below the assurance floor (full coverage, D7), both
// stop the lease; the batch with the zero note settles the earlier pieces.
func TestZeroAcknowledgementStops(t *testing.T) {
	for _, name := range []string{"outage", "assurance"} {
		p := wparams(3, 0, 9500)
		s := newSim(t, p)
		// Piece 0 in full.
		for j := uint32(0); s.piece == 0; j++ {
			s.step(j)
		}
		// Piece 1: with no stop rule beyond coverage, an honest outage of the
		// whole hour would stop by coverage first; use a floor of 0 for the
		// outage so that only SS-14 decides, and full coverage for D7.
		if name == "outage" {
			s.l.P.MinCoverageBP = 0
			s.l.P.LivenessMissSlots = 1 << 30 // isolate SS-14 from the five-slot rule
			for j := slot(p, p.Start(1)) + 1; j <= slot(p, p.End(1)); j++ {
				s.dropped[j] = true
			}
		}
		for j := s.l.nextSlot; s.l.P.SlotTime(j+1) <= p.End(1); j++ {
			must(t, s.l.Watch(j, s.obs(j), p.AnchorDeadline(j)))
		}
		j := slot(p, p.End(1))
		now := p.AnchorDeadline(j)
		must(t, s.l.Watch(j, s.obs(j), now))
		must(t, s.l.PieceEnd(1, 0, now)) // outage: no credit; assurance: D7
		check(t, s.l)
		if s.l.State != Stopping || s.l.Pieces[2] != Unserved {
			t.Fatalf("%s: zero-payable piece did not stop: %s\n%s", name, s.l.State, dump(s.l))
		}
		answer(t, s.l, 1, 0, now+1) // a correct zero note
		if s.l.State != Stopped || len(s.l.Underpaid) != 0 || len(s.l.Batches[0].Notes) != 2 {
			t.Fatalf("%s: state %s notes %v\n%s", name, s.l.State, s.l.Batches[0].Notes, dump(s.l))
		}
		got, err := s.l.Settle(0, p.End(1)+600, true)
		must(t, err)
		if got != cap || s.l.Ledger.Lost != 0 {
			t.Fatalf("%s: settled %d ledger %+v", name, got, s.l.Ledger)
		}
	}
}

// The last interval of piece k ends at End(k), so it can be lost after the
// challenge for k is open and piece k+1 is provisional. The coverage stop then
// releases the provisional piece, the seller's expectation for k becomes zero,
// and a zero note for k is correct, not underpayment.
func TestCoverageStopWhileChallenging(t *testing.T) {
	p := wparams(3, 0, 9500)
	s := newSim(t, p)
	last := slot(p, p.End(0))
	for _, off := range []int64{300, 1500, 2700} {
		s.uncredited[slot(p, p.Start(0)+off)] = true
	}
	for j := uint32(0); j < last; j++ {
		s.step(j)
	}
	must(t, s.l.PieceEnd(0, 3420*price, p.End(0))) // challenged before the last deadline
	if s.l.Pieces[1] != Provisional {
		t.Fatalf("piece 1 %d", s.l.Pieces[1])
	}
	s.uncredited[last] = true
	must(t, s.l.Watch(last, s.obs(last), p.AnchorDeadline(last)))
	check(t, s.l)
	if s.l.State != Stopping || s.l.Pieces[1] != Unserved || s.l.Expected[0] != 0 || s.l.Ledger.Lost != cap {
		t.Fatalf("state %s pieces %v expected %d ledger %+v\n%s", s.l.State, s.l.Pieces, s.l.Expected[0], s.l.Ledger, dump(s.l))
	}
	answer(t, s.l, 0, 0, p.AnchorDeadline(last)+1)
	if s.l.State != Stopped || len(s.l.Underpaid) != 0 {
		t.Fatalf("state %s underpaid %v", s.l.State, s.l.Underpaid)
	}
	loss(t, s.l)
}

// The provisional piece k+1 is the current piece while note k is awaited.
// When it can no longer reach its floor inside that window, the lease stops:
// piece k+1 is never billable, and note k still settles.
func TestCoverageStopProvisionalPiece(t *testing.T) {
	p := wparams(3, 0, 9500)
	s := newSim(t, p)
	end0 := slot(p, p.End(0))
	for j := uint32(0); j < end0; j++ {
		s.step(j)
	}
	must(t, s.l.Watch(end0, s.obs(end0), p.AnchorDeadline(end0)))
	must(t, s.l.PieceEnd(0, cap, p.AnchorDeadline(end0))) // note 0 not yet signed
	for j := end0 + 1; j <= end0+3; j++ {
		s.dropped[j] = true // intervals end0+1 .. end0+4 lost
	}
	for j := end0 + 1; s.l.State == Running && j <= end0+10; j++ {
		must(t, s.l.Watch(j, s.obs(j), p.AnchorDeadline(j)))
	}
	if stoppedAt(s.l) != p.AnchorDeadline(end0+4) || stoppedAt(s.l) >= p.End(0)+timeout ||
		!strings.Contains(s.l.Stopped, "piece 1 cannot reach") || s.l.Pieces[1] != Unserved {
		t.Fatalf("why %q at %d pieces %v\n%s", s.l.Stopped, stoppedAt(s.l), s.l.Pieces, dump(s.l))
	}
	answer(t, s.l, 0, cap, p.End(0)+timeout-1)
	got, err := s.l.Settle(0, p.End(0)+600, true)
	must(t, err)
	if s.l.State != Stopped || got != cap || s.l.Ledger.Lost != cap {
		t.Fatalf("state %s settled %d ledger %+v", s.l.State, got, s.l.Ledger)
	}
	loss(t, s.l)
}

// DL-15, decision 47: the five-consecutive-slot rule, an early final heartbeat
// and a failed entry each stop the lease; a notary outage of four slots does
// not, and its slots earn nothing. A floor of 0 isolates these rules from the
// coverage stop.
func TestLivenessStops(t *testing.T) {
	p := wparams(3, 0, 0)
	mid := slot(p, p.Start(1)+600)

	s := newSim(t, p)
	for j := mid; j < mid+4; j++ {
		s.dropped[j] = true
	}
	s.run()
	if s.l.Stopped != "service_end" || s.l.LostS[1] != 300 {
		t.Fatalf("four missed slots: %q lost %d\n%s", s.l.Stopped, s.l.LostS[1], dump(s.l))
	}

	s = newSim(t, p)
	for j := mid; j < mid+5; j++ {
		s.dropped[j] = true
	}
	s.run()
	if !strings.Contains(s.l.Stopped, "5 consecutive slots") || stoppedAt(s.l) != p.AnchorDeadline(mid+4) {
		t.Fatalf("five missed slots: %q at %d\n%s", s.l.Stopped, stoppedAt(s.l), dump(s.l))
	}
	loss(t, s.l)

	s = newSim(t, p)
	s.final[mid] = true
	s.run()
	if !strings.Contains(s.l.Stopped, "final heartbeat") || s.l.Pieces[2] != Unserved {
		t.Fatalf("early final: %q\n%s", s.l.Stopped, dump(s.l))
	}

	s = newSim(t, p)
	s.failed[mid] = true
	s.run()
	if !strings.Contains(s.l.Stopped, "failed the content check") || s.l.LostS[1] != 60 {
		t.Fatalf("failed entry: %q lost %d\n%s", s.l.Stopped, s.l.LostS[1], dump(s.l))
	}
	loss(t, s.l)
}

func TestWatchParameters(t *testing.T) {
	p := wparams(3, 0, 9500)
	must(t, p.Check())
	bad := []func(*Params){
		func(p *Params) { p.LivenessMissSlots = 6 }, // 6 x 60 > 300
		func(p *Params) { p.LivenessMissSlots = 0 },
		func(p *Params) { p.FirstSlotAt = p.ServiceStart - 1 },
		func(p *Params) { p.FirstSlotAt = p.ServiceStart + 60 },
		func(p *Params) { p.BracketS = 0 },
		func(p *Params) { p.MinCoverageBP = 10001 },
	}
	for i, f := range bad {
		q := p
		f(&q)
		if q.Check() == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	l, err := New(params(3, 3, 3*cap))
	must(t, err)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	if l.Watch(0, Observation{Live: true}, start+60) == nil {
		t.Fatal("an unwatched lease took an observation")
	}
}
