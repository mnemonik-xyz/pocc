package lease

import (
	"strings"
	"testing"
)

// Regression tests for decisions 47 and 48 (lease evidence SS-12, SS-14,
// DL-15): consecutive gaps, scattered gaps, boundary hours, the anchoring
// deadline, zero acknowledgements, failed entries, early final heartbeats and
// the consecutive-slot rule.

const (
	slot    = int64(60)
	bracket = int64(30)
)

func watchParams(hours int64, bp uint16, miss uint32) Params {
	p := params(hours, uint32(hours), uint64(hours)*cap)
	p.SlotS, p.MinCoverageBP, p.LivenessMissSlots = slot, bp, miss
	return p
}

func full(n int) []uint64 {
	c := make([]uint64, n)
	for i := range c {
		c[i] = uint64(hour)
	}
	return c
}

// rig is a lease that booted on the slot at service_start and a watch on it.
type rig struct {
	t *testing.T
	l *Lease
	w *Watch
	n int64 // time of the next slot to report
}

func newRig(t *testing.T, p Params, creditable []uint64, bootTimely bool) *rig {
	t.Helper()
	l, err := New(p)
	must(t, err)
	must(t, l.Accept(start-600))
	must(t, l.Boot(start-120))
	w, err := NewWatch(l, creditable, bracket, start, bootTimely)
	must(t, err)
	return &rig{t: t, l: l, w: w, n: start + slot}
}

// slot reports the next slot after its anchoring deadline.
func (r *rig) slot(s Slot) {
	r.t.Helper()
	must(r.t, r.w.Observe(r.n, s, r.n+bracket))
	check(r.t, r.l)
	r.n += slot
}

// until reports s for every slot up to and including time t.
func (r *rig) until(t int64, s Slot) {
	r.t.Helper()
	for r.n <= t {
		r.slot(s)
	}
}

// endPiece ends piece k with a full expectation and the buyer's full note, as a
// cooperative buyer does, before the last slot of the piece is reported.
func (r *rig) endPiece(k uint32) {
	r.t.Helper()
	p := r.l.P
	r.until(p.End(k)-slot, SlotValid)
	must(r.t, r.l.PieceEnd(k, cap, p.End(k)))
	answer(r.t, r.l, k, cap, p.End(k)+bracket)
}

func wantStop(t *testing.T, l *Lease, why string) {
	t.Helper()
	if l.State == Running || !strings.Contains(l.Stopped, why) {
		t.Fatalf("want a stop with %q, got %s %q\n%s", why, l.State, l.Stopped, dump(l))
	}
}

func wantRunning(t *testing.T, l *Lease) {
	t.Helper()
	if l.State != Running {
		t.Fatalf("lease stopped: %s %q\n%s", l.State, l.Stopped, dump(l))
	}
}

func TestCoverageReachable(t *testing.T) {
	for _, c := range []struct {
		creditable, lost uint64
		bp               uint16
		want             bool
	}{
		{3600, 0, 9500, true},
		{3600, 180, 9500, true},   // 3,420 of 3,600: exactly the floor
		{3600, 240, 9500, false},  // 3,360: the reproduced attack
		{3540, 120, 9500, true},   // boundary hour: 3,420 >= 3,363
		{3540, 180, 9500, false},  // boundary hour: 3,360 < 3,363
		{3600, 3600, 0, true},     // no floor
		{3600, 4000, 9500, false}, // more lost than creditable
		{3600, 0, 10000, true},
		{3600, 60, 10000, false},
	} {
		if got := CoverageReachable(c.creditable, c.lost, c.bp); got != c.want {
			t.Errorf("CoverageReachable(%d, %d, %d) = %v, want %v", c.creditable, c.lost, c.bp, got, c.want)
		}
	}
}

// The reproduced attack: the buyer drops three consecutive slots, under the
// five-slot rule, so the middle hour can reach only 3,360 of 3,420 credited
// seconds. The lease stops at the deadline of the fourth lost interval and the
// next hour is never served.
func TestCoverageStopConsecutiveGaps(t *testing.T) {
	r := newRig(t, watchParams(3, 9500, 5), full(3), true)
	r.endPiece(0)
	r.slot(SlotValid) // the slot at End(0): piece 0's last interval
	r.until(r.l.P.Start(1)+10*slot, SlotValid)
	for i := 0; i < 3; i++ {
		r.slot(SlotMissing)
		wantRunning(t, r.l)
	}
	if r.w.Lost[1] != 180 {
		t.Fatalf("lost %d after three missing slots, want 180", r.w.Lost[1])
	}
	r.slot(SlotValid) // its interval touches the third missing slot: the fourth lost interval
	wantStop(t, r.l, "SS-12: piece 1 cannot reach")
	if r.l.Pieces[2] != Unserved {
		t.Fatalf("piece 2 status %d", r.l.Pieces[2])
	}
	// The final challenge for piece 1 gets a zero note (below the floor); the
	// batch settles piece 0.
	answer(t, r.l, 1, 0, r.n)
	if r.l.State != Stopped {
		t.Fatalf("state %s\n%s", r.l.State, dump(r.l))
	}
	got, err := r.l.Settle(0, r.n+600, true)
	must(t, err)
	if got != cap {
		t.Fatalf("settled %d", got)
	}
}

// Scattered gaps add up: two isolated missing slots lose four intervals.
func TestCoverageStopScatteredGaps(t *testing.T) {
	r := newRig(t, watchParams(3, 9500, 5), full(3), true)
	r.endPiece(0)
	r.slot(SlotValid)
	r.until(r.l.P.Start(1)+5*slot, SlotValid)
	r.slot(SlotMissing)
	r.until(r.l.P.Start(1)+30*slot, SlotValid)
	wantRunning(t, r.l)
	r.slot(SlotMissing) // third lost interval
	wantRunning(t, r.l)
	r.slot(SlotValid) // fourth
	wantStop(t, r.l, "SS-12: piece 1 cannot reach")
}

// Three lost intervals in a middle hour leave exactly 3,420 seconds: no stop.
// The missing slot at the hour boundary loses one interval in each hour.
func TestCoverageThreeLostIntervalsDoNotStop(t *testing.T) {
	r := newRig(t, watchParams(3, 9500, 5), full(3), true)
	r.until(r.l.P.End(0)-slot, SlotValid)
	must(t, r.l.PieceEnd(0, cap, r.l.P.End(0)))
	answer(t, r.l, 0, cap, r.l.P.End(0)+bracket)
	r.slot(SlotMissing) // the slot at End(0): one interval of piece 0, one of piece 1
	r.until(r.l.P.Start(1)+20*slot, SlotValid)
	r.slot(SlotMissing)
	r.until(r.l.P.End(1)-slot, SlotValid)
	if r.w.Lost[1] != 180 {
		t.Fatalf("lost %d in piece 1, want 180", r.w.Lost[1])
	}
	wantRunning(t, r.l)
}

// A boundary hour of 3,540 creditable seconds needs 3,363: three lost
// intervals stop it. The same pattern in a full hour does not.
func TestCoverageStopBoundaryHour(t *testing.T) {
	boundary := full(3)
	boundary[0] = 3540
	r := newRig(t, watchParams(3, 9500, 5), boundary, false) // boot late: the first interval is lost
	r.until(start+10*slot, SlotValid)
	r.slot(SlotMissing)
	wantRunning(t, r.l)
	r.slot(SlotValid)
	wantStop(t, r.l, "SS-12: piece 0 cannot reach")

	m := newRig(t, watchParams(3, 9500, 5), full(3), false)
	m.until(start+10*slot, SlotValid)
	m.slot(SlotMissing)
	m.slot(SlotValid)
	wantRunning(t, m.l)
}

// A slot is never counted before its anchoring deadline: its interval may
// still be credited.
func TestCoverageWaitsForAnchoringDeadline(t *testing.T) {
	r := newRig(t, watchParams(3, 9500, 5), full(3), true)
	t0 := r.n
	if err := r.w.Observe(t0, SlotMissing, t0+bracket-1); err == nil {
		t.Fatal("slot reported before its anchoring deadline")
	}
	if r.w.Lost[0] != 0 {
		t.Fatalf("lost %d before the deadline", r.w.Lost[0])
	}
	if err := r.w.Observe(t0+slot, SlotValid, t0+slot+bracket); err == nil {
		t.Fatal("a slot was skipped")
	}
	must(t, r.w.Observe(t0, SlotValid, t0+bracket))
}

// The consecutive-slot rule stays: five slots without a valid anchored
// heartbeat stop the lease, late entries included. The coverage floor is off
// here so that the rule is tested alone.
func TestLivenessMissedSlots(t *testing.T) {
	r := newRig(t, watchParams(3, 0, 5), full(3), true)
	r.until(start+10*slot, SlotValid)
	for i := 0; i < 4; i++ {
		r.slot(SlotMissing)
	}
	r.slot(SlotValid) // resets the count
	for i := 0; i < 4; i++ {
		r.slot(SlotLate)
	}
	wantRunning(t, r.l)
	r.slot(SlotMissing)
	wantStop(t, r.l, "SS-12: 5 slots without a valid anchored heartbeat")
}

// A correctly signed but malformed heartbeat stops the lease at once.
func TestLivenessFailedEntry(t *testing.T) {
	r := newRig(t, watchParams(3, 9500, 5), full(3), true)
	r.until(start+10*slot, SlotValid)
	r.slot(SlotFailed)
	wantStop(t, r.l, "failed the content check")
}

// A final heartbeat before service_end stops the lease; one at service_end
// is the normal end.
func TestLivenessEarlyFinal(t *testing.T) {
	r := newRig(t, watchParams(3, 9500, 5), full(3), true)
	r.until(start+10*slot, SlotValid)
	r.slot(SlotFinal)
	wantStop(t, r.l, "final heartbeat")
}

// Zero acknowledgement: the seller's verifier expects zero for piece 1 (an
// honest outage). The lease stops at the end of piece 1, the buyer's correct
// zero note is kept, and the batch settles piece 0.
func TestZeroAcknowledgementStops(t *testing.T) {
	r := newRig(t, watchParams(3, 9500, 5), full(3), true)
	r.endPiece(0)
	r.slot(SlotValid)
	r.until(r.l.P.End(1)-slot, SlotValid)
	must(t, r.l.PieceEnd(1, 0, r.l.P.End(1)))
	wantStop(t, r.l, "SS-14: piece 1 is zero-payable")
	answer(t, r.l, 1, 0, r.l.P.End(1)+bracket)
	if r.l.State != Stopped || r.l.Pieces[2] != Unserved {
		t.Fatalf("state %s piece 2 %d\n%s", r.l.State, r.l.Pieces[2], dump(r.l))
	}
	got, err := r.l.Settle(0, r.l.P.End(1)+600, true)
	must(t, err)
	if got != cap {
		t.Fatalf("settled %d", got)
	}
}

// The watch's parameters are bounded: the consecutive-slot window must fit in
// the challenge timeout so that E stays the bound, and the floor in 10000.
func TestWatchParameters(t *testing.T) {
	p := watchParams(3, 9500, 6) // 6 x 60 s > 300 s
	if _, err := New(p); err == nil {
		t.Fatal("accepted liveness_miss_slots x slot_s above challenge_timeout_s")
	}
	p = watchParams(3, 10001, 5)
	if _, err := New(p); err == nil {
		t.Fatal("accepted min_coverage_bp above 10000")
	}
	l, _ := New(watchParams(3, 9500, 5))
	if _, err := NewWatch(l, full(2), bracket, start, true); err == nil {
		t.Fatal("accepted creditable for the wrong number of pieces")
	}
}
