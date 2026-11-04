package lease

import (
	"errors"
	"fmt"
)

// Slot is the seller's finding for one PoCC slot, taken once the slot's
// anchoring deadline (its round time plus bracket_s) has passed (lease
// evidence SS-12, decisions 47 and 48). The caller derives it from the notary's
// entries and the verifier run over the stored valid prefix (SS-13).
type Slot int

const (
	// SlotValid: an entry that passes the verifier's content check and is
	// anchored inside the bracket. It counts as liveness.
	SlotValid Slot = iota
	// SlotLate: passes the content check, anchored after the bracket. Valid,
	// earns no credit, does not count as liveness, is not a failure.
	SlotLate
	// SlotMissing: no entry for the slot by its anchoring deadline.
	SlotMissing
	// SlotFailed: an entry that fails the content check (sequence, schedule,
	// beacon value, chain link, signature, entry after a final heartbeat). The
	// notary accepts such an entry; a receipt that includes it is INVALID, so
	// the seller stops and keeps the prefix before it.
	SlotFailed
	// SlotFinal: a valid final heartbeat anchored inside the bracket.
	SlotFinal
)

func (s Slot) String() string {
	return [...]string{"valid", "late", "missing", "failed", "final"}[s]
}

// Watch is the decision logic of the liveness and coverage watch of SS-12. It
// stops the lease on a failed entry, on an early final heartbeat, after
// LivenessMissSlots consecutive slots without a valid anchored heartbeat, and
// as soon as the running piece can no longer reach min_coverage_bp. An interval
// earns credit only when both of its ends are valid and anchored in time, as
// in the verifier; a missing or late heartbeat therefore loses both intervals
// that touch it. An interval belongs to the piece of its end time minus one
// second, as in the verifier's per-hour credit.
type Watch struct {
	L          *Lease
	Creditable []uint64 // per piece: the verifier's creditable seconds (verify.Creditable)
	BracketS   int64    // the anchoring bracket: a slot is reported only after round time + BracketS
	Lost       []uint64 // per piece: seconds that can no longer be credited

	last   int64 // time of the last reported slot (the boot slot at first)
	prevOK bool  // the last reported slot was valid and anchored in time
	misses uint32
}

// NewWatch starts the watch at the boot slot bootT; bootTimely is whether the
// boot proof was anchored inside the bracket.
func NewWatch(l *Lease, creditable []uint64, bracketS, bootT int64, bootTimely bool) (*Watch, error) {
	switch {
	case l == nil || l.P.SlotS <= 0:
		return nil, errors.New("watch needs a lease with a slot length")
	case uint32(len(creditable)) != l.P.Pieces():
		return nil, fmt.Errorf("creditable for %d pieces, lease has %d", len(creditable), l.P.Pieces())
	case bracketS < 0:
		return nil, errors.New("negative bracket")
	}
	for k, c := range creditable {
		if c > uint64(l.P.PieceS) {
			return nil, fmt.Errorf("creditable %d of piece %d above piece_s", c, k)
		}
	}
	return &Watch{L: l, Creditable: creditable, BracketS: bracketS, Lost: make([]uint64, len(creditable)),
		last: bootT, prevOK: bootTimely}, nil
}

// Observe reports slot t, the next slot after the last one reported, at time
// now. A slot before its anchoring deadline is refused and nothing is counted:
// its interval may still be credited.
func (w *Watch) Observe(t int64, s Slot, now int64) error {
	l := w.L
	switch {
	case t != w.last+l.P.SlotS:
		return fmt.Errorf("slot %d is not the next slot after %d", t, w.last)
	case now < t+w.BracketS:
		return fmt.Errorf("slot %d reported at %d, before its anchoring deadline %d", t, now, t+w.BracketS)
	case s < SlotValid || s > SlotFinal:
		return fmt.Errorf("unknown slot finding %d", s)
	}
	ok := s == SlotValid || s == SlotFinal
	credited := ok && w.prevOK
	w.last, w.prevOK = t, ok
	if l.State != Running {
		return nil
	}
	if s == SlotFailed {
		l.stop(now, fmt.Sprintf("SS-12: entry for slot %d failed the content check", t))
		return nil
	}

	// The interval (t - slot, t]: inside the service, attributed by end time.
	if !credited && t-l.P.SlotS >= l.P.ServiceStart && t <= l.P.ServiceEnd {
		k := uint32((t - 1 - l.P.ServiceStart) / l.P.PieceS)
		lost, err := add(w.Lost[k], uint64(l.P.SlotS))
		if err != nil {
			return err
		}
		w.Lost[k] = lost
		if l.running(k) && w.Creditable[k] > 0 {
			if err := l.Coverage(k, w.Creditable[k], w.Lost[k], now); err != nil {
				return err
			}
			if l.State != Running {
				return nil
			}
		}
	}

	if s == SlotFinal && t < l.P.ServiceEnd {
		l.stop(now, fmt.Sprintf("SS-12: final heartbeat at %d before service_end", t))
		return nil
	}
	if ok {
		w.misses = 0
		return nil
	}
	w.misses++
	if l.P.LivenessMissSlots > 0 && w.misses >= l.P.LivenessMissSlots {
		l.stop(now, fmt.Sprintf("SS-12: %d slots without a valid anchored heartbeat", w.misses))
	}
	return nil
}
