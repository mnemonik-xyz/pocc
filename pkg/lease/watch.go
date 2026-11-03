package lease

import "fmt"

// Observation is the seller's reading of one slot of a PoCC lease, made by the
// liveness watch (lease evidence SS-12) once the slot's anchoring deadline has
// passed. The watch reads the notary's entries for the lease's agent, checks
// each new entry with the verifier against the stored valid prefix (SS-13),
// and reports the result here. The lease does not re-derive credit: Credited
// is the verifier's verdict over the valid prefix.
type Observation struct {
	// Live: a valid heartbeat for the slot was anchored inside the bracket. A
	// late entry is valid but not live; it is not a failed entry either.
	Live bool
	// Final: the valid heartbeat for the slot is marked final.
	Final bool
	// Failed: an entry for the slot fails the verifier's content check (wrong
	// round, beacon value or chain link, or an entry after a final heartbeat).
	Failed bool
	// Credited: the verifier, over the valid prefix, credited the interval that
	// ends at this slot. Slot 0 ends no interval and its Credited is ignored.
	Credited bool
}

// Watch takes the observation for slot j, in order from slot 0, at time now.
// now must be at or after the slot's anchoring deadline (slot time plus
// BracketS): before it an interval is not irrecoverably missed and is not
// counted, so an early observation is refused and changes nothing.
//
// It stops a running lease, in this order of cause, when:
//   - an entry fails the content check;
//   - a final heartbeat arrives before service_end;
//   - liveness_miss_slots consecutive slots have no live heartbeat (decision 47);
//   - the piece of the interval can no longer reach min_coverage_bp, counting
//     every interval, consecutive or scattered, that was not credited once its
//     anchoring deadline passed (decision 48).
//
// Observations after the lease stopped are recorded and stop nothing more.
// Slots after service_end are ignored.
func (l *Lease) Watch(j uint32, o Observation, now int64) error {
	p := l.P
	switch {
	case !p.Watched():
		return fmt.Errorf("lease has no liveness watch")
	case l.State != Running && l.State != Stopping && l.State != Stopped:
		return fmt.Errorf("watch in state %s", l.State)
	case j != l.nextSlot:
		return fmt.Errorf("SS-12: slot %d observed, slot %d expected", j, l.nextSlot)
	case now < p.AnchorDeadline(j):
		return fmt.Errorf("SS-12: slot %d observed at %d, before its anchoring deadline %d", j, now, p.AnchorDeadline(j))
	}
	l.nextSlot++
	t := p.SlotTime(j)
	if t > p.ServiceEnd {
		return nil
	}

	// The interval that ends at slot j belongs to the piece that contains its end.
	var k uint32
	interval := j >= 1 && t > p.ServiceStart
	if interval {
		k = p.PieceOf(t)
		if o.Credited && !o.Failed {
			l.Credited[k] += p.SlotS
		} else {
			l.LostS[k] += p.SlotS
		}
	}

	if o.Live && !o.Failed {
		l.missed = 0
	} else {
		l.missed++
	}

	if l.State != Running {
		return nil
	}
	switch {
	case o.Failed:
		l.stop(now, fmt.Sprintf("SS-12: entry for slot %d failed the content check", j))
	case o.Final && t < p.ServiceEnd:
		l.stop(now, fmt.Sprintf("SS-12: final heartbeat at slot %d before service_end", j))
	case l.missed >= p.LivenessMissSlots:
		l.stop(now, fmt.Sprintf("SS-12: %d consecutive slots without a live heartbeat", l.missed))
	case interval && l.floorOutOfReach(k):
		// The current piece is the one being served, the provisional one, or
		// the challenged one whose last interval is still inside its bracket.
		st := l.Pieces[k]
		if st != Served && st != Provisional && st != Challenged {
			return nil // a piece already decided or never served keeps its outcome
		}
		// The seller's own view of the piece is now zero-payable: a zero note
		// for it is correct, and nothing after it is served (SS-14).
		l.Expected[k] = 0
		l.stop(now, fmt.Sprintf("SS-12: piece %d cannot reach min_coverage_bp %d (lost %d of %d s)",
			k, p.MinCoverageBP, l.LostS[k], p.Creditable(k)))
	}
	return nil
}

func (l *Lease) floorOutOfReach(k uint32) bool {
	return FloorOutOfReach(l.P.Creditable(k), l.LostS[k], l.P.MinCoverageBP)
}
