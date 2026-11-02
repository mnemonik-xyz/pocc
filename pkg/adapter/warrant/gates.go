package warrant

import (
	"errors"
	"fmt"
	"math/bits"
)

// Decide is the Go reference for the per-record parts of gates D1 and D4 to
// D9 (lease evidence 5a.3), for one record and the amount of its note. It is
// not the whole delivery check: D1's batch shape, D2 (signature under
// meter_key), D3 (scope, lease and meter_spec equality) and D5's binding
// note.deliverable_hash == hash(record) need the batch, the key and Warrant's
// own encodings, and are Warrant's to decide; PoCC never computes a Warrant
// hash (decision 18). Warrant's guest implements every gate in Rust;
// test/vectors/usage-gates.json holds the cases both must decide alike.
// It returns nil when the note may settle as far as these checks go.
func Decide(d Delivery, r UsageRecord, amount uint64) error {
	w := r.WindowEnd - r.WindowStart
	switch {
	case r.FirstIndex != r.LastIndex:
		return errors.New("D1: a record covers one piece in v1")
	case r.WindowEnd <= r.WindowStart || int64(w) != d.PieceS:
		return errors.New("D4: window is not one piece")
	case d.ServiceStart < 0 || int64(r.WindowStart) != d.ServiceStart+int64(r.FirstIndex)*d.PieceS:
		return errors.New("D4: window is not the window of its index")
	case int64(r.WindowEnd) > d.ServiceEnd:
		return errors.New("D4: window ends after the service period")
	case r.Creditable == 0 || r.Creditable > w:
		return errors.New("D8: creditable is zero or longer than the window")
	case r.Units > r.Creditable:
		return errors.New("D8: units above creditable")
	case r.Assurance > 1:
		return errors.New("D8: assurance is not 0 or 1")
	}
	hi, due := bits.Mul64(r.Units, uint64(d.PricePerUnit))
	if hi != 0 || d.PricePerUnit < 0 || d.Tolerance < 0 {
		return errors.New("D9: units x price overflows")
	}
	due, carry := bits.Add64(due, uint64(d.Tolerance), 0)
	if carry != 0 {
		return errors.New("D9: due + tolerance overflows")
	}
	if amount > due {
		return fmt.Errorf("D5: amount %d above units x price + tolerance %d", amount, due)
	}
	hi, lhs := bits.Mul64(r.Units, 10000)
	hi2, rhs := bits.Mul64(uint64(d.MinCoverageBP), r.Creditable)
	if hi != 0 || hi2 != 0 {
		return errors.New("D9: coverage product overflows")
	}
	if lhs < rhs && amount != 0 {
		return fmt.Errorf("D6: coverage %d bp below %d, note must be 0", lhs/r.Creditable, d.MinCoverageBP)
	}
	if r.Assurance < d.MinAssurance && amount != 0 {
		return errors.New("D7: assurance below the floor, note must be 0")
	}
	return nil
}
