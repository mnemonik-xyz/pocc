package warrant

import (
	"errors"
	"fmt"
	"math/bits"
)

// Decide is the reference implementation of gates D4 to D9 for one record and
// its note (lease evidence 5a.3). Warrant's guest implements the same gates
// in Rust; test/vectors/usage-gates.json holds cases both must agree on.
// D1 to D3 (batch shape, signature, scope) need the batch and the key and are
// not decided here. It returns nil when the note may settle.
func Decide(d Delivery, r UsageRecord, amount uint64) error {
	w := r.WindowEnd - r.WindowStart
	switch {
	case r.FirstIndex != r.LastIndex:
		return errors.New("D1: a record covers one piece in v1")
	case r.WindowEnd <= r.WindowStart || int64(w) != d.PieceS:
		return errors.New("D4: window is not one piece")
	case d.ServiceStart < 0 || int64(r.WindowStart) != d.ServiceStart+int64(r.FirstIndex)*d.PieceS:
		return errors.New("D4: window is not the window of its index")
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
	hi2, rhs := bits.Mul64(uint64(d.MinUptimeBP), r.Creditable)
	if hi != 0 || hi2 != 0 {
		return errors.New("D9: uptime product overflows")
	}
	if lhs < rhs && amount != 0 {
		return fmt.Errorf("D6: uptime %d bp below %d, note must be 0", lhs/r.Creditable, d.MinUptimeBP)
	}
	if r.Assurance < d.MinAssurance && amount != 0 {
		return errors.New("D7: assurance below the floor, note must be 0")
	}
	return nil
}
