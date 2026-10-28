package sim

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/mnemonik-xyz/pocc/pkg/pocc"
	"github.com/mnemonik-xyz/pocc/pkg/verify"
)

const slots = 480 // 8 h: boot on a slot, then 480 heartbeats

// fullCredit is 480 slot intervals of 60 s.
const fullCredit = slots * 60

func run(t *testing.T, w *World, skip func(int) bool, billed int64) *pocc.Receipt {
	t.Helper()
	agentPub, err := w.Run(slots, skip)
	if err != nil {
		t.Fatal(err)
	}
	R, err := w.Receipt(agentPub, billed)
	if err != nil {
		t.Fatal(err)
	}
	return R
}

func expect(t *testing.T, v pocc.Verdict, status string, codes ...string) {
	t.Helper()
	if v.Status != status {
		t.Fatalf("status %s, want %s (codes %v)", v.Status, status, v.Codes)
	}
	for _, c := range codes {
		if !slices.Contains(v.Codes, c) {
			t.Fatalf("codes %v do not include %s", v.Codes, c)
		}
	}
}

// T1: the full cycle, request to usage records, verifies VALID.
func TestT1HappyPath(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil, fullCredit)
	v := w.Verify(R)
	expect(t, v, verify.StatusValid)
	if v.CreditedS != fullCredit || v.Assurance != "L0" {
		t.Fatalf("credited %d assurance %s, want %d L0", v.CreditedS, v.Assurance, fullCredit)
	}
	if v.Disclosed["480/cpu_ms"] != 480*30_000 {
		t.Fatalf("disclosed cpu_ms %v", v.Disclosed)
	}
	recs, err := w.Meter(R, v)
	if err != nil {
		t.Fatal(err)
	}
	var sum int64
	for _, r := range recs {
		sum += r.Units
		meterKey := R.Request.Policy.Delivery.MeterKey
		if err := pocc.VerifyDoc(meterKey, pocc.TagUsageRecord, r, r.Sig); err != nil {
			t.Fatalf("usage record signature: %v", err)
		}
		if r.Lease != R.Order.OrderID || r.UptimeBP > 10000 {
			t.Fatalf("bad record %+v", r)
		}
	}
	if sum != v.CreditedS {
		t.Fatalf("usage records sum to %d, verdict credited %d", sum, v.CreditedS)
	}
}

// Integrity check that also holds in Stage 0: a key generated outside the VM.
func TestForeignKeyHeartbeat(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil, fullCredit)
	_, other := pocc.GenerateSigningKey()
	R.Heartbeats[41].Sig = pocc.SignRaw(other, pocc.MustUnhex(R.Heartbeats[41].E))
	w.Resign(R)
	expect(t, w.Verify(R), verify.StatusInvalid, "E_CHAIN")
}

// T3: heartbeat 10 resubmitted in place of heartbeat 11.
func TestT3Replay(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil, fullCredit)
	R.Heartbeats[10] = R.Heartbeats[9]
	w.Resign(R)
	expect(t, w.Verify(R), verify.StatusInvalid, "E_SEQ", "E_SCHEDULE")
}

// T4: one batch held for 60 s before anchoring. The late heartbeat and both
// intervals touching it earn nothing; billing them is overbilling.
func TestT4Backdated(t *testing.T) {
	held := func(w *World) {
		slot := w.Slot0 + 200*SlotRounds
		w.AnchorDelay = func(s uint64) time.Duration {
			if s == slot {
				return 60 * time.Second
			}
			return 5 * time.Second
		}
	}
	w := NewWorld(slots, RateMicros)
	held(w)
	R := run(t, w, nil, fullCredit-120)
	v := w.Verify(R)
	expect(t, v, verify.StatusValidWithGaps)
	if v.Late != 1 || v.CreditedS != fullCredit-120 {
		t.Fatalf("late %d credited %d, want 1 and %d", v.Late, v.CreditedS, fullCredit-120)
	}
	w2 := NewWorld(slots, RateMicros)
	held(w2)
	expect(t, w2.Verify(run(t, w2, nil, fullCredit)), verify.StatusInvalid, "E_OVERBILL")
}

// T6: billed 600 s more than proven.
func TestT6Overbilling(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil, fullCredit+600)
	expect(t, w.Verify(R), verify.StatusInvalid, "E_OVERBILL")
}

// T7: order A's proofs moved into a receipt for order B.
func TestT7MovedProofs(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil, fullCredit)
	R.Order = w.NewOrder("ord-sim-2")
	w.Resign(R)
	expect(t, w.Verify(R), verify.StatusInvalid, "E_BIND")
}

// T8: a disclosed usage value higher than committed.
func TestT8AlteredUsage(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil, fullCredit)
	R.Openings[0].Value += 1000
	w.Resign(R)
	expect(t, w.Verify(R), verify.StatusInvalid, "E_OPENING")
}

// T9: the agent is paused for 10 slots; the gap and the interval across it earn nothing.
func TestT9Outage(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	want := int64(fullCredit - 11*60)
	R := run(t, w, func(i int) bool { return i >= 100 && i < 110 }, want)
	v := w.Verify(R)
	expect(t, v, verify.StatusValidWithGaps)
	if v.CreditedS != want || v.Gaps != 1 {
		t.Fatalf("credited %d gaps %d, want %d 1", v.CreditedS, v.Gaps, want)
	}
	if R2 := run(t, NewWorld(slots, RateMicros), func(i int) bool { return i >= 100 && i < 110 }, fullCredit); w.Verify(R2).Status != verify.StatusInvalid {
		t.Fatal("billing the outage was accepted")
	}
}

// Stage 0 boot evidence: the Nova record must match the request.
func TestNovaMismatch(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil, fullCredit)
	R.NovaServer.Flavor = "d1.cpu1ram1"
	w.Resign(R)
	expect(t, w.Verify(R), verify.StatusInvalid, "E_NOVA")
}

// The tenant's policy fixes the price; an order at another price is rejected.
func TestPolicyMismatch(t *testing.T) {
	w := NewWorld(slots, 1000) // policy price differs from the order rate
	R := run(t, w, nil, fullCredit)
	expect(t, w.Verify(R), verify.StatusInvalid, "E_POLICY")
}

// The notary refuses a second history for the same agent and seq.
func TestNotaryRejectsFork(t *testing.T) {
	w := NewWorld(3, RateMicros)
	agentPub, err := w.Run(3, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := w.Notary.Entries(agentPub)[1]
	e.E = pocc.Hex(make([]byte, 32))
	if err := w.Notary.Submit(e); err == nil {
		t.Fatal("tampered entry accepted")
	}
	if c, _ := w.Notary.HasConflict(context.Background(), agentPub, 1, e.E); !c {
		t.Fatal("conflict not reported")
	}
}
