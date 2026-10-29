package sim

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mnemonik-xyz/pocc/pkg/adapter/warrant"
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
	meterKey := pocc.B64.EncodeToString(w.MeterPriv.Public().(ed25519.PublicKey))
	for _, r := range recs {
		sum += r.Units
		if err := pocc.VerifyDoc(meterKey, pocc.TagUsageRecord, r, r.Sig); err != nil {
			t.Fatalf("usage record signature: %v", err)
		}
		if r.Lease != pocc.Hex(pocc.LeaseID(R.Request)) || r.UptimeBP > 10000 || r.Hour < 0 || r.Hour > 8 {
			t.Fatalf("bad record %+v", r)
		}
	}
	if sum != v.CreditedS {
		t.Fatalf("usage records sum to %d, verdict credited %d", sum, v.CreditedS)
	}
	// drand slots fall at :24 past each minute, so an hour-aligned 8 h period
	// yields nine records: 3,540 s in the first hour and 60 s in the ninth.
	if len(recs) != 9 || recs[0].Units != 3540 || recs[8].Units != 60 {
		t.Fatalf("hourly records: %+v", recs)
	}
}

// Escrow mode: the Warrant policy in the request, h0 from the escrow order,
// and Warrant-shaped records from the adapter.
func TestEscrowModeHappyPath(t *testing.T) {
	w := NewEscrowWorld(slots, RateMicros)
	R := run(t, w, nil, 0)
	if R.EscrowOrder == nil || R.Order.OrderID != "" {
		t.Fatal("receipt is not in escrow mode")
	}
	v := w.Verify(R)
	expect(t, v, verify.StatusValid)
	if v.CreditedS != fullCredit || v.MaxAmountMicros != fullCredit*RateMicros {
		t.Fatalf("credited %d max %d", v.CreditedS, v.MaxAmountMicros)
	}
	recs, err := verify.UsageRecords(R, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	wr, err := warrant.Records(R.Request, recs)
	if err != nil {
		t.Fatal(err)
	}
	if len(wr) != 9 || wr[0].FirstIndex != 0 || wr[8].LastIndex != 8 || wr[0].Units != 3540 || wr[1].Units != 3600 || wr[0].Scope.ChainID != EscrowChainID {
		t.Fatalf("warrant records: %d records, first %+v", len(wr), wr[0])
	}
	b, _ := json.Marshal(wr[0])
	if !strings.Contains(string(b), `"lease_id":[`) || !strings.Contains(string(b), `"vault":[`) {
		t.Fatalf("records must serialize hashes and addresses as byte arrays: %s", b)
	}
	ms, _ := pocc.MeterSpecHash(w.MeterSpec)
	if wr[0].MeterSpec != warrant.Bytes32(ms) {
		t.Fatal("meter_spec in the record differs from the request's")
	}
}

// Escrow mode: a policy pinning another meter spec is refused, and so is a
// receipt bound to another escrow order.
func TestEscrowModePolicyAndBinding(t *testing.T) {
	w := NewEscrowWorld(slots, RateMicros)
	R := run(t, w, nil, 0)
	other := w.Request
	other.Policy = WarrantPolicy(w.Request, "k", RateMicros, strings.Repeat("ab", 32))
	other.Sig, _ = pocc.SignDoc(w.TenantPriv, pocc.TagRequest, other)
	R2 := *R
	R2.Request = other
	expect(t, w.Verify(&R2), verify.StatusInvalid, "E_POLICY")

	R3 := *R
	R3.EscrowOrder = &pocc.EscrowOrder{ChainID: EscrowChainID, Escrow: EscrowAddr,
		OrderID: "0x4444444444444444444444444444444444444444444444444444444444444444"}
	expect(t, w.Verify(&R3), verify.StatusInvalid, "E_BIND")

	// A policy whose price exceeds the request's maximum rate.
	pricey := w.Request
	ms, _ := pocc.MeterSpecHash(w.MeterSpec)
	pricey.Policy = WarrantPolicy(w.Request, "k", 5000, pocc.Hex(ms))
	pricey.Sig, _ = pocc.SignDoc(w.TenantPriv, pocc.TagRequest, pricey)
	R4 := *R
	R4.Request = pricey
	expect(t, w.Verify(&R4), verify.StatusInvalid, "E_POLICY")
}

// Escrow mode: the period must start on a clock hour.
func TestEscrowModePeriodAlignment(t *testing.T) {
	w := NewEscrowWorld(slots, RateMicros)
	ps, _ := time.Parse(time.RFC3339, w.Request.Period.Start)
	w.Request.Period.Start = ps.Add(30 * time.Second).Format(time.RFC3339)
	ms, _ := pocc.MeterSpecHash(w.MeterSpec)
	w.Request.Policy = WarrantPolicy(w.Request, "k", RateMicros, pocc.Hex(ms))
	w.Request.Sig, _ = pocc.SignDoc(w.TenantPriv, pocc.TagRequest, w.Request)
	R := run(t, w, nil, 0)
	expect(t, w.Verify(R), verify.StatusInvalid, "E_PERIOD")
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

// In escrow mode the policy's price, not the request's maximum, prices the hours.
func TestEscrowModePolicyPrice(t *testing.T) {
	w := NewEscrowWorld(slots, 1000)
	R := run(t, w, nil, 0)
	v := w.Verify(R)
	expect(t, v, verify.StatusValid)
	if v.MaxAmountMicros != v.CreditedS*1000 {
		t.Fatalf("max amount %d, want credited %d x 1000", v.MaxAmountMicros, v.CreditedS)
	}
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
