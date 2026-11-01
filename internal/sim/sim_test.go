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

func run(t *testing.T, w *World, skip func(int) bool) *pocc.Receipt {
	t.Helper()
	agentPub, err := w.Run(slots, skip)
	if err != nil {
		t.Fatal(err)
	}
	R, err := w.Receipt(agentPub)
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
	R := run(t, w, nil)
	v := w.Verify(R)
	expect(t, v, verify.StatusValid)
	if v.CreditedS != fullCredit || v.Assurance != "L0" || v.MaxAmountMicros != fullCredit*RateMicros {
		t.Fatalf("credited %d assurance %s max %d, want %d L0 %d", v.CreditedS, v.Assurance, v.MaxAmountMicros, fullCredit, fullCredit*RateMicros)
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

// The Warrant policy in the request, h0 from the escrow order, and
// Warrant-shaped records from the adapter.
func TestWarrantRecords(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil)
	v := w.Verify(R)
	expect(t, v, verify.StatusValid)
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

// A policy pinning another meter spec is refused, and so is a receipt bound
// to another escrow order.
func TestPolicyAndBinding(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil)
	other := w.Request
	other.Policy = WarrantPolicy(w.Request, "k", RateMicros, strings.Repeat("ab", 32))
	other.Sig, _ = pocc.SignDoc(w.TenantPriv, pocc.TagRequest, other)
	R2 := *R
	R2.Request = other
	expect(t, w.Verify(&R2), verify.StatusInvalid, "E_POLICY")

	R3 := *R
	R3.EscrowOrder = pocc.EscrowOrder{ChainID: EscrowChainID, Escrow: EscrowAddr,
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

// The period must start on a clock hour.
func TestPeriodAlignment(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	ps, _ := time.Parse(time.RFC3339, w.Request.Period.Start)
	w.Request.Period.Start = ps.Add(30 * time.Second).Format(time.RFC3339)
	ms, _ := pocc.MeterSpecHash(w.MeterSpec)
	w.Request.Policy = WarrantPolicy(w.Request, "k", RateMicros, pocc.Hex(ms))
	w.Request.Sig, _ = pocc.SignDoc(w.TenantPriv, pocc.TagRequest, w.Request)
	R := run(t, w, nil)
	expect(t, w.Verify(R), verify.StatusInvalid, "E_PERIOD")
}

// Integrity check that also holds in Stage 0: a key generated outside the VM.
func TestForeignKeyHeartbeat(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil)
	_, other := pocc.GenerateSigningKey()
	R.Heartbeats[41].Sig = pocc.SignRaw(other, pocc.MustUnhex(R.Heartbeats[41].E))
	expect(t, w.Verify(R), verify.StatusInvalid, "E_CHAIN")
}

// T3: heartbeat 10 resubmitted in place of heartbeat 11.
func TestT3Replay(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil)
	R.Heartbeats[10] = R.Heartbeats[9]
	expect(t, w.Verify(R), verify.StatusInvalid, "E_SEQ", "E_SCHEDULE")
}

// T4: one batch held for 60 s before anchoring. The late heartbeat and both
// intervals touching it earn nothing, so the usage record for that hour is
// short; a note billing the full hour fails Warrant gate D5.
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
	R := run(t, w, nil)
	v := w.Verify(R)
	expect(t, v, verify.StatusValidWithGaps)
	if v.Late != 1 || v.CreditedS != fullCredit-120 {
		t.Fatalf("late %d credited %d, want 1 and %d", v.Late, v.CreditedS, fullCredit-120)
	}
	assertNoteDenied(t, R, v, 200*60/3600, 3600*RateMicros)
}

// T6: overbilling. The bill is a Warrant note, not a receipt field, so the
// check is Warrant's gate D5 against the usage record: with full delivery a
// note of 3,600 s x price passes and one token unit more fails.
func TestT6Overbilling(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil)
	v := w.Verify(R)
	expect(t, v, verify.StatusValid)
	recs, _ := verify.UsageRecords(R, v, nil)
	wr, err := warrant.Records(R.Request, recs)
	if err != nil {
		t.Fatal(err)
	}
	full := int64(wr[1].Units) * RateMicros
	if full != 3600*RateMicros || noteAllowed(wr[1], full+1) || !noteAllowed(wr[1], full) {
		t.Fatalf("hour 1: %d units, D5 bound %d", wr[1].Units, full)
	}
}

// noteAllowed is Warrant gate D5 with zero tolerance: amount <= units x price.
func noteAllowed(r warrant.UsageRecord, amount int64) bool {
	return amount <= int64(r.Units)*RateMicros
}

// assertNoteDenied checks that a note of amount for the given hour fails D5.
func assertNoteDenied(t *testing.T, R *pocc.Receipt, v pocc.Verdict, hour int, amount int64) {
	t.Helper()
	recs, _ := verify.UsageRecords(R, v, nil)
	wr, err := warrant.Records(R.Request, recs)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range wr {
		if int(r.FirstIndex) == hour {
			if noteAllowed(r, amount) {
				t.Fatalf("hour %d: %d units, a note of %d would pass D5", hour, r.Units, amount)
			}
			return
		}
	}
	t.Fatalf("no record for hour %d", hour)
}

// T7: the proofs of one deal moved into a receipt bound to another escrow order.
func TestT7MovedProofs(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil)
	R.EscrowOrder.OrderID = "0x5555555555555555555555555555555555555555555555555555555555555555"
	expect(t, w.Verify(R), verify.StatusInvalid, "E_BIND")
}

// T8: a disclosed usage value higher than committed.
func TestT8AlteredUsage(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil)
	R.Openings[0].Value += 1000
	expect(t, w.Verify(R), verify.StatusInvalid, "E_OPENING")
}

// T9: the agent is paused for 10 slots; the gap and the interval across it
// earn nothing, and a note for the full hour fails D5.
func TestT9Outage(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	want := int64(fullCredit - 11*60)
	R := run(t, w, func(i int) bool { return i >= 100 && i < 110 })
	v := w.Verify(R)
	expect(t, v, verify.StatusValidWithGaps)
	if v.CreditedS != want || v.Gaps != 1 {
		t.Fatalf("credited %d gaps %d, want %d 1", v.CreditedS, v.Gaps, want)
	}
	assertNoteDenied(t, R, v, 100*60/3600, 3600*RateMicros)
}

// Stage 0 boot evidence: the Nova record must match the request.
func TestNovaMismatch(t *testing.T) {
	w := NewWorld(slots, RateMicros)
	R := run(t, w, nil)
	R.NovaServer.Flavor = "d1.cpu1ram1"
	expect(t, w.Verify(R), verify.StatusInvalid, "E_NOVA")
}

// The policy's price, not the request's maximum, prices the hours.
func TestPolicyPrice(t *testing.T) {
	w := NewWorld(slots, 1000)
	R := run(t, w, nil)
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
