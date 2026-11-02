package verify

import (
	"testing"
	"time"

	"github.com/mnemonik-xyz/pocc/pkg/beacon"
	"github.com/mnemonik-xyz/pocc/pkg/pocc"
)

// The three probes of the 2 Nov audit, kept as regression tests.

func TestCreditableThreeHours(t *testing.T) {
	start := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	cr := Creditable(beacon.Quicknet, 20, start, start.Add(3*time.Hour))
	want := []int64{3540, 3600, 3600} // the last hour has 60 intervals (lease evidence 5a.2)
	for k, w := range want {
		if got := cr[start.Add(time.Duration(k)*time.Hour).Format(time.RFC3339)]; got != w {
			t.Fatalf("hour %d: %d, want %d", k, got, w)
		}
	}
	var sum int64
	for _, v := range cr {
		sum += v
	}
	if sum != 3*3600-60 {
		t.Fatalf("total %d", sum)
	}
}

func TestUsageRecordsFillUncreditedHour(t *testing.T) {
	start := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	end := start.Add(3 * time.Hour)
	R := &pocc.Receipt{Request: pocc.Request{
		Period:    pocc.Period{Start: start.Format(time.RFC3339), End: end.Format(time.RFC3339)},
		MeterSpec: pocc.MeterSpec{Format: pocc.Version, BeaconChainHash: beacon.Quicknet.ChainHash, SlotRounds: 20}}}
	v := pocc.Verdict{Status: StatusValidWithGaps, Assurance: "L0", PerHourS: map[string]int64{
		start.Format(time.RFC3339):                    3540,
		start.Add(2 * time.Hour).Format(time.RFC3339): 3600}}
	recs, err := UsageRecords(R, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || recs[0].Hour != 0 || recs[1].Hour != 1 || recs[2].Hour != 2 {
		t.Fatalf("records: %+v", recs)
	}
	if recs[1].Units != 0 || recs[1].Creditable != 3600 || recs[1].CoverageBP != 0 {
		t.Fatalf("uncredited middle hour: %+v", recs[1])
	}
	if recs[0].CoverageBP != 10000 || recs[2].CoverageBP != 10000 {
		t.Fatalf("coverage: %d %d", recs[0].CoverageBP, recs[2].CoverageBP)
	}
	// An INVALID verdict is not evidence: no records at all.
	v.Status = StatusInvalid
	if recs, _ := UsageRecords(R, v, nil); recs != nil {
		t.Fatal("records for an INVALID verdict")
	}
}
