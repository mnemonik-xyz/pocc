package verify

import (
	"encoding/json"
	"testing"

	"github.com/mnemonik-xyz/pocc/pkg/pocc"
)

func TestDryRunRule(t *testing.T) {
	rule := json.RawMessage(`{"all":[{"assurance_at_least":"L0"},{"uptime_at_least_bp":9500},{"amount_at_most":4000000}]}`)
	full := pocc.UsageRecord{Assurance: "L0", Units: 3600, UptimeBP: 10000}
	if ok, err := DryRunRule(rule, full, 1100); err != nil || !ok {
		t.Fatalf("full hour: %v %v", ok, err)
	}
	paused := pocc.UsageRecord{Assurance: "L0", Units: 2700, UptimeBP: 7500}
	if ok, _ := DryRunRule(rule, paused, 1100); ok {
		t.Fatal("75% uptime allowed")
	}
	if ok, _ := DryRunRule(json.RawMessage(`{"any":[{"assurance_at_least":"L1"},{"uptime_at_least_bp":7000}]}`), paused, 1100); !ok {
		t.Fatal("any branch not taken")
	}
	if _, err := DryRunRule(json.RawMessage(`{"nope":1}`), full, 1100); err == nil {
		t.Fatal("unknown atom accepted")
	}
}
