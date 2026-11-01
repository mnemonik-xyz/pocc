package warrant

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The shared vectors (DL-12): every case decides the same way here and in
// Warrant's authorize_meter.
func TestGateVectors(t *testing.T) {
	b, err := os.ReadFile("../../../test/vectors/usage-gates.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Delivery Delivery `json:"delivery"`
		Cases    []struct {
			Name   string      `json:"name"`
			Record UsageRecord `json:"record"`
			Amount uint64      `json:"amount"`
			Price  *int64      `json:"price_per_unit"`
			OK     bool        `json:"ok"`
			Gate   string      `json:"gate"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		d := v.Delivery
		if c.Price != nil {
			d.PricePerUnit = *c.Price
		}
		err := Decide(d, c.Record, c.Amount)
		switch {
		case c.OK && err != nil:
			t.Errorf("%s: refused: %v", c.Name, err)
		case !c.OK && err == nil:
			t.Errorf("%s: accepted, want %s", c.Name, c.Gate)
		case !c.OK && !strings.HasPrefix(err.Error(), c.Gate+":"):
			t.Errorf("%s: %v, want gate %s", c.Name, err, c.Gate)
		}
	}
}
