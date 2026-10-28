package verify

import (
	"encoding/json"
	"fmt"

	"github.com/mnemonik-xyz/pocc/pkg/pocc"
)

// DryRunRule evaluates the policy's rule tree against one usage record, for
// demonstration only. Warrant's verified evaluator is the authority; this
// mirrors the atoms PoCC proposes for the rent case: all, any,
// assurance_at_least, uptime_at_least_bp, and amount_at_most (in currency
// micro-units for the record's window).
func DryRunRule(rule json.RawMessage, rec pocc.UsageRecord, pricePerUnit int64) (bool, error) {
	var node map[string]json.RawMessage
	if err := json.Unmarshal(rule, &node); err != nil || len(node) != 1 {
		return false, fmt.Errorf("rule node must be an object with one key")
	}
	for k, v := range node {
		switch k {
		case "all", "any":
			var kids []json.RawMessage
			if err := json.Unmarshal(v, &kids); err != nil || len(kids) == 0 {
				return false, fmt.Errorf("%s needs a non-empty list", k)
			}
			for _, kid := range kids {
				ok, err := DryRunRule(kid, rec, pricePerUnit)
				if err != nil {
					return false, err
				}
				if k == "all" && !ok {
					return false, nil
				}
				if k == "any" && ok {
					return true, nil
				}
			}
			return k == "all", nil
		case "assurance_at_least":
			var lvl string
			if err := json.Unmarshal(v, &lvl); err != nil {
				return false, err
			}
			rank := map[string]int{"L0": 0, "L1": 1}
			want, ok1 := rank[lvl]
			got, ok2 := rank[rec.Assurance]
			return ok1 && ok2 && got >= want, nil
		case "uptime_at_least_bp":
			var n int64
			if err := json.Unmarshal(v, &n); err != nil {
				return false, err
			}
			return rec.UptimeBP >= n, nil
		case "amount_at_most":
			var n int64
			if err := json.Unmarshal(v, &n); err != nil {
				return false, err
			}
			return rec.Units*pricePerUnit <= n, nil
		default:
			return false, fmt.Errorf("unknown atom %q", k)
		}
	}
	return false, nil
}
