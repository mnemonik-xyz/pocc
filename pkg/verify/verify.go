// Package verify implements the PoCC verifier (spec section 5) and turns a
// verdict into per-hour usage records for Warrant's rent case (spec section 10).
package verify

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/mnemonik-xyz/pocc/pkg/anchor"
	"github.com/mnemonik-xyz/pocc/pkg/beacon"
	"github.com/mnemonik-xyz/pocc/pkg/pocc"
)

// VerifierVersion is written into every verdict.
const VerifierVersion = "pocc-verify/0.2.0"

// Statuses.
const (
	StatusValid         = "VALID"
	StatusValidWithGaps = "VALID_WITH_GAPS"
	StatusInvalid       = "INVALID"
)

// ForkChecker reports whether the log holds a different e for (agent, seq).
type ForkChecker interface {
	HasConflict(ctx context.Context, agentPub string, seq uint64, e string) (bool, error)
}

// Env holds the verifier's independent sources. None of them come from the receipt.
type Env struct {
	Beacon      beacon.Source  // the verifier's own beacon access
	Anchors     anchor.Checker // checks anchors and returns their time
	Forks       ForkChecker    // optional
	ProviderKey string         // optional pin; otherwise the order's key is used
}

type checker struct {
	codes []string
	seen  map[string]bool
}

func (c *checker) check(ok bool, code string) bool {
	if !ok && !c.seen[code] {
		c.seen[code] = true
		c.codes = append(c.codes, code)
	}
	return ok
}

// Verify checks a receipt and returns the verdict. It never stops at the first
// failure, so one verdict lists every failure code.
func Verify(ctx context.Context, R *pocc.Receipt, env Env) pocc.Verdict {
	c := &checker{seen: map[string]bool{}}
	q, o := R.Request, R.Order
	v := pocc.Verdict{Version: pocc.Version, VerifierVersion: VerifierVersion,
		PerHourS: map[string]int64{}, Codes: []string{}}
	if h, err := pocc.DocHash(pocc.TagReceipt, R); err == nil {
		v.ReceiptHash = pocc.Hex(h)
	}

	// Ordered.
	c.check(pocc.VerifyDoc(q.TenantPubKey, pocc.TagRequest, q, q.Sig) == nil, "E_REQUEST_SIG")
	providerKey := o.ProviderPubKey
	if env.ProviderKey != "" {
		c.check(env.ProviderKey == providerKey, "E_ORDER")
		providerKey = env.ProviderKey
	}
	reqHash, _ := pocc.DocHash(pocc.TagRequest, q)
	c.check(pocc.VerifyDoc(providerKey, pocc.TagOrder, o, o.Sig) == nil &&
		o.RequestHash == pocc.Hex(reqHash) && o.RateMicros <= q.MaxRateMicros &&
		o.Currency == q.Currency, "E_ORDER")
	c.check(checkPolicy(q, o) == nil, "E_POLICY")
	h0, _ := pocc.DocHash(pocc.TagOrder, o)
	info := o.Beacon
	slot := uint64(o.SlotRounds)
	if slot == 0 {
		slot = 20
	}

	// Genuine.
	b := R.Boot
	agentPub, err := pocc.DecodePub(b.AgentPubKey)
	c.check(err == nil, "E_BIND")
	r0, err := env.Beacon.Get(ctx, b.Round)
	c.check(err == nil && b.Randomness == pocc.Hex(r0.Randomness), "E_BEACON")
	gpuID := ""
	if b.GPU != nil {
		gpuID = b.GPU.DeviceID
	}
	e0 := pocc.BootE0(h0, b.ServerID, agentPub, gpuID, b.Round, pocc.MustUnhex(b.Randomness), b.SeedEnc)
	c.check(pocc.Hex(e0) == b.E0, "E_BIND")
	c.check(pocc.VerifyRaw(b.AgentPubKey, e0, b.Sig), "E_BIND")
	switch q.Attestation {
	case pocc.AttestationNone:
		v.Assurance = "L0"
		n := R.NovaServer
		c.check(b.Attestation == pocc.AttestationNone && n != nil && n.ID == b.ServerID &&
			n.Flavor == q.Resource.Flavor && n.ImageID == q.AllowedImage, "E_NOVA")
	case pocc.AttestationSEVSNP:
		v.Assurance = "L1"
		c.check(false, "E_SNP_UNSUPPORTED") // Stage 1 is not implemented in this PoC build
	default:
		c.check(false, "E_ORDER")
	}
	c.check(len(R.Proofs) == len(R.Heartbeats)+1, "E_LOG")
	bracket := o.BracketS
	if len(R.Proofs) > 0 {
		t, err := checkProof(ctx, env, R.Proofs[0], pocc.EntryLeaf(agentPub, 0, e0))
		c.check(err == nil, "E_LOG")
		if err == nil {
			d := t - beacon.Time(info, b.Round).Unix()
			c.check(d >= 0 && d <= bracket, "E_BRACKET")
		}
	}

	// Delivered.
	start, errS := time.Parse(time.RFC3339, q.Period.Start)
	end, errE := time.Parse(time.RFC3339, q.Period.End)
	c.check(errS == nil && errE == nil && start.Before(end), "E_REQUEST_SIG")
	prevE, prevR := e0, b.Round
	finalSeen := false
	var credited int64
	for i, hb := range R.Heartbeats {
		seq := uint64(i + 1)
		c.check(!finalSeen, "E_AFTER_FINAL")
		c.check(hb.Seq == seq, "E_SEQ")
		c.check(hb.Round > prevR && hb.Round%slot == 0, "E_SCHEDULE")
		rb, err := env.Beacon.Get(ctx, hb.Round)
		c.check(err == nil && hb.Randomness == pocc.Hex(rb.Randomness), "E_BEACON")
		e := pocc.HeartbeatE(prevE, hb.Seq, hb.Round, pocc.MustUnhex(hb.Randomness), pocc.MustUnhex(hb.UsageCommit), hb.Final)
		c.check(pocc.Hex(e) == hb.E && pocc.VerifyRaw(b.AgentPubKey, e, hb.Sig), "E_CHAIN")
		anchored := false
		if i+1 < len(R.Proofs) {
			t, err := checkProof(ctx, env, R.Proofs[i+1], pocc.EntryLeaf(agentPub, hb.Seq, e))
			if c.check(err == nil, "E_LOG") {
				d := t - beacon.Time(info, hb.Round).Unix()
				anchored = c.check(d >= 0 && d <= bracket, "E_BRACKET")
			}
		}
		if hb.Round == beacon.NextSlot(prevR, slot) && anchored {
			tEnd := beacon.Time(info, hb.Round)
			tStart := beacon.Time(info, prevR)
			if !tStart.Before(start) && !tEnd.After(end) {
				secs := int64(hb.Round-prevR) * info.PeriodS
				credited += secs
				v.PerHourS[tEnd.Truncate(time.Hour).Format(time.RFC3339)] += secs
			}
		} else if hb.Round != beacon.NextSlot(prevR, slot) {
			v.Gaps++
		}
		if hb.Final {
			finalSeen = true
		}
		prevE, prevR = e, hb.Round
	}
	if env.Forks != nil {
		bad := false
		for i, hb := range R.Heartbeats {
			if conflict, err := env.Forks.HasConflict(ctx, b.AgentPubKey, uint64(i+1), hb.E); err != nil || conflict {
				bad = true
			}
		}
		c.check(!bad, "E_FORK")
	}
	v.CreditedS = credited

	// Used: only what is opened.
	for _, op := range R.Openings {
		ok := op.Seq >= 1 && op.Seq <= uint64(len(R.Heartbeats)) &&
			pocc.VerifyOpening(op, pocc.MustUnhex(R.Heartbeats[op.Seq-1].UsageCommit))
		if c.check(ok, "E_OPENING") {
			if v.Disclosed == nil {
				v.Disclosed = map[string]uint64{}
			}
			v.Disclosed[fmt.Sprintf("%d/%s", op.Seq, op.Field)] = op.Value
		}
	}

	// Billed.
	c.check(R.Billed.Seconds <= credited, "E_OVERBILL")
	c.check(R.Billed.AmountMicros <= o.RateMicros*R.Billed.Seconds, "E_AMOUNT")
	c.check(pocc.VerifyDoc(providerKey, pocc.TagReceipt, R, R.Sig) == nil, "E_RECEIPT_SIG")

	v.MaxAmountMicros = o.RateMicros * credited
	v.Codes = c.codes
	switch {
	case len(c.codes) > 0:
		v.Status = StatusInvalid
	case v.Gaps > 0:
		v.Status = StatusValidWithGaps
	default:
		v.Status = StatusValid
	}
	return v
}

// checkPolicy compares the tenant-signed policy with the order and request.
func checkPolicy(q pocc.Request, o pocc.Order) error {
	p := q.Policy
	if p == nil {
		return fmt.Errorf("request carries no policy")
	}
	d := p.Delivery
	switch {
	case p.Case != "rent":
		return fmt.Errorf("policy case %q", p.Case)
	case d.Kind != pocc.DeliveryKindSignedUsage || d.MeterKey == "":
		return fmt.Errorf("delivery kind %q", d.Kind)
	case d.PoCC.Format != pocc.Version:
		return fmt.Errorf("delivery format %q", d.PoCC.Format)
	case d.PoCC.Attestation != q.Attestation:
		return fmt.Errorf("attestation differs")
	case d.PoCC.AllowedImage != q.AllowedImage || d.PoCC.AllowedMeasurement != q.AllowedMeasurement:
		return fmt.Errorf("image differs")
	case d.PoCC.Flavor != q.Resource.Flavor:
		return fmt.Errorf("flavor differs")
	case d.PoCC.BeaconChainHash != o.Beacon.ChainHash:
		return fmt.Errorf("beacon differs")
	case d.PoCC.SlotRounds != o.SlotRounds || d.PoCC.BracketS != o.BracketS:
		return fmt.Errorf("slot or bracket differs")
	case d.PricePerUnit != o.RateMicros:
		return fmt.Errorf("price differs")
	}
	return nil
}

func checkProof(ctx context.Context, env Env, p pocc.BatchProof, leaf []byte) (int64, error) {
	root := pocc.MustUnhex(p.Root)
	var path [][]byte
	for _, s := range p.Path {
		path = append(path, pocc.MustUnhex(s))
	}
	if err := pocc.VerifyInclusion(leaf, p.Index, p.TreeSize, path, root); err != nil {
		return 0, err
	}
	if env.Anchors == nil {
		return 0, fmt.Errorf("no anchor checker")
	}
	return env.Anchors.Check(ctx, p.Anchor, root)
}

// UsageRecords turns a verdict into one signed usage record per billing hour,
// for Warrant's signed_usage delivery check. An INVALID verdict yields none.
func UsageRecords(R *pocc.Receipt, v pocc.Verdict, sign func(any) (string, error)) ([]pocc.UsageRecord, error) {
	if v.Status == StatusInvalid || R.Request.Policy == nil {
		return nil, nil
	}
	ph, err := pocc.DocHash(pocc.TagPolicy, R.Request.Policy)
	if err != nil {
		return nil, err
	}
	hours := make([]string, 0, len(v.PerHourS))
	for h := range v.PerHourS {
		hours = append(hours, h)
	}
	sort.Strings(hours)
	var out []pocc.UsageRecord
	for _, h := range hours {
		t, err := time.Parse(time.RFC3339, h)
		if err != nil {
			return nil, err
		}
		s := v.PerHourS[h]
		rec := pocc.UsageRecord{Version: pocc.Version, Lease: R.Order.OrderID, PolicyHash: pocc.Hex(ph),
			WindowStart: t.Unix(), WindowEnd: t.Add(time.Hour).Unix(), Unit: R.Request.Policy.Delivery.Unit,
			Units: s, Assurance: v.Assurance, UptimeBP: s * 10000 / 3600, ReceiptHash: v.ReceiptHash}
		if rec.Sig, err = sign(rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}
