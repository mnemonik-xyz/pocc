// Package verify implements the PoCC verifier (spec section 5) in two modes:
// offline (a provider-signed Order) and escrow (the consumer's escrow order is
// the order and h0 derives from it, integration spec section 5). It also turns
// a verdict into PoCC-native per-hour usage records; consumer adapters
// translate those.
package verify

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/mnemonik-xyz/pocc/pkg/anchor"
	"github.com/mnemonik-xyz/pocc/pkg/beacon"
	"github.com/mnemonik-xyz/pocc/pkg/pocc"
)

// VerifierVersion is written into every verdict.
const VerifierVersion = "pocc-verify/0.3.0"

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
	ProviderKey string         // optional pin; otherwise the order's key is used (offline mode)
	// KnownBeacons maps a beacon chain hash to its info (escrow mode). Default: drand quicknet.
	KnownBeacons map[string]pocc.BeaconInfo
}

// ConsumerCheck validates a consumer's policy inside a Request and returns the
// price per second it fixes. Adapters register one per consumer name.
type ConsumerCheck func(q pocc.Request) (rateMicros int64, err error)

var (
	consumersMu sync.RWMutex
	consumers   = map[string]ConsumerCheck{}
)

// RegisterConsumer makes a consumer's policy check available to the verifier.
func RegisterConsumer(name string, check ConsumerCheck) {
	consumersMu.Lock()
	defer consumersMu.Unlock()
	consumers[name] = check
}

func consumerCheck(name string) (ConsumerCheck, bool) {
	consumersMu.RLock()
	defer consumersMu.RUnlock()
	c, ok := consumers[name]
	return c, ok
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
	q := R.Request
	v := pocc.Verdict{Version: pocc.Version, VerifierVersion: VerifierVersion,
		PerHourS: map[string]int64{}, Codes: []string{}}
	if h, err := pocc.DocHash(pocc.TagReceipt, R); err == nil {
		v.ReceiptHash = pocc.Hex(h)
	}

	// Ordered.
	c.check(pocc.VerifyDoc(q.TenantPubKey, pocc.TagRequest, q, q.Sig) == nil, "E_REQUEST_SIG")
	var (
		h0         []byte
		info       pocc.BeaconInfo
		slot       uint64
		bracket    int64
		rate       int64
		escrowMode = R.EscrowOrder != nil
		signerKey  string // who signs the receipt, if anyone
	)
	if escrowMode {
		// Escrow mode: the consumer's escrow order is the order (decision 23).
		known := env.KnownBeacons
		if known == nil {
			known = map[string]pocc.BeaconInfo{beacon.Quicknet.ChainHash: beacon.Quicknet}
		}
		c.check(pocc.CheckMeterSpec(q) == nil, "E_POLICY")
		c.check(pocc.HourAligned(q.Period), "E_PERIOD")
		rate = q.MaxRateMicros
		if chk, ok := consumerCheck(q.Consumer); c.check(ok, "E_CONSUMER") {
			r, err := chk(q)
			if c.check(err == nil, "E_POLICY") {
				rate = r
			}
		}
		b, err := pocc.EscrowBinding(q, *R.EscrowOrder, known)
		if c.check(err == nil, "E_BIND") {
			h0, info, slot, bracket = b.H0, b.Beacon, b.SlotRounds, b.BracketS
		} else {
			info, slot, bracket = beacon.Quicknet, 20, 30
		}
		signerKey = env.ProviderKey
	} else {
		o := R.Order
		signerKey = o.ProviderPubKey
		if env.ProviderKey != "" {
			c.check(env.ProviderKey == signerKey, "E_ORDER")
			signerKey = env.ProviderKey
		}
		reqHash, _ := pocc.DocHash(pocc.TagRequest, q)
		c.check(pocc.VerifyDoc(signerKey, pocc.TagOrder, o, o.Sig) == nil &&
			o.RequestHash == pocc.Hex(reqHash) && o.RateMicros <= q.MaxRateMicros &&
			o.Currency == q.Currency, "E_ORDER")
		if q.MeterSpec != nil {
			c.check(pocc.CheckMeterSpec(q) == nil && q.MeterSpec.BeaconChainHash == o.Beacon.ChainHash &&
				q.MeterSpec.SlotRounds == o.SlotRounds && q.MeterSpec.BracketS == o.BracketS, "E_POLICY")
		}
		h0, _ = pocc.DocHash(pocc.TagOrder, o)
		info, slot, bracket, rate = o.Beacon, uint64(o.SlotRounds), o.BracketS, o.RateMicros
		if slot == 0 {
			slot = 20
		}
	}

	// Genuine.
	b := R.Boot
	agentPub, err := pocc.DecodePub(b.AgentPubKey)
	c.check(err == nil, "E_BIND")
	c.check(b.Round%slot == 0, "E_SCHEDULE")
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
	// timely reports whether an entry was anchored within the bracket after its
	// round. A late entry earns no credit; an anchor before its round is fatal.
	timely := func(p pocc.BatchProof, leaf []byte, round uint64) bool {
		t, err := checkProof(ctx, env, p, leaf)
		if !c.check(err == nil, "E_LOG") {
			return false
		}
		d := t - beacon.Time(info, round).Unix()
		c.check(d >= 0, "E_ANCHOR_TIME")
		if d > bracket {
			v.Late++
			return false
		}
		return d >= 0
	}
	prevTimely := false
	if len(R.Proofs) > 0 {
		prevTimely = timely(R.Proofs[0], pocc.EntryLeaf(agentPub, 0, e0), b.Round)
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
			anchored = timely(R.Proofs[i+1], pocc.EntryLeaf(agentPub, hb.Seq, e), hb.Round)
		}
		// Credit needs both ends of the interval anchored in time.
		if hb.Round == beacon.NextSlot(prevR, slot) && anchored && prevTimely {
			tEnd := beacon.Time(info, hb.Round)
			tStart := beacon.Time(info, prevR)
			if !tStart.Before(start) && !tEnd.After(end) {
				secs := int64(hb.Round-prevR) * info.PeriodS
				credited += secs
				v.PerHourS[tEnd.Add(-time.Second).Truncate(time.Hour).Format(time.RFC3339)] += secs
			}
		} else if hb.Round != beacon.NextSlot(prevR, slot) {
			v.Gaps++
		}
		if hb.Final {
			finalSeen = true
		}
		prevE, prevR, prevTimely = e, hb.Round, anchored
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

	// Billed. In escrow mode billing happens through the consumer's notes; the
	// receipt's billed fields and signature are checked only when present.
	if !escrowMode || R.Billed.Seconds != 0 || R.Billed.AmountMicros != 0 || R.Sig != "" {
		c.check(R.Billed.Seconds <= credited, "E_OVERBILL")
		c.check(R.Billed.AmountMicros <= rate*R.Billed.Seconds, "E_AMOUNT")
		c.check(signerKey != "" && pocc.VerifyDoc(signerKey, pocc.TagReceipt, R, R.Sig) == nil, "E_RECEIPT_SIG")
	}

	v.MaxAmountMicros = rate * credited
	v.Codes = c.codes
	if v.Codes == nil {
		v.Codes = []string{}
	}
	switch {
	case len(c.codes) > 0:
		v.Status = StatusInvalid
	case v.Gaps > 0 || v.Late > 0:
		v.Status = StatusValidWithGaps
	default:
		v.Status = StatusValid
	}
	return v
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

// UsageRecords turns a verdict into one PoCC-native usage record per billing
// hour. sign may be nil (unsigned records for an adapter to translate). An
// INVALID verdict yields none. Hour indices count from the period start.
func UsageRecords(R *pocc.Receipt, v pocc.Verdict, sign func(any) (string, error)) ([]pocc.UsageRecord, error) {
	if v.Status == StatusInvalid {
		return nil, nil
	}
	start, err := time.Parse(time.RFC3339, R.Request.Period.Start)
	if err != nil {
		return nil, err
	}
	meterSpec := ""
	if R.Request.MeterSpec != nil {
		h, err := pocc.MeterSpecHash(*R.Request.MeterSpec)
		if err != nil {
			return nil, err
		}
		meterSpec = pocc.Hex(h)
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
		rec := pocc.UsageRecord{Version: pocc.Version, Lease: pocc.Hex(pocc.LeaseID(R.Request)),
			Hour: int64(t.Sub(start) / time.Hour), WindowStart: t.Unix(), WindowEnd: t.Add(time.Hour).Unix(),
			Unit: "instance-second", Units: s, Assurance: v.Assurance, UptimeBP: s * 10000 / 3600,
			MeterSpec: meterSpec, ReceiptHash: v.ReceiptHash}
		if sign != nil {
			if rec.Sig, err = sign(rec); err != nil {
				return nil, err
			}
		}
		out = append(out, rec)
	}
	return out, nil
}
