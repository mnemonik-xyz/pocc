// Package sim runs the whole PoCC cycle in memory, on a simulated clock and a
// fake beacon, for the acceptance tests in the spec (section 8).
package sim

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/mnemonik-xyz/pocc/pkg/agent"
	"github.com/mnemonik-xyz/pocc/pkg/anchor"
	"github.com/mnemonik-xyz/pocc/pkg/beacon"
	"github.com/mnemonik-xyz/pocc/pkg/notary"
	"github.com/mnemonik-xyz/pocc/pkg/pocc"
	"github.com/mnemonik-xyz/pocc/pkg/receipt"
	"github.com/mnemonik-xyz/pocc/pkg/verify"
)

// Fixed sim parameters.
const (
	ServerID   = "0d6b2f4e-sim"
	Flavor     = "d2.cpu1ram1"
	ImageID    = "img-pocc-agent-sim"
	RateMicros = 1100 // 0.0011 currency units per second
	SlotRounds = 20
	BracketS   = 30
)

// World holds every party's keys and the shared services.
type World struct {
	Info        pocc.BeaconInfo
	Beacon      beacon.Fake
	TenantPriv  ed25519.PrivateKey
	TenantSeal  *ecdh.PrivateKey
	ProvPriv    ed25519.PrivateKey
	ProvSeal    *ecdh.PrivateKey
	AnchorPub   string
	MeterPriv   ed25519.PrivateKey
	Request     pocc.Request
	Order       pocc.Order
	Notary      *notary.Notary
	Clock       time.Time
	AnchorDelay func(slot uint64) time.Duration
	Slot0       uint64
}

// NewWorld creates parties, a signed request with its policy, and a signed order
// for a period of n slots starting at the first slot after start.
func NewWorld(n int, policyPrice int64) *World {
	w := &World{Info: beacon.Quicknet}
	w.Beacon = beacon.Fake{Info: w.Info}
	_, w.TenantPriv = pocc.GenerateSigningKey()
	_, w.ProvPriv = pocc.GenerateSigningKey()
	meterPub, meterPriv := pocc.GenerateSigningKey()
	w.MeterPriv = meterPriv
	w.TenantSeal, _ = pocc.GenerateSealKey()
	w.ProvSeal, _ = pocc.GenerateSealKey()
	anchorPub, anchorPriv := pocc.GenerateSigningKey()
	w.AnchorPub = pocc.B64.EncodeToString(anchorPub)

	start := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	w.Slot0 = beacon.NextSlot(beacon.RoundAt(w.Info, start), SlotRounds)
	r0 := w.Slot0 - 5
	periodStart := beacon.Time(w.Info, r0).Add(-time.Second)
	periodEnd := beacon.Time(w.Info, w.Slot0+uint64(n-1)*SlotRounds)

	w.Request = pocc.Request{
		Version: pocc.Version, RequestID: "req-sim-1",
		Resource:      pocc.Resource{Flavor: Flavor, VCPUs: 1, RAMMB: 1024},
		Period:        pocc.Period{Start: periodStart.Format(time.RFC3339), End: periodEnd.Format(time.RFC3339)},
		MaxRateMicros: 1200, Currency: "EUR", Attestation: pocc.AttestationNone, AllowedImage: ImageID,
		TenantPubKey:  pocc.B64.EncodeToString(w.TenantPriv.Public().(ed25519.PublicKey)),
		TenantSealKey: pocc.B64.EncodeToString(w.TenantSeal.PublicKey().Bytes()),
		Policy: &pocc.RentPolicy{
			Case: "rent", Version: 1,
			Scope:    pocc.PolicyScope{ChainID: "sim", Vault: "0xescrow", Token: "0xusdc"},
			Validity: pocc.PolicyValidity{After: periodStart.Unix(), Until: periodEnd.Add(7 * 24 * time.Hour).Unix()},
			Delivery: pocc.Delivery{
				Kind: pocc.DeliveryKindSignedUsage, MeterKey: pocc.B64.EncodeToString(meterPub),
				Unit: "instance-second", PricePerUnit: policyPrice,
				PoCC: pocc.DeliveryPoCC{Format: pocc.Version, Attestation: pocc.AttestationNone, AllowedImage: ImageID,
					Flavor: Flavor, BeaconChainHash: w.Info.ChainHash, SlotRounds: SlotRounds, BracketS: BracketS, Anchor: anchor.KindDevFile},
			},
			Rule: json.RawMessage(`{"all":[{"assurance_at_least":"L0"},{"uptime_at_least_bp":9500},{"amount_at_most":4000}]}`),
		},
	}
	w.Request.Sig, _ = pocc.SignDoc(w.TenantPriv, pocc.TagRequest, w.Request)
	w.Order = w.NewOrder("ord-sim-1")

	w.AnchorDelay = func(uint64) time.Duration { return 5 * time.Second }
	dev := &anchor.DevFile{Key: anchorPriv, Now: func() time.Time { return w.Clock }}
	w.Notary, _ = notary.New(w.Info, SlotRounds, dev, "")
	return w
}

// NewOrder signs an order for the world's request.
func (w *World) NewOrder(id string) pocc.Order {
	rh, _ := pocc.DocHash(pocc.TagRequest, w.Request)
	o := pocc.Order{Version: pocc.Version, OrderID: id, RequestHash: pocc.Hex(rh), RateMicros: RateMicros,
		Currency: "EUR", Beacon: w.Info, Notary: pocc.NotaryInfo{URL: "sim", AnchorKey: w.AnchorPub},
		SlotRounds: SlotRounds, BracketS: BracketS,
		ProviderPubKey:  pocc.B64.EncodeToString(w.ProvPriv.Public().(ed25519.PublicKey)),
		ProviderSealKey: pocc.B64.EncodeToString(w.ProvSeal.PublicKey().Bytes())}
	o.Sig, _ = pocc.SignDoc(w.ProvPriv, pocc.TagOrder, o)
	return o
}

type direct struct{ n *notary.Notary }

func (d direct) Submit(_ context.Context, e pocc.Entry) error { return d.n.Submit(e) }

type fakeCounters struct{ u pocc.Usage }

func (f *fakeCounters) Read() (pocc.Usage, error) {
	f.u.CPUMs += 30_000
	return f.u, nil
}

// Run boots an agent 15 s before the first slot and beats n slots. Slots for
// which skip returns true get no heartbeat (the agent is paused). The last
// slot carries the final heartbeat. It returns the agent's public key.
func (w *World) Run(n int, skip func(i int) bool) (string, error) {
	ctx := context.Background()
	a, err := agent.New(w.Request, w.Order, ServerID, w.Beacon, &fakeCounters{}, direct{w.Notary})
	if err != nil {
		return "", err
	}
	r0 := w.Slot0 - 5
	w.Clock = beacon.Time(w.Info, r0).Add(2 * time.Second)
	if _, err := a.Boot(ctx, r0); err != nil {
		return "", err
	}
	for i := 0; i < n; i++ {
		slot := w.Slot0 + uint64(i)*SlotRounds
		if skip == nil || !skip(i) {
			if _, err := a.Beat(ctx, slot, i == n-1); err != nil {
				return "", err
			}
		}
		w.Clock = beacon.Time(w.Info, slot).Add(w.AnchorDelay(slot))
		if err := w.Notary.CloseBatch(ctx, slot); err != nil {
			return "", err
		}
	}
	return a.AgentPubKey(), nil
}

// Receipt assembles a provider-signed receipt with the final usage disclosed.
func (w *World) Receipt(agentPub string, billedSeconds int64) (*pocc.Receipt, error) {
	entries := w.Notary.Entries(agentPub)
	last := entries[len(entries)-1].Seq
	ops, err := receipt.Disclose(entries, w.TenantSeal, []uint64{last}, pocc.UsageFields)
	if err != nil {
		return nil, err
	}
	nova := &pocc.NovaServer{ID: ServerID, Flavor: Flavor, ImageID: ImageID, Status: "ACTIVE"}
	billed := pocc.Billed{Seconds: billedSeconds, AmountMicros: billedSeconds * RateMicros}
	return receipt.Assemble(w.Request, w.Order, w.Notary, agentPub, nova, billed, ops, w.ProvPriv)
}

// Resign re-signs a tampered receipt with the provider key, as a cheating
// provider would.
func (w *World) Resign(R *pocc.Receipt) {
	R.Sig, _ = pocc.SignDoc(w.ProvPriv, pocc.TagReceipt, R)
}

// Verify runs the verifier with the world's independent sources.
func (w *World) Verify(R *pocc.Receipt) pocc.Verdict {
	return verify.Verify(context.Background(), R, verify.Env{
		Beacon: w.Beacon, Anchors: anchor.DevChecker{PubKey: w.AnchorPub}, Forks: w.Notary,
		ProviderKey: w.Order.ProviderPubKey,
	})
}

// Meter signs usage records with the meter key named in the policy.
func (w *World) Meter(R *pocc.Receipt, v pocc.Verdict) ([]pocc.UsageRecord, error) {
	return verify.UsageRecords(R, v, func(x any) (string, error) {
		return pocc.SignDoc(w.MeterPriv, pocc.TagUsageRecord, x)
	})
}
