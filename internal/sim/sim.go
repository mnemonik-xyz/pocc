// Package sim runs the whole PoCC cycle in memory, on a simulated clock and a
// fake beacon, for the acceptance tests in the spec (section 8).
package sim

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/mnemonik-xyz/pocc/pkg/adapter/warrant"
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
	Escrow      *pocc.EscrowOrder // set by NewEscrowWorld
	MeterSpec   pocc.MeterSpec
}

// Escrow constants for the simulated Warrant deal.
const (
	EscrowChainID  = 5042002
	EscrowAddr     = "0x1111111111111111111111111111111111111111"
	TokenAddr      = "0x3600000000000000000000000000000000000000"
	EscrowOrderID  = "0x2222222222222222222222222222222222222222222222222222222222222222"
	FakePolicyHash = "0x3333333333333333333333333333333333333333333333333333333333333333"
)

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
	bootSlot := beacon.NextSlot(beacon.RoundAt(w.Info, start), SlotRounds) // first slot after 09:00
	w.Slot0 = bootSlot + SlotRounds                                        // first heartbeat slot
	periodStart := start                                                   // on the clock hour (decision 19)
	periodEnd := beacon.Time(w.Info, w.Slot0+uint64(n-1)*SlotRounds).Add(time.Hour).Truncate(time.Hour)

	w.MeterSpec = pocc.MeterSpec{Format: pocc.Version, Attestation: pocc.AttestationNone, AllowedImage: ImageID,
		Flavor: Flavor, BeaconChainHash: w.Info.ChainHash, SlotRounds: SlotRounds, BracketS: BracketS,
		Anchor: pocc.AnchorSpec{Kind: anchor.KindDevFile, AnchorKey: w.AnchorPub}, NotaryURL: "sim"}
	w.Request = pocc.Request{
		Version: pocc.Version, RequestID: "req-sim-1",
		Resource:      pocc.Resource{Flavor: Flavor, VCPUs: 1, RAMMB: 1024},
		Period:        pocc.Period{Start: periodStart.Format(time.RFC3339), End: periodEnd.Format(time.RFC3339)},
		MaxRateMicros: 1200, Currency: "EUR", Attestation: pocc.AttestationNone, AllowedImage: ImageID,
		TenantPubKey:  pocc.B64.EncodeToString(w.TenantPriv.Public().(ed25519.PublicKey)),
		TenantSealKey: pocc.B64.EncodeToString(w.TenantSeal.PublicKey().Bytes()),
		MeterSpec:     &w.MeterSpec,
	}
	_ = policyPrice
	_ = meterPub
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

// NewEscrowWorld is NewWorld in escrow mode: the request carries a Warrant
// rent policy and the deal is bound to a (simulated) escrow order. There is no
// provider-signed Order.
func NewEscrowWorld(n int, policyPrice int64) *World {
	w := NewWorld(n, policyPrice)
	ms, _ := pocc.MeterSpecHash(w.MeterSpec)
	meterPub := w.MeterPriv.Public().(ed25519.PublicKey)
	w.Request.Sig = ""
	w.Request.Consumer = pocc.ConsumerWarrant
	w.Request.PolicyHash = FakePolicyHash
	w.Request.Policy = WarrantPolicy(w.Request, pocc.B64.EncodeToString(meterPub), policyPrice, pocc.Hex(ms))
	w.Request.Sig, _ = pocc.SignDoc(w.TenantPriv, pocc.TagRequest, w.Request)
	w.Escrow = &pocc.EscrowOrder{ChainID: EscrowChainID, Escrow: EscrowAddr, OrderID: EscrowOrderID}
	return w
}

// WarrantPolicy builds the rent policy of integration spec section 4 for a request.
func WarrantPolicy(q pocc.Request, meterKey string, price int64, meterSpecHex string) json.RawMessage {
	ps, _ := time.Parse(time.RFC3339, q.Period.Start)
	pe, _ := time.Parse(time.RFC3339, q.Period.End)
	p := warrant.Policy{Case: "rent", Version: 1,
		Scope:    warrant.Scope{ChainID: EscrowChainID, Vault: EscrowAddr, Token: TokenAddr},
		Validity: warrant.Validity{After: ps.Unix(), Until: pe.Add(7 * 24 * time.Hour).Unix()},
		LeaseID:  pocc.Hex(pocc.LeaseID(q)), Ceiling: 50_000_000, MaxNote: 4_000_000, BatchSize: 24,
		Delivery: warrant.Delivery{Kind: warrant.KindSignedUsage, MeterKey: meterKey, Unit: warrant.UnitInstanceSecond,
			PricePerUnit: price, MinUptimeBP: 9500, MeterSpec: meterSpecHex},
		Rule: json.RawMessage(`{"all":["accepted",{"amount_at_most":4000000}]}`)}
	b, _ := json.Marshal(p)
	return b
}

type direct struct{ n *notary.Notary }

func (d direct) Submit(_ context.Context, e pocc.Entry) error { return d.n.Submit(e) }

type fakeCounters struct{ u pocc.Usage }

func (f *fakeCounters) Read() (pocc.Usage, error) {
	f.u.CPUMs += 30_000
	return f.u, nil
}

// Run boots an agent on the slot before the first slot and beats n slots. Slots for
// which skip returns true get no heartbeat (the agent is paused). The last
// slot carries the final heartbeat. It returns the agent's public key.
func (w *World) Run(n int, skip func(i int) bool) (string, error) {
	ctx := context.Background()
	bind, err := w.binding()
	if err != nil {
		return "", err
	}
	a, err := agent.New(w.Request, bind, ServerID, w.Beacon, &fakeCounters{}, direct{w.Notary})
	if err != nil {
		return "", err
	}
	a.ProviderSealKey = w.Order.ProviderSealKey
	r0 := w.Slot0 - SlotRounds
	w.Clock = beacon.Time(w.Info, r0).Add(w.AnchorDelay(r0))
	if _, err := a.Boot(ctx, r0); err != nil {
		return "", err
	}
	if err := w.Notary.CloseBatch(ctx, r0); err != nil {
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

func (w *World) binding() (pocc.Binding, error) {
	if w.Escrow != nil {
		return pocc.EscrowBinding(w.Request, *w.Escrow, map[string]pocc.BeaconInfo{w.Info.ChainHash: w.Info})
	}
	return pocc.OfflineBinding(w.Request, w.Order)
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
	R, err := receipt.Assemble(w.Request, w.Order, w.Notary, agentPub, nova, billed, ops, w.ProvPriv)
	if err != nil {
		return nil, err
	}
	if w.Escrow != nil {
		R.Order = pocc.Order{}
		R.EscrowOrder = w.Escrow
		w.Resign(R)
	}
	return R, nil
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

// Meter signs PoCC-native usage records with the meter key.
func (w *World) Meter(R *pocc.Receipt, v pocc.Verdict) ([]pocc.UsageRecord, error) {
	return verify.UsageRecords(R, v, func(x any) (string, error) {
		return pocc.SignDoc(w.MeterPriv, pocc.TagUsageRecord, x)
	})
}
