package pocc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mnemonik-xyz/pocc/internal/canon"
)

// MeterSpec is PoCC's own parameter document: which proofs count. A consumer
// such as Warrant pins its hash (meter_spec) in its policy and never learns the
// fields. It is mandatory in the Request (decision 30): the verifier takes
// these values from the tenant-signed Request and from nowhere else, so the
// proof of delivery is fixed before anything runs.
type MeterSpec struct {
	Format             string     `json:"format"`
	Attestation        string     `json:"attestation"`
	AllowedImage       string     `json:"allowed_image,omitempty"`
	AllowedMeasurement string     `json:"allowed_measurement,omitempty"`
	Flavor             string     `json:"flavor"`
	BeaconChainHash    string     `json:"beacon_chain_hash"`
	SlotRounds         int64      `json:"slot_rounds"`
	BracketS           int64      `json:"bracket_s"`
	Anchor             AnchorSpec `json:"anchor"`
	NotaryURL          string     `json:"notary_url,omitempty"`
}

// AnchorSpec pins where batch roots must be anchored.
type AnchorSpec struct {
	Kind          string `json:"kind"`                    // "dev-file" or "evm"
	ChainID       uint64 `json:"chain_id,omitempty"`      // evm
	Contract      string `json:"contract,omitempty"`      // evm: PoccAnchor address
	Confirmations int    `json:"confirmations,omitempty"` // evm
	AnchorKey     string `json:"anchor_key,omitempty"`    // dev-file: the notary's signing key
}

// Domain tags for the integration constructions.
const (
	TagMeterSpec = "PoCC/poc/meter-spec"
	TagLease     = "PoCC/poc/lease"
)

// MeterSpecHash is H(meter-spec ‖ JCS(spec)); a consumer pins it as meter_spec.
func MeterSpecHash(m MeterSpec) ([]byte, error) {
	c, err := canon.Marshal(m)
	if err != nil {
		return nil, err
	}
	return H(TagMeterSpec, c), nil
}

// LeaseID identifies the deal across PoCC, the consumer's policy and the
// escrow (poId). It is derived from request fields that do not include the
// policy, because the policy itself carries the lease id:
//
//	lease_id = H(lease ‖ tenant_pubkey ‖ request_id ‖ period.start ‖ period.end)
func LeaseID(q Request) []byte {
	return H(TagLease, []byte(q.TenantPubKey), []byte(q.RequestID), []byte(q.Period.Start), []byte(q.Period.End))
}

// EscrowOrder names the consumer's on-chain order that pays for this lease.
// The escrow order is the order (decision 23): the provider's acceptance is
// accept(orderId) on the escrow, and h0 is derived from these values.
type EscrowOrder struct {
	ChainID uint64 `json:"chain_id"`
	Escrow  string `json:"escrow"`   // contract address, 0x-hex
	OrderID string `json:"order_id"` // 32-byte order id, 0x-hex or hex
}

// EscrowH0 is the boot binding:
//
//	h0 = H(order ‖ policy_hash ‖ lease_id ‖ chain_id ‖ escrow ‖ orderId)
func EscrowH0(policyHash, leaseID []byte, chainID uint64, escrow, orderID []byte) []byte {
	return H(TagOrder, policyHash, leaseID, U64(chainID), escrow, orderID)
}

// Unhex0x decodes hex with or without a 0x prefix.
func Unhex0x(field, s string) ([]byte, error) {
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	return Unhex(field, s)
}

// Consumer names. A Request carries its consumer's policy; the consumer's
// adapter checks it (decision 24).
const ConsumerWarrant = "warrant"

// Binding is everything the agent needs to bind to a deal: the boot binding
// h0 and the timing and notary settings. It comes from the EscrowOrder plus
// the Request's MeterSpec.
type Binding struct {
	H0         []byte
	SlotRounds uint64
	BracketS   int64
	Beacon     BeaconInfo
	NotaryURL  string
}

// EscrowBinding derives the binding from the escrow order and the Request's
// policy hash and meter spec. knownBeacons maps a chain hash to its BeaconInfo.
func EscrowBinding(q Request, e EscrowOrder, knownBeacons map[string]BeaconInfo) (Binding, error) {
	if err := CheckMeterSpec(q); err != nil {
		return Binding{}, err
	}
	if q.PolicyHash == "" {
		return Binding{}, fmt.Errorf("request has no policy hash")
	}
	ph, err := Unhex0x("policy_hash", q.PolicyHash)
	if err != nil {
		return Binding{}, err
	}
	esc, err := Unhex0x("escrow", e.Escrow)
	if err != nil {
		return Binding{}, err
	}
	oid, err := Unhex0x("order_id", e.OrderID)
	if err != nil {
		return Binding{}, err
	}
	if len(ph) != 32 || len(oid) != 32 || len(esc) != 20 || e.ChainID == 0 {
		return Binding{}, fmt.Errorf("escrow order fields have wrong sizes")
	}
	info, ok := knownBeacons[q.MeterSpec.BeaconChainHash]
	if !ok {
		return Binding{}, fmt.Errorf("unknown beacon chain %s", q.MeterSpec.BeaconChainHash)
	}
	m := q.MeterSpec
	return Binding{H0: EscrowH0(ph, LeaseID(q), e.ChainID, esc, oid), SlotRounds: uint64(m.SlotRounds),
		BracketS: m.BracketS, Beacon: info, NotaryURL: m.NotaryURL}, nil
}

// CheckMeterSpec compares the meter spec with the rest of the request. It is
// consumer-agnostic; a consumer's own policy checks live in its adapter.
func CheckMeterSpec(q Request) error {
	m := q.MeterSpec
	switch {
	case m.Format != Version:
		return fmt.Errorf("meter spec format %q", m.Format)
	case m.Attestation != q.Attestation:
		return fmt.Errorf("attestation differs from the request")
	case m.AllowedImage != q.AllowedImage || m.AllowedMeasurement != q.AllowedMeasurement:
		return fmt.Errorf("image differs from the request")
	case m.Flavor != q.Resource.Flavor:
		return fmt.Errorf("flavor differs from the request")
	case m.SlotRounds <= 0 || m.BracketS <= 0:
		return fmt.Errorf("slot or bracket not positive")
	case m.Anchor.Kind == "":
		return fmt.Errorf("anchor kind missing")
	}
	return nil
}

// HourAligned reports whether the period starts on a clock hour (decision 19).
func HourAligned(p Period) bool {
	t, err := time.Parse(time.RFC3339, p.Start)
	return err == nil && t.Unix()%3600 == 0
}

// RawPolicy is the consumer's policy as the owner approved it. PoCC keeps the
// bytes and never recomputes the consumer's hash.
type RawPolicy = json.RawMessage

// UsageRecord is PoCC's own per-hour delivery statement (consumer-agnostic).
// Adapters translate it into a consumer's record format.
type UsageRecord struct {
	Version     string `json:"pocc"`
	Lease       string `json:"lease"` // lease_id, hex
	Hour        int64  `json:"hour"`  // index from the period start
	WindowStart int64  `json:"window_start"`
	WindowEnd   int64  `json:"window_end"`
	Unit        string `json:"unit"`
	Units       int64  `json:"units"`      // credited seconds in the window
	Creditable  int64  `json:"creditable"` // the most seconds the window can earn under the slot schedule
	Assurance   string `json:"assurance"`
	UptimeBP    int64  `json:"uptime_bp"`  // units x 10000 / creditable
	MeterSpec   string `json:"meter_spec"` // hex
	ReceiptHash string `json:"receipt_hash"`
	Sig         string `json:"sig,omitempty"` // PoCC-native Ed25519, optional
}

// TagUsageRecord domain-separates PoCC-native usage record signatures.
const TagUsageRecord = "PoCC/poc/usage-record"
