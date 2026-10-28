package pocc

import "encoding/json"

// RentPolicy is the Warrant rent-case policy carried inside the Request
// (spec section 10). It follows the "one DSL shape" of Warrant's framework
// design: case, version, scope, validity, a mandatory delivery section, and a
// rule tree. PoCC reads the delivery section; Warrant's evaluator reads the rule.
type RentPolicy struct {
	Case     string          `json:"case"` // "rent"
	Version  int             `json:"version"`
	Scope    PolicyScope     `json:"scope"`
	Validity PolicyValidity  `json:"validity"`
	Delivery Delivery        `json:"delivery"`
	Rule     json.RawMessage `json:"rule"`
}

// PolicyScope fixes where payment happens.
type PolicyScope struct {
	ChainID string `json:"chain_id"`
	Vault   string `json:"vault"`
	Token   string `json:"token"`
}

// PolicyValidity is the window in which the policy authorizes payment.
type PolicyValidity struct {
	After int64 `json:"after"`
	Until int64 `json:"until"`
}

// Delivery is the mandatory delivery check. For PoCC it is "signed_usage":
// usage records signed by MeterKey, the tenant's own PoCC verifier key.
type Delivery struct {
	Kind         string       `json:"kind"`
	MeterKey     string       `json:"meter_key"`
	Unit         string       `json:"unit"`
	PricePerUnit int64        `json:"price_per_unit"`
	Tolerance    int64        `json:"tolerance"`
	PoCC         DeliveryPoCC `json:"pocc"`
}

// DeliveryPoCC says which PoCC proofs count. The verifier takes these values
// from the tenant-signed policy, never from the order or the receipt.
type DeliveryPoCC struct {
	Format             string `json:"format"`
	Attestation        string `json:"attestation"`
	AllowedImage       string `json:"allowed_image,omitempty"`
	AllowedMeasurement string `json:"allowed_measurement,omitempty"`
	Flavor             string `json:"flavor"`
	BeaconChainHash    string `json:"beacon_chain_hash"`
	SlotRounds         int64  `json:"slot_rounds"`
	BracketS           int64  `json:"bracket_s"`
	Anchor             string `json:"anchor"` // e.g. "dev-file" or "evm:<chain>/<contract>"
}

// DeliveryKindSignedUsage is the Warrant delivery kind PoCC serves.
const DeliveryKindSignedUsage = "signed_usage"

// UsageRecord is what the PoCC verifier signs per billing hour with the
// policy's meter key. Warrant's rent case consumes it as delivery evidence.
type UsageRecord struct {
	Version     string `json:"pocc"`
	Lease       string `json:"lease"` // order_id
	PolicyHash  string `json:"policy_hash"`
	WindowStart int64  `json:"window_start"`
	WindowEnd   int64  `json:"window_end"`
	Unit        string `json:"unit"`
	Units       int64  `json:"units"` // credited seconds in the window
	Assurance   string `json:"assurance"`
	UptimeBP    int64  `json:"uptime_bp"` // credited share of the window, basis points
	ReceiptHash string `json:"receipt_hash"`
	Sig         string `json:"sig,omitempty"`
}

// TagUsageRecord domain-separates usage record signatures.
const TagUsageRecord = "PoCC/poc/usage-record"

// TagPolicy domain-separates the policy hash.
const TagPolicy = "PoCC/poc/policy"
