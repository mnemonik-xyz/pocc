// Package warrant is the only PoCC package that knows Warrant's shapes
// (decision 24). It validates the Warrant rent policy carried in a Request
// against PoCC's meter spec, and translates PoCC's per-hour usage records into
// Warrant's UsageRecord JSON (integration spec sections 4 and 7).
//
// PoCC never computes Warrant's hashes or signatures: policy_hash comes from
// `warrant-host hash`, and records are signed by `warrant-evidence sign-usage`,
// which this package can invoke as an external command.
package warrant

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mnemonik-xyz/pocc/pkg/pocc"
	"github.com/mnemonik-xyz/pocc/pkg/verify"
)

// Policy is Warrant's rent policy in its "one DSL shape". PoCC reads only the
// fields it needs and keeps the rest opaque.
type Policy struct {
	Case          string          `json:"case"`
	Version       int             `json:"version"`
	Scope         Scope           `json:"scope"`
	Validity      Validity        `json:"validity"`
	Customer      string          `json:"customer,omitempty"`
	RegistryKey   string          `json:"registry_key,omitempty"`
	AcceptanceKey string          `json:"acceptance_key,omitempty"`
	LeaseID       string          `json:"lease_id"`
	Ceiling       int64           `json:"ceiling"`
	MaxNote       int64           `json:"max_note"`
	BatchSize     int             `json:"batch_size"`
	Delivery      Delivery        `json:"delivery"`
	Rule          json.RawMessage `json:"rule"`
}

// Scope fixes where payment happens.
type Scope struct {
	ChainID uint64 `json:"chain_id"`
	Vault   string `json:"vault"`
	Token   string `json:"token"`
}

// Validity is the window in which the policy authorizes payment.
type Validity struct {
	After int64 `json:"after"`
	Until int64 `json:"until"`
}

// Delivery is Warrant's typed SignedUsage delivery section.
type Delivery struct {
	Kind         string `json:"kind"`
	MeterKey     string `json:"meter_key"`
	Unit         uint16 `json:"unit"`
	PricePerUnit int64  `json:"price_per_unit"`
	Tolerance    int64  `json:"tolerance"`
	MinUptimeBP  uint16 `json:"min_uptime_bp"`
	MinAssurance uint8  `json:"min_assurance"`
	MeterSpec    string `json:"meter_spec"`
}

// Delivery kinds and units.
const (
	KindSignedUsage    = "signed_usage"
	UnitInstanceSecond = 1
	UnitGPUSecond      = 2
)

// Check validates the policy inside a Request against PoCC's meter spec and
// returns the price per second it fixes. It is registered with the verifier
// under the consumer name "warrant".
func Check(q pocc.Request) (int64, error) {
	p, err := Parse(q.Policy)
	if err != nil {
		return 0, err
	}
	if q.MeterSpec == nil {
		return 0, errors.New("request has no meter spec")
	}
	ms, err := pocc.MeterSpecHash(*q.MeterSpec)
	if err != nil {
		return 0, err
	}
	d := p.Delivery
	switch {
	case p.Case != "rent":
		return 0, fmt.Errorf("policy case %q", p.Case)
	case d.Kind != KindSignedUsage || d.MeterKey == "":
		return 0, fmt.Errorf("delivery kind %q or missing meter key", d.Kind)
	case !sameHex(d.MeterSpec, ms):
		return 0, errors.New("policy meter_spec differs from the request's meter spec")
	case !sameHex(p.LeaseID, pocc.LeaseID(q)):
		return 0, errors.New("policy lease_id differs from the request's lease")
	case d.Unit != UnitInstanceSecond:
		return 0, fmt.Errorf("unit %d not supported by this verifier", d.Unit)
	case d.PricePerUnit <= 0 || d.PricePerUnit > q.MaxRateMicros:
		return 0, errors.New("price_per_unit is zero or above the request's maximum rate")
	case d.MinUptimeBP > 10000:
		return 0, errors.New("min_uptime_bp above 10000")
	case q.MeterSpec.Anchor.Kind == "evm" && (q.MeterSpec.Anchor.ChainID != p.Scope.ChainID):
		return 0, errors.New("anchor chain differs from the policy scope chain")
	}
	return d.PricePerUnit, nil
}

// Parse decodes a policy, requiring the fields PoCC reads.
func Parse(raw json.RawMessage) (Policy, error) {
	var p Policy
	if len(raw) == 0 {
		return p, errors.New("request carries no policy")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&p); err != nil {
		return p, fmt.Errorf("policy: %w", err)
	}
	return p, nil
}

func sameHex(s string, b []byte) bool {
	got, err := pocc.Unhex0x("hex", s)
	return err == nil && bytes.Equal(got, b)
}

func init() { verify.RegisterConsumer(pocc.ConsumerWarrant, Check) }

// Bytes32 and Bytes20 serialize as JSON arrays of integers, matching Warrant's
// Rust input schema ("arrays of 20/32 bytes").
type Bytes32 [32]byte

// Bytes20 is an EVM address.
type Bytes20 [20]byte

// MarshalJSON encodes as an array of integers, as serde does for [u8; N].
func (b Bytes32) MarshalJSON() ([]byte, error) { return json.Marshal(ints(b[:])) }

// MarshalJSON encodes as an array of integers, as serde does for [u8; N].
func (b Bytes20) MarshalJSON() ([]byte, error) { return json.Marshal(ints(b[:])) }

func ints(b []byte) []int {
	out := make([]int, len(b))
	for i, x := range b {
		out[i] = int(x)
	}
	return out
}

// UsageRecord mirrors core/src/meter.rs UsageRecord (integration spec 7).
type UsageRecord struct {
	Scope           RecordScope `json:"scope"`
	LeaseID         Bytes32     `json:"lease_id"`
	FirstIndex      uint32      `json:"first_index"`
	LastIndex       uint32      `json:"last_index"`
	WindowStart     uint64      `json:"window_start"`
	WindowEnd       uint64      `json:"window_end"`
	Units           uint64      `json:"units"`
	Assurance       uint8       `json:"assurance"`
	MeterSpec       Bytes32     `json:"meter_spec"`
	DeliverableHash Bytes32     `json:"deliverable_hash"`
}

// RecordScope is Warrant's Scope with byte-array addresses.
type RecordScope struct {
	ChainID uint64  `json:"chain_id"`
	Vault   Bytes20 `json:"vault"`
	Token   Bytes20 `json:"token"`
}

// Records translates PoCC's per-hour records into Warrant's shape, using the
// policy's scope. Hour k maps to note index k.
func Records(q pocc.Request, recs []pocc.UsageRecord) ([]UsageRecord, error) {
	p, err := Parse(q.Policy)
	if err != nil {
		return nil, err
	}
	var vault, token Bytes20
	if err := fill20(&vault, p.Scope.Vault); err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	if err := fill20(&token, p.Scope.Token); err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	out := make([]UsageRecord, 0, len(recs))
	for _, r := range recs {
		var w UsageRecord
		w.Scope = RecordScope{ChainID: p.Scope.ChainID, Vault: vault, Token: token}
		if err := fill32(&w.LeaseID, r.Lease); err != nil {
			return nil, fmt.Errorf("lease: %w", err)
		}
		if err := fill32(&w.MeterSpec, r.MeterSpec); err != nil {
			return nil, fmt.Errorf("meter_spec: %w", err)
		}
		if err := fill32(&w.DeliverableHash, r.ReceiptHash); err != nil {
			return nil, fmt.Errorf("receipt_hash: %w", err)
		}
		if r.Hour < 0 {
			return nil, fmt.Errorf("hour %d before the period start", r.Hour)
		}
		w.FirstIndex, w.LastIndex = uint32(r.Hour), uint32(r.Hour)
		w.WindowStart, w.WindowEnd = uint64(r.WindowStart), uint64(r.WindowEnd)
		w.Units = uint64(r.Units)
		if r.Assurance == "L1" {
			w.Assurance = 1
		}
		out = append(out, w)
	}
	return out, nil
}

func fill32(dst *Bytes32, s string) error {
	b, err := pocc.Unhex0x("hex", s)
	if err != nil || len(b) != 32 {
		return errors.New("need 32 bytes of hex")
	}
	copy(dst[:], b)
	return nil
}

func fill20(dst *Bytes20, s string) error {
	b, err := pocc.Unhex0x("hex", s)
	if err != nil || len(b) != 20 {
		return errors.New("need a 20-byte address")
	}
	copy(dst[:], b)
	return nil
}

// Signed pairs a record file with its signature file, as warrant-evidence writes them.
type Signed struct {
	Record    string `json:"record"`    // path of the record JSON
	Signature string `json:"signature"` // path of the signature JSON
}

// SignExternal writes each record to dir and runs the signer command for it.
// cmd is a template such as "warrant-evidence sign-usage {key} {in} {out}";
// {key} is replaced by keyPath. Warrant signs; PoCC only invokes.
func SignExternal(dir, cmd, keyPath string, recs []UsageRecord) ([]Signed, error) {
	if !strings.Contains(cmd, "{in}") || !strings.Contains(cmd, "{out}") {
		return nil, errors.New("signer command must contain {in} and {out}")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var out []Signed
	for _, r := range recs {
		in := filepath.Join(dir, fmt.Sprintf("usage-%d.json", r.FirstIndex))
		sig := filepath.Join(dir, fmt.Sprintf("usage-%d.sig.json", r.FirstIndex))
		b, _ := json.MarshalIndent(r, "", "  ")
		if err := os.WriteFile(in, append(b, '\n'), 0o644); err != nil {
			return nil, err
		}
		line := strings.NewReplacer("{key}", keyPath, "{in}", in, "{out}", sig).Replace(cmd)
		parts := strings.Fields(line)
		c := exec.Command(parts[0], parts[1:]...)
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return nil, fmt.Errorf("signer for hour %d: %w", r.FirstIndex, err)
		}
		out = append(out, Signed{Record: in, Signature: sig})
	}
	return out, nil
}

// HexHash formats a hash for the policy's meter_spec field.
func HexHash(b []byte) string { return hex.EncodeToString(b) }
