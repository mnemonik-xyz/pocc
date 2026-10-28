package pocc

// Version is the artifact format version written into every document.
const Version = "poc-0.2"

// Attestation kinds.
const (
	AttestationNone   = "none"    // Stage 0: no hardware report
	AttestationSEVSNP = "sev-snp" // Stage 1: AMD SEV-SNP report
)

// Usage field names, in commitment order. Values are cumulative since boot.
var UsageFields = []string{"cpu_ms", "gpu_busy_ms"}

// Resource is what the tenant orders.
type Resource struct {
	Flavor   string `json:"flavor"`
	VCPUs    int    `json:"vcpus"`
	RAMMB    int    `json:"ram_mb"`
	GPUModel string `json:"gpu_model,omitempty"`
	GPUCount int    `json:"gpu_count"`
}

// Period is the ordered delivery window, RFC 3339 UTC.
type Period struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// Request is step 1: what the tenant wants, signed by the tenant.
type Request struct {
	Version            string   `json:"pocc"`
	RequestID          string   `json:"request_id"`
	Resource           Resource `json:"resource"`
	Period             Period   `json:"period"`
	MaxRateMicros      int64    `json:"max_rate_micros_per_s"` // currency micro-units per second
	Currency           string   `json:"currency"`
	Attestation        string   `json:"attestation"`
	AllowedImage       string   `json:"allowed_image,omitempty"`       // Stage 0: Glance image ID
	AllowedMeasurement string   `json:"allowed_measurement,omitempty"` // Stage 1: SNP launch measurement
	TenantPubKey       string   `json:"tenant_pubkey"`                 // base64 Ed25519
	TenantSealKey      string      `json:"tenant_seal_key"`               // base64 X25519
	Policy             *RentPolicy `json:"policy,omitempty"`              // Warrant rent policy (spec 10)
	Sig                string      `json:"sig,omitempty"`
}

// BeaconInfo identifies the public randomness beacon.
type BeaconInfo struct {
	URL         string `json:"url"`
	ChainHash   string `json:"chain_hash"`
	PeriodS     int64  `json:"period_s"`
	GenesisTime int64  `json:"genesis_time"`
}

// NotaryInfo identifies the notary that batches and anchors heartbeats.
type NotaryInfo struct {
	URL       string `json:"url"`
	AnchorKey string `json:"anchor_key,omitempty"` // base64 Ed25519; dev file anchor only
}

// Order is step 2: the provider's acceptance of a request.
type Order struct {
	Version         string     `json:"pocc"`
	OrderID         string     `json:"order_id"`
	RequestHash     string     `json:"request_hash"`
	RateMicros      int64      `json:"rate_micros_per_s"`
	Currency        string     `json:"currency"`
	Beacon          BeaconInfo `json:"beacon"`
	Notary          NotaryInfo `json:"notary"`
	SlotRounds      int64      `json:"slot_rounds"` // 20 rounds of 3 s = 60 s
	BracketS        int64      `json:"bracket_s"`
	ProviderPubKey  string     `json:"provider_pubkey"`
	ProviderSealKey string     `json:"provider_seal_key"`
	Sig             string     `json:"sig,omitempty"`
}

// SealedBox is data encrypted to one X25519 recipient.
type SealedBox struct {
	Recipient  string `json:"recipient"` // base64 X25519 public key
	Ephemeral  string `json:"ephemeral"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// GPUEvidence is the Stage 1 GPU attestation.
type GPUEvidence struct {
	DeviceID  string `json:"device_id"`
	Model     string `json:"model"`
	NRASToken string `json:"nras_token"`
}

// BootProof is step 4: the start of delivery.
type BootProof struct {
	OrderHash   string       `json:"order_hash"`
	ServerID    string       `json:"server_id"`
	AgentPubKey string       `json:"agent_pubkey"` // base64 Ed25519
	Round       uint64       `json:"round"`
	Randomness  string       `json:"randomness"`
	SeedEnc     []SealedBox  `json:"seed_enc"`
	Attestation string       `json:"attestation"`
	SNPReport   string       `json:"snp_report,omitempty"`
	VCEKChain   []string     `json:"vcek_chain,omitempty"`
	GPU         *GPUEvidence `json:"gpu,omitempty"`
	E0          string       `json:"e0"`
	Sig         string       `json:"sig"` // agent signature over e0
}

// Heartbeat is step 5 (and step 6 when Final is set).
type Heartbeat struct {
	Seq         uint64 `json:"seq"`
	Round       uint64 `json:"round"`
	Randomness  string `json:"randomness"`
	UsageCommit string `json:"usage_commit"`
	Final       bool   `json:"final"`
	E           string `json:"e"`
	Sig         string `json:"sig"`
}

// Usage holds the cumulative counters committed in a heartbeat.
type Usage struct {
	CPUMs     uint64 `json:"cpu_ms"`
	GPUBusyMs uint64 `json:"gpu_busy_ms"`
}

// Get returns the value of a usage field by name.
func (u Usage) Get(field string) (uint64, bool) {
	switch field {
	case "cpu_ms":
		return u.CPUMs, true
	case "gpu_busy_ms":
		return u.GPUBusyMs, true
	}
	return 0, false
}

// Entry is what the agent submits to the notary: seq 0 carries the boot proof.
type Entry struct {
	AgentPubKey string     `json:"agent_pubkey"`
	Seq         uint64     `json:"seq"`
	E           string     `json:"e"`
	Sig         string     `json:"sig"`
	Boot        *BootProof `json:"boot,omitempty"`
	Heartbeat   *Heartbeat `json:"heartbeat,omitempty"`
	SealedUsage *SealedBox `json:"sealed_usage,omitempty"` // encrypted under a key derived from the seed
}

// AnchorRef points at the place a batch root was anchored.
type AnchorRef struct {
	Kind string `json:"kind"` // "dev-file" or "evm"
	Ref  string `json:"ref"`  // file line id or transaction hash
	Time int64  `json:"time"` // unix seconds: anchor block or file timestamp
	Sig  string `json:"sig,omitempty"`
}

// BatchProof proves one entry is in an anchored batch.
type BatchProof struct {
	BatchID  uint64    `json:"batch_id"`
	Slot     uint64    `json:"slot"`
	Root     string    `json:"root"`
	Index    uint64    `json:"index"`
	TreeSize uint64    `json:"tree_size"`
	Path     []string  `json:"path"`
	Anchor   AnchorRef `json:"anchor"`
}

// Opening discloses one committed usage value.
type Opening struct {
	Seq         uint64   `json:"seq"`
	Field       string   `json:"field"`
	Value       uint64   `json:"value"`
	Salt        string   `json:"salt"`
	OtherLeaves []string `json:"other_leaves"` // the other leaves, in UsageFields order
}

// NovaServer is the Stage 0 boot evidence read from the Nova API.
type NovaServer struct {
	ID      string `json:"id"`
	Flavor  string `json:"flavor"`
	ImageID string `json:"image_id"`
	Created string `json:"created"`
	Status  string `json:"status"`
}

// Billed is what the provider charges.
type Billed struct {
	Seconds      int64 `json:"seconds"`
	AmountMicros int64 `json:"amount_micros"`
}

// Receipt is step 7: everything the verifier needs, signed by the provider.
type Receipt struct {
	Version    string       `json:"pocc"`
	Request    Request      `json:"request"`
	Order      Order        `json:"order"`
	Boot       BootProof    `json:"boot"`
	Heartbeats []Heartbeat  `json:"heartbeats"`
	Proofs     []BatchProof `json:"proofs"` // proofs[0] for the boot entry, proofs[i] for heartbeat i
	Openings   []Opening    `json:"openings,omitempty"`
	NovaServer *NovaServer  `json:"nova_server,omitempty"`
	Billed     Billed       `json:"billed"`
	Sig        string       `json:"sig,omitempty"`
}

// Verdict is step 8: the verifier's result.
type Verdict struct {
	Version         string            `json:"pocc"`
	VerifierVersion string            `json:"verifier_version"`
	ReceiptHash     string            `json:"receipt_hash"`
	Status          string            `json:"status"`    // VALID, VALID_WITH_GAPS, INVALID
	Assurance       string            `json:"assurance"` // L0 (Stage 0) or L1 (Stage 1)
	Gaps            int               `json:"gaps"`
	CreditedS       int64             `json:"credited_s"`
	PerHourS        map[string]int64  `json:"per_hour_s"`
	MaxAmountMicros int64             `json:"max_amount_micros"`
	Disclosed       map[string]uint64 `json:"disclosed,omitempty"` // "seq/field" -> value
	Codes           []string          `json:"codes"`
}

// Settlement is step 9 outside Warrant: the tenant's signed decision.
type Settlement struct {
	Version     string   `json:"pocc"`
	ReceiptHash string   `json:"receipt_hash"`
	VerdictHash string   `json:"verdict_hash"`
	Decision    string   `json:"decision"` // accept or dispute
	Codes       []string `json:"codes,omitempty"`
	Sig         string   `json:"sig,omitempty"`
}
