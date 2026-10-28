// Package beacon reads the public randomness beacon (drand quicknet).
//
// The PoC does not verify drand's BLS signatures. Instead the verifier fetches
// every round it needs directly from drand (or several relays) and compares
// the values, so a party that invents a beacon value is caught by comparison.
package beacon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/mnemonik-xyz/pocc/pkg/pocc"
)

// Quicknet is drand's 3-second unchained network.
var Quicknet = pocc.BeaconInfo{
	URL:         "https://api.drand.sh",
	ChainHash:   "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
	PeriodS:     3,
	GenesisTime: 1692803367,
}

// Round is one beacon output.
type Round struct {
	Round      uint64
	Randomness []byte
}

// Source returns beacon rounds.
type Source interface {
	Get(ctx context.Context, round uint64) (Round, error)
}

// Time returns the publication time of a round.
func Time(info pocc.BeaconInfo, round uint64) time.Time {
	return time.Unix(info.GenesisTime+int64(round-1)*info.PeriodS, 0).UTC()
}

// RoundAt returns the latest round published at or before t.
func RoundAt(info pocc.BeaconInfo, t time.Time) uint64 {
	d := t.Unix() - info.GenesisTime
	if d < 0 {
		return 0
	}
	return uint64(d/info.PeriodS) + 1
}

// NextSlot returns the first slot round strictly after r. Slots are the
// rounds divisible by slotRounds and are shared by every VM.
func NextSlot(r uint64, slotRounds uint64) uint64 {
	return (r/slotRounds + 1) * slotRounds
}

// HTTP fetches rounds from a drand HTTP endpoint and caches them.
type HTTP struct {
	Info   pocc.BeaconInfo
	Client *http.Client
	mu     sync.Mutex
	cache  map[uint64]Round
}

// NewHTTP returns a drand HTTP client for info.
func NewHTTP(info pocc.BeaconInfo) *HTTP {
	return &HTTP{Info: info, Client: &http.Client{Timeout: 10 * time.Second}, cache: map[uint64]Round{}}
}

// Get fetches one round. It waits if the round is not yet published.
func (h *HTTP) Get(ctx context.Context, round uint64) (Round, error) {
	h.mu.Lock()
	if r, ok := h.cache[round]; ok {
		h.mu.Unlock()
		return r, nil
	}
	h.mu.Unlock()
	if wait := time.Until(Time(h.Info, round)); wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return Round{}, ctx.Err()
		}
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		r, err := h.fetch(ctx, round)
		if err == nil {
			h.mu.Lock()
			h.cache[round] = r
			h.mu.Unlock()
			return r, nil
		}
		lastErr = err
		select {
		case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
		case <-ctx.Done():
			return Round{}, ctx.Err()
		}
	}
	return Round{}, lastErr
}

func (h *HTTP) fetch(ctx context.Context, round uint64) (Round, error) {
	url := fmt.Sprintf("%s/%s/public/%d", h.Info.URL, h.Info.ChainHash, round)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := h.Client.Do(req)
	if err != nil {
		return Round{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Round{}, fmt.Errorf("drand round %d: HTTP %d", round, resp.StatusCode)
	}
	var body struct {
		Round      uint64 `json:"round"`
		Randomness string `json:"randomness"`
		Signature  string `json:"signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Round{}, err
	}
	rnd, err := hex.DecodeString(body.Randomness)
	if err != nil || body.Round != round {
		return Round{}, fmt.Errorf("drand round %d: malformed response", round)
	}
	sig, err := hex.DecodeString(body.Signature)
	if err != nil {
		return Round{}, fmt.Errorf("drand round %d: malformed signature", round)
	}
	// drand defines randomness as SHA-256 of the signature.
	if s := sha256.Sum256(sig); hex.EncodeToString(s[:]) != body.Randomness {
		return Round{}, fmt.Errorf("drand round %d: randomness does not match signature", round)
	}
	return Round{Round: round, Randomness: rnd}, nil
}

// Fake is a deterministic beacon for tests.
type Fake struct{ Info pocc.BeaconInfo }

// Get returns SHA-256("fake" ‖ round) as randomness.
func (f Fake) Get(_ context.Context, round uint64) (Round, error) {
	s := sha256.Sum256(append([]byte("fake-beacon"), pocc.U64(round)...))
	return Round{Round: round, Randomness: s[:]}, nil
}
