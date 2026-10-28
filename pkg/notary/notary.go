// Package notary accepts agent entries, batches them once per slot into a
// Merkle tree, anchors the root, and serves inclusion proofs (spec 3, 7).
//
// One root per slot covers every VM, so the anchoring cost does not grow with
// the number of VMs.
package notary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/mnemonik-xyz/pocc/pkg/anchor"
	"github.com/mnemonik-xyz/pocc/pkg/beacon"
	"github.com/mnemonik-xyz/pocc/pkg/pocc"
)

// ErrFork is returned when an agent submits a different e for a known seq.
var ErrFork = errors.New("fork: a different entry exists for this agent and seq")

type pendingLeaf struct {
	Agent string
	Seq   uint64
	Leaf  []byte
}

type state struct {
	Entries   map[string]map[uint64]pocc.Entry      `json:"entries"`
	Proofs    map[string]map[uint64]pocc.BatchProof `json:"proofs"`
	NextBatch uint64                                `json:"next_batch"`
}

// Notary is safe for concurrent use.
type Notary struct {
	Beacon     pocc.BeaconInfo
	SlotRounds uint64
	Anchor     anchor.Poster
	DataDir    string // optional; state is saved here after each batch

	mu      sync.Mutex
	st      state
	pending []pendingLeaf
}

// New returns a notary, loading saved state from dataDir if present.
func New(info pocc.BeaconInfo, slotRounds uint64, a anchor.Poster, dataDir string) (*Notary, error) {
	n := &Notary{Beacon: info, SlotRounds: slotRounds, Anchor: a, DataDir: dataDir,
		st: state{Entries: map[string]map[uint64]pocc.Entry{}, Proofs: map[string]map[uint64]pocc.BatchProof{}}}
	if dataDir != "" {
		b, err := os.ReadFile(filepath.Join(dataDir, "notary-state.json"))
		if err == nil {
			if err := json.Unmarshal(b, &n.st); err != nil {
				return nil, fmt.Errorf("load state: %w", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		// Entries saved without a proof were pending when the notary stopped.
		for agent, m := range n.st.Entries {
			for seq, e := range m {
				if _, ok := n.st.Proofs[agent][seq]; !ok {
					pub, _ := pocc.DecodePub(agent)
					n.pending = append(n.pending, pendingLeaf{agent, seq, pocc.EntryLeaf(pub, seq, pocc.MustUnhex(e.E))})
				}
			}
		}
	}
	return n, nil
}

// Submit validates and stores one entry. Resubmitting the same entry is a no-op.
func (n *Notary) Submit(e pocc.Entry) error {
	pub, err := pocc.DecodePub(e.AgentPubKey)
	if err != nil {
		return err
	}
	eb, err := pocc.Unhex("e", e.E)
	if err != nil || len(eb) != 32 {
		return errors.New("bad e")
	}
	if !pocc.VerifyRaw(e.AgentPubKey, eb, e.Sig) {
		return errors.New("entry signature does not verify")
	}
	switch {
	case e.Seq == 0:
		if e.Boot == nil || e.Boot.E0 != e.E || e.Boot.AgentPubKey != e.AgentPubKey || e.Heartbeat != nil {
			return errors.New("seq 0 must carry the boot proof")
		}
	default:
		if e.Heartbeat == nil || e.Heartbeat.E != e.E || e.Heartbeat.Seq != e.Seq || e.Boot != nil {
			return errors.New("heartbeat entry does not match its heartbeat")
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	m := n.st.Entries[e.AgentPubKey]
	if old, ok := m[e.Seq]; ok {
		if old.E == e.E {
			return nil
		}
		return ErrFork
	}
	if e.Seq > 0 {
		if _, ok := m[e.Seq-1]; !ok {
			return fmt.Errorf("seq %d submitted before seq %d", e.Seq, e.Seq-1)
		}
	}
	if m == nil {
		m = map[uint64]pocc.Entry{}
		n.st.Entries[e.AgentPubKey] = m
	}
	m[e.Seq] = e
	n.pending = append(n.pending, pendingLeaf{e.AgentPubKey, e.Seq, pocc.EntryLeaf(pub, e.Seq, eb)})
	return nil
}

// CloseBatch anchors everything pending as one tree for the given slot.
func (n *Notary) CloseBatch(ctx context.Context, slot uint64) error {
	n.mu.Lock()
	batch := n.pending
	n.pending = nil
	n.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	leaves := make([][]byte, len(batch))
	for i, p := range batch {
		leaves[i] = p.Leaf
	}
	root := pocc.MerkleRoot(leaves)
	ref, err := n.Anchor.Post(ctx, root)
	if err != nil {
		n.mu.Lock()
		n.pending = append(batch, n.pending...)
		n.mu.Unlock()
		return fmt.Errorf("anchor: %w", err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	id := n.st.NextBatch
	n.st.NextBatch++
	for i, p := range batch {
		var path []string
		for _, h := range pocc.MerklePath(i, leaves) {
			path = append(path, pocc.Hex(h))
		}
		bp := pocc.BatchProof{BatchID: id, Slot: slot, Root: pocc.Hex(root), Index: uint64(i),
			TreeSize: uint64(len(leaves)), Path: path, Anchor: ref}
		if n.st.Proofs[p.Agent] == nil {
			n.st.Proofs[p.Agent] = map[uint64]pocc.BatchProof{}
		}
		n.st.Proofs[p.Agent][p.Seq] = bp
	}
	return n.saveLocked()
}

func (n *Notary) saveLocked() error {
	if n.DataDir == "" {
		return nil
	}
	b, err := json.Marshal(n.st)
	if err != nil {
		return err
	}
	tmp := filepath.Join(n.DataDir, "notary-state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(n.DataDir, "notary-state.json"))
}

// Proof returns the inclusion proof for (agent, seq), once anchored.
func (n *Notary) Proof(agent string, seq uint64) (pocc.BatchProof, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	p, ok := n.st.Proofs[agent][seq]
	return p, ok
}

// Entries returns an agent's entries in seq order.
func (n *Notary) Entries(agent string) []pocc.Entry {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []pocc.Entry
	for _, e := range n.st.Entries[agent] {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

// HasConflict implements verify.ForkChecker against the notary's own log.
func (n *Notary) HasConflict(_ context.Context, agent string, seq uint64, e string) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	old, ok := n.st.Entries[agent][seq]
	return ok && old.E != e, nil
}

// Run closes one batch per slot, closeDelay after the slot's round is published.
func (n *Notary) Run(ctx context.Context, closeDelay time.Duration, logf func(string, ...any)) {
	for {
		slot := beacon.NextSlot(beacon.RoundAt(n.Beacon, time.Now().Add(-closeDelay)), n.SlotRounds)
		at := beacon.Time(n.Beacon, slot).Add(closeDelay)
		select {
		case <-time.After(time.Until(at)):
		case <-ctx.Done():
			return
		}
		if err := n.CloseBatch(ctx, slot); err != nil {
			logf("close batch for slot %d: %v", slot, err)
		}
	}
}

// Handler serves the notary HTTP API.
//
//	POST /v0/entries               submit an Entry
//	GET  /v0/entries?agent=...     list an agent's entries
//	GET  /v0/proof?agent=...&seq=N inclusion proof once anchored
func (n *Notary) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v0/entries", func(w http.ResponseWriter, r *http.Request) {
		var e pocc.Entry
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&e); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch err := n.Submit(e); {
		case errors.Is(err, ErrFork):
			http.Error(w, err.Error(), http.StatusConflict)
		case err != nil:
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	})
	mux.HandleFunc("GET /v0/entries", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, n.Entries(r.URL.Query().Get("agent")))
	})
	mux.HandleFunc("GET /v0/proof", func(w http.ResponseWriter, r *http.Request) {
		seq, err := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
		if err != nil {
			http.Error(w, "bad seq", http.StatusBadRequest)
			return
		}
		p, ok := n.Proof(r.URL.Query().Get("agent"), seq)
		if !ok {
			http.Error(w, "not anchored yet", http.StatusNotFound)
			return
		}
		writeJSON(w, p)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
