// Package receipt assembles a receipt from the notary's log (spec step 7)
// and produces usage openings for seed holders (spec 4.5).
package receipt

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mnemonik-xyz/pocc/pkg/pocc"
)

// Source is read access to a notary's log.
type Source interface {
	Entries(agent string) []pocc.Entry
	Proof(agent string, seq uint64) (pocc.BatchProof, bool)
}

// Assemble builds and signs a receipt. It includes the boot proof and every
// heartbeat that is already anchored, stopping at the first one that is not.
func Assemble(req pocc.Request, order pocc.Order, src Source, agent string, nova *pocc.NovaServer,
	billed pocc.Billed, openings []pocc.Opening, providerPriv ed25519.PrivateKey) (*pocc.Receipt, error) {
	entries := src.Entries(agent)
	if len(entries) == 0 || entries[0].Seq != 0 || entries[0].Boot == nil {
		return nil, errors.New("no boot proof for this agent")
	}
	R := &pocc.Receipt{Version: pocc.Version, Request: req, Order: order, Boot: *entries[0].Boot,
		NovaServer: nova, Billed: billed, Openings: openings}
	for i, e := range entries {
		if e.Seq != uint64(i) {
			break
		}
		p, ok := src.Proof(agent, e.Seq)
		if !ok {
			break
		}
		R.Proofs = append(R.Proofs, p)
		if i > 0 {
			R.Heartbeats = append(R.Heartbeats, *e.Heartbeat)
		}
	}
	sig, err := pocc.SignDoc(providerPriv, pocc.TagReceipt, R)
	if err != nil {
		return nil, err
	}
	R.Sig = sig
	return R, nil
}

// Disclose opens the given fields at the given heartbeats. The caller holds a
// seal key that the agent sealed the seed to (tenant or provider).
func Disclose(entries []pocc.Entry, sealPriv *ecdh.PrivateKey, seqs []uint64, fields []string) ([]pocc.Opening, error) {
	if len(entries) == 0 || entries[0].Boot == nil {
		return nil, errors.New("no boot proof")
	}
	seed, err := pocc.OpenSeed(sealPriv, entries[0].Boot.SeedEnc)
	if err != nil {
		return nil, err
	}
	bySeq := map[uint64]pocc.Entry{}
	for _, e := range entries {
		bySeq[e.Seq] = e
	}
	var out []pocc.Opening
	for _, s := range seqs {
		e, ok := bySeq[s]
		if !ok || e.SealedUsage == nil {
			return nil, fmt.Errorf("no sealed usage for seq %d", s)
		}
		gotSeq, u, err := pocc.OpenUsage(seed, *e.SealedUsage)
		if err != nil || gotSeq != s {
			return nil, fmt.Errorf("open usage for seq %d: %v", s, err)
		}
		for _, f := range fields {
			op, err := pocc.Open(seed, s, u, f)
			if err != nil {
				return nil, err
			}
			out = append(out, op)
		}
	}
	return out, nil
}

// NotaryClient reads a notary over HTTP and implements Source.
type NotaryClient struct {
	URL    string
	Client *http.Client
	Ctx    context.Context
}

func (n NotaryClient) get(path string, v any) error {
	cl := n.Client
	if cl == nil {
		cl = &http.Client{Timeout: 15 * time.Second}
	}
	ctx := n.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(n.URL, "/")+path, nil)
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("notary %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// Entries lists an agent's entries; errors yield an empty list.
func (n NotaryClient) Entries(agent string) []pocc.Entry {
	var out []pocc.Entry
	_ = n.get("/v0/entries?agent="+url.QueryEscape(agent), &out)
	return out
}

// Proof fetches one inclusion proof.
func (n NotaryClient) Proof(agent string, seq uint64) (pocc.BatchProof, bool) {
	var p pocc.BatchProof
	err := n.get(fmt.Sprintf("/v0/proof?agent=%s&seq=%d", url.QueryEscape(agent), seq), &p)
	return p, err == nil
}

// HasConflict implements verify.ForkChecker over HTTP.
func (n NotaryClient) HasConflict(_ context.Context, agent string, seq uint64, e string) (bool, error) {
	for _, x := range n.Entries(agent) {
		if x.Seq == seq {
			return x.E != e, nil
		}
	}
	return false, nil
}
