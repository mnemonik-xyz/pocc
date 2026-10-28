// Package agent is the in-VM side of PoCC (spec 4): it binds the VM to the
// order at boot, signs a chained heartbeat on every shared slot, and sends a
// final heartbeat at the end of the period or on shutdown.
package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mnemonik-xyz/pocc/pkg/beacon"
	"github.com/mnemonik-xyz/pocc/pkg/pocc"
)

// Counters reads cumulative usage since boot.
type Counters interface {
	Read() (pocc.Usage, error)
}

// Submitter delivers entries to the notary. Submitting an identical entry
// twice must succeed.
type Submitter interface {
	Submit(ctx context.Context, e pocc.Entry) error
}

// Agent holds the chain state. It is not safe for concurrent use.
type Agent struct {
	Request  pocc.Request
	Order    pocc.Order
	ServerID string
	Beacon   beacon.Source
	Counters Counters
	Notary   Submitter
	Logf     func(string, ...any)

	priv      ed25519.PrivateKey
	pub       string
	seed      []byte
	h0        []byte
	prevE     []byte
	prevRound uint64
	seq       uint64
	pending   *pocc.Entry // built but not confirmed by the notary
	done      bool
}

// New checks that the order belongs to the request and prepares an agent.
func New(req pocc.Request, order pocc.Order, serverID string, b beacon.Source, c Counters, n Submitter) (*Agent, error) {
	rh, err := pocc.DocHash(pocc.TagRequest, req)
	if err != nil {
		return nil, err
	}
	if order.RequestHash != pocc.Hex(rh) {
		return nil, errors.New("order does not belong to this request")
	}
	if err := pocc.VerifyDoc(order.ProviderPubKey, pocc.TagOrder, order, order.Sig); err != nil {
		return nil, fmt.Errorf("order signature: %w", err)
	}
	h0, err := pocc.DocHash(pocc.TagOrder, order)
	if err != nil {
		return nil, err
	}
	if serverID == "" {
		return nil, errors.New("server id is empty")
	}
	return &Agent{Request: req, Order: order, ServerID: serverID, Beacon: b, Counters: c, Notary: n, h0: h0,
		Logf: func(string, ...any) {}}, nil
}

// AgentPubKey returns the agent's public key after Boot.
func (a *Agent) AgentPubKey() string { return a.pub }

// Boot creates the agent key and seed and submits the boot proof for round r0.
func (a *Agent) Boot(ctx context.Context, r0 uint64) (pocc.BootProof, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return pocc.BootProof{}, err
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return pocc.BootProof{}, err
	}
	seedEnc, err := pocc.SealSeed(seed, a.Request.TenantSealKey, a.Order.ProviderSealKey)
	if err != nil {
		return pocc.BootProof{}, err
	}
	rnd, err := a.Beacon.Get(ctx, r0)
	if err != nil {
		return pocc.BootProof{}, fmt.Errorf("beacon round %d: %w", r0, err)
	}
	e0 := pocc.BootE0(a.h0, a.ServerID, pub, "", r0, rnd.Randomness, seedEnc)
	bp := pocc.BootProof{
		OrderHash: pocc.Hex(a.h0), ServerID: a.ServerID, AgentPubKey: pocc.B64.EncodeToString(pub),
		Round: r0, Randomness: pocc.Hex(rnd.Randomness), SeedEnc: seedEnc,
		Attestation: a.Request.Attestation, E0: pocc.Hex(e0), Sig: pocc.SignRaw(priv, e0),
	}
	if a.Request.Attestation != pocc.AttestationNone {
		return pocc.BootProof{}, fmt.Errorf("attestation %q is not supported by this build", a.Request.Attestation)
	}
	entry := pocc.Entry{AgentPubKey: bp.AgentPubKey, Seq: 0, E: bp.E0, Sig: bp.Sig, Boot: &bp}
	if err := a.Notary.Submit(ctx, entry); err != nil {
		return pocc.BootProof{}, fmt.Errorf("submit boot proof: %w", err)
	}
	a.priv, a.pub, a.seed = priv, bp.AgentPubKey, seed
	a.prevE, a.prevRound, a.seq = e0, r0, 0
	return bp, nil
}

// Beat builds and submits the heartbeat for slot round r. If the notary
// cannot be reached, the heartbeat is kept and retried first at the next slot,
// so the chain never forks; the late slot then earns no credit.
func (a *Agent) Beat(ctx context.Context, r uint64, final bool) (pocc.Heartbeat, error) {
	if a.priv == nil {
		return pocc.Heartbeat{}, errors.New("not booted")
	}
	if a.done {
		return pocc.Heartbeat{}, errors.New("final heartbeat already sent")
	}
	if a.pending != nil {
		if err := a.Notary.Submit(ctx, *a.pending); err != nil {
			return pocc.Heartbeat{}, fmt.Errorf("resubmit seq %d: %w", a.pending.Seq, err)
		}
		a.confirm(*a.pending)
	}
	if r <= a.prevRound || r%uint64(a.Order.SlotRounds) != 0 {
		return pocc.Heartbeat{}, fmt.Errorf("round %d is not a slot after %d", r, a.prevRound)
	}
	rnd, err := a.Beacon.Get(ctx, r)
	if err != nil {
		return pocc.Heartbeat{}, fmt.Errorf("beacon round %d: %w", r, err)
	}
	u, err := a.Counters.Read()
	if err != nil {
		return pocc.Heartbeat{}, fmt.Errorf("counters: %w", err)
	}
	seq := a.seq + 1
	commit := pocc.UsageCommit(a.seed, seq, u)
	e := pocc.HeartbeatE(a.prevE, seq, r, rnd.Randomness, commit, final)
	hb := pocc.Heartbeat{Seq: seq, Round: r, Randomness: pocc.Hex(rnd.Randomness),
		UsageCommit: pocc.Hex(commit), Final: final, E: pocc.Hex(e), Sig: pocc.SignRaw(a.priv, e)}
	sealed, err := pocc.SealUsage(a.seed, seq, u)
	if err != nil {
		return pocc.Heartbeat{}, err
	}
	entry := pocc.Entry{AgentPubKey: a.pub, Seq: seq, E: hb.E, Sig: hb.Sig, Heartbeat: &hb, SealedUsage: &sealed}
	if err := a.Notary.Submit(ctx, entry); err != nil {
		a.pending = &entry
		return hb, fmt.Errorf("submit seq %d (will retry): %w", seq, err)
	}
	a.confirm(entry)
	if final {
		a.done = true
		for i := range a.priv {
			a.priv[i] = 0
		}
	}
	return hb, nil
}

func (a *Agent) confirm(e pocc.Entry) {
	a.prevE = pocc.MustUnhex(e.E)
	a.prevRound = e.Heartbeat.Round
	a.seq = e.Seq
	a.pending = nil
}

// Run boots and then beats on every slot until the period ends or stop closes.
// After stop closes, the agent sends a final heartbeat at the next slot.
func (a *Agent) Run(ctx context.Context, info pocc.BeaconInfo, stop <-chan struct{}) error {
	end, err := time.Parse(time.RFC3339, a.Request.Period.End)
	if err != nil {
		return fmt.Errorf("period end: %w", err)
	}
	r0 := beacon.RoundAt(info, time.Now())
	if _, err := a.Boot(ctx, r0); err != nil {
		return err
	}
	a.Logf("booted: agent %s, round %d", a.pub, r0)
	stopping := false
	slotRounds := uint64(a.Order.SlotRounds)
	for !a.done {
		slot := beacon.NextSlot(a.prevRound, slotRounds)
		// Skip slots already in the past (for example after a long notary outage).
		if now := beacon.RoundAt(info, time.Now()); now > slot {
			slot = beacon.NextSlot(now-1, slotRounds) // first slot at or after now
		}
		at := beacon.Time(info, slot)
		final := stopping || !at.Before(end) || !beacon.Time(info, slot+slotRounds).Before(end.Add(time.Second))
		select {
		case <-time.After(time.Until(at)):
		case <-stop:
			if !stopping {
				stopping = true
				a.Logf("stop requested: final heartbeat at slot %d", slot)
			}
			continue
		case <-ctx.Done():
			return ctx.Err()
		}
		hb, err := a.Beat(ctx, slot, final)
		if err != nil {
			a.Logf("slot %d: %v", slot, err)
			continue
		}
		a.Logf("heartbeat seq %d round %d final=%v", hb.Seq, hb.Round, hb.Final)
	}
	return nil
}

// ProcCounters reads CPU time from /proc/stat. The PoC has no GPU counter.
type ProcCounters struct{ Path string }

// Read returns busy CPU milliseconds since boot (user+nice+system+irq+softirq).
func (p ProcCounters) Read() (pocc.Usage, error) {
	path := p.Path
	if path == "" {
		path = "/proc/stat"
	}
	f, err := os.Open(path)
	if err != nil {
		return pocc.Usage{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 8 || fs[0] != "cpu" {
			continue
		}
		var busy uint64
		for _, i := range []int{1, 2, 3, 6, 7} { // user nice system irq softirq
			v, err := strconv.ParseUint(fs[i], 10, 64)
			if err != nil {
				return pocc.Usage{}, err
			}
			busy += v
		}
		return pocc.Usage{CPUMs: busy * 10}, nil // USER_HZ is 100 on Linux
	}
	return pocc.Usage{}, errors.New("no cpu line in " + path)
}

// HTTPNotary submits entries to a notary over HTTP.
type HTTPNotary struct {
	URL    string
	Client *http.Client
}

// Submit posts one entry. 202 means accepted; resubmitting the same entry is accepted too.
func (h HTTPNotary) Submit(ctx context.Context, e pocc.Entry) error {
	body, _ := json.Marshal(e)
	cl := h.Client
	if cl == nil {
		cl = &http.Client{Timeout: 10 * time.Second}
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(h.URL, "/")+"/v0/entries", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := cl.Do(req)
		if err == nil {
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusAccepted {
				return nil
			}
			if resp.StatusCode < 500 {
				return fmt.Errorf("notary: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
			}
			err = fmt.Errorf("notary: HTTP %d", resp.StatusCode)
		}
		lastErr = err
		select {
		case <-time.After(time.Duration(attempt+1) * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return lastErr
}
