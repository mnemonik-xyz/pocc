// Package anchor posts batch roots somewhere that fixes their time, and
// checks those posts later.
//
// The PoC ships a signed-file anchor for development: the notary's anchor key
// signs (root, time). It is only as honest as the notary. The production
// anchor posts roots to the chain Warrant's escrow uses, where the block time
// is the upper time bound; it plugs in behind the same two interfaces.
package anchor

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/mnemonik-xyz/pocc/pkg/pocc"
)

// KindDevFile marks roots anchored by the development file anchor.
const KindDevFile = "dev-file"

// Poster anchors a root and returns where and when.
type Poster interface {
	Post(ctx context.Context, root []byte) (pocc.AnchorRef, error)
}

// Checker confirms an anchor and returns its time (unix seconds).
type Checker interface {
	Check(ctx context.Context, ref pocc.AnchorRef, root []byte) (int64, error)
}

func devMessage(root []byte, ref string, t int64) []byte {
	return pocc.H(pocc.TagAnchor, root, []byte(ref), pocc.U64(uint64(t)))
}

// DevFile is the development anchor: it signs (root, ref, time) and appends
// the record to a JSON-lines file.
type DevFile struct {
	Key  ed25519.PrivateKey
	Path string           // optional; empty keeps records in memory only
	Now  func() time.Time // optional clock for tests
	mu   sync.Mutex
	next uint64
}

// Post signs and records one root.
func (d *DevFile) Post(_ context.Context, root []byte) (pocc.AnchorRef, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	d.next++
	ref := "dev-" + strconv.FormatUint(d.next, 10)
	t := now().Unix()
	a := pocc.AnchorRef{Kind: KindDevFile, Ref: ref, Time: t,
		Sig: pocc.SignRaw(d.Key, devMessage(root, ref, t))}
	if d.Path != "" {
		f, err := os.OpenFile(d.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return pocc.AnchorRef{}, err
		}
		defer f.Close()
		line, _ := json.Marshal(struct {
			Root string         `json:"root"`
			Ref  pocc.AnchorRef `json:"anchor"`
		}{pocc.Hex(root), a})
		if _, err := f.Write(append(line, '\n')); err != nil {
			return pocc.AnchorRef{}, err
		}
	}
	return a, nil
}

// DevChecker verifies DevFile anchors against the notary's anchor key.
type DevChecker struct{ PubKey string }

// Check verifies the signature and returns the recorded time.
func (c DevChecker) Check(_ context.Context, ref pocc.AnchorRef, root []byte) (int64, error) {
	if ref.Kind != KindDevFile {
		return 0, fmt.Errorf("anchor kind %q not supported by this checker", ref.Kind)
	}
	if c.PubKey == "" {
		return 0, errors.New("no anchor key configured")
	}
	if !pocc.VerifyRaw(c.PubKey, devMessage(root, ref.Ref, ref.Time), ref.Sig) {
		return 0, errors.New("anchor signature does not verify")
	}
	return ref.Time, nil
}
