package pocc

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/mnemonik-xyz/pocc/internal/canon"
)

func TestMerkleInclusionAllSizes(t *testing.T) {
	for n := 1; n <= 33; n++ {
		var leaves [][]byte
		for i := 0; i < n; i++ {
			leaves = append(leaves, []byte(fmt.Sprintf("leaf-%d", i)))
		}
		root := MerkleRoot(leaves)
		for i := 0; i < n; i++ {
			if err := VerifyInclusion(leaves[i], uint64(i), uint64(n), MerklePath(i, leaves), root); err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if VerifyInclusion([]byte("other"), uint64(i), uint64(n), MerklePath(i, leaves), root) == nil {
				t.Fatalf("n=%d i=%d: wrong leaf accepted", n, i)
			}
		}
	}
}

func TestUsageOpening(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	u := Usage{CPUMs: 123456, GPUBusyMs: 789}
	c := UsageCommit(seed, 5, u)
	for _, f := range UsageFields {
		op, err := Open(seed, 5, u, f)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyOpening(op, c) {
			t.Fatalf("%s: valid opening rejected", f)
		}
		op.Value++
		if VerifyOpening(op, c) {
			t.Fatalf("%s: altered opening accepted", f)
		}
	}
}

func TestSealRoundTrip(t *testing.T) {
	a, _ := GenerateSealKey()
	b, _ := GenerateSealKey()
	seed := []byte("0123456789abcdef0123456789abcdef")
	boxes, err := SealSeed(seed, B64.EncodeToString(a.PublicKey().Bytes()), B64.EncodeToString(b.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenSeed(a, boxes); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("open seed for a: %v", err)
	}
	if got, err := OpenSeed(b, boxes); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("open seed for b: %v", err)
	}
	box, _ := SealUsage(seed, 3, Usage{CPUMs: 9})
	seq, u, err := OpenUsage(seed, box)
	if err != nil || seq != 3 || u.CPUMs != 9 {
		t.Fatalf("open usage: %v %d %+v", err, seq, u)
	}
}

func TestCanonSortsAndDrops(t *testing.T) {
	type doc struct {
		B   int    `json:"b"`
		A   string `json:"a"`
		Sig string `json:"sig"`
	}
	got, err := canon.MarshalWithout(doc{B: 2, A: "<x>", Sig: "s"}, "sig")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":"<x>","b":2}` {
		t.Fatalf("got %s", got)
	}
}

func TestSignDoc(t *testing.T) {
	pub, priv := GenerateSigningKey()
	r := Request{Version: Version, RequestID: "r1"}
	sig, err := SignDoc(priv, TagRequest, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Sig = sig
	if err := VerifyDoc(B64.EncodeToString(pub), TagRequest, r, r.Sig); err != nil {
		t.Fatal(err)
	}
	r.RequestID = "r2"
	if VerifyDoc(B64.EncodeToString(pub), TagRequest, r, r.Sig) == nil {
		t.Fatal("tampered doc accepted")
	}
}
