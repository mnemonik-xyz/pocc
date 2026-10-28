// Package pocc holds the PoCC artifact types and the cryptographic
// constructions from the PoC spec v0.2: domain-separated hashing, the boot
// binding e0, the heartbeat chain e_i, salted usage commitments, seed sealing
// and Merkle inclusion proofs.
package pocc

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
)

// Domain tags. Every hash in PoCC is H(tag, parts...).
const (
	TagRequest    = "PoCC/poc/request"
	TagOrder      = "PoCC/poc/order"
	TagBoot       = "PoCC/poc/boot"
	TagHeartbeat  = "PoCC/poc/hb"
	TagLeaf       = "PoCC/poc/leaf"
	TagUsage      = "PoCC/poc/usage"
	TagSeedEnc    = "PoCC/poc/seed-enc"
	TagEntry      = "PoCC/poc/entry"
	TagReceipt    = "PoCC/poc/receipt"
	TagVerdict    = "PoCC/poc/verdict"
	TagSettlement = "PoCC/poc/settlement"
	TagAnchor     = "PoCC/poc/anchor"
	TagGPU        = "PoCC/poc/gpu"
)

// H is SHA-256 over the tag and the parts, each prefixed with its 4-byte
// big-endian length. The length prefixes make the concatenation unambiguous;
// the spec writes this as H(tag ‖ part1 ‖ part2 ‖ ...).
func H(tag string, parts ...[]byte) []byte {
	h := sha256.New()
	writeLP(h, []byte(tag))
	for _, p := range parts {
		writeLP(h, p)
	}
	return h.Sum(nil)
}

func writeLP(h hash.Hash, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	h.Write(l[:])
	h.Write(b)
}

// U64 encodes v as 8 big-endian bytes.
func U64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// Hex encodes b as lowercase hex.
func Hex(b []byte) string { return hex.EncodeToString(b) }

// Unhex decodes a lowercase hex string, returning an error that names the field.
func Unhex(field, s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: bad hex: %w", field, err)
	}
	return b, nil
}

// MustUnhex decodes hex and returns nil on error. Callers compare the result,
// so a malformed field simply fails the comparison.
func MustUnhex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// BoolByte encodes a boolean as one byte.
func BoolByte(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}
