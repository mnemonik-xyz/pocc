package pocc

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

// Merkle trees follow RFC 9162 (Certificate Transparency v2): leaf hash
// SHA-256(0x00 ‖ data), node hash SHA-256(0x01 ‖ left ‖ right), and a
// tree of n leaves splits at the largest power of two below n.

func leafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(data)
	return h.Sum(nil)
}

func nodeHash(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

func split(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// MerkleRoot returns the root over the leaf data.
func MerkleRoot(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		s := sha256.Sum256(nil)
		return s[:]
	case 1:
		return leafHash(leaves[0])
	}
	k := split(len(leaves))
	return nodeHash(MerkleRoot(leaves[:k]), MerkleRoot(leaves[k:]))
}

// MerklePath returns the inclusion path for leaf m (RFC 9162 PATH).
func MerklePath(m int, leaves [][]byte) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := split(len(leaves))
	if m < k {
		return append(MerklePath(m, leaves[:k]), MerkleRoot(leaves[k:]))
	}
	return append(MerklePath(m-k, leaves[k:]), MerkleRoot(leaves[:k]))
}

// VerifyInclusion checks an inclusion proof (RFC 9162 section 2.1.3.2).
func VerifyInclusion(leaf []byte, index, size uint64, path [][]byte, root []byte) error {
	if index >= size {
		return errors.New("index beyond tree size")
	}
	fn, sn := index, size-1
	r := leafHash(leaf)
	for _, p := range path {
		if sn == 0 {
			return errors.New("path too long")
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return errors.New("path too short")
	}
	if !bytes.Equal(r, root) {
		return errors.New("root mismatch")
	}
	return nil
}
