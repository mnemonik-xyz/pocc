package pocc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strconv"
)

// Salt derives the salt for one usage field (spec 4.2):
//
//	s_{i,k} = HMAC(seed, i ‖ name_k)
func Salt(seed []byte, seq uint64, field string) []byte {
	m := hmac.New(sha256.New, seed)
	m.Write(U64(seq))
	m.Write([]byte(field))
	return m.Sum(nil)
}

// Leaf is H(leaf ‖ salt ‖ name ‖ value), with the value in decimal.
func Leaf(salt []byte, field string, value uint64) []byte {
	return H(TagLeaf, salt, []byte(field), []byte(strconv.FormatUint(value, 10)))
}

// UsageLeaves returns the leaves of heartbeat seq in UsageFields order.
func UsageLeaves(seed []byte, seq uint64, u Usage) [][]byte {
	out := make([][]byte, len(UsageFields))
	for i, f := range UsageFields {
		v, _ := u.Get(f)
		out[i] = Leaf(Salt(seed, seq, f), f, v)
	}
	return out
}

// CommitLeaves is u_i = H(usage ‖ leaf_1 ‖ ... ‖ leaf_K).
func CommitLeaves(leaves [][]byte) []byte { return H(TagUsage, leaves...) }

// UsageCommit commits to all usage fields of heartbeat seq.
func UsageCommit(seed []byte, seq uint64, u Usage) []byte {
	return CommitLeaves(UsageLeaves(seed, seq, u))
}

// Open discloses one field of heartbeat seq.
func Open(seed []byte, seq uint64, u Usage, field string) (Opening, error) {
	idx := fieldIndex(field)
	if idx < 0 {
		return Opening{}, fmt.Errorf("unknown usage field %q", field)
	}
	leaves := UsageLeaves(seed, seq, u)
	var others []string
	for i, l := range leaves {
		if i != idx {
			others = append(others, Hex(l))
		}
	}
	v, _ := u.Get(field)
	return Opening{Seq: seq, Field: field, Value: v, Salt: Hex(Salt(seed, seq, field)), OtherLeaves: others}, nil
}

// VerifyOpening checks an opening against the committed u_i.
func VerifyOpening(op Opening, commit []byte) bool {
	idx := fieldIndex(op.Field)
	if idx < 0 || len(op.OtherLeaves) != len(UsageFields)-1 {
		return false
	}
	salt := MustUnhex(op.Salt)
	if len(salt) != sha256.Size {
		return false
	}
	leaves := make([][]byte, 0, len(UsageFields))
	j := 0
	for i := range UsageFields {
		if i == idx {
			leaves = append(leaves, Leaf(salt, op.Field, op.Value))
		} else {
			leaves = append(leaves, MustUnhex(op.OtherLeaves[j]))
			j++
		}
	}
	return bytes.Equal(CommitLeaves(leaves), commit)
}

func fieldIndex(field string) int {
	for i, f := range UsageFields {
		if f == field {
			return i
		}
	}
	return -1
}
