package pocc

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/mnemonik-xyz/pocc/internal/canon"
)

// B64 is the encoding for keys and signatures.
var B64 = base64.StdEncoding

// DocHash is H(tag, canonical JSON of the whole document, signature included).
// It is how one document refers to another: request_hash, h0, receipt_hash.
func DocHash(tag string, v any) ([]byte, error) {
	c, err := canon.Marshal(v)
	if err != nil {
		return nil, err
	}
	return H(tag, c), nil
}

// sigMessage is what gets signed: H(tag+"/sig", canonical JSON without "sig").
func sigMessage(tag string, v any) ([]byte, error) {
	c, err := canon.MarshalWithout(v, "sig")
	if err != nil {
		return nil, err
	}
	return H(tag+"/sig", c), nil
}

// SignDoc signs v (ignoring its "sig" field) and returns a base64 signature.
func SignDoc(priv ed25519.PrivateKey, tag string, v any) (string, error) {
	m, err := sigMessage(tag, v)
	if err != nil {
		return "", err
	}
	return B64.EncodeToString(ed25519.Sign(priv, m)), nil
}

// VerifyDoc checks a base64 signature over v (ignoring its "sig" field).
func VerifyDoc(pubB64, tag string, v any, sigB64 string) error {
	pub, err := DecodePub(pubB64)
	if err != nil {
		return err
	}
	sig, err := B64.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	m, err := sigMessage(tag, v)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, m, sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// GenerateSigningKey returns a new Ed25519 key pair.
func GenerateSigningKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

// DecodePub decodes a base64 Ed25519 public key.
func DecodePub(s string) (ed25519.PublicKey, error) {
	b, err := B64.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// SignRaw signs a raw message (used for e0 and e_i).
func SignRaw(priv ed25519.PrivateKey, msg []byte) string {
	return B64.EncodeToString(ed25519.Sign(priv, msg))
}

// VerifyRaw checks a base64 signature over a raw message.
func VerifyRaw(pubB64 string, msg []byte, sigB64 string) bool {
	pub, err := DecodePub(pubB64)
	if err != nil {
		return false
	}
	sig, err := B64.DecodeString(sigB64)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}
