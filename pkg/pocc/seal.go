package pocc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

// GenerateSealKey returns a new X25519 key pair for receiving sealed seeds.
func GenerateSealKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// DecodeSealPub decodes a base64 X25519 public key.
func DecodeSealPub(s string) (*ecdh.PublicKey, error) {
	b, err := B64.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(b)
}

// DecodeSealPriv decodes a base64 X25519 private key.
func DecodeSealPriv(s string) (*ecdh.PrivateKey, error) {
	b, err := B64.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(b)
}

// Seal encrypts plaintext to one X25519 recipient: ephemeral X25519,
// HKDF-SHA256, AES-256-GCM.
func Seal(recipientB64 string, plaintext []byte) (SealedBox, error) {
	pub, err := DecodeSealPub(recipientB64)
	if err != nil {
		return SealedBox{}, fmt.Errorf("seal recipient: %w", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return SealedBox{}, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return SealedBox{}, err
	}
	key, err := hkdf.Key(sha256.New, shared, eph.PublicKey().Bytes(), "PoCC/poc/seal", 32)
	if err != nil {
		return SealedBox{}, err
	}
	nonce, ct, err := aeadSeal(key, plaintext)
	if err != nil {
		return SealedBox{}, err
	}
	return SealedBox{
		Recipient:  recipientB64,
		Ephemeral:  B64.EncodeToString(eph.PublicKey().Bytes()),
		Nonce:      B64.EncodeToString(nonce),
		Ciphertext: B64.EncodeToString(ct),
	}, nil
}

// Unseal decrypts a box addressed to priv.
func Unseal(priv *ecdh.PrivateKey, box SealedBox) ([]byte, error) {
	ephB, err := B64.DecodeString(box.Ephemeral)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.X25519().NewPublicKey(ephB)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, ephB, "PoCC/poc/seal", 32)
	if err != nil {
		return nil, err
	}
	return aeadOpen(key, box.Nonce, box.Ciphertext)
}

// SealSeed seals the disclosure seed to every recipient.
func SealSeed(seed []byte, recipients ...string) ([]SealedBox, error) {
	var out []SealedBox
	for _, r := range recipients {
		b, err := Seal(r, seed)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// OpenSeed finds the box for priv and returns the seed.
func OpenSeed(priv *ecdh.PrivateKey, boxes []SealedBox) ([]byte, error) {
	me := B64.EncodeToString(priv.PublicKey().Bytes())
	for _, b := range boxes {
		if b.Recipient == me {
			return Unseal(priv, b)
		}
	}
	return nil, errors.New("no sealed seed for this key")
}

// usageRecord is the plaintext of sealed usage values.
type usageRecord struct {
	Seq   uint64 `json:"seq"`
	Usage Usage  `json:"usage"`
}

func usageKey(seed []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, seed, nil, "PoCC/poc/usage-key", 32)
}

// SealUsage encrypts the usage values of one heartbeat under a key derived
// from the seed, so only seed holders can later produce openings.
func SealUsage(seed []byte, seq uint64, u Usage) (SealedBox, error) {
	key, err := usageKey(seed)
	if err != nil {
		return SealedBox{}, err
	}
	pt, _ := json.Marshal(usageRecord{Seq: seq, Usage: u})
	nonce, ct, err := aeadSeal(key, pt)
	if err != nil {
		return SealedBox{}, err
	}
	return SealedBox{Recipient: "seed", Nonce: B64.EncodeToString(nonce), Ciphertext: B64.EncodeToString(ct)}, nil
}

// OpenUsage decrypts sealed usage values.
func OpenUsage(seed []byte, box SealedBox) (uint64, Usage, error) {
	key, err := usageKey(seed)
	if err != nil {
		return 0, Usage{}, err
	}
	pt, err := aeadOpen(key, box.Nonce, box.Ciphertext)
	if err != nil {
		return 0, Usage{}, err
	}
	var r usageRecord
	if err := json.Unmarshal(pt, &r); err != nil {
		return 0, Usage{}, err
	}
	return r.Seq, r.Usage, nil
}

func aeadSeal(key, pt []byte) (nonce, ct []byte, err error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, g.Seal(nil, nonce, pt, nil), nil
}

func aeadOpen(key []byte, nonceB64, ctB64 string) ([]byte, error) {
	nonce, err := B64.DecodeString(nonceB64)
	if err != nil {
		return nil, err
	}
	ct, err := B64.DecodeString(ctB64)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	if len(nonce) != g.NonceSize() {
		return nil, errors.New("bad nonce")
	}
	return g.Open(nil, nonce, ct, nil)
}
