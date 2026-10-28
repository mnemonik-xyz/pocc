// Package keys reads and writes a party's key file: an Ed25519 signing key and
// an X25519 seal key, base64-encoded in JSON. Keep key files out of git.
package keys

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"

	"github.com/mnemonik-xyz/pocc/pkg/pocc"
)

// File is the on-disk format.
type File struct {
	SigningSeed string `json:"signing_seed"` // base64 32-byte Ed25519 seed
	SigningPub  string `json:"signing_pub"`
	SealPriv    string `json:"seal_priv"` // base64 X25519 private key
	SealPub     string `json:"seal_pub"`
}

// Party is a decoded key file.
type Party struct {
	Signing ed25519.PrivateKey
	Seal    *ecdh.PrivateKey
	File    File
}

// Generate creates a new key file at path. It refuses to overwrite.
func Generate(path string) (*Party, error) {
	pub, priv := pocc.GenerateSigningKey()
	seal, err := pocc.GenerateSealKey()
	if err != nil {
		return nil, err
	}
	f := File{SigningSeed: pocc.B64.EncodeToString(priv.Seed()), SigningPub: pocc.B64.EncodeToString(pub),
		SealPriv: pocc.B64.EncodeToString(seal.Bytes()), SealPub: pocc.B64.EncodeToString(seal.PublicKey().Bytes())}
	b, _ := json.MarshalIndent(f, "", "  ")
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	if _, err := fh.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	return &Party{Signing: priv, Seal: seal, File: f}, nil
}

// Load reads a key file.
func Load(path string) (*Party, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	seed, err := pocc.B64.DecodeString(f.SigningSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: bad signing seed", path)
	}
	seal, err := pocc.DecodeSealPriv(f.SealPriv)
	if err != nil {
		return nil, fmt.Errorf("%s: bad seal key", path)
	}
	return &Party{Signing: ed25519.NewKeyFromSeed(seed), Seal: seal, File: f}, nil
}
