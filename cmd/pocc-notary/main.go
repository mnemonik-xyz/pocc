// Command pocc-notary runs the notary: it accepts entries over HTTP, anchors
// one Merkle root per 60 s slot, and serves inclusion proofs. It can also serve
// the pocc-agent binary so that VMs can download it at boot.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mnemonik-xyz/pocc/pkg/anchor"
	"github.com/mnemonik-xyz/pocc/pkg/beacon"
	"github.com/mnemonik-xyz/pocc/pkg/notary"
	"github.com/mnemonik-xyz/pocc/pkg/pocc"
)

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	data := flag.String("data", "./data", "state directory")
	closeDelay := flag.Duration("close-delay", 10*time.Second, "how long after a slot to close its batch")
	agentBin := flag.String("agent-binary", "", "optional pocc-agent binary to serve at /agent/pocc-agent")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC)

	if err := os.MkdirAll(*data, 0o700); err != nil {
		log.Fatal(err)
	}
	key, err := loadOrCreateKey(filepath.Join(*data, "anchor.key"))
	if err != nil {
		log.Fatal(err)
	}
	pub := pocc.B64.EncodeToString(key.Public().(ed25519.PublicKey))
	log.Printf("dev anchor key: %s (development anchor; trust is in this key)", pub)

	dev := &anchor.DevFile{Key: key, Path: filepath.Join(*data, "anchors.jsonl")}
	n, err := notary.New(beacon.Quicknet, 20, dev, *data)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/v0/", n.Handler())
	mux.HandleFunc("GET /v0/info", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"anchor_key": pub, "anchor_kind": anchor.KindDevFile,
			"beacon": beacon.Quicknet, "slot_rounds": 20})
	})
	if *agentBin != "" {
		mux.HandleFunc("GET /agent/pocc-agent", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, *agentBin)
		})
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	go n.Run(ctx, *closeDelay, log.Printf)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shut, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(shut)
	}()
	log.Printf("notary listening on %s", *listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		seed, err := pocc.B64.DecodeString(string(b))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, errors.New("bad anchor key file")
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	_, priv := pocc.GenerateSigningKey()
	if err := os.WriteFile(path, []byte(pocc.B64.EncodeToString(priv.Seed())), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}
