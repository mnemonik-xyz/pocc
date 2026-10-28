// Command pocc-agent runs inside the tenant's VM. It reads the signed request
// and order, binds to them at boot, and sends a heartbeat on every 60 s slot
// until the period ends or it receives SIGTERM.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mnemonik-xyz/pocc/internal/jsonfile"
	"github.com/mnemonik-xyz/pocc/pkg/agent"
	"github.com/mnemonik-xyz/pocc/pkg/beacon"
	"github.com/mnemonik-xyz/pocc/pkg/pocc"
)

// Config is /etc/pocc/agent.json, written by cloud-init.
type Config struct {
	Request pocc.Request `json:"request"`
	Order   pocc.Order   `json:"order"`
}

func main() {
	cfgPath := flag.String("config", "/etc/pocc/agent.json", "request and order JSON")
	serverID := flag.String("server-id", "", "Nova server ID (default: metadata service, then cloud-init)")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC)

	var cfg Config
	if err := jsonfile.Read(*cfgPath, &cfg); err != nil {
		log.Fatal(err)
	}
	id := *serverID
	if id == "" {
		id = discoverServerID()
	}
	if id == "" {
		log.Fatal("cannot determine the server ID; pass -server-id")
	}
	a, err := agent.New(cfg.Request, cfg.Order, id, beacon.NewHTTP(cfg.Order.Beacon),
		agent.ProcCounters{}, agent.HTTPNotary{URL: cfg.Order.Notary.URL})
	if err != nil {
		log.Fatal(err)
	}
	a.Logf = log.Printf

	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		log.Print("signal received: sending the final heartbeat at the next slot")
		close(stop)
	}()
	if err := a.Run(context.Background(), cfg.Order.Beacon, stop); err != nil {
		log.Fatal(err)
	}
	log.Print("final heartbeat sent; agent key erased")
}

func discoverServerID() string {
	cl := &http.Client{Timeout: 3 * time.Second}
	if resp, err := cl.Get("http://169.254.169.254/openstack/latest/meta_data.json"); err == nil {
		defer resp.Body.Close()
		var md struct {
			UUID string `json:"uuid"`
		}
		if json.NewDecoder(resp.Body).Decode(&md) == nil && md.UUID != "" {
			return md.UUID
		}
	}
	for _, p := range []string{"/var/lib/cloud/data/instance-id", "/run/cloud-init/.instance-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" && !strings.HasPrefix(s, "iid-") {
				return s
			}
		}
	}
	fmt.Fprintln(os.Stderr, "server ID not found in metadata service or cloud-init")
	return ""
}
