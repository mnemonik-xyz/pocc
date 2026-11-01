// Command pocc-broker drives the PoCC cycle around the VM:
//
//	keygen     create a party key file (tenant, provider or meter)
//	request    tenant: write and sign a request carrying the Warrant rent policy
//	order      provider: accept a request and sign the order
//	netsetup   provider: create the network, router and security group (Stage 0)
//	provision  provider: boot a notary or agent VM from a volume with cloud-init
//	fip        provider: attach a floating IP to a server
//	receipt    provider: assemble and sign the receipt from the notary's log
//	settle     tenant: sign accept or dispute for a verdict
//	image      print a Glance image ID by name
//	pause      pause or unpause a server (test: the provider stops delivery)
//	down       delete everything netsetup and provision created
//
// OpenStack credentials come from the standard OS_* environment variables.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mnemonik-xyz/pocc/internal/jsonfile"
	"github.com/mnemonik-xyz/pocc/internal/keys"
	"github.com/mnemonik-xyz/pocc/pkg/adapter/warrant"
	"github.com/mnemonik-xyz/pocc/pkg/anchor"
	"github.com/mnemonik-xyz/pocc/pkg/beacon"
	"github.com/mnemonik-xyz/pocc/pkg/openstack"
	"github.com/mnemonik-xyz/pocc/pkg/pocc"
	"github.com/mnemonik-xyz/pocc/pkg/receipt"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}
	cmds := map[string]func([]string){
		"keygen": keygen, "request": request, "netsetup": netsetup,
		"provision": provision, "fip": fip, "receipt": mkReceipt,
		"image": image, "pause": pause, "down": down, "ip": ip,
	}
	f, ok := cmds[os.Args[1]]
	if !ok {
		usage()
	}
	f(os.Args[2:])
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pocc-broker keygen|request|netsetup|provision|fip|receipt|image|pause|down|ip [flags]")
	os.Exit(2)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "key file to create (refuses to overwrite)")
	_ = fs.Parse(args)
	if *out == "" {
		log.Fatal("-out is required")
	}
	p, err := keys.Generate(*out)
	must(err)
	fmt.Printf("signing_pub %s\nseal_pub    %s\n", p.File.SigningPub, p.File.SealPub)
}

func request(args []string) {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	k := fs.String("keys", "tenant.json", "tenant key file")
	id := fs.String("id", "", "request ID (default: generated)")
	flavor := fs.String("flavor", "d2.cpu1ram1", "Nova flavor")
	vcpus := fs.Int("vcpus", 1, "vCPUs")
	ram := fs.Int("ram-mb", 1024, "RAM in MB")
	image := fs.String("image", "", "allowed Glance image ID")
	start := fs.String("start", "", "period start, RFC 3339, on a clock hour")
	end := fs.String("end", "", "period end, RFC 3339")
	price := fs.Int64("price", 0, "price per second in token units (the policy's price_per_unit)")
	currency := fs.String("currency", "USDC", "currency label of the token")
	notaryURL := fs.String("notary", "", "notary URL (meter spec)")
	anchorKey := fs.String("anchor-key", "", "notary's dev anchor key (meter spec, dev-file anchor)")
	meter := fs.String("meter-key", "", "warrant: meter key named in the policy (SEC1 hex or any string the policy uses)")
	policyHash := fs.String("policy-hash", "", "warrant: policy hash from warrant-policy hash (hex); required")
	policyFile := fs.String("policy", "", "warrant: use this approved policy JSON instead of building one")
	chain := fs.Uint64("chain-id", 0, "warrant: escrow chain ID")
	vault := fs.String("vault", "", "warrant: escrow address")
	token := fs.String("token", "", "warrant: token address")
	maxNote := fs.Int64("max-note", 0, "warrant: per-hour cap in token units (default 3600 x price)")
	ceiling := fs.Int64("ceiling", 0, "warrant: order ceiling in token units (default hours x max-note)")
	minUptime := fs.Int("min-uptime-bp", 9500, "warrant: uptime floor in basis points")
	rule := fs.String("rule", `{"all":["accepted"]}`, "warrant: rule tree")
	out := fs.String("out", "request.json", "output")
	_ = fs.Parse(args)
	t, err := keys.Load(*k)
	must(err)
	ps, err := time.Parse(time.RFC3339, *start)
	must(err)
	pe, err := time.Parse(time.RFC3339, *end)
	must(err)
	if *image == "" || *price <= 0 || *policyHash == "" {
		log.Fatal("-image, -price and -policy-hash are required")
	}
	if ps.Unix()%3600 != 0 {
		log.Fatal("-start must be on a clock hour (decision 19)")
	}
	if *id == "" {
		*id = fmt.Sprintf("req-%d", time.Now().Unix())
	}
	q := pocc.Request{Version: pocc.Version, RequestID: *id,
		Resource:      pocc.Resource{Flavor: *flavor, VCPUs: *vcpus, RAMMB: *ram},
		Period:        pocc.Period{Start: ps.UTC().Format(time.RFC3339), End: pe.UTC().Format(time.RFC3339)},
		MaxRateMicros: *price, Currency: *currency, Attestation: pocc.AttestationNone, AllowedImage: *image,
		TenantPubKey: t.File.SigningPub, TenantSealKey: t.File.SealPub,
		MeterSpec: pocc.MeterSpec{Format: pocc.Version, Attestation: pocc.AttestationNone, AllowedImage: *image,
			Flavor: *flavor, BeaconChainHash: beacon.Quicknet.ChainHash, SlotRounds: 20, BracketS: 30,
			Anchor: pocc.AnchorSpec{Kind: anchor.KindDevFile, AnchorKey: *anchorKey}, NotaryURL: *notaryURL},
		Consumer: pocc.ConsumerWarrant, PolicyHash: *policyHash}
	{
		if *policyFile != "" {
			b, err := os.ReadFile(*policyFile)
			must(err)
			q.Policy = b
		} else {
			if *meter == "" || *chain == 0 || *vault == "" || *token == "" {
				log.Fatal("-meter-key, -chain-id, -vault and -token are required to build the policy")
			}
			if !json.Valid([]byte(*rule)) {
				log.Fatal("-rule is not valid JSON")
			}
			ms, err := pocc.MeterSpecHash(q.MeterSpec)
			must(err)
			hours := int64(pe.Sub(ps) / time.Hour)
			if *maxNote == 0 {
				*maxNote = 3600 * *price
			}
			if *ceiling == 0 {
				*ceiling = hours * *maxNote
			}
			p := warrant.Policy{Case: "rent", Version: 1,
				Scope:    warrant.Scope{ChainID: *chain, Vault: *vault, Token: *token},
				Validity: warrant.Validity{After: ps.Unix(), Until: pe.Add(7 * 24 * time.Hour).Unix()},
				LeaseID:  pocc.Hex(pocc.LeaseID(q)), Ceiling: *ceiling, MaxNote: *maxNote, BatchSize: 24,
				Delivery: warrant.Delivery{Kind: warrant.KindSignedUsage, MeterKey: *meter, Unit: warrant.UnitInstanceSecond,
					PricePerUnit: *price, MinUptimeBP: uint16(*minUptime), MeterSpec: pocc.Hex(ms),
					ServiceStart: ps.Unix(), ServiceEnd: pe.Unix(), PieceS: 3600, ChallengeTimeoutS: 300},
				Rule: json.RawMessage(*rule)}
			q.Policy, _ = json.MarshalIndent(p, "", "  ")
		}
		if _, err := warrant.Check(q); err != nil {
			log.Fatalf("policy does not match the request: %v", err)
		}
	}
	q.Sig, err = pocc.SignDoc(t.Signing, pocc.TagRequest, q)
	must(err)
	must(jsonfile.Write(*out, q))
	fmt.Fprintf(os.Stderr, "request %s written to %s (lease %s)\n", q.RequestID, *out, pocc.Hex(pocc.LeaseID(q)))
}

func netsetup(args []string) {
	fs := flag.NewFlagSet("netsetup", flag.ExitOnError)
	name := fs.String("name", "pocc", "name prefix")
	cidr := fs.String("cidr", "10.42.0.0/24", "subnet CIDR")
	_ = fs.Parse(args)
	ctx := context.Background()
	c, err := openstack.FromEnv(ctx)
	must(err)
	var nets struct {
		Networks []struct {
			ID, Name string
			External bool `json:"router:external"`
		} `json:"networks"`
	}
	must(c.Do(ctx, "network", http.MethodGet, "/v2.0/networks", nil, &nets))
	ext, netID := "", ""
	for _, n := range nets.Networks {
		if n.External {
			ext = n.ID
		}
		if n.Name == *name+"-net" {
			netID = n.ID
		}
	}
	if ext == "" {
		log.Fatal("no external network found")
	}
	if netID == "" {
		var r struct{ Network struct{ ID string } }
		must(c.Do(ctx, "network", http.MethodPost, "/v2.0/networks", map[string]any{"network": map[string]any{"name": *name + "-net"}}, &r))
		netID = r.Network.ID
		var s struct{ Subnet struct{ ID string } }
		must(c.Do(ctx, "network", http.MethodPost, "/v2.0/subnets", map[string]any{"subnet": map[string]any{
			"name": *name + "-subnet", "network_id": netID, "ip_version": 4, "cidr": *cidr,
			"dns_nameservers": []string{"1.1.1.1", "8.8.8.8"}}}, &s))
		var rt struct{ Router struct{ ID string } }
		must(c.Do(ctx, "network", http.MethodPost, "/v2.0/routers", map[string]any{"router": map[string]any{
			"name": *name + "-router", "external_gateway_info": map[string]any{"network_id": ext}}}, &rt))
		must(c.Do(ctx, "network", http.MethodPut, "/v2.0/routers/"+rt.Router.ID+"/add_router_interface",
			map[string]any{"subnet_id": s.Subnet.ID}, nil))
		var sg struct {
			SecurityGroup struct{ ID string } `json:"security_group"`
		}
		must(c.Do(ctx, "network", http.MethodPost, "/v2.0/security-groups", map[string]any{"security_group": map[string]any{
			"name": *name + "-notary", "description": "PoCC notary HTTP"}}, &sg))
		must(c.Do(ctx, "network", http.MethodPost, "/v2.0/security-group-rules", map[string]any{"security_group_rule": map[string]any{
			"security_group_id": sg.SecurityGroup.ID, "direction": "ingress", "ethertype": "IPv4",
			"protocol": "tcp", "port_range_min": 8080, "port_range_max": 8080}}, nil))
	}
	fmt.Printf("network %s\nexternal %s\n", netID, ext)
}

const agentUnit = `[Unit]
Description=PoCC agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/pocc-agent -config /etc/pocc/agent.json
StandardOutput=journal+console
StandardError=journal+console
Restart=no
KillSignal=SIGTERM
TimeoutStopSec=90

[Install]
WantedBy=multi-user.target
`

const notaryUnit = `[Unit]
Description=PoCC notary
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/pocc-notary -listen :8080 -data /var/lib/pocc-notary
StandardOutput=journal+console
StandardError=journal+console
Restart=always

[Install]
WantedBy=multi-user.target
`

// cloudInit builds user data that fetches the pinned source, builds the
// binary on the VM, and starts it under systemd.
func cloudInit(role, ref, goVersion string, files map[string]string) string {
	var b strings.Builder
	b.WriteString("#cloud-config\nwrite_files:\n")
	for path, content := range files {
		fmt.Fprintf(&b, "  - path: %s\n    permissions: '0644'\n    encoding: b64\n    content: %s\n",
			path, base64.StdEncoding.EncodeToString([]byte(content)))
	}
	bin := "pocc-" + role
	b.WriteString("runcmd:\n")
	for _, cmd := range []string{
		fmt.Sprintf("curl -fsSL https://go.dev/dl/go%s.linux-amd64.tar.gz | tar -C /usr/local -xz", goVersion),
		fmt.Sprintf("mkdir -p /opt/pocc && curl -fsSL https://github.com/mnemonik-xyz/pocc/archive/%s.tar.gz | tar -C /opt/pocc --strip-components=1 -xz", ref),
		fmt.Sprintf("cd /opt/pocc && HOME=/root GOCACHE=/tmp/gocache GOFLAGS=-mod=mod /usr/local/go/bin/go build -o /usr/local/bin/%s ./cmd/%s", bin, bin),
		"systemctl daemon-reload",
		fmt.Sprintf("systemctl enable --now %s", bin),
	} {
		fmt.Fprintf(&b, "  - [sh, -c, %q]\n", cmd)
	}
	return b.String()
}

// gatewayInit runs Caddy as an HTTPS front for the notary, for operators
// whose own network allows only HTTPS to named hosts. tls internal uses
// Caddy's local CA; clients that cannot trust it need their own route.
func gatewayInit(host, backend string) string {
	return fmt.Sprintf(`#cloud-config
write_files:
  - path: /etc/caddy/Caddyfile
    content: |
      https://%s {
        tls internal
        reverse_proxy %s
      }
runcmd:
  - [sh, -c, "curl -fsSL https://github.com/caddyserver/caddy/releases/download/v2.8.4/caddy_2.8.4_linux_amd64.tar.gz | tar -C /usr/local/bin -xz caddy"]
  - [sh, -c, "nohup /usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile > /var/log/caddy.log 2>&1 &"]
`, host, backend)
}

func provision(args []string) {
	fs := flag.NewFlagSet("provision", flag.ExitOnError)
	role := fs.String("role", "agent", "agent or notary")
	name := fs.String("name", "", "server name (default: pocc-<role>)")
	flavor := fs.String("flavor", "d2.cpu1ram1", "flavor name (agent: must match the request)")
	image := fs.String("image", "", "Glance image ID (agent: must match the request)")
	network := fs.String("network", "", "network ID from netsetup")
	secgroup := fs.String("secgroup", "pocc-notary", "security group for the notary")
	volGB := fs.Int("volume-gb", 5, "boot volume size")
	ref := fs.String("ref", "main", "pocc git commit or branch to build on the VM")
	goVersion := fs.String("go", "1.24.7", "Go version to build with on the VM")
	backend := fs.String("backend", "", "gateway: notary private address, e.g. 10.42.0.190:8080")
	host := fs.String("host", "", "gateway: public hostname, e.g. 85-204-255-147.sslip.io")
	reqPath := fs.String("request", "request.json", "agent: signed request")
	escChain := fs.Uint64("escrow-chain-id", 0, "agent: chain ID of the escrow order")
	escAddr := fs.String("escrow", "", "agent: escrow contract address")
	escOrder := fs.String("escrow-order-id", "", "agent: 32-byte order id, hex")
	userDataOut := fs.String("user-data-out", "", "also write the user data to this file")
	_ = fs.Parse(args)
	if *image == "" || *network == "" {
		log.Fatal("-image and -network are required")
	}
	files := map[string]string{}
	switch *role {
	case "agent":
		var q pocc.Request
		must(jsonfile.Read(*reqPath, &q))
		if q.Resource.Flavor != *flavor || q.AllowedImage != *image {
			log.Fatal("flavor and image must match the request")
		}
		e := pocc.EscrowOrder{ChainID: *escChain, Escrow: *escAddr, OrderID: *escOrder}
		if _, err := pocc.EscrowBinding(q, e, beacon.Known); err != nil {
			log.Fatalf("escrow binding (-escrow-chain-id, -escrow, -escrow-order-id): %v", err)
		}
		cfg, _ := json.Marshal(map[string]any{"request": q, "escrow_order": e})
		files["/etc/pocc/agent.json"] = string(cfg)
		files["/etc/systemd/system/pocc-agent.service"] = agentUnit
	case "notary":
		files["/etc/systemd/system/pocc-notary.service"] = notaryUnit
	case "gateway":
		if *backend == "" || *host == "" {
			log.Fatal("gateway needs -backend and -host")
		}
	default:
		log.Fatal("-role must be agent, notary or gateway")
	}
	ud := cloudInit(*role, *ref, *goVersion, files)
	if *role == "gateway" {
		ud = gatewayInit(*host, *backend)
	}
	if *userDataOut != "" {
		must(os.WriteFile(*userDataOut, []byte(ud), 0o644))
	}
	if *name == "" {
		*name = "pocc-" + *role
	}
	ctx := context.Background()
	c, err := openstack.FromEnv(ctx)
	must(err)
	fid, err := c.FlavorID(ctx, *flavor)
	must(err)
	srv := map[string]any{"name": *name, "flavorRef": fid, "networks": []map[string]string{{"uuid": *network}},
		"user_data": base64.StdEncoding.EncodeToString([]byte(ud)), "config_drive": true,
		"block_device_mapping_v2": []map[string]any{{"boot_index": 0, "uuid": *image, "source_type": "image",
			"destination_type": "volume", "volume_size": *volGB, "delete_on_termination": true}}}
	if *role == "notary" || *role == "gateway" {
		srv["security_groups"] = []map[string]string{{"name": "default"}, {"name": *secgroup}}
	}
	var r struct{ Server struct{ ID string } }
	must(c.Do(ctx, "compute", http.MethodPost, "/servers", map[string]any{"server": srv}, &r))
	fmt.Println(r.Server.ID)
}

func fip(args []string) {
	fs := flag.NewFlagSet("fip", flag.ExitOnError)
	server := fs.String("server", "", "server ID")
	allocate := fs.Bool("allocate-only", false, "allocate a floating IP without a port; prints \"ip id\"")
	existing := fs.String("id", "", "associate this existing floating IP ID instead of allocating")
	_ = fs.Parse(args)
	ctx := context.Background()
	c, err := openstack.FromEnv(ctx)
	must(err)
	if *allocate {
		var nets struct {
			Networks []struct{ ID string } `json:"networks"`
		}
		must(c.Do(ctx, "network", http.MethodGet, "/v2.0/networks?router:external=true", nil, &nets))
		if len(nets.Networks) == 0 {
			log.Fatal("no external network")
		}
		var f struct {
			FloatingIP struct {
				ID      string `json:"id"`
				Address string `json:"floating_ip_address"`
			} `json:"floatingip"`
		}
		must(c.Do(ctx, "network", http.MethodPost, "/v2.0/floatingips", map[string]any{"floatingip": map[string]any{
			"floating_network_id": nets.Networks[0].ID}}, &f))
		fmt.Println(f.FloatingIP.Address, f.FloatingIP.ID)
		return
	}
	var ports struct{ Ports []struct{ ID string } }
	must(c.Do(ctx, "network", http.MethodGet, "/v2.0/ports?device_id="+*server, nil, &ports))
	if len(ports.Ports) == 0 {
		log.Fatal("server has no port yet")
	}
	if *existing != "" {
		must(c.Do(ctx, "network", http.MethodPut, "/v2.0/floatingips/"+*existing,
			map[string]any{"floatingip": map[string]any{"port_id": ports.Ports[0].ID}}, nil))
		fmt.Println("associated", *existing)
		return
	}
	var nets struct {
		Networks []struct {
			ID       string
			External bool `json:"router:external"`
		} `json:"networks"`
	}
	must(c.Do(ctx, "network", http.MethodGet, "/v2.0/networks?router:external=true", nil, &nets))
	if len(nets.Networks) == 0 {
		log.Fatal("no external network")
	}
	var f struct {
		FloatingIP struct {
			Address string `json:"floating_ip_address"`
		} `json:"floatingip"`
	}
	must(c.Do(ctx, "network", http.MethodPost, "/v2.0/floatingips", map[string]any{"floatingip": map[string]any{
		"floating_network_id": nets.Networks[0].ID, "port_id": ports.Ports[0].ID}}, &f))
	fmt.Println(f.FloatingIP.Address)
}

func mkReceipt(args []string) {
	fs := flag.NewFlagSet("receipt", flag.ExitOnError)
	reqPath := fs.String("request", "request.json", "signed request")
	escChain := fs.Uint64("escrow-chain-id", 0, "chain ID of the escrow order")
	escAddr := fs.String("escrow", "", "escrow contract address")
	escOrder := fs.String("escrow-order-id", "", "32-byte order id, hex")
	k := fs.String("keys", "", "tenant key file: discloses the final usage counters (optional)")
	agentPub := fs.String("agent", "", "agent public key (from the boot proof)")
	serverID := fs.String("server", "", "Nova server ID")
	novaJSON := fs.String("nova-json", "", "read the Nova server record from this file instead of OpenStack")
	notaryURL := fs.String("notary-url", "", "read the notary here instead of the meter spec's URL (e.g. an HTTPS gateway)")
	insecure := fs.Bool("notary-insecure-tls", false, "accept a self-signed gateway certificate; notary data is verified by signature anyway")
	out := fs.String("out", "receipt.json", "output")
	_ = fs.Parse(args)
	var q pocc.Request
	must(jsonfile.Read(*reqPath, &q))
	esc := pocc.EscrowOrder{ChainID: *escChain, Escrow: *escAddr, OrderID: *escOrder}
	if _, err := pocc.EscrowBinding(q, esc, beacon.Known); err != nil {
		log.Fatalf("escrow binding (-escrow-chain-id, -escrow, -escrow-order-id): %v", err)
	}
	nURL := *notaryURL
	if nURL == "" {
		nURL = q.MeterSpec.NotaryURL
	}
	ctx := context.Background()
	src := receipt.NotaryClient{URL: nURL, Client: notaryHTTP(*insecure)}
	entries := src.Entries(*agentPub)
	if len(entries) == 0 {
		log.Fatal("notary has no entries for this agent")
	}
	nova := &pocc.NovaServer{}
	if *novaJSON != "" {
		must(jsonfile.Read(*novaJSON, nova))
	} else {
		c, err := openstack.FromEnv(ctx)
		must(err)
		s, err := c.GetServer(ctx, *serverID)
		must(err)
		img, err := c.ServerImageID(ctx, s)
		must(err)
		nova = &pocc.NovaServer{ID: s.ID, Flavor: s.Flavor.OriginalName, ImageID: img, Created: s.Created, Status: s.Status}
		ps, _ := time.Parse(time.RFC3339, q.Period.Start)
		pe, _ := time.Parse(time.RFC3339, q.Period.End)
		if secs, err := c.UsageSeconds(ctx, s.ID, ps, pe); err == nil {
			// For comparison with the verdict only; the receipt carries no bill.
			fmt.Fprintf(os.Stderr, "Nova's own usage meter: %d s\n", secs)
		}
	}
	var ops []pocc.Opening
	if *k != "" {
		t, err := keys.Load(*k)
		must(err)
		last := entries[len(entries)-1].Seq
		ops, err = receipt.Disclose(entries, t.Seal, []uint64{last}, pocc.UsageFields)
		if err != nil {
			fmt.Fprintf(os.Stderr, "no openings in the receipt (%v)\n", err)
			ops = nil
		}
	}
	R, err := receipt.Assemble(q, esc, src, *agentPub, nova, ops)
	must(err)
	must(jsonfile.Write(*out, R))
	fmt.Fprintf(os.Stderr, "receipt with %d heartbeat(s) written to %s\n", len(R.Heartbeats), *out)
}

func image(args []string) {
	fs := flag.NewFlagSet("image", flag.ExitOnError)
	name := fs.String("name", "debian-13-genericcloud-amd64-20260723", "image name")
	_ = fs.Parse(args)
	ctx := context.Background()
	c, err := openstack.FromEnv(ctx)
	must(err)
	var r struct{ Images []struct{ ID string } }
	must(c.Do(ctx, "image", http.MethodGet, "/v2/images?name="+url.QueryEscape(*name), nil, &r))
	if len(r.Images) == 0 {
		log.Fatalf("image %q not found", *name)
	}
	fmt.Println(r.Images[0].ID)
}

func pause(args []string) {
	fs := flag.NewFlagSet("pause", flag.ExitOnError)
	server := fs.String("server", "", "server ID")
	resume := fs.Bool("resume", false, "unpause instead")
	_ = fs.Parse(args)
	ctx := context.Background()
	c, err := openstack.FromEnv(ctx)
	must(err)
	action := map[string]any{"pause": nil}
	if *resume {
		action = map[string]any{"unpause": nil}
	}
	must(c.Do(ctx, "compute", http.MethodPost, "/servers/"+*server+"/action", action, nil))
}

// down deletes the servers named <name>-*, their floating IPs, and the router,
// subnet, network and security group that netsetup created.
func down(args []string) {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	name := fs.String("name", "pocc", "name prefix used by netsetup and provision")
	_ = fs.Parse(args)
	ctx := context.Background()
	c, err := openstack.FromEnv(ctx)
	must(err)
	warn := func(err error) {
		if err != nil {
			log.Print(err)
		}
	}
	var srv struct{ Servers []struct{ ID, Name string } }
	must(c.Do(ctx, "compute", http.MethodGet, "/servers", nil, &srv))
	var ids []string
	for _, s := range srv.Servers {
		if strings.HasPrefix(s.Name, *name+"-") {
			ids = append(ids, s.ID)
			var fips struct {
				FloatingIPs []struct {
					ID string `json:"id"`
				} `json:"floatingips"`
			}
			var ports struct{ Ports []struct{ ID string } }
			warn(c.Do(ctx, "network", http.MethodGet, "/v2.0/ports?device_id="+s.ID, nil, &ports))
			for _, p := range ports.Ports {
				warn(c.Do(ctx, "network", http.MethodGet, "/v2.0/floatingips?port_id="+p.ID, nil, &fips))
				for _, f := range fips.FloatingIPs {
					warn(c.Do(ctx, "network", http.MethodDelete, "/v2.0/floatingips/"+f.ID, nil, nil))
					fmt.Println("deleted floating IP", f.ID)
				}
			}
			warn(c.Do(ctx, "compute", http.MethodDelete, "/servers/"+s.ID, nil, nil))
			fmt.Println("deleting server", s.Name, s.ID)
		}
	}
	for _, id := range ids {
		for i := 0; i < 60; i++ {
			if _, err := c.GetServer(ctx, id); errors.Is(err, openstack.ErrNotFound) {
				break
			}
			time.Sleep(5 * time.Second)
		}
	}
	type named struct{ ID, Name string }
	var routers struct{ Routers []named }
	var subnets struct{ Subnets []named }
	var nets struct{ Networks []named }
	var sgs struct {
		SGs []named `json:"security_groups"`
	}
	warn(c.Do(ctx, "network", http.MethodGet, "/v2.0/subnets", nil, &subnets))
	warn(c.Do(ctx, "network", http.MethodGet, "/v2.0/routers", nil, &routers))
	for _, r := range routers.Routers {
		if r.Name != *name+"-router" {
			continue
		}
		for _, sn := range subnets.Subnets {
			if sn.Name == *name+"-subnet" {
				warn(c.Do(ctx, "network", http.MethodPut, "/v2.0/routers/"+r.ID+"/remove_router_interface",
					map[string]any{"subnet_id": sn.ID}, nil))
			}
		}
		warn(c.Do(ctx, "network", http.MethodDelete, "/v2.0/routers/"+r.ID, nil, nil))
		fmt.Println("deleted router", r.ID)
	}
	warn(c.Do(ctx, "network", http.MethodGet, "/v2.0/networks", nil, &nets))
	for _, n := range nets.Networks {
		if n.Name == *name+"-net" {
			warn(c.Do(ctx, "network", http.MethodDelete, "/v2.0/networks/"+n.ID, nil, nil))
			fmt.Println("deleted network", n.ID)
		}
	}
	warn(c.Do(ctx, "network", http.MethodGet, "/v2.0/security-groups", nil, &sgs))
	for _, g := range sgs.SGs {
		if g.Name == *name+"-notary" {
			warn(c.Do(ctx, "network", http.MethodDelete, "/v2.0/security-groups/"+g.ID, nil, nil))
			fmt.Println("deleted security group", g.ID)
		}
	}
}

func notaryHTTP(insecure bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // transport only; content is signed
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: tr}
}

func ip(args []string) {
	fs := flag.NewFlagSet("ip", flag.ExitOnError)
	server := fs.String("server", "", "server ID")
	_ = fs.Parse(args)
	ctx := context.Background()
	c, err := openstack.FromEnv(ctx)
	must(err)
	s, err := c.GetServer(ctx, *server)
	must(err)
	for _, addrs := range s.Addresses {
		for _, a := range addrs {
			fmt.Println(a.Addr)
			return
		}
	}
	log.Fatal("server has no address yet")
}
