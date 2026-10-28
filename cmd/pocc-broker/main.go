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
		"keygen": keygen, "request": request, "order": order, "netsetup": netsetup,
		"provision": provision, "fip": fip, "receipt": mkReceipt, "settle": settle,
		"image": image, "pause": pause, "down": down, "ip": ip,
	}
	f, ok := cmds[os.Args[1]]
	if !ok {
		usage()
	}
	f(os.Args[2:])
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pocc-broker keygen|request|order|netsetup|provision|fip|receipt|settle|image|pause|down [flags]")
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
	start := fs.String("start", "", "period start, RFC 3339")
	end := fs.String("end", "", "period end, RFC 3339")
	price := fs.Int64("price", 0, "agreed price in currency micro-units per second")
	currency := fs.String("currency", "EUR", "currency")
	meter := fs.String("meter-pub", "", "meter public key named in the policy (the tenant's verifier)")
	chain := fs.String("chain-id", "", "escrow chain ID")
	vault := fs.String("vault", "", "escrow address")
	token := fs.String("token", "", "token address")
	rule := fs.String("rule", `{"all":[{"assurance_at_least":"L0"},{"uptime_at_least_bp":9500}]}`, "Warrant rule tree")
	out := fs.String("out", "request.json", "output")
	_ = fs.Parse(args)
	t, err := keys.Load(*k)
	must(err)
	ps, err := time.Parse(time.RFC3339, *start)
	must(err)
	pe, err := time.Parse(time.RFC3339, *end)
	must(err)
	if *image == "" || *price <= 0 || *meter == "" {
		log.Fatal("-image, -price and -meter-pub are required")
	}
	if !json.Valid([]byte(*rule)) {
		log.Fatal("-rule is not valid JSON")
	}
	if *id == "" {
		*id = fmt.Sprintf("req-%d", time.Now().Unix())
	}
	q := pocc.Request{Version: pocc.Version, RequestID: *id,
		Resource:      pocc.Resource{Flavor: *flavor, VCPUs: *vcpus, RAMMB: *ram},
		Period:        pocc.Period{Start: ps.UTC().Format(time.RFC3339), End: pe.UTC().Format(time.RFC3339)},
		MaxRateMicros: *price, Currency: *currency, Attestation: pocc.AttestationNone, AllowedImage: *image,
		TenantPubKey: t.File.SigningPub, TenantSealKey: t.File.SealPub,
		Policy: &pocc.RentPolicy{Case: "rent", Version: 1,
			Scope:    pocc.PolicyScope{ChainID: *chain, Vault: *vault, Token: *token},
			Validity: pocc.PolicyValidity{After: ps.Unix(), Until: pe.Add(7 * 24 * time.Hour).Unix()},
			Delivery: pocc.Delivery{Kind: pocc.DeliveryKindSignedUsage, MeterKey: *meter, Unit: "instance-second",
				PricePerUnit: *price, PoCC: pocc.DeliveryPoCC{Format: pocc.Version, Attestation: pocc.AttestationNone,
					AllowedImage: *image, Flavor: *flavor, BeaconChainHash: beacon.Quicknet.ChainHash,
					SlotRounds: 20, BracketS: 30, Anchor: anchor.KindDevFile}},
			Rule: json.RawMessage(*rule)}}
	q.Sig, err = pocc.SignDoc(t.Signing, pocc.TagRequest, q)
	must(err)
	must(jsonfile.Write(*out, q))
	fmt.Fprintf(os.Stderr, "request %s written to %s\n", q.RequestID, *out)
}

func order(args []string) {
	fs := flag.NewFlagSet("order", flag.ExitOnError)
	reqPath := fs.String("request", "request.json", "signed request")
	k := fs.String("keys", "provider.json", "provider key file")
	id := fs.String("id", "", "order ID (default: generated)")
	notaryURL := fs.String("notary", "", "notary URL reachable from the VM")
	anchorKey := fs.String("anchor-key", "", "notary's dev anchor key (GET /v0/info)")
	out := fs.String("out", "order.json", "output")
	_ = fs.Parse(args)
	var q pocc.Request
	must(jsonfile.Read(*reqPath, &q))
	must(pocc.VerifyDoc(q.TenantPubKey, pocc.TagRequest, q, q.Sig))
	if q.Policy == nil {
		log.Fatal("request carries no policy")
	}
	p, err := keys.Load(*k)
	must(err)
	if *notaryURL == "" {
		log.Fatal("-notary is required")
	}
	rh, err := pocc.DocHash(pocc.TagRequest, q)
	must(err)
	if *id == "" {
		*id = fmt.Sprintf("ord-%d", time.Now().Unix())
	}
	o := pocc.Order{Version: pocc.Version, OrderID: *id, RequestHash: pocc.Hex(rh),
		RateMicros: q.Policy.Delivery.PricePerUnit, Currency: q.Currency, Beacon: beacon.Quicknet,
		Notary: pocc.NotaryInfo{URL: *notaryURL, AnchorKey: *anchorKey}, SlotRounds: 20, BracketS: 30,
		ProviderPubKey: p.File.SigningPub, ProviderSealKey: p.File.SealPub}
	o.Sig, err = pocc.SignDoc(p.Signing, pocc.TagOrder, o)
	must(err)
	must(jsonfile.Write(*out, o))
	h0, _ := pocc.DocHash(pocc.TagOrder, o)
	fmt.Fprintf(os.Stderr, "order %s written to %s, h0 %s\n", o.OrderID, *out, pocc.Hex(h0))
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
	ordPath := fs.String("order", "order.json", "agent: signed order")
	userDataOut := fs.String("user-data-out", "", "also write the user data to this file")
	_ = fs.Parse(args)
	if *image == "" || *network == "" {
		log.Fatal("-image and -network are required")
	}
	files := map[string]string{}
	switch *role {
	case "agent":
		var q pocc.Request
		var o pocc.Order
		must(jsonfile.Read(*reqPath, &q))
		must(jsonfile.Read(*ordPath, &o))
		if q.Resource.Flavor != *flavor || q.AllowedImage != *image {
			log.Fatal("flavor and image must match the request")
		}
		cfg, _ := json.Marshal(map[string]any{"request": q, "order": o})
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
	ordPath := fs.String("order", "order.json", "signed order")
	k := fs.String("keys", "provider.json", "provider key file")
	agentPub := fs.String("agent", "", "agent public key (from the boot proof)")
	serverID := fs.String("server", "", "Nova server ID")
	billed := fs.Int64("billed-seconds", -1, "seconds to bill (default: Nova's own usage meter)")
	novaJSON := fs.String("nova-json", "", "offline: read the Nova server record from this file instead of OpenStack")
	notaryURL := fs.String("notary-url", "", "read the notary here instead of the order's URL (e.g. an HTTPS gateway)")
	insecure := fs.Bool("notary-insecure-tls", false, "accept a self-signed gateway certificate; notary data is verified by signature anyway")
	out := fs.String("out", "receipt.json", "output")
	_ = fs.Parse(args)
	var q pocc.Request
	var o pocc.Order
	must(jsonfile.Read(*reqPath, &q))
	must(jsonfile.Read(*ordPath, &o))
	p, err := keys.Load(*k)
	must(err)
	ctx := context.Background()
	src := receipt.NotaryClient{URL: o.Notary.URL, Client: notaryHTTP(*insecure)}
	if *notaryURL != "" {
		src.URL = *notaryURL
	}
	entries := src.Entries(*agentPub)
	if len(entries) == 0 {
		log.Fatal("notary has no entries for this agent")
	}
	nova := &pocc.NovaServer{}
	secs := *billed
	if *novaJSON != "" {
		must(jsonfile.Read(*novaJSON, nova))
		if secs < 0 {
			log.Fatal("-billed-seconds is required with -nova-json")
		}
	} else {
		c, err := openstack.FromEnv(ctx)
		must(err)
		s, err := c.GetServer(ctx, *serverID)
		must(err)
		img, err := c.ServerImageID(ctx, s)
		must(err)
		nova = &pocc.NovaServer{ID: s.ID, Flavor: s.Flavor.OriginalName, ImageID: img, Created: s.Created, Status: s.Status}
		if secs < 0 {
			ps, _ := time.Parse(time.RFC3339, q.Period.Start)
			pe, _ := time.Parse(time.RFC3339, q.Period.End)
			secs, err = c.UsageSeconds(ctx, s.ID, ps, pe)
			must(err)
			fmt.Fprintf(os.Stderr, "Nova's usage meter: %d s\n", secs)
		}
	}
	last := entries[len(entries)-1].Seq
	ops, err := receipt.Disclose(entries, p.Seal, []uint64{last}, pocc.UsageFields)
	must(err)
	R, err := receipt.Assemble(q, o, src, *agentPub, nova,
		pocc.Billed{Seconds: secs, AmountMicros: secs * o.RateMicros}, ops, p.Signing)
	must(err)
	must(jsonfile.Write(*out, R))
	fmt.Fprintf(os.Stderr, "receipt with %d heartbeat(s) written to %s\n", len(R.Heartbeats), *out)
}

func settle(args []string) {
	fs := flag.NewFlagSet("settle", flag.ExitOnError)
	rPath := fs.String("receipt", "receipt.json", "receipt")
	vPath := fs.String("verdict", "verdict.json", "verdict")
	k := fs.String("keys", "tenant.json", "tenant key file")
	out := fs.String("out", "settlement.json", "output")
	_ = fs.Parse(args)
	var R pocc.Receipt
	var v pocc.Verdict
	must(jsonfile.Read(*rPath, &R))
	must(jsonfile.Read(*vPath, &v))
	t, err := keys.Load(*k)
	must(err)
	rh, _ := pocc.DocHash(pocc.TagReceipt, R)
	if pocc.Hex(rh) != v.ReceiptHash {
		log.Fatal("verdict is for a different receipt")
	}
	vh, _ := pocc.DocHash(pocc.TagVerdict, v)
	s := pocc.Settlement{Version: pocc.Version, ReceiptHash: v.ReceiptHash, VerdictHash: pocc.Hex(vh), Decision: "accept"}
	if v.Status == "INVALID" {
		s.Decision, s.Codes = "dispute", v.Codes
	}
	s.Sig, err = pocc.SignDoc(t.Signing, pocc.TagSettlement, s)
	must(err)
	must(jsonfile.Write(*out, s))
	fmt.Fprintf(os.Stderr, "%s written to %s\n", s.Decision, *out)
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
