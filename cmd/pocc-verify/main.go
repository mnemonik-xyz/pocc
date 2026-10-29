// Command pocc-verify checks a receipt (spec 5), prints the verdict, and
// writes one usage record per hour: PoCC-native records (signed with a PoCC
// meter key when given), and Warrant records through the adapter when the
// request carries a Warrant policy. Warrant records are signed by Warrant's
// own tool, invoked as an external command, never by PoCC.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/mnemonik-xyz/pocc/internal/jsonfile"
	"github.com/mnemonik-xyz/pocc/internal/keys"
	"github.com/mnemonik-xyz/pocc/pkg/adapter/warrant"
	"github.com/mnemonik-xyz/pocc/pkg/anchor"
	"github.com/mnemonik-xyz/pocc/pkg/beacon"
	"github.com/mnemonik-xyz/pocc/pkg/pocc"
	"github.com/mnemonik-xyz/pocc/pkg/receipt"
	"github.com/mnemonik-xyz/pocc/pkg/verify"
)

func main() {
	in := flag.String("receipt", "receipt.json", "receipt to verify")
	out := flag.String("out", "-", "where to write the verdict")
	anchorKey := flag.String("anchor-key", "", "trusted dev anchor key (default: the order's or the meter spec's, with a warning)")
	providerKey := flag.String("provider-key", "", "pin the provider's public key (required for the receipt signature in escrow mode)")
	notaryURL := flag.String("notary", "", "optional notary URL for fork checks")
	insecure := flag.Bool("notary-insecure-tls", false, "accept a self-signed gateway certificate for the fork check")
	meterKeys := flag.String("meter-keys", "", "PoCC key file; signs the PoCC-native usage records")
	recordsOut := flag.String("records", "usage-records.json", "where to write PoCC-native usage records")
	warrantOut := flag.String("warrant-records", "", "write Warrant-shaped usage records here (needs a Warrant policy in the request)")
	signCmd := flag.String("warrant-sign-cmd", "", "external signer template, e.g. \"warrant-evidence sign-usage {key} {in} {out}\"")
	signKey := flag.String("warrant-sign-key", "", "key path substituted for {key}")
	signDir := flag.String("warrant-sign-dir", "warrant-records", "directory for per-record files when signing")
	flag.Parse()
	log.SetFlags(0)

	var R pocc.Receipt
	if err := jsonfile.Read(*in, &R); err != nil {
		log.Fatal(err)
	}
	chainHash := R.Order.Beacon.ChainHash
	if R.EscrowOrder != nil && R.Request.MeterSpec != nil {
		chainHash = R.Request.MeterSpec.BeaconChainHash
	}
	if chainHash != beacon.Quicknet.ChainHash {
		log.Fatalf("beacon %s named; this verifier trusts drand quicknet only", chainHash)
	}
	ak := *anchorKey
	if ak == "" {
		if R.EscrowOrder != nil && R.Request.MeterSpec != nil {
			ak = R.Request.MeterSpec.Anchor.AnchorKey
			fmt.Fprintln(os.Stderr, "warning: using the anchor key named in the tenant-signed meter spec; pass -anchor-key to pin it")
		} else {
			ak = R.Order.Notary.AnchorKey
			fmt.Fprintln(os.Stderr, "warning: using the anchor key named in the order; pass -anchor-key to pin it")
		}
	}
	env := verify.Env{Beacon: beacon.NewHTTP(beacon.Quicknet), Anchors: anchor.DevChecker{PubKey: ak},
		ProviderKey: *providerKey, KnownBeacons: beacon.Known}
	if *notaryURL != "" {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if *insecure {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // transport only
		}
		env.Forks = receipt.NotaryClient{URL: *notaryURL, Client: &http.Client{Timeout: 20 * time.Second, Transport: tr}}
	}
	v := verify.Verify(context.Background(), &R, env)
	if err := jsonfile.Write(*out, v); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "%s, assurance %s: credited %d s, %d gap(s), %d late, max amount %d micros, codes %v\n",
		v.Status, v.Assurance, v.CreditedS, v.Gaps, v.Late, v.MaxAmountMicros, v.Codes)

	var sign func(any) (string, error)
	if *meterKeys != "" {
		k, err := keys.Load(*meterKeys)
		if err != nil {
			log.Fatal(err)
		}
		sign = func(x any) (string, error) { return pocc.SignDoc(k.Signing, pocc.TagUsageRecord, x) }
	}
	recs, err := verify.UsageRecords(&R, v, sign)
	if err != nil {
		log.Fatal(err)
	}
	if err := jsonfile.Write(*recordsOut, recs); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "%d usage record(s) written to %s\n", len(recs), *recordsOut)

	if *warrantOut != "" {
		if R.Request.Consumer != pocc.ConsumerWarrant {
			log.Fatal("the request carries no Warrant policy")
		}
		wr, err := warrant.Records(R.Request, recs)
		if err != nil {
			log.Fatal(err)
		}
		if err := jsonfile.Write(*warrantOut, wr); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "%d Warrant usage record(s) written to %s\n", len(wr), *warrantOut)
		pol, err := warrant.Parse(R.Request.Policy)
		if err == nil {
			for _, r := range wr {
				uptime := r.Units * 10000 / (r.WindowEnd - r.WindowStart)
				verdict := "would pass D5-D7"
				if uptime < uint64(pol.Delivery.MinUptimeBP) || r.Assurance < pol.Delivery.MinAssurance {
					verdict = "would be denied: below the policy's floors"
				}
				fmt.Fprintf(os.Stderr, "  hour %d: %d s, uptime %d bp, assurance %d -> %s\n",
					r.FirstIndex, r.Units, uptime, r.Assurance, verdict)
			}
		}
		if *signCmd != "" {
			signed, err := warrant.SignExternal(*signDir, *signCmd, *signKey, wr)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintf(os.Stderr, "%d record(s) signed by the external signer into %s\n", len(signed), *signDir)
		}
	}
	if v.Status == verify.StatusInvalid {
		os.Exit(2)
	}
}
