// Command pocc-verify checks a receipt (spec 5), prints the verdict, and with
// -meter-keys signs one usage record per hour for Warrant's signed_usage check.
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
	"github.com/mnemonik-xyz/pocc/pkg/anchor"
	"github.com/mnemonik-xyz/pocc/pkg/beacon"
	"github.com/mnemonik-xyz/pocc/pkg/pocc"
	"github.com/mnemonik-xyz/pocc/pkg/receipt"
	"github.com/mnemonik-xyz/pocc/pkg/verify"
)

func main() {
	in := flag.String("receipt", "receipt.json", "receipt to verify")
	out := flag.String("out", "-", "where to write the verdict")
	anchorKey := flag.String("anchor-key", "", "trusted dev anchor key (default: the order's, with a warning)")
	providerKey := flag.String("provider-key", "", "pin the provider's public key")
	notaryURL := flag.String("notary", "", "optional notary URL for fork checks")
	insecure := flag.Bool("notary-insecure-tls", false, "accept a self-signed gateway certificate for the fork check")
	meterKeys := flag.String("meter-keys", "", "key file of the policy's meter key; signs usage records")
	recordsOut := flag.String("records", "usage-records.json", "where to write usage records")
	flag.Parse()
	log.SetFlags(0)

	var R pocc.Receipt
	if err := jsonfile.Read(*in, &R); err != nil {
		log.Fatal(err)
	}
	if R.Order.Beacon.ChainHash != beacon.Quicknet.ChainHash {
		log.Fatalf("order names beacon %s; this verifier trusts drand quicknet only", R.Order.Beacon.ChainHash)
	}
	ak := *anchorKey
	if ak == "" {
		ak = R.Order.Notary.AnchorKey
		fmt.Fprintln(os.Stderr, "warning: using the anchor key named in the order; pass -anchor-key to pin it")
	}
	env := verify.Env{Beacon: beacon.NewHTTP(beacon.Quicknet), Anchors: anchor.DevChecker{PubKey: ak},
		ProviderKey: *providerKey}
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
	fmt.Fprintf(os.Stderr, "%s, assurance %s: credited %d s, %d gap(s), max amount %d micros, codes %v\n",
		v.Status, v.Assurance, v.CreditedS, v.Gaps, v.MaxAmountMicros, v.Codes)

	if *meterKeys != "" {
		k, err := keys.Load(*meterKeys)
		if err != nil {
			log.Fatal(err)
		}
		if R.Request.Policy == nil || R.Request.Policy.Delivery.MeterKey != k.File.SigningPub {
			log.Fatal("this key is not the meter key named in the policy")
		}
		recs, err := verify.UsageRecords(&R, v, func(x any) (string, error) {
			return pocc.SignDoc(k.Signing, pocc.TagUsageRecord, x)
		})
		if err != nil {
			log.Fatal(err)
		}
		if err := jsonfile.Write(*recordsOut, recs); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "%d usage record(s) written to %s\n", len(recs), *recordsOut)
		pol := R.Request.Policy
		for _, rec := range recs {
			ok, err := verify.DryRunRule(pol.Rule, rec, pol.Delivery.PricePerUnit)
			decision := "Deny"
			if err != nil {
				decision = "Error: " + err.Error()
			} else if ok {
				decision = "Allow"
			}
			fmt.Fprintf(os.Stderr, "  window %s: %d s, uptime %d bp, assurance %s -> rule dry run: %s\n",
				time.Unix(rec.WindowStart, 0).UTC().Format("2006-01-02 15:04"), rec.Units, rec.UptimeBP, rec.Assurance, decision)
		}
	}
	if v.Status == verify.StatusInvalid {
		os.Exit(2)
	}
}
