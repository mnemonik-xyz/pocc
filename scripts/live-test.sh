#!/usr/bin/env bash
# Reproducible Stage 0 live test on an OpenStack project (spec section 8).
#
# Usage: scripts/live-test.sh <phase> [phase...]
#   up        build binaries, create keys, network, notary VM + floating IP,
#             and an HTTPS gateway VM (for operators whose egress is HTTPS-only)
#   order     tenant request with the Warrant rent policy, provider order
#   agent     boot the agent VM (must precede PERIOD_START by a few minutes)
#   status    show the agent's log tail and its anchored entries
#   pause     provider pauses the agent VM (scenario L3), resume with "resume"
#   receipt   two receipts: billed by Nova's own meter, and billed = credited
#   verify    verify both, sign hourly usage records, settle
#   down      delete every resource this script created
#
# Required environment: OS_AUTH_URL OS_USERNAME OS_PASSWORD OS_PROJECT_ID
#   OS_USER_DOMAIN_NAME OS_REGION_NAME, PERIOD_START and PERIOD_END (RFC 3339 UTC).
# Optional: STATE (default ./live-run), REF (pocc commit built on the VMs),
#   IMAGE_NAME, FLAVOR, PRICE (micro-units per second), GATEWAY=0 to skip it.
#
# The state directory holds keys: never commit it. Copy results/ only.
set -euo pipefail

STATE=${STATE:-./live-run}
REF=${REF:-$(git rev-parse HEAD)}
IMAGE_NAME=${IMAGE_NAME:-debian-13-genericcloud-amd64-20260723}
FLAVOR=${FLAVOR:-d2.cpu1ram1}
PRICE=${PRICE:-1100}
GATEWAY=${GATEWAY:-1}
REPO=$(cd "$(dirname "$0")/.." && pwd)
B="$STATE/bin"

mkdir -p "$STATE/results"
cd "$STATE"
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }

console() { # console <server-id-file> : print the VM's serial console
  python3 - "$1" <<'PY'
import json, os, sys, urllib.request
def req(url, body=None, token=None, method=None):
    h = {"Content-Type": "application/json"}
    if token: h["X-Auth-Token"] = token
    r = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, headers=h, method=method)
    return urllib.request.urlopen(r, timeout=60)
auth = {"auth": {"identity": {"methods": ["password"], "password": {"user": {"name": os.environ["OS_USERNAME"],
        "domain": {"name": os.environ.get("OS_USER_DOMAIN_NAME", "Default")}, "password": os.environ["OS_PASSWORD"]}}},
        "scope": {"project": {"id": os.environ["OS_PROJECT_ID"]}}}}
r = req(os.environ["OS_AUTH_URL"].rstrip("/") + "/auth/tokens", auth)
tok = r.headers["X-Subject-Token"]
cat = json.load(r)["token"]["catalog"]
nova = [e["url"] for s in cat if s["type"] == "compute" for e in s["endpoints"]
        if e["interface"] == "public" and e["region"] == os.environ.get("OS_REGION_NAME", e["region"])][0]
sid = open(sys.argv[1]).read().strip()
out = json.load(req(f"{nova}/servers/{sid}/action", {"os-getConsoleOutput": {}}, tok))["output"]
print(out)
PY
}

agent_key() { console agent-id | grep -o 'booted: agent [^,]*' | tail -1 | awk '{print $3}'; }
notary_url() { if [ -f gw-host ]; then echo "https://$(cat gw-host)"; else echo "http://$(cat notary-fip)"; fi; }
curl_n() { if [ "$GATEWAY" = 1 ]; then curl -sfk -m 20 "$@"; else curl -sf -m 20 "$@"; fi; }

phase_up() {
  log "build binaries from $REPO"
  (cd "$REPO" && go build -o "$OLDPWD/bin/" ./cmd/...)
  for p in tenant provider meter; do [ -f "$p.json" ] || "$B/pocc-broker" keygen -out "$p.json" >/dev/null; done
  "$B/pocc-broker" image -name "$IMAGE_NAME" > image
  "$B/pocc-broker" netsetup > net.txt
  awk '/^network/{print $2}' net.txt > net
  log "notary VM (builds $REF)"
  "$B/pocc-broker" provision -role notary -name pocc-notary -flavor "$FLAVOR" -image "$(cat image)" \
    -network "$(cat net)" -ref "$REF" > notary-id
  sleep 30
  "$B/pocc-broker" fip -server "$(cat notary-id)" > notary-fip
  log "notary public address $(cat notary-fip)"
  if [ "$GATEWAY" = 1 ]; then
    read -r gwip gwid < <("$B/pocc-broker" fip -allocate-only)
    echo "${gwip//./-}.sslip.io" > gw-host
    local priv
    priv=$("$B/pocc-broker" ip -server "$(cat notary-id)")
    "$B/pocc-broker" provision -role gateway -name pocc-gw -flavor "$FLAVOR" -image "$(cat image)" \
      -network "$(cat net)" -backend "$priv:8080" -host "$(cat gw-host)" -volume-gb 3 > gw-id
    sleep 30
    "$B/pocc-broker" fip -server "$(cat gw-id)" -id "$gwid"
    log "gateway https://$(cat gw-host)"
  fi
  log "waiting for the notary"
  until curl_n "$(notary_url)/v0/info" > notary-info.json; do sleep 10; done
  python3 -c "import json;print(json.load(open('notary-info.json'))['anchor_key'])" > anchor-key
  log "notary up, anchor key $(cat anchor-key)"
}

phase_order() {
  : "${PERIOD_START:?}" "${PERIOD_END:?}"
  local meter
  meter=$(python3 -c "import json;print(json.load(open('meter.json'))['signing_pub'])")
  "$B/pocc-broker" request -keys tenant.json -id "req-$(date -u +%Y%m%d%H%M)" -image "$(cat image)" -flavor "$FLAVOR" \
    -start "$PERIOD_START" -end "$PERIOD_END" -price "$PRICE" -meter-pub "$meter" \
    -chain-id live-dev -vault none -token none -out request.json
  "$B/pocc-broker" order -request request.json -keys provider.json -id "ord-$(date -u +%Y%m%d%H%M)" \
    -notary "http://$(cat notary-fip):8080" -anchor-key "$(cat anchor-key)" -out order.json
}

phase_agent() {
  "$B/pocc-broker" provision -role agent -name pocc-agent -flavor "$FLAVOR" -image "$(cat image)" \
    -network "$(cat net)" -ref "$REF" -request request.json -order order.json > agent-id
  log "agent VM $(cat agent-id); it boots on the first 60 s slot after its build"
}

phase_status() {
  console agent-id | grep -E 'booted|heartbeat|final|waiting|slot' | tail -5 || true
  local k; k=$(agent_key)
  [ -n "$k" ] && curl_n "$(notary_url)/v0/entries?agent=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$k")" \
    | python3 -c "import json,sys;e=json.load(sys.stdin) or [];print(len(e),'entries, last seq',e[-1]['seq'] if e else '-')"
}

phase_pause()  { "$B/pocc-broker" pause -server "$(cat agent-id)"; log "agent VM paused"; }
phase_resume() { "$B/pocc-broker" pause -server "$(cat agent-id)" -resume; log "agent VM resumed"; }

phase_receipt() {
  local k; k=$(agent_key)
  [ -n "$k" ] || { echo "agent key not found on the console" >&2; exit 1; }
  echo "$k" > agent-key
  local tls=(); [ "$GATEWAY" = 1 ] && tls=(-notary-insecure-tls)
  log "receipt A: billed by Nova's own usage meter"
  "$B/pocc-broker" receipt -agent "$k" -server "$(cat agent-id)" -notary-url "$(notary_url)" "${tls[@]}" \
    -out results/receipt-nova.json
  "$B/pocc-verify" -receipt results/receipt-nova.json -anchor-key "$(cat anchor-key)" -out results/verdict-nova.json || true
  local credited
  credited=$(python3 -c "import json;print(json.load(open('results/verdict-nova.json'))['credited_s'])")
  log "receipt B: billed = credited ($credited s)"
  "$B/pocc-broker" receipt -agent "$k" -server "$(cat agent-id)" -notary-url "$(notary_url)" "${tls[@]}" \
    -billed-seconds "$credited" -out results/receipt.json
}

phase_verify() {
  local tls=(); [ "$GATEWAY" = 1 ] && tls=(-notary-insecure-tls)
  "$B/pocc-verify" -receipt results/receipt.json -anchor-key "$(cat anchor-key)" -notary "$(notary_url)" "${tls[@]}" \
    -meter-keys meter.json -records results/usage-records.json -out results/verdict.json || true
  "$B/pocc-broker" settle -receipt results/receipt.json -verdict results/verdict.json -keys tenant.json \
    -out results/settlement.json
  cp request.json order.json results/
}

phase_down() { "$B/pocc-broker" down -name pocc; [ -f gw-id ] || true; log "resources deleted"; }

[ $# -gt 0 ] || { sed -n '2,22p' "$0"; exit 2; }
for p in "$@"; do "phase_$p"; done
