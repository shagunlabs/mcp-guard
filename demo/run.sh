#!/usr/bin/env bash
# One-command Sentryra demo: ./demo/run.sh   (or: make demo)
# Local only: generates throwaway keys under demo/.run, no network, no accounts.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
echo "== build"; cargo build --release -q -p sentryra-edge -p sentryra-verify
EDGE=target/release/sentryra-edge; VERIFY=target/release/sentryra-verify; R=demo/.run
rm -rf "$R"; mkdir -p "$R"
$EDGE keygen "$R/keys" >/dev/null
cp spec/examples/connector-demo-db.json "$R/catalogue.json"; $EDGE sign-catalogue "$R/keys" "$R/catalogue.json" >/dev/null
NBF=$(date -u -d '-1 hour' +%Y-%m-%dT%H:%M:%SZ); EXP=$(date -u -d '+8 hour' +%Y-%m-%dT%H:%M:%SZ)
cat > "$R/mandate.json" <<J
{"mandate_id":"mdt_demo","spec":"sentryra.mandate/v0","tenant":"org_demo",
 "principal":{"id":"priya@acme.example"},"agent":{"id":"agt_support"},
 "purpose":"Answer support tickets using read-only lookups in the demo DB",
 "scopes":[{"tool":"db.query","resource":"db:demo","effect":"allow"},
           {"tool":"db.admin","resource":"unknown","effect":"allow"}],
 "default_effect":"deny","not_before":"$NBF","expires_at":"$EXP"}
J
export SENTRYRA_MANDATE=$($EDGE issue "$R/keys" "$R/mandate.json")
echo "== signed mandate issued (Biscuit, ${#SENTRYRA_MANDATE} chars, revocation ids: $($EDGE revocation-ids "$R/keys" "$SENTRYRA_MANDATE" | tr '\n' ' '))"
PROXY=($EDGE mcp-proxy "$R/keys" --mode enforce --catalogue "$R/catalogue.json" --evidence "$R/evidence.jsonl" -- python3 demo/sample_mcp_server.py)

echo; echo "== A. ENFORCE mode: agent -> Sentryra stdio MCP proxy -> sample SQL MCP server"
python3 demo/agent.py "${PROXY[@]}" 2> "$R/proxy.log"
echo; echo "-- proxy decision log"; cat "$R/proxy.log"

echo; echo "== B. evidence: offline verification + the DROP TABLE record"
$VERIFY "$R/evidence.jsonl" "$R/keys/evidence.pub"
python3 - "$R/evidence.jsonl" <<'P'
import json,sys
for l in open(sys.argv[1]):
    e=json.loads(l)
    if e["tool"]=="db.query" and "sql-forbid-ddl" in e["policy_ids"]:
        print(json.dumps({k:e[k] for k in ["seq","decision_id","tool","resource","decision","enforced","tainted","policy_ids","args_hmac","prev_hash","entry_hash","sig"]},indent=1)); break
P
echo "-- tamper test: flip the DROP decision to allow"
python3 - "$R/evidence.jsonl" "$R/tampered.jsonl" <<'P'
import sys; open(sys.argv[2],"w").write(open(sys.argv[1]).read().replace('"decision":"deny"','"decision":"allow"',1))
P
$VERIFY "$R/tampered.jsonl" "$R/keys/evidence.pub" || true

echo; echo "== C. HTTP /v1/decide in SHADOW mode + Edge-served approval view"
$EDGE serve "$R/keys" --mode shadow --catalogue "$R/catalogue.json" --addr 127.0.0.1:18787 --edge-url http://127.0.0.1:18787 2>"$R/serve.log" &
SP=$!; trap 'kill $SP 2>/dev/null || true' EXIT
for i in $(seq 50); do curl -sf -o /dev/null http://127.0.0.1:18787/v1/evidence && break; sleep 0.1; done
D() { curl -s -X POST http://127.0.0.1:18787/v1/decide -H 'content-type: application/json' -d "{\"mandate\":\"$SENTRYRA_MANDATE\",\"tool\":\"db.query\",\"args\":{\"db\":\"demo\",\"sql\":\"$1\"}}"; }
echo "-- DROP TABLE (shadow: decided + logged, not enforced)"; D "DROP TABLE users" | python3 -m json.tool
echo "-- DELETE (escalate: only decision id + deep link leave the Edge)"; ESC=$(D "DELETE FROM users WHERE id = 2"); echo "$ESC" | python3 -m json.tool
LINK=$(echo "$ESC" | python3 -c 'import json,sys;print(json.load(sys.stdin)["approval_link"])')
echo "-- approver opens $LINK (served by the customer-side Edge; raw args live only here)"; curl -s "$LINK" | python3 -m json.tool
kill $SP; trap - EXIT

echo; echo "== D. Tier 1 latency (box-local benchmark)"
$EDGE bench "$R/keys" --catalogue "$R/catalogue.json" --n 20000
