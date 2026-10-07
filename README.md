# Sentryra — Edge (M0–M2)
Policy enforcement for AI-agent tool calls. Deterministic Tier 1 (signed Biscuit mandate + signed tool catalogue + Cedar + SQL parsing + taint) is the only automatic path to *allow*; ML can only escalate.

## Quick start (all local; throwaway keys; no network or accounts)
```
make demo            # = ./demo/run.sh
make test            # = cargo test --workspace
```
Toolchain: Rust 1.99.0 (`rust-toolchain.toml`), Python 3 for the sample MCP server and scripted agent.

`./demo/run.sh` builds the Edge, generates demo keys, signs the tool catalogue, issues a signed mandate, and then:
- **A.** runs a scripted agent through `sentryra-edge mcp-proxy` (stdio, enforce mode) in front of `demo/sample_mcp_server.py` (SQLite SQL tool). The agent reads a ticket containing a prompt injection, then tries `DROP TABLE users`: **denied** (`sql-forbid-ddl`, also flagged as tainted). An uncatalogued `db.admin` tool and a `DELETE` are **escalated**, and the agent gets only a decision ID and a link. The table survives.
- **B.** verifies the signed evidence chain offline with `sentryra-verify`, prints the DROP TABLE record and shows that tampering with it is detected.
- **C.** runs `sentryra-edge serve` (HTTP `POST /v1/decide`) in **shadow** mode (decides and logs, doesn't enforce), and opens the Edge-served approval view for an escalation.
- **D.** runs the Tier 1 latency benchmark.

## Commands
```
sentryra-edge keygen <keydir>
sentryra-edge sign-catalogue <keydir> <manifest.json>
sentryra-edge issue <keydir> <mandate.json>               # Biscuit v3 token (base64)
sentryra-edge attenuate <keydir> <token> <tool> <resource> [expires_at]
sentryra-edge revocation-ids <keydir> <token>
sentryra-edge serve <keydir> --mode shadow|enforce --catalogue m.json [--evidence e.jsonl] [--addr 127.0.0.1:8787]
SENTRYRA_MANDATE=<token> sentryra-edge mcp-proxy <keydir> --mode enforce --catalogue m.json --evidence e.jsonl -- <mcp server cmd>
sentryra-edge bench <keydir> --catalogue m.json [--n 20000]
sentryra-edge doctor [--no-network] [--home DIR]          # standing-credential + egress lockdown report (names/paths only)
sentryra-verify <evidence.jsonl> <evidence.pub>
```

## Measured Tier 1 latency (box-local benchmark)
`sentryra-edge bench`, release build, in-process `decide()` over 20,000 decisions (allow/deny/escalate mix), including Biscuit verification, SQL parsing, taint lookup, Cedar evaluation and the signed evidence append (no fsync, no network). Measured on the shared dev box (8 vCPUs), 2026-10-07:

| p50 | p90 | p99 |
|---|---|---|
| [not published] | [not published] | [not published] |

This is a box-local micro-benchmark, not a published number: no WAL fsync, no gRPC/HTTP hop, no Tier 2, no replayed design-partner traces. Through the stdio proxy with a replay server, client round-trip was [not published] (see `../bench`).

## Layout
| Path | What | Licence |
|---|---|---|
| `crates/mandate` | Mandate v0 JSON model; **M1** Biscuit issue/verify/attenuate/expiry/revocation IDs (`token.rs`) | Apache-2.0 |
| `crates/pdp` | **M2** Tier 1 engine: signed catalogue, Cedar, SQL classifier, taint store, shadow/enforce, evidence | Apache-2.0 |
| `crates/evidence` | Signed (Ed25519) hash chain over salted hashes only | Apache-2.0 |
| `crates/connector-manifest` | Connector manifest v0 | Apache-2.0 |
| `policies/default.cedar` | Default Tier 1 policy set (`@effect("escalate")` convention) | Apache-2.0 |
| `edge/` | `sentryra-edge` binary: HTTP decide API, stdio MCP proxy, doctor, bench, key tooling | Apache-2.0 |
| `verify/` | `sentryra-verify` offline evidence verifier | Apache-2.0 |
| `sidecar-risk/` | Tier 2 interface (escalate-only `combine()`), model choices | Apache-2.0 |
| `control/` | Control plane placeholder | Proprietary, `publish = false` |
| `spec/` | Open drafts: mandate v0, evidence v0, connector manifest v0 | Apache-2.0 |
| `demo/` | Sample SQL MCP server, scripted agent, `run.sh` | Apache-2.0 |
| `deploy/terraform`, `.github/workflows/ci.yml`, `deny.toml` | Skeletons; CI never run remotely | — |

## Not yet built (known gaps)
- Generic mandate `constraints` (branch, path, domain, amount, `cmd_prefix`, recipient) aren't evaluated yet; only SQL statement class is.
- Approvals: no approval receipts, no consume-once or approve flow yet; the approval view is unauthenticated (localhost demo only).
- Evidence: no WAL fsync, no instance-key certification, no Merkle checkpoints (M3), so tail truncation isn't detected.
- Proxy: stdio only (no streamable HTTP), no `tools/list` filtering or manifest pinning against the server, no OAuth (M4).
- Taint: exact word n-gram fingerprints, so paraphrased or encoded copies are missed, and benign copies (for example replying to a sender) escalate.
- `doctor` is a heuristic name/path scan, and the egress probe checks 4 public destinations.

## Repository
Planned home `github.com/shagunlabs/sentryra` (org name **placeholder, to be confirmed**). No remote configured; nothing pushed.
