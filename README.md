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
- **D.** approval receipt flow: escalate → approver (bearer token) approves → signed receipt → retry allowed once; a receipt for different SQL is rejected, and so is a replay.
- **E.** runs the Tier 1 benchmark locally (results are not published).

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

## Performance
Performance numbers are not published pre-release. `sentryra-edge bench` is available for local measurement.

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
| `spec/` | Open drafts: mandate v0, evidence v0, connector manifest v0 | Apache-2.0 |
| `demo/` | Sample SQL MCP server, scripted agent, `run.sh` | Apache-2.0 |
| `deploy/terraform`, `.github/workflows/ci.yml`, `deny.toml` | Skeletons; CI never run remotely | — |

## Not yet built (known gaps)
- Constraint `$` context bindings (e.g. `$ticket.requester`) aren't resolved, so they escalate. `max_rows` is recorded but not yet applied to results.
- Approvals: receipts are signed, single-use and bound to the action hash. The approval view uses one shared bearer token (`keydir/approver.token`), and the Edge itself holds the approval key. Production design: approver SSO + WebAuthn, with the receipt signed by the tenant approval key.
- Evidence: no WAL fsync, no instance-key certification, no Merkle checkpoints (M3), so tail truncation isn't detected.
- Proxy: stdio only (no streamable HTTP), no `tools/list` filtering or manifest pinning against the server, no OAuth (M4).
- Taint: fingerprints need ≥12-char atoms or ≥16-char 3–4-word shingles with entropy ≥3.0 bits/char, so short copied values (≤11 chars) go undetected, as do paraphrased or encoded copies. Only declared sink args are checked. Copies that pass an explicit mandate allowlist are recorded as a signal only.
- `doctor` is a heuristic name/path scan, and the egress probe checks 4 public destinations.

## Repository
Planned home `github.com/shagunlabs/sentryra` (org name **placeholder, to be confirmed**). No remote configured; nothing pushed.

## Taint matching (v0.3)
- Typed sinks (table, recipient, branch, amount, host, path, channel, group, id, URL, cmd, SQL; from manifest `args` or inferred from the name) match exact normalized atoms with no length minimum. URLs are parsed into host/path/query; paths match on segment suffixes; shell `$VAR` sigils are stripped; SQL matches tables, identifiers and literals.
- The length/entropy minimum applies only to free-text args; tokens from the mandate `purpose` are trusted and excluded.
- Decoding passes (URL-encoding, base64 std/url-safe, hex; two levels) run on outbound args before matching.
- Uncatalogued tools: every argument is a sink (they also escalate as destructive).
- `max_rows` is enforced on results at the proxy: JSON arrays (or `{rows:[...]}`) are truncated, other text by line; `_meta["com.sentryra/row_cap"]` marks the cut.
- Mandate scope resources support globs (`*` within a segment, `**` across segments).
- `$name` bindings in constraints (e.g. `idp.users: ["$ticket.requester"]`) resolve only from trusted context: the signed mandate `context` (wins), host-supplied context (`SENTRYRA_CONTEXT` for the proxy, `context` on `/v1/decide`), and built-in `$principal.id`. Never from agent args or tool outputs. Unresolved bindings escalate.
- SQL taint: the free-text `purpose` never clears SQL identifiers; only `sql.tables` and signed mandate `context` values do. Table names NOT so allowed, plus string and number literals, are taint-checked (columns/identifiers are not). Numeric literals 0–99 are ignored as non-identifying.
- The proxy annotates every capped result with `_meta["com.sentryra/row_cap"] = {cap, truncated}`.

## Tier 2 sidecar (sidecar-risk)
- `sentryra-edge mcp-proxy ... --tier2-scorer <tier2-prototype dir>` starts ONE scorer process (one ONNX session, single-threaded) on a private unix socket (0600) and talks newline-delimited JSON. Nothing listens on TCP; the scorer runs in the data plane next to the Edge.
- Model allowlist by sha256 (`sidecar-risk/model-allowlist.sha256`, pinned copy of the INT8 row in the internal licence register; exactly one hash). The Edge hashes the file and refuses to start the scorer on any other digest; the scorer re-checks before creating its session.
- Per-call deadline `--tier2-deadline-ms` (default 10). Missed deadline, or untrusted-output cache not yet ready => `T2_TIMEOUT`; escalates for destructive / privilege / external_send, none + log for read / write. Late replies are logged (`--tier2-log`), never applied.
- Threshold `--tier2-threshold` (default 0.50); `|score − threshold| ≤ 0.03` => `T2_NEAR_THRESHOLD`. Outbound sends with `windows_read < windows_total`, or either field missing / non-integer => `T2_PARTIAL_READ`.
- Escalate-only: the final join is `sidecar_risk::combine`; Tier 2 never lowers a deny/escalate and never produces allow. Evidence carries only score, band and approver-visible codes (`T2_UNSCORABLE_PLACEHOLDER` is internal; unknown codes are dropped).
- Untrusted outputs are sent to the scorer for embedding as they arrive (async).
- Gaps: the Tier 2 session is per Edge process (fine for the stdio proxy; `serve` mixes mandates); the wire is JSON over UDS, not the contract's gRPC; no `T2_UNAVAILABLE` alerting; per-window diagnostic scores (`--tier2-diag`) are computed at shutdown, off the decision path.
- Versioned scorer config (`sidecar-risk/scorer-config.v0.json`, `config_version` t2cfg-v0): scorer version + weights file sha256 + threshold 0.50 + near margin 0.03 + probe reference. Swap with `--tier2-config <file>` (e.g. a V1) without code changes; `cfg=<config_version>` is recorded in every decision record.
- Startup probe self-check: the sidecar scores the fixed probes in the reference file (`handoff/probe-reference.json`, the research; placeholder path until delivered, `probe_reference_sha256` pins it) in its single INT8 session and refuses to start if any score is off by more than 0.005 or the file is missing. A refused sidecar fails closed (`T2_UNAVAILABLE`: external_send / destructive / privilege escalate). One INT8 session only; no AMX blocking.

### Tier 2 update (7 Oct, evening)
- Configs use the research ids: `sidecar-risk/scorer-config.t2-v0-pooled.json` (default, compiled in) and `scorer-config.t2-v1-perwin.json`. Each pins its probe file by sha256 (`handoff/probe_refs.json`, `handoff/probe_refs_v1.json`). The probe check refuses a reference whose config_version, model sha256 or threshold differs from the active config. The dev-only devref reference stays in bench/dev/ and is not on any default path.
- Rules record every reason that applies. A timeout or unavailable on an outbound send also gets `T2_PARTIAL_READ`, because the windows were not reported. An outbound send whose session has seen untrusted output but has no scorable text gets `T2_UNSCORABLE`.
- Timeout, unavailable, partial read and unscorable act only when the call's (mandate, session) has seen untrusted output. With no untrusted output, Tier 2 does not act and Tier 1 behaves exactly as it does without Tier 2. This fixes the credential-exfil regressions (see tests `tier1_taint_identical_with_tier2_unavailable_vs_tier1_only`).
- Tier 2 state is keyed per mandate and session (`t2_session_key`). The sidecar keeps one shared INT8 inference session behind a single FIFO queue, and time spent waiting in the queue counts toward the deadline. A periodic probe re-check runs through the same queue (`--tier2-recheck-secs`, default 60). If a re-check fails, Tier 2 is marked unavailable and fails closed.
- `--tier2-diagnostic-no-probe` is for score-only diagnostics only. Its records are tagged `<id>+diag-noprobe`.
