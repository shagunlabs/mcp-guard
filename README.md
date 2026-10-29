# Sentryra — Edge (M0–M2)
Policy enforcement for AI-agent tool calls. Deterministic Tier 1 (signed Biscuit mandate + signed tool catalogue + Cedar + SQL parsing + taint) is the only automatic path to *allow*; ML can only escalate.
Under Tier 1, long outbound sends after untrusted content always go to human approval (`LONG_SEND_HOLD`); this is a fixed rule and cannot be switched off.

## Quick start (all local; throwaway keys; no network or accounts)
```
make demo            # = ./demo/run.sh
make test            # = cargo test --workspace
```
Toolchain: Rust 1.99.0 (`rust-toolchain.toml`), Python 3 for the sample MCP server and scripted agent.

`./demo/run.sh` builds the Edge, generates demo keys, signs the tool catalogue, issues a signed mandate, and then:
- **A.** runs a scripted agent through `sentryra-edge mcp-proxy` (stdio, enforce mode) in front of `demo/sample_mcp_server.py` (SQLite SQL tool). The agent reads a ticket containing a prompt injection, then tries `DROP TABLE users`: **denied** (`sql-forbid-ddl`). The same DROP through an uncatalogued `db.admin` tool is also **denied** (treated as destructive, and flagged as copied from untrusted output). A `DELETE` is **escalated**, and the agent gets only a decision ID and a link. The table survives.
- **B.** verifies the signed evidence chain offline with `sentryra-verify`, prints the DROP TABLE record and shows that tampering with it is detected.
- **C.** runs `sentryra-edge serve` (HTTP `POST /v1/decide`) in **shadow** mode (decides and logs, doesn't enforce), and opens the Edge-served approval view for an escalation.
- **D.** approval receipt flow: escalate → approver (bearer token) approves → signed receipt → retry allowed once; a receipt for different SQL is rejected, and so is a replay.
- **F.** builds a support mandate with `sentryra-edge mandate new` (defaults `mail.recipients` to `$ticket.requester` when that context field is present), then shows that a long outbound send after untrusted tool output is **held** (`LONG_SEND_HOLD`) while a short reply is allowed.
- **E.** runs the Tier 1 benchmark locally (results are not published).

## Commands
```
sentryra-edge keygen <keydir>
sentryra-edge sign-catalogue <keydir> <manifest.json>
sentryra-edge mandate new <keydir> <spec.json> [--catalogue m.json]         # build + sign from a small JSON spec
sentryra-edge issue <keydir> <mandate.json>               # Biscuit v3 token (base64)
sentryra-edge attenuate <keydir> <token> <tool> <resource> [expires_at]
sentryra-edge revocation-ids <keydir> <token>
sentryra-edge serve <keydir> --mode shadow|enforce --catalogue m.json [--evidence e.jsonl] [--addr 127.0.0.1:8787]
SENTRYRA_MANDATE=<token> sentryra-edge mcp-proxy <keydir> --mode enforce --catalogue m.json --evidence e.jsonl -- <mcp server cmd>
sentryra-edge bench <keydir> --catalogue m.json [--n 20000]
sentryra-edge doctor [--no-network] [--home DIR]          # standing-credential + egress lockdown report (names/paths only)
sentryra-verify <evidence.jsonl> <evidence.pub>
```

### Building a mandate from a spec (`mandate new`)
`sentryra-edge mandate new <keydir> <spec.json> [--catalogue m.json] [--json-out f]` builds and signs a mandate from a JSON spec and prints the token. Every scope gets default-deny around it, and `not_before`/`expires_at` come from `ttl` (default `8h`, max `30d`).

    {
      "tenant": "org_acme",
      "principal": "priya@acme.example",
      "agent": "support-bot",
      "purpose": "Answer support tickets",
      "ttl": "8h",
      "context": {
        "ticket.requester": "customer@cust.example"
      },
      "tools": [
        {"tool": "ticket.read"},
        {"tool": "mail.send"}
      ]
    }

Recipients for `external_send` tools:
- **Default:** if the spec has a `ticket.requester` context field, every `external_send` scope with no recipient rule gets `mail.recipients: ["$ticket.requester"]`. Sends to other addresses are denied or escalated per the rules.
- **Override:** `recipients: [ops@acme.example, ...]` sets an explicit allowlist, and a `mail.recipients` or `mail.recipient_domains` constraint is kept as written.
- **Opt-out:** `recipients: escalate` (needs `approvers`) holds every send through that scope for approval.

The side-effect class is read from `--catalogue` only when its `.sig` verifies with the keydir's catalogue key. Signed context values are never printed or logged; the summary on stderr names context keys only. `--json-out` writes the unsigned mandate JSON (which includes the values) with mode 0600.

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
- Approvals: receipts are signed, single-use and bound to the action hash. Used receipt ids are kept in `<evidence>.consumed-receipts` (fsynced before a receipt is accepted; if the write fails the receipt is refused), so single use survives a restart; with `--no-evidence` they are kept in memory only. The approval view uses one shared bearer token (`keydir/approver.token`), and the Edge itself holds the approval key. The approver name in an approve request is self-declared by whoever holds that token; it is not authenticated. When the hold came from a mandate escalate scope, the name must exactly match one of that scope's `approvers` (signed into the mandate token); otherwise the Edge refuses (HTTP 403, no receipt) and records the refusal in evidence. `POST /v1/approvals/<id>/deny` (same token, self-declared name, optional reason) drops a held call, records the denial in evidence and blocks later approval of it. This is a consistency check, not authentication. Holds from the default policy or Tier 2 have no list and accept any non-empty name. Production design: approver SSO + WebAuthn, with the receipt signed by the tenant approval key.
- Evidence: no WAL fsync, no instance-key certification, no Merkle checkpoints (M3), so tail truncation isn't detected.
- Proxy: stdio only (no streamable HTTP), no `tools/list` filtering or manifest pinning against the server, no OAuth (M4).
- Taint: in free-text args, fingerprints need ≥12-char atoms or ≥16-char 3–4-word shingles with entropy ≥3.0 bits/char, so short copied values (≤11 chars) in free text go undetected, as do paraphrased copies and encodings deeper than two decoding passes. Typed sinks match exact atoms with no length minimum (see Taint matching below). For catalogued tools only declared sink args are checked; uncatalogued tools treat every arg as a sink. Copies that pass an explicit mandate allowlist are recorded as a signal only.
- `doctor` is a heuristic name/path scan, and the egress probe checks 4 public destinations.

## Repository
Home: `github.com/shagunlabs/mcp-guard`.

## Taint matching (v0.3)
- Typed sinks (table, recipient, branch, amount, host, path, channel, group, id, URL, cmd, SQL; from manifest `args` or inferred from the name) match exact normalized atoms with no length minimum. URLs are parsed into host/path/query; paths match on segment suffixes; shell `$VAR` sigils are stripped; SQL matches tables, identifiers and literals.
- The length/entropy minimum applies only to free-text args; tokens from the mandate `purpose` are trusted and excluded.
- Decoding passes (URL-encoding, base64 std/url-safe, hex; two levels) run on outbound args before matching.
- Uncatalogued tools: every argument is a sink (they also escalate as destructive).
- `max_rows` is enforced on results at the proxy: JSON arrays (or `{rows:[...]}`) are truncated, other text by line; `_meta["com.sentryra/row_cap"]` marks the cut.
- Mandate scope resources support globs (`*` within a segment, `**` across segments).
- `$` bindings resolve against signed context; unresolved bindings escalate. `$name` bindings in constraints (e.g. `idp.users: ["$ticket.requester"]`) resolve only from trusted context: the signed mandate `context` (wins), host-supplied context (`SENTRYRA_CONTEXT` for the proxy, `context` on `/v1/decide`), and built-in `$principal.id`. Never from agent args or tool outputs.
- SQL taint: the free-text `purpose` never clears SQL identifiers; only `sql.tables` and signed mandate `context` values do. Table names NOT so allowed, plus string and number literals, are taint-checked (columns/identifiers are not). Numeric literals 0–99 are ignored as non-identifying.
- The proxy annotates every capped result with `_meta["com.sentryra/row_cap"] = {cap, truncated}`.

## Tier 2 sidecar (sidecar-risk)
Tier 2 is off by default and escalate-only: it can add an escalation, never an allow.
- `sentryra-edge mcp-proxy ... --tier2-scorer <tier2-prototype dir>` starts ONE scorer process (one ONNX session, single-threaded) on a private unix socket (0600) and talks newline-delimited JSON. Nothing listens on TCP; the scorer runs in the data plane next to the Edge.
- Model allowlist by sha256 (`sidecar-risk/model-allowlist.sha256`; exactly one hash). The Edge hashes the file and refuses to start the scorer on any other digest; the scorer re-checks before creating its session.
- Per-call deadline `--tier2-deadline-ms` (default 10). Missed deadline, or untrusted-output cache not yet ready => `T2_TIMEOUT`; escalates for destructive / privilege / external_send, none + log for read / write. Late replies are logged (`--tier2-log`), never applied.
- Threshold `--tier2-threshold` (default 0.50, an untuned placeholder); `|score − threshold| ≤ 0.03` => `T2_NEAR_THRESHOLD`. Outbound sends with `windows_read < windows_total`, or either field missing / non-integer => `T2_PARTIAL_READ`.
- Escalate-only: the final join is `sidecar_risk::combine`; Tier 2 never lowers a deny/escalate and never produces allow. Evidence carries only score, band and approver-visible codes (`T2_UNSCORABLE_PLACEHOLDER` is internal; unknown codes are dropped).
- Untrusted outputs are sent to the scorer for embedding as they arrive (async).
- Gaps: the Tier 2 session is per Edge process (fine for the stdio proxy; `serve` mixes mandates); the wire is JSON over UDS, not the contract's gRPC; no `T2_UNAVAILABLE` alerting; per-window diagnostic scores (`--tier2-diag`) are computed at shutdown, off the decision path.
- Versioned scorer config (`sidecar-risk/scorer-config.v0.json`, `config_version` t2cfg-v0): scorer version + weights file sha256 + threshold 0.50 (untuned placeholder) + near margin 0.03 + probe reference. Swap with `--tier2-config <file>` (e.g. a V1) without code changes; `cfg=<config_version>` is recorded in every decision record.
- Startup probe self-check: the sidecar scores the fixed probes in the reference file (probe files are private and pinned by sha256 via `probe_reference_sha256`) in its single INT8 session and refuses to start if any score is off by more than 0.005 or the file is missing. A refused sidecar fails closed (`T2_UNAVAILABLE`: external_send / destructive / privilege escalate). One INT8 session only; no AMX blocking.
- Configs: `sidecar-risk/scorer-config.t2-v0-pooled.json` (default, compiled in) and `scorer-config.t2-v1-perwin.json`. Each pins its probe file by sha256; probe files are private. The probe check refuses a reference whose config_version, model sha256 or threshold differs from the active config. The dev-only devref reference stays in bench/dev/ and is not on any default path.
- Rules record every reason that applies. A timeout or unavailable on an outbound send also gets `T2_PARTIAL_READ`, because the windows were not reported. An outbound send whose session has seen untrusted output but has no scorable text gets `T2_UNSCORABLE`.
- Timeout, unavailable, partial read and unscorable act only when the call's (mandate, session) has seen untrusted output. With no untrusted output, Tier 2 does not act and Tier 1 behaves exactly as it does without Tier 2. See test `tier1_taint_identical_with_tier2_unavailable_vs_tier1_only`.
- Tier 2 state is keyed per mandate and session (`t2_session_key`). The sidecar keeps one shared INT8 inference session behind a single FIFO queue, and time spent waiting in the queue counts toward the deadline. A periodic probe re-check runs through the same queue (`--tier2-recheck-secs`, default 60). If a re-check fails, Tier 2 is marked unavailable and fails closed.
- `--tier2-diagnostic-no-probe` is for score-only diagnostics only. Its records are tagged `<id>+diag-noprobe`.
