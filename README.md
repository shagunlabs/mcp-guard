# Sentryra (M0 — Foundations)
Policy enforcement for AI-agent tool calls: deterministic Tier 1 (signed mandate + Cedar + taint) decides; ML can only escalate.

## Layout
| Path | What | Status |
|---|---|---|
| `crates/mandate` | Mandate v0 model + structural validation + scope lookup | M0 (Biscuit in M1) |
| `crates/evidence` | Evidence v0 hash chain + verifier | M0 (signatures/checkpoints M3) |
| `crates/connector-manifest` | Connector manifest v0 | M0 |
| `edge/` | Proxy + PDP binary (CLI stub) | M2/M4 |
| `verify/` | Open-source `sentryra verify` | M0 chain check |
| `control/` | Control plane | placeholder |
| `sidecar-risk/` | Tier 2 interface; `combine()` proves ML can't allow | M0 |
| `spec/` | Open drafts: mandate v0, evidence v0, connector manifest v0 | draft |
| `deploy/terraform` | Skeleton, never applied | M0 |
| `.github/workflows/ci.yml`, `deny.toml` | CI with fmt/clippy/test/cargo-deny/audit/gitleaks/terraform validate | not yet run remotely |
Threat model: `../engineering/threat-model.md`.

## Build
```
cargo build --workspace && cargo test --workspace
cargo run -p sentryra-edge -- spec/examples/mandate-v0.json k8s.apply cluster:prod/ns:billing   # Escalate
```

## Licensing
- **Apache-2.0** (`LICENSE`): Edge proxy/PDP (`edge/`), data-plane crates (`crates/*`, `sidecar-risk/`), `verify/`, `spec/`, SDKs (`sdk/*`).
- **Proprietary** (`control/LICENSE`): control plane — `publish = false`, `license = "LicenseRef-Shagun-Proprietary"`.

## Repository
Planned home: `github.com/shagunlabs/sentryra` (org name **placeholder, to be confirmed**). No remote is configured; nothing has been pushed.
