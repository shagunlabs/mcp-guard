# Sentryra Edge: design-partner runbook (v0.0.1, DEV build)

The Edge sits between your agent and its tools. For every tool call it checks the signed mandate, the signed tool catalogue, the Cedar policies and taint, then allows, holds or blocks the call. Every decision goes into a signed evidence log. It runs in your environment. Raw tool arguments never leave it: approvers open them on the Edge itself.

## 1. Install

**Container (recommended).** The image is `sentryra-edge:0.0.1`. It holds static musl binaries on `scratch`: no shell, no package manager, and it runs as uid 65532.

    podman load -i sentryra-edge-0.0.1.tar        # or pull from your registry
    cosign verify --key cosign.DEV-NOT-FOR-RELEASE.pub --insecure-ignore-tlog=true <registry>/sentryra-edge@sha256:<digest>

**Static binary** (any x86_64 Linux, no dependencies):

    cosign verify-blob --key cosign.DEV-NOT-FOR-RELEASE.pub --insecure-ignore-tlog=true \
      --bundle sentryra-edge.sigstore.json sentryra-edge && sha256sum -c sentryra-edge.sha256
    install -m 0755 sentryra-edge /usr/local/bin/

The SBOMs are CycloneDX JSON: `sbom.cargo.cdx.json` is the Rust dependency graph from Cargo.lock, and `sbom.image.cdx.json` covers the image contents. The image SBOM is also attached as a signed cosign attestation (`cosign verify-attestation --type cyclonedx …`).

> **`cosign.DEV-NOT-FOR-RELEASE.pub` is NOT a release key.** It only verifies local development builds. Never trust it for a production or design-partner build. Release builds are signed keyless by the `shagunlabs` org workflow; see "Verifying a release" below.

**Signing (dev key).** `deploy/container/sign.sh` signs with a LOCAL cosign key pair, not keyless (keyless needs an OIDC sign-in). The private key stays outside the repo in `~/.sentryra-signing/` (`cosign.key`, password in `cosign.pass`, both 0600). Only `deploy/signing/cosign.DEV-NOT-FOR-RELEASE.pub` is committed. Signatures skip the public transparency log, so verify with `--insecure-ignore-tlog=true`. Real releases use keyless signing from `.github/workflows/release.yml`, never this key.

Build steps: `deploy/container/build.sh` (musl build, then the image), then `deploy/container/sign.sh` (SBOMs, signatures, local-registry push, then verify). `deploy/container/smoke.sh` is the container smoke test.

### Verifying a release (keyless)

Tagged releases (`v*`) are built by `.github/workflows/release.yml` in the `shagunlabs` GitHub org, pushed to `ghcr.io/shagunlabs/sentryra-edge`, and signed with cosign keyless: a short-lived Fulcio certificate bound to that workflow's GitHub OIDC identity, logged in the public Rekor transparency log. There is no long-lived private key. Verify by pinning both the identity and the issuer:

    ID='^https://github\.com/shagunlabs/[^/]+/\.github/workflows/release\.yml@refs/tags/v.*$'
    ISS=https://token.actions.githubusercontent.com
    cosign verify --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISS" \
      ghcr.io/shagunlabs/sentryra-edge@sha256:<digest>
    cosign verify-attestation --type cyclonedx --certificate-identity-regexp "$ID" \
      --certificate-oidc-issuer "$ISS" ghcr.io/shagunlabs/sentryra-edge@sha256:<digest>
    cosign verify-blob --bundle sentryra-edge.sigstore.json --certificate-identity-regexp "$ID" \
      --certificate-oidc-issuer "$ISS" sentryra-edge

Always verify by digest, not tag. Do not use `--insecure-ignore-tlog` for releases. A signature from any other org, repo workflow or non-tag ref fails the regexp and must be rejected.

## 2. Pre-flight: `edge doctor`

Run this before you put an agent behind the Edge, on the agent host and in the container:

    sentryra-edge doctor                         # agent host: standing credentials + egress
    podman run --rm -v $PWD/data:/data sentryra-edge:0.0.1 doctor --no-network --home /data

In a container entrypoint or a Kubernetes initContainer, run `doctor` first and only start `serve` once it has passed. With no standing credentials and restricted egress, the verdict reads `LOCKED DOWN`. Any finding means the agent can bypass the Edge with its own credentials, so remove them first.

## 3. Configure

    sentryra-edge keygen /keys                   # root, catalogue, evidence, approval keys + approver.token + ingest.token
    sentryra-edge sign-catalogue /keys catalogue.json
    sentryra-edge mandate new /keys spec.json --catalogue catalogue.json   # signed mandate from a small JSON spec
    sentryra-edge issue /keys mandate.json       # or: sign a full mandate JSON

#### Building a mandate from a spec (`mandate new`)
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

Run it:

    podman run -d --name sentryra -p 8787:8787 -v /srv/sentryra/keys:/keys:ro -v /srv/sentryra/data:/data \
      sentryra-edge:0.0.1 serve /keys --mode shadow --catalogue /keys/catalogue.json --addr 0.0.0.0:8787 \
      --edge-url https://sentryra.internal.example

Defaults:

| Setting | Default | Change with |
|---|---|---|
| mode | `enforce` (the image CMD uses `shadow`, so start there) | `--mode shadow\|enforce` |
| policies | compiled-in `policies/default.cedar` | `--policies <file>` |
| evidence log | **on**: `$SENTRYRA_EVIDENCE` (image: `/data/evidence.jsonl`), else `<keydir>/evidence.jsonl` | `--evidence <file>`, `--no-evidence` (not for production) |
| Tier 2 scorer | **off**; opt-in only | `--tier2-scorer <dir> [--tier2-config <file>]` (mcp-proxy; needs the Python sidecar, which is not in the image) |
| output ingest | on if `<keydir>/ingest.token` exists | delete the token to disable |

The tool host (MCP server side) reports tool outputs so taint can see them:

    POST /v1/outputs   Authorization: Bearer <ingest.token>
    {"mandate": "<token>", "decision_id": "<id from /v1/decide>", "tool": "...", "output": "...", "context": {"session_id": "..."}}

The Edge accepts an output only under a verified mandate, against a prior allow (or shadow) decision for the same mandate, session and tool, and only once. State is keyed by the verified mandate id plus `session_id`.

Shadow mode first: run 1–2 weeks in `shadow` and review the evidence log for would-be holds. Switch to `enforce` after that.

## 4. What gets held, and why

| Result | Typical cause (reason in the decision) |
|---|---|
| deny | tool or resource not in the mandate; argument outside a signed constraint (path, recipients, tables, amount); tool not in the signed catalogue; DDL without a mandate; shell metacharacters |
| escalate (held for approval) | the mandate scope says `escalate`; a sink argument copied from untrusted tool output (taint); DML on a read-only purpose; Tier 2 (if enabled): the score is over the threshold, or near it within 0.03, or there was a timeout, partial read, unscorable send or an unavailable scorer on an outbound send / destructive / privilege call after untrusted output |
| allow | in scope, constraints pass, no taint, Cedar permits |

Each decision carries `reasons` and `policy_ids`. Tier 2 is escalate-only: it never allows or lowers a decision.

## 5. Approve a held call

1. The agent gets `pending approval, decision <id>` and an approver link `https://<edge>/v1/approvals/<id>`.
2. The approver opens it with `Authorization: Bearer <approver.token>`. The link shows tool, resource, args and reasons, and is served only by your Edge.
3. To approve: `POST /v1/approvals/<id>/approve {"approver": "name@company"}`. This returns a signed receipt.
4. The agent retries the same call with the receipt in `_meta.com.sentryra/receipt` (MCP) or `receipt` (HTTP). The receipt is single-use and bound to the action hash: a different argument or a replay is refused.

## 6. Export the evidence log

- **File:** copy `/data/evidence.jsonl` (append-only, hash-chained, Ed25519-signed).
- **HTTP:** `GET /v1/evidence` with `Authorization: Bearer <approver.token>`.
- **Verify offline:** `sentryra-verify evidence.jsonl /keys/evidence.pub`. In the image: `podman run --rm --entrypoint /sentryra-verify -v …:/data -v …:/keys sentryra-edge:0.0.1 /data/evidence.jsonl /keys/evidence.pub`.

Entries hold salted digests of arguments, never raw secrets in the clear. Share `evidence.pub` with your auditors.

## 7. Rollback

- **Fastest:** switch back to `--mode shadow`. Decisions are still logged, nothing is blocked.
- **Bypass:** point the agent back at the tool directly. The Edge is a proxy, so you don't need to migrate any data.
- **Version rollback:** run the previous image by digest (`podman run …@sha256:<previous>`). The keys and `/data` volumes are compatible within 0.0.x, and the evidence chain continues across versions.
- **Keep `/data/evidence.jsonl`** across rollbacks; it is the audit record.

## 8. Health

`GET /healthz` returns `ok`. Logs go to stderr, one line per decision.
