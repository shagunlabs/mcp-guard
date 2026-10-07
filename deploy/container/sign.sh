#!/usr/bin/env bash
# SBOM + local-key signing for the static binaries and the image (DEV KEY, not keyless).
# The private key stays OUTSIDE the repo. Default is ~/.sentryra-signing/cosign.key, with its password
# in cosign.pass. Signatures skip the public transparency log (--tlog-upload=false), so we publish nothing.
set -euo pipefail
cd "$(dirname "$0")/../.."
KEYDIR=${SENTRYRA_SIGNING_DIR:-$HOME/.sentryra-signing}
export COSIGN_PASSWORD=$(cat "$KEYDIR/cosign.pass")
COSIGN=${COSIGN:-cosign}; SYFT=${SYFT:-syft}
TAG=${TAG:-sentryra-edge:0.0.1}; REG=${REG:-127.0.0.1:5000}
D=deploy/container/dist; OUT=dist/release; mkdir -p "$OUT"
cp "$D/sentryra-edge" "$D/sentryra-verify" "$OUT/"
# SBOMs (CycloneDX JSON): Rust dependency graph from Cargo.lock, and the image contents.
$SYFT scan dir:. --override-default-catalogers rust-cargo-lock-cataloger --exclude ./target --exclude ./dist --exclude ./deploy/container/dist --source-name sentryra-edge --source-version 0.0.1 -o cyclonedx-json="$OUT/sbom.cargo.cdx.json" -q
for b in sentryra-edge sentryra-verify; do
  (cd "$OUT" && sha256sum "$b" > "$b.sha256")
  $COSIGN sign-blob --yes --key "$KEYDIR/cosign.key" --tlog-upload=false --use-signing-config=false --bundle "$OUT/$b.sigstore.json" "$OUT/$b" >/dev/null
  $COSIGN verify-blob --key deploy/signing/cosign.DEV-NOT-FOR-RELEASE.pub --insecure-ignore-tlog=true --bundle "$OUT/$b.sigstore.json" "$OUT/$b"
done
# Image: push to a LOCAL registry (127.0.0.1 only), sign by digest, attach the SBOM as an attestation.
podman push --tls-verify=false "$TAG" "$REG/$TAG" -q
DIG=$(skopeo inspect --tls-verify=false "docker://$REG/$TAG" | python3 -c 'import json,sys;print(json.load(sys.stdin)["Digest"])')
REF="$REG/${TAG%%:*}@$DIG"
$SYFT scan "registry:$REF" -o cyclonedx-json="$OUT/sbom.image.cdx.json" -q 2>/dev/null || SYFT_REGISTRY_INSECURE_USE_HTTP=true $SYFT scan "registry:$REF" -o cyclonedx-json="$OUT/sbom.image.cdx.json" -q
$COSIGN sign --yes --key "$KEYDIR/cosign.key" --tlog-upload=false --use-signing-config=false --allow-insecure-registry --allow-http-registry "$REF" >/dev/null
$COSIGN attest --yes --key "$KEYDIR/cosign.key" --tlog-upload=false --use-signing-config=false --allow-insecure-registry --allow-http-registry --type cyclonedx --predicate "$OUT/sbom.cargo.cdx.json" "$REF" >/dev/null
$COSIGN verify --key deploy/signing/cosign.DEV-NOT-FOR-RELEASE.pub --insecure-ignore-tlog=true --allow-insecure-registry --allow-http-registry "$REF" >/dev/null && echo "image signature verified: $REF"
echo "$DIG" > "$OUT/image.digest"
