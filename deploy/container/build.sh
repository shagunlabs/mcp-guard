#!/usr/bin/env bash
# Build the static release binaries and the scratch image. Tier 2 is NOT in the image (opt-in
# sidecar; see RUNBOOK). The dev-export feature is never enabled here.
set -euo pipefail
cd "$(dirname "$0")/../.."
TAG=${TAG:-sentryra-edge:0.0.1}
cargo build --release --locked --target x86_64-unknown-linux-musl -p sentryra-edge -p sentryra-verify
D=deploy/container/dist; rm -rf "$D"; mkdir -p "$D/rootfs/data" "$D/rootfs/keys"
cp target/x86_64-unknown-linux-musl/release/sentryra-edge target/x86_64-unknown-linux-musl/release/sentryra-verify "$D/"
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
podman build --timestamp "$SOURCE_DATE_EPOCH" -f deploy/container/Containerfile -t "$TAG" deploy/container
podman image inspect "$TAG" --format '{{.Digest}}'
