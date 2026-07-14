#!/usr/bin/env sh
# SPDX-License-Identifier: AGPL-3.0
#
# Reproducibility gate (MYND-437, SYNC-28): build the server image twice with no
# cache and assert identical OCI image digests. The SHIPPED artefact is the image,
# so the verification unit is the image digest — a third party rebuilds from source
# and must get the same sha256. Fails the pipeline on digest drift.
#
# Determinism requires:
#   - SOURCE_DATE_EPOCH pinned to the source commit time (reproducible clock)
#   - buildkit rewrite-timestamp=true (normalize layer mtimes)
#   - no provenance/SBOM baked in (they carry build-env metadata and are attached
#     SEPARATELY as digest-bound attestations, OUTSIDE the reproduced image —
#     baking them in would perturb the digest). buildctl attaches neither by
#     default; docker buildx needs --provenance=false --sbom=false.
#   - digest-pinned base images (in the Dockerfile)
#
# Usage: scripts/repro-gate.sh   (run from the repo root). Uses buildctl when
# present (the CI buildkit image) and falls back to `docker buildx` locally —
# both drive the same buildkit OCI exporter, so the digest is identical.
set -eu

SDE="$(git log -1 --format=%ct)"
DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

build() {
  if command -v buildctl-daemonless.sh >/dev/null 2>&1; then
    buildctl-daemonless.sh build \
      --frontend dockerfile.v0 --local context=. --local dockerfile=. \
      --opt build-arg:SOURCE_DATE_EPOCH="$SDE" --no-cache \
      --output "type=oci,dest=$DIR/img$1.tar,rewrite-timestamp=true" \
      >"$DIR/build$1.log" 2>&1
  else
    docker buildx build --no-cache --provenance=false --sbom=false \
      --build-arg SOURCE_DATE_EPOCH="$SDE" \
      --output "type=oci,dest=$DIR/img$1.tar,rewrite-timestamp=true" \
      . >"$DIR/build$1.log" 2>&1
  fi
}

digest() {
  # The first manifest digest in the OCI index = the image's content digest
  # (single-platform build -> manifests[0]). Read without python3 (absent from
  # the buildkit image); the OCI index is one-line JSON, so the first sha256 is
  # the manifest digest.
  tar -xOf "$DIR/img$1.tar" index.json \
    | grep -oE 'sha256:[0-9a-f]{64}' | head -1
}

echo "repro-gate: SOURCE_DATE_EPOCH=$SDE"
echo "repro-gate: build 1/2 ..."; build 1
echo "repro-gate: build 2/2 ..."; build 2

D1="$(digest 1)"; D2="$(digest 2)"
echo "repro-gate: digest 1 = $D1"
echo "repro-gate: digest 2 = $D2"

if [ -n "$D1" ] && [ "$D1" = "$D2" ]; then
  echo "repro-gate: REPRODUCIBLE — identical image digest ✓"
  exit 0
fi
echo "repro-gate: DIGEST DRIFT — the image is not reproducible ✗" >&2
echo "repro-gate: inspect $DIR/build1.log and $DIR/build2.log" >&2
exit 1
