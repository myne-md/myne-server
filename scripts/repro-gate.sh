#!/usr/bin/env sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Reproducibility gate (MYND-437, SYNC-28): build the server image twice with no
# cache and assert identical OCI image digests. The SHIPPED artefact is the image,
# so the verification unit is the image digest — a third party rebuilds from source
# and must get the same sha256. Fails the pipeline on digest drift.
#
# Determinism requires:
#   - SOURCE_DATE_EPOCH pinned to the source commit time (reproducible clock)
#   - buildkit rewrite-timestamp=true (normalize layer mtimes)
#   - --provenance=false --sbom=false (provenance/SBOM carry build-env metadata and
#     are attached SEPARATELY as digest-bound attestations, OUTSIDE the reproduced
#     image — baking them in would perturb the digest)
#   - digest-pinned base images (in the Dockerfile)
#
# Usage: scripts/repro-gate.sh   (run from the repo root; needs docker buildx)
set -eu

SDE="$(git log -1 --format=%ct)"
DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

build() {
  docker buildx build --no-cache --provenance=false --sbom=false \
    --build-arg SOURCE_DATE_EPOCH="$SDE" \
    --output "type=oci,dest=$DIR/img$1.tar,rewrite-timestamp=true" \
    . >"$DIR/build$1.log" 2>&1
}

digest() {
  # The manifest digest the OCI index points at = the image's content digest.
  tar -xOf "$DIR/img$1.tar" index.json \
    | python3 -c "import json,sys;print(json.load(sys.stdin)['manifests'][0]['digest'])"
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
