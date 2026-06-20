# SPDX-License-Identifier: AGPL-3.0-or-later
#
# myne-server container image (MYND-437).
#
# Reproducible, minimal, non-root. The SHIPPED artefact is the OCI image, and its
# digest is the verification unit (SYNC-28): with buildkit's SOURCE_DATE_EPOCH +
# rewrite-timestamp and the digest-pinned bases below, a rebuild from the same
# source yields the same image digest. Both bases are pinned by @sha256 (SYNC-20),
# never a floating tag — a tag would defeat reproducibility and supply-chain pinning.
#
# Build (deterministic; see the operations repository runbook for the canonical invocation):
#   DOCKER_BUILDKIT=1 docker buildx build \
#     --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
#     --output type=image,rewrite-timestamp=true \
#     -t myne-server .
#
# syntax=docker/dockerfile:1.7

# --- build stage: static, trimmed, reproducible Go binary -------------------
# Pin to $BUILDPLATFORM so the build stage always runs on the native builder and
# CROSS-COMPILES via GOOS/GOARCH (Go needs no emulation for a CGO_ENABLED=0 build).
# This keeps multi-arch builds fast and avoids qemu in the Go toolchain.
FROM --platform=$BUILDPLATFORM golang:1.26.4@sha256:792443b89f65105abba56b9bd5e97f680a80074ac62fc844a584212f8c8102c3 AS build

# SOURCE_DATE_EPOCH makes the build clock deterministic (reproducible-builds.org).
ARG SOURCE_DATE_EPOCH=0
# TARGETOS/TARGETARCH are injected by buildx per target platform (multi-arch).
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

# The server is pure stdlib today (no go.sum). Copy the module graph first so the
# layer caches independently of source churn; when a real go.sum lands it caches here.
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

# CGO_ENABLED=0 → a fully static binary (runs on distroless static / scratch).
# -trimpath strips local paths; -buildid= empties the build id; together with
# SOURCE_DATE_EPOCH these make the binary bit-identical across rebuilds.
ENV CGO_ENABLED=0
RUN GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags="-buildid= -s -w" \
    -o /out/myne-server ./cmd/myne-server

# --- runtime stage: distroless static, non-root -----------------------------
# distroless static:nonroot carries ca-certificates (for a future S3 backend,
# SYNC-22) + a nonroot UID (65532) + no shell/package-manager/secrets.
FROM gcr.io/distroless/static:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240

COPY --from=build /out/myne-server /usr/local/bin/myne-server

# Non-root by default (distroless nonroot = UID 65532); restated for clarity.
USER nonroot:nonroot

# The server reads MYNE_SERVER_ADDR (default :8080). No secrets are baked in —
# the server is zero-knowledge and holds no keys.
EXPOSE 8080

# The binary self-probes /healthz over loopback (distroless has no shell/curl).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/myne-server", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/myne-server"]
