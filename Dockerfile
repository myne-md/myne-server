# SPDX-License-Identifier: AGPL-3.0-only
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
FROM --platform=$BUILDPLATFORM golang:1.26.11@sha256:6e59e17a20f13c102e49d82dffab66d41cffe6c266b225d82794328aea859ab5 AS build

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

# --- fetch stage: sha256-pinned restic + rclone (backup engine + transport) --
# MYND-505: the server drives a bundled restic for encrypted off-box backups.
# distroless has no shell/ssh, so restic's SFTP backend rides rclone's pure-Go
# SFTP (restic `rclone:` backend) — no external ssh. Both binaries are pinned by
# sha256 (the SYNC-20 pin-by-digest discipline) and extracted by the stdlib-only
# fetchtool, so the fetch is deterministic and the repro-gate's two-build digest
# holds. Runs on the native builder ($BUILDPLATFORM) but downloads TARGETARCH.
FROM --platform=$BUILDPLATFORM golang:1.26.11@sha256:6e59e17a20f13c102e49d82dffab66d41cffe6c266b225d82794328aea859ab5 AS fetch
ARG TARGETARCH=amd64
ARG RESTIC_VERSION=0.20.0
ARG RCLONE_VERSION=1.76.0
WORKDIR /src
COPY go.mod ./
COPY scripts/fetchtool ./scripts/fetchtool
RUN set -eu; mkdir -p /out; \
    case "${TARGETARCH}" in \
      amd64) RESTIC_SHA=0ccd9fa7885074a24603b051e01bf9bd8b5e45d6a1791e9d9887e9e9372107f7; \
             RCLONE_SHA=b00f00b3266c3764413afe599d3ec316f6f43b3e0ea8a0bc1d186d2133e46df7 ;; \
      arm64) RESTIC_SHA=1188daded239bccb5952a01d2ad33e77a0d3dc34f9d9fc1e7fdda618d44938ef; \
             RCLONE_SHA=ee169016675e23a69d77240565133ff7dbc9b33d16fa8f7053d4af39f1eaeb78 ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    go run ./scripts/fetchtool \
      "https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic_${RESTIC_VERSION}_linux_${TARGETARCH}.bz2" \
      "${RESTIC_SHA}" bz2 "" /out/restic; \
    go run ./scripts/fetchtool \
      "https://github.com/rclone/rclone/releases/download/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-linux-${TARGETARCH}.zip" \
      "${RCLONE_SHA}" zip "/rclone" /out/rclone

# --- runtime stage: distroless static, non-root -----------------------------
# distroless static:nonroot carries ca-certificates (for a future S3 backend,
# SYNC-22) + a nonroot UID (65532) + no shell/package-manager/secrets.
FROM gcr.io/distroless/static:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240

LABEL org.opencontainers.image.source="https://github.com/myne-md/myne-server"
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"

COPY --from=build /out/myne-server /usr/local/bin/myne-server

# Third-party notices for the binaries this image redistributes (restic,
# rclone) and for the empty Go module graph. `lefthook`'s `third-party-notices`
# check holds NOTICE to the pinned downloads above, so a third one cannot land
# without a row; nothing else here would notice, since a download pinned by
# sha256 leaves no trace in the module graph a compiler reads.
COPY NOTICE /NOTICE

# Bundled backup engine (MYND-505): sha256-pinned restic + its rclone SFTP
# transport. The server invokes restic via os/exec (no shell needed); restic
# finds rclone on PATH. RESTIC_CACHE_DIR must be writable for UID 65532 (the
# distroless HOME is not) — /tmp is. These are defaults; backup stays OFF until
# the operator sets MYNE_BACKUP_ENABLED + a repository + a password file.
COPY --from=fetch /out/restic /usr/local/bin/restic
COPY --from=fetch /out/rclone /usr/local/bin/rclone
ENV PATH="/usr/local/bin" \
    MYNE_BACKUP_RESTIC_BIN="/usr/local/bin/restic" \
    MYNE_BACKUP_CACHE_DIR="/tmp/restic-cache"

# Non-root by default (distroless nonroot = UID 65532); restated for clarity.
USER nonroot:nonroot

# The server reads MYNE_SERVER_ADDR (default :8080). No secrets are baked in —
# the server is zero-knowledge and holds no keys.
EXPOSE 8080

# The binary self-probes /healthz over loopback (distroless has no shell/curl).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/myne-server", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/myne-server"]
