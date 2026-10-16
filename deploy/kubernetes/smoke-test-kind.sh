#!/usr/bin/env sh
# SPDX-License-Identifier: AGPL-3.0
#
# smoke-test-kind.sh — install the myne-server chart on a REAL cluster (kind) and assert
# the deployment actually runs. `helm lint` and `helm template` prove the manifests render;
# this is the only thing that proves the shape works: the image runs as the nonroot UID, the
# security context is satisfiable, the volume mounts, both probes pass, the admin socket
# answers, and a pod restart keeps the claim.
#
# ── What it deliberately does NOT prove ─────────────────────────────────────
#
# It does not enrol a device, so it says nothing about sync, and it does not exercise the
# B2B surface (`b2b.json` durability is covered by `internal/b2bpersist`'s tests, which drive
# a real save/reload cycle). It also says nothing about the no-IP obligation, because the
# chart ships no edge: whatever Ingress an operator adds is where that obligation lives.
#
# ── Requirements ────────────────────────────────────────────────────────────
#
#   kind, kubectl, helm, and a running container runtime. Roughly 2 GB of image pulls the
#   first time. On an arm64 host this also exercises the multi-arch digest the chart pins: a
#   single-platform pin fails here with `exec format error` rather than at a self-hoster.
#
# Usage:  ./smoke-test-kind.sh [--keep]
set -eu

HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# WHICH chart to install. The default is the chart beside this script (the thing you are
# editing). Set MYNE_SMOKE_CHART to an `oci://` reference to verify what a self-hoster
# actually pulls instead — the check that matters AFTER a publish, because a published chart
# is a different artifact from the directory it was packaged from.
CHART="${MYNE_SMOKE_CHART:-$HERE/../helm/myne-server}"
CHART_VERSION="${MYNE_SMOKE_CHART_VERSION:-0.9.0}"
[[ -d "$CHART" ]] || [ "${CHART#oci://}" != "$CHART" ] || CHART="$HERE/helm/myne-server"

CLUSTER="${MYNE_KIND_CLUSTER:-myne-chart-smoke}"
NS="${MYNE_SMOKE_NS:-myne-smoke}"
RELEASE="${MYNE_SMOKE_RELEASE:-myne-smoke}"
PORT="${MYNE_SMOKE_PORT:-18080}"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

fail() { echo "smoke: FAIL — $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

for bin in kind kubectl helm; do
  command -v "$bin" >/dev/null 2>&1 || fail "$bin is not on PATH"
done

PF_PID=""
cleanup() {
  [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true
  if [ "$KEEP" = "0" ]; then
    echo "smoke: deleting the cluster (re-run with --keep to inspect it)"
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  else
    echo "smoke: keeping cluster '$CLUSTER' (kubectl --context kind-$CLUSTER get pods -A)"
  fi
}
trap cleanup EXIT INT TERM

step "cluster"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "smoke: reusing the kind cluster '$CLUSTER'"
else
  kind create cluster --name "$CLUSTER" --wait 180s
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null

step "install the chart"
echostr="chart: $CHART"
[ "${CHART#oci://}" != "$CHART" ] && echostr="$echostr (version $CHART_VERSION, pulled from the registry)"
echo "smoke: $echostr"
helm uninstall "$RELEASE" -n "$NS" >/dev/null 2>&1 || true
kubectl delete ns "$NS" --wait=false >/dev/null 2>&1 || true
kubectl create ns "$NS" >/dev/null
# Small on purpose: this asserts the shape, not the sizing model.
set -- --set storage.size=1Gi \
  --set resources.requests.memory=64Mi \
  --set resources.limits.memory=256Mi
[ "${CHART#oci://}" != "$CHART" ] && set -- "$@" --version "$CHART_VERSION"
helm install "$RELEASE" "$CHART" -n "$NS" "$@" >/dev/null

step "rollout (proves the image runs non-root, the RWO claim mounts, and /readyz gates)"
kubectl -n "$NS" rollout status "deploy/$RELEASE-myne-server" --timeout=240s \
  || {
    kubectl -n "$NS" get pods
    kubectl -n "$NS" describe pod -l "app.kubernetes.io/instance=$RELEASE" | tail -40
    fail "the pod never became Ready"
  }

step "probes"
kubectl -n "$NS" port-forward "svc/$RELEASE-myne-server" "$PORT:8080" >/dev/null 2>&1 &
PF_PID=$!
i=0
until curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -gt 30 ] && fail "port-forward never answered /healthz"
  sleep 1
done
echo "smoke: /healthz      -> $(curl -fsS "http://127.0.0.1:$PORT/healthz")"
echo "smoke: /readyz       -> $(curl -fsS "http://127.0.0.1:$PORT/readyz")"

step "operator admin socket (distroless: exec the binary, never a shell)"
kubectl -n "$NS" exec "deploy/$RELEASE-myne-server" -- myne-server admin list \
  || fail "the admin socket did not answer (MYNE_ADMIN_SOCKET unwired, or /tmp not writable)"

step "restart keeps the claim (the store must not be recreated)"
PVC_UID_BEFORE="$(kubectl -n "$NS" get pvc "$RELEASE-myne-server-data" -o jsonpath='{.metadata.uid}')"
kubectl -n "$NS" rollout restart "deploy/$RELEASE-myne-server" >/dev/null
kubectl -n "$NS" rollout status "deploy/$RELEASE-myne-server" --timeout=240s >/dev/null
PVC_UID_AFTER="$(kubectl -n "$NS" get pvc "$RELEASE-myne-server-data" -o jsonpath='{.metadata.uid}')"
[ "$PVC_UID_BEFORE" = "$PVC_UID_AFTER" ] || fail "the PVC was recreated across a restart"
echo "smoke: same claim after a restart ($PVC_UID_AFTER)"

step "the validations still refuse what they should"
helm template t "$CHART" --set replicaCount=2 >/dev/null 2>&1 \
  && fail "replicaCount=2 rendered; the single-writer refusal is gone"
echo "smoke: replicaCount=2 refused, as documented"

echo
echo "smoke: ok — the chart installs, runs, answers both probes, admits the admin socket,"
echo "       survives a restart on the same claim, and still refuses a second replica."
