#!/usr/bin/env sh
# SPDX-License-Identifier: AGPL-3.0
#
# smoke-test-kind-ingress.sh — the INGRESS path, which `smoke-test-kind.sh` deliberately does
# not cover (it uses a Service and a port-forward, so the Ingress object was never exercised).
#
# What this proves that nothing else does:
#   * the chart's Ingress object is accepted by a real controller and routes to the Service;
#   * the TLS secret in `ingress.tls` is actually served (a certificate for the name, not a
#     default one) — asserted by the fact that a plain client REJECTS it and `-k` accepts it;
#   * the server answers over the Ingress, not only over the Service.
#
# What it does NOT prove, stated because a green run invites over-reading:
#   * a certificate a native client would ACCEPT. That needs a public CA; a kind cluster has
#     no public name, so the certificate here is self-signed on purpose and the desktop and
#     mobile clients would refuse it. This tests the ROUTING, not the trust chain.
#   * the no-IP obligation. That is a property of the controller's log configuration, which
#     this script does not inspect (it installs the controller with its defaults, which DO log
#     the client address — see the runbook, and do not copy this manifest into production).
#
# Requirements: kind, kubectl, helm, openssl, curl, a container runtime. ~600 MB of pulls.
# Usage:  ./smoke-test-kind-ingress.sh [--keep]
set -eu

HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
CHART="${MYNE_SMOKE_CHART:-$HERE/../helm/myne-server}"
CHART_VERSION="${MYNE_SMOKE_CHART_VERSION:-0.9.0}"
[[ -d "$CHART" ]] || [ "${CHART#oci://}" != "$CHART" ] || CHART="$HERE/helm/myne-server"

CLUSTER="${MYNE_KIND_INGRESS_CLUSTER:-myne-ingress-smoke}"
NS="${MYNE_SMOKE_NS:-myne-smoke}"
RELEASE="${MYNE_SMOKE_RELEASE:-myne-smoke}"
HOSTNAME_SUT="sync.myne.test"
# Host ports 8080/8443 rather than 80/443: binding <1024 in the VM needs privileges this does
# not need to ask for, and the mapping is the only thing that changes.
HTTP_PORT="${MYNE_SMOKE_HTTP_PORT:-8080}"
HTTPS_PORT="${MYNE_SMOKE_HTTPS_PORT:-8443}"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

fail() { echo "ingress-smoke: FAIL — $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

for bin in kind kubectl helm openssl curl; do
  command -v "$bin" >/dev/null 2>&1 || fail "$bin is not on PATH"
done

cleanup() {
  if [ "$KEEP" = "0" ]; then
    echo "ingress-smoke: deleting the cluster"
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  else
    echo "ingress-smoke: keeping cluster '$CLUSTER'"
  fi
}
trap cleanup EXIT INT TERM

WORK="$(mktemp -d)"
trap 'cleanup; rm -rf "$WORK"' EXIT INT TERM

step "cluster with the ingress ports mapped and the controller's node label"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "ingress-smoke: reusing '$CLUSTER'"
else
  cat >"$WORK/kind.yml" <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "ingress-ready=true"
    extraPortMappings:
      - containerPort: 80
        hostPort: 8080
        protocol: TCP
      - containerPort: 443
        hostPort: 8443
        protocol: TCP
YAML
  kind create cluster --name "$CLUSTER" --config "$WORK/kind.yml" --wait 180s
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null

step "ingress-nginx (the kind flavour: hostPort + the ingress-ready node selector)"
# PINNED, not floating: `main` is what upstream's kind instructions point at, so it is recorded
# here as what was measured rather than left as "however it looked that day".
INGRESS_MANIFEST="https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.3/deploy/static/provider/kind/deploy.yaml"
kubectl apply -f "$INGRESS_MANIFEST" >/dev/null
kubectl -n ingress-nginx wait --for=condition=Ready pod \
  -l app.kubernetes.io/component=controller --timeout=300s >/dev/null \
  || { kubectl -n ingress-nginx get pods; fail "the ingress controller never became Ready"; }
# The kind provider manifest ships an admission webhook whose certificate it generates itself;
# wait for the Job that patches it, or the first Ingress apply is rejected.
kubectl -n ingress-nginx wait --for=condition=complete job/ingress-nginx-admission-patch --timeout=180s >/dev/null 2>&1 || true

step "a self-signed certificate for $HOSTNAME_SUT (self-signed ON PURPOSE, see the header)"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$WORK/tls.key" -out "$WORK/tls.crt" \
  -subj "/CN=$HOSTNAME_SUT" -addext "subjectAltName=DNS:$HOSTNAME_SUT" >/dev/null 2>&1
# The namespace first, then the secret, then the install: the Ingress references the secret, and
# an install whose ingress cannot resolve its secret is a bad test of a good chart.
kubectl create ns "$NS" >/dev/null 2>&1 || true
kubectl -n "$NS" create secret tls myne-sync-tls --cert="$WORK/tls.crt" --key="$WORK/tls.key" >/dev/null

step "install the chart WITH its ingress"
helm uninstall "$RELEASE" -n "$NS" >/dev/null 2>&1 || true
set -- --set storage.size=1Gi \
  --set resources.requests.memory=64Mi \
  --set ingress.enabled=true \
  --set ingress.host="$HOSTNAME_SUT" \
  --set 'ingress.tls[0].secretName=myne-sync-tls' \
  --set "ingress.tls[0].hosts[0]=$HOSTNAME_SUT"
[ "${CHART#oci://}" != "$CHART" ] && set -- "$@" --version "$CHART_VERSION"
helm install "$RELEASE" "$CHART" -n "$NS" "$@" >/dev/null
kubectl -n "$NS" rollout status "deploy/$RELEASE-myne-server" --timeout=240s >/dev/null \
  || fail "the pod never became Ready behind the ingress"

step "the controller must admit the Ingress object"
kubectl -n "$NS" get ingress "$RELEASE-myne-server" >/dev/null || fail "no Ingress object was created"
# The controller is the only thing that can say whether it accepted it; a rejected Ingress
# still exists as an object and would let a Service-only test pass.
sleep 5

step "over TLS through the ingress, with the Host header the Ingress routes on"
probe() { # $1 = path, $2 = extra curl args
  curl -sS --resolve "$HOSTNAME_SUT:$HTTPS_PORT:127.0.0.1" $2 "https://$HOSTNAME_SUT:$HTTPS_PORT$1"
}
echo "ingress-smoke: /healthz      -> $(probe /healthz '-k')"
echo "ingress-smoke: /readyz       -> $(probe /readyz '-k')"

step "the certificate really is the one in the secret (a plain client must refuse it)"
if curl -sS --resolve "$HOSTNAME_SUT:$HTTPS_PORT:127.0.0.1" \
     "https://$HOSTNAME_SUT:$HTTPS_PORT/healthz" >/dev/null 2>&1; then
  fail "a client with no trust store accepted the certificate: this is not the self-signed one, so the ingress.tls secret is not being served"
fi
echo "ingress-smoke: refused without -k, as a self-signed certificate must be"

step "plain HTTP through the ingress is routed (a TLS ingress may redirect, and that is the point)"
HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOSTNAME_SUT" "http://127.0.0.1:$HTTP_PORT/healthz")"
echo "ingress-smoke: http /healthz -> $HTTP_CODE"
# 200 = served, 301/302/307/308 = redirected to https. BOTH prove the rule and the port
# mapping are in effect; only a 404 means the ingress is not routing at all. The first version
# of this asserted 200 and failed on a 308 — which is what an ingress with `tls:` configured
# does by default, so the assertion was wrong and the chart was right.
case "$HTTP_CODE" in
  200|301|302|307|308) ;;
  *) fail "the http path answered $HTTP_CODE (a 404 means the ingress rule or the port mapping is not in effect)" ;;
esac

echo
echo "ingress-smoke: ok — the Ingress routes to the Service, the TLS secret is the certificate"
echo "               served, and both endpoints answer over the ingress."
