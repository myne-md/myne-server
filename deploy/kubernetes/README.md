<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Running Myne on Kubernetes

Two charts, one server each:

| Chart | What it runs | Needs |
|---|---|---|
| [`helm/myne-server`](helm/myne-server/) | The zero-knowledge sync server: opaque ciphertext blobs, one filesystem store on a `ReadWriteOnce` volume | A storage class, a public domain, a publicly trusted certificate |
| [`helm/myne-web`](helm/myne-web/) | The browser client, served from your own address | A sync server, a public domain, TLS in front |

They are independent on purpose. A native-only deployment (desktop + phone) needs only
the server; the browser client is a different trust story and a different address.

## What the Compose bundle does that these charts do not

The primary self-host path is Docker Compose, documented end to end in the user guide
("Run your own sync server" and "Run your own browser client"). The charts deploy the
same images with the same knobs. Three differences are worth knowing before you pick a
chart:

1. **The edge is yours.** The Compose bundle ships a Caddy edge whose access log
   deletes every IP-bearing field. On a cluster, whatever your ingress controller logs
   is your log — and the server's no-persistent-IP-logging commitment is inherited by
   whoever operates it. Turn the controller's access log off, or use a format without
   the client address and the `X-Forwarded-For` chain.
2. **One replica.** The server is a single writer on one filesystem; there is no
   object-store or SQL backend today. The server chart refuses `replicaCount > 1` for
   that reason. The web client is stateless and scales freely.
3. **Backup is an object you manage.** The Compose path copies a directory; on a
   cluster the equivalent is a volume snapshot of the claim (one consistent unit:
   blobs, account metadata, head chain and `auth.json` together) plus, optionally, the
   server's own bundled restic backup.

## Not supported today

- **Member vaults and live collaboration are not restart-safe** (pending invites and
  the only copy of per-person profiles live in RAM). Kubernetes restarts pods
  routinely, so read that as "not supported on Kubernetes yet" rather than as a rare
  edge case. Tracked in `myne-server/KNOWN-GAPS-711.md` item 1.
- **Scaling the server out.** It needs a storage backend that supports concurrent
  writers; deferred (SYNC-22 in the main repository's ledger).
- **Scheduled reclamation of deleted ciphertext.** The tombstone sweep has no
  production caller yet (`KNOWN-GAPS-711.md` item 2), so disk grows with deletion even
  though the retention documentation implies otherwise.
- **arm64 web client.** The published web images are `linux/amd64` only. The server's
  chart pins a multi-arch manifest-list digest, so it is fine on arm64.

## Verifying what you installed

```sh
helm lint deploy/helm/myne-server deploy/helm/myne-web
helm template myne-server deploy/helm/myne-server | kubectl apply --dry-run=server -f -
helm template myne-web deploy/helm/myne-web --set syncOrigin=https://sync.example.org \
  | kubectl apply --dry-run=server -f -
```

Rendering is not running. `smoke-test-kind.sh` (beside this file) installs the server chart on a
`kind` cluster and asserts the parts only a real cluster shows: the pod becomes Ready as the
nonroot UID, the claim mounts, both probes answer, the admin socket accepts a command, a restart
keeps the claim, and a second replica is still refused.

```sh
./smoke-test-kind.sh
```

Run and green on 2026-10-16, on a `kind` cluster on `arm64` hardware — which is also the evidence
that the multi-arch digest the chart pins resolves and runs on a second architecture. Then run again
against the **published** artifact, because a published chart is a different thing from the directory
it was packaged from: `MYNE_SMOKE_CHART=oci://ghcr.io/myne-md/charts/myne-server
MYNE_SMOKE_CHART_VERSION=0.9.0 ./smoke-test-kind.sh` also passed on 2026-10-16, so what a self-hoster
installs is verified end to end and not just the source beside this file. What neither run covers: no
device is enrolled (a deployment check, not a sync check), and the no-IP obligation is not exercised
because the chart ships no edge.

`smoke-test-kind-ingress.sh` is the third run, and it is the only one that exercises the **Ingress**
object: it installs a real `ingress-nginx` controller, creates a self-signed certificate for a test
host name, installs the chart with `ingress.enabled=true`, and asserts that both endpoints answer over
TLS through the ingress with that Host header, that the certificate being served is the one in the
secret (a client without the CA refuses it), and that the plain-HTTP path is routed (a 308 to https,
which is what a TLS-fronted ingress does). Green on 2026-10-16. It tests the ROUTING and not the trust
chain: a certificate a desktop or phone client would accept needs a public authority, which a `kind`
cluster has no name for.

There is no chart pipeline: `myne-server` has no CI of its own, and the platform's pipelines
verify the main client repository. The guard that keeps these charts aligned with the server
lives in the main repository (`scripts/check-server-env-roster.mjs`, which fails any `MYNE_*`
name that is not on the server's documented environment roster) and it covers the charts because
it scans this directory.

## Publishing

Charts are published to `oci://ghcr.io/myne-md/charts` — a **public** package, like the
images, from a private source repository. The procedure is
`the operations runbooks`.

## Licence

AGPL-3.0-only, matching the server and the web client they deploy.
