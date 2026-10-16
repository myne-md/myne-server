<!-- SPDX-License-Identifier: AGPL-3.0 -->
# `myne-server` Helm chart

Runs Myne's zero-knowledge sync server on Kubernetes. The server stores and relays
opaque ciphertext blobs and never holds a key that could decrypt anything, so
running it on a cluster changes **who operates it**, not what it can see
(`docs/self-host-policy.md`, trust boundary TB5).

The Compose path is the primary one and is what the user guide walks through
("Run your own sync server"). This chart is the same server, the same image and the
same knobs; what changes is the orchestration, and with it three obligations that the
Compose bundle's Caddy edge carries for you.

```sh
helm install myne-server ./deploy/helm/myne-server \
  --namespace myne --create-namespace \
  --set storage.size=20Gi
```

Then read the printed notes, or:

```sh
kubectl -n myne port-forward svc/myne-server-myne-server 8080:8080
curl http://127.0.0.1:8080/healthz    # {"status":"ok"}
curl http://127.0.0.1:8080/readyz     # {"status":"ready"} once migrations finish
```

## What you need first

- A cluster and a **StorageClass that can provision a `ReadWriteOnce` volume**. The
  store is a filesystem; there is no object-store or SQL backend today.
- An **ingress controller**, and a **publicly trusted certificate** for a public DNS
  name. Native clients verify the chain against the Mozilla roots bundled with the
  app and check the server name on every connection; a private CA — including one
  installed on the machine or pushed by device management — is **not consulted**, and
  a self-signed certificate is refused (`docs/self-host-policy.md` §6). `cert-manager`
  with an ACME issuer is the ordinary way to satisfy this.

## One replica, one writer

`replicaCount: 1` and `strategy: Recreate`, and the chart **refuses** a higher
`replicaCount` rather than letting you find out.

The server is a single writer on one filesystem: `MYNE_STORAGE_BACKEND` is `mem` or
`fs` and nothing else, the store holds blobs, account metadata, the head chain and
device registrations together, and it needs its own volume. Two replicas would mean
two writers over one dataset; a `RollingUpdate` would strand the new pod `Pending` on
`AttachVolume` while the old one holds the ReadWriteOnce claim, so a rollout would
hang instead of restarting.

That is also why scaling this chart out is not a tuning exercise: it needs a storage
backend that supports concurrent writers, which does not exist yet (deferred,
SYNC-22). Everything else about the pod — resources, probes, security context — is
ordinary.

## Known limits of this deployment shape

**Member vaults and live collaboration are not safe on a restarting pod.** Pending
vault invites and the only copy of per-person `MYY5` profiles are held in RAM today
(`myne-server/KNOWN-GAPS-711.md` item 1); device registrations and tokens are not
(they are in `auth.json` beside the blobs and survive). So a **single-user, multi-device
deployment is fine** — a pod restart keeps every device enrolled — while a
**shared vault** loses pending invites and member profiles when the pod restarts, and
the owner-only write gate reverts to its pre-B2B path until they are re-created.
Kubernetes restarts pods routinely, which makes this a routine event here rather than
a rare one. Track it in `KNOWN-GAPS-711.md`; do not read this chart as "collaboration
is supported on Kubernetes".

**Deleted ciphertext is reclaimed by the horizon sweep, and retired namespaces by their own
grace.** Both are scheduled, and the retired-namespace reclaimer was a real gap until recently (item 2
of the same file). One thing to keep in mind: reclamation runs on a timer, so the volume holds deleted
and retired ciphertext for up to that window plus the retention horizon. Size the volume for that, not
for the live data alone.

**Two surfaces must not be exposed.** The admin API is a Unix socket inside the pod
(use `kubectl exec`); the read-only operator panel has **no authentication** and reads
the account roster, so it stays cluster-internal and is reached with `port-forward`.
Neither belongs behind an Ingress.

## Ingress and the no-IP obligation

The Compose bundle ships a Caddy edge whose access log deletes every IP-bearing field,
because the server's no-persistent-IP-logging commitment is inherited by whoever
operates it. An Ingress replaces that edge, and **whatever your ingress controller
logs is now your log** — including the client address and the `X-Forwarded-For` chain.

Enabling `ingress.enabled` therefore asks you to do two things:

- turn the controller's access log off, or configure a format that drops the
  IP-bearing fields (`ingress-nginx`: `disable-access-log: "true"`, or an access-log
  template without `$remote_addr` / `$http_x_forwarded_for`);
- strip the forwarding headers on the way in.

Enabling this Ingress against a default-configured controller silently reintroduces
exactly the logging the server is built not to do.

## Backup

The image bundles `restic` (and `rclone` for an SFTP-style target without an ssh
client). Backups are **off** unless you turn them on, and they need a Secret you
create:

```sh
kubectl -n myne create secret generic myne-restic \
  --from-file=restic-password=/path/to/password-file
```

```sh
helm upgrade myne-server ./deploy/helm/myne-server -n myne \
  --set backup.enabled=true \
  --set backup.existingSecret=myne-restic \
  --set backup.repository=sftp://user@host/backups/myne
```

The chart mounts the password at `backup.passwordFile` (read-only, `0440`) and never
reads or stores it. On-demand runs use the bundled binary:

```sh
kubectl -n myne exec deploy/myne-server-myne-server -- \
  myne-server backup-check      # integrity check of the repository
```

Enabling the built-in backup is not confidentiality-neutral in one direction and
neutral in another: the blobs are already client-encrypted, so the server's inability
to read them is unchanged, but the window in which a **deleted** note still exists
somewhere becomes `retention horizon + backup retention`, and the restic repository
key plus destination credentials become a new operator-held secret. That window is
one you owe your users, not one you set quietly (`docs/self-host-policy.md` §3/§4).

**The volume itself is the other half of the backup story**, and it is the one that
restores fast: blobs, account metadata, the head chain and `auth.json` live in one
claim, and every write is an atomic rename, so a volume snapshot taken on a running
server is always restorable (old or new, never partial). The chart keeps the PVC on
`helm uninstall` for exactly that reason. Whichever way you back up, **check that you
can restore**: an untested backup is a guess.

## Upgrades

Migrations run before the listener binds, and `/readyz` stays unready until they
finish, so the readiness probe is the honest gate for a rollout and `kubectl rollout
status` reflects what is actually serving.

Because the strategy is `Recreate`, an upgrade is a short outage, not a rolling one.
Take a volume snapshot before an upgrade if the release notes mention a store change;
the previous image can be rolled back with `helm rollback`, but a store migration
cannot be rolled back by the chart.

## Values

The important ones; `values.yaml` is annotated and is the reference.

| Value | Default | Notes |
|---|---|---|
| `image.digest` | the current multi-arch manifest-list digest | Preferred over `image.tag`. See "Image tags" below. |
| `image.tag` | empty | Falls back to `appVersion` when `digest` is empty. |
| `replicaCount` | `1` | `> 1` fails the install. |
| `storage.size` | `10Gi` | Budget your ciphertext plus roughly twice that (tombstones + a snapshot). |
| `storage.storageClassName` | empty | Empty means the cluster default. |
| `storage.keepOnDelete` | `true` | Keeps the PVC across `helm uninstall`. |
| `storage.existingClaim` | empty | Use a claim you manage instead of the chart's. |
| `config.*` | the Compose bundle's defaults | Every `MYNE_*` knob, same names, same meanings. |
| `metrics.enabled` | `false` | Aggregate-only Prometheus text on its own port. Never public. |
| `serviceMonitor.enabled` | `false` | Needs the Prometheus Operator CRDs. |
| `backup.enabled` | `false` | Needs `backup.existingSecret` + `backup.repository`. |
| `ingress.enabled` | `false` | Read the no-IP section above first. |
| `networkPolicy.enabled` | `false` | Ingress-only; egress is left open for the backup. |
| `resources` | 100m/128Mi → 1/512Mi | Disk is the resource that grows; memory follows concurrent devices. |

### Image tags, and which release the chart is

The default is a **digest**, not a tag, and three measured facts are why:

- The pinned digest is the newest published server build: the **v0.9.0** cycle's image, built
  2026-10-02 (commit `6a7f5100`).
- **`latest` is a different, older build** — 2026-08-12 against 2026-10-02 — so pointing at it would
  be a downgrade dressed as currency. The 2026-10-02 build was published under a commit-SHA tag;
  `v0.9.0` was added to that same digest later, as a tag rather than a rebuild.
- The **version tags that do exist** (`0.8.0`, `v0.8.1`) each resolve to a single `linux/amd64`
  manifest, while the pin is a multi-architecture list. A tag-pinned install on an arm64 node either
  needs emulation or fails outright.

**The chart's version tracks the server image, not the app.** They are not the same number, and a
release cycle can skip the server entirely: **v0.10.0 (2026-10-14) shipped no server image**, recorded
as skipped in `the operations repository/runbooks/release-checklist.md`, which is why this chart says `0.9.0` while the
app says `0.10.0`. Bump the chart's `version`, its `appVersion`, `image.digest` and the user guide's
`--version` together, in the cycle that publishes a new server image; the checklist's phase-10 rows
exist so that is one tick rather than four edits from memory.

## Verifying this chart

```sh
helm lint deploy/helm/myne-server
helm template myne-server deploy/helm/myne-server | kubectl apply --dry-run=server -f -
helm template myne-server deploy/helm/myne-server --set ingress.enabled=true \
  --set ingress.host=sync.example.org
```

There is no CI for this chart today: the platform's pipelines verify the main client
repository, and `myne-server` has no pipeline of its own. The guards that keep this
chart honest live in the main repository instead — `scripts/check-server-env-roster.mjs`
fails a `MYNE_*` name that is not on the server's documented environment roster, so the
chart cannot grow a knob nothing reads, and `scripts/check-referenced-digests.mjs` fails a
pin that does not resolve or that is not multi-arch.

**Rendering is not running.** `deploy/kubernetes/smoke-test-kind.sh` brings up a `kind`
cluster, installs this chart, and asserts what rendering cannot: the pod becomes Ready as
the nonroot UID, the ReadWriteOnce claim mounts, both probes answer, the admin socket on
`/tmp` accepts a command, a pod restart keeps the same claim, and `replicaCount: 2` is
still refused.

```sh
./deploy/kubernetes/smoke-test-kind.sh        # needs kind + kubectl + a container runtime
```

## Licence

AGPL-3.0. The server is AGPL like the rest of the application code; the specification
documents it implements are published under a permissive content licence so independent
implementations can reuse the protocol.
