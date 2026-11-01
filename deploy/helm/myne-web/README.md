<!-- SPDX-License-Identifier: AGPL-3.0 -->
# `myne-web` Helm chart

Serves Myne's browser client from an address you control. It is the same client as
`app.example.com`, and the same bundle; what changes is **who hands the page its code on
every visit**, which is the code-delivery trust boundary (threat model A15/TB11). A
browser verifies no signature over page resources and keeps no copy to compare, so an
instance you run removes an outside operator from the path **for your own use** and not
for anyone else you serve.

```sh
helm install myne-web ./deploy/helm/myne-web \
  --namespace myne \
  --set syncOrigin=https://sync.example.org \
  --set ingress.enabled=true \
  --set ingress.host=notes.example.org \
  --set 'ingress.tls[0].secretName=myne-notes-tls' \
  --set 'ingress.tls[0].hosts[0]=notes.example.org'
```

## What you need first

1. **A sync server.** The client holds an encrypted copy of a vault that arrives over
   sync: it cannot create a standalone vault and it will not open offline. The
   `myne-server` chart in the sibling directory brings one up.
2. **A public domain and a TLS terminator.** The container serves plain HTTP on 8080
   and expects HTTPS in front; a browser refuses to give a page your master password
   over anything else. The certificate must be one the **browser** trusts (unlike the
   sync server, whose certificate the native clients check against the roots they
   bundle).
3. **Two settings that have to agree.** `syncOrigin` here, and `MYNE_ALLOWED_ORIGINS`
   on the sync server, set to **this deployment's origin**. One without the other
   fails in opposite directions: this container refuses to start without a sync
   origin, and the sync server refuses a cross-origin request it was not told about.
   The install notes print the value to copy.

## Nothing to back up

The bundle is baked into the image, the container writes nothing to persistent
storage, and the only user state is the browser's own copy (OPFS). There is no volume,
no backup unit and no restore drill: recovery is `up -d`. The chart deliberately
declares no PVC.

## Security context, stated honestly

The published image's entrypoint generates two files at container start — the CSP
header snippet and `/srv/web/config.json`, both derived from `syncOrigin` — into its
own filesystem, next to the Caddy config it reads. That is why this chart **does not
set `readOnlyRootFilesystem` or `runAsNonRoot`**: either would break the container
rather than harden it, and a chart that set them anyway would produce
`CrashLoopBackOff` that reads like a cluster problem.

What it does enforce: every Linux capability dropped, `allowPrivilegeEscalation:
false`, the default seccomp profile, no service-account token, and httpGet probes. A
future image that pre-generates those two files at build time could run read-only and
non-root; today's cannot, and the fix belongs in the image rather than in a value
here.

## Architecture

The published web images are **`linux/amd64` only** (with a build attestation entry
that appears as an unknown platform in the manifest index). On an arm64 node the pod
either needs `--platform` emulation (Docker Desktop does it for you; a Linux cluster
needs `binfmt`/qemu registered) or the image will not start. If you build the image
yourself on your own architecture you avoid it entirely — at the cost of needing the
source, which is not published. The multi-arch gap is the image's, not this chart's.

## Values

| Value | Default | Notes |
|---|---|---|
| `image.tag` | `v0.11.3` | Read with `image.digest`, which is the index digest and wins. |
| `syncOrigin` | *(required)* | An origin, e.g. `https://sync.example.org`. Plain http is accepted only for a loopback host. |
| `replicaCount` | `2` | The container is stateless, so replicas are safe here; 1 is fine for a personal instance. |
| `ingress.enabled` | `false` | TLS must terminate in front of the pod. |
| `networkPolicy.enabled` | `false` | Ingress-only egress is unrestricted. |
| `resources` | 50m/96Mi → 500m/256Mi | Small; this serves static files. |

## Verifying this chart

```sh
helm lint deploy/helm/myne-web
helm template myne-web deploy/helm/myne-web --set syncOrigin=https://sync.example.org
```

The chart refuses a malformed origin at install time rather than letting the container
fail later, and refuses `http://` for a non-loopback host, because that deployment
cannot work.
