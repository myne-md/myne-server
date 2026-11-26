# Security Policy

## Reporting a vulnerability

Report security issues to **security@myne.md** privately. Please do not open a
public GitHub issue for a vulnerability.

If you do not get an acknowledgment within 5 business days, send a reminder; the
address may have failed silently.

## What to include

- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- The affected component and version/commit.
- Whether it affects the server code, a self-hosted deployment, or the
  maintainer-run instance at sync.myne.md (if you tested it there).
- How you want to be credited.

## Scope

In scope:

- The ciphertext-only boundary: any path that gives the server plaintext, a
  usable key, or a way to correlate content across accounts.
- SCRAM/auth, device approval/revocation, pairing tokens and session handling.
- Sync push/pull, cursors, retention/reclamation, quota and attachment handling.
- B2B routes: invites, membership, group packages, profiles and retirement.
- Operator surfaces (admin socket, read-only panel, metrics) and their exposure.
- Persistent per-IP logging or a violation of the documented no-email policy.
- The container image build: a bundled binary or base image that does not match
  the pinned digest/sha256 in `Dockerfile`/`NOTICE`.

Out of scope:

- A self-hosted instance run by a third party; report to its operator.
- Client-side cryptography and the vault format: report those against
  `myne-md/myne`.
- Third-party dependencies: report upstream first; we will relay.

## Response commitment

- Acknowledge within 5 business days.
- Initial assessment within 14 days.
- Coordinated disclosure: we ask for a 90-day window from acknowledgment,
  extended by agreement if a fix needs more time.

## Pre-1.0 caveat

Myne is pre-alpha. The server and the B2B surface are still hardening; reports
outside the published threat model (TB5) are still welcome.
