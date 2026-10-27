# Security

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/workrr-trust/certify/security/advisories/new)
or by email to info@workrr.ai. Don't open a public issue. We'll acknowledge within
3 business days.

In scope: anything that could make a verifier accept a certificate it shouldn't — for
example signing as the certifier identity from artifact code, forging or replaying a
certificate, digest collisions or divergence between implementations, scan-rule
bypasses that should be high/critical, and trust-policy matching errors.

## What a certificate does and doesn't claim

A certificate records that the public certifier at a specific commit ran the checks in
[spec/README.md](spec/README.md) and got the recorded results. A scan `pass` means "no
high or critical findings from the pinned ruleset," **not** that an artifact is safe.

## Hardening of this repository

The path of `.github/workflows/certify.yml` in this repo is the signing identity
recorded in every certificate, so write access to this repo is effectively signing
authority. Access is limited to a small set of org admins. The built-in trust policy
accepts only the released tags v0.1.0 to v0.1.4, each older tag pinned to its Build Signer
Digest, plus the public-scan workflow `scan.yml` as an observer at the newest tag (level
`scanned` only; docs/public-scans.md). Workflow actions are pinned by commit SHA. The signed trust policy's
embedded fallback is that same set.

The root `action.yml` is a verifier. It does not request an OIDC token and it does
not attest. A composite action runs inside the caller's job, so a certificate minted
there would name the caller, which this policy rejects. The action also has no input
that replaces the built-in signer set.

`.github/workflows/trust-policy.yml` and `.github/workflows/revoke.yml` are the
identities that sign the trust policy and revocations. Both are accepted only
from a release tag. Their Build Signer Digests are not pinned yet; pin them in
`src/trust-feed.ts` and `go/trustfeed.go` after the first tagged run. The trust
API that distributes those documents does not need to be trusted: clients check
the signatures.
