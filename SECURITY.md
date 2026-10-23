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
accepts only the released tags v0.1.0 and v0.1.1, each pinned to its Build Signer
Digest, and workflow actions are pinned by commit SHA. Distributing that policy as a
TUF-signed file under the offline root key is still planned for v0.2.

The root `action.yml` is a verifier. It does not request an OIDC token and it does
not attest. A composite action runs inside the caller's job, so a certificate minted
there would name the caller, which this policy rejects. The action also has no input
that replaces the built-in signer set.
