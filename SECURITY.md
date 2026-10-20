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
authority. Access is limited to a small set of org admins. Pinning accepted certifier
commits in a signed trust policy is planned for v0.2.
