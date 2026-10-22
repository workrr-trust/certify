# workrr-trust/certify

[![npm](https://img.shields.io/npm/v/@workrr-trust/certify?label=npm%20%40workrr-trust%2Fcertify)](https://www.npmjs.com/package/@workrr-trust/certify)
[![Go Reference](https://pkg.go.dev/badge/github.com/workrr-trust/certify/go.svg)](https://pkg.go.dev/github.com/workrr-trust/certify/go)
[![release](https://img.shields.io/github/v/release/workrr-trust/certify)](https://github.com/workrr-trust/certify/releases/latest)
[![ci](https://github.com/workrr-trust/certify/actions/workflows/ci.yml/badge.svg)](https://github.com/workrr-trust/certify/actions/workflows/ci.yml)

Certify and verify AI agent artifacts (skills, MCP servers, rulesets, `AGENTS.md`)
with **publicly logged certificates anyone can verify without trusting workrr**.

| Get it | |
|---|---|
| **TypeScript / Node** | [`@workrr-trust/certify`](https://www.npmjs.com/package/@workrr-trust/certify) on npm, published with provenance · `npx @workrr-trust/certify verify …` |
| **Go** | [`github.com/workrr-trust/certify/go`](https://pkg.go.dev/github.com/workrr-trust/certify/go) · `go install github.com/workrr-trust/certify/go/cmd/workrr@latest` |
| **Binaries** | [GitHub releases](https://github.com/workrr-trust/certify/releases), with Sigstore build attestations |
| **Guide** | [How to use](https://trust.workrr.ai/guide/) · [instructions for AI agents](https://trust.workrr.ai/instructions.md) |
| **How it works** | [trust.workrr.ai/how-it-works](https://trust.workrr.ai/how-it-works/) · [live ledger](https://trust.workrr.ai/ledger/) · [spec](https://trust.workrr.ai/certificate/v0.1/) |

- **Certificate format:** [spec/README.md](spec/README.md) (in-toto Statement, predicate
  `https://trust.workrr.ai/certificate/v0.1`)
- **Implementations:** TypeScript (this directory) and Go ([go/](go/), single static
  binary), held byte-for-byte to each other by the shared [test vectors](spec/test-vectors/README.md)
- **Design rationale:** [docs/design.md](docs/design.md)
- **Security:** [SECURITY.md](SECURITY.md)
- **License:** [Apache-2.0](LICENSE)

> Status: v0.1, pre-release. The path of this repo's
> `.github/workflows/certify.yml` is the certifier's public signing identity, so
> changes to it are changes to what workrr signs.

## Certify in CI (GitHub)

In the artifact's **public** repo:

```yaml
# .github/workflows/workrr.yml
on: { push: { tags: ["v*"] } }
jobs:
  certify:
    permissions: { contents: read, id-token: write, attestations: write }
    uses: workrr-trust/certify/.github/workflows/certify.yml@v0.1.1
    with:
      path: skills/my-skill
```

The workflow:
1. **`resolve`** reads its own commit from its OIDC token, so the certifier code that
   runs is the code the signing identity names.
2. **`test`** runs the artifact's declared suite (`workrr.json` →
   `{"test":{"command":"..."}}`). It has **no signing permission**, because it runs
   artifact code.
3. **`certify`** re-derives the digest, runs the provenance, policy, and known-pattern
   scan checks, and accepts the test report only if its digest matches. If everything
   passes, it signs with Sigstore via `actions/attest` and logs to public Rekor. The
   certificate is uploaded as the `workrr-certificate` artifact.

## Verify

```bash
# npm (published with provenance)
npx @workrr-trust/certify verify ./my-skill --bundle certificate.sigstore.json

# Go
go install github.com/workrr-trust/certify/go/cmd/workrr@latest
workrr verify ./my-skill --bundle certificate.sigstore.json
```

Prebuilt binaries for Linux, macOS and Windows are attached to each
[release](https://github.com/workrr-trust/certify/releases) with build attestations:
`gh attestation verify <file> --repo workrr-trust/certify`.

Checks the artifact digest, the Sigstore certificate chain and signature, Rekor
inclusion, that the signer is a released workrr certifier tag pinned in the trust
policy, and that the certificate is not revoked. The output names the publisher
repository and the policy name and digest. Silver, gold, and banded are reported
only when that digest is the known baseline. `--source <repo>` fails when the
certificate's publisher does not match. The default trust policy has no second
forge, so it does not award **Gold**.

`verify` fetches the signed trust policy from the trust API (cached for one hour)
and the revocation feed on every run. `--offline` uses the policy embedded in this
build and does not check revocation. It prints
`offline: using the embedded trust policy; revocation was not checked`. A revoked
certificate can still verify in that mode. The policy and revocation formats are
[spec §7](spec/README.md). Until the trust API is deployed, fetch failure falls
back to the embedded policy (the v0.1.0 and v0.1.1 tag pins) and says so.

## Local use

```bash
npm ci && npm run build
node dist/cli.js digest  <path>
node dist/cli.js certify <path> --run-tests   # local only; never in a signing job
npm test
```

## What the checks claim

| Check | Claim |
|---|---|
| provenance | The artifact is committed and unchanged at the recorded source commit |
| policy | Conforms to the named policy, pinned by digest. The name `workrr-baseline-v0.1` is reserved for that baseline; a verifier reports a baseline level only for its digest |
| scan | No high/critical findings from ruleset `workrr-scan-v0.1`, pinned by digest. **Not** "safe" or "injection-free." |
| tests | The artifact's own declared suite passed. Without a suite the level is `banded`. |

## Known limits (v0.1)

- The signed trust policy and revocation feed are implemented ([spec §7](spec/README.md),
  [trust API](docs/trust-api.md)). No policy has been signed or deployed yet, so
  `verify` falls back to the embedded policy and does not see revocations until
  that deploy. That fallback is the v0.1.2 trust set: only
  `certify.yml@refs/tags/v0.1.0` and `@refs/tags/v0.1.1`, each pinned to the Build
  Signer Digest Fulcio recorded for that annotated tag (the tag object, not the peeled
  commit). `refs/heads/main` is not accepted, and there is no GitLab certifier.
  `EMBEDDED_POLICY_SEQUENCE` is still 0. The policy-signer and revoke-signer Build
  Signer Digests are still empty. A release is not trusted until its tag object is added.
- A policy digest other than `workrr-baseline-v0.1` does not verify at a baseline
  level. Reusing that name on a different document is rejected.
- `--offline` skips revocation on purpose. See the warning it prints.
- Workflow actions are pinned by commit SHA.
- Private repos sign with GitHub's private Sigstore instance (no public Rekor entry). The
  private tier uses its own trust root and the hash-only public log design.
- There is no GitLab certifier in the trust set, so the default policy does not award
  Gold.
