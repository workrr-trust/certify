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
inclusion, and that the signer is an accepted workrr certifier identity. Pass a second
`--bundle` from the GitLab certifier for **Gold**: two forges with identical results.

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
| policy | Conforms to the named policy, pinned by digest (default: `workrr-baseline-v0.1`) |
| scan | No high/critical findings from ruleset `workrr-scan-v0.1`, pinned by digest. **Not** "safe" or "injection-free." |
| tests | The artifact's own declared suite passed. Without a suite the level is `banded`. |

## Known limits (v0.1)

- Revocation isn't checked yet; the revocation ledger ships in v0.2.
- The trust policy is built into the CLI. v0.2 moves it to a TUF-signed file under the
  offline workrr root key, and pins certifier commits (Build Signer Digest).
- Actions are pinned by major version; pin to commit SHAs before v1.
- Private repos sign with GitHub's private Sigstore instance (no public Rekor entry). The
  private tier uses its own trust root and the hash-only public log design.
- GitLab certifier (`workrr-trust/certify-gitlab`) isn't built yet, so no Gold
  certificates until it is.
