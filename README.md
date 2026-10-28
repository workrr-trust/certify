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
| **GitHub Action** | [`workrr verify`](action.yml) — Marketplace consumer gate (verify only). [Quickstart](docs/quickstart.md) |
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
on: { push: { branches: [main], tags: ["v*"] }, workflow_dispatch: {} }
jobs:
  certify:
    permissions: { contents: read, id-token: write, attestations: write }
    uses: workrr-trust/certify/.github/workflows/certify.yml@v0.1.5
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

Annotated copy: [`examples/certify.yml`](examples/certify.yml) and the
[five-minute quickstart](docs/quickstart.md). Do not replace this job with the
root action. That action cannot certify. See [GitHub Marketplace](#github-marketplace).

## Public scans (nothing to install)

A maintainer who doesn't want an outside workflow in their repo can still have a
certificate. workrr runs [`scan.yml`](.github/workflows/scan.yml) in this repo at a
release tag. It reads a public commit, never runs the project's code, and signs the
result. The level is **Scanned**: anyone can reproduce it, it is not signed by the
maintainer, and it ranks below Signed. See [docs/public-scans.md](docs/public-scans.md).

A scan that fails a security check signs a **finding** instead: a reproducible,
factual record (rule, file, line, commit) that `workrr verify-finding` re-checks.
[`watch.yml`](.github/workflows/watch.yml) re-scans each target when its path
changes. There is no opt-out from scanning public code. See [docs/findings.md](docs/findings.md).

## Levels

Named for how much scrutiny an artifact got. Signed predicates keep the v0.1 wire
values; verifiers print both (`VERIFIED · Tested (silver)`).

| Level | Wire value | What happened |
|---|---|---|
| Scanned | `scanned` | workrr read a public commit; checks passed; not signed by the maintainer |
| Signed | `banded` | The maintainer's own CI signed it; checks passed |
| Tested | `silver` | Signed, and the artifact's tests passed in an isolated job |
| Reproduced | `gold` | Two independent forges certified the same digest |

**Flagged** is outside the ladder: a signed finding for the newest commit.

## GitHub Marketplace

The action GitHub Marketplace can list is **`workrr verify`**
([`action.yml`](action.yml)). It is a consumer gate: one step fails the job
unless an artifact already has a workrr certificate at the level and source you
name.

### Why this action does not certify

A certificate is trusted only when its Fulcio identity is

`https://github.com/workrr-trust/certify/.github/workflows/certify.yml@refs/tags/v0.1.0`

or the same path at `v0.1.1` to `v0.1.5`. Each released tag except the
newest is pinned to its annotated tag object, the Build Signer Digest Fulcio records
(`9fbe3e45…`, `78d8c1a9…`, `7ed4c1de…`, `7cf13e72…`, `54b6c3a8…`; full values in
[`src/trust-policy.ts`](src/trust-policy.ts)). The newest release (`v0.1.5`) is
accepted by exact tag, because a release can't contain its own tag object; the next
release pins it. Release tags are protected, and the public ledger alerts if one moves.

Fulcio sets that identity from `job_workflow_ref` of the **called reusable
workflow**, not from the caller. A composite `action.yml` does not get its own
job. Its steps run inside the caller's job, so a signature minted there would
name the caller's workflow. The trust policy rejects that certificate.
Certification stays on [`.github/workflows/certify.yml`](.github/workflows/certify.yml)
at a released tag (`v0.1.5` today). Public scans and findings sign from
[`scan.yml`](.github/workflows/scan.yml) instead (level Scanned; see above). It is
dispatched, not called, so Fulcio records the tagged commit for it, and older
releases of it are pinned to that commit (`14466afa…` for `v0.1.4`).

The action also has no input that replaces the trust policy. The signer set is
the built-in policy in the commit you pin. `level: gold` fails closed today:
the built-in policy has no second forge.

Publishers: [`docs/quickstart.md`](docs/quickstart.md). Consumers:

```yaml
permissions:
  contents: read

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: workrr-trust/certify@<40-character SHA>
        with:
          path: skills/my-skill
          bundle: certificate.sigstore.json
          source: owner/repo
          level: silver
```

Replace `<40-character SHA>` with the full commit you reviewed (from `v0.1.2`
on, a release tag's commit contains `action.yml`). `v0.1.0` and `v0.1.1` do not
contain it. Do not use a moving tag. Grant `contents:
read` only. `id-token` and `attestations` belong on the certify job, not here.

In this repository the same step is `uses: ./` ([`examples/verify.yml`](examples/verify.yml)).
Starter workflows live in [`.github/workflow-templates/`](.github/workflow-templates/).

The verifier is built from that commit's `package-lock.json` (`npm ci`), not
from an npm dist-tag. The install does not run dependency scripts, and the
step clears the OIDC request variables before it builds.

### Publishing the listing

This repository does not publish itself. An owner does the following after
review. Never move a release tag.

1. Merge the change that adds `action.yml`. Confirm the repository is public
   and that `action.yml` is the only action metadata file at the repository
   root. Marketplace lists that file. Workflows and the Go module stay in this
   repo so the verifier and the certifier are the same commit.
2. Confirm `name` is `workrr verify`, with `branding.icon: shield` and
   `branding.color: blue`. An organization named `Workrr` already exists, so
   the name must not be `workrr`. GitHub also rejects a name that matches an
   existing Marketplace action or a Marketplace category. If it rejects
   `workrr verify`, rename `name` and release again. Do not rename by moving a
   tag.
3. Accept the [GitHub Marketplace Developer Agreement](https://docs.github.com/en/site-policy/github-terms/github-marketplace-developer-agreement).
   An organization owner has to do this. Open `action.yml` on GitHub; the
   publish banner links the agreement when it is still outstanding. The
   publish checkbox stays disabled until an owner accepts it.
4. Turn on two-factor authentication for the account that publishes. GitHub
   requires it to publish a release.
5. Cut a **new** immutable tag. `release.yml` runs on `v*` and requires
   `package.json`, `src/version.ts`, and `go/certify.go` to equal the tag.
   Bump those three to X.Y.Z and merge that first. Then,
   because tags are protected and the workflow cannot create them:
   `git tag -a vX.Y.Z -m vX.Y.Z`, `git tag -a go/vX.Y.Z -m go/vX.Y.Z` on the
   same commit, and `git push origin vX.Y.Z go/vX.Y.Z`.
6. Before tagging, the release commit's trust policy must pin the previous
   release's tag object (`git rev-parse vPREV`, not `vPREV^{commit}`) and accept
   `certify.yml@refs/tags/vX.Y.Z` by exact tag. A release can't pin its own tag
   object; the next release does. Then regenerate the test vectors
   (`node spec/test-vectors/generate.mjs && node spec/trust-feed/generate.mjs`).
7. Let `release.yml` create the GitHub release and publish npm. It does not
   tick the Marketplace checkbox. If you create the release from the
   `action.yml` banner first, `gh release create` inside `release.yml` can
   fail because the release already exists. The npm job is separate; check it.
8. Edit the release. Check **Publish this Action to the GitHub Marketplace**.
   Fix any metadata warning until GitHub reports that everything looks good.
   Primary category: **Security**. Publish. That is the step that lists the
   action.
9. Do not create a floating major tag (`v1`, `v0`). A tag in this repository
   is never moved. Consumers pin `workrr verify` by full commit SHA. After the
   release exists, `git rev-parse vX.Y.Z^{commit}` is that SHA. A Marketplace
   "use latest" snippet that inserts `@vX.Y.Z` is a tag; replace it with the
   commit SHA.
10. Smoke the listing from a different public repository: one step, SHA pin,
    `contents: read`, no OIDC permission. A missing bundle fails the job. A
    certificate from `certify.yml@v0.1.5` passes at `level: silver` when
    `source` is the publisher.

## Verify

```bash
# npm (published with provenance)
npx @workrr-trust/certify verify ./my-skill --bundle certificate.sigstore.json

# Go
go install github.com/workrr-trust/certify/go/cmd/workrr@latest
workrr verify ./my-skill --bundle certificate.sigstore.json

# Machine-readable JSON output (ok, level, artifactDigest, source, policyName, policyDigest, policyStatus, bundles, notes)
npx @workrr-trust/certify verify ./my-skill --bundle certificate.sigstore.json --json
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
back to the embedded policy (the released tags, as above) and says so.

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
| tests | The artifact's own declared suite passed. Without a suite the level is Signed (`banded`). |

## Known limits (v0.1)

- The signed trust policy and revocation feed are implemented ([spec §7](spec/README.md),
  [trust API](docs/trust-api.md)). No policy has been signed or deployed yet, so
  `verify` falls back to the embedded policy and does not see revocations until
  that deploy. That fallback is the v0.1.5 trust set: `certify.yml` at
  `refs/tags/v0.1.0` to `v0.1.4`, each pinned to the Build Signer Digest Fulcio
  recorded for that annotated tag (the tag object, not the peeled commit), and
  `v0.1.5` by exact tag, plus the `scan.yml` observer at `v0.1.4` (pinned to its
  commit) and `v0.1.5` (by exact tag). `refs/heads/main` is not accepted. `EMBEDDED_POLICY_SEQUENCE` is still 0.
  The policy-signer and revoke-signer Build Signer Digests are still empty.
- The Marketplace action only verifies. It does not add a signer. A certificate
  still has to come from `certify.yml` at a released tag.
- A policy digest other than `workrr-baseline-v0.1` does not verify at a baseline
  level. Reusing that name on a different document is rejected.
- `--offline` skips revocation on purpose. See the warning it prints.
- Workflow actions are pinned by commit SHA.
- Private repos sign with GitHub's private Sigstore instance (no public Rekor entry). The
  private tier uses its own trust root and the hash-only public log design.
- There is no GitLab certifier in the trust set, so the default policy does not award
  Gold.
