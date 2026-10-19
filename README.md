# workrr-trust/certify

Certify and verify AI agent artifacts (skills, MCP servers, rulesets, `AGENTS.md`)
with **publicly logged certificates anyone can verify without trusting Workrr**.

- **Certificate format:** [spec/README.md](spec/README.md) (in-toto Statement, predicate
  `https://trust.workrr.ai/certificate/v0.1`)
- **Design:** `docs/trust-authority.md` in [workrr-trust](https://github.com/shawnbure/workrr-trust)
- **License:** Apache-2.0

> Status: v0.1, pre-release. It lives in `certify/` of the workrr-trust repo until the
> `workrr-trust` GitHub org exists; it then becomes the root of `workrr-trust/certify`,
> whose workflow path is the certifier's public signing identity.

## Certify in CI (GitHub)

In the artifact's **public** repo:

```yaml
# .github/workflows/workrr.yml
on: { push: { tags: ["v*"] } }
jobs:
  certify:
    permissions: { contents: read, id-token: write, attestations: write }
    uses: workrr-trust/certify/.github/workflows/certify.yml@v0.1.0
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
npx @workrr-trust/certify verify ./my-skill --bundle certificate.sigstore.json
```

Checks the artifact digest, the Sigstore certificate chain and signature, Rekor
inclusion, and that the signer is an accepted Workrr certifier identity. Pass a second
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
  offline Workrr root key, and pins certifier commits (Build Signer Digest).
- Actions are pinned by major version; pin to commit SHAs before v1.
- Private repos sign with GitHub's private Sigstore instance (no public Rekor entry). The
  private tier uses its own trust root and the hash-only public log design.
- GitLab certifier (`workrr-trust/certify-gitlab`) isn't built yet, so no Gold
  certificates until it is.
