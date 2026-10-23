# GitLab Certifier & Two-Forge Gold Setup

`workrr-trust/certify` ships `.gitlab-ci.yml` at the repository root so the same tagged certifier release can run on GitLab CI (`https://gitlab.com/workrr-trust/certify-gitlab`) and issue a second, independent Silver certificate for **Gold** verification.

## 1. Mirroring `workrr-trust/certify` to GitLab

1. Create the public GitLab group and project `https://gitlab.com/workrr-trust/certify-gitlab`.
2. Push this repository and its annotated release tags (`v0.1.0`, `v0.1.1`, and subsequent tags) to GitLab so the annotated tag objects match:
   ```bash
   git remote add gitlab https://gitlab.com/workrr-trust/certify-gitlab.git
   git push gitlab main --tags
   ```
   Because Git tag objects are content-addressed, pushing the annotated tags preserves the exact `Build Signer Digest` (`1.3.6.1.4.1.57264.1.10`) pinned in `src/trust-policy.ts` and `go/trustpolicy.go`.

## 2. Calling the GitLab certifier from an artifact repository

In the artifact's public GitLab repository (or GitLab mirror of a GitHub repository), add `.gitlab-ci.yml`:

```yaml
include:
  - project: workrr-trust/certify-gitlab
    file: /.gitlab-ci.yml
    ref: v0.1.1

variables:
  WORKRR_PATH: skills/my-skill
```

### Security isolation

Just like `.github/workflows/certify.yml` on GitHub Actions:
- `workrr-resolve` extracts `ci_config_sha` from the OIDC token so the certifier checkout matches the signing identity.
- `workrr-test` runs the artifact's declared test suite with **no `id_tokens`** (zero signing authority).
- `workrr-certify` requests `SIGSTORE_ID_TOKEN` (`aud: sigstore`), never executes artifact code, re-computes the artifact digest, checks that `tests.json` matches that digest, and signs the statement with Sigstore Fulcio + public Rekor via `scripts/gitlab-sign.mjs`.

## 3. Verifying Gold (Two-Forge Agreement)

Pass both the GitHub Actions bundle and the GitLab CI bundle to `workrr verify`:

```bash
npx @workrr-trust/certify verify ./skills/my-skill \
  --bundle github-certificate.sigstore.json \
  --bundle gitlab-certificate.sigstore.json \
  --source workrr-trust/sample-skills
```

A verifier awards **`gold`** only when:
1. Both bundles cryptographically verify against the Sigstore root and Rekor transparency log.
2. One bundle is signed by an accepted `github` certifier identity and the other by an accepted `gitlab` certifier identity in the trust policy.
3. Both certificates qualify for **`silver`** (`provenance`, `policy`, `scan`, and `tests` all `pass`) under the baseline policy.
4. Both certificates attest to the **same artifact digest**, **same source commit**, **same artifact path**, and **byte-identical canonical `checks`**.
