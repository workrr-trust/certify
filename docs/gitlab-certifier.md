# GitLab Certifier & Two-Forge Gold Setup

`workrr-trust/certify` ships `.gitlab-ci.yml` at the repository root so the same tagged certifier release can run on GitLab CI (`https://gitlab.com/workrr-trust/ledger` via `mirror/gitlab-ci.yml` or `https://gitlab.com/workrr-trust/certify-gitlab` via `.gitlab-ci.yml`) and issue a second, independent Silver certificate for **Gold** verification.

## 1. Public GitLab Mirror (`gitlab.com/workrr-trust/ledger`)

`https://gitlab.com/workrr-trust/ledger` is already public and syncing on a 6-hourly pipeline schedule via `mirror/gitlab-ci.yml`. The trust policy in `src/trust-policy.ts` and `go/trustpolicy.go` accepts tagged certifier runs from both `gitlab.com/workrr-trust/ledger//mirror/gitlab-ci.yml@refs/tags/v0.1.x` and `gitlab.com/workrr-trust/certify-gitlab//.gitlab-ci.yml@refs/tags/v0.1.x` pinned to the exact release tag object digests (`v0.1.0`, `v0.1.1`).

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
