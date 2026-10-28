# GitLab witness and Reproduced (gold)

Reproduced (wire level `gold`) means two independent forges certified the same
artifact and agree. The first is the publisher's own Tested certificate from
[`certify.yml`](../.github/workflows/certify.yml) on GitHub Actions. The second is the
**GitLab witness**: the same certifier release, run on GitLab CI against the same
public commit. A compromised GitHub runner, account or OIDC issuer can't produce
both certificates. Neither can workrr: verifiers assign `gold` from what Rekor holds,
and no certifier can claim it.

## Why a dedicated project

GitLab signs keylessly only with `id_tokens` in the top-level `.gitlab-ci.yml` of the
project running the pipeline, so a CI file included from another project can't be
the signer. The witness is therefore its own public project,
[`gitlab.com/workrr-trust/certify-gitlab`](https://gitlab.com/workrr-trust/certify-gitlab):
GitLab's copy of this repository, with the same release tags. Its
[`.gitlab-ci.yml`](../.gitlab-ci.yml) certifies a public GitHub commit named by
pipeline variables. Fulcio records:

| Field | Value |
| --- | --- |
| SAN | `https://gitlab.com/workrr-trust/certify-gitlab//.gitlab-ci.yml@refs/tags/<tag>` |
| Issuer | `https://gitlab.com` |
| Build Signer Digest | the tagged commit (`ci_config_sha`) |
| Source repository | `https://gitlab.com/workrr-trust/certify-gitlab` |

The trust policy lists that identity with `"role": "witness"`, from v0.1.7. As with
`certify.yml`, the release that ships the policy is accepted by its exact tag and the
next release pins its commit. Tags `v*` are protected in that project.

## What a witness run does

A pipeline runs only in that project, on a `vX.Y.Z` tag, with:

| Variable | Value |
| --- | --- |
| `WORKRR_REPO` | `https://github.com/<owner>/<repo>` (public) |
| `WORKRR_COMMIT` | full commit SHA |
| `WORKRR_PATH` | artifact path in that repository |

- `workrr-test` (no `id_tokens`) builds the certifier from the tagged checkout, fetches
  the commit and runs the artifact's tests, as the `test` job does on GitHub.
- `workrr-certify` builds the certifier again, fetches the commit, runs
  `workrr certify --witness <repo>` (provenance, policy, scan, and the test report for
  that digest), and signs with Fulcio and public Rekor
  ([`scripts/gitlab-sign.mjs`](../scripts/gitlab-sign.mjs)). The certificate is the
  job artifact `certificate/certificate.sigstore.json`.

No variable can change the certifier code: it is the project's own checkout at the
tag. A run can only certify what a public commit contains, under the certifier's own
checks.

## Verifying

Pass both bundles:

```bash
npx @workrr-trust/certify verify ./skills/my-skill \
  --bundle github.sigstore.json --bundle gitlab.sigstore.json \
  --source workrr-trust/sample-skills
```

A verifier reports `gold` only when:

1. Both bundles verify: signature, Fulcio chain, Rekor inclusion.
2. One is signed by an accepted GitHub publisher identity (`certify.yml`) and derives
   `silver`; its Fulcio source repository and commit match its predicate.
3. The other is signed by the witness, ran in `certify-gitlab`, and derives `silver`.
4. Both name the same repository, commit and path, and their `checks` are
   byte-identical in canonical JSON. Both forges must therefore run the same
   certifier release: a different scan ruleset gives different checks.

Alone, a witness bundle verifies as `scanned`: workrr read a public commit, and the
maintainer didn't sign it.

## Where the witness certificate lives

The publisher's workflow that started the witness run stores the GitLab bundle in its
repository's GitHub attestation store, next to its own certificate
(`POST /repos/{owner}/{repo}/attestations`). The ledger pulls both from there and
verifies them like any other bundle; where a bundle is stored adds no trust.
[`workrr-trust/sample-skills`](https://github.com/workrr-trust/sample-skills) does this
on every push.

## Limits

- workrr starts witness runs (a pipeline trigger token). Today that is
  `workrr-trust/sample-skills` only. GitLab's free tier gives about 400 CI minutes a
  month, and a run takes a few.
- A publisher's own GitLab CI can't be a signer: GitLab can't sign from an included
  CI file, and the cert identity would be the publisher's project.
- Codeberg can't be a forge for Reproduced until public Fulcio trusts its OIDC issuer.
