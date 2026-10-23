# Certify an artifact in about five minutes

Certificates are signed by the reusable workflow
[`.github/workflows/certify.yml`](../.github/workflows/certify.yml) at a tag the
trust policy already pins. The GitHub Marketplace action
([`action.yml`](../action.yml)) only verifies. A composite action runs inside
your job, so a certificate it signed would name your workflow and would not
verify.

The artifact's repository has to be **public**. A private repository signs with
GitHub's private Sigstore instance and does not get a public Rekor entry.

## 1. Add the workflow

Copy [`examples/certify.yml`](../examples/certify.yml) to
`.github/workflows/workrr.yml` in the artifact's repository. Change `path` if
the artifact is not `skills/my-skill`.

```yaml
name: workrr

on:
  push:
    tags: ["v*"]

jobs:
  certify:
    permissions:
      contents: read
      id-token: write
      attestations: write
    uses: workrr-trust/certify/.github/workflows/certify.yml@v0.1.1
    with:
      path: skills/my-skill
```

`v0.1.0` is the other trusted tag. Those two are the only refs that verify.
Do not point this `uses` line at a commit SHA, at `main`, or at a tag you cut
yourself. `id-token` and `attestations` belong on this job because the called
workflow signs. Do not copy them onto a job that only verifies.

Same file, annotated, is the starter workflow GitHub shows under **New
workflow** in this repository
([`.github/workflow-templates/workrr-certify.yml`](../.github/workflow-templates/workrr-certify.yml)).

## 2. Point it at a real artifact

`path` is a file or directory in the repository being certified. A skill that
should reach **silver** needs a suite declared in `workrr.json`. Without a
suite the level is `banded`. A failing check signs nothing.

[`test/fixtures/good-skill`](../test/fixtures/good-skill) is a working example:
`SKILL.md`, `workrr.json`, and a `check.cjs` that exits 0.

## 3. Push a tag

```bash
git tag v1.0.0
git push origin v1.0.0
```

That tag is yours. It is not a workrr certifier identity.

## 4. Take the certificate

Open the workflow run and download the `workrr-certificate` artifact. The
bundle is `certificate.sigstore.json`.

## 5. Check it

```bash
npx @workrr-trust/certify verify ./skills/my-skill \
  --bundle certificate.sigstore.json \
  --source your-org/your-repo
```

Or fail a pull request in the consuming repository. Pin the verify action by
the full commit you reviewed. `v0.1.0` and `v0.1.1` do not contain `action.yml`.

```yaml
name: workrr

on:
  pull_request:

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
          source: your-org/your-repo
          level: silver
```

`level: gold` fails closed with the built-in policy: there is no second forge
in the trust set. The default minimum is silver. One accepted bundle is enough
for silver. Publishing the Marketplace listing is a separate step; see the
[README](../README.md#github-marketplace).
