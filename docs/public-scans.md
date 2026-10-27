# Public scans: certificates with nothing installed

A maintainer gets a **Silver** or **Banded** certificate by adding one workflow file
that calls `certify.yml`. That gives the strongest statement ("this repo's own CI
certified this commit"), but it asks a maintainer to grant an outside workflow
`id-token: write`. Many decline, and that is a reasonable choice.

A **public scan** needs nothing from the maintainer. workrr's certifier runs in
workrr's own public repository, reads a public commit, and signs what it saw. The
result is the level **`scanned`**.

## What a scanned certificate says

> workrr's open-source certifier, at release tag `vX.Y.Z`, read `<path>` in
> `<repo>` at commit `<sha>`, computed this digest, and the baseline policy and
> pattern scan passed.

What it does **not** say:

- It does not say the maintainer published or approved it. The Fulcio certificate
  names `workrr-trust/certify`, not the maintainer's repo.
- It does not say tests passed. A scan never runs the project's code, so `tests` is
  always `none`.
- It does not say "safe". Like every level, it reports which checks passed at one
  commit.

Levels from weakest to strongest are `scanned` < `banded` < `silver` < `gold`. A
scanned certificate never counts toward Gold. When a maintainer-signed certificate
also verifies for the same digest, the maintainer's level is reported.

## Why this keeps workrr out of the trust path

- **Open code.** `.github/workflows/scan.yml` lives in the public certify repo. It
  runs only at a protected release tag, and the trust policy pins that tag.
- **Open log.** Every run is a public GitHub Actions log. Every certificate is in
  Rekor, and the ledger indexes it alongside maintainer certificates.
- **Reproducible.** Anyone can check out the same commit, run
  `workrr certify --observe <repo>`, and get the same digest and check results. A
  scanned certificate claims nothing a reader can't recompute.
- **No hosting.** Nothing is copied. The certificate points at the repo and the
  commit.

workrr chooses *which* commits to scan, so a missing certificate means nothing.
Only a present one carries a claim, and anyone can check that claim.

## Mechanics

| | Maintainer path | Public scan |
|---|---|---|
| Runs in | maintainer's repo (`certify.yml`, `workflow_call`) | `workrr-trust/certify` (`scan.yml`, `workflow_dispatch` at a release tag) |
| Fulcio SAN | `…/certify.yml@refs/tags/vX` | `…/scan.yml@refs/tags/vX` |
| Fulcio source repo | the maintainer's repo, which must match `predicate.source` | `workrr-trust/certify`; `predicate.source` names the scanned repo |
| Tests | run in an unprivileged job | never run |
| Level | `silver` / `banded` | `scanned` (with the same A–E band rubric) |
| Attestation store | maintainer's repo | `workrr-trust/certify` |

In the trust policy, the `scan.yml` signer has `"role": "observer"`. Verifiers
handle an observer signer as follows:

1. The usual checks run: signature, Rekor inclusion, signer pinned by tag and Build
   Signer Digest, artifact digest.
2. The Fulcio source-repo cross-check is skipped, since the signer is not the
   publisher. The Fulcio source repo must instead be `workrr-trust/certify`.
3. Provenance, policy and scan must pass, `tests` must be `none`, and
   `predicate.level` must be `scanned`.
4. The reported level is `scanned`, and `--source` matches against
   `predicate.source`.

Verifiers from v0.1.3 and earlier don't know observers. They reject scanned
certificates because the source cross-check fails, so older clients fail closed.

## Running scans

```sh
gh workflow run scan.yml -R workrr-trust/certify --ref vX.Y.Z \
  -f repository=owner/repo -f commit=<40-hex> -f path=skills/name
```

The job refuses private repositories, non-40-hex commits and unsafe paths. Only
workrr-trust maintainers can dispatch it, and every dispatch is public.
