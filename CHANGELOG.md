# Changelog

## 0.1.7 (2026-10-28)

Reproduced (gold) can be awarded. The second forge is the **GitLab witness**: this
release's `.gitlab-ci.yml`, run in `gitlab.com/workrr-trust/certify-gitlab` against
a public GitHub commit (docs/gitlab-certifier.md).

- Trust policy: new signer role `witness` for
  `https://gitlab.com/workrr-trust/certify-gitlab//.gitlab-ci.yml@refs/tags/v0.1.7`
  (issuer `https://gitlab.com`). Its Fulcio source repository must be that project.
  Alone it verifies as `scanned`; next to the publisher's own Tested certificate
  from GitHub for the same repository, commit, path and checks it makes `gold`.
- Removed the GitLab identities v0.1.1 listed for `certify-gitlab@v0.1.0/v0.1.1` and
  the ledger mirror's CI file. None was ever a signer, and the mirror is not a
  certifier.
- `.gitlab-ci.yml` rewritten: runs only in `certify-gitlab` on a release tag, builds
  the certifier from its own checkout (variables can no longer name another
  certifier repository or commit), and takes `WORKRR_REPO`, `WORKRR_COMMIT` and
  `WORKRR_PATH` for the commit to certify.
- `workrr certify --witness https://github.com/<owner>/<repo>` (TypeScript and Go):
  records that repository as the source of a checkout made outside its own CI.
  Tests still count.
- Gold compares the publisher (owner/repo across forges) as well as commit, path and
  checks. Any agreeing pair counts: a digest often has certificates from
  several commits.
- Signed trust policies: a signer with a role this release doesn't know is skipped
  instead of rejecting the policy. Releases before 0.1.7 reject a signed policy that
  lists the witness, so none is published while they are in use.
- Trust policy: pin v0.1.6: `certify.yml` to its tag object
  `90f9138d6ed5e55981ad1dbb90b5a2345f420b0e`, and `scan.yml` to the tagged commit
  `a6aaa8f664d87f7dc2b8becb6382b29c15763025`. Accept this release by exact tag
  until v0.1.8 pins it.
- `watch.yml` dispatches `scan.yml` at v0.1.7.

## 0.1.6 (2026-10-28)

Fewer false findings. The first public backfill flagged wording that is not
concealment; this release narrows the rules that misfired. Every finding v0.1.5
signed stays in Rekor and the ledger; the targets it flagged are re-scanned at
this release, and the newest result is what listings show.

- **Ruleset `workrr-scan-v0.2`** (new ruleset digest):
  - WT007 matches "do not / don't / never tell (or inform) the user about / that
    …" and "… mention / reveal / disclose … to the user". It no longer matches
    "don't tell the user *to* do something", "what / whether" or "show". A match
    right after a quote mark is an example being discussed, not an instruction.
  - WT008 needs a specific phrase in the hidden comment: instruction-override
    wording, "you are now", "exfiltrate", or "don't tell the user". The v0.1 words
    `ignore`, `instruction`, `you are`, `assistant` and `system prompt` matched
    `prettier-ignore`, template notes and diagram labels.
  - WT001, WT007 and WT008 skip tests, fixtures and snapshots. Shell, credential
    and character rules (WT002–WT006) do not.
- **Finding kind**: `concealment` now means WT002 or WT003 outside tests and
  fixtures. WT007 and WT008 findings are `check` (they get the fix window).
- Shared rule cases (`test/fixtures/scan-rule-cases.json`), taken from wording
  v0.1 matched in public repositories, run in both the TypeScript and Go tests.
- Trust policy: pin v0.1.5: `certify.yml` to its tag object
  `ab877ee7bc33604f1d1b95d7e1377f340fd5d476`, and `scan.yml` to the tagged commit
  `5fb6a6635f5cee1f8fe51cfa27fa997298d2faf3`. Accept this release by exact tag
  until v0.1.7 pins it.
- `watch.yml` dispatches `scan.yml` at v0.1.6.

## 0.1.5 (2026-10-28)

- **Signed findings** ([docs/findings.md](docs/findings.md)): a public scan that
  fails a security check (a high or critical scan rule, a compiled binary, an
  escaping symlink) signs a finding with its own predicate type,
  `https://trust.workrr.ai/finding/v0.1`, so it can never verify as a certificate.
  It states facts: rule, file, line, commit, and a kind (`concealment` for WT002,
  WT003, WT007, WT008; otherwise `check`). Layout problems alone sign nothing.
  `workrr certify --observe … --finding-out finding.json` writes it.
- `workrr verify-finding <path> --bundle <file>` (TypeScript and Go): checks the
  signature, Rekor inclusion and observer signer, then reproduces the finding by
  re-running the checks on the checkout. Only observer signers may issue findings.
- **Level names** for scrutiny: Scanned, Signed, Tested, Reproduced (wire values
  `scanned`, `banded`, `silver`, `gold` unchanged). The verify headline is now
  `VERIFIED · Tested (silver)`; scripts matching `level silver` need updating.
  `--min-level` and the action's `level` accept either name.
- `scan.yml` takes a batch of up to 50 targets (`targets` JSON input) and runs them
  as a matrix; each job uploads `workrr-scan-<index>` with `statement.json` and the
  signed bundle. Single-target inputs still work.
- `watch.yml` + `scripts/watch.mjs`: hourly, checks targets from the ledger's
  `scan-targets.txt` (about 3,000 per run, each once a day; GH Archive pushes
  first) and dispatches `scan.yml` for any path with a new commit. No signing
  permission.
- Trust policy: pin v0.1.4: `certify.yml` to its tag object
  `54b6c3a8f7818d1c8edba145edbf2157c35208d9`, and `scan.yml` to the tagged commit
  `14466afa6a8bc8612292b74ae63e764590041031` (dispatched workflows record the
  commit). Accept this release (`certify.yml` and `scan.yml` at
  `refs/tags/v0.1.5`) by exact tag until v0.1.6 pins it.

## 0.1.4 (2026-10-27)

- **Public scans** ([docs/public-scans.md](docs/public-scans.md)): a new level,
  `scanned`, for certificates that need nothing installed by the maintainer.
  `.github/workflows/scan.yml` runs in this repo at a release tag, reads a public
  commit (it never runs the project's code), and signs with Sigstore. The trust
  policy lists it as an `observer` signer. Verifiers accept an observer only from
  `workrr-trust/certify`, only at level `scanned` with tests `none`, and never count
  it toward Gold. When a maintainer certificate also verifies, the maintainer's
  level is reported. `scanned` ranks below `banded` in `gate` and the verify action.
  Verifiers v0.1.3 and earlier reject scanned certificates, so older clients fail
  closed.
- `workrr certify --observe <repo-url>` (TypeScript and Go).
- Trust policy: pin v0.1.3 to its tag object
  `7cf13e7228c6f2bdf01b6d3ab670edef6f77fe4b`, and accept this release
  (`certify.yml` and `scan.yml` at `refs/tags/v0.1.4`) by exact tag until v0.1.5
  pins it.

## 0.1.3 (2026-10-26)

- `certify.yml`: each call names its tests report `workrr-tests-report-<hash of path>`
  and downloads it by that name. The 0.1.2 fix (download by artifact ID) did not
  work: download-artifact only sees the newest artifact of each name, even when
  asked by ID, so with two or more certify calls in one run all but one still
  failed. Tested with three calls in one run.
- Trust policy: pin v0.1.2 to its tag object
  `7ed4c1ded5e6e611cfea5234b42d9601e827ff07`, and accept this release
  (`certify.yml@refs/tags/v0.1.3`) by exact tag until v0.1.4 pins it.

## 0.1.2 (2026-10-26)

- Trust policy: accept certificates from this release (`certify.yml@refs/tags/v0.1.2`)
  by exact tag. A release can't pin its own tag digest, so v0.1.3 pins it. Release
  tags are protected, and the ledger's identity-watch alerts if one moves.
- `certify.yml`: download the tests report by artifact ID. With two or more certify
  calls in one workflow run, a certify job could get another call's report and fail.

### Security

- The built-in trust policy accepts only `certify.yml` at `refs/tags/v0.1.0`,
  `v0.1.1` and `v0.1.2`. The first two are pinned to the Build Signer Digest Fulcio
  recorded for that annotated tag
  (`9fbe3e453cbd80bef0301f08db79408bb12c7d64` and
  `78d8c1a98c929b7b1c1b532c25256582a84887b1`). Those are the tag objects, not the
  peeled commits. v0.1.2 is accepted by exact tag until v0.1.3 pins it.
  `refs/heads/main` is not accepted.
- The unpublished GitLab certifier (`workrr-trust/certify-gitlab`) is not in the
  trust set. The default policy does not award Gold.
- `verify` reports the policy name and digest from the certificate. A digest that
  is not `workrr-baseline-v0.1` does not verify at a baseline level (`silver`,
  `gold`, or `banded`). The result is `custom policy, not baseline`.
- The name `workrr-baseline-v0.1` is reserved. A custom policy that reuses it,
  including a one-line `{"name":"workrr-baseline-v0.1"}`, fails certification, and
  a certificate that reuses it with any other digest is rejected.
- `verify --source <repo>` fails when the certificate's publisher repository does
  not match.
- Every action in `certify.yml`, `ci.yml`, and `release.yml` is pinned by commit
  SHA. The one-time npm bootstrap token is removed; publish uses trusted
  publishing only.
- The root Marketplace action does not sign and is not a trusted signer. The
  trust set is `certify.yml` at v0.1.0, v0.1.1 and v0.1.2.

### Added

- Root `action.yml` (`workrr verify`) is a verify-only GitHub Action eligible
  for the Marketplace. It fails the job unless a certificate meets a minimum
  level and source, using the built-in trust policy of the pinned commit.
  Certification stays on `.github/workflows/certify.yml`. A copy-paste
  quickstart and starter workflows cover publishers; consumers use the action.

### Breaking

- Certificates signed from `refs/heads/main`, from any tag other than v0.1.0,
  v0.1.1 and v0.1.2, or by the GitLab identity no longer verify.
- Certificates whose policy digest is not the baseline no longer verify as
  silver, gold, or banded.
