# Changelog

## 0.1.2 (unreleased)

- Trust policy: accept certificates from this release (`certify.yml@refs/tags/v0.1.2`,
  GitHub and GitLab) by exact tag. A release can't pin its own tag digest, so v0.1.3
  pins it. Without this, the v0.1.2 verifier would reject v0.1.2 certificates.
- `certify.yml`: download the tests report by artifact ID. With two or more certify
  calls in one workflow run, a certify job could get another call's report and fail.

### Security

- The built-in trust policy accepts only
  `certify.yml@refs/tags/v0.1.0` and `certify.yml@refs/tags/v0.1.1`. Each tag is
  pinned to the Build Signer Digest Fulcio recorded for that annotated tag
  (`9fbe3e453cbd80bef0301f08db79408bb12c7d64` and
  `78d8c1a98c929b7b1c1b532c25256582a84887b1`). Those are the tag objects, not the
  peeled commits. `refs/heads/main` is not accepted.
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
  trust set is unchanged: still only `certify.yml` at v0.1.0 and v0.1.1.

### Added

- Root `action.yml` (`workrr verify`) is a verify-only GitHub Action eligible
  for the Marketplace. It fails the job unless a certificate meets a minimum
  level and source, using the built-in trust policy of the pinned commit.
  Certification stays on `.github/workflows/certify.yml`. A copy-paste
  quickstart and starter workflows cover publishers; consumers use the action.

### Breaking

- Certificates signed from `refs/heads/main`, from any tag other than v0.1.0 and
  v0.1.1, or by the GitLab identity no longer verify.
- Certificates whose policy digest is not the baseline no longer verify as
  silver, gold, or banded.
- v0.1.2's own tag cannot be pinned in this commit: an annotated tag's Build
  Signer Digest does not exist until the tag is created. Certificates from that
  tag will not verify until a later release records the tag object.
