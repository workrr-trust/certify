// The trust policy: which certifier identities a verifier accepts.
// v0.1.2 ships the default inline. v0.2 distributes it as a TUF-signed file under the
// offline workrr root key (docs/design.md §2).

export type Forge = "github" | "gitlab";

export type AcceptedSigner = {
  forge: Forge;
  issuer: string;
  // Anchored regular expression matched against the certificate SAN.
  subjectAlternativeName: string;
  // Pinned certifier identities (Build Signer Digest, OID 1.3.6.1.4.1.57264.1.10).
  // Empty means any commit of this workflow at that exact ref. The built-in policy
  // uses that only for the release that ships it (see NEWEST below); every older
  // release lists the digest Fulcio recorded for it. A custom --trust-policy file may.
  buildSignerDigests: string[];
  // "publisher" (the default): the signer runs in the artifact's own repo, and Fulcio's
  // source repo must match the certificate's source. "observer": a public scan run in
  // OBSERVER_REPOSITORY; it reports level "scanned" only (docs/public-scans.md).
  // "witness": the GitLab certifier run in WITNESS_REPOSITORY against a public commit;
  // alone it reports "scanned", and it makes a publisher's Tested certificate
  // Reproduced (gold) when both agree (docs/gitlab-certifier.md).
  role?: SignerRole;
};

export type SignerRole = "publisher" | "observer" | "witness";

// The only repository an observer signer may run in (Fulcio's SourceRepositoryURI).
export const OBSERVER_REPOSITORY = "https://github.com/workrr-trust/certify";

// The only repository a witness signer may run in: GitLab's copy of this repository.
export const WITNESS_REPOSITORY = "https://gitlab.com/workrr-trust/certify-gitlab";

export type TrustPolicy = { version: string; signers: AcceptedSigner[] };

// GitHub's job_workflow_sha for an annotated tag is the tag object, not the
// peeled commit. These are the Build Signer Digests on certificates from
// certify.yml@refs/tags/v0.1.0 to v0.1.3 (git rev-parse <tag>, not <tag>^{commit}).
//   v0.1.0 tag 9fbe3e453cbd80bef0301f08db79408bb12c7d64
//          commit edf382958dd7ce070db0ed13af1cc8c31a150901
//   v0.1.1 tag 78d8c1a98c929b7b1c1b532c25256582a84887b1
//          commit 5a1d5c47fc1175db9979e13a2301dae57458a135
//   v0.1.2 tag 7ed4c1ded5e6e611cfea5234b42d9601e827ff07
//          commit 2bbb72964e862c326af210c0117e47c740b463b0
//   v0.1.3 tag 7cf13e7228c6f2bdf01b6d3ab670edef6f77fe4b
//          commit 46c524bf97e8f580375edff746c847b86f4b23f9
//   v0.1.4 tag 54b6c3a8f7818d1c8edba145edbf2157c35208d9
//          commit 14466afa6a8bc8612292b74ae63e764590041031
//   v0.1.5 tag ab877ee7bc33604f1d1b95d7e1377f340fd5d476
//          commit 5fb6a6635f5cee1f8fe51cfa27fa997298d2faf3
//   v0.1.6 tag 90f9138d6ed5e55981ad1dbb90b5a2345f420b0e
//          commit a6aaa8f664d87f7dc2b8becb6382b29c15763025
//   v0.1.7 tag 6291248fc63176cbf4b182c0aaae5aae14819729
//          commit 0efed0e76b1d0be3d3488ead7ed26023dbe32be6
//   v0.1.8 tag 7b19119ca8e446e2fa533b366e6b6921f6349470
//          commit 723c2563519c43b86b4518339c13a6cf90fb57c2
//   v0.1.9 tag fc014737ebdaa35f618ba9abc4bf1dbcad7605d6
//          commit 9ac10f8660310f300ef7b5aed560388b06068746
//   v0.1.10 tag 8ce93989d40ef463444f6077ecc9222a69806b79
//          commit b20bff30d84ba48585517508829c45145b5d57b4
//
// scan.yml is dispatched directly (workflow_dispatch), not called, so for it Fulcio
// records the tagged COMMIT, not the tag object: scan.yml@v0.1.4 is 14466afa….
// GitLab's ci_config_sha is the tagged commit too.
//
// A release can't list its own digest: the tag object names the commit that would
// contain it. So the newest release is accepted by its exact tag name alone, and the
// next release pins its digest. That is safe because release tags are protected
// (only an org admin can create, move or delete v* tags) and the ledger's
// identity-watch alerts if a released tag ever moves.
const CERTIFY_SAN = String.raw`https://github\.com/workrr-trust/certify/\.github/workflows/certify\.yml@refs/tags/`;
const SCAN_SAN = String.raw`https://github\.com/workrr-trust/certify/\.github/workflows/scan\.yml@refs/tags/`;
const WITNESS_SAN = String.raw`https://gitlab\.com/workrr-trust/certify-gitlab//\.gitlab-ci\.yml@refs/tags/`;

export const DEFAULT_TRUST_POLICY: TrustPolicy = {
  version: "workrr-trust-policy-v0.1",
  signers: [
    {
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${CERTIFY_SAN}v0\\.1\\.0$`,
      buildSignerDigests: ["9fbe3e453cbd80bef0301f08db79408bb12c7d64"],
    },
    {
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${CERTIFY_SAN}v0\\.1\\.1$`,
      buildSignerDigests: ["78d8c1a98c929b7b1c1b532c25256582a84887b1"],
    },
    {
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${CERTIFY_SAN}v0\\.1\\.2$`,
      buildSignerDigests: ["7ed4c1ded5e6e611cfea5234b42d9601e827ff07"],
    },
    {
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${CERTIFY_SAN}v0\\.1\\.3$`,
      buildSignerDigests: ["7cf13e7228c6f2bdf01b6d3ab670edef6f77fe4b"],
    },
    {
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${CERTIFY_SAN}v0\\.1\\.4$`,
      buildSignerDigests: ["54b6c3a8f7818d1c8edba145edbf2157c35208d9"],
    },
    {
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${CERTIFY_SAN}v0\\.1\\.5$`,
      buildSignerDigests: ["ab877ee7bc33604f1d1b95d7e1377f340fd5d476"],
    },
    {
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${CERTIFY_SAN}v0\\.1\\.6$`,
      buildSignerDigests: ["90f9138d6ed5e55981ad1dbb90b5a2345f420b0e"],
    },
    {
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${CERTIFY_SAN}v0\\.1\\.7$`,
      buildSignerDigests: ["6291248fc63176cbf4b182c0aaae5aae14819729"],
    },
    {
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${CERTIFY_SAN}v0\\.1\\.8$`,
      buildSignerDigests: ["7b19119ca8e446e2fa533b366e6b6921f6349470"],
    },
    {
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${CERTIFY_SAN}v0\\.1\\.9$`,
      buildSignerDigests: ["fc014737ebdaa35f618ba9abc4bf1dbcad7605d6"],
    },
    {
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${CERTIFY_SAN}v0\\.1\\.10$`,
      buildSignerDigests: ["8ce93989d40ef463444f6077ecc9222a69806b79"],
    },
    {
      // NEWEST: this release, by exact tag; v0.1.12 pins its digest.
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${CERTIFY_SAN}v0\\.1\\.11$`,
      buildSignerDigests: [],
    },
    {
      // Public scans (scan.yml, workflow_dispatch): the tagged commit.
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${SCAN_SAN}v0\\.1\\.4$`,
      buildSignerDigests: ["14466afa6a8bc8612292b74ae63e764590041031"],
      role: "observer",
    },
    {
      // Public scans and signed findings: the tagged commit.
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${SCAN_SAN}v0\\.1\\.5$`,
      buildSignerDigests: ["5fb6a6635f5cee1f8fe51cfa27fa997298d2faf3"],
      role: "observer",
    },
    {
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${SCAN_SAN}v0\\.1\\.6$`,
      buildSignerDigests: ["a6aaa8f664d87f7dc2b8becb6382b29c15763025"],
      role: "observer",
    },
    {
      // Public scans and signed findings: the tagged commit.
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${SCAN_SAN}v0\\.1\\.7$`,
      buildSignerDigests: ["0efed0e76b1d0be3d3488ead7ed26023dbe32be6"],
      role: "observer",
    },
    {
      // Public scans and signed findings: the tagged commit.
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${SCAN_SAN}v0\\.1\\.8$`,
      buildSignerDigests: ["723c2563519c43b86b4518339c13a6cf90fb57c2"],
      role: "observer",
    },
    {
      // Public scans and signed findings: the tagged commit.
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${SCAN_SAN}v0\\.1\\.9$`,
      buildSignerDigests: ["9ac10f8660310f300ef7b5aed560388b06068746"],
      role: "observer",
    },
    {
      // Public scans and signed findings: the tagged commit.
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${SCAN_SAN}v0\\.1\\.10$`,
      buildSignerDigests: ["b20bff30d84ba48585517508829c45145b5d57b4"],
      role: "observer",
    },
    {
      // Public scans and signed findings. NEWEST, by exact tag; v0.1.12 pins its commit.
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${SCAN_SAN}v0\\.1\\.11$`,
      buildSignerDigests: [],
      role: "observer",
    },
    {
      // GitLab witness (.gitlab-ci.yml run in WITNESS_REPOSITORY): the tagged commit
      // (ci_config_sha). GitLab protects v* tags in that project too.
      forge: "gitlab",
      issuer: "https://gitlab.com",
      subjectAlternativeName: `^${WITNESS_SAN}v0\\.1\\.7$`,
      buildSignerDigests: ["0efed0e76b1d0be3d3488ead7ed26023dbe32be6"],
      role: "witness",
    },
    {
      // GitLab witness: the tagged commit (ci_config_sha).
      forge: "gitlab",
      issuer: "https://gitlab.com",
      subjectAlternativeName: `^${WITNESS_SAN}v0\\.1\\.8$`,
      buildSignerDigests: ["723c2563519c43b86b4518339c13a6cf90fb57c2"],
      role: "witness",
    },
    {
      // GitLab witness: the tagged commit (ci_config_sha).
      forge: "gitlab",
      issuer: "https://gitlab.com",
      subjectAlternativeName: `^${WITNESS_SAN}v0\\.1\\.9$`,
      buildSignerDigests: ["9ac10f8660310f300ef7b5aed560388b06068746"],
      role: "witness",
    },
    {
      // GitLab witness: the tagged commit (ci_config_sha).
      forge: "gitlab",
      issuer: "https://gitlab.com",
      subjectAlternativeName: `^${WITNESS_SAN}v0\\.1\\.10$`,
      buildSignerDigests: ["b20bff30d84ba48585517508829c45145b5d57b4"],
      role: "witness",
    },
    {
      // GitLab witness. NEWEST, by exact tag; v0.1.12 pins its commit.
      forge: "gitlab",
      issuer: "https://gitlab.com",
      subjectAlternativeName: `^${WITNESS_SAN}v0\\.1\\.11$`,
      buildSignerDigests: [],
      role: "witness",
    },
  ],
};
