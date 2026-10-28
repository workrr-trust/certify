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
  role?: SignerRole;
};

export type SignerRole = "publisher" | "observer";

// The only repository an observer signer may run in (Fulcio's SourceRepositoryURI).
export const OBSERVER_REPOSITORY = "https://github.com/workrr-trust/certify";

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
//
// scan.yml is dispatched directly (workflow_dispatch), not called, so for it Fulcio
// records the tagged COMMIT, not the tag object: scan.yml@v0.1.5 is 14466afa….
//
// A release can't list its own digest: the tag object names the commit that would
// contain it. So the newest release is accepted by its exact tag name alone, and the
// next release pins its digest. That is safe because release tags are protected
// (only an org admin can create, move or delete v* tags) and the ledger's
// identity-watch alerts if a released tag ever moves.
const CERTIFY_SAN = String.raw`https://github\.com/workrr-trust/certify/\.github/workflows/certify\.yml@refs/tags/`;
const SCAN_SAN = String.raw`https://github\.com/workrr-trust/certify/\.github/workflows/scan\.yml@refs/tags/`;
const GITLAB_CERTIFY_SAN = String.raw`https://gitlab\.com/workrr-trust/(?:certify(?:-gitlab)?//?\.gitlab-ci\.yml|ledger//?mirror/gitlab-ci\.yml)@refs/tags/`;

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
      // NEWEST: this release, by exact tag; v0.1.6 pins its digest.
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${CERTIFY_SAN}v0\\.1\\.5$`,
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
      // Public scans and signed findings. NEWEST, by exact tag; v0.1.6 pins its commit.
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName: `^${SCAN_SAN}v0\\.1\\.5$`,
      buildSignerDigests: [],
      role: "observer",
    },
    {
      forge: "gitlab",
      issuer: "https://gitlab.com",
      subjectAlternativeName: `^${GITLAB_CERTIFY_SAN}v0\\.1\\.0$`,
      buildSignerDigests: ["9fbe3e453cbd80bef0301f08db79408bb12c7d64"],
    },
    {
      forge: "gitlab",
      issuer: "https://gitlab.com",
      subjectAlternativeName: `^${GITLAB_CERTIFY_SAN}v0\\.1\\.1$`,
      buildSignerDigests: ["78d8c1a98c929b7b1c1b532c25256582a84887b1"],
    },
  ],
};
