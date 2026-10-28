// The trust policy: which certifier identities a verifier accepts.
// v0.1.2 ships the default inline. v0.2 distributes it as a TUF-signed file under the
// offline workrr root key (docs/design.md §2).
package certify

type Forge string

const (
	ForgeGitHub Forge = "github"
	ForgeGitLab Forge = "gitlab"
)

type AcceptedSigner struct {
	Forge  Forge  `json:"forge"`
	Issuer string `json:"issuer"`
	// Anchored regular expression matched against the certificate SAN.
	SubjectAlternativeName string `json:"subjectAlternativeName"`
	// Pinned certifier identities (Build Signer Digest, OID 1.3.6.1.4.1.57264.1.10).
	// Empty means any commit of this workflow. The built-in policy never uses that:
	// every older release lists the digest Fulcio recorded for it; the release that
	// ships the policy is accepted by its exact tag (see below). A custom
	// --trust-policy file may leave it empty.
	BuildSignerDigests []string `json:"buildSignerDigests"`
	// "" or "publisher": the signer runs in the artifact's own repo, and Fulcio's
	// source repo must match the certificate's source. "observer": a public scan run
	// in ObserverRepository; it reports level "scanned" only (docs/public-scans.md).
	Role string `json:"role,omitempty"`
}

// RoleObserver marks a public-scan signer.
const RoleObserver = "observer"

// ObserverRepository is the only repository an observer signer may run in.
const ObserverRepository = "https://github.com/workrr-trust/certify"

type TrustPolicy struct {
	Version string           `json:"version"`
	Signers []AcceptedSigner `json:"signers"`
}

// GitHub's job_workflow_sha for an annotated tag is the tag object, not the
// peeled commit. These are the Build Signer Digests on certificates from
// certify.yml@refs/tags/v0.1.0 to v0.1.3 (git rev-parse <tag>, not <tag>^{commit}).
//
//	v0.1.0 tag 9fbe3e453cbd80bef0301f08db79408bb12c7d64
//	       commit edf382958dd7ce070db0ed13af1cc8c31a150901
//	v0.1.1 tag 78d8c1a98c929b7b1c1b532c25256582a84887b1
//	       commit 5a1d5c47fc1175db9979e13a2301dae57458a135
//	v0.1.2 tag 7ed4c1ded5e6e611cfea5234b42d9601e827ff07
//	       commit 2bbb72964e862c326af210c0117e47c740b463b0
//	v0.1.3 tag 7cf13e7228c6f2bdf01b6d3ab670edef6f77fe4b
//	       commit 46c524bf97e8f580375edff746c847b86f4b23f9
//	v0.1.4 tag 54b6c3a8f7818d1c8edba145edbf2157c35208d9
//	       commit 14466afa6a8bc8612292b74ae63e764590041031
//
// scan.yml is dispatched directly (workflow_dispatch), not called, so for it Fulcio
// records the tagged COMMIT, not the tag object: scan.yml@v0.1.5 is 14466afa….
//
// A release can't list its own digest: the tag object names the commit that would
// contain it. So the newest release is accepted by its exact tag name alone, and the
// next release pins its digest. That is safe because release tags are protected
// (only an org admin can create, move or delete v* tags) and the ledger's
// identity-watch alerts if a released tag ever moves.
const certifySAN = `https://github\.com/workrr-trust/certify/\.github/workflows/certify\.yml@refs/tags/`
const scanSAN = `https://github\.com/workrr-trust/certify/\.github/workflows/scan\.yml@refs/tags/`
const gitlabCertifySAN = `https://gitlab\.com/workrr-trust/(?:certify(?:-gitlab)?//?\.gitlab-ci\.yml|ledger//?mirror/gitlab-ci\.yml)@refs/tags/`

var DefaultTrustPolicy = TrustPolicy{
	Version: "workrr-trust-policy-v0.1",
	Signers: []AcceptedSigner{
		{
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + certifySAN + `v0\.1\.0$`,
			BuildSignerDigests:     []string{"9fbe3e453cbd80bef0301f08db79408bb12c7d64"},
		},
		{
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + certifySAN + `v0\.1\.1$`,
			BuildSignerDigests:     []string{"78d8c1a98c929b7b1c1b532c25256582a84887b1"},
		},
		{
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + certifySAN + `v0\.1\.2$`,
			BuildSignerDigests:     []string{"7ed4c1ded5e6e611cfea5234b42d9601e827ff07"},
		},
		{
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + certifySAN + `v0\.1\.3$`,
			BuildSignerDigests:     []string{"7cf13e7228c6f2bdf01b6d3ab670edef6f77fe4b"},
		},
		{
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + certifySAN + `v0\.1\.4$`,
			BuildSignerDigests:     []string{"54b6c3a8f7818d1c8edba145edbf2157c35208d9"},
		},
		{
			// Newest: this release, by exact tag; v0.1.6 pins its digest.
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + certifySAN + `v0\.1\.5$`,
			BuildSignerDigests:     []string{},
		},
		{
			// Public scans (scan.yml, workflow_dispatch): the tagged commit.
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + scanSAN + `v0\.1\.4$`,
			BuildSignerDigests:     []string{"14466afa6a8bc8612292b74ae63e764590041031"},
			Role:                   RoleObserver,
		},
		{
			// Public scans and signed findings. Newest, by exact tag; v0.1.6 pins its commit.
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + scanSAN + `v0\.1\.5$`,
			BuildSignerDigests:     []string{},
			Role:                   RoleObserver,
		},
		{
			Forge:                  ForgeGitLab,
			Issuer:                 "https://gitlab.com",
			SubjectAlternativeName: `^` + gitlabCertifySAN + `v0\.1\.0$`,
			BuildSignerDigests:     []string{"9fbe3e453cbd80bef0301f08db79408bb12c7d64"},
		},
		{
			Forge:                  ForgeGitLab,
			Issuer:                 "https://gitlab.com",
			SubjectAlternativeName: `^` + gitlabCertifySAN + `v0\.1\.1$`,
			BuildSignerDigests:     []string{"78d8c1a98c929b7b1c1b532c25256582a84887b1"},
		},
	},
}
