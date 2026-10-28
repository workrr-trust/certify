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
	// "witness": the GitLab certifier run in WitnessRepository against a public
	// commit; alone it reports "scanned", and it makes a publisher's Tested
	// certificate Reproduced (gold) when both agree (docs/gitlab-certifier.md).
	Role string `json:"role,omitempty"`
}

// RoleObserver marks a public-scan signer.
const RoleObserver = "observer"

// RoleWitness marks the GitLab witness signer.
const RoleWitness = "witness"

// ObserverRepository is the only repository an observer signer may run in.
const ObserverRepository = "https://github.com/workrr-trust/certify"

// WitnessRepository is the only repository a witness signer may run in: GitLab's
// copy of this repository.
const WitnessRepository = "https://gitlab.com/workrr-trust/certify-gitlab"

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
//	v0.1.5 tag ab877ee7bc33604f1d1b95d7e1377f340fd5d476
//	       commit 5fb6a6635f5cee1f8fe51cfa27fa997298d2faf3
//	v0.1.6 tag 90f9138d6ed5e55981ad1dbb90b5a2345f420b0e
//	       commit a6aaa8f664d87f7dc2b8becb6382b29c15763025
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
const certifySAN = `https://github\.com/workrr-trust/certify/\.github/workflows/certify\.yml@refs/tags/`
const scanSAN = `https://github\.com/workrr-trust/certify/\.github/workflows/scan\.yml@refs/tags/`
const witnessSAN = `https://gitlab\.com/workrr-trust/certify-gitlab//\.gitlab-ci\.yml@refs/tags/`

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
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + certifySAN + `v0\.1\.5$`,
			BuildSignerDigests:     []string{"ab877ee7bc33604f1d1b95d7e1377f340fd5d476"},
		},
		{
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + certifySAN + `v0\.1\.6$`,
			BuildSignerDigests:     []string{"90f9138d6ed5e55981ad1dbb90b5a2345f420b0e"},
		},
		{
			// Newest: this release, by exact tag; v0.1.8 pins its digest.
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + certifySAN + `v0\.1\.7$`,
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
			// Public scans and signed findings: the tagged commit.
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + scanSAN + `v0\.1\.5$`,
			BuildSignerDigests:     []string{"5fb6a6635f5cee1f8fe51cfa27fa997298d2faf3"},
			Role:                   RoleObserver,
		},
		{
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + scanSAN + `v0\.1\.6$`,
			BuildSignerDigests:     []string{"a6aaa8f664d87f7dc2b8becb6382b29c15763025"},
			Role:                   RoleObserver,
		},
		{
			// Public scans and signed findings. Newest, by exact tag; v0.1.8 pins its commit.
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^` + scanSAN + `v0\.1\.7$`,
			BuildSignerDigests:     []string{},
			Role:                   RoleObserver,
		},
		{
			// GitLab witness (.gitlab-ci.yml run in WitnessRepository). Newest, by exact
			// tag; v0.1.8 pins its commit. GitLab protects v* tags in that project too.
			Forge:                  ForgeGitLab,
			Issuer:                 "https://gitlab.com",
			SubjectAlternativeName: `^` + witnessSAN + `v0\.1\.7$`,
			BuildSignerDigests:     []string{},
			Role:                   RoleWitness,
		},
	},
}
