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
	// every released tag lists the digest Fulcio recorded for it. A custom
	// --trust-policy file still may.
	BuildSignerDigests []string `json:"buildSignerDigests"`
}

type TrustPolicy struct {
	Version string           `json:"version"`
	Signers []AcceptedSigner `json:"signers"`
}

// GitHub's job_workflow_sha for an annotated tag is the tag object, not the
// peeled commit. These are the Build Signer Digests on certificates from
// certify.yml@refs/tags/v0.1.0 and v0.1.1 (git rev-parse <tag>, not <tag>^{commit}).
//
//	v0.1.0 tag 9fbe3e453cbd80bef0301f08db79408bb12c7d64
//	       commit edf382958dd7ce070db0ed13af1cc8c31a150901
//	v0.1.1 tag 78d8c1a98c929b7b1c1b532c25256582a84887b1
//	       commit 5a1d5c47fc1175db9979e13a2301dae57458a135
const certifySAN = `https://github\.com/workrr-trust/certify/\.github/workflows/certify\.yml@refs/tags/`

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
	},
}
