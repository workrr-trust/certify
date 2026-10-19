// The trust policy: which certifier identities a verifier accepts.
// v0.1 ships the default inline. v0.2 distributes it as a TUF-signed file under the
// offline Workrr root key (docs/trust-authority.md §2).
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
	// Pinned certifier commits (Build Signer Digest, OID 1.3.6.1.4.1.57264.1.10).
	// Empty means "any commit of this workflow" — acceptable only before v1.
	BuildSignerDigests []string `json:"buildSignerDigests"`
}

type TrustPolicy struct {
	Version string           `json:"version"`
	Signers []AcceptedSigner `json:"signers"`
}

var DefaultTrustPolicy = TrustPolicy{
	Version: "workrr-trust-policy-v0.1",
	Signers: []AcceptedSigner{
		{
			Forge:                  ForgeGitHub,
			Issuer:                 "https://token.actions.githubusercontent.com",
			SubjectAlternativeName: `^https://github\.com/workrr-trust/certify/\.github/workflows/certify\.yml@refs/(tags/v\d+\.\d+\.\d+|heads/main)$`,
			BuildSignerDigests:     []string{},
		},
		{
			Forge:                  ForgeGitLab,
			Issuer:                 "https://gitlab.com",
			SubjectAlternativeName: `^https://gitlab\.com/workrr-trust/certify-gitlab//\.gitlab-ci\.yml@refs/(tags/v\d+\.\d+\.\d+|heads/main)$`,
			BuildSignerDigests:     []string{},
		},
	},
}
