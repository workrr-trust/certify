// The trust policy: which certifier identities a verifier accepts.
// v0.1 ships the default inline. v0.2 distributes it as a TUF-signed file under the
// offline workrr root key (docs/design.md §2).

export type Forge = "github" | "gitlab";

export type AcceptedSigner = {
  forge: Forge;
  issuer: string;
  // Anchored regular expression matched against the certificate SAN.
  subjectAlternativeName: string;
  // Pinned certifier commits (Build Signer Digest, OID 1.3.6.1.4.1.57264.1.10).
  // Empty means "any commit of this workflow" — acceptable only before v1.
  buildSignerDigests: string[];
};

export type TrustPolicy = { version: string; signers: AcceptedSigner[] };

export const DEFAULT_TRUST_POLICY: TrustPolicy = {
  version: "workrr-trust-policy-v0.1",
  signers: [
    {
      forge: "github",
      issuer: "https://token.actions.githubusercontent.com",
      subjectAlternativeName:
        String.raw`^https://github\.com/workrr-trust/certify/\.github/workflows/certify\.yml@refs/(tags/v\d+\.\d+\.\d+|heads/main)$`,
      buildSignerDigests: [],
    },
    {
      forge: "gitlab",
      issuer: "https://gitlab.com",
      subjectAlternativeName: String.raw`^https://gitlab\.com/workrr-trust/certify-gitlab//\.gitlab-ci\.yml@refs/(tags/v\d+\.\d+\.\d+|heads/main)$`,
      buildSignerDigests: [],
    },
  ],
};
