// Verify certificates (spec §6): digest → predicate type → Sigstore bundle
// (chain, signature, Rekor inclusion) → signer identity against the trust policy.
package certify

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sync"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// OIDBuildSignerDigest is the Fulcio extension that pins the certifier commit.
// sigstore-go decodes it into certificate.Extensions.BuildSignerDigest.
const OIDBuildSignerDigest = "1.3.6.1.4.1.57264.1.10"

type BundleResult struct {
	BundlePath     string `json:"bundlePath"`
	OK             bool   `json:"ok"`
	Error          string `json:"error,omitempty"`
	Forge          Forge  `json:"forge,omitempty"`
	SignerIdentity string `json:"signerIdentity,omitempty"`
	// Statement is the attestation payload exactly as signed (generic JSON).
	Statement any `json:"statement,omitempty"`
}

type VerifyResult struct {
	OK             bool           `json:"ok"`
	Level          string         `json:"level,omitempty"`
	ArtifactDigest string         `json:"artifactDigest"`
	Bundles        []BundleResult `json:"bundles"`
	Notes          []string       `json:"notes"`
}

// Signer is the certificate identity that signed a bundle.
type Signer struct {
	SAN               string
	Issuer            string
	BuildSignerDigest string // "" when the certificate has no such extension
}

func MatchSigner(policy *TrustPolicy, s *Signer) *AcceptedSigner {
	for i := range policy.Signers {
		a := &policy.Signers[i]
		if a.Issuer != s.Issuer {
			continue
		}
		re, err := regexp.Compile(a.SubjectAlternativeName)
		if err != nil || !re.MatchString(s.SAN) {
			continue
		}
		if len(a.BuildSignerDigests) == 0 || (s.BuildSignerDigest != "" && slices.Contains(a.BuildSignerDigests, s.BuildSignerDigest)) {
			return a
		}
	}
	return nil
}

// TrustedMaterialSource loads the Sigstore trust root once, on first use.
type TrustedMaterialSource struct {
	// Path to a trusted_root.json; empty fetches the public-good root via TUF
	// (cached under ~/.sigstore), as sigstore-js does.
	Path string
	once sync.Once
	tm   root.TrustedMaterial
	err  error
}

func (t *TrustedMaterialSource) Get() (root.TrustedMaterial, error) {
	t.once.Do(func() {
		if t.Path != "" {
			t.tm, t.err = root.NewTrustedRootFromPath(t.Path)
		} else {
			t.tm, t.err = root.FetchTrustedRoot()
		}
	})
	return t.tm, t.err
}

// VerifySigstore checks the certificate chain to the Fulcio root, the signed
// certificate timestamp, the signature, Rekor inclusion with an integrated
// timestamp, and that the in-toto subject carries the given digest. It returns
// the signing identity; matching it to a trust policy is the caller's job.
func VerifySigstore(b *bundle.Bundle, tm root.TrustedMaterial, digestAlg string, digest []byte) (*Signer, error) {
	v, err := verify.NewVerifier(tm,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, err
	}
	res, err := v.Verify(b, verify.NewPolicy(verify.WithArtifactDigest(digestAlg, digest), verify.WithoutIdentitiesUnsafe()))
	if err != nil {
		return nil, err
	}
	if res.Signature == nil || res.Signature.Certificate == nil {
		return nil, fmt.Errorf("bundle is not signed by a Fulcio certificate")
	}
	c := res.Signature.Certificate
	return &Signer{SAN: c.SubjectAlternativeName, Issuer: c.Extensions.Issuer, BuildSignerDigest: c.Extensions.BuildSignerDigest}, nil
}

func VerifyBundle(bundlePath, artifactDigest string, policy *TrustPolicy, tms *TrustedMaterialSource) BundleResult {
	fail := func(msg string, statement any) BundleResult {
		return BundleResult{BundlePath: bundlePath, OK: false, Error: msg, Statement: statement}
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return fail("cannot read bundle: "+err.Error(), nil)
	}
	var raw struct {
		DSSEEnvelope *struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fail("cannot read bundle: "+err.Error(), nil)
	}
	if raw.DSSEEnvelope == nil {
		return fail("bundle has no DSSE envelope (not an attestation)", nil)
	}
	payload, err := base64.StdEncoding.DecodeString(raw.DSSEEnvelope.Payload)
	if err != nil {
		return fail("attestation payload is not valid JSON", nil)
	}
	statement, err := DecodeJSON(payload)
	if err != nil {
		return fail("attestation payload is not valid JSON", nil)
	}
	st, _ := statement.(map[string]any)
	if pt, _ := st["predicateType"].(string); pt != PredicateType {
		got := "undefined"
		if v, ok := st["predicateType"]; ok {
			got = JSString(v)
		}
		return fail("unsupported predicate type: "+got, statement)
	}
	subjects, _ := st["subject"].([]any)
	if !slices.ContainsFunc(subjects, func(s any) bool {
		m, _ := s.(map[string]any)
		d, _ := m["digest"].(map[string]any)
		return d["sha256"] == artifactDigest
	}) {
		return fail("certificate is for a different artifact (digest mismatch)", statement)
	}

	digest, err := hex.DecodeString(artifactDigest)
	if err != nil {
		return fail("invalid artifact digest", statement)
	}
	tm, err := tms.Get()
	if err != nil {
		return fail("cannot load Sigstore trusted root: "+err.Error(), statement)
	}
	b, err := bundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return fail("signature verification failed: "+err.Error(), statement)
	}
	signer, err := VerifySigstore(b, tm, "sha256", digest)
	if err != nil {
		return fail("signature verification failed: "+err.Error(), statement)
	}
	accepted := MatchSigner(policy, signer)
	if accepted == nil {
		san := signer.SAN
		if san == "" {
			san = "unknown"
		}
		r := fail("signer is not an accepted workrr certifier: "+san, statement)
		r.SignerIdentity = signer.SAN
		return r
	}
	return BundleResult{BundlePath: bundlePath, OK: true, Forge: accepted.Forge, SignerIdentity: signer.SAN, Statement: statement}
}

func predicateField(statement any, key string) any {
	st, _ := statement.(map[string]any)
	p, _ := st["predicate"].(map[string]any)
	return p[key]
}

func VerifyArtifact(path string, bundlePaths []string, policy *TrustPolicy, tms *TrustedMaterialSource) (*VerifyResult, error) {
	d, err := DigestArtifact(path)
	if err != nil {
		return nil, err
	}
	res := &VerifyResult{ArtifactDigest: d.SHA256, Bundles: []BundleResult{}, Notes: []string{"revocation is not checked in v0.1 (revocation ledger ships in v0.2)"}}
	var valid []BundleResult
	for _, bp := range bundlePaths {
		r := VerifyBundle(bp, d.SHA256, policy, tms)
		res.Bundles = append(res.Bundles, r)
		if r.OK {
			valid = append(valid, r)
		}
	}
	if len(valid) == 0 {
		return res, nil
	}
	res.OK = true

	// Gold: two forges, silver on both, identical checks (spec §4).
	var silver []BundleResult
	forges := map[Forge]bool{}
	for _, b := range valid {
		if predicateField(b.Statement, "level") == "silver" {
			silver = append(silver, b)
			forges[b.Forge] = true
		}
	}
	res.Level = "banded"
	if len(silver) > 0 {
		res.Level = "silver"
	}
	if len(forges) >= 2 {
		find := func(f Forge) *BundleResult {
			for i := range silver {
				if silver[i].Forge == f {
					return &silver[i]
				}
			}
			return nil
		}
		a, b := find(ForgeGitHub), find(ForgeGitLab)
		same := false
		if a != nil && b != nil {
			ca, errA := CanonicalJSON(predicateField(a.Statement, "checks"))
			cb, errB := CanonicalJSON(predicateField(b.Statement, "checks"))
			same = errA == nil && errB == nil && ca == cb
		}
		if same {
			res.Level = "gold"
		} else {
			res.Notes = append(res.Notes, "two forges signed, but their check results differ — not Gold")
		}
	}
	return res, nil
}
