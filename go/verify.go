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
	"strings"
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
	// LogIndexes are the Rekor log indexes carried in the bundle.
	LogIndexes []string `json:"logIndexes,omitempty"`
}

type VerifyResult struct {
	OK             bool           `json:"ok"`
	Status         string         `json:"status,omitempty"`
	Level          string         `json:"level,omitempty"`
	Band           string         `json:"band,omitempty"`
	ArtifactDigest string         `json:"artifactDigest"`
	Source         string         `json:"source,omitempty"`
	PolicyName     string         `json:"policyName,omitempty"`
	PolicyDigest   string         `json:"policyDigest,omitempty"`
	PolicyStatus   string         `json:"policyStatus,omitempty"`
	Bundles        []BundleResult `json:"bundles"`
	Notes          []string       `json:"notes"`
}

// VerificationGate is the policy and publisher decision applied after the
// signature checks. A non-baseline policy never keeps a level.
type VerificationGate struct {
	OK           bool
	Level        string
	Band         string
	Source       string
	PolicyName   string
	PolicyDigest string
	PolicyStatus string
	Notes        []string
}

// VerifyOptions is the signed-policy hook on VerifyArtifact.
// Leaving it zero keeps the v0.1 "revocation is not checked" note.
type VerifyOptions struct {
	Revocations           []*RevocationEntry
	CheckRevocation       bool
	Offline               bool
	BaselinePolicyDigests map[string]string
	ExpectedSource        string
}

// Signer is the certificate identity that signed a bundle.
type Signer struct {
	SAN                    string
	Issuer                 string
	BuildSignerDigest      string // "" when the certificate has no such extension
	SourceRepositoryURI    string // OID 1.3.6.1.4.1.57264.1.12
	SourceRepositoryDigest string // OID 1.3.6.1.4.1.57264.1.13
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

// AssessPolicy classifies the policy recorded in a certificate.
// Status is "baseline", "custom", or "reject". reason is set only for reject.
func AssessPolicy(name, digest string) (status, reason string) {
	baselineDigest := BaselinePolicy().Digest()
	if digest == baselineDigest && name == BaselinePolicyName {
		return "baseline", ""
	}
	if name == BaselinePolicyName {
		return "reject", `policy name "` + BaselinePolicyName + `" is reserved; digest is not the baseline`
	}
	if digest == baselineDigest {
		shown := "missing"
		if name != "" {
			shown = `"` + name + `"`
		}
		return "reject", "policy digest is the baseline but policy name is " + shown
	}
	return "custom", ""
}

func canonicalSource(uri string) string {
	return strings.ToLower(strings.TrimRight(NormalizeRepoURI(strings.TrimSpace(uri)), "/"))
}

// SourceMatches reports whether expected names the certificate's repository.
// expected may be a full repository URL or an owner/repo (or host/owner/repo) shorthand.
func SourceMatches(certificateURI, expected string) bool {
	got := canonicalSource(certificateURI)
	if got == canonicalSource(expected) {
		return true
	}
	flag := strings.ToLower(strings.TrimRight(strings.TrimSuffix(strings.TrimSpace(expected), ".git"), "/"))
	if strings.Contains(flag, "://") || strings.HasPrefix(flag, "git@") {
		return false
	}
	if got == "https://"+flag {
		return true
	}
	path := got
	if i := strings.Index(path, "://"); i >= 0 {
		rest := path[i+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			path = rest[slash+1:]
		}
	}
	return path == flag
}

func worstStatus(statuses []string) string {
	if slices.Contains(statuses, "reject") {
		return "reject"
	}
	if slices.Contains(statuses, "custom") {
		return "custom"
	}
	return "baseline"
}

// VerificationHeadline is the result line verify prints. It never includes a
// baseline level unless the gate accepted the policy.
func VerificationHeadline(ok bool, level, policyStatus string, notes []string, band ...string) string {
	if ok && level != "" {
		if level == "banded" && len(band) > 0 && band[0] != "" {
			return "VERIFIED · level " + level + " · band " + band[0]
		}
		return "VERIFIED · level " + level
	}
	hard := false
	for _, n := range notes {
		if strings.HasPrefix(n, "source mismatch:") || strings.HasPrefix(n, "publishers differ:") {
			hard = true
			break
		}
	}
	if policyStatus == "custom" && !hard {
		return "custom policy, not baseline"
	}
	return "NOT VERIFIED"
}

func uniqueNonEmpty(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ApplyVerificationGates turns a cryptographically valid level into the result
// a caller may print. A non-baseline policy never keeps silver, gold, or banded.
func ApplyVerificationGates(level string, policies [][2]string, sources []string, expectedSource string, notes []string, band ...string) VerificationGate {
	outNotes := append([]string{}, notes...)
	var statuses []string
	var assessments [][3]string // status, name, digest; reason stored separately
	var rejectReason string
	for _, p := range policies {
		status, reason := AssessPolicy(p[0], p[1])
		statuses = append(statuses, status)
		assessments = append(assessments, [3]string{status, p[0], p[1]})
		if status == "reject" && rejectReason == "" {
			rejectReason = reason
		}
	}
	status := ""
	if len(statuses) > 0 {
		status = worstStatus(statuses)
	}
	var policyName, policyDigest string
	if len(assessments) > 0 {
		policyName, policyDigest = assessments[0][1], assessments[0][2]
	}
	uniqueSources := uniqueNonEmpty(sources)
	source := ""
	if len(uniqueSources) == 1 {
		source = uniqueSources[0]
	}
	digestSeen := map[string]bool{}
	var digests []string
	for _, a := range assessments {
		if a[2] != "" && !digestSeen[a[2]] {
			digestSeen[a[2]] = true
			digests = append(digests, a[2])
		}
	}
	if len(digests) > 1 {
		outNotes = append(outNotes, "policy digests differ: "+strings.Join(digests, ", "))
	}
	if len(uniqueSources) > 1 {
		outNotes = append(outNotes, "publishers differ: "+strings.Join(uniqueSources, ", "))
	}
	if expectedSource != "" {
		urls := sources
		if len(urls) == 0 {
			urls = []string{""}
		}
		for _, uri := range urls {
			if !SourceMatches(uri, expectedSource) {
				shown := uri
				if shown == "" {
					shown = "(none)"
				}
				outNotes = append(outNotes, "source mismatch: certificate is for "+shown+", --source is "+expectedSource)
			}
		}
	}
	if rejectReason != "" {
		outNotes = append(outNotes, rejectReason)
	}
	hard := false
	for _, n := range outNotes {
		if strings.HasPrefix(n, "source mismatch:") || strings.HasPrefix(n, "publishers differ:") || strings.HasPrefix(n, "policy digests differ:") {
			hard = true
			break
		}
	}
	gate := VerificationGate{
		Source: source, PolicyName: policyName, PolicyDigest: policyDigest, PolicyStatus: status, Notes: outNotes,
	}
	if status == "baseline" && !hard {
		gate.OK = true
		gate.Level = level
		if level == "banded" && len(band) > 0 && band[0] != "" {
			gate.Band = band[0]
		}
	}
	return gate
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
	return &Signer{
		SAN:                    c.SubjectAlternativeName,
		Issuer:                 c.Extensions.Issuer,
		BuildSignerDigest:      c.Extensions.BuildSignerDigest,
		SourceRepositoryURI:    c.Extensions.SourceRepositoryURI,
		SourceRepositoryDigest: c.Extensions.SourceRepositoryDigest,
	}, nil
}

// DeriveStatementLevel computes the certified level from the signed checks
// rather than trusting predicate.level alone.
func DeriveStatementLevel(statement any) string {
	checks, _ := predicateField(statement, "checks").(map[string]any)
	if checks == nil {
		return ""
	}
	resOf := func(k string) string {
		m, _ := checks[k].(map[string]any)
		r, _ := m["result"].(string)
		return r
	}
	if resOf("provenance") != "pass" || resOf("policy") != "pass" || resOf("scan") != "pass" {
		return ""
	}
	switch resOf("tests") {
	case "pass":
		return "silver"
	case "none":
		return "banded"
	}
	return ""
}

// CheckCertificateSourceAndCommit compares the predicate's source URI and commit
// against the Fulcio certificate's SourceRepositoryURI and SourceRepositoryDigest.
func CheckCertificateSourceAndCommit(statement any, signer *Signer) string {
	src, _ := predicateField(statement, "source").(map[string]any)
	if src == nil {
		return "statement has no source field"
	}
	uri, _ := src["uri"].(string)
	commit, _ := src["commit"].(string)
	if signer != nil && signer.SourceRepositoryURI != "" && canonicalSource(uri) != canonicalSource(signer.SourceRepositoryURI) {
		return "certificate source URI mismatch: predicate claims " + uri + ", Fulcio certificate recorded " + signer.SourceRepositoryURI
	}
	if signer != nil && signer.SourceRepositoryDigest != "" && !strings.EqualFold(commit, signer.SourceRepositoryDigest) {
		return "certificate source commit mismatch: predicate claims " + commit + ", Fulcio certificate recorded " + signer.SourceRepositoryDigest
	}
	return ""
}

func bundleLogIndexes(data []byte) []string {
	var raw struct {
		VerificationMaterial struct {
			TlogEntries []struct {
				LogIndex string `json:"logIndex"`
			} `json:"tlogEntries"`
		} `json:"verificationMaterial"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	var out []string
	for _, e := range raw.VerificationMaterial.TlogEntries {
		if logIndexRe.MatchString(e.LogIndex) {
			out = append(out, e.LogIndex)
		}
	}
	return out
}

func VerifyBundle(bundlePath, artifactDigest string, policy *TrustPolicy, tms *TrustedMaterialSource) BundleResult {
	var indexes []string
	fail := func(msg string, statement any) BundleResult {
		return BundleResult{BundlePath: bundlePath, OK: false, Error: msg, Statement: statement, LogIndexes: indexes}
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
	indexes = bundleLogIndexes(data)
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
	if mismatch := CheckCertificateSourceAndCommit(statement, signer); mismatch != "" {
		r := fail(mismatch, statement)
		r.Forge = accepted.Forge
		r.SignerIdentity = signer.SAN
		return r
	}
	derived := DeriveStatementLevel(statement)
	if derived == "" {
		r := fail("certificate checks did not pass", statement)
		r.Forge = accepted.Forge
		r.SignerIdentity = signer.SAN
		return r
	}
	if predicateField(statement, "level") == "silver" && derived != "silver" {
		r := fail("certificate claims level silver, but signed checks do not support silver", statement)
		r.Forge = accepted.Forge
		r.SignerIdentity = signer.SAN
		return r
	}
	return BundleResult{BundlePath: bundlePath, OK: true, Forge: accepted.Forge, SignerIdentity: signer.SAN, Statement: statement, LogIndexes: indexes}
}

func predicateField(statement any, key string) any {
	st, _ := statement.(map[string]any)
	p, _ := st["predicate"].(map[string]any)
	return p[key]
}

func predicatePolicy(statement any) (name, digest string) {
	checks, _ := predicateField(statement, "checks").(map[string]any)
	policy, _ := checks["policy"].(map[string]any)
	name, _ = policy["policyName"].(string)
	digest, _ = policy["policyDigest"].(string)
	return name, digest
}

func predicateSource(statement any) string {
	src, _ := predicateField(statement, "source").(map[string]any)
	uri, _ := src["uri"].(string)
	return uri
}

func policyDigestOf(statement any) string {
	_, digest := predicatePolicy(statement)
	return digest
}

func VerifyArtifact(path string, bundlePaths []string, policy *TrustPolicy, tms *TrustedMaterialSource, opts ...VerifyOptions) (*VerifyResult, error) {
	var opt VerifyOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	expectedSource := opt.ExpectedSource
	d, err := DigestArtifact(path)
	if err != nil {
		return nil, err
	}
	notes := []string{"revocation is not checked in v0.1 (revocation ledger ships in v0.2)"}
	if opt.Offline {
		notes = []string{OfflineWarning}
	} else if opt.CheckRevocation {
		notes = []string{}
	}
	res := &VerifyResult{ArtifactDigest: d.SHA256, Bundles: []BundleResult{}, Notes: notes}
	var valid []BundleResult
	revoked := false
	for _, bp := range bundlePaths {
		r := VerifyBundle(bp, d.SHA256, policy, tms)
		if r.OK && opt.CheckRevocation && !opt.Offline {
			if msg := RevocationError(opt.Revocations, d.SHA256, r.LogIndexes); msg != "" {
				r.OK = false
				r.Error = msg
			}
		}
		if r.OK && BaselineRejected(policyDigestOf(r.Statement), opt.BaselinePolicyDigests) {
			r.OK = false
			r.Error = "policy digest is not in the signed trust policy"
		}
		if strings.HasPrefix(r.Error, "REVOKED:") {
			revoked = true
		}
		res.Bundles = append(res.Bundles, r)
		if r.OK {
			valid = append(valid, r)
		}
	}
	if len(valid) == 0 {
		res.Status = "rejected"
		if revoked {
			res.Status = "REVOKED"
		}
		return res, nil
	}
	res.OK = true
	res.Status = "verified"

	// Gold: two forges, silver on both (derived from signed checks), identical checks and commit (spec §4).
	var silver []BundleResult
	forges := map[Forge]bool{}
	for _, b := range valid {
		if DeriveStatementLevel(b.Statement) == "silver" {
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
			srcA, _ := predicateField(a.Statement, "source").(map[string]any)
			srcB, _ := predicateField(b.Statement, "source").(map[string]any)
			commitA, _ := srcA["commit"].(string)
			commitB, _ := srcB["commit"].(string)
			same = errA == nil && errB == nil && ca == cb && strings.EqualFold(commitA, commitB)
		}
		if same {
			res.Level = "gold"
		} else {
			res.Notes = append(res.Notes, "two forges signed, but their check results or commits differ — not Gold")
		}
	}
	policies := make([][2]string, len(valid))
	sources := make([]string, len(valid))
	band := ""
	for i, b := range valid {
		policies[i][0], policies[i][1] = predicatePolicy(b.Statement)
		sources[i] = predicateSource(b.Statement)
		if res.Level == "banded" && band == "" {
			if bv, ok := predicateField(b.Statement, "band").(string); ok {
				band = bv
			}
		}
	}
	gate := ApplyVerificationGates(res.Level, policies, sources, expectedSource, res.Notes, band)
	res.OK = gate.OK
	res.Level = gate.Level
	res.Band = gate.Band
	res.Source = gate.Source
	res.PolicyName = gate.PolicyName
	res.PolicyDigest = gate.PolicyDigest
	res.PolicyStatus = gate.PolicyStatus
	res.Notes = gate.Notes
	if !gate.OK {
		res.Status = "rejected"
	}
	return res, nil
}
