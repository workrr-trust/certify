// Signed findings (docs/findings.md): what a public scan records when an artifact
// fails a security check. Mirrors src/finding.ts.
package certify

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"slices"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

const FindingPredicateType = "https://trust.workrr.ai/finding/v0.1"

// ConcealmentRules are rules whose matches are rarely accidental.
var ConcealmentRules = []string{"WT002", "WT003", "WT007", "WT008"}

type FindingItem struct {
	Check    string `json:"check"`
	Rule     string `json:"rule,omitempty"`
	Severity string `json:"severity,omitempty"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Detail   string `json:"detail"`
}

type FindingPredicate struct {
	Artifact  any           `json:"artifact"`
	Source    Source        `json:"source"`
	Checks    Checks        `json:"checks"`
	Kind      string        `json:"kind"`
	Findings  []FindingItem `json:"findings"`
	Certifier any           `json:"certifier"`
	ScannedAt string        `json:"scannedAt"`
}

type FindingStatement struct {
	Type          string           `json:"_type"`
	Subject       []Subject        `json:"subject"`
	PredicateType string           `json:"predicateType"`
	Predicate     FindingPredicate `json:"predicate"`
}

var (
	forbiddenRe = regexp.MustCompile(`^forbidden file type: (.+)$`)
	escapingRe  = regexp.MustCompile(`^symlink points outside artifact directory: (.+)$`)
)

// FindingItems lists security-relevant failures only; layout problems are not findings.
func FindingItems(o *CertifyOutcome) []FindingItem {
	c := o.Statement.Predicate.Checks
	items := []FindingItem{}
	for _, f := range c.Scan.Findings {
		if f.Severity == "warn" || f.Excepted {
			continue
		}
		items = append(items, FindingItem{Check: "scan", Rule: f.Rule, Severity: string(f.Severity), File: f.File, Line: f.Line,
			Detail: f.Rule + " (" + string(f.Severity) + ")"})
	}
	for _, v := range c.Policy.Violations {
		if m := forbiddenRe.FindStringSubmatch(v); m != nil {
			items = append(items, FindingItem{Check: "policy", Rule: "forbidden-file-type", File: m[1], Detail: v})
		}
		if m := escapingRe.FindStringSubmatch(v); m != nil {
			items = append(items, FindingItem{Check: "policy", Rule: "escaping-symlink", File: m[1], Detail: v})
		}
	}
	return items
}

// NewFindingStatement returns the finding for a failed public scan, or nil.
func NewFindingStatement(o *CertifyOutcome) *FindingStatement {
	p := o.Statement.Predicate
	if p.Level != "scanned" || o.Certified {
		return nil
	}
	items := FindingItems(o)
	if len(items) == 0 {
		return nil
	}
	kind := "check"
	if slices.ContainsFunc(items, func(i FindingItem) bool { return slices.Contains(ConcealmentRules, i.Rule) }) {
		kind = "concealment"
	}
	return &FindingStatement{
		Type:          StatementType,
		Subject:       o.Statement.Subject,
		PredicateType: FindingPredicateType,
		Predicate: FindingPredicate{
			Artifact: p.Artifact, Source: p.Source, Checks: p.Checks, Kind: kind, Findings: items,
			Certifier: p.Certifier, ScannedAt: p.CertifiedAt,
		},
	}
}

type FindingResult struct {
	OK             bool          `json:"ok"`
	ArtifactDigest string        `json:"artifactDigest"`
	Source         string        `json:"source,omitempty"`
	Commit         string        `json:"commit,omitempty"`
	Path           string        `json:"path,omitempty"`
	Kind           string        `json:"kind,omitempty"`
	Findings       []FindingItem `json:"findings,omitempty"`
	SignerIdentity string        `json:"signerIdentity,omitempty"`
	LogIndexes     []string      `json:"logIndexes,omitempty"`
	Error          string        `json:"error,omitempty"`
}

// VerifyFinding checks a signed finding against a checkout of the commit it names:
// signature, Rekor inclusion and observer signer, then reproduces it by re-running
// the checks and requiring the same failures.
func VerifyFinding(path, bundlePath string, policy *TrustPolicy, tms *TrustedMaterialSource) (*FindingResult, error) {
	d, err := DigestArtifact(path)
	if err != nil {
		return nil, err
	}
	r := &FindingResult{ArtifactDigest: d.SHA256}
	fail := func(msg string) (*FindingResult, error) { r.Error = msg; return r, nil }
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return fail("cannot read bundle: " + err.Error())
	}
	var raw struct {
		DSSEEnvelope *struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fail("cannot read bundle: " + err.Error())
	}
	r.LogIndexes = bundleLogIndexes(data)
	if raw.DSSEEnvelope == nil {
		return fail("bundle has no DSSE envelope (not an attestation)")
	}
	payload, err := base64.StdEncoding.DecodeString(raw.DSSEEnvelope.Payload)
	if err != nil {
		return fail("attestation payload is not valid JSON")
	}
	var st struct {
		Subject       []Subject `json:"subject"`
		PredicateType string    `json:"predicateType"`
		Predicate     struct {
			Source   Source          `json:"source"`
			Checks   Checks          `json:"checks"`
			Kind     string          `json:"kind"`
			Findings json.RawMessage `json:"findings"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &st); err != nil {
		return fail("attestation payload is not valid JSON")
	}
	if st.PredicateType != FindingPredicateType {
		return fail("not a finding: predicate type " + st.PredicateType)
	}
	if !slices.ContainsFunc(st.Subject, func(s Subject) bool { return s.Digest["sha256"] == d.SHA256 }) {
		return fail("finding is for a different artifact (digest mismatch)")
	}
	p := st.Predicate
	r.Source, r.Commit, r.Path = p.Source.URI, p.Source.Commit, p.Source.Path

	digest, err := hex.DecodeString(d.SHA256)
	if err != nil {
		return fail("invalid artifact digest")
	}
	tm, err := tms.Get()
	if err != nil {
		return fail("cannot load Sigstore trusted root: " + err.Error())
	}
	b, err := bundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return fail("signature verification failed: " + err.Error())
	}
	signer, err := verifySigstoreMode(b, tm, "sha256", digest, false)
	if err != nil {
		return fail("signature verification failed: " + err.Error())
	}
	accepted := MatchSigner(policy, signer)
	if accepted == nil {
		return fail("signer is not an accepted workrr certifier: " + signer.SAN)
	}
	if accepted.Role != RoleObserver {
		return fail("findings come only from public scans; this signer is a publisher certifier")
	}
	if signer.SourceRepositoryURI == "" || canonicalSource(signer.SourceRepositoryURI) != canonicalSource(ObserverRepository) {
		return fail("public scan signed outside " + ObserverRepository + ": " + signer.SourceRepositoryURI)
	}

	// Reproduce: the same checks on the same files must fail in the same way.
	outcome, err := Certify(path, CertifyOptions{Observe: p.Source.URI})
	if err != nil {
		return nil, err
	}
	again := NewFindingStatement(outcome)
	if again == nil {
		return fail("not reproduced: the checks pass on this checkout")
	}
	c := outcome.Statement.Predicate.Checks
	if c.Scan.RulesetDigest != p.Checks.Scan.RulesetDigest || c.Policy.PolicyDigest != p.Checks.Policy.PolicyDigest {
		return fail("cannot reproduce with this certifier: its ruleset or policy differs from the one that signed the finding")
	}
	signed, err := DecodeJSON(p.Findings)
	if err != nil {
		return fail("finding has no valid findings list")
	}
	againJSON, _ := json.Marshal(again.Predicate.Findings)
	local, _ := DecodeJSON(againJSON)
	a1, err1 := CanonicalJSON(signed)
	a2, err2 := CanonicalJSON(local)
	if err1 != nil || err2 != nil || a1 != a2 || again.Predicate.Kind != p.Kind {
		return fail("not reproduced: the checks fail differently on this checkout")
	}
	r.OK, r.Kind, r.Findings, r.SignerIdentity = true, p.Kind, again.Predicate.Findings, signer.SAN
	return r, nil
}
