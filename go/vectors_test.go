// Cross-implementation test vectors (spec/test-vectors). The TypeScript
// reference asserts against the same expected.json; Gold depends on both
// producing byte-identical canonical `checks`.
package certify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const vectorsDir = "../spec/test-vectors"

type vectorFile struct {
	Path    string            `json:"path"`
	Text    *string           `json:"text"`
	Symlink *string           `json:"symlink"`
	Parts   []json.RawMessage `json:"parts"`
}

type vectorCase struct {
	ID       string       `json:"id"`
	Dir      string       `json:"dir"`
	Target   string       `json:"target"`
	Policies []string     `json:"policies"`
	Files    []vectorFile `json:"files"`
}

type vectorCases struct {
	CanonicalJSON []json.RawMessage          `json:"canonicalJson"`
	Policies      map[string]json.RawMessage `json:"policies"`
	FixedChecks   struct {
		Provenance ProvenanceResult `json:"provenance"`
		Tests      TestsResult      `json:"tests"`
	} `json:"fixedChecks"`
	Artifacts []vectorCase `json:"artifacts"`
}

type vectorExpected struct {
	RulesetVersion string            `json:"rulesetVersion"`
	RulesetDigest  string            `json:"rulesetDigest"`
	PolicyDigests  map[string]string `json:"policyDigests"`
	CanonicalJSON  []string          `json:"canonicalJson"`
	Artifacts      map[string]struct {
		Algorithm string                     `json:"algorithm"`
		Digest    string                     `json:"digest"`
		Files     json.RawMessage            `json:"files"`
		Type      string                     `json:"type"`
		Name      string                     `json:"name"`
		Scan      json.RawMessage            `json:"scan"`
		Policies  map[string]json.RawMessage `json:"policies"`
		Checks    map[string]string          `json:"checks"`
	} `json:"artifacts"`
}

func readJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// canon re-serializes JSON (expected values) or Go values canonically.
func canon(t *testing.T, v any) string {
	t.Helper()
	var g any
	var err error
	if raw, ok := v.(json.RawMessage); ok {
		g, err = DecodeJSON(raw)
	} else {
		g, err = ToGeneric(v)
	}
	if err != nil {
		t.Fatal(err)
	}
	s, err := CanonicalJSON(g)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func fileBytes(t *testing.T, f vectorFile) []byte {
	if f.Text != nil {
		return []byte(*f.Text)
	}
	var out bytes.Buffer
	for _, raw := range f.Parts {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			out.WriteString(s)
			continue
		}
		var p struct {
			Text   *string `json:"text"`
			Base64 *string `json:"base64"`
			Times  *int    `json:"times"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		var one []byte
		if p.Base64 != nil {
			b, err := base64.StdEncoding.DecodeString(*p.Base64)
			if err != nil {
				t.Fatal(err)
			}
			one = b
		} else {
			one = []byte(*p.Text)
		}
		times := 1
		if p.Times != nil {
			times = *p.Times
		}
		out.Write(bytes.Repeat(one, times))
	}
	return out.Bytes()
}

// materialize writes a case under <root>/<id>/ (so the basename is the id).
func materialize(t *testing.T, c vectorCase, root string) string {
	if c.Dir != "" {
		return filepath.Join(vectorsDir, c.Dir)
	}
	dir := filepath.Join(root, c.ID)
	for _, f := range c.Files {
		abs := filepath.Join(dir, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		var err error
		if f.Symlink != nil {
			err = os.Symlink(*f.Symlink, abs)
		} else {
			err = os.WriteFile(abs, fileBytes(t, f), 0o644)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if c.Target != "" {
		return filepath.Join(dir, c.Target)
	}
	return dir
}

func loadVectors(t *testing.T) (vectorCases, vectorExpected, map[string]*Policy) {
	var cases vectorCases
	var expected vectorExpected
	readJSONFile(t, filepath.Join(vectorsDir, "cases.json"), &cases)
	readJSONFile(t, filepath.Join(vectorsDir, "expected.json"), &expected)
	policies := map[string]*Policy{}
	for name, raw := range cases.Policies {
		if string(raw) == "null" {
			policies[name] = BaselinePolicy()
			continue
		}
		p, err := ParsePolicy(raw)
		if err != nil {
			t.Fatalf("policy %s: %v", name, err)
		}
		policies[name] = p
	}
	return cases, expected, policies
}

func TestTrustVectors(t *testing.T) {
	var doc struct {
		Trust struct {
			Signers []struct {
				ID                string `json:"id"`
				SAN               string `json:"san"`
				Issuer            string `json:"issuer"`
				BuildSignerDigest string `json:"buildSignerDigest"`
				Accepted          bool   `json:"accepted"`
			} `json:"signers"`
			Policies []struct {
				ID               string `json:"id"`
				PolicyName       string `json:"policyName"`
				PolicyDigest     string `json:"policyDigest"`
				CertificateLevel string `json:"certificateLevel"`
				Status           string `json:"status"`
				OK               bool   `json:"ok"`
				Headline         string `json:"headline"`
				Reason           string `json:"reason"`
			} `json:"policies"`
			Sources []struct {
				ID          string `json:"id"`
				Certificate string `json:"certificate"`
				Flag        string `json:"flag"`
				Match       bool   `json:"match"`
				Note        string `json:"note"`
			} `json:"sources"`
		} `json:"trust"`
	}
	readJSONFile(t, filepath.Join(vectorsDir, "cases.json"), &doc)
	revocation := "revocation is not checked in v0.1 (revocation ledger ships in v0.2)"
	for _, signer := range doc.Trust.Signers {
		t.Run("signer "+signer.ID, func(t *testing.T) {
			got := MatchSigner(&DefaultTrustPolicy, &Signer{SAN: signer.SAN, Issuer: signer.Issuer, BuildSignerDigest: signer.BuildSignerDigest})
			if (got != nil) != signer.Accepted {
				t.Fatalf("accepted=%v, want %v", got != nil, signer.Accepted)
			}
		})
	}
	for _, policy := range doc.Trust.Policies {
		t.Run("policy "+policy.ID, func(t *testing.T) {
			gate := ApplyVerificationGates(policy.CertificateLevel, [][2]string{{policy.PolicyName, policy.PolicyDigest}}, []string{"https://github.com/workrr-trust/sample-skills"}, "", []string{revocation})
			if gate.PolicyStatus != policy.Status || gate.OK != policy.OK {
				t.Fatalf("status %s ok %v, want %s ok %v", gate.PolicyStatus, gate.OK, policy.Status, policy.OK)
			}
			if got := VerificationHeadline(gate.OK, gate.Level, gate.PolicyStatus, gate.Notes); got != policy.Headline {
				t.Fatalf("headline %q, want %q", got, policy.Headline)
			}
			if policy.Status != "baseline" && gate.Level != "" {
				t.Fatalf("reported baseline level %q", gate.Level)
			}
			if policy.Reason != "" && !slices.Contains(gate.Notes, policy.Reason) {
				t.Fatalf("notes %v", gate.Notes)
			}
			if policy.Status == "baseline" && policy.PolicyDigest != BaselinePolicy().Digest() {
				t.Fatalf("vector baseline digest %s, implementation %s", policy.PolicyDigest, BaselinePolicy().Digest())
			}
		})
	}
	for _, source := range doc.Trust.Sources {
		t.Run("source "+source.ID, func(t *testing.T) {
			if SourceMatches(source.Certificate, source.Flag) != source.Match {
				t.Fatalf("match=%v, want %v", !source.Match, source.Match)
			}
			gate := ApplyVerificationGates("silver", [][2]string{{BaselinePolicyName, BaselinePolicy().Digest()}}, []string{source.Certificate}, source.Flag, []string{revocation})
			if source.Match {
				if !gate.OK || gate.Level != "silver" || VerificationHeadline(gate.OK, gate.Level, gate.PolicyStatus, gate.Notes) != "VERIFIED · Tested (silver)" {
					t.Fatalf("gate %+v", gate)
				}
				return
			}
			if gate.OK || gate.Level != "" || VerificationHeadline(gate.OK, gate.Level, gate.PolicyStatus, gate.Notes) != "NOT VERIFIED" {
				t.Fatalf("gate %+v headline %s", gate, VerificationHeadline(gate.OK, gate.Level, gate.PolicyStatus, gate.Notes))
			}
			if !slices.Contains(gate.Notes, source.Note) {
				t.Fatalf("notes %v", gate.Notes)
			}
		})
	}
}

func TestVectorsDigests(t *testing.T) {
	_, expected, policies := loadVectors(t)
	if RulesetVersion != expected.RulesetVersion {
		t.Errorf("ruleset version %q, want %q", RulesetVersion, expected.RulesetVersion)
	}
	if got := RulesetDigest(); got != expected.RulesetDigest {
		t.Errorf("ruleset digest %s, want %s", got, expected.RulesetDigest)
	}
	for name, p := range policies {
		if got := p.Digest(); got != expected.PolicyDigests[name] {
			t.Errorf("policy %s digest %s, want %s", name, got, expected.PolicyDigests[name])
		}
	}
}

func TestVectorsCanonicalJSON(t *testing.T) {
	cases, expected, _ := loadVectors(t)
	for i, raw := range cases.CanonicalJSON {
		if got := canon(t, raw); got != expected.CanonicalJSON[i] {
			t.Errorf("canonicalJson[%d]:\n got %s\nwant %s", i, got, expected.CanonicalJSON[i])
		}
	}
}

func TestVectorsArtifacts(t *testing.T) {
	cases, expected, policies := loadVectors(t)
	root := t.TempDir()
	if len(cases.Artifacts) != len(expected.Artifacts) {
		t.Fatalf("%d cases but %d expectations", len(cases.Artifacts), len(expected.Artifacts))
	}
	for _, c := range cases.Artifacts {
		t.Run(c.ID, func(t *testing.T) {
			e, ok := expected.Artifacts[c.ID]
			if !ok {
				t.Fatalf("no expectation for %s", c.ID)
			}
			a, err := LoadArtifact(materialize(t, c, root))
			if err != nil {
				t.Fatal(err)
			}
			check := func(what, got, want string) {
				t.Helper()
				if got != want {
					t.Errorf("%s:\n got %s\nwant %s", what, got, want)
				}
			}
			check("algorithm", string(a.Digest.Algorithm), e.Algorithm)
			check("digest", a.Digest.SHA256, e.Digest)
			check("files", canon(t, a.Digest.Files), canon(t, e.Files))
			check("type", string(a.Type), e.Type)
			check("name", a.Name, e.Name)
			scan := ScanArtifact(a)
			check("scan", canon(t, scan), canon(t, e.Scan))
			for _, name := range c.Policies {
				pr := CheckPolicy(a, policies[name])
				check("policy "+name, canon(t, pr), canon(t, e.Policies[name]))
				checks := Checks{Provenance: cases.FixedChecks.Provenance, Policy: pr, Scan: scan, Tests: cases.FixedChecks.Tests}
				// The Gold comparison is over these exact strings.
				check("checks "+name, MustCanonicalJSON(checks), e.Checks[name])
			}
		})
	}
}
