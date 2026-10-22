// Policy conformance against a named, digested policy.
package certify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type Policy struct {
	Name                *string  `json:"name,omitempty"`
	MaxTotalBytes       *float64 `json:"maxTotalBytes,omitempty"`
	ForbiddenExtensions []string `json:"forbiddenExtensions,omitempty"`
	RequiredSkillFields []string `json:"requiredSkillFields,omitempty"`
	// When set (even to []), a skill's `allowed-tools` frontmatter may only list these tools.
	AllowedTools   *[]string `json:"allowedTools,omitempty"`
	RequireLicense bool      `json:"requireLicense,omitempty"`

	// raw is the policy exactly as supplied; its canonical JSON is the digest
	// input, so unknown keys are pinned too (as in the TypeScript reference).
	raw any
}

// BaselinePolicyName is reserved. A custom policy may not reuse it.
const BaselinePolicyName = "workrr-baseline-v0.1"

// BaselinePolicy is workrr-baseline-v0.1.
func BaselinePolicy() *Policy {
	p, err := ParsePolicy([]byte(`{
		"name": "` + BaselinePolicyName + `",
		"maxTotalBytes": 5000000,
		"forbiddenExtensions": [".exe", ".dll", ".so", ".dylib", ".bin", ".jar", ".class", ".pyc"],
		"requiredSkillFields": ["name", "description"]
	}`))
	if err != nil {
		panic(err)
	}
	return p
}

// ParsePolicy reads a policy JSON document. Fields of the wrong type are an
// error rather than being coerced, so a malformed policy never yields checks
// that silently differ from another implementation's.
func ParsePolicy(data []byte) (*Policy, error) {
	raw, err := DecodeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if _, ok := raw.(map[string]any); !ok {
		return nil, fmt.Errorf("policy: not a JSON object")
	}
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	p.raw = raw
	return &p, nil
}

// WithOverrides returns a copy of p with top-level keys replaced, like
// `{ ...policy, ...overrides }`.
func (p *Policy) WithOverrides(overrides map[string]any) (*Policy, error) {
	m := map[string]any{}
	for k, v := range p.raw.(map[string]any) {
		m[k] = v
	}
	for k, v := range overrides {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return ParsePolicy(b)
}

func (p *Policy) Digest() string {
	s, err := CanonicalJSON(p.raw)
	if err != nil {
		panic(err) // raw came from DecodeJSON
	}
	return "sha256:" + SHA256Hex([]byte(s))
}

type PolicyResult struct {
	Result       string   `json:"result"`
	PolicyName   *string  `json:"policyName,omitempty"`
	PolicyDigest string   `json:"policyDigest"`
	Violations   []string `json:"violations"`
}

var licenseRe = regexp.MustCompile(`^(` + asciiFold("LICENSE|LICENCE|COPYING") + `)(\.[a-zA-Z]+)?$`)

func CheckPolicy(a *Artifact, p *Policy) PolicyResult {
	if p == nil {
		p = BaselinePolicy()
	}
	violations := []string{}
	files := a.Digest.Files

	total := 0
	for _, f := range files {
		total += f.Size
	}
	if p.MaxTotalBytes != nil && float64(total) > *p.MaxTotalBytes {
		violations = append(violations, fmt.Sprintf("total size %s bytes exceeds %s", strconv.Itoa(total), JSNumber(*p.MaxTotalBytes)))
	}
	for _, f := range files {
		ext := ""
		if i := strings.LastIndex(f.Path, "."); i >= 0 {
			ext = JSToLower(f.Path[i:])
		}
		if slices.Contains(p.ForbiddenExtensions, ext) {
			violations = append(violations, "forbidden file type: "+f.Path)
		}
	}
	if a.Type == TypeSkill {
		fm := a.Frontmatter
		if fm == nil {
			violations = append(violations, "SKILL.md has no parseable YAML frontmatter")
		}
		for _, field := range p.RequiredSkillFields {
			v, ok := fm[field].(string)
			if !ok || JSTrim(v) == "" {
				violations = append(violations, `SKILL.md frontmatter missing "`+field+`"`)
			}
		}
		if p.AllowedTools != nil {
			for _, tool := range listTools(fm["allowed-tools"]) {
				if !slices.Contains(*p.AllowedTools, tool) {
					violations = append(violations, "tool not allowed by policy: "+tool)
				}
			}
		}
	}
	if p.RequireLicense && !slices.ContainsFunc(files, func(f ArtifactFile) bool { return licenseRe.MatchString(f.Path) }) {
		violations = append(violations, "no LICENSE file")
	}
	if reserved := baselineNameViolation(p); reserved != "" {
		violations = append(violations, reserved)
	}
	result := "pass"
	if len(violations) > 0 {
		result = "fail"
	}
	return PolicyResult{Result: result, PolicyName: p.Name, PolicyDigest: p.Digest(), Violations: violations}
}

// baselineNameViolation reports when a policy reuses the baseline name without
// being the baseline document. Empty means the name is not being misused.
func baselineNameViolation(p *Policy) string {
	if p == nil || p.Name == nil || *p.Name != BaselinePolicyName {
		return ""
	}
	if p.Digest() == BaselinePolicy().Digest() {
		return ""
	}
	return `policy name "` + BaselinePolicyName + `" is reserved for the baseline policy`
}

var toolSplitRe = regexp.MustCompile(`[,` + JSWhitespaceClass + `]+`)

// `allowed-tools` may be a YAML list or a comma/space-separated string.
func listTools(v any) []string {
	var parts []string
	switch x := v.(type) {
	case []any:
		for _, it := range x {
			parts = append(parts, JSString(it))
		}
	case string:
		parts = toolSplitRe.Split(x, -1)
	default:
		return nil
	}
	out := []string{}
	for _, s := range parts {
		if s = JSTrim(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
