// Org policy gate: discovers all skills in a repository and blocks merge if any
// skill is uncertified, modified since certification, below the org's minimum
// level, or violates the org's required policy or allowed publisher sources.
package certify

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

var gateLevelRank = map[string]int{
	"scanned": 0,
	"banded":  1,
	"silver":  2,
	"gold":    3,
}

var gateSkipDirs = map[string]bool{
	".git":              true,
	"node_modules":      true,
	"dist":              true,
	".workrr-certifier": true,
	".workrr-py":        true,
}

type SkillGateItem struct {
	Path    string   `json:"path"`
	Name    string   `json:"name"`
	Digest  string   `json:"digest"`
	OK      bool     `json:"ok"`
	Level   string   `json:"level,omitempty"`
	Bundles []string `json:"bundles"`
	Reasons []string `json:"reasons"`
}

type OrgGateOptions struct {
	MinLevel        string
	RequiredPolicy  *Policy
	CertificatesDir string
	AllowedSources  []string
	TrustPolicy     *TrustPolicy
	TrustedMaterial *TrustedMaterialSource
	VerifyBundleFn  func(bundlePath, artifactDigest string, policy *TrustPolicy) BundleResult
}

type OrgGateResult struct {
	OK                   bool            `json:"ok"`
	MinLevel             string          `json:"minLevel"`
	RequiredPolicyName   string          `json:"requiredPolicyName"`
	RequiredPolicyDigest string          `json:"requiredPolicyDigest"`
	TotalSkills          int             `json:"totalSkills"`
	PassedSkills         int             `json:"passedSkills"`
	FailedSkills         int             `json:"failedSkills"`
	Skills               []SkillGateItem `json:"skills"`
}

func LevelMeetsMinimum(actual, minLevel string) bool {
	got, okGot := gateLevelRank[actual]
	want, okWant := gateLevelRank[minLevel]
	if !okGot || !okWant {
		return false
	}
	return got >= want
}

func DiscoverSkills(rootDir string) ([]string, error) {
	root, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, err
	}
	var found []string
	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !e.IsDir() && e.Name() == "SKILL.md" {
				rel, err := filepath.Rel(root, dir)
				if err != nil {
					return err
				}
				rel = filepath.ToSlash(rel)
				if rel == "" {
					rel = "."
				}
				found = append(found, rel)
				break
			}
		}
		for _, e := range entries {
			if !e.IsDir() || gateSkipDirs[e.Name()] {
				continue
			}
			if err := walk(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	slices.Sort(found)
	return found, nil
}

func FindSkillBundles(rootDir, skillRelPath, artifactDigest, certificatesDir string) []string {
	root, err := filepath.Abs(rootDir)
	if err != nil {
		root = rootDir
	}
	skillDir := root
	if skillRelPath != "." {
		skillDir = filepath.Join(root, filepath.FromSlash(skillRelPath))
	}
	candidates := []string{
		filepath.Join(skillDir, "certificate.sigstore.json"),
		filepath.Join(skillDir, ".workrr", "certificate.sigstore.json"),
	}
	if certificatesDir != "" {
		certRoot, err := filepath.Abs(certificatesDir)
		if err != nil {
			certRoot = certificatesDir
		}
		candidates = append(candidates, filepath.Join(certRoot, artifactDigest+".sigstore.json"))
		if skillRelPath != "." {
			candidates = append(candidates, filepath.Join(certRoot, filepath.FromSlash(skillRelPath), "certificate.sigstore.json"))
		}
	}
	var existing []string
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			existing = append(existing, c)
		}
	}
	return existing
}

func sourceAllowed(certificateURI string, allowedSources []string) bool {
	for _, allowed := range allowedSources {
		if SourceMatches(certificateURI, allowed) {
			return true
		}
		normAllowed := canonicalSource(allowed)
		normCert := canonicalSource(certificateURI)
		if strings.HasPrefix(normCert, normAllowed+"/") {
			return true
		}
	}
	return false
}

func RunOrgPolicyGate(rootDir string, opts OrgGateOptions) (*OrgGateResult, error) {
	minLevel := opts.MinLevel
	if minLevel == "" {
		minLevel = "silver"
	}
	policy := opts.RequiredPolicy
	if policy == nil {
		policy = BaselinePolicy()
	}
	reqPolicyName := "custom"
	if policy.Name != nil && *policy.Name != "" {
		reqPolicyName = *policy.Name
	}
	reqPolicyDigest := policy.Digest()
	trustPolicy := opts.TrustPolicy
	if trustPolicy == nil {
		trustPolicy = &DefaultTrustPolicy
	}
	tms := opts.TrustedMaterial
	if tms == nil {
		tms = &TrustedMaterialSource{}
	}

	skillPaths, err := DiscoverSkills(rootDir)
	if err != nil {
		return nil, err
	}
	root, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, err
	}

	skills := make([]SkillGateItem, 0, len(skillPaths))
	for _, relPath := range skillPaths {
		absPath := root
		if relPath != "." {
			absPath = filepath.Join(root, filepath.FromSlash(relPath))
		}
		artifact, err := LoadArtifact(absPath)
		if err != nil {
			return nil, err
		}
		reasons := []string{}
		policyRes := CheckPolicy(artifact, policy)
		if policyRes.Result != "pass" {
			for _, v := range policyRes.Violations {
				reasons = append(reasons, "policy violation: "+v)
			}
		}
		scanRes := ScanArtifact(artifact)
		if scanRes.Result != "pass" {
			highCount := 0
			for _, f := range scanRes.Findings {
				if f.Severity != "warn" {
					highCount++
				}
			}
			reasons = append(reasons, fmt.Sprintf("scan failed with %d high/critical finding(s)", highCount))
		}

		bundles := FindSkillBundles(rootDir, relPath, artifact.Digest.SHA256, opts.CertificatesDir)
		if len(bundles) == 0 {
			reasons = append(reasons, "uncertified skill: no certificate bundle found")
			skills = append(skills, SkillGateItem{
				Path:    relPath,
				Name:    artifact.Name,
				Digest:  artifact.Digest.SHA256,
				OK:      false,
				Bundles: []string{},
				Reasons: reasons,
			})
			continue
		}

		var valid []BundleResult
		for _, bp := range bundles {
			var br BundleResult
			if opts.VerifyBundleFn != nil {
				br = opts.VerifyBundleFn(bp, artifact.Digest.SHA256, trustPolicy)
			} else {
				br = VerifyBundle(bp, artifact.Digest.SHA256, trustPolicy, tms)
			}
			if br.OK && br.Statement != nil {
				valid = append(valid, br)
			} else if br.Error != "" {
				reasons = append(reasons, bp+": "+br.Error)
			}
		}

		level := ""
		if len(valid) > 0 {
			_, certDigest := predicatePolicy(valid[0].Statement)
			if certDigest != reqPolicyDigest {
				reasons = append(reasons, fmt.Sprintf("certificate policy digest %s does not match required %s", certDigest, reqPolicyDigest))
			}
			if len(opts.AllowedSources) > 0 {
				uri := predicateSource(valid[0].Statement)
				if !sourceAllowed(uri, opts.AllowedSources) {
					reasons = append(reasons, fmt.Sprintf("publisher %s is not in allowed sources (%s)", uri, strings.Join(opts.AllowedSources, ", ")))
				}
			}
			// A public scan counts only when no publisher certificate verified.
			forges := map[Forge]bool{}
			hasSilver, hasPublisher := false, false
			for _, b := range valid {
				if b.Observer || predicateField(b.Statement, "level") == "scanned" {
					continue
				}
				hasPublisher = true
				if predicateField(b.Statement, "level") == "silver" {
					hasSilver = true
					forges[b.Forge] = true
				}
			}
			switch {
			case !hasPublisher:
				level = "scanned"
			case len(forges) >= 2:
				level = "gold"
			case hasSilver:
				level = "silver"
			default:
				level = "banded"
			}
		}

		if !LevelMeetsMinimum(level, minLevel) {
			shown := level
			if shown == "" {
				shown = "(none)"
			}
			reasons = append(reasons, fmt.Sprintf("certificate level %s is below required minimum %s", shown, minLevel))
		}

		skills = append(skills, SkillGateItem{
			Path:    relPath,
			Name:    artifact.Name,
			Digest:  artifact.Digest.SHA256,
			OK:      len(reasons) == 0,
			Level:   level,
			Bundles: bundles,
			Reasons: reasons,
		})
	}

	passed := 0
	for _, s := range skills {
		if s.OK {
			passed++
		}
	}
	failed := len(skills) - passed
	return &OrgGateResult{
		OK:                   failed == 0,
		MinLevel:             minLevel,
		RequiredPolicyName:   reqPolicyName,
		RequiredPolicyDigest: reqPolicyDigest,
		TotalSkills:          len(skills),
		PassedSkills:         passed,
		FailedSkills:         failed,
		Skills:               skills,
	}, nil
}
