// Package certify is the Go implementation of the workrr Trust certificate
// spec (spec/README.md). Given the same artifact, policy and ruleset it
// produces byte-identical canonical `checks` to the TypeScript reference.
package certify

import (
	"fmt"
	"os"
	"time"
)

const (
	Version       = "0.1.1"
	PredicateType = "https://trust.workrr.ai/certificate/v0.1"
	StatementType = "https://in-toto.io/Statement/v1"
)

type Checks struct {
	Provenance ProvenanceResult `json:"provenance"`
	Policy     PolicyResult     `json:"policy"`
	Scan       ScanResult       `json:"scan"`
	Tests      TestsResult      `json:"tests"`
}

type Predicate struct {
	Artifact struct {
		Name            string          `json:"name"`
		Type            ArtifactType    `json:"type"`
		DigestAlgorithm DigestAlgorithm `json:"digestAlgorithm"`
		FileCount       int             `json:"fileCount"`
	} `json:"artifact"`
	Source    Source `json:"source"`
	Checks    Checks `json:"checks"`
	Level     string `json:"level"`
	Band      string `json:"band,omitempty"`
	Certifier struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Runtime string `json:"runtime"`
	} `json:"certifier"`
	CertifiedAt string `json:"certifiedAt"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

type CertifyOutcome struct {
	Artifact  *Artifact
	Statement Statement
	// Certificate is issued only when no check failed.
	Certified bool
	Failures  []string
}

func DetectRuntime() string {
	switch {
	case os.Getenv("GITHUB_ACTIONS") == "true":
		return "github-actions"
	case os.Getenv("GITLAB_CI") == "true":
		return "gitlab-ci"
	}
	return "local"
}

type CertifyOptions struct {
	Policy *Policy
	// Result from a separate, unprivileged test job (required in CI).
	TestsReport *TestsReport
	// Run the artifact's tests in-process. Only for local use: never in a job that can sign.
	RunTestsLocally bool
}

func Certify(path string, opts CertifyOptions) (*CertifyOutcome, error) {
	a, err := LoadArtifact(path)
	if err != nil {
		return nil, err
	}
	source, provenance, err := CheckProvenance(path)
	if err != nil {
		return nil, err
	}
	policy := CheckPolicy(a, opts.Policy)
	scan := ScanArtifact(a)

	tests := TestsResult{Result: "none"}
	failures := []string{}
	switch {
	case opts.TestsReport != nil:
		if opts.TestsReport.ArtifactDigest != a.Digest.SHA256 {
			failures = append(failures, "tests report was produced for a different artifact digest")
			tests = TestsResult{Result: "fail"}
		} else {
			tests = opts.TestsReport.Tests
		}
	case opts.RunTestsLocally:
		tests = RunTests(a, 10*time.Minute)
	}

	if provenance.Result == "fail" {
		reason := provenance.Reason
		if reason == "" {
			reason = "failed"
		}
		failures = append(failures, "provenance: "+reason)
	}
	if policy.Result == "fail" {
		for _, v := range policy.Violations {
			failures = append(failures, "policy: "+v)
		}
	}
	if scan.Result == "fail" {
		for _, f := range scan.Findings {
			if f.Severity != "warn" {
				failures = append(failures, fmt.Sprintf("scan: %s (%s) %s:%d", f.Rule, f.Severity, f.File, f.Line))
			}
		}
	}
	if tests.Result == "fail" {
		code := "?"
		if tests.ExitCode != nil {
			code = fmt.Sprint(*tests.ExitCode)
		}
		failures = append(failures, "tests: exit code "+code)
	}

	var p Predicate
	p.Artifact.Name = a.Name
	p.Artifact.Type = a.Type
	p.Artifact.DigestAlgorithm = a.Digest.Algorithm
	p.Artifact.FileCount = len(a.Digest.Files)
	p.Source = source
	p.Checks = Checks{Provenance: provenance, Policy: policy, Scan: scan, Tests: tests}
	// Silver only when every check passed. A reserved-name or other policy failure
	// must not leave level "silver" on the statement.
	p.Level = "banded"
	if provenance.Result == "pass" && policy.Result == "pass" && scan.Result == "pass" && tests.Result == "pass" {
		p.Level = "silver"
	}
	p.Certifier.Name = "workrr-certify"
	p.Certifier.Version = Version
	p.Certifier.Runtime = DetectRuntime()
	p.CertifiedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	st := Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: a.Name, Digest: map[string]string{"sha256": a.Digest.SHA256}}},
		PredicateType: PredicateType,
		Predicate:     p,
	}
	return &CertifyOutcome{Artifact: a, Statement: st, Certified: len(failures) == 0, Failures: failures}, nil
}
