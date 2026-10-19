// workrr — certify and verify AI agent artifacts (Go implementation).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	certify "github.com/workrr-trust/certify/go"
)

const help = `workrr ` + certify.Version + ` — certify and verify AI agent artifacts

Usage:
  workrr digest  <path>
  workrr test    <path> [--out tests.json]
  workrr certify <path> [--policy policy.json] [--tests-report tests.json | --run-tests]
                        [--statement-out statement.json] [--predicate-out predicate.json]
  workrr verify  <path> --bundle <file> [--bundle <file>] [--trust-policy policy.json] [--json]
                        [--trusted-root trusted_root.json]

  test     Runs the artifact's declared suite (workrr.json). Runs artifact code:
           in CI, use a job WITHOUT signing permission.
  certify  Runs provenance, policy and scan checks; exits 1 if any check fails.
           In GitHub Actions also writes subject-name / subject-digest outputs.
  verify   Checks the artifact digest, Sigstore signature, Rekor inclusion and
           certifier identity. Two bundles from different forges → Gold.
           --trusted-root pins a Sigstore trusted root instead of fetching it via TUF.
`

type args struct {
	strings   map[string]string
	bools     map[string]bool
	bundles   []string
	positions []string
}

var stringOpts = map[string]bool{"out": true, "policy": true, "tests-report": true, "statement-out": true, "predicate-out": true, "bundle": true, "trust-policy": true, "trusted-root": true}
var boolOpts = map[string]bool{"run-tests": true, "json": true}

// parseArgs follows node:util parseArgs in strict mode: --name value,
// --name=value, booleans take no value, `--` ends options.
func parseArgs(argv []string) (*args, error) {
	a := &args{strings: map[string]string{}, bools: map[string]bool{}}
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			a.positions = append(a.positions, argv[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			a.positions = append(a.positions, arg)
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		switch {
		case !strings.HasPrefix(arg, "--"):
			return nil, fmt.Errorf("Unknown option '%s'", arg)
		case boolOpts[name]:
			if hasValue {
				return nil, fmt.Errorf("Option '--%s' does not take an argument", name)
			}
			a.bools[name] = true
		case stringOpts[name]:
			if !hasValue {
				if i+1 >= len(argv) || strings.HasPrefix(argv[i+1], "-") {
					return nil, fmt.Errorf("Option '--%s <value>' argument missing", name)
				}
				i++
				value = argv[i]
			}
			if name == "bundle" {
				a.bundles = append(a.bundles, value)
			} else {
				a.strings[name] = value
			}
		default:
			return nil, fmt.Errorf("Unknown option '--%s'", name)
		}
	}
	return a, nil
}

func prettyJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func run(argv []string) (int, error) {
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "--help" {
		fmt.Print(help)
		return 0, nil
	}
	cmd := argv[0]
	if cmd == "--version" || cmd == "-v" {
		fmt.Println(certify.Version)
		return 0, nil
	}
	a, err := parseArgs(argv[1:])
	if err != nil {
		return 0, err
	}
	if len(a.positions) == 0 {
		return 0, fmt.Errorf("missing <path>\n\n%s", help)
	}
	path := a.positions[0]

	switch cmd {
	case "digest":
		d, err := certify.DigestArtifact(path)
		if err != nil {
			return 0, err
		}
		fmt.Printf("sha256:%s  %s  %d file(s)\n", d.SHA256, d.Algorithm, len(d.Files))
		return 0, nil

	case "test":
		art, err := certify.LoadArtifact(path)
		if err != nil {
			return 0, err
		}
		report := certify.TestsReport{ArtifactDigest: art.Digest.SHA256, Tests: certify.RunTests(art, 10*time.Minute)}
		out := prettyJSON(report)
		if p := a.strings["out"]; p != "" {
			if err := os.WriteFile(p, out, 0o644); err != nil {
				return 0, err
			}
		} else {
			os.Stdout.Write(out)
		}
		fmt.Fprintf(os.Stderr, "tests: %s\n", report.Tests.Result)
		if report.Tests.Result == "fail" {
			return 1, nil
		}
		return 0, nil

	case "certify":
		opts := certify.CertifyOptions{Policy: certify.BaselinePolicy(), RunTestsLocally: a.bools["run-tests"]}
		if p := a.strings["policy"]; p != "" {
			b, err := os.ReadFile(p)
			if err != nil {
				return 0, err
			}
			if opts.Policy, err = certify.ParsePolicy(b); err != nil {
				return 0, err
			}
		}
		if p := a.strings["tests-report"]; p != "" {
			b, err := os.ReadFile(p)
			if err != nil {
				return 0, err
			}
			var r certify.TestsReport
			if err := json.Unmarshal(b, &r); err != nil {
				return 0, err
			}
			opts.TestsReport = &r
		}
		outcome, err := certify.Certify(path, opts)
		if err != nil {
			return 0, err
		}
		st := outcome.Statement
		p := st.Predicate
		c := p.Checks
		reason := ""
		if c.Provenance.Reason != "" {
			reason = " — " + c.Provenance.Reason
		}
		policyName := "undefined"
		if c.Policy.PolicyName != nil {
			policyName = *c.Policy.PolicyName
		}
		commit := p.Source.Commit
		if len(commit) > 12 {
			commit = commit[:12]
		}
		last := "level      " + p.Level
		if !outcome.Certified {
			last = "NOT CERTIFIED:\n  - " + strings.Join(outcome.Failures, "\n  - ")
		}
		fmt.Fprint(os.Stderr, strings.Join([]string{
			fmt.Sprintf("artifact   %s (%s, %d file(s))", p.Artifact.Name, p.Artifact.Type, p.Artifact.FileCount),
			"digest     sha256:" + st.Subject[0].Digest["sha256"],
			fmt.Sprintf("source     %s@%s %s", p.Source.URI, commit, p.Source.Path),
			"provenance " + c.Provenance.Result + reason,
			fmt.Sprintf("policy     %s (%s)", c.Policy.Result, policyName),
			fmt.Sprintf("scan       %s (%d finding(s), %s)", c.Scan.Result, len(c.Scan.Findings), c.Scan.RulesetVersion),
			"tests      " + c.Tests.Result,
			last,
			"",
		}, "\n"))
		for _, f := range c.Scan.Findings {
			if f.Severity == "warn" {
				fmt.Fprintf(os.Stderr, "  warn: %s %s:%d\n", f.Rule, f.File, f.Line)
			}
		}
		if out := a.strings["statement-out"]; out != "" {
			if err := os.WriteFile(out, prettyJSON(st), 0o644); err != nil {
				return 0, err
			}
		}
		if out := a.strings["predicate-out"]; out != "" {
			if err := os.WriteFile(out, prettyJSON(p), 0o644); err != nil {
				return 0, err
			}
		}
		if gh := os.Getenv("GITHUB_OUTPUT"); gh != "" {
			f, err := os.OpenFile(gh, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return 0, err
			}
			_, err = fmt.Fprintf(f, "certified=%t\nsubject-name=%s\nsubject-digest=sha256:%s\nlevel=%s\n",
				outcome.Certified, st.Subject[0].Name, st.Subject[0].Digest["sha256"], p.Level)
			f.Close()
			if err != nil {
				return 0, err
			}
		}
		if outcome.Certified {
			return 0, nil
		}
		return 1, nil

	case "verify":
		if len(a.bundles) == 0 {
			return 0, fmt.Errorf("verify needs at least one --bundle")
		}
		policy := certify.DefaultTrustPolicy
		if p := a.strings["trust-policy"]; p != "" {
			b, err := os.ReadFile(p)
			if err != nil {
				return 0, err
			}
			if err := json.Unmarshal(b, &policy); err != nil {
				return 0, err
			}
		}
		tms := &certify.TrustedMaterialSource{Path: a.strings["trusted-root"]}
		result, err := certify.VerifyArtifact(path, a.bundles, &policy, tms)
		if err != nil {
			return 0, err
		}
		if a.bools["json"] {
			os.Stdout.Write(prettyJSON(result))
		} else {
			fmt.Printf("artifact sha256:%s\n", result.ArtifactDigest)
			for _, b := range result.Bundles {
				if b.OK {
					fmt.Printf("  ✓ %s — %s: %s\n", b.BundlePath, b.Forge, b.SignerIdentity)
				} else {
					fmt.Printf("  ✗ %s — %s\n", b.BundlePath, b.Error)
				}
			}
			if result.OK {
				fmt.Printf("VERIFIED · level %s\n", result.Level)
			} else {
				fmt.Println("NOT VERIFIED")
			}
			for _, n := range result.Notes {
				fmt.Printf("  note: %s\n", n)
			}
		}
		if result.OK {
			return 0, nil
		}
		return 1, nil
	}
	return 0, fmt.Errorf("unknown command: %s\n\n%s", cmd, help)
}

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "workrr: %s\n", err)
		os.Exit(2)
	}
	os.Exit(code)
}
