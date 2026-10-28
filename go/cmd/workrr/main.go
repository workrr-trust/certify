// workrr — certify and verify AI agent artifacts (Go implementation).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
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
                        [--observe https://github.com/<owner>/<repo> [--finding-out finding.json]]
  workrr verify  <path> --bundle <file> [--bundle <file>] [--trust-policy policy.json]
                        [--source <repo>] [--offline] [--private] [--json]
                        [--trusted-root trusted_root.json] [--anchor-receipt receipt.json]
  workrr verify-finding <path> --bundle <file> [--trust-policy policy.json] [--json]
  workrr anchor  <path> --bundle <file> [--out anchor-request.json]
  workrr gate    <repo-dir> [--min-level scanned|signed|tested|reproduced] [--policy policy.json]
                            [--certificates-dir <dir>] [--source <repo>] [--json]

  test     Runs the artifact's declared suite (workrr.json). Runs artifact code:
           in CI, use a job WITHOUT signing permission.
  certify  Runs provenance, policy and scan checks; exits 1 if any check fails.
           In GitHub Actions also writes subject-name / subject-digest outputs.
           --observe makes a public scan (level scanned) of that repository's
           checkout: tests never run (docs/public-scans.md). With
           --finding-out, a scan that fails a security check writes a finding
           statement to sign instead (docs/findings.md).
  verify   Checks the artifact digest, Sigstore signature, Rekor inclusion,
           certifier identity, and revocation. Reports the policy name and digest.
           A policy that is not the baseline does not verify at a baseline level.
           --source fails when the certificate's publisher repo does not match.
           --json prints the structured VerifyResult JSON (ok, level, artifactDigest,
           source, policyName, policyDigest, policyStatus, bundles, notes).
           Fetches the signed trust policy from the trust API and caches it for 1 hour.
           --offline uses the policy embedded in this build and does not check
           revocation. It prints:
             offline: using the embedded trust policy; revocation was not checked
           A revoked certificate can still verify in that mode. Pass --trusted-root
           to verify the Sigstore certificate without fetching the Sigstore TUF root.
           --trust-policy FILE uses that file. A signed blob is verified; a legacy
           {version, signers} file is a local override and its signature is not checked.
           --private accepts private-tier TSA attestations and optional hash-only
           anchor receipts (--anchor-receipt).
  verify-finding
           Verifies a signed finding from a public scan (signature, Rekor,
           observer signer), then reproduces it: re-runs the checks on <path>
           (a checkout of the commit it names) and requires the same failures.
  Levels, least to most scrutiny: Scanned, Signed, Tested, Reproduced (wire
  values scanned, banded, silver, gold). Either name works for --min-level.
  anchor   Computes the hash-only public anchor request payload for a private bundle.
  gate     Org policy gate: discovers all skills in <repo-dir> and exits 1 if
           any skill is uncertified, fails policy/scan, or is below --min-level.
`

type args struct {
	strings   map[string]string
	bools     map[string]bool
	bundles   []string
	positions []string
}

var observeRe = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)

var stringOpts = map[string]bool{"out": true, "policy": true, "tests-report": true, "statement-out": true, "predicate-out": true, "bundle": true, "trust-policy": true, "trusted-root": true, "anchor-receipt": true, "min-level": true, "certificates-dir": true, "source": true, "observe": true, "finding-out": true}
var boolOpts = map[string]bool{"run-tests": true, "private": true, "json": true, "offline": true}

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

func findingLine(f certify.FindingItem) string {
	s := f.Detail
	if f.File != "" {
		s += " " + f.File
		if f.Line > 0 {
			s += fmt.Sprintf(":%d", f.Line)
		}
	}
	return s
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
		if a.strings["finding-out"] != "" && a.strings["observe"] == "" {
			return 0, fmt.Errorf("--finding-out needs --observe")
		}
		if o := a.strings["observe"]; o != "" {
			if !observeRe.MatchString(o) {
				return 0, fmt.Errorf("--observe must be https://github.com/<owner>/<repo>")
			}
			if a.strings["tests-report"] != "" || opts.RunTestsLocally {
				return 0, fmt.Errorf("--observe never runs tests; drop --tests-report / --run-tests")
			}
			opts.Observe = o
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
		last := "level      " + certify.LevelName(p.Level) + " (" + p.Level + ")"
		if p.Band != "" {
			last += ", band " + p.Band
		}
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
		var finding *certify.FindingStatement
		if out := a.strings["finding-out"]; out != "" {
			if finding = certify.NewFindingStatement(outcome); finding != nil {
				if err := os.WriteFile(out, prettyJSON(finding.Predicate), 0o644); err != nil {
					return 0, err
				}
				var parts []string
				for _, f := range finding.Predicate.Findings {
					parts = append(parts, findingLine(f))
				}
				fmt.Fprintf(os.Stderr, "finding    %s: %s\n", finding.Predicate.Kind, strings.Join(parts, "; "))
			}
		}
		if gh := os.Getenv("GITHUB_OUTPUT"); gh != "" {
			f, err := os.OpenFile(gh, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return 0, err
			}
			kind := ""
			if finding != nil {
				kind = finding.Predicate.Kind
			}
			_, err = fmt.Fprintf(f, "finding=%s\ncertified=%t\nsubject-name=%s\nsubject-digest=sha256:%s\nlevel=%s\nband=%s\n",
				kind, outcome.Certified, st.Subject[0].Name, st.Subject[0].Digest["sha256"], p.Level, p.Band)
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
		loaded, err := certify.LoadTrustPolicy(certify.LoadOptions{
			Offline: a.bools["offline"], File: a.strings["trust-policy"], TrustedRoot: a.strings["trusted-root"],
		})
		if err != nil {
			return 0, err
		}
		if loaded.Status != "ok" {
			d, err := certify.DigestArtifact(path)
			if err != nil {
				return 0, err
			}
			status := "rejected"
			headline := "NOT VERIFIED"
			if loaded.Status == "rollback" {
				status = "ROLLBACK"
				headline = "ROLLBACK"
			}
			failed := map[string]any{
				"ok": false, "status": status, "artifactDigest": d.SHA256,
				"bundles": []any{}, "notes": loaded.Warnings,
			}
			if a.bools["json"] {
				os.Stdout.Write(prettyJSON(failed))
			} else {
				fmt.Printf("artifact sha256:%s\n%s\n", d.SHA256, headline)
				for _, n := range loaded.Warnings {
					fmt.Printf("  note: %s\n", n)
				}
			}
			return 1, nil
		}
		var anchorReceipt *certify.AnchorReceipt
		if ar := a.strings["anchor-receipt"]; ar != "" {
			b, err := os.ReadFile(ar)
			if err != nil {
				return 0, err
			}
			var r certify.AnchorReceipt
			if err := json.Unmarshal(b, &r); err != nil {
				return 0, err
			}
			anchorReceipt = &r
		}
		tms := &certify.TrustedMaterialSource{Path: a.strings["trusted-root"]}
		result, err := certify.VerifyArtifact(path, a.bundles, &loaded.Policy, tms, certify.VerifyOptions{
			Revocations: loaded.Revocations, CheckRevocation: loaded.RevocationChecked && !a.bools["offline"],
			Offline: a.bools["offline"], BaselinePolicyDigests: loaded.BaselinePolicyDigests,
			ExpectedSource: a.strings["source"], PrivateMode: a.bools["private"],
			AnchorReceipt: anchorReceipt,
		})
		if err != nil {
			return 0, err
		}
		if !a.bools["offline"] && !loaded.RevocationChecked {
			filtered := result.Notes[:0]
			for _, n := range result.Notes {
				if !strings.HasPrefix(n, "revocation is not checked in v0.1") {
					filtered = append(filtered, n)
				}
			}
			result.Notes = filtered
		}
		for _, w := range loaded.Warnings {
			if !slices.Contains(result.Notes, w) {
				result.Notes = append(result.Notes, w)
			}
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
			if result.Source != "" {
				if result.Level == "scanned" {
					fmt.Printf("  source %s (public scan by workrr; not signed by the maintainer)\n", result.Source)
				} else {
					fmt.Printf("  publisher %s\n", result.Source)
				}
			}
			if result.PolicyName != "" || result.PolicyDigest != "" {
				name := result.PolicyName
				if name == "" {
					name = "(unnamed)"
				}
				if result.PolicyDigest != "" {
					fmt.Printf("  policy %s %s\n", name, result.PolicyDigest)
				} else {
					fmt.Printf("  policy %s\n", name)
				}
			}
			if result.Anchor != nil {
				fmt.Printf("  anchor #%d %s (%s)\n", result.Anchor.Sequence, result.Anchor.ChainHash, result.Anchor.AnchoredAt)
			}
			if result.Band != "" {
				fmt.Printf("  band %s\n", result.Band)
			}
			if result.Status == "REVOKED" {
				fmt.Println("REVOKED")
			} else {
				fmt.Println(certify.VerificationHeadline(result.OK, result.Level, result.PolicyStatus, result.Notes, result.Band))
			}
			for _, n := range result.Notes {
				fmt.Printf("  note: %s\n", n)
			}
		}
		if result.OK {
			return 0, nil
		}
		return 1, nil

	case "gate":
		minLevel := "silver"
		if m := a.strings["min-level"]; m != "" {
			if minLevel = certify.ParseLevel(m); minLevel == "" {
				return 0, fmt.Errorf("--min-level must be scanned, signed, tested, or reproduced")
			}
		}
		reqPolicy := certify.BaselinePolicy()
		if p := a.strings["policy"]; p != "" {
			b, err := os.ReadFile(p)
			if err != nil {
				return 0, err
			}
			if reqPolicy, err = certify.ParsePolicy(b); err != nil {
				return 0, err
			}
		}
		trustPolicy := certify.DefaultTrustPolicy
		if p := a.strings["trust-policy"]; p != "" {
			b, err := os.ReadFile(p)
			if err != nil {
				return 0, err
			}
			if err := json.Unmarshal(b, &trustPolicy); err != nil {
				return 0, err
			}
		}
		var allowed []string
		if s := a.strings["source"]; s != "" {
			allowed = []string{s}
		}
		res, err := certify.RunOrgPolicyGate(path, certify.OrgGateOptions{
			MinLevel:        minLevel,
			RequiredPolicy:  reqPolicy,
			CertificatesDir: a.strings["certificates-dir"],
			AllowedSources:  allowed,
			TrustPolicy:     &trustPolicy,
			TrustedMaterial: &certify.TrustedMaterialSource{Path: a.strings["trusted-root"]},
		})
		if err != nil {
			return 0, err
		}
		if a.bools["json"] {
			os.Stdout.Write(prettyJSON(res))
		} else {
			fmt.Printf("org gate: %d/%d skill(s) pass (required: %s, policy: %s)\n", res.PassedSkills, res.TotalSkills, res.MinLevel, res.RequiredPolicyName)
			for _, s := range res.Skills {
				if s.OK {
					fmt.Printf("  ✓ %s (%s) — %s (%s)\n", s.Path, s.Name, certify.LevelName(s.Level), s.Level)
				} else {
					fmt.Printf("  ✗ %s (%s) — %s\n", s.Path, s.Name, strings.Join(s.Reasons, "; "))
				}
			}
			if res.OK {
				fmt.Println("ORG GATE PASSED")
			} else {
				fmt.Println("ORG GATE FAILED")
			}
		}
		if res.OK {
			return 0, nil
		}
		return 1, nil

	case "verify-finding":
		if len(a.bundles) != 1 {
			return 0, fmt.Errorf("verify-finding needs exactly one --bundle")
		}
		loaded, err := certify.LoadTrustPolicy(certify.LoadOptions{
			Offline: a.bools["offline"], File: a.strings["trust-policy"], TrustedRoot: a.strings["trusted-root"],
		})
		if err != nil {
			return 0, err
		}
		if loaded.Status != "ok" {
			return 0, fmt.Errorf("trust policy: %s %s", loaded.Status, strings.Join(loaded.Warnings, "; "))
		}
		r, err := certify.VerifyFinding(path, a.bundles[0], &loaded.Policy, &certify.TrustedMaterialSource{Path: a.strings["trusted-root"]})
		if err != nil {
			return 0, err
		}
		if a.bools["json"] {
			os.Stdout.Write(prettyJSON(r))
		} else {
			fmt.Printf("artifact sha256:%s\n", r.ArtifactDigest)
			if r.Source != "" {
				commit := r.Commit
				if len(commit) > 12 {
					commit = commit[:12]
				}
				fmt.Printf("  source %s@%s %s\n", r.Source, commit, r.Path)
			}
			for _, f := range r.Findings {
				fmt.Printf("  %s\n", findingLine(f))
			}
			if r.OK {
				fmt.Printf("FINDING REPRODUCED · %s\n", r.Kind)
			} else {
				fmt.Printf("NOT REPRODUCED: %s\n", r.Error)
			}
		}
		if r.OK {
			return 0, nil
		}
		return 1, nil

	case "anchor":
		if len(a.bundles) == 0 {
			return 0, fmt.Errorf("anchor needs --bundle <file>")
		}
		d, err := certify.DigestArtifact(path)
		if err != nil {
			return 0, err
		}
		rawBytes, err := os.ReadFile(a.bundles[0])
		if err != nil {
			return 0, err
		}
		genericBundle, err := certify.DecodeJSON(rawBytes)
		if err != nil {
			return 0, err
		}
		bm, _ := genericBundle.(map[string]any)
		if bm["dsseEnvelope"] == nil {
			return 0, fmt.Errorf("bundle has no DSSE envelope")
		}
		hashes, err := certify.ComputeAnchorHashes(rawBytes, bm["dsseEnvelope"], d.SHA256)
		if err != nil {
			return 0, err
		}
		out := prettyJSON(hashes)
		if p := a.strings["out"]; p != "" {
			if err := os.WriteFile(p, out, 0o644); err != nil {
				return 0, err
			}
		} else {
			os.Stdout.Write(out)
		}
		return 0, nil
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
