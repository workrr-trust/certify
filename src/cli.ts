#!/usr/bin/env node
// workrr — certify and verify AI agent artifacts.
import { appendFile, chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { loadArtifact } from "./artifact.js";
import { certify } from "./certify.js";
import { findingStatement, verifyFinding } from "./finding.js";
import { levelName, parseLevel } from "./levels.js";
import { BASELINE_POLICY, type Policy } from "./checks/policy.js";
import { runTests, type TestsReport } from "./checks/tests.js";
import { digestArtifact } from "./digest.js";
import { buildPack, collectDependencies, collectPublisher, primaryBundle, PROFILES, type PackBundle, type Profile } from "./evidence.js";
import { runOrgPolicyGate, type GateLevel } from "./gate.js";
import { loadTrustPolicy } from "./policy-loader.js";
import { DEFAULT_TRUST_POLICY, type TrustPolicy } from "./trust-policy.js";
import { computeAnchorHashes, verificationHeadline, verifyArtifact, type AnchorReceipt } from "./verify.js";
import { VERSION } from "./version.js";

const HELP = `workrr ${VERSION} — certify and verify AI agent artifacts

Usage:
  workrr digest  <path>
  workrr test    <path> [--out tests.json]
  workrr certify <path> [--policy policy.json] [--tests-report tests.json | --run-tests]
                        [--statement-out statement.json] [--predicate-out predicate.json]
                        [--observe https://github.com/<owner>/<repo> [--finding-out finding.json]]
                        [--witness https://github.com/<owner>/<repo>]
  workrr verify  <path> --bundle <file> [--bundle <file>] [--trust-policy policy.json]
                        [--source <repo>] [--offline] [--private] [--json]
                        [--trusted-root trusted_root.json] [--anchor-receipt receipt.json]
  workrr verify-finding <path> --bundle <file> [--trust-policy policy.json] [--json]
  workrr anchor  <path> --bundle <file> [--out anchor-request.json]
  workrr evidence <path> --bundle <file> [--bundle <file>] --profile cra --out <dir>
                        [--trust-policy policy.json] [--offline] [--trusted-root trusted_root.json]
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
           --witness names that repository as the source of a checkout made
           elsewhere (the GitLab witness, docs/gitlab-certifier.md); tests
           still count.
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
           A revoked certificate can still verify in that mode. Sigstore's own
           trust root may still be fetched unless it is already cached.
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
  evidence Verifies like \`verify\`, then writes an evidence pack to --out: the
           certificate mapped to one regulation's records (docs/evidence.md).
           Profiles: cra (EU Cyber Resilience Act). Refuses when verification
           fails. The pack is evidence for the user's own assessment, never a
           conformity assessment or declaration.
  gate     Org policy gate: discovers all skills in <repo-dir> and exits 1 if
           any skill is uncertified, fails policy/scan, or is below --min-level.
`;

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === "-h" || cmd === "--help") {
    process.stdout.write(HELP);
    return 0;
  }
  if (cmd === "--version" || cmd === "-v") {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  const { values, positionals } = parseArgs({
    args: rest,
    allowPositionals: true,
    options: {
      out: { type: "string" },
      policy: { type: "string" },
      "tests-report": { type: "string" },
      "run-tests": { type: "boolean" },
      observe: { type: "string" },
      witness: { type: "string" },
      "finding-out": { type: "string" },
      "statement-out": { type: "string" },
      "predicate-out": { type: "string" },
      bundle: { type: "string", multiple: true },
      "trust-policy": { type: "string" },
      "min-level": { type: "string" },
      "certificates-dir": { type: "string" },
      "trusted-root": { type: "string" },
      "anchor-receipt": { type: "string" },
      source: { type: "string" },
      private: { type: "boolean" },
      offline: { type: "boolean" },
      json: { type: "boolean" },
      profile: { type: "string" },
    },
  });
  const path = positionals[0];
  if (!path) throw new Error(`missing <path>\n\n${HELP}`);

  switch (cmd) {
    case "digest": {
      const d = await digestArtifact(path);
      process.stdout.write(`sha256:${d.sha256}  ${d.algorithm}  ${d.files.length} file(s)\n`);
      return 0;
    }
    case "test": {
      const artifact = await loadArtifact(path);
      const report: TestsReport = { artifactDigest: artifact.digest.sha256, tests: await runTests(artifact) };
      const json = JSON.stringify(report, null, 2) + "\n";
      if (values.out) await writeFile(values.out, json);
      else process.stdout.write(json);
      process.stderr.write(`tests: ${report.tests.result}\n`);
      return report.tests.result === "fail" ? 1 : 0;
    }
    case "certify": {
      const policy = values.policy ? await readJson<Policy>(values.policy) : BASELINE_POLICY;
      const testsReport = values["tests-report"] ? await readJson<TestsReport>(values["tests-report"]) : undefined;
      const observe = values.observe;
      if (observe !== undefined && !/^https:\/\/github\.com\/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/.test(observe)) {
        throw new Error("--observe must be https://github.com/<owner>/<repo>");
      }
      if (values["finding-out"] && observe === undefined) throw new Error("--finding-out needs --observe");
      const witness = values.witness;
      if (witness !== undefined && !/^https:\/\/github\.com\/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/.test(witness)) {
        throw new Error("--witness must be https://github.com/<owner>/<repo>");
      }
      if (witness !== undefined && observe !== undefined) throw new Error("use --observe or --witness, not both");
      if (observe !== undefined && (testsReport || values["run-tests"])) {
        throw new Error("--observe never runs tests; drop --tests-report / --run-tests");
      }
      const outcome = await certify(path, { policy, testsReport, runTestsLocally: values["run-tests"], observe, witness });
      const { statement } = outcome;
      const p = statement.predicate;
      const c = p.checks;
      process.stderr.write(
        [
          `artifact   ${p.artifact.name} (${p.artifact.type}, ${p.artifact.fileCount} file(s))`,
          `digest     sha256:${statement.subject[0].digest.sha256}`,
          `source     ${p.source.uri}@${p.source.commit.slice(0, 12)} ${p.source.path}`,
          `provenance ${c.provenance.result}${c.provenance.reason ? ` — ${c.provenance.reason}` : ""}`,
          `policy     ${c.policy.result} (${c.policy.policyName})`,
          `scan       ${c.scan.result} (${c.scan.findings.length} finding(s), ${c.scan.rulesetVersion})`,
          `tests      ${c.tests.result}`,
          outcome.certified
            ? `level      ${levelName(p.level)} (${p.level})${p.band ? `, band ${p.band}` : ""}`
            : `NOT CERTIFIED:\n  - ${outcome.failures.join("\n  - ")}`,
          "",
        ].join("\n"),
      );
      for (const f of c.scan.findings.filter((x) => x.severity === "warn")) {
        process.stderr.write(`  warn: ${f.rule} ${f.file}:${f.line}\n`);
      }
      if (values["statement-out"]) await writeFile(values["statement-out"], JSON.stringify(statement, null, 2) + "\n");
      if (values["predicate-out"]) await writeFile(values["predicate-out"], JSON.stringify(p, null, 2) + "\n");
      const finding = values["finding-out"] ? findingStatement(outcome) : undefined;
      if (finding) {
        await writeFile(values["finding-out"]!, JSON.stringify(finding.predicate, null, 2) + "\n");
        process.stderr.write(`finding    ${finding.predicate.kind}: ${finding.predicate.findings.map((f) => f.detail + (f.file ? ` ${f.file}${f.line ? `:${f.line}` : ""}` : "")).join("; ")}\n`);
      }
      if (process.env.GITHUB_OUTPUT) {
        await appendFile(
          process.env.GITHUB_OUTPUT,
          `finding=${finding ? finding.predicate.kind : ""}\ncertified=${outcome.certified}\nsubject-name=${statement.subject[0].name}\nsubject-digest=sha256:${statement.subject[0].digest.sha256}\nlevel=${p.level}\nband=${p.band ?? ""}\n`,
        );
      }
      return outcome.certified ? 0 : 1;
    }
    case "verify": {
      if (!values.bundle?.length) throw new Error("verify needs at least one --bundle");
      const loaded = await loadTrustPolicy({ offline: values.offline, file: values["trust-policy"] });
      if (loaded.status !== "ok") {
        const { sha256 } = await digestArtifact(path);
        const failed = {
          ok: false,
          status: loaded.status === "rollback" ? "ROLLBACK" : "rejected",
          artifactDigest: sha256,
          bundles: [],
          notes: loaded.warnings,
        };
        if (values.json) process.stdout.write(JSON.stringify(failed, null, 2) + "\n");
        else {
          process.stdout.write(`artifact sha256:${sha256}\n`);
          process.stdout.write(loaded.status === "rollback" ? "ROLLBACK\n" : "NOT VERIFIED\n");
          for (const n of loaded.warnings) process.stdout.write(`  note: ${n}\n`);
        }
        return 1;
      }
      const anchorReceipt = values["anchor-receipt"] ? await readJson<AnchorReceipt>(values["anchor-receipt"]) : undefined;
      const result = await verifyArtifact(path, values.bundle, loaded.policy, {
        offline: values.offline,
        expectedSource: values.source,
        revocations: loaded.revocationChecked ? loaded.revocations : undefined,
        baselinePolicyDigests: loaded.baselinePolicyDigests,
        privateMode: values.private,
        trustedRootPath: values["trusted-root"],
        anchorReceipt,
      });
      if (!values.offline && !loaded.revocationChecked) {
        result.notes = result.notes.filter((n) => !n.startsWith("revocation is not checked in v0.1"));
      }
      for (const warning of loaded.warnings) {
        if (!result.notes.includes(warning)) result.notes.push(warning);
      }
      if (values.json) {
        process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      } else {
        process.stdout.write(`artifact sha256:${result.artifactDigest}\n`);
        for (const b of result.bundles) {
          process.stdout.write(b.ok ? `  ✓ ${b.bundlePath} — ${b.forge}: ${b.signerIdentity}\n` : `  ✗ ${b.bundlePath} — ${b.error}\n`);
        }
        if (result.source) {
          process.stdout.write(
            result.level === "scanned"
              ? `  source ${result.source} (public scan by workrr; not signed by the maintainer)\n`
              : `  publisher ${result.source}\n`,
          );
        }
        if (result.policyName || result.policyDigest) {
          process.stdout.write(`  policy ${result.policyName ?? "(unnamed)"}${result.policyDigest ? ` ${result.policyDigest}` : ""}\n`);
        }
        if (result.anchor) {
          process.stdout.write(`  anchor #${result.anchor.sequence} ${result.anchor.chainHash} (${result.anchor.anchoredAt})\n`);
        }
        if (result.band) {
          process.stdout.write(`  band ${result.band}\n`);
        }
        const headline = result.status === "REVOKED" ? "REVOKED" : verificationHeadline(result);
        process.stdout.write(`${headline}\n`);
        for (const n of result.notes) process.stdout.write(`  note: ${n}\n`);
      }
      return result.ok ? 0 : 1;
    }
    case "gate": {
      const minLevel: GateLevel | undefined = values["min-level"] ? parseLevel(values["min-level"]) : "silver";
      if (!minLevel) throw new Error("--min-level must be scanned, signed, tested, or reproduced");
      const requiredPolicy = values.policy ? await readJson<Policy>(values.policy) : BASELINE_POLICY;
      const trustPolicy = values["trust-policy"] ? await readJson<TrustPolicy>(values["trust-policy"]) : DEFAULT_TRUST_POLICY;
      const result = await runOrgPolicyGate(path, {
        minLevel,
        requiredPolicy,
        certificatesDir: values["certificates-dir"],
        allowedSources: values.source ? [values.source] : undefined,
        trustPolicy,
      });
      if (values.json) {
        process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      } else {
        process.stdout.write(
          `org gate: ${result.passedSkills}/${result.totalSkills} skill(s) pass (required: ${result.minLevel}, policy: ${result.requiredPolicyName})\n`,
        );
        for (const s of result.skills) {
          if (s.ok) {
            process.stdout.write(`  ✓ ${s.path} (${s.name}) — ${levelName(s.level)} (${s.level})\n`);
          } else {
            process.stdout.write(`  ✗ ${s.path} (${s.name}) — ${s.reasons.join("; ")}\n`);
          }
        }
        process.stdout.write(result.ok ? "ORG GATE PASSED\n" : "ORG GATE FAILED\n");
      }
      return result.ok ? 0 : 1;
    }
    case "verify-finding": {
      if (values.bundle?.length !== 1) throw new Error("verify-finding needs exactly one --bundle");
      const loaded = await loadTrustPolicy({ offline: values.offline, file: values["trust-policy"] });
      if (loaded.status !== "ok") throw new Error(`trust policy: ${loaded.warnings.join("; ") || loaded.status}`);
      const r = await verifyFinding(path, values.bundle[0], loaded.policy, { trustedRootPath: values["trusted-root"] });
      if (values.json) {
        process.stdout.write(JSON.stringify(r, null, 2) + "\n");
      } else {
        process.stdout.write(`artifact sha256:${r.artifactDigest}\n`);
        if (r.source) process.stdout.write(`  source ${r.source}@${(r.commit ?? "").slice(0, 12)} ${r.path ?? ""}\n`);
        for (const f of r.findings ?? []) {
          process.stdout.write(`  ${f.detail}${f.file ? ` ${f.file}${f.line ? `:${f.line}` : ""}` : ""}\n`);
        }
        process.stdout.write(r.ok ? `FINDING REPRODUCED · ${r.kind}\n` : `NOT REPRODUCED: ${r.error}\n`);
      }
      return r.ok ? 0 : 1;
    }
    case "anchor": {
      if (!values.bundle?.length) throw new Error("anchor needs --bundle <file>");
      const { sha256: artifactDigest } = await digestArtifact(path);
      const rawBytes = await readFile(values.bundle[0]);
      const parsed = JSON.parse(rawBytes.toString("utf8")) as { dsseEnvelope?: unknown };
      if (!parsed.dsseEnvelope) throw new Error("bundle has no DSSE envelope");
      const hashes = computeAnchorHashes(rawBytes, parsed.dsseEnvelope, artifactDigest);
      const out = JSON.stringify(hashes, null, 2) + "\n";
      if (values.out) await writeFile(values.out, out);
      else process.stdout.write(out);
      return 0;
    }
    case "evidence": {
      if (!values.bundle?.length) throw new Error("evidence needs at least one --bundle");
      const profile = values.profile as Profile | undefined;
      if (!profile || !PROFILES.includes(profile)) throw new Error(`--profile must be one of: ${PROFILES.join(", ")}`);
      if (!values.out) throw new Error("evidence needs --out <dir>");
      const loaded = await loadTrustPolicy({ offline: values.offline, file: values["trust-policy"] });
      if (loaded.status !== "ok") throw new Error(`trust policy: ${loaded.warnings.join("; ") || loaded.status}`);
      const revocationChecked = !values.offline && loaded.revocationChecked;
      const result = await verifyArtifact(path, values.bundle, loaded.policy, {
        offline: values.offline,
        revocations: revocationChecked ? loaded.revocations : undefined,
        baselinePolicyDigests: loaded.baselinePolicyDigests,
        trustedRootPath: values["trusted-root"],
      });
      if (revocationChecked) result.notes = result.notes.filter((n) => !n.startsWith("revocation is not checked in v0.1"));
      for (const warning of loaded.warnings) if (!result.notes.includes(warning)) result.notes.push(warning);
      if (!result.ok || result.status !== "verified") {
        process.stdout.write(`${result.status === "REVOKED" ? "REVOKED" : "NOT VERIFIED"}: no evidence pack was built\n`);
        for (const b of result.bundles) if (!b.ok) process.stdout.write(`  ✗ ${b.bundlePath} — ${b.error}\n`);
        return 1;
      }
      const used = new Set<string>();
      const bundles: PackBundle[] = await Promise.all(result.bundles.map(async (r, i) => {
        let file = `certificate/${basename(r.bundlePath)}`;
        if (used.has(file)) file = `certificate/${i}-${basename(r.bundlePath)}`;
        used.add(file);
        return { file, bytes: await readFile(r.bundlePath), result: r };
      }));
      const artifact = await loadArtifact(path);
      const predicate = primaryBundle(bundles).result.statement!.predicate;
      const pack = buildPack({
        artifact,
        verify: result,
        bundles,
        publisher: await collectPublisher(artifact, predicate),
        dependencies: await collectDependencies(artifact),
        revocationChecked,
        builtAt: new Date().toISOString(),
      }, profile);
      for (const [name, contents] of pack) {
        const dest = join(values.out, name);
        await mkdir(dirname(dest), { recursive: true });
        await writeFile(dest, contents);
      }
      await chmod(join(values.out, "verify.sh"), 0o755);
      process.stdout.write(`evidence pack (${profile}) for sha256:${result.artifactDigest} written to ${values.out}\n`);
      for (const name of pack.keys()) process.stdout.write(`  ${name}\n`);
      for (const n of result.notes) process.stdout.write(`  note: ${n}\n`);
      return 0;
    }
    default:
      throw new Error(`unknown command: ${cmd}\n\n${HELP}`);
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`workrr: ${(err as Error).message}\n`);
    process.exit(2);
  },
);
