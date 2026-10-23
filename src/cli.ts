#!/usr/bin/env node
// workrr — certify and verify AI agent artifacts.
import { appendFile, readFile, writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { loadArtifact } from "./artifact.js";
import { certify } from "./certify.js";
import { BASELINE_POLICY, type Policy } from "./checks/policy.js";
import { runTests, type TestsReport } from "./checks/tests.js";
import { digestArtifact } from "./digest.js";
import { DEFAULT_TRUST_POLICY, type TrustPolicy } from "./trust-policy.js";
import { computeAnchorHashes, verificationHeadline, verifyArtifact, type AnchorReceipt } from "./verify.js";
import { VERSION } from "./version.js";

const HELP = `workrr ${VERSION} — certify and verify AI agent artifacts

Usage:
  workrr digest  <path>
  workrr test    <path> [--out tests.json]
  workrr certify <path> [--policy policy.json] [--tests-report tests.json | --run-tests]
                        [--statement-out statement.json] [--predicate-out predicate.json]
  workrr verify  <path> --bundle <file> [--bundle <file>] [--trust-policy policy.json]
                        [--source <repo>] [--private] [--trusted-root trusted_root.json]
                        [--anchor-receipt receipt.json] [--json]
  workrr anchor  <path> --bundle <file> [--out anchor-request.json]

  test     Runs the artifact's declared suite (workrr.json). Runs artifact code:
           in CI, use a job WITHOUT signing permission.
  certify  Runs provenance, policy and scan checks; exits 1 if any check fails.
           In GitHub Actions also writes subject-name / subject-digest outputs.
  verify   Checks the artifact digest, Sigstore signature, Rekor inclusion and
           certifier identity. Reports the policy name and digest. A policy that
           is not the baseline does not verify at a baseline level. --source
           fails when the certificate's publisher repo does not match.
           --private accepts private-tier TSA attestations and optional hash-only
           anchor receipts (--anchor-receipt).
  anchor   Computes the hash-only public anchor request payload for a private bundle.
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
      "statement-out": { type: "string" },
      "predicate-out": { type: "string" },
      bundle: { type: "string", multiple: true },
      "trust-policy": { type: "string" },
      "trusted-root": { type: "string" },
      "anchor-receipt": { type: "string" },
      source: { type: "string" },
      private: { type: "boolean" },
      json: { type: "boolean" },
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
      const outcome = await certify(path, { policy, testsReport, runTestsLocally: values["run-tests"] });
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
          outcome.certified ? `level      ${p.level}` : `NOT CERTIFIED:\n  - ${outcome.failures.join("\n  - ")}`,
          "",
        ].join("\n"),
      );
      for (const f of c.scan.findings.filter((x) => x.severity === "warn")) {
        process.stderr.write(`  warn: ${f.rule} ${f.file}:${f.line}\n`);
      }
      if (values["statement-out"]) await writeFile(values["statement-out"], JSON.stringify(statement, null, 2) + "\n");
      if (values["predicate-out"]) await writeFile(values["predicate-out"], JSON.stringify(p, null, 2) + "\n");
      if (process.env.GITHUB_OUTPUT) {
        await appendFile(
          process.env.GITHUB_OUTPUT,
          `certified=${outcome.certified}\nsubject-name=${statement.subject[0].name}\nsubject-digest=sha256:${statement.subject[0].digest.sha256}\nlevel=${p.level}\n`,
        );
      }
      return outcome.certified ? 0 : 1;
    }
    case "verify": {
      if (!values.bundle?.length) throw new Error("verify needs at least one --bundle");
      const policy = values["trust-policy"] ? await readJson<TrustPolicy>(values["trust-policy"]) : DEFAULT_TRUST_POLICY;
      const anchorReceipt = values["anchor-receipt"] ? await readJson<AnchorReceipt>(values["anchor-receipt"]) : undefined;
      const result = await verifyArtifact(path, values.bundle, policy, values.source, {
        privateMode: values.private,
        trustedRootPath: values["trusted-root"],
        anchorReceipt,
      });
      if (values.json) {
        process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      } else {
        process.stdout.write(`artifact sha256:${result.artifactDigest}\n`);
        for (const b of result.bundles) {
          process.stdout.write(b.ok ? `  ✓ ${b.bundlePath} — ${b.forge}: ${b.signerIdentity}\n` : `  ✗ ${b.bundlePath} — ${b.error}\n`);
        }
        if (result.source) process.stdout.write(`  publisher ${result.source}\n`);
        if (result.policyName || result.policyDigest) {
          process.stdout.write(`  policy ${result.policyName ?? "(unnamed)"}${result.policyDigest ? ` ${result.policyDigest}` : ""}\n`);
        }
        if (result.anchor) {
          process.stdout.write(`  anchor #${result.anchor.sequence} ${result.anchor.chainHash} (${result.anchor.anchoredAt})\n`);
        }
        process.stdout.write(`${verificationHeadline(result)}\n`);
        for (const n of result.notes) process.stdout.write(`  note: ${n}\n`);
      }
      return result.ok ? 0 : 1;
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
