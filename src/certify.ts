// Assemble the certificate predicate and in-toto Statement (spec §3–4).
import { loadArtifact, type Artifact, type ArtifactType } from "./artifact.js";
import { checkPolicy, type Policy, type PolicyResult } from "./checks/policy.js";
import { checkProvenance, type ProvenanceResult, type Source } from "./checks/provenance.js";
import { scanArtifact, type ScanResult } from "./checks/scan.js";
import { runTests, type TestsReport, type TestsResult } from "./checks/tests.js";
import type { DigestAlgorithm } from "./digest.js";
import { VERSION } from "./version.js";

export const PREDICATE_TYPE = "https://trust.workrr.ai/certificate/v0.1";
export const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";

export type Checks = { provenance: ProvenanceResult; policy: PolicyResult; scan: ScanResult; tests: TestsResult };
export type Runtime = "github-actions" | "gitlab-ci" | "local";

export type Predicate = {
  artifact: { name: string; type: ArtifactType; digestAlgorithm: DigestAlgorithm; fileCount: number };
  source: Source;
  checks: Checks;
  level: "silver" | "banded";
  band?: "A" | "B" | "C" | "D" | "E";
  certifier: { name: string; version: string; runtime: Runtime };
  certifiedAt: string;
};

export type Statement = {
  _type: typeof STATEMENT_TYPE;
  subject: { name: string; digest: { sha256: string } }[];
  predicateType: typeof PREDICATE_TYPE;
  predicate: Predicate;
};

export type CertifyOutcome = {
  artifact: Artifact;
  statement: Statement;
  // Certificate is issued only when no check failed.
  certified: boolean;
  failures: string[];
};

export function detectRuntime(): Runtime {
  if (process.env.GITHUB_ACTIONS === "true") return "github-actions";
  if (process.env.GITLAB_CI === "true") return "gitlab-ci";
  return "local";
}

export type CertifyOptions = {
  policy?: Policy;
  // Result from a separate, unprivileged test job (required in CI).
  testsReport?: TestsReport;
  // Run the artifact's tests in-process. Only for local use: never in a job that can sign.
  runTestsLocally?: boolean;
};

export async function certify(path: string, opts: CertifyOptions = {}): Promise<CertifyOutcome> {
  const artifact = await loadArtifact(path);
  const { source, check: provenance } = await checkProvenance(path);
  const policy = checkPolicy(artifact, opts.policy);
  const scan = await scanArtifact(artifact, opts.policy?.scanExceptions);

  let tests: TestsResult = { result: "none" };
  const failures: string[] = [];
  if (opts.testsReport) {
    if (opts.testsReport.artifactDigest !== artifact.digest.sha256) {
      failures.push("tests report was produced for a different artifact digest");
      tests = { result: "fail" };
    } else {
      tests = opts.testsReport.tests;
    }
  } else if (opts.runTestsLocally) {
    tests = await runTests(artifact);
  }

  if (provenance.result === "fail") failures.push(`provenance: ${provenance.reason ?? "failed"}`);
  if (policy.result === "fail") failures.push(...policy.violations.map((v) => `policy: ${v}`));
  if (scan.result === "fail") {
    failures.push(
      ...scan.findings
        .filter((f) => f.severity !== "warn" && !f.excepted)
        .map((f) => `scan: ${f.rule} (${f.severity}) ${f.file}:${f.line}`),
    );
  }
  if (tests.result === "fail") failures.push(`tests: exit code ${tests.exitCode ?? "?"}`);

  const predicate: Predicate = {
    artifact: {
      name: artifact.name,
      type: artifact.type,
      digestAlgorithm: artifact.digest.algorithm,
      fileCount: artifact.digest.files.length,
    },
    source,
    checks: { provenance, policy, scan, tests },
    // Silver only when every check passed. A reserved-name or other policy failure
    // must not leave level "silver" on the statement.
    level:
      provenance.result === "pass" && policy.result === "pass" && scan.result === "pass" && tests.result === "pass"
        ? "silver"
        : "banded",
    certifier: { name: "workrr-certify", version: VERSION, runtime: detectRuntime() },
    certifiedAt: new Date().toISOString(),
  };
  const statement: Statement = {
    _type: STATEMENT_TYPE,
    subject: [{ name: artifact.name, digest: { sha256: artifact.digest.sha256 } }],
    predicateType: PREDICATE_TYPE,
    predicate,
  };
  return { artifact, statement, certified: failures.length === 0, failures };
}
