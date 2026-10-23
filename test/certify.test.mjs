// Run with `npm test` (builds first). Uses only node:test — no test framework dependency.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { loadArtifact } from "../dist/artifact.js";
import { certify } from "../dist/certify.js";
import { checkPolicy, BASELINE_POLICY } from "../dist/checks/policy.js";
import { scanArtifact, scanText } from "../dist/checks/scan.js";
import { runTests } from "../dist/checks/tests.js";
import { canonicalJson, digestArtifact, sha256Hex } from "../dist/digest.js";
import { normalizeRepoUri } from "../dist/checks/provenance.js";
import { applyVerificationGates, baselinePolicyDigest, evaluateGoldBundles } from "../dist/verify.js";
import { signStatementWithSigstore } from "../scripts/gitlab-sign.mjs";

const exec = promisify(execFile);

const fixtures = fileURLToPath(new URL("./fixtures/", import.meta.url));
const good = join(fixtures, "good-skill");
const bad = join(fixtures, "bad-skill");

test("dirhash is the sha256 of the sorted manifest (spec §1)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "workrr-"));
  await mkdir(join(dir, "b"));
  await writeFile(join(dir, "b", "x.txt"), "x");
  await writeFile(join(dir, "a.txt"), "a");
  await mkdir(join(dir, ".git"));
  await writeFile(join(dir, ".git", "HEAD"), "ignored");
  const d = await digestArtifact(dir);
  const manifest = `${sha256Hex("a")}  a.txt\n${sha256Hex("x")}  b/x.txt\n`;
  assert.equal(d.algorithm, "workrr-dirhash-v1");
  assert.equal(d.sha256, sha256Hex(manifest));
  assert.deepEqual(d.files.map((f) => f.path), ["a.txt", "b/x.txt"]);
});

test("single file digest is the file's sha256", async () => {
  const d = await digestArtifact(join(good, "SKILL.md"));
  assert.equal(d.algorithm, "file-sha256");
  assert.equal(d.files.length, 1);
});

test("canonical JSON sorts keys and drops undefined", () => {
  assert.equal(canonicalJson({ b: 1, a: [true, null], c: undefined }), '{"a":[true,null],"b":1}');
});

test("detects skill type and name from frontmatter", async () => {
  const a = await loadArtifact(good);
  assert.equal(a.type, "skill");
  assert.equal(a.name, "csv-summary");
});

test("good skill passes policy and scan", async () => {
  const a = await loadArtifact(good);
  assert.equal(checkPolicy(a).result, "pass");
  const scan = await scanArtifact(a);
  assert.equal(scan.result, "pass", JSON.stringify(scan.findings));
  assert.match(scan.rulesetDigest, /^sha256:[0-9a-f]{64}$/);
});

test("malicious skill fails the scan with the expected rules", async () => {
  const scan = await scanArtifact(await loadArtifact(bad));
  assert.equal(scan.result, "fail");
  const rules = new Set(scan.findings.map((f) => f.rule));
  for (const r of ["WT001", "WT002", "WT005", "WT006", "WT007", "WT008"]) assert.ok(rules.has(r), `expected ${r}`);
});

test("scan does not flag ordinary prose", () => {
  const text = "Ignore whitespace when comparing.\nTell the user the result.\nUse curl to fetch the page.\n";
  assert.deepEqual(scanText(text, "x.md"), []);
});

test("policy flags missing frontmatter fields and disallowed tools", async () => {
  const a = await loadArtifact(good);
  const r = checkPolicy(a, { ...BASELINE_POLICY, name: "strict", allowedTools: ["Grep"] });
  assert.equal(r.result, "fail");
  assert.deepEqual(r.violations, ["tool not allowed by policy: Read"]);
  assert.notEqual(r.policyDigest, checkPolicy(a).policyDigest);
});

test("runs the declared suite", async () => {
  const r = await runTests(await loadArtifact(good));
  assert.equal(r.result, "pass");
  assert.equal(r.command, "node check.cjs");
});

test("no suite → tests none", async () => {
  assert.equal((await runTests(await loadArtifact(bad))).result, "none");
});

test("reserved baseline name cannot certify payload.exe as silver", async () => {
  const dir = await mkdtemp(join(tmpdir(), "workrr-attack-"));
  await writeFile(join(dir, "SKILL.md"), "---\nname: evil\ndescription: Reserved-name regression.\n---\n# Evil\n");
  await writeFile(join(dir, "payload.exe"), "MZ");
  await writeFile(join(dir, "workrr.json"), JSON.stringify({ test: { command: "true" } }));
  const git = (...args) =>
    exec("git", ["-C", dir, ...args], {
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: "workrr",
        GIT_AUTHOR_EMAIL: "workrr@example.com",
        GIT_COMMITTER_NAME: "workrr",
        GIT_COMMITTER_EMAIL: "workrr@example.com",
      },
    });
  await git("init");
  await git("add", ".");
  await git("commit", "-m", "attack");
  await git("remote", "add", "origin", "https://github.com/evil/payload.git");

  const outcome = await certify(dir, { policy: { name: "workrr-baseline-v0.1" }, runTestsLocally: true });
  assert.equal(outcome.statement.predicate.checks.tests.result, "pass");
  assert.equal(outcome.statement.predicate.checks.provenance.result, "pass");
  assert.equal(outcome.certified, false);
  assert.notEqual(outcome.statement.predicate.level, "silver");
  assert.ok(outcome.failures.some((f) => f.includes("reserved")), outcome.failures.join("\n"));

  const baseline = await certify(dir, { policy: BASELINE_POLICY, runTestsLocally: true });
  assert.equal(baseline.certified, false);
  assert.notEqual(baseline.statement.predicate.level, "silver");
  assert.ok(baseline.statement.predicate.checks.policy.violations.some((v) => v.includes("forbidden file type: payload.exe")));
});

test("normalizes git remotes", () => {
  assert.equal(normalizeRepoUri("git@github.com:workrr-trust/certify.git"), "https://github.com/workrr-trust/certify");
  assert.equal(normalizeRepoUri("https://token@github.com/a/b.git"), "https://github.com/a/b");
});

test("GitLab signing helper validates statement and writes Sigstore bundle", async () => {
  const dir = await mkdtemp(join(tmpdir(), "workrr-gl-"));
  const stmtPath = join(dir, "statement.json");
  const outPath = join(dir, "certificate", "certificate.sigstore.json");
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "csv-summary", digest: { sha256: "a".repeat(64) } }],
    predicateType: "https://trust.workrr.ai/certificate/v0.1",
    predicate: {},
  };
  await writeFile(stmtPath, JSON.stringify(statement));
  let capturedType;
  let capturedToken;
  const fakeBundle = { mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", dsseEnvelope: {} };
  const res = await signStatementWithSigstore({
    statementPath: stmtPath,
    outPath,
    identityToken: "eyJ.fake.token",
    attestFn: async (_payload, payloadType, opts) => {
      capturedType = payloadType;
      capturedToken = opts.identityToken;
      return fakeBundle;
    },
  });
  assert.equal(capturedType, "application/vnd.in-toto+json");
  assert.equal(capturedToken, "eyJ.fake.token");
  assert.deepEqual(res, fakeBundle);
});

test("Gold requires GitHub and GitLab Silver for the same digest, commit, path, and identical checks", () => {
  const baseChecks = {
    provenance: { result: "pass", unchangedFromCommit: true },
    policy: { result: "pass", policyName: "workrr-baseline-v0.1", policyDigest: baselinePolicyDigest(), violations: [] },
    scan: { result: "pass", rulesetVersion: "workrr-scan-v0.1", rulesetDigest: `sha256:${"0".repeat(64)}`, findings: [] },
    tests: { result: "pass", command: "npm test", exitCode: 0 },
  };
  const makeBundle = (forge, commit, checks = baseChecks, uri = `https://${forge}.com/workrr-trust/sample-skills`) => ({
    bundlePath: `${forge}.sigstore.json`,
    ok: true,
    forge,
    statement: {
      _type: "https://in-toto.io/Statement/v1",
      subject: [{ name: "csv-summary", digest: { sha256: "f".repeat(64) } }],
      predicateType: "https://trust.workrr.ai/certificate/v0.1",
      predicate: {
        artifact: { name: "csv-summary", type: "skill", digestAlgorithm: "workrr-dirhash-v1", fileCount: 3 },
        source: { uri, commit, path: "skills/csv-summary" },
        checks,
        level: "silver",
        certifier: { name: "@workrr-trust/certify", version: "0.1.1", runtime: forge === "github" ? "github-actions" : "gitlab-ci" },
        certifiedAt: "2026-10-22T00:00:00Z",
      },
    },
  });

  const gh = makeBundle("github", "a".repeat(40));
  const gl = makeBundle("gitlab", "a".repeat(40));
  const goldEval = evaluateGoldBundles([gh, gl], []);
  assert.equal(goldEval.level, "gold");
  const goldGate = applyVerificationGates({
    level: goldEval.level,
    policies: [gh.statement.predicate.checks.policy, gl.statement.predicate.checks.policy],
    sources: [gh.statement.predicate.source.uri, gl.statement.predicate.source.uri],
    expectedSource: "https://github.com/workrr-trust/sample-skills",
    notes: goldEval.notes,
  });
  assert.equal(goldGate.ok, true, goldGate.notes.join("\n"));
  assert.equal(goldGate.level, "gold");

  // Different source commits → Silver, not Gold
  const glDiffCommit = makeBundle("gitlab", "b".repeat(40));
  const commitMismatch = evaluateGoldBundles([gh, glDiffCommit], []);
  assert.equal(commitMismatch.level, "silver");
  assert.ok(commitMismatch.notes.includes("two forges signed, but their source commits differ — not Gold"));

  // Different check results → Silver, not Gold
  const glDiffChecks = makeBundle("gitlab", "a".repeat(40), {
    ...baseChecks,
    tests: { result: "pass", command: "pytest", exitCode: 0 },
  });
  const checkMismatch = evaluateGoldBundles([gh, glDiffChecks], []);
  assert.equal(checkMismatch.level, "silver");
  assert.ok(checkMismatch.notes.includes("two forges signed, but their check results differ — not Gold"));
});
