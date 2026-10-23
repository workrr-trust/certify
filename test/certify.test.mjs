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
import { certify, computeTrustBand } from "../dist/certify.js";
import { checkPolicy, BASELINE_POLICY } from "../dist/checks/policy.js";
import { scanArtifact, scanText } from "../dist/checks/scan.js";
import { runTests } from "../dist/checks/tests.js";
import { canonicalJson, digestArtifact, sha256Hex } from "../dist/digest.js";
import { normalizeRepoUri } from "../dist/checks/provenance.js";

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

test("computes deterministic A-E trust bands for banded artifacts", async () => {
  const dir = await mkdtemp(join(tmpdir(), "workrr-band-"));
  await writeFile(
    join(dir, "SKILL.md"),
    "---\nname: banded-skill\ndescription: Summarize notes. Use when reviewing notes.\nallowed-tools: Read\nlicense: Apache-2.0\n---\n# Banded Skill\n1. Read notes.\n",
  );
  const a = await loadArtifact(dir);
  const scan = await scanArtifact(a);
  assert.equal(computeTrustBand(a, BASELINE_POLICY, scan), "A");
  assert.equal(computeTrustBand(a, BASELINE_POLICY, scan, "C"), "C");

  const dirE = await mkdtemp(join(tmpdir(), "workrr-band-e-"));
  await writeFile(
    join(dirE, "SKILL.md"),
    "---\nname: min-skill\ndescription: Minimal description.\n---\nPlain text with zero\u200bwidth warning.\n",
  );
  const aE = await loadArtifact(dirE);
  const scanE = await scanArtifact(aE);
  assert.equal(computeTrustBand(aE, BASELINE_POLICY, scanE), "E");
});
