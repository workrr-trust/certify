// The built-in trust policy: older releases pinned by tag digest, the newest by exact tag.
import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_TRUST_POLICY } from "../dist/trust-policy.js";
import { checkObserverSigner, evaluateGoldBundles, matchDescribedSigner } from "../dist/verify.js";

const issuer = "https://token.actions.githubusercontent.com";
const san = (ref) => `https://github.com/workrr-trust/certify/.github/workflows/certify.yml@${ref}`;
const match = (ref, buildSignerDigest) => matchDescribedSigner(DEFAULT_TRUST_POLICY, { san: san(ref), issuer, buildSignerDigest });

test("older releases need their pinned tag digest", () => {
  assert.ok(match("refs/tags/v0.1.1", "78d8c1a98c929b7b1c1b532c25256582a84887b1"));
  assert.equal(match("refs/tags/v0.1.1", "5a1d5c47fc1175db9979e13a2301dae57458a135"), undefined);
});

test("v0.1.2 needs its pinned tag digest", () => {
  assert.ok(match("refs/tags/v0.1.2", "7ed4c1ded5e6e611cfea5234b42d9601e827ff07"));
  assert.equal(match("refs/tags/v0.1.2", "2bbb72964e862c326af210c0117e47c740b463b0"), undefined);
  assert.equal(match("refs/tags/v0.1.2", "1234567890123456789012345678901234567890"), undefined);
});

test("v0.1.3 needs its pinned tag digest", () => {
  assert.ok(match("refs/tags/v0.1.3", "7cf13e7228c6f2bdf01b6d3ab670edef6f77fe4b"));
  assert.equal(match("refs/tags/v0.1.3", "46c524bf97e8f580375edff746c847b86f4b23f9"), undefined);
});

test("the newest release is accepted by its exact tag", () => {
  assert.ok(match("refs/tags/v0.1.4", "1234567890123456789012345678901234567890"));
});

test("unlisted, look-alike and branch refs are rejected", () => {
  for (const ref of ["refs/tags/v0.1.5", "refs/tags/v0.1.4x", "refs/tags/v0.1.4-rc1", "refs/heads/v0.1.4", "refs/heads/main"]) {
    assert.equal(match(ref, "78d8c1a98c929b7b1c1b532c25256582a84887b1"), undefined, ref);
  }
});

test("the GitLab identity is not trusted at the newest release", () => {
  const gl = { san: "https://gitlab.com/workrr-trust/certify-gitlab//.gitlab-ci.yml@refs/tags/v0.1.4", issuer: "https://gitlab.com", buildSignerDigest: "1234567890123456789012345678901234567890" };
  assert.equal(matchDescribedSigner(DEFAULT_TRUST_POLICY, gl), undefined);
});

// Public scans (docs/public-scans.md).
const scanSan = (ref) => `https://github.com/workrr-trust/certify/.github/workflows/scan.yml@${ref}`;
const scanMatch = (ref) =>
  matchDescribedSigner(DEFAULT_TRUST_POLICY, { san: scanSan(ref), issuer, buildSignerDigest: "1234567890123456789012345678901234567890" });

test("scan.yml is an observer signer at the newest release only", () => {
  assert.equal(scanMatch("refs/tags/v0.1.4")?.role, "observer");
  for (const ref of ["refs/tags/v0.1.3", "refs/heads/main", "refs/tags/v0.1.4-rc1"]) assert.equal(scanMatch(ref), undefined, ref);
  assert.equal(match("refs/tags/v0.1.4", "1234567890123456789012345678901234567890")?.role, undefined);
});

const scanned = (over = {}) => ({
  _type: "https://in-toto.io/Statement/v1",
  subject: [{ name: "s", digest: { sha256: "f".repeat(64) } }],
  predicateType: "https://trust.workrr.ai/certificate/v0.1",
  predicate: {
    source: { uri: "https://github.com/someone/skills", commit: "a".repeat(40), path: "skills/s" },
    checks: {
      provenance: { result: "pass", unchangedFromCommit: true },
      policy: { result: "pass", policyName: "workrr-baseline-v0.1", policyDigest: "x", violations: [] },
      scan: { result: "pass", findings: [] },
      tests: { result: "none" },
    },
    level: "scanned",
    band: "B",
    ...over,
  },
});
const certifyRepo = { sourceRepositoryURI: "https://github.com/workrr-trust/certify" };

test("an observer must run in workrr-trust/certify, claim scanned, and carry no tests", () => {
  assert.equal(checkObserverSigner(scanned(), certifyRepo), undefined);
  assert.match(checkObserverSigner(scanned(), { sourceRepositoryURI: "https://github.com/someone/skills" }), /outside/);
  assert.match(checkObserverSigner(scanned(), {}), /outside/);
  assert.match(checkObserverSigner(scanned({ level: "banded" }), certifyRepo), /not scanned/);
  const withTests = scanned();
  withTests.predicate.checks.tests = { result: "pass", command: "npm test", exitCode: 0 };
  assert.match(checkObserverSigner(withTests, certifyRepo), /test result/);
});

test("a scan stands alone only without a publisher certificate, and never makes gold", () => {
  const obs = { bundlePath: "scan.json", ok: true, forge: "github", observer: true, statement: scanned() };
  assert.equal(evaluateGoldBundles([obs], []).level, "scanned");
  const pub = structuredClone(obs);
  delete pub.observer;
  pub.statement.predicate.level = "banded";
  assert.equal(evaluateGoldBundles([obs, pub], []).level, "banded");
  const silver = structuredClone(pub);
  silver.statement.predicate.level = "silver";
  silver.statement.predicate.checks.tests = { result: "pass", command: "t", exitCode: 0 };
  const obsGitlab = { ...obs, forge: "gitlab" };
  assert.equal(evaluateGoldBundles([silver, obsGitlab], []).level, "silver");
});
