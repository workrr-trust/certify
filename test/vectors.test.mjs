// Cross-implementation test vectors (spec/test-vectors). The Go implementation
// (go/) asserts against the same expected.json; Gold depends on both
// producing byte-identical canonical `checks`.
import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluate, readVectors } from "../spec/test-vectors/vectors.mjs";
import { DEFAULT_TRUST_POLICY } from "../dist/trust-policy.js";
import { applyVerificationGates, baselinePolicyDigest, matchDescribedSigner, sourceMatches, verificationHeadline } from "../dist/verify.js";

const { cases, expected } = await readVectors();
// Round-trip through JSON so `undefined` fields compare as absent, as serialized.
const actual = JSON.parse(JSON.stringify(await evaluate(cases)));

test("vectors: ruleset and policy digests", () => {
  assert.equal(actual.rulesetVersion, expected.rulesetVersion);
  assert.equal(actual.rulesetDigest, expected.rulesetDigest);
  assert.deepEqual(actual.policyDigests, expected.policyDigests);
});

test("vectors: canonical JSON", () => {
  assert.deepEqual(actual.canonicalJson, expected.canonicalJson);
});

for (const id of Object.keys(expected.artifacts)) {
  test(`vectors: artifact ${id}`, () => {
    const a = actual.artifacts[id];
    const e = expected.artifacts[id];
    assert.ok(a, `missing artifact ${id}`);
    const { checks: _a, ...restA } = a;
    const { checks: _e, ...restE } = e;
    assert.deepEqual(restA, restE);
    // The Gold comparison is over these exact strings.
    for (const p of Object.keys(e.checks)) assert.equal(a.checks[p], e.checks[p], `checks under policy ${p}`);
  });
}

test("vectors: every case has expectations", () => {
  assert.deepEqual(Object.keys(actual.artifacts), Object.keys(expected.artifacts));
});

const revocation = "revocation is not checked in v0.1 (revocation ledger ships in v0.2)";

for (const signer of cases.trust.signers) {
  test(`vectors: trust signer ${signer.id}`, () => {
    const accepted = matchDescribedSigner(DEFAULT_TRUST_POLICY, signer);
    assert.equal(Boolean(accepted), signer.accepted, signer.id);
  });
}

for (const policy of cases.trust.policies) {
  test(`vectors: trust policy ${policy.id}`, () => {
    const gate = applyVerificationGates({
      level: policy.certificateLevel,
      policies: [{ policyName: policy.policyName, policyDigest: policy.policyDigest }],
      sources: ["https://github.com/workrr-trust/sample-skills"],
      notes: [revocation],
    });
    assert.equal(gate.policyStatus, policy.status);
    assert.equal(gate.ok, policy.ok);
    assert.equal(verificationHeadline(gate), policy.headline);
    if (policy.status !== "baseline") assert.equal(gate.level, undefined);
    if (policy.reason) assert.ok(gate.notes.includes(policy.reason), gate.notes.join("\n"));
    if (policy.status === "baseline") assert.equal(policy.policyDigest, baselinePolicyDigest());
  });
}

for (const source of cases.trust.sources) {
  test(`vectors: trust source ${source.id}`, () => {
    assert.equal(sourceMatches(source.certificate, source.flag), source.match);
    const gate = applyVerificationGates({
      level: "silver",
      policies: [{ policyName: "workrr-baseline-v0.1", policyDigest: baselinePolicyDigest() }],
      sources: [source.certificate],
      expectedSource: source.flag,
      notes: [revocation],
    });
    if (source.match) {
      assert.equal(gate.ok, true);
      assert.equal(gate.level, "silver");
      assert.equal(verificationHeadline(gate), "VERIFIED · level silver");
    } else {
      assert.equal(gate.ok, false);
      assert.equal(gate.level, undefined);
      assert.equal(verificationHeadline(gate), "NOT VERIFIED");
      assert.ok(gate.notes.includes(source.note), gate.notes.join("\n"));
    }
  });
}
