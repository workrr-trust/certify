// Cross-implementation test vectors (spec/test-vectors). The Go implementation
// (go/) asserts against the same expected.json; Gold depends on both
// producing byte-identical canonical `checks`.
import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluate, readVectors } from "../spec/test-vectors/vectors.mjs";

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
