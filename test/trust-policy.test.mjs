// The built-in trust policy: older releases pinned by tag digest, the newest by exact tag.
import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_TRUST_POLICY } from "../dist/trust-policy.js";
import { matchDescribedSigner } from "../dist/verify.js";

const issuer = "https://token.actions.githubusercontent.com";
const san = (ref) => `https://github.com/workrr-trust/certify/.github/workflows/certify.yml@${ref}`;
const match = (ref, buildSignerDigest) => matchDescribedSigner(DEFAULT_TRUST_POLICY, { san: san(ref), issuer, buildSignerDigest });

test("older releases need their pinned tag digest", () => {
  assert.ok(match("refs/tags/v0.1.1", "78d8c1a98c929b7b1c1b532c25256582a84887b1"));
  assert.equal(match("refs/tags/v0.1.1", "5a1d5c47fc1175db9979e13a2301dae57458a135"), undefined);
});

test("the newest release is accepted by its exact tag", () => {
  assert.ok(match("refs/tags/v0.1.2", "1234567890123456789012345678901234567890"));
});

test("unlisted, look-alike and branch refs are rejected", () => {
  for (const ref of ["refs/tags/v0.1.3", "refs/tags/v0.1.2x", "refs/tags/v0.1.2-rc1", "refs/heads/v0.1.2", "refs/heads/main"]) {
    assert.equal(match(ref, "78d8c1a98c929b7b1c1b532c25256582a84887b1"), undefined, ref);
  }
});

test("the GitLab identity is not trusted at the newest release", () => {
  const gl = { san: "https://gitlab.com/workrr-trust/certify-gitlab//.gitlab-ci.yml@refs/tags/v0.1.2", issuer: "https://gitlab.com", buildSignerDigest: "1234567890123456789012345678901234567890" };
  assert.equal(matchDescribedSigner(DEFAULT_TRUST_POLICY, gl), undefined);
});
