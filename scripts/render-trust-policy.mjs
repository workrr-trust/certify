// Render the canonical trust-policy document the release workflow signs.
// Signers come from the embedded policy, so a change to src/trust-policy.ts
// is picked up here without editing this script.
import { readFileSync, writeFileSync } from "node:fs";
import { BASELINE_POLICY } from "../dist/checks/policy.js";
import { canonicalJson, jsonDigest } from "../dist/digest.js";
import { DEFAULT_REVOCATION_FEED, GENESIS_PREV, TRUST_POLICY_SCHEMA } from "../dist/trust-feed.js";
import { DEFAULT_TRUST_POLICY } from "../dist/trust-policy.js";

const meta = JSON.parse(readFileSync(new URL("../trust/policy-meta.json", import.meta.url), "utf8"));
if (!Number.isInteger(meta.sequence) || meta.sequence < 1) throw new Error("trust/policy-meta.json sequence must be an integer >= 1");
if (meta.revocationWatermark === 0 && meta.revocationHead !== GENESIS_PREV) {
  throw new Error("revocationHead must be 64 zeros when revocationWatermark is 0");
}
const text = canonicalJson({
  schema: TRUST_POLICY_SCHEMA,
  sequence: meta.sequence,
  issuedAt: meta.issuedAt,
  signers: DEFAULT_TRUST_POLICY.signers,
  baselinePolicyDigests: { [BASELINE_POLICY.name]: jsonDigest(BASELINE_POLICY) },
  revocationFeed: DEFAULT_REVOCATION_FEED,
  revocationWatermark: meta.revocationWatermark,
  revocationHead: meta.revocationHead,
});
const out = process.argv[2] ?? "policy.json";
// No trailing newline: these bytes are what Sigstore signs.
writeFileSync(out, text);
console.log(`wrote ${out} (${text.length} bytes, sequence ${meta.sequence})`);
