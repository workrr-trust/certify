// Regenerates spec/trust-feed/vectors.json. The ed25519 seed is a test key.
// Production verifiers do not accept it; they require the pinned Sigstore identity.
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { BASELINE_POLICY } from "../../dist/checks/policy.js";
import { canonicalJson, jsonDigest, sha256Hex } from "../../dist/digest.js";
import { GENESIS_PREV, OFFLINE_WARNING, TRUST_POLICY_SCHEMA } from "../../dist/trust-feed.js";
import { DEFAULT_TRUST_POLICY } from "../../dist/trust-policy.js";

const seed = Buffer.from("workrr-trust-feed-test-key-v1!!!");
if (seed.length !== 32) throw new Error(`seed is ${seed.length} bytes, want 32`);

const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
const privateKey = createPrivateKey({ key: Buffer.concat([pkcs8Prefix, seed]), format: "der", type: "pkcs8" });
const publicKey = createPublicKey(privateKey).export({ type: "spki", format: "der" }).subarray(-32);

const POLICY = "application/vnd.workrr.trust-policy+json";
const ENTRY = "application/vnd.workrr.revocation-entry+json";
const CHECKPOINT = "application/vnd.workrr.revocation-checkpoint+json";
const MEDIA = "application/vnd.workrr.signed-blob+json;version=1";
const SIGNER = "https://github.com/workrr-trust/certify/.github/workflows/revoke.yml@refs/tags/v0.1.1";

function signed(payloadType, text) {
  return {
    mediaType: MEDIA,
    payloadType,
    payload: Buffer.from(text).toString("base64"),
    signature: {
      algorithm: "ed25519",
      publicKey: publicKey.toString("base64"),
      sig: sign(null, Buffer.from(text), privateKey).toString("base64"),
    },
  };
}

function policy(sequence) {
  return canonicalJson({
    schema: TRUST_POLICY_SCHEMA,
    sequence,
    issuedAt: "2026-10-22T00:00:00Z",
    signers: DEFAULT_TRUST_POLICY.signers,
    baselinePolicyDigests: {
      [BASELINE_POLICY.name]: jsonDigest(BASELINE_POLICY),
    },
    revocationFeed: "https://trust-api.workrr.ai/v1/revocations",
    revocationWatermark: 0,
    revocationHead: GENESIS_PREV,
  });
}

function revocation(subject, reason) {
  const text = canonicalJson({
    schema: "workrr-revocation-v1",
    sequence: 1,
    subject,
    reason,
    timestamp: "2026-10-22T12:00:00Z",
    signer: SIGNER,
    prev: GENESIS_PREV,
  });
  const checkpoint = canonicalJson({
    schema: "workrr-revocation-checkpoint-v1",
    sequence: 1,
    head: sha256Hex(text),
    timestamp: "2026-10-22T12:00:01Z",
    signer: SIGNER,
  });
  return { entry: signed(ENTRY, text), checkpoint: signed(CHECKPOINT, checkpoint) };
}

const validText = policy(2);
const validBlob = signed(POLICY, validText);
const tamperedText = validText.replace('"sequence":2', '"sequence":9');
if (tamperedText === validText) throw new Error("tamper did not change the policy");
const tamperedBlob = { ...validBlob, payload: Buffer.from(tamperedText).toString("base64") };
const rollbackBlob = signed(POLICY, policy(1));
const byDigest = revocation({ artifactDigest: "a".repeat(64) }, "compromised certifier");
const byLog = revocation({ logIndex: "1697019812" }, "certificate log entry withdrawn");

const vectors = {
  $comment:
    "Shared trust-feed vectors. Payloads are canonical JSON. Signatures are ed25519 from the test seed in generate.mjs; production verifiers do not accept that key.",
  publicKey: publicKey.toString("base64"),
  cases: [
    {
      id: "valid-policy",
      op: "policy",
      floorSequence: 1,
      blob: validBlob,
      expect: { ok: true, sequence: 2, schema: TRUST_POLICY_SCHEMA },
    },
    {
      id: "tampered-policy",
      op: "policy",
      floorSequence: 1,
      blob: tamperedBlob,
      expect: { ok: false, error: "signature invalid" },
    },
    {
      id: "rollback",
      op: "policy",
      floorSequence: 3,
      blob: rollbackBlob,
      expect: { ok: false, error: "ROLLBACK: trust policy sequence 1 is older than 3" },
    },
    {
      id: "revoked-certificate",
      op: "revocation",
      artifactDigest: "a".repeat(64),
      logIndexes: [],
      watermark: 0,
      revocationHead: GENESIS_PREV,
      entries: [byDigest.entry],
      checkpoint: byDigest.checkpoint,
      expect: { ok: false, status: "REVOKED", reason: "compromised certifier" },
    },
    {
      id: "revoked-log-index",
      op: "revocation",
      artifactDigest: "b".repeat(64),
      logIndexes: ["1697019812"],
      watermark: 0,
      revocationHead: GENESIS_PREV,
      entries: [byLog.entry],
      checkpoint: byLog.checkpoint,
      expect: { ok: false, status: "REVOKED", reason: "certificate log entry withdrawn" },
    },
    {
      id: "offline-fallback",
      op: "offline",
      expect: { source: "embedded", revocationChecked: false, warning: OFFLINE_WARNING },
    },
  ],
};

const out = join(dirname(fileURLToPath(import.meta.url)), "vectors.json");
writeFileSync(out, JSON.stringify(vectors, null, 2) + "\n");
console.log(`wrote ${out}`);
