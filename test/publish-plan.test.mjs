import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { planPolicy, planRevocation } from "../services/trust-api/scripts/publish-plan.mjs";

function blob(payloadType, payload) {
  return {
    mediaType: "application/vnd.workrr.signed-blob+json;version=1",
    payloadType,
    payload: Buffer.from(JSON.stringify(payload)).toString("base64"),
    signature: { algorithm: "sigstore", bundle: {} },
  };
}

const dir = mkdtempSync(join(tmpdir(), "publish-plan-"));
test.after(() => rmSync(dir, { recursive: true, force: true }));

test("policy plan names sequence 1 and only prints wrangler commands", () => {
  const path = join(dir, "signed-policy.json");
  writeFileSync(
    path,
    JSON.stringify(
      blob("application/vnd.workrr.trust-policy+json", {
        schema: "workrr-trust-policy-v1",
        sequence: 1,
        issuedAt: "2026-10-22T00:00:00Z",
      }),
    ),
  );
  const plan = planPolicy(path);
  assert.equal(plan.sequence, 1);
  assert.equal(plan.key, "policy/1.json");
  assert.equal(
    plan.sql,
    "INSERT INTO policies (sequence, issued_at, r2_key)\nVALUES (1, '2026-10-22T00:00:00Z', 'policy/1.json');\n",
  );
  assert.deepEqual(plan.commands, [
    `npx wrangler r2 object put workrr-trust-blobs/policy/1.json --file ${path} --content-type application/json --remote`,
    "npx wrangler d1 execute workrr-trust --remote --yes --file publish.sql",
  ]);
});

test("revocation plan indexes exactly one subject", () => {
  const entry = join(dir, "entry.signed.json");
  const checkpoint = join(dir, "checkpoint.signed.json");
  writeFileSync(
    entry,
    JSON.stringify(
      blob("application/vnd.workrr.revocation-entry+json", {
        schema: "workrr-revocation-v1",
        sequence: 1,
        subject: { artifactDigest: "a".repeat(64) },
        reason: "compromised certifier",
        timestamp: "2026-10-22T12:00:00Z",
        signer: "https://github.com/workrr-trust/certify/.github/workflows/revoke.yml@refs/tags/v0.2.0",
      }),
    ),
  );
  writeFileSync(
    checkpoint,
    JSON.stringify(
      blob("application/vnd.workrr.revocation-checkpoint+json", {
        schema: "workrr-revocation-checkpoint-v1",
        sequence: 1,
        head: "b".repeat(64),
        timestamp: "2026-10-22T12:00:01Z",
        signer: "https://github.com/workrr-trust/certify/.github/workflows/revoke.yml@refs/tags/v0.2.0",
      }),
    ),
  );
  const plan = planRevocation(entry, checkpoint);
  assert.match(plan.sql, /'a{64}', NULL,/);
  assert.match(plan.sql, /revocations\/checkpoint.json/);
  assert.equal(plan.commands.length, 3);
  assert.throws(() => planRevocation(checkpoint, entry), /not a revocation entry/);
});
