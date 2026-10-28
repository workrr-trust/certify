// Shared trust-feed vectors (spec/trust-feed/vectors.json). The Go tests assert
// the same file. Also covers policy loading: offline, cache, and a bad signature.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  FETCH_FAILED_CACHE_WARNING,
  FETCH_FAILED_EMBEDDED_WARNING,
  OFFLINE_WARNING,
  POLICY_CACHE_TTL_MS,
  REVOCATION_SIGNER,
  REVOCATION_UNCHECKED_WARNING,
  SIGNATURE_INVALID_WARNING,
  TRUST_POLICY_SIGNER,
  decidePolicy,
  decideRevocation,
  offlineFallback,
  parseTrustPolicy,
} from "../dist/trust-feed.js";
import { loadTrustPolicy } from "../dist/policy-loader.js";
import { matchSigner } from "../dist/verify.js";

const vectors = JSON.parse(await readFile(fileURLToPath(new URL("../spec/trust-feed/vectors.json", import.meta.url)), "utf8"));

for (const c of vectors.cases) {
  test(`trust-feed vector: ${c.id}`, async () => {
    if (c.op === "policy") {
      assert.deepEqual(decidePolicy(c.blob, c.floorSequence, [vectors.publicKey]), c.expect);
    } else if (c.op === "revocation") {
      assert.deepEqual(
        await decideRevocation({
          entryBlobs: c.entries,
          checkpointBlob: c.checkpoint,
          watermark: c.watermark,
          revocationHead: c.revocationHead,
          artifactDigest: c.artifactDigest,
          logIndexes: c.logIndexes,
          allowKeys: [vectors.publicKey],
        }),
        c.expect,
      );
    } else if (c.op === "offline") {
      assert.deepEqual(offlineFallback(), c.expect);
    } else {
      throw new Error(`unknown op ${c.op}`);
    }
  });
}

test("verify --help documents --offline", () => {
  const help = spawnSync(process.execPath, [fileURLToPath(new URL("../dist/cli.js", import.meta.url)), "--help"], { encoding: "utf8" });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /--offline/);
  assert.match(help.stdout, /offline: using the embedded trust policy; revocation was not checked/);
});

test("policy and revocation signers accept release tags only", () => {
  const policy = { version: "x", signers: [TRUST_POLICY_SIGNER] };
  const revocation = { version: "x", signers: [REVOCATION_SIGNER] };
  const id = (san, signer) => ({ subjectAlternativeName: san, extensions: { issuer: signer.issuer } });
  assert.ok(matchSigner(policy, id("https://github.com/workrr-trust/certify/.github/workflows/trust-policy.yml@refs/tags/v1.2.3", TRUST_POLICY_SIGNER)));
  assert.equal(matchSigner(policy, id("https://github.com/workrr-trust/certify/.github/workflows/trust-policy.yml@refs/heads/main", TRUST_POLICY_SIGNER)), undefined);
  assert.equal(matchSigner(policy, id("https://github.com/workrr-trust/certify/.github/workflows/certify.yml@refs/tags/v1.2.3", TRUST_POLICY_SIGNER)), undefined);
  assert.ok(matchSigner(revocation, id("https://github.com/workrr-trust/certify/.github/workflows/revoke.yml@refs/tags/v1.2.3", REVOCATION_SIGNER)));
  assert.equal(matchSigner(revocation, id("https://github.com/workrr-trust/certify/.github/workflows/revoke.yml@refs/heads/main", REVOCATION_SIGNER)), undefined);
});

const valid = vectors.cases.find((c) => c.id === "valid-policy");
const tampered = vectors.cases.find((c) => c.id === "tampered-policy");
const emptyFeed = { since: 0, checkpoint: null, entries: [] };

function fetchMock(routes) {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(String(url));
    const hit = routes.find((r) => String(url).includes(r.includes));
    if (!hit) throw new Error(`unexpected fetch ${url}`);
    if (hit.throw) throw new Error("network down");
    return new Response(JSON.stringify(hit.body), { status: hit.status ?? 200, headers: { "content-type": "application/json" } });
  };
  return { fetchImpl, calls };
}

test("offline does not contact the trust API and warns", async () => {
  const { fetchImpl, calls } = fetchMock([]);
  const loaded = await loadTrustPolicy({ offline: true, fetchImpl, cachePath: join(tmpdir(), "missing-workrr-cache.json") });
  assert.deepEqual(calls, []);
  assert.equal(loaded.source, "embedded");
  assert.equal(loaded.revocationChecked, false);
  assert.deepEqual(loaded.warnings, [OFFLINE_WARNING]);
});

test("a verified policy is cached and a tampered one falls back", async () => {
  const dir = await mkdtemp(join(tmpdir(), "workrr-trust-"));
  const cachePath = join(dir, "trust-policy.json");
  const keys = [vectors.publicKey];
  const ok = fetchMock([
    { includes: "/v1/policy", body: valid.blob },
    { includes: "/since/0", body: emptyFeed },
  ]);
  const loaded = await loadTrustPolicy({
    cachePath,
    allowEd25519Keys: keys,
    fetchImpl: ok.fetchImpl,
    baseUrl: "https://trust.test",
    now: 1_700_000_000_000,
  });
  assert.equal(loaded.source, "signed");
  assert.equal(loaded.status, "ok");
  assert.equal(loaded.revocationChecked, true);
  assert.deepEqual(loaded.warnings, []);
  assert.deepEqual(loaded.revocations, []);

  const cached = fetchMock([{ includes: "/since/0", body: emptyFeed }]);
  const again = await loadTrustPolicy({
    cachePath,
    allowEd25519Keys: keys,
    fetchImpl: cached.fetchImpl,
    baseUrl: "https://trust.test",
    now: 1_700_000_000_000 + 1000,
  });
  assert.equal(again.source, "cache");
  assert.deepEqual(cached.calls, ["https://trust-api.workrr.ai/v1/revocations/since/0"]);

  const bad = fetchMock([
    { includes: "/v1/policy", body: tampered.blob },
    { includes: "/since/0", body: emptyFeed },
  ]);
  const fell = await loadTrustPolicy({
    cachePath: join(dir, "empty.json"),
    allowEd25519Keys: keys,
    fetchImpl: bad.fetchImpl,
    baseUrl: "https://trust.test",
    now: 1_700_000_000_000,
  });
  assert.equal(fell.source, "embedded");
  assert.deepEqual(fell.warnings, [SIGNATURE_INVALID_WARNING]);
  assert.equal(fell.revocationChecked, true);
});

test("fetch failure uses a stale cache, or the embedded policy", async () => {
  const dir = await mkdtemp(join(tmpdir(), "workrr-trust-"));
  const cachePath = join(dir, "trust-policy.json");
  const keys = [vectors.publicKey];
  const now = 1_700_000_000_000;
  await loadTrustPolicy({
    cachePath,
    allowEd25519Keys: keys,
    baseUrl: "https://trust.test",
    now,
    fetchImpl: fetchMock([
      { includes: "/v1/policy", body: valid.blob },
      { includes: "/since/0", body: emptyFeed },
    ]).fetchImpl,
  });
  const stale = await loadTrustPolicy({
    cachePath,
    allowEd25519Keys: keys,
    baseUrl: "https://trust.test",
    now: now + POLICY_CACHE_TTL_MS + 1,
    fetchImpl: fetchMock([
      { includes: "/v1/policy", throw: true },
      { includes: "/since/0", body: emptyFeed },
    ]).fetchImpl,
  });
  assert.equal(stale.source, "cache");
  assert.ok(stale.warnings.includes(FETCH_FAILED_CACHE_WARNING));

  const missing = await loadTrustPolicy({
    cachePath: join(dir, "nope.json"),
    allowEd25519Keys: keys,
    baseUrl: "https://trust.test",
    now,
    fetchImpl: fetchMock([
      { includes: "/v1/policy", throw: true },
      { includes: "/since/0", throw: true },
    ]).fetchImpl,
  });
  assert.equal(missing.source, "embedded");
  assert.deepEqual(missing.warnings, [FETCH_FAILED_EMBEDDED_WARNING, REVOCATION_UNCHECKED_WARNING]);
  assert.equal(missing.revocationChecked, false);
});

test("a signer with an unknown role is skipped; witness signers are kept", () => {
  const valid = vectors.cases.find((c) => c.id === "valid-policy");
  const doc = JSON.parse(Buffer.from(valid.blob.payload, "base64").toString("utf8"));
  const witness = doc.signers.find((s) => s.role === "witness");
  assert.ok(witness, "the policy lists the GitLab witness");
  const future = { ...witness, role: "auditor" };
  const parsed = parseTrustPolicy(JSON.stringify({ ...doc, signers: [...doc.signers, future] }));
  assert.equal(parsed.ok, undefined, parsed.error);
  assert.equal(parsed.signers.length, doc.signers.length);
  assert.equal(parsed.signers.find((s) => s.forge === "gitlab")?.role, "witness");
  assert.equal(parseTrustPolicy(JSON.stringify({ ...doc, signers: [future] })).error, "malformed trust policy");
});
