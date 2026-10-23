import { env } from "cloudflare:workers";
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index";

const bindings = env as Env;
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

const policyBlob = {
  mediaType: "application/vnd.workrr.signed-blob+json;version=1",
  payloadType: "application/vnd.workrr.trust-policy+json",
  payload: "e30",
  signature: { algorithm: "ed25519", publicKey: "AAAA", sig: "BBBB" },
};
const entry1 = { ...policyBlob, payloadType: "application/vnd.workrr.revocation-entry+json", payload: "ZW50cnkx" };
const entry2 = { ...policyBlob, payloadType: "application/vnd.workrr.revocation-entry+json", payload: "ZW50cnky" };
const checkpoint = { ...policyBlob, payloadType: "application/vnd.workrr.revocation-checkpoint+json", payload: "Y2hlY2s" };

async function call(path: string): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(new IncomingRequest("https://trust-api.test" + path), bindings, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

beforeEach(async () => {
  await bindings.DB.exec("DELETE FROM policies; DELETE FROM revocations; DELETE FROM revocation_checkpoint;");
  const listed = await bindings.BLOBS.list();
  await Promise.all(listed.objects.map((obj) => bindings.BLOBS.delete(obj.key)));
});

async function seed(): Promise<void> {
  await bindings.BLOBS.put("policy/2.json", JSON.stringify(policyBlob));
  await bindings.BLOBS.put("revocations/1.json", JSON.stringify(entry1));
  await bindings.BLOBS.put("revocations/2.json", JSON.stringify(entry2));
  await bindings.BLOBS.put("revocations/checkpoint.json", JSON.stringify(checkpoint));
  await bindings.DB.prepare("INSERT INTO policies (sequence, issued_at, r2_key) VALUES (?, ?, ?)").bind(2, "2026-10-22T00:00:00Z", "policy/2.json").run();
  await bindings.DB.prepare(
    "INSERT INTO revocations (sequence, artifact_digest, log_index, reason, timestamp, signer, r2_key) VALUES (?, ?, NULL, ?, ?, ?, ?)",
  )
    .bind(1, "a".repeat(64), "compromised certifier", "2026-10-22T12:00:00Z", "https://github.com/workrr-trust/certify/.github/workflows/revoke.yml@refs/tags/v0.1.1", "revocations/1.json")
    .run();
  await bindings.DB.prepare(
    "INSERT INTO revocations (sequence, artifact_digest, log_index, reason, timestamp, signer, r2_key) VALUES (?, NULL, ?, ?, ?, ?, ?)",
  )
    .bind(2, "1697019812", "certificate log entry withdrawn", "2026-10-22T12:00:02Z", "https://github.com/workrr-trust/certify/.github/workflows/revoke.yml@refs/tags/v0.1.1", "revocations/2.json")
    .run();
  await bindings.DB.prepare("INSERT INTO revocation_checkpoint (id, sequence, r2_key) VALUES (1, ?, ?)").bind(2, "revocations/checkpoint.json").run();
}

describe("trust API", () => {
  it("serves the highest signed policy with a short cache", async () => {
    await seed();
    await bindings.BLOBS.put("policy/1.json", JSON.stringify({ ...policyBlob, payload: "b2xk" }));
    await bindings.DB.prepare("INSERT INTO policies (sequence, issued_at, r2_key) VALUES (?, ?, ?)").bind(1, "2026-01-01T00:00:00Z", "policy/1.json").run();
    const res = await call("/v1/policy");
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("public, max-age=300");
    expect(res.headers.get("etag")).toBe('"2"');
    expect(res.headers.get("x-workrr-sequence")).toBe("2");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(await res.json()).toEqual(policyBlob);
  });

  it("returns 404 when no policy has been published", async () => {
    const res = await call("/v1/policy");
    expect(res.status).toBe(404);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({ error: "no trust policy published" });
  });

  it("looks up revocations by artifact digest", async () => {
    await seed();
    const res = await call(`/v1/revocations?digest=${"a".repeat(64)}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("public, max-age=60");
    expect(await res.json()).toEqual({ digest: "a".repeat(64), entries: [entry1] });
    const empty = await call(`/v1/revocations?digest=${"b".repeat(64)}`);
    expect(empty.status).toBe(200);
    expect(await empty.json()).toEqual({ digest: "b".repeat(64), entries: [] });
  });

  it("rejects a digest that is not 64 lowercase hex characters", async () => {
    const res = await call("/v1/revocations?digest=AABB");
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "digest must be 64 lowercase hex characters" });
    const missing = await call("/v1/revocations");
    expect(missing.status).toBe(400);
  });

  it("returns the signed feed after a sequence, including the checkpoint", async () => {
    await seed();
    const res = await call("/v1/revocations/since/1");
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("public, max-age=60");
    expect(await res.json()).toEqual({ since: 1, checkpoint, entries: [entry2] });
    const all = await call("/v1/revocations/since/0");
    expect(await all.json()).toEqual({ since: 0, checkpoint, entries: [entry1, entry2] });
  });

  it("returns an empty feed when nothing has been revoked", async () => {
    const res = await call("/v1/revocations/since/0");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ since: 0, checkpoint: null, entries: [] });
  });

  it("rejects a since value that is not a non-negative integer", async () => {
    const res = await call("/v1/revocations/since/nope");
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "since must be a non-negative integer" });
    expect((await call("/v1/revocations/since/-1")).status).toBe(400);
    expect((await call("/v1/revocations/since/01")).status).toBe(400);
  });

  it("rejects unknown routes and non-GET methods", async () => {
    expect((await call("/v1/other")).status).toBe(404);
    const ctx = createExecutionContext();
    const posted = await worker.fetch(new IncomingRequest("https://trust-api.test/v1/policy", { method: "POST" }), bindings, ctx);
    await waitOnExecutionContext(ctx);
    expect(posted.status).toBe(405);
  });
});
