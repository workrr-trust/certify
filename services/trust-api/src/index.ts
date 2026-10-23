// Transport for the signed trust policy and the revocation feed.
// The worker does not verify signatures. Clients do. A response is only as
// trustworthy as the Sigstore signature inside it.

export interface Env {
  DB: D1Database;
  BLOBS: R2Bucket;
}

const POLICY_CACHE = "public, max-age=300";
const FEED_CACHE = "public, max-age=60";
const DIGEST = /^[0-9a-f]{64}$/;
const SINCE = /^(0|[1-9][0-9]*)$/;

type PolicyRow = { sequence: number; r2_key: string };
type RevocationRow = { sequence: number; r2_key: string };

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    if (request.method !== "GET") return json({ error: "method not allowed" }, 405, { allow: "GET" });
    const url = new URL(request.url);
    if (url.pathname === "/v1/policy") return policy(env);
    if (url.pathname === "/v1/revocations") return byDigest(env, url);
    const since = url.pathname.match(/^\/v1\/revocations\/since\/([^/]+)$/);
    if (since) return feedSince(env, since[1]);
    return json({ error: "not found" }, 404);
  },
} satisfies ExportedHandler<Env>;

async function policy(env: Env): Promise<Response> {
  const row = await env.DB.prepare("SELECT sequence, r2_key FROM policies ORDER BY sequence DESC LIMIT 1").first<PolicyRow>();
  if (!row) return json({ error: "no trust policy published" }, 404, { "cache-control": "no-store" });
  const obj = await env.BLOBS.get(row.r2_key);
  if (!obj) return json({ error: "trust policy blob missing" }, 500, { "cache-control": "no-store" });
  return new Response(await obj.arrayBuffer(), {
    status: 200,
    headers: baseHeaders({
      "cache-control": POLICY_CACHE,
      etag: `"${row.sequence}"`,
      "x-workrr-sequence": String(row.sequence),
    }),
  });
}

async function byDigest(env: Env, url: URL): Promise<Response> {
  const digest = url.searchParams.get("digest");
  if (digest === null || !DIGEST.test(digest)) {
    return json({ error: "digest must be 64 lowercase hex characters" }, 400, { "cache-control": "no-store" });
  }
  const { results } = await env.DB.prepare(
    "SELECT sequence, r2_key FROM revocations WHERE artifact_digest = ? ORDER BY sequence ASC",
  )
    .bind(digest)
    .all<RevocationRow>();
  const entries = await readAll(env, results ?? []);
  if (entries instanceof Response) return entries;
  return json({ digest, entries }, 200, { "cache-control": FEED_CACHE });
}

async function feedSince(env: Env, since: string): Promise<Response> {
  if (!SINCE.test(since)) return json({ error: "since must be a non-negative integer" }, 400, { "cache-control": "no-store" });
  const { results } = await env.DB.prepare("SELECT sequence, r2_key FROM revocations WHERE sequence > ? ORDER BY sequence ASC")
    .bind(Number(since))
    .all<RevocationRow>();
  const entries = await readAll(env, results ?? []);
  if (entries instanceof Response) return entries;
  const checkpointRow = await env.DB.prepare("SELECT sequence, r2_key FROM revocation_checkpoint WHERE id = 1").first<RevocationRow>();
  let checkpoint: unknown = null;
  if (checkpointRow) {
    const body = await readBlob(env, checkpointRow.r2_key);
    if (body instanceof Response) return body;
    checkpoint = body;
  }
  return json({ since: Number(since), checkpoint, entries }, 200, { "cache-control": FEED_CACHE });
}

async function readAll(env: Env, rows: RevocationRow[]): Promise<unknown[] | Response> {
  const entries: unknown[] = [];
  for (const row of rows) {
    const body = await readBlob(env, row.r2_key);
    if (body instanceof Response) return body;
    entries.push(body);
  }
  return entries;
}

async function readBlob(env: Env, key: string): Promise<unknown | Response> {
  const obj = await env.BLOBS.get(key);
  if (!obj) return json({ error: "signed blob missing" }, 500, { "cache-control": "no-store" });
  try {
    return await obj.json();
  } catch {
    return json({ error: "signed blob is not JSON" }, 500, { "cache-control": "no-store" });
  }
}

function baseHeaders(extra: Record<string, string> = {}): Headers {
  return new Headers({
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
    "access-control-allow-origin": "*",
    ...extra,
  });
}

function json(body: unknown, status: number, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: baseHeaders(extra) });
}
