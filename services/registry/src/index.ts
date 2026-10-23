// workrr Registry Worker (R2 + D1): verified publishers, certified artifact
// index backed by Sigstore bundles in R2, and a SHA-256 hash-chained D1 audit log.

export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  run(): Promise<{ success: boolean }>;
  all<T = Record<string, unknown>>(): Promise<{ results?: T[] }>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
}

export interface R2ObjectBody {
  arrayBuffer(): Promise<ArrayBuffer>;
  text(): Promise<string>;
  json<T = unknown>(): Promise<T>;
}

export interface R2Bucket {
  put(key: string, value: string | ArrayBuffer | Uint8Array): Promise<unknown>;
  get(key: string): Promise<R2ObjectBody | null>;
}

export interface Env {
  DB: D1Database;
  BLOBS: R2Bucket;
}

const HEX64 = /^[0-9a-f]{64}$/;
const SHA256_PREF = /^sha256:[0-9a-f]{64}$/;
const GENESIS_HASH = "0".repeat(64);

export type PublisherRecord = {
  publisherId: string;
  forge: "github" | "gitlab";
  namespace: string;
  displayName: string;
  verificationMethod: string;
  verifiedAt: string;
  status: "active" | "revoked";
};

export type AuditEntry = {
  sequence: number;
  eventType: string;
  actor: string;
  subjectId: string;
  payload: Record<string, unknown>;
  payloadHash: string;
  createdAt: string;
  prevHash: string;
  entryHash: string;
};

export async function sha256HexWeb(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map((x) => canonicalJson(x === undefined ? null : x)).join(",")}]`;
  const rec = v as Record<string, unknown>;
  const keys = Object.keys(rec)
    .filter((k) => rec[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(rec[k])}`).join(",")}}`;
}

export async function computeAuditEntryHash(input: {
  sequence: number;
  eventType: string;
  actor: string;
  subjectId: string;
  payloadHash: string;
  createdAt: string;
  prevHash: string;
}): Promise<string> {
  return sha256HexWeb(
    `${input.sequence}:${input.eventType}:${input.actor}:${input.subjectId}:${input.payloadHash}:${input.createdAt}:${input.prevHash}`,
  );
}

async function appendAuditEntry(
  env: Env,
  eventType: string,
  actor: string,
  subjectId: string,
  payload: Record<string, unknown>,
): Promise<AuditEntry> {
  const head = await env.DB.prepare("SELECT sequence, entry_hash FROM audit_log ORDER BY sequence DESC LIMIT 1").first<{
    sequence: number;
    entry_hash: string;
  }>();
  const sequence = (head?.sequence ?? 0) + 1;
  const prevHash = head?.entry_hash ?? GENESIS_HASH;
  const payloadJson = canonicalJson(payload);
  const payloadHash = await sha256HexWeb(payloadJson);
  const createdAt = new Date().toISOString();
  const entryHash = await computeAuditEntryHash({
    sequence,
    eventType,
    actor,
    subjectId,
    payloadHash,
    createdAt,
    prevHash,
  });
  await env.DB.prepare(
    "INSERT INTO audit_log (sequence, event_type, actor, subject_id, payload_json, payload_hash, created_at, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(sequence, eventType, actor, subjectId, payloadJson, payloadHash, createdAt, prevHash, entryHash)
    .run();
  return {
    sequence,
    eventType,
    actor,
    subjectId,
    payload,
    payloadHash,
    createdAt,
    prevHash,
    entryHash,
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/v1/publishers") {
      return registerPublisher(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v1/publishers") {
      return listPublishers(env);
    }
    const pubMatch = url.pathname.match(/^\/v1\/publishers\/(.+)$/);
    if (request.method === "GET" && pubMatch) {
      return getPublisher(env, decodeURIComponent(pubMatch[1]));
    }
    if (request.method === "POST" && url.pathname === "/v1/artifacts") {
      return publishArtifact(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v1/artifacts") {
      return listArtifacts(env, url);
    }
    const bundleMatch = url.pathname.match(/^\/v1\/artifacts\/([0-9a-f]{64})\/bundle$/);
    if (request.method === "GET" && bundleMatch) {
      return getArtifactBundle(env, bundleMatch[1]);
    }
    const artMatch = url.pathname.match(/^\/v1\/artifacts\/([0-9a-f]{64})$/);
    if (request.method === "GET" && artMatch) {
      return getArtifact(env, artMatch[1]);
    }
    if (request.method === "GET" && url.pathname === "/v1/audit") {
      return listAudit(env);
    }
    if (request.method === "GET" && url.pathname === "/v1/audit/verify") {
      return verifyAuditChain(env);
    }
    return json({ error: "not found" }, 404);
  },
};

async function registerPublisher(request: Request, env: Env): Promise<Response> {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "request body must be valid JSON" }, 400);
  }
  const forge = body?.forge;
  const namespace = typeof body?.namespace === "string" ? body.namespace.trim().toLowerCase() : "";
  const displayName = typeof body?.displayName === "string" ? body.displayName.trim() : "";
  const verificationMethod = typeof body?.verificationMethod === "string" ? body.verificationMethod.trim() : "";
  if ((forge !== "github" && forge !== "gitlab") || !namespace || !displayName || !verificationMethod) {
    return json({ error: "forge ('github'|'gitlab'), namespace, displayName, and verificationMethod are required" }, 400);
  }
  const publisherId = `${forge}.com/${namespace}`;
  const verifiedAt = new Date().toISOString();
  await env.DB.prepare(
    "INSERT OR REPLACE INTO publishers (publisher_id, forge, namespace, display_name, verification_method, verified_at, status) VALUES (?, ?, ?, ?, ?, ?, 'active')",
  )
    .bind(publisherId, forge, namespace, displayName, verificationMethod, verifiedAt)
    .run();

  const audit = await appendAuditEntry(env, "publisher.verified", publisherId, publisherId, {
    publisherId,
    forge,
    namespace,
    displayName,
    verificationMethod,
    verifiedAt,
  });

  return json(
    {
      publisher: {
        publisherId,
        forge,
        namespace,
        displayName,
        verificationMethod,
        verifiedAt,
        status: "active",
      },
      audit,
    },
    201,
  );
}

async function listPublishers(env: Env): Promise<Response> {
  const { results } = await env.DB.prepare(
    "SELECT publisher_id, forge, namespace, display_name, verification_method, verified_at, status FROM publishers ORDER BY publisher_id ASC",
  ).all<Record<string, string>>();
  const publishers = (results ?? []).map((r) => ({
    publisherId: r.publisher_id,
    forge: r.forge,
    namespace: r.namespace,
    displayName: r.display_name,
    verificationMethod: r.verification_method,
    verifiedAt: r.verified_at,
    status: r.status,
  }));
  return json({ publishers }, 200);
}

async function getPublisher(env: Env, publisherId: string): Promise<Response> {
  const r = await env.DB.prepare(
    "SELECT publisher_id, forge, namespace, display_name, verification_method, verified_at, status FROM publishers WHERE publisher_id = ?",
  )
    .bind(publisherId)
    .first<Record<string, string>>();
  if (!r) return json({ error: "publisher not found" }, 404);
  return json(
    {
      publisherId: r.publisher_id,
      forge: r.forge,
      namespace: r.namespace,
      displayName: r.display_name,
      verificationMethod: r.verification_method,
      verifiedAt: r.verified_at,
      status: r.status,
    },
    200,
  );
}

async function publishArtifact(request: Request, env: Env): Promise<Response> {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "request body must be valid JSON" }, 400);
  }
  const artifactDigest = typeof body.artifactDigest === "string" ? body.artifactDigest : "";
  const publisherId = typeof body.publisherId === "string" ? body.publisherId.toLowerCase() : "";
  const name = typeof body.name === "string" ? body.name : "";
  const artifactType = typeof body.artifactType === "string" ? body.artifactType : "";
  const sourceUri = typeof body.sourceUri === "string" ? body.sourceUri : "";
  const sourceCommit = typeof body.sourceCommit === "string" ? body.sourceCommit : "";
  const sourcePath = typeof body.sourcePath === "string" ? body.sourcePath : "";
  const level = typeof body.level === "string" ? body.level : "";
  const band = typeof body.band === "string" ? body.band : null;
  const policyName = typeof body.policyName === "string" ? body.policyName : "";
  const policyDigest = typeof body.policyDigest === "string" ? body.policyDigest : "";
  const certifiedAt = typeof body.certifiedAt === "string" ? body.certifiedAt : new Date().toISOString();
  const bundle = body.bundle;

  if (!HEX64.test(artifactDigest)) {
    return json({ error: "artifactDigest must be 64 lowercase hex characters" }, 400);
  }
  if (!["skill", "mcp-server", "agent-context", "other"].includes(artifactType)) {
    return json({ error: "invalid artifactType" }, 400);
  }
  if (!["gold", "silver", "banded"].includes(level)) {
    return json({ error: "invalid level" }, 400);
  }
  if (band !== null && !["A", "B", "C", "D", "E"].includes(band)) {
    return json({ error: "invalid band" }, 400);
  }
  if (!SHA256_PREF.test(policyDigest)) {
    return json({ error: "policyDigest must be sha256:<64-hex>" }, 400);
  }
  if (!bundle || typeof bundle !== "object") {
    return json({ error: "bundle (Sigstore attestation bundle JSON) is required" }, 400);
  }

  const pub = await env.DB.prepare("SELECT publisher_id, forge, namespace, status FROM publishers WHERE publisher_id = ?")
    .bind(publisherId)
    .first<{ publisher_id: string; forge: string; namespace: string; status: string }>();
  if (!pub || pub.status !== "active") {
    return json({ error: `publisher is not verified and active: ${publisherId}` }, 403);
  }
  const expectedPrefix = `https://${pub.forge}.com/${pub.namespace}/`;
  if (!sourceUri.toLowerCase().startsWith(expectedPrefix)) {
    return json({ error: `sourceUri ${sourceUri} does not belong to verified publisher ${publisherId}` }, 403);
  }

  const bundleR2Key = `bundles/${artifactDigest}.sigstore.json`;
  const bundleStr = JSON.stringify(bundle);
  await env.BLOBS.put(bundleR2Key, bundleStr);

  const publishedAt = new Date().toISOString();
  await env.DB.prepare(
    "INSERT OR REPLACE INTO artifacts (artifact_digest, publisher_id, name, artifact_type, source_uri, source_commit, source_path, level, band, policy_name, policy_digest, bundle_r2_key, certified_at, published_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      artifactDigest,
      publisherId,
      name,
      artifactType,
      sourceUri,
      sourceCommit,
      sourcePath,
      level,
      band,
      policyName,
      policyDigest,
      bundleR2Key,
      certifiedAt,
      publishedAt,
    )
    .run();

  const bundleSha256 = await sha256HexWeb(bundleStr);
  const audit = await appendAuditEntry(env, "artifact.published", publisherId, artifactDigest, {
    artifactDigest,
    publisherId,
    name,
    artifactType,
    sourceUri,
    sourceCommit,
    sourcePath,
    level,
    ...(band ? { band } : {}),
    policyName,
    policyDigest,
    bundleR2Key,
    bundleSha256,
    publishedAt,
  });

  return json(
    {
      artifact: {
        artifactDigest,
        publisherId,
        name,
        artifactType,
        sourceUri,
        sourceCommit,
        sourcePath,
        level,
        ...(band ? { band } : {}),
        policyName,
        policyDigest,
        bundleR2Key,
        certifiedAt,
        publishedAt,
      },
      audit,
    },
    201,
  );
}

async function listArtifacts(env: Env, url: URL): Promise<Response> {
  const publisher = url.searchParams.get("publisher");
  const sql = publisher
    ? "SELECT * FROM artifacts WHERE publisher_id = ? ORDER BY published_at DESC"
    : "SELECT * FROM artifacts ORDER BY published_at DESC";
  const stmt = publisher ? env.DB.prepare(sql).bind(publisher) : env.DB.prepare(sql);
  const { results } = await stmt.all<Record<string, unknown>>();
  return json({ artifacts: results ?? [] }, 200);
}

async function getArtifact(env: Env, digest: string): Promise<Response> {
  const row = await env.DB.prepare("SELECT * FROM artifacts WHERE artifact_digest = ?").bind(digest).first();
  if (!row) return json({ error: "artifact not found" }, 404);
  return json(row, 200);
}

async function getArtifactBundle(env: Env, digest: string): Promise<Response> {
  const row = await env.DB.prepare("SELECT bundle_r2_key FROM artifacts WHERE artifact_digest = ?")
    .bind(digest)
    .first<{ bundle_r2_key: string }>();
  if (!row) return json({ error: "artifact not found" }, 404);
  const obj = await env.BLOBS.get(row.bundle_r2_key);
  if (!obj) return json({ error: "bundle blob missing" }, 500);
  return new Response(await obj.text(), {
    status: 200,
    headers: new Headers({
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
      "access-control-allow-origin": "*",
    }),
  });
}

type AuditRow = {
  sequence: number;
  event_type: string;
  actor: string;
  subject_id: string;
  payload_json: string;
  payload_hash: string;
  created_at: string;
  prev_hash: string;
  entry_hash: string;
};

async function listAudit(env: Env): Promise<Response> {
  const { results } = await env.DB.prepare("SELECT * FROM audit_log ORDER BY sequence ASC").all<AuditRow>();
  const entries = (results ?? []).map((r) => ({
    sequence: r.sequence,
    eventType: r.event_type,
    actor: r.actor,
    subjectId: r.subject_id,
    payload: JSON.parse(r.payload_json),
    payloadHash: r.payload_hash,
    createdAt: r.created_at,
    prevHash: r.prev_hash,
    entryHash: r.entry_hash,
  }));
  return json({ entries }, 200);
}

async function verifyAuditChain(env: Env): Promise<Response> {
  const { results } = await env.DB.prepare("SELECT * FROM audit_log ORDER BY sequence ASC").all<AuditRow>();
  const rows = results ?? [];
  let expectedPrev = GENESIS_HASH;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (r.sequence !== i + 1) {
      return json({ ok: false, error: `sequence gap at index ${i}: got ${r.sequence}` }, 200);
    }
    if (r.prev_hash !== expectedPrev) {
      return json({ ok: false, error: `prev_hash mismatch at sequence ${r.sequence}` }, 200);
    }
    const computedPayloadHash = await sha256HexWeb(r.payload_json);
    if (r.payload_hash !== computedPayloadHash) {
      return json({ ok: false, error: `payload_hash mismatch at sequence ${r.sequence}` }, 200);
    }
    const computedEntryHash = await computeAuditEntryHash({
      sequence: r.sequence,
      eventType: r.event_type,
      actor: r.actor,
      subjectId: r.subject_id,
      payloadHash: r.payload_hash,
      createdAt: r.created_at,
      prevHash: r.prev_hash,
    });
    if (r.entry_hash !== computedEntryHash) {
      return json({ ok: false, error: `entry_hash mismatch at sequence ${r.sequence}` }, 200);
    }
    expectedPrev = r.entry_hash;
  }
  return json({ ok: true, count: rows.length, headHash: expectedPrev }, 200);
}

function json(body: unknown, status: number, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: new Headers({
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
      "access-control-allow-origin": "*",
      ...extra,
    }),
  });
}
