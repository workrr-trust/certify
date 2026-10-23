// Hash-only public anchor Worker on D1 for private-tier certificates.
// Accepts and serves only 64-character lowercase hex SHA-256 digests; rejects
// any payload carrying plaintext metadata.

export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  run(): Promise<{ success: boolean }>;
  all<T = Record<string, unknown>>(): Promise<{ results?: T[] }>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
}

export interface Env {
  DB: D1Database;
}

const HEX64 = /^[0-9a-f]{64}$/;
const GENESIS_PREV_HASH = "0".repeat(64);
const ALLOWED_KEYS = new Set(["envelopeHash", "bundleHash", "subjectDigestHash"]);

type AnchorRow = {
  sequence: number;
  envelope_hash: string;
  bundle_hash: string;
  subject_digest_hash: string;
  anchored_at: string;
  prev_chain_hash: string;
  chain_hash: string;
};

export type AnchorReceipt = {
  sequence: number;
  envelopeHash: string;
  bundleHash: string;
  subjectDigestHash: string;
  anchoredAt: string;
  prevChainHash: string;
  chainHash: string;
};

export async function sha256HexWeb(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function computeChainHash(input: {
  sequence: number;
  envelopeHash: string;
  bundleHash: string;
  subjectDigestHash: string;
  anchoredAt: string;
  prevChainHash: string;
}): Promise<string> {
  return sha256HexWeb(
    `${input.sequence}:${input.envelopeHash}:${input.bundleHash}:${input.subjectDigestHash}:${input.anchoredAt}:${input.prevChainHash}`,
  );
}

function toReceipt(row: AnchorRow): AnchorReceipt {
  return {
    sequence: row.sequence,
    envelopeHash: row.envelope_hash,
    bundleHash: row.bundle_hash,
    subjectDigestHash: row.subject_digest_hash,
    anchoredAt: row.anchored_at,
    prevChainHash: row.prev_chain_hash,
    chainHash: row.chain_hash,
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/v1/anchors") {
      return createAnchor(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v1/anchors/head") {
      return getHead(env);
    }
    const match = url.pathname.match(/^\/v1\/anchors\/([^/]+)$/);
    if (request.method === "GET" && match) {
      return getAnchor(env, match[1]);
    }
    if (url.pathname === "/v1/anchors" || url.pathname === "/v1/anchors/head" || match) {
      return json({ error: "method not allowed" }, 405, { allow: "GET, POST" });
    }
    return json({ error: "not found" }, 404);
  },
};

async function createAnchor(request: Request, env: Env): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return json({ error: "request body must be valid JSON" }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return json({ error: "request body must be a JSON object" }, 400);
  }
  const record = body as Record<string, unknown>;
  for (const k of Object.keys(record)) {
    if (!ALLOWED_KEYS.has(k)) {
      return json({ error: `anchor payload must contain only hash fields (unexpected key: ${k})` }, 400);
    }
  }
  const envelopeHash = record.envelopeHash;
  const bundleHash = record.bundleHash;
  const subjectDigestHash = record.subjectDigestHash;
  if (typeof envelopeHash !== "string" || !HEX64.test(envelopeHash)) {
    return json({ error: "envelopeHash must be 64 lowercase hex characters" }, 400);
  }
  if (typeof bundleHash !== "string" || !HEX64.test(bundleHash)) {
    return json({ error: "bundleHash must be 64 lowercase hex characters" }, 400);
  }
  if (typeof subjectDigestHash !== "string" || !HEX64.test(subjectDigestHash)) {
    return json({ error: "subjectDigestHash must be 64 lowercase hex characters" }, 400);
  }

  const existing = await env.DB.prepare(
    "SELECT sequence, envelope_hash, bundle_hash, subject_digest_hash, anchored_at, prev_chain_hash, chain_hash FROM anchors WHERE envelope_hash = ?",
  )
    .bind(envelopeHash)
    .first<AnchorRow>();
  if (existing) {
    return json(toReceipt(existing), 200);
  }

  const head = await env.DB.prepare("SELECT sequence, chain_hash FROM anchors ORDER BY sequence DESC LIMIT 1").first<{
    sequence: number;
    chain_hash: string;
  }>();
  const sequence = (head?.sequence ?? 0) + 1;
  const prevChainHash = head?.chain_hash ?? GENESIS_PREV_HASH;
  const anchoredAt = new Date().toISOString();
  const chainHash = await computeChainHash({
    sequence,
    envelopeHash,
    bundleHash,
    subjectDigestHash,
    anchoredAt,
    prevChainHash,
  });

  await env.DB.prepare(
    "INSERT INTO anchors (sequence, envelope_hash, bundle_hash, subject_digest_hash, anchored_at, prev_chain_hash, chain_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(sequence, envelopeHash, bundleHash, subjectDigestHash, anchoredAt, prevChainHash, chainHash)
    .run();

  return json(
    {
      sequence,
      envelopeHash,
      bundleHash,
      subjectDigestHash,
      anchoredAt,
      prevChainHash,
      chainHash,
    },
    201,
  );
}

async function getHead(env: Env): Promise<Response> {
  const row = await env.DB.prepare(
    "SELECT sequence, envelope_hash, bundle_hash, subject_digest_hash, anchored_at, prev_chain_hash, chain_hash FROM anchors ORDER BY sequence DESC LIMIT 1",
  ).first<AnchorRow>();
  if (!row) return json({ sequence: 0, chainHash: GENESIS_PREV_HASH, anchoredAt: null }, 200);
  return json(
    {
      sequence: row.sequence,
      chainHash: row.chain_hash,
      anchoredAt: row.anchored_at,
    },
    200,
  );
}

async function getAnchor(env: Env, hash: string): Promise<Response> {
  if (!HEX64.test(hash)) {
    return json({ error: "hash must be 64 lowercase hex characters" }, 400);
  }
  const row = await env.DB.prepare(
    "SELECT sequence, envelope_hash, bundle_hash, subject_digest_hash, anchored_at, prev_chain_hash, chain_hash FROM anchors WHERE envelope_hash = ? OR bundle_hash = ? ORDER BY sequence ASC LIMIT 1",
  )
    .bind(hash, hash)
    .first<AnchorRow>();
  if (!row) return json({ error: "anchor not found" }, 404);
  return json(toReceipt(row), 200, { "cache-control": "public, max-age=3600, immutable" });
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
