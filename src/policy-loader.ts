// Fetch, verify, and cache the signed trust policy.
//
// Kept apart from src/trust-policy.ts and from the certificate matcher in
// src/verify.ts so a change to the embedded certifier list rebases as an import,
// not a rewrite of this file. Signature checks call the existing `matchSigner`.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { verify as sigstoreVerify } from "sigstore";
import { BASELINE_POLICY } from "./checks/policy.js";
import { jsonDigest } from "./digest.js";
import {
  DEFAULT_REVOCATION_FEED,
  DEFAULT_TRUST_API,
  EMBEDDED_POLICY_SEQUENCE,
  FETCH_FAILED_CACHE_WARNING,
  FETCH_FAILED_EMBEDDED_WARNING,
  GENESIS_PREV,
  OFFLINE_WARNING,
  POLICY_CACHE_TTL_MS,
  REVOCATION_CHECKPOINT_PAYLOAD,
  REVOCATION_ENTRY_PAYLOAD,
  REVOCATION_SIGNER,
  REVOCATION_UNCHECKED_WARNING,
  SIGNATURE_INVALID_WARNING,
  TRUST_POLICY_PAYLOAD,
  TRUST_POLICY_SCHEMA,
  TRUST_POLICY_SIGNER,
  canonicalPayloadText,
  decodeSignedBytes,
  decidePolicyPayload,
  openEd25519Blob,
  parseSignedBlob,
  parseTrustPolicy,
  verifyRevocationFeed,
  isTrustPolicy,
  type RevocationEntry,
  type SignedBlob,
  type TrustPolicyDocument,
} from "./trust-feed.js";
import { DEFAULT_TRUST_POLICY, type TrustPolicy } from "./trust-policy.js";
import { matchSigner } from "./verify.js";
import { VERSION } from "./version.js";

const LOCAL_FILE_WARNING = "local trust policy file; signature was not checked";

export type LoadedPolicy = {
  policy: TrustPolicy;
  source: "embedded" | "signed" | "cache" | "file";
  warnings: string[];
  revocations: RevocationEntry[];
  revocationChecked: boolean;
  baselinePolicyDigests?: Record<string, string>;
  status: "ok" | "rollback" | "rejected";
  error?: string;
  document?: TrustPolicyDocument;
};

export type LoadOptions = {
  offline?: boolean;
  /** `--trust-policy`. A signed blob is verified; a legacy `{version, signers}` file is a local override. */
  file?: string;
  cachePath?: string;
  now?: number;
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  /** Ed25519 keys accepted in addition to the pinned Sigstore identity. Tests only. */
  allowEd25519Keys?: readonly string[];
  floorSequence?: number;
  trustedRoot?: string;
};

type CacheRecord = {
  fetchedAt: number;
  checkpointSequence: number;
  document: TrustPolicyDocument;
  blob: SignedBlob;
};

export function defaultCachePath(): string {
  // Same directory Go's os.UserCacheDir uses, then workrr/trust-policy.json.
  let base: string;
  if (process.platform === "darwin") base = join(homedir(), "Library", "Caches");
  else if (process.platform === "win32") base = process.env.LOCALAPPDATA || join(homedir(), "AppData", "Local");
  else base = process.env.XDG_CACHE_HOME || join(homedir(), ".cache");
  return join(base, "workrr", "trust-policy.json");
}

export function embeddedPolicyDocument(): TrustPolicyDocument {
  return {
    schema: TRUST_POLICY_SCHEMA,
    sequence: EMBEDDED_POLICY_SEQUENCE,
    issuedAt: "1970-01-01T00:00:00Z",
    signers: DEFAULT_TRUST_POLICY.signers,
    baselinePolicyDigests: { [BASELINE_POLICY.name]: jsonDigest(BASELINE_POLICY) },
    revocationFeed: DEFAULT_REVOCATION_FEED,
    revocationWatermark: 0,
    revocationHead: GENESIS_PREV,
  };
}

function embedded(warnings: string[]): LoadedPolicy {
  return {
    policy: DEFAULT_TRUST_POLICY,
    source: "embedded",
    warnings,
    revocations: [],
    revocationChecked: false,
    status: "ok",
  };
}

function fromDocument(doc: TrustPolicyDocument, source: LoadedPolicy["source"], warnings: string[]): LoadedPolicy {
  return {
    policy: { version: doc.schema, signers: doc.signers },
    source,
    warnings,
    revocations: [],
    revocationChecked: false,
    baselinePolicyDigests: doc.baselinePolicyDigests,
    status: "ok",
    document: doc,
  };
}

function trustApiBase(opts: LoadOptions): string {
  const raw = opts.baseUrl ?? process.env.WORKRR_TRUST_API ?? DEFAULT_TRUST_API;
  return raw.replace(/\/$/, "");
}

type SigstoreBundle = Parameters<typeof sigstoreVerify>[0];
type SignerIdentity = Parameters<typeof matchSigner>[1];

async function openBlob(blob: SignedBlob, opts: LoadOptions): Promise<{ ok: true; payload: string } | { ok: false; error: string }> {
  if (blob.signature.algorithm === "ed25519") return openEd25519Blob(blob, opts.allowEd25519Keys ?? []);
  if (blob.signature.algorithm !== "sigstore" || blob.signature.bundle === undefined) return { ok: false, error: "malformed signed blob" };
  const bytes = decodeSignedBytes(blob.payload);
  if (!bytes) return { ok: false, error: "malformed signed blob" };
  const expected = blob.payloadType === TRUST_POLICY_PAYLOAD ? TRUST_POLICY_SIGNER : REVOCATION_SIGNER;
  let san: string | undefined;
  try {
    const signer = await sigstoreVerify(blob.signature.bundle as SigstoreBundle, bytes, opts.trustedRoot ? { tufRootPath: opts.trustedRoot } : undefined);
    san = signer.identity?.subjectAlternativeName;
    const accepted = matchSigner({ version: "workrr-trust-feed-signer", signers: [expected] }, (signer.identity ?? {}) as SignerIdentity);
    if (!accepted) return { ok: false, error: "signer is not an accepted trust-policy identity" };
  } catch {
    return { ok: false, error: "signature invalid" };
  }
  const text = canonicalPayloadText(bytes);
  if (!text.ok) return text;
  // The signer field on a revocation document is the certificate SAN, not a hint.
  if (blob.payloadType === REVOCATION_ENTRY_PAYLOAD || blob.payloadType === REVOCATION_CHECKPOINT_PAYLOAD) {
    let body: { signer?: unknown };
    try {
      body = JSON.parse(text.payload) as { signer?: unknown };
    } catch {
      return { ok: false, error: "malformed signed blob" };
    }
    if (typeof body.signer !== "string" || body.signer !== san) return { ok: false, error: "signer is not an accepted trust-policy identity" };
  }
  return text;
}

async function readCache(path: string | undefined, opts: LoadOptions): Promise<CacheRecord | undefined> {
  if (!path) return undefined;
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object") return undefined;
  const rec = parsed as { fetchedAt?: unknown; checkpointSequence?: unknown; blob?: unknown };
  if (typeof rec.fetchedAt !== "number" || typeof rec.checkpointSequence !== "number") return undefined;
  const blob = parseSignedBlob(rec.blob);
  if (!blob) return undefined;
  const opened = await openBlob(blob, opts);
  if (!opened.ok) return undefined;
  const doc = parseTrustPolicy(opened.payload);
  if (!isTrustPolicy(doc)) return undefined;
  return { fetchedAt: rec.fetchedAt, checkpointSequence: rec.checkpointSequence, document: doc, blob };
}

async function writeCache(path: string, record: CacheRecord): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  await writeFile(
    tmp,
    JSON.stringify({ fetchedAt: record.fetchedAt, checkpointSequence: record.checkpointSequence, blob: record.blob }) + "\n",
  );
  await rename(tmp, path);
}

async function fetchJSON(url: string, fetchImpl: typeof fetch): Promise<{ ok: true; body: unknown } | { ok: false }> {
  try {
    const res = await fetchImpl(url, {
      headers: { accept: "application/json", "user-agent": `workrr-trust/${VERSION}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return { ok: false };
    return { ok: true, body: await res.json() };
  } catch {
    return { ok: false };
  }
}

function isLegacyPolicy(v: unknown): v is TrustPolicy {
  return !!v && typeof v === "object" && !Array.isArray(v) && typeof (v as TrustPolicy).version === "string" && Array.isArray((v as TrustPolicy).signers);
}

async function loadFile(opts: LoadOptions): Promise<LoadedPolicy> {
  const parsed = JSON.parse(await readFile(opts.file!, "utf8")) as unknown;
  const blob = parseSignedBlob(parsed);
  if (blob) {
    const opened = await openBlob(blob, opts);
    if (!opened.ok) return { ...embedded([]), status: "rejected", error: opened.error, warnings: [opened.error] };
    const floor = opts.floorSequence ?? EMBEDDED_POLICY_SEQUENCE;
    const decision = decidePolicyPayload(opened.payload, floor);
    if (!decision.ok) {
      const status = decision.error.startsWith("ROLLBACK:") ? "rollback" : "rejected";
      return { ...embedded([]), status, error: decision.error, warnings: [decision.error] };
    }
    const doc = parseTrustPolicy(opened.payload);
    if (!isTrustPolicy(doc)) return { ...embedded([]), status: "rejected", error: doc.error, warnings: [doc.error] };
    const loaded = fromDocument(doc, "file", []);
    if (opts.offline) {
      loaded.warnings.push(OFFLINE_WARNING);
      return loaded;
    }
    return attachRevocations(loaded, opts, 0);
  }
  if (!isLegacyPolicy(parsed)) return { ...embedded([]), status: "rejected", error: "malformed trust policy", warnings: ["malformed trust policy"] };
  const loaded: LoadedPolicy = {
    policy: parsed,
    source: "file",
    warnings: [LOCAL_FILE_WARNING],
    revocations: [],
    revocationChecked: false,
    status: "ok",
  };
  if (opts.offline) {
    loaded.warnings.push(OFFLINE_WARNING);
    return loaded;
  }
  return attachRevocations(loaded, opts, 0);
}

export async function loadTrustPolicy(opts: LoadOptions = {}): Promise<LoadedPolicy> {
  const now = opts.now ?? Date.now();
  const cachePath = opts.cachePath;
  if (opts.file) return loadFile(opts);
  if (opts.offline) return embedded([OFFLINE_WARNING]);

  const cache = await readCache(cachePath, opts);
  const floor = Math.max(opts.floorSequence ?? EMBEDDED_POLICY_SEQUENCE, cache?.document.sequence ?? 0);
  const fetchImpl = opts.fetchImpl ?? fetch;
  let loaded: LoadedPolicy;
  let checkpointSequence = cache?.checkpointSequence ?? 0;

  if (cache && now - cache.fetchedAt < POLICY_CACHE_TTL_MS && cache.document.sequence >= (opts.floorSequence ?? EMBEDDED_POLICY_SEQUENCE)) {
    loaded = fromDocument(cache.document, "cache", []);
  } else {
    const response = await fetchJSON(`${trustApiBase(opts)}/v1/policy`, fetchImpl);
    if (!response.ok) {
      if (cache) loaded = fromDocument(cache.document, "cache", [FETCH_FAILED_CACHE_WARNING]);
      else loaded = embedded([FETCH_FAILED_EMBEDDED_WARNING]);
    } else {
      const blob = parseSignedBlob(response.body);
      if (!blob) loaded = embedded([SIGNATURE_INVALID_WARNING]);
      else {
        const opened = await openBlob(blob, opts);
        if (!opened.ok) {
          if (opened.error.startsWith("ROLLBACK:")) {
            return { ...embedded([]), status: "rollback", error: opened.error, warnings: [opened.error] };
          }
          loaded = embedded([opened.error === "signature invalid" || opened.error === "signer is not an accepted trust-policy identity" ? SIGNATURE_INVALID_WARNING : opened.error]);
        } else {
          const decision = decidePolicyPayload(opened.payload, floor);
          if (!decision.ok) {
            const status = decision.error.startsWith("ROLLBACK:") ? "rollback" : "rejected";
            return { ...embedded([]), status, error: decision.error, warnings: [decision.error] };
          }
          const doc = parseTrustPolicy(opened.payload);
          if (!isTrustPolicy(doc)) return { ...embedded([]), status: "rejected", error: doc.error, warnings: [doc.error] };
          loaded = fromDocument(doc, "signed", []);
          if (cachePath) {
            const record = { fetchedAt: now, checkpointSequence, document: doc, blob };
            await writeCache(cachePath, record);
          }
        }
      }
    }
  }

  if (loaded.status !== "ok") return loaded;
  const withFeed = await attachRevocations(loaded, opts, checkpointSequence);
  if (withFeed.status === "ok" && withFeed.revocationChecked && cachePath && withFeed.document) {
    const highest = withFeed.revocations.reduce((n, e) => Math.max(n, e.sequence), checkpointSequence);
    if (highest !== checkpointSequence) {
      const blob = cache?.blob;
      if (blob) await writeCache(cachePath, { fetchedAt: cache?.fetchedAt ?? now, checkpointSequence: highest, document: withFeed.document, blob });
    }
  }
  return withFeed;
}

async function attachRevocations(loaded: LoadedPolicy, opts: LoadOptions, cachedCheckpointSequence: number): Promise<LoadedPolicy> {
  const doc = loaded.document ?? embeddedPolicyDocument();
  const feed = (loaded.document?.revocationFeed ?? DEFAULT_REVOCATION_FEED).replace(/\/$/, "");
  const fetchImpl = opts.fetchImpl ?? fetch;
  const response = await fetchJSON(`${feed}/since/${doc.revocationWatermark}`, fetchImpl);
  if (!response.ok) {
    return { ...loaded, warnings: [...loaded.warnings, REVOCATION_UNCHECKED_WARNING] };
  }
  const body = response.body as { checkpoint?: unknown; entries?: unknown };
  if (!body || typeof body !== "object" || !Array.isArray(body.entries)) {
    return { ...loaded, status: "rejected", error: "malformed revocation feed", warnings: [...loaded.warnings, "malformed revocation feed"] };
  }
  const checkpoint = body.checkpoint === undefined ? null : body.checkpoint;
  if (checkpoint !== null && (typeof checkpoint !== "object" || Array.isArray(checkpoint))) {
    return { ...loaded, status: "rejected", error: "malformed revocation feed", warnings: [...loaded.warnings, "malformed revocation feed"] };
  }
  const feedResult = await verifyRevocationFeed({
    entryBlobs: body.entries,
    checkpointBlob: checkpoint,
    watermark: doc.revocationWatermark,
    revocationHead: doc.revocationHead,
    allowKeys: opts.allowEd25519Keys ?? [],
    cachedCheckpointSequence,
    open: (blob, payloadType) => {
      const signed = parseSignedBlob(blob);
      if (!signed || signed.payloadType !== payloadType) return { ok: false, error: "malformed signed blob" };
      return openBlob(signed, opts);
    },
  });
  if (!feedResult.ok) {
    const status = feedResult.error.startsWith("ROLLBACK:") ? "rollback" : "rejected";
    return { ...loaded, status, error: feedResult.error, warnings: [...loaded.warnings, feedResult.error], revocationChecked: false, revocations: [] };
  }
  return { ...loaded, revocations: feedResult.entries, revocationChecked: true };
}

