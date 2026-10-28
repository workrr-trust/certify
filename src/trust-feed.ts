// Signed trust policy and revocation feed (spec §7).
//
// This module is the verifier's policy document, separate from src/trust-policy.ts
// on purpose: another change is editing the embedded certifier list in that file,
// and this one only consumes `AcceptedSigner`.
//
// Production signatures are Sigstore bundles (see policy-loader.ts). The ed25519
// path exists so the shared test vectors can check tamper, rollback, and
// revocation offline. A production verify does not pass an ed25519 allow-list,
// so those keys are not trust anchors.

import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { canonicalJson, sha256Hex } from "./digest.js";
import type { AcceptedSigner, Forge } from "./trust-policy.js";

export const SIGNED_BLOB_MEDIA_TYPE = "application/vnd.workrr.signed-blob+json;version=1";
export const TRUST_POLICY_PAYLOAD = "application/vnd.workrr.trust-policy+json";
export const REVOCATION_ENTRY_PAYLOAD = "application/vnd.workrr.revocation-entry+json";
export const REVOCATION_CHECKPOINT_PAYLOAD = "application/vnd.workrr.revocation-checkpoint+json";

export const TRUST_POLICY_SCHEMA = "workrr-trust-policy-v1";
export const REVOCATION_ENTRY_SCHEMA = "workrr-revocation-v1";
export const REVOCATION_CHECKPOINT_SCHEMA = "workrr-revocation-checkpoint-v1";

/** sha256 of "no previous entry". The first revocation's `prev` is this value. */
export const GENESIS_PREV = "0".repeat(64);

/**
 * Highest signed-policy sequence compiled into this build.
 * Stays 0 until a release ships that has verified a signed policy; a fetched
 * sequence lower than this (or lower than a sequence this install has already
 * verified and cached) is a rollback.
 */
export const EMBEDDED_POLICY_SEQUENCE = 0;

/** How long a verified signed policy may be reused without contacting the trust API. */
export const POLICY_CACHE_TTL_MS = 60 * 60 * 1000;

export const DEFAULT_TRUST_API = "https://trust-api.workrr.ai";
export const DEFAULT_REVOCATION_FEED = `${DEFAULT_TRUST_API}/v1/revocations`;

export const OFFLINE_WARNING = "offline: using the embedded trust policy; revocation was not checked";
export const SIGNATURE_INVALID_WARNING = "trust policy signature invalid; using the embedded trust policy";
export const FETCH_FAILED_EMBEDDED_WARNING = "trust policy fetch failed; using the embedded trust policy";
export const FETCH_FAILED_CACHE_WARNING = "trust policy fetch failed; using cached trust policy";
export const REVOCATION_UNCHECKED_WARNING = "revocation was not checked";

export const MAX_SIGNED_BLOB_BYTES = 256 * 1024;
export const MAX_REVOCATION_ENTRIES = 10_000;

const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;
const GIT_SHA = /^[0-9a-f]{40}$/;
const LOG_INDEX = /^(0|[1-9][0-9]*)$/;
const REASON = /^[^\u0000-\u001f\u007f]{1,200}$/;
const MAX_SEQUENCE = Number.MAX_SAFE_INTEGER;

export const TRUST_POLICY_SIGNER: AcceptedSigner = {
  forge: "github",
  issuer: "https://token.actions.githubusercontent.com",
  // Release tags only. A signature from refs/heads/main is not accepted.
  // buildSignerDigests stays empty until the first tagged run of this workflow;
  // pin that commit here once it exists (a moved tag would otherwise still verify).
  subjectAlternativeName:
    String.raw`^https://github\.com/workrr-trust/certify/\.github/workflows/trust-policy\.yml@refs/tags/v\d+\.\d+\.\d+$`,
  buildSignerDigests: [],
};

export const REVOCATION_SIGNER: AcceptedSigner = {
  forge: "github",
  issuer: "https://token.actions.githubusercontent.com",
  subjectAlternativeName:
    String.raw`^https://github\.com/workrr-trust/certify/\.github/workflows/revoke\.yml@refs/tags/v\d+\.\d+\.\d+$`,
  buildSignerDigests: [],
};

export type SignedBlob = {
  mediaType: typeof SIGNED_BLOB_MEDIA_TYPE;
  payloadType: string;
  payload: string;
  signature: {
    algorithm: "ed25519" | "sigstore";
    publicKey?: string;
    sig?: string;
    bundle?: unknown;
  };
};

export type TrustPolicyDocument = {
  schema: typeof TRUST_POLICY_SCHEMA;
  sequence: number;
  issuedAt: string;
  signers: AcceptedSigner[];
  baselinePolicyDigests: Record<string, string>;
  revocationFeed: string;
  revocationWatermark: number;
  revocationHead: string;
};

export type RevocationSubject = { artifactDigest: string } | { logIndex: string };

export type RevocationEntry = {
  schema: typeof REVOCATION_ENTRY_SCHEMA;
  sequence: number;
  subject: RevocationSubject;
  reason: string;
  timestamp: string;
  signer: string;
  prev: string;
};

export type RevocationCheckpoint = {
  schema: typeof REVOCATION_CHECKPOINT_SCHEMA;
  sequence: number;
  head: string;
  timestamp: string;
  signer: string;
};

export type PolicyDecision =
  | { ok: true; sequence: number; schema: typeof TRUST_POLICY_SCHEMA }
  | { ok: false; error: string };

export type RevocationDecision =
  | { ok: true }
  | { ok: false; status: "REVOKED"; reason: string }
  | { ok: false; error: string };

type Opened = { ok: true; payload: string } | { ok: false; error: string };

function fail(error: string): { ok: false; error: string } {
  return { ok: false, error };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function decodeSignedBytes(s: string): Buffer | undefined {
  return decodeStrictBase64(s);
}

function decodeStrictBase64(s: string): Buffer | undefined {
  if (typeof s !== "string" || s.length === 0 || s.length % 4 !== 0) return undefined;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return undefined;
  const buf = Buffer.from(s, "base64");
  if (buf.toString("base64") !== s) return undefined;
  return buf;
}

function sequence(v: unknown, min: number): number | undefined {
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > MAX_SEQUENCE) return undefined;
  return v;
}

export function canonicalPayloadText(bytes: Buffer): Opened {
  if (bytes.length === 0 || bytes.length > MAX_SIGNED_BLOB_BYTES) return fail("malformed signed blob");
  const text = bytes.toString("utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return fail("malformed signed blob");
  }
  if (canonicalJson(parsed) !== text) return fail("not canonical JSON");
  return { ok: true, payload: text };
}

function ed25519PublicKey(raw: Buffer) {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({ key: Buffer.concat([prefix, raw]), format: "der", type: "spki" });
}

/** Verify an ed25519 signed blob. `allowKeys` are standard-base64 raw 32-byte keys. */
export function openEd25519Blob(blob: SignedBlob, allowKeys: readonly string[]): Opened {
  if (blob.signature.algorithm !== "ed25519") return fail("malformed signed blob");
  const pub = blob.signature.publicKey ? decodeStrictBase64(blob.signature.publicKey) : undefined;
  const sig = blob.signature.sig ? decodeStrictBase64(blob.signature.sig) : undefined;
  const payload = decodeStrictBase64(blob.payload);
  if (!pub || pub.length !== 32 || !sig || sig.length !== 64 || !payload) return fail("malformed signed blob");
  if (!keyAllowed(pub, allowKeys)) return fail("signer is not an accepted trust-policy identity");
  let ok = false;
  try {
    ok = cryptoVerify(null, payload, ed25519PublicKey(pub), sig);
  } catch {
    ok = false;
  }
  if (!ok) return fail("signature invalid");
  return canonicalPayloadText(payload);
}

function keyAllowed(pub: Buffer, allowKeys: readonly string[]): boolean {
  let ok = false;
  for (const k of allowKeys) {
    const raw = decodeStrictBase64(k);
    if (raw && raw.length === pub.length && timingEqual(raw, pub)) ok = true;
  }
  return ok;
}

function timingEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function parseSignedBlob(value: unknown): SignedBlob | undefined {
  if (!isRecord(value)) return undefined;
  if (value.mediaType !== SIGNED_BLOB_MEDIA_TYPE) return undefined;
  if (typeof value.payloadType !== "string" || typeof value.payload !== "string") return undefined;
  if (!isRecord(value.signature) || (value.signature.algorithm !== "ed25519" && value.signature.algorithm !== "sigstore")) {
    return undefined;
  }
  return value as SignedBlob;
}

const KNOWN_ROLES = new Set(["publisher", "observer", "witness"]);

function parseSigner(v: unknown): AcceptedSigner | undefined {
  if (!isRecord(v)) return undefined;
  if (v.forge !== "github" && v.forge !== "gitlab") return undefined;
  if (typeof v.issuer !== "string" || !v.issuer.startsWith("https://")) return undefined;
  if (typeof v.subjectAlternativeName !== "string" || v.subjectAlternativeName.length === 0) return undefined;
  if (!Array.isArray(v.buildSignerDigests)) return undefined;
  if (v.role !== undefined && v.role !== "publisher" && v.role !== "observer" && v.role !== "witness") return undefined;
  const digests: string[] = [];
  for (const d of v.buildSignerDigests) {
    if (typeof d !== "string" || !GIT_SHA.test(d)) return undefined;
    digests.push(d);
  }
  return {
    forge: v.forge as Forge,
    issuer: v.issuer,
    subjectAlternativeName: v.subjectAlternativeName,
    buildSignerDigests: digests,
    ...(v.role === "observer" || v.role === "witness" ? { role: v.role } : {}),
  };
}

export function parseTrustPolicy(payload: string): TrustPolicyDocument | { ok: false; error: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    return fail("malformed trust policy");
  }
  if (!isRecord(parsed)) return fail("malformed trust policy");
  const seq = sequence(parsed.sequence, 1);
  const watermark = sequence(parsed.revocationWatermark, 0);
  if (parsed.schema !== TRUST_POLICY_SCHEMA || seq === undefined || watermark === undefined) return fail("malformed trust policy");
  if (typeof parsed.issuedAt !== "string" || !TIMESTAMP.test(parsed.issuedAt)) return fail("malformed trust policy");
  if (!Array.isArray(parsed.signers) || parsed.signers.length === 0) return fail("malformed trust policy");
  const signers: AcceptedSigner[] = [];
  for (const s of parsed.signers) {
    // A signer whose role this release doesn't know is skipped, not trusted: a newer
    // policy can add roles without making older verifiers reject the whole policy.
    if (isRecord(s) && typeof s.role === "string" && !KNOWN_ROLES.has(s.role)) continue;
    const signer = parseSigner(s);
    if (!signer) return fail("malformed trust policy");
    signers.push(signer);
  }
  if (signers.length === 0) return fail("malformed trust policy");
  if (!isRecord(parsed.baselinePolicyDigests)) return fail("malformed trust policy");
  const baselinePolicyDigests: Record<string, string> = {};
  for (const [name, digest] of Object.entries(parsed.baselinePolicyDigests)) {
    if (name.length === 0 || typeof digest !== "string" || !SHA256_DIGEST.test(digest)) return fail("malformed trust policy");
    baselinePolicyDigests[name] = digest;
  }
  if (typeof parsed.revocationFeed !== "string" || !parsed.revocationFeed.startsWith("https://")) return fail("malformed trust policy");
  if (typeof parsed.revocationHead !== "string" || !HEX64.test(parsed.revocationHead)) return fail("malformed trust policy");
  if (watermark === 0 && parsed.revocationHead !== GENESIS_PREV) return fail("malformed trust policy");
  return {
    schema: TRUST_POLICY_SCHEMA,
    sequence: seq,
    issuedAt: parsed.issuedAt,
    signers,
    baselinePolicyDigests,
    revocationFeed: parsed.revocationFeed,
    revocationWatermark: watermark,
    revocationHead: parsed.revocationHead,
  };
}

export function isTrustPolicy(v: TrustPolicyDocument | { ok: false; error: string }): v is TrustPolicyDocument {
  return !("ok" in v);
}

function parseSubject(v: unknown): RevocationSubject | undefined {
  if (!isRecord(v)) return undefined;
  const keys = Object.keys(v);
  if (keys.length !== 1) return undefined;
  if (keys[0] === "artifactDigest" && typeof v.artifactDigest === "string" && HEX64.test(v.artifactDigest)) {
    return { artifactDigest: v.artifactDigest };
  }
  if (keys[0] === "logIndex" && typeof v.logIndex === "string" && LOG_INDEX.test(v.logIndex)) {
    return { logIndex: v.logIndex };
  }
  return undefined;
}

export function parseRevocationEntry(payload: string): RevocationEntry | { ok: false; error: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    return fail("malformed revocation entry");
  }
  if (!isRecord(parsed)) return fail("malformed revocation entry");
  const seq = sequence(parsed.sequence, 1);
  const subject = parseSubject(parsed.subject);
  if (parsed.schema !== REVOCATION_ENTRY_SCHEMA || seq === undefined || !subject) return fail("malformed revocation entry");
  if (typeof parsed.reason !== "string" || !REASON.test(parsed.reason)) return fail("malformed revocation entry");
  if (typeof parsed.timestamp !== "string" || !TIMESTAMP.test(parsed.timestamp)) return fail("malformed revocation entry");
  if (typeof parsed.signer !== "string" || !parsed.signer.startsWith("https://")) return fail("malformed revocation entry");
  if (typeof parsed.prev !== "string" || !HEX64.test(parsed.prev)) return fail("malformed revocation entry");
  return {
    schema: REVOCATION_ENTRY_SCHEMA,
    sequence: seq,
    subject,
    reason: parsed.reason,
    timestamp: parsed.timestamp,
    signer: parsed.signer,
    prev: parsed.prev,
  };
}

export function isRevocationEntry(v: RevocationEntry | { ok: false; error: string }): v is RevocationEntry {
  return !("ok" in v);
}

export function parseCheckpoint(payload: string): RevocationCheckpoint | { ok: false; error: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    return fail("malformed revocation checkpoint");
  }
  if (!isRecord(parsed)) return fail("malformed revocation checkpoint");
  const seq = sequence(parsed.sequence, 0);
  if (parsed.schema !== REVOCATION_CHECKPOINT_SCHEMA || seq === undefined) return fail("malformed revocation checkpoint");
  if (typeof parsed.head !== "string" || !HEX64.test(parsed.head)) return fail("malformed revocation checkpoint");
  if (typeof parsed.timestamp !== "string" || !TIMESTAMP.test(parsed.timestamp)) return fail("malformed revocation checkpoint");
  if (typeof parsed.signer !== "string" || !parsed.signer.startsWith("https://")) return fail("malformed revocation checkpoint");
  return { schema: REVOCATION_CHECKPOINT_SCHEMA, sequence: seq, head: parsed.head, timestamp: parsed.timestamp, signer: parsed.signer };
}

export function isCheckpoint(v: RevocationCheckpoint | { ok: false; error: string }): v is RevocationCheckpoint {
  return !("ok" in v);
}

export function rollbackError(kind: "trust policy" | "revocation checkpoint", got: number, floor: number): string {
  return `ROLLBACK: ${kind} sequence ${got} is older than ${floor}`;
}

/** Verify an ed25519 policy blob and reject a sequence older than `floor`. */
export function decidePolicy(blob: unknown, floorSequence: number, allowKeys: readonly string[]): PolicyDecision {
  const signed = parseSignedBlob(blob);
  if (!signed || signed.payloadType !== TRUST_POLICY_PAYLOAD) return fail("malformed signed blob");
  const opened = openEd25519Blob(signed, allowKeys);
  if (!opened.ok) return opened;
  return decidePolicyPayload(opened.payload, floorSequence);
}

export function decidePolicyPayload(payload: string, floorSequence: number): PolicyDecision {
  const doc = parseTrustPolicy(payload);
  if (!isTrustPolicy(doc)) return doc;
  if (!Number.isInteger(floorSequence) || floorSequence < 0) return fail("malformed trust policy");
  if (doc.sequence < floorSequence) return fail(rollbackError("trust policy", doc.sequence, floorSequence));
  return { ok: true, sequence: doc.sequence, schema: doc.schema };
}

export type DecideRevocationInput = {
  entryBlobs: unknown[];
  checkpointBlob: unknown | null;
  watermark: number;
  revocationHead: string;
  artifactDigest: string;
  logIndexes: readonly string[];
  allowKeys: readonly string[];
  /** Highest checkpoint sequence this client has already verified. 0 if none. */
  cachedCheckpointSequence?: number;
  /** Defaults to the ed25519 test-key opener. Production passes a Sigstore opener. */
  open?: BlobOpener;
};

type OpenEntry = { entry: RevocationEntry; digest: string };

/** Opens one signed blob and returns its canonical payload text. */
export type BlobOpener = (blob: unknown, payloadType: string) => Promise<Opened> | Opened;

function ed25519Opener(allowKeys: readonly string[]): BlobOpener {
  return (blob, payloadType) => {
    const signed = parseSignedBlob(blob);
    if (!signed || signed.payloadType !== payloadType) return fail("malformed signed blob");
    return openEd25519Blob(signed, allowKeys);
  };
}

async function openEntry(blob: unknown, open: BlobOpener): Promise<OpenEntry | { ok: false; error: string }> {
  const opened = await open(blob, REVOCATION_ENTRY_PAYLOAD);
  if (!opened.ok) return opened;
  const entry = parseRevocationEntry(opened.payload);
  if (!isRevocationEntry(entry)) return entry;
  return { entry, digest: sha256Hex(opened.payload) };
}

async function openCheckpoint(blob: unknown, open: BlobOpener): Promise<RevocationCheckpoint | { ok: false; error: string }> {
  const opened = await open(blob, REVOCATION_CHECKPOINT_PAYLOAD);
  if (!opened.ok) return opened;
  return parseCheckpoint(opened.payload);
}

export type VerifiedFeed = { ok: true; entries: RevocationEntry[] } | { ok: false; error: string };

/**
 * Verify a revocation feed snapshot. Entries are individually signed and chained
 * from `revocationHead` (the digest the signed policy committed to) up to a
 * signed checkpoint. Matching an artifact to those entries is `decideRevocation`.
 */
export async function verifyRevocationFeed(input: Omit<DecideRevocationInput, "artifactDigest" | "logIndexes">): Promise<VerifiedFeed> {
  if (!HEX64.test(input.revocationHead)) return fail("malformed revocation entry");
  if (input.entryBlobs.length > MAX_REVOCATION_ENTRIES) return fail("malformed revocation entry");
  const open = input.open ?? ed25519Opener(input.allowKeys);
  const opened: OpenEntry[] = [];
  for (const blob of input.entryBlobs) {
    const entry = await openEntry(blob, open);
    if ("ok" in entry) return entry;
    opened.push(entry);
  }
  opened.sort((a, b) => a.entry.sequence - b.entry.sequence);
  const checkpoint = input.checkpointBlob === null ? null : await openCheckpoint(input.checkpointBlob, open);
  if (checkpoint && "ok" in checkpoint) return checkpoint;

  const cached = input.cachedCheckpointSequence ?? 0;
  if (checkpoint && checkpoint.sequence < cached) {
    return fail(rollbackError("revocation checkpoint", checkpoint.sequence, cached));
  }
  const chainError = checkChain(opened, checkpoint, input.watermark, input.revocationHead);
  if (chainError) return fail(chainError);
  return { ok: true, entries: opened.map((e) => e.entry) };
}

/** Verify the feed, then fail with REVOKED when an entry names this certificate. */
export async function decideRevocation(input: DecideRevocationInput): Promise<RevocationDecision> {
  if (!HEX64.test(input.artifactDigest)) return fail("malformed revocation entry");
  const feed = await verifyRevocationFeed(input);
  if (!feed.ok) return feed;
  const hit = findRevocation(feed.entries, input.artifactDigest, input.logIndexes);
  if (hit) return { ok: false, status: "REVOKED", reason: hit.reason };
  return { ok: true };
}

function checkChain(
  entries: OpenEntry[],
  checkpoint: RevocationCheckpoint | null,
  watermark: number,
  head: string,
): string | undefined {
  if (entries.length === 0) {
    if (watermark === 0 && checkpoint === null) return undefined;
    if (checkpoint === null) return "revocation checkpoint missing";
    if (checkpoint.sequence < watermark) return "revocation feed truncated";
    if (checkpoint.sequence === watermark && checkpoint.head === head) return undefined;
    return "revocation chain invalid";
  }
  if (checkpoint === null) return "revocation checkpoint missing";
  let expectedSeq = watermark + 1;
  let expectedPrev = head;
  for (const { entry, digest } of entries) {
    if (entry.sequence !== expectedSeq || entry.prev !== expectedPrev) return "revocation chain invalid";
    expectedPrev = digest;
    expectedSeq++;
  }
  const last = entries[entries.length - 1];
  if (last.entry.sequence !== checkpoint.sequence || expectedPrev !== checkpoint.head) return "revocation chain invalid";
  if (checkpoint.sequence < watermark) return "revocation feed truncated";
  return undefined;
}

export function findRevocation(
  entries: readonly RevocationEntry[],
  artifactDigest: string,
  logIndexes: readonly string[],
): RevocationEntry | undefined {
  const digest = artifactDigest.toLowerCase();
  return entries.find((e) => {
    if ("artifactDigest" in e.subject && e.subject.artifactDigest === digest) return true;
    if ("logIndex" in e.subject && logIndexes.includes(e.subject.logIndex)) return true;
    return false;
  });
}

export function revocationError(entries: readonly RevocationEntry[], artifactDigest: string, logIndexes: readonly string[]): string | undefined {
  const hit = findRevocation(entries, artifactDigest, logIndexes);
  return hit ? `REVOKED: ${hit.reason}` : undefined;
}

/** True when a signed policy lists baseline digests and this certificate used another. */
export function baselineRejected(policyDigest: string | undefined, allowed: Record<string, string> | undefined): boolean {
  if (!allowed) return false;
  const digests = Object.values(allowed);
  if (digests.length === 0) return false;
  return policyDigest === undefined || !digests.includes(policyDigest);
}

export function offlineFallback(): { source: "embedded"; revocationChecked: false; warning: string } {
  return { source: "embedded", revocationChecked: false, warning: OFFLINE_WARNING };
}

export function entryDigest(payload: string): string {
  return sha256Hex(payload);
}
