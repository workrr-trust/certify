// Verify certificates (spec §6): digest → predicate type → Sigstore bundle
// (chain, signature, Rekor inclusion) → signer identity against the trust policy.
import { readFile } from "node:fs/promises";
import { verify as sigstoreVerify } from "sigstore";
import { PREDICATE_TYPE, type Statement, type TrustBand } from "./certify.js";
import { BASELINE_POLICY, BASELINE_POLICY_NAME } from "./checks/policy.js";
import { normalizeRepoUri } from "./checks/provenance.js";
import { canonicalJson, digestArtifact, jsonDigest } from "./digest.js";
import { baselineRejected, OFFLINE_WARNING, revocationError, type RevocationEntry } from "./trust-feed.js";
import { DEFAULT_TRUST_POLICY, type AcceptedSigner, type Forge, type TrustPolicy } from "./trust-policy.js";

const OID_BUILD_SIGNER_DIGEST = "1.3.6.1.4.1.57264.1.10";
const OID_SOURCE_REPOSITORY_URI = "1.3.6.1.4.1.57264.1.12";
const OID_SOURCE_REPOSITORY_DIGEST = "1.3.6.1.4.1.57264.1.13";

export type BundleResult = {
  bundlePath: string;
  ok: boolean;
  error?: string;
  forge?: Forge;
  signerIdentity?: string;
  statement?: Statement;
  /** Rekor log indexes carried in the bundle. Revocation entries name one of these. */
  logIndexes?: string[];
};

export type PolicyStatus = "baseline" | "custom" | "reject";
export type VerifyStatus = "verified" | "REVOKED" | "rejected";

export type VerifyResult = {
  ok: boolean;
  status: VerifyStatus;
  level?: "gold" | "silver" | "banded";
  band?: TrustBand;
  artifactDigest: string;
  source?: string;
  policyName?: string;
  policyDigest?: string;
  policyStatus?: PolicyStatus;
  bundles: BundleResult[];
  notes: string[];
};

export type VerificationGate = {
  ok: boolean;
  level?: VerifyResult["level"];
  band?: TrustBand;
  source?: string;
  policyName?: string;
  policyDigest?: string;
  policyStatus?: PolicyStatus;
  notes: string[];
};

export type VerifyOptions = {
  /** When set, revocation entries are enforced. Omit to keep the v0.1 note. */
  revocations?: readonly RevocationEntry[];
  offline?: boolean;
  /** Digests from a signed trust policy. Enforced only when provided. */
  baselinePolicyDigests?: Record<string, string>;
  /** Publisher repository. A mismatch fails closed and is not a baseline result. */
  expectedSource?: string;
};

type SerializedBundle = Parameters<typeof sigstoreVerify>[0];
type Oid = { oid?: { id?: number[] }; value: Buffer };

// Fulcio v2 extensions hold a DER UTF8String.
function derUtf8(value: Buffer): string {
  if (value[0] !== 0x0c) return value.toString("utf8");
  let len = value[1];
  let off = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | value[2 + i];
    off = 2 + n;
  }
  return value.subarray(off, off + len).toString("utf8");
}

type Identity = { subjectAlternativeName?: string; extensions?: { issuer?: string }; oids?: Oid[] };

export type DescribedSigner = {
  san: string;
  issuer?: string;
  buildSignerDigest?: string;
  sourceRepositoryURI?: string;
  sourceRepositoryDigest?: string;
};

export function describeSigner(identity: Identity): DescribedSigner {
  const findOid = (oid: string): string | undefined => {
    const found = identity.oids?.find((o) => o.oid?.id?.join(".") === oid);
    return found ? derUtf8(found.value) : undefined;
  };
  return {
    san: identity.subjectAlternativeName ?? "",
    issuer: identity.extensions?.issuer,
    buildSignerDigest: findOid(OID_BUILD_SIGNER_DIGEST),
    sourceRepositoryURI: findOid(OID_SOURCE_REPOSITORY_URI),
    sourceRepositoryDigest: findOid(OID_SOURCE_REPOSITORY_DIGEST),
  };
}

// Derive the certified level from the signed checks rather than trusting predicate.level alone.
export function deriveStatementLevel(statement: Statement | undefined): "silver" | "banded" | undefined {
  const p = statement?.predicate;
  const c = p?.checks;
  if (!p || !c) return undefined;
  if (c.provenance?.result !== "pass" || c.policy?.result !== "pass" || c.scan?.result !== "pass") {
    return undefined;
  }
  if (c.tests?.result === "pass") return "silver";
  if (c.tests?.result === "none") return "banded";
  return undefined;
}

// Compare the predicate's source URI and commit against the signing certificate's
// Fulcio SourceRepositoryURI (.1.12) and SourceRepositoryDigest (.1.13) when present.
export function checkCertificateSourceAndCommit(
  statement: Statement | undefined,
  signer: { sourceRepositoryURI?: string; sourceRepositoryDigest?: string },
): string | undefined {
  const src = statement?.predicate?.source;
  if (!src) return "statement has no source field";
  if (signer.sourceRepositoryURI && canonicalSource(src.uri) !== canonicalSource(signer.sourceRepositoryURI)) {
    return `certificate source URI mismatch: predicate claims ${src.uri}, Fulcio certificate recorded ${signer.sourceRepositoryURI}`;
  }
  if (signer.sourceRepositoryDigest && src.commit.toLowerCase() !== signer.sourceRepositoryDigest.toLowerCase()) {
    return `certificate source commit mismatch: predicate claims ${src.commit}, Fulcio certificate recorded ${signer.sourceRepositoryDigest}`;
  }
  return undefined;
}

export function matchDescribedSigner(
  policy: TrustPolicy,
  signer: { san: string; issuer?: string; buildSignerDigest?: string },
): AcceptedSigner | undefined {
  return policy.signers.find(
    (s) =>
      s.issuer === signer.issuer &&
      new RegExp(s.subjectAlternativeName).test(signer.san) &&
      (s.buildSignerDigests.length === 0 ||
        (signer.buildSignerDigest !== undefined && s.buildSignerDigests.includes(signer.buildSignerDigest))),
  );
}

export function matchSigner(policy: TrustPolicy, identity: Identity): AcceptedSigner | undefined {
  return matchDescribedSigner(policy, describeSigner(identity));
}

export function baselinePolicyDigest(): string {
  return jsonDigest(BASELINE_POLICY);
}

export type PolicyAssessment = {
  status: PolicyStatus;
  policyName?: string;
  policyDigest?: string;
  reason?: string;
};

// baseline: name and digest are the known baseline.
// reject: the reserved baseline name is reused with any other digest, or the
// baseline digest is paired with a different name.
// custom: any other digest. Callers must not report a baseline level.
export function assessPolicy(policyName?: string, policyDigest?: string): PolicyAssessment {
  const baselineDigest = baselinePolicyDigest();
  if (policyDigest === baselineDigest && policyName === BASELINE_POLICY_NAME) {
    return { status: "baseline", policyName, policyDigest };
  }
  if (policyName === BASELINE_POLICY_NAME) {
    return {
      status: "reject",
      policyName,
      policyDigest,
      reason: `policy name "${BASELINE_POLICY_NAME}" is reserved; digest is not the baseline`,
    };
  }
  if (policyDigest === baselineDigest) {
    return {
      status: "reject",
      policyName,
      policyDigest,
      reason: `policy digest is the baseline but policy name is ${policyName ? `"${policyName}"` : "missing"}`,
    };
  }
  return { status: "custom", policyName, policyDigest };
}

export function canonicalSource(uri: string): string {
  return normalizeRepoUri(uri.trim()).replace(/\/+$/, "").toLowerCase();
}

function publisherKey(uri: string): string {
  const c = canonicalSource(uri);
  const m = /^https:\/\/(?:github\.com|gitlab\.com)\/([^/]+\/[^/]+)$/.exec(c);
  return m ? m[1] : c;
}

// expected may be a full repository URL or an owner/repo (or host/owner/repo) shorthand.
export function sourceMatches(certificateURI: string, expected: string): boolean {
  const got = canonicalSource(certificateURI);
  const want = canonicalSource(expected);
  if (got === want) return true;
  const flag = expected.trim().replace(/\.git$/, "").replace(/\/+$/, "").toLowerCase();
  if (flag.includes("://") || flag.startsWith("git@")) return false;
  if (got === `https://${flag}`) return true;
  return got.replace(/^https?:\/\/[^/]+\//, "") === flag;
}

export function evaluateGoldBundles(
  valid: BundleResult[],
  notes: string[],
): { level?: "gold" | "silver" | "banded"; notes: string[] } {
  const outNotes = [...notes];
  const withLevels = valid
    .map((b) => ({ bundle: b, level: deriveStatementLevel(b.statement) }))
    .filter((x): x is { bundle: BundleResult; level: "silver" | "banded" } => x.level !== undefined);
  if (withLevels.length === 0) return { notes: outNotes };

  const silver = withLevels.filter((x) => x.level === "silver").map((x) => x.bundle);
  const forges = new Set(silver.map((b) => b.forge));
  let level: VerifyResult["level"] = silver.length > 0 ? "silver" : "banded";
  if (forges.size >= 2) {
    const [a, b] = [silver.find((x) => x.forge === "github"), silver.find((x) => x.forge === "gitlab")];
    if (a?.statement && b?.statement) {
      const sameCommit =
        a.statement.predicate.source.commit.toLowerCase() === b.statement.predicate.source.commit.toLowerCase() &&
        a.statement.predicate.source.path === b.statement.predicate.source.path;
      const sameChecks = canonicalJson(a.statement.predicate.checks) === canonicalJson(b.statement.predicate.checks);
      if (!sameCommit) {
        outNotes.push("two forges signed, but their source commits differ — not Gold");
      } else if (!sameChecks) {
        outNotes.push("two forges signed, but their check results differ — not Gold");
      } else {
        level = "gold";
      }
    }
  }
  return { level, notes: outNotes };
}

export function verificationHeadline(r: { ok: boolean; level?: string; band?: TrustBand; policyStatus?: PolicyStatus; notes: string[] }): string {
  if (r.ok && r.level) {
    if (r.level === "banded" && r.band) return `VERIFIED · level ${r.level} · band ${r.band}`;
    return `VERIFIED · level ${r.level}`;
  }
  const hard = r.notes.some((n) => n.startsWith("source mismatch:") || n.startsWith("publishers differ:"));
  if (r.policyStatus === "custom" && !hard) return "custom policy, not baseline";
  return "NOT VERIFIED";
}

function worstStatus(statuses: PolicyStatus[]): PolicyStatus {
  if (statuses.includes("reject")) return "reject";
  if (statuses.includes("custom")) return "custom";
  return "baseline";
}

// applyVerificationGates turns a cryptographically valid level into the result
// a caller may print. A non-baseline policy never keeps silver, gold, or banded.
export function applyVerificationGates(input: {
  level?: VerifyResult["level"];
  band?: TrustBand;
  policies: { policyName?: string; policyDigest?: string }[];
  sources: string[];
  expectedSource?: string;
  notes: string[];
}): VerificationGate {
  const notes = [...input.notes];
  const assessments = input.policies.map((p) => assessPolicy(p.policyName, p.policyDigest));
  const status = assessments.length ? worstStatus(assessments.map((a) => a.status)) : undefined;
  const first = assessments[0];
  const uniqueSources = [...new Set(input.sources.filter((s) => s))];
  const uniquePublishers = [...new Set(uniqueSources.map((s) => publisherKey(s)))];
  const source = uniquePublishers.length === 1 ? uniqueSources[0] : undefined;
  const digests = [...new Set(assessments.map((a) => a.policyDigest).filter((d): d is string => !!d))];
  if (digests.length > 1) notes.push(`policy digests differ: ${digests.join(", ")}`);
  if (uniquePublishers.length > 1) notes.push(`publishers differ: ${uniqueSources.join(", ")}`);
  if (input.expectedSource) {
    const urls = input.sources.length ? input.sources : [""];
    const crossForgeSamePublisher =
      uniquePublishers.length === 1 && uniqueSources.length > 1 && urls.some((u) => sourceMatches(u, input.expectedSource!));
    if (!crossForgeSamePublisher) {
      for (const uri of urls) {
        if (!sourceMatches(uri, input.expectedSource)) {
          notes.push(`source mismatch: certificate is for ${uri || "(none)"}, --source is ${input.expectedSource}`);
        }
      }
    }
  }
  const reject = assessments.find((a) => a.status === "reject");
  if (reject?.reason) notes.push(reject.reason);
  const hard = notes.some((n) => n.startsWith("source mismatch:") || n.startsWith("publishers differ:") || n.startsWith("policy digests differ:"));
  const base = {
    source,
    policyName: first?.policyName,
    policyDigest: first?.policyDigest,
    policyStatus: status,
    notes,
  };
  if (status === "baseline" && !hard) {
    return {
      ok: true,
      level: input.level,
      ...(input.level === "banded" && input.band ? { band: input.band } : {}),
      ...base,
    };
  }
  return { ok: false, ...base };
}

export function bundleLogIndexes(bundle: unknown): string[] {
  const entries = (bundle as { verificationMaterial?: { tlogEntries?: { logIndex?: unknown }[] } })?.verificationMaterial?.tlogEntries;
  if (!Array.isArray(entries)) return [];
  const out: string[] = [];
  for (const entry of entries) {
    const value = entry?.logIndex;
    if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) out.push(value);
  }
  return out;
}

export async function verifyBundle(bundlePath: string, artifactDigest: string, policy: TrustPolicy): Promise<BundleResult> {
  const fail = (error: string, extra: Partial<BundleResult> = {}): BundleResult => ({ bundlePath, ok: false, error, ...extra });
  let bundle: SerializedBundle & { dsseEnvelope?: { payload: string; payloadType: string }; verificationMaterial?: unknown };
  let logIndexes: string[] = [];
  try {
    bundle = JSON.parse(await readFile(bundlePath, "utf8"));
    logIndexes = bundleLogIndexes(bundle);
  } catch (e) {
    return fail(`cannot read bundle: ${(e as Error).message}`);
  }
  const withLog = (result: BundleResult): BundleResult => (logIndexes.length ? { ...result, logIndexes } : result);
  if (!bundle.dsseEnvelope) return withLog(fail("bundle has no DSSE envelope (not an attestation)"));

  let statement: Statement;
  try {
    statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  } catch {
    return withLog(fail("attestation payload is not valid JSON"));
  }
  if (statement.predicateType !== PREDICATE_TYPE) {
    return withLog(fail(`unsupported predicate type: ${statement.predicateType}`, { statement }));
  }
  if (!statement.subject?.some((s) => s.digest?.sha256 === artifactDigest)) {
    return withLog(fail("certificate is for a different artifact (digest mismatch)", { statement }));
  }

  let signer;
  try {
    // Checks certificate chain to the Sigstore root, signature, and Rekor inclusion.
    signer = await sigstoreVerify(bundle);
  } catch (e) {
    return withLog(fail(`signature verification failed: ${(e as Error).message}`, { statement }));
  }
  const identity = (signer.identity ?? {}) as Identity;
  const described = describeSigner(identity);
  const accepted = matchDescribedSigner(policy, described);
  if (!accepted) {
    return withLog(fail(`signer is not an accepted workrr certifier: ${identity.subjectAlternativeName ?? "unknown"}`, {
      statement,
      signerIdentity: identity.subjectAlternativeName,
    }));
  }
  const sourceMismatch = checkCertificateSourceAndCommit(statement, described);
  if (sourceMismatch) {
    return withLog(fail(sourceMismatch, {
      statement,
      forge: accepted.forge,
      signerIdentity: identity.subjectAlternativeName,
    }));
  }
  const derivedLevel = deriveStatementLevel(statement);
  if (!derivedLevel) {
    return withLog(fail("certificate checks did not pass", {
      statement,
      forge: accepted.forge,
      signerIdentity: identity.subjectAlternativeName,
    }));
  }
  if (statement.predicate.level === "silver" && derivedLevel !== "silver") {
    return withLog(fail("certificate claims level silver, but signed checks do not support silver", {
      statement,
      forge: accepted.forge,
      signerIdentity: identity.subjectAlternativeName,
    }));
  }
  return withLog({ bundlePath, ok: true, forge: accepted.forge, signerIdentity: identity.subjectAlternativeName, statement });
}

function policyOf(statement: Statement | undefined): { policyName?: string; policyDigest?: string } {
  const policy = statement?.predicate.checks.policy;
  return { policyName: policy?.policyName, policyDigest: policy?.policyDigest };
}

export async function verifyArtifact(
  path: string,
  bundlePaths: string[],
  policy: TrustPolicy = DEFAULT_TRUST_POLICY,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const { sha256: artifactDigest } = await digestArtifact(path);
  const bundles = await Promise.all(bundlePaths.map((b) => verifyBundle(b, artifactDigest, policy)));
  const checkRevocation = options.revocations !== undefined && !options.offline;
  for (const bundle of bundles) {
    if (!bundle.ok) continue;
    if (checkRevocation) {
      const revoked = revocationError(options.revocations ?? [], artifactDigest, bundle.logIndexes ?? []);
      if (revoked) {
        bundle.ok = false;
        bundle.error = revoked;
        continue;
      }
    }
    if (baselineRejected(policyOf(bundle.statement).policyDigest, options.baselinePolicyDigests)) {
      bundle.ok = false;
      bundle.error = "policy digest is not in the signed trust policy";
    }
  }
  const notes = options.offline
    ? [OFFLINE_WARNING]
    : checkRevocation
      ? []
      : ["revocation is not checked in v0.1 (revocation ledger ships in v0.2)"];
  const valid = bundles.filter((b) => b.ok);
  const revoked = bundles.some((b) => b.error?.startsWith("REVOKED:"));
  if (valid.length === 0) {
    return { ok: false, status: revoked ? "REVOKED" : "rejected", artifactDigest, bundles, notes };
  }

  const evaluated = evaluateGoldBundles(valid, notes);
  if (!evaluated.level) return { ok: false, status: "rejected", artifactDigest, bundles, notes: evaluated.notes };
  const band = evaluated.level === "banded" ? valid.find((b) => b.statement?.predicate.band)?.statement?.predicate.band : undefined;
  const gated = applyVerificationGates({
    level: evaluated.level,
    band,
    policies: valid.map((b) => policyOf(b.statement)),
    sources: valid.map((b) => b.statement?.predicate.source.uri ?? ""),
    expectedSource: options.expectedSource,
    notes: evaluated.notes,
  });
  return { artifactDigest, bundles, status: gated.ok ? "verified" : "rejected", ...gated };
}
