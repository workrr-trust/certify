// Verify certificates (spec §6): digest → predicate type → Sigstore bundle
// (chain, signature, Rekor inclusion) → signer identity against the trust policy.
import { readFile } from "node:fs/promises";
import { verify as sigstoreVerify } from "sigstore";
import { PREDICATE_TYPE, type Statement, type TrustBand } from "./certify.js";
import { BASELINE_POLICY, BASELINE_POLICY_NAME } from "./checks/policy.js";
import { normalizeRepoUri } from "./checks/provenance.js";
import { canonicalJson, digestArtifact, jsonDigest } from "./digest.js";
import { DEFAULT_TRUST_POLICY, type AcceptedSigner, type Forge, type TrustPolicy } from "./trust-policy.js";

const OID_BUILD_SIGNER_DIGEST = "1.3.6.1.4.1.57264.1.10";

export type BundleResult = {
  bundlePath: string;
  ok: boolean;
  error?: string;
  forge?: Forge;
  signerIdentity?: string;
  statement?: Statement;
};

export type PolicyStatus = "baseline" | "custom" | "reject";

export type VerifyResult = {
  ok: boolean;
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

export function describeSigner(identity: Identity): { san: string; issuer?: string; buildSignerDigest?: string } {
  const bsd = identity.oids?.find((o) => o.oid?.id?.join(".") === OID_BUILD_SIGNER_DIGEST);
  return {
    san: identity.subjectAlternativeName ?? "",
    issuer: identity.extensions?.issuer,
    buildSignerDigest: bsd ? derUtf8(bsd.value) : undefined,
  };
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
  const source = uniqueSources.length === 1 ? uniqueSources[0] : undefined;
  const digests = [...new Set(assessments.map((a) => a.policyDigest).filter((d): d is string => !!d))];
  if (digests.length > 1) notes.push(`policy digests differ: ${digests.join(", ")}`);
  if (uniqueSources.length > 1) notes.push(`publishers differ: ${uniqueSources.join(", ")}`);
  if (input.expectedSource) {
    const urls = input.sources.length ? input.sources : [""];
    for (const uri of urls) {
      if (!sourceMatches(uri, input.expectedSource)) {
        notes.push(`source mismatch: certificate is for ${uri || "(none)"}, --source is ${input.expectedSource}`);
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

export async function verifyBundle(bundlePath: string, artifactDigest: string, policy: TrustPolicy): Promise<BundleResult> {
  const fail = (error: string, extra: Partial<BundleResult> = {}): BundleResult => ({ bundlePath, ok: false, error, ...extra });
  let bundle: SerializedBundle & { dsseEnvelope?: { payload: string; payloadType: string } };
  try {
    bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  } catch (e) {
    return fail(`cannot read bundle: ${(e as Error).message}`);
  }
  if (!bundle.dsseEnvelope) return fail("bundle has no DSSE envelope (not an attestation)");

  let statement: Statement;
  try {
    statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  } catch {
    return fail("attestation payload is not valid JSON");
  }
  if (statement.predicateType !== PREDICATE_TYPE) {
    return fail(`unsupported predicate type: ${statement.predicateType}`, { statement });
  }
  if (!statement.subject?.some((s) => s.digest?.sha256 === artifactDigest)) {
    return fail("certificate is for a different artifact (digest mismatch)", { statement });
  }

  let signer;
  try {
    // Checks certificate chain to the Sigstore root, signature, and Rekor inclusion.
    signer = await sigstoreVerify(bundle);
  } catch (e) {
    return fail(`signature verification failed: ${(e as Error).message}`, { statement });
  }
  const identity = (signer.identity ?? {}) as Identity;
  const accepted = matchSigner(policy, identity);
  if (!accepted) {
    return fail(`signer is not an accepted workrr certifier: ${identity.subjectAlternativeName ?? "unknown"}`, {
      statement,
      signerIdentity: identity.subjectAlternativeName,
    });
  }
  return { bundlePath, ok: true, forge: accepted.forge, signerIdentity: identity.subjectAlternativeName, statement };
}

function policyOf(statement: Statement | undefined): { policyName?: string; policyDigest?: string } {
  const policy = statement?.predicate.checks.policy;
  return { policyName: policy?.policyName, policyDigest: policy?.policyDigest };
}

export async function verifyArtifact(
  path: string,
  bundlePaths: string[],
  policy: TrustPolicy = DEFAULT_TRUST_POLICY,
  expectedSource?: string,
): Promise<VerifyResult> {
  const { sha256: artifactDigest } = await digestArtifact(path);
  const bundles = await Promise.all(bundlePaths.map((b) => verifyBundle(b, artifactDigest, policy)));
  const valid = bundles.filter((b) => b.ok);
  const notes = ["revocation is not checked in v0.1 (revocation ledger ships in v0.2)"];
  if (valid.length === 0) return { ok: false, artifactDigest, bundles, notes };

  // Gold: two forges, silver on both, identical checks (spec §4).
  const silver = valid.filter((b) => b.statement?.predicate.level === "silver");
  const forges = new Set(silver.map((b) => b.forge));
  let level: VerifyResult["level"] = valid.some((b) => b.statement?.predicate.level === "silver") ? "silver" : "banded";
  if (forges.size >= 2) {
    const [a, b] = [silver.find((x) => x.forge === "github"), silver.find((x) => x.forge === "gitlab")];
    if (a && b && canonicalJson(a.statement!.predicate.checks) === canonicalJson(b.statement!.predicate.checks)) {
      level = "gold";
    } else {
      notes.push("two forges signed, but their check results differ — not Gold");
    }
  }
  const band = level === "banded" ? valid.find((b) => b.statement?.predicate.band)?.statement?.predicate.band : undefined;
  const gated = applyVerificationGates({
    level,
    band,
    policies: valid.map((b) => policyOf(b.statement)),
    sources: valid.map((b) => b.statement?.predicate.source.uri ?? ""),
    expectedSource,
    notes,
  });
  return { artifactDigest, bundles, ...gated };
}
