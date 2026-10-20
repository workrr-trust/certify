// Verify certificates (spec §6): digest → predicate type → Sigstore bundle
// (chain, signature, Rekor inclusion) → signer identity against the trust policy.
import { readFile } from "node:fs/promises";
import { verify as sigstoreVerify } from "sigstore";
import { PREDICATE_TYPE, type Statement } from "./certify.js";
import { canonicalJson, digestArtifact } from "./digest.js";
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

export type VerifyResult = {
  ok: boolean;
  level?: "gold" | "silver" | "banded";
  artifactDigest: string;
  bundles: BundleResult[];
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

export function matchSigner(policy: TrustPolicy, identity: Identity): AcceptedSigner | undefined {
  const { san, issuer, buildSignerDigest } = describeSigner(identity);
  return policy.signers.find(
    (s) =>
      s.issuer === issuer &&
      new RegExp(s.subjectAlternativeName).test(san) &&
      (s.buildSignerDigests.length === 0 || (buildSignerDigest !== undefined && s.buildSignerDigests.includes(buildSignerDigest))),
  );
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

export async function verifyArtifact(path: string, bundlePaths: string[], policy: TrustPolicy = DEFAULT_TRUST_POLICY): Promise<VerifyResult> {
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
  return { ok: true, level, artifactDigest, bundles, notes };
}
