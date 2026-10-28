// Signed findings (docs/findings.md): what a public scan records when an artifact
// fails a security check. A finding has its own predicate type, so no verifier can
// mistake it for a certificate. It states facts (rule, file, line, commit) and is
// reproducible: `verify-finding` re-runs the same checks on the same commit and
// accepts the finding only if they fail in exactly the same way.
import { readFile } from "node:fs/promises";
import { verify as sigstoreVerify } from "sigstore";
import { certify, detectRuntime, STATEMENT_TYPE, type Checks, type CertifyOutcome, type Predicate } from "./certify.js";
import { TEST_PATH } from "./checks/scan.js";
import { canonicalJson, digestArtifact } from "./digest.js";
import { DEFAULT_TRUST_POLICY, OBSERVER_REPOSITORY, type TrustPolicy } from "./trust-policy.js";
import { VERSION } from "./version.js";
import { bundleLogIndexes, canonicalSource, describeSigner, matchDescribedSigner } from "./verify.js";

export const FINDING_PREDICATE_TYPE = "https://trust.workrr.ai/finding/v0.1";

// Rules whose matches are rarely accidental: invisible Unicode tag characters and
// bidirectional overrides. A finding with either, outside tests and fixtures (where
// sanitizers keep their samples) and outside bundled or minified code (where
// libraries such as mermaid ship these characters in their own text handling), is
// kind "concealment". Phrase rules (WT007, WT008) match innocent wording too often
// to be called that. Bundles still fail the scan: their items stay, as "check".
export const CONCEALMENT_RULES = ["WT002", "WT003"];
export const BUNDLE_PATH = /(^|\/)(dist|build)\/|\.(min|bundle)\.[cm]?js$/;

export function isConcealment(items: FindingItem[]): boolean {
  return items.some((i) => i.rule && CONCEALMENT_RULES.includes(i.rule) && !TEST_PATH.test(i.file ?? "") && !BUNDLE_PATH.test(i.file ?? ""));
}

export type FindingItem = {
  check: "scan" | "policy";
  rule?: string;
  severity?: string;
  file?: string;
  line?: number;
  detail: string;
};

export type FindingPredicate = {
  artifact: Predicate["artifact"];
  source: Predicate["source"];
  checks: Checks;
  kind: "concealment" | "check";
  findings: FindingItem[];
  certifier: Predicate["certifier"];
  scannedAt: string;
};

export type FindingStatement = {
  _type: typeof STATEMENT_TYPE;
  subject: { name: string; digest: { sha256: string } }[];
  predicateType: typeof FINDING_PREDICATE_TYPE;
  predicate: FindingPredicate;
};

// Security-relevant failures only. Layout problems (a missing description, an
// oversized folder) make an artifact uncertifiable but are not findings.
export function findingItems(outcome: CertifyOutcome): FindingItem[] {
  const c = outcome.statement.predicate.checks;
  const items: FindingItem[] = [];
  for (const f of c.scan.findings) {
    if (f.severity === "warn" || f.excepted) continue;
    items.push({ check: "scan", rule: f.rule, severity: f.severity, file: f.file, line: f.line, detail: `${f.rule} (${f.severity})` });
  }
  for (const v of c.policy.violations) {
    let m = /^forbidden file type: (.+)$/.exec(v);
    if (m) items.push({ check: "policy", rule: "forbidden-file-type", file: m[1], detail: v });
    m = /^symlink points outside artifact directory: (.+)$/.exec(v);
    if (m) items.push({ check: "policy", rule: "escaping-symlink", file: m[1], detail: v });
  }
  return items;
}

// The finding statement for a failed public scan, or undefined when nothing
// security-relevant failed.
export function findingStatement(outcome: CertifyOutcome): FindingStatement | undefined {
  const p = outcome.statement.predicate;
  if (p.level !== "scanned" || outcome.certified) return undefined;
  const items = findingItems(outcome);
  if (!items.length) return undefined;
  return {
    _type: STATEMENT_TYPE,
    subject: outcome.statement.subject,
    predicateType: FINDING_PREDICATE_TYPE,
    predicate: {
      artifact: p.artifact,
      source: p.source,
      checks: p.checks,
      kind: isConcealment(items) ? "concealment" : "check",
      findings: items,
      certifier: { name: "workrr-certify", version: VERSION, runtime: detectRuntime() },
      scannedAt: p.certifiedAt,
    },
  };
}

export type FindingResult = {
  ok: boolean;
  artifactDigest: string;
  source?: string;
  commit?: string;
  path?: string;
  kind?: FindingPredicate["kind"];
  findings?: FindingItem[];
  signerIdentity?: string;
  logIndexes?: string[];
  error?: string;
};

// Verify a signed finding against a checkout of the commit it names: the signature,
// Rekor inclusion and observer signer, then reproduce it by re-running the checks.
export async function verifyFinding(
  path: string,
  bundlePath: string,
  policy: TrustPolicy = DEFAULT_TRUST_POLICY,
  options: { trustedRootPath?: string } = {},
): Promise<FindingResult> {
  const { sha256: artifactDigest } = await digestArtifact(path);
  const fail = (error: string, extra: Partial<FindingResult> = {}): FindingResult => ({ ok: false, artifactDigest, error, ...extra });
  let bundle: Parameters<typeof sigstoreVerify>[0] & { dsseEnvelope?: { payload: string } };
  try {
    bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  } catch (e) {
    return fail(`cannot read bundle: ${(e as Error).message}`);
  }
  const logIndexes = bundleLogIndexes(bundle);
  if (!bundle.dsseEnvelope) return fail("bundle has no DSSE envelope (not an attestation)");
  let statement: FindingStatement;
  try {
    statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  } catch {
    return fail("attestation payload is not valid JSON");
  }
  if (statement.predicateType !== FINDING_PREDICATE_TYPE) return fail(`not a finding: predicate type ${statement.predicateType}`);
  if (!statement.subject?.some((s) => s.digest?.sha256 === artifactDigest)) {
    return fail("finding is for a different artifact (digest mismatch)");
  }
  const p = statement.predicate;
  const facts = { source: p?.source?.uri, commit: p?.source?.commit, path: p?.source?.path, logIndexes };

  let signer;
  try {
    signer = await sigstoreVerify(bundle, options.trustedRootPath ? { tufRootPath: options.trustedRootPath } : undefined);
  } catch (e) {
    return fail(`signature verification failed: ${(e as Error).message}`, facts);
  }
  const described = describeSigner((signer.identity ?? {}) as Parameters<typeof describeSigner>[0]);
  const accepted = matchDescribedSigner(policy, described);
  if (!accepted) return fail(`signer is not an accepted workrr certifier: ${described.san || "unknown"}`, facts);
  if (accepted.role !== "observer") return fail("findings come only from public scans; this signer is a publisher certifier", facts);
  if (!described.sourceRepositoryURI || canonicalSource(described.sourceRepositoryURI) !== canonicalSource(OBSERVER_REPOSITORY)) {
    return fail(`public scan signed outside ${OBSERVER_REPOSITORY}: ${described.sourceRepositoryURI ?? "(no source repository)"}`, facts);
  }

  // Reproduce: the same checks on the same files must fail in the same way.
  const outcome = await certify(path, { observe: p.source.uri });
  // A different ruleset or policy can't reproduce it either way: say which certifier can.
  const c = outcome.statement.predicate.checks;
  if (c.scan.rulesetDigest !== p.checks.scan.rulesetDigest || c.policy.policyDigest !== p.checks.policy.policyDigest) {
    return fail(
      `cannot reproduce with this certifier: its ruleset or policy differs from the one that signed the finding (use certify ${p.certifier.version})`,
      facts,
    );
  }
  const again = findingStatement(outcome);
  if (!again) return fail("not reproduced: the checks pass on this checkout", facts);
  if (canonicalJson(again.predicate.findings) !== canonicalJson(p.findings) || again.predicate.kind !== p.kind) {
    return fail("not reproduced: the checks fail differently on this checkout", facts);
  }
  return { ok: true, artifactDigest, ...facts, kind: p.kind, findings: p.findings, signerIdentity: described.san };
}
