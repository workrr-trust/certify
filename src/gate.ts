// Org policy gate: discovers all skills in a repository and blocks merge if any
// skill is uncertified, modified since certification, below the org's minimum
// level, or violates the org's required policy or allowed publisher sources.
import { readdir, stat } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { loadArtifact } from "./artifact.js";
import { BASELINE_POLICY, checkPolicy, type Policy } from "./checks/policy.js";
import { scanArtifact } from "./checks/scan.js";
import { jsonDigest } from "./digest.js";
import { DEFAULT_TRUST_POLICY, type TrustPolicy } from "./trust-policy.js";
import { canonicalSource, sourceMatches, verifyArtifact, verifyBundle } from "./verify.js";

export type GateLevel = "banded" | "silver" | "gold";

const LEVEL_RANK: Record<GateLevel, number> = {
  banded: 1,
  silver: 2,
  gold: 3,
};

const SKIP_DIRS = new Set([".git", "node_modules", "dist", ".workrr-certifier", ".workrr-py"]);

export type SkillGateItem = {
  path: string;
  name: string;
  digest: string;
  ok: boolean;
  level?: GateLevel;
  bundles: string[];
  reasons: string[];
};

export type OrgGateOptions = {
  minLevel?: GateLevel;
  requiredPolicy?: Policy;
  certificatesDir?: string;
  allowedSources?: string[];
  trustPolicy?: TrustPolicy;
  // Optional injection for unit testing without live Rekor network calls
  verifyBundleFn?: typeof verifyBundle;
};

export type OrgGateResult = {
  ok: boolean;
  minLevel: GateLevel;
  requiredPolicyName: string;
  requiredPolicyDigest: string;
  totalSkills: number;
  passedSkills: number;
  failedSkills: number;
  skills: SkillGateItem[];
};

export function levelMeetsMinimum(actual: GateLevel | undefined, minLevel: GateLevel): boolean {
  if (!actual) return false;
  return LEVEL_RANK[actual] >= LEVEL_RANK[minLevel];
}

export async function discoverSkills(rootDir: string): Promise<string[]> {
  const root = resolve(rootDir);
  const found: string[] = [];

  async function walk(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    if (entries.some((e) => (e.isFile() || e.isSymbolicLink()) && e.name === "SKILL.md")) {
      const rel = relative(root, dir).split("\\").join("/") || ".";
      found.push(rel);
    }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      if (SKIP_DIRS.has(e.name)) continue;
      await walk(join(dir, e.name));
    }
  }

  await walk(root);
  found.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return found;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

export async function findSkillBundles(
  rootDir: string,
  skillRelPath: string,
  artifactDigest: string,
  certificatesDir?: string,
): Promise<string[]> {
  const root = resolve(rootDir);
  const skillDir = skillRelPath === "." ? root : join(root, skillRelPath);
  const candidates = [
    join(skillDir, "certificate.sigstore.json"),
    join(skillDir, ".workrr", "certificate.sigstore.json"),
  ];
  if (certificatesDir) {
    const certRoot = resolve(certificatesDir);
    candidates.push(join(certRoot, `${artifactDigest}.sigstore.json`));
    if (skillRelPath !== ".") {
      candidates.push(join(certRoot, skillRelPath, "certificate.sigstore.json"));
    }
  }
  const existing: string[] = [];
  for (const c of candidates) {
    if (await fileExists(c)) existing.push(c);
  }
  return existing;
}

function sourceAllowed(certificateUri: string, allowedSources: string[]): boolean {
  for (const allowed of allowedSources) {
    if (sourceMatches(certificateUri, allowed)) return true;
    const normAllowed = canonicalSource(allowed);
    const normCert = canonicalSource(certificateUri);
    if (normCert.startsWith(`${normAllowed}/`)) return true;
  }
  return false;
}

export async function runOrgPolicyGate(rootDir: string, options: OrgGateOptions = {}): Promise<OrgGateResult> {
  const minLevel: GateLevel = options.minLevel ?? "silver";
  const policy: Policy = options.requiredPolicy ?? BASELINE_POLICY;
  const requiredPolicyName = policy.name || "custom";
  const requiredPolicyDigest = jsonDigest(policy);
  const trustPolicy = options.trustPolicy ?? DEFAULT_TRUST_POLICY;

  const skillPaths = await discoverSkills(rootDir);
  const skills: SkillGateItem[] = [];

  for (const relPath of skillPaths) {
    const absPath = relPath === "." ? resolve(rootDir) : join(resolve(rootDir), relPath);
    const artifact = await loadArtifact(absPath);
    const reasons: string[] = [];

    // Local policy and scan conformance against the org's required policy
    const policyRes = checkPolicy(artifact, policy);
    if (policyRes.result !== "pass") {
      for (const v of policyRes.violations) reasons.push(`policy violation: ${v}`);
    }
    const scanRes = await scanArtifact(artifact);
    if (scanRes.result !== "pass") {
      reasons.push(`scan failed with ${scanRes.findings.filter((f) => f.severity !== "warn").length} high/critical finding(s)`);
    }

    const bundles = await findSkillBundles(rootDir, relPath, artifact.digest.sha256, options.certificatesDir);
    if (bundles.length === 0) {
      reasons.push("uncertified skill: no certificate bundle found");
      skills.push({
        path: relPath,
        name: artifact.name,
        digest: artifact.digest.sha256,
        ok: false,
        bundles: [],
        reasons,
      });
      continue;
    }

    let level: GateLevel | undefined;
    if (options.verifyBundleFn) {
      const bundleResults = await Promise.all(
        bundles.map((b) => options.verifyBundleFn!(b, artifact.digest.sha256, trustPolicy)),
      );
      const valid = bundleResults.filter((b) => b.ok && b.statement);
      for (const b of bundleResults) {
        if (!b.ok && b.error) reasons.push(`${b.bundlePath}: ${b.error}`);
      }
      if (valid.length > 0) {
        const st = valid[0].statement!;
        const certPolicy = st.predicate.checks.policy;
        if (certPolicy.policyDigest !== requiredPolicyDigest) {
          reasons.push(
            `certificate policy digest ${certPolicy.policyDigest} does not match required ${requiredPolicyDigest}`,
          );
        }
        if (options.allowedSources?.length) {
          const uri = st.predicate.source.uri;
          if (!sourceAllowed(uri, options.allowedSources)) {
            reasons.push(`publisher ${uri} is not in allowed sources (${options.allowedSources.join(", ")})`);
          }
        }
        const forges = new Set(
          valid.filter((b) => b.statement?.predicate.level === "silver").map((b) => b.forge),
        );
        level = forges.size >= 2 ? "gold" : valid.some((b) => b.statement?.predicate.level === "silver") ? "silver" : "banded";
      }
    } else {
      const verifyRes = await verifyArtifact(absPath, bundles, trustPolicy);
      for (const b of verifyRes.bundles) {
        if (!b.ok && b.error) reasons.push(`${b.bundlePath}: ${b.error}`);
      }
      if (verifyRes.policyDigest && verifyRes.policyDigest !== requiredPolicyDigest) {
        reasons.push(`certificate policy digest ${verifyRes.policyDigest} does not match required ${requiredPolicyDigest}`);
      }
      if (options.allowedSources?.length && verifyRes.source) {
        if (!sourceAllowed(verifyRes.source, options.allowedSources)) {
          reasons.push(`publisher ${verifyRes.source} is not in allowed sources (${options.allowedSources.join(", ")})`);
        }
      }
      const valid = verifyRes.bundles.filter((b) => b.ok && b.statement);
      if (valid.length > 0) {
        const forges = new Set(
          valid.filter((b) => b.statement?.predicate.level === "silver").map((b) => b.forge),
        );
        level =
          verifyRes.level ??
          (forges.size >= 2 ? "gold" : valid.some((b) => b.statement?.predicate.level === "silver") ? "silver" : "banded");
      }
    }

    if (!levelMeetsMinimum(level, minLevel)) {
      reasons.push(`certificate level ${level ?? "(none)"} is below required minimum ${minLevel}`);
    }

    skills.push({
      path: relPath,
      name: artifact.name,
      digest: artifact.digest.sha256,
      ok: reasons.length === 0,
      level,
      bundles,
      reasons,
    });
  }

  const passedSkills = skills.filter((s) => s.ok).length;
  const failedSkills = skills.length - passedSkills;
  return {
    ok: failedSkills === 0,
    minLevel,
    requiredPolicyName,
    requiredPolicyDigest,
    totalSkills: skills.length,
    passedSkills,
    failedSkills,
    skills,
  };
}
