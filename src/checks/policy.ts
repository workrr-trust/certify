// Policy conformance against a named, digested policy.
import type { Artifact } from "../artifact.js";
import { jsonDigest } from "../digest.js";

export type Policy = {
  name: string;
  maxTotalBytes?: number;
  forbiddenExtensions?: string[];
  requiredSkillFields?: string[];
  // When set, a skill's `allowed-tools` frontmatter may only list these tools.
  allowedTools?: string[];
  requireLicense?: boolean;
};

export const BASELINE_POLICY_NAME = "workrr-baseline-v0.1";

export const BASELINE_POLICY: Policy = {
  name: BASELINE_POLICY_NAME,
  maxTotalBytes: 5_000_000,
  forbiddenExtensions: [".exe", ".dll", ".so", ".dylib", ".bin", ".jar", ".class", ".pyc"],
  requiredSkillFields: ["name", "description"],
};

// The baseline name is reserved. A custom policy may not reuse it, even a one-line
// `{"name":"workrr-baseline-v0.1"}` that drops the forbidden-extension rules.
export function baselineNameViolation(policy: Policy): string | undefined {
  if (policy.name !== BASELINE_POLICY_NAME) return undefined;
  if (jsonDigest(policy) === jsonDigest(BASELINE_POLICY)) return undefined;
  return `policy name "${BASELINE_POLICY_NAME}" is reserved for the baseline policy`;
}

export type PolicyResult = {
  result: "pass" | "fail";
  policyName: string;
  policyDigest: string;
  violations: string[];
};

export function checkPolicy(artifact: Artifact, policy: Policy = BASELINE_POLICY): PolicyResult {
  const violations: string[] = [];
  const files = artifact.digest.files;

  const total = files.reduce((n, f) => n + f.size, 0);
  if (policy.maxTotalBytes !== undefined && total > policy.maxTotalBytes) {
    violations.push(`total size ${total} bytes exceeds ${policy.maxTotalBytes}`);
  }
  for (const f of files) {
    const ext = f.path.includes(".") ? f.path.slice(f.path.lastIndexOf(".")).toLowerCase() : "";
    if (policy.forbiddenExtensions?.includes(ext)) violations.push(`forbidden file type: ${f.path}`);
  }
  for (const sym of artifact.escapingSymlinks ?? []) {
    violations.push(`symlink points outside artifact directory: ${sym}`);
  }
  if (artifact.type === "skill") {
    const fm = artifact.frontmatter;
    if (!fm) violations.push("SKILL.md has no parseable YAML frontmatter");
    for (const field of policy.requiredSkillFields ?? []) {
      const v = fm?.[field];
      if (typeof v !== "string" || !v.trim()) violations.push(`SKILL.md frontmatter missing "${field}"`);
    }
    if (policy.allowedTools) {
      for (const tool of listTools(fm?.["allowed-tools"])) {
        if (!policy.allowedTools.includes(tool)) violations.push(`tool not allowed by policy: ${tool}`);
      }
    }
  }
  if (policy.requireLicense && !files.some((f) => /^(LICENSE|LICENCE|COPYING)(\.[a-z]+)?$/i.test(f.path))) {
    violations.push("no LICENSE file");
  }
  const reserved = baselineNameViolation(policy);
  if (reserved) violations.push(reserved);
  return {
    result: violations.length ? "fail" : "pass",
    policyName: policy.name,
    policyDigest: jsonDigest(policy),
    violations,
  };
}

// `allowed-tools` may be a YAML list or a comma/space-separated string.
function listTools(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String).map((s) => s.trim()).filter(Boolean);
  if (typeof v === "string") return v.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  return [];
}
