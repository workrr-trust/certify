// Known-pattern scan. A pass means "no high or critical findings from this ruleset",
// never "safe". The ruleset is data so its digest pins exactly what ran.
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Artifact } from "../artifact.js";
import { jsonDigest } from "../digest.js";

export type Severity = "warn" | "high" | "critical";
type Rule = { id: string; severity: Severity; description: string; pattern: string; flags: string };

export const RULESET_VERSION = "workrr-scan-v0.1";

export const RULES: Rule[] = [
  { id: "WT001", severity: "high", description: "Instruction override phrasing",
    pattern: String.raw`\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts|rules|directions)`, flags: "gi" },
  { id: "WT002", severity: "critical", description: "Unicode tag characters (invisible ASCII smuggling)",
    pattern: String.raw`[\u{E0000}-\u{E007F}]`, flags: "gu" },
  { id: "WT003", severity: "high", description: "Bidirectional control characters (Trojan Source)",
    pattern: String.raw`[‪-‮⁦-⁩]`, flags: "gu" },
  { id: "WT004", severity: "warn", description: "Zero-width characters",
    pattern: String.raw`[​‌⁠]|(?<!^)﻿`, flags: "gu" },
  { id: "WT005", severity: "high", description: "Remote script piped to a shell",
    pattern: String.raw`\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`, flags: "gi" },
  { id: "WT006", severity: "high", description: "Reads credential stores",
    pattern: String.raw`(~|\$HOME)?/?\.(ssh/(id_[a-z0-9]+|authorized_keys)|aws/credentials|netrc|git-credentials|docker/config\.json|kube/config)\b`, flags: "gi" },
  { id: "WT007", severity: "high", description: "Instructs concealment from the user",
    pattern: String.raw`\b(do\s+not|don't|never)\s+(tell|inform|mention|reveal|show)\b[^\n]{0,40}\b(the\s+)?(user|human|operator)\b`, flags: "gi" },
  { id: "WT008", severity: "high", description: "Hidden HTML comment carrying instructions",
    pattern: String.raw`<!--(?:(?!-->)[\s\S]){0,2000}?\b(ignore|instruction|system prompt|you are|assistant|exfiltrate)\b[\s\S]*?-->`, flags: "gi" },
  { id: "WT009", severity: "warn", description: "Sends data to a URL",
    pattern: String.raw`\b(post|send|upload|exfiltrate|forward)\b[^\n]{0,60}https?://`, flags: "gi" },
  { id: "WT010", severity: "warn", description: "Large encoded blob",
    pattern: String.raw`[A-Za-z0-9+/]{240,}={0,2}`, flags: "g" },
];

export type Finding = { rule: string; severity: Severity; file: string; line: number };
export type ScanResult = { result: "pass" | "fail"; rulesetVersion: string; rulesetDigest: string; findings: Finding[] };

export async function scanArtifact(artifact: Artifact): Promise<ScanResult> {
  const findings: Finding[] = [];
  for (const f of artifact.digest.files) {
    const abs = artifact.isDirectory ? join(artifact.root, f.path) : artifact.root;
    const bytes = await readFile(abs).catch(() => undefined);
    if (!bytes || bytes.includes(0)) continue; // symlink or binary
    findings.push(...scanText(bytes.toString("utf8"), f.path));
  }
  findings.sort((a, b) => (a.file === b.file ? a.line - b.line || a.rule.localeCompare(b.rule) : a.file < b.file ? -1 : 1));
  const failing = findings.some((x) => x.severity !== "warn");
  return {
    result: failing ? "fail" : "pass",
    rulesetVersion: RULESET_VERSION,
    rulesetDigest: jsonDigest({ version: RULESET_VERSION, rules: RULES }),
    findings,
  };
}

export function scanText(text: string, file: string): Finding[] {
  const out: Finding[] = [];
  for (const rule of RULES) {
    const re = new RegExp(rule.pattern, rule.flags.includes("m") ? rule.flags : rule.flags + "m");
    const seenLines = new Set<number>();
    for (const m of text.matchAll(re)) {
      const line = text.slice(0, m.index).split("\n").length;
      if (seenLines.has(line)) continue;
      seenLines.add(line);
      out.push({ rule: rule.id, severity: rule.severity, file, line });
    }
  }
  return out;
}
