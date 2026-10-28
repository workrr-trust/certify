// Known-pattern scan. A pass means "no high or critical findings from this ruleset",
// never "safe". The ruleset is data so its digest pins exactly what ran.
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Artifact } from "../artifact.js";
import { byteOrder, jsonDigest } from "../digest.js";

export type Severity = "warn" | "high" | "critical";
type Rule = { id: string; severity: Severity; description: string; pattern: string; flags: string };

export const RULESET_VERSION = "workrr-scan-v0.2";

export type ScanException = {
  rule: string;
  file: string;
  line?: number;
  reason: string;
  approvedBy?: string;
};

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
    pattern: String.raw`\b(do\s+not|don't|never)\s+(tell|inform)\s+the\s+(user|human|operator)\s+(about|that)\b|\b(do\s+not|don't|never)\s+(mention|reveal|disclose)\b[^\n]{0,40}\bto\s+the\s+(user|human|operator)\b`, flags: "gi" },
  { id: "WT008", severity: "high", description: "Hidden HTML comment carrying instructions",
    pattern: String.raw`<!--(?:(?!-->)[\s\S]){0,2000}?(\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts|rules|directions)|\byou\s+are\s+now\b|\bexfiltrate\b|\b(do\s+not|don't|never)\s+(tell|inform)\s+the\s+(user|human|operator)\b)[\s\S]*?-->`, flags: "gi" },
  { id: "WT009", severity: "warn", description: "Sends data to a URL",
    pattern: String.raw`\b(post|send|upload|exfiltrate|forward)\b[^\n]{0,60}https?://`, flags: "gi" },
  { id: "WT010", severity: "warn", description: "Large encoded blob",
    pattern: String.raw`[A-Za-z0-9+/]{240,}={0,2}`, flags: "g" },
];

export type Finding = { rule: string; severity: Severity; file: string; line: number; excepted?: boolean; exceptionReason?: string };
export type ScanResult = {
  result: "pass" | "fail";
  rulesetVersion: string;
  rulesetDigest: string;
  findings: Finding[];
  exceptions?: ScanException[];
};

const DEFENSIVE_WT001_LINE = /\b(never\s+follow|not\s+an?\s+instruction|neither\s+an?\s+instruction|prompt[- ]injection|untrusted\s+data)\b/i;

// Rules about text an agent reads as instructions. Tests, fixtures and snapshots are
// not loaded as instructions (and are where scanners and sanitizers keep their
// samples), so these rules skip them. Shell, credential and character rules do not.
const PROMPT_RULES = ["WT001", "WT007", "WT008"];
export const TEST_PATH = /(^|\/)(test|tests|__tests__|fixtures|__snapshots__)\/|(^|\/)test[_-][^/]*$|[._](test|spec)\.[A-Za-z0-9]+$|\.(snap|snapshot)$/;

function isDefensiveExample(ruleId: string, file: string, lineText: string, matchStartInLine: number): boolean {
  if (PROMPT_RULES.includes(ruleId) && TEST_PATH.test(file)) return true;
  // A quoted phrase is an example being discussed ("don't tell the user …"), not an instruction.
  if (ruleId === "WT007" && /["'`\u201c]/.test(lineText[matchStartInLine - 1] ?? "")) return true;
  if (ruleId !== "WT001") return false;
  if (/(^|\/)(evals|test|tests|fixtures)\//.test(file) && file.endsWith(".json")) return true;
  const before = lineText.slice(0, matchStartInLine);
  if ((before.endsWith('"') || before.endsWith("\u201c") || before.endsWith("'")) && DEFENSIVE_WT001_LINE.test(lineText)) {
    return true;
  }
  if (DEFENSIVE_WT001_LINE.test(lineText) && /["\u201c']/.test(before)) {
    return true;
  }
  return false;
}

export async function scanArtifact(artifact: Artifact, exceptions?: ScanException[]): Promise<ScanResult> {
  const findings: Finding[] = [];
  const escaping = new Set(artifact.escapingSymlinks ?? []);
  for (const f of artifact.digest.files) {
    if (escaping.has(f.path)) continue;
    const abs = artifact.isDirectory ? join(artifact.root, f.path) : artifact.root;
    const bytes = await readFile(abs).catch(() => undefined);
    if (!bytes || bytes.includes(0)) continue; // symlink or binary
    findings.push(...scanText(bytes.toString("utf8"), f.path));
  }
  // File by UTF-8 byte order (not JS UTF-16 order), then line, then rule id, so
  // every implementation orders findings identically (spec §3).
  findings.sort((a, b) => byteOrder(a.file, b.file) || a.line - b.line || byteOrder(a.rule, b.rule));
  const appliedExceptions: ScanException[] = [];
  if (exceptions?.length) {
    for (const f of findings) {
      const ex = exceptions.find(
        (e) => e.rule === f.rule && e.file === f.file && (e.line === undefined || e.line === f.line),
      );
      if (ex) {
        f.excepted = true;
        f.exceptionReason = ex.reason;
        if (!appliedExceptions.includes(ex)) appliedExceptions.push(ex);
      }
    }
  }
  const failing = findings.some((x) => x.severity !== "warn" && !x.excepted);
  return {
    result: failing ? "fail" : "pass",
    rulesetVersion: RULESET_VERSION,
    rulesetDigest: jsonDigest({ version: RULESET_VERSION, rules: RULES }),
    findings,
    ...(appliedExceptions.length ? { exceptions: appliedExceptions } : {}),
  };
}

export function scanText(text: string, file: string): Finding[] {
  const out: Finding[] = [];
  const lines = text.split("\n");
  for (const rule of RULES) {
    const re = new RegExp(rule.pattern, rule.flags.includes("m") ? rule.flags : rule.flags + "m");
    const seenLines = new Set<number>();
    for (const m of text.matchAll(re)) {
      const prefix = text.slice(0, m.index);
      const lineIdx = prefix.split("\n").length - 1;
      const line = lineIdx + 1;
      if (seenLines.has(line)) continue;
      const lastNl = prefix.lastIndexOf("\n");
      const col = lastNl < 0 ? (m.index ?? 0) : (m.index ?? 0) - lastNl - 1;
      if (isDefensiveExample(rule.id, file, lines[lineIdx] ?? "", col)) continue;
      seenLines.add(line);
      out.push({ rule: rule.id, severity: rule.severity, file, line });
    }
  }
  return out;
}
