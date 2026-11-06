#!/usr/bin/env node
// Turns a raw SkillSpector JSON report into a small, repeatable report: the same
// skill and SkillSpector commit give the same bytes (docs/skillspector-report.md).
//
// It keeps rule, severity, confidence, file and line. It drops:
// - recommendation and risk score: SkillSpector's labels include "SAFE", which
//   workrr never says, and its "DO_NOT_INSTALL" is not a workrr verdict;
// - finding text and code snippets: they copy third-party content (point, don't host);
// - finding_id, scanned_at and local paths: they differ on every run.
import { readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

// SC4 reads OSV.dev live, so its result depends on the day it ran.
const LIVE_RULES = new Set(["SC4"]);
// AE1 says the scanner didn't finish reading a referenced file: a limit of the
// scan, not something the skill does. Counted under coverage instead.
const COVERAGE_RULES = new Set(["AE1"]);

export function toReport(raw, { commit }) {
  if (raw.execution_successful !== true) throw new Error("SkillSpector did not finish: no report");
  if (raw.metadata?.llm_requested !== false) throw new Error("LLM analysis was on: results would not repeat");
  if (!/^[0-9a-f]{40}$/.test(commit ?? "")) throw new Error("commit must be a full SkillSpector commit sha");

  const issues = raw.issues ?? [];
  const findings = issues
    .filter((i) => !LIVE_RULES.has(i.id) && !COVERAGE_RULES.has(i.id))
    .map((i) => ({
      rule: i.id,
      severity: i.severity.toLowerCase(),
      confidence: i.confidence ?? null,
      file: i.location?.file ?? null,
      line: i.location?.start_line ?? null,
    }))
    .sort((a, b) => JSON.stringify(a) < JSON.stringify(b) ? -1 : 1);

  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

  return {
    tool: { name: "SkillSpector", version: raw.metadata.skillspector_version, commit, mode: "static" },
    coverage: {
      status: raw.analysis_completeness?.status ?? "unknown",
      incomplete_references: issues.filter((i) => COVERAGE_RULES.has(i.id)).length,
    },
    counts: Object.fromEntries(Object.entries(counts).sort()),
    findings,
  };
}

async function main([input, output, commit]) {
  if (!input || !output || !commit) {
    console.error("usage: skillspector-report.mjs <raw.json> <report.json> <skillspector-commit>");
    process.exit(2);
  }
  const report = toReport(JSON.parse(await readFile(input, "utf8")), { commit });
  await writeFile(output, JSON.stringify(report, null, 2) + "\n");
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) await main(process.argv.slice(2));
