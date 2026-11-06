// The SkillSpector report repeats byte for byte, carries no verdict or third-party
// text, and its workflow has no signing power.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { parse as parseYaml } from "yaml";
import { toReport } from "../scripts/skillspector-report.mjs";

const commit = "54824463814a0be01360792523ec7245a69190fc";

function issue(id, severity, file, line, extra = {}) {
  return {
    id, severity, confidence: 0.8, finding_id: `finding-${Math.random()}`,
    location: { file, start_line: line }, finding: "copied text", code_snippet: "copied code", ...extra,
  };
}

function raw(issues) {
  return {
    execution_successful: true,
    skill: { source: "/tmp/run/skill", scanned_at: new Date().toISOString() },
    risk_assessment: { score: 100, recommendation: "SAFE" },
    metadata: { skillspector_version: "2.13.4", llm_requested: false },
    analysis_completeness: { status: "partial" },
    issues,
  };
}

test("two runs give the same bytes, whatever the order and run-specific fields", () => {
  const a = toReport(raw([issue("E2", "HIGH", "a.py", 3), issue("P9", "MEDIUM", "b.md", 1)]), { commit });
  const b = toReport(raw([issue("P9", "MEDIUM", "b.md", 1), issue("E2", "HIGH", "a.py", 3)]), { commit });
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

test("no verdict, score, snippet or local path reaches the report", () => {
  const text = JSON.stringify(toReport(raw([issue("E2", "HIGH", "a.py", 3)]), { commit }));
  for (const word of ["SAFE", "recommendation", "score", "copied", "/tmp/run", "finding-"]) {
    assert.ok(!text.includes(word), word);
  }
});

test("live and coverage rules are not findings", () => {
  const r = toReport(raw([issue("SC4", "HIGH", "package.json", 1), issue("AE1", "HIGH", "SKILL.md", 9), issue("E1", "LOW", "a.py", 1)]), { commit });
  assert.deepEqual(r.findings.map((f) => f.rule), ["E1"]);
  assert.deepEqual(r.counts, { low: 1 });
  assert.deepEqual(r.coverage, { status: "partial", incomplete_references: 1 });
});

test("refuses an unfinished scan, an LLM scan and a short commit", () => {
  assert.throws(() => toReport({ ...raw([]), execution_successful: false }, { commit }), /did not finish/);
  assert.throws(() => toReport({ ...raw([]), metadata: { llm_requested: true } }, { commit }), /LLM/);
  assert.throws(() => toReport(raw([]), { commit: "5482446" }), /full SkillSpector commit/);
});

test("the workflow can't sign: read-only token, no id-token, no attest step", async () => {
  const text = await readFile(new URL("../.github/workflows/skillspector-report.yml", import.meta.url), "utf8");
  const wf = parseYaml(text);
  assert.deepEqual(wf.permissions, { contents: "read" });
  for (const job of Object.values(wf.jobs)) assert.equal(job.permissions, undefined);
  assert.ok(!text.includes("id-token"));
  assert.ok(!text.includes("actions/attest"));
});
