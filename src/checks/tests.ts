// Reproducible test suite. The artifact declares its suite in workrr.json:
//   { "test": { "command": "node test.js" } }
// The suite is part of the artifact, so it is covered by the artifact digest.
//
// SECURITY: this runs artifact-supplied code. In CI it must run in a job that has
// no OIDC / signing permission; the signing job only consumes the result file.
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Artifact } from "../artifact.js";

export type TestsResult = { result: "pass" | "fail" | "none"; command?: string; exitCode?: number };

// What the test job hands to the signing job.
export type TestsReport = { artifactDigest: string; tests: TestsResult };

export async function readTestCommand(artifact: Artifact): Promise<string | undefined> {
  if (!artifact.isDirectory) return undefined;
  try {
    const manifest = JSON.parse(await readFile(join(artifact.root, "workrr.json"), "utf8"));
    const cmd = manifest?.test?.command;
    return typeof cmd === "string" && cmd.trim() ? cmd.trim() : undefined;
  } catch {
    return undefined;
  }
}

export async function runTests(artifact: Artifact, timeoutMs = 10 * 60_000): Promise<TestsResult> {
  const command = await readTestCommand(artifact);
  if (!command) return { result: "none" };
  const exitCode = await new Promise<number>((resolve) => {
    const child = spawn(command, { cwd: artifact.root, shell: true, stdio: "inherit", timeout: timeoutMs });
    child.on("error", () => resolve(127));
    child.on("close", (code) => resolve(code ?? 1));
  });
  return { result: exitCode === 0 ? "pass" : "fail", command, exitCode };
}
