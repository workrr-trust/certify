// Provenance: the artifact is committed, unchanged, at a known source commit.
import { execFile } from "node:child_process";
import { realpath, stat } from "node:fs/promises";
import { dirname, relative } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);

export type Source = { uri: string; commit: string; path: string };
export type ProvenanceResult = { result: "pass" | "fail"; unchangedFromCommit: boolean; reason?: string };

async function git(cwd: string, ...args: string[]): Promise<string> {
  const { stdout } = await run("git", ["-C", cwd, ...args], { maxBuffer: 16 * 1024 * 1024 });
  return stdout.trim();
}

// git@github.com:org/repo.git and https://github.com/org/repo.git → https://github.com/org/repo
export function normalizeRepoUri(remote: string): string {
  const ssh = /^git@([^:]+):(.+?)(\.git)?$/.exec(remote);
  if (ssh) return `https://${ssh[1]}/${ssh[2]}`;
  return remote.replace(/\.git$/, "").replace(/^https:\/\/[^@/]+@/, "https://");
}

export async function checkProvenance(artifactPath: string): Promise<{ source: Source; check: ProvenanceResult }> {
  const abs = await realpath(artifactPath);
  const dir = (await stat(abs)).isDirectory() ? abs : dirname(abs);
  let top: string;
  try {
    top = await git(dir, "rev-parse", "--show-toplevel");
  } catch {
    return {
      source: { uri: "", commit: "0".repeat(40), path: artifactPath },
      check: { result: "fail", unchangedFromCommit: false, reason: "not inside a git repository" },
    };
  }
  const repoRoot = await realpath(top);
  const path = relative(repoRoot, abs) || ".";
  const commit = await git(repoRoot, "rev-parse", "HEAD");

  // CI knows the canonical repo URL; locally fall back to the origin remote.
  let uri = "";
  if (process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY) {
    uri = `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}`;
  } else if (process.env.CI_PROJECT_URL) {
    uri = process.env.CI_PROJECT_URL;
  } else {
    uri = normalizeRepoUri(await git(repoRoot, "remote", "get-url", "origin").catch(() => ""));
  }
  const source = { uri, commit, path };

  // Any modified, untracked, or ignored file inside the artifact means the digest
  // would not correspond to the commit.
  const dirty = await git(repoRoot, "status", "--porcelain", "--ignored", "--untracked-files=all", "--", path);
  if (dirty) {
    return { source, check: { result: "fail", unchangedFromCommit: false, reason: "artifact has uncommitted, untracked, or ignored files" } };
  }
  if (!uri) {
    return { source, check: { result: "fail", unchangedFromCommit: true, reason: "no source repository URL (set an origin remote)" } };
  }
  return { source, check: { result: "pass", unchangedFromCommit: true } };
}
