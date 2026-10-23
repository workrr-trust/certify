// Artifact type detection (spec §2), naming, and SKILL.md frontmatter.
import { readFile, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import { parse as parseYaml } from "yaml";
import { digestArtifact, type ArtifactDigest } from "./digest.js";

export type ArtifactType = "skill" | "mcp-server" | "agent-context" | "other";

export type Artifact = {
  root: string;
  isDirectory: boolean;
  name: string;
  type: ArtifactType;
  digest: ArtifactDigest;
  frontmatter?: Record<string, unknown>;
  skillBody?: string;
};

export async function loadArtifact(root: string): Promise<Artifact> {
  const isDirectory = (await stat(root)).isDirectory();
  const digest = await digestArtifact(root);
  const has = (p: string) => digest.files.some((f) => f.path === p);
  const single = isDirectory ? undefined : basename(root);

  let type: ArtifactType = "other";
  if (has("SKILL.md") || single === "SKILL.md") type = "skill";
  else if (has("server.json")) type = "mcp-server";
  else if (has("AGENTS.md") || has("CLAUDE.md") || single === "AGENTS.md" || single === "CLAUDE.md") type = "agent-context";

  let name = basename(root);
  let frontmatter: Record<string, unknown> | undefined;
  let skillBody: string | undefined;
  if (type === "skill") {
    const text = await readFile(isDirectory ? join(root, "SKILL.md") : root, "utf8");
    skillBody = stripFrontmatter(text);
    frontmatter = parseFrontmatter(text);
    if (typeof frontmatter?.name === "string" && frontmatter.name) name = frontmatter.name;
  } else if (type === "mcp-server") {
    try {
      const server = JSON.parse(await readFile(join(root, "server.json"), "utf8"));
      if (typeof server?.name === "string" && server.name) name = server.name;
    } catch {
      // Unparseable server.json: keep the directory name; policy reports it.
    }
  }
  return { root, isDirectory, name, type, digest, frontmatter, skillBody };
}

export function stripFrontmatter(text: string): string {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
  return m ? text.slice(m[0].length) : text;
}

export function parseFrontmatter(text: string): Record<string, unknown> | undefined {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
  if (!m) return undefined;
  try {
    const parsed = parseYaml(m[1]);
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}
