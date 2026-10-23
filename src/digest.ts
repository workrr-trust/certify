// Artifact digests (spec §1) and canonical JSON (spec §3).
import { createHash } from "node:crypto";
import { lstat, readdir, readFile, readlink } from "node:fs/promises";
import { join } from "node:path";

export type DigestAlgorithm = "file-sha256" | "workrr-dirhash-v1";

export type ArtifactFile = { path: string; sha256: string; size: number };

export type ArtifactDigest = {
  algorithm: DigestAlgorithm;
  sha256: string;
  files: ArtifactFile[];
  symlinkTargets?: Map<string, string>;
};

export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

// Sort by UTF-8 byte order, not JS string (UTF-16) order, so Go and TS agree.
export function byteOrder(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

export async function digestArtifact(root: string): Promise<ArtifactDigest> {
  const st = await lstat(root);
  if (st.isFile()) {
    const bytes = await readFile(root);
    const sha = sha256Hex(bytes);
    const name = root.split(/[\\/]/).pop() ?? root;
    return { algorithm: "file-sha256", sha256: sha, files: [{ path: name, sha256: sha, size: bytes.length }] };
  }
  if (!st.isDirectory()) throw new Error(`Not a file or directory: ${root}`);

  const files: ArtifactFile[] = [];
  const symlinkTargets = new Map<string, string>();
  async function walk(dir: string, rel: string): Promise<void> {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (entry.name === ".git") continue;
      const abs = join(dir, entry.name);
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) {
        const target = await readlink(abs);
        symlinkTargets.set(relPath, target);
        files.push({ path: relPath, sha256: sha256Hex(target), size: Buffer.byteLength(target) });
      } else if (entry.isDirectory()) {
        await walk(abs, relPath);
      } else if (entry.isFile()) {
        const bytes = await readFile(abs);
        files.push({ path: relPath, sha256: sha256Hex(bytes), size: bytes.length });
      }
    }
  }
  await walk(root, "");
  if (files.length === 0) throw new Error(`Artifact directory is empty: ${root}`);
  files.sort((a, b) => byteOrder(a.path, b.path));
  const manifest = files.map((f) => `${f.sha256}  ${f.path}\n`).join("");
  return { algorithm: "workrr-dirhash-v1", sha256: sha256Hex(manifest), files, symlinkTargets };
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort(byteOrder);
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

export function jsonDigest(value: unknown): string {
  return `sha256:${sha256Hex(canonicalJson(value))}`;
}
