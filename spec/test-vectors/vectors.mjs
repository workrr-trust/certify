// Evaluates cases.json with the TypeScript certifier (dist/) into the
// shape of expected.json. Used by test/vectors.test.mjs and by
// generate.mjs. The Go implementation has its own evaluator (go/vectors_test.go).
import { mkdir, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadArtifact } from "../../dist/artifact.js";
import { BASELINE_POLICY, checkPolicy } from "../../dist/checks/policy.js";
import { RULES, RULESET_VERSION, scanArtifact } from "../../dist/checks/scan.js";
import { canonicalJson, jsonDigest } from "../../dist/digest.js";

export const vectorsDir = dirname(fileURLToPath(import.meta.url));

export async function readVectors() {
  const read = async (f) => JSON.parse(await readFile(join(vectorsDir, f), "utf8"));
  return { cases: await read("cases.json"), expected: await read("expected.json").catch(() => undefined) };
}

function fileBytes(file) {
  if (file.text !== undefined) return Buffer.from(file.text, "utf8");
  return Buffer.concat(
    file.parts.map((p) => {
      if (typeof p === "string") return Buffer.from(p, "utf8");
      const one = p.base64 !== undefined ? Buffer.from(p.base64, "base64") : Buffer.from(p.text, "utf8");
      return Buffer.concat(Array(p.times ?? 1).fill(one));
    }),
  );
}

// Writes a case's files under <tmp>/<id>/ (so the directory basename is the id)
// and returns the artifact path.
async function materialize(c, root) {
  if (c.dir) return join(vectorsDir, c.dir);
  const dir = join(root, c.id);
  for (const f of c.files) {
    const abs = join(dir, f.path);
    await mkdir(dirname(abs), { recursive: true });
    if (f.symlink !== undefined) await symlink(f.symlink, abs);
    else await writeFile(abs, fileBytes(f));
  }
  return c.target ? join(dir, c.target) : dir;
}

export async function evaluate(cases) {
  const root = await mkdtemp(join(tmpdir(), "workrr-vectors-"));
  const policies = Object.fromEntries(Object.entries(cases.policies).map(([k, v]) => [k, v ?? BASELINE_POLICY]));
  const out = {
    rulesetVersion: RULESET_VERSION,
    rulesetDigest: jsonDigest({ version: RULESET_VERSION, rules: RULES }),
    policyDigests: Object.fromEntries(Object.entries(policies).map(([k, p]) => [k, jsonDigest(p)])),
    canonicalJson: cases.canonicalJson.map((v) => canonicalJson(v)),
    artifacts: {},
  };
  for (const c of cases.artifacts) {
    const a = await loadArtifact(await materialize(c, root));
    const scan = await scanArtifact(a);
    const results = {};
    const checks = {};
    for (const name of c.policies) {
      const policy = checkPolicy(a, policies[name]);
      results[name] = policy;
      checks[name] = canonicalJson({ ...cases.fixedChecks, $comment: undefined, policy, scan });
    }
    out.artifacts[c.id] = {
      algorithm: a.digest.algorithm,
      digest: a.digest.sha256,
      files: a.digest.files,
      type: a.type,
      name: a.name,
      scan,
      policies: results,
      checks,
    };
  }
  return out;
}
