// Evidence packs (docs/evidence.md). Run with `npm test` (builds first).
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { loadArtifact } from "../dist/artifact.js";
import { buildPack, collectDependencies, collectPublisher } from "../dist/evidence.js";

async function fixture(files) {
  const root = await mkdtemp(join(tmpdir(), "workrr-evidence-"));
  for (const [path, body] of Object.entries(files)) {
    await mkdir(join(root, path, ".."), { recursive: true });
    await writeFile(join(root, path), typeof body === "string" ? body : JSON.stringify(body));
  }
  return root;
}

const SKILL = "---\nname: demo-skill\ndescription: A demo.\n---\nDo the thing.\n";

function input(artifact, overrides = {}) {
  const digest = artifact.digest.sha256;
  const statement = {
    predicate: {
      artifact: { name: artifact.name, type: artifact.type, digestAlgorithm: artifact.digest.algorithm, fileCount: artifact.digest.files.length },
      source: { uri: "https://github.com/acme/skills", commit: "a".repeat(40), path: "skills/demo" },
      checks: {
        provenance: { result: "pass", unchangedFromCommit: true },
        policy: { result: "pass", policyName: "workrr-baseline-v0.1", policyDigest: `sha256:${"b".repeat(64)}`, violations: [] },
        scan: { result: "pass", rulesetVersion: "workrr-scan-v0.2", rulesetDigest: `sha256:${"c".repeat(64)}`, findings: [] },
        tests: { result: "none" },
      },
      level: "banded",
      band: "A",
      certifier: { name: "workrr", version: "0.1.9", runtime: "github-actions" },
      certifiedAt: "2026-10-28T12:00:00.000Z",
    },
  };
  const result = { bundlePath: "/x/123.sigstore.json", ok: true, forge: "github", signerIdentity: "https://github.com/workrr-trust/certify/.github/workflows/certify.yml@refs/tags/v0.1.9", statement, logIndexes: ["123"] };
  return {
    artifact,
    verify: { ok: true, status: "verified", level: "banded", band: "A", artifactDigest: digest, bundles: [result], notes: [] },
    bundles: [{ file: "certificate/123.sigstore.json", bytes: Buffer.from("{}"), result }],
    publisher: {},
    dependencies: { dependencies: [], unparsed: [] },
    revocationChecked: true,
    builtAt: "2026-10-29T00:00:00.000Z",
    ...overrides,
  };
}

test("evidence: publisher declarations come from workrr.json and are covered by the certificate", async () => {
  const root = await fixture({
    "SKILL.md": SKILL,
    "workrr.json": { support: { until: "2031-12-31" }, security: { policy: "https://acme.example/security", contact: "mailto:security@acme.example" } },
  });
  const pub = await collectPublisher(await loadArtifact(root));
  assert.deepEqual(pub.supportUntil, { value: "2031-12-31", from: "workrr.json", coveredByCertificate: true });
  assert.equal(pub.securityPolicy.value, "https://acme.example/security");
  assert.equal(pub.securityContact.value, "mailto:security@acme.example");
});

test("evidence: malformed declarations are ignored; a SECURITY.md in the artifact links to the source commit", async () => {
  const root = await fixture({
    "SKILL.md": SKILL,
    "SECURITY.md": "Report to security@acme.example",
    "workrr.json": { support: { until: "soon" }, security: { policy: "http://insecure.example", contact: "call us" } },
  });
  const artifact = await loadArtifact(root);
  const pub = await collectPublisher(artifact, input(artifact).bundles[0].result.statement.predicate);
  assert.equal(pub.supportUntil, undefined);
  assert.equal(pub.securityContact, undefined);
  assert.deepEqual(pub.securityPolicy, {
    value: `https://github.com/acme/skills/blob/${"a".repeat(40)}/skills/demo/SECURITY.md`,
    from: "SECURITY.md",
    coveredByCertificate: true,
  });
});

test("evidence: a SECURITY.md at the checkout root is marked as outside the certificate", async () => {
  const repo = await fixture({ ".git/HEAD": "ref: refs/heads/main\n", "SECURITY.md": "x", "skills/demo/SKILL.md": SKILL });
  const pub = await collectPublisher(await loadArtifact(join(repo, "skills/demo")));
  assert.deepEqual(pub.securityPolicy, { value: "SECURITY.md", from: "repository SECURITY.md", coveredByCertificate: false });
});

test("evidence: top-level dependencies from npm, pip and go manifests", async () => {
  const root = await fixture({
    "server.json": { name: "demo-server" },
    "package.json": { dependencies: { "@modelcontextprotocol/sdk": "^1.0.0", zod: "^3.23.0" }, devDependencies: { typescript: "^5" } },
    "package-lock.json": { packages: { "node_modules/@modelcontextprotocol/sdk": { version: "1.2.3" } } },
    "py/requirements.txt": "# comment\nRequests==2.32.3\nPyYAML>=6 ; python_version>'3'\n-r other.txt\n",
    "go/go.mod": "module x\n\nrequire (\n\tgithub.com/a/b v1.2.0\n\tgithub.com/c/d v0.1.0 // indirect\n)\nrequire github.com/e/f v2.0.0\n",
    "pyproject.toml": "[project]\n",
    "node_modules/zod/package.json": { dependencies: { nope: "1" } },
  });
  const { dependencies, unparsed } = await collectDependencies(await loadArtifact(root));
  const purls = dependencies.map((d) => d.purl).sort();
  assert.deepEqual(purls, [
    "pkg:golang/github.com/a/b@v1.2.0",
    "pkg:golang/github.com/e/f@v2.0.0",
    "pkg:npm/%40modelcontextprotocol/sdk@1.2.3",
    "pkg:npm/zod",
    "pkg:pypi/pyyaml",
    "pkg:pypi/requests@2.32.3",
  ]);
  assert.equal(dependencies.find((d) => d.name === "zod").range, "^3.23.0");
  assert.equal(dependencies.find((d) => d.name === "pyyaml").range, ">=6");
  assert.deepEqual(unparsed, ["pyproject.toml"]);
});

test("evidence: CRA pack maps clauses, hashes every file and is reproducible apart from build time", async () => {
  const root = await fixture({ "SKILL.md": SKILL, "workrr.json": { support: { until: "2031-12-31" } } });
  const artifact = await loadArtifact(root);
  const pub = await collectPublisher(artifact);
  const a = buildPack(input(artifact, { publisher: pub }), "cra");
  const b = buildPack(input(artifact, { publisher: pub, builtAt: "2027-01-01T00:00:00.000Z" }), "cra");
  assert.deepEqual([...a.keys()], [
    "summary.html", "evidence.json", "mapping.cra.json", "sbom.cdx.json", "certificate/123.sigstore.json",
    "verify.sh", "statement-template.md", "verification.json",
  ]);
  for (const name of a.keys()) {
    if (name === "summary.html" || name === "verification.json") assert.notEqual(a.get(name), b.get(name), name);
    else assert.deepEqual(a.get(name), b.get(name), name);
  }

  const status = Object.fromEntries(JSON.parse(a.get("mapping.cra.json")).clauses.map((c) => [c.id, c.status]));
  assert.equal(status["art-13-5"], "evidenced");
  assert.equal(status["art-13-8"], "publisher-declared");
  assert.equal(status["annex-i-2-5"], "missing");
  assert.equal(status["manufacturer-acts"], "not-covered");

  const sbom = JSON.parse(a.get("sbom.cdx.json"));
  assert.equal(sbom.specVersion, "1.6");
  assert.match(sbom.serialNumber, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(sbom.metadata.component.hashes[0].content, artifact.digest.sha256);
  assert.deepEqual(sbom.components.map((c) => c.name), artifact.digest.files.map((f) => f.path));

  const all = [...a.values()].map(String).join("\n").toLowerCase();
  for (const word of ["compliant", "conformant", "approved", " safe"]) assert.ok(!all.includes(word), `pack says "${word}"`);
});

test("evidence: no pack from a certificate that did not verify or was revoked", async () => {
  const artifact = await loadArtifact(await fixture({ "SKILL.md": SKILL }));
  for (const verify of [{ ok: false, status: "rejected" }, { ok: false, status: "REVOKED" }]) {
    const i = input(artifact);
    assert.throws(() => buildPack({ ...i, verify: { ...i.verify, ...verify } }, "cra"), /did not verify/);
  }
});

test("evidence: summary escapes publisher-controlled text", async () => {
  const artifact = await loadArtifact(await fixture({ "SKILL.md": SKILL }));
  const html = buildPack(input(artifact, {
    publisher: { securityPolicy: { value: "https://x.example/\"><script>alert(1)</script>", from: "workrr.json", coveredByCertificate: true } },
  }), "cra").get("summary.html");
  assert.ok(!html.includes("<script>"));
});
