// Evidence packs (docs/evidence.md). Run with `npm test` (builds first).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { loadArtifact } from "../dist/artifact.js";
import { buildPack, collectDependencies, collectFacts, collectPublisher } from "../dist/evidence.js";

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
    facts: { files: {} },
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
  const facts = await collectFacts(artifact);
  const a = buildPack(input(artifact, { publisher: pub, facts }), "cra");
  const b = buildPack(input(artifact, { publisher: pub, facts, builtAt: "2027-01-01T00:00:00.000Z" }), "cra");
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
  assert.deepEqual(sbom.metadata.component.components.map((c) => c.name), artifact.digest.files.map((f) => f.path));

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

test("evidence: facts from the artifact's bytes: SHA-512, executable, archive, declared version and licence", async () => {
  const root = await fixture({
    "SKILL.md": "---\nname: demo-skill\ndescription: A demo.\nlicense: Apache-2.0\nmetadata:\n  version: 1.4.0\n---\nDo the thing.\n",
    "scripts/run": "#!/bin/sh\necho hi\n",
    "scripts/tool.py": "print(1)\n",
    "assets/data.tar.gz": "x",
    "notes.txt": "plain",
  });
  const facts = await collectFacts(await loadArtifact(root));
  assert.equal(facts.files["scripts/run"].executable, true);
  assert.equal(facts.files["scripts/tool.py"].executable, true);
  assert.equal(facts.files["notes.txt"].executable, false);
  assert.equal(facts.files["assets/data.tar.gz"].archive, true);
  assert.equal(facts.files["notes.txt"].sha512, createHash("sha512").update("plain").digest("hex"));
  assert.deepEqual(facts.version, { value: "1.4.0", from: "SKILL.md" });
  assert.deepEqual(facts.license, { expression: "Apache-2.0", from: "SKILL.md" });
});

test("evidence: licence text that isn't an SPDX expression is not used", async () => {
  for (const license of ["Complete terms in LICENSE.txt", "see LICENSE", "UNLICENSED"]) {
    const root = await fixture({ "SKILL.md": SKILL, "package.json": { version: "2.0.0", license } });
    const facts = await collectFacts(await loadArtifact(root));
    assert.equal(facts.license, undefined, license);
    assert.deepEqual(facts.version, { value: "2.0.0", from: "package.json" });
  }
  const root = await fixture({ "SKILL.md": SKILL, "package.json": { license: "(MIT OR Apache-2.0) AND GPL-2.0-only WITH Classpath-exception-2.0" } });
  assert.equal((await collectFacts(await loadArtifact(root))).license.from, "package.json");
});

test("evidence: SBOM carries the BSI TR-03183-2 data fields", async () => {
  const root = await fixture({ "SKILL.md": SKILL, "run.sh": "#!/bin/sh\n", "package.json": { license: "MIT", dependencies: { zod: "^3.23.0" } } });
  const artifact = await loadArtifact(root);
  const dependencies = await collectDependencies(artifact);
  const facts = await collectFacts(artifact);
  const pack = buildPack(input(artifact, { dependencies, facts, sbomCreator: "mailto:sbom@acme.example" }), "cra");
  const sbom = JSON.parse(pack.get("sbom.cdx.json"));
  assert.deepEqual(sbom.metadata.manufacturer, { contact: [{ email: "sbom@acme.example" }] });
  assert.equal(sbom.metadata.timestamp, "2026-10-28T12:00:00.000Z");
  const main = sbom.metadata.component;
  assert.deepEqual(main.manufacturer.url, ["https://github.com/acme/skills"]);
  assert.deepEqual(main.licenses, [{ expression: "MIT", acknowledgement: "concluded" }]);
  assert.ok(main.properties.some((p) => p.name === "workrr:declared-license" && p.value === "MIT"));
  assert.equal(main.purl, `pkg:github/acme/skills@${"a".repeat(40)}#skills/demo`);
  assert.ok(main.externalReferences.some((r) => r.type === "source-distribution" && r.url === `https://github.com/acme/skills/tree/${"a".repeat(40)}/skills/demo`));
  for (const f of main.components) {
    const props = Object.fromEntries(f.properties.map((p) => [p.name, p.value]));
    for (const name of ["bsi:component:executable", "bsi:component:archive", "bsi:component:structured", "bsi:component:filename"]) {
      assert.equal(f.properties.filter((p) => p.name === name).length, 1, `${f.name} ${name}`);
    }
    assert.equal(props["bsi:component:filename"], f.name.split("/").pop());
    const dist = f.externalReferences.find((r) => r.type === "distribution");
    assert.equal(dist.url, `https://raw.githubusercontent.com/acme/skills/${"a".repeat(40)}/skills/demo/${f.name}`);
    assert.equal(dist.hashes[0].alg, "SHA-512");
    assert.equal(dist.hashes[0].content, facts.files[f.name].sha512);
    assert.ok(f.manufacturer && f.version && f.licenses);
  }
  assert.equal(main.components.find((f) => f.name === "run.sh").properties.find((p) => p.name === "bsi:component:executable").value, "executable");
  const zod = sbom.components.find((c) => c.name === "zod");
  assert.equal(zod.version, "3.23.0");
  assert.deepEqual(zod.manufacturer.url, ["https://www.npmjs.com/package/zod"]);
  // Every component appears in the dependency graph, and completeness is stated.
  const refs = new Set(sbom.dependencies.map((d) => d.ref));
  for (const c of [main, ...main.components, ...sbom.components]) assert.ok(refs.has(c["bom-ref"]), c["bom-ref"]);
  assert.deepEqual(sbom.compositions.map((c) => c.aggregate), ["complete", "unknown", "unknown"]);
  assert.deepEqual(JSON.parse(pack.get("evidence.json")).sbom.gaps, []);
});

test("evidence: unfilled TR-03183-2 fields are reported, not invented", async () => {
  const artifact = await loadArtifact(await fixture({ "SKILL.md": SKILL }));
  const pack = buildPack(input(artifact, { facts: await collectFacts(artifact) }), "cra");
  const sbom = JSON.parse(pack.get("sbom.cdx.json"));
  assert.equal(sbom.metadata.manufacturer, undefined);
  assert.equal(sbom.metadata.component.licenses, undefined);
  const gaps = JSON.parse(pack.get("evidence.json")).sbom.gaps;
  assert.equal(gaps.length, 2);
  assert.match(gaps[0], /--sbom-creator/);
  assert.match(gaps[1], /licence/);
  const clause = JSON.parse(pack.get("mapping.cra.json")).clauses.find((c) => c.id === "annex-i-2-1");
  assert.match(clause.note, /Required fields not filled/);
});
