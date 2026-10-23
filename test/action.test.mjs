// The Marketplace action is a verify-only gate. These tests cover the gate,
// the action entrypoint, and the rule that third-party actions stay SHA-pinned.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { parse as parseYaml } from "yaml";
import { gate, levelMeets, parseBundles, parseLevel } from "../action/gate.mjs";
import { main, outputBody } from "../action/run.mjs";

const exec = promisify(execFile);
const root = fileURLToPath(new URL("..", import.meta.url));

const THIRD_PARTY = new Set([
  "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
  "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1",
  "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
  "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
  "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
  "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
  "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
]);

const TRUSTED_CERTIFIER = /^workrr-trust\/certify\/\.github\/workflows\/certify\.yml@v0\.1\.[01]$/;

function allowedUse(ref) {
  if (ref.startsWith("./")) return true;
  if (TRUSTED_CERTIFIER.test(ref)) return true;
  return THIRD_PARTY.has(ref);
}

function collectUses(value, found = []) {
  if (!value || typeof value !== "object") return found;
  if (Array.isArray(value)) {
    for (const item of value) collectUses(item, found);
    return found;
  }
  for (const [key, child] of Object.entries(value)) {
    if (key === "uses" && typeof child === "string") found.push(child);
    else collectUses(child, found);
  }
  return found;
}

async function walkYaml(dir, found = []) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === "node_modules" || entry.name === "dist" || entry.name === ".git") continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) await walkYaml(path, found);
    else if (entry.name.endsWith(".yml") || entry.name.endsWith(".yaml")) found.push(path);
  }
  return found;
}

test("level ordering: gold satisfies silver, banded does not, default is silver", () => {
  assert.equal(parseLevel(""), "silver");
  assert.equal(parseLevel("  Silver "), "silver");
  assert.equal(parseLevel("gold"), "gold");
  assert.throws(() => parseLevel("platinum"), /banded, silver, or gold/);
  assert.equal(levelMeets("gold", "silver"), true);
  assert.equal(levelMeets("silver", "silver"), true);
  assert.equal(levelMeets("silver", "gold"), false);
  assert.equal(levelMeets("banded", "silver"), false);
  assert.equal(levelMeets("banded", "banded"), true);
  assert.equal(levelMeets("nope", "silver"), false);
});

test("bundles are one path per line", () => {
  assert.deepEqual(parseBundles("a.json"), ["a.json"]);
  assert.deepEqual(parseBundles(" a.json \n\nb.json\r\n"), ["a.json", "b.json"]);
  assert.throws(() => parseBundles(" \n"), /bundle is required/);
});

test("gate fails closed below the minimum and keeps a higher level", () => {
  const revocation = "revocation is not checked in v0.1 (revocation ledger ships in v0.2)";
  const silver = gate(
    {
      ok: true,
      level: "silver",
      headline: "VERIFIED · level silver",
      notes: [revocation],
      bundles: [{ ok: true, bundlePath: "a.json", signerIdentity: "certify.yml@v0.1.1" }],
    },
    "silver",
  );
  assert.equal(silver.verified, true);
  assert.equal(silver.level, "silver");
  assert.equal(silver.headline, "VERIFIED · level silver");

  const tooLow = gate({ ...silver, ok: true, level: "silver", headline: "VERIFIED · level silver", notes: [revocation], bundles: [] }, "gold");
  assert.equal(tooLow.verified, false);
  assert.equal(tooLow.level, "silver");
  assert.equal(tooLow.headline, "NOT VERIFIED");
  assert.ok(tooLow.notes.some((note) => note.includes("level silver is below required gold")));

  const custom = gate(
    { ok: false, headline: "custom policy, not baseline", notes: [revocation], bundles: [] },
    "silver",
  );
  assert.equal(custom.verified, false);
  assert.equal(custom.level, "");
  assert.equal(custom.headline, "custom policy, not baseline");

  const withBadExtra = gate(
    {
      ok: true,
      level: "silver",
      notes: [revocation],
      bundles: [
        { ok: true, bundlePath: "a.json" },
        { ok: false, bundlePath: "b.json", error: "nope" },
      ],
    },
    "banded",
  );
  assert.equal(withBadExtra.verified, true);
  assert.equal(withBadExtra.level, "silver");
  assert.ok(withBadExtra.notes.some((note) => note === "b.json: nope"));
});

test("output values cannot inject extra lines", () => {
  const body = outputBody({ verified: "false", signer: "a\nb=c", headline: "NOT VERIFIED" });
  assert.equal(body, "verified=false\nsigner=a b=c\nheadline=NOT VERIFIED\n");
});

test("missing bundle and a non-workrr bundle fail closed", async () => {
  const dir = await mkdtemp(join(tmpdir(), "workrr-action-"));
  const output = join(dir, "output");
  const summary = join(dir, "summary");
  const missing = await main({
    WORKRR_PATH: join(root, "test/fixtures/good-skill"),
    WORKRR_BUNDLE: join(dir, "no-such-certificate.sigstore.json"),
    WORKRR_SOURCE: "workrr-trust/certify",
    WORKRR_LEVEL: "silver",
    GITHUB_OUTPUT: output,
    GITHUB_STEP_SUMMARY: summary,
  });
  assert.equal(missing, 1);
  const missingOut = await readFile(output, "utf8");
  assert.match(missingOut, /^verified=false$/m);
  assert.match(missingOut, /^headline=NOT VERIFIED$/m);
  assert.match(missingOut, /^level=$/m);
  assert.match(await readFile(summary, "utf8"), /cannot read bundle/);

  const foreignOutput = join(dir, "foreign-output");
  const foreignSummary = join(dir, "foreign-summary");
  const foreign = await main({
    WORKRR_PATH: join(root, "test/fixtures/good-skill"),
    WORKRR_BUNDLE: join(root, "spec/test-vectors/sigstore/npm-sigstore-5.0.0.sigstore.json"),
    WORKRR_SOURCE: "workrr-trust/certify",
    WORKRR_LEVEL: "gold",
    GITHUB_OUTPUT: foreignOutput,
    GITHUB_STEP_SUMMARY: foreignSummary,
  });
  assert.equal(foreign, 1);
  const foreignOut = await readFile(foreignOutput, "utf8");
  assert.match(foreignOut, /^verified=false$/m);
  assert.match(foreignOut, /^headline=NOT VERIFIED$/m);
  assert.match(foreignOut, /^artifact-digest=sha256:[0-9a-f]{64}$/m);
  assert.match(await readFile(foreignSummary, "utf8"), /unsupported predicate type/);
});

test("usage errors exit 2 and a missing artifact exits 1", async () => {
  const dir = await mkdtemp(join(tmpdir(), "workrr-action-"));
  const output = join(dir, "output");
  const summary = join(dir, "summary");
  const env = { GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary };
  assert.equal(await main({ ...env, WORKRR_PATH: "", WORKRR_BUNDLE: "c.json", WORKRR_SOURCE: "a/b" }), 2);
  assert.match(await readFile(summary, "utf8"), /path is required/);
  assert.match(await readFile(output, "utf8"), /^verified=false$/m);
  await writeFile(output, "");
  await writeFile(summary, "");
  assert.equal(await main({ ...env, WORKRR_PATH: "x", WORKRR_BUNDLE: "c.json", WORKRR_SOURCE: "  " }), 2);
  assert.match(await readFile(summary, "utf8"), /source is required/);
  await writeFile(output, "");
  await writeFile(summary, "");
  assert.equal(
    await main({ ...env, WORKRR_PATH: "x", WORKRR_BUNDLE: "c.json", WORKRR_SOURCE: "a/b", WORKRR_LEVEL: "safe" }),
    2,
  );
  assert.match(await readFile(summary, "utf8"), /banded, silver, or gold/);
  await writeFile(output, "");
  await writeFile(summary, "");
  const code = await main({
    ...env,
    WORKRR_PATH: join(dir, "missing-artifact"),
    WORKRR_BUNDLE: join(root, "spec/test-vectors/sigstore/npm-sigstore-5.0.0.sigstore.json"),
    WORKRR_SOURCE: "a/b",
    WORKRR_LEVEL: "silver",
  });
  assert.equal(code, 1);
  assert.match(await readFile(output, "utf8"), /^verified=false$/m);
});

test("verify.sh refuses to run outside the action tree and does not sign", async () => {
  const script = await readFile(join(root, "action/verify.sh"), "utf8");
  assert.match(script, /npm ci --ignore-scripts --include=dev/);
  assert.match(script, /unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL/);
  assert.doesNotMatch(script, /npx |actions\/attest|id-token/);
  await exec("bash", ["-n", join(root, "action/verify.sh")]);
  const result = await exec("bash", [join(root, "action/verify.sh")], {
    env: { ...process.env, GITHUB_ACTION_PATH: "" },
  }).then(
    () => ({ code: 0 }),
    (error) => ({ code: error.code }),
  );
  assert.equal(result.code, 2);
});

test("starter workflows match the examples", async () => {
  const certify = await readFile(join(root, "examples/certify.yml"), "utf8");
  const verify = await readFile(join(root, "examples/verify.yml"), "utf8");
  assert.equal(certify, await readFile(join(root, ".github/workflow-templates/workrr-certify.yml"), "utf8"));
  assert.equal(verify, await readFile(join(root, ".github/workflow-templates/workrr-verify.yml"), "utf8"));
  for (const properties of ["workrr-certify.properties.json", "workrr-verify.properties.json"]) {
    const parsed = JSON.parse(await readFile(join(root, ".github/workflow-templates", properties), "utf8"));
    assert.equal(typeof parsed.name, "string");
    assert.equal(typeof parsed.description, "string");
    assert.equal(parsed.iconName, "shield");
    assert.ok(parsed.categories.includes("Security"));
  }
});

test("action.yml is the only action metadata file and it only verifies", async () => {
  const metadata = [];
  async function walk(dir) {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === "node_modules" || entry.name === "dist" || entry.name === ".git") continue;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (entry.name === "action.yml" || entry.name === "action.yaml") metadata.push(path);
    }
  }
  await walk(root);
  assert.deepEqual(
    metadata.map((path) => relative(root, path)),
    ["action.yml"],
  );

  const action = parseYaml(await readFile(join(root, "action.yml"), "utf8"));
  assert.equal(action.name, "workrr verify");
  assert.match(action.description, /does not sign/);
  assert.equal(action.branding.icon, "shield");
  assert.equal(action.branding.color, "blue");
  assert.equal(action.runs.using, "composite");
  for (const name of ["path", "bundle", "source"]) assert.equal(action.inputs[name].required, true);
  assert.equal(action.inputs.level.required, false);
  assert.equal(action.inputs.level.default, "silver");
  assert.equal(action.inputs["trust-policy"], undefined);
  for (const name of ["verified", "level", "source", "policy-name", "policy-digest", "artifact-digest", "signer", "headline"]) {
    assert.match(action.outputs[name].value, /steps\.verify\.outputs/);
  }
  assert.equal(action.runs.steps[1].id, "verify");
  assert.match(action.runs.steps[1].run, /action\/verify\.sh/);
  assert.deepEqual(collectUses(action), ["actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1"]);
  const text = await readFile(join(root, "action.yml"), "utf8");
  assert.doesNotMatch(text, /id-token|trust-policy|actions\/attest/);
});

test("every action is pinned by an allowlisted SHA", async () => {
  const files = [
    join(root, "action.yml"),
    ...(await walkYaml(join(root, ".github"))),
    ...(await walkYaml(join(root, "examples"))),
  ];
  const refs = [];
  for (const file of files) {
    const doc = parseYaml(await readFile(file, "utf8"));
    for (const ref of collectUses(doc)) {
      refs.push(ref);
      assert.equal(allowedUse(ref), true, `${file} uses ${ref}`);
    }
  }
  assert.ok(refs.includes("actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1"));
  assert.ok(refs.includes("workrr-trust/certify/.github/workflows/certify.yml@v0.1.1"));
  assert.ok(refs.includes("./"));
  assert.equal(refs.some((ref) => /@v0\.1\.[2-9]/.test(ref) || /@main\b/.test(ref) || /@v1\b/.test(ref)), false);

  const ci = parseYaml(await readFile(join(root, ".github/workflows/ci.yml"), "utf8"));
  assert.deepEqual(ci.jobs["verify-action"].permissions, { contents: "read" });
  assert.equal(JSON.stringify(ci.jobs["verify-action"]).includes("id-token"), false);

  const verifyExample = parseYaml(await readFile(join(root, "examples/verify.yml"), "utf8"));
  assert.deepEqual(verifyExample.permissions, { contents: "read" });
  assert.equal(JSON.stringify(verifyExample).includes("id-token"), false);
  assert.deepEqual(collectUses(verifyExample), [
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "./",
  ]);
  const certifyExample = parseYaml(await readFile(join(root, "examples/certify.yml"), "utf8"));
  assert.deepEqual(collectUses(certifyExample), ["workrr-trust/certify/.github/workflows/certify.yml@v0.1.1"]);
});
