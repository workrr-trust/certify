// Evidence packs (docs/evidence.md): a verified certificate rearranged for one regulation's records.
// A pack adds no claim and no signature: every fact comes from the certificate, the artifact's bytes,
// or the publisher's own declarations, and says which.
import { readFile, stat } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import type { Artifact } from "./artifact.js";
import type { Predicate } from "./certify.js";
import { sha256Hex } from "./digest.js";
import { levelName } from "./levels.js";
import { canonicalSource, type BundleResult, type VerifyResult } from "./verify.js";
import { VERSION } from "./version.js";

export const PACK_FORMAT = "workrr-evidence-v0.1";
export const PROFILES = ["cra"] as const;
export type Profile = (typeof PROFILES)[number];

export type Declaration = { value: string; from: string; coveredByCertificate: boolean };
export type PublisherDeclarations = { supportUntil?: Declaration; securityPolicy?: Declaration; securityContact?: Declaration };

export type Dependency = { ecosystem: "npm" | "pypi" | "golang"; name: string; version?: string; range?: string; purl: string; manifest: string };
export type Dependencies = { dependencies: Dependency[]; unparsed: string[] };

export type PackBundle = { file: string; bytes: Buffer; result: BundleResult };

export type EvidenceInput = {
  artifact: Artifact;
  verify: VerifyResult;
  bundles: PackBundle[];
  publisher: PublisherDeclarations;
  dependencies: Dependencies;
  revocationChecked: boolean;
  builtAt: string;
};

/** File name → contents. */
export type Pack = Map<string, string | Buffer>;

// ── collection ───────────────────────────────────────────────────────────────

/** The certificate a pack describes: the publisher's when several verified (gold), else the first. */
export function primaryBundle(bundles: PackBundle[]): PackBundle {
  const ok = bundles.filter((b) => b.result.ok && b.result.statement);
  const pick = ok.find((b) => !b.result.observer && !b.result.witness) ?? ok[0];
  if (!pick) throw new Error("no verified certificate");
  return pick;
}

function sourceFileUrl(predicate: Predicate | undefined, relPath: string): string | undefined {
  if (!predicate || !/^https:\/\/github\.com\//.test(predicate.source.uri)) return undefined;
  return `${canonicalSource(predicate.source.uri)}/blob/${predicate.source.commit}/${relPath}`;
}

async function exists(p: string): Promise<boolean> {
  return stat(p).then(() => true, () => false);
}

/** Support period and security contact, from the artifact's workrr.json, else a SECURITY.md. */
export async function collectPublisher(artifact: Artifact, predicate?: Predicate): Promise<PublisherDeclarations> {
  const out: PublisherDeclarations = {};
  if (artifact.isDirectory) {
    try {
      const manifest = JSON.parse(await readFile(join(artifact.root, "workrr.json"), "utf8"));
      const until = manifest?.support?.until;
      if (typeof until === "string" && /^\d{4}-\d{2}-\d{2}$/.test(until)) {
        out.supportUntil = { value: until, from: "workrr.json", coveredByCertificate: true };
      }
      const policy = manifest?.security?.policy;
      if (typeof policy === "string" && /^https:\/\//.test(policy)) {
        out.securityPolicy = { value: policy, from: "workrr.json", coveredByCertificate: true };
      }
      const contact = manifest?.security?.contact;
      if (typeof contact === "string" && /^(mailto:|https:\/\/)/.test(contact)) {
        out.securityContact = { value: contact, from: "workrr.json", coveredByCertificate: true };
      }
    } catch {
      // No or unparseable workrr.json: nothing declared there.
    }
  }
  if (!out.securityPolicy) {
    const inArtifact = ["SECURITY.md", ".github/SECURITY.md"].find((p) => artifact.digest.files.some((f) => f.path === p));
    if (inArtifact) {
      const repoPath = predicate ? join(predicate.source.path, inArtifact).replace(/^\.?\/+/, "") : inArtifact;
      out.securityPolicy = { value: sourceFileUrl(predicate, repoPath) ?? inArtifact, from: inArtifact, coveredByCertificate: true };
    } else {
      // The checkout's root (the nearest directory holding .git), outside the certified bytes.
      let dir = resolve(artifact.isDirectory ? artifact.root : dirname(artifact.root));
      for (;;) {
        if (await exists(join(dir, ".git"))) {
          for (const p of ["SECURITY.md", ".github/SECURITY.md"]) {
            if (await exists(join(dir, p))) {
              out.securityPolicy = { value: sourceFileUrl(predicate, p) ?? p, from: `repository ${p}`, coveredByCertificate: false };
              break;
            }
          }
          break;
        }
        const up = dirname(dir);
        if (up === dir) break;
        dir = up;
      }
    }
  }
  return out;
}

const UNPARSED = ["pyproject.toml", "Pipfile", "Cargo.toml", "Gemfile", "composer.json", "pom.xml", "build.gradle", "build.gradle.kts"];

function npmPurl(name: string, version?: string): string {
  const path = name.startsWith("@") ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${path}${version ? `@${encodeURIComponent(version)}` : ""}`;
}

function pypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

/** Top-level dependencies the artifact declares (runtime only), with purls. */
export async function collectDependencies(artifact: Artifact): Promise<Dependencies> {
  const dependencies: Dependency[] = [];
  const unparsed: string[] = [];
  if (!artifact.isDirectory) return { dependencies, unparsed };
  const paths = artifact.digest.files.map((f) => f.path).filter((p) => !p.split("/").includes("node_modules"));
  const read = (p: string) => readFile(join(artifact.root, p), "utf8");
  for (const p of paths) {
    const file = basename(p);
    const dir = p.includes("/") ? p.slice(0, p.lastIndexOf("/") + 1) : "";
    if (file === "package.json") {
      let pkg: { dependencies?: Record<string, string> };
      try {
        pkg = JSON.parse(await read(p));
      } catch {
        unparsed.push(p);
        continue;
      }
      let lock: { packages?: Record<string, { version?: string }> } | undefined;
      if (paths.includes(`${dir}package-lock.json`)) {
        try {
          lock = JSON.parse(await read(`${dir}package-lock.json`));
        } catch {
          lock = undefined;
        }
      }
      for (const [name, range] of Object.entries(pkg.dependencies ?? {})) {
        const version = lock?.packages?.[`node_modules/${name}`]?.version;
        dependencies.push({ ecosystem: "npm", name, version, range: version ? undefined : range, purl: npmPurl(name, version), manifest: p });
      }
    } else if (file === "requirements.txt") {
      for (const raw of (await read(p)).split(/\r?\n/)) {
        const line = raw.replace(/\s+#.*$/, "").trim();
        if (!line || line.startsWith("#") || line.startsWith("-")) continue;
        const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$/.exec(line.split(";")[0].trim());
        if (!m) continue;
        const name = pypiName(m[1]);
        const spec = m[3].trim();
        const pinned = /^==\s*([^,\s*]+)$/.exec(spec)?.[1];
        dependencies.push({
          ecosystem: "pypi",
          name,
          version: pinned,
          range: pinned ? undefined : spec || undefined,
          purl: `pkg:pypi/${name}${pinned ? `@${encodeURIComponent(pinned)}` : ""}`,
          manifest: p,
        });
      }
    } else if (file === "go.mod") {
      let block = false;
      for (const raw of (await read(p)).split(/\r?\n/)) {
        const line = raw.trim();
        if (line.startsWith("require (")) block = true;
        else if (block && line === ")") block = false;
        const req = block ? line : /^require\s+(.*)$/.exec(line)?.[1];
        if (!req || req.startsWith("require") || req.includes("// indirect")) continue;
        const m = /^(\S+)\s+(v\S+)/.exec(req);
        if (m) dependencies.push({ ecosystem: "golang", name: m[1], version: m[2], purl: `pkg:golang/${m[1]}@${encodeURIComponent(m[2])}`, manifest: p });
      }
    } else if (UNPARSED.includes(file)) {
      unparsed.push(p);
    }
  }
  return { dependencies, unparsed };
}

// ── pack contents ────────────────────────────────────────────────────────────

function bundleKind(r: BundleResult): "publisher" | "observer" | "witness" {
  return r.observer ? "observer" : r.witness ? "witness" : "publisher";
}

function rekorUrl(logIndex: string): string {
  return `https://search.sigstore.dev/?logIndex=${logIndex}`;
}

/** Deterministic UUID (version 5 layout) so the same component always gets the same SBOM serial. */
function serialFor(digest: string): string {
  const h = sha256Hex(`workrr-sbom:${digest}`);
  const variant = ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16);
  return `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

export function buildEvidence(input: EvidenceInput, profile: string) {
  const primary = primaryBundle(input.bundles);
  const p = primary.result.statement!.predicate;
  const digest = `sha256:${input.verify.artifactDigest}`;
  const supplier = canonicalSource(p.source.uri);
  return {
    packFormat: PACK_FORMAT,
    profile,
    generator: { name: "workrr", version: VERSION },
    component: {
      name: p.artifact.name,
      type: p.artifact.type,
      digest,
      digestAlgorithm: p.artifact.digestAlgorithm,
      fileCount: p.artifact.fileCount,
      version: p.source.commit,
      source: p.source,
      supplier,
    },
    certificate: {
      statement: `${p.artifact.name} at ${digest} passed the checks in this pack at ${p.certifiedAt}, signed by ${primary.result.signerIdentity ?? "the certifier identity"}.`,
      level: input.verify.level,
      levelName: levelName(input.verify.level),
      band: input.verify.band,
      certifiedAt: p.certifiedAt,
      certifier: p.certifier,
      policy: { name: input.verify.policyName, digest: input.verify.policyDigest, status: input.verify.policyStatus },
      checks: p.checks,
      bundles: input.bundles
        .filter((b) => b.result.ok)
        .map((b) => ({
          file: b.file,
          kind: bundleKind(b.result),
          forge: b.result.forge,
          signerIdentity: b.result.signerIdentity,
          rekorLogIndexes: b.result.logIndexes ?? [],
          rekor: (b.result.logIndexes ?? []).map(rekorUrl),
        })),
      ledger: `https://github.com/workrr-trust/ledger/tree/main/certificates/sha256/${input.verify.artifactDigest}`,
    },
    publisher: input.publisher,
    dependencies: input.dependencies,
    componentIdentification: { name: p.artifact.name, version: p.source.commit, digest, supplier, sbom: "sbom.cdx.json" },
  };
}

export type Evidence = ReturnType<typeof buildEvidence>;

export function buildSbom(input: EvidenceInput, ev: Evidence) {
  const c = ev.component;
  const extRefs: { type: string; url: string; comment?: string }[] = [{ type: "vcs", url: c.supplier }];
  for (const b of ev.certificate.bundles) for (const url of b.rekor) extRefs.push({ type: "attestation", url, comment: `workrr trust certificate (${b.kind})` });
  const security = input.publisher.securityContact ?? input.publisher.securityPolicy;
  if (security) extRefs.push({ type: "security-contact", url: security.value });
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: serialFor(c.digest),
    version: 1,
    metadata: {
      timestamp: ev.certificate.certifiedAt,
      tools: { components: [{ type: "application", name: "workrr", version: VERSION }] },
      component: {
        "bom-ref": "component",
        type: "application",
        name: c.name,
        version: c.version,
        supplier: { name: c.supplier, url: [c.supplier] },
        hashes: [{ alg: "SHA-256", content: c.digest.slice("sha256:".length) }],
        externalReferences: extRefs,
        properties: [
          { name: "workrr:artifact-type", value: c.type },
          { name: "workrr:digest-algorithm", value: c.digestAlgorithm },
          { name: "workrr:source-path", value: c.source.path },
          ...(input.publisher.supportUntil ? [{ name: "workrr:support-until", value: input.publisher.supportUntil.value }] : []),
        ],
      },
    },
    components: [
      ...input.artifact.digest.files.map((f) => ({
        "bom-ref": `file:${f.path}`,
        type: "file",
        name: f.path,
        hashes: [{ alg: "SHA-256", content: f.sha256 }],
      })),
      ...input.dependencies.dependencies.map((d) => ({
        "bom-ref": `${d.purl}#${d.manifest}`,
        type: "library",
        name: d.name,
        ...(d.version ? { version: d.version } : {}),
        purl: d.purl,
        scope: "required",
        properties: [{ name: "workrr:manifest", value: d.manifest }, ...(d.range ? [{ name: "workrr:version-range", value: d.range }] : [])],
      })),
    ],
    dependencies: [{ ref: "component", dependsOn: input.dependencies.dependencies.map((d) => `${d.purl}#${d.manifest}`) }],
  };
}

export type ClauseStatus = "evidenced" | "partial" | "publisher-declared" | "missing" | "not-covered";
export type Clause = { id: string; title: string; status: ClauseStatus; evidence: string[]; note?: string; remains: string };

export const CRA_PROFILE = "cra-v0.1";

export function craClauses(input: EvidenceInput, ev: Evidence): Clause[] {
  const pub = input.publisher;
  const declared = (d: Declaration | undefined) => (d ? `${d.value} (from ${d.from}${d.coveredByCertificate ? ", covered by the certificate" : ", not covered by the certificate"})` : undefined);
  const security = [declared(pub.securityPolicy), declared(pub.securityContact)].filter(Boolean).join("; ");
  const checks = ev.certificate.checks;
  return [
    {
      id: "art-13-5",
      title: "Art. 13(5): due diligence when integrating third-party components",
      status: "evidenced",
      evidence: ["evidence.json#/certificate", "certificate/", "verify.sh"],
      note: `${ev.certificate.levelName ?? ev.certificate.level} certificate verified: signature, Rekor entry, signer identity and digest match. Provenance ${checks.provenance.result}, policy ${checks.policy.result}, scan ${checks.scan.result}, tests ${checks.tests.result}.`,
      remains: "Decide whether this evidence is enough for your product's risk, and record that decision (statement-template.md).",
    },
    {
      id: "annex-i-1-2-f",
      title: "Annex I Part I(2)(f): integrity of programs and configuration",
      status: "partial",
      evidence: ["evidence.json#/component/digest", "sbom.cdx.json#/components"],
      note: "The digest and per-file hashes let you check that the component you ship is byte-for-byte the one certified.",
      remains: "Integrity protection of the product as a whole, including how it installs and updates this component.",
    },
    {
      id: "annex-i-2-1",
      title: "Annex I Part II(1): software bill of materials",
      status: "partial",
      evidence: ["sbom.cdx.json"],
      note: `Component SBOM: ${input.artifact.digest.files.length} file(s), ${input.dependencies.dependencies.length} declared top-level dependenc${input.dependencies.dependencies.length === 1 ? "y" : "ies"}.${input.dependencies.unparsed.length ? ` Not parsed: ${input.dependencies.unparsed.join(", ")}.` : ""}`,
      remains: "Include this component in your product's SBOM.",
    },
    {
      id: "annex-i-2-3",
      title: "Annex I Part II(3): effective and regular tests and reviews",
      status: "partial",
      evidence: ["evidence.json#/certificate/checks"],
      note: `Point-in-time results at ${ev.certificate.certifiedAt}: scan ruleset ${checks.scan.rulesetVersion}, test suite ${checks.tests.result === "none" ? "not declared" : checks.tests.result}.`,
      remains: "Regular testing of your product, and fresh evidence for each new version of this component.",
    },
    {
      id: "annex-i-2-2-4",
      title: "Annex I Part II(2) and (4), Art. 13(6): vulnerability handling, disclosure and upstream reporting",
      status: security ? "publisher-declared" : "missing",
      evidence: ["evidence.json#/publisher", "verification.json#/revocationChecked"],
      note: security ? `Where to report a vulnerability in this component: ${security}.` : "The publisher declared no security policy or contact.",
      remains: "Handle vulnerabilities in your product, report ones you find in this component to its publisher, and watch for revocation of this certificate.",
    },
    {
      id: "annex-i-2-5",
      title: "Annex I Part II(5): coordinated vulnerability disclosure policy",
      status: pub.securityPolicy ? "publisher-declared" : "missing",
      evidence: ["evidence.json#/publisher/securityPolicy"],
      note: pub.securityPolicy ? `Publisher policy: ${declared(pub.securityPolicy)}.` : "The publisher declared no disclosure policy.",
      remains: "Your own product's disclosure policy.",
    },
    {
      id: "art-13-8",
      title: "Art. 13(8): support period",
      status: pub.supportUntil ? "publisher-declared" : "missing",
      evidence: ["evidence.json#/publisher/supportUntil"],
      note: pub.supportUntil ? `Publisher states support until ${declared(pub.supportUntil)}.` : "The publisher declared no support period.",
      remains: "Your product's support period, which must account for this component's.",
    },
    {
      id: "art-13-13",
      title: "Art. 13(13): technical documentation kept for at least 10 years",
      status: "partial",
      evidence: ["certificate/", "verify.sh"],
      note: "The pack is self-contained, and the certificate stays verifiable against Sigstore's public log and the public ledger.",
      remains: "Keep this pack with your technical documentation (Annex VII) for 10 years after the product is placed on the market, or the support period if longer.",
    },
    {
      id: "art-14",
      title: "Art. 14: reporting actively exploited vulnerabilities and severe incidents",
      status: "partial",
      evidence: ["evidence.json#/componentIdentification"],
      note: "Component identification (name, version, digest, supplier) ready to copy into a report.",
      remains: "Early warning, notification and final report through the single reporting platform. Only you can file them.",
    },
    {
      id: "manufacturer-acts",
      title: "Art. 13(2)–(3) risk assessment, Art. 28 EU declaration of conformity, Arts. 29–30 CE marking, Art. 32 conformity assessment",
      status: "not-covered",
      evidence: [],
      remains: "These are your own legal acts. No evidence pack can supply them.",
    },
  ];
}

const DISCLAIMER =
  "This pack is evidence for the manufacturer's own assessment. It is not a conformity assessment, an EU declaration of conformity or a CE marking, and it does not state that the component is secure. Article references follow Regulation (EU) 2024/2847 as published in the Official Journal; this mapping is an engineering aid, not legal advice.";

function esc(s: unknown): string {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

function link(url: string): string {
  return /^(https:\/\/|mailto:)/.test(url) ? `<a href="${esc(url)}">${esc(url)}</a>` : esc(url);
}

const STATUS_LABEL: Record<ClauseStatus, string> = {
  evidenced: "Evidenced",
  partial: "Partial",
  "publisher-declared": "Publisher-declared",
  missing: "Not declared",
  "not-covered": "Not covered",
};

function summaryHtml(input: EvidenceInput, ev: Evidence, clauses: Clause[]): string {
  const c = ev.component;
  const ck = ev.certificate.checks;
  const rows = (pairs: [string, string][]) => pairs.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${v}</td></tr>`).join("\n");
  const sources = `${esc(c.source.uri)} @ <code>${esc(c.source.commit)}</code>${c.source.path && c.source.path !== "." ? `, <code>${esc(c.source.path)}</code>` : ""}`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Component evidence: ${esc(c.name)}</title>
<style>
  :root { color-scheme: light; --ink: #1d2320; --muted: #5b655f; --line: #d9dfdb; --soft: #f4f6f5; }
  body { margin: 0; background: #fff; color: var(--ink); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { max-width: 860px; margin: 0 auto; padding: 32px 16px 48px; }
  h1 { font-size: 24px; margin: 0 0 4px; } h2 { font-size: 17px; margin: 28px 0 8px; }
  .sub { color: var(--muted); margin: 0 0 20px; }
  .claim { background: var(--soft); border-left: 3px solid var(--ink); padding: 12px 14px; margin: 0 0 8px; }
  table { width: 100%; border-collapse: collapse; margin: 0 0 8px; } th, td { text-align: left; vertical-align: top; padding: 7px 8px; border-bottom: 1px solid var(--line); }
  th { width: 30%; font-weight: 600; } code { font: 13px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
  .status { white-space: nowrap; font-weight: 600; } .fine { color: var(--muted); font-size: 13px; }
  .clauses th { width: 34%; } .clauses td.remains { color: var(--muted); }
  @media print { main { padding: 0; } a { color: inherit; } }
</style>
</head>
<body>
<main>
<h1>Component evidence for EU Cyber Resilience Act due diligence</h1>
<p class="sub">Evidence pack ${esc(PACK_FORMAT)}, profile ${esc(ev.profile)}, built ${esc(input.builtAt)} by workrr ${esc(VERSION)}</p>
<p class="claim">${esc(ev.certificate.statement)}</p>
<p class="fine">${esc(DISCLAIMER)}</p>

<h2>Component</h2>
<table>
${rows([
  ["Name", esc(c.name)],
  ["Type", esc(c.type)],
  ["Digest", `<code>${esc(c.digest)}</code> (${esc(c.digestAlgorithm)}, ${esc(c.fileCount)} file(s))`],
  ["Source", sources],
  ["Supplier", link(c.supplier)],
])}
</table>

<h2>Certificate</h2>
<table>
${rows([
  ["Level", `${esc(ev.certificate.levelName ?? ev.certificate.level)}${ev.certificate.band ? `, band ${esc(ev.certificate.band)}` : ""}`],
  ["Certified at", esc(ev.certificate.certifiedAt)],
  ["Provenance", esc(ck.provenance.result)],
  ["Policy", `${esc(ck.policy.result)} (${esc(ck.policy.policyName ?? "unnamed")}, <code>${esc(ck.policy.policyDigest)}</code>)`],
  ["Scan", `${esc(ck.scan.result)}, ruleset ${esc(ck.scan.rulesetVersion)}, ${ck.scan.findings.length} finding(s)`],
  ["Tests", esc(ck.tests.result === "none" ? "no test suite declared" : ck.tests.result)],
  ...ev.certificate.bundles.map((b): [string, string] => [`Signed (${b.kind})`, `${esc(b.signerIdentity)}<br>${b.rekor.map(link).join("<br>")}`]),
  ["Ledger", link(ev.certificate.ledger)],
])}
</table>

<h2>Publisher declarations</h2>
<table>
${rows([
  ["Support until", input.publisher.supportUntil ? `${esc(input.publisher.supportUntil.value)} <span class="fine">(${esc(input.publisher.supportUntil.from)})</span>` : "Not declared"],
  ["Security policy", input.publisher.securityPolicy ? `${link(input.publisher.securityPolicy.value)} <span class="fine">(${esc(input.publisher.securityPolicy.from)}${input.publisher.securityPolicy.coveredByCertificate ? "" : ", not covered by the certificate"})</span>` : "Not declared"],
  ["Security contact", input.publisher.securityContact ? link(input.publisher.securityContact.value) : "Not declared"],
])}
</table>
<p class="fine">Declarations are the publisher's own statements. The certifier does not check them.</p>

<h2>Regulation (EU) 2024/2847 clauses</h2>
<table class="clauses">
<tr><th>Clause</th><th>Status and evidence</th><th>Remains with the manufacturer</th></tr>
${clauses.map((cl) => `<tr><th>${esc(cl.title)}</th><td><span class="status">${esc(STATUS_LABEL[cl.status])}</span>${cl.note ? `<br>${esc(cl.note)}` : ""}</td><td class="remains">${esc(cl.remains)}</td></tr>`).join("\n")}
</table>

<h2>Verify it yourself</h2>
<p>Check out <code>${esc(c.source.path)}</code> of ${esc(c.source.uri)} at commit <code>${esc(c.source.commit)}</code>, then run <code>sh verify.sh &lt;that directory&gt;</code>. It re-checks the signature, the Rekor entry, the signer identity and the digest with the open-source workrr CLI, without trusting this pack or workrr.</p>
</main>
</body>
</html>
`;
}

function verifyScript(ev: Evidence): string {
  const bundles = ev.certificate.bundles.map((b) => ` --bundle "$here/${b.file}"`).join("");
  return `#!/bin/sh
# Re-verifies the certificate(s) in this evidence pack with the open-source workrr CLI (Node.js 22+).
# Usage: sh verify.sh <dir>
#   <dir> is ${ev.component.source.path} from ${ev.component.source.uri}
#   at commit ${ev.component.source.commit}.
set -eu
[ $# -eq 1 ] || { echo "usage: sh verify.sh <component dir>" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
exec npx --yes @workrr-trust/certify@${VERSION} verify "$1"${bundles} --source ${ev.component.supplier}
`;
}

function statementTemplate(ev: Evidence): string {
  return `# Component due-diligence record (template)

Fill this in and keep it with your technical documentation. It is your record, not
workrr's, and nothing in it has been signed.

| | |
|---|---|
| Manufacturer | _______________________ |
| Product and version | _______________________ |
| Component | ${ev.component.name} |
| Component digest | \`${ev.component.digest}\` |
| Component source | ${ev.component.source.uri} @ \`${ev.component.source.commit}\` |
| Evidence pack | ${PACK_FORMAT}, profile ${ev.profile} |

## Assessment

- Evidence reviewed: this evidence pack (summary.html, evidence.json, mapping.cra.json, sbom.cdx.json), re-verified with verify.sh on ____ (date).
- Risk of this component in our product: _______________________
- Gaps from mapping.cra.json and how we address them: _______________________
- Decision: [ ] integrate  [ ] integrate with mitigations: ______  [ ] do not integrate

Reviewed by: ______________________  Date: __________
`;
}

/** Builds the pack for a profile. Only call with a verification that succeeded. */
export function buildPack(input: EvidenceInput, profile: Profile): Pack {
  if (!input.verify.ok || input.verify.status !== "verified") throw new Error("the certificate did not verify; no evidence pack was built");
  const ev = buildEvidence(input, CRA_PROFILE);
  const clauses = craClauses(input, ev);
  const json = (v: unknown) => JSON.stringify(v, null, 2) + "\n";
  const pack: Pack = new Map();
  pack.set("summary.html", summaryHtml(input, ev, clauses));
  pack.set("evidence.json", json(ev));
  pack.set(`mapping.${profile}.json`, json({
    profile: CRA_PROFILE,
    regulation: "Regulation (EU) 2024/2847 (Cyber Resilience Act)",
    component: ev.component.digest,
    disclaimer: DISCLAIMER,
    clauses,
  }));
  pack.set("sbom.cdx.json", json(buildSbom(input, ev)));
  for (const b of input.bundles.filter((x) => x.result.ok)) pack.set(b.file, b.bytes);
  pack.set("verify.sh", verifyScript(ev));
  pack.set("statement-template.md", statementTemplate(ev));
  pack.set("verification.json", json({
    builtAt: input.builtAt,
    generator: { name: "workrr", version: VERSION },
    status: input.verify.status,
    level: input.verify.level,
    revocationChecked: input.revocationChecked,
    notes: input.verify.notes,
  }));
  return pack;
}
