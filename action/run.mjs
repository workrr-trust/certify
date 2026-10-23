// Entrypoint for action/verify.sh. Uses the built-in trust policy only.
// A workflow input cannot swap in a weaker signer.
import { appendFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { gate, parseBundles, parseLevel } from "./gate.mjs";
import { DEFAULT_TRUST_POLICY } from "../dist/trust-policy.js";
import { verificationHeadline, verifyArtifact } from "../dist/verify.js";

function oneLine(value) {
  return String(value ?? "").replace(/[\r\n]/g, " ").trim();
}

export function outputBody(fields) {
  return Object.entries(fields).map(([key, value]) => `${key}=${oneLine(value)}`).join("\n") + "\n";
}

// Workflow commands treat %, CR, and LF as syntax. Bundle fields are untrusted.
function workflowError(message) {
  const escaped = oneLine(message).replace(/%/g, "%25");
  return `::error::${escaped}`;
}

function signerOf(result) {
  return (result?.bundles ?? [])
    .filter((bundle) => bundle.ok && bundle.signerIdentity)
    .map((bundle) => bundle.signerIdentity)
    .join(",");
}

function fieldsOf(decision, result) {
  return {
    verified: decision.verified ? "true" : "false",
    level: decision.level,
    source: result?.source ?? "",
    "policy-name": result?.policyName ?? "",
    "policy-digest": result?.policyDigest ?? "",
    "artifact-digest": result?.artifactDigest ? `sha256:${result.artifactDigest}` : "",
    signer: signerOf(result),
    headline: decision.headline,
  };
}

function summaryOf(decision, result, minimum, source) {
  const digest = result?.artifactDigest ? `sha256:${result.artifactDigest}` : "(none)";
  const lines = [
    "### workrr verify",
    "",
    `- verified: **${decision.verified ? "true" : "false"}**`,
    `- level: ${decision.level || "(none)"} (required ${minimum || "(unset)"})`,
    `- publisher: ${result?.source || "(none)"}`,
    `- required source: ${source || "(none)"}`,
    `- policy: ${result?.policyName || "(none)"}${result?.policyDigest ? ` ${result.policyDigest}` : ""}`,
    `- artifact: \`${digest}\``,
    `- signer: ${signerOf(result) || "(none)"}`,
    `- ${decision.headline}`,
  ];
  for (const note of decision.notes) lines.push(`- note: ${note}`);
  return lines.join("\n") + "\n";
}

function report(decision, result, minimum) {
  const lines = [
    `artifact   ${result?.artifactDigest ? `sha256:${result.artifactDigest}` : "(none)"}`,
    `publisher  ${result?.source ?? "(none)"}`,
    `policy     ${result?.policyName ?? "(none)"}${result?.policyDigest ? ` ${result.policyDigest}` : ""}`,
    `signer     ${signerOf(result) || "(none)"}`,
    `level      ${decision.level || "(none)"} (required ${minimum || "(unset)"})`,
    decision.headline,
    ...decision.notes.map((note) => `  note: ${note}`),
    "",
  ];
  return lines.join("\n");
}

async function emit(env, decision, result, minimum, source) {
  const body = outputBody(fieldsOf(decision, result));
  if (env.GITHUB_OUTPUT) await appendFile(env.GITHUB_OUTPUT, body);
  if (env.GITHUB_STEP_SUMMARY) await appendFile(env.GITHUB_STEP_SUMMARY, summaryOf(decision, result, minimum, source));
  process.stderr.write(report(decision, result, minimum));
  if (!decision.verified) process.stdout.write(`${workflowError(`${decision.headline}. ${decision.notes.join(" | ")}`)}\n`);
}

const empty = {
  verified: false,
  level: "",
  headline: "NOT VERIFIED",
  notes: [],
};

export async function main(env = process.env) {
  const path = env.WORKRR_PATH ?? "";
  const source = env.WORKRR_SOURCE ?? "";
  let minimum = "";
  let bundles;
  try {
    if (!String(path).trim()) throw new Error("path is required");
    if (!String(source).trim()) throw new Error("source is required");
    minimum = parseLevel(env.WORKRR_LEVEL);
    bundles = parseBundles(env.WORKRR_BUNDLE);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const decision = { ...empty, notes: [message] };
    await emit(env, decision, undefined, env.WORKRR_LEVEL ?? "", source);
    return 2;
  }

  let result;
  try {
    result = await verifyArtifact(path, bundles, DEFAULT_TRUST_POLICY, source);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const decision = { ...empty, notes: [message] };
    await emit(env, decision, undefined, minimum, source);
    return 1;
  }

  const decision = gate({ ...result, headline: verificationHeadline(result) }, minimum);
  await emit(env, decision, result, minimum, source);
  return decision.verified ? 0 : 1;
}

const entry = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (import.meta.url === entry) {
  main().then(
    (code) => process.exit(code),
    (error) => {
      process.stderr.write(`workrr: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exit(2);
    },
  );
}
