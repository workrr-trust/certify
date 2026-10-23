#!/usr/bin/env node
// Keyless Sigstore attestation helper for GitLab CI (`.gitlab-ci.yml`).
// Signs an in-toto v1 statement with Fulcio using SIGSTORE_ID_TOKEN and logs
// the DSSE envelope to public Rekor, writing a Sigstore v0.3 bundle JSON.
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { parseArgs } from "node:util";
import { attest } from "sigstore";
import { PREDICATE_TYPE } from "../dist/certify.js";

const INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";

export function parseGitLabSignArgs(argv = process.argv.slice(2)) {
  const { values } = parseArgs({
    args: argv,
    options: {
      statement: { type: "string" },
      out: { type: "string" },
      "id-token": { type: "string" },
    },
  });
  if (!values.statement || !values.out) {
    throw new Error("usage: gitlab-sign.mjs --statement <statement.json> --out <certificate.sigstore.json>");
  }
  return {
    statementPath: values.statement,
    outPath: values.out,
    identityToken: values["id-token"] ?? process.env.SIGSTORE_ID_TOKEN,
  };
}

export async function signStatementWithSigstore({
  statementPath,
  outPath,
  identityToken,
  attestFn = attest,
}) {
  if (!identityToken) {
    throw new Error("missing SIGSTORE_ID_TOKEN (configure id_tokens.SIGSTORE_ID_TOKEN.aud = sigstore)");
  }
  const raw = await readFile(statementPath, "utf8");
  const parsed = JSON.parse(raw);
  if (parsed?._type !== "https://in-toto.io/Statement/v1" || parsed?.predicateType !== PREDICATE_TYPE) {
    throw new Error(`refusing to sign unexpected statement predicateType: ${parsed?.predicateType ?? "unknown"}`);
  }
  if (!Array.isArray(parsed.subject) || !parsed.subject[0]?.digest?.sha256) {
    throw new Error("statement is missing subject sha256 digest");
  }
  const bundle = await attestFn(Buffer.from(raw, "utf8"), INTOTO_PAYLOAD_TYPE, {
    identityToken,
  });
  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, JSON.stringify(bundle, null, 2) + "\n", "utf8");
  return bundle;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const args = parseGitLabSignArgs();
    await signStatementWithSigstore(args);
  } catch (err) {
    console.error(`workrr gitlab-sign: ${(err && err.message) || err}`);
    process.exit(1);
  }
}
