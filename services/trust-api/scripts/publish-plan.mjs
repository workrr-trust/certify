#!/usr/bin/env node
// Print the wrangler commands that publish one signed blob.
// This process does not talk to Cloudflare and does not check the Sigstore signature.
// The trust-policy workflow already verified the bundle. Clients verify it again.
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const BUCKET = "workrr-trust-blobs";
const DATABASE = "workrr-trust";
const POLICY_TYPE = "application/vnd.workrr.trust-policy+json";
const ENTRY_TYPE = "application/vnd.workrr.revocation-entry+json";
const CHECKPOINT_TYPE = "application/vnd.workrr.revocation-checkpoint+json";
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const HEX64 = /^[0-9a-f]{64}$/;

export function sqlString(value) {
  if (typeof value !== "string" || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error("refusing a SQL value with control characters");
  }
  return `'${value.replaceAll("'", "''")}'`;
}

function readBlob(path) {
  const blob = JSON.parse(readFileSync(path, "utf8"));
  if (blob?.mediaType !== "application/vnd.workrr.signed-blob+json;version=1") {
    throw new Error(`${path} is not a signed blob`);
  }
  if (typeof blob.payload !== "string") throw new Error(`${path} has no payload`);
  const payload = Buffer.from(blob.payload, "base64").toString("utf8");
  return { blob, payload: JSON.parse(payload) };
}

function sequenceOf(value, label) {
  if (!Number.isInteger(value) || value < 1) throw new Error(`${label} sequence must be an integer >= 1`);
  return value;
}

export function planPolicy(file) {
  const { blob, payload } = readBlob(file);
  if (blob.payloadType !== POLICY_TYPE) throw new Error(`${file} is not a trust policy`);
  if (payload.schema !== "workrr-trust-policy-v1") throw new Error("payload schema is not workrr-trust-policy-v1");
  const sequence = sequenceOf(payload.sequence, "policy");
  if (!TIMESTAMP.test(payload.issuedAt)) throw new Error("policy issuedAt is not YYYY-MM-DDThh:mm:ssZ");
  const key = `policy/${sequence}.json`;
  const sql =
    `INSERT INTO policies (sequence, issued_at, r2_key)\n` +
    `VALUES (${sequence}, ${sqlString(payload.issuedAt)}, ${sqlString(key)});\n`;
  return {
    sequence,
    issuedAt: payload.issuedAt,
    key,
    sql,
    commands: [
      `npx wrangler r2 object put ${BUCKET}/${key} --file ${file} --content-type application/json --remote`,
      `npx wrangler d1 execute ${DATABASE} --remote --yes --file publish.sql`,
    ],
  };
}

export function planRevocation(entryFile, checkpointFile) {
  const entry = readBlob(entryFile);
  const checkpoint = readBlob(checkpointFile);
  if (entry.blob.payloadType !== ENTRY_TYPE) throw new Error(`${entryFile} is not a revocation entry`);
  if (checkpoint.blob.payloadType !== CHECKPOINT_TYPE) throw new Error(`${checkpointFile} is not a revocation checkpoint`);
  const body = entry.payload;
  const point = checkpoint.payload;
  if (body.schema !== "workrr-revocation-v1") throw new Error("entry schema is not workrr-revocation-v1");
  if (point.schema !== "workrr-revocation-checkpoint-v1") throw new Error("checkpoint schema is not workrr-revocation-checkpoint-v1");
  const sequence = sequenceOf(body.sequence, "entry");
  if (point.sequence !== sequence) throw new Error("checkpoint sequence must equal the entry sequence");
  if (!TIMESTAMP.test(body.timestamp)) throw new Error("entry timestamp is not YYYY-MM-DDThh:mm:ssZ");
  const digest = body.subject?.artifactDigest ?? null;
  const logIndex = body.subject?.logIndex ?? null;
  if ((digest === null) === (logIndex === null)) throw new Error("entry subject must set exactly one of artifactDigest or logIndex");
  if (digest !== null && !HEX64.test(digest)) throw new Error("artifactDigest must be 64 lowercase hex characters");
  if (logIndex !== null && !/^(0|[1-9][0-9]*)$/.test(logIndex)) throw new Error("logIndex must be a decimal integer");
  if (typeof body.reason !== "string" || body.reason.length < 1 || body.reason.length > 200) {
    throw new Error("reason must be 1–200 characters");
  }
  const key = `revocations/${sequence}.json`;
  const checkpointKey = "revocations/checkpoint.json";
  const sql =
    `INSERT INTO revocations (sequence, artifact_digest, log_index, reason, timestamp, signer, r2_key)\n` +
    `VALUES (${sequence}, ${digest === null ? "NULL" : sqlString(digest)}, ${logIndex === null ? "NULL" : sqlString(logIndex)}, ${sqlString(body.reason)}, ${sqlString(body.timestamp)}, ${sqlString(body.signer)}, ${sqlString(key)});\n` +
    `\n` +
    `INSERT INTO revocation_checkpoint (id, sequence, r2_key) VALUES (1, ${sequence}, ${sqlString(checkpointKey)})\n` +
    `ON CONFLICT(id) DO UPDATE SET sequence = excluded.sequence, r2_key = excluded.r2_key;\n`;
  return {
    sequence,
    key,
    checkpointKey,
    sql,
    commands: [
      `npx wrangler r2 object put ${BUCKET}/${key} --file ${entryFile} --content-type application/json --remote`,
      `npx wrangler r2 object put ${BUCKET}/${checkpointKey} --file ${checkpointFile} --content-type application/json --remote`,
      `npx wrangler d1 execute ${DATABASE} --remote --yes --file publish.sql`,
    ],
  };
}

function main(argv) {
  const [kind, ...rest] = argv;
  const outFlag = rest.indexOf("--out");
  const out = outFlag === -1 ? "publish.sql" : rest[outFlag + 1];
  const args = rest.filter((arg, i) => outFlag === -1 || (i !== outFlag && i !== outFlag + 1));
  let plan;
  if (kind === "policy") plan = planPolicy(args[0]);
  else if (kind === "revocation") plan = planRevocation(args[0], args[1]);
  else {
    console.error("usage: publish-plan.mjs policy <signed-policy.json> [--out publish.sql]");
    console.error("       publish-plan.mjs revocation <entry.signed.json> <checkpoint.signed.json> [--out publish.sql]");
    process.exit(2);
  }
  writeFileSync(out, plan.sql);
  console.log(`wrote ${out}`);
  console.log("Review the SQL. These commands write to production:");
  for (const command of plan.commands) console.log(command);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(`publish-plan: ${error.message}`);
    process.exit(2);
  }
}
