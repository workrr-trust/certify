// Render a canonical revocation entry and the checkpoint that covers it.
// The revoke workflow signs both files. Sequence numbers only go up.
import { mkdirSync, writeFileSync } from "node:fs";
import { canonicalJson, sha256Hex } from "../dist/digest.js";
import { GENESIS_PREV } from "../dist/trust-feed.js";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, arg, i, all) => {
    if (arg.startsWith("--")) pairs.push([arg.slice(2), all[i + 1]]);
    return pairs;
  }, []),
);
const sequence = Number(args.sequence);
const prev = args.prev;
const reason = args.reason;
const timestamp = args.timestamp;
const signer = args.signer;
const digest = args["artifact-digest"] || "";
const logIndex = args["log-index"] || "";
const outDir = args["out-dir"] || ".";
if (!Number.isInteger(sequence) || sequence < 1) throw new Error("--sequence must be an integer >= 1");
if (!/^[0-9a-f]{64}$/.test(prev)) throw new Error("--prev must be 64 lowercase hex characters");
if ((digest === "") === (logIndex === "")) throw new Error("pass exactly one of --artifact-digest or --log-index");
if (digest && !/^[0-9a-f]{64}$/.test(digest)) throw new Error("--artifact-digest must be 64 lowercase hex characters");
if (logIndex && !/^(0|[1-9][0-9]*)$/.test(logIndex)) throw new Error("--log-index must be a decimal integer");
const subject = digest ? { artifactDigest: digest } : { logIndex };
const entry = canonicalJson({
  schema: "workrr-revocation-v1",
  sequence,
  subject,
  reason,
  timestamp,
  signer,
  prev,
});
const checkpoint = canonicalJson({
  schema: "workrr-revocation-checkpoint-v1",
  sequence,
  head: sha256Hex(entry),
  timestamp,
  signer,
});
mkdirSync(outDir, { recursive: true });
writeFileSync(`${outDir}/entry.json`, entry);
writeFileSync(`${outDir}/checkpoint.json`, checkpoint);
console.log(`wrote ${outDir}/entry.json and checkpoint.json (prev ${prev === GENESIS_PREV ? "genesis" : prev.slice(0, 12)})`);
