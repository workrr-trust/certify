// Wrap a canonical payload and a cosign bundle into the signed-blob envelope
// the trust API stores and verifiers fetch. Does not verify the bundle.
import { readFileSync, writeFileSync } from "node:fs";

const [payloadType, payloadPath, bundlePath, outPath] = process.argv.slice(2);
if (!payloadType || !payloadPath || !bundlePath || !outPath) {
  console.error("usage: pack-signed-blob.mjs <payloadType> <payload.json> <bundle.sigstore.json> <out.json>");
  process.exit(2);
}
const payload = readFileSync(payloadPath);
const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
const blob = {
  mediaType: "application/vnd.workrr.signed-blob+json;version=1",
  payloadType,
  payload: payload.toString("base64"),
  signature: { algorithm: "sigstore", bundle },
};
writeFileSync(outPath, JSON.stringify(blob) + "\n");
console.log(`wrote ${outPath}`);
