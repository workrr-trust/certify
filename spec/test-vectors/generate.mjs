// Regenerates expected.json from the TypeScript reference. Run only for an
// intentional spec or ruleset change, review the diff line by line, and make the
// Go implementation pass the new vectors in the same change.
//   cd certify && npm run build && node spec/test-vectors/generate.mjs
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { evaluate, readVectors, vectorsDir } from "./vectors.mjs";

const { cases } = await readVectors();
const expected = await evaluate(cases);
// Escape non-ASCII so invisible characters stay visible in review.
const ascii = JSON.stringify(expected, null, 2).replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
await writeFile(join(vectorsDir, "expected.json"), ascii + "\n");
console.log(`wrote expected.json (${Object.keys(expected.artifacts).length} artifacts)`);
