// Consumer-gate rules for the root action. Cryptographic verification stays in
// src/verify.ts; this only decides whether that result meets the caller's minimum.

const RANK = { banded: 1, silver: 2, gold: 3 };

export function parseLevel(input) {
  const level = String(input ?? "").trim().toLowerCase();
  if (!level) return "silver";
  if (!Object.hasOwn(RANK, level)) throw new Error("level must be banded, silver, or gold");
  return level;
}

export function parseBundles(input) {
  const bundles = String(input ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (bundles.length === 0) throw new Error("bundle is required");
  return bundles;
}

export function levelMeets(actual, minimum) {
  const got = RANK[actual];
  const need = RANK[minimum];
  if (!got || !need) return false;
  return got >= need;
}

// result is a VerifyResult plus an optional headline from verificationHeadline.
// A certificate above the minimum passes. A certificate below it fails closed
// and still reports the level the verifier actually found.
export function gate(result, minimum) {
  const notes = [...(result.notes ?? [])];
  for (const bundle of result.bundles ?? []) {
    if (!bundle.ok && bundle.error) notes.push(`${bundle.bundlePath}: ${bundle.error}`);
  }
  if (!result.ok || !result.level || !levelMeets(result.level, minimum)) {
    if (result.ok && result.level && !levelMeets(result.level, minimum)) {
      notes.push(`level ${result.level} is below required ${minimum}`);
    }
    return {
      verified: false,
      level: result.ok && result.level ? result.level : "",
      headline: result.ok && result.level ? "NOT VERIFIED" : (result.headline ?? "NOT VERIFIED"),
      notes,
    };
  }
  return {
    verified: true,
    level: result.level,
    headline: `VERIFIED · level ${result.level}`,
    notes,
  };
}
