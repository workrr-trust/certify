// Level names say how much scrutiny an artifact got. The wire values in signed
// predicates are unchanged from v0.1 (scanned, banded, silver, gold); these are the
// names people read.
//   Scanned     workrr read a public commit; checks passed; not signed by the maintainer
//   Signed      the maintainer's own CI signed it; checks passed
//   Tested      Signed, and the artifact's tests passed in an isolated job
//   Reproduced  two independent forges certified the same digest
export type WireLevel = "scanned" | "banded" | "silver" | "gold";

export const LEVEL_NAMES: Record<WireLevel, string> = {
  scanned: "Scanned",
  banded: "Signed",
  silver: "Tested",
  gold: "Reproduced",
};

const ALIASES: Record<string, WireLevel> = {
  scanned: "scanned",
  banded: "banded",
  signed: "banded",
  silver: "silver",
  tested: "silver",
  gold: "gold",
  reproduced: "gold",
};

export function levelName(level: string | undefined): string | undefined {
  return level && level in LEVEL_NAMES ? LEVEL_NAMES[level as WireLevel] : undefined;
}

// Accepts a display name or a wire value, any case.
export function parseLevel(input: string): WireLevel | undefined {
  return ALIASES[input.trim().toLowerCase()];
}
