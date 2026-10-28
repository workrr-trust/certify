# Signed findings and the change watcher

workrr trust is a watchdog, not just a directory. A public scan that passes signs
a **Scanned** certificate (docs/public-scans.md). A public scan that fails a
security check signs a **finding**, so failures are as public and as verifiable
as passes. A watcher re-scans each target when its path changes, so the record
follows the code.

## Level names

Levels are named for how much scrutiny an artifact got. The wire values inside
signed predicates are unchanged from v0.1, and verifiers print both.

| Name | Wire value | What happened |
|---|---|---|
| Scanned | `scanned` | workrr read a public commit. Static checks passed. Not signed by the maintainer. |
| Signed | `banded` | The maintainer's own CI signed it. Static checks passed. |
| Tested | `silver` | Signed, and the artifact's tests passed in an isolated job. |
| Reproduced | `gold` | Two independent forges certified the same digest. |

**Flagged** sits outside the ladder: a signed finding for the latest commit. The
A–E band stays a quality grade within Scanned and Signed.

`--min-level` and the action's `level` input accept either name.

## What a finding says

> workrr's open-source certifier, at release tag `vX.Y.Z`, read `<path>` in
> `<repo>` at commit `<sha>`, computed this digest, and these checks failed:
> `<rule> <file>:<line>`, ….

It is stated as fact. It never says "malicious", "unsafe" or "scam": the scanner
matches patterns, and some matches are innocent (a README that tells people to run
`curl … | sh` matches WT005).

A finding is made only for security-relevant failures:

- a high or critical scan rule (WT001–WT003, WT005–WT008);
- a forbidden file type (compiled binaries);
- a symlink that points outside the artifact.

Layout problems (missing frontmatter, an oversized folder) make an artifact
uncertifiable but are not findings, and nothing is signed for them.

**Kind.** A finding is `concealment` when a failing rule is one whose matches
are rarely accidental: Unicode tag characters (WT002) or bidirectional overrides
(WT003), in a file that is not a test or fixture (sanitizers keep such characters
in their tests on purpose) and not bundled or minified code (`dist/`, `build/`,
`*.min.js`, `*.bundle.js`: libraries such as mermaid ship these characters in their
own text handling). Those matches still fail the scan; they are listed as `check`. Everything else is `check`, including the phrase rules
WT007 (instructions to keep something from the user) and WT008 (instructions in a
hidden HTML comment): wording matches innocent text too often to be called
concealment. Listings show concealment findings at once. A `check` finding gets a
short fix window before a listing ranks it as Flagged.

**Tests and fixtures.** The rules about text an agent reads as instructions
(WT001, WT007, WT008) skip tests, fixtures and snapshots (`test/`, `tests/`,
`__tests__/`, `fixtures/`, `__snapshots__/`, `test_*`, `test-*`, `*.test.*`,
`*.spec.*`, `*.snap`, `*.snapshot`): scanners and prompt-injection defences keep
their samples there. The shell, credential and character rules still apply.

## Format

A finding is an in-toto Statement with its own predicate type, so no verifier can
mistake it for a certificate (`verify` rejects any other predicate type):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "<artifact>", "digest": { "sha256": "<hex>" } }],
  "predicateType": "https://trust.workrr.ai/finding/v0.1",
  "predicate": {
    "artifact": { "name": "…", "type": "skill", "digestAlgorithm": "…", "fileCount": 3 },
    "source": { "uri": "https://github.com/<owner>/<repo>", "commit": "<40-hex>", "path": "<path>" },
    "checks": { "provenance": {…}, "policy": {…}, "scan": {…}, "tests": { "result": "none" } },
    "kind": "concealment" | "check",
    "findings": [{ "check": "scan", "rule": "WT005", "severity": "high", "file": "SKILL.md", "line": 12, "detail": "WT005 (high)" }],
    "certifier": { "name": "workrr-certify", "version": "0.1.5", "runtime": "github-actions" },
    "scannedAt": "<ISO 8601>"
  }
}
```

Only an observer signer (`scan.yml` at a pinned release, running in
`workrr-trust/certify`) can issue findings.

## Reproducible, so it is evidence and not opinion

```sh
git clone https://github.com/<owner>/<repo> && git -C <repo> checkout <commit>
workrr verify-finding <repo>/<path> --bundle finding.sigstore.json
```

`verify-finding` checks the signature, Rekor inclusion and observer signer, then
re-runs the same checks on the checkout and requires the same failures (same
ruleset and policy digests, same rule, file and line for each item). The ledger
runs exactly this before indexing a finding.

## Clearing a finding

There is nothing to request. The watcher re-scans when the path changes. A fixed
commit gets a Scanned certificate, and listings show the newest commit's result.
The old finding stays in Rekor and the ledger, marked superseded.

If a finding is wrong (the rule misfired), say so in a public issue on this
repository. The fix goes into the scanner for everyone, and the next scan reflects
it.

There is no opt-out from scanning public code, paid or otherwise: a watchdog that
can be switched off by the people it watches is not one. A repository that goes
private or is deleted drops out by itself, since nothing is hosted. Legal
takedowns are the only removals, and they are logged publicly.

## The watcher

`.github/workflows/watch.yml` runs hourly in this repository. It holds no signing
permission; it only dispatches `scan.yml` at `SCAN_TAG` (bump it with each
release).

1. **Targets** come from the ledger's `scan-targets.txt` (`owner/repo path` per
   line), so the list is public and changes by signed ledger commits.
2. **Sweep (main path).** Each run checks up to 3,000 targets, never-checked first,
   then least recently checked, with one GraphQL query per 40 targets: the newest
   commit on the default branch that touched the target's path. At hourly runs
   that cycles through about 70,000 targets a day.
3. **Fast path.** GH Archive's public event record for the last three hours: a
   push to a target repo makes its targets candidates at once. GitHub's public
   event feed is sampled, so this catches only some pushes early.
4. A commit not dispatched before goes to `scan.yml` in batches of 50. State (last
   commit dispatched per target) is the `watch-state` artifact, kept 30 days.

A maintainer who wants every push certified right away can add the one-file
workflow and get the Signed or Tested level instead.
