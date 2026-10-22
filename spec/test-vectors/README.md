# Cross-implementation test vectors

Gold requires two certifiers (TypeScript on one forge, Go or TypeScript on another) to
produce byte-identical canonical `checks`. These vectors pin that. Both
`test/vectors.test.mjs` and `go/vectors_test.go` assert against
`expected.json`.

| File | Contents |
|---|---|
| `cases.json` | Inputs: canonical-JSON values, policies, and artifacts |
| `expected.json` | Outputs from the TypeScript reference: ruleset digest, policy digests, canonical JSON, and per artifact the digest, file list, type, name, scan result, policy results, and the canonical `checks` string |
| `vectors.mjs` | TypeScript evaluator (shared by the test and the generator) |
| `generate.mjs` | Regenerates `expected.json` |
| `sigstore/` | A real public-good Sigstore bundle, a pinned `trusted_root.json`, and the expected signer identity |
| `cases.json` `trust` | Verifier rejection cases (main-branch signer, unknown policy digest, reused baseline name, source mismatch). Asserted directly by both test suites; not generated into `expected.json` |

## Artifacts

An artifact case is either `dir` (a committed fixture, relative to this folder) or
`files`, written to `<tmp>/<id>/` so the directory basename is the case id. A file is
`text`, `symlink`, or `parts`: a list of strings and `{ "text" | "base64", "times" }`
objects, concatenated as bytes. `target` makes the artifact a single file in the tree.

`provenance` and `tests` depend on git state and on running code, so `fixedChecks` pins
them. Each artifact's `checks` under each listed policy is
`canonicalJson({ provenance, policy, scan, tests })`.

## What `scan-edges` covers

Each line of its `SKILL.md` is a place where a naive Go/RE2 port diverges from
ECMAScript (see `go/README.md`):

| Line | Case | Expected |
|---|---|---|
| 5, 6 | NBSP and `\v` as `\s` | WT001 |
| 7, 8 | U+212A KELVIN SIGN and U+017F LONG S under non-unicode `i` | no finding |
| 10 | 25 emoji = 50 UTF-16 units, beyond `[^\n]{0,40}` | no finding |
| 13, 15, 16 | BOM at a line start (after `\n`, `\r`, U+2028) | no finding |
| 14 | BOM mid-line | WT004 |
| 22 | WT008 keyword beyond 2000 code units | no finding |
| 23 | WT008 keyword within 2000 code units | WT008 |
| 24 | `-->` before the keyword | no finding |
| 25–27 | Comment spanning lines | WT008 on line 25 |

Plus: findings ordered by file in UTF-8 byte order (`～.md` before `😀.md`; JavaScript's
`<` would reverse them), a symlink scanned through to its target, a dangling symlink,
invalid UTF-8 decoded with WHATWG replacement (`invalid-utf8.md`: 30 U+FFFD, so WT007
matches; per-byte replacement would give 60 and miss), a binary file skipped, and CRLF.

## Changing the vectors

Only for an intentional spec or ruleset change:

```bash
cd certify && npm run build && node spec/test-vectors/generate.mjs
```

Review the `expected.json` diff line by line, and make `go test ./...` in `go/`
pass in the same change. `generate.mjs` escapes non-ASCII so invisible characters stay
visible in review.
