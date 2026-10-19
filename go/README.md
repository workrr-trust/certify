# workrr-trust/certify — Go

Go implementation of the Workrr Trust certifier: the same certificate spec
([../spec/README.md](../spec/README.md)) and the same `workrr` CLI as
the TypeScript reference at the [repo root](..), as a single static binary.

Gold certificates need two forges to produce **byte-identical canonical `checks`**,
so this implementation is held to the TypeScript one by shared test vectors
([../spec/test-vectors](../spec/test-vectors)), not just by the spec text.

## Build and test

```bash
CGO_ENABLED=0 go build -trimpath -o workrr ./cmd/workrr
go test ./...
```

`CGO_ENABLED=0` gives a fully static binary on Linux (macOS binaries always link libSystem).

## Usage

Same commands, flags, output and exit codes as the TypeScript `workrr`:

```bash
workrr digest  <path>
workrr test    <path> [--out tests.json]
workrr certify <path> [--policy policy.json] [--tests-report tests.json | --run-tests]
                      [--statement-out statement.json] [--predicate-out predicate.json]
workrr verify  <path> --bundle <file> [--bundle <file>] [--trust-policy policy.json] [--json]
```

One addition: `verify --trusted-root trusted_root.json` pins a Sigstore trusted root
instead of fetching the public-good root via TUF (useful offline or air-gapped).

## Verification

`verify` uses [sigstore-go](https://github.com/sigstore/sigstore-go): certificate chain
to the Fulcio root, signed certificate timestamp, DSSE signature, Rekor inclusion with an
integrated timestamp, and the in-toto subject digest. The signer identity (SAN regex,
issuer, Build Signer Digest OID `1.3.6.1.4.1.57264.1.10`) is then matched against the
same default trust policy as the TypeScript CLI.

`TestVerifySigstorePublicGoodBundle` verifies a real public-good bundle (npm provenance
for `sigstore@5.0.0`) offline against a pinned trusted root, and checks that a wrong
digest and a tampered signature are rejected.

## How parity is kept

The ruleset records (`id`, `severity`, `description`, `pattern`, `flags`) are
byte-for-byte the TypeScript ones, because they are the ruleset digest input. The
patterns are ECMAScript regular expressions; Go's RE2 differs, so [scan.go](scan.go)
runs each rule with a matcher that reproduces ECMAScript semantics:

| ECMAScript behaviour | Go handling |
|---|---|
| Without `u`, repeats count UTF-16 code units (`[^\n]{0,40}`: an emoji is 2) | Non-`u` rules run over `CodeUnitString(text)`: one rune per code unit |
| `\s` includes Unicode spaces, `\v`, U+FEFF | Rewritten to JavaScript's exact whitespace class |
| Non-`u` `i` never folds non-ASCII to ASCII | `i` rewritten to ASCII classes (`[kK]`); RE2's `(?i)` would let U+212A KELVIN SIGN match `k` and U+017F LONG S match `s` |
| **WT004** `(?<!^)\uFEFF` (lookbehind; `m` flag, so `^` follows `\n`, `\r`, U+2028, U+2029) | Hand-written: a BOM not at the start of input or after one of those four characters |
| **WT008** `(?:(?!-->)[\s\S]){0,2000}?` (lookahead; RE2 caps repeats at 1000) | Hand-written backtracking over UTF-16 code units: lazy 0–2000 units, none starting `-->`, then the keyword with word boundaries, then the first `-->` |

Other JavaScript behaviour the reference relies on implicitly, reproduced here:

- **Text decoding:** files are decoded like Node's `Buffer#toString("utf8")` (WHATWG,
  one U+FFFD per maximal invalid subpart). Go's decoder emits one per byte.
- **Canonical JSON:** `JSON.stringify` string escaping (only `"`, `\`, C0 controls) and
  number formatting (`1e+21`, `1e-7`, `-0` → `0`).
- **YAML frontmatter:** scalars resolve by the YAML 1.2 core schema, as the npm `yaml`
  package does. yaml.v3's own resolution reads `012` as octal, applies `<<` merge keys,
  and decodes `!!binary` to a string.
- **`toLowerCase`, `trim`, `String(v)`:** see [jsstr.go](jsstr.go).

Known residual differences (only reachable with hostile or malformed inputs; the
consequence is "no Gold", never a wrong certificate):

- Unicode table versions differ between Go and V8 (lowercasing, case-ignorable).
- YAML documents that one parser accepts and the other rejects.
- Policy fields of the wrong JSON type: Go rejects the policy; TypeScript coerces.
- Directory entries or symlink targets that aren't valid UTF-8.
- Unknown keys in a `--tests-report` `tests` object are dropped by Go, kept by TypeScript.
