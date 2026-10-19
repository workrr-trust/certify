# Workrr Trust Certificate — Specification v0.1 (draft)

A Workrr certificate is an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
inside a DSSE envelope, signed keylessly through Sigstore and recorded in the public
Rekor transparency log. This document is the contract every implementation (TypeScript,
Go) must follow. Two implementations given the same artifact, policy, and ruleset must
produce byte-identical `checks`.

- **Predicate type:** `https://trust.workrr.ai/certificate/v0.1`
- **JSON Schema:** [predicate-v0.1.schema.json](predicate-v0.1.schema.json)
- **Design rationale:** [docs/design.md](../docs/design.md)

## 1. Artifact digest

The subject digest is always `sha256`.

- **Single file:** sha256 of the file's bytes. `predicate.artifact.digestAlgorithm = "file-sha256"`.
- **Directory:** `workrr-dirhash-v1`:
  1. Walk the directory recursively. Skip any path segment named `.git`. Don't follow
     symlinks. A symlink is hashed as its link-target string.
  2. For each regular file, compute `sha256(bytes)` as lowercase hex.
  3. Relative paths use `/` separators and are sorted by UTF-8 byte order.
  4. Build the manifest: one line per file, `<hex>  <path>\n` (two spaces).
  5. The digest is `sha256(manifest)`.

The subject `name` is the artifact's declared name (SKILL.md `name`, `server.json`
`name`) or else the directory/file basename.

## 2. Artifact type

Detected in this order: `SKILL.md` present → `skill`; `server.json` present →
`mcp-server`; `AGENTS.md` or `CLAUDE.md` present → `agent-context`; else `other`.
A single file named `SKILL.md`, `AGENTS.md`, or `CLAUDE.md` maps the same way.

## 3. Checks

Every check records exactly what was used, so anyone can re-run it.

| Check | Result values | Recorded inputs |
|---|---|---|
| `provenance` | `pass` · `fail` | source URI, commit, path; whether the artifact is unchanged from that commit |
| `policy` | `pass` · `fail` | policy digest (sha256 of canonical JSON), violations |
| `scan` | `pass` · `fail` | ruleset version + digest, findings (rule id, severity, file, line) |
| `tests` | `pass` · `fail` · `none` | command, exit code, duration |

**Scan wording.** A `pass` means "no known-pattern findings of severity `high` or
`critical`." It never means safe or injection-free. Findings of severity `warn` are
recorded and don't fail the check.

**Canonical JSON.** Object keys sorted lexicographically, no whitespace, UTF-8.
Precisely: keys sorted by UTF-8 byte order; strings and numbers serialized as
ECMAScript `JSON.stringify` does (only `"`, `\` and U+0000–U+001F are escaped;
`1e+21`, `1e-7`, `-0` → `0`); absent optional fields are omitted, never `null`.

**Determinism rules.** Gold compares `checks` byte for byte, so these are part of the
contract, not implementation details:

- **Scan input.** Files containing a NUL byte are skipped. Other files are decoded as
  UTF-8 with WHATWG replacement (one U+FFFD per maximal invalid subpart; a BOM is kept).
  Symlinks are read through to their target; unreadable files are skipped.
- **Scan patterns** are ECMAScript regular expressions, run with their flags plus `m`.
  Without `u`, they operate on UTF-16 code units. A finding's line is 1 + the number of
  `\n` before the match start; each rule reports at most one finding per line.
- **Findings order:** file (UTF-8 byte order), then line, then rule id.
- **SKILL.md frontmatter** is the YAML between a leading `---` line and the next
  `---` line, parsed with the YAML 1.2 core schema (no merge keys; duplicate keys are
  a parse error). A frontmatter field counts only if it is a non-blank string.

Cross-implementation test vectors live in [test-vectors/](test-vectors/README.md); every
implementation must pass them.

## 4. Level

| Level | Rule |
|---|---|
| `silver` | provenance, policy, scan, and tests all `pass` |
| `banded` | provenance, policy, scan `pass`; tests `none` (not deterministically testable). A trust band is attached only when evidence exists. |
| *(no certificate)* | any check `fail` — the certifier exits non-zero and nothing is signed |
| `gold` | **Assigned only by verifiers, never by certifiers:** two `silver` certificates for the same digest, signed by accepted certifier identities on two different forges, with identical `checks`. |

## 5. Signing and logging

- Certificates are signed keylessly with Sigstore Fulcio from the certifier's CI OIDC
  identity, and recorded in public Rekor.
- On GitHub the identity is the reusable workflow
  `https://github.com/workrr-trust/certify/.github/workflows/certify.yml@<ref>`, with
  Build Signer Digest (OID `1.3.6.1.4.1.57264.1.10`) = the certifier commit.
- Only identities listed in the signed trust policy are accepted.

## 6. Verification

A verifier must:
1. Recompute the artifact digest (§1) and match it to the Statement subject.
2. Check `predicateType` is a supported version.
3. Verify the Sigstore bundle: certificate chain, signature, and Rekor inclusion.
4. Match the signer identity (SAN, issuer, Build Signer Digest) against the trust policy.
5. Check the certificate isn't revoked *(revocation ledger: v0.2)*.
6. For `gold`: repeat 1–4 for a second bundle from a different forge and compare
   `checks` byte-for-byte as canonical JSON.

## Versioning

Breaking changes bump the predicate type URI. Verifiers must reject unknown
predicate types.
