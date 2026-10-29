# Evidence packs (draft, v0.1)

A certificate says that artifact X at digest Y passed checks Z at time T, signed by
identity W. Regulation and audit frameworks ask the people who **use** such an
artifact to show the same kind of facts in their own records: component due
diligence, an SBOM, test results, vulnerability handling, support periods.

An **evidence pack** is the certificate rearranged for one of those records. It is
a directory the user files with their technical documentation or hands to an
auditor, with each piece of evidence mapped to the clause it supports.

```bash
workrr evidence ./my-skill --bundle certificate.sigstore.json --profile cra --out evidence/
```

## Principles

- **Derived, never issued.** A pack adds no new claim and no new signature. Every
  fact in it comes from a certificate that verified, from the artifact's own bytes,
  or from the publisher's own declarations, and says which.
- **Built by the user.** The open CLI builds the pack on the user's machine. workrr
  stores nothing, sees nothing, and files nothing with any authority.
- **Verifiable on its own.** The pack includes the original Sigstore bundle(s) and a
  `verify.sh` that re-checks them with the open CLI. Nobody has to trust the pack,
  the CLI build that made it, or workrr.
- **Reproducible.** The same certificate, artifact and CLI version give the same
  `evidence.json`, `mapping.<profile>.json` and `sbom.cdx.json`, byte for byte. Only
  `verification.json` and the summary page carry the time the pack was made.
- **Says what it does not cover.** Every mapping lists the obligations that remain
  the user's own legal acts. A pack is never a conformity assessment, a declaration
  of conformity, a CE marking or a statement that a component is secure.
- **Only from a verified certificate.** `workrr evidence` runs the same checks as
  `workrr verify` and refuses to build a pack if they fail or the certificate is
  revoked.

## Contents

| File | What it is | Reproducible |
|---|---|---|
| `summary.html` | One printable page for a human reviewer: the certificate statement, the component, the checks, the clause table, what is not covered, how to verify | No (shows the build time) |
| `evidence.json` | Machine-readable facts: component identification, certificate, checks, publisher declarations | Yes |
| `mapping.<profile>.json` | Clause → status → evidence fields → what remains the user's job | Yes |
| `sbom.cdx.json` | CycloneDX 1.6 SBOM of the certified component: its files with SHA-256 hashes, and the top-level dependencies it declares | Yes |
| `certificate/*.sigstore.json` | The original bundle(s), unchanged | Yes |
| `verify.sh` | Re-verifies the bundle(s) against an artifact checkout with the pinned CLI version | Yes |
| `verification.json` | When the pack was built, the CLI version, and the verifier's notes (for example, whether revocation was checked) | No |
| `statement-template.md` | An unsigned template for the user's own internal due-diligence record | Yes |

### Clause status values

| Status | Meaning |
|---|---|
| `evidenced` | The certificate or the artifact's bytes carry evidence for this clause |
| `partial` | Evidence for part of the clause; `remains` says what is left |
| `publisher-declared` | The evidence is a declaration by the publisher (see below), not a check |
| `missing` | The clause could carry evidence here, but the publisher declared nothing |
| `not-covered` | The user's own legal act or process. No pack can supply it |

### Publisher declarations

Some evidence is a promise only the publisher can make: how long the artifact is
supported and where to report a vulnerability. Publishers declare it in the
artifact's `workrr.json`, next to the test command:

```json
{
  "test": { "command": "node test.js" },
  "support": { "until": "2031-12-31" },
  "security": { "policy": "https://example.com/security", "contact": "mailto:security@example.com" }
}
```

`workrr.json` is part of the artifact, so these declarations are covered by the
certificate's digest. If `security` is absent, a `SECURITY.md` inside the artifact
is used, then one at the root of the local checkout. A file outside the artifact is
marked `"coveredByCertificate": false`.

The certifier does not check these declarations. A pack reports them as
`publisher-declared`, never as `evidenced`.

### SBOM

`sbom.cdx.json` describes the certified component exactly as signed:

- `metadata.component` is the artifact: name, the source commit as its version, the
  certificate digest (algorithm in the `workrr:digest-algorithm` property), the
  source repository, the Rekor entry, and the security contact if declared.
- One `file` component per artifact file, with its SHA-256. Together they recompute
  the certificate digest.
- One `library` component per top-level dependency the artifact declares, with a
  purl: `package.json` (versions from `package-lock.json` when present),
  `requirements.txt` (pinned `==` versions), and `go.mod`. Other manifests are
  listed in `evidence.json` as not parsed.

The SBOM is component-level. A manufacturer merges it into the product's own SBOM.

## Profiles

| Profile | For | Status |
|---|---|---|
| `cra` | EU Cyber Resilience Act (Regulation (EU) 2024/2847): component due diligence and technical documentation | **v0.1, this release** |
| `ai-act` | EU AI Act: Annex IV component entries, Art. 25(4) supplier information, Art. 15 screening record | Planned |
| `nis2`, `dora` | Supplier assurance records; DORA register of information row | Planned |
| `pld` | Product Liability Directive: preserved record for evidence disclosure | Planned |
| `ssdf`, `fedramp` | OSCAL component definitions for SSDF PS.2, PS.3, PW.8 and NIST 800-53 SR-4, SR-11 | Planned |
| `iso27001`, `soc2` | Auditor evidence sheets for supplier controls | Planned |

There is no profile for regimes where filings run only from an operator to a
government with no route for component evidence (for example, China's algorithm
and generative-AI filings).

Later: `workrr evidence --lock <file>` builds one pack for every artifact an agent
uses, and `vex.json` carries advisories once the revocation feed publishes them.

### `cra` v0.1

The manufacturer of a product with digital elements keeps technical documentation
(Annex VII) for 10 years (Art. 13(13)) and shows it to a market surveillance
authority or notified body on request. The pack is an input to that file.

| Clause | Status | Evidence |
|---|---|---|
| Art. 13(5) due diligence on integrated components | `evidenced` | Verified signature, Rekor entry, signer identity, digest match, checks passed |
| Annex I Part I(2)(f) integrity | `partial` | Digest and signature let the manufacturer check the component as integrated |
| Annex I Part II(1) SBOM | `partial` | Component SBOM; the product SBOM is the manufacturer's |
| Annex I Part II(3) regular tests | `partial` | Point-in-time scan, policy and test results; regular testing is the manufacturer's |
| Annex I Part II(2), (4) and Art. 13(6) vulnerability handling | `publisher-declared` / `missing` | Security policy and contact; revocation checked at build time |
| Annex I Part II(5) coordinated vulnerability disclosure | `publisher-declared` / `missing` | Security policy |
| Art. 13(8) support period | `publisher-declared` / `missing` | `support.until` |
| Art. 13(13) documentation kept 10 years | `partial` | Self-contained pack, verifiable offline against public logs |
| Art. 14 reporting | `partial` | Component identification fields for a report the manufacturer files |
| Art. 13(2)–(3) risk assessment, Art. 28 declaration of conformity, Arts. 29–30 CE marking, Art. 32 conformity assessment | `not-covered` | The manufacturer's own acts |

Article references follow the Official Journal text of Regulation (EU) 2024/2847.
The mapping is an engineering aid, not legal advice. Whether a given artifact is a
product with digital elements, and what its manufacturer must do, is for the
manufacturer and their counsel.

## Wording

A pack says "evidence for", "supports" and "passed these checks". It never says
compliant, certified to a regulation, conformant, approved or secure.
