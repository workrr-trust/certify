# workrr Trust Authority — Public Trust Ledger Design

*Framework design · 2026-10-19 · status: draft, pre-build*

## Goal and principles

Make every workrr certificate a **public, tamper-evident trust document** that anyone
can verify without trusting workrr — while workrr itself runs as little as possible.

1. **Maximum trust.** Every claim is checkable by a third party. Nothing in the trust
   path depends on workrr's word, workrr's servers, or any single forge.
2. **Smallest technical footprint.** Reuse public-good infrastructure (Sigstore,
   public CI, git, public archives). workrr operates no log, no key server, and no
   signing service for the public tier.
3. **Survives workrr.** If workrr disappears, every certificate already issued stays
   verifiable.
4. **Point, don't host.** Certificates bind to an artifact's sha256 digest and point
   to its source. workrr never redistributes third-party artifacts.
5. **No single forge in control.** GitHub is used, not depended on: the
   highest-assurance certificates require agreement across two independent forges.

No blockchain: an append-only Merkle transparency log (Sigstore Rekor) plus
independent witnesses gives the same tamper-evidence without tokens or consensus.

## Architecture at a glance

```
 Artifact (SKILL.md / MCP server / ruleset / AGENTS.md)
     │ sha256 digest + source URL (pointed to, never copied)
     ▼
 Certifier = open-source reusable CI workflow, pinned by commit
     ├── runs on GitHub Actions ──┐   each independently runs the four checks
     └── runs on GitLab CI ───────┤   and signs keylessly (Sigstore Fulcio;
                                  │   identity = the certifier workflow on
                                  │   GitHub, the workrr certifier project on GitLab)
                                  ▼
 Certificate = in-toto attestation (DSSE) ──► Sigstore Rekor (public log)
                                  │                 │ signed, witnessed checkpoints
                                  ▼                 ▼
 Ledger repo (index of certs + checkpoints) mirrored to GitHub · GitLab · Codeberg
                                  │                 (Codeberg = mirror only, no signing)
                                  │                 └─ archived by Software Heritage
                                  ▼
 Daily OpenTimestamps anchor of the latest checkpoint (Bitcoin)

 workrr Trust Authority = one offline root key signing one small trust-policy file
```

## 1. The certificate

An **in-toto attestation** in a DSSE envelope (the format Sigstore, SLSA, and GitHub
artifact attestations already use), with a workrr predicate type:

- `subject`: artifact name + **sha256 digest**
- `source`: canonical source URL + commit (the pointer — no copy is stored)
- `checks`, each recorded with the **digest of the exact tool/suite/policy** used, so
  anyone can re-run it:
  1. **Provenance** — built from the stated source, unchanged
  2. **Policy conformance** — against a named, published policy digest
  3. **Injection scan** — "passed known-pattern scanning" with scanner version
     (never claim "injection-free" or "safe")
  4. **Reproducible test suite** — pass/fail against a suite digest
- `band`: A–E trust band + pointer to its evidence (omitted when no evidence exists)
- `certifier`: workflow identity and commit that produced it

The predicate schema is part of the open spec (Apache-2.0). Keep the predicate small
(digests and pointers, not raw evidence): Rekor v1's server default caps stored
attestations at 100 KiB, and evidence belongs behind a digest anyway.

## 2. The Trust Authority

The authority is **a policy, not a server**.

- **Keyless signing.** Certificates are signed via Sigstore Fulcio using the CI's
  OIDC identity. No long-lived workrr signing keys exist to steal, rotate, or leak.
  - **GitHub:** the signing identity *is* the public certifier reusable workflow.
    Fulcio puts `job_workflow_ref` (the *called* reusable workflow, not the caller)
    in the cert SAN, e.g.
    `https://github.com/workrr-trust/certify/.github/workflows/certify.yml@<ref>`,
    and records `job_workflow_sha` in the Build Signer Digest extension. For an
    annotated tag that value is the tag object, not the peeled commit. The trust
    policy pins **both** (SAN + Build Signer Digest). The caller's own workflow shows
    up separately as Build Config URI. The v0.1.2 built-in policy lists only
    `certify.yml@refs/tags/v0.1.0` and `v0.1.1`, with those tag-object digests. It
    does not accept `refs/heads/main`.
  - **GitLab:** keyless signing requires `id_tokens` in the project's own
    `.gitlab-ci.yml`, and GitLab does not support it from CI files included from
    another repository. The cert identity (SAN and Build Signer URI =
    `ci_config_ref_uri`) is therefore the **project running the pipeline**, not a
    shared component. The intended design is a dedicated public
    `workrr-trust/certify-gitlab` project whose top-level `.gitlab-ci.yml` is the
    certifier, pinned by the trust policy to project + ref + commit. Since v0.1.7
    that project is the **GitLab witness** (`docs/gitlab-certifier.md`): it
    certifies a public GitHub commit, and counts only toward Gold next to the
    publisher's own GitHub certificate.
- **Marketplace action is verify-only.** GitHub Marketplace lists a root
  `action.yml`. A composite action runs inside the caller's job, so a
  certificate it signed would carry the caller's `job_workflow_ref`, not
  `certify.yml@refs/tags/v0.1.x`. The trust policy would reject it. The root
  action only verifies a bundle the caller already has, and it fails the job
  when the level or source misses. It does not take a replacement trust
  policy, so a workflow cannot point it at a weaker signer. Publishers still
  call the reusable workflow at the pinned tags.
- **The certifier is public code.** Anyone can read exactly what produced a
  certificate. Changing the checks means a new commit, which is a new, visible
  identity.
- **Signed trust policy, keyless.** The implementation (spec §7) does not use a
  long-lived root key. A release-tag run of `trust-policy.yml` signs the policy
  with Sigstore, and `revoke.yml` signs revocations the same way. A Cloudflare
  Worker (`services/trust-api/`) stores the blobs in R2 and indexes them in D1.
  The worker is transport: verifiers check the signatures and reject a policy
  sequence that goes backwards. The paragraph below is the earlier sketch of an
  offline root; the keyless workflow is what verifiers implement.
- **One offline root key** (hardware token, ideally split across 2+ holders) signs a
  small **trust-policy file** (TUF-style `root.json`) listing:
  - which certifier workflow identities and commits are accepted
  - required forges per assurance level
  - revocation pointers and policy version
  The root key is used only when the certifier itself changes. This file — not a
  service — is "the workrr Trust Authority."
- **Revocation is append-only too.** A revocation is a signed attestation logged in
  Rekor and indexed in the ledger: visible, timestamped, with a reason. Never a
  silent delete.

## 3. The log — Sigstore Rekor

Use the public-good **Sigstore Rekor** instance (run by the OpenSSF community) as the
append-only log. workrr runs no log.

- **Version:** sign against whatever the TUF-distributed Sigstore SigningConfig says.
  Today that is **Rekor v1** (`rekor.sigstore.dev`). Sigstore decided in June 2026 to
  keep v1 as the public-good default "for the foreseeable future". Rekor v2 (tiled,
  `log20XX-N.rekor.sigstore.dev`, sharded about every 6 months) is in production as
  opt-in only. Never hard-code a log URL. Verifiers must accept both, because bundles
  carry their own log ID.
- **Entry type:** v1 takes `dsse` entries, which is what `actions/attest` and
  `cosign attest` write today. v2 accepts **only `hashedrekord`**: a DSSE attestation
  is logged as a hashedrekord over the envelope's PAE. Either way the full envelope
  lives in our ledger, not in the log.
- Every certificate and revocation is entered in Rekor, which returns an
  **inclusion proof** and a signed **checkpoint** (tree size + root hash). v2 returns
  both synchronously in C2SP `tlog-checkpoint` / signed-note format.
- Rekor is a Merkle tree: any edit or deletion of a past entry is mathematically
  detectable by anyone holding an earlier checkpoint.
- Trust gain: the log is operated by an independent party, not by workrr.
- Trade-off: a 99.5% availability SLO but no contractual SLA. Mitigated because the
  ledger mirrors (§5) keep every entry plus its inclusion proof, so verification
  never depends on Rekor being up.

## 4. Witnesses

Witnesses stop a log from showing different histories to different people.

- **Rekor's own witnessing — not there yet.** Public Rekor checkpoints are signed only
  by the log. Rekor v2 launched **unwitnessed**: C2SP `tlog-cosignature` co-signing,
  with a witness policy distributed through Sigstore TUF, is planned but not shipped.
  Clients don't verify witness signatures yet. Until it ships, **we witness it
  ourselves**: a scheduled CI job fetches the latest checkpoint, verifies consistency
  against the previous one (Sigstore's reusable `rekor-monitor` workflow, or
  `omniwitness`), and commits it to the ledger mirrors. When Sigstore witnessing goes
  live, require its cosignatures in addition.
- **Two-forge agreement — the strongest witness.** For **Gold** certificates the
  certifier runs independently on GitHub Actions *and* GitLab CI. Both must produce
  identical check results for the same artifact digest. A compromised forge, runner,
  or account cannot forge a Gold certificate alone. This is what removes "trust
  GitHub" from the trust path.
- **Ledger mirrors as witnesses.** Each mirror commits Rekor checkpoints. Their
  histories must agree; any split view shows up as a mismatch.
- **Later:** invite design partners, OpenSSF, or a university lab to co-sign
  checkpoints for extra independent witnesses.

Assurance levels, published in the trust policy:

| Level | Requirement |
|---|---|
| **Gold** | 2 independent forges agree, all four checks pass, logged in Rekor |
| **Silver** | 1 forge, all four checks pass, logged in Rekor |
| **Banded** | Not deterministically testable — A–E band with evidence, logged |

## 5. Public mirrors — GitHub, GitLab, Codeberg

The **ledger repo** (`workrr-trust/ledger`) is the human-browsable record.

- Contents: one file per certificate (the DSSE envelope + Rekor inclusion proof),
  revocations, a `checkpoints/` history, and the signed trust-policy file.
  **Index only. No artifact copies.**
- Written only by the certifier CI. Every commit signed. Protected branches,
  force-push disabled.
- Mirrored to **GitHub, GitLab, and Codeberg** (Codeberg is non-profit, which reduces
  dependence on corporate forges). Any divergence between mirrors is itself evidence
  of tampering. **Codeberg is mirror-only.** Forgejo Actions can mint OIDC tokens, but
  public Fulcio doesn't trust Codeberg's issuer yet (open request, no merged change).
  Codeberg can't be a signing forge for Gold until that lands.
- **Software Heritage** crawls GitHub, GitLab.com, and Codeberg on its own: a
  permanent, independent, non-profit copy at zero cost to us. Crawl frequency is not
  guaranteed, so the ledger CI also calls the Save Code Now API after each update
  (rate-limited; one call per mirror per day is enough).
- The mirrors are a **convenience and durability layer, not the source of truth.**
  Truth is the signatures and the Rekor inclusion proofs inside each file. That's why
  depending on GitHub here doesn't reduce trust.

## 6. Blockchain anchor (optional, near-zero cost)

- A daily CI job timestamps the latest Rekor checkpoint hash with **OpenTimestamps**,
  which anchors it in Bitcoin. The `.ots` proof is committed to the ledger.
- It gives a proof of "this checkpoint existed by this date" that's independent of
  Sigstore, git, and workrr.
- It costs nothing and needs no wallet or token. It also supports an accurate
  "anchored on-chain" claim.

## Verification (what anyone can do)

1. Hash the artifact; look up its certificate by digest (ledger repo, any mirror, or
   Rekor).
2. Check the signature identity is a certifier allowed by the signed trust policy.
3. Check the Rekor inclusion proof against a witnessed checkpoint.
4. Check it's not revoked.
5. For Gold, check both forge attestations agree.
6. Optionally re-run the checks from the recorded digests and get the same result.

Steps 1–5 ship as the open `workrr verify` CLI and a library. Harnesses, registries,
and CI call it at load time. It's built on existing Sigstore clients (cosign /
sigstore-js / sigstore-python), not a new crypto stack.

## Public vs private — the business model (GitHub-style)

| | **Public (free)** | **Private (paid: Team / Enterprise)** |
|---|---|---|
| Artifacts | Public, open-source | Customer-internal |
| Certifier | workrr's public workflow | Same workflow, run in the **customer's own CI** |
| Signing | Keyless (Fulcio, public identity) | Customer-tenant key (or private Fulcio identity) |
| Log | Full attestation in public Rekor | **Only the attestation's hash** in public Rekor (proves existence and time, reveals nothing); full attestation stays in the customer's private ledger repo |
| Registry | Public index | Private vetted registry + policy authoring + audit trail + SSO |
| Assurance | Silver / Gold / Banded | Same, plus customer policy conformance |

Private certificates keep the same tamper-evidence. Their existence and timing are
publicly provable, but their content, names, and policies never leave the customer.

## Enterprise source-control integration

Customers **install the certifier into their CI**. They don't grant workrr access to
their code.

- **GitHub:** publishers call the reusable workflow
  `workrr-trust/certify/.github/workflows/certify.yml` at a tag the trust
  policy pins (`v0.1.0` or `v0.1.1`). Fulcio records that workflow, not the
  caller, and workrr never sees source. The Marketplace action
  (`workrr-trust/certify@<sha>`) only verifies a certificate the caller
  already has. It does not sign.
- **GitLab:** the customer adds the certifier steps to their own top-level
  `.gitlab-ci.yml`, vendored at a pinned commit. A remote include or component can't
  hold the `id_tokens` that keyless signing needs. The cert identity is then the
  customer's project, so the certifier commit is recorded in the predicate and
  checked by re-running. This is weaker than GitHub, where the certifier itself is the
  signer.
- **Later, if needed:** a GitHub App / GitLab integration only for convenience (auto-PR
  policy updates, registry sync) — never for signing, and never required.

"workrr never sees your code" is both the strongest trust story and the smallest
footprint. It's also the clearest answer to a security reviewer.

## What workrr actually runs

| | |
|---|---|
| In the trust path | **Nothing.** Public CI + Sigstore + git + Software Heritage + OpenTimestamps |
| workrr-held secrets | One offline root key (trust-policy file only) |
| Outside the trust path | The Cloudflare app: search/index UI, private-tier registry, billing, audit dashboards |

If every workrr server went dark, issued certificates would remain verifiable from
Rekor, any mirror, or Software Heritage.

## Honest limits

- A transparency log proves workrr *said* something and never changed its story. It
  doesn't make the checks correct. Trust in the checks comes from public certifier
  code, recorded tool digests, reproducibility, and fast public revocation.
- Keyless signing depends on Sigstore's Fulcio and the forges' OIDC issuers.
  Two-forge Gold limits damage from any one of them; it doesn't remove the
  dependency.
- Public Rekor has no SLA; mirrors hold proofs so verification survives outages.
- Never claim "safe." Claim provenance, policy conformance, known-pattern scan
  results, reproducible test results, and a trust band.

## Verified (2026-10-19)

- **Rekor.** The public-good default is still **v1**. v2 is production but opt-in, and
  accepts only `hashedrekord` (DSSE goes in as hashedrekord over the PAE). v2 serves
  C2SP checkpoints synchronously. Witness cosigning is planned, not live. v1 server
  defaults: 100 KiB max stored attestation, no request-body cap. The public
  instance's deployed limits aren't published. Sources:
  [Rekor evolution (Jun 2026)](https://blog.sigstore.dev/rekor-evolution/),
  [Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/),
  [rekor-tiles CLIENTS.md](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md),
  [rekor-server flags](https://github.com/sigstore/rekor/blob/main/cmd/rekor-server/app/root.go),
  [Rekor overview](https://docs.sigstore.dev/logging/overview/).
- **Fulcio issuers.** GitHub Actions and **gitlab.com** are trusted. Self-managed
  GitLab works only for specifically allow-listed instances (e.g.
  `gitlab.archlinux.org`), so customers on their own GitLab need a private Fulcio or
  a key. **Codeberg/Forgejo is not trusted** (request open), so Codeberg is
  mirror-only. Sources:
  [Fulcio issuer config](https://github.com/sigstore/fulcio/blob/main/config/identity/config.yaml),
  [OIDC in Fulcio](https://docs.sigstore.dev/certificate_authority/oidc-in-fulcio/),
  [fulcio#2442](https://github.com/sigstore/fulcio/issues/2442),
  [Forgejo Actions OIDC](https://forgejo.org/docs/latest/user/actions/reference/).
- **Custom predicates.** `actions/attest` takes `predicate-type` plus
  `predicate`/`predicate-path` (≤16 MB). For public repos it signs with public-good
  Sigstore and writes to the public log, so cosign isn't needed on GitHub. GitLab has
  no first-party equivalent: use `cosign attest-blob --type <uri> --predicate`, with
  `id_tokens: {SIGSTORE_ID_TOKEN: {aud: sigstore}}` in the project's own
  `.gitlab-ci.yml` (not an included file). Sources:
  [actions/attest](https://github.com/actions/attest),
  [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations),
  [GitLab keyless signing](https://docs.gitlab.com/ci/yaml/signing_examples/).
- **Reusable-workflow identity.** Yes on GitHub: the SAN is `job_workflow_ref` (the
  called workflow), Build Signer Digest is `job_workflow_sha`, and the caller is Build
  Config URI. On GitLab, Build Signer URI is `ci_config_ref_uri` (the top-level
  config), so a shared certifier can't be the signing identity there (§2). Sources:
  [Fulcio OID info](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md),
  [GitHub OIDC with reusable workflows](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/using-openid-connect-with-reusable-workflows).
- **Software Heritage.** Yes for all three. GitHub, GitLab, and Gitea/Forgejo listers
  exist, and the SWH API shows recent full visits to sample repos on github.com,
  gitlab.com, and codeberg.org (checked 2026-10-19). Frequency isn't guaranteed, so we
  also trigger Save Code Now. Sources:
  [SWH listers](https://docs.softwareheritage.org/devel/swh-lister/index.html),
  [SWH FAQ](https://docs.softwareheritage.org/user/faq/).
