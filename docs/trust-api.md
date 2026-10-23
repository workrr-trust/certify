# Trust API

`services/trust-api/` is a Cloudflare Worker. It serves two kinds of signed
bytes: the trust policy, and the revocation feed. It does not hold a signing
key and it does not check signatures. Verification happens in the TypeScript
and Go clients.

Nothing in this repository creates the Cloudflare resources or deploys the
worker. The ids in `wrangler.jsonc` are placeholders. The executable procedure
is [docs/deploy/trust-api-runbook.md](deploy/trust-api-runbook.md).

## Endpoints

| Method | Path | Cache-Control | Body |
|---|---|---|---|
| GET | `/v1/policy` | `public, max-age=300` | the signed policy blob for the highest sequence |
| GET | `/v1/revocations?digest=<64 hex>` | `public, max-age=60` | signed entries whose artifact digest matches |
| GET | `/v1/revocations/since/<n>` | `public, max-age=60` | signed entries with sequence > n, plus the signed checkpoint |

`/v1/policy` is `404` until a policy row exists. `/v1/revocations/since/0` is
`200` with an empty list before the first revocation, so a client can tell
"nothing is revoked" from "the feed could not be fetched".

Clients fetch `/v1/policy` and `/v1/revocations/since/<watermark>`. The digest
route is for lookup. Both responses are untrusted until the signature check
described in [spec §7](../spec/README.md) succeeds.

Default base URL, overridable with `WORKRR_TRUST_API`:

```text
https://trust-api.workrr.ai
```

That hostname is not the `trust.workrr.ai` site. This change does not touch the site.

## Deploy checklist (needs Shawn's approval)

Do these by hand. Do not point them at CI.

1. `cd services/trust-api && npm ci`
2. Create the database and the bucket:
   ```bash
   npx wrangler d1 create workrr-trust
   npx wrangler r2 bucket create workrr-trust-blobs
   ```
3. Replace `database_id` in `wrangler.jsonc` (`00000000-0000-0000-0000-000000000000` is a placeholder). The bucket binding name stays `BLOBS` and the D1 binding name stays `DB`.
4. Apply the migration:
   ```bash
   npx wrangler d1 migrations apply workrr-trust --remote
   ```
5. Run the `trust-policy` workflow from a **release tag**. Download `signed-policy.json`. Do not deploy from the workflow.
6. Upload the blob and index it. `SEQUENCE` and `ISSUED_AT` are the values inside the policy:
   ```bash
   npx wrangler r2 object put workrr-trust-blobs/policy/SEQUENCE.json --file signed-policy.json --remote
   npx wrangler d1 execute workrr-trust --remote --command \
     "INSERT INTO policies (sequence, issued_at, r2_key) VALUES (SEQUENCE, 'ISSUED_AT', 'policy/SEQUENCE.json')"
   ```
7. Deploy the worker and attach the hostname `trust-api.workrr.ai`:
   ```bash
   npx wrangler deploy
   ```
8. After that policy is the one you want new binaries to refuse to roll back past, set `EMBEDDED_POLICY_SEQUENCE` in `src/trust-feed.ts` and `embeddedPolicySequence` in `go/trustfeed.go` to that sequence and ship a release.
9. When the trust-policy workflow has run, pin its Build Signer Digest in `TRUST_POLICY_SIGNER` / `TrustPolicySigner`. Do the same for `revoke.yml` after the first revocation. Until then an empty digest list accepts any commit of that tagged workflow.
10. Revocations, when there is something to revoke: [revocation.md](revocation.md). Upload `entry.signed.json` as `revocations/<sequence>.json` and `checkpoint.signed.json` as `revocations/checkpoint.json`, then insert the D1 rows:

   ```sql
   INSERT INTO revocations (sequence, artifact_digest, log_index, reason, timestamp, signer, r2_key)
   VALUES (1, '<64 hex or NULL>', '<log index or NULL>', '<reason>', '<timestamp>', '<signer URI>', 'revocations/1.json');

   INSERT INTO revocation_checkpoint (id, sequence, r2_key) VALUES (1, 1, 'revocations/checkpoint.json')
   ON CONFLICT(id) DO UPDATE SET sequence = excluded.sequence, r2_key = excluded.r2_key;
   ```

   Exactly one of `artifact_digest` and `log_index` is set.

Local tests use Miniflare through Vitest (`npm test` in this directory). They do not contact Cloudflare.
