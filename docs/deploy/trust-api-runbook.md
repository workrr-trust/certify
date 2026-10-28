# Deploy trust-api.workrr.ai

Executable procedure for the Cloudflare Worker in `services/trust-api/`. The Worker stores signed trust-policy and revocation blobs. It does not hold a signing key and it does not check signatures. Clients do.

Run it by hand from `services/trust-api/` after `npm ci`, so `npx wrangler` is wrangler `4.152.0` from that package. Do not point any of this at CI.

Every step that creates a Cloudflare resource, writes production data, publishes a signature, or cuts a release tag is marked **needs Shawn's approval**. Read-only commands are not.

This hostname is `trust-api.workrr.ai`. It is not the `trust.workrr.ai` site. Do not change that site.

## 1. Prerequisites

1. A Cloudflare account that already owns the `workrr.ai` zone. This runbook does not create the zone or change the site.
2. Wrangler logged into that account. From `services/trust-api/`:

   ```bash
   cd services/trust-api
   npm ci
   npx wrangler login
   npx wrangler whoami
   ```

   `whoami` must show the account that owns `workrr.ai`. If you are on a machine without a browser callback, use `npx wrangler login --device` instead of `npx wrangler login`.
3. Permission to dispatch GitHub Actions on `workrr-trust/certify` and to push a release tag. Tags `v0.1.0` and `v0.1.1` do not contain `.github/workflows/trust-policy.yml`. The first signing run needs a newer release tag. Cutting that tag is its own release, and it is **needs Shawn's approval**.
4. `curl` and `jq` on the machine that runs the smoke tests. `workrr` is `npx @workrr-trust/certify` once the release that contains this verifier is installed, or `node dist/cli.js` from a checkout of that release.

## 2. Create the bucket, the database, and the schema

**needs Shawn's approval.** Creates the R2 bucket.

```bash
npx wrangler r2 bucket create workrr-trust-blobs
```

Do not pass `--update-config`. The binding is already in `wrangler.jsonc`.

**needs Shawn's approval.** Creates the D1 database.

```bash
npx wrangler d1 create workrr-trust
```

Do not pass `--update-config`. Copy the `database_id` UUID from the command output. Paste it over `00000000-0000-0000-0000-000000000000` in `wrangler.jsonc`, and paste the account id from `npx wrangler whoami` over `REPLACE_WITH_ACCOUNT_ID`. Section 3 lists every field. Leave the binding name `DB` and the database name `workrr-trust` as they are. Migrations fail against the placeholder UUID, so do this before the next command.

**needs Shawn's approval.** Applies `migrations/0001_init.sql` to the remote database. Wrangler asks you to confirm. Confirm only `0001_init.sql`.

```bash
npx wrangler d1 migrations apply workrr-trust --remote
```

There are no Worker secrets and no plaintext vars. Do not run `wrangler secret put`, and do not pass `--var` or `--secrets-file` on deploy. Signing keys do not belong in this Worker. After the deploy in section 4, confirm the secret list is empty:

```bash
npx wrangler secret list
```

Expected output is an empty list. `secret list` is read-only. `secret put` is not part of this procedure.

## 3. Values to fill in

`services/trust-api/wrangler.jsonc` is the config wrangler reads. There is no `wrangler.toml`. Fill these two fields. Leave every other field as it is in the repo.

| Field | Value |
|---|---|
| `account_id` | The account id from `npx wrangler whoami` for the account that owns `workrr.ai`. The file ships as `REPLACE_WITH_ACCOUNT_ID`. |
| `d1_databases[0].database_id` | The UUID printed by `wrangler d1 create workrr-trust`. The file ships as `00000000-0000-0000-0000-000000000000`. |

Already set, and not placeholders:

| Field | Value |
|---|---|
| `name` | `workrr-trust-api` |
| `main` | `src/index.ts` |
| `workers_dev` | `false` |
| `preview_urls` | `false` |
| `vars` | `{}` |
| `routes[0].pattern` | `trust-api.workrr.ai` |
| `routes[0].custom_domain` | `true` |
| `d1_databases[0].binding` | `DB` |
| `d1_databases[0].database_name` | `workrr-trust` |
| `d1_databases[0].migrations_dir` | `migrations` |
| `r2_buckets[0].binding` | `BLOBS` |
| `r2_buckets[0].bucket_name` | `workrr-trust-blobs` |
| `observability.enabled` | `true` |
| `observability.head_sampling_rate` | `1` |

`workers_dev: false` keeps wrangler from attaching a `*.workers.dev` hostname. The only hostname this deploy creates is `trust-api.workrr.ai`.

## 4. Deploy and the custom domain

**needs Shawn's approval.** Uploads the Worker, attaches the D1 and R2 bindings, and creates the custom hostname `trust-api.workrr.ai` on the `workrr.ai` zone, including its certificate.

```bash
npx wrangler deploy
```

Wrangler prints the route `trust-api.workrr.ai`. DNS for that name is created in the zone. Do not add a second CNAME by hand.

Then confirm no secret was stored:

```bash
npx wrangler secret list
```

Before a policy object exists, the policy route is a 404 and the feed is an empty 200. That is the check that the Worker is up and the index is empty:

```bash
curl -sS -D - -o /tmp/trust-policy-body.json https://trust-api.workrr.ai/v1/policy
```

Expected status and headers (the status line may say `HTTP/2 404` or `HTTP/1.1 404`):

```text
404
content-type: application/json; charset=utf-8
cache-control: no-store
x-content-type-options: nosniff
access-control-allow-origin: *
```

Expected body, exactly:

```json
{"error":"no trust policy published"}
```

```bash
curl -sS -D - https://trust-api.workrr.ai/v1/revocations/since/0
```

Expected: status `200`, header `cache-control: public, max-age=60`, and this body exactly:

```json
{"since":0,"checkpoint":null,"entries":[]}
```

## 5. First signed trust policy

### Who holds the signing key

Nobody holds a long-lived key. `trust-policy.yml` signs with Sigstore keyless signing (`cosign sign-blob --yes --bundle`). GitHub issues a short-lived OIDC token for the job (`id-token: write`, `contents: read`). Fulcio turns that token into a certificate and the private key stays on the Actions runner for that job. The workflow uploads `signed-policy.json` as a GitHub artifact. It does not deploy, tag, or write to R2.

The certificate identity must be:

```text
https://github.com/workrr-trust/certify/.github/workflows/trust-policy.yml@refs/tags/vX.Y.Z
```

Issuer: `https://token.actions.githubusercontent.com`. A signature from `refs/heads/main` is rejected. Do not dispatch the workflow on `main`.

### Sequence 1

`trust/policy-meta.json` in this branch already says `"sequence": 1`. The workflow renders that file into the document it signs. Before the run, confirm the file still has:

```json
{
  "sequence": 1,
  "revocationWatermark": 0,
  "revocationHead": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

`issuedAt` is the timestamp in that same file (`2026-10-22T00:00:00Z` unless you changed it on purpose). Do not set `EMBEDDED_POLICY_SEQUENCE` in `src/trust-feed.ts` or `embeddedPolicySequence` in `go/trustfeed.go` during this deploy. Both stay `0`. A client whose floor is `0` accepts sequence `1`. Raising the floor is a later release, after this policy is the one new binaries must not roll back past.

### Build Signer Digest lists

Two different lists:

- The certifier list inside the signed document comes from `DEFAULT_TRUST_POLICY` / `DefaultTrustPolicy`. It is only `certify.yml@refs/tags/v0.1.0` (`9fbe3e453cbd80bef0301f08db79408bb12c7d64`) and `v0.1.1` (`78d8c1a98c929b7b1c1b532c25256582a84887b1`). Those are tag objects, not peeled commits. Do not edit that list as part of this deploy.
- The list that accepts the policy signature itself is `TRUST_POLICY_SIGNER.buildSignerDigests` in `src/trust-feed.ts` and `TrustPolicySigner.BuildSignerDigests` in `go/trustfeed.go`. Both are empty on purpose until this first tagged run. An empty list accepts any commit of `trust-policy.yml` on a release tag. Record the digest now. Pinning it is a follow-up pull request, not this deploy.

After the workflow finishes, the digest to record is the tag object, not the peeled commit:

```bash
git fetch origin tag vX.Y.Z
git rev-parse vX.Y.Z
git rev-parse "vX.Y.Z^{commit}"
```

Keep the first value. The second is the commit and is not the Build Signer Digest GitHub puts on an annotated tag. The same rule is how `v0.1.0` and `v0.1.1` were pinned. `RevocationSigner` stays empty until the first real `revoke.yml` run. There is nothing to revoke in this procedure, so do not run `revoke.yml`.

### Run the workflow

**needs Shawn's approval.** This publishes a Fulcio certificate and a Rekor entry. It does not deploy the Worker.

1. The tag `vX.Y.Z` must point at a commit that contains `.github/workflows/trust-policy.yml`, `trust/policy-meta.json` at sequence 1, and this Worker. `v0.1.0` and `v0.1.1` do not.
2. GitHub → Actions → `trust-policy` → Run workflow. Choose that tag in the ref selector, not `main`.
3. The job refuses any ref that is not `refs/tags/v<digits>.<digits>.<digits>`.
4. Download the `signed-trust-policy` artifact: `policy.json`, `policy.sigstore.json`, and `signed-policy.json`.
5. Read `policy.json`. `sequence` is `1`. `signers` is the two pinned certifier tags above. `revocationWatermark` is `0`.

The workflow's own `cosign verify-blob` step already checked the identity. Check it again locally before upload:

```bash
cosign verify-blob \
  --bundle policy.sigstore.json \
  --certificate-identity "https://github.com/workrr-trust/certify/.github/workflows/trust-policy.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  policy.json
```

## 6. Publish the first policy and the empty feed

The feed has no rows until something is revoked. Publishing the first policy does not upload a revocation. The empty `since/0` response from section 4 is the feed.

From `services/trust-api/`, plan the index SQL. This command only reads the file and writes `publish.sql`. It does not verify the signature and it does not call Cloudflare.

```bash
node scripts/publish-plan.mjs policy /path/to/signed-policy.json
```

For the document rendered from the current `trust/policy-meta.json`, `publish.sql` is:

```sql
INSERT INTO policies (sequence, issued_at, r2_key)
VALUES (1, '2026-10-22T00:00:00Z', 'policy/1.json');
```

and the planner prints:

```bash
npx wrangler r2 object put workrr-trust-blobs/policy/1.json --file /path/to/signed-policy.json --content-type application/json --remote
npx wrangler d1 execute workrr-trust --remote --yes --file publish.sql
```

**needs Shawn's approval.** Both commands write production data. Run the two lines the planner printed, with the real path. `--remote` is required. Without it, wrangler writes a local simulation and the Worker does not see it.

If `issuedAt` in the signed file differs from `2026-10-22T00:00:00Z`, use the planner's SQL, not the sample above.

Do not delete or overwrite `policy/1.json` with an older sequence later. Clients treat a lower sequence as a rollback. A correction is a new signed document with sequence `2`.

## 7. Smoke tests

Use a fresh cache so a previous verify does not hide a failed fetch. On Linux and macOS the cache file is `$XDG_CACHE_HOME/workrr/trust-policy.json` when `XDG_CACHE_HOME` is set (the Go CLI uses the same directory via the OS cache dir).

```bash
export XDG_CACHE_HOME="$(mktemp -d)"
```

### Policy and feed

```bash
curl -sS -D - -o /tmp/trust-policy.json https://trust-api.workrr.ai/v1/policy
```

Expected: status `200` and these headers:

```text
content-type: application/json; charset=utf-8
cache-control: public, max-age=300
etag: "1"
x-workrr-sequence: 1
x-content-type-options: nosniff
access-control-allow-origin: *
```

Expected body shape:

```bash
jq -r '.mediaType, .payloadType, .signature.algorithm' /tmp/trust-policy.json
```

```text
application/vnd.workrr.signed-blob+json;version=1
application/vnd.workrr.trust-policy+json
sigstore
```

```bash
jq -r '.payload' /tmp/trust-policy.json | base64 -d | jq '{sequence, revocationWatermark, signers: [.signers[].subjectAlternativeName]}'
```

Expected: `sequence` is `1`, `revocationWatermark` is `0`, and the two subject names end in `@refs/tags/v0.1.0` and `@refs/tags/v0.1.1`.

```bash
curl -sS https://trust-api.workrr.ai/v1/revocations/since/0
```

Expected body, exactly:

```json
{"since":0,"checkpoint":null,"entries":[]}
```

```bash
DIGEST="$(python3 -c 'print("ab"*32)')"
curl -sS "https://trust-api.workrr.ai/v1/revocations?digest=${DIGEST}"
```

Expected body, exactly, for that unused digest:

```json
{"digest":"abababababababababababababababababababababababababababababababab","entries":[]}
```

A digest that is not 64 lowercase hex characters returns `400` and `{"error":"digest must be 64 lowercase hex characters"}`.

### `workrr verify` with the feed

Take one certificate from the public ledger at `https://trust.workrr.ai/ledger/`. Read that page. Do not edit the site. Use a certificate whose signer is `certify.yml@refs/tags/v0.1.0` or `v0.1.1` and whose policy name is `workrr-baseline-v0.1`. Download the artifact bytes and the bundle next to each other.

```bash
export XDG_CACHE_HOME="$(mktemp -d)"
npx @workrr-trust/certify verify ./artifact --bundle certificate.sigstore.json --source OWNER/REPO
echo "exit=$?"
```

`OWNER/REPO` is the publisher repository on that certificate. Expected when the API is up and the feed is empty:

- exit `0`
- a `✓` line for the bundle naming forge `github` and the certifier SAN
- a `publisher` line for that repository
- a `policy workrr-baseline-v0.1 sha256:…` line
- headline `VERIFIED · Tested (silver)` or `VERIFIED · Signed (banded)` (banded when that certificate recorded no test suite)
- no note `revocation was not checked`
- no note `offline:`
- no note `trust policy fetch failed`

`--json` adds `"ok": true` and `"status": "verified"`. `notes` does not contain a revocation warning.

### `workrr verify` without the feed

Same artifact, same bundle, fresh cache, `--offline`. This does not fetch the policy or the feed.

```bash
export XDG_CACHE_HOME="$(mktemp -d)"
npx @workrr-trust/certify verify ./artifact --bundle certificate.sigstore.json --source OWNER/REPO --offline
echo "exit=$?"
```

Expected:

- exit `0` for the same baseline certificate
- the same `VERIFIED · <Name> (<level>)` headline
- this note, exactly:

```text
offline: using the embedded trust policy; revocation was not checked
```

A revoked certificate can still verify in this mode. That is the documented meaning of `--offline`.

The Go CLI prints the same lines:

```bash
export XDG_CACHE_HOME="$(mktemp -d)"
workrr verify ./artifact --bundle certificate.sigstore.json --source OWNER/REPO --offline
```

## 8. Monitoring

Read-only tail, from `services/trust-api/`:

```bash
npx wrangler tail workrr-trust-api --format pretty
```

Then `curl` `/v1/policy` once. The tail shows a `GET` with status `200`. Leave the tail with Ctrl-C.

`observability.enabled` is already true, with full sampling. In the Cloudflare dashboard open Workers & Pages → `workrr-trust-api` → Observability. A policy fetch and a `since/0` fetch each write one log event. Workers Logs retention is 3 days on the Free plan and 7 days on Workers Paid (prices in section 10).

D1 → `workrr-trust` → Metrics shows rows read. A healthy `/v1/policy` reads one policy row. A healthy `since/0` on an empty feed reads no revocation rows and one checkpoint lookup.

**needs Shawn's approval** if you create a notification. Dashboard → Notifications → a Workers alert on `workrr-trust-api` for error rate above zero for 5 minutes. The Worker returns `500` with `{"error":"trust policy blob missing"}` or `{"error":"signed blob missing"}` when D1 points at an R2 key that is not there. That is the page to watch after a publish.

## 9. Rollback

### The API is down

Verify does not fail closed when the host is unreachable.

With no cache, a fetch failure uses the policy embedded in that binary and does not check revocation. The notes are:

```text
trust policy fetch failed; using the embedded trust policy
revocation was not checked
```

The headline is still `VERIFIED · <Name> (<level>)` for a baseline certificate signed by `v0.1.0` or `v0.1.1`. Exit `0`. The embedded policy is that same trust set.

A cache younger than one hour is reused without fetching the policy again. The feed is still fetched. If only the feed fails, the note is:

```text
revocation was not checked
```

A cache older than one hour, when the fetch fails, is still used. The note is:

```text
trust policy fetch failed; using cached trust policy
```

`--offline` never reads the cache and never opens a connection. The note is the one in section 7.

A response that arrives but whose signature does not verify falls back to the embedded policy and prints `trust policy signature invalid; using the embedded trust policy`. A feed that arrives but does not verify fails closed: exit `1`, headline `NOT VERIFIED` or `ROLLBACK`, and no `VERIFIED` line. Unreachable and invalid are different.

To see the down behavior without undeploying, point one command at a closed port. **This does not change production.**

```bash
export XDG_CACHE_HOME="$(mktemp -d)"
WORKRR_TRUST_API=http://127.0.0.1:9 \
  npx @workrr-trust/certify verify ./artifact --bundle certificate.sigstore.json
```

Expected notes include `trust policy fetch failed; using the embedded trust policy` and `revocation was not checked`.

### Undo a Worker deploy

```bash
npx wrangler versions list
```

**needs Shawn's approval.**

```bash
npx wrangler rollback VERSION_ID --message "restore trust-api before VERSION_ID"
```

`VERSION_ID` is an older id from `versions list`. Rollback restores that Worker version. It does not delete the R2 objects or the D1 rows. Custom hostname `trust-api.workrr.ai` stays.

### Undo a bad policy

Do not publish a document whose `sequence` is less than `1`, and do not delete `policy/1.json` to "go back". Clients that have accepted sequence `1` reject an older sequence with `ROLLBACK` and exit `1`.

**needs Shawn's approval.** Sign a new document with `"sequence": 2` in `trust/policy-meta.json` from a release tag, then publish `policy/2.json` and insert that row. The Worker serves the highest sequence. Sequence `2` replaces sequence `1` for clients. Clients that already cached sequence `1` pick up sequence `2` within one hour, or immediately with a fresh `XDG_CACHE_HOME`.

D1 time travel can restore the index if the insert itself was wrong. Listing bookmarks is read-only:

```bash
npx wrangler d1 time-travel info workrr-trust --remote
```

Restoring a bookmark rewrites the database. **needs Shawn's approval.** Do not restore across a sequence clients have already accepted unless you are also publishing a higher sequence that matches the restored bytes.

## 10. Cost estimate

**Estimate, not a quote.** Read from the public price cards on 2026-10-23: [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/) (page updated 2026-10-02), [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/) (page updated 2026-04-21), and [R2 pricing](https://developers.cloudflare.com/r2/pricing/) (page updated 2026-10-01). Prices change. The Workers Logs card on that Workers page says it is replaced by Observability pricing on 2026-12-01.

This Worker does one D1 point read and one R2 get per policy request, and one D1 checkpoint read per empty feed request. Clients cache a verified policy for one hour and still fetch the feed on every `verify` that is not `--offline`. The Worker sets `Cache-Control` but does not use the Cache API, so those requests still invoke the Worker.

| Item | Included | Overage | This service at low volume |
|---|---|---|---|
| Workers Paid subscription | 10 million requests and 30 million CPU-ms per month | $0.30 / million requests, $0.02 / million CPU-ms | One policy fetch per client per hour, plus one feed fetch per `verify`. 10,000 verifies a day is about 300,000 Worker requests a month, inside the included 10 million. |
| Workers Free | 100,000 requests / day, 10 ms CPU / invocation | No paid overage; requests past the cap fail | The same 10,000 verifies a day fits under 100,000 requests / day only if policy fetches are not a second burst on top. Prefer Paid if the account is already there. |
| D1, Workers Paid | 25 billion rows read / month, 50 million rows written / month, 5 GB | $0.001 / million reads, $1.00 / million writes, $0.75 / GB-month | A few hundred thousand indexed reads. Storage is one JSON object, kilobytes. Inside the included amounts. |
| D1, Workers Free | 5 million rows read / day, 100,000 rows written / day, 5 GB | Daily caps | The first migration and the one policy insert are the writes. Reads at the volume above stay under the daily cap. |
| R2 Standard | 10 GB-month, 1 million Class A ops, 10 million Class B ops | $0.015 / GB-month, $4.50 / million Class A, $0.36 / million Class B | One `PUT` to publish, then one `GET` per policy request. Egress is free on the card. Far inside the free tier. Infrequent Access is not used. |
| Custom hostname | No separate line on those cards | | `trust-api.workrr.ai` and its certificate ride on the existing `workrr.ai` zone. |
| Workers Logs | Free: 200,000 events / day, 3 days. Paid: 20 million / month included, then $0.60 / million, 7 days. | | `head_sampling_rate` is `1`, so each request is one event. 300,000 events a month is inside the Paid inclusion and inside the Free daily cap. |

**Estimated monthly total** if the Cloudflare account is already on Workers Paid and this is the only extra traffic: **$5**, the plan minimum, with this Worker's usage inside the included amounts. **Estimated monthly total** on Workers Free, under the daily request cap: **$0**. A busy month past 10 million Worker requests adds about **$0.30 per extra million**. This estimate does not include a Logpush job, a notification destination, or any other Worker in the account.
