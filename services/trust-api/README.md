# workrr trust API

Cloudflare Worker that stores signed trust-policy and revocation blobs in R2
and indexes them in D1. It is transport. Clients verify the signatures.

Setup, the SQL Shawn runs, and the deploy checklist: [docs/trust-api.md](../../docs/trust-api.md).

```bash
npm ci
npm test
npm run typecheck
```

`wrangler.jsonc` uses a placeholder D1 database id (`00000000-0000-0000-0000-000000000000`) and does not create resources. Tests run locally on Miniflare.
