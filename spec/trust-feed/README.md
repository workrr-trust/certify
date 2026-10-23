# Trust-feed test vectors

Cases shared by `test/trust-feed.test.mjs` and `go/trustfeed_test.go`. They
cover a valid signed policy, a tampered policy, a sequence rollback, a
revocation by artifact digest, a revocation by Rekor log index, and the
offline fallback.

Signatures are ed25519 from the seed in [generate.mjs](generate.mjs). That key
is not a trust anchor. Production verifiers accept only the Sigstore identities
in spec §7.

Regenerate after an intentional format change, with `dist/` already built:

```bash
npm run build && node spec/trust-feed/generate.mjs
```

CI checks the committed `vectors.json` matches the generator.
