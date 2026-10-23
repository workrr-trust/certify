# Revoking a certificate

A revocation is a signed statement that an artifact digest, or one Rekor log
index, must not verify. The statement is signed the same way as the trust
policy: Sigstore keyless, from a release tag of `.github/workflows/revoke.yml`.
The trust API only stores the bytes. Verifiers check the signature themselves.

Do not run the workflow until there is something to revoke. Running it publishes
a signature. It does not deploy anything and it does not write to R2.

## What gets signed

One revocation entry, and a checkpoint that covers the chain so far.

- The first entry uses `prev` = 64 zeros.
- The next entry's `prev` is the sha256 of the previous entry's canonical JSON
  (the exact bytes in `entry.json`, with no trailing newline).
- `sequence` starts at 1 and only increases.
- Pass exactly one of the artifact's sha256 or the certificate's Rekor log index.

The format is [spec §7](../spec/README.md).

## Sign

On GitHub: Actions → revoke → Run workflow. Select the **release tag**, not
`main`. A signature from `refs/heads/main` is rejected.

| Input | Example |
|---|---|
| sequence | `1` |
| prev | `0000000000000000000000000000000000000000000000000000000000000000` |
| reason | `compromised certifier commit` |
| artifact_digest | 64 lowercase hex, or empty |
| log_index | decimal Rekor index, or empty |

Download the `signed-revocation` artifact. Review `entry.json` before uploading.

## Publish

Follow [trust API setup](trust-api.md) to put the signed blobs in R2 and the
index rows in D1. Then bump `trust/policy-meta.json`:

- `revocationWatermark` = this entry's sequence
- `revocationHead` = sha256 of `entry.json`

Commit that, tag a release, and run the [trust-policy workflow](../.github/workflows/trust-policy.yml)
from that tag. Clients that only have an older policy still accept a newer
signed checkpoint, and they reject a checkpoint sequence lower than one they
have already verified. Putting the new head in the next signed policy is what
lets a client that has never seen the feed detect a truncated one.

## What verify does

- A matching, validly signed entry fails the certificate with `REVOKED` and exit 1.
- A feed that is reachable but badly signed fails closed (`NOT VERIFIED`). An
  attacker who can modify the response cannot make a revocation disappear without
  breaking the chain, and cannot add one without the revoke workflow's identity.
- `--offline`, or a feed the client cannot reach, does **not** check revocation.
  The command says so. A revoked certificate can still verify in that mode.
