# workrr Registry & Audit Trail (`services/registry`)

Cloudflare Worker backed by **R2** (`BLOBS` for signed Sigstore certificate bundles) and **D1** (`DB` for verified publishers, certified artifact metadata, and an append-only SHA-256 hash-chained audit trail).

## Endpoints

- **`POST /v1/publishers`** — Registers a verified publisher (`github` or `gitlab` namespace) and records a `publisher.verified` entry in the hash-chained audit log.
- **`GET /v1/publishers`** / **`GET /v1/publishers/:id`** — Lists or fetches verified publishers.
- **`POST /v1/artifacts`** — Publishes a certified artifact (`gold`, `silver`, or `banded`), enforcing that `sourceUri` belongs to an active verified publisher, storing the signed Sigstore bundle in R2 (`bundles/<digest>.sigstore.json`), and appending an `artifact.published` entry to the audit log.
- **`GET /v1/artifacts`** / **`GET /v1/artifacts/:digest`** / **`GET /v1/artifacts/:digest/bundle`** — Queries indexed artifacts or fetches the raw Sigstore bundle from R2.
- **`GET /v1/audit`** — Returns the ordered hash-chained audit trail.
- **`GET /v1/audit/verify`** — Recomputes `payload_hash`, `prev_hash`, and `entry_hash` from genesis across every row in `audit_log` to detect any tampering or sequence gap.
