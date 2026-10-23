-- Hash-only public anchor log for private-tier certificates.
-- Stores ONLY SHA-256 digests so private-tier certificates gain public existence
-- and timing proofs without revealing artifact names, source URLs, or policies.

CREATE TABLE anchors (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  envelope_hash TEXT NOT NULL UNIQUE,
  bundle_hash TEXT NOT NULL,
  subject_digest_hash TEXT NOT NULL,
  anchored_at TEXT NOT NULL,
  prev_chain_hash TEXT NOT NULL,
  chain_hash TEXT NOT NULL
);

CREATE INDEX idx_anchors_bundle_hash ON anchors (bundle_hash);
CREATE INDEX idx_anchors_subject_digest_hash ON anchors (subject_digest_hash);
