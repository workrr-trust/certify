-- Index for the signed trust policy and the revocation feed.
-- Blobs live in R2. This database is a lookup index, not a trust anchor:
-- clients verify every signature themselves.

CREATE TABLE policies (
  sequence INTEGER PRIMARY KEY,
  issued_at TEXT NOT NULL,
  r2_key TEXT NOT NULL
);

CREATE TABLE revocations (
  sequence INTEGER PRIMARY KEY,
  artifact_digest TEXT,
  log_index TEXT,
  reason TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  signer TEXT NOT NULL,
  r2_key TEXT NOT NULL,
  CHECK (
    (artifact_digest IS NOT NULL AND log_index IS NULL)
    OR (artifact_digest IS NULL AND log_index IS NOT NULL)
  )
);

CREATE INDEX idx_revocations_artifact_digest ON revocations (artifact_digest);
CREATE INDEX idx_revocations_log_index ON revocations (log_index);

-- One signed checkpoint covering the revocation chain. id is always 1.
CREATE TABLE revocation_checkpoint (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  sequence INTEGER NOT NULL,
  r2_key TEXT NOT NULL
);
