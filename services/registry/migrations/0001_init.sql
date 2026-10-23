-- Verified publishers, certified artifact metadata index, and append-only
-- SHA-256 hash-chained audit log. Signed Sigstore bundles live in R2 (BLOBS).

CREATE TABLE publishers (
  publisher_id TEXT PRIMARY KEY,
  forge TEXT NOT NULL CHECK (forge IN ('github', 'gitlab')),
  namespace TEXT NOT NULL,
  display_name TEXT NOT NULL,
  verification_method TEXT NOT NULL,
  verified_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked'))
);

CREATE INDEX idx_publishers_namespace ON publishers (forge, namespace);

CREATE TABLE artifacts (
  artifact_digest TEXT PRIMARY KEY,
  publisher_id TEXT NOT NULL REFERENCES publishers (publisher_id),
  name TEXT NOT NULL,
  artifact_type TEXT NOT NULL CHECK (artifact_type IN ('skill', 'mcp-server', 'agent-context', 'other')),
  source_uri TEXT NOT NULL,
  source_commit TEXT NOT NULL,
  source_path TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level IN ('gold', 'silver', 'banded')),
  band TEXT CHECK (band IN ('A', 'B', 'C', 'D', 'E')),
  policy_name TEXT NOT NULL,
  policy_digest TEXT NOT NULL,
  bundle_r2_key TEXT NOT NULL,
  certified_at TEXT NOT NULL,
  published_at TEXT NOT NULL
);

CREATE INDEX idx_artifacts_publisher ON artifacts (publisher_id);
CREATE INDEX idx_artifacts_type_level ON artifacts (artifact_type, level);

CREATE TABLE audit_log (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL UNIQUE
);

CREATE INDEX idx_audit_log_subject ON audit_log (subject_id);
