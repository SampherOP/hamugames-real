-- Optional: the Vercel API auto-creates these tables on first request.
CREATE TABLE IF NOT EXISTS accounts (
  uid TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  email_key TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
  path TEXT PRIMARY KEY,
  value JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS kv_path_prefix_idx ON kv (path text_pattern_ops);
