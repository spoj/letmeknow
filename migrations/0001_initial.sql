CREATE TABLE IF NOT EXISTS questions (
  answer_hash TEXT PRIMARY KEY,
  status_hash TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  fields TEXT NOT NULL,
  answers TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  answered_at INTEGER
);

CREATE INDEX IF NOT EXISTS questions_expiry_idx ON questions (expires_at);
