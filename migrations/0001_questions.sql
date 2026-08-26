CREATE TABLE questions (
  answer_code TEXT PRIMARY KEY,
  status_hash TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  fields_json TEXT NOT NULL,
  answers_json TEXT,
  expires_at INTEGER NOT NULL,
  answered_at INTEGER
);

CREATE INDEX questions_expires_at ON questions (expires_at);
