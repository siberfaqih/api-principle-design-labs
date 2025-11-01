-- Initialize database schema and seed dummy data
-- This script is auto-executed by the official Postgres image

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

INSERT INTO users (email, name)
VALUES
  ('alice@example.com', 'Alice'),
  ('bob@example.com', 'Bob'),
  ('carol@example.com', 'Carol')
ON CONFLICT (email) DO NOTHING;

-- Helpful index for lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);