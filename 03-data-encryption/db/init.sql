-- Postgres init schema and dummy data
CREATE TABLE IF NOT EXISTS users_plain (
  id SERIAL PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL,
  national_id TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS users_secure (
  id SERIAL PRIMARY KEY,
  ciphertext BYTEA NOT NULL,
  role TEXT NOT NULL DEFAULT 'user'
);

-- Dummy data for vulnerable table (plaintext PII)
INSERT INTO users_plain (full_name, email, national_id, role) VALUES
('Alice Example', 'alice@example.com', '1234567890123456', 'admin'),
('Bob Example', 'bob@example.com', '6543210987654321', 'user');

-- Dummy encrypted row for secure table (AES-GCM packed [iv|tag|ciphertext] base64)
-- Key: ENCRYPTION_KEY_BASE64 (same as in docker-compose)
INSERT INTO users_secure (ciphertext, role) VALUES (
  decode('GxLo+QyK8QQvNQUE2100SGeNqCEZ8CjXykSIMP9KTcRf2YBubHZjon6mLS3M7OMYrhayCYGE1U+LKRsNZVo74vhKTugUazzQhUFUje3F2A9MF8ICixNWSOc+Tuo5DudCXEgxBKpzzzEqNussrfK2iwezdf4fHZzB', 'base64'),
  'admin'
);