-- Initialize Postgres schema and seed data for the Secure API Lab

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  nik TEXT UNIQUE NOT NULL,
  full_name TEXT NOT NULL,
  account_number TEXT UNIQUE NOT NULL,
  balance NUMERIC(15,2) DEFAULT 0.00,
  profile_bio TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Transactions table
CREATE TABLE IF NOT EXISTS transactions (
  id SERIAL PRIMARY KEY,
  from_account TEXT NOT NULL,
  to_account TEXT NOT NULL,
  amount NUMERIC(15,2) NOT NULL,
  description TEXT,
  transaction_type TEXT NOT NULL,
  status TEXT DEFAULT 'completed',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed sample users
INSERT INTO users (email, nik, full_name, account_number, balance, profile_bio)
VALUES
  ('john.doe@email.com', '3201234567890123', 'John Doe', 'ACC001234567890', 1000000.00, 'Software Engineer from Jakarta'),
  ('jane.smith@email.com', '3301234567890124', 'Jane Smith', 'ACC001234567891', 750000.00, 'Marketing Manager from Bandung'),
  ('bob.wilson@email.com', '3401234567890125', 'Bob Wilson', 'ACC001234567892', 500000.00, 'Business Analyst from Surabaya'),
  ('alice.brown@email.com', '3501234567890126', 'Alice Brown', 'ACC001234567893', 250000.00, 'Graphic Designer from Yogyakarta')
ON CONFLICT (email) DO NOTHING;

-- Seed sample transactions
INSERT INTO transactions (from_account, to_account, amount, description, transaction_type)
VALUES
  ('ACC001234567890', 'ACC001234567891', 100000.00, 'Monthly salary transfer', 'transfer'),
  ('ACC001234567891', 'ACC001234567892', 50000.00, 'Freelance payment', 'transfer'),
  ('ACC001234567892', 'ACC001234567893', 25000.00, 'Dinner bill split', 'transfer');