-- init_db.sql
-- Database initialization for secure API lab with dynamic project storage
-- Creates users and projects tables for IDOR vulnerability simulation
-- Compatible with SQLite syntax

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL,
  tenant_id TEXT,
  display_name TEXT,
  bio TEXT
);

CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  owner_id INTEGER NOT NULL,
  tenant_id TEXT NOT NULL,
  secret TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT OR IGNORE INTO users(username,password,role,tenant_id) VALUES
  ('alice','password1','user','t1'),
  ('bob','password2','admin','t1'),
  ('charlie','password3','user','t1'),
  ('diana','password4','user','t2');

INSERT OR IGNORE INTO projects(name,description,owner_id,tenant_id,secret) VALUES
  ('Alpha Project','Alice''s first project',1,'t1','alpha-secret-key'),
  ('Beta System','Bob''s admin project',2,'t1','beta-admin-secret'),
  ('Gamma App','Alice''s second project',1,'t1','gamma-user-secret'),
  ('Delta Service','Charlie''s project',3,'t1','delta-charlie-secret'),
  ('Epsilon Platform','Diana''s cross-tenant project',4,'t2','epsilon-diana-secret'),
  ('Zeta Framework','Bob''s framework project',2,'t1','zeta-framework-secret');
