const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(bodyParser.json());
const PORT = process.env.PORT || 3001;

// SECURE secret should be provided via env and rotated in real envs
const SECRET = process.env.JWT_SECRET || 'replace-with-secure-secret';

// Initialize Postgres database
const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  port: parseInt(process.env.PGPORT || '5432', 10),
  user: process.env.PGUSER || 'labuser',
  password: process.env.PGPASSWORD || 'labpass',
  database: process.env.PGDATABASE || 'labdb',
});

// Initialize database with schema and hashed passwords
function initializeDatabase(callback) {
  const hashed = {
    password1: bcrypt.hashSync('password1', 8),
    password2: bcrypt.hashSync('password2', 8),
    password3: bcrypt.hashSync('password3', 8),
    password4: bcrypt.hashSync('password4', 8)
  };

  const statements = [
    `CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      tenant_id TEXT,
      display_name TEXT,
      bio TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS projects (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      owner_id INTEGER NOT NULL,
      tenant_id TEXT NOT NULL,
      secret TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(name, owner_id)
    )`,
    {
      text: `INSERT INTO users(username,password,role,tenant_id) VALUES
        ('alice',$1,'user','t1'),
        ('bob',$2,'admin','t1'),
        ('charlie',$3,'user','t1'),
        ('diana',$4,'user','t2')
      ON CONFLICT (username) DO UPDATE SET password = EXCLUDED.password, role = EXCLUDED.role, tenant_id = EXCLUDED.tenant_id`,
      values: [hashed.password1, hashed.password2, hashed.password3, hashed.password4]
    },
    `INSERT INTO projects(name,description,owner_id,tenant_id,secret) VALUES
      ('Alpha Project','Alice''s first project',1,'t1','alpha-secret-key'),
      ('Beta System','Bob''s admin project',2,'t1','beta-admin-secret'),
      ('Gamma App','Alice''s second project',1,'t1','gamma-user-secret'),
      ('Delta Service','Charlie''s project',3,'t1','delta-charlie-secret'),
      ('Epsilon Platform','Diana''s cross-tenant project',4,'t2','epsilon-diana-secret')
    ON CONFLICT DO NOTHING`
  ];

  (async () => {
    try {
      for (const stmt of statements) {
        if (typeof stmt === 'string') {
          await pool.query(stmt);
        } else {
          await pool.query(stmt.text, stmt.values);
        }
      }
      console.log('Database initialized successfully in Postgres with hashed passwords');
      if (callback) callback();
    } catch (err) {
      console.error('Error initializing database:', err);
      if (callback) callback(err);
    }
  })();
}

// Initialize database on startup
initializeDatabase(() => {
  app.listen(PORT, () => console.log('FIXED API listening on', PORT));
});

function findUser(username, callback) {
  pool.query('SELECT * FROM users WHERE username = $1', [username], (err, result) => {
    const user = result && result.rows ? result.rows[0] : undefined;
    callback(err, user);
  });
}

// middleware to verify token strictly
function authMiddleware(req, res, next) {
  const auth = req.get('authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'no token' });
  try {
    const decoded = jwt.verify(token, SECRET, {
      algorithms: ['HS256'],
      audience: 'secure-api',
      issuer: 'auth.myorg'
    });
    req.user = decoded;
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

// Ownership enforced for object-level authorization (IDOR fix)
app.get('/projects/:id', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  
  pool.query('SELECT * FROM projects WHERE id = $1', [id], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const project = result.rows[0];
    if (!project) return res.status(404).json({ error: 'no project' });
    
    // enforce ownership or admin role
    if (project.owner_id !== req.user.sub && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'forbidden' });
    }
    return res.json(project);
  });
});

// Get projects with proper filtering
app.get('/projects', authMiddleware, (req, res) => {
  let query = '';
  let params = [];
  
  if (req.user.role === 'admin') {
    // Admins can see all projects in their tenant
    query = 'SELECT * FROM projects WHERE tenant_id = $1';
    params = [req.user.tenant_id];
  } else {
    // Regular users can only see their own projects
    query = 'SELECT * FROM projects WHERE owner_id = $1';
    params = [req.user.sub];
  }
  
  pool.query(query, params, (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    return res.json(result.rows);
  });
});

// Create new project with proper authentication and validation
app.post('/projects', authMiddleware, (req, res) => {
  const { name, description, secret } = req.body;
  
  // Input validation
  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Project name is required' });
  }
  
  // Use authenticated user's info
  const owner_id = req.user.sub;
  const tenant_id = req.user.tenant_id;
  const projectSecret = secret || 'default-secret-' + Date.now();
  
  // Pre-check for duplicate name per owner to return a consistent 409
  pool.query('SELECT id FROM projects WHERE name = $1 AND owner_id = $2', [name.trim(), owner_id], (checkErr, checkResult) => {
    if (checkErr) return res.status(500).json({ error: 'Database error' });
    if (checkResult.rows.length > 0) {
      return res.status(409).json({ error: 'Project name already exists for this owner' });
    }

    pool.query(
      'INSERT INTO projects(name, description, owner_id, tenant_id, secret) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, description, owner_id, tenant_id, created_at, updated_at',
      [name.trim(), description || '', owner_id, tenant_id, projectSecret],
      (err, result) => {
        if (err) {
          // Handle unique constraint violation (duplicate project name per owner)
          if (err.code === '23505') {
            return res.status(409).json({ error: 'Project name already exists for this owner' });
          }
          return res.status(500).json({ error: 'Database error' });
        }
        const project = result.rows[0];
        return res.status(201).json(project);
      }
    );
  });
});

// Update project with ownership verification
app.patch('/projects/:id', authMiddleware, (req, res) => {
  const projId = parseInt(req.params.id);
  
  // First check if project exists and user has permission
  pool.query('SELECT * FROM projects WHERE id = $1', [projId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const project = result.rows[0];
    if (!project) return res.status(404).json({ error: 'Project not found' });
    
    // Check ownership or admin role
    if (project.owner_id !== req.user.sub && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'forbidden' });
    }
    
    // Whitelist allowed fields for update
    const allowedFields = ['name', 'description'];
    const updates = {};
    
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    }
    
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    
    // Add updated_at timestamp (server-side)
    const keys = Object.keys(updates);
    const setClause = keys.map((k, idx) => `${k} = $${idx + 1}`).join(', ');
    const values = keys.map(k => updates[k]);
    values.push(projId);
    
    const sql = `UPDATE projects SET ${setClause}, updated_at = NOW() WHERE id = $${values.length}`;
    pool.query(sql, values, (err2) => {
      if (err2) {
        if (err2.code === '23505') {
          return res.status(409).json({ error: 'Project name already exists for this owner' });
        }
        return res.status(500).json({ error: 'Database error' });
      }
      return res.json({ message: 'Project updated' });
    });
  });
});

// Delete project with ownership verification
app.delete('/projects/:id', authMiddleware, (req, res) => {
  const projId = parseInt(req.params.id);
  
  // First check if project exists and user has permission
  pool.query('SELECT * FROM projects WHERE id = $1', [projId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const project = result.rows[0];
    if (!project) return res.status(404).json({ error: 'Project not found' });
    
    // Check ownership or admin role
    if (project.owner_id !== req.user.sub && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'forbidden' });
    }
    
    pool.query('DELETE FROM projects WHERE id = $1', [projId], (err2) => {
      if (err2) return res.status(500).json({ error: 'Database error' });
      return res.json({ message: 'Project deleted' });
    });
  });
});

// Mass-assignment mitigation: whitelist fields for update
app.patch('/users/:id', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  
  if (req.user.sub !== id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  
  pool.query('SELECT * FROM users WHERE id = $1', [id], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'no user' });
    
    // Whitelist allowed fields
    const allowed = ['display_name', 'bio'];
    const updates = {};
    
    for (const k of allowed) {
      if (req.body[k] !== undefined) {
        updates[k] = req.body[k];
      }
    }
    
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    
    const keys = Object.keys(updates);
    const setClause = keys.map((k, idx) => `${k} = $${idx + 1}`).join(', ');
    const values = keys.map(k => updates[k]);
    values.push(id);
    
    pool.query(`UPDATE users SET ${setClause} WHERE id = $${values.length}`, values, (err2) => {
      if (err2) return res.status(500).json({ error: 'Database error' });
      return res.json({ ok: true, message: 'User updated' });
    });
  });
});

// Secure whoami endpoint
app.get('/whoami', authMiddleware, (req, res) => {
  // Return user info from token (already verified by middleware)
  pool.query('SELECT id, username, role, tenant_id, display_name, bio FROM users WHERE id = $1', 
    [req.user.sub], (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      const user = result.rows[0];
      if (!user) return res.status(404).json({ error: 'User not found' });
      return res.json({ user, token_info: req.user });
    });
});

app.get('/', (req, res) => res.send('FIXED API running with Postgres database'));

// Graceful shutdown
process.on('SIGINT', () => {
  pool.end(() => {
    console.log('Database connection closed.');
    process.exit(0);
  });
});

// API key management: check simple allowlist & scope binding
const API_KEYS = { 'dynamic-key-abc': { owner: 'ci-service', scopes: ['read'] } };
app.get('/m2m/data', (req, res) => {
  const k = req.get('x-api-key');
  if (!k || !API_KEYS[k]) return res.status(401).json({ error: 'no key' });
  // check scope
  if (!API_KEYS[k].scopes.includes('read')) return res.status(403).json({ error: 'insufficient scope' });
  return res.json({ data: 'sensitive-machine-data' });
});

// Simple login rate limiter (per username)
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_ATTEMPTS = 5;
const loginAttempts = new Map();

function isRateLimited(key) {
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (!entry) return false;
  if (now - entry.firstAttemptAt > RATE_LIMIT_WINDOW_MS) {
    loginAttempts.delete(key);
    return false;
  }
  return entry.count >= RATE_LIMIT_MAX_ATTEMPTS;
}

function recordAttempt(key) {
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (!entry || now - entry.firstAttemptAt > RATE_LIMIT_WINDOW_MS) {
    loginAttempts.set(key, { count: 1, firstAttemptAt: now });
  } else {
    entry.count += 1;
    loginAttempts.set(key, entry);
  }
}

function resetAttempts(key) {
  loginAttempts.delete(key);
}

// Secure login endpoint
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  const key = username || req.ip;

  if (!username || !password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (isRateLimited(key)) {
    return res.status(429).json({ error: 'Too many login attempts' });
  }

  findUser(username, async (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    if (!user) {
      recordAttempt(key);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    try {
      const ok = await bcrypt.compare(password, user.password);
      if (!ok) {
        recordAttempt(key);
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    } catch (e) {
      return res.status(500).json({ error: 'Auth error' });
    }

    resetAttempts(key);

    const token = jwt.sign(
      { sub: user.id, role: user.role, tenant_id: user.tenant_id },
      SECRET,
      { algorithm: 'HS256', expiresIn: '1h', audience: 'secure-api', issuer: 'auth.myorg' }
    );

    return res.json({ access_token: token });
  });
});
