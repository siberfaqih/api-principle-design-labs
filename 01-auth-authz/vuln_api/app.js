const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
app.use(bodyParser.json());
const PORT = process.env.PORT || 3000;

// Weak secret (vulnerability)
const SECRET = process.env.JWT_SECRET || 'random';

// Postgres database setup
const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  port: parseInt(process.env.PGPORT || '5432', 10),
  user: process.env.PGUSER || 'labuser',
  password: process.env.PGPASSWORD || 'labpass',
  database: process.env.PGDATABASE || 'labdb',
});

// Initialize database schema and seed data (vulnerable passwords)
function initializeDatabase(callback) {
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
    `INSERT INTO users(username,password,role,tenant_id) VALUES
      ('alice','password1','user','t1'),
      ('bob','password2','admin','t1'),
      ('charlie','password3','user','t1'),
      ('diana','password4','user','t2')
    ON CONFLICT (username) DO NOTHING`,
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
      for (const sql of statements) {
        await pool.query(sql);
      }
      console.log('Database initialized successfully in Postgres');
      if (callback) callback();
    } catch (err) {
      console.error('Error initializing database:', err);
      if (callback) callback(err);
    }
  })();
}

// Initialize database on startup
initializeDatabase(() => {
  app.listen(PORT, () => console.log('VULN API listening on', PORT));
});

// Helper: find user
function findUser(username, callback) {
  pool.query('SELECT * FROM users WHERE username = $1', [username], (err, result) => {
    const user = result && result.rows ? result.rows[0] : undefined;
    callback(err, user);
  });
}

// 1) Weak password auth, no rate limit, verbose error messages
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  
  findUser(username, async (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(400).json({ error: 'User not found' }); // username enumeration
    
    try {
      // Support both plaintext and bcrypt-hashed passwords (shared DB with fixed_api may seed hashes)
      if (user.password && /^\$2[aby]\$/.test(user.password)) {
        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(401).json({ error: 'Wrong password' });
      } else {
        if (password !== user.password) return res.status(401).json({ error: 'Wrong password' });
      }
    } catch (e) {
      return res.status(500).json({ error: 'Auth error' });
    }
    
    // create token with NO exp (intentional for lab)
    const token = jwt.sign({ sub: user.id, role: user.role, tenant_id: user.tenant_id }, SECRET, { algorithm: 'HS256' });
    return res.json({ access_token: token });
  });
});

// 2) JWT-protected endpoint but no scope/ownership checks (IDOR)
app.get('/projects/:id', (req, res) => {
  const projId = parseInt(req.params.id);
  
  // VULNERABLE: No authentication or authorization checks
  pool.query('SELECT * FROM projects WHERE id = $1', [projId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const project = result.rows[0];
    if (!project) return res.status(404).json({ error: 'Project not found' });
    
    // VULNERABLE: Returns project data regardless of ownership
    return res.json(project);
  });
});

// 3) Get all projects (VULNERABLE: No filtering by user)
app.get('/projects', (req, res) => {
  // VULNERABLE: Returns all projects without any access control
  pool.query('SELECT * FROM projects', [], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    return res.json(result.rows);
  });
});

// 4) Create new project (VULNERABLE: No authentication)
app.post('/projects', (req, res) => {
  const { name, description, owner_id, tenant_id, secret } = req.body;
  
  // VULNERABLE: No authentication or input validation
  pool.query(
    'INSERT INTO projects(name, description, owner_id, tenant_id, secret) VALUES ($1, $2, $3, $4, $5) RETURNING id',
    [name, description, owner_id, tenant_id, secret],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      return res.json({ id: result.rows[0].id, message: 'Project created' });
    }
  );
});

// 5) Update project (VULNERABLE: No ownership check)
app.patch('/projects/:id', (req, res) => {
  const projId = parseInt(req.params.id);
  const updates = req.body;
  
  // VULNERABLE: No authentication or ownership verification
  const keys = Object.keys(updates);
  if (keys.length === 0) return res.status(400).json({ error: 'No fields' });
  const fields = keys.map((key, idx) => `${key} = $${idx + 1}`).join(', ');
  const values = keys.map(k => updates[k]);
  values.push(projId);
  
  pool.query(`UPDATE projects SET ${fields} WHERE id = $${values.length}`, values, (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (result.rowCount === 0) return res.status(404).json({ error: 'Project not found' });
    return res.json({ message: 'Project updated' });
  });
});

// 6) Delete project (VULNERABLE: No ownership check)
app.delete('/projects/:id', (req, res) => {
  const projId = parseInt(req.params.id);
  
  // VULNERABLE: No authentication or ownership verification
  pool.query('DELETE FROM projects WHERE id = $1', [projId], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (result.rowCount === 0) return res.status(404).json({ error: 'Project not found' });
    return res.json({ message: 'Project deleted' });
  });
});

// 7) Endpoint that allows mass-assignment via update (vulnerable)
app.patch('/users/:id', (req, res) => {
  // naive apply body to user object - vulnerable to updating role
  const id = parseInt(req.params.id);
  
  pool.query('SELECT * FROM users WHERE id = $1', [id], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'no user' });
    
    // MASS ASSIGNMENT vulnerability - allows updating any field including role
    const updates = req.body;
    const keys = Object.keys(updates);
    const fields = keys.map((key, idx) => `${key} = $${idx + 1}`).join(', ');
    const values = keys.map(k => updates[k]);
    values.push(id);
    
    pool.query(`UPDATE users SET ${fields} WHERE id = $${values.length}`, values, (err2) => {
      if (err2) return res.status(500).json({ error: 'Database error' });
      return res.json({ ok: true, message: 'User updated' });
    });
  });
});

// 8) Endpoint that accepts API key via header but no binding/rotation
const API_KEYS = { 'static-key-123': { owner: 'ci-service', scopes: ['read', 'write'] } };
app.get('/m2m/data', (req, res) => {
  const k = req.get('x-api-key');
  if (!k || !API_KEYS[k]) return res.status(401).json({ error: 'no key' });
  return res.json({ data: 'sensitive-machine-data', scopes: API_KEYS[k].scopes });
});

// 9) Token acceptance: purposely lenient verification (vulnerable)
app.get('/whoami', (req, res) => {
  const auth = req.get('authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'no token' });
  try {
    // VULN: jwt.verify without algorithm enforcement -> may accept alg=none tokens from some libs
    const decoded = jwt.verify(token, SECRET, { ignoreExpiration: true });
    return res.json({ decoded });
  } catch (e) {
    return res.status(401).json({ error: 'invalid token', detail: e.message });
  }
});

// simple health
app.get('/', (req, res) => res.send('VULN API running with Postgres database'));

// Graceful shutdown
process.on('SIGINT', () => {
  pool.end(() => {
    console.log('Database connection closed.');
    process.exit(0);
  });
});
